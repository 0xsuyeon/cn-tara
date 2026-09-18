from __future__ import annotations

import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, RLock, Thread
from urllib.parse import parse_qs, urlparse

from cntara_db import AssessmentLimitError, CNTaraDB, SQLITE_STORAGE_SIDECAR_RESERVE_BYTES
from manifest_collector import build_manifest_proposal


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = Path(os.getenv("CNTARA_DB_PATH", str(BASE_DIR / "data" / "cntara.db")))
HOST = os.getenv("CNTARA_HOST", "127.0.0.1")
PORT = int(os.getenv("CNTARA_PORT", "8080"))
OPENAI_BASE_URL = "https://api.openai.com/v1"
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"
ANTHROPIC_OFFICIAL_BASE_URL = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"
OUTBOUND_USER_AGENT = "CloudTARA/0.1"
SESSION_COOKIE_NAME = "cntara_session"
SESSION_COOKIE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
LLM_SESSION_IDLE_SECONDS = 2 * 60 * 60
LLM_PROVIDER_RATE_LIMIT_RETRIES = 3
LLM_PROVIDER_RATE_LIMIT_MAX_WAIT_SECONDS = 60.0
# Request and retry limits for one cart-wide risk action.
LLM_RISK_BATCH_MAX_ITEMS = 30
LLM_RISK_BATCH_MAX_FACTORS = 12
LLM_RISK_BATCH_MAX_CELLS = 160
LLM_RISK_BATCH_TARGET_CELLS_PER_CHUNK = 24
LLM_RISK_BATCH_MAX_ITEMS_PER_CHUNK = 6
LLM_RISK_BATCH_MAX_INITIAL_PROVIDER_CALLS = 8
LLM_RISK_BATCH_MAX_PROVIDER_CALLS = 24
LLM_RISK_BATCH_MAX_PROVIDER_ATTEMPTS = (
    LLM_RISK_BATCH_MAX_PROVIDER_CALLS * (LLM_PROVIDER_RATE_LIMIT_RETRIES + 1)
)
LLM_RISK_BATCH_MAX_CHUNK_INPUT_BYTES = 64 * 1024
LLM_RISK_BATCH_MAX_TOTAL_INPUT_BYTES = 512 * 1024
LLM_RISK_BATCH_MIN_COMPLETION_TOKENS = 2048
LLM_RISK_BATCH_MAX_COMPLETION_TOKENS = 8192
LLM_RISK_BATCH_SINGLE_ITEM_ESCALATION_CAP = 4096
LLM_RISK_BATCH_COMPLETION_BASE_TOKENS = 1024
LLM_RISK_BATCH_COMPLETION_TOKENS_PER_CELL = 160

# Request limits for CRRA 2.3 batch review.
LLM_CRRA_BATCH_MAX_ITEMS = 200
LLM_CRRA_BATCH_ITEMS_PER_CHUNK = 8
LLM_CRRA_BATCH_MAX_INITIAL_PROVIDER_CALLS = 25
LLM_CRRA_BATCH_MAX_PROVIDER_CALLS = 48
LLM_CRRA_BATCH_MAX_CHUNK_INPUT_BYTES = 32 * 1024
LLM_CRRA_BATCH_MAX_TOTAL_INPUT_BYTES = 512 * 1024
LLM_CRRA_BATCH_MIN_COMPLETION_TOKENS = 1536
LLM_CRRA_BATCH_MAX_COMPLETION_TOKENS = 6144
LLM_CRRA_BATCH_COMPLETION_BASE_TOKENS = 512
LLM_CRRA_BATCH_COMPLETION_TOKENS_PER_ITEM = 256

LLM_RISK_BATCH_PROMPT = """당신은 MITRE TARA 위험 요인 평가 보조자다. 제공된 사실과 현재 Risk Calculator 정의만 사용한다.
각 item_id와 각 factor code를 빠짐없이 한 번씩 반환한다. 확인되지 않은 시스템 구조, 공격 성공, 실제 피해나 사례를 추측하지 않는다.
반드시 JSON 객체만 반환한다. 형식: {"items":[{"item_id":숫자,"factors":{"factor_code":{"information_status":"RECOMMENDED","qualitative_value":"정의에 있는 정확한 label","rationale":"한국어 판정 근거"}},"missing_information":[]}]}.
각 factor는 반드시 RECOMMENDED로 결론 내리고 해당 factor의 qualitative option label 중 하나를 정확히 선택한다. INSUFFICIENT, null, '판단 정보 부족'은 반환하지 않는다.
자료가 제한적이어도 제공된 DFD·매핑·Scope 안에서 가장 상대적으로 부합하는 값을 선택하고, 그 한계와 현재 제공 정보 기준 판단임을 비어 있지 않은 독립 근거에 간결하게 명시하되 240자를 넘지 않는다.
missing_information은 항상 빈 배열로 반환하며 추가 확인 항목을 만들지 않는다.
가중치 계산, Risk Score, 위험 등급은 절대 생성하지 않는다."""

LLM_CRRA_BATCH_PROMPT = """당신은 MITRE TARA의 CRRA 대응책 후보 검토 보조자다. 제공된 평가 Scope, 공격 벡터, 대응책, KM 매핑과 현재 검토값만 사용한다.
각 item_id를 빠짐없이 정확히 한 번씩 반환한다. 입력의 item_id와 current_effect를 기준으로 각 행을 독립 검토한다. 대응책이 이 평가 맥락에서 해당 공격 벡터를 실질적으로 예방·탐지·대응할 수 있으면 INCLUDED, 관계가 적용되지 않거나 효과를 뒷받침하지 못하면 EXCLUDED를 선택한다.
effect는 PREVENT(공격에 필요한 조건 제거), DETECT(공격이 발생했거나 진행 중이거나 잠재함을 판별), RESPOND(공격의 가능성 또는 영향을 감소) 중 가장 직접적인 하나만 선택한다. confidence는 HIGH(공학적 검증 근거), MODERATE(사이버 보안 전문가 판단), LOW(타당해 보이지만 실증되지 않음)의 기준으로 선택한다. 같은 AV-대응책에 여러 item_id가 있으면 각 행은 서로 다른 effect를 유지하여 P/D/R 복수 효과를 표현하고 동일 effect로 합치지 않는다.
반드시 JSON 객체만 반환한다. 형식: {"suggestions":[{"item_id":숫자,"status":"INCLUDED|EXCLUDED","effect":"PREVENT|DETECT|RESPOND","confidence":"HIGH|MODERATE|LOW","reason":"한국어 판단 근거","missing_information":[]}]}.
자료가 제한적이어도 현재 제공 정보 안에서 가장 타당한 결론을 반드시 선택한다. UNREVIEWED, null, '판단 정보 부족'을 반환하지 않는다. reason에는 AV-대응책 관계와 평가 맥락에 근거한 이유를 간결하게 쓰고 500자를 넘지 않는다. missing_information은 항상 빈 배열이다.
기존 KM 매핑은 명시적인 Scope·아키텍처 불일치가 없다면 보수적으로 INCLUDED를 우선한다. 공학적 검증 근거가 제시되지 않았다면 HIGH를 선택하지 않는다. 근거가 제한적이면 중단하지 말고 현재 정보에 기초한 가정을 reason에 명시하며 LOW를 선택한다.
추천은 검토 초안이며 최종 판단은 사용자가 수행한다."""


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return min(max(value, minimum), maximum)


try:
    LLM_SESSION_RATE_LIMIT_PER_MINUTE = int(
        os.getenv("CNTARA_LLM_RATE_LIMIT_PER_MINUTE", "20")
    )
except ValueError:
    LLM_SESSION_RATE_LIMIT_PER_MINUTE = 20
LLM_SESSION_RATE_LIMIT_PER_MINUTE = min(max(LLM_SESSION_RATE_LIMIT_PER_MINUTE, 1), 1000)
LLM_CONFIG_RATE_LIMIT_PER_SESSION = _bounded_env_int(
    "CNTARA_LLM_CONFIG_RATE_LIMIT_PER_SESSION", 5, 1, 100,
)
LLM_CONFIG_RATE_LIMIT_GLOBAL = _bounded_env_int(
    "CNTARA_LLM_CONFIG_RATE_LIMIT_GLOBAL", 30, 1, 10_000,
)
MAX_LLM_SESSIONS = _bounded_env_int(
    "CNTARA_MAX_LLM_SESSIONS", 500, 1, 100_000,
)
MAX_ASSESSMENTS_PER_SESSION = _bounded_env_int(
    "CNTARA_MAX_ASSESSMENTS_PER_SESSION", 100, 1, 100_000,
)
MAX_ASSESSMENTS_TOTAL = _bounded_env_int(
    "CNTARA_MAX_ASSESSMENTS_TOTAL", 2_000, 1, 1_000_000,
)
MAX_DB_BYTES = _bounded_env_int(
    "CNTARA_MAX_DB_BYTES", 256 * 1024 * 1024, 16 * 1024 * 1024,
    1024 * 1024 * 1024 * 1024,
)
_SESSION_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
KM_ADMIN_ENABLED = os.getenv("CNTARA_KM_ADMIN_ENABLED", "false").strip().lower() in {
    "1", "true", "yes", "on",
}
_KM_MUTATION_PATTERNS = (
    re.compile(r"/api/km/asset-mappings"),
    re.compile(r"/api/km/attack-vectors(?:/[^/]+)?"),
    re.compile(r"/api/km/countermeasures(?:/[^/]+)?"),
    re.compile(r"/api/km/mappings(?:/\d+|/import)?"),
    re.compile(r"/api/km/vector-groups(?:/\d+(?:/members)?)?"),
)


def _empty_session_llm_config() -> dict[str, str]:
    """Return a key-free default; browser sessions must never inherit server keys."""
    return {
        "provider": "groq",
        "base_url": GROQ_BASE_URL,
        "api_key": "",
        "model": "",
    }


def _config_text(value: object, field: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} 값을 문자열로 입력해 주세요.")
    text = value.strip()
    if not text:
        raise ValueError(f"{field} 값을 입력해 주세요.")
    if len(text) > max_length:
        raise ValueError(f"{field} 값이 너무 깁니다.")
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f"{field} 값에 제어 문자를 사용할 수 없습니다.")
    return text


def _config_base_url(value: object) -> str:
    base_url = _config_text(value, "base_url", 2048).rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url은 http 또는 https URL이어야 합니다.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base_url에 사용자 정보, 쿼리 또는 fragment를 포함할 수 없습니다.")
    hostname = parsed.hostname or ""
    is_loopback = hostname.lower() == "localhost"
    try:
        is_loopback = is_loopback or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        pass
    if parsed.scheme.lower() == "http" and not is_loopback:
        raise ValueError("원격 base_url은 API 키 보호를 위해 https를 사용해야 합니다.")
    return base_url


class LLMClient:
    """Small OpenAI-compatible client used only for optional suggestions."""

    def __init__(self, *, use_environment: bool = True, allow_custom_runtime: bool = True) -> None:
        self._lock = RLock()
        self._environment_config = (
            self._read_environment_config() if use_environment else _empty_session_llm_config()
        )
        self._config = dict(self._environment_config)
        self._initial_source = "environment" if use_environment else "session"
        self._runtime_source = "runtime" if use_environment else "session"
        self._allow_custom_runtime = allow_custom_runtime
        self._configured_via = self._initial_source
        self._verified = False

    @staticmethod
    def _read_environment_config() -> dict[str, str]:
        explicit_base_url = os.getenv("CNTARA_LLM_BASE_URL", "").strip().rstrip("/")
        provider_hint = os.getenv("CNTARA_LLM_PROVIDER", "").strip().lower()
        openai_key = os.getenv("OPENAI_API_KEY", "").strip()
        groq_key = os.getenv("GROQ_API_KEY", "").strip()
        gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
        anthropic_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        anthropic_base_url = os.getenv("ANTHROPIC_BASE_URL", ANTHROPIC_OFFICIAL_BASE_URL).strip().rstrip("/")
        model = os.getenv("CNTARA_LLM_MODEL", "").strip()
        explicit_host = urlparse(explicit_base_url).hostname if explicit_base_url else ""

        use_anthropic = provider_hint == "anthropic" or (
            not provider_hint
            and bool(anthropic_key)
            and not openai_key
            and not groq_key
            and not gemini_key
            and not explicit_base_url
        )
        if use_anthropic:
            return {
                "provider": "anthropic",
                "base_url": _config_base_url(anthropic_base_url or ANTHROPIC_OFFICIAL_BASE_URL),
                "api_key": anthropic_key,
                "model": model,
            }

        use_groq = (
            provider_hint == "groq"
            or (not provider_hint and explicit_host == "api.groq.com")
            or (
                not provider_hint
                and bool(groq_key)
                and not openai_key
                and not anthropic_key
                and not gemini_key
                and not explicit_base_url
            )
        )
        if use_groq:
            return {
                "provider": "groq",
                "base_url": GROQ_BASE_URL,
                "api_key": groq_key or openai_key,
                "model": model,
            }

        use_gemini = (
            provider_hint == "gemini"
            or (not provider_hint and explicit_host == "generativelanguage.googleapis.com")
            or (
                not provider_hint
                and bool(gemini_key)
                and not openai_key
                and not groq_key
                and not anthropic_key
                and not explicit_base_url
            )
        )
        if use_gemini:
            return {
                "provider": "gemini",
                "base_url": GEMINI_BASE_URL,
                # Provider credentials are isolated.
                "api_key": gemini_key,
                "model": model,
            }

        base_url = _config_base_url(explicit_base_url) if explicit_base_url else OPENAI_BASE_URL
        base_host = urlparse(base_url).hostname
        provider = "openai" if base_host == "api.openai.com" else "openai-compatible"
        if provider_hint in {"openai", "openai-compatible", "custom"}:
            provider = "openai-compatible" if provider_hint == "custom" else provider_hint
        return {"provider": provider, "base_url": base_url, "api_key": openai_key, "model": model}

    @staticmethod
    def _enabled_for(config: dict[str, str]) -> bool:
        if not config["model"]:
            return False
        if config["provider"] in {"groq", "openai", "gemini", "anthropic"}:
            return bool(config["api_key"])
        # Keyless self-hosted endpoint.
        return bool(config["api_key"] or "openai.com" not in config["base_url"])

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled_for(self._config)

    def status(self) -> dict[str, object]:
        with self._lock:
            config = dict(self._config)
            configured_via = self._configured_via
            verified = self._verified
        return {
            "enabled": self._enabled_for(config),
            "verified": verified and self._enabled_for(config),
            "model": config["model"] or None,
            "base_url": config["base_url"],
            "provider": config["provider"],
            "configured_via": configured_via,
        }

    @staticmethod
    def _provider_label(config: dict[str, str]) -> str:
        return {
            "groq": "Groq",
            "openai": "OpenAI",
            "gemini": "Google Gemini",
            "anthropic": "Anthropic",
            "openai-compatible": "OpenAI 호환 서버",
        }.get(config["provider"], "LLM 서비스")

    @staticmethod
    def _error_detail(raw_detail: str) -> str:
        try:
            parsed = json.loads(raw_detail)
        except (json.JSONDecodeError, TypeError):
            return ""
        if not isinstance(parsed, dict):
            return ""
        error = parsed.get("error")
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            return error["message"].strip()
        if isinstance(error, str):
            return error.strip()
        if isinstance(parsed.get("message"), str):
            return parsed["message"].strip()
        return ""

    @staticmethod
    def _retry_hint_seconds(value: object) -> float | None:
        text = str(value or "").strip().lower()
        if not text:
            return None
        if re.fullmatch(r"\d+(?:\.\d+)?", text):
            return float(text)
        match = re.fullmatch(
            r"(?:(\d+(?:\.\d+)?)m)?\s*(?:(\d+(?:\.\d+)?)s)?",
            text,
        )
        if match and (match.group(1) or match.group(2)):
            return float(match.group(1) or 0) * 60.0 + float(match.group(2) or 0)
        return None

    @classmethod
    def _rate_limit_retry_delay(
        cls, headers: object, raw_detail: str, attempt: int,
    ) -> float:
        get_header = getattr(headers, "get", None)
        if callable(get_header):
            for name in ("Retry-After", "x-ratelimit-reset-tokens"):
                seconds = cls._retry_hint_seconds(get_header(name))
                if seconds is not None:
                    return min(max(seconds, 0.25), LLM_PROVIDER_RATE_LIMIT_MAX_WAIT_SECONDS)

        # Gemini may return retry metadata in error.details.
        try:
            parsed_detail = json.loads(raw_detail)
        except (json.JSONDecodeError, TypeError):
            parsed_detail = None
        error = parsed_detail.get("error") if isinstance(parsed_detail, dict) else None
        details = error.get("details") if isinstance(error, dict) else None
        if isinstance(details, list):
            for item in details:
                if not isinstance(item, dict):
                    continue
                seconds = cls._retry_hint_seconds(
                    item.get("retryDelay", item.get("retry_delay"))
                )
                if seconds is not None:
                    return min(max(seconds, 0.25), LLM_PROVIDER_RATE_LIMIT_MAX_WAIT_SECONDS)

        detail = cls._error_detail(raw_detail)
        match = re.search(
            r"(?:try again in|retry after|retry in)\s*([0-9]+(?:\.[0-9]+)?)\s*(ms|s|sec(?:ond)?s?)",
            detail,
            flags=re.IGNORECASE,
        )
        if match:
            seconds = float(match.group(1))
            if match.group(2).lower() == "ms":
                seconds /= 1000.0
            return min(max(seconds, 0.25), LLM_PROVIDER_RATE_LIMIT_MAX_WAIT_SECONDS)
        return min(float(2 ** attempt), 8.0)

    @classmethod
    def _http_error_message(cls, config: dict[str, str], code: int, raw_detail: str) -> str:
        provider = cls._provider_label(config)
        detail = cls._error_detail(raw_detail)
        api_key = config.get("api_key", "")
        if api_key and detail:
            detail = detail.replace(api_key, "[redacted]")
        suffix = f" 공급자 응답: {detail}" if detail else ""
        if code in {401, 403}:
            return (
                f"{provider}에서 API 키를 거부했습니다. 키가 올바른지, 만료되거나 폐기되지 않았는지 "
                f"확인해 주세요.{suffix}"
            )
        if code == 404:
            return (
                f"{provider}에서 입력한 모델 또는 API 주소를 찾지 못했습니다. 모델 ID와 Base URL을 "
                f"확인해 주세요.{suffix}"
            )
        if code == 429:
            return (
                f"{provider}의 분당 요청·토큰 사용 한도에 도달했습니다. "
                "자동 재시도 후에도 제한이 계속되어 중단했습니다. 잠시 후 다시 시도해 주세요."
            )
        if code == 413:
            detail_lower = detail.lower()
            if "tokens per minute" in detail_lower or "request too large" in detail_lower:
                return (
                    f"{provider}의 분당 토큰 한도보다 이번 LLM 요청이 큽니다. "
                    "평가 항목을 더 작은 묶음으로 나눠 다시 시도해 주세요."
                )
            return (
                f"{provider}에 보낸 LLM 입력이 허용 크기를 초과했습니다. "
                "긴 설명이나 평가 항목을 줄인 뒤 다시 시도해 주세요."
            )
        return f"{provider} 요청에 실패했습니다. (HTTP {code}){suffix}"

    @staticmethod
    def _request_headers(config: dict[str, str]) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": OUTBOUND_USER_AGENT,
        }
        if config["provider"] == "anthropic":
            headers.update({
                "x-api-key": config["api_key"],
                "anthropic-version": ANTHROPIC_VERSION,
            })
        elif config["api_key"]:
            headers["Authorization"] = f"Bearer {config['api_key']}"
        return headers

    @staticmethod
    def _has_known_unusable_local_proxy(request_url: str) -> bool:
        """Detect a loopback discard proxy for approved provider hosts."""
        parsed_request = urlparse(request_url)
        request_host = parsed_request.hostname or ""
        if parsed_request.scheme.lower() != "https" or request_host not in {
            "api.groq.com",
            "api.openai.com",
            "generativelanguage.googleapis.com",
            "api.anthropic.com",
        }:
            return False
        # NO_PROXY already selects a direct connection.
        if urllib.request.proxy_bypass(request_host):
            return False

        proxies = urllib.request.getproxies()
        # Use only the HTTPS proxy selected by ProxyHandler.
        proxy_url = proxies.get("https")
        if not isinstance(proxy_url, str) or not proxy_url.strip():
            return False
        proxy_url = proxy_url.strip()
        if "://" not in proxy_url:
            proxy_url = f"http://{proxy_url}"
        try:
            parsed_proxy = urlparse(proxy_url)
            proxy_host = parsed_proxy.hostname or ""
            proxy_port = parsed_proxy.port
        except ValueError:
            return False
        if (
            parsed_proxy.scheme.lower() not in {"http", "https"}
            or parsed_proxy.username
            or parsed_proxy.password
            or parsed_proxy.query
            or parsed_proxy.fragment
            or parsed_proxy.path not in {"", "/"}
        ):
            return False

        is_loopback = proxy_host.lower() == "localhost"
        try:
            is_loopback = is_loopback or ipaddress.ip_address(proxy_host).is_loopback
        except ValueError:
            pass
        return is_loopback and proxy_port == 9

    @staticmethod
    def _direct_urlopen(request: urllib.request.Request, timeout: int):
        """Open one HTTPS request without environment/system proxy handlers."""
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        return opener.open(request, timeout=timeout)

    @classmethod
    def _open_provider_request(cls, request: urllib.request.Request, timeout: int):
        """Avoid only the known discard proxy; otherwise preserve normal proxy policy."""
        if cls._has_known_unusable_local_proxy(request.full_url):
            try:
                return cls._direct_urlopen(request, timeout)
            except (urllib.error.URLError, TimeoutError) as direct_error:
                # Exception text may contain credentials.
                setattr(direct_error, "cntara_direct_fallback_attempted", True)
                raise
        return urllib.request.urlopen(request, timeout=timeout)

    @classmethod
    def _connection_error_message(
        cls, config: dict[str, str], exc: BaseException, request_url: str,
    ) -> str:
        provider = cls._provider_label(config)
        reason = getattr(exc, "reason", exc)
        reason_text = str(reason).lower()
        if getattr(exc, "cntara_direct_fallback_attempted", False):
            detail = "응답하지 않는 로컬 프록시를 우회한 직접 연결도 실패했습니다."
        elif cls._has_known_unusable_local_proxy(request_url):
            detail = "실행 환경의 로컬 프록시(127.0.0.1:9)가 연결을 차단했습니다."
        elif isinstance(reason, TimeoutError) or "timed out" in reason_text:
            detail = "연결 시간이 초과되었습니다."
        elif "certificate" in reason_text or "ssl" in reason_text:
            detail = "TLS 인증서를 검증하지 못했습니다."
        elif "name or service not known" in reason_text or "getaddrinfo" in reason_text:
            detail = "API 서버의 DNS 주소를 확인하지 못했습니다."
        elif "refused" in reason_text or "10061" in reason_text:
            detail = "프록시 또는 원격 서버가 연결을 거부했습니다."
        else:
            detail = f"네트워크 오류 유형: {type(reason).__name__}."
        return (
            f"CloudTARA 서버에서 {provider}에 접속하지 못했습니다. {detail} "
            "인터넷 연결과 방화벽·프록시 설정을 확인해 주세요."
        )

    def _verify_connection(self, config: dict[str, str]) -> None:
        """Check credentials and the selected model without sending assessment data."""
        if config["provider"] == "anthropic":
            request_url = f"{config['base_url']}/v1/models?limit=1000"
        else:
            request_url = f"{config['base_url']}/models"
        request = urllib.request.Request(
            request_url,
            headers=self._request_headers(config),
            method="GET",
        )
        try:
            with self._open_provider_request(request, timeout=20) as response:
                result = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(self._http_error_message(config, exc.code, detail)) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(self._connection_error_message(config, exc, request_url)) from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("LLM 서비스의 모델 목록 응답을 읽을 수 없습니다. API 주소를 확인해 주세요.") from exc

        rows = result.get("data") if isinstance(result, dict) else None
        model_ids = {
            row.get("id")
            for row in rows
            if isinstance(row, dict) and isinstance(row.get("id"), str)
        } if isinstance(rows, list) else set()
        if config["provider"] == "gemini":
            # Accept Gemini model IDs with or without the models/ prefix.
            model_ids |= {
                model_id.removeprefix("models/")
                for model_id in model_ids
            }
            if not model_ids:
                raise RuntimeError(
                    "Google Gemini 모델 목록이 비어 있어 입력한 모델을 확인할 수 없습니다. "
                    "API 키의 프로젝트 권한과 모델 사용 가능 여부를 확인해 주세요."
                )
        if model_ids and config["model"] not in model_ids:
            provider = self._provider_label(config)
            raise RuntimeError(
                f"{provider} 연결은 확인했지만 모델 '{config['model']}'을 사용할 수 없습니다. "
                "공급자 콘솔의 모델 ID와 정확히 일치하는지 확인해 주세요."
            )

    def configure(self, data: dict[str, object]) -> dict[str, object]:
        """Apply a process-memory-only override, or restore the startup environment config."""
        if not isinstance(data, dict):
            raise ValueError("LLM 설정은 JSON 객체로 입력해 주세요.")
        if "clear" in data and not isinstance(data["clear"], bool):
            raise ValueError("clear 값은 true 또는 false여야 합니다.")
        if data.get("clear") is True:
            with self._lock:
                self._config = dict(self._environment_config)
                self._configured_via = self._initial_source
                self._verified = False
            return self.status()

        if "verify" in data and not isinstance(data["verify"], bool):
            raise ValueError("verify 값은 true 또는 false여야 합니다.")

        provider = _config_text(data.get("provider", "groq"), "provider", 32).lower()
        if provider == "custom":
            provider = "openai-compatible"
        if provider not in {"groq", "openai", "gemini", "anthropic", "openai-compatible"}:
            raise ValueError(
                "provider는 groq, openai, gemini, anthropic 또는 "
                "openai-compatible이어야 합니다."
            )
        if provider == "openai-compatible" and not self._allow_custom_runtime:
            raise ValueError(
                "공개 서비스에서는 Groq, OpenAI, Google Gemini 또는 "
                "Anthropic 공식 API만 연결할 수 있습니다."
            )
        api_key = _config_text(data.get("api_key"), "api_key", 4096)
        model = _config_text(data.get("model"), "model", 256)

        if provider == "groq":
            base_url = GROQ_BASE_URL
        elif provider == "openai":
            base_url = OPENAI_BASE_URL
        elif provider == "gemini":
            base_url = GEMINI_BASE_URL
        elif provider == "anthropic":
            base_url = ANTHROPIC_OFFICIAL_BASE_URL
        else:
            base_url = _config_base_url(data.get("base_url"))

        new_config = {
            "provider": provider,
            "base_url": base_url,
            "api_key": api_key,
            "model": model,
        }
        verify = data.get("verify") is True
        if verify:
            self._verify_connection(new_config)

        with self._lock:
            self._config = new_config
            self._configured_via = self._runtime_source
            self._verified = verify
        return self.status()

    def complete_json(
        self,
        system_prompt: str,
        payload: dict[str, object],
        *,
        max_completion_tokens: int | None = None,
    ) -> dict[str, object]:
        with self._lock:
            config = dict(self._config)
        if not self._enabled_for(config):
            raise RuntimeError("LLM이 설정되지 않았습니다. API 키 설정을 확인해 주세요.")
        if (
            max_completion_tokens is not None
            and (
                isinstance(max_completion_tokens, bool)
                or not isinstance(max_completion_tokens, int)
                or not 1 <= max_completion_tokens <= 8192
            )
        ):
            raise ValueError("LLM 최대 응답 토큰은 1~8192 사이의 정수여야 합니다.")
        if config["provider"] == "anthropic":
            user_content = (
                json.dumps(payload, ensure_ascii=False)
                + "\n\n위 입력만 근거로 사용하고, 설명이나 Markdown 코드 블록 없이 JSON 객체만 반환하세요."
            )
            request_body = json.dumps(
                {
                    "model": config["model"],
                    "max_tokens": max_completion_tokens or 2048,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_content}],
                },
                ensure_ascii=False,
            ).encode("utf-8")
            headers = {"Content-Type": "application/json", **self._request_headers(config)}
            request_url = f"{config['base_url']}/v1/messages"
        else:
            request_payload: dict[str, object] = {
                "model": config["model"],
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
                ],
                "response_format": {"type": "json_object"},
            }
            if max_completion_tokens is not None:
                # Gemini's compatibility endpoint uses max_tokens.
                token_field = "max_tokens" if config["provider"] == "gemini" else "max_completion_tokens"
                request_payload[token_field] = max_completion_tokens
            if config["provider"] == "gemini":
                # Keep classification responses concise.
                request_payload["reasoning_effort"] = "low"
            if (
                config["provider"] == "groq"
                and config["model"] in {"openai/gpt-oss-20b", "openai/gpt-oss-120b"}
            ):
                # gpt-oss reasoning controls supported by Groq.
                request_payload["reasoning_effort"] = "low"
                request_payload["include_reasoning"] = False
            request_body = json.dumps(request_payload, ensure_ascii=False).encode("utf-8")
            headers = {"Content-Type": "application/json", **self._request_headers(config)}
            request_url = f"{config['base_url']}/chat/completions"
        request = urllib.request.Request(request_url, data=request_body, headers=headers, method="POST")
        for attempt in range(LLM_PROVIDER_RATE_LIMIT_RETRIES + 1):
            try:
                with self._open_provider_request(request, timeout=60) as response:
                    result = json.loads(response.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")
                if exc.code == 429 and attempt < LLM_PROVIDER_RATE_LIMIT_RETRIES:
                    time.sleep(self._rate_limit_retry_delay(exc.headers, detail, attempt))
                    continue
                message = self._http_error_message(config, exc.code, detail)
                if exc.code == 413:
                    raise LLMProviderRequestTooLarge(message) from exc
                raise RuntimeError(message) from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                raise RuntimeError(self._connection_error_message(config, exc, request_url)) from exc
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise LLMResponseFormatError(
                    "LLM 서비스 응답을 JSON으로 해석할 수 없습니다."
                ) from exc
        if config["provider"] == "anthropic":
            truncated = isinstance(result, dict) and result.get("stop_reason") == "max_tokens"
        else:
            choices = result.get("choices") if isinstance(result, dict) else None
            first_choice = choices[0] if isinstance(choices, list) and choices else None
            finish_reason = (
                str(first_choice.get("finish_reason", "")).strip().lower()
                if isinstance(first_choice, dict)
                else ""
            )
            truncated = finish_reason in {"length", "max_tokens"}
        if truncated:
            raise LLMCompletionTruncated(
                "LLM 응답이 최대 토큰 한도에서 잘려 완전한 추천안을 만들 수 없습니다. "
                "쇼핑 카트 항목이나 사용자 정의 계산기 요인을 줄인 뒤 다시 요청해 주세요."
            )
        if config["provider"] == "gemini" and finish_reason in {
            "content_filter",
            "safety",
            "recitation",
            "blocklist",
            "prohibited_content",
            "spii",
        }:
            raise RuntimeError(
                "Google Gemini가 안전 또는 콘텐츠 정책에 따라 응답을 중단했습니다. "
                "전송할 평가 맥락을 확인한 뒤 다시 요청해 주세요."
            )
        try:
            if config["provider"] == "anthropic":
                content = "".join(
                    block["text"]
                    for block in result["content"]
                    if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
                )
                if not content.strip():
                    raise ValueError("empty Anthropic text response")
            else:
                content = result["choices"][0]["message"]["content"]
            parsed_content = json.loads(content)
            with self._lock:
                if self._config == config:
                    self._verified = True
            return parsed_content
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LLMResponseFormatError("LLM 응답을 JSON 추천안으로 해석할 수 없습니다.") from exc


@dataclass
class _SessionLLMState:
    client: LLMClient
    last_activity: float


class LLMSessionUnavailable(RuntimeError):
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class LLMSessionRateLimited(RuntimeError):
    code = "LLM_RATE_LIMITED"


class LLMSessionConfigurationSuperseded(RuntimeError):
    code = "LLM_CONFIG_SUPERSEDED"


class LLMSessionConfigurationRateLimited(RuntimeError):
    code = "LLM_CONFIG_RATE_LIMITED"


class LLMSessionCapacityExceeded(RuntimeError):
    code = "LLM_SESSION_CAPACITY_REACHED"


class LLMRiskBatchTooLarge(RuntimeError):
    code = "LLM_RISK_BATCH_TOO_LARGE"

    def __init__(self, message: str, details: dict[str, object]) -> None:
        super().__init__(message)
        self.details = details


class LLMCompletionTruncated(RuntimeError):
    """Raised when a provider explicitly reports output-token truncation."""


class LLMProviderRequestTooLarge(RuntimeError):
    """Raised when one provider request cannot fit within its token/size limit."""

    code = "LLM_PROVIDER_REQUEST_TOO_LARGE"


class LLMResponseFormatError(RuntimeError):
    """Raised only when a successful provider response cannot be decoded as JSON output."""


class LLMRiskBatchExecutionLimit(RuntimeError):
    code = "LLM_RISK_BATCH_PROVIDER_LIMIT"


class LLMRiskResponseInvalid(RuntimeError):
    code = "LLM_RISK_RESPONSE_INVALID"


class LLMCRRABatchTooLarge(RuntimeError):
    code = "LLM_CRRA_BATCH_TOO_LARGE"

    def __init__(self, message: str, details: dict[str, object]) -> None:
        super().__init__(message)
        self.details = details


class LLMCRRABatchExecutionLimit(RuntimeError):
    code = "LLM_CRRA_BATCH_PROVIDER_LIMIT"


class LLMCRRAResponseInvalid(RuntimeError):
    code = "LLM_CRRA_RESPONSE_INVALID"


class LLMSessionStore:
    """Keep each browser's BYOK client in process memory with an idle timeout."""

    def __init__(
        self,
        idle_timeout_seconds: int = LLM_SESSION_IDLE_SECONDS,
        *,
        rate_limit_per_minute: int = LLM_SESSION_RATE_LIMIT_PER_MINUTE,
        config_rate_limit_per_session: int = LLM_CONFIG_RATE_LIMIT_PER_SESSION,
        config_rate_limit_global: int = LLM_CONFIG_RATE_LIMIT_GLOBAL,
        max_sessions: int = MAX_LLM_SESSIONS,
        cleanup_interval_seconds: float | None = None,
        clock: object = time.monotonic,
        utcnow: object | None = None,
    ) -> None:
        if idle_timeout_seconds <= 0:
            raise ValueError("LLM 세션 만료 시간은 1초 이상이어야 합니다.")
        if rate_limit_per_minute <= 0:
            raise ValueError("LLM 분당 요청 한도는 1회 이상이어야 합니다.")
        if config_rate_limit_per_session <= 0 or config_rate_limit_global <= 0:
            raise ValueError("LLM 연결 확인 한도는 1회 이상이어야 합니다.")
        if max_sessions <= 0:
            raise ValueError("LLM 동시 세션 한도는 1개 이상이어야 합니다.")
        self.idle_timeout_seconds = idle_timeout_seconds
        self.rate_limit_per_minute = rate_limit_per_minute
        self.config_rate_limit_per_session = config_rate_limit_per_session
        self.config_rate_limit_global = config_rate_limit_global
        self.max_sessions = max_sessions
        self._clock = clock
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._states: dict[str, _SessionLLMState] = {}
        self._expired_at: dict[str, float] = {}
        self._request_times: dict[str, deque[float]] = {}
        self._config_request_times: dict[str, deque[float]] = {}
        self._global_config_request_times: deque[float] = deque()
        self._next_config_generation = 0
        self._config_generations: dict[str, int] = {}
        self._closed = False
        self._cleanup_stop = Event()
        self._cleanup_thread: Thread | None = None
        if cleanup_interval_seconds is not None:
            if cleanup_interval_seconds <= 0:
                raise ValueError("LLM 세션 정리 주기는 0초보다 커야 합니다.")
            self._cleanup_thread = Thread(
                target=self._cleanup_loop,
                args=(cleanup_interval_seconds,),
                name="cntara-llm-session-cleanup",
                daemon=True,
            )
            self._cleanup_thread.start()

    def _now(self) -> float:
        return float(self._clock())  # type: ignore[operator]

    def _cleanup_loop(self, interval: float) -> None:
        while not self._cleanup_stop.wait(interval):
            self.purge_expired()

    def purge_expired(self) -> None:
        """Actively erase idle API keys, even when their browser sends no more requests."""
        now = self._now()
        with self._lock:
            for session_key, state in list(self._states.items()):
                if now - state.last_activity >= self.idle_timeout_seconds:
                    del self._states[session_key]
                    self._request_times.pop(session_key, None)
                    self._expired_at[session_key] = now
            for session_key, expired_at in list(self._expired_at.items()):
                if now - expired_at >= self.idle_timeout_seconds:
                    del self._expired_at[session_key]
            cutoff = now - 60.0
            for session_key, request_times in list(self._request_times.items()):
                while request_times and request_times[0] <= cutoff:
                    request_times.popleft()
                if not request_times:
                    del self._request_times[session_key]
            for session_key, request_times in list(self._config_request_times.items()):
                while request_times and request_times[0] <= cutoff:
                    request_times.popleft()
                if not request_times:
                    del self._config_request_times[session_key]
            while self._global_config_request_times and self._global_config_request_times[0] <= cutoff:
                self._global_config_request_times.popleft()

    def close(self) -> None:
        self._cleanup_stop.set()
        if self._cleanup_thread is not None:
            self._cleanup_thread.join(timeout=2)
        with self._lock:
            self._closed = True
            self._config_generations.clear()
            self._states.clear()
            self._expired_at.clear()
            self._request_times.clear()
            self._config_request_times.clear()
            self._global_config_request_times.clear()

    def _expire_locked(self, session_key: str, now: float) -> bool:
        state = self._states.get(session_key)
        if state is not None and now - state.last_activity >= self.idle_timeout_seconds:
            del self._states[session_key]
            self._request_times.pop(session_key, None)
            self._expired_at[session_key] = now
            return True
        expired_at = self._expired_at.get(session_key)
        if expired_at is not None and now - expired_at >= self.idle_timeout_seconds:
            del self._expired_at[session_key]
        return session_key in self._expired_at

    @staticmethod
    def _empty_status() -> dict[str, object]:
        return {
            "enabled": False,
            "verified": False,
            "model": None,
            "base_url": GROQ_BASE_URL,
            "provider": "groq",
            "configured_via": "session",
        }

    def status(self, session_key: str) -> dict[str, object]:
        now = self._now()
        with self._lock:
            expired = self._expire_locked(session_key, now)
            state = self._states.get(session_key)
            if state is None:
                result = self._empty_status()
                remaining = None
            else:
                result = state.client.status()
                remaining = max(0.0, self.idle_timeout_seconds - (now - state.last_activity))
        expires_at = None
        if remaining is not None:
            expires_at = (self._utcnow() + timedelta(seconds=remaining)).isoformat(timespec="seconds")
        return {
            **result,
            "expires_at": expires_at,
            "idle_timeout_seconds": self.idle_timeout_seconds,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "expired": expired,
        }

    def configure(self, session_key: str, data: dict[str, object]) -> dict[str, object]:
        if not isinstance(data, dict):
            raise ValueError("LLM 설정은 JSON 객체로 입력해 주세요.")
        if data.get("clear") is True:
            return self.clear(session_key)

        self.purge_expired()
        started_at = self._now()
        with self._lock:
            if self._closed:
                raise LLMSessionConfigurationSuperseded(
                    "서버가 종료되어 LLM 연결 설정을 저장하지 않았습니다."
                )
            cutoff = started_at - 60.0
            session_attempts = self._config_request_times.get(session_key, deque())
            while session_attempts and session_attempts[0] <= cutoff:
                session_attempts.popleft()
            while (
                self._global_config_request_times
                and self._global_config_request_times[0] <= cutoff
            ):
                self._global_config_request_times.popleft()
            if len(session_attempts) >= self.config_rate_limit_per_session:
                raise LLMSessionConfigurationRateLimited(
                    f"API 키 연결 확인은 브라우저별 분당 "
                    f"{self.config_rate_limit_per_session}회까지 가능합니다. 잠시 후 다시 시도해 주세요."
                )
            if len(self._global_config_request_times) >= self.config_rate_limit_global:
                raise LLMSessionConfigurationRateLimited(
                    "서버의 API 키 연결 확인 요청이 많습니다. 잠시 후 다시 시도해 주세요."
                )
            active_or_pending = set(self._states) | set(self._config_generations)
            if session_key not in active_or_pending and len(active_or_pending) >= self.max_sessions:
                raise LLMSessionCapacityExceeded(
                    "서버의 동시 LLM 연결 세션 한도에 도달했습니다. 잠시 후 다시 시도해 주세요."
                )
            self._config_request_times[session_key] = session_attempts
            session_attempts.append(started_at)
            self._global_config_request_times.append(started_at)
            self._next_config_generation += 1
            generation = self._next_config_generation
            self._config_generations[session_key] = generation

        # Network verification runs outside the store lock.
        client = LLMClient(use_environment=False, allow_custom_runtime=False)
        try:
            client.configure(data)
        except Exception:
            with self._lock:
                if self._config_generations.get(session_key) == generation:
                    self._config_generations.pop(session_key, None)
            raise
        now = self._now()
        with self._lock:
            current_generation = self._config_generations.get(session_key)
            if self._closed or current_generation != generation:
                superseded = True
                capacity_exceeded = False
            elif session_key not in self._states and len(self._states) >= self.max_sessions:
                superseded = False
                capacity_exceeded = True
                self._config_generations.pop(session_key, None)
            else:
                superseded = False
                capacity_exceeded = False
                self._states[session_key] = _SessionLLMState(client=client, last_activity=now)
                self._expired_at.pop(session_key, None)
                self._config_generations.pop(session_key, None)
        if superseded or capacity_exceeded:
            client.configure({"clear": True})
        if capacity_exceeded:
            raise LLMSessionCapacityExceeded(
                "서버의 동시 LLM 연결 세션 한도에 도달했습니다. 잠시 후 다시 시도해 주세요."
            )
        if superseded:
            raise LLMSessionConfigurationSuperseded(
                "더 최근의 연결 설정 또는 연결 해제가 적용되어 이전 LLM 설정을 저장하지 않았습니다."
            )
        return self.status(session_key)

    def clear(self, session_key: str) -> dict[str, object]:
        with self._lock:
            self._config_generations.pop(session_key, None)
            self._states.pop(session_key, None)
            self._expired_at.pop(session_key, None)
            self._request_times.pop(session_key, None)
        return self.status(session_key)

    def client(self, session_key: str) -> LLMClient:
        now = self._now()
        with self._lock:
            expired = self._expire_locked(session_key, now)
            state = self._states.get(session_key)
            if state is None:
                if expired:
                    raise LLMSessionUnavailable(
                        "LLM 연결이 2시간 동안 사용되지 않아 만료되었습니다. API 키를 다시 연결해 주세요.",
                        "LLM_SESSION_EXPIRED",
                    )
                raise LLMSessionUnavailable(
                    "이 브라우저에 LLM이 연결되지 않았습니다. 본인의 API 키를 연결해 주세요.",
                    "LLM_NOT_CONFIGURED",
                )
            state.last_activity = now
            return state.client

    def complete_json(
        self,
        session_key: str,
        system_prompt: str,
        payload: dict[str, object],
        *,
        max_completion_tokens: int | None = None,
        count_toward_rate_limit: bool = True,
    ) -> dict[str, object]:
        now = self._now()
        with self._lock:
            expired = self._expire_locked(session_key, now)
            state = self._states.get(session_key)
            if state is None:
                if expired:
                    raise LLMSessionUnavailable(
                        "LLM 연결이 2시간 동안 사용되지 않아 만료되었습니다. API 키를 다시 연결해 주세요.",
                        "LLM_SESSION_EXPIRED",
                    )
                raise LLMSessionUnavailable(
                    "이 브라우저에 LLM이 연결되지 않았습니다. 본인의 API 키를 연결해 주세요.",
                    "LLM_NOT_CONFIGURED",
                )
            if count_toward_rate_limit:
                request_times = self._request_times.setdefault(session_key, deque())
                cutoff = now - 60.0
                while request_times and request_times[0] <= cutoff:
                    request_times.popleft()
                if len(request_times) >= self.rate_limit_per_minute:
                    raise LLMSessionRateLimited(
                        f"LLM 추천은 브라우저별 분당 {self.rate_limit_per_minute}회까지 요청할 수 있습니다. 잠시 후 다시 시도해 주세요."
                    )
                request_times.append(now)
            state.last_activity = now
            client = state.client
        return client.complete_json(
            system_prompt, payload, max_completion_tokens=max_completion_tokens,
        )


def _normalize_missing_information(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RuntimeError("LLM의 부족 정보 목록 형식이 올바르지 않습니다.")
    return [item.strip() for item in value if item.strip()]


def normalize_plausibility_suggestion(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("LLM의 타당성 추천 형식이 올바르지 않습니다.")
    status = value.get("status")
    if status not in {"PLAUSIBLE", "ELIMINATED"}:
        raise RuntimeError("LLM 타당성 추천은 PLAUSIBLE 또는 ELIMINATED여야 합니다.")
    reason = value.get("reason", "")
    if not isinstance(reason, str) or not reason.strip():
        raise RuntimeError("LLM의 판단 근거 형식이 올바르지 않습니다.")
    if "판단 정보 부족" in reason:
        raise RuntimeError("LLM이 필수 타당성 결론과 구체적인 근거를 반환하지 않았습니다.")
    return {
        "status": status,
        "reason": reason.strip(),
        # 추천 결과에는 별도의 추가 확인 목록을 만들지 않는다.
        "missing_information": [],
    }


def normalize_plausibility_suggestions(
    value: object, expected_item_ids: list[int],
) -> list[dict[str, object]]:
    if not isinstance(value, dict) or not isinstance(value.get("suggestions"), list):
        raise RuntimeError("LLM의 쇼핑 카트 판정 초안 형식이 올바르지 않습니다.")
    expected = set(expected_item_ids)
    normalized: list[dict[str, object]] = []
    seen: set[int] = set()
    for raw in value["suggestions"]:
        if not isinstance(raw, dict):
            raise RuntimeError("LLM의 개별 판정 초안 형식이 올바르지 않습니다.")
        item_id = raw.get("item_id")
        if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id not in expected:
            raise RuntimeError("LLM이 알 수 없는 쇼핑 카트 항목을 반환했습니다.")
        if item_id in seen:
            raise RuntimeError("LLM이 중복된 쇼핑 카트 항목을 반환했습니다.")
        seen.add(item_id)
        normalized.append({"item_id": item_id, **normalize_plausibility_suggestion(raw)})
    if seen != expected:
        raise RuntimeError("LLM이 쇼핑 카트의 모든 공격 벡터 초안을 반환하지 않았습니다.")
    return normalized


def normalize_risk_suggestion(
    value: object,
    model: object,
    *,
    require_all_factors: bool = False,
) -> dict[str, object]:
    if not isinstance(value, dict) or not isinstance(model, dict):
        raise RuntimeError("LLM의 위험 평가 추천 형식이 올바르지 않습니다.")
    if any(key in value for key in ("risk_score", "score", "risk_level")):
        raise RuntimeError("LLM은 최종 위험 점수나 등급을 추천할 수 없습니다.")
    proposed = value.get("factors", {})
    if not isinstance(proposed, dict):
        raise RuntimeError("LLM의 위험 요인 추천 형식이 올바르지 않습니다.")
    definitions = {
        factor.get("code"): factor
        for factor in model.get("factors", [])
        if isinstance(factor, dict) and isinstance(factor.get("code"), str)
    }
    if require_all_factors and set(proposed) != set(definitions):
        raise RuntimeError("LLM이 모든 위험 요인에 RECOMMENDED 추천을 반환하지 않았습니다.")
    clean_factors: dict[str, dict[str, object]] = {}
    for code, recommendation in proposed.items():
        if code not in definitions or not isinstance(recommendation, dict):
            raise RuntimeError("LLM이 정의되지 않은 위험 요인을 추천했습니다.")
        if recommendation.get("information_status") != "RECOMMENDED":
            raise RuntimeError("LLM은 모든 위험 요인에 RECOMMENDED 결론을 반환해야 합니다.")

        levels = definitions[code].get("levels", [])
        qualitative_value = recommendation.get("qualitative_value")
        if not isinstance(qualitative_value, str) or not qualitative_value.strip():
            raise RuntimeError("LLM은 각 위험 요인을 계산기 정의의 정성값으로 추천해야 합니다.")
        requested_label = qualitative_value.strip()
        matched_level = next((
            level for level in levels
            if isinstance(level, dict)
            and isinstance(level.get("label"), str)
            and level["label"].strip() == requested_label
        ), None)
        raw_value = recommendation.get("value")
        if matched_level is None:
            raise RuntimeError("LLM이 허용 척도를 벗어난 위험 요인 값을 추천했습니다.")
        if raw_value is not None:
            try:
                if isinstance(raw_value, bool):
                    raise TypeError
                if float(raw_value) != float(matched_level["value"]):
                    raise RuntimeError("LLM의 정성값과 숫자 매핑이 서로 일치하지 않습니다.")
            except (TypeError, ValueError) as exc:
                raise RuntimeError("LLM의 위험 요인 값 형식이 올바르지 않습니다.") from exc
        reason = recommendation.get("rationale")
        if not isinstance(reason, str) or not reason.strip():
            raise RuntimeError("LLM의 위험 요인 근거 형식이 올바르지 않습니다.")
        if "판단 정보 부족" in reason:
            raise RuntimeError("LLM이 필수 위험 요인 결론과 구체적인 근거를 반환하지 않았습니다.")
        if len(reason.strip()) > 240:
            raise RuntimeError("LLM의 위험 요인 판정 근거는 240자 이하여야 합니다.")
        clean_factors[code] = {
            "value": matched_level["value"],
            "qualitative_value": matched_level.get("label", str(matched_level["value"])),
            "reason": reason.strip(),
            "information_status": "RECOMMENDED",
        }
    return {
        "factors": clean_factors,
        "missing_information": [],
    }


def normalize_risk_suggestions(
    value: object, expected_item_ids: list[int], model: object,
) -> list[dict[str, object]]:
    if not isinstance(value, dict) or not isinstance(value.get("items"), list):
        raise RuntimeError("LLM의 쇼핑 카트 위험 평가 초안 형식이 올바르지 않습니다.")
    if any(key in value for key in ("risk_score", "score", "risk_level")):
        raise RuntimeError("LLM은 최종 위험 점수나 등급을 추천할 수 없습니다.")
    expected = set(expected_item_ids)
    normalized: list[dict[str, object]] = []
    seen: set[int] = set()
    for raw in value["items"]:
        if not isinstance(raw, dict):
            raise RuntimeError("LLM의 개별 공격 벡터 위험 평가 형식이 올바르지 않습니다.")
        if any(key in raw for key in ("risk_score", "score", "risk_level")):
            raise RuntimeError("LLM은 최종 위험 점수나 등급을 추천할 수 없습니다.")
        item_id = raw.get("item_id")
        if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id not in expected:
            raise RuntimeError("LLM이 알 수 없는 쇼핑 카트 항목을 반환했습니다.")
        if item_id in seen:
            raise RuntimeError("LLM이 중복된 쇼핑 카트 항목을 반환했습니다.")
        seen.add(item_id)
        normalized.append({
            "item_id": item_id,
            **normalize_risk_suggestion(raw, model, require_all_factors=True),
        })
    if seen != expected:
        raise RuntimeError("LLM이 쇼핑 카트의 모든 공격 벡터 위험 평가를 반환하지 않았습니다.")
    return normalized


def partition_risk_suggestions_for_retry(
    value: object, expected_item_ids: list[int], model: object,
) -> tuple[list[dict[str, object]], list[int]]:
    """Return valid rows and the item IDs that require retry."""
    expected_order = list(expected_item_ids)
    expected = set(expected_order)
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("items"), list)
        or any(key in value for key in ("risk_score", "score", "risk_level"))
    ):
        return [], expected_order

    grouped: dict[int, list[dict[str, object]]] = {item_id: [] for item_id in expected_order}
    unexpected_row = False
    for raw in value["items"]:
        if not isinstance(raw, dict):
            unexpected_row = True
            continue
        item_id = raw.get("item_id")
        if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id not in expected:
            unexpected_row = True
            continue
        grouped[item_id].append(raw)
    if unexpected_row:
        return [], expected_order

    valid: list[dict[str, object]] = []
    unresolved: list[int] = []
    for item_id in expected_order:
        candidates = grouped[item_id]
        if len(candidates) != 1:
            unresolved.append(item_id)
            continue
        try:
            normalized = normalize_risk_suggestions(
                {"items": candidates}, [item_id], model,
            )
        except RuntimeError:
            unresolved.append(item_id)
            continue
        valid.extend(normalized)
    return valid, unresolved


def revalidate_collected_risk_suggestions(
    suggestions: object, expected_item_ids: list[int], model: object,
) -> list[dict[str, object]]:
    """Strictly revalidate the fully collected, normalized batch in original order."""
    if not isinstance(suggestions, list):
        raise LLMRiskResponseInvalid("LLM 위험 평가 결과를 완전한 목록으로 구성하지 못했습니다.")
    raw_items: list[dict[str, object]] = []
    for suggestion in suggestions:
        if not isinstance(suggestion, dict) or not isinstance(suggestion.get("factors"), dict):
            raise LLMRiskResponseInvalid("LLM 위험 평가 결과의 최종 형식이 올바르지 않습니다.")
        raw_factors: dict[str, object] = {}
        for code, factor in suggestion["factors"].items():
            if not isinstance(code, str) or not isinstance(factor, dict):
                raise LLMRiskResponseInvalid("LLM 위험 요인 결과의 최종 형식이 올바르지 않습니다.")
            raw_factors[code] = {
                "information_status": factor.get("information_status"),
                "qualitative_value": factor.get("qualitative_value"),
                "value": factor.get("value"),
                "rationale": factor.get("reason"),
            }
        raw_items.append({"item_id": suggestion.get("item_id"), "factors": raw_factors})
    try:
        return normalize_risk_suggestions(
            {"items": raw_items}, expected_item_ids, model,
        )
    except RuntimeError as exc:
        raise LLMRiskResponseInvalid(
            "LLM이 모든 공격 벡터의 완전한 위험 요인 추천을 반환하지 못했습니다."
        ) from exc


def plan_llm_risk_batch(context: object) -> dict[str, object]:
    """Build every provider chunk, or reject the whole action before quota use."""
    if not isinstance(context, dict):
        raise RuntimeError("LLM 위험 평가에 필요한 쇼핑 카트 맥락 형식이 올바르지 않습니다.")
    items = context.get("items")
    risk_model = context.get("risk_model")
    factors = risk_model.get("factors") if isinstance(risk_model, dict) else None
    if not isinstance(items, list) or not items or not isinstance(factors, list) or not factors:
        raise RuntimeError("LLM 위험 평가에 필요한 항목 또는 계산기 요인 정의가 없습니다.")
    item_ids: list[int] = []
    for item in items:
        item_id = item.get("item_id") if isinstance(item, dict) else None
        if isinstance(item_id, bool) or not isinstance(item_id, int):
            raise RuntimeError("LLM 위험 평가 쇼핑 카트 항목 ID 형식이 올바르지 않습니다.")
        item_ids.append(item_id)
    if len(set(item_ids)) != len(item_ids):
        raise RuntimeError("LLM 위험 평가 쇼핑 카트 항목 ID가 중복되었습니다.")

    item_count = len(items)
    factor_count = len(factors)
    cell_count = item_count * factor_count
    chunk_size = max(
        1,
        min(
            LLM_RISK_BATCH_MAX_ITEMS_PER_CHUNK,
            LLM_RISK_BATCH_TARGET_CELLS_PER_CHUNK // factor_count,
        ),
    )
    provider_calls = (item_count + chunk_size - 1) // chunk_size
    limits: dict[str, int] = {
        "max_items": LLM_RISK_BATCH_MAX_ITEMS,
        "max_factors": LLM_RISK_BATCH_MAX_FACTORS,
        "max_item_factor_cells": LLM_RISK_BATCH_MAX_CELLS,
        "max_initial_provider_calls": LLM_RISK_BATCH_MAX_INITIAL_PROVIDER_CALLS,
        "max_provider_calls": LLM_RISK_BATCH_MAX_PROVIDER_CALLS,
        "max_provider_attempts": LLM_RISK_BATCH_MAX_PROVIDER_ATTEMPTS,
        "max_chunk_input_bytes": LLM_RISK_BATCH_MAX_CHUNK_INPUT_BYTES,
        "max_total_input_bytes": LLM_RISK_BATCH_MAX_TOTAL_INPUT_BYTES,
        "max_completion_tokens_per_call": LLM_RISK_BATCH_MAX_COMPLETION_TOKENS,
    }
    actual: dict[str, int | None] = {
        "items": item_count,
        "factors": factor_count,
        "item_factor_cells": cell_count,
        "provider_calls": provider_calls,
        "provider_attempts_with_retries": provider_calls * (LLM_PROVIDER_RATE_LIMIT_RETRIES + 1),
        "largest_chunk_input_bytes": None,
        "total_input_bytes": None,
    }
    violations: list[str] = []
    if item_count > LLM_RISK_BATCH_MAX_ITEMS:
        violations.append("MAX_ITEMS")
    if factor_count > LLM_RISK_BATCH_MAX_FACTORS:
        violations.append("MAX_FACTORS")
    if cell_count > LLM_RISK_BATCH_MAX_CELLS:
        violations.append("MAX_ITEM_FACTOR_CELLS")
    if violations:
        raise LLMRiskBatchTooLarge(
            "이 쇼핑 카트는 동기식 LLM 일괄 추천 지원 한도를 초과합니다. "
            "공격 벡터나 사용자 정의 계산기 요인을 줄이거나 수동으로 평가해 주세요.",
            {"actual": actual, "limits": limits, "violations": violations, "retryable": False},
        )

    shared_context = {key: value for key, value in context.items() if key != "items"}
    plans: list[dict[str, object]] = []
    total_input_bytes = 0
    largest_chunk_input_bytes = 0

    def request_input_bytes(payload: dict[str, object]) -> int:
        user_content = json.dumps(payload, ensure_ascii=False)
        # Include JSON escaping and the fixed system prompt in the size estimate.
        return len(json.dumps(
            {
                "messages": [
                    {"role": "system", "content": LLM_RISK_BATCH_PROMPT},
                    {"role": "user", "content": user_content},
                ]
            },
            ensure_ascii=False,
        ).encode("utf-8"))

    pending_chunks = [
        items[offset:offset + chunk_size]
        for offset in range(0, item_count, chunk_size)
    ]
    while pending_chunks:
        chunk = pending_chunks.pop(0)
        payload = {**shared_context, "items": chunk}
        input_bytes = request_input_bytes(payload)
        if input_bytes > LLM_RISK_BATCH_MAX_CHUNK_INPUT_BYTES and len(chunk) > 1:
            midpoint = len(chunk) // 2
            pending_chunks[0:0] = [chunk[:midpoint], chunk[midpoint:]]
            continue
        total_input_bytes += input_bytes
        largest_chunk_input_bytes = max(largest_chunk_input_bytes, input_bytes)
        chunk_cells = len(chunk) * factor_count
        completion_tokens = min(
            LLM_RISK_BATCH_MAX_COMPLETION_TOKENS,
            max(
                LLM_RISK_BATCH_MIN_COMPLETION_TOKENS,
                LLM_RISK_BATCH_COMPLETION_BASE_TOKENS
                + chunk_cells * LLM_RISK_BATCH_COMPLETION_TOKENS_PER_CELL,
            ),
        )
        plans.append({
            "items": chunk,
            "expected_item_ids": [int(item["item_id"]) for item in chunk],
            "payload": payload,
            "input_bytes": input_bytes,
            "max_completion_tokens": completion_tokens,
        })
    provider_calls = len(plans)
    actual["provider_calls"] = provider_calls
    actual["provider_attempts_with_retries"] = provider_calls * (LLM_PROVIDER_RATE_LIMIT_RETRIES + 1)
    actual["largest_chunk_input_bytes"] = largest_chunk_input_bytes
    actual["total_input_bytes"] = total_input_bytes
    if provider_calls > LLM_RISK_BATCH_MAX_INITIAL_PROVIDER_CALLS:
        violations.append("MAX_INITIAL_PROVIDER_CALLS")
    if largest_chunk_input_bytes > LLM_RISK_BATCH_MAX_CHUNK_INPUT_BYTES:
        violations.append("MAX_CHUNK_INPUT_BYTES")
    if total_input_bytes > LLM_RISK_BATCH_MAX_TOTAL_INPUT_BYTES:
        violations.append("MAX_TOTAL_INPUT_BYTES")
    if violations:
        raise LLMRiskBatchTooLarge(
            "이 쇼핑 카트의 LLM 입력 맥락이 동기식 일괄 추천 지원 한도를 초과합니다. "
            "긴 설명이나 사용자 정의 계산기 정의를 줄이거나 수동으로 평가해 주세요.",
            {"actual": actual, "limits": limits, "violations": violations, "retryable": False},
        )
    return {"chunks": plans, "metrics": actual, "limits": limits}


def normalize_countermeasure_mapping_suggestion(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("LLM의 대응책 매핑 추천 형식이 올바르지 않습니다.")
    effect = value.get("effect")
    if not isinstance(effect, str) or effect not in {"PREVENT", "DETECT", "RESPOND"}:
        raise RuntimeError("LLM이 지원하지 않는 대응책 효과를 반환했습니다.")
    confidence = value.get("confidence")
    if not isinstance(confidence, str) or confidence not in {"HIGH", "MODERATE", "LOW"}:
        raise RuntimeError("LLM이 지원하지 않는 효과 신뢰도를 반환했습니다.")
    rationale = value.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        raise RuntimeError("LLM의 대응책 매핑 근거 형식이 올바르지 않습니다.")
    return {
        "effect": effect,
        "confidence": confidence,
        "rationale": rationale.strip(),
        "missing_information": _normalize_missing_information(value.get("missing_information")),
    }


def normalize_crra_mapping_suggestions(
    value: object, expected_mapping_ids: list[int],
) -> list[dict[str, object]]:
    """Require exactly one decisive, usable CRRA recommendation per mapping row."""
    if not isinstance(value, dict) or not isinstance(value.get("suggestions"), list):
        raise RuntimeError("LLM의 CRRA 대응책 검토 초안 형식이 올바르지 않습니다.")
    expected = set(expected_mapping_ids)
    normalized: list[dict[str, object]] = []
    seen: set[int] = set()
    for raw in value["suggestions"]:
        if not isinstance(raw, dict):
            raise RuntimeError("LLM의 개별 CRRA 대응책 검토 초안 형식이 올바르지 않습니다.")
        item_id = raw.get("item_id")
        mapping_alias = raw.get("mapping_id")
        if item_id is None:
            item_id = mapping_alias
        elif mapping_alias is not None and mapping_alias != item_id:
            raise RuntimeError("LLM의 CRRA 매핑 항목 ID가 서로 일치하지 않습니다.")
        mapping_id = item_id
        if (
            isinstance(mapping_id, bool)
            or not isinstance(mapping_id, int)
            or mapping_id not in expected
        ):
            raise RuntimeError("LLM이 알 수 없는 CRRA 매핑 항목을 반환했습니다.")
        if mapping_id in seen:
            raise RuntimeError("LLM이 중복된 CRRA 매핑 항목을 반환했습니다.")
        seen.add(mapping_id)
        status = raw.get("status")
        if status not in {"INCLUDED", "EXCLUDED"}:
            raise RuntimeError("LLM의 CRRA 검토 결과는 INCLUDED 또는 EXCLUDED여야 합니다.")
        effect = raw.get("effect")
        if effect not in {"PREVENT", "DETECT", "RESPOND"}:
            raise RuntimeError("LLM이 지원하지 않는 CRRA 대응책 효과를 반환했습니다.")
        confidence = raw.get("confidence")
        if confidence not in {"HIGH", "MODERATE", "LOW"}:
            raise RuntimeError("LLM이 지원하지 않는 CRRA 효과 신뢰도를 반환했습니다.")
        reason = raw.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise RuntimeError("LLM의 CRRA 판단 근거 형식이 올바르지 않습니다.")
        reason = reason.strip()
        if "판단 정보 부족" in reason:
            raise RuntimeError("LLM이 필수 CRRA 결론과 구체적인 근거를 반환하지 않았습니다.")
        if len(reason) > 500:
            raise RuntimeError("LLM의 CRRA 판단 근거는 500자 이하여야 합니다.")
        missing = raw.get("missing_information", [])
        if missing not in (None, []):
            raise RuntimeError("LLM은 CRRA 일괄 검토에서 추가 확인 항목을 반환할 수 없습니다.")
        normalized.append({
            "item_id": mapping_id,
            "mapping_id": mapping_id,
            "status": status,
            "effect": effect,
            "confidence": confidence,
            "reason": reason,
            "missing_information": [],
        })
    if seen != expected:
        raise RuntimeError("LLM이 모든 CRRA 매핑 항목의 검토 초안을 반환하지 않았습니다.")
    by_id = {int(item["mapping_id"]): item for item in normalized}
    return [by_id[mapping_id] for mapping_id in expected_mapping_ids]


def partition_crra_mapping_suggestions_for_retry(
    value: object, expected_mapping_ids: list[int],
) -> tuple[list[dict[str, object]], list[int]]:
    """Keep valid rows in memory and identify only incomplete/invalid rows."""
    expected_order = list(expected_mapping_ids)
    expected = set(expected_order)
    if not isinstance(value, dict) or not isinstance(value.get("suggestions"), list):
        return [], expected_order
    grouped: dict[int, list[dict[str, object]]] = {
        mapping_id: [] for mapping_id in expected_order
    }
    for raw in value["suggestions"]:
        if not isinstance(raw, dict):
            return [], expected_order
        mapping_id = raw.get("item_id", raw.get("mapping_id"))
        if (
            isinstance(mapping_id, bool)
            or not isinstance(mapping_id, int)
            or mapping_id not in expected
        ):
            return [], expected_order
        grouped[mapping_id].append(raw)
    valid: list[dict[str, object]] = []
    unresolved: list[int] = []
    for mapping_id in expected_order:
        candidates = grouped[mapping_id]
        if len(candidates) != 1:
            unresolved.append(mapping_id)
            continue
        try:
            valid.extend(normalize_crra_mapping_suggestions(
                {"suggestions": candidates}, [mapping_id],
            ))
        except RuntimeError:
            unresolved.append(mapping_id)
    return valid, unresolved


def validate_crra_effect_uniqueness(
    suggestions: list[dict[str, object]], context_items: list[dict[str, object]],
) -> None:
    """Do not silently collapse distinct P/D/R rows for one AV-CM pair."""
    item_by_id = {
        item.get("item_id", item.get("mapping_id")): item
        for item in context_items
        if isinstance(item, dict) and isinstance(item.get("mapping_id"), int)
    }
    selected_ids = {
        int(item.get("item_id", item.get("mapping_id")))
        for item in context_items
        if isinstance(item, dict)
        and isinstance(item.get("item_id", item.get("mapping_id")), int)
    }
    seen: dict[tuple[str, str, str], int] = {}
    for suggestion in suggestions:
        mapping_id = suggestion.get("item_id", suggestion.get("mapping_id"))
        context = item_by_id.get(mapping_id)
        if not isinstance(context, dict):
            raise LLMCRRAResponseInvalid("CRRA 매핑 초안의 원본 평가 맥락을 찾을 수 없습니다.")
        key = (
            str(context.get("av_id", "")),
            str(context.get("cm_id", "")),
            str(suggestion.get("effect", "")),
        )
        prior = seen.get(key)
        if prior is not None:
            raise LLMCRRAResponseInvalid(
                f"LLM이 동일한 공격 벡터·대응책에 중복 효과를 제안했습니다 "
                f"(매핑 {prior}, {mapping_id}). 다시 요청해 주세요."
            )
        for peer in context.get("pair_effect_rows", []):
            if not isinstance(peer, dict):
                continue
            peer_id = peer.get("item_id")
            if (
                isinstance(peer_id, int)
                and peer_id not in selected_ids
                and str(peer.get("current_effect", "")) == key[2]
            ):
                raise LLMCRRAResponseInvalid(
                    f"LLM이 선택 범위 밖의 기존 매핑 {peer_id}와 중복되는 효과를 "
                    f"항목 {mapping_id}에 제안했습니다. 같은 AV-대응책 행을 함께 요청해 주세요."
                )
        seen[key] = int(mapping_id)


def reconcile_crra_effect_suggestions(
    suggestions: list[dict[str, object]], context_items: list[dict[str, object]],
) -> None:
    """Restore stored P/D/R effects when a response creates duplicates."""
    context_by_id: dict[int, dict[str, object]] = {}
    selected_ids: set[int] = set()
    for item in context_items:
        if not isinstance(item, dict):
            continue
        raw_id = item.get("item_id", item.get("mapping_id"))
        if isinstance(raw_id, bool) or not isinstance(raw_id, int):
            continue
        context_by_id[raw_id] = item
        selected_ids.add(raw_id)

    groups: dict[tuple[str, str], list[dict[str, object]]] = {}
    for suggestion in suggestions:
        raw_id = suggestion.get("item_id", suggestion.get("mapping_id"))
        context = context_by_id.get(int(raw_id)) if isinstance(raw_id, int) else None
        if not isinstance(context, dict):
            continue
        groups.setdefault(
            (str(context.get("av_id", "")), str(context.get("cm_id", ""))), []
        ).append(suggestion)

    for pair_suggestions in groups.values():
        proposed = [str(item.get("effect", "")) for item in pair_suggestions]
        first_id = pair_suggestions[0].get("item_id", pair_suggestions[0].get("mapping_id"))
        first_context = context_by_id.get(int(first_id)) if isinstance(first_id, int) else None
        outside_effects = {
            str(peer.get("current_effect", ""))
            for peer in (first_context or {}).get("pair_effect_rows", [])
            if isinstance(peer, dict)
            and isinstance(peer.get("item_id"), int)
            and int(peer["item_id"]) not in selected_ids
        }
        if len(proposed) == len(set(proposed)) and not (set(proposed) & outside_effects):
            continue
        for suggestion in pair_suggestions:
            raw_id = suggestion.get("item_id", suggestion.get("mapping_id"))
            context = context_by_id.get(int(raw_id)) if isinstance(raw_id, int) else None
            current_effect = str((context or {}).get("current_effect", ""))
            original_effect = str(suggestion.get("effect", ""))
            if current_effect not in {"PREVENT", "DETECT", "RESPOND"}:
                raise LLMCRRAResponseInvalid(
                    "CRRA 매핑의 기존 P/D/R 효과를 확인할 수 없습니다."
                )
            if original_effect == current_effect:
                continue
            note = (
                f"[도구 보정: 복수 효과 중복을 피하기 위해 기존 KM 행의 "
                f"{current_effect} 분류를 유지함.]"
            )
            reason = str(suggestion.get("reason", "")).strip()
            max_reason = max(0, 500 - len(note) - 1)
            suggestion["reason"] = f"{reason[:max_reason]} {note}".strip()
            suggestion["proposed_effect"] = original_effect
            suggestion["effect"] = current_effect
            suggestion["effect_adjusted"] = True


def plan_llm_crra_mapping_batch(context: object) -> dict[str, object]:
    """Preflight and split a CRRA-wide request into bounded provider calls."""
    if not isinstance(context, dict):
        raise RuntimeError("LLM 추천에 필요한 CRRA 일괄 평가 맥락 형식이 올바르지 않습니다.")
    items = context.get("mapping_items")
    if not isinstance(items, list) or not items:
        raise RuntimeError("LLM 초안을 만들 CRRA 대응책 매핑이 없습니다.")
    mapping_ids: list[int] = []
    for item in items:
        mapping_id = (
            item.get("item_id", item.get("mapping_id")) if isinstance(item, dict) else None
        )
        if isinstance(mapping_id, bool) or not isinstance(mapping_id, int) or mapping_id <= 0:
            raise RuntimeError("LLM CRRA 매핑 항목 ID 형식이 올바르지 않습니다.")
        mapping_ids.append(mapping_id)
    if len(mapping_ids) != len(set(mapping_ids)):
        raise RuntimeError("LLM CRRA 매핑 항목 ID가 중복되었습니다.")

    item_count = len(items)
    # Keep all P/D/R rows for an AV-CM pair in one request.
    groups: dict[tuple[str, str], list[dict[str, object]]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise RuntimeError("LLM CRRA 매핑 항목 형식이 올바르지 않습니다.")
        av_id = item.get("av_id")
        cm_id = item.get("cm_id")
        if not isinstance(av_id, str) or not av_id or not isinstance(cm_id, str) or not cm_id:
            raise RuntimeError("LLM CRRA 매핑의 공격 벡터 또는 대응책 ID가 없습니다.")
        groups.setdefault((av_id, cm_id), []).append(item)
    grouped_chunks: list[list[dict[str, object]]] = []
    pending: list[dict[str, object]] = []
    for group in groups.values():
        if pending and len(pending) + len(group) > LLM_CRRA_BATCH_ITEMS_PER_CHUNK:
            grouped_chunks.append(pending)
            pending = []
        pending.extend(group)
        if len(pending) >= LLM_CRRA_BATCH_ITEMS_PER_CHUNK:
            grouped_chunks.append(pending)
            pending = []
    if pending:
        grouped_chunks.append(pending)
    provider_calls = len(grouped_chunks)
    limits = {
        "max_items": LLM_CRRA_BATCH_MAX_ITEMS,
        "max_initial_provider_calls": LLM_CRRA_BATCH_MAX_INITIAL_PROVIDER_CALLS,
        "max_provider_calls": LLM_CRRA_BATCH_MAX_PROVIDER_CALLS,
        "max_chunk_input_bytes": LLM_CRRA_BATCH_MAX_CHUNK_INPUT_BYTES,
        "max_total_input_bytes": LLM_CRRA_BATCH_MAX_TOTAL_INPUT_BYTES,
        "max_completion_tokens_per_call": LLM_CRRA_BATCH_MAX_COMPLETION_TOKENS,
    }
    actual: dict[str, int | None] = {
        "items": item_count,
        "provider_calls": provider_calls,
        "largest_chunk_input_bytes": None,
        "total_input_bytes": None,
    }
    violations: list[str] = []
    if item_count > LLM_CRRA_BATCH_MAX_ITEMS:
        violations.append("MAX_ITEMS")
    if provider_calls > LLM_CRRA_BATCH_MAX_INITIAL_PROVIDER_CALLS:
        violations.append("MAX_INITIAL_PROVIDER_CALLS")
    if violations:
        raise LLMCRRABatchTooLarge(
            "이 평가의 CRRA 매핑 수가 동기식 LLM 일괄 추천 지원 한도를 초과합니다. "
            "일부 매핑을 선택해 요청하거나 수동으로 검토해 주세요.",
            {"actual": actual, "limits": limits, "violations": violations, "retryable": False},
        )

    shared_context = {key: value for key, value in context.items() if key != "mapping_items"}
    plans: list[dict[str, object]] = []
    total_input_bytes = 0
    largest_chunk_input_bytes = 0
    for chunk in grouped_chunks:
        payload = {**shared_context, "mapping_items": chunk}
        user_content = json.dumps(payload, ensure_ascii=False)
        input_bytes = len(json.dumps(
            {
                "messages": [
                    {"role": "system", "content": LLM_CRRA_BATCH_PROMPT},
                    {"role": "user", "content": user_content},
                ]
            },
            ensure_ascii=False,
        ).encode("utf-8"))
        total_input_bytes += input_bytes
        largest_chunk_input_bytes = max(largest_chunk_input_bytes, input_bytes)
        plans.append({
            "items": chunk,
            "expected_mapping_ids": [
                int(item.get("item_id", item.get("mapping_id"))) for item in chunk
            ],
            "payload": payload,
            "input_bytes": input_bytes,
            "max_completion_tokens": min(
                LLM_CRRA_BATCH_MAX_COMPLETION_TOKENS,
                max(
                    LLM_CRRA_BATCH_MIN_COMPLETION_TOKENS,
                    LLM_CRRA_BATCH_COMPLETION_BASE_TOKENS
                    + len(chunk) * LLM_CRRA_BATCH_COMPLETION_TOKENS_PER_ITEM,
                ),
            ),
        })
    actual["largest_chunk_input_bytes"] = largest_chunk_input_bytes
    actual["total_input_bytes"] = total_input_bytes
    if largest_chunk_input_bytes > LLM_CRRA_BATCH_MAX_CHUNK_INPUT_BYTES:
        violations.append("MAX_CHUNK_INPUT_BYTES")
    if total_input_bytes > LLM_CRRA_BATCH_MAX_TOTAL_INPUT_BYTES:
        violations.append("MAX_TOTAL_INPUT_BYTES")
    if violations:
        raise LLMCRRABatchTooLarge(
            "이 평가의 CRRA LLM 입력 맥락이 일괄 추천 지원 한도를 초과합니다. "
            "긴 Scope 설명을 줄이거나 일부 매핑을 선택해 요청해 주세요.",
            {"actual": actual, "limits": limits, "violations": violations, "retryable": False},
        )
    return {"chunks": plans, "metrics": actual, "limits": limits}


def _required_text(value: object, field: str, max_length: int = 256) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} 값을 문자열로 입력해 주세요.")
    text = value.strip()
    if not text:
        raise ValueError(f"{field} 값을 입력해 주세요.")
    if len(text) > max_length:
        raise ValueError(f"{field} 값이 너무 깁니다.")
    return text


def _optional_text(value: object, field: str, max_length: int = 10_000) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{field} 값을 문자열로 입력해 주세요.")
    text = value.strip()
    if len(text) > max_length:
        raise ValueError(f"{field} 값이 너무 깁니다.")
    return text


def _object_rows(value: object, field: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"{field} 값은 JSON 객체 목록이어야 합니다.")
    return value


def _attack_vector_ids(value: object) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("attack_vector_ids 값은 목록이어야 합니다.")
    clean: list[str] = []
    for item in value:
        clean.append(_required_text(item, "attack_vector_id", 128))
    if len(set(clean)) != len(clean):
        raise ValueError("attack_vector_ids에 중복된 값이 있습니다.")
    return clean


def _context_allows_external_llm(context: object) -> dict[str, object]:
    if not isinstance(context, dict):
        raise RuntimeError("LLM 추천에 필요한 CRRA 평가 맥락 형식이 올바르지 않습니다.")
    assessment = context.get("assessment")
    nested = assessment if isinstance(assessment, dict) else {}
    candidates = [
        context.get("external_llm_allowed"),
        context.get("llm_allowed"),
        context.get("llm_enabled"),
        nested.get("external_llm_allowed"),
        nested.get("llm_allowed"),
        nested.get("llm_enabled"),
    ]
    declared = next((item for item in candidates if item is not None), None)
    allowed = declared is True or (
        isinstance(declared, int) and not isinstance(declared, bool) and declared == 1
    )
    if not allowed:
        raise ValueError("이 평가에서는 외부 LLM 추천 사용을 허용하지 않았습니다.")
    return context


COUNTERMEASURE_MAPPING_PROMPT = """당신은 TARA 대응책 매핑 검토 보조자다. 제공된 공격 벡터, 대응책과 근거만 사용한다.
반드시 JSON 객체만 반환한다. 형식: {"effect":"PREVENT|DETECT|RESPOND","confidence":"HIGH|MODERATE|LOW","rationale":"한국어 판단 근거","missing_information":["부족 정보"]}.
effect와 confidence는 제시된 값 중 하나만 사용한다. 근거가 부족하면 missing_information에 명시하고 사실을 추측하지 않는다.
이 결과는 사용자가 검토할 추천안일 뿐이며, 최종 효과·신뢰도·판단 근거를 확정하지 않는다."""


DB = CNTaraDB(DB_PATH, max_storage_bytes=MAX_DB_BYTES)
LLM_SESSIONS = LLMSessionStore(cleanup_interval_seconds=60)
LEGACY_CLAIM_LOCK = RLock()
ASSESSMENT_CREATE_LOCK = RLock()
DATABASE_CAPACITY_LOCK = RLock()
PENDING_DATABASE_BYTES = 0
LEGACY_CLAIM_CODE: str | None = (
    secrets.token_urlsafe(18) if DB.legacy_assessment_count() > 0 else None
)


class BrowserSessionExpired(RuntimeError):
    code = "BROWSER_SESSION_EXPIRED"


class AssessmentCapacityExceeded(RuntimeError):
    code = "ASSESSMENT_CAPACITY_REACHED"


class DatabaseCapacityExceeded(RuntimeError):
    code = "DATABASE_CAPACITY_REACHED"


def _database_storage_bytes() -> int:
    """Count SQLite's durable files without exposing their paths to clients."""
    raw_path = getattr(DB, "path", None)
    if not isinstance(raw_path, str) or not raw_path or raw_path == ":memory:":
        return 0
    path = Path(raw_path)
    total = 0
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-journal"), Path(f"{path}-shm")):
        try:
            total += candidate.stat().st_size
        except FileNotFoundError:
            continue
        except OSError:
            # Block writes when DB file size cannot be checked.
            return MAX_DB_BYTES
    return total


def _database_main_file_bytes() -> int:
    raw_path = getattr(DB, "path", None)
    if not isinstance(raw_path, str) or not raw_path or raw_path == ":memory:":
        return 0
    try:
        return Path(raw_path).stat().st_size
    except FileNotFoundError:
        return 0
    except OSError:
        return MAX_DB_BYTES


def _legacy_claim_available() -> bool:
    with LEGACY_CLAIM_LOCK:
        return LEGACY_CLAIM_CODE is not None and DB.legacy_assessment_count() > 0


def _llm_provenance(session_key: str) -> dict[str, object]:
    status = LLM_SESSIONS.status(session_key)
    return {
        "provider": status.get("provider"),
        "model": status.get("model"),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


class APIHandler(BaseHTTPRequestHandler):
    server_version = "CloudTARA/0.1"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stdout.write(f"[{self.log_date_time_string()}] {fmt % args}\n")

    def _session_token(self) -> str:
        cached = getattr(self, "_cntara_session_token", None)
        if isinstance(cached, str):
            return cached
        token = ""
        raw_cookie = self.headers.get("Cookie", "")
        if 0 < len(raw_cookie) <= 4096:
            try:
                cookies = SimpleCookie()
                cookies.load(raw_cookie)
                morsel = cookies.get(SESSION_COOKIE_NAME)
                candidate = morsel.value if morsel is not None else ""
                if _SESSION_TOKEN_PATTERN.fullmatch(candidate):
                    token = candidate
            except CookieError:
                token = ""
        self._cntara_session_cookie_supplied = bool(token)
        if not token:
            token = secrets.token_urlsafe(32)
        self._cntara_session_token = token
        return token

    @property
    def owner_id(self) -> str:
        """Return a stable owner after enforcing the server-side idle lifetime."""
        cached = getattr(self, "_cntara_owner_id", None)
        if isinstance(cached, str):
            return cached
        owner_id = hashlib.sha256(self._session_token().encode("ascii")).hexdigest()
        touch = getattr(DB, "touch_browser_session", None)
        count = getattr(DB, "assessment_count", None)
        if callable(touch):
            session = touch(
                owner_id,
                ttl_seconds=SESSION_COOKIE_MAX_AGE_SECONDS,
                create_if_missing=False,
            )
            status = session.get("status") if isinstance(session, dict) else None
            if status == "expired":
                LLM_SESSIONS.clear(owner_id)
                self._cntara_session_token = secrets.token_urlsafe(32)
                self._cntara_owner_id = hashlib.sha256(
                    self._cntara_session_token.encode("ascii")
                ).hexdigest()
                raise BrowserSessionExpired(
                    "이 브라우저의 평가 세션이 30일 동안 사용되지 않아 만료되었습니다. "
                    "새 개인 세션에서 평가를 시작해 주세요."
                )
            if status == "missing" and callable(count) and count(owner_id=owner_id) > 0:
                # Register sessions created before server-side expiry support.
                session = touch(
                    owner_id,
                    ttl_seconds=SESSION_COOKIE_MAX_AGE_SECONDS,
                    create_if_missing=True,
                )
                if isinstance(session, dict) and session.get("status") == "expired":
                    LLM_SESSIONS.clear(owner_id)
                    self._cntara_session_token = secrets.token_urlsafe(32)
                    self._cntara_owner_id = hashlib.sha256(
                        self._cntara_session_token.encode("ascii")
                    ).hexdigest()
                    raise BrowserSessionExpired(
                        "이 브라우저의 평가 세션이 30일 동안 사용되지 않아 만료되었습니다. "
                        "새 개인 세션에서 평가를 시작해 주세요."
                    )
        self._cntara_owner_id = owner_id
        return owner_id

    def _register_current_browser_session(self) -> None:
        """Persist a session only once it owns evaluation data."""
        owner_id = self.owner_id
        touch = getattr(DB, "touch_browser_session", None)
        if not callable(touch):
            return
        session = touch(
            owner_id,
            ttl_seconds=SESSION_COOKIE_MAX_AGE_SECONDS,
            create_if_missing=True,
        )
        if isinstance(session, dict) and session.get("status") == "expired":
            LLM_SESSIONS.clear(owner_id)
            self._cntara_session_token = secrets.token_urlsafe(32)
            self._cntara_owner_id = hashlib.sha256(
                self._cntara_session_token.encode("ascii")
            ).hexdigest()
            raise BrowserSessionExpired(
                "이 브라우저의 평가 세션이 30일 동안 사용되지 않아 만료되었습니다. "
                "새 개인 세션에서 평가를 시작해 주세요."
            )

    def _owner_id(self) -> str:
        """Compatibility helper for route code that prefers a method call."""
        return self.owner_id

    @staticmethod
    def _require_km_admin(path: str) -> None:
        if not KM_ADMIN_ENABLED and any(pattern.fullmatch(path) for pattern in _KM_MUTATION_PATTERNS):
            raise PermissionError(
                "공개 모드에서는 공용 KM 데이터 변경이 비활성화되어 있습니다. "
                "관리자는 CNTARA_KM_ADMIN_ENABLED=true로 서버를 시작해 주세요."
            )

    @staticmethod
    def _post_writes_database(path: str) -> bool:
        if path == "/api/session/claim-legacy":
            return True
        if any(pattern.fullmatch(path) for pattern in _KM_MUTATION_PATTERNS):
            return True
        if path == "/api/assessments":
            return True
        if re.fullmatch(r"/api/assessments/\d+/crra/llm/mappings?", path):
            return False
        if re.fullmatch(r"/api/assessments/\d+/.+", path):
            return True
        return bool(re.fullmatch(r"/api/(?:carts|cart-items)/\d+/.+", path))

    def _require_database_capacity(self, minimum_reservation: int = 0) -> None:
        try:
            incoming = max(0, int(self.headers.get("Content-Length", "0")))
        except ValueError:
            incoming = 0
        # Reserve space for server-generated rows.
        reservation = max(incoming, int(minimum_reservation or 0), 64 * 1024)
        current_reservation = int(
            getattr(self, "_cntara_reserved_database_bytes", 0) or 0
        )
        if current_reservation >= reservation:
            return
        additional_reservation = reservation - current_reservation
        global PENDING_DATABASE_BYTES
        with DATABASE_CAPACITY_LOCK:
            current = _database_storage_bytes()
            safe_main_bytes = max(
                0, (MAX_DB_BYTES - SQLITE_STORAGE_SIDECAR_RESERVE_BYTES) // 2,
            )
            if (
                current >= MAX_DB_BYTES
                or _database_main_file_bytes() > safe_main_bytes
                or current + PENDING_DATABASE_BYTES + additional_reservation > MAX_DB_BYTES
            ):
                raise DatabaseCapacityExceeded(
                    "서버의 CloudTARA 데이터 저장 한도에 도달했습니다. 운영자가 DB를 백업·정리하거나 "
                    "CNTARA_MAX_DB_BYTES 값을 조정해야 합니다."
                )
            PENDING_DATABASE_BYTES += additional_reservation
            self._cntara_reserved_database_bytes = reservation

    def _release_database_capacity(self) -> None:
        reservation = int(getattr(self, "_cntara_reserved_database_bytes", 0) or 0)
        if not reservation:
            return
        global PENDING_DATABASE_BYTES
        with DATABASE_CAPACITY_LOCK:
            PENDING_DATABASE_BYTES = max(0, PENDING_DATABASE_BYTES - reservation)
        self._cntara_reserved_database_bytes = 0

    @staticmethod
    def _require_assessment_capacity(owner_id: str) -> None:
        count = getattr(DB, "assessment_count", None)
        if not callable(count):
            return
        if count(owner_id=owner_id) >= MAX_ASSESSMENTS_PER_SESSION:
            raise AssessmentCapacityExceeded(
                f"현재 브라우저는 평가를 최대 {MAX_ASSESSMENTS_PER_SESSION}개까지 만들 수 있습니다."
            )
        if count() >= MAX_ASSESSMENTS_TOTAL:
            raise AssessmentCapacityExceeded(
                f"서버의 전체 평가 한도({MAX_ASSESSMENTS_TOTAL}개)에 도달했습니다. "
                "운영자가 기존 데이터를 백업·정리해야 합니다."
            )

    def _externally_secure(self) -> bool:
        forwarded_proto = self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
        if forwarded_proto == "https":
            return True
        forwarded = self.headers.get("Forwarded", "")
        return bool(re.search(r"(?:^|;)\s*proto=https(?:;|$)", forwarded, flags=re.IGNORECASE))

    def _send_session_cookie(self) -> None:
        token = self._session_token()
        expires = datetime.now(timezone.utc) + timedelta(seconds=SESSION_COOKIE_MAX_AGE_SECONDS)
        parts = [
            f"{SESSION_COOKIE_NAME}={token}",
            "Path=/",
            f"Max-Age={SESSION_COOKIE_MAX_AGE_SECONDS}",
            f"Expires={expires.strftime('%a, %d %b %Y %H:%M:%S GMT')}",
            "HttpOnly",
            "SameSite=Strict",
        ]
        if self._externally_secure():
            parts.append("Secure")
        self.send_header("Set-Cookie", "; ".join(parts))

    def _send_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
            "script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; form-action 'self'",
        )
        if self._externally_secure():
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def _json(self, data: object, status: int = 200) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self._send_security_headers()
        self._send_session_cookie()
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, message: str, status: int = 400, *, code: str | None = None) -> None:
        payload: dict[str, object] = {"error": message}
        if code:
            payload["code"] = code
        self._json(payload, status)

    def _sqlite_error(self, exc: sqlite3.OperationalError) -> None:
        if "full" in str(exc).lower():
            self._error(
                "서버의 CloudTARA 데이터 저장 한도에 도달했습니다. 운영자가 DB를 정리해야 합니다.",
                HTTPStatus.INSUFFICIENT_STORAGE,
                code=DatabaseCapacityExceeded.code,
            )
            return
        self.log_error("SQLite operational error: %r", exc)
        self._error("데이터베이스 요청을 처리하는 중 오류가 발생했습니다.", 500)

    def _body(self, max_length: int = 2_000_000) -> dict[str, object]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("요청 크기가 올바르지 않습니다.") from exc
        if length < 0 or length > max_length:
            raise ValueError("요청 데이터가 너무 큽니다.")
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type은 application/json이어야 합니다.")
        origin = self.headers.get("Origin")
        if origin:
            parsed_origin = urlparse(origin)
            request_host = self.headers.get("Host", "").lower()
            if parsed_origin.scheme not in {"http", "https"} or parsed_origin.netloc.lower() != request_host:
                raise ValueError("다른 출처에서는 CloudTARA 데이터를 변경할 수 없습니다.")
        if not length:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("JSON 요청 형식을 확인해 주세요.") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON 객체 형식으로 요청해 주세요.")
        return data

    def _serve_static(self, path: str) -> None:
        relative = "index.html" if path in {"/", ""} else path.removeprefix("/static/")
        if path not in {"/", ""} and not path.startswith("/static/"):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        target = (STATIC_DIR / relative).resolve()
        if STATIC_DIR.resolve() not in target.parents and target != STATIC_DIR.resolve():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content = target.read_bytes()
        mime = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", f"{mime}; charset=utf-8" if mime.startswith("text/") or mime == "application/javascript" else mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self._send_security_headers()
        if path in {"/", ""}:
            self._send_session_cookie()
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if not path.startswith("/api/"):
            self._serve_static(path)
            return
        try:
            owner_id = self.owner_id
            if path == "/api/health":
                self._json({"status": "ok", "name": "CloudTARA"})
            elif path == "/api/bootstrap":
                bootstrap = DB.bootstrap()
                if not isinstance(bootstrap, dict):
                    raise RuntimeError("초기 설정 데이터 형식이 올바르지 않습니다.")
                self._json({
                    **bootstrap,
                    "km_admin_enabled": KM_ADMIN_ENABLED,
                    "legacy_claim_available": _legacy_claim_available(),
                })
            elif path == "/api/km":
                self._json(DB.km_workspace())
            elif path == "/api/assessments":
                self._json(DB.list_assessments(owner_id=owner_id))
            elif path == "/api/llm/status":
                self._json(LLM_SESSIONS.status(self.owner_id))
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra", path):
                self._json(DB.crra_workspace(int(match.group(1)), owner_id=owner_id))
            elif match := re.fullmatch(r"/api/assessments/(\d+)/workspace", path):
                self._json(DB.workspace(int(match.group(1)), owner_id=owner_id))
            elif path == "/api/catalog/attack-vectors":
                params = parse_qs(parsed.query)
                assessment_id = int(params.get("assessment_id", ["0"])[0])
                query = params.get("q", [""])[0]
                self._json(DB.catalog_search(assessment_id, query, owner_id=owner_id))
            else:
                self._error("API 경로를 찾을 수 없습니다.", 404)
        except BrowserSessionExpired as exc:
            self._error(str(exc), HTTPStatus.UNAUTHORIZED, code=exc.code)
        except LLMSessionConfigurationSuperseded as exc:
            self._error(str(exc), 409, code=exc.code)
        except LLMSessionRateLimited as exc:
            self._error(str(exc), 429, code=exc.code)
        except LLMSessionUnavailable as exc:
            self._error(str(exc), 409, code=exc.code)
        except LookupError as exc:
            self._error(str(exc), 404)
        except sqlite3.OperationalError as exc:
            self._sqlite_error(exc)
        except (ValueError, RuntimeError) as exc:
            self._error(str(exc), 400)
        except Exception as exc:  # pragma: no cover
            self.log_error("Unhandled GET error: %r", exc)
            self._error("요청을 처리하는 중 오류가 발생했습니다.", 500)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            session_key = self.owner_id
            owner_id = session_key
            # Allow JSON escaping overhead; the collector enforces decoded limits.
            manifest_preview = bool(
                re.fullmatch(r"/api/assessments/\d+/manifest/preview", path)
            )
            body = self._body(4_000_000 if manifest_preview else 2_000_000)
            self._require_km_admin(path)
            if self._post_writes_database(path):
                self._require_database_capacity()
            if path == "/api/llm/config":
                if body.get("clear") is not True and body.get("verify") is not True:
                    raise ValueError("공개 브라우저의 LLM 연결은 verify=true로 확인해야 합니다.")
                self._json(LLM_SESSIONS.configure(session_key, body))
            elif path == "/api/session/claim-legacy":
                if not bool(getattr(self, "_cntara_session_cookie_supplied", False)):
                    self._error(
                        "기존 평가를 안전하게 받을 브라우저 세션이 아직 없습니다. "
                        "페이지를 새로고침한 뒤 다시 시도해 주세요.",
                        409,
                        code="LEGACY_CLAIM_SESSION_REQUIRED",
                    )
                    return
                submitted = body.get("code")
                if not isinstance(submitted, str) or not submitted.strip():
                    self._error("기존 평가 가져오기 코드를 입력해 주세요.", 400, code="LEGACY_CLAIM_CODE_REQUIRED")
                    return
                global LEGACY_CLAIM_CODE
                with LEGACY_CLAIM_LOCK:
                    expected = LEGACY_CLAIM_CODE
                    if expected is None or not secrets.compare_digest(submitted.strip(), expected):
                        self._error("기존 평가 가져오기 코드가 올바르지 않습니다.", 403, code="LEGACY_CLAIM_DENIED")
                        return
                    self._register_current_browser_session()
                    claimed_count = DB.claim_legacy_assessments(owner_id)
                    LEGACY_CLAIM_CODE = None
                self._json({"claimed_count": claimed_count})
            elif path == "/api/km/attack-vectors":
                self._json(DB.save_km_attack_vector(body), 201)
            elif path == "/api/km/countermeasures":
                self._json(DB.save_km_countermeasure(body), 201)
            elif path == "/api/km/asset-mappings":
                self._json(DB.save_km_asset_mapping({
                    "asset_type_id": _required_text(body.get("asset_type_id"), "asset_type_id", 128),
                    "attack_vector_id": _required_text(
                        body.get("attack_vector_id"), "attack_vector_id", 128,
                    ),
                    "mapping_note": _optional_text(body.get("mapping_note"), "mapping_note", 10_000),
                }), 201)
            elif path == "/api/km/mappings":
                self._json(DB.save_km_mapping(body), 201)
            elif path == "/api/km/vector-groups":
                self._json(DB.save_vector_group(body), 201)
            elif match := re.fullmatch(r"/api/km/vector-groups/(\d+)/members", path):
                result = DB.set_vector_group_members(
                    int(match.group(1)), _attack_vector_ids(body.get("attack_vector_ids")),
                )
                self._json({"ok": True} if result is None else result)
            elif path == "/api/km/mappings/import":
                self._json(DB.import_km_mappings(_object_rows(body.get("rows"), "rows")))
            elif path == "/api/km/llm/mapping":
                attack_vector_id = _required_text(body.get("attack_vector_id"), "attack_vector_id", 128)
                countermeasure_id = _required_text(body.get("countermeasure_id"), "countermeasure_id", 128)
                context = DB.km_mapping_context(attack_vector_id, countermeasure_id)
                if not isinstance(context, dict):
                    raise RuntimeError("LLM 추천에 필요한 KM 매핑 맥락 형식이 올바르지 않습니다.")
                suggestion = normalize_countermeasure_mapping_suggestion(
                    LLM_SESSIONS.complete_json(session_key, COUNTERMEASURE_MAPPING_PROMPT, context),
                )
                suggestion["_llm"] = _llm_provenance(session_key)
                self._json(suggestion)
            elif path == "/api/assessments":
                with ASSESSMENT_CREATE_LOCK:
                    self._require_assessment_capacity(owner_id)
                    try:
                        created = DB.create_assessment(
                            body,
                            owner_id=owner_id,
                            max_per_owner=MAX_ASSESSMENTS_PER_SESSION,
                            max_total=MAX_ASSESSMENTS_TOTAL,
                        )
                    except AssessmentLimitError as exc:
                        if exc.scope == "per-owner":
                            message = (
                                f"현재 브라우저는 평가를 최대 {exc.limit}개까지 만들 수 있습니다."
                            )
                        else:
                            message = (
                                f"서버의 전체 평가 한도({exc.limit}개)에 도달했습니다. "
                                "운영자가 기존 데이터를 백업·정리해야 합니다."
                            )
                        raise AssessmentCapacityExceeded(message) from exc
                    self._register_current_browser_session()
                self._json(created, 201)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/duplicate", path):
                with ASSESSMENT_CREATE_LOCK:
                    self._require_assessment_capacity(owner_id)
                    try:
                        duplicated = DB.duplicate_assessment(
                            int(match.group(1)),
                            owner_id=owner_id,
                            name=body.get("name"),
                            max_per_owner=MAX_ASSESSMENTS_PER_SESSION,
                            max_total=MAX_ASSESSMENTS_TOTAL,
                        )
                    except AssessmentLimitError as exc:
                        if exc.scope == "per-owner":
                            message = (
                                f"현재 브라우저는 평가를 최대 {exc.limit}개까지 만들 수 있습니다."
                            )
                        else:
                            message = (
                                f"서버의 전체 평가 한도({exc.limit}개)에 도달했습니다. "
                                "운영자가 기존 데이터를 백업·정리해야 합니다."
                            )
                        raise AssessmentCapacityExceeded(message) from exc
                    self._register_current_browser_session()
                self._json(duplicated, 201)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/manifest/preview", path):
                assessment_id = int(match.group(1))
                # Verify ownership before parsing.
                assessment = DB.get_assessment(assessment_id, owner_id=owner_id)
                # Inject the release-scoped catalog used by the collector.
                requested_level = body.get("dfd_level", 0)
                if isinstance(requested_level, bool) or not isinstance(requested_level, int) or requested_level not in {0, 1}:
                    raise ValueError("DFD 구성 수준은 기본(0) 또는 상세(1)만 선택할 수 있습니다.")
                dfd_level = requested_level
                projection_mode = body.get("projection_mode", "platform")
                if not isinstance(projection_mode, str) or projection_mode not in {"platform", "logical"}:
                    raise ValueError("Manifest DFD 투영 방식은 platform 또는 logical이어야 합니다.")
                element_templates = DB.list_dfd_element_templates(
                    int(assessment["km_release_id"]),
                    level=dfd_level,
                )
                flow_templates = DB.list_dfd_flow_templates(
                    int(assessment["km_release_id"]),
                    level=dfd_level,
                )
                proposal = build_manifest_proposal(
                    body.get("files"),
                    element_templates=element_templates,
                    flow_templates=flow_templates,
                    dfd_level=dfd_level,
                    strict_catalog=True,
                    projection_mode=projection_mode,
                )
                # Reserve storage using the redacted proposal size.
                proposal_bytes = len(
                    json.dumps(proposal, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                )
                self._require_database_capacity(proposal_bytes * 2 + 64 * 1024)
                run = DB.create_collection_run(
                    assessment_id,
                    source_type="MANIFEST",
                    source_digest=str(proposal.get("source_digest", "")),
                    mapper_version=str(proposal.get("mapper_version", "")),
                    summary=proposal.get("summary", {}),
                    warnings=proposal.get("warnings", []),
                    proposal=proposal,
                    owner_id=owner_id,
                )
                self._json({**proposal, "run_id": run["id"], "status": run["status"]}, 201)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra/initialize", path):
                result = DB.initialize_crra(int(match.group(1)), owner_id=owner_id)
                self._json({"ok": True} if result is None else result)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra/vectors", path):
                result = DB.save_crra_vector_selection(int(match.group(1)), body, owner_id=owner_id)
                self._json({"ok": True} if result is None else result)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra/mappings/generate", path):
                result = DB.generate_crra_mappings(int(match.group(1)), owner_id=owner_id)
                self._json({"ok": True} if result is None else result)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra/mappings/complete", path):
                result = DB.complete_crra_mapping_review(int(match.group(1)), owner_id=owner_id)
                self._json({"ok": True} if result is None else result)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra/mappings", path):
                self._json(DB.add_crra_mapping(int(match.group(1)), body, owner_id=owner_id), 201)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra/score", path):
                result = DB.score_crra(int(match.group(1)), body, owner_id=owner_id)
                self._json({"ok": True} if result is None else result)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra/solution/confirm", path):
                result = DB.confirm_crra_solution(
                    int(match.group(1)), _optional_text(body.get("gap_reason"), "gap_reason"), owner_id=owner_id,
                )
                self._json({"ok": True} if result is None else result)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra/solution", path):
                result = DB.generate_crra_solution(int(match.group(1)), body, owner_id=owner_id)
                self._json({"ok": True} if result is None else result)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra/llm/mappings", path):
                assessment_id = int(match.group(1))
                mapping_ids = body.get("mapping_ids") if "mapping_ids" in body else None
                context = _context_allows_external_llm(DB.crra_mapping_batch_context(
                    assessment_id, mapping_ids=mapping_ids, owner_id=owner_id,
                ))
                batch_plan = plan_llm_crra_mapping_batch(context)
                suggestions: list[dict[str, object]] = []
                provider_calls = 0

                def retry_crra_plan(
                    retry_items: list[dict[str, object]], reason: str,
                ) -> dict[str, object]:
                    required_ids = [
                        int(item.get("item_id", item.get("mapping_id")))
                        for item in retry_items
                    ]
                    child_context = {
                        **context,
                        "mapping_items": retry_items,
                        "response_correction": {
                            "reason": reason,
                            "required_item_ids": required_ids,
                            "instruction": (
                                "이 item_id를 빠짐없이 각각 한 번만 반환하고, "
                                "같은 AV-대응책 쌍의 effect가 중복되지 않게 하세요."
                            ),
                        },
                    }
                    plans = plan_llm_crra_mapping_batch(child_context)["chunks"]
                    if not isinstance(plans, list) or len(plans) != 1:
                        raise LLMCRRAResponseInvalid(
                            "LLM CRRA 검토 재요청 계획을 만들 수 없습니다."
                        )
                    return plans[0]

                def complete_crra_chunk(
                    chunk_plan: dict[str, object], *, allow_terminal_retry: bool = True,
                ) -> list[dict[str, object]]:
                    nonlocal provider_calls
                    if provider_calls >= LLM_CRRA_BATCH_MAX_PROVIDER_CALLS:
                        raise LLMCRRABatchExecutionLimit(
                            "LLM CRRA 응답을 안전하게 보정할 수 있는 최대 호출 횟수에 "
                            "도달했습니다. 잠시 후 다시 요청하거나 수동으로 검토해 주세요."
                        )
                    count_toward_rate_limit = provider_calls == 0
                    provider_calls += 1
                    try:
                        response = LLM_SESSIONS.complete_json(
                            session_key,
                            LLM_CRRA_BATCH_PROMPT,
                            chunk_plan["payload"],
                            max_completion_tokens=chunk_plan["max_completion_tokens"],
                            count_toward_rate_limit=count_toward_rate_limit,
                        )
                    except (LLMCompletionTruncated, LLMResponseFormatError):
                        response = None

                    expected_ids = chunk_plan.get("expected_mapping_ids")
                    chunk_items = chunk_plan.get("items")
                    if (
                        not isinstance(expected_ids, list)
                        or any(
                            isinstance(item_id, bool) or not isinstance(item_id, int)
                            for item_id in expected_ids
                        )
                        or not isinstance(chunk_items, list)
                    ):
                        raise LLMCRRAResponseInvalid(
                            "LLM CRRA 검토 청크 계획 형식이 올바르지 않습니다."
                        )
                    valid, unresolved_ids = partition_crra_mapping_suggestions_for_retry(
                        response, expected_ids,
                    )
                    if not unresolved_ids:
                        return valid
                    # Retry the complete AV-CM pair when one P/D/R row is invalid.
                    item_pair_by_id = {
                        int(item.get("item_id", item.get("mapping_id"))): (
                            str(item.get("av_id", "")), str(item.get("cm_id", ""))
                        )
                        for item in chunk_items if isinstance(item, dict)
                    }
                    unresolved_pairs = {
                        item_pair_by_id[item_id] for item_id in unresolved_ids
                        if item_id in item_pair_by_id
                    }
                    unresolved = {
                        item_id for item_id, pair in item_pair_by_id.items()
                        if pair in unresolved_pairs
                    }
                    valid = [
                        item for item in valid if int(item["item_id"]) not in unresolved
                    ]
                    retry_items = [
                        item for item in chunk_items
                        if isinstance(item, dict)
                        and item.get("item_id", item.get("mapping_id")) in unresolved
                    ]
                    if len(retry_items) != len(unresolved):
                        raise LLMCRRAResponseInvalid(
                            "LLM CRRA 검토에서 누락된 항목의 재요청 맥락을 찾을 수 없습니다."
                        )
                    pair_groups: dict[tuple[str, str], list[dict[str, object]]] = {}
                    for item in retry_items:
                        pair_groups.setdefault(
                            (str(item.get("av_id", "")), str(item.get("cm_id", ""))), []
                        ).append(item)
                    if len(pair_groups) == 1:
                        if not allow_terminal_retry:
                            raise LLMCRRAResponseInvalid(
                                "동일 공격 벡터·대응책 매핑 그룹의 완전한 추천을 "
                                "보정 재요청 후에도 받지 못했습니다."
                            )
                        retry_groups = [retry_items]
                    elif valid:
                        retry_groups = [retry_items]
                    else:
                        grouped_items = list(pair_groups.values())
                        midpoint = len(grouped_items) // 2
                        retry_groups = [
                            [item for group in grouped_items[:midpoint] for item in group],
                            [item for group in grouped_items[midpoint:] for item in group],
                        ]

                    repaired: list[dict[str, object]] = []
                    for group in retry_groups:
                        child = retry_crra_plan(group, "INCOMPLETE_OR_INVALID_ITEMS")
                        repaired.extend(complete_crra_chunk(
                            child, allow_terminal_retry=len({
                                (str(item.get("av_id", "")), str(item.get("cm_id", "")))
                                for item in group
                            }) != 1,
                        ))
                    collected = {
                        int(item["item_id"]): item for item in [*valid, *repaired]
                    }
                    if set(collected) != set(expected_ids) or len(collected) != len(valid) + len(repaired):
                        raise LLMCRRAResponseInvalid(
                            "LLM CRRA 보정 결과에 누락되거나 중복된 매핑 항목이 있습니다."
                        )
                    return [collected[item_id] for item_id in expected_ids]

                for initial_plan in batch_plan["chunks"]:
                    suggestions.extend(complete_crra_chunk(initial_plan))
                all_items = context["mapping_items"]
                expected_mapping_ids = [
                    int(item.get("item_id", item.get("mapping_id"))) for item in all_items
                ]
                try:
                    suggestions = normalize_crra_mapping_suggestions(
                        {"suggestions": suggestions}, expected_mapping_ids,
                    )
                except RuntimeError as exc:
                    raise LLMCRRAResponseInvalid(
                        "LLM이 모든 CRRA 매핑의 완전한 검토 초안을 반환하지 못했습니다."
                    ) from exc
                reconcile_crra_effect_suggestions(suggestions, all_items)
                validate_crra_effect_uniqueness(suggestions, all_items)
                provenance = _llm_provenance(session_key)
                for suggestion in suggestions:
                    suggestion["_llm"] = provenance
                # Recommendations remain drafts until the all-row PUT.
                self._json({
                    "assessment_id": assessment_id,
                    "suggestions": suggestions,
                    "metrics": {
                        **batch_plan["metrics"],
                        "provider_calls_executed": provider_calls,
                    },
                })
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra/llm/mapping", path):
                assessment_id = int(match.group(1))
                attack_vector_id = _required_text(body.get("attack_vector_id"), "attack_vector_id", 128)
                countermeasure_id = _required_text(body.get("countermeasure_id"), "countermeasure_id", 128)
                context = _context_allows_external_llm(DB.crra_mapping_context(
                    assessment_id, attack_vector_id, countermeasure_id, owner_id=owner_id,
                ))
                suggestion = normalize_countermeasure_mapping_suggestion(
                    LLM_SESSIONS.complete_json(session_key, COUNTERMEASURE_MAPPING_PROMPT, context),
                )
                suggestion["_llm"] = _llm_provenance(session_key)
                self._json(suggestion)
            elif match := re.fullmatch(r"/api/assessments/(\d+)/confirm-threat-model", path):
                self._json(
                    DB.confirm_threat_model(
                        int(match.group(1)), body, owner_id=owner_id,
                    )
                )
            elif match := re.fullmatch(r"/api/assessments/(\d+)/complete-candidate-identification", path):
                self._json(DB.complete_candidate_identification(
                    int(match.group(1)), owner_id=owner_id,
                ))
            elif match := re.fullmatch(r"/api/carts/(\d+)/items/catalog", path):
                DB.add_catalog_item(
                    int(match.group(1)), str(body.get("attack_vector_id", "")),
                    body.get("node_ids", body.get("node_id", "")), str(body.get("reason", "")),
                    owner_id=owner_id,
                )
                self._json({"ok": True}, 201)
            elif match := re.fullmatch(r"/api/carts/(\d+)/items/custom", path):
                if body.get("publish_to_km") and not KM_ADMIN_ENABLED:
                    raise PermissionError("공용 KM 등록은 KM 관리 모드에서만 사용할 수 있습니다.")
                vector_id = DB.add_custom_item(int(match.group(1)), body, owner_id=owner_id)
                self._json({"ok": True, "attack_vector_id": vector_id}, 201)
            elif match := re.fullmatch(r"/api/carts/(\d+)/complete", path):
                DB.complete_cart(int(match.group(1)), owner_id=owner_id)
                self._json({"ok": True})
            elif match := re.fullmatch(r"/api/carts/(\d+)/complete-review", path):
                DB.complete_review(int(match.group(1)), owner_id=owner_id)
                self._json({"ok": True})
            elif match := re.fullmatch(r"/api/carts/(\d+)/llm/plausibility", path):
                cart_id = int(match.group(1))
                context = DB.llm_cart_plausibility_context(cart_id, owner_id=owner_id)
                shared_context = {key: value for key, value in context.items() if key != "items"}
                suggestions: list[dict[str, object]] = []
                chunk_size = 8
                for offset in range(0, len(context["items"]), chunk_size):
                    chunk = context["items"][offset:offset + chunk_size]
                    expected_ids = [int(item["item_id"]) for item in chunk]
                    response = LLM_SESSIONS.complete_json(
                        session_key,
                        """당신은 TARA 분석 보조자다. 제공된 평가 맥락만 사용해 모든 공격 벡터의 타당성을 각각 추천한다.
반드시 JSON 객체만 반환한다. 형식: {"suggestions":[{"item_id":숫자,"status":"PLAUSIBLE|ELIMINATED","reason":"한국어 판단 근거","missing_information":[]}]}.
입력된 item_id를 하나도 빠뜨리거나 추가·중복하지 않는다. 각 item은 반드시 PLAUSIBLE 또는 ELIMINATED 중 하나로 결론 내린다.
자료가 제한적이어도 제공된 DFD·매핑·Scope 안에서 가장 상대적으로 부합하는 결론을 선택하고, reason에 현재 제공 정보 기준의 상대적 판단이라는 한계와 핵심 근거를 함께 명시한다. UNREVIEWED나 '판단 정보 부족'을 반환하거나 추가 확인 항목을 만들지 않는다.""",
                        {**shared_context, "items": chunk},
                        count_toward_rate_limit=offset == 0,
                    )
                    suggestions.extend(normalize_plausibility_suggestions(response, expected_ids))
                provenance = _llm_provenance(session_key)
                for suggestion in suggestions:
                    suggestion["_llm"] = provenance
                DB.save_llm_plausibility_suggestions(cart_id, suggestions, owner_id=owner_id)
                self._json({"cart_id": cart_id, "suggestions": suggestions})
            elif match := re.fullmatch(r"/api/carts/(\d+)/llm/risk", path):
                cart_id = int(match.group(1))
                context = DB.llm_cart_risk_context(cart_id, owner_id=owner_id)
                risk_model = context["risk_model"]
                batch_plan = plan_llm_risk_batch(context)
                suggestions: list[dict[str, object]] = []
                provider_calls = 0

                def retry_plans(
                    retry_items: list[dict[str, object]], reason: str,
                ) -> list[dict[str, object]]:
                    required_item_ids = [int(item["item_id"]) for item in retry_items]
                    response_correction = {
                        "reason": reason,
                        "required_item_ids": required_item_ids,
                        "instruction": (
                            "이 재요청의 item_id를 빠짐없이 각각 한 번만 반환하고, "
                            "모든 factor에 RECOMMENDED 정성 label과 근거를 작성하세요."
                        ),
                    }
                    # Include retry instructions in the request-size estimate.
                    child_context = {
                        **context,
                        "items": retry_items,
                        "response_correction": response_correction,
                    }
                    plans = plan_llm_risk_batch(child_context)["chunks"]
                    if not isinstance(plans, list) or not plans:
                        raise LLMRiskResponseInvalid("LLM 위험 평가 재요청 계획을 만들 수 없습니다.")
                    if any(
                        not isinstance(plan, dict) or not isinstance(plan.get("payload"), dict)
                        for plan in plans
                    ):
                        raise LLMRiskResponseInvalid("LLM 위험 평가 재요청 계획 형식이 올바르지 않습니다.")
                    return plans

                def complete_chunk(
                    chunk_plan: dict[str, object], *,
                    allow_single_item_escalation: bool = True,
                    allow_single_item_incomplete_retry: bool = True,
                ) -> list[dict[str, object]]:
                    nonlocal provider_calls
                    if provider_calls >= LLM_RISK_BATCH_MAX_PROVIDER_CALLS:
                        raise LLMRiskBatchExecutionLimit(
                            "LLM 응답 청크를 안전하게 분할할 수 있는 최대 호출 횟수에 도달했습니다. "
                            "쇼핑 카트 항목이나 계산기 요인을 줄인 뒤 다시 요청해 주세요."
                        )
                    count_toward_rate_limit = provider_calls == 0
                    provider_calls += 1
                    try:
                        response = LLM_SESSIONS.complete_json(
                            session_key,
                            LLM_RISK_BATCH_PROMPT,
                            chunk_plan["payload"],
                            max_completion_tokens=chunk_plan["max_completion_tokens"],
                            count_toward_rate_limit=count_toward_rate_limit,
                        )
                    except LLMProviderRequestTooLarge as exc:
                        chunk_items = chunk_plan.get("items", [])
                        if not isinstance(chunk_items, list) or len(chunk_items) <= 1:
                            raise exc
                        midpoint = len(chunk_items) // 2
                        split_results: list[dict[str, object]] = []
                        for subset in (chunk_items[:midpoint], chunk_items[midpoint:]):
                            for child_plan in retry_plans(subset, "PROVIDER_REQUEST_TOO_LARGE"):
                                split_results.extend(complete_chunk(child_plan))
                        return split_results
                    except LLMCompletionTruncated as exc:
                        chunk_items = chunk_plan["items"]
                        item_ids = chunk_plan.get("expected_item_ids", [])
                        if not isinstance(chunk_items, list) or len(chunk_items) <= 1:
                            current_tokens = int(chunk_plan.get("max_completion_tokens", 0) or 0)
                            escalation_tokens = min(
                                LLM_RISK_BATCH_MAX_COMPLETION_TOKENS,
                                LLM_RISK_BATCH_SINGLE_ITEM_ESCALATION_CAP,
                                max(current_tokens + 1, current_tokens * 2),
                            )
                            if (
                                isinstance(chunk_items, list)
                                and len(chunk_items) == 1
                                and allow_single_item_escalation
                                and current_tokens < escalation_tokens
                            ):
                                escalated_plan = retry_plans(
                                    chunk_items, "OUTPUT_TRUNCATED",
                                )[0]
                                return complete_chunk(
                                    {
                                        **escalated_plan,
                                        "max_completion_tokens": escalation_tokens,
                                    },
                                    allow_single_item_escalation=False,
                                    allow_single_item_incomplete_retry=False,
                                )
                            item_label = item_ids[0] if isinstance(item_ids, list) and item_ids else "알 수 없음"
                            raise LLMRiskResponseInvalid(
                                f"공격 벡터 항목 {item_label} 하나만 보낸 LLM 응답도 최대 토큰 "
                                "한도에서 잘렸습니다. 계산기 요인 정의를 줄이거나 이 항목을 "
                                "수동으로 평가해 주세요."
                            ) from exc
                        midpoint = len(chunk_items) // 2
                        split_results: list[dict[str, object]] = []
                        for subset in (chunk_items[:midpoint], chunk_items[midpoint:]):
                            for child_plan in retry_plans(subset, "OUTPUT_TRUNCATED"):
                                child_items = child_plan.get("items", [])
                                is_single = isinstance(child_items, list) and len(child_items) == 1
                                split_results.extend(complete_chunk(
                                    child_plan,
                                    allow_single_item_escalation=True,
                                    allow_single_item_incomplete_retry=not is_single,
                                ))
                        return split_results
                    except LLMResponseFormatError:
                        response = None

                    expected_ids = chunk_plan.get("expected_item_ids", [])
                    chunk_items = chunk_plan.get("items", [])
                    if (
                        not isinstance(expected_ids, list)
                        or any(isinstance(item_id, bool) or not isinstance(item_id, int) for item_id in expected_ids)
                        or not isinstance(chunk_items, list)
                    ):
                        raise LLMRiskResponseInvalid("LLM 위험 평가 청크 계획 형식이 올바르지 않습니다.")
                    valid, unresolved_ids = partition_risk_suggestions_for_retry(
                        response, expected_ids, risk_model,
                    )
                    if not unresolved_ids:
                        return valid

                    unresolved = set(unresolved_ids)
                    retry_items_for_ids = [
                        item for item in chunk_items
                        if isinstance(item, dict) and item.get("item_id") in unresolved
                    ]
                    if len(retry_items_for_ids) != len(unresolved):
                        raise LLMRiskResponseInvalid(
                            "LLM 위험 평가에서 누락된 항목의 재요청 맥락을 찾을 수 없습니다."
                        )
                    if len(retry_items_for_ids) == 1:
                        item_id = unresolved_ids[0]
                        if not allow_single_item_incomplete_retry:
                            raise LLMRiskResponseInvalid(
                                f"공격 벡터 항목 {item_id}의 완전한 위험 요인 추천을 "
                                "보정 재요청 후에도 받지 못했습니다."
                            )
                        retry_groups = [retry_items_for_ids]
                    elif valid:
                        # Retry unresolved rows only.
                        retry_groups = [retry_items_for_ids]
                    else:
                        # Bisect a batch that makes no progress.
                        midpoint = len(retry_items_for_ids) // 2
                        retry_groups = [
                            retry_items_for_ids[:midpoint], retry_items_for_ids[midpoint:],
                        ]

                    repaired: list[dict[str, object]] = []
                    for group in retry_groups:
                        for child_plan in retry_plans(group, "INCOMPLETE_OR_INVALID_ITEMS"):
                            child_items = child_plan.get("items", [])
                            is_single = isinstance(child_items, list) and len(child_items) == 1
                            repaired.extend(complete_chunk(
                                child_plan,
                                allow_single_item_escalation=True,
                                allow_single_item_incomplete_retry=not is_single,
                            ))

                    collected = {int(item["item_id"]): item for item in [*valid, *repaired]}
                    if set(collected) != set(expected_ids) or len(collected) != len(valid) + len(repaired):
                        raise LLMRiskResponseInvalid(
                            "LLM 위험 평가 보정 결과에 누락되거나 중복된 공격 벡터 항목이 있습니다."
                        )
                    return [collected[item_id] for item_id in expected_ids]

                for initial_plan in batch_plan["chunks"]:
                    suggestions.extend(complete_chunk(initial_plan))
                expected_item_ids = [int(item["item_id"]) for item in context["items"]]
                suggestions = revalidate_collected_risk_suggestions(
                    suggestions, expected_item_ids, risk_model,
                )
                provenance = _llm_provenance(session_key)
                for suggestion in suggestions:
                    suggestion["_llm"] = provenance
                DB.save_llm_risk_suggestions(
                    cart_id,
                    suggestions,
                    owner_id=owner_id,
                    expected_model_id=str(risk_model["id"]),
                )
                self._json({"cart_id": cart_id, "suggestions": suggestions})
            elif match := re.fullmatch(r"/api/assessments/(\d+)/risk-model", path):
                DB.select_risk_model(int(match.group(1)), str(body.get("model_id", "")), owner_id=owner_id)
                self._json({"ok": True})
            elif match := re.fullmatch(r"/api/assessments/(\d+)/matrix", path):
                self._json(DB.generate_matrix(int(match.group(1)), owner_id=owner_id))
            elif match := re.fullmatch(r"/api/assessments/(\d+)/matrix/confirm", path):
                DB.confirm_matrix(int(match.group(1)), owner_id=owner_id)
                self._json({"ok": True})
            elif match := re.fullmatch(r"/api/cart-items/(\d+)/llm/plausibility", path):
                item_id = int(match.group(1))
                suggestion = normalize_plausibility_suggestion(LLM_SESSIONS.complete_json(
                    session_key,
                    """당신은 TARA 분석 보조자다. 제공된 평가 맥락만 사용해 공격 벡터의 타당성을 추천한다.
반드시 JSON 객체만 반환한다. 형식: {"status":"PLAUSIBLE|ELIMINATED","reason":"한국어 판단 근거","missing_information":[]}.
자료가 제한적이어도 제공된 DFD·매핑·Scope 안에서 가장 상대적으로 부합하는 결론을 반드시 선택한다. reason에 현재 제공 정보 기준의 상대적 판단이라는 한계와 핵심 근거를 함께 명시한다. UNREVIEWED나 '판단 정보 부족'을 반환하거나 추가 확인 항목을 만들지 않는다.""",
                    DB.llm_context(item_id, owner_id=owner_id),
                ))
                suggestion["_llm"] = _llm_provenance(session_key)
                DB.save_llm_suggestion(item_id, "plausibility", suggestion, owner_id=owner_id)
                self._json(suggestion)
            elif match := re.fullmatch(r"/api/cart-items/(\d+)/llm/risk", path):
                self._error(
                    "개별 공격 벡터 LLM 위험 평가는 폐기되었습니다. 현재 쇼핑카트의 'LLM 일괄 Risk 평가'를 사용해 주세요.",
                    HTTPStatus.GONE,
                    code="CART_RISK_BATCH_REQUIRED",
                )
            else:
                self._error("API 경로를 찾을 수 없습니다.", 404)
        except BrowserSessionExpired as exc:
            self._error(str(exc), HTTPStatus.UNAUTHORIZED, code=exc.code)
        except LLMSessionConfigurationSuperseded as exc:
            self._error(str(exc), 409, code=exc.code)
        except LLMSessionConfigurationRateLimited as exc:
            self._error(str(exc), HTTPStatus.TOO_MANY_REQUESTS, code=exc.code)
        except LLMSessionCapacityExceeded as exc:
            self._error(str(exc), HTTPStatus.SERVICE_UNAVAILABLE, code=exc.code)
        except LLMRiskBatchTooLarge as exc:
            self._json(
                {"error": str(exc), "code": exc.code, "details": exc.details},
                HTTPStatus.UNPROCESSABLE_ENTITY,
            )
        except LLMRiskBatchExecutionLimit as exc:
            self._error(str(exc), HTTPStatus.BAD_GATEWAY, code=exc.code)
        except LLMRiskResponseInvalid as exc:
            self._error(str(exc), HTTPStatus.BAD_GATEWAY, code=exc.code)
        except LLMCRRABatchTooLarge as exc:
            self._json(
                {"error": str(exc), "code": exc.code, "details": exc.details},
                HTTPStatus.UNPROCESSABLE_ENTITY,
            )
        except LLMCRRABatchExecutionLimit as exc:
            self._error(str(exc), HTTPStatus.BAD_GATEWAY, code=exc.code)
        except LLMCRRAResponseInvalid as exc:
            self._error(str(exc), HTTPStatus.BAD_GATEWAY, code=exc.code)
        except LLMProviderRequestTooLarge as exc:
            self._error(str(exc), HTTPStatus.REQUEST_ENTITY_TOO_LARGE, code=exc.code)
        except LLMSessionRateLimited as exc:
            self._error(str(exc), 429, code=exc.code)
        except LLMSessionUnavailable as exc:
            self._error(str(exc), 409, code=exc.code)
        except PermissionError as exc:
            self._error(str(exc), 403, code="KM_ADMIN_DISABLED")
        except AssessmentCapacityExceeded as exc:
            self._error(str(exc), HTTPStatus.INSUFFICIENT_STORAGE, code=exc.code)
        except DatabaseCapacityExceeded as exc:
            self._error(str(exc), HTTPStatus.INSUFFICIENT_STORAGE, code=exc.code)
        except LookupError as exc:
            self._error(str(exc), 404)
        except sqlite3.OperationalError as exc:
            self._sqlite_error(exc)
        except (ValueError, RuntimeError) as exc:
            self._error(str(exc), 400)
        except Exception as exc:  # pragma: no cover
            self.log_error("Unhandled POST error: %r", exc)
            self._error("요청을 처리하는 중 오류가 발생했습니다.", 500)
        finally:
            self._release_database_capacity()

    def do_PUT(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            owner_id = self.owner_id
            body = self._body()
            self._require_km_admin(path)
            self._require_database_capacity()
            if match := re.fullmatch(r"/api/km/attack-vectors/([^/]+)", path):
                payload = {**body, "id": match.group(1)}
                self._json(DB.save_km_attack_vector(payload))
            elif match := re.fullmatch(r"/api/km/countermeasures/([^/]+)", path):
                payload = {**body, "id": match.group(1)}
                self._json(DB.save_km_countermeasure(payload))
            elif match := re.fullmatch(r"/api/km/mappings/(\d+)", path):
                payload = {**body, "id": int(match.group(1))}
                self._json(DB.save_km_mapping(payload))
            elif match := re.fullmatch(r"/api/km/vector-groups/(\d+)", path):
                payload = {**body, "id": int(match.group(1))}
                self._json(DB.save_vector_group(payload))
            elif match := re.fullmatch(r"/api/assessments/(\d+)/crra/mappings/reviews", path):
                self._json(DB.review_crra_mappings_batch(
                    int(match.group(1)), body.get("reviews"), owner_id=owner_id,
                ))
            elif match := re.fullmatch(r"/api/crra/mappings/(\d+)", path):
                result = DB.review_crra_mapping(int(match.group(1)), body, owner_id=owner_id)
                self._json({"ok": True} if result is None else result)
            elif match := re.fullmatch(r"/api/assessments/(\d+)", path):
                self._json(DB.update_assessment(int(match.group(1)), body, owner_id=owner_id))
            elif match := re.fullmatch(r"/api/assessments/(\d+)/custom-risk-model", path):
                self._json(DB.save_custom_risk_model(
                    int(match.group(1)), body, owner_id=owner_id,
                ))
            elif match := re.fullmatch(r"/api/assessments/(\d+)/tailored-risk-model", path):
                self._json(DB.save_tailored_risk_model(
                    int(match.group(1)), body, owner_id=owner_id,
                ))
            elif match := re.fullmatch(r"/api/assessments/(\d+)/dfd/edge-layout", path):
                self._json(DB.save_dfd_edge_layout(
                    int(match.group(1)), body.get("edges"), owner_id=owner_id,
                ))
            elif match := re.fullmatch(r"/api/assessments/(\d+)/dfd", path):
                DB.save_dfd(int(match.group(1)), body, owner_id=owner_id)
                self._json({"ok": True})
            elif match := re.fullmatch(r"/api/carts/(\d+)", path):
                DB.update_cart(int(match.group(1)), body, owner_id=owner_id)
                self._json({"ok": True})
            elif match := re.fullmatch(r"/api/cart-items/(\d+)/custom", path):
                self._json(DB.update_custom_cart_item(
                    int(match.group(1)), body, owner_id=owner_id,
                ))
            elif match := re.fullmatch(r"/api/carts/(\d+)/reviews", path):
                self._json(DB.review_items_batch(
                    int(match.group(1)), body.get("reviews"), owner_id=owner_id,
                ))
            elif match := re.fullmatch(r"/api/carts/(\d+)/risks", path):
                self._json(DB.score_items_batch(
                    int(match.group(1)),
                    body.get("items"),
                    owner_id=owner_id,
                    expected_model_id=_required_text(body.get("model_id"), "model_id", 128),
                ))
            elif match := re.fullmatch(r"/api/cart-items/(\d+)/review", path):
                DB.review_item(
                    int(match.group(1)), str(body.get("status", "")),
                    str(body.get("reason", "")), owner_id=owner_id,
                )
                self._json({"ok": True})
            elif match := re.fullmatch(r"/api/cart-items/(\d+)/risk", path):
                self._error(
                    "개별 위험 점수 저장은 폐기되었습니다. 현재 쇼핑카트 전체 저장을 사용해 주세요.",
                    HTTPStatus.GONE,
                    code="CART_RISK_BATCH_REQUIRED",
                )
            else:
                self._error("API 경로를 찾을 수 없습니다.", 404)
        except BrowserSessionExpired as exc:
            self._error(str(exc), HTTPStatus.UNAUTHORIZED, code=exc.code)
        except PermissionError as exc:
            self._error(str(exc), 403, code="KM_ADMIN_DISABLED")
        except DatabaseCapacityExceeded as exc:
            self._error(str(exc), HTTPStatus.INSUFFICIENT_STORAGE, code=exc.code)
        except LookupError as exc:
            self._error(str(exc), 404)
        except sqlite3.OperationalError as exc:
            self._sqlite_error(exc)
        except (ValueError, RuntimeError) as exc:
            self._error(str(exc), 400)
        except Exception as exc:  # pragma: no cover
            self.log_error("Unhandled PUT error: %r", exc)
            self._error("요청을 처리하는 중 오류가 발생했습니다.", 500)
        finally:
            self._release_database_capacity()

    def do_DELETE(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            owner_id = self.owner_id
            body = self._body()
            self._require_km_admin(path)
            if path == "/api/km/asset-mappings":
                self._json(DB.delete_km_asset_mapping({
                    "asset_type_id": _required_text(body.get("asset_type_id"), "asset_type_id", 128),
                    "attack_vector_id": _required_text(
                        body.get("attack_vector_id"), "attack_vector_id", 128,
                    ),
                }))
            elif match := re.fullmatch(r"/api/km/mappings/(\d+)", path):
                result = DB.delete_km_mapping(int(match.group(1)))
                self._json({"ok": True} if result is None else result)
            elif match := re.fullmatch(r"/api/carts/(\d+)/items", path):
                self._json(DB.delete_cart_items(
                    int(match.group(1)), body.get("item_ids"), owner_id=owner_id,
                ))
            elif match := re.fullmatch(r"/api/assessments/(\d+)", path):
                confirm_name = _required_text(body.get("confirm_name"), "confirm_name", 160)
                self._json(DB.delete_assessment(
                    int(match.group(1)), owner_id=owner_id, confirm_name=confirm_name,
                ))
            else:
                self._error("API 경로를 찾을 수 없습니다.", 404)
        except BrowserSessionExpired as exc:
            self._error(str(exc), HTTPStatus.UNAUTHORIZED, code=exc.code)
        except PermissionError as exc:
            self._error(str(exc), 403, code="KM_ADMIN_DISABLED")
        except LookupError as exc:
            self._error(str(exc), 404)
        except sqlite3.OperationalError as exc:
            self._sqlite_error(exc)
        except (ValueError, RuntimeError) as exc:
            self._error(str(exc), 400)
        except Exception as exc:  # pragma: no cover
            self.log_error("Unhandled DELETE error: %r", exc)
            self._error("요청을 처리하는 중 오류가 발생했습니다.", 500)


class CloudTARAHTTPServer(ThreadingHTTPServer):
    """Prevent multiple CloudTARA processes from sharing one Windows port."""

    allow_reuse_address = os.name != "nt"

    def server_bind(self) -> None:
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def run() -> None:
    server = CloudTARAHTTPServer((HOST, PORT), APIHandler)
    print(f"CloudTARA is running at http://{HOST}:{PORT}")
    print(f"SQLite DB: {DB_PATH}")
    if _legacy_claim_available():
        print("Existing assessments are quarantined. In the dashboard, choose '기존 평가 가져오기'.")
        print(f"One-time legacy claim code: {LEGACY_CLAIM_CODE}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCloudTARA stopped.")
    finally:
        server.server_close()
        LLM_SESSIONS.close()


if __name__ == "__main__":
    run()
