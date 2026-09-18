from __future__ import annotations

import json
import math
import re
import sqlite3
import uuid
from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dfd_catalog import (
    DFD_ELEMENT_TEMPLATES,
    DFD_FLOW_AUTO_CONDITIONS,
    DFD_FLOW_TEMPLATES,
    LEVEL1_ASSET_TYPES,
)


# Reserved owner for assessments created before browser-session ownership.
LEGACY_OWNER_ID = "__cntara_legacy_local_owner__"
BROWSER_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60
BROWSER_SESSION_REFRESH_INTERVAL_SECONDS = 60 * 60
MIN_SQLITE_STORAGE_BYTES = 16 * 1024 * 1024
SQLITE_STORAGE_SIDECAR_RESERVE_BYTES = 4 * 1024 * 1024

ASSESSMENT_TEXT_LIMITS = {
    "name": ("평가 이름", 60),
    "evaluation_target": ("대상 시스템 또는 서비스명", 100),
    "scope_in": ("포함 범위", 800),
    "scope_out": ("제외 범위", 400),
    "technical_info": ("가정 및 참고사항", 1200),
    "actor_motivation": ("위협 행위자 참고사항", 500),
}
DFD_NODE_TEXT_LIMITS = {
    "name": ("DFD 구성요소 표시 이름", 80),
    "description": ("DFD 구성요소 설명", 500),
}


def validate_assessment_text_lengths(data: dict[str, Any]) -> None:
    for field, (label, limit) in ASSESSMENT_TEXT_LIMITS.items():
        if len(clean_text(data.get(field))) > limit:
            raise ValueError(f"{label}은(는) {limit:,}자 이내로 입력해 주세요.")


def validate_dfd_node_text_lengths(node: dict[str, Any]) -> None:
    for field, (label, limit) in DFD_NODE_TEXT_LIMITS.items():
        value = node.get(field, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise ValueError(f"{label}은(는) 문자열이어야 합니다.")
        if len(value.strip()) > limit:
            raise ValueError(f"{label}은(는) {limit:,}자 이내로 입력해 주세요.")

BASE_DFD_COLUMNS = {
    "E.1": 0, "E.2": 0,
    "P.1": 1,
    "P.2": 2,
    "P.3": 3, "P.4": 3,
    "P.5": 4,
    "P.7": 5, "P.6": 5,
    "D.1": 6, "D.4": 6,
}

# Internal reference codes; these are not MITRE TARA enums.
LIFECYCLE_PHASE_OPTIONS = (
    ("DESIGN", "설계"),
    ("DEVELOPMENT", "개발"),
    ("DEPLOYMENT", "배포"),
    ("OPERATION", "운영"),
    ("RETIREMENT", "폐기"),
    ("OTHER", "기타"),
)
THREAT_RANGE_OPTIONS = (
    ("EXTERNAL_NETWORK", "외부 네트워크"),
    ("APPLICATION_API", "애플리케이션·API"),
    ("IDENTITY_CREDENTIAL", "ID·자격 증명"),
    ("KUBERNETES_CONTROL_PLANE", "Kubernetes 제어 영역"),
    ("CONTAINER_WORKLOAD", "컨테이너 워크로드"),
    ("SOFTWARE_SUPPLY_CHAIN", "소프트웨어 공급망"),
    ("DATA_COMPROMISE", "데이터 침해"),
    ("AVAILABILITY_DISRUPTION", "가용성 저해"),
    ("INSIDER", "내부자"),
    ("OTHER", "기타"),
)
ACTOR_TYPE_OPTIONS = (
    ("EXTERNAL", "외부 공격자"),
    ("INSIDER", "내부자"),
    ("SUPPLY_CHAIN", "공급망 공격자"),
    ("THIRD_PARTY_OPERATOR", "제3자 운영자"),
    ("UNKNOWN", "아직 모름"),
    ("OTHER", "기타"),
)
CAPABILITY_TAG_OPTIONS = (
    ("NETWORK", "네트워크"),
    ("WEB_API", "웹·API"),
    ("CREDENTIAL", "자격 증명"),
    ("CLOUD_IAM", "Cloud IAM"),
    ("KUBERNETES", "Kubernetes"),
    ("CONTAINER_RUNTIME", "컨테이너 런타임"),
    ("SOFTWARE_SUPPLY_CHAIN", "소프트웨어 공급망"),
    ("SOCIAL_ENGINEERING", "사회공학"),
    ("PHYSICAL", "물리적 접근"),
    ("OTHER", "기타"),
)
ATTACK_OBJECTIVE_OPTIONS = (
    ("EXFILTRATE", "정보·데이터 반출"),
    ("DEGRADE", "성능·기능 저하"),
    ("DISRUPT", "운영 방해"),
    ("DENY", "서비스 이용 차단"),
    ("DESTROY", "데이터·시스템 파괴"),
    ("DECEIVE", "정보·상태 기만"),
    ("OTHER", "기타"),
)
KNOWLEDGE_STATE_OPTIONS = (
    ("KNOWN", "알려짐"),
    ("UNKNOWN", "아직 모름"),
    ("NOT_AVAILABLE", "자료 없음"),
)
MODELING_METHOD_OPTIONS = (
    ("MANUAL_DFD", "DFD 직접 작성"),
    ("MANIFEST_DFD", "Manifest로 DFD 초안 생성"),
)

LIFECYCLE_LABELS = dict(LIFECYCLE_PHASE_OPTIONS)
LIFECYCLE_CODES_BY_LABEL = {label: code for code, label in LIFECYCLE_PHASE_OPTIONS}
THREAT_RANGE_LABELS = dict(THREAT_RANGE_OPTIONS)
ACTOR_TYPE_LABELS = dict(ACTOR_TYPE_OPTIONS)
CAPABILITY_TAG_LABELS = dict(CAPABILITY_TAG_OPTIONS)
ATTACK_OBJECTIVE_LABELS = dict(ATTACK_OBJECTIVE_OPTIONS)
KNOWLEDGE_STATE_LABELS = dict(KNOWLEDGE_STATE_OPTIONS)
MODELING_METHOD_LABELS = dict(MODELING_METHOD_OPTIONS)


class AssessmentLimitError(RuntimeError):
    """Raised when an atomic assessment count limit would be exceeded."""

    def __init__(self, scope: str, limit: int):
        self.scope = scope
        self.limit = limit
        super().__init__(f"assessment {scope} limit reached: {limit}")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def session_utc_iso(value: datetime) -> str:
    """Return one canonical, second-precision UTC representation for session rows."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("browser session time must include a UTC offset")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_session_utc_iso(value: str) -> datetime:
    """Parse a persisted session timestamp as an aware UTC datetime."""
    if not isinstance(value, str) or not value:
        raise ValueError("browser session timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise ValueError("browser session timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("browser session timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def dump_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def load_json(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def collector_run_ids_from_dfd(elements: list[dict[str, Any]]) -> set[int]:
    """Return validated run IDs carried by browser-applied collector elements."""
    run_ids: set[int] = set()
    for element in elements:
        properties = element.get("properties")
        if not isinstance(properties, dict):
            continue
        collector = properties.get("collector")
        if not isinstance(collector, dict) or collector.get("generated") is not True:
            continue
        provenance = properties.get("provenance")
        provenance = provenance if isinstance(provenance, dict) else {}
        raw_run_id = collector.get("run_id") or provenance.get("collection_run_id")
        try:
            run_id = int(raw_run_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("Manifest 초안 실행 ID가 올바르지 않습니다.") from exc
        if run_id <= 0:
            raise ValueError("Manifest 초안 실행 ID가 올바르지 않습니다.")
        run_ids.add(run_id)
    return run_ids


def clean_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalize_code(value: Any, labels: dict[str, str], field: str, *, allow_empty: bool = True) -> str:
    code = clean_text(value).upper()
    if not code and allow_empty:
        return ""
    if code not in labels:
        raise ValueError(f"{field} 선택값이 올바르지 않습니다: {code or '(비어 있음)'}")
    return code


def _normalize_code_list(value: Any, labels: dict[str, str], field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field}은(는) 목록 형식이어야 합니다.")
    result: list[str] = []
    for item in value:
        code = _normalize_code(item, labels, field, allow_empty=False)
        if code not in result:
            result.append(code)
    return [code for code in labels if code in result]


def normalize_scope_profile(value: Any, *, lifecycle_fallback: str = "OPERATION") -> dict[str, Any]:
    if isinstance(value, str):
        value = load_json(value, None)
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("Scope Brief 프로필 형식이 올바르지 않습니다.")
    version = value.get("schema_version", 1)
    if version != 1:
        raise ValueError("지원하지 않는 Scope Brief 프로필 버전입니다.")
    lifecycle = _normalize_code(
        value.get("lifecycle_phase_code") or lifecycle_fallback,
        LIFECYCLE_LABELS,
        "생명주기",
        allow_empty=False,
    )
    threat_ranges = _normalize_code_list(
        value.get("threat_range_codes"), THREAT_RANGE_LABELS, "위협 범위",
    )
    actor_value = value.get("actor") or {}
    if not isinstance(actor_value, dict):
        raise ValueError("위협 행위자 프로필 형식이 올바르지 않습니다.")
    actor_type = _normalize_code(actor_value.get("actor_type_code"), ACTOR_TYPE_LABELS, "위협 행위자")
    objectives = _normalize_code_list(
        actor_value.get("objective_codes"), ATTACK_OBJECTIVE_LABELS, "공격 목표",
    )
    intent_state = _normalize_code(
        actor_value.get("intent_knowledge_state"), KNOWLEDGE_STATE_LABELS, "공격 목표 파악 상태",
    )
    if objectives and not intent_state:
        intent_state = "KNOWN"
    if intent_state == "KNOWN" and not objectives:
        raise ValueError("공격 목표가 '알려짐'이면 목표를 하나 이상 선택해 주세요.")
    if intent_state and intent_state != "KNOWN":
        objectives = []
    capabilities = _normalize_code_list(
        actor_value.get("capability_codes"), CAPABILITY_TAG_LABELS, "행위자 역량",
    )
    capability_state = _normalize_code(
        actor_value.get("capability_knowledge_state"), KNOWLEDGE_STATE_LABELS, "역량 파악 상태",
    )
    if capabilities:
        capability_state = "KNOWN"
    elif capability_state == "KNOWN":
        raise ValueError("행위자 역량이 '알려짐'이면 역량을 하나 이상 선택해 주세요.")
    elif not capability_state:
        capability_state = "UNKNOWN"
    elif capability_state != "KNOWN":
        capabilities = []
    return {
        "schema_version": 1,
        "lifecycle_phase_code": lifecycle,
        "threat_range_codes": threat_ranges,
        "actor": {
            "actor_type_code": actor_type,
            "intent_knowledge_state": intent_state,
            "objective_codes": objectives,
            "capability_knowledge_state": capability_state,
            "capability_codes": capabilities,
            "notes": clean_text(actor_value.get("notes")),
        },
    }


def profile_legacy_fields(profile: dict[str, Any]) -> dict[str, str]:
    actor = profile.get("actor") or {}
    intent_state = actor.get("intent_knowledge_state", "")
    objective_codes = actor.get("objective_codes") or []
    capability_state = actor.get("capability_knowledge_state", "")
    capability_codes = actor.get("capability_codes") or []
    return {
        "lifecycle_phase": LIFECYCLE_LABELS.get(profile.get("lifecycle_phase_code"), "운영"),
        "threat_range": ", ".join(THREAT_RANGE_LABELS[code] for code in profile.get("threat_range_codes", []) if code in THREAT_RANGE_LABELS),
        "actor_type": ACTOR_TYPE_LABELS.get(actor.get("actor_type_code"), ""),
        "actor_motivation": clean_text(actor.get("notes")),
        "actor_intent": (
            ", ".join(ATTACK_OBJECTIVE_LABELS[code] for code in objective_codes if code in ATTACK_OBJECTIVE_LABELS)
            if intent_state == "KNOWN"
            else KNOWLEDGE_STATE_LABELS.get(intent_state, "")
        ),
        "actor_capabilities": (
            ", ".join(CAPABILITY_TAG_LABELS[code] for code in capability_codes if code in CAPABILITY_TAG_LABELS)
            if capability_state == "KNOWN"
            else KNOWLEDGE_STATE_LABELS.get(capability_state, "")
        ),
    }


def scope_missing_fields(assessment: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    if not clean_text(assessment.get("scope_in")):
        missing.append("포함 범위")
    raw_profile = assessment.get("scope_profile")
    if raw_profile is None:
        raw_profile = load_json(assessment.get("scope_profile_json"), {})
    if isinstance(raw_profile, dict) and raw_profile.get("schema_version") == 1:
        actor = raw_profile.get("actor") if isinstance(raw_profile.get("actor"), dict) else {}
        if not raw_profile.get("threat_range_codes"):
            missing.append("위협 범위")
        if not clean_text(actor.get("actor_type_code")):
            missing.append("위협 행위자")
        intent_state = clean_text(actor.get("intent_knowledge_state"))
        if not intent_state or (intent_state == "KNOWN" and not actor.get("objective_codes")):
            missing.append("공격 목표 또는 '아직 모름'")
    else:
        if not clean_text(assessment.get("threat_range")):
            missing.append("위협 범위")
        if not clean_text(assessment.get("actor_type")):
            missing.append("위협 행위자")
        if not clean_text(assessment.get("actor_intent")):
            missing.append("공격 목표")
    return missing


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS km_releases (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS asset_types (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    group_name TEXT NOT NULL,
    dfd_kind TEXT NOT NULL CHECK (dfd_kind IN ('external', 'process', 'data_store')),
    description TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dfd_element_templates (
    km_release_id INTEGER NOT NULL REFERENCES km_releases(id),
    level INTEGER NOT NULL CHECK (level IN (0,1)),
    asset_type_id TEXT NOT NULL REFERENCES asset_types(id),
    parent_asset_type_id TEXT REFERENCES asset_types(id),
    sort_order INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (km_release_id,level,asset_type_id)
);

CREATE TABLE IF NOT EXISTS dfd_flow_templates (
    km_release_id INTEGER NOT NULL,
    level INTEGER NOT NULL CHECK (level IN (0,1)),
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    source_asset_type_id TEXT NOT NULL,
    target_asset_type_id TEXT NOT NULL,
    review_status TEXT NOT NULL DEFAULT 'REVIEW_REQUIRED'
        CHECK (review_status IN ('APPROVED','REVIEW_REQUIRED')),
    auto_instantiation INTEGER NOT NULL DEFAULT 0
        CHECK (auto_instantiation IN (0,1)),
    condition_key TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    notes TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (km_release_id,level,id),
    FOREIGN KEY (km_release_id,level,source_asset_type_id)
        REFERENCES dfd_element_templates(km_release_id,level,asset_type_id),
    FOREIGN KEY (km_release_id,level,target_asset_type_id)
        REFERENCES dfd_element_templates(km_release_id,level,asset_type_id),
    CHECK (
        auto_instantiation=0 OR
        (condition_key<>'' AND review_status='APPROVED')
    )
);

CREATE INDEX IF NOT EXISTS idx_dfd_flow_templates_endpoints
    ON dfd_flow_templates(km_release_id,level,source_asset_type_id,target_asset_type_id,active);

CREATE TABLE IF NOT EXISTS attack_vectors (
    id TEXT PRIMARY KEY,
    catalog_id TEXT UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    prerequisite TEXT,
    source TEXT NOT NULL,
    source_identifier TEXT,
    reference_url TEXT NOT NULL DEFAULT '',
    assessment_id INTEGER
);

CREATE TABLE IF NOT EXISTS public_id_sequences (
    entity_type TEXT PRIMARY KEY,
    next_value INTEGER NOT NULL CHECK (next_value > 0)
);

CREATE TABLE IF NOT EXISTS asset_attack_vectors (
    km_release_id INTEGER NOT NULL REFERENCES km_releases(id),
    asset_type_id TEXT NOT NULL REFERENCES asset_types(id),
    attack_vector_id TEXT NOT NULL REFERENCES attack_vectors(id),
    mapping_note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (km_release_id, asset_type_id, attack_vector_id)
);

CREATE TABLE IF NOT EXISTS countermeasures (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    reference_url TEXT NOT NULL DEFAULT '',
    assessment_id INTEGER REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS av_countermeasure_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    km_release_id INTEGER NOT NULL REFERENCES km_releases(id),
    av_id TEXT NOT NULL REFERENCES attack_vectors(id),
    cm_id TEXT NOT NULL REFERENCES countermeasures(id),
    effect TEXT NOT NULL CHECK (effect IN ('PREVENT','DETECT','RESPOND')),
    confidence TEXT NOT NULL CHECK (confidence IN ('HIGH','MODERATE','LOW')),
    rationale TEXT NOT NULL DEFAULT '',
    review_status TEXT NOT NULL DEFAULT 'REVIEW_REQUIRED'
        CHECK (review_status IN ('APPROVED','REVIEW_REQUIRED')),
    UNIQUE (km_release_id,av_id,cm_id,effect)
);

CREATE TABLE IF NOT EXISTS vector_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    km_release_id INTEGER NOT NULL REFERENCES km_releases(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    parent_id INTEGER REFERENCES vector_groups(id) ON DELETE SET NULL,
    UNIQUE (km_release_id,name)
);

CREATE TABLE IF NOT EXISTS vector_group_members (
    group_id INTEGER NOT NULL REFERENCES vector_groups(id) ON DELETE CASCADE,
    av_id TEXT NOT NULL REFERENCES attack_vectors(id),
    PRIMARY KEY (group_id,av_id)
);

CREATE TABLE IF NOT EXISTS risk_models (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method IN ('weighted_sum', 'product')),
    decimals INTEGER NOT NULL DEFAULT 2,
    bands_json TEXT NOT NULL DEFAULT '[]',
    source_note TEXT NOT NULL DEFAULT '',
    basis TEXT NOT NULL DEFAULT 'PR20_EXPLICIT',
    formula_text TEXT NOT NULL DEFAULT '',
    formula_json TEXT NOT NULL DEFAULT '{}',
    score_min REAL,
    score_max REAL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    assessment_id INTEGER,
    model_kind TEXT NOT NULL DEFAULT 'BUILTIN'
        CHECK (model_kind IN ('BUILTIN','CUSTOM'))
);

CREATE TABLE IF NOT EXISTS risk_factors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id TEXT NOT NULL REFERENCES risk_models(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    factor_group TEXT NOT NULL DEFAULT '',
    question TEXT NOT NULL,
    weight REAL NOT NULL DEFAULT 1,
    levels_json TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    UNIQUE (model_id, code)
);

CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT NOT NULL DEFAULT '__cntara_legacy_local_owner__',
    name TEXT NOT NULL,
    evaluation_target TEXT NOT NULL,
    scope_in TEXT NOT NULL DEFAULT '',
    scope_out TEXT NOT NULL DEFAULT '',
    threat_range TEXT NOT NULL DEFAULT '',
    lifecycle_phase TEXT NOT NULL DEFAULT '운영',
    actor_type TEXT NOT NULL DEFAULT '',
    actor_motivation TEXT NOT NULL DEFAULT '',
    actor_intent TEXT NOT NULL DEFAULT '',
    actor_capabilities TEXT NOT NULL DEFAULT '',
    technical_info TEXT NOT NULL DEFAULT '',
    domain_profile_code TEXT NOT NULL DEFAULT 'CLOUD_NATIVE',
    modeling_method TEXT NOT NULL DEFAULT 'MANUAL_DFD',
    scope_profile_json TEXT NOT NULL DEFAULT '{}',
    external_llm_allowed INTEGER NOT NULL DEFAULT 0,
    km_release_id INTEGER NOT NULL DEFAULT 1 REFERENCES km_releases(id),
    risk_model_id TEXT REFERENCES risk_models(id),
    threat_model_confirmed INTEGER NOT NULL DEFAULT 0,
    matrix_confirmed INTEGER NOT NULL DEFAULT 0,
    current_step INTEGER NOT NULL DEFAULT 1,
    crra_current_step INTEGER NOT NULL DEFAULT 0,
    crra_confirmed INTEGER NOT NULL DEFAULT 0,
    base_dfd_initialized INTEGER NOT NULL DEFAULT 0,
    base_dfd_flows_initialized INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS browser_sessions (
    owner_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    expired_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_browser_sessions_expires_at
    ON browser_sessions(expires_at);

CREATE TABLE IF NOT EXISTS dfd_nodes (
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    asset_type_id TEXT NOT NULL REFERENCES asset_types(id),
    dfd_kind TEXT NOT NULL,
    x REAL NOT NULL,
    y REAL NOT NULL,
    width REAL NOT NULL DEFAULT 150,
    height REAL NOT NULL DEFAULT 64,
    description TEXT NOT NULL DEFAULT '',
    properties_json TEXT NOT NULL DEFAULT '{}',
    is_entry INTEGER NOT NULL DEFAULT 0,
    is_target INTEGER NOT NULL DEFAULT 0,
    entry_reason TEXT NOT NULL DEFAULT '',
    target_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (assessment_id, id)
);

CREATE TABLE IF NOT EXISTS dfd_edges (
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT '',
    data_type TEXT NOT NULL DEFAULT '',
    properties_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (assessment_id, id)
);

CREATE TABLE IF NOT EXISTS trust_boundaries (
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    x REAL NOT NULL,
    y REAL NOT NULL,
    width REAL NOT NULL,
    height REAL NOT NULL,
    PRIMARY KEY (assessment_id, id)
);

CREATE TABLE IF NOT EXISTS attack_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    client_case_id TEXT,
    name TEXT NOT NULL,
    entry_node_id TEXT,
    entry_node_ids_json TEXT NOT NULL DEFAULT '[]',
    target_node_id TEXT NOT NULL,
    intended_effect TEXT NOT NULL DEFAULT '',
    rationale TEXT NOT NULL DEFAULT '',
    actor_snapshot_json TEXT NOT NULL DEFAULT '{}',
    path_mode TEXT NOT NULL DEFAULT 'DIRECTED'
        CHECK (path_mode IN ('DIRECTED','UNDIRECTED','MANUAL','LEGACY_AGGREGATED')),
    path_rationale TEXT NOT NULL DEFAULT '',
    path_edge_ids_json TEXT NOT NULL DEFAULT '[]',
    legacy_entry_node_ids_json TEXT NOT NULL DEFAULT '[]',
    case_kind TEXT NOT NULL DEFAULT 'EXPLICIT'
        CHECK (case_kind IN ('EXPLICIT','LEGACY_AGGREGATED')),
    status TEXT NOT NULL DEFAULT 'CONFIRMED'
        CHECK (status IN ('CONFIRMED','LEGACY_REVIEW_REQUIRED')),
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (case_kind='EXPLICIT' AND entry_node_id IS NOT NULL AND entry_node_id<>target_node_id)
        OR case_kind='LEGACY_AGGREGATED'
    )
);

CREATE INDEX IF NOT EXISTS idx_attack_cases_assessment_order
    ON attack_cases(assessment_id,sort_order,id);

CREATE TABLE IF NOT EXISTS attack_case_nodes (
    attack_case_id INTEGER NOT NULL REFERENCES attack_cases(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    sequence_order INTEGER NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('ENTRY','PATH','TARGET','LEGACY_ENTRY')),
    PRIMARY KEY (attack_case_id,node_id)
);

CREATE INDEX IF NOT EXISTS idx_attack_case_nodes_case_order
    ON attack_case_nodes(attack_case_id,sequence_order);

CREATE TABLE IF NOT EXISTS collection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    source_type TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    mapper_version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PREVIEWED'
        CHECK (status IN ('PREVIEWED','APPLIED')),
    summary_json TEXT NOT NULL DEFAULT '{}',
    warnings_json TEXT NOT NULL DEFAULT '[]',
    proposal_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    applied_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_collection_runs_assessment_created
    ON collection_runs(assessment_id, created_at DESC);

CREATE TABLE IF NOT EXISTS candidate_vectors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    attack_case_id INTEGER REFERENCES attack_cases(id) ON DELETE CASCADE,
    entry_node_id TEXT,
    target_node_id TEXT NOT NULL,
    attack_vector_id TEXT NOT NULL REFERENCES attack_vectors(id),
    entry_node_ids_json TEXT NOT NULL DEFAULT '[]',
    related_node_ids_json TEXT NOT NULL DEFAULT '[]',
    path_node_ids_json TEXT NOT NULL DEFAULT '[]',
    mapping_evidence_json TEXT NOT NULL DEFAULT '[]',
    context_status TEXT NOT NULL DEFAULT 'EXPLICIT_CASE'
        CHECK (context_status IN ('EXPLICIT_CASE','LEGACY_AGGREGATED')),
    UNIQUE (attack_case_id, attack_vector_id)
);

CREATE TABLE IF NOT EXISTS shopping_carts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    attack_case_id INTEGER REFERENCES attack_cases(id) ON DELETE CASCADE,
    entry_node_id TEXT,
    target_node_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'READY', 'REVIEWED')),
    context_status TEXT NOT NULL DEFAULT 'EXPLICIT_CASE'
        CHECK (context_status IN ('EXPLICIT_CASE','LEGACY_AGGREGATED')),
    UNIQUE (attack_case_id)
);

CREATE TABLE IF NOT EXISTS cart_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cart_id INTEGER NOT NULL REFERENCES shopping_carts(id) ON DELETE CASCADE,
    attack_vector_id TEXT NOT NULL REFERENCES attack_vectors(id),
    candidate_id INTEGER REFERENCES candidate_vectors(id) ON DELETE SET NULL,
    item_source TEXT NOT NULL DEFAULT 'AUTO',
    related_entry_ids_json TEXT NOT NULL DEFAULT '[]',
    related_node_ids_json TEXT NOT NULL DEFAULT '[]',
    mapping_evidence_json TEXT NOT NULL DEFAULT '[]',
    addition_reason TEXT NOT NULL DEFAULT '',
    review_status TEXT NOT NULL DEFAULT 'UNREVIEWED' CHECK (review_status IN ('UNREVIEWED', 'PLAUSIBLE', 'ELIMINATED')),
    decision_reason TEXT NOT NULL DEFAULT '',
    llm_plausibility_json TEXT,
    factor_values_json TEXT NOT NULL DEFAULT '{}',
    factor_reasons_json TEXT NOT NULL DEFAULT '{}',
    llm_risk_json TEXT,
    risk_score REAL,
    risk_level TEXT,
    calculation_trace_json TEXT NOT NULL DEFAULT '{}',
    risk_review_status TEXT NOT NULL DEFAULT 'UNASSESSED'
        CHECK (risk_review_status IN ('UNASSESSED','LLM_COMPLETED','USER_REVIEWED','USER_MODIFIED','NEEDS_REVIEW')),
    UNIQUE (cart_id, attack_vector_id)
);

CREATE TABLE IF NOT EXISTS susceptibility_matrices (
    assessment_id INTEGER PRIMARY KEY REFERENCES assessments(id) ON DELETE CASCADE,
    risk_model_id TEXT NOT NULL REFERENCES risk_models(id),
    data_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'CONFIRMED')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS crra_settings (
    assessment_id INTEGER PRIMARY KEY REFERENCES assessments(id) ON DELETE CASCADE,
    current_step INTEGER NOT NULL DEFAULT 1 CHECK (current_step BETWEEN 1 AND 5),
    status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','CONFIRMED')),
    prevent_weight REAL NOT NULL DEFAULT 1,
    respond_weight REAL NOT NULL DEFAULT 1,
    strategy TEXT NOT NULL DEFAULT 'BANG_FOR_BUCK'
        CHECK (strategy IN ('BANG_FOR_BUCK','MAX_UTILITY','LEAST_COST')),
    min_total INTEGER NOT NULL DEFAULT 1 CHECK (min_total >= 0),
    min_prevent INTEGER NOT NULL DEFAULT 0 CHECK (min_prevent >= 0),
    min_respond INTEGER NOT NULL DEFAULT 0 CHECK (min_respond >= 0),
    gap_reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS crra_vectors (
    assessment_id INTEGER NOT NULL REFERENCES crra_settings(assessment_id) ON DELETE CASCADE,
    av_id TEXT NOT NULL REFERENCES attack_vectors(id),
    selected INTEGER NOT NULL DEFAULT 1,
    selection_reason TEXT NOT NULL DEFAULT '',
    risk_score REAL,
    rank INTEGER NOT NULL,
    PRIMARY KEY (assessment_id,av_id)
);

CREATE TABLE IF NOT EXISTS crra_mapping_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES crra_settings(assessment_id) ON DELETE CASCADE,
    av_id TEXT NOT NULL REFERENCES attack_vectors(id),
    cm_id TEXT NOT NULL REFERENCES countermeasures(id),
    effect TEXT NOT NULL CHECK (effect IN ('PREVENT','DETECT','RESPOND')),
    confidence TEXT NOT NULL CHECK (confidence IN ('HIGH','MODERATE','LOW')),
    review_status TEXT NOT NULL DEFAULT 'UNREVIEWED'
        CHECK (review_status IN ('UNREVIEWED','INCLUDED','EXCLUDED')),
    decision_reason TEXT NOT NULL DEFAULT '',
    item_source TEXT NOT NULL DEFAULT 'KM',
    UNIQUE (assessment_id,av_id,cm_id,effect)
);

CREATE TABLE IF NOT EXISTS crra_countermeasures (
    assessment_id INTEGER NOT NULL REFERENCES crra_settings(assessment_id) ON DELETE CASCADE,
    cm_id TEXT NOT NULL REFERENCES countermeasures(id),
    cost_score REAL,
    cost_reason TEXT NOT NULL DEFAULT '',
    prevent_count INTEGER NOT NULL DEFAULT 0,
    detect_count INTEGER NOT NULL DEFAULT 0,
    respond_count INTEGER NOT NULL DEFAULT 0,
    utility REAL,
    uc_ratio REAL,
    selected INTEGER NOT NULL DEFAULT 0,
    selection_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (assessment_id,cm_id)
);

CREATE TABLE IF NOT EXISTS crra_solutions (
    assessment_id INTEGER PRIMARY KEY REFERENCES crra_settings(assessment_id) ON DELETE CASCADE,
    data_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','CONFIRMED')),
    updated_at TEXT NOT NULL
);
"""


ASSET_TYPES = [
    ("GEN-EXT", "외부 사용자/시스템", "일반", "external", "시스템 외부에서 통신하는 사용자 또는 시스템", 1),
    ("E.1", "User Device", "일반", "external", "사용자가 시스템에 접근하는 단말", 2),
    ("E.2", "Prometheus", "관측", "external", "컨테이너 및 인프라 상태를 수집하는 모니터링 시스템", 3),
    ("GEN-PROC", "일반 프로세스", "일반", "process", "서비스 또는 애플리케이션 프로세스", 10),
    ("P.1", "Kubectl", "Kubernetes", "process", "Kubernetes 클러스터 관리 CLI", 11),
    ("P.2", "Control Plane", "Kubernetes", "process", "Kubernetes 클러스터의 상태와 배치를 관리", 12),
    ("P.3", "Kube Proxy", "Kubernetes", "process", "노드의 서비스 네트워크 규칙과 라우팅을 관리", 13),
    ("P.4", "Kubelet", "Kubernetes", "process", "노드에서 Pod와 컨테이너를 관리", 14),
    ("P.6", "Pod", "Kubernetes", "process", "Kubernetes의 최소 배포 단위", 15),
    ("P.5", "Containerd", "Container", "process", "컨테이너 생성과 실행을 관리하는 런타임", 20),
    ("P.6.1", "Container", "Container", "process", "애플리케이션을 패키징하여 실행하는 격리 단위", 21),
    ("P.7", "runc", "Container", "process", "OCI 표준에 따라 컨테이너를 실행하는 저수준 런타임", 22),
    ("P.8", "Kubelet Volume Manager (hostPath)", "Kubernetes", "process", "kubelet에서 hostPath 볼륨 마운트를 조정하는 논리 기능", 23),
    ("GEN-DATA", "일반 데이터 저장소", "일반", "data_store", "데이터를 보관하는 저장소", 30),
    ("D.1", "Image Registry", "저장소", "data_store", "컨테이너 이미지를 저장하고 배포하는 저장소", 31),
    ("D.2", "Content Store", "저장소", "data_store", "이미지 레이어와 콘텐츠를 저장", 32),
    ("D.3", "Volumes", "저장소", "data_store", "Pod와 컨테이너가 사용하는 볼륨", 33),
    ("D.4", "Host File System", "저장소", "data_store", "컨테이너가 접근할 수 있는 호스트 파일 시스템", 34),
    ("DB.1", "BoltDB", "저장소", "data_store", "컨테이너 메타데이터 저장소", 35),
] + list(LEVEL1_ASSET_TYPES)


ATTACK_VECTORS = [
    ("T1190", "Exploit Public-Facing Application", "외부에 공개된 애플리케이션의 취약점이나 잘못된 설정을 악용한다."),
    ("T1078.001", "Valid Accounts: Default Accounts", "기본 계정이나 기본 자격 증명을 악용한다."),
    ("T1078.003", "Valid Accounts: Local Accounts", "로컬 계정의 자격 증명을 획득하여 악용한다."),
    ("T1609", "Container Administration Command", "컨테이너 관리 API나 명령을 이용하여 컨테이너 안에서 명령을 실행한다."),
    ("T1053.007", "Scheduled Task/Job: Container Orchestration Job", "오케스트레이션 작업을 이용해 악성 컨테이너 실행을 예약한다."),
    ("T1204.003", "User Execution: Malicious Image", "사용자가 악성 또는 변조된 이미지를 실행하도록 유도한다."),
    ("T1098.006", "Account Manipulation: Additional Container Cluster Roles", "계정에 컨테이너 클러스터 권한을 추가한다."),
    ("T1136.001", "Create Account: Local Account", "지속적인 접근을 위해 로컬 계정을 생성한다."),
    ("T1543.005", "Create or Modify System Process: Container Service", "컨테이너 관련 서비스나 에이전트를 생성 또는 변경한다."),
    ("T1525", "Implant Internal Image", "내부 이미지 저장소에 악성 이미지를 삽입한다."),
    ("T1610", "Deploy Container", "악성 행위를 수행하는 컨테이너를 배포한다."),
    ("T1611", "Escape to Host", "컨테이너 격리를 벗어나 호스트에 접근한다."),
    ("T1612", "Build Image on Host", "호스트에서 직접 컨테이너 이미지를 빌드한다."),
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", "보안 또는 모니터링 도구를 비활성화하거나 변경한다."),
    ("T1036.005", "Masquerading: Match Legitimate Name or Location", "정상적인 이름이나 위치와 유사하게 위장한다."),
    ("T1036.010", "Masquerading: Masquerade Account Name", "정상 계정과 비슷한 이름으로 계정을 위장한다."),
    ("T1550.001", "Use Alternate Authentication Material: Application Access Token", "애플리케이션 접근 토큰을 악용한다."),
    ("T1110.001", "Brute Force: Password Guessing", "반복적인 비밀번호 추측으로 계정 접근을 시도한다."),
    ("T1110.003", "Brute Force: Password Spraying", "소수의 비밀번호를 여러 계정에 대입한다."),
    ("T1110.004", "Brute Force: Credential Stuffing", "유출된 계정 정보를 다른 서비스에 대입한다."),
    ("T1528", "Steal Application Access Token", "애플리케이션이나 서비스 계정의 접근 토큰을 탈취한다."),
    ("T1070", "Indicator Removal", "로그나 흔적을 삭제하여 활동을 숨긴다."),
    ("T1068", "Exploitation for Privilege Escalation", "소프트웨어 취약점을 악용하여 권한을 상승시킨다."),
    ("T1133", "External Remote Services", "외부 원격 서비스를 이용해 시스템에 접근한다."),
]


MAPPINGS = {
    "E.2": ["T1190", "T1078.003"],
    "P.1": ["T1190", "T1078.001", "T1609", "T1053.007", "T1098.006", "T1136.001", "T1543.005", "T1562.001"],
    "P.2": ["T1190", "T1053.007", "T1098.006", "T1543.005", "T1562.001", "T1036.010", "T1550.001", "T1078.001", "T1078.003", "T1110.001", "T1110.003", "T1110.004"],
    "P.4": ["T1070", "T1609", "T1610", "T1098.006", "T1543.005", "T1611", "T1068"],
    "P.6": ["T1562.001", "T1110.001", "T1068", "T1110.003", "T1110.004", "T1078.003", "T1078.001", "T1133", "T1190", "T1036.010"],
    "P.7": ["T1543.005", "T1611", "T1612"],
    "D.1": ["T1204.003", "T1525"],
    "D.3": ["T1528"],
    "D.4": ["T1543.005", "T1611"],
}


COUNTERMEASURES = [
    ("M1017", "User Training", "사용자가 악성 콘텐츠와 신뢰할 수 없는 이미지·링크를 식별하도록 교육한다."),
    ("M1018", "User Account Management", "계정의 생성·사용·폐기를 관리하고 비정상 계정을 점검한다."),
    ("M1022", "Restrict File and Directory Permissions", "파일과 디렉터리 권한을 필요한 주체로 제한한다."),
    ("M1026", "Privileged Account Management", "관리·특권 계정과 권한 사용을 제한하고 관리한다."),
    ("M1027", "Password Policies", "안전한 비밀번호 정책과 자격 증명 수명주기를 적용한다."),
    ("M1032", "Multi-factor Authentication", "추가 인증 요소를 요구하여 계정 악용 가능성을 줄인다."),
    ("M1035", "Limit Access to Resource Over Network", "네트워크를 통한 자원 접근을 필요한 경로와 주체로 제한한다."),
    ("M1036", "Account Use Policies", "계정 사용 조건과 허용 범위를 정책으로 제한한다."),
    ("M1037", "Filter Network Traffic", "방화벽과 네트워크 정책으로 허용되지 않은 트래픽을 필터링한다."),
    ("M1038", "Execution Prevention", "허용되지 않은 코드·명령·프로세스 실행을 차단한다."),
    ("M1041", "Encrypt Sensitive Information", "민감한 정보와 자격 증명을 암호화하여 보호한다."),
    ("M1042", "Disable or Remove Feature or Program", "필요하지 않거나 위험한 기능과 프로그램을 비활성화한다."),
    ("M1045", "Code Signing", "신뢰된 코드와 이미지의 서명을 검증한다."),
    ("M1047", "Audit", "보안 관련 활동과 변경을 감사 기록으로 남기고 검토한다."),
    ("M1048", "Application Isolation and Sandboxing", "애플리케이션과 컨테이너를 격리된 환경에서 실행한다."),
    ("M1050", "Exploit Protection", "메모리 보호 등 취약점 악용 방지 기능을 적용한다."),
    ("M1051", "Update Software", "보안 업데이트와 패치를 적시에 적용한다."),
    ("M1054", "Software Configuration", "소프트웨어를 안전한 기준에 맞게 구성한다."),
]

# ATT&CK supplies the relation only; P/D/R and confidence are review proposals.
AV_COUNTERMEASURE_SEED = {
    "T1190": [("M1035", "PREVENT"), ("M1037", "DETECT"), ("M1051", "PREVENT")],
    "T1078.001": [("M1027", "PREVENT"), ("M1032", "PREVENT")],
    "T1078.003": [("M1018", "RESPOND"), ("M1027", "PREVENT"), ("M1032", "PREVENT")],
    "T1609": [("M1026", "PREVENT"), ("M1035", "PREVENT"), ("M1042", "PREVENT")],
    "T1053.007": [("M1018", "RESPOND"), ("M1026", "PREVENT")],
    "T1204.003": [("M1017", "PREVENT"), ("M1045", "PREVENT"), ("M1047", "DETECT")],
    "T1098.006": [("M1018", "RESPOND"), ("M1032", "PREVENT")],
    "T1136.001": [("M1026", "PREVENT"), ("M1032", "PREVENT")],
    "T1543.005": [("M1018", "RESPOND"), ("M1054", "PREVENT")],
    "T1525": [("M1026", "PREVENT"), ("M1045", "PREVENT"), ("M1047", "DETECT")],
    "T1610": [("M1018", "RESPOND"), ("M1035", "PREVENT"), ("M1047", "DETECT")],
    "T1611": [("M1026", "PREVENT"), ("M1038", "PREVENT"), ("M1048", "PREVENT"), ("M1051", "PREVENT")],
    "T1612": [("M1026", "PREVENT"), ("M1035", "PREVENT"), ("M1047", "DETECT")],
    "T1562.001": [("M1047", "DETECT")],
    "T1036.005": [("M1022", "PREVENT"), ("M1038", "PREVENT"), ("M1045", "PREVENT")],
    "T1036.010": [("M1018", "RESPOND"), ("M1047", "DETECT")],
    "T1550.001": [("M1036", "RESPOND"), ("M1041", "PREVENT"), ("M1047", "DETECT")],
    "T1110.001": [("M1027", "PREVENT"), ("M1032", "PREVENT"), ("M1036", "RESPOND"), ("M1051", "PREVENT")],
    "T1110.003": [("M1027", "PREVENT"), ("M1032", "PREVENT"), ("M1036", "RESPOND")],
    "T1110.004": [("M1018", "RESPOND"), ("M1027", "PREVENT"), ("M1032", "PREVENT"), ("M1036", "RESPOND")],
    "T1528": [("M1017", "PREVENT"), ("M1018", "RESPOND"), ("M1047", "DETECT")],
    "T1070": [("M1022", "PREVENT"), ("M1041", "PREVENT")],
    "T1068": [("M1038", "PREVENT"), ("M1048", "PREVENT"), ("M1050", "PREVENT"), ("M1051", "PREVENT")],
    "T1133": [("M1032", "PREVENT"), ("M1035", "PREVENT"), ("M1042", "PREVENT")],
}

KM_SEED_RATIONALE = (
    "Legacy ATT&CK technique↔mitigation 관계를 바탕으로 한 CloudTARA 초기 효과 제안입니다. "
    "PREVENT/DETECT/RESPOND 분류와 LOW confidence는 MITRE 원문 속성이 아니며 사용자 검토가 필요합니다."
)


LIKELIHOOD_LEVELS = [
    {"value": 1, "label": "Very unlikely", "description": "공격 성공 가능성이 매우 낮다."},
    {"value": 2, "label": "Unlikely", "description": "공격 성공 가능성이 낮다."},
    {"value": 3, "label": "Possible", "description": "공격이 성공할 가능성이 있다."},
    {"value": 4, "label": "Likely", "description": "공격이 성공할 가능성이 높다."},
    {"value": 5, "label": "Very likely", "description": "공격이 성공할 가능성이 매우 높다."},
]

IMPACT_LEVELS = [
    {"value": 1, "label": "Negligible impact", "description": "무시할 수 있는 영향이다."},
    {"value": 2, "label": "Minimal impact", "description": "최소한의 영향이다."},
    {"value": 3, "label": "Moderate impact", "description": "중간 수준의 영향이다."},
    {"value": 4, "label": "Serious impact", "description": "심각한 영향이다."},
    {"value": 5, "label": "Catastrophic impact", "description": "치명적인 영향이다."},
]

MISSION_IMPACT_LEVELS = [
    {"value": 1, "label": "Sporadic loss of mission capability", "description": "임무 수행 능력이 일시적으로 산발적으로 상실된다."},
    {"value": 2, "label": "Intermittent loss of mission capability", "description": "임무 수행 능력이 간헐적으로 상실된다."},
    {"value": 3, "label": "Regular loss of mission capability", "description": "임무 수행 능력이 정기적으로 상실된다."},
    {"value": 4, "label": "Extended loss of mission capability", "description": "임무 수행 능력이 장기간 상실된다."},
    {"value": 5, "label": "Permanent loss of mission capability", "description": "임무 수행 능력이 영구적으로 상실된다."},
]

VULNERABILITY_LEVELS = [
    {"value": 1, "label": "Negligible vulnerabilities", "description": "취약점이 무시할 수 있는 수준이다."},
    {"value": 2, "label": "Limited vulnerabilities", "description": "취약점이 제한적이다."},
    {"value": 3, "label": "Moderate vulnerabilities", "description": "취약점이 중간 수준이다."},
    {"value": 4, "label": "Serious vulnerabilities", "description": "취약점이 심각한 수준이다."},
    {"value": 5, "label": "Extremely vulnerable", "description": "시스템이 극도로 취약하다."},
]

EXPOSURE_LEVELS = [
    {"value": 1, "label": "Negligible exposure", "description": "노출이 무시할 수 있는 수준이다."},
    {"value": 2, "label": "Limited exposure", "description": "노출이 제한적이다."},
    {"value": 3, "label": "Moderately exposed", "description": "시스템이 중간 수준으로 노출되어 있다."},
    {"value": 4, "label": "Serious exposure", "description": "노출이 심각한 수준이다."},
    {"value": 5, "label": "Extremely exposed", "description": "시스템이 극도로 노출되어 있다."},
]

# 아래 V1 식별자와 계산 정의는 기존 평가를 보존하기 위해 변경하지 않는다.
# 계산 정의를 바꿀 때는 기존 행을 덮어쓰지 않고 V2 식별자를 추가한다.
RISK_MODELS = [
    {
        "id": "PR20-P66-WEIGHTED-SUM-V1",
        "name": "사용자 정의 위험 계산기 (MITRE 예시)",
        "description": "MITRE TARA 2020 p.66의 5개 요인·가중치·1/2/3 척도를 그대로 사용하는 Custom 기본 예시",
        "method": "weighted_sum",
        "decimals": 1,
        "basis": "PR20_EXPLICIT",
        "formula_text": "S = 0.2×영향 범위 + 0.2×기밀성 영향 + 0.2×가용성 영향 + 0.3×과거 사용 + 0.1×탐지 난이도",
        "formula": {"op": "weighted_sum", "terms": [
            {"factor": "locality", "weight": 0.2},
            {"factor": "confidentiality", "weight": 0.2},
            {"factor": "availability", "weight": 0.2},
            {"factor": "prior_use", "weight": 0.3},
            {"factor": "stealth", "weight": 0.1},
        ]},
        "score_min": 1,
        "score_max": 3,
        "sort_order": 10,
        "source_note": "MITRE TARA Training Workshop (2020), p.66 · 원문 명시 공식. p.125의 별도 사용자 정의 표는 선언 척도(1·2·3)와 예시값(1·3·5)이 충돌하므로 이 preset에 혼합하지 않음.",
        "factor_groups": {
            "locality": "Custom", "confidentiality": "Impact", "availability": "Impact",
            "prior_use": "Likelihood", "stealth": "Custom",
        },
        "factors": [
            ("locality", "영향 범위", "이 공격의 영향은 얼마나 국지적인가?", 0.2, [
                {"value": 1, "label": "Low", "description": "단일 장치에만 영향이 한정된다."},
                {"value": 2, "label": "Medium", "description": "외부 네트워크가 영향을 받을 수 있다."},
                {"value": 3, "label": "High", "description": "모든 장치와 관련 기반시설에 전역적으로 영향을 줄 수 있다."},
            ]),
            ("confidentiality", "기밀성 영향", "공격 성공으로 데이터 기밀성이 상실될 때 영향은 얼마나 심각한가?", 0.2, [
                {"value": 1, "label": "Low", "description": "기밀성에 미치는 영향이 없다."},
                {"value": 2, "label": "Medium", "description": "일부 복구가 필요한 제한적인 영향이다."},
                {"value": 3, "label": "High", "description": "데이터 유출 대응 훈련이 정기적으로 필요할 수준이다."},
            ]),
            ("availability", "가용성 영향", "공격 성공으로 시스템 가용성이 상실될 때 영향은 얼마나 심각한가?", 0.2, [
                {"value": 1, "label": "Low", "description": "가용성에 미치는 영향이 없다."},
                {"value": 2, "label": "Medium", "description": "일부 복구가 필요한 제한적인 영향이다."},
                {"value": 3, "label": "High", "description": "시스템 중단 대응 훈련이 정기적으로 필요할 수준이다."},
            ]),
            ("prior_use", "과거 사용", "이 공격이 이전에 성공적으로 사용되었다는 근거가 있는가?", 0.3, [
                {"value": 1, "label": "Low", "description": "사용되었다는 근거가 없다."},
                {"value": 2, "label": "Medium", "description": "사용된 사실이 확인된 근거가 있다."},
                {"value": 3, "label": "High", "description": "광범위하게 사용된 사례가 보고되었다."},
            ]),
            ("stealth", "탐지 난이도", "이 공격이 적용될 때 얼마나 탐지하기 어려운가?", 0.1, [
                {"value": 1, "label": "Low", "description": "별도 모니터링 없이도 공격이 분명히 드러난다."},
                {"value": 2, "label": "Medium", "description": "일상적인 모니터링으로 탐지할 가능성이 높다."},
                {"value": 3, "label": "High", "description": "탐지할 수 없다."},
            ]),
        ],
    },
    {
        "id": "CNTARA-PR20-STANDARD-V1",
        "name": "표준 위험 계산기",
        "description": "가능성과 영향을 곱하는 표준 계산기. 계산식은 p.121 표의 1·9·25 예시에 맞춰 CloudTARA가 고정한 도출 규칙이다.",
        "method": "product",
        "decimals": 1,
        "basis": "CNTARA_DERIVED",
        "formula_text": "S = 공격 성공 가능성 × 피해 영향",
        "formula": {"op": "multiply", "terms": [{"factor": "likelihood"}, {"factor": "impact"}]},
        "score_min": 1,
        "score_max": 25,
        "sort_order": 20,
        "source_note": "PR-20 p.121 표의 요인·가중치·예시값으로부터 도출한 CloudTARA 계산 규칙",
        "factor_groups": {"likelihood": "Likelihood", "impact": "Impact"},
        "factors": [
            ("likelihood", "공격 성공 가능성", "공격이 성공할 가능성은 어느 정도인가?", 1, LIKELIHOOD_LEVELS),
            ("impact", "피해 영향", "공격이 성공하면 어떤 영향이 발생하는가?", 1, IMPACT_LEVELS),
        ],
    },
    {
        "id": "CNTARA-PR20-CIA-V1",
        "name": "기밀성·무결성·가용성(CIA) 위험 계산기",
        "description": "가능성과 가중 CIA 영향을 결합한다. 계산식은 p.122 표의 1·9·25 예시에 맞춰 CloudTARA가 고정한 도출 규칙이다.",
        "method": "product",
        "decimals": 1,
        "basis": "CNTARA_DERIVED",
        "formula_text": "S = 공격 성공 가능성 × (0.3×기밀성 영향 + 0.3×무결성 영향 + 0.4×가용성 영향)",
        "formula": {"op": "multiply", "terms": [
            {"factor": "likelihood"},
            {"op": "weighted_sum", "terms": [
                {"factor": "confidentiality", "weight": 0.3},
                {"factor": "integrity", "weight": 0.3},
                {"factor": "availability", "weight": 0.4},
            ]},
        ]},
        "score_min": 1,
        "score_max": 25,
        "sort_order": 30,
        "source_note": "PR-20 p.122 표의 요인·가중치·예시값으로부터 도출한 CloudTARA 계산 규칙",
        "factor_groups": {
            "likelihood": "Likelihood", "confidentiality": "Impact",
            "integrity": "Impact", "availability": "Impact",
        },
        "factors": [
            ("likelihood", "공격 성공 가능성", "공격이 성공할 가능성은 어느 정도인가?", 1, LIKELIHOOD_LEVELS),
            ("confidentiality", "기밀성 영향", "공격 성공 시 기밀성에 미치는 영향은 어느 정도인가?", 0.3, IMPACT_LEVELS),
            ("integrity", "무결성 영향", "공격 성공 시 무결성에 미치는 영향은 어느 정도인가?", 0.3, IMPACT_LEVELS),
            ("availability", "가용성 영향", "공격 성공 시 가용성에 미치는 영향은 어느 정도인가?", 0.4, IMPACT_LEVELS),
        ],
    },
    {
        "id": "CNTARA-PR20-MISSION-V1",
        "name": "임무 위험 계산기",
        "description": "공격 성공 가능성과 임무 영향을 곱한다. 계산식은 p.123 표의 1·9·25 예시에 맞춰 CloudTARA가 고정한 도출 규칙이다.",
        "method": "product",
        "decimals": 1,
        "basis": "CNTARA_DERIVED",
        "formula_text": "S = 공격 성공 가능성 × 임무 영향",
        "formula": {"op": "multiply", "terms": [{"factor": "likelihood"}, {"factor": "mission_impact"}]},
        "score_min": 1,
        "score_max": 25,
        "sort_order": 40,
        "source_note": "PR-20 p.123 표의 요인·가중치·예시값으로부터 도출한 CloudTARA 계산 규칙. 레벨 3 원문은 'Regular loss of mission impact'로 인쇄되어 있으나, 다른 레벨 및 의미 일관성을 위해 CloudTARA 표시 문구는 'Regular loss of mission capability'로 정규화함.",
        "factor_groups": {"likelihood": "Likelihood", "mission_impact": "Impact"},
        "factors": [
            ("likelihood", "공격 성공 가능성", "공격이 성공할 가능성은 어느 정도인가?", 1, LIKELIHOOD_LEVELS),
            ("mission_impact", "임무 영향", "공격이 성공하면 임무 수행에 어떤 영향이 발생하는가?", 1, MISSION_IMPACT_LEVELS),
        ],
    },
    {
        "id": "CNTARA-PR20-VXE-V1",
        "name": "취약성×노출 위험 계산기",
        "description": "가중 취약성·노출 값과 피해 영향을 결합한다. 계산식은 p.124 표의 1·9·25 예시에 맞춰 CloudTARA가 고정한 도출 규칙이다.",
        "method": "product",
        "decimals": 1,
        "basis": "CNTARA_DERIVED",
        "formula_text": "S = (0.5×취약성 + 0.5×노출) × 피해 영향",
        "formula": {"op": "multiply", "terms": [
            {"op": "weighted_sum", "terms": [
                {"factor": "vulnerability", "weight": 0.5},
                {"factor": "exposure", "weight": 0.5},
            ]},
            {"factor": "impact"},
        ]},
        "score_min": 1,
        "score_max": 25,
        "sort_order": 50,
        "source_note": "PR-20 p.124 표의 요인·가중치·예시값으로부터 도출한 CloudTARA 계산 규칙",
        "factor_groups": {"vulnerability": "Likelihood", "exposure": "Likelihood", "impact": "Impact"},
        "factors": [
            ("vulnerability", "취약성", "시스템은 공격에 얼마나 취약한가?", 0.5, VULNERABILITY_LEVELS),
            ("exposure", "노출", "악의적 위협 행위자가 시스템에 얼마나 쉽게 접근할 수 있는가?", 0.5, EXPOSURE_LEVELS),
            ("impact", "피해 영향", "공격이 성공하면 어떤 영향이 발생하는가?", 1, IMPACT_LEVELS),
        ],
    },
]

# Only calculator-defined weighted groups accept custom weights.
TAILORABLE_RISK_FACTORS = {
    "PR20-P66-WEIGHTED-SUM-V1": (
        "locality", "confidentiality", "availability", "prior_use", "stealth",
    ),
    "CNTARA-PR20-CIA-V1": ("confidentiality", "integrity", "availability"),
    "CNTARA-PR20-VXE-V1": ("vulnerability", "exposure"),
}

RISK_REFERENCE_APPROACHES = [
    {
        "id": "PR20-CUSTOM-P125",
        "name": "사용자 정의 위험 계산기",
        "source": "PR-20 p.125",
        "status": "추가 정의 필요",
        "reason": "프로그램별 요인·척도·가중치를 정의해야 하며, 원문 표의 선언 척도(1·2·3)와 예시값(1·3·5)이 서로 충돌한다.",
    },
    {
        "id": "PR20-RISK-CUBE",
        "name": "위험 큐브",
        "source": "PR-20 p.65",
        "status": "계산 규칙 없음",
        "reason": "원문은 접근 방식의 이름만 언급하며 축, 셀, 계산식과 구간을 정의하지 않는다.",
    },
    {
        "id": "PR20-MAUA",
        "name": "다속성 효용 분석(MAUA)",
        "source": "PR-20 p.65",
        "status": "계산 규칙 없음",
        "reason": "원문은 접근 방식의 이름만 언급하며 효용함수, 정규화, 가중치와 결합식을 제공하지 않는다.",
    },
]


class CNTaraDB:
    def __init__(self, path: str | Path, max_storage_bytes: int | None = None):
        self.path = str(path)
        if max_storage_bytes is not None and (
            isinstance(max_storage_bytes, bool)
            or not isinstance(max_storage_bytes, int)
            or max_storage_bytes < MIN_SQLITE_STORAGE_BYTES
        ):
            raise ValueError(
                f"max_storage_bytes must be an integer of at least {MIN_SQLITE_STORAGE_BYTES}"
            )
        self.max_storage_bytes = max_storage_bytes
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=20)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            if self.max_storage_bytes is not None:
                page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
                main_budget = (
                    self.max_storage_bytes - SQLITE_STORAGE_SIDECAR_RESERVE_BYTES
                ) // 2
                requested_pages = max(1, main_budget // page_size)
                # Existing page count may set the effective lower bound.
                conn.execute(f"PRAGMA max_page_count={requested_pages}").fetchone()
            return conn
        except Exception:
            conn.close()
            raise

    def initialize(self) -> None:
        with closing(self.connect()) as conn, conn:
            conn.executescript(SCHEMA)
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(assessments)")}
            if "owner_id" not in columns:
                # Move pre-session rows to the reserved legacy owner.
                conn.execute(
                    f"ALTER TABLE assessments ADD COLUMN owner_id TEXT NOT NULL DEFAULT '{LEGACY_OWNER_ID}'"
                )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_assessments_owner_updated "
                "ON assessments(owner_id,updated_at DESC)"
            )
            session_columns = {row["name"] for row in conn.execute("PRAGMA table_info(browser_sessions)")}
            if "expired_at" not in session_columns:
                conn.execute("ALTER TABLE browser_sessions ADD COLUMN expired_at TEXT")
            edge_columns = {row["name"] for row in conn.execute("PRAGMA table_info(dfd_edges)")}
            if "properties_json" not in edge_columns:
                conn.execute("ALTER TABLE dfd_edges ADD COLUMN properties_json TEXT NOT NULL DEFAULT '{}'")
            if "external_llm_allowed" not in columns:
                conn.execute("ALTER TABLE assessments ADD COLUMN external_llm_allowed INTEGER NOT NULL DEFAULT 0")
            if "domain_profile_code" not in columns:
                conn.execute("ALTER TABLE assessments ADD COLUMN domain_profile_code TEXT NOT NULL DEFAULT 'CLOUD_NATIVE'")
            if "modeling_method" not in columns:
                conn.execute("ALTER TABLE assessments ADD COLUMN modeling_method TEXT NOT NULL DEFAULT 'MANUAL_DFD'")
            if "scope_profile_json" not in columns:
                conn.execute("ALTER TABLE assessments ADD COLUMN scope_profile_json TEXT NOT NULL DEFAULT '{}'")
            if "crra_current_step" not in columns:
                conn.execute("ALTER TABLE assessments ADD COLUMN crra_current_step INTEGER NOT NULL DEFAULT 0")
            if "crra_confirmed" not in columns:
                conn.execute("ALTER TABLE assessments ADD COLUMN crra_confirmed INTEGER NOT NULL DEFAULT 0")
            if "base_dfd_initialized" not in columns:
                conn.execute("ALTER TABLE assessments ADD COLUMN base_dfd_initialized INTEGER NOT NULL DEFAULT 0")
            if "base_dfd_flows_initialized" not in columns:
                conn.execute("ALTER TABLE assessments ADD COLUMN base_dfd_flows_initialized INTEGER NOT NULL DEFAULT 0")
            attack_vector_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(attack_vectors)")
            }
            if "prerequisite" not in attack_vector_columns:
                conn.execute("ALTER TABLE attack_vectors ADD COLUMN prerequisite TEXT")
            if "catalog_id" not in attack_vector_columns:
                conn.execute("ALTER TABLE attack_vectors ADD COLUMN catalog_id TEXT")
            if "source_identifier" not in attack_vector_columns:
                conn.execute("ALTER TABLE attack_vectors ADD COLUMN source_identifier TEXT")
            conn.execute(
                """UPDATE assessments SET crra_current_step=0,crra_confirmed=0
                   WHERE NOT EXISTS (
                       SELECT 1 FROM crra_settings cs WHERE cs.assessment_id=assessments.id
                   )"""
            )
            risk_columns = {row["name"] for row in conn.execute("PRAGMA table_info(risk_models)")}
            risk_migrations = {
                "basis": "ALTER TABLE risk_models ADD COLUMN basis TEXT NOT NULL DEFAULT 'LEGACY_UNVERIFIED'",
                "formula_text": "ALTER TABLE risk_models ADD COLUMN formula_text TEXT NOT NULL DEFAULT ''",
                "formula_json": "ALTER TABLE risk_models ADD COLUMN formula_json TEXT NOT NULL DEFAULT '{}'",
                "score_min": "ALTER TABLE risk_models ADD COLUMN score_min REAL",
                "score_max": "ALTER TABLE risk_models ADD COLUMN score_max REAL",
                "sort_order": "ALTER TABLE risk_models ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0",
                "active": "ALTER TABLE risk_models ADD COLUMN active INTEGER NOT NULL DEFAULT 1",
                "assessment_id": "ALTER TABLE risk_models ADD COLUMN assessment_id INTEGER",
                "model_kind": "ALTER TABLE risk_models ADD COLUMN model_kind TEXT NOT NULL DEFAULT 'BUILTIN' CHECK (model_kind IN ('BUILTIN','CUSTOM'))",
            }
            for column, statement in risk_migrations.items():
                if column not in risk_columns:
                    conn.execute(statement)
            # 알려진 구버전 계산기의 근거 유형만 보정한다.
            conn.execute("UPDATE risk_models SET basis='PR20_EXPLICIT' WHERE id='PR20-WEIGHTED-SUM'")
            conn.execute("UPDATE risk_models SET basis='CNTARA_DERIVED' WHERE id='PR20-STANDARD-PRODUCT'")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_risk_models_assessment "
                "ON risk_models(assessment_id,active,sort_order)"
            )
            factor_columns = {row["name"] for row in conn.execute("PRAGMA table_info(risk_factors)")}
            if "factor_group" not in factor_columns:
                conn.execute("ALTER TABLE risk_factors ADD COLUMN factor_group TEXT NOT NULL DEFAULT ''")
            cart_item_columns = {row["name"] for row in conn.execute("PRAGMA table_info(cart_items)")}
            if "calculation_trace_json" not in cart_item_columns:
                conn.execute("ALTER TABLE cart_items ADD COLUMN calculation_trace_json TEXT NOT NULL DEFAULT '{}'")
            risk_review_status_added = "risk_review_status" not in cart_item_columns
            if risk_review_status_added:
                conn.execute(
                    "ALTER TABLE cart_items ADD COLUMN risk_review_status TEXT NOT NULL DEFAULT 'UNASSESSED' "
                    "CHECK (risk_review_status IN ('UNASSESSED','LLM_COMPLETED','USER_REVIEWED','USER_MODIFIED','NEEDS_REVIEW'))"
                )
                # Preserve saved deterministic scores during migration.
                conn.execute(
                    "UPDATE cart_items SET risk_review_status='USER_REVIEWED' WHERE risk_score IS NOT NULL"
                )
                conn.execute(
                    "UPDATE cart_items SET risk_review_status='NEEDS_REVIEW' "
                    "WHERE risk_score IS NULL AND llm_risk_json IS NOT NULL"
                )
            self._migrate_attack_case_storage(conn)
            self._seed(conn)
            self._ensure_attack_vector_catalog_ids(conn)
            self._ensure_attack_vector_source_identifiers(conn)
            self._initialize_existing_base_dfds(conn)

    @staticmethod
    def _sync_attack_vector_catalog_sequence(conn: sqlite3.Connection) -> int:
        largest = 0
        for row in conn.execute("SELECT catalog_id FROM attack_vectors WHERE catalog_id IS NOT NULL"):
            match = re.fullmatch(r"AV-(\d{6})", clean_text(row["catalog_id"]))
            if match:
                largest = max(largest, int(match.group(1)))
        conn.execute(
            """INSERT INTO public_id_sequences(entity_type,next_value) VALUES('ATTACK_VECTOR',?)
               ON CONFLICT(entity_type) DO UPDATE SET next_value=MAX(next_value,excluded.next_value)""",
            (largest + 1,),
        )
        row = conn.execute(
            "SELECT next_value FROM public_id_sequences WHERE entity_type='ATTACK_VECTOR'"
        ).fetchone()
        return int(row["next_value"])

    @classmethod
    def _next_attack_vector_catalog_id(cls, conn: sqlite3.Connection) -> str:
        sequence = cls._sync_attack_vector_catalog_sequence(conn)
        conn.execute(
            "UPDATE public_id_sequences SET next_value=? WHERE entity_type='ATTACK_VECTOR'",
            (sequence + 1,),
        )
        return f"AV-{sequence:06d}"

    @classmethod
    def _ensure_attack_vector_catalog_ids(cls, conn: sqlite3.Connection) -> None:
        """Give every legacy and new vector one stable, user-facing CloudTARA ID."""
        used: set[str] = set()
        rows = list(
            conn.execute(
                """SELECT rowid,id,catalog_id FROM attack_vectors
                   ORDER BY CASE WHEN assessment_id IS NULL THEN 0 ELSE 1 END,rowid,id"""
            )
        )
        # Reserve existing AV IDs before allocating migration replacements.
        legacy_catalog_rows: set[int] = set()
        for row in rows:
            legacy_id = clean_text(row["id"])
            if not re.fullmatch(r"AV-\d{6}", legacy_id) or legacy_id in used:
                continue
            if clean_text(row["catalog_id"]) != legacy_id:
                conn.execute(
                    "UPDATE attack_vectors SET catalog_id=NULL WHERE catalog_id=? AND rowid<>?",
                    (legacy_id, row["rowid"]),
                )
                conn.execute(
                    "UPDATE attack_vectors SET catalog_id=? WHERE rowid=?",
                    (legacy_id, row["rowid"]),
                )
            used.add(legacy_id)
            legacy_catalog_rows.add(int(row["rowid"]))

        # Reserve valid assignments before filling gaps.
        rows = list(
            conn.execute(
                """SELECT rowid,id,catalog_id FROM attack_vectors
                   ORDER BY CASE WHEN assessment_id IS NULL THEN 0 ELSE 1 END,rowid,id"""
            )
        )
        for row in rows:
            if int(row["rowid"]) in legacy_catalog_rows:
                continue
            current = clean_text(row["catalog_id"])
            if re.fullmatch(r"AV-\d{6}", current) and current not in used:
                used.add(current)
                continue
            if current:
                conn.execute(
                    "UPDATE attack_vectors SET catalog_id=NULL WHERE rowid=?",
                    (row["rowid"],),
                )

        for row in rows:
            if int(row["rowid"]) in legacy_catalog_rows:
                continue
            current_row = conn.execute(
                "SELECT catalog_id FROM attack_vectors WHERE rowid=?", (row["rowid"],)
            ).fetchone()
            current = clean_text(current_row["catalog_id"] if current_row else "")
            if re.fullmatch(r"AV-\d{6}", current):
                continue
            candidate = cls._next_attack_vector_catalog_id(conn)
            while candidate in used:
                candidate = cls._next_attack_vector_catalog_id(conn)
            conn.execute(
                "UPDATE attack_vectors SET catalog_id=? WHERE rowid=?",
                (candidate, row["rowid"]),
            )
            used.add(candidate)
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_attack_vectors_catalog_id ON attack_vectors(catalog_id)"
        )
        cls._sync_attack_vector_catalog_sequence(conn)

    @staticmethod
    def _ensure_attack_vector_source_identifiers(conn: sqlite3.Connection) -> None:
        """Separate source-native identifiers from CloudTARA's public AV IDs."""
        conn.execute(
            """UPDATE attack_vectors
               SET source_identifier=id
               WHERE (source_identifier IS NULL OR TRIM(source_identifier)='')
                 AND id NOT LIKE 'AV-%'
                 AND id NOT LIKE 'CUSTOM-%'
                 AND id NOT LIKE 'LOCAL-%'"""
        )
        conn.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_attack_vectors_global_source_identifier
               ON attack_vectors(LOWER(source),UPPER(source_identifier))
               WHERE assessment_id IS NULL AND source_identifier IS NOT NULL
                 AND TRIM(source_identifier)<>''"""
        )

    @staticmethod
    def _migrate_attack_case_storage(conn: sqlite3.Connection) -> None:
        """Move target-aggregated carts into LEGACY_AGGREGATED cases."""
        attack_case_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(attack_cases)")
        }
        if "entry_node_ids_json" not in attack_case_columns:
            conn.execute(
                "ALTER TABLE attack_cases ADD COLUMN entry_node_ids_json "
                "TEXT NOT NULL DEFAULT '[]'"
            )
            for row in conn.execute(
                "SELECT id,entry_node_id,legacy_entry_node_ids_json FROM attack_cases"
            ):
                entry_ids = (
                    [str(row["entry_node_id"])] if row["entry_node_id"] is not None
                    else load_json(row["legacy_entry_node_ids_json"], [])
                )
                conn.execute(
                    "UPDATE attack_cases SET entry_node_ids_json=? WHERE id=?",
                    (dump_json(entry_ids), row["id"]),
                )

        cart_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(shopping_carts)")
        }
        candidate_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(candidate_vectors)")
        }
        required_cart = {"attack_case_id", "entry_node_id", "context_status"}
        required_candidate = {"attack_case_id", "entry_node_id", "context_status"}
        if required_cart <= cart_columns and required_candidate <= candidate_columns:
            return

        # Remove incomplete migration artifacts inside the caller's transaction.
        conn.execute("DROP TABLE IF EXISTS cart_items_case_v2")
        conn.execute("DROP TABLE IF EXISTS candidate_vectors_case_v2")
        conn.execute("DROP TABLE IF EXISTS shopping_carts_case_v2")
        conn.execute(
            "DELETE FROM attack_cases WHERE case_kind='LEGACY_AGGREGATED'"
        )

        old_carts = [dict(row) for row in conn.execute("SELECT * FROM shopping_carts ORDER BY id")]
        case_by_cart_id: dict[int, int] = {}
        case_by_target: dict[tuple[int, str], int] = {}
        stamp = now_iso()
        for order, cart in enumerate(old_carts):
            assessment_id = int(cart["assessment_id"])
            target_id = str(cart["target_node_id"])
            related_entries: set[str] = set()
            for row in conn.execute(
                "SELECT related_entry_ids_json FROM cart_items WHERE cart_id=?",
                (cart["id"],),
            ):
                related_entries.update(
                    str(value) for value in load_json(row["related_entry_ids_json"], [])
                    if str(value) and str(value) != target_id
                )
            for row in conn.execute(
                """SELECT entry_node_ids_json FROM candidate_vectors
                   WHERE assessment_id=? AND target_node_id=?""",
                (assessment_id, target_id),
            ):
                related_entries.update(
                    str(value) for value in load_json(row["entry_node_ids_json"], [])
                    if str(value) and str(value) != target_id
                )
            existing_node_ids = {
                str(row["id"])
                for row in conn.execute(
                    "SELECT id FROM dfd_nodes WHERE assessment_id=?", (assessment_id,)
                )
            }
            related_entries.intersection_update(existing_node_ids)
            cursor = conn.execute(
                """INSERT INTO attack_cases(
                       assessment_id,name,entry_node_id,target_node_id,intended_effect,
                       rationale,actor_snapshot_json,path_mode,path_rationale,
                       path_edge_ids_json,legacy_entry_node_ids_json,case_kind,status,
                       sort_order,created_at,updated_at
                   ) VALUES(?,?,NULL,?,'',?,'{}','LEGACY_AGGREGATED',?,'[]',?,
                            'LEGACY_AGGREGATED','LEGACY_REVIEW_REQUIRED',?,?,?)""",
                (
                    assessment_id,
                    f"Legacy aggregate: {cart['name']}",
                    target_id,
                    "Migrated from a target-aggregated shopping cart; select one entry point and reconfirm before treating this as an explicit attack case.",
                    "The historical DFD path and entry set were aggregated and are retained only as legacy evidence.",
                    dump_json(sorted(related_entries)),
                    order,
                    stamp,
                    stamp,
                ),
            )
            case_id = int(cursor.lastrowid)
            case_by_cart_id[int(cart["id"])] = case_id
            case_by_target[(assessment_id, target_id)] = case_id
            for sequence, entry_id in enumerate(sorted(related_entries)):
                conn.execute(
                    """INSERT OR IGNORE INTO attack_case_nodes(
                           attack_case_id,node_id,sequence_order,role
                       ) VALUES(?,?,?,'LEGACY_ENTRY')""",
                    (case_id, entry_id, sequence),
                )
            if target_id in existing_node_ids:
                conn.execute(
                    """INSERT OR IGNORE INTO attack_case_nodes(
                           attack_case_id,node_id,sequence_order,role
                       ) VALUES(?,?,?,'TARGET')""",
                    (case_id, target_id, len(related_entries)),
                )

        conn.execute(
            """CREATE TABLE candidate_vectors_case_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                attack_case_id INTEGER REFERENCES attack_cases(id) ON DELETE CASCADE,
                entry_node_id TEXT,
                target_node_id TEXT NOT NULL,
                attack_vector_id TEXT NOT NULL REFERENCES attack_vectors(id),
                entry_node_ids_json TEXT NOT NULL DEFAULT '[]',
                related_node_ids_json TEXT NOT NULL DEFAULT '[]',
                path_node_ids_json TEXT NOT NULL DEFAULT '[]',
                mapping_evidence_json TEXT NOT NULL DEFAULT '[]',
                context_status TEXT NOT NULL DEFAULT 'EXPLICIT_CASE'
                    CHECK (context_status IN ('EXPLICIT_CASE','LEGACY_AGGREGATED')),
                UNIQUE (attack_case_id,attack_vector_id)
            )"""
        )
        conn.execute(
            """CREATE TABLE shopping_carts_case_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                attack_case_id INTEGER REFERENCES attack_cases(id) ON DELETE CASCADE,
                entry_node_id TEXT,
                target_node_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'DRAFT'
                    CHECK (status IN ('DRAFT','READY','REVIEWED')),
                context_status TEXT NOT NULL DEFAULT 'EXPLICIT_CASE'
                    CHECK (context_status IN ('EXPLICIT_CASE','LEGACY_AGGREGATED')),
                UNIQUE (attack_case_id)
            )"""
        )
        conn.execute(
            """CREATE TABLE cart_items_case_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cart_id INTEGER NOT NULL REFERENCES shopping_carts_case_v2(id) ON DELETE CASCADE,
                attack_vector_id TEXT NOT NULL REFERENCES attack_vectors(id),
                candidate_id INTEGER REFERENCES candidate_vectors_case_v2(id) ON DELETE SET NULL,
                item_source TEXT NOT NULL DEFAULT 'AUTO',
                related_entry_ids_json TEXT NOT NULL DEFAULT '[]',
                related_node_ids_json TEXT NOT NULL DEFAULT '[]',
                mapping_evidence_json TEXT NOT NULL DEFAULT '[]',
                addition_reason TEXT NOT NULL DEFAULT '',
                review_status TEXT NOT NULL DEFAULT 'UNREVIEWED'
                    CHECK (review_status IN ('UNREVIEWED','PLAUSIBLE','ELIMINATED')),
                decision_reason TEXT NOT NULL DEFAULT '',
                llm_plausibility_json TEXT,
                factor_values_json TEXT NOT NULL DEFAULT '{}',
                factor_reasons_json TEXT NOT NULL DEFAULT '{}',
                llm_risk_json TEXT,
                risk_score REAL,
                risk_level TEXT,
                calculation_trace_json TEXT NOT NULL DEFAULT '{}',
                risk_review_status TEXT NOT NULL DEFAULT 'UNASSESSED'
                    CHECK (risk_review_status IN ('UNASSESSED','LLM_COMPLETED','USER_REVIEWED','USER_MODIFIED','NEEDS_REVIEW')),
                UNIQUE (cart_id,attack_vector_id)
            )"""
        )

        for cart in old_carts:
            conn.execute(
                """INSERT INTO shopping_carts_case_v2(
                       id,assessment_id,attack_case_id,entry_node_id,target_node_id,
                       name,description,status,context_status
                   ) VALUES(?,?,?,NULL,?,?,?,?,'LEGACY_AGGREGATED')""",
                (
                    cart["id"], cart["assessment_id"],
                    case_by_cart_id[int(cart["id"])], cart["target_node_id"],
                    cart["name"], cart["description"], cart["status"],
                ),
            )
        for candidate in conn.execute("SELECT * FROM candidate_vectors ORDER BY id"):
            case_id = case_by_target.get(
                (int(candidate["assessment_id"]), str(candidate["target_node_id"]))
            )
            conn.execute(
                """INSERT INTO candidate_vectors_case_v2(
                       id,assessment_id,attack_case_id,entry_node_id,target_node_id,
                       attack_vector_id,entry_node_ids_json,related_node_ids_json,
                       path_node_ids_json,mapping_evidence_json,context_status
                   ) VALUES(?,?,?,NULL,?,?,?,?,?,?,'LEGACY_AGGREGATED')""",
                (
                    candidate["id"], candidate["assessment_id"], case_id,
                    candidate["target_node_id"], candidate["attack_vector_id"],
                    candidate["entry_node_ids_json"], candidate["related_node_ids_json"],
                    candidate["path_node_ids_json"], candidate["mapping_evidence_json"],
                ),
            )
        conn.execute(
            """INSERT INTO cart_items_case_v2(
                   id,cart_id,attack_vector_id,candidate_id,item_source,
                   related_entry_ids_json,related_node_ids_json,mapping_evidence_json,
                   addition_reason,review_status,decision_reason,llm_plausibility_json,
                   factor_values_json,factor_reasons_json,llm_risk_json,risk_score,
                   risk_level,calculation_trace_json,risk_review_status)
               SELECT id,cart_id,attack_vector_id,candidate_id,item_source,
                      related_entry_ids_json,related_node_ids_json,mapping_evidence_json,
                      addition_reason,review_status,decision_reason,llm_plausibility_json,
                      factor_values_json,factor_reasons_json,llm_risk_json,risk_score,
                      risk_level,calculation_trace_json,risk_review_status
               FROM cart_items"""
        )
        conn.execute("DROP TABLE cart_items")
        conn.execute("DROP TABLE candidate_vectors")
        conn.execute("DROP TABLE shopping_carts")
        conn.execute(
            "ALTER TABLE candidate_vectors_case_v2 RENAME TO candidate_vectors"
        )
        conn.execute(
            "ALTER TABLE shopping_carts_case_v2 RENAME TO shopping_carts"
        )
        conn.execute("ALTER TABLE cart_items_case_v2 RENAME TO cart_items")
        conn.execute(
            """CREATE INDEX IF NOT EXISTS idx_candidate_vectors_case
               ON candidate_vectors(attack_case_id,attack_vector_id)"""
        )
        conn.execute(
            """CREATE INDEX IF NOT EXISTS idx_shopping_carts_case
               ON shopping_carts(attack_case_id)"""
        )

    def _seed(self, conn: sqlite3.Connection) -> None:
        flow_rows = []
        level_sort_order = defaultdict(int)
        for level, flow_id, name, source_id, target_id, status, auto, active, notes in DFD_FLOW_TEMPLATES:
            level_sort_order[level] += 1
            condition_key = DFD_FLOW_AUTO_CONDITIONS.get((level, flow_id), "")
            if auto and (not condition_key or status != "APPROVED"):
                raise RuntimeError(
                    "automatic DFD flow must be APPROVED and name an evidence condition: "
                    f"level={level}, id={flow_id}"
                )
            flow_rows.append(
                (
                    level,
                    flow_id,
                    name,
                    source_id,
                    target_id,
                    status,
                    int(auto),
                    condition_key,
                    int(active),
                    notes,
                    level_sort_order[level],
                )
            )
        conn.execute(
            """INSERT INTO km_releases(id,name,description,active) VALUES(1,?,?,1)
               ON CONFLICT(id) DO UPDATE SET
                   name=excluded.name,
                   description=excluded.description,
                   active=excluded.active""",
            ("Cloud-Native KM Seed v0.1", "cloud_db의 Kubernetes/containerd 자산-ATT&CK 매핑을 정리한 CloudTARA 초기 데이터"),
        )
        conn.executemany(
            """INSERT INTO asset_types(id,name,group_name,dfd_kind,description,sort_order)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                   name=excluded.name,
                   group_name=excluded.group_name,
                   dfd_kind=excluded.dfd_kind,
                   description=excluded.description,
                   sort_order=excluded.sort_order""",
            ASSET_TYPES,
        )
        # Synchronize bundled release-1 catalog rows in dependency order.
        curated_flow_keys = {(level, flow_id) for level, flow_id, *_ in DFD_FLOW_TEMPLATES}
        stale_flow_keys = [
            (row["level"], row["id"])
            for row in conn.execute(
                "SELECT level,id FROM dfd_flow_templates WHERE km_release_id=1"
            )
            if (row["level"], row["id"]) not in curated_flow_keys
        ]
        conn.executemany(
            "DELETE FROM dfd_flow_templates WHERE km_release_id=1 AND level=? AND id=?",
            stale_flow_keys,
        )
        curated_element_keys = {
            (level, asset_type_id)
            for level, asset_type_id, _parent_id, _sort_order in DFD_ELEMENT_TEMPLATES
        }
        stale_element_keys = [
            (row["level"], row["asset_type_id"])
            for row in conn.execute(
                "SELECT level,asset_type_id FROM dfd_element_templates WHERE km_release_id=1"
            )
            if (row["level"], row["asset_type_id"]) not in curated_element_keys
        ]
        conn.executemany(
            """DELETE FROM dfd_element_templates
               WHERE km_release_id=1 AND level=? AND asset_type_id=?""",
            stale_element_keys,
        )
        conn.executemany(
            """INSERT INTO dfd_element_templates(
                   km_release_id,level,asset_type_id,parent_asset_type_id,sort_order
               ) VALUES(1,?,?,?,?)
               ON CONFLICT(km_release_id,level,asset_type_id) DO UPDATE SET
                   parent_asset_type_id=excluded.parent_asset_type_id,
                   sort_order=excluded.sort_order""",
            DFD_ELEMENT_TEMPLATES,
        )
        conn.executemany(
            """INSERT INTO dfd_flow_templates(
                   km_release_id,level,id,name,source_asset_type_id,target_asset_type_id,
                   review_status,auto_instantiation,condition_key,active,notes,sort_order
               ) VALUES(1,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(km_release_id,level,id) DO UPDATE SET
                   name=excluded.name,
                   source_asset_type_id=excluded.source_asset_type_id,
                   target_asset_type_id=excluded.target_asset_type_id,
                   review_status=excluded.review_status,
                   auto_instantiation=excluded.auto_instantiation,
                   condition_key=excluded.condition_key,
                   active=excluded.active,
                   notes=excluded.notes,
                   sort_order=excluded.sort_order""",
            flow_rows,
        )
        conn.executemany(
            """INSERT OR IGNORE INTO attack_vectors(
                   id,name,description,prerequisite,source,source_identifier,reference_url
               ) VALUES(?,?,?,NULL,'MITRE ATT&CK',?,?)""",
            [(av_id, name, desc, av_id, f"https://attack.mitre.org/techniques/{av_id.replace('.', '/')}/") for av_id, name, desc in ATTACK_VECTORS],
        )
        conn.executemany(
            "INSERT OR IGNORE INTO countermeasures(id,name,description,source,reference_url) VALUES(?,?,?,'MITRE ATT&CK',?)",
            [(cm_id, name, desc, f"https://attack.mitre.org/mitigations/{cm_id}/") for cm_id, name, desc in COUNTERMEASURES],
        )
        for av_id, mappings in AV_COUNTERMEASURE_SEED.items():
            conn.executemany(
                """INSERT OR IGNORE INTO av_countermeasure_mappings(
                       km_release_id,av_id,cm_id,effect,confidence,rationale,review_status
                   ) VALUES(1,?,?,?,'LOW',?,'REVIEW_REQUIRED')""",
                [(av_id, cm_id, effect, KM_SEED_RATIONALE) for cm_id, effect in mappings],
            )
        for asset_id, vector_ids in MAPPINGS.items():
            conn.executemany(
                "INSERT OR IGNORE INTO asset_attack_vectors(km_release_id,asset_type_id,attack_vector_id,mapping_note) VALUES(1,?,?,?)",
                [(asset_id, vector_id, f"{asset_id} 자산과 {vector_id}의 초기 KM 매핑") for vector_id in vector_ids],
            )
        conn.execute("UPDATE risk_models SET active=0 WHERE id IN ('PR20-WEIGHTED-SUM','PR20-STANDARD-PRODUCT')")
        for model in RISK_MODELS:
            conn.execute(
                """INSERT INTO risk_models(
                       id,name,description,method,decimals,bands_json,source_note,basis,
                       formula_text,formula_json,score_min,score_max,sort_order,active,
                       assessment_id,model_kind
                    ) VALUES(?,?,?,?,?,'[]',?,?,?,?,?,?,?,1,NULL,'BUILTIN')
                    ON CONFLICT(id) DO UPDATE SET
                       name=excluded.name,
                       description=excluded.description,
                       source_note=excluded.source_note,
                       sort_order=excluded.sort_order,
                       active=1,
                       assessment_id=NULL,
                       model_kind='BUILTIN'""",
                (
                    model["id"], model["name"], model["description"], model["method"], model["decimals"],
                    model["source_note"], model["basis"], model["formula_text"], dump_json(model["formula"]),
                    model["score_min"], model["score_max"], model["sort_order"],
                ),
            )
            for order, (code, name, question, weight, levels) in enumerate(model["factors"]):
                conn.execute(
                    """INSERT INTO risk_factors(
                           model_id,code,name,factor_group,question,weight,levels_json,sort_order
                       ) VALUES(?,?,?,?,?,?,?,?)
                       ON CONFLICT(model_id,code) DO UPDATE SET
                           name=excluded.name,
                           factor_group=excluded.factor_group,
                           question=excluded.question,
                           sort_order=excluded.sort_order""",
                    (
                        model["id"], code, name, model.get("factor_groups", {}).get(code, ""),
                        question, weight, dump_json(levels), order,
                    ),
                )
                # Refresh labels only when the stored numeric scale matches V1.
                stored = conn.execute(
                    "SELECT weight,levels_json FROM risk_factors WHERE model_id=? AND code=?",
                    (model["id"], code),
                ).fetchone()
                stored_levels = load_json(stored["levels_json"], []) if stored else []
                try:
                    stored_values = [float(level["value"]) for level in stored_levels]
                    seed_values = [float(level["value"]) for level in levels]
                except (KeyError, TypeError, ValueError):
                    stored_values = []
                    seed_values = [float(level["value"]) for level in levels]
                if stored_values == seed_values and math.isclose(float(stored["weight"]), float(weight)):
                    conn.execute(
                        "UPDATE risk_factors SET levels_json=? WHERE model_id=? AND code=?",
                        (dump_json(levels), model["id"], code),
                    )

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row else None

    @staticmethod
    def _assessment_dict(row: sqlite3.Row) -> dict[str, Any]:
        assessment = dict(row)
        assessment.pop("owner_id", None)
        assessment.pop("base_dfd_initialized", None)
        assessment.pop("base_dfd_flows_initialized", None)
        profile = load_json(assessment.pop("scope_profile_json", "{}"), {})
        assessment["scope_profile"] = profile if isinstance(profile, dict) else {}
        assessment["scope_missing_fields"] = scope_missing_fields(assessment)
        assessment["scope_ready"] = not assessment["scope_missing_fields"]
        assessment["external_llm_allowed"] = bool(assessment.get("external_llm_allowed"))
        return assessment

    @staticmethod
    def _collection_run_dict(row: sqlite3.Row) -> dict[str, Any]:
        run = dict(row)
        run["summary"] = load_json(run.pop("summary_json"), {})
        run["warnings"] = load_json(run.pop("warnings_json"), [])
        run["proposal"] = load_json(run.pop("proposal_json"), {})
        return run

    @staticmethod
    def _owner_id(owner_id: str | None) -> str:
        if owner_id is None:
            return LEGACY_OWNER_ID
        if not isinstance(owner_id, str):
            raise ValueError("owner_id must be a string")
        normalized = owner_id.strip()
        if not normalized or len(normalized) > 200:
            raise ValueError("owner_id must contain between 1 and 200 characters")
        return normalized

    @staticmethod
    def _catalog_level(level: int | None) -> int | None:
        if level is None:
            return None
        if isinstance(level, bool) or level not in (0, 1):
            raise ValueError("DFD catalog level must be 0 or 1")
        return int(level)

    @staticmethod
    def _catalog_elements(
        conn: sqlite3.Connection,
        km_release_id: int,
        level: int | None = None,
    ) -> list[dict[str, Any]]:
        params: list[Any] = [km_release_id]
        level_clause = ""
        if level is not None:
            level_clause = " AND det.level=?"
            params.append(level)
        return [
            dict(row)
            for row in conn.execute(
                f"""SELECT det.km_release_id,det.level,det.asset_type_id,
                           det.parent_asset_type_id,det.sort_order,
                           at.name,at.group_name,at.dfd_kind,at.description,
                           parent.name AS parent_name
                    FROM dfd_element_templates det
                    JOIN asset_types at ON at.id=det.asset_type_id
                    LEFT JOIN asset_types parent ON parent.id=det.parent_asset_type_id
                    WHERE det.km_release_id=?{level_clause}
                    ORDER BY det.level,det.sort_order,at.name,det.asset_type_id""",
                params,
            )
        ]

    @staticmethod
    def _catalog_flows(
        conn: sqlite3.Connection,
        km_release_id: int,
        level: int | None = None,
        *,
        active_only: bool = True,
    ) -> list[dict[str, Any]]:
        params: list[Any] = [km_release_id]
        clauses = []
        if level is not None:
            clauses.append("dft.level=?")
            params.append(level)
        if active_only:
            clauses.append("dft.active=1")
        suffix = "" if not clauses else " AND " + " AND ".join(clauses)
        flows = []
        for row in conn.execute(
            f"""SELECT dft.km_release_id,dft.level,dft.id,dft.name,
                       dft.source_asset_type_id,dft.target_asset_type_id,
                       source.name AS source_name,target.name AS target_name,
                       dft.review_status,dft.auto_instantiation,dft.condition_key,
                       dft.active,dft.notes,dft.sort_order
                FROM dfd_flow_templates dft
                JOIN asset_types source ON source.id=dft.source_asset_type_id
                JOIN asset_types target ON target.id=dft.target_asset_type_id
                WHERE dft.km_release_id=?{suffix}
                ORDER BY dft.level,dft.sort_order,dft.id""",
            params,
        ):
            flow = dict(row)
            flow["auto_instantiation"] = bool(flow["auto_instantiation"])
            flow["active"] = bool(flow["active"])
            flows.append(flow)
        return flows

    def list_dfd_element_templates(
        self,
        km_release_id: int | None = None,
        level: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return the release-scoped Level 0/1 element catalog without mutation."""
        normalized_level = self._catalog_level(level)
        with closing(self.connect()) as conn:
            release_id = (
                int(km_release_id)
                if km_release_id is not None
                else int(self._active_km_release(conn)["id"])
            )
            return self._catalog_elements(conn, release_id, normalized_level)

    def list_dfd_flow_templates(
        self,
        km_release_id: int | None = None,
        level: int | None = None,
        *,
        active_only: bool = True,
    ) -> list[dict[str, Any]]:
        """Return release-scoped flow templates; inactive audit rows are opt-in."""
        normalized_level = self._catalog_level(level)
        if not isinstance(active_only, bool):
            raise ValueError("active_only must be a boolean")
        with closing(self.connect()) as conn:
            release_id = (
                int(km_release_id)
                if km_release_id is not None
                else int(self._active_km_release(conn)["id"])
            )
            return self._catalog_flows(
                conn,
                release_id,
                normalized_level,
                active_only=active_only,
            )

    @staticmethod
    def _initialize_base_dfd_nodes(
        conn: sqlite3.Connection,
        assessment_id: int,
        km_release_id: int,
    ) -> int:
        elements = [
            dict(row)
            for row in conn.execute(
                """SELECT det.asset_type_id,det.sort_order,
                          at.name,at.dfd_kind,at.description
                   FROM dfd_element_templates det
                   JOIN asset_types at ON at.id=det.asset_type_id
                   WHERE det.km_release_id=? AND det.level=0
                   ORDER BY det.sort_order,det.asset_type_id""",
                (km_release_id,),
            )
        ]
        existing_asset_types = {
            str(row["asset_type_id"])
            for row in conn.execute(
                "SELECT asset_type_id FROM dfd_nodes WHERE assessment_id=?",
                (assessment_id,),
            )
        }
        grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for element in elements:
            grouped[int(BASE_DFD_COLUMNS.get(str(element["asset_type_id"]), 9))].append(element)
        max_rows = max((len(items) for items in grouped.values()), default=1)
        created = 0
        for column, items in grouped.items():
            column_height = (len(items) - 1) * 104
            available_height = (max_rows - 1) * 104
            start_y = 104 + max(0, (available_height - column_height) / 2)
            for index, element in enumerate(items):
                asset_type_id = str(element["asset_type_id"])
                if asset_type_id in existing_asset_types:
                    continue
                properties = {
                    "catalog": {
                        "km_release_id": km_release_id,
                        "level": 0,
                        "element_template_id": asset_type_id,
                        "match_basis": "BASE_CATALOG_INITIALIZATION",
                    }
                }
                conn.execute(
                    """INSERT INTO dfd_nodes(
                           assessment_id,id,name,asset_type_id,dfd_kind,x,y,width,height,
                           description,properties_json,is_entry,is_target,entry_reason,target_reason
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        assessment_id, f"base:0:{asset_type_id}", element["name"], asset_type_id,
                        element["dfd_kind"], 70 + column * 216, start_y + index * 104,
                        172, 66, element["description"], dump_json(properties), 0, 0, "", "",
                    ),
                )
                existing_asset_types.add(asset_type_id)
                created += 1
        conn.execute(
            "UPDATE assessments SET base_dfd_initialized=1 WHERE id=?",
            (assessment_id,),
        )
        return created

    @staticmethod
    def _initialize_base_dfd_flows(
        conn: sqlite3.Connection,
        assessment_id: int,
        km_release_id: int,
    ) -> int:
        node_by_asset_type: dict[str, str] = {}
        for row in conn.execute(
            """SELECT id,asset_type_id FROM dfd_nodes
               WHERE assessment_id=?
               ORDER BY CASE WHEN id LIKE 'base:0:%' THEN 0 ELSE 1 END,id""",
            (assessment_id,),
        ):
            node_by_asset_type.setdefault(str(row["asset_type_id"]), str(row["id"]))

        existing_template_ids: set[str] = set()
        existing_endpoints: set[tuple[str, str]] = set()
        for row in conn.execute(
            """SELECT source_node_id,target_node_id,properties_json
               FROM dfd_edges WHERE assessment_id=?""",
            (assessment_id,),
        ):
            existing_endpoints.add((str(row["source_node_id"]), str(row["target_node_id"])))
            properties = load_json(row["properties_json"], {})
            catalog = properties.get("catalog") if isinstance(properties, dict) else None
            if isinstance(catalog, dict) and clean_text(catalog.get("flow_template_id")):
                existing_template_ids.add(clean_text(catalog["flow_template_id"]))

        flows = conn.execute(
            """SELECT id,name,source_asset_type_id,target_asset_type_id
               FROM dfd_flow_templates
               WHERE km_release_id=? AND level=0 AND active=1 AND review_status='APPROVED'
               ORDER BY sort_order,id""",
            (km_release_id,),
        ).fetchall()
        created = 0
        for flow in flows:
            flow_id = str(flow["id"])
            source_id = node_by_asset_type.get(str(flow["source_asset_type_id"]))
            target_id = node_by_asset_type.get(str(flow["target_asset_type_id"]))
            if not source_id or not target_id:
                continue
            if flow_id in existing_template_ids or (source_id, target_id) in existing_endpoints:
                continue
            properties = {
                "catalog": {
                    "flow_template_id": flow_id,
                    "km_release_id": km_release_id,
                    "level": 0,
                    "match_basis": "BASE_CATALOG_INITIALIZATION",
                    "requires_user_confirmation": False,
                }
            }
            conn.execute(
                """INSERT INTO dfd_edges(
                       assessment_id,id,source_node_id,target_node_id,name,protocol,data_type,properties_json
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    assessment_id, f"base-flow:0:{flow_id}", source_id, target_id,
                    flow["name"], "", "", dump_json(properties),
                ),
            )
            existing_template_ids.add(flow_id)
            existing_endpoints.add((source_id, target_id))
            created += 1
        conn.execute(
            "UPDATE assessments SET base_dfd_flows_initialized=1 WHERE id=?",
            (assessment_id,),
        )
        return created

    def _initialize_existing_base_dfds(self, conn: sqlite3.Connection) -> None:
        assessments = conn.execute(
            """SELECT id,km_release_id,threat_model_confirmed,
                      base_dfd_initialized,base_dfd_flows_initialized
               FROM assessments
               WHERE base_dfd_initialized=0 OR base_dfd_flows_initialized=0"""
        ).fetchall()
        for assessment in assessments:
            if assessment["threat_model_confirmed"]:
                conn.execute(
                    """UPDATE assessments
                       SET base_dfd_initialized=1,base_dfd_flows_initialized=1
                       WHERE id=?""",
                    (assessment["id"],),
                )
                continue
            assessment_id = int(assessment["id"])
            release_id = int(assessment["km_release_id"])
            if not assessment["base_dfd_initialized"]:
                self._initialize_base_dfd_nodes(conn, assessment_id, release_id)
            if not assessment["base_dfd_flows_initialized"]:
                self._initialize_base_dfd_flows(conn, assessment_id, release_id)

    def touch_browser_session(
        self,
        owner_id: str,
        *,
        ttl_seconds: int = BROWSER_SESSION_TTL_SECONDS,
        refresh_interval_seconds: int = BROWSER_SESSION_REFRESH_INTERVAL_SECONDS,
        create_if_missing: bool = True,
        at: datetime | None = None,
    ) -> dict[str, Any]:
        """Register or refresh an opaque browser owner ID."""
        normalized_owner = self._owner_id(owner_id)
        if normalized_owner == LEGACY_OWNER_ID:
            raise ValueError("the reserved legacy owner cannot be a browser session")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive integer")
        if (
            isinstance(refresh_interval_seconds, bool)
            or not isinstance(refresh_interval_seconds, int)
            or refresh_interval_seconds < BROWSER_SESSION_REFRESH_INTERVAL_SECONDS
        ):
            raise ValueError("refresh_interval_seconds must be an integer of at least 3600")
        if not isinstance(create_if_missing, bool):
            raise ValueError("create_if_missing must be a boolean")

        observed_at = parse_session_utc_iso(session_utc_iso(at or datetime.now(timezone.utc)))
        observed_text = session_utc_iso(observed_at)

        def result_for(status: str, stored: dict[str, Any] | None = None) -> dict[str, Any]:
            source = stored or {}
            return {
                "status": status,
                "created_at": source.get("created_at"),
                "last_seen_at": source.get("last_seen_at"),
                "expires_at": source.get("expires_at"),
                "expired_at": source.get("expired_at"),
            }

        def mutation_needed(row: sqlite3.Row | None) -> bool:
            if row is None:
                return create_if_missing
            stored = dict(row)
            if stored.get("expired_at"):
                return False
            expires_at = parse_session_utc_iso(stored["expires_at"])
            if expires_at <= observed_at:
                return True
            last_seen_at = parse_session_utc_iso(stored["last_seen_at"])
            return observed_at - last_seen_at >= timedelta(seconds=refresh_interval_seconds)

        # Read-only requests do not acquire SQLite's writer slot.
        with closing(self.connect()) as conn:
            initial_row = conn.execute(
                "SELECT * FROM browser_sessions WHERE owner_id=?", (normalized_owner,)
            ).fetchone()
        if not mutation_needed(initial_row):
            if initial_row is None:
                return result_for("missing")
            initial = dict(initial_row)
            return result_for("expired" if initial.get("expired_at") else "active", initial)

        # Re-read after acquiring the writer lock.
        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM browser_sessions WHERE owner_id=?", (normalized_owner,)
                ).fetchone()
                if row is None:
                    if create_if_missing:
                        expires_text = session_utc_iso(observed_at + timedelta(seconds=ttl_seconds))
                        conn.execute(
                            """INSERT INTO browser_sessions(
                                   owner_id,created_at,last_seen_at,expires_at,expired_at
                               ) VALUES(?,?,?,?,NULL)""",
                            (normalized_owner, observed_text, observed_text, expires_text),
                        )
                        result = result_for(
                            "new",
                            {
                                "created_at": observed_text,
                                "last_seen_at": observed_text,
                                "expires_at": expires_text,
                                "expired_at": None,
                            },
                        )
                    else:
                        result = result_for("missing")
                else:
                    stored = dict(row)
                    if stored.get("expired_at"):
                        result = result_for("expired", stored)
                    else:
                        expires_at = parse_session_utc_iso(stored["expires_at"])
                        if expires_at <= observed_at:
                            conn.execute(
                                "UPDATE browser_sessions SET expired_at=? WHERE owner_id=? AND expired_at IS NULL",
                                (observed_text, normalized_owner),
                            )
                            stored["expired_at"] = observed_text
                            result = result_for("expired", stored)
                        else:
                            last_seen_at = parse_session_utc_iso(stored["last_seen_at"])
                            refresh_due = (
                                observed_at - last_seen_at
                                >= timedelta(seconds=refresh_interval_seconds)
                            )
                            if refresh_due:
                                expires_text = session_utc_iso(
                                    observed_at + timedelta(seconds=ttl_seconds)
                                )
                                conn.execute(
                                    """UPDATE browser_sessions
                                       SET last_seen_at=?,expires_at=?
                                       WHERE owner_id=? AND expired_at IS NULL""",
                                    (observed_text, expires_text, normalized_owner),
                                )
                                stored["last_seen_at"] = observed_text
                                stored["expires_at"] = expires_text
                            result = result_for("active", stored)
                conn.commit()
                return result
            except Exception:
                conn.rollback()
                raise

    @classmethod
    def _require_owned_assessment(
        cls,
        conn: sqlite3.Connection,
        assessment_id: int,
        owner_id: str | None,
        columns: str = "a.*",
    ) -> sqlite3.Row:
        row = conn.execute(
            f"SELECT {columns} FROM assessments a WHERE a.id=? AND a.owner_id=?",
            (assessment_id, cls._owner_id(owner_id)),
        ).fetchone()
        if not row:
            # Do not reveal assessment IDs owned by another session.
            raise LookupError("평가를 찾을 수 없습니다.")
        return row

    @classmethod
    def _require_owned_cart(
        cls, conn: sqlite3.Connection, cart_id: int, owner_id: str | None,
    ) -> sqlite3.Row:
        row = conn.execute(
            """SELECT sc.* FROM shopping_carts sc
               JOIN assessments a ON a.id=sc.assessment_id
               WHERE sc.id=? AND a.owner_id=?""",
            (cart_id, cls._owner_id(owner_id)),
        ).fetchone()
        if not row:
            raise LookupError("쇼핑 카트를 찾을 수 없습니다.")
        if row["context_status"] == "LEGACY_AGGREGATED":
            raise ValueError(
                "기존 Target 집계형 쇼핑 카트는 읽기 전용입니다. "
                "Attack Case별 Entry/Target을 다시 지정·확정해 주세요."
            )
        return row

    @classmethod
    def _require_owned_item(
        cls, conn: sqlite3.Connection, item_id: int, owner_id: str | None,
    ) -> sqlite3.Row:
        row = conn.execute(
            """SELECT ci.*,sc.assessment_id,sc.status AS cart_status,
                      sc.context_status AS cart_context_status
               FROM cart_items ci
               JOIN shopping_carts sc ON sc.id=ci.cart_id
               JOIN assessments a ON a.id=sc.assessment_id
               WHERE ci.id=? AND a.owner_id=?""",
            (item_id, cls._owner_id(owner_id)),
        ).fetchone()
        if not row:
            raise LookupError("쇼핑 카트 항목을 찾을 수 없습니다.")
        if row["cart_context_status"] == "LEGACY_AGGREGATED":
            raise ValueError(
                "기존 Target 집계형 쇼핑 카트는 읽기 전용입니다. "
                "Attack Case별 Entry/Target을 다시 지정·확정해 주세요."
            )
        return row

    @classmethod
    def _require_owned_crra_mapping(
        cls, conn: sqlite3.Connection, item_id: int, owner_id: str | None,
    ) -> sqlite3.Row:
        row = conn.execute(
            """SELECT mi.* FROM crra_mapping_items mi
               JOIN assessments a ON a.id=mi.assessment_id
               WHERE mi.id=? AND a.owner_id=?""",
            (item_id, cls._owner_id(owner_id)),
        ).fetchone()
        if not row:
            raise LookupError("CRRA 매핑 항목을 찾을 수 없습니다.")
        return row

    def bootstrap(self) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            assets = [dict(row) for row in conn.execute("SELECT * FROM asset_types ORDER BY sort_order,name")]
            releases = [dict(row) for row in conn.execute("SELECT * FROM km_releases WHERE active=1 ORDER BY id")]
            catalog_release = self._active_km_release(conn)
            return {
                "asset_types": assets,
                "km_releases": releases,
                "dfd_catalog_release_id": catalog_release["id"],
                "dfd_catalog_elements": self._catalog_elements(conn, catalog_release["id"]),
                "dfd_flow_templates": self._catalog_flows(conn, catalog_release["id"]),
                "risk_models": self._risk_models(conn),
                "risk_reference_approaches": RISK_REFERENCE_APPROACHES,
                "scope_brief_options": {
                    "lifecycle_phases": [{"code": code, "label": label} for code, label in LIFECYCLE_PHASE_OPTIONS],
                    "threat_ranges": [{"code": code, "label": label} for code, label in THREAT_RANGE_OPTIONS],
                    "actor_types": [{"code": code, "label": label} for code, label in ACTOR_TYPE_OPTIONS],
                    "capability_tags": [{"code": code, "label": label} for code, label in CAPABILITY_TAG_OPTIONS],
                    "attack_objectives": [{"code": code, "label": label} for code, label in ATTACK_OBJECTIVE_OPTIONS],
                    "knowledge_states": [{"code": code, "label": label} for code, label in KNOWLEDGE_STATE_OPTIONS],
                    "modeling_methods": [{"code": code, "label": label} for code, label in MODELING_METHOD_OPTIONS],
                },
            }

    def _risk_models(
        self,
        conn: sqlite3.Connection,
        include_model_id: str | None = None,
        assessment_id: int | None = None,
    ) -> list[dict[str, Any]]:
        models = []
        if assessment_id is None:
            rows = conn.execute(
                "SELECT * FROM risk_models WHERE assessment_id IS NULL AND active=1 ORDER BY sort_order,name"
            )
        elif include_model_id:
            rows = conn.execute(
                """SELECT * FROM risk_models
                   WHERE (assessment_id IS NULL OR assessment_id=?)
                     AND (active=1 OR id=?)
                   ORDER BY sort_order,name""",
                (assessment_id, include_model_id),
            )
        else:
            rows = conn.execute(
                """SELECT * FROM risk_models
                   WHERE active=1 AND (assessment_id IS NULL OR assessment_id=?)
                   ORDER BY sort_order,name""",
                (assessment_id,),
            )
        for row in rows:
            model = dict(row)
            model["bands"] = load_json(model.pop("bands_json"), [])
            model["formula"] = load_json(model.pop("formula_json"), {})
            model["active"] = bool(model["active"])
            model["factors"] = []
            for factor_row in conn.execute("SELECT * FROM risk_factors WHERE model_id=? ORDER BY sort_order", (model["id"],)):
                factor = dict(factor_row)
                factor["levels"] = load_json(factor.pop("levels_json"), [])
                model["factors"].append(factor)
            models.append(model)
        return models

    def legacy_assessment_count(self) -> int:
        with closing(self.connect()) as conn, conn:
            return int(conn.execute(
                "SELECT COUNT(*) FROM assessments WHERE owner_id=?", (LEGACY_OWNER_ID,)
            ).fetchone()[0])

    def assessment_count(self, owner_id: str | None = None) -> int:
        """Count all assessments, or only those belonging to an explicit owner."""
        with closing(self.connect()) as conn, conn:
            if owner_id is None:
                return int(conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0])
            return int(conn.execute(
                "SELECT COUNT(*) FROM assessments WHERE owner_id=?",
                (self._owner_id(owner_id),),
            ).fetchone()[0])

    def claim_legacy_assessments(self, owner_id: str) -> int:
        normalized_owner = self._owner_id(owner_id)
        if normalized_owner == LEGACY_OWNER_ID:
            raise ValueError("legacy assessments must be claimed by a non-legacy owner")
        with closing(self.connect()) as conn, conn:
            cursor = conn.execute(
                "UPDATE assessments SET owner_id=?,updated_at=? WHERE owner_id=?",
                (normalized_owner, now_iso(), LEGACY_OWNER_ID),
            )
            return int(cursor.rowcount)

    def list_assessments(self, owner_id: str | None = None) -> list[dict[str, Any]]:
        with closing(self.connect()) as conn, conn:
            return [self._assessment_dict(row) for row in conn.execute(
                """SELECT a.*,
                          EXISTS(
                              SELECT 1 FROM attack_cases ac
                              WHERE ac.assessment_id=a.id
                                AND ac.status='LEGACY_REVIEW_REQUIRED'
                          ) AS legacy_case_review_required
                   FROM assessments a WHERE a.owner_id=? ORDER BY a.updated_at DESC""",
                (self._owner_id(owner_id),),
            )]

    def create_assessment(
        self,
        data: dict[str, Any],
        owner_id: str | None = None,
        *,
        max_per_owner: int | None = None,
        max_total: int | None = None,
    ) -> dict[str, Any]:
        required = ["name", "evaluation_target"]
        missing = [field for field in required if not clean_text(data.get(field))]
        if missing:
            raise ValueError("필수 입력값을 확인해 주세요: " + ", ".join(missing))
        for label, limit in (("max_per_owner", max_per_owner), ("max_total", max_total)):
            if limit is not None and (
                isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0
            ):
                raise ValueError(f"{label} must be a positive integer or None")
        normalized_owner = self._owner_id(owner_id)
        stamp = now_iso()
        modeling_method = _normalize_code(
            data.get("modeling_method", "MANUAL_DFD"), MODELING_METHOD_LABELS, "모델링 방식", allow_empty=False,
        )
        lifecycle_code_input = clean_text(data.get("lifecycle_phase_code")).upper()
        if lifecycle_code_input:
            lifecycle_code = _normalize_code(
                lifecycle_code_input, LIFECYCLE_LABELS, "생명주기", allow_empty=False,
            )
            lifecycle_phase = LIFECYCLE_LABELS[lifecycle_code]
        else:
            lifecycle_phase = clean_text(data.get("lifecycle_phase")) or "운영"
            lifecycle_code = LIFECYCLE_CODES_BY_LABEL.get(lifecycle_phase, "OPERATION")
        profile: dict[str, Any] | None = None
        if "scope_profile" in data:
            profile = normalize_scope_profile(data.get("scope_profile"), lifecycle_fallback=lifecycle_code)
        legacy = profile_legacy_fields(profile) if profile else {}
        validate_assessment_text_lengths({**data, **legacy})
        fields = (
            normalized_owner, clean_text(data["name"]), clean_text(data["evaluation_target"]), clean_text(data.get("scope_in")),
            clean_text(data.get("scope_out")), legacy.get("threat_range", clean_text(data.get("threat_range"))),
            legacy.get("lifecycle_phase", lifecycle_phase), legacy.get("actor_type", clean_text(data.get("actor_type"))),
            legacy.get("actor_motivation", clean_text(data.get("actor_motivation"))),
            legacy.get("actor_intent", clean_text(data.get("actor_intent"))),
            legacy.get("actor_capabilities", clean_text(data.get("actor_capabilities"))),
            clean_text(data.get("technical_info")), "CLOUD_NATIVE", modeling_method,
            dump_json(profile) if profile else "{}",
            int(str(data.get("external_llm_allowed", "0")) in {"1", "true", "True"}),
            int(data.get("km_release_id", 1)), 0, 0, stamp, stamp,
        )
        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if max_per_owner is not None:
                    owner_count = int(conn.execute(
                        "SELECT COUNT(*) FROM assessments WHERE owner_id=?", (normalized_owner,)
                    ).fetchone()[0])
                    if owner_count >= max_per_owner:
                        raise AssessmentLimitError("per-owner", max_per_owner)
                if max_total is not None:
                    total_count = int(conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0])
                    if total_count >= max_total:
                        raise AssessmentLimitError("total", max_total)
                cur = conn.execute(
                    """INSERT INTO assessments(
                        owner_id,name,evaluation_target,scope_in,scope_out,threat_range,lifecycle_phase,
                        actor_type,actor_motivation,actor_intent,actor_capabilities,technical_info,
                        domain_profile_code,modeling_method,scope_profile_json,external_llm_allowed,
                        km_release_id,crra_current_step,crra_confirmed,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    fields,
                )
                self._initialize_base_dfd_nodes(
                    conn,
                    int(cur.lastrowid),
                    int(data.get("km_release_id", 1)),
                )
                self._initialize_base_dfd_flows(
                    conn,
                    int(cur.lastrowid),
                    int(data.get("km_release_id", 1)),
                )
                result = self._assessment_dict(
                    conn.execute("SELECT * FROM assessments WHERE id=?", (cur.lastrowid,)).fetchone()
                )
                conn.commit()
                return result
            except Exception:
                conn.rollback()
                raise

    def update_assessment(
        self, assessment_id: int, data: dict[str, Any], owner_id: str | None = None,
    ) -> dict[str, Any]:
        allowed = [
            "name", "evaluation_target", "scope_in", "scope_out", "threat_range", "lifecycle_phase",
            "actor_type", "actor_motivation", "actor_intent", "actor_capabilities", "technical_info",
            "external_llm_allowed", "modeling_method",
        ]
        current = self.get_assessment(assessment_id, owner_id)
        derived_profile_fields = {
            "threat_range", "lifecycle_phase", "actor_type", "actor_motivation",
            "actor_intent", "actor_capabilities",
        }
        if (
            current.get("scope_profile", {}).get("schema_version") == 1
            and "scope_profile" not in data
            and derived_profile_fields.intersection(data)
        ):
            raise ValueError("구조화된 위협 프로필은 Scope Brief 프로필로 수정해 주세요.")
        updates = {field: data[field] for field in allowed if field in data}
        if "modeling_method" in updates:
            updates["modeling_method"] = _normalize_code(
                updates["modeling_method"], MODELING_METHOD_LABELS, "모델링 방식", allow_empty=False,
            )
        profile: dict[str, Any] | None = None
        if "scope_profile" in data:
            current_lifecycle_code = LIFECYCLE_CODES_BY_LABEL.get(clean_text(current.get("lifecycle_phase")), "OPERATION")
            profile = normalize_scope_profile(data.get("scope_profile"), lifecycle_fallback=current_lifecycle_code)
            updates.update(profile_legacy_fields(profile))
        merged = {**current, **updates}
        if profile is not None:
            merged["scope_profile"] = profile
        required = ["name", "evaluation_target"]
        missing = [field for field in required if not clean_text(merged.get(field))]
        if missing:
            raise ValueError("필수 입력값을 확인해 주세요: " + ", ".join(missing))
        validate_assessment_text_lengths(updates)
        if current.get("threat_model_confirmed"):
            incomplete_scope = scope_missing_fields(merged)
            if incomplete_scope:
                raise ValueError("확정된 평가의 Scope Brief 필수값은 비울 수 없습니다: " + ", ".join(incomplete_scope))
        assignments, values = [], []
        changed_fields: set[str] = set()
        for field, value in updates.items():
            normalized_value: Any = (
                int(str(value) in {"1", "true", "True"})
                if field == "external_llm_allowed"
                else clean_text(value)
            )
            current_value: Any = (
                int(bool(current.get(field)))
                if field == "external_llm_allowed"
                else clean_text(current.get(field))
            )
            if normalized_value == current_value:
                continue
            assignments.append(f"{field}=?")
            values.append(normalized_value)
            changed_fields.add(field)
        if profile is not None and profile != current.get("scope_profile"):
            assignments.append("scope_profile_json=?")
            values.append(dump_json(profile))
            changed_fields.add("scope_profile")
        if assignments:
            values.extend([now_iso(), assessment_id])
            with closing(self.connect()) as conn, conn:
                self._require_owned_assessment(conn, assessment_id, owner_id)
                conn.execute(f"UPDATE assessments SET {','.join(assignments)},updated_at=? WHERE id=?", values)
                # Keep completed results when only the scope JSON format changes.
                context_fields = set(allowed) - {"name", "external_llm_allowed"}
                assessment = conn.execute("SELECT threat_model_confirmed FROM assessments WHERE id=?", (assessment_id,)).fetchone()
                if assessment and assessment["threat_model_confirmed"]:
                    actor_fields = {
                        "actor_type", "actor_motivation", "actor_intent",
                        "actor_capabilities", "scope_profile",
                    }
                    if actor_fields.intersection(changed_fields):
                        updated_assessment = conn.execute(
                            "SELECT * FROM assessments WHERE id=?", (assessment_id,)
                        ).fetchone()
                        conn.execute(
                            """UPDATE attack_cases SET actor_snapshot_json=?,updated_at=?
                               WHERE assessment_id=? AND case_kind='EXPLICIT'""",
                            (
                                dump_json(self._attack_case_actor_snapshot(updated_assessment)),
                                now_iso(), assessment_id,
                            ),
                        )
                if assessment and assessment["threat_model_confirmed"] and context_fields.intersection(changed_fields):
                    conn.execute(
                        """UPDATE cart_items SET review_status='UNREVIEWED',decision_reason='',factor_values_json='{}',
                           factor_reasons_json='{}',llm_plausibility_json=NULL,llm_risk_json=NULL,
                           risk_score=NULL,risk_level=NULL,calculation_trace_json='{}',
                           risk_review_status='UNASSESSED'
                           WHERE cart_id IN (
                               SELECT id FROM shopping_carts
                               WHERE assessment_id=? AND context_status='EXPLICIT_CASE'
                           )""",
                        (assessment_id,),
                    )
                    conn.execute(
                        """UPDATE shopping_carts SET status='READY'
                           WHERE assessment_id=? AND status='REVIEWED'
                             AND context_status='EXPLICIT_CASE'""",
                        (assessment_id,),
                    )
                    has_explicit = conn.execute(
                        """SELECT 1 FROM shopping_carts
                           WHERE assessment_id=? AND context_status='EXPLICIT_CASE' LIMIT 1""",
                        (assessment_id,),
                    ).fetchone()
                    has_draft = conn.execute(
                        """SELECT 1 FROM shopping_carts
                           WHERE assessment_id=? AND status='DRAFT'
                             AND context_status='EXPLICIT_CASE' LIMIT 1""",
                        (assessment_id,),
                    ).fetchone()
                    # Keep migrated aggregate results until case reconfirmation.
                    if has_explicit:
                        self._invalidate_matrix(conn, assessment_id, 3 if has_draft else 4)
        return self.get_assessment(assessment_id, owner_id)

    def get_assessment(self, assessment_id: int, owner_id: str | None = None) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            return self._assessment_dict(
                self._require_owned_assessment(conn, assessment_id, owner_id)
            )

    @staticmethod
    def _duplicated_dfd_properties(raw: Any) -> str:
        """Remove assessment-specific collector metadata from a copied DFD."""
        properties = load_json(raw, {})
        if not isinstance(properties, dict):
            return "{}"
        properties.pop("collector", None)
        provenance = properties.get("provenance")
        if isinstance(provenance, dict):
            provenance = dict(provenance)
            provenance.pop("collection_run_id", None)
            if provenance:
                properties["provenance"] = provenance
            else:
                properties.pop("provenance", None)
        return dump_json(properties)

    def duplicate_assessment(
        self,
        assessment_id: int,
        owner_id: str | None = None,
        *,
        name: str | None = None,
        max_per_owner: int | None = None,
        max_total: int | None = None,
    ) -> dict[str, Any]:
        """Copy the Scope Brief and DFD into a fresh, unconfirmed assessment."""
        for label, limit in (("max_per_owner", max_per_owner), ("max_total", max_total)):
            if limit is not None and (
                isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0
            ):
                raise ValueError(f"{label} must be a positive integer or None")
        normalized_owner = self._owner_id(owner_id)
        stamp = now_iso()
        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                source = self._require_owned_assessment(conn, assessment_id, normalized_owner)
                copy_suffix = " 복사본"
                copied_name = clean_text(name) or f"{clean_text(source['name'])[:60 - len(copy_suffix)]}{copy_suffix}"
                validate_assessment_text_lengths({"name": copied_name})
                if max_per_owner is not None:
                    owner_count = int(conn.execute(
                        "SELECT COUNT(*) FROM assessments WHERE owner_id=?", (normalized_owner,)
                    ).fetchone()[0])
                    if owner_count >= max_per_owner:
                        raise AssessmentLimitError("per-owner", max_per_owner)
                if max_total is not None:
                    total_count = int(conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0])
                    if total_count >= max_total:
                        raise AssessmentLimitError("total", max_total)

                cursor = conn.execute(
                    """INSERT INTO assessments(
                           owner_id,name,evaluation_target,scope_in,scope_out,threat_range,lifecycle_phase,
                           actor_type,actor_motivation,actor_intent,actor_capabilities,technical_info,
                           domain_profile_code,modeling_method,scope_profile_json,external_llm_allowed,
                           km_release_id,risk_model_id,threat_model_confirmed,matrix_confirmed,current_step,
                           crra_current_step,crra_confirmed,created_at,updated_at
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,0,0,1,0,0,?,?)""",
                    (
                        normalized_owner, copied_name, source["evaluation_target"], source["scope_in"],
                        source["scope_out"], source["threat_range"], source["lifecycle_phase"],
                        source["actor_type"], source["actor_motivation"], source["actor_intent"],
                        source["actor_capabilities"], source["technical_info"],
                        source["domain_profile_code"], "MANUAL_DFD", source["scope_profile_json"],
                        0, int(source["km_release_id"]), stamp, stamp,
                    ),
                )
                duplicated_id = int(cursor.lastrowid)

                for node in conn.execute(
                    "SELECT * FROM dfd_nodes WHERE assessment_id=? ORDER BY id", (assessment_id,)
                ):
                    conn.execute(
                        """INSERT INTO dfd_nodes(
                               assessment_id,id,name,asset_type_id,dfd_kind,x,y,width,height,description,
                               properties_json,is_entry,is_target,entry_reason,target_reason
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            duplicated_id, node["id"], node["name"], node["asset_type_id"], node["dfd_kind"],
                            node["x"], node["y"], node["width"], node["height"], node["description"],
                            self._duplicated_dfd_properties(node["properties_json"]), node["is_entry"],
                            node["is_target"], node["entry_reason"], node["target_reason"],
                        ),
                    )
                for edge in conn.execute(
                    "SELECT * FROM dfd_edges WHERE assessment_id=? ORDER BY id", (assessment_id,)
                ):
                    conn.execute(
                        """INSERT INTO dfd_edges(
                               assessment_id,id,source_node_id,target_node_id,name,protocol,data_type,properties_json
                           ) VALUES(?,?,?,?,?,?,?,?)""",
                        (
                            duplicated_id, edge["id"], edge["source_node_id"], edge["target_node_id"],
                            edge["name"], edge["protocol"], edge["data_type"],
                            self._duplicated_dfd_properties(edge["properties_json"]),
                        ),
                    )
                conn.execute(
                    """INSERT INTO trust_boundaries(assessment_id,id,name,x,y,width,height)
                       SELECT ?,id,name,x,y,width,height FROM trust_boundaries WHERE assessment_id=?""",
                    (duplicated_id, assessment_id),
                )
                conn.execute(
                    """UPDATE assessments
                       SET base_dfd_initialized=1,base_dfd_flows_initialized=1
                       WHERE id=?""",
                    (duplicated_id,),
                )
                result = self._assessment_dict(
                    conn.execute("SELECT * FROM assessments WHERE id=?", (duplicated_id,)).fetchone()
                )
                conn.commit()
                return result
            except Exception:
                conn.rollback()
                raise

    def delete_assessment(
        self,
        assessment_id: int,
        owner_id: str | None = None,
        *,
        confirm_name: str | None = None,
    ) -> dict[str, Any]:
        """Delete one owned assessment and its assessment-scoped catalog rows."""
        normalized_owner = self._owner_id(owner_id)
        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                source = self._require_owned_assessment(conn, assessment_id, normalized_owner)
                if confirm_name is not None and clean_text(confirm_name) != clean_text(source["name"]):
                    raise ValueError("삭제 확인용 평가 이름이 일치하지 않습니다.")
                local_vectors = [
                    str(row["id"]) for row in conn.execute(
                        "SELECT id FROM attack_vectors WHERE assessment_id=?", (assessment_id,)
                    )
                ]
                local_countermeasures = [
                    str(row["id"]) for row in conn.execute(
                        "SELECT id FROM countermeasures WHERE assessment_id=?", (assessment_id,)
                    )
                ]
                if local_vectors:
                    placeholders = ",".join("?" for _ in local_vectors)
                    conn.execute(
                        f"DELETE FROM asset_attack_vectors WHERE attack_vector_id IN ({placeholders})",
                        local_vectors,
                    )
                    conn.execute(
                        f"DELETE FROM vector_group_members WHERE av_id IN ({placeholders})", local_vectors,
                    )
                    conn.execute(
                        f"DELETE FROM av_countermeasure_mappings WHERE av_id IN ({placeholders})", local_vectors,
                    )
                if local_countermeasures:
                    placeholders = ",".join("?" for _ in local_countermeasures)
                    conn.execute(
                        f"DELETE FROM av_countermeasure_mappings WHERE cm_id IN ({placeholders})",
                        local_countermeasures,
                    )

                deleted = conn.execute(
                    "DELETE FROM assessments WHERE id=? AND owner_id=?", (assessment_id, normalized_owner)
                )
                if deleted.rowcount != 1:
                    raise LookupError("평가를 찾을 수 없습니다.")
                # attack_vectors.assessment_id has no cascade.
                conn.execute("DELETE FROM attack_vectors WHERE assessment_id=?", (assessment_id,))
                # Remove assessment-scoped calculators explicitly to avoid the FK cycle.
                conn.execute("DELETE FROM risk_models WHERE assessment_id=?", (assessment_id,))
                conn.commit()
                return {"ok": True, "id": int(assessment_id), "name": str(source["name"])}
            except Exception:
                conn.rollback()
                raise

    def create_collection_run(
        self,
        assessment_id: int,
        *,
        source_type: str,
        source_digest: str,
        mapper_version: str,
        summary: dict[str, Any] | None = None,
        warnings: list[Any] | None = None,
        proposal: dict[str, Any] | None = None,
        owner_id: str | None = None,
    ) -> dict[str, Any]:
        """Persist a secret-safe DFD proposal, never the source manifests themselves."""
        normalized_source_type = clean_text(source_type).upper()
        normalized_digest = clean_text(source_digest)
        normalized_mapper_version = clean_text(mapper_version)
        if not normalized_source_type or len(normalized_source_type) > 80:
            raise ValueError("source_type must contain between 1 and 80 characters")
        if not normalized_digest or len(normalized_digest) > 256:
            raise ValueError("source_digest must contain between 1 and 256 characters")
        if not normalized_mapper_version or len(normalized_mapper_version) > 120:
            raise ValueError("mapper_version must contain between 1 and 120 characters")

        normalized_summary: dict[str, Any] = {} if summary is None else summary
        normalized_warnings: list[Any] = [] if warnings is None else warnings
        normalized_proposal: dict[str, Any] = {} if proposal is None else proposal
        if not isinstance(normalized_summary, dict):
            raise ValueError("summary must be a JSON object")
        if not isinstance(normalized_warnings, list):
            raise ValueError("warnings must be a JSON array")
        if not isinstance(normalized_proposal, dict):
            raise ValueError("proposal must be a JSON object")

        summary_json = dump_json(normalized_summary)
        warnings_json = dump_json(normalized_warnings)
        proposal_json = dump_json(normalized_proposal)
        stamp = now_iso()
        with closing(self.connect()) as conn, conn:
            self._require_owned_assessment(conn, assessment_id, owner_id, "a.id")
            # Keep a bounded preview history per owner.
            conn.execute(
                """DELETE FROM collection_runs WHERE id IN (
                       SELECT cr.id FROM collection_runs cr
                       JOIN assessments a ON a.id=cr.assessment_id
                       WHERE a.owner_id=? AND cr.status='PREVIEWED'
                       ORDER BY cr.created_at DESC,cr.id DESC
                       LIMIT -1 OFFSET 9
                   )""",
                (self._owner_id(owner_id),),
            )
            cursor = conn.execute(
                """INSERT INTO collection_runs(
                       assessment_id,source_type,source_digest,mapper_version,status,
                       summary_json,warnings_json,proposal_json,created_at,updated_at,applied_at
                   ) VALUES(?,?,?,?,'PREVIEWED',?,?,?,?,?,NULL)""",
                (
                    assessment_id,
                    normalized_source_type,
                    normalized_digest,
                    normalized_mapper_version,
                    summary_json,
                    warnings_json,
                    proposal_json,
                    stamp,
                    stamp,
                ),
            )
            row = conn.execute(
                "SELECT * FROM collection_runs WHERE id=?", (cursor.lastrowid,)
            ).fetchone()
            if not row:
                raise RuntimeError("collection run was not persisted")
            return self._collection_run_dict(row)

    def get_collection_run(
        self, run_id: int, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            row = conn.execute(
                """SELECT cr.* FROM collection_runs cr
                   JOIN assessments a ON a.id=cr.assessment_id
                   WHERE cr.id=? AND a.owner_id=?""",
                (run_id, self._owner_id(owner_id)),
            ).fetchone()
            if not row:
                raise LookupError("collection run not found")
            return self._collection_run_dict(row)

    def mark_collection_run_applied(
        self, run_id: int, owner_id: str | None = None,
    ) -> dict[str, Any]:
        """Return an applied run; PREVIEWED runs become APPLIED only in save_dfd."""
        with closing(self.connect()) as conn, conn:
            row = conn.execute(
                """SELECT cr.* FROM collection_runs cr
                   JOIN assessments a ON a.id=cr.assessment_id
                   WHERE cr.id=? AND a.owner_id=?""",
                (run_id, self._owner_id(owner_id)),
            ).fetchone()
            if not row:
                raise LookupError("collection run not found")
            if row["status"] != "APPLIED":
                raise ValueError("Manifest 초안을 DFD에 반영하고 DFD 저장을 먼저 완료해 주세요.")
            return self._collection_run_dict(row)

    @staticmethod
    def _invalidate_crra(conn: sqlite3.Connection, assessment_id: int) -> None:
        conn.execute("DELETE FROM crra_settings WHERE assessment_id=?", (assessment_id,))
        conn.execute(
            "UPDATE assessments SET crra_current_step=0,crra_confirmed=0,updated_at=? WHERE id=?",
            (now_iso(), assessment_id),
        )

    @staticmethod
    def _invalidate_matrix(conn: sqlite3.Connection, assessment_id: int, current_step: int | None = None) -> None:
        conn.execute("DELETE FROM susceptibility_matrices WHERE assessment_id=?", (assessment_id,))
        CNTaraDB._invalidate_crra(conn, assessment_id)
        if current_step is None:
            conn.execute("UPDATE assessments SET matrix_confirmed=0,updated_at=? WHERE id=?", (now_iso(), assessment_id))
        else:
            conn.execute(
                "UPDATE assessments SET matrix_confirmed=0,current_step=?,updated_at=? WHERE id=?",
                (current_step, now_iso(), assessment_id),
            )

    def save_dfd(
        self, assessment_id: int, data: dict[str, Any], owner_id: str | None = None,
    ) -> None:
        nodes = data.get("nodes") or []
        edges = data.get("edges") or []
        boundaries = data.get("boundaries") or []
        if not isinstance(nodes, list) or not all(isinstance(node, dict) for node in nodes):
            raise ValueError("DFD 구성요소 목록 형식을 확인해 주세요.")
        if not isinstance(edges, list) or not all(isinstance(edge, dict) for edge in edges):
            raise ValueError("데이터 흐름 목록 형식을 확인해 주세요.")
        if not isinstance(boundaries, list) or not all(isinstance(boundary, dict) for boundary in boundaries):
            raise ValueError("신뢰 경계 목록 형식을 확인해 주세요.")
        for node in nodes:
            validate_dfd_node_text_lengths(node)
        collector_run_ids = collector_run_ids_from_dfd([*nodes, *edges])
        node_ids = {str(node.get("id", "")) for node in nodes}
        if "" in node_ids or len(node_ids) != len(nodes):
            raise ValueError("DFD 구성요소 ID가 올바르지 않습니다.")
        edge_ids = {str(edge.get("id", "")) for edge in edges}
        boundary_ids = {str(boundary.get("id", "")) for boundary in boundaries}
        if "" in edge_ids or len(edge_ids) != len(edges):
            raise ValueError("데이터 흐름 ID가 올바르지 않습니다.")
        if "" in boundary_ids or len(boundary_ids) != len(boundaries):
            raise ValueError("신뢰 경계 ID가 올바르지 않습니다.")
        for edge in edges:
            if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
                raise ValueError("데이터 흐름의 출발 또는 도착 구성요소를 확인해 주세요.")
        with closing(self.connect()) as conn, conn:
            # Read and confirm the DFD under one write lock.
            conn.execute("BEGIN IMMEDIATE")
            assessment = self._require_owned_assessment(
                conn, assessment_id, owner_id,
                "a.threat_model_confirmed,a.km_release_id",
            )
            if assessment["threat_model_confirmed"] and not bool(data.get("reset_downstream")):
                raise ValueError("확정된 DFD를 변경하면 이후 CTSA 결과가 초기화됩니다. 다시 편집을 확인해 주세요.")
            asset_kinds = {row["id"]: row["dfd_kind"] for row in conn.execute("SELECT id,dfd_kind FROM asset_types")}
            unknown_assets = [str(node.get("asset_type_id", "")) for node in nodes if node.get("asset_type_id") not in asset_kinds]
            if unknown_assets:
                raise ValueError("DFD 구성요소의 자산 유형을 확인해 주세요: " + ", ".join(unknown_assets))
            release_id = int(assessment["km_release_id"])
            catalog_memberships: set[tuple[int, str]] = set()
            for row in conn.execute(
                "SELECT level,asset_type_id FROM dfd_element_templates WHERE km_release_id=?",
                (release_id,),
            ):
                membership = (int(row["level"]), str(row["asset_type_id"]))
                catalog_memberships.add(membership)

            catalog_levels: set[int] = set()

            def explicit_catalog(item: dict[str, Any]) -> dict[str, Any]:
                properties = item.get("properties")
                if not isinstance(properties, dict):
                    return {}
                catalog = properties.get("catalog")
                return catalog if isinstance(catalog, dict) else {}

            for node in nodes:
                asset_type_id = str(node.get("asset_type_id", ""))
                catalog = explicit_catalog(node)
                if catalog:
                    level = catalog.get("level")
                    if isinstance(level, bool) or not isinstance(level, int) or level not in {0, 1}:
                        raise ValueError("DFD 구성요소의 카탈로그 수준을 확인해 주세요.")
                    catalog_release = catalog.get("km_release_id")
                    if catalog_release is not None and (
                        isinstance(catalog_release, bool)
                        or not isinstance(catalog_release, int)
                        or catalog_release != release_id
                    ):
                        raise ValueError("현재 평가와 다른 KM 릴리스의 DFD 구성요소는 저장할 수 없습니다.")
                    if (level, asset_type_id) not in catalog_memberships:
                        raise ValueError("선택한 구성 수준에 속하지 않는 DFD 구성요소가 있습니다.")
                    catalog_levels.add(level)

            node_asset_types = {
                str(node["id"]): str(node.get("asset_type_id", "")) for node in nodes
            }
            for edge in edges:
                catalog = explicit_catalog(edge)
                flow_template_id = str(catalog.get("flow_template_id", "")).strip()
                if not flow_template_id:
                    continue
                level = catalog.get("level")
                catalog_release = catalog.get("km_release_id")
                if isinstance(level, bool) or not isinstance(level, int) or level not in {0, 1}:
                    raise ValueError("데이터 흐름의 카탈로그 수준을 확인해 주세요.")
                if catalog_release is not None and (
                    isinstance(catalog_release, bool)
                    or not isinstance(catalog_release, int)
                    or catalog_release != release_id
                ):
                    raise ValueError("현재 평가와 다른 KM 릴리스의 데이터 흐름은 저장할 수 없습니다.")
                flow = conn.execute(
                    """SELECT source_asset_type_id,target_asset_type_id
                       FROM dfd_flow_templates
                       WHERE km_release_id=? AND level=? AND id=? AND active=1""",
                    (release_id, level, flow_template_id),
                ).fetchone()
                if not flow:
                    raise ValueError("사용할 수 없는 DFD 데이터 흐름 카탈로그 항목이 있습니다.")
                if (
                    node_asset_types.get(str(edge.get("source", ""))) != flow["source_asset_type_id"]
                    or node_asset_types.get(str(edge.get("target", ""))) != flow["target_asset_type_id"]
                ):
                    raise ValueError("DFD 데이터 흐름의 출발·도착 유형이 카탈로그와 일치하지 않습니다.")
                catalog_levels.add(level)
            if len(catalog_levels) > 1:
                raise ValueError("기본 구성과 상세 구성 요소를 한 DFD에 섞어 저장할 수 없습니다.")
            if collector_run_ids:
                placeholders = ",".join("?" for _ in collector_run_ids)
                owned_run_ids = {
                    int(row["id"])
                    for row in conn.execute(
                        f"SELECT id FROM collection_runs WHERE assessment_id=? AND id IN ({placeholders})",
                        (assessment_id, *sorted(collector_run_ids)),
                    )
                }
                if owned_run_ids != collector_run_ids:
                    raise ValueError("현재 평가에 속하지 않는 Manifest 초안이 포함되어 있습니다.")
            self._invalidate_matrix(conn, assessment_id)
            conn.execute("DELETE FROM shopping_carts WHERE assessment_id=?", (assessment_id,))
            conn.execute("DELETE FROM candidate_vectors WHERE assessment_id=?", (assessment_id,))
            # Replacing the DFD invalidates cases and derived artifacts.
            conn.execute("DELETE FROM attack_cases WHERE assessment_id=?", (assessment_id,))
            conn.execute("DELETE FROM dfd_edges WHERE assessment_id=?", (assessment_id,))
            conn.execute("DELETE FROM trust_boundaries WHERE assessment_id=?", (assessment_id,))
            conn.execute("DELETE FROM dfd_nodes WHERE assessment_id=?", (assessment_id,))
            for node in nodes:
                conn.execute(
                    """INSERT INTO dfd_nodes(
                        assessment_id,id,name,asset_type_id,dfd_kind,x,y,width,height,description,properties_json,
                        is_entry,is_target,entry_reason,target_reason
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        assessment_id, node["id"], str(node.get("name", "구성요소")).strip(), node["asset_type_id"],
                        asset_kinds[node["asset_type_id"]], float(node.get("x", 0)), float(node.get("y", 0)),
                        float(node.get("width", 150)), float(node.get("height", 64)), str(node.get("description", "")),
                        dump_json(node.get("properties", {})), int(bool(node.get("is_entry"))), int(bool(node.get("is_target"))),
                        str(node.get("entry_reason", "")).strip(), str(node.get("target_reason", "")).strip(),
                    ),
                )
            for edge in edges:
                conn.execute(
                    """INSERT INTO dfd_edges(
                           assessment_id,id,source_node_id,target_node_id,name,protocol,data_type,properties_json
                       ) VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        assessment_id, edge["id"], edge["source"], edge["target"],
                        str(edge.get("name", "")), str(edge.get("protocol", "")),
                        str(edge.get("data_type", "")), dump_json(edge.get("properties", {})),
                    ),
                )
            for boundary in boundaries:
                conn.execute(
                    "INSERT INTO trust_boundaries(assessment_id,id,name,x,y,width,height) VALUES(?,?,?,?,?,?,?)",
                    (assessment_id, boundary["id"], str(boundary.get("name", "신뢰 경계")), float(boundary.get("x", 30)), float(boundary.get("y", 30)), float(boundary.get("width", 360)), float(boundary.get("height", 240))),
                )
            if collector_run_ids:
                stamp = now_iso()
                placeholders = ",".join("?" for _ in collector_run_ids)
                conn.execute(
                    f"""UPDATE collection_runs
                           SET status='APPLIED',proposal_json='{{}}',updated_at=?,
                               applied_at=COALESCE(applied_at,?)
                           WHERE assessment_id=? AND id IN ({placeholders})""",
                    (stamp, stamp, assessment_id, *sorted(collector_run_ids)),
                )
                # Remove proposal history after a full graph replacement.
                conn.execute(
                    f"""DELETE FROM collection_runs
                           WHERE assessment_id=? AND status='APPLIED'
                           AND id NOT IN ({placeholders})""",
                    (assessment_id, *sorted(collector_run_ids)),
                )
                modeling_method = "MANIFEST_DFD"
            else:
                conn.execute(
                    "DELETE FROM collection_runs WHERE assessment_id=? AND status='APPLIED'",
                    (assessment_id,),
                )
                modeling_method = "MANUAL_DFD"
            conn.execute(
                """UPDATE assessments
                   SET threat_model_confirmed=0,matrix_confirmed=0,current_step=1,
                       modeling_method=?,updated_at=? WHERE id=?""",
                (modeling_method, now_iso(), assessment_id),
            )

    def save_dfd_edge_layout(
        self, assessment_id: int, items: list[dict[str, Any]], owner_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise ValueError("데이터 흐름 배치 정보 형식을 확인해 주세요.")
        normalized: list[tuple[str, float | int | None, float | None]] = []
        seen_ids: set[str] = set()
        for item in items:
            edge_id = str(item.get("id", "")).strip()
            if not edge_id or edge_id in seen_ids:
                raise ValueError("데이터 흐름 배치 정보의 ID를 확인해 주세요.")
            seen_ids.add(edge_id)
            curve_offset = item.get("curve_offset")
            if curve_offset is not None:
                if isinstance(curve_offset, bool) or not isinstance(curve_offset, (int, float)):
                    raise ValueError("데이터 흐름의 선 휨 값을 확인해 주세요.")
                curve_offset = float(curve_offset)
                if not math.isfinite(curve_offset) or not -180 <= curve_offset <= 180:
                    raise ValueError("데이터 흐름의 선 휨 값은 -180에서 180 사이여야 합니다.")
                if curve_offset.is_integer():
                    curve_offset = int(curve_offset)
            label_t = item.get("label_t")
            if label_t is not None:
                if isinstance(label_t, bool) or not isinstance(label_t, (int, float)):
                    raise ValueError("데이터 흐름 라벨의 위치 값을 확인해 주세요.")
                label_t = float(label_t)
                if not math.isfinite(label_t) or not 0.05 <= label_t <= 0.95:
                    raise ValueError("데이터 흐름 라벨의 위치 값은 0.05에서 0.95 사이여야 합니다.")
            normalized.append((edge_id, curve_offset, label_t))

        with closing(self.connect()) as conn, conn:
            self._require_owned_assessment(conn, assessment_id, owner_id)
            stored = {
                str(row["id"]): row
                for row in conn.execute(
                    "SELECT id,properties_json FROM dfd_edges WHERE assessment_id=?",
                    (assessment_id,),
                )
            }
            missing = [edge_id for edge_id, _, _ in normalized if edge_id not in stored]
            if missing:
                raise LookupError("데이터 흐름을 찾을 수 없습니다.")
            for edge_id, curve_offset, label_t in normalized:
                properties = load_json(stored[edge_id]["properties_json"], {})
                if not isinstance(properties, dict):
                    properties = {}
                layout = properties.get("layout")
                layout = dict(layout) if isinstance(layout, dict) else {}
                if curve_offset is None:
                    layout.pop("curve_offset", None)
                else:
                    layout["curve_offset"] = curve_offset
                if label_t is None:
                    layout.pop("label_t", None)
                else:
                    layout["label_t"] = label_t
                if layout:
                    properties["layout"] = layout
                else:
                    properties.pop("layout", None)
                conn.execute(
                    "UPDATE dfd_edges SET properties_json=? WHERE assessment_id=? AND id=?",
                    (dump_json(properties), assessment_id, edge_id),
                )
            conn.execute(
                "UPDATE assessments SET updated_at=? WHERE id=?",
                (now_iso(), assessment_id),
            )
        return {"ok": True, "updated_count": len(normalized)}

    @staticmethod
    def _reachable(start_ids: list[str], adjacency: dict[str, set[str]]) -> set[str]:
        seen: set[str] = set(start_ids)
        queue = deque(start_ids)
        while queue:
            current = queue.popleft()
            for neighbor in adjacency.get(current, set()):
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append(neighbor)
        return seen

    @staticmethod
    def _shortest_dfd_path(
        entry_node_id: str,
        target_node_id: str,
        edges: list[dict[str, Any]],
        *,
        undirected: bool = False,
    ) -> tuple[list[str], list[str]] | None:
        """Return one deterministic shortest DFD route and its edge IDs."""
        if entry_node_id == target_node_id:
            return None
        adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for index, edge in enumerate(edges):
            source = str(edge.get("source_node_id", edge.get("source", "")))
            target = str(edge.get("target_node_id", edge.get("target", "")))
            if not source or not target:
                continue
            edge_id = str(edge.get("id") or f"dfd-edge-{index}")
            adjacency[source].append((target, edge_id))
            if undirected:
                adjacency[target].append((source, edge_id))
        for values in adjacency.values():
            values.sort(key=lambda value: (value[0], value[1]))
        predecessor: dict[str, tuple[str, str] | None] = {entry_node_id: None}
        queue = deque([entry_node_id])
        while queue:
            current = queue.popleft()
            for neighbor, edge_id in adjacency.get(current, []):
                if neighbor in predecessor:
                    continue
                predecessor[neighbor] = (current, edge_id)
                if neighbor == target_node_id:
                    queue.clear()
                    break
                queue.append(neighbor)
        if target_node_id not in predecessor:
            return None
        node_ids = [target_node_id]
        edge_ids: list[str] = []
        current = target_node_id
        while current != entry_node_id:
            previous = predecessor[current]
            if previous is None:  # pragma: no cover - guarded by the loop condition
                return None
            current, edge_id = previous
            node_ids.append(current)
            edge_ids.append(edge_id)
        node_ids.reverse()
        edge_ids.reverse()
        return node_ids, edge_ids

    @classmethod
    def _threat_model_path_findings(
        cls,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, str]]]:
        """Derive path gaps without turning unused entry points into a hard gate."""
        entries = [node for node in nodes if node.get("is_entry")]
        targets = [node for node in nodes if node.get("is_target")]
        target_ids = {str(node["id"]) for node in targets}
        adjacency: dict[str, set[str]] = defaultdict(set)
        for edge in edges:
            source = edge.get("source_node_id", edge.get("source"))
            target = edge.get("target_node_id", edge.get("target"))
            if source is not None and target is not None:
                adjacency[str(source)].add(str(target))
        return {
            "unreachable_targets": [
                {"node_id": str(node["id"]), "name": str(node["name"])}
                for node in targets
                if not any(
                    str(entry["id"]) != str(node["id"])
                    and str(node["id"]) in cls._reachable([str(entry["id"])], adjacency)
                    for entry in entries
                )
            ],
            "unreachable_entries": [
                {"node_id": str(node["id"]), "name": str(node["name"])}
                for node in entries
                if not any(
                    target_id != str(node["id"])
                    and target_id in cls._reachable([str(node["id"])], adjacency)
                    for target_id in target_ids
                )
            ],
        }

    @staticmethod
    def _asset_attack_vector_rows(
        conn: sqlite3.Connection,
        km_release_id: int,
        asset_type_id: str,
    ) -> list[sqlite3.Row]:
        """Resolve mappings on an asset type or its nearest mapped parent."""
        current_id = asset_type_id
        visited: set[str] = set()
        while current_id and current_id not in visited:
            visited.add(current_id)
            rows = list(
                conn.execute(
                    """SELECT aav.attack_vector_id,av.name,
                              aav.asset_type_id AS matched_asset_type_id,
                              aav.mapping_note
                       FROM asset_attack_vectors aav
                       JOIN attack_vectors av ON av.id=aav.attack_vector_id
                       WHERE aav.km_release_id=? AND aav.asset_type_id=?
                       ORDER BY aav.attack_vector_id""",
                    (km_release_id, current_id),
                )
            )
            if rows:
                return rows
            parent = conn.execute(
                """SELECT parent_asset_type_id
                   FROM dfd_element_templates
                   WHERE km_release_id=? AND asset_type_id=?
                     AND parent_asset_type_id IS NOT NULL
                   ORDER BY level DESC LIMIT 1""",
                (km_release_id, current_id),
            ).fetchone()
            current_id = parent["parent_asset_type_id"] if parent else ""
        return []

    @staticmethod
    def _attack_case_actor_snapshot(assessment: sqlite3.Row) -> dict[str, Any]:
        """Capture the owned Scope Brief used when a case is confirmed."""
        profile = load_json(assessment["scope_profile_json"], {})
        return {
            "actor_type": assessment["actor_type"],
            "motivation": assessment["actor_motivation"],
            "intent": assessment["actor_intent"],
            "capabilities": assessment["actor_capabilities"],
            "scope_profile": profile if isinstance(profile, dict) else {},
        }

    @classmethod
    def _directed_case_scope(
        cls,
        entry_node_id: str,
        target_node_id: str,
        edges: list[dict[str, Any]],
    ) -> tuple[list[str], list[str]] | None:
        """Return every node/edge participating in any directed Entry->Target route."""
        adjacency: dict[str, set[str]] = defaultdict(set)
        reverse: dict[str, set[str]] = defaultdict(set)
        normalized_edges: list[tuple[str, str, str]] = []
        for index, edge in enumerate(edges):
            source = str(edge.get("source_node_id", edge.get("source", "")))
            target = str(edge.get("target_node_id", edge.get("target", "")))
            if not source or not target:
                continue
            edge_id = str(edge.get("id") or f"dfd-edge-{index}")
            adjacency[source].add(target)
            reverse[target].add(source)
            normalized_edges.append((edge_id, source, target))
        forward = cls._reachable([entry_node_id], adjacency)
        if target_node_id not in forward:
            return None
        backward = cls._reachable([target_node_id], reverse)
        route_nodes = forward & backward
        route_edges = sorted(
            edge_id for edge_id, source, target in normalized_edges
            if source in route_nodes and target in route_nodes
            and source in forward and target in backward
        )
        shortest = cls._shortest_dfd_path(entry_node_id, target_node_id, edges)
        shortest_nodes = shortest[0] if shortest else [entry_node_id, target_node_id]
        ordered_nodes = [*shortest_nodes]
        ordered_nodes.extend(sorted(route_nodes - set(ordered_nodes)))
        return ordered_nodes, route_edges

    def confirm_threat_model(
        self,
        assessment_id: int,
        data: dict[str, Any] | str | None = None,
        owner_id: str | None = None,
    ) -> dict[str, Any]:
        """Confirm Entry-to-Target cases and create one cart per case."""
        if isinstance(data, str) and owner_id is None:
            owner_id = data
            data = None
        if data is None:
            payload: dict[str, Any] = {}
        elif isinstance(data, dict):
            payload = data
        else:
            raise ValueError("사이버 위협 모델 요청 형식이 올바르지 않습니다.")

        current_assessment = self.get_assessment(assessment_id, owner_id)
        explicit_cases_supplied = "attack_cases" in payload
        if current_assessment["threat_model_confirmed"] and not explicit_cases_supplied:
            return self.workspace(assessment_id, owner_id)
        incomplete_scope = scope_missing_fields(current_assessment)
        if incomplete_scope:
            raise ValueError(
                "Scope Brief 설정을 먼저 완료해 주세요: " + ", ".join(incomplete_scope)
            )

        with closing(self.connect()) as conn, conn:
            # Serialize DFD validation and replacement.
            conn.execute("BEGIN IMMEDIATE")
            assessment = self._require_owned_assessment(conn, assessment_id, owner_id)
            locked_scope_missing = scope_missing_fields(dict(assessment))
            if locked_scope_missing:
                raise ValueError(
                    "Scope Brief 설정을 먼저 완료해 주세요: "
                    + ", ".join(locked_scope_missing)
                )
            nodes = [
                dict(row) for row in conn.execute(
                    "SELECT * FROM dfd_nodes WHERE assessment_id=? ORDER BY rowid",
                    (assessment_id,),
                )
            ]
            if not nodes:
                raise ValueError("DFD 구성요소를 하나 이상 배치해 주세요.")
            node_by_id = {str(node["id"]): node for node in nodes}
            edges = [
                dict(row) for row in conn.execute(
                    "SELECT * FROM dfd_edges WHERE assessment_id=? ORDER BY rowid",
                    (assessment_id,),
                )
            ]

            raw_cases: Any
            if explicit_cases_supplied:
                raw_cases = payload.get("attack_cases")
                if not isinstance(raw_cases, list):
                    raise ValueError("Attack Case 목록 형식을 확인해 주세요.")
                if not raw_cases:
                    raise ValueError("Attack Case를 하나 이상 추가해 주세요.")
                if len(raw_cases) > 100:
                    raise ValueError("한 평가에는 Attack Case를 최대 100개까지 확정할 수 있습니다.")
            else:
                entries = [node for node in nodes if node.get("is_entry")]
                targets = [node for node in nodes if node.get("is_target")]
                if not entries or not targets:
                    raise ValueError("진입 지점과 공격 대상을 각각 하나 이상 지정해 주세요.")
                if any(not clean_text(node.get("entry_reason")) for node in entries):
                    raise ValueError("모든 진입 지점의 지정 이유를 입력해 주세요.")
                if any(not clean_text(node.get("target_reason")) for node in targets):
                    raise ValueError("모든 공격 대상의 지정 이유를 입력해 주세요.")
                if {node["id"] for node in entries} & {node["id"] for node in targets}:
                    raise ValueError("같은 DFD 구성요소를 진입 지점과 공격 대상으로 동시에 지정할 수 없습니다.")
                raw_cases = []
                for target in targets:
                    target_has_route = False
                    for entry in entries:
                        if self._directed_case_scope(str(entry["id"]), str(target["id"]), edges):
                            target_has_route = True
                            raw_cases.append(
                                {
                                    "name": f"{entry['name']} → {target['name']}",
                                    "entry_node_id": entry["id"],
                                    "target_node_id": target["id"],
                                    "intended_effect": clean_text(assessment["actor_intent"])
                                    or clean_text(target.get("target_reason"))
                                    or f"{target['name']} 침해",
                                    "rationale": (
                                        f"Entry: {clean_text(entry.get('entry_reason'))}; "
                                        f"Target: {clean_text(target.get('target_reason'))}"
                                    ),
                                    "path_mode": "DIRECTED",
                                }
                            )
                    if not target_has_route:
                        raise ValueError(
                            "진입 지점에서 방향성 데이터 흐름으로 연결되지 않은 공격 대상이 있습니다: "
                            + str(target["name"])
                        )

            actor_snapshot = self._attack_case_actor_snapshot(assessment)
            normalized_cases: list[dict[str, Any]] = []
            identities: set[tuple[tuple[str, ...], str, str]] = set()
            for index, raw_case in enumerate(raw_cases):
                if not isinstance(raw_case, dict):
                    raise ValueError(f"Attack Case {index + 1} 형식을 확인해 주세요.")

                def case_text(field: str, label: str, limit: int, *, required: bool = True) -> str:
                    value = raw_case.get(field)
                    if value is None and not required:
                        return ""
                    if not isinstance(value, str):
                        raise ValueError(f"Attack Case {index + 1}의 {label}은 문자열이어야 합니다.")
                    value = value.strip()
                    if required and not value:
                        raise ValueError(f"Attack Case {index + 1}의 {label}을 입력해 주세요.")
                    if len(value) > limit:
                        raise ValueError(f"Attack Case {index + 1}의 {label}이 너무 깁니다.")
                    return value

                raw_entry_ids = raw_case.get("entry_node_ids")
                if raw_entry_ids is None:
                    legacy_entry_id = raw_case.get("entry_node_id")
                    raw_entry_ids = [legacy_entry_id] if legacy_entry_id is not None else []
                if not isinstance(raw_entry_ids, list):
                    raise ValueError(f"Attack Case {index + 1}의 Entry Point 목록 형식을 확인해 주세요.")
                entry_ids: list[str] = []
                for raw_entry_id in raw_entry_ids:
                    if not isinstance(raw_entry_id, str):
                        raise ValueError(f"Attack Case {index + 1}의 Entry Point는 문자열이어야 합니다.")
                    entry_id = raw_entry_id.strip()
                    if not entry_id:
                        continue
                    if len(entry_id) > 200:
                        raise ValueError(f"Attack Case {index + 1}의 Entry Point가 너무 깁니다.")
                    if entry_id not in entry_ids:
                        entry_ids.append(entry_id)
                if not entry_ids:
                    raise ValueError(
                        f"Attack Case {index + 1}의 Entry Point를 하나 이상 선택해 주세요. "
                        "MITRE TARA의 확정 Attack Vector는 Entry Point에서 Intended Target으로 향하는 경로입니다."
                    )
                if len(entry_ids) > 100:
                    raise ValueError(f"Attack Case {index + 1}에는 Entry Point를 최대 100개까지 지정할 수 있습니다.")
                entry_id = entry_ids[0]
                target_id = case_text("target_node_id", "Intended Target", 200)
                if any(value not in node_by_id for value in entry_ids) or target_id not in node_by_id:
                    raise ValueError(f"Attack Case {index + 1}의 Entry/Target이 현재 DFD에 없습니다.")
                if target_id in entry_ids:
                    raise ValueError("한 Attack Case의 Entry Point와 Intended Target은 서로 달라야 합니다.")
                intended_effect = case_text(
                    "intended_effect", "공격 목적/예상 효과", 2_000, required=False,
                ) or clean_text(assessment["actor_intent"]) or clean_text(
                    node_by_id[target_id].get("target_reason")
                ) or f"{node_by_id[target_id]['name']} 침해"
                rationale = case_text("rationale", "선정 근거", 10_000, required=False)
                name_value = raw_case.get("name")
                if name_value is None or (isinstance(name_value, str) and not name_value.strip()):
                    name = f"Attack Case {index + 1}"
                elif not isinstance(name_value, str):
                    raise ValueError(f"Attack Case {index + 1}의 이름은 문자열이어야 합니다.")
                else:
                    name = name_value.strip()
                if len(name) > 160:
                    raise ValueError(f"Attack Case {index + 1}의 이름이 너무 깁니다.")
                identity = (tuple(sorted(entry_ids)), target_id, intended_effect.casefold())
                if identity in identities:
                    raise ValueError("같은 Entry Point 목록 → Intended Target과 예상 효과의 Attack Case가 중복되었습니다.")
                identities.add(identity)
                path_mode = clean_text(raw_case.get("path_mode") or "DIRECTED").upper()
                if path_mode == "AUTO":
                    path_mode = "DIRECTED"
                if path_mode not in {"DIRECTED", "MANUAL"}:
                    raise ValueError(f"Attack Case {index + 1}의 경로 방식이 올바르지 않습니다.")
                entry_paths: dict[str, list[str]] = {}
                path_node_ids: list[str] = []
                path_edge_ids: list[str] = []
                missing_route_entries: list[str] = []
                for current_entry_id in entry_ids:
                    directed_route = self._directed_case_scope(current_entry_id, target_id, edges)
                    if directed_route is None:
                        missing_route_entries.append(current_entry_id)
                        entry_paths[current_entry_id] = [current_entry_id, target_id]
                        continue
                    route_nodes, route_edges = directed_route
                    entry_paths[current_entry_id] = route_nodes
                    for node_id in route_nodes:
                        if node_id not in path_node_ids:
                            path_node_ids.append(node_id)
                    for edge_id in route_edges:
                        if edge_id not in path_edge_ids:
                            path_edge_ids.append(edge_id)

                if not missing_route_entries:
                    # Stored DFD routes take precedence over client omissions.
                    path_mode = "DIRECTED"
                    path_rationale = "각 Entry Point에서 Intended Target까지의 모든 DFD 방향 경로에 속하는 구성요소를 후보 범위로 사용"
                else:
                    missing_names = ", ".join(
                        clean_text(node_by_id[value].get("name")) or value
                        for value in missing_route_entries
                    )
                    if path_mode == "DIRECTED":
                        raise ValueError(
                            f"Attack Case {index + 1}: 다음 Entry Point에서 Target으로 향하는 DFD 방향 경로가 없습니다: "
                            f"{missing_names}. 실제 별도 경로가 있다면 수동 경로 확인을 선택해 주세요."
                        )
                    if raw_case.get("manual_path_confirmed") is not True:
                        raise ValueError(
                            f"Attack Case {index + 1}: DFD 방향 경로가 없는 Entry Point가 포함된 수동 Case임을 확인해 주세요."
                        )
                    if not rationale:
                        raise ValueError(
                            f"Attack Case {index + 1}: DFD 방향 경로가 없는 Entry Point의 별도 경로 근거를 입력해 주세요."
                        )
                    path_mode = "MANUAL"
                    for current_entry_id in missing_route_entries:
                        if current_entry_id not in path_node_ids:
                            path_node_ids.append(current_entry_id)
                    if target_id not in path_node_ids:
                        path_node_ids.append(target_id)
                    path_rationale = case_text(
                        "path_rationale", "수동 경로 근거", 10_000, required=False,
                    ) or rationale
                normalized_cases.append(
                    {
                        "name": name,
                        "entry_node_id": entry_id,
                        "entry_node_ids": entry_ids,
                        "target_node_id": target_id,
                        "intended_effect": intended_effect,
                        "rationale": rationale,
                        "actor_snapshot": actor_snapshot,
                        "path_mode": path_mode,
                        "path_rationale": path_rationale,
                        "path_node_ids": path_node_ids,
                        "path_edge_ids": path_edge_ids,
                        "entry_paths": entry_paths,
                    }
                )

            existing_cases = [
                dict(row) for row in conn.execute(
                    """SELECT name,entry_node_id,entry_node_ids_json,target_node_id,
                              intended_effect,rationale,path_mode
                       FROM attack_cases WHERE assessment_id=? AND case_kind='EXPLICIT'
                       ORDER BY sort_order,id""",
                    (assessment_id,),
                )
            ]
            requested_identity = [
                (
                    case["name"], tuple(case["entry_node_ids"]), case["target_node_id"],
                    case["intended_effect"], case["rationale"], case["path_mode"],
                )
                for case in normalized_cases
            ]
            stored_identity = [
                (
                    case["name"], tuple(load_json(case["entry_node_ids_json"], [case["entry_node_id"]])), case["target_node_id"],
                    case["intended_effect"], case["rationale"], case["path_mode"],
                )
                for case in existing_cases
            ]
            if assessment["threat_model_confirmed"] and requested_identity == stored_identity:
                return self.workspace(assessment_id, owner_id)
            if assessment["threat_model_confirmed"] and payload.get("reset_downstream") is not True:
                raise ValueError(
                    "확정된 Attack Case를 변경하면 후보, 쇼핑 카트, 위험 평가와 매트릭스가 초기화됩니다. "
                    "reset_downstream=true로 다시 확인해 주세요."
                )

            self._invalidate_matrix(conn, assessment_id)
            conn.execute("DELETE FROM shopping_carts WHERE assessment_id=?", (assessment_id,))
            conn.execute("DELETE FROM candidate_vectors WHERE assessment_id=?", (assessment_id,))
            conn.execute("DELETE FROM attack_cases WHERE assessment_id=?", (assessment_id,))
            if explicit_cases_supplied:
                # Derive node badges from cases; preserve legacy no-body behavior.
                conn.execute(
                    """UPDATE dfd_nodes SET is_entry=0,is_target=0,
                           entry_reason='',target_reason=''
                       WHERE assessment_id=?""",
                    (assessment_id,),
                )
            stamp = now_iso()
            for order, case in enumerate(normalized_cases):
                cursor = conn.execute(
                    """INSERT INTO attack_cases(
                           assessment_id,client_case_id,name,entry_node_id,entry_node_ids_json,target_node_id,
                           intended_effect,rationale,actor_snapshot_json,path_mode,path_rationale,
                           path_edge_ids_json,legacy_entry_node_ids_json,case_kind,status,
                           sort_order,created_at,updated_at
                       ) VALUES(?,NULL,?,?,?,?,?,?,?,?,?,?,'[]','EXPLICIT','CONFIRMED',?,?,?)""",
                    (
                        assessment_id, case["name"], case["entry_node_id"], dump_json(case["entry_node_ids"]),
                        case["target_node_id"], case["intended_effect"], case["rationale"],
                        dump_json(case["actor_snapshot"]), case["path_mode"],
                        case["path_rationale"], dump_json(case["path_edge_ids"]),
                        order, stamp, stamp,
                    ),
                )
                case["id"] = int(cursor.lastrowid)
                ordered_case_nodes = [*case["entry_node_ids"]]
                ordered_case_nodes.extend(
                    node_id for node_id in case["path_node_ids"]
                    if node_id not in ordered_case_nodes and node_id != case["target_node_id"]
                )
                if case["target_node_id"] not in ordered_case_nodes:
                    ordered_case_nodes.append(case["target_node_id"])
                for sequence, node_id in enumerate(ordered_case_nodes):
                    role = (
                        "ENTRY" if node_id in case["entry_node_ids"]
                        else "TARGET" if node_id == case["target_node_id"]
                        else "PATH"
                    )
                    conn.execute(
                        """INSERT INTO attack_case_nodes(attack_case_id,node_id,sequence_order,role)
                           VALUES(?,?,?,?)""",
                        (case["id"], node_id, sequence, role),
                    )
                for current_entry_id in case["entry_node_ids"]:
                    conn.execute(
                        """UPDATE dfd_nodes SET is_entry=1,
                               entry_reason=CASE WHEN entry_reason='' THEN ? ELSE entry_reason END
                           WHERE assessment_id=? AND id=?""",
                        (case["rationale"], assessment_id, current_entry_id),
                    )
                conn.execute(
                    """UPDATE dfd_nodes SET is_target=1,
                           target_reason=CASE WHEN target_reason='' THEN ? ELSE target_reason END
                       WHERE assessment_id=? AND id=?""",
                    (case["rationale"], assessment_id, case["target_node_id"]),
                )

            self._generate_candidates(conn, assessment_id, nodes, normalized_cases)
            conn.execute(
                """UPDATE assessments SET threat_model_confirmed=1,current_step=2,
                       matrix_confirmed=0,updated_at=? WHERE id=?""",
                (stamp, assessment_id),
            )
        return self.workspace(assessment_id, owner_id)

    def complete_candidate_identification(
        self, assessment_id: int, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            assessment = self._require_owned_assessment(conn, assessment_id, owner_id)
            if not assessment["threat_model_confirmed"]:
                raise ValueError("사이버 위협 모델을 먼저 확정해 주세요.")
            cart_count = int(conn.execute(
                "SELECT COUNT(*) FROM shopping_carts WHERE assessment_id=?",
                (assessment_id,),
            ).fetchone()[0])
            if cart_count == 0:
                raise ValueError("확인할 후보 공격 벡터 쇼핑 카트가 없습니다.")
            legacy_count = int(conn.execute(
                """SELECT COUNT(*) FROM shopping_carts
                   WHERE assessment_id=? AND context_status='LEGACY_AGGREGATED'""",
                (assessment_id,),
            ).fetchone()[0])
            if legacy_count:
                raise ValueError("기존 통합 쇼핑 카트를 Attack Case별로 다시 생성해 주세요.")
            conn.execute(
                "UPDATE assessments SET current_step=MAX(current_step,3),updated_at=? WHERE id=?",
                (now_iso(), assessment_id),
            )
            current_step = int(conn.execute(
                "SELECT current_step FROM assessments WHERE id=?", (assessment_id,),
            ).fetchone()[0])
            candidate_count = int(conn.execute(
                "SELECT COUNT(*) FROM candidate_vectors WHERE assessment_id=?",
                (assessment_id,),
            ).fetchone()[0])
            return {
                "ok": True,
                "assessment_id": int(assessment_id),
                "current_step": current_step,
                "candidate_count": candidate_count,
            }

    def _generate_candidates(
        self,
        conn: sqlite3.Connection,
        assessment_id: int,
        nodes: list[dict[str, Any]],
        attack_cases: list[dict[str, Any]],
    ) -> None:
        """Generate route evidence and a target-scoped cart for each case."""
        assessment = conn.execute(
            "SELECT * FROM assessments WHERE id=?", (assessment_id,)
        ).fetchone()
        node_by_id = {str(node["id"]): node for node in nodes}
        conn.execute("DELETE FROM shopping_carts WHERE assessment_id=?", (assessment_id,))
        conn.execute("DELETE FROM candidate_vectors WHERE assessment_id=?", (assessment_id,))

        for case in attack_cases:
            case_id = int(case["id"])
            entry_id = str(case["entry_node_id"])
            entry_ids = [
                str(value) for value in case.get("entry_node_ids", [entry_id])
                if str(value) in node_by_id
            ] or [entry_id]
            target_id = str(case["target_node_id"])
            path_nodes = [
                str(node_id) for node_id in case.get("path_node_ids", [])
                if str(node_id) in node_by_id
            ]
            target_node = node_by_id.get(target_id)
            target_vector_ids = {
                str(mapping["attack_vector_id"])
                for mapping in self._asset_attack_vector_rows(
                    conn,
                    int(assessment["km_release_id"]),
                    str(target_node["asset_type_id"]),
                )
            } if target_node else set()
            grouped: dict[str, dict[str, Any]] = {}
            entry_paths = case.get("entry_paths", {})
            for current_entry_id in entry_ids:
                scoped_nodes = entry_paths.get(current_entry_id, path_nodes)
                for node_id in scoped_nodes:
                    node = node_by_id.get(str(node_id))
                    if node is None:
                        continue
                    for mapping in self._asset_attack_vector_rows(
                        conn, int(assessment["km_release_id"]), str(node["asset_type_id"]),
                    ):
                        record = grouped.setdefault(
                            str(mapping["attack_vector_id"]),
                            {"nodes": set(), "entries": set(), "evidence": []},
                        )
                        record["nodes"].add(str(node_id))
                        record["entries"].add(current_entry_id)
                        record["evidence"].append(
                            {
                                "attack_case_id": case_id,
                                "entry_node_id": current_entry_id,
                                "target_node_id": target_id,
                                "node_id": str(node_id),
                                "node_name": node["name"],
                                "asset_type_id": node["asset_type_id"],
                                "matched_asset_type_id": mapping["matched_asset_type_id"],
                                "mapping_inherited": mapping["matched_asset_type_id"] != node["asset_type_id"],
                                "attack_vector_id": mapping["attack_vector_id"],
                            }
                        )
            cart_cursor = conn.execute(
                """INSERT INTO shopping_carts(
                       assessment_id,attack_case_id,entry_node_id,target_node_id,
                       name,description,status,context_status
                   ) VALUES(?,?,?,?,?,?,'DRAFT','EXPLICIT_CASE')""",
                (
                    assessment_id, case_id, entry_id, target_id,
                    clean_text(node_by_id.get(target_id, {}).get("name")) or target_id,
                    f"{', '.join(entry_ids)} → {target_id} · {case['intended_effect']}",
                ),
            )
            cart_id = int(cart_cursor.lastrowid)
            for attack_vector_id in sorted(grouped):
                record = grouped[attack_vector_id]
                related_entry_ids = sorted(record["entries"])
                evidence = sorted(
                    record["evidence"],
                    key=lambda item: (item["entry_node_id"], item["node_id"], item["attack_vector_id"]),
                )
                candidate_cursor = conn.execute(
                    """INSERT INTO candidate_vectors(
                           assessment_id,attack_case_id,entry_node_id,target_node_id,
                           attack_vector_id,entry_node_ids_json,related_node_ids_json,
                           path_node_ids_json,mapping_evidence_json,context_status
                       ) VALUES(?,?,?,?,?,?,?,?,?,'EXPLICIT_CASE')""",
                    (
                        assessment_id, case_id, entry_id, target_id, attack_vector_id,
                        dump_json(related_entry_ids), dump_json(sorted(record["nodes"])),
                        dump_json(path_nodes), dump_json(evidence),
                    ),
                )
                if attack_vector_id in target_vector_ids:
                    conn.execute(
                        """INSERT INTO cart_items(
                               cart_id,attack_vector_id,candidate_id,item_source,
                               related_entry_ids_json,related_node_ids_json,mapping_evidence_json
                           ) VALUES(?,?,?,'AUTO',?,?,?)""",
                        (
                            cart_id, attack_vector_id, int(candidate_cursor.lastrowid),
                            dump_json(related_entry_ids), dump_json(sorted(record["nodes"])),
                            dump_json(evidence),
                        ),
                    )

    def catalog_search(
        self, assessment_id: int, query: str = "", owner_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = query.strip()
        if len(query) > 200:
            raise ValueError("KM 검색어는 최대 200자까지 입력할 수 있습니다.")
        like = f"%{query}%"
        with closing(self.connect()) as conn, conn:
            self._require_owned_assessment(conn, assessment_id, owner_id)
            self._ensure_attack_vector_catalog_ids(conn)
            rows = conn.execute(
                """SELECT id,catalog_id,name,description,prerequisite,source,source_identifier,reference_url
                   FROM attack_vectors
                   WHERE assessment_id IS NULL
                     AND (?='' OR catalog_id LIKE ? OR source_identifier LIKE ? OR id LIKE ? OR name LIKE ? OR description LIKE ? OR prerequisite LIKE ? OR source LIKE ?)
                   ORDER BY catalog_id,id""",
                (query, like, like, like, like, like, like, like),
            )
            return [dict(row) for row in rows]

    def update_cart(
        self, cart_id: int, data: dict[str, Any], owner_id: str | None = None,
    ) -> None:
        with closing(self.connect()) as conn, conn:
            cart = self._require_owned_cart(conn, cart_id, owner_id)
            if "name" in data or "description" in data:
                current = conn.execute("SELECT name,description FROM shopping_carts WHERE id=?", (cart_id,)).fetchone()
                if not current:
                    raise LookupError("쇼핑 카트를 찾을 수 없습니다.")
                conn.execute(
                    "UPDATE shopping_carts SET name=?,description=? WHERE id=?",
                    (str(data.get("name", current["name"])).strip(), str(data.get("description", current["description"])).strip(), cart_id),
                )
                assessment_id = conn.execute("SELECT assessment_id FROM shopping_carts WHERE id=?", (cart_id,)).fetchone()[0]
                self._invalidate_matrix(conn, assessment_id)

    def add_catalog_item(
        self, cart_id: int, attack_vector_id: str, node_id: str | list[str], reason: str,
        owner_id: str | None = None,
    ) -> None:
        if not reason.strip():
            raise ValueError("공격 벡터를 추가한 이유를 입력해 주세요.")
        node_ids = self._related_node_ids(node_id)
        if not node_ids:
            raise ValueError("관련 DFD 구성요소를 선택해 주세요.")
        with closing(self.connect()) as conn, conn:
            self._require_owned_cart(conn, cart_id, owner_id)
            cart = conn.execute("SELECT * FROM shopping_carts WHERE id=?", (cart_id,)).fetchone()
            if not cart:
                raise LookupError("쇼핑 카트를 찾을 수 없습니다.")
            vector = conn.execute(
                "SELECT assessment_id FROM attack_vectors WHERE id=?", (attack_vector_id,),
            ).fetchone()
            if not vector:
                raise ValueError("KM 카탈로그에서 공격 벡터를 찾을 수 없습니다.")
            if vector["assessment_id"] is not None:
                raise ValueError("평가에서 직접 만든 공격 벡터는 공용 KM 항목으로 추가할 수 없습니다.")
            self._require_related_nodes(conn, int(cart["assessment_id"]), node_ids)
            try:
                conn.execute(
                    """INSERT INTO cart_items(
                        cart_id,attack_vector_id,item_source,related_node_ids_json,addition_reason
                    ) VALUES(?,?,'MANUAL_CATALOG',?,?)""",
                    (cart_id, attack_vector_id, dump_json(node_ids), reason.strip()),
                )
                conn.execute("UPDATE shopping_carts SET status='DRAFT' WHERE id=?", (cart_id,))
                self._invalidate_matrix(conn, cart["assessment_id"], 3)
            except sqlite3.IntegrityError as exc:
                raise ValueError("이미 쇼핑 카트에 포함된 공격 벡터입니다.") from exc

    def add_custom_item(
        self, cart_id: int, data: dict[str, Any], owner_id: str | None = None,
    ) -> str:
        name = self._required_text(
            data, "name", "공격 벡터 이름", max_length=200,
        )
        description = self._required_text(
            data, "description", "공격 벡터 설명", max_length=2_000,
        )
        prerequisite = self._nullable_text(
            data.get("prerequisite"), "공격 벡터 선행조건", max_length=1_000,
        )
        reason = self._required_text(
            data, "reason", "추가 이유", max_length=1_000,
        )
        node_ids = self._related_node_ids(data.get("node_ids", data.get("node_id", "")))
        source = self._required_text(data, "source", "출처", max_length=200)
        reference_url = self._reference_url(data.get("reference_url"))
        publish_to_km = bool(data.get("publish_to_km", False))
        if not node_ids:
            raise ValueError("관련 DFD 구성요소를 하나 이상 선택해 주세요.")
        with closing(self.connect()) as conn, conn:
            self._require_owned_cart(conn, cart_id, owner_id)
            cart = conn.execute("SELECT * FROM shopping_carts WHERE id=?", (cart_id,)).fetchone()
            if not cart:
                raise LookupError("쇼핑 카트를 찾을 수 없습니다.")
            self._require_related_nodes(conn, int(cart["assessment_id"]), node_ids)
            vector_id = self._next_attack_vector_catalog_id(conn)
            conn.execute(
                """INSERT INTO attack_vectors(
                       id,catalog_id,name,description,prerequisite,source,reference_url,assessment_id
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    vector_id, vector_id, name, description, prerequisite, source, reference_url,
                    None if publish_to_km else cart["assessment_id"],
                ),
            )
            if publish_to_km:
                assessment = conn.execute(
                    "SELECT km_release_id FROM assessments WHERE id=?",
                    (cart["assessment_id"],),
                ).fetchone()
                placeholders = ",".join("?" for _ in node_ids)
                asset_type_ids = {
                    str(row["asset_type_id"])
                    for row in conn.execute(
                        f"SELECT asset_type_id FROM dfd_nodes WHERE assessment_id=? AND id IN ({placeholders})",
                        (cart["assessment_id"], *node_ids),
                    )
                }
                for asset_type_id in sorted(asset_type_ids):
                    conn.execute(
                        """INSERT OR IGNORE INTO asset_attack_vectors(
                               km_release_id,asset_type_id,attack_vector_id,mapping_note
                           ) VALUES(?,?,?,?)""",
                        (assessment["km_release_id"], asset_type_id, vector_id, reason),
                    )
            conn.execute(
                """INSERT INTO cart_items(
                    cart_id,attack_vector_id,item_source,related_node_ids_json,addition_reason
                ) VALUES(?,?,?,?,?)""",
                (
                    cart_id, vector_id,
                    "MANUAL_CATALOG" if publish_to_km else "MANUAL_CUSTOM",
                    dump_json(node_ids), reason,
                ),
            )
            conn.execute("UPDATE shopping_carts SET status='DRAFT' WHERE id=?", (cart_id,))
            self._invalidate_matrix(conn, cart["assessment_id"], 3)
            return vector_id

    def update_custom_cart_item(
        self, item_id: int, data: dict[str, Any], owner_id: str | None = None,
    ) -> dict[str, Any]:
        name = self._required_text(
            data, "name", "공격 벡터 이름", max_length=200,
        )
        description = self._required_text(
            data, "description", "공격 벡터 설명", max_length=2_000,
        )
        prerequisite = self._nullable_text(
            data.get("prerequisite"), "공격 벡터 선행조건", max_length=1_000,
        )
        reason = self._required_text(
            data, "reason", "추가 이유", max_length=1_000,
        )
        node_ids = self._related_node_ids(data.get("node_ids", data.get("node_id", "")))
        if not node_ids:
            raise ValueError("관련 DFD 구성요소를 하나 이상 선택해 주세요.")
        source = self._required_text(data, "source", "출처", max_length=200)
        reference_url = self._reference_url(data.get("reference_url"))

        with closing(self.connect()) as conn, conn:
            row = conn.execute(
                """SELECT ci.id,ci.cart_id,ci.attack_vector_id,ci.item_source,
                          sc.assessment_id,av.assessment_id AS vector_assessment_id
                   FROM cart_items ci
                   JOIN shopping_carts sc ON sc.id=ci.cart_id
                   JOIN attack_vectors av ON av.id=ci.attack_vector_id
                   WHERE ci.id=?""",
                (item_id,),
            ).fetchone()
            if not row:
                raise LookupError("쇼핑 카트 항목을 찾을 수 없습니다.")
            self._require_owned_cart(conn, int(row["cart_id"]), owner_id)
            if (
                row["item_source"] != "MANUAL_CUSTOM"
                or row["vector_assessment_id"] is None
                or int(row["vector_assessment_id"]) != int(row["assessment_id"])
            ):
                raise ValueError("현재 평가에서 직접 만든 공격 벡터만 수정할 수 있습니다.")
            self._require_related_nodes(conn, int(row["assessment_id"]), node_ids)
            conn.execute(
                """UPDATE attack_vectors
                   SET name=?,description=?,prerequisite=?,source=?,reference_url=?
                   WHERE id=?""",
                (
                    name, description, prerequisite, source, reference_url,
                    row["attack_vector_id"],
                ),
            )
            conn.execute(
                """UPDATE cart_items
                   SET related_node_ids_json=?,addition_reason=?
                   WHERE id=?""",
                (dump_json(node_ids), reason, item_id),
            )
            conn.execute(
                "UPDATE shopping_carts SET status='DRAFT' WHERE id=?",
                (row["cart_id"],),
            )
            self._invalidate_matrix(conn, int(row["assessment_id"]), 3)
            return {
                "ok": True,
                "item_id": int(item_id),
                "attack_vector_id": str(row["attack_vector_id"]),
            }

    def delete_cart_items(
        self, cart_id: int, item_ids: list[int], owner_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(item_ids, list) or not item_ids:
            raise ValueError("삭제할 쇼핑 카트 항목을 하나 이상 선택해 주세요.")
        normalized_ids: list[int] = []
        seen_ids: set[int] = set()
        for item_id in item_ids:
            if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id <= 0:
                raise ValueError("삭제할 쇼핑 카트 항목 ID를 확인해 주세요.")
            if item_id not in seen_ids:
                seen_ids.add(item_id)
                normalized_ids.append(item_id)

        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cart = self._require_owned_cart(conn, cart_id, owner_id)
                cart_items = {
                    int(row["id"]): row
                    for row in conn.execute(
                        """SELECT ci.id,ci.attack_vector_id,ci.item_source,
                                  av.assessment_id AS vector_assessment_id
                           FROM cart_items ci
                           JOIN attack_vectors av ON av.id=ci.attack_vector_id
                           WHERE ci.cart_id=?""",
                        (cart_id,),
                    )
                }
                if any(item_id not in cart_items for item_id in normalized_ids):
                    raise LookupError("쇼핑 카트 항목을 찾을 수 없습니다.")

                custom_vector_ids = {
                    str(cart_items[item_id]["attack_vector_id"])
                    for item_id in normalized_ids
                    if (
                        cart_items[item_id]["item_source"] == "MANUAL_CUSTOM"
                        and cart_items[item_id]["vector_assessment_id"] is not None
                        and int(cart_items[item_id]["vector_assessment_id"])
                        == int(cart["assessment_id"])
                    )
                }

                conn.executemany(
                    "DELETE FROM cart_items WHERE cart_id=? AND id=?",
                    [(cart_id, item_id) for item_id in normalized_ids],
                )
                for vector_id in custom_vector_ids:
                    conn.execute(
                        """DELETE FROM attack_vectors
                           WHERE id=? AND assessment_id=?
                             AND NOT EXISTS (
                                 SELECT 1 FROM cart_items WHERE attack_vector_id=?
                             )""",
                        (vector_id, int(cart["assessment_id"]), vector_id),
                    )
                conn.execute(
                    "UPDATE shopping_carts SET status='DRAFT' WHERE id=?", (cart_id,),
                )
                self._invalidate_matrix(conn, int(cart["assessment_id"]), 3)
                conn.commit()
                return {
                    "ok": True,
                    "cart_id": int(cart_id),
                    "deleted_item_ids": normalized_ids,
                    "deleted_count": len(normalized_ids),
                }
            except Exception:
                conn.rollback()
                raise

    def complete_cart(self, cart_id: int, owner_id: str | None = None) -> None:
        with closing(self.connect()) as conn, conn:
            self._require_owned_cart(conn, cart_id, owner_id)
            cart = conn.execute("SELECT * FROM shopping_carts WHERE id=?", (cart_id,)).fetchone()
            if not cart:
                raise LookupError("쇼핑 카트를 찾을 수 없습니다.")
            if cart["status"] == "DRAFT":
                conn.execute("UPDATE shopping_carts SET status='READY' WHERE id=?", (cart_id,))
            assessment_id = cart["assessment_id"]
            conn.execute("UPDATE assessments SET current_step=MAX(current_step,3),updated_at=? WHERE id=?", (now_iso(), assessment_id))

    def review_item(
        self, item_id: int, status: str, reason: str, owner_id: str | None = None,
    ) -> None:
        if status not in {"UNREVIEWED", "PLAUSIBLE", "ELIMINATED"}:
            raise ValueError("검토 상태가 올바르지 않습니다.")
        with closing(self.connect()) as conn, conn:
            self._require_owned_item(conn, item_id, owner_id)
            context = conn.execute(
                """SELECT ci.cart_id,sc.assessment_id,sc.status AS cart_status FROM cart_items ci
                   JOIN shopping_carts sc ON sc.id=ci.cart_id WHERE ci.id=?""",
                (item_id,),
            ).fetchone()
            if not context:
                raise LookupError("쇼핑 카트 항목을 찾을 수 없습니다.")
            if context["cart_status"] == "DRAFT":
                raise ValueError("쇼핑 카트 구성을 먼저 완료해 주세요.")
            conn.execute(
                """UPDATE cart_items SET review_status=?,decision_reason=?,factor_values_json='{}',
                   factor_reasons_json='{}',llm_risk_json=NULL,risk_score=NULL,risk_level=NULL,
                   calculation_trace_json='{}',risk_review_status='UNASSESSED' WHERE id=?""",
                (status, reason.strip(), item_id),
            )
            conn.execute("UPDATE shopping_carts SET status='READY' WHERE id=?", (context["cart_id"],))
            self._invalidate_matrix(conn, context["assessment_id"], 4)

    def review_items_batch(
        self,
        cart_id: int,
        reviews: Any,
        owner_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(reviews, list) or len(reviews) > 500:
            raise ValueError("전체 판정 목록 형식을 확인해 주세요.")
        normalized: list[dict[str, Any]] = []
        seen: set[int] = set()
        for review in reviews:
            if not isinstance(review, dict):
                raise ValueError("각 판정은 객체 형식이어야 합니다.")
            item_id = review.get("item_id")
            if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id <= 0:
                raise ValueError("판정할 공격 벡터 항목 ID를 확인해 주세요.")
            if item_id in seen:
                raise ValueError("중복된 공격 벡터 판정이 있습니다.")
            seen.add(item_id)
            raw_status = review.get("status", "")
            if not isinstance(raw_status, str):
                raise ValueError("검토 상태가 올바르지 않습니다.")
            status = raw_status.strip().upper()
            if status not in {"UNREVIEWED", "PLAUSIBLE", "ELIMINATED"}:
                raise ValueError("검토 상태가 올바르지 않습니다.")
            raw_reason = review.get("reason", "")
            if not isinstance(raw_reason, str):
                raise ValueError("판단 근거 형식을 확인해 주세요.")
            reason = raw_reason.strip()
            if len(reason) > 10_000:
                raise ValueError("판단 근거는 10,000자 이내로 입력해 주세요.")
            normalized.append({"item_id": item_id, "status": status, "reason": reason})

        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._require_owned_cart(conn, cart_id, owner_id)
                cart = conn.execute(
                    "SELECT assessment_id,status FROM shopping_carts WHERE id=?", (cart_id,),
                ).fetchone()
                if not cart:
                    raise LookupError("쇼핑 카트를 찾을 수 없습니다.")
                if cart["status"] == "DRAFT":
                    raise ValueError("쇼핑 카트 구성을 먼저 완료해 주세요.")
                current_rows = conn.execute(
                    """SELECT id,review_status,decision_reason FROM cart_items
                       WHERE cart_id=? ORDER BY id""",
                    (cart_id,),
                ).fetchall()
                expected_ids = {int(row["id"]) for row in current_rows}
                if seen != expected_ids:
                    raise ValueError("현재 쇼핑 카트의 모든 공격 벡터 판정을 한 번에 보내 주세요.")
                current_by_id = {int(row["id"]): row for row in current_rows}
                changed = 0
                for review in normalized:
                    current = current_by_id[review["item_id"]]
                    if (
                        str(current["review_status"]) == review["status"]
                        and str(current["decision_reason"]).strip() == review["reason"]
                    ):
                        continue
                    conn.execute(
                        """UPDATE cart_items
                           SET review_status=?,decision_reason=?,factor_values_json='{}',
                               factor_reasons_json='{}',llm_risk_json=NULL,risk_score=NULL,risk_level=NULL,
                               calculation_trace_json='{}',risk_review_status='UNASSESSED'
                           WHERE id=?""",
                        (review["status"], review["reason"], review["item_id"]),
                    )
                    changed += 1
                complete = all(review["status"] != "UNREVIEWED" for review in normalized)
                cart_status = "REVIEWED" if complete else "READY"
                conn.execute("UPDATE shopping_carts SET status=? WHERE id=?", (cart_status, cart_id))
                assessment_id = int(cart["assessment_id"])
                if changed:
                    self._invalidate_matrix(conn, assessment_id, 4)
                if complete:
                    conn.execute(
                        """UPDATE assessments SET current_step=MAX(current_step,4),updated_at=?
                           WHERE id=?""",
                        (now_iso(), assessment_id),
                    )
                conn.commit()
                return {
                    "ok": True,
                    "cart_id": cart_id,
                    "cart_status": cart_status,
                    "saved_count": len(normalized),
                    "changed_count": changed,
                    "reviewed_count": sum(review["status"] != "UNREVIEWED" for review in normalized),
                }
            except Exception:
                conn.rollback()
                raise

    def save_llm_suggestion(
        self, item_id: int, kind: str, suggestion: dict[str, Any], owner_id: str | None = None,
    ) -> None:
        if kind not in {"plausibility", "risk"}:
            raise ValueError("LLM 추천 종류가 올바르지 않습니다.")
        with closing(self.connect()) as conn, conn:
            item = self._require_owned_item(conn, item_id, owner_id)
            if kind == "plausibility":
                conn.execute(
                    "UPDATE cart_items SET llm_plausibility_json=? WHERE id=?",
                    (dump_json(suggestion), item_id),
                )
                return
            if item["cart_status"] != "REVIEWED" or item["review_status"] != "PLAUSIBLE":
                raise ValueError("타당함으로 확정된 공격 벡터만 위험 평가 추천을 저장할 수 있습니다.")
            model = conn.execute(
                """SELECT rm.* FROM assessments a JOIN risk_models rm ON rm.id=a.risk_model_id
                   WHERE a.id=? AND (rm.assessment_id IS NULL OR rm.assessment_id=a.id)""",
                (item["assessment_id"],),
            ).fetchone()
            if not model:
                raise ValueError("위험 평가 모델을 먼저 선택해 주세요.")
            factors = [
                dict(row) for row in conn.execute(
                    "SELECT * FROM risk_factors WHERE model_id=? ORDER BY sort_order", (model["id"],)
                )
            ]
            normalized, review_status = self._normalize_risk_suggestion_storage(suggestion, factors)
            review_status = self._risk_status_after_llm_refresh(
                normalized, review_status, item, factors
            )
            conn.execute(
                "UPDATE cart_items SET llm_risk_json=?,risk_review_status=? WHERE id=?",
                (dump_json(normalized), review_status, item_id),
            )

    def llm_cart_plausibility_context(
        self, cart_id: int, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn:
            cart = self._require_owned_cart(conn, cart_id, owner_id)
            if cart["context_status"] == "LEGACY_AGGREGATED":
                raise ValueError(
                    "기존 Target 집계형 쇼핑 카트는 Attack Case를 다시 지정·확정한 뒤 LLM을 사용할 수 있습니다."
                )
            if cart["status"] == "DRAFT":
                raise ValueError("쇼핑 카트 구성을 먼저 완료해 주세요.")
            item_ids = [
                int(row["id"])
                for row in conn.execute(
                    "SELECT id FROM cart_items WHERE cart_id=? ORDER BY id", (cart_id,),
                )
            ]
        if not item_ids:
            raise ValueError("LLM 초안을 만들 공격 벡터가 없습니다.")
        contexts = [self.llm_context(item_id, owner_id=owner_id) for item_id in item_ids]
        first = contexts[0]
        return {
            "assessment": first["assessment"],
            "shopping_cart": first["shopping_cart"],
            "attack_case": first.get("attack_case"),
            "target": first["target"],
            "data_flows": first["data_flows"],
            "items": [
                {
                    "item_id": item_id,
                    "attack_vector": context["attack_vector"],
                    "current_decision": context["cart_item_decision"],
                    "entry_points": context["entry_points"],
                    "related_nodes": context["related_nodes"],
                    "mapping_evidence": context["mapping_evidence"],
                }
                for item_id, context in zip(item_ids, contexts)
            ],
        }

    def save_llm_plausibility_suggestions(
        self,
        cart_id: int,
        suggestions: list[dict[str, Any]],
        owner_id: str | None = None,
    ) -> None:
        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._require_owned_cart(conn, cart_id, owner_id)
                expected_ids = {
                    int(row["id"])
                    for row in conn.execute("SELECT id FROM cart_items WHERE cart_id=?", (cart_id,))
                }
                suggestion_ids = {int(item["item_id"]) for item in suggestions}
                if suggestion_ids != expected_ids or len(suggestions) != len(expected_ids):
                    raise ValueError("현재 쇼핑 카트의 모든 LLM 판정 초안이 필요합니다.")
                for suggestion in suggestions:
                    payload = {key: value for key, value in suggestion.items() if key != "item_id"}
                    conn.execute(
                        "UPDATE cart_items SET llm_plausibility_json=? WHERE id=? AND cart_id=?",
                        (dump_json(payload), int(suggestion["item_id"]), cart_id),
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    @staticmethod
    def _normalize_risk_suggestion_storage(
        suggestion: Any, factors: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], str]:
        if not isinstance(suggestion, dict):
            raise ValueError("LLM 위험 평가 추천 형식을 확인해 주세요.")
        raw_factors = suggestion.get("factors", {})
        if not isinstance(raw_factors, dict):
            raise ValueError("LLM 위험 요인 추천 형식을 확인해 주세요.")
        definitions = {str(factor["code"]): factor for factor in factors}
        unknown = set(raw_factors) - set(definitions)
        if unknown:
            raise ValueError("LLM이 선택한 모델에 없는 위험 요인을 반환했습니다.")
        normalized_factors: dict[str, dict[str, Any]] = {}
        needs_review = set(raw_factors) != set(definitions)
        for code, raw in raw_factors.items():
            if not isinstance(raw, dict):
                raise ValueError("LLM 위험 요인 추천 형식을 확인해 주세요.")
            supplied_status = raw.get("information_status")
            if supplied_status is not None and not isinstance(supplied_status, str):
                raise ValueError("LLM 위험 요인 정보 상태가 올바르지 않습니다.")
            raw_status = clean_text(supplied_status).upper()
            if supplied_status is None:
                raw_status = "INSUFFICIENT" if raw.get("value") is None else "RECOMMENDED"
            if raw_status not in {"RECOMMENDED", "INSUFFICIENT"}:
                raise ValueError("LLM 위험 요인 정보 상태가 올바르지 않습니다.")
            reason = clean_text(raw.get("reason"))
            if len(reason) > 10_000:
                raise ValueError("LLM 위험 요인 판정 근거는 10,000자 이하여야 합니다.")
            if raw_status == "INSUFFICIENT":
                if raw.get("value") is not None or raw.get("qualitative_value") is not None:
                    raise ValueError("판단 정보 부족 요인에는 추천 정성값이나 숫자값을 저장할 수 없습니다.")
                normalized_factors[code] = {
                    "value": None,
                    "qualitative_value": None,
                    "reason": reason or "판단 정보 부족",
                    "information_status": "INSUFFICIENT",
                }
                needs_review = True
                continue
            raw_value = raw.get("value")
            if isinstance(raw_value, bool):
                raise ValueError("LLM 위험 요인 추천값 형식을 확인해 주세요.")
            try:
                numeric_value = float(raw_value)
            except (TypeError, ValueError) as exc:
                raise ValueError("LLM 위험 요인 추천값 형식을 확인해 주세요.") from exc
            if not math.isfinite(numeric_value):
                raise ValueError("LLM 위험 요인 추천값 형식을 확인해 주세요.")
            levels = definitions[code].get("levels")
            if not isinstance(levels, list):
                levels = load_json(definitions[code].get("levels_json", "[]"), [])
            matched = next(
                (
                    level for level in levels
                    if isinstance(level, dict)
                    and not isinstance(level.get("value"), bool)
                    and float(level.get("value")) == numeric_value
                ),
                None,
            )
            if matched is None:
                raise ValueError("LLM 위험 요인 추천값이 허용 척도를 벗어났습니다.")
            supplied_label = raw.get("qualitative_value")
            if supplied_label is not None and (
                not isinstance(supplied_label, str)
                or supplied_label.strip().casefold() != clean_text(matched.get("label")).casefold()
            ):
                raise ValueError("LLM 위험 요인의 정성값과 숫자 매핑이 서로 일치하지 않습니다.")
            if not reason:
                needs_review = True
            normalized_factors[code] = {
                "value": matched["value"],
                "qualitative_value": matched.get("label"),
                "reason": reason,
                "information_status": "RECOMMENDED",
            }
        raw_missing = suggestion.get("missing_information", [])
        if raw_missing is None:
            raw_missing = []
        if not isinstance(raw_missing, list) or len(raw_missing) > 100:
            raise ValueError("LLM 부족 정보 목록 형식을 확인해 주세요.")
        missing_information: list[str] = []
        for raw in raw_missing:
            if not isinstance(raw, str):
                raise ValueError("LLM 부족 정보 목록 형식을 확인해 주세요.")
            value = raw.strip()
            if value and value not in missing_information:
                if len(value) > 1_000:
                    raise ValueError("LLM 부족 정보 설명은 1,000자 이하여야 합니다.")
                missing_information.append(value)
        if missing_information:
            needs_review = True
        normalized: dict[str, Any] = {
            "factors": normalized_factors,
            "missing_information": missing_information,
        }
        if isinstance(suggestion.get("_llm"), dict):
            normalized["_llm"] = suggestion["_llm"]
        return normalized, "NEEDS_REVIEW" if needs_review else "LLM_COMPLETED"

    @staticmethod
    def _risk_status_after_llm_refresh(
        suggestion: dict[str, Any],
        draft_status: str,
        stored_item: sqlite3.Row | dict[str, Any],
        factors: list[dict[str, Any]],
    ) -> str:
        """Keep an already-saved deterministic result final after an LLM refresh."""
        if draft_status == "NEEDS_REVIEW":
            return "NEEDS_REVIEW"
        if stored_item["risk_score"] is None:
            return draft_status
        values = load_json(stored_item["factor_values_json"], {})
        reasons = load_json(stored_item["factor_reasons_json"], {})
        expected_codes = {str(factor["code"]) for factor in factors}
        if set(values) != expected_codes or set(reasons) != expected_codes:
            return draft_status
        recommendations = suggestion.get("factors", {})
        if set(recommendations) != expected_codes:
            return "USER_MODIFIED"
        for code in expected_codes:
            recommendation = recommendations.get(code)
            if not isinstance(recommendation, dict) or recommendation.get("information_status") != "RECOMMENDED":
                return "USER_MODIFIED"
            raw_value = recommendation.get("value")
            if isinstance(raw_value, bool):
                return "USER_MODIFIED"
            try:
                if float(values[code]) != float(raw_value):
                    return "USER_MODIFIED"
            except (TypeError, ValueError):
                return "USER_MODIFIED"
        return "USER_REVIEWED"

    def llm_cart_risk_context(
        self, cart_id: int, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn:
            cart = self._require_owned_cart(conn, cart_id, owner_id)
            if cart["context_status"] == "LEGACY_AGGREGATED":
                raise ValueError(
                    "기존 Target 집계형 쇼핑 카트는 Attack Case를 다시 지정·확정한 뒤 LLM을 사용할 수 있습니다."
                )
            if cart["status"] != "REVIEWED":
                raise ValueError("쇼핑 카트의 타당성 검토를 먼저 완료해 주세요.")
            assessment = conn.execute(
                "SELECT risk_model_id FROM assessments WHERE id=?", (cart["assessment_id"],)
            ).fetchone()
            if not assessment or not assessment["risk_model_id"]:
                raise ValueError("위험 평가 모델을 먼저 선택해 주세요.")
            model_allowed = conn.execute(
                """SELECT 1 FROM risk_models
                   WHERE id=? AND active=1 AND (assessment_id IS NULL OR assessment_id=?)""",
                (assessment["risk_model_id"], cart["assessment_id"]),
            ).fetchone()
            if not model_allowed:
                raise ValueError("이 평가에서 사용할 수 없는 위험 평가 모델입니다.")
            item_ids = [
                int(row["id"])
                for row in conn.execute(
                    """SELECT id FROM cart_items
                       WHERE cart_id=? AND review_status='PLAUSIBLE' ORDER BY id""",
                    (cart_id,),
                )
            ]
            path_node_ids: set[str] = set()
            for row in conn.execute(
                """SELECT cv.path_node_ids_json
                   FROM cart_items ci
                   LEFT JOIN candidate_vectors cv ON cv.id=ci.candidate_id
                   WHERE ci.cart_id=? AND ci.review_status='PLAUSIBLE'""",
                (cart_id,),
            ):
                path_node_ids.update(str(value) for value in load_json(row["path_node_ids_json"], []))
            path_nodes = {
                str(row["id"]): dict(row)
                for row in conn.execute(
                    """SELECT id,name,asset_type_id,description,is_entry,is_target
                       FROM dfd_nodes WHERE assessment_id=?""",
                    (cart["assessment_id"],),
                )
                if str(row["id"]) in path_node_ids
            }
        if not item_ids:
            raise ValueError("LLM 위험 평가를 요청할 타당한 공격 벡터가 없습니다.")
        contexts = [
            self.llm_context(item_id, include_model=True, owner_id=owner_id)
            for item_id in item_ids
        ]
        first = contexts[0]
        relevant_nodes: dict[str, dict[str, Any]] = dict(path_nodes)
        for context in contexts:
            for node in [context.get("target"), *context["entry_points"], *context["related_nodes"]]:
                if isinstance(node, dict) and node.get("id") is not None:
                    relevant_nodes[str(node["id"])] = node
        # Use only flows from the stored case route.
        relevant_flows = first["data_flows"]

        def compact_evidence(values: Any) -> list[dict[str, Any]]:
            allowed = (
                "entry_node_id", "node_id", "node_name", "asset_type_id",
                "matched_asset_type_id", "mapping_inherited", "attack_vector_id",
            )
            return [
                {key: value[key] for key in allowed if key in value}
                for value in values if isinstance(value, dict)
            ] if isinstance(values, list) else []

        return {
            "assessment": first["assessment"],
            "shopping_cart": first["shopping_cart"],
            "attack_case": first.get("attack_case"),
            "target": first["target"],
            "data_flows": relevant_flows,
            "items": [
                {
                    "item_id": item_id,
                    "attack_vector": context["attack_vector"],
                    "current_decision": context["cart_item_decision"],
                    "entry_points": context["entry_points"],
                    "related_nodes": context["related_nodes"],
                    "mapping_evidence": compact_evidence(context["mapping_evidence"]),
                }
                for item_id, context in zip(item_ids, contexts)
            ],
            "risk_model": first["risk_model"],
        }

    def save_llm_risk_suggestions(
        self,
        cart_id: int,
        suggestions: Any,
        owner_id: str | None = None,
        expected_model_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(suggestions, list) or len(suggestions) > 500:
            raise ValueError("LLM 위험 평가 추천 목록 형식을 확인해 주세요.")
        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cart = self._require_owned_cart(conn, cart_id, owner_id)
                if cart["status"] != "REVIEWED":
                    raise ValueError("쇼핑 카트의 타당성 검토를 먼저 완료해 주세요.")
                model = conn.execute(
                    """SELECT rm.* FROM assessments a JOIN risk_models rm ON rm.id=a.risk_model_id
                       WHERE a.id=? AND rm.active=1
                         AND (rm.assessment_id IS NULL OR rm.assessment_id=a.id)""",
                    (cart["assessment_id"],),
                ).fetchone()
                if not model:
                    raise ValueError("위험 평가 모델을 먼저 선택해 주세요.")
                if expected_model_id is not None and str(model["id"]) != str(expected_model_id):
                    raise ValueError("LLM 요청 후 위험 평가 모델이 변경되었습니다. 다시 요청해 주세요.")
                factors = [
                    dict(row) for row in conn.execute(
                        "SELECT * FROM risk_factors WHERE model_id=? ORDER BY sort_order", (model["id"],)
                    )
                ]
                expected_rows = {
                    int(row["id"]): row
                    for row in conn.execute(
                        """SELECT id,factor_values_json,factor_reasons_json,risk_score
                           FROM cart_items
                           WHERE cart_id=? AND review_status='PLAUSIBLE'""",
                        (cart_id,),
                    )
                }
                expected_ids = set(expected_rows)
                if not expected_ids:
                    raise ValueError("LLM 위험 평가를 저장할 타당한 공격 벡터가 없습니다.")
                normalized: list[tuple[int, dict[str, Any], str]] = []
                seen: set[int] = set()
                for suggestion in suggestions:
                    if not isinstance(suggestion, dict):
                        raise ValueError("LLM 위험 평가 추천 형식을 확인해 주세요.")
                    item_id = suggestion.get("item_id")
                    if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id <= 0:
                        raise ValueError("LLM 위험 평가 항목 ID를 확인해 주세요.")
                    if item_id in seen:
                        raise ValueError("중복된 LLM 위험 평가 항목이 있습니다.")
                    seen.add(item_id)
                    payload = {key: value for key, value in suggestion.items() if key != "item_id"}
                    clean_payload, status = self._normalize_risk_suggestion_storage(payload, factors)
                    if item_id in expected_rows:
                        status = self._risk_status_after_llm_refresh(
                            clean_payload, status, expected_rows[item_id], factors
                        )
                    normalized.append((item_id, clean_payload, status))
                if seen != expected_ids:
                    raise ValueError("현재 쇼핑 카트의 모든 타당한 공격 벡터 추천을 한 번에 보내 주세요.")
                for item_id, payload, status in normalized:
                    conn.execute(
                        """UPDATE cart_items SET llm_risk_json=?,risk_review_status=?
                           WHERE id=? AND cart_id=? AND review_status='PLAUSIBLE'""",
                        (dump_json(payload), status, item_id, cart_id),
                    )
                conn.commit()
                return {
                    "ok": True,
                    "cart_id": cart_id,
                    "saved_count": len(normalized),
                    "items": [
                        {"item_id": item_id, "risk_review_status": status}
                        for item_id, _payload, status in normalized
                    ],
                }
            except Exception:
                conn.rollback()
                raise

    def complete_review(self, cart_id: int, owner_id: str | None = None) -> None:
        with closing(self.connect()) as conn, conn:
            self._require_owned_cart(conn, cart_id, owner_id)
            cart = conn.execute("SELECT * FROM shopping_carts WHERE id=?", (cart_id,)).fetchone()
            if not cart:
                raise LookupError("쇼핑 카트를 찾을 수 없습니다.")
            if cart["status"] == "DRAFT":
                raise ValueError("쇼핑 카트 구성을 먼저 완료해 주세요.")
            items = [dict(row) for row in conn.execute("SELECT * FROM cart_items WHERE cart_id=?", (cart_id,))]
            unreviewed = [item for item in items if item["review_status"] == "UNREVIEWED"]
            if unreviewed:
                raise ValueError("미검토 공격 벡터가 남아 있습니다.")
            conn.execute("UPDATE shopping_carts SET status='REVIEWED' WHERE id=?", (cart_id,))
            assessment_id = cart["assessment_id"]
            conn.execute("UPDATE assessments SET current_step=MAX(current_step,4),updated_at=? WHERE id=?", (now_iso(), assessment_id))

    @staticmethod
    def _normalize_custom_risk_factors(raw_factors: Any) -> list[dict[str, Any]]:
        if not isinstance(raw_factors, list) or not 1 <= len(raw_factors) <= 50:
            raise ValueError("사용자 정의 계산기는 1개 이상 50개 이하의 위험 요인이 필요합니다.")
        normalized: list[dict[str, Any]] = []
        seen_codes: set[str] = set()
        seen_orders: set[int] = set()
        for index, raw in enumerate(raw_factors):
            if not isinstance(raw, dict):
                raise ValueError("사용자 정의 위험 요인 형식을 확인해 주세요.")
            code = clean_text(raw.get("code", raw.get("factor_id"))).lower()
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
                raise ValueError("위험 요인 코드는 영문 소문자로 시작하고 영문·숫자·밑줄만 사용할 수 있습니다.")
            if code in seen_codes:
                raise ValueError("중복된 위험 요인 코드가 있습니다.")
            seen_codes.add(code)
            name = clean_text(raw.get("name", raw.get("factor_name")))
            factor_group = clean_text(raw.get("factor_group"))
            question = clean_text(raw.get("question"))
            if not name or len(name) > 160:
                raise ValueError("위험 요인 이름은 1자 이상 160자 이하여야 합니다.")
            if not factor_group or len(factor_group) > 100:
                raise ValueError("위험 요인 그룹은 1자 이상 100자 이하여야 합니다.")
            if not question or len(question) > 1_000:
                raise ValueError("위험 요인 평가 질문은 1자 이상 1,000자 이하여야 합니다.")
            raw_weight = raw.get("weight")
            if isinstance(raw_weight, bool):
                raise ValueError("위험 요인 가중치 형식을 확인해 주세요.")
            try:
                weight = float(raw_weight)
            except (TypeError, ValueError) as exc:
                raise ValueError("위험 요인 가중치 형식을 확인해 주세요.") from exc
            if not math.isfinite(weight) or weight < 0 or weight > 1_000_000:
                raise ValueError("위험 요인 가중치는 0 이상인 유한한 숫자여야 합니다.")
            raw_order = raw.get("display_order", raw.get("sort_order", index))
            if isinstance(raw_order, bool):
                raise ValueError("위험 요인 표시 순서 형식을 확인해 주세요.")
            try:
                numeric_order = float(raw_order)
            except (TypeError, ValueError) as exc:
                raise ValueError("위험 요인 표시 순서 형식을 확인해 주세요.") from exc
            if not math.isfinite(numeric_order) or not numeric_order.is_integer():
                raise ValueError("위험 요인 표시 순서 형식을 확인해 주세요.")
            display_order = int(numeric_order)
            if display_order < 0 or display_order > 10_000 or display_order in seen_orders:
                raise ValueError("위험 요인 표시 순서는 중복되지 않는 0 이상의 정수여야 합니다.")
            seen_orders.add(display_order)

            raw_levels = raw.get("levels", raw.get("qualitative_options"))
            if not isinstance(raw_levels, list) or not 2 <= len(raw_levels) <= 20:
                raise ValueError("각 위험 요인은 2개 이상 20개 이하의 척도 옵션이 필요합니다.")
            levels: list[dict[str, Any]] = []
            seen_values: set[float] = set()
            seen_labels: set[str] = set()
            for raw_level in raw_levels:
                if not isinstance(raw_level, dict):
                    raise ValueError("위험 요인 척도 형식을 확인해 주세요.")
                raw_value = raw_level.get("value", raw_level.get("numeric_value"))
                if isinstance(raw_value, bool):
                    raise ValueError("위험 요인 척도의 숫자 매핑 형식을 확인해 주세요.")
                try:
                    numeric_value = float(raw_value)
                except (TypeError, ValueError) as exc:
                    raise ValueError("위험 요인 척도의 숫자 매핑 형식을 확인해 주세요.") from exc
                label = clean_text(raw_level.get("label", raw_level.get("qualitative_value")))
                description = clean_text(raw_level.get("description", raw_level.get("qualitative_effect")))
                if not math.isfinite(numeric_value):
                    raise ValueError("위험 요인 척도에는 유한한 숫자만 사용할 수 있습니다.")
                if numeric_value in seen_values:
                    raise ValueError("위험 요인 척도에 중복된 숫자 매핑이 있습니다.")
                if not label or len(label) > 160 or label.casefold() in seen_labels:
                    raise ValueError("위험 요인 척도 이름은 비어 있지 않고 서로 달라야 합니다.")
                if not description or len(description) > 1_000:
                    raise ValueError("위험 요인 척도 설명은 1자 이상 1,000자 이하여야 합니다.")
                seen_values.add(numeric_value)
                seen_labels.add(label.casefold())
                stored_value: int | float = int(numeric_value) if numeric_value.is_integer() else numeric_value
                levels.append({"value": stored_value, "label": label, "description": description})
            levels.sort(key=lambda level: float(level["value"]))
            normalized.append(
                {
                    "code": code,
                    "name": name,
                    "factor_group": factor_group,
                    "question": question,
                    "weight": weight,
                    "levels": levels,
                    "sort_order": display_order,
                }
            )
        if not any(factor["weight"] > 0 for factor in normalized):
            raise ValueError("사용자 정의 계산기에는 0보다 큰 가중치가 하나 이상 필요합니다.")
        normalized.sort(key=lambda factor: (factor["sort_order"], factor["code"]))
        return normalized

    def save_tailored_risk_model(
        self, assessment_id: int, payload: Any, owner_id: str | None = None,
    ) -> dict[str, Any]:
        """Create an assessment-scoped calculator revision."""
        if not isinstance(payload, dict):
            raise ValueError("위험 계산기 설정 형식을 확인해 주세요.")
        base_model_id = clean_text(payload.get("model_id", payload.get("base_model_id")))
        adjustable_codes = TAILORABLE_RISK_FACTORS.get(base_model_id)
        if not adjustable_codes:
            raise ValueError("이 계산기는 별도로 조정할 수 있는 가중치가 없습니다.")
        raw_weights = payload.get("weights")
        if not isinstance(raw_weights, dict) or set(raw_weights) != set(adjustable_codes):
            raise ValueError("조정 가능한 모든 평가 항목의 중요도를 입력해 주세요.")
        weights: dict[str, float] = {}
        for code in adjustable_codes:
            raw_weight = raw_weights.get(code)
            if isinstance(raw_weight, bool):
                raise ValueError("평가 항목 중요도 형식을 확인해 주세요.")
            try:
                weight = float(raw_weight)
            except (TypeError, ValueError) as exc:
                raise ValueError("평가 항목 중요도 형식을 확인해 주세요.") from exc
            if not math.isfinite(weight) or weight < 0 or weight > 1:
                raise ValueError("각 평가 항목 중요도는 0% 이상 100% 이하여야 합니다.")
            weights[code] = weight
        if not math.isclose(sum(weights.values()), 1.0, rel_tol=0.0, abs_tol=1e-9):
            raise ValueError("조정 가능한 평가 항목의 중요도 합계가 100%가 되어야 합니다.")

        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                assessment = self._require_owned_assessment(conn, assessment_id, owner_id)
                carts = list(conn.execute(
                    "SELECT status,context_status FROM shopping_carts WHERE assessment_id=?",
                    (assessment_id,),
                ))
                if any(cart["context_status"] == "LEGACY_AGGREGATED" for cart in carts):
                    raise ValueError(
                        "기존 Target 집계형 쇼핑 카트는 읽기 전용입니다. "
                        "Attack Case별 Entry/Target을 다시 지정·확정해 주세요."
                    )
                if not assessment["threat_model_confirmed"] or not carts or any(cart["status"] != "REVIEWED" for cart in carts):
                    raise ValueError("모든 쇼핑 카트의 타당성 검토를 먼저 완료해 주세요.")
                base = conn.execute(
                    "SELECT * FROM risk_models WHERE id=? AND assessment_id IS NULL AND active=1",
                    (base_model_id,),
                ).fetchone()
                if not base:
                    raise ValueError("기본 위험 계산기를 찾을 수 없습니다.")
                factor_rows = [
                    dict(row) for row in conn.execute(
                        "SELECT * FROM risk_factors WHERE model_id=? ORDER BY sort_order",
                        (base_model_id,),
                    )
                ]
                factor_by_code = {str(row["code"]): row for row in factor_rows}
                if not set(adjustable_codes).issubset(factor_by_code):
                    raise ValueError("기본 위험 계산기의 평가 항목 정의가 올바르지 않습니다.")

                formula = load_json(base["formula_json"], {})
                if not isinstance(formula, dict):
                    raise ValueError("기본 위험 계산식이 올바르지 않습니다.")
                found: set[str] = set()

                def tailor_expression(expression: Any) -> dict[str, Any]:
                    if not isinstance(expression, dict):
                        raise ValueError("기본 위험 계산식이 올바르지 않습니다.")
                    result = dict(expression)
                    code = result.get("factor")
                    if isinstance(code, str) and code in weights:
                        if "weight" not in result:
                            raise ValueError("조정 대상이 가중 계산 항목으로 정의되어 있지 않습니다.")
                        result["weight"] = weights[code]
                        found.add(code)
                    terms = result.get("terms")
                    if isinstance(terms, list):
                        result["terms"] = [tailor_expression(term) for term in terms]
                    return result

                formula = tailor_expression(formula)
                if found != set(adjustable_codes):
                    raise ValueError("기본 위험 계산식에서 조정할 평가 항목을 모두 찾을 수 없습니다.")
                formula["base_model_id"] = base_model_id

                for row in factor_rows:
                    if row["code"] in weights:
                        row["weight"] = weights[row["code"]]
                factor_names = {str(row["code"]): str(row["name"]) for row in factor_rows}

                def expression_text(expression: dict[str, Any]) -> str:
                    if isinstance(expression.get("factor"), str):
                        label = factor_names.get(expression["factor"], expression["factor"])
                        if "weight" in expression:
                            return f"{float(expression['weight']):g}×{label}"
                        return label
                    terms = expression.get("terms") or []
                    rendered = [expression_text(term) for term in terms]
                    if expression.get("op") == "multiply":
                        return " × ".join(f"({item})" if " + " in item else item for item in rendered)
                    if expression.get("op") == "weighted_sum":
                        return " + ".join(rendered)
                    raise ValueError("기본 위험 계산식이 올바르지 않습니다.")

                formula_text = "S = " + expression_text(formula)
                min_values: dict[str, float] = {}
                max_values: dict[str, float] = {}
                for row in factor_rows:
                    levels = load_json(row["levels_json"], [])
                    values = [float(level["value"]) for level in levels]
                    if not values or not all(math.isfinite(value) for value in values):
                        raise ValueError("기본 위험 계산기의 척도 정의가 올바르지 않습니다.")
                    min_values[row["code"]] = min(values)
                    max_values[row["code"]] = max(values)
                score_min = self._evaluate_risk_formula(formula, min_values, factor_names)[0]
                score_max = self._evaluate_risk_formula(formula, max_values, factor_names)[0]

                prefix = f"TAILORED-{assessment_id}-V"
                revisions = []
                for row in conn.execute(
                    "SELECT id FROM risk_models WHERE assessment_id=? AND id LIKE ?",
                    (assessment_id, f"{prefix}%"),
                ):
                    match = re.fullmatch(re.escape(prefix) + r"(\d+)", str(row["id"]))
                    if match:
                        revisions.append(int(match.group(1)))
                model_id = f"{prefix}{max(revisions, default=0) + 1}"
                conn.execute(
                    "UPDATE risk_models SET active=0 WHERE assessment_id=? AND model_kind='CUSTOM'",
                    (assessment_id,),
                )
                weight_note = ", ".join(
                    f"{factor_names[code]} {weights[code] * 100:g}%" for code in adjustable_codes
                )
                conn.execute(
                    """INSERT INTO risk_models(
                           id,name,description,method,decimals,bands_json,source_note,basis,
                           formula_text,formula_json,score_min,score_max,sort_order,active,
                           assessment_id,model_kind
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,'CUSTOM')""",
                    (
                        model_id, f"{base['name']} (평가별 조정)",
                        "기본 계산기 구조를 유지하고 이 평가에서 가중치만 조정한 계산기",
                        base["method"], base["decimals"], base["bands_json"],
                        f"기본 구조: {base['source_note']} · 평가별 사용자 조정: {weight_note}",
                        "ASSESSMENT_CUSTOM", formula_text, dump_json(formula), score_min,
                        score_max, base["sort_order"], assessment_id,
                    ),
                )
                conn.executemany(
                    """INSERT INTO risk_factors(
                           model_id,code,name,factor_group,question,weight,levels_json,sort_order
                       ) VALUES(?,?,?,?,?,?,?,?)""",
                    [
                        (
                            model_id, row["code"], row["name"], row["factor_group"],
                            row["question"], row["weight"], row["levels_json"], row["sort_order"],
                        )
                        for row in factor_rows
                    ],
                )
                conn.execute(
                    """UPDATE cart_items
                       SET factor_values_json='{}',factor_reasons_json='{}',llm_risk_json=NULL,
                           risk_score=NULL,risk_level=NULL,calculation_trace_json='{}',
                           risk_review_status='UNASSESSED'
                       WHERE cart_id IN (SELECT id FROM shopping_carts WHERE assessment_id=?)""",
                    (assessment_id,),
                )
                self._invalidate_matrix(conn, assessment_id)
                conn.execute(
                    """UPDATE assessments
                       SET risk_model_id=?,matrix_confirmed=0,current_step=5,updated_at=?
                       WHERE id=?""",
                    (model_id, now_iso(), assessment_id),
                )
                model = next(
                    item for item in self._risk_models(conn, model_id, assessment_id)
                    if item["id"] == model_id
                )
                conn.commit()
                return model
            except Exception:
                conn.rollback()
                raise

    def save_custom_risk_model(
        self, assessment_id: int, payload: Any, owner_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("사용자 정의 위험 계산기 형식을 확인해 주세요.")
        name = clean_text(payload.get("name", payload.get("calculator_name"))) or "사용자 정의 위험 계산기"
        description = clean_text(payload.get("description")) or "이 평가에서 정의한 가중합 위험 계산기"
        if len(name) > 160:
            raise ValueError("위험 계산기 이름은 160자 이내로 입력해 주세요.")
        if len(description) > 2_000:
            raise ValueError("위험 계산기 설명은 2,000자 이내로 입력해 주세요.")
        raw_decimals = payload.get("decimals", 2)
        if isinstance(raw_decimals, bool):
            raise ValueError("반올림 자릿수 형식을 확인해 주세요.")
        try:
            numeric_decimals = float(raw_decimals)
        except (TypeError, ValueError) as exc:
            raise ValueError("반올림 자릿수 형식을 확인해 주세요.") from exc
        if not math.isfinite(numeric_decimals) or not numeric_decimals.is_integer():
            raise ValueError("반올림 자릿수 형식을 확인해 주세요.")
        decimals = int(numeric_decimals)
        if decimals < 0 or decimals > 6:
            raise ValueError("반올림 자릿수는 0 이상 6 이하로 입력해 주세요.")
        factors = self._normalize_custom_risk_factors(
            payload.get("factors", payload.get("factor_definitions"))
        )
        if payload.get("normalized_weights") is True and not math.isclose(
            sum(factor["weight"] for factor in factors), 1.0,
            rel_tol=0.0, abs_tol=1e-9,
        ):
            raise ValueError("평가 항목 중요도의 합계가 100%가 되어야 합니다.")
        formula = {
            "op": "weighted_sum",
            "terms": [
                {"factor": factor["code"], "weight": factor["weight"]}
                for factor in factors
            ],
        }
        formula_text = "S = " + " + ".join(
            f"{factor['weight']:g}×{factor['name']}" for factor in factors
        )
        score_min = sum(min(float(level["value"]) for level in factor["levels"]) * factor["weight"] for factor in factors)
        score_max = sum(max(float(level["value"]) for level in factor["levels"]) * factor["weight"] for factor in factors)
        if not math.isfinite(score_min) or not math.isfinite(score_max):
            raise ValueError("사용자 정의 계산기의 점수 범위를 계산할 수 없습니다.")

        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                assessment = self._require_owned_assessment(conn, assessment_id, owner_id)
                carts = list(conn.execute(
                    "SELECT status,context_status FROM shopping_carts WHERE assessment_id=?",
                    (assessment_id,),
                ))
                if any(cart["context_status"] == "LEGACY_AGGREGATED" for cart in carts):
                    raise ValueError(
                        "기존 Target 집계형 쇼핑 카트는 읽기 전용입니다. "
                        "Attack Case별 Entry/Target을 다시 지정·확정해 주세요."
                    )
                if not assessment["threat_model_confirmed"] or not carts or any(cart["status"] != "REVIEWED" for cart in carts):
                    raise ValueError("모든 쇼핑 카트의 타당성 검토를 먼저 완료해 주세요.")
                prefix = f"CUSTOM-{assessment_id}-V"
                revisions = []
                for row in conn.execute(
                    "SELECT id FROM risk_models WHERE assessment_id=? AND model_kind='CUSTOM'",
                    (assessment_id,),
                ):
                    match = re.fullmatch(re.escape(prefix) + r"(\d+)", str(row["id"]))
                    if match:
                        revisions.append(int(match.group(1)))
                model_id = f"{prefix}{max(revisions, default=0) + 1}"
                conn.execute(
                    "UPDATE risk_models SET active=0 WHERE assessment_id=? AND model_kind='CUSTOM'",
                    (assessment_id,),
                )
                conn.execute(
                    """INSERT INTO risk_models(
                           id,name,description,method,decimals,bands_json,source_note,basis,
                           formula_text,formula_json,score_min,score_max,sort_order,active,
                           assessment_id,model_kind
                       ) VALUES(?,?,?,?,?,'[]',?,?,?,?,?,?,60,1,?,'CUSTOM')""",
                    (
                        model_id, name, description, "weighted_sum", decimals,
                        "평가별 사용자 정의 · 사용자가 검토한 metadata", "ASSESSMENT_CUSTOM",
                        formula_text, dump_json(formula), score_min, score_max, assessment_id,
                    ),
                )
                conn.execute("DELETE FROM risk_factors WHERE model_id=?", (model_id,))
                conn.executemany(
                    """INSERT INTO risk_factors(
                           model_id,code,name,factor_group,question,weight,levels_json,sort_order
                       ) VALUES(?,?,?,?,?,?,?,?)""",
                    [
                        (
                            model_id, factor["code"], factor["name"], factor["factor_group"],
                            factor["question"], factor["weight"], dump_json(factor["levels"]),
                            factor["sort_order"],
                        )
                        for factor in factors
                    ],
                )
                conn.execute(
                    """UPDATE cart_items
                       SET factor_values_json='{}',factor_reasons_json='{}',llm_risk_json=NULL,
                           risk_score=NULL,risk_level=NULL,calculation_trace_json='{}',
                           risk_review_status='UNASSESSED'
                       WHERE cart_id IN (
                           SELECT id FROM shopping_carts WHERE assessment_id=?
                       )""",
                    (assessment_id,),
                )
                self._invalidate_matrix(conn, assessment_id)
                conn.execute(
                    """UPDATE assessments
                       SET risk_model_id=?,matrix_confirmed=0,current_step=5,updated_at=?
                       WHERE id=?""",
                    (model_id, now_iso(), assessment_id),
                )
                model = next(
                    item for item in self._risk_models(conn, model_id, assessment_id)
                    if item["id"] == model_id
                )
                conn.commit()
                return model
            except Exception:
                conn.rollback()
                raise

    def select_risk_model(
        self, assessment_id: int, model_id: str, owner_id: str | None = None,
    ) -> None:
        with closing(self.connect()) as conn, conn:
            self._require_owned_assessment(conn, assessment_id, owner_id)
            if not conn.execute(
                """SELECT 1 FROM risk_models
                   WHERE id=? AND active=1 AND (assessment_id IS NULL OR assessment_id=?)""",
                (model_id, assessment_id),
            ).fetchone():
                raise ValueError("위험 평가 모델을 찾을 수 없습니다.")
            current = conn.execute("SELECT risk_model_id FROM assessments WHERE id=?", (assessment_id,)).fetchone()
            if not current:
                raise LookupError("평가를 찾을 수 없습니다.")
            assessment = conn.execute("SELECT threat_model_confirmed FROM assessments WHERE id=?", (assessment_id,)).fetchone()
            carts = list(conn.execute(
                "SELECT status,context_status FROM shopping_carts WHERE assessment_id=?",
                (assessment_id,),
            ))
            if any(cart["context_status"] == "LEGACY_AGGREGATED" for cart in carts):
                raise ValueError(
                    "기존 Target 집계형 쇼핑 카트는 읽기 전용입니다. "
                    "Attack Case별 Entry/Target을 다시 지정·확정해 주세요."
                )
            if not assessment["threat_model_confirmed"] or not carts or any(cart["status"] != "REVIEWED" for cart in carts):
                raise ValueError("모든 쇼핑 카트의 타당성 검토를 먼저 완료해 주세요.")
            if current["risk_model_id"] == model_id:
                return
            if current["risk_model_id"] != model_id:
                conn.execute(
                    "UPDATE cart_items SET factor_values_json='{}',factor_reasons_json='{}',llm_risk_json=NULL,risk_score=NULL,risk_level=NULL,calculation_trace_json='{}',risk_review_status='UNASSESSED' WHERE cart_id IN (SELECT id FROM shopping_carts WHERE assessment_id=?)",
                    (assessment_id,),
                )
                self._invalidate_matrix(conn, assessment_id)
            conn.execute(
                "UPDATE assessments SET risk_model_id=?,matrix_confirmed=0,current_step=5,updated_at=? WHERE id=?",
                (model_id, now_iso(), assessment_id),
            )

    @staticmethod
    def _evaluate_risk_formula(
        expression: dict[str, Any], values: dict[str, float], factor_names: dict[str, str],
    ) -> tuple[float, dict[str, Any]]:
        if not isinstance(expression, dict):
            raise ValueError("위험 평가 모델의 계산식이 올바르지 않습니다.")
        if "factor" in expression:
            code = expression.get("factor")
            if not isinstance(code, str) or code not in values:
                raise ValueError("위험 평가 모델이 정의되지 않은 요인을 참조합니다.")
            value = values[code]
            return value, {"type": "factor", "code": code, "name": factor_names[code], "value": value}

        operator = expression.get("op")
        terms = expression.get("terms")
        if operator not in {"weighted_sum", "multiply"} or not isinstance(terms, list) or not terms:
            raise ValueError("지원하지 않는 위험 계산식입니다.")

        trace_terms: list[dict[str, Any]] = []
        if operator == "weighted_sum":
            result = 0.0
            for term in terms:
                if not isinstance(term, dict):
                    raise ValueError("가중합 계산식이 올바르지 않습니다.")
                try:
                    weight = float(term["weight"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError("가중합 계산식의 가중치가 올바르지 않습니다.") from exc
                if not math.isfinite(weight):
                    raise ValueError("가중합 계산식의 가중치가 올바르지 않습니다.")
                value, child_trace = CNTaraDB._evaluate_risk_formula(term, values, factor_names)
                subtotal = value * weight
                result += subtotal
                trace_terms.append({"weight": weight, "value": value, "subtotal": subtotal, "term": child_trace})
        else:
            result = 1.0
            for term in terms:
                value, child_trace = CNTaraDB._evaluate_risk_formula(term, values, factor_names)
                result *= value
                trace_terms.append({"value": value, "term": child_trace})
        if not math.isfinite(result):
            raise ValueError("위험 점수를 계산할 수 없습니다.")
        return result, {"type": operator, "terms": trace_terms, "result": result}

    @staticmethod
    def _round_half_even(value: float, decimals: int) -> float:
        """Mirror static/risk-calculation.js for an identical browser preview."""
        if not math.isfinite(value) or not isinstance(decimals, int) or not 0 <= decimals <= 12:
            raise ValueError("위험 점수 반올림 설정이 올바르지 않습니다.")
        if value == 0:
            return value
        scale = 10 ** decimals
        numerator, denominator = abs(value).as_integer_ratio()
        numerator *= scale
        quotient, remainder = divmod(numerator, denominator)
        doubled = remainder * 2
        if doubled > denominator or (doubled == denominator and quotient % 2):
            quotient += 1
        result = quotient / scale
        return -result if value < 0 else result

    def _calculate_risk_values(
        self,
        model: sqlite3.Row | dict[str, Any],
        factors: list[dict[str, Any]],
        values: Any,
        reasons: Any,
    ) -> dict[str, Any]:
        if not isinstance(values, dict) or not isinstance(reasons, dict):
            raise ValueError("위험 요인 값과 판단 근거 형식을 확인해 주세요.")
        expected_codes = {str(factor["code"]) for factor in factors}
        if set(values) != expected_codes or set(reasons) != expected_codes:
            raise ValueError("선택한 모델의 위험 요인만 빠짐없이 입력해 주세요.")
        numeric_values: dict[str, float] = {}
        clean_reasons: dict[str, str] = {}
        for factor in factors:
            code = str(factor["code"])
            levels = factor.get("levels")
            if not isinstance(levels, list):
                levels = load_json(factor.get("levels_json", "[]"), [])
            allowed = {float(level["value"]) for level in levels}
            if isinstance(values.get(code), bool):
                raise ValueError(f"'{factor['name']}' 평가값 형식을 확인해 주세요.")
            try:
                value = float(values[code])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"'{factor['name']}' 평가값을 선택해 주세요.") from exc
            if not math.isfinite(value) or value not in allowed:
                raise ValueError(f"'{factor['name']}' 평가값이 허용 범위를 벗어났습니다.")
            reason = clean_text(reasons.get(code))
            if len(reason) > 10_000:
                raise ValueError(f"'{factor['name']}'의 판단 근거는 10,000자 이하여야 합니다.")
            numeric_values[code] = value
            clean_reasons[code] = reason
        formula = load_json(model["formula_json"], {})
        if formula:
            raw_score, expression_trace = self._evaluate_risk_formula(
                formula, numeric_values, {factor["code"]: factor["name"] for factor in factors},
            )
        elif model["method"] == "weighted_sum":
            raw_score = sum(numeric_values[factor["code"]] * float(factor["weight"]) for factor in factors)
            expression_trace = {"type": "legacy_weighted_sum", "result": raw_score}
        elif model["method"] == "product":
            raw_score = math.prod(numeric_values[factor["code"]] for factor in factors)
            expression_trace = {"type": "legacy_product", "result": raw_score}
        else:
            raise ValueError("지원하지 않는 위험 계산 방식입니다.")
        decimals = int(model["decimals"])
        score = self._round_half_even(raw_score, decimals)
        risk_level = self._risk_level(score, load_json(model["bands_json"], []))
        calculation_trace = {
            "model_id": model["id"],
            "model_name": model["name"],
            "formula": model["formula_text"],
            "basis": model["basis"],
            "raw_score": raw_score,
            "decimals": decimals,
            "final_score": score,
            "expression": expression_trace,
        }
        return {
            "numeric_values": numeric_values,
            "clean_reasons": clean_reasons,
            "risk_score": score,
            "risk_level": risk_level,
            "calculation_trace": calculation_trace,
        }

    @staticmethod
    def _risk_status_for_saved_values(
        llm_risk_json: str | None,
        numeric_values: dict[str, float],
        factors: list[dict[str, Any]],
    ) -> str:
        suggestion = load_json(llm_risk_json, None)
        if not isinstance(suggestion, dict):
            return "USER_REVIEWED"
        recommendations = suggestion.get("factors")
        expected_codes = {str(factor["code"]) for factor in factors}
        if not isinstance(recommendations, dict) or set(recommendations) != expected_codes:
            return "USER_MODIFIED"
        for code in expected_codes:
            recommendation = recommendations.get(code)
            if not isinstance(recommendation, dict):
                return "USER_MODIFIED"
            if recommendation.get("information_status", "RECOMMENDED") != "RECOMMENDED":
                return "USER_MODIFIED"
            raw_value = recommendation.get("value")
            if isinstance(raw_value, bool):
                return "USER_MODIFIED"
            try:
                if float(raw_value) != numeric_values[code]:
                    return "USER_MODIFIED"
            except (TypeError, ValueError):
                return "USER_MODIFIED"
        return "USER_REVIEWED"

    def score_item(
        self, item_id: int, values: dict[str, Any], reasons: dict[str, Any],
        owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            self._require_owned_item(conn, item_id, owner_id)
            context = conn.execute(
                """SELECT ci.*,sc.assessment_id,sc.status AS cart_status,a.risk_model_id
                   FROM cart_items ci JOIN shopping_carts sc ON sc.id=ci.cart_id
                   JOIN assessments a ON a.id=sc.assessment_id WHERE ci.id=?""",
                (item_id,),
            ).fetchone()
            if not context:
                raise LookupError("쇼핑 카트 항목을 찾을 수 없습니다.")
            if context["review_status"] != "PLAUSIBLE":
                raise ValueError("타당함으로 확정된 공격 벡터만 위험을 평가할 수 있습니다.")
            if context["cart_status"] != "REVIEWED":
                raise ValueError("쇼핑 카트의 타당성 검토를 먼저 완료해 주세요.")
            if not context["risk_model_id"]:
                raise ValueError("위험 평가 모델을 먼저 선택해 주세요.")
            model = conn.execute(
                """SELECT * FROM risk_models
                   WHERE id=? AND (assessment_id IS NULL OR assessment_id=?)""",
                (context["risk_model_id"], context["assessment_id"]),
            ).fetchone()
            if not model:
                raise ValueError("이 평가에서 사용할 수 없는 위험 평가 모델입니다.")
            factors = [dict(row) for row in conn.execute("SELECT * FROM risk_factors WHERE model_id=? ORDER BY sort_order", (model["id"],))]
            result = self._calculate_risk_values(model, factors, values, reasons)
            review_status = self._risk_status_for_saved_values(
                context["llm_risk_json"], result["numeric_values"], factors
            )
            conn.execute(
                """UPDATE cart_items SET factor_values_json=?,factor_reasons_json=?,risk_score=?,risk_level=?,
                   calculation_trace_json=?,risk_review_status=? WHERE id=?""",
                (
                    dump_json(result["numeric_values"]), dump_json(result["clean_reasons"]),
                    result["risk_score"], result["risk_level"], dump_json(result["calculation_trace"]),
                    review_status, item_id,
                ),
            )
            self._invalidate_matrix(conn, context["assessment_id"], 5)
            return {
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "risk_review_status": review_status,
                "calculation_trace": result["calculation_trace"],
            }

    def score_items_batch(
        self,
        cart_id: int,
        items: Any,
        owner_id: str | None = None,
        expected_model_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(items, list) or len(items) > 500:
            raise ValueError("전체 위험 평가 목록 형식을 확인해 주세요.")
        normalized_inputs: list[dict[str, Any]] = []
        seen: set[int] = set()
        for raw in items:
            if not isinstance(raw, dict):
                raise ValueError("각 위험 평가는 객체 형식이어야 합니다.")
            item_id = raw.get("item_id")
            if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id <= 0:
                raise ValueError("위험 평가 항목 ID를 확인해 주세요.")
            if item_id in seen:
                raise ValueError("중복된 위험 평가 항목이 있습니다.")
            seen.add(item_id)
            normalized_inputs.append(
                {"item_id": item_id, "values": raw.get("values"), "reasons": raw.get("reasons")}
            )

        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cart = self._require_owned_cart(conn, cart_id, owner_id)
                if cart["status"] != "REVIEWED":
                    raise ValueError("쇼핑 카트의 타당성 검토를 먼저 완료해 주세요.")
                model = conn.execute(
                    """SELECT rm.* FROM assessments a JOIN risk_models rm ON rm.id=a.risk_model_id
                       WHERE a.id=? AND rm.active=1
                         AND (rm.assessment_id IS NULL OR rm.assessment_id=a.id)""",
                    (cart["assessment_id"],),
                ).fetchone()
                if not model:
                    raise ValueError("위험 평가 모델을 먼저 선택해 주세요.")
                if expected_model_id is not None and str(model["id"]) != str(expected_model_id):
                    raise ValueError("위험 평가 입력 후 계산 모델이 변경되었습니다. 현재 모델로 다시 검토해 주세요.")
                factors = [
                    dict(row) for row in conn.execute(
                        "SELECT * FROM risk_factors WHERE model_id=? ORDER BY sort_order", (model["id"],)
                    )
                ]
                current_rows = {
                    int(row["id"]): row
                    for row in conn.execute(
                        """SELECT id,llm_risk_json FROM cart_items
                           WHERE cart_id=? AND review_status='PLAUSIBLE'""",
                        (cart_id,),
                    )
                }
                if seen != set(current_rows):
                    raise ValueError("현재 쇼핑 카트의 모든 타당한 공격 벡터 위험 평가를 한 번에 보내 주세요.")
                pending: list[dict[str, Any]] = []
                for raw in normalized_inputs:
                    result = self._calculate_risk_values(
                        model, factors, raw["values"], raw["reasons"]
                    )
                    result["item_id"] = raw["item_id"]
                    result["risk_review_status"] = self._risk_status_for_saved_values(
                        current_rows[raw["item_id"]]["llm_risk_json"], result["numeric_values"], factors
                    )
                    pending.append(result)
                for result in pending:
                    conn.execute(
                        """UPDATE cart_items
                           SET factor_values_json=?,factor_reasons_json=?,risk_score=?,risk_level=?,
                               calculation_trace_json=?,risk_review_status=?
                           WHERE id=? AND cart_id=? AND review_status='PLAUSIBLE'""",
                        (
                            dump_json(result["numeric_values"]), dump_json(result["clean_reasons"]),
                            result["risk_score"], result["risk_level"],
                            dump_json(result["calculation_trace"]), result["risk_review_status"],
                            result["item_id"], cart_id,
                        ),
                    )
                if pending:
                    self._invalidate_matrix(conn, int(cart["assessment_id"]), 5)
                conn.commit()
                return {
                    "ok": True,
                    "cart_id": cart_id,
                    "saved_count": len(pending),
                    "items": [
                        {
                            "item_id": result["item_id"],
                            "risk_score": result["risk_score"],
                            "risk_level": result["risk_level"],
                            "risk_review_status": result["risk_review_status"],
                            "calculation_trace": result["calculation_trace"],
                        }
                        for result in pending
                    ],
                }
            except Exception:
                conn.rollback()
                raise

    @staticmethod
    def _risk_level(score: float, bands: list[dict[str, Any]]) -> str | None:
        for band in bands:
            if float(band.get("min", float("-inf"))) <= score <= float(band.get("max", float("inf"))):
                return str(band.get("label", "")) or None
        return None

    def generate_matrix(
        self, assessment_id: int, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            self._ensure_attack_vector_catalog_ids(conn)
            assessment = self._require_owned_assessment(conn, assessment_id, owner_id)
            if not assessment["threat_model_confirmed"]:
                raise ValueError("사이버 위협 모델을 먼저 확정해 주세요.")
            if not assessment["risk_model_id"]:
                raise ValueError("위험 평가 모델을 먼저 선택해 주세요.")
            carts = [
                dict(row) for row in conn.execute(
                """SELECT sc.*,ac.name AS attack_case_name,ac.intended_effect,
                              ac.rationale,ac.path_mode,ac.status AS attack_case_status,
                              ac.entry_node_ids_json
                       FROM shopping_carts sc
                       LEFT JOIN attack_cases ac ON ac.id=sc.attack_case_id
                       WHERE sc.assessment_id=? ORDER BY sc.id""",
                    (assessment_id,),
                )
            ]
            if not carts:
                raise ValueError("생성된 쇼핑 카트가 없습니다.")
            if any(cart["context_status"] == "LEGACY_AGGREGATED" for cart in carts):
                raise ValueError(
                    "기존 Target 집계형 쇼핑 카트가 있습니다. Attack Case별 Entry/Target을 다시 지정·확정해 주세요."
                )
            if any(cart["status"] != "REVIEWED" for cart in carts):
                raise ValueError("모든 쇼핑 카트의 타당성 검토를 완료해 주세요.")
            rows_by_vector: dict[str, dict[str, Any]] = {}
            for cart in carts:
                items = [dict(row) for row in conn.execute(
                    """SELECT ci.*,av.catalog_id AS attack_vector_catalog_id,
                              av.name AS attack_vector_name,av.source AS attack_vector_source,
                              av.source_identifier AS attack_vector_source_id
                       FROM cart_items ci JOIN attack_vectors av ON av.id=ci.attack_vector_id
                       WHERE ci.cart_id=? AND ci.review_status='PLAUSIBLE' ORDER BY av.id""",
                    (cart["id"],),
                )]
                for item in items:
                    if item["risk_score"] is None or item["risk_review_status"] not in {
                        "USER_REVIEWED", "USER_MODIFIED",
                    }:
                        raise ValueError(f"'{cart['name']}' 쇼핑 카트의 위험 평가가 완료되지 않았습니다.")
                    row = rows_by_vector.setdefault(
                        item["attack_vector_id"],
                        {
                            "attack_vector_id": item["attack_vector_id"],
                            "attack_vector_catalog_id": item["attack_vector_catalog_id"],
                            "attack_vector_name": item["attack_vector_name"],
                            "source": item["attack_vector_source"],
                            "cells": {},
                            "representative_score": float(item["risk_score"]),
                            "risk_level": item["risk_level"],
                        },
                    )
                    row["cells"][str(cart["id"])] = {
                        "included": True,
                        "score": float(item["risk_score"]),
                        "risk_level": item["risk_level"],
                    }
                    if float(item["risk_score"]) > float(row["representative_score"]):
                        row["representative_score"] = float(item["risk_score"])
                        row["risk_level"] = item["risk_level"]
            rows = sorted(rows_by_vector.values(), key=lambda row: (-float(row["representative_score"]), row["attack_vector_id"]))
            for rank, row in enumerate(rows, 1):
                row["rank"] = rank
                for cart in carts:
                    row["cells"].setdefault(str(cart["id"]), {"included": False, "score": None, "risk_level": None})
            data = {
                "assessment_id": assessment_id,
                "risk_model_id": assessment["risk_model_id"],
                "carts": [
                    {
                        "id": cart["id"],
                        "name": cart["name"],
                        "attack_case_id": cart["attack_case_id"],
                        "attack_case_name": cart["attack_case_name"],
                        "entry_node_id": cart["entry_node_id"],
                        "entry_node_ids": load_json(
                            cart.get("entry_node_ids_json"),
                            [cart["entry_node_id"]] if cart.get("entry_node_id") else [],
                        ),
                        "target_node_id": cart["target_node_id"],
                        "intended_effect": cart["intended_effect"],
                        "rationale": cart["rationale"],
                        "path_mode": cart["path_mode"],
                        "context_status": cart["context_status"],
                    }
                    for cart in carts
                ],
                "rows": rows,
            }
            self._invalidate_crra(conn, assessment_id)
            conn.execute(
                """INSERT INTO susceptibility_matrices(assessment_id,risk_model_id,data_json,status,created_at)
                   VALUES(?,?,?,'DRAFT',?)
                   ON CONFLICT(assessment_id) DO UPDATE SET risk_model_id=excluded.risk_model_id,
                   data_json=excluded.data_json,status='DRAFT',created_at=excluded.created_at""",
                (assessment_id, assessment["risk_model_id"], dump_json(data), now_iso()),
            )
            conn.execute("UPDATE assessments SET current_step=6,matrix_confirmed=0,updated_at=? WHERE id=?", (now_iso(), assessment_id))
            return data

    def confirm_matrix(self, assessment_id: int, owner_id: str | None = None) -> None:
        with closing(self.connect()) as conn, conn:
            self._require_owned_assessment(conn, assessment_id, owner_id)
            self._require_case_scoped_analysis(conn, assessment_id)
            if not conn.execute("SELECT 1 FROM susceptibility_matrices WHERE assessment_id=?", (assessment_id,)).fetchone():
                raise ValueError("먼저 위협 민감도 매트릭스를 생성해 주세요.")
            conn.execute("UPDATE susceptibility_matrices SET status='CONFIRMED' WHERE assessment_id=?", (assessment_id,))
            conn.execute("UPDATE assessments SET matrix_confirmed=1,updated_at=? WHERE id=?", (now_iso(), assessment_id))

    def llm_context(
        self, item_id: int, include_model: bool = False, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            self._require_owned_item(conn, item_id, owner_id)
            row = conn.execute(
                """SELECT ci.*,av.name AS av_name,av.description AS av_description,av.source AS av_source,
                          av.reference_url AS av_reference_url,av.prerequisite AS av_prerequisite,
                          sc.name AS cart_name,sc.attack_case_id,
                          sc.entry_node_id AS cart_entry_node_id,sc.target_node_id,
                          sc.assessment_id,sc.status AS cart_status,sc.context_status,
                          ac.name AS attack_case_name,ac.intended_effect,
                          ac.rationale AS attack_case_rationale,ac.path_mode,
                          ac.path_rationale,ac.path_edge_ids_json,ac.entry_node_ids_json,
                          ac.actor_snapshot_json,ac.status AS attack_case_status,
                          a.evaluation_target,a.scope_in,a.scope_out,a.threat_range,a.lifecycle_phase,
                          a.actor_type,a.actor_motivation,a.actor_intent,
                          a.actor_capabilities,a.technical_info,a.scope_profile_json,
                          a.external_llm_allowed,a.risk_model_id
                   FROM cart_items ci JOIN attack_vectors av ON av.id=ci.attack_vector_id
                   JOIN shopping_carts sc ON sc.id=ci.cart_id JOIN assessments a ON a.id=sc.assessment_id
                   LEFT JOIN attack_cases ac ON ac.id=sc.attack_case_id
                   WHERE ci.id=?""",
                (item_id,),
            ).fetchone()
            if not row:
                raise LookupError("쇼핑 카트 항목을 찾을 수 없습니다.")
            if not row["external_llm_allowed"]:
                raise ValueError("이 평가에서는 외부 LLM 전송이 허용되지 않았습니다.")
            if row["context_status"] == "LEGACY_AGGREGATED":
                raise ValueError(
                    "기존 Target 집계형 쇼핑 카트는 Attack Case를 다시 지정·확정한 뒤 LLM을 사용할 수 있습니다."
                )
            node_rows = conn.execute(
                "SELECT id,name,asset_type_id,description,is_entry,is_target FROM dfd_nodes WHERE assessment_id=?",
                (row["assessment_id"],),
            )
            node_map = {node["id"]: dict(node) for node in node_rows}
            related_ids = load_json(row["related_node_ids_json"], [])
            entry_ids = load_json(row["related_entry_ids_json"], [])
            if not entry_ids and row["cart_entry_node_id"]:
                entry_ids = [row["cart_entry_node_id"]]
            path_node_rows = list(
                conn.execute(
                    """SELECT node_id,sequence_order,role FROM attack_case_nodes
                       WHERE attack_case_id=? ORDER BY sequence_order,node_id""",
                    (row["attack_case_id"],),
                )
            ) if row["attack_case_id"] is not None else []
            path_node_ids = [str(item["node_id"]) for item in path_node_rows]
            path_edge_ids = {
                str(value) for value in load_json(row["path_edge_ids_json"], [])
            }
            case_flows = []
            if row["path_mode"] == "DIRECTED":
                for edge in conn.execute(
                    "SELECT * FROM dfd_edges WHERE assessment_id=? ORDER BY rowid",
                    (row["assessment_id"],),
                ):
                    if str(edge["id"]) not in path_edge_ids:
                        continue
                    case_flows.append(
                        {
                            "source": node_map.get(edge["source_node_id"], {}).get(
                                "name", edge["source_node_id"]
                            ),
                            "target": node_map.get(edge["target_node_id"], {}).get(
                                "name", edge["target_node_id"]
                            ),
                            "protocol": edge["protocol"],
                            "data_type": edge["data_type"],
                        }
                    )
            context = {
                "attack_vector": {
                    "id": row["attack_vector_id"],
                    "name": row["av_name"],
                    "description": row["av_description"],
                    "source": row["av_source"],
                    "reference_url": row["av_reference_url"],
                    # Keep missing prerequisites explicit.
                    "prerequisite": clean_text(row["av_prerequisite"]) or None,
                },
                "assessment": {
                    "evaluation_target": row["evaluation_target"], "scope_in": row["scope_in"],
                    "scope_out": row["scope_out"], "threat_range": row["threat_range"],
                    "lifecycle_phase": row["lifecycle_phase"],
                    "actor_type": row["actor_type"], "actor_motivation": row["actor_motivation"],
                    "actor_intent": row["actor_intent"], "actor_capabilities": row["actor_capabilities"],
                    "technical_info": row["technical_info"],
                    "scope_profile": load_json(row["scope_profile_json"], {}),
                },
                "shopping_cart": row["cart_name"],
                "attack_case": {
                    "id": row["attack_case_id"],
                    "name": row["attack_case_name"],
                    "entry_node_id": row["cart_entry_node_id"],
                    "entry_node_ids": load_json(
                        row["entry_node_ids_json"],
                        [row["cart_entry_node_id"]] if row["cart_entry_node_id"] else [],
                    ),
                    "target_node_id": row["target_node_id"],
                    "intended_effect": row["intended_effect"],
                    "rationale": row["attack_case_rationale"],
                    "path_mode": row["path_mode"],
                    "path_rationale": row["path_rationale"],
                    "path_node_ids": path_node_ids,
                    "path_nodes": [node_map[node_id] for node_id in path_node_ids if node_id in node_map],
                    "path_edge_ids": sorted(path_edge_ids),
                    "actor_snapshot": load_json(row["actor_snapshot_json"], {}),
                    "status": row["attack_case_status"],
                },
                "cart_item_decision": {
                    "review_status": row["review_status"],
                    "decision_reason": row["decision_reason"],
                    "addition_reason": row["addition_reason"],
                },
                "target": node_map.get(row["target_node_id"]),
                "entry_points": [node_map[node_id] for node_id in entry_ids if node_id in node_map],
                "related_nodes": [node_map[node_id] for node_id in related_ids if node_id in node_map],
                "mapping_evidence": load_json(row["mapping_evidence_json"], []),
                "data_flows": case_flows,
            }
            if include_model:
                if row["cart_status"] != "REVIEWED" or row["review_status"] != "PLAUSIBLE":
                    raise ValueError("타당함으로 확정된 공격 벡터만 위험 평가 추천을 요청할 수 있습니다.")
                if not row["risk_model_id"]:
                    raise ValueError("위험 평가 모델을 먼저 선택해 주세요.")
                context["risk_model"] = next(
                    model for model in self._risk_models(
                        conn, row["risk_model_id"], int(row["assessment_id"])
                    )
                    if model["id"] == row["risk_model_id"]
                )
            return context

    @staticmethod
    def _required_text(
        data: dict[str, Any], field: str, label: str | None = None,
        *, max_length: int | None = None,
    ) -> str:
        value = clean_text(data.get(field))
        if not value:
            raise ValueError(f"{label or field} 값을 입력해 주세요.")
        if max_length is not None and len(value) > max_length:
            raise ValueError(
                f"{label or field}은(는) 최대 {max_length:,}자까지 입력할 수 있습니다."
            )
        return value

    @staticmethod
    def _related_node_ids(value: Any) -> list[str]:
        values = value if isinstance(value, list) else [value]
        node_ids: list[str] = []
        for raw_value in values:
            if not isinstance(raw_value, str):
                raise ValueError("관련 DFD 구성요소 값은 문자열이어야 합니다.")
            node_id = raw_value.strip()
            if node_id and node_id not in node_ids:
                node_ids.append(node_id)
        if len(node_ids) > 100:
            raise ValueError("관련 DFD 구성요소는 최대 100개까지 선택할 수 있습니다.")
        return node_ids

    @staticmethod
    def _require_related_nodes(
        conn: sqlite3.Connection, assessment_id: int, node_ids: list[str],
    ) -> None:
        placeholders = ",".join("?" for _ in node_ids)
        found = {
            str(row["id"])
            for row in conn.execute(
                f"SELECT id FROM dfd_nodes WHERE assessment_id=? AND id IN ({placeholders})",
                (assessment_id, *node_ids),
            )
        }
        if found != set(node_ids):
            raise ValueError("관련 DFD 구성요소를 찾을 수 없습니다.")

    @staticmethod
    def _reference_url(value: Any) -> str:
        url = clean_text(value)
        if not url:
            return ""
        if len(url) > 2_000:
            raise ValueError("참조 링크가 너무 깁니다.")
        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("참조 링크는 http:// 또는 https://로 시작하는 주소를 입력해 주세요.")
        return url

    @staticmethod
    def _nullable_text(
        value: Any, label: str, *, max_length: int,
    ) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"{label} 값은 문자열이어야 합니다.")
        normalized = value.strip()
        if len(normalized) > max_length:
            raise ValueError(f"{label}은(는) 최대 {max_length:,}자까지 입력할 수 있습니다.")
        return normalized or None

    @staticmethod
    def _active_km_release(conn: sqlite3.Connection) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM km_releases WHERE active=1 ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            raise ValueError("활성 KM 릴리스를 찾을 수 없습니다.")
        return row

    @staticmethod
    def _validate_enum(value: Any, allowed: set[str], label: str) -> str:
        normalized = clean_text(value).upper()
        if normalized not in allowed:
            raise ValueError(f"{label} 값이 올바르지 않습니다: {value}")
        return normalized

    def km_workspace(self) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            self._ensure_attack_vector_catalog_ids(conn)
            release = self._active_km_release(conn)
            asset_types = [
                dict(row) for row in conn.execute(
                    "SELECT * FROM asset_types ORDER BY sort_order,name,id"
                )
            ]
            attack_vectors = [
                dict(row) for row in conn.execute(
                    "SELECT * FROM attack_vectors WHERE assessment_id IS NULL ORDER BY catalog_id,id"
                )
            ]
            asset_mappings = [
                dict(row) for row in conn.execute(
                    """SELECT aav.*,at.name AS asset_type_name,at.group_name,at.dfd_kind,
                              av.name AS attack_vector_name,av.catalog_id AS attack_vector_catalog_id
                       FROM asset_attack_vectors aav
                       JOIN asset_types at ON at.id=aav.asset_type_id
                       JOIN attack_vectors av ON av.id=aav.attack_vector_id
                       WHERE aav.km_release_id=? AND av.assessment_id IS NULL
                       ORDER BY at.sort_order,at.name,aav.attack_vector_id""",
                    (release["id"],),
                )
            ]
            countermeasures = [
                dict(row) for row in conn.execute(
                    "SELECT * FROM countermeasures WHERE assessment_id IS NULL ORDER BY id"
                )
            ]
            mappings = [
                dict(row) for row in conn.execute(
                    """SELECT m.*,av.name AS av_name,av.catalog_id AS av_catalog_id,cm.name AS cm_name
                       FROM av_countermeasure_mappings m
                       JOIN attack_vectors av ON av.id=m.av_id
                       JOIN countermeasures cm ON cm.id=m.cm_id
                       WHERE m.km_release_id=? ORDER BY m.av_id,m.cm_id,m.effect""",
                    (release["id"],),
                )
            ]
            groups: list[dict[str, Any]] = []
            for row in conn.execute(
                "SELECT * FROM vector_groups WHERE km_release_id=? ORDER BY name,id", (release["id"],)
            ):
                group = dict(row)
                group["member_ids"] = [
                    member["av_id"] for member in conn.execute(
                        "SELECT av_id FROM vector_group_members WHERE group_id=? ORDER BY av_id", (row["id"],)
                    )
                ]
                groups.append(group)
            return {
                "release": dict(release),
                "asset_types": asset_types,
                "dfd_catalog_elements": self._catalog_elements(conn, release["id"]),
                "dfd_flow_templates": self._catalog_flows(conn, release["id"]),
                "asset_mappings": asset_mappings,
                "attack_vectors": attack_vectors,
                "countermeasures": countermeasures,
                "mappings": mappings,
                "vector_groups": groups,
            }

    @staticmethod
    def _km_asset_mapping_row(
        conn: sqlite3.Connection, release_id: int, asset_type_id: str, attack_vector_id: str,
    ) -> sqlite3.Row | None:
        return conn.execute(
            """SELECT aav.*,at.name AS asset_type_name,at.group_name,at.dfd_kind,
                      av.name AS attack_vector_name,av.catalog_id AS attack_vector_catalog_id
               FROM asset_attack_vectors aav
               JOIN asset_types at ON at.id=aav.asset_type_id
               JOIN attack_vectors av ON av.id=aav.attack_vector_id
               WHERE aav.km_release_id=? AND aav.asset_type_id=?
                 AND aav.attack_vector_id=? AND av.assessment_id IS NULL""",
            (release_id, asset_type_id, attack_vector_id),
        ).fetchone()

    def save_km_asset_mapping(self, data: dict[str, Any]) -> dict[str, Any]:
        asset_type_id = self._required_text(data, "asset_type_id", "자산 유형 ID")
        attack_vector_id = self._required_text(data, "attack_vector_id", "공격 벡터 ID")
        if len(asset_type_id) > 128:
            raise ValueError("자산 유형 ID 값이 너무 깁니다.")
        if len(attack_vector_id) > 128:
            raise ValueError("공격 벡터 ID 값이 너무 깁니다.")
        raw_note = data.get("mapping_note", "")
        if not isinstance(raw_note, str):
            raise ValueError("매핑 근거 값은 문자열이어야 합니다.")
        mapping_note = raw_note.strip()
        if len(mapping_note) > 10_000:
            raise ValueError("매핑 근거 값이 너무 깁니다.")

        with closing(self.connect()) as conn, conn:
            release = self._active_km_release(conn)
            if not conn.execute("SELECT 1 FROM asset_types WHERE id=?", (asset_type_id,)).fetchone():
                raise ValueError("자산 유형을 찾을 수 없습니다.")
            attack_vector = conn.execute(
                "SELECT assessment_id FROM attack_vectors WHERE id=?", (attack_vector_id,)
            ).fetchone()
            if not attack_vector or attack_vector["assessment_id"] is not None:
                raise ValueError("전역 KM 공격 벡터를 찾을 수 없습니다.")
            conn.execute(
                """INSERT INTO asset_attack_vectors(
                       km_release_id,asset_type_id,attack_vector_id,mapping_note
                   ) VALUES(?,?,?,?)
                   ON CONFLICT(km_release_id,asset_type_id,attack_vector_id)
                   DO UPDATE SET mapping_note=excluded.mapping_note""",
                (release["id"], asset_type_id, attack_vector_id, mapping_note),
            )
            row = self._km_asset_mapping_row(
                conn, int(release["id"]), asset_type_id, attack_vector_id,
            )
            if not row:  # pragma: no cover
                raise RuntimeError("저장한 자산 유형–공격 벡터 매핑을 불러올 수 없습니다.")
            return dict(row)

    def delete_km_asset_mapping(self, data: dict[str, Any]) -> dict[str, Any]:
        asset_type_id = self._required_text(data, "asset_type_id", "자산 유형 ID")
        attack_vector_id = self._required_text(data, "attack_vector_id", "공격 벡터 ID")
        if len(asset_type_id) > 128:
            raise ValueError("자산 유형 ID 값이 너무 깁니다.")
        if len(attack_vector_id) > 128:
            raise ValueError("공격 벡터 ID 값이 너무 깁니다.")

        with closing(self.connect()) as conn, conn:
            release = self._active_km_release(conn)
            result = conn.execute(
                """DELETE FROM asset_attack_vectors
                   WHERE km_release_id=? AND asset_type_id=? AND attack_vector_id=?""",
                (release["id"], asset_type_id, attack_vector_id),
            )
            if result.rowcount == 0:
                raise LookupError("활성 KM 릴리스에서 자산 유형–공격 벡터 매핑을 찾을 수 없습니다.")
            return {
                "ok": True,
                "km_release_id": int(release["id"]),
                "asset_type_id": asset_type_id,
                "attack_vector_id": attack_vector_id,
            }

    def save_km_attack_vector(self, data: dict[str, Any]) -> dict[str, Any]:
        requested_id = self._nullable_text(data.get("id"), "공격 벡터 내부 ID", max_length=200)
        name = self._required_text(data, "name", "공격 벡터 이름")
        description = self._required_text(data, "description", "공격 벡터 설명")
        prerequisite = self._nullable_text(
            data.get("prerequisite"), "공격 벡터 선행조건", max_length=10_000,
        )
        source = self._required_text(data, "source", "출처")
        reference_url = self._reference_url(data.get("reference_url"))
        source_identifier = self._nullable_text(
            data.get("source_identifier"), "출처 원본 ID", max_length=200,
        )
        if not source_identifier and requested_id and not re.match(
            r"^(?:AV|CUSTOM|LOCAL|KM-AV)-", requested_id, re.IGNORECASE,
        ):
            source_identifier = requested_id
        av_id = requested_id or f"KM-AV-{uuid.uuid4().hex[:12].upper()}"
        with closing(self.connect()) as conn, conn:
            local = conn.execute("SELECT assessment_id,catalog_id FROM attack_vectors WHERE id=?", (av_id,)).fetchone()
            if local and local["assessment_id"] is not None:
                raise ValueError("평가 전용 공격 벡터 ID는 전역 KM에서 사용할 수 없습니다.")
            catalog_id = clean_text(local["catalog_id"]) if local else ""
            if not catalog_id:
                catalog_id = self._next_attack_vector_catalog_id(conn)
            conn.execute(
                """INSERT INTO attack_vectors(
                       id,catalog_id,name,description,prerequisite,source,source_identifier,reference_url,assessment_id
                   ) VALUES(?,?,?,?,?,?,?,?,NULL)
                   ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,
                   prerequisite=excluded.prerequisite,source=excluded.source,
                   source_identifier=excluded.source_identifier,reference_url=excluded.reference_url""",
                (
                    av_id,
                    catalog_id,
                    name, description, prerequisite, source, source_identifier, reference_url,
                ),
            )
            return dict(conn.execute("SELECT * FROM attack_vectors WHERE id=?", (av_id,)).fetchone())

    def save_km_countermeasure(self, data: dict[str, Any]) -> dict[str, Any]:
        cm_id = self._required_text(data, "id", "대응책 ID")
        name = self._required_text(data, "name", "대응책 이름")
        description = self._required_text(data, "description", "대응책 설명")
        source = self._required_text(data, "source", "출처")
        reference_url = clean_text(data.get("reference_url"))
        with closing(self.connect()) as conn, conn:
            local = conn.execute("SELECT assessment_id FROM countermeasures WHERE id=?", (cm_id,)).fetchone()
            if local and local["assessment_id"] is not None:
                raise ValueError("평가 전용 대응책 ID는 전역 KM에서 사용할 수 없습니다.")
            conn.execute(
                """INSERT INTO countermeasures(id,name,description,source,reference_url,assessment_id)
                   VALUES(?,?,?,?,?,NULL)
                   ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,
                   source=excluded.source,reference_url=excluded.reference_url""",
                (cm_id, name, description, source, reference_url),
            )
            return dict(conn.execute("SELECT * FROM countermeasures WHERE id=?", (cm_id,)).fetchone())

    def save_km_mapping(self, data: dict[str, Any]) -> dict[str, Any]:
        av_id = self._required_text(data, "av_id", "공격 벡터 ID")
        cm_id = self._required_text(data, "cm_id", "대응책 ID")
        effect = self._validate_enum(data.get("effect"), {"PREVENT", "DETECT", "RESPOND"}, "효과")
        confidence = self._validate_enum(data.get("confidence"), {"HIGH", "MODERATE", "LOW"}, "신뢰도")
        rationale = self._required_text(data, "rationale", "매핑 근거")
        review_status = self._validate_enum(
            data.get("review_status", "REVIEW_REQUIRED"), {"APPROVED", "REVIEW_REQUIRED"}, "검토 상태"
        )
        with closing(self.connect()) as conn, conn:
            release_id = int(data.get("km_release_id") or self._active_km_release(conn)["id"])
            if not conn.execute("SELECT 1 FROM km_releases WHERE id=?", (release_id,)).fetchone():
                raise ValueError("KM 릴리스를 찾을 수 없습니다.")
            av = conn.execute("SELECT assessment_id FROM attack_vectors WHERE id=?", (av_id,)).fetchone()
            cm = conn.execute("SELECT assessment_id FROM countermeasures WHERE id=?", (cm_id,)).fetchone()
            if not av or av["assessment_id"] is not None:
                raise ValueError("전역 KM 공격 벡터를 찾을 수 없습니다.")
            if not cm or cm["assessment_id"] is not None:
                raise ValueError("전역 KM 대응책을 찾을 수 없습니다.")
            mapping_id = data.get("id")
            try:
                if mapping_id is not None:
                    current = conn.execute(
                        "SELECT 1 FROM av_countermeasure_mappings WHERE id=?", (int(mapping_id),)
                    ).fetchone()
                    if not current:
                        raise LookupError("KM 매핑을 찾을 수 없습니다.")
                    conn.execute(
                        """UPDATE av_countermeasure_mappings SET km_release_id=?,av_id=?,cm_id=?,effect=?,
                           confidence=?,rationale=?,review_status=? WHERE id=?""",
                        (release_id, av_id, cm_id, effect, confidence, rationale, review_status, int(mapping_id)),
                    )
                    row_id = int(mapping_id)
                else:
                    existing = conn.execute(
                        """SELECT id FROM av_countermeasure_mappings
                           WHERE km_release_id=? AND av_id=? AND cm_id=? AND effect=?""",
                        (release_id, av_id, cm_id, effect),
                    ).fetchone()
                    if existing:
                        row_id = int(existing["id"])
                        conn.execute(
                            """UPDATE av_countermeasure_mappings SET confidence=?,rationale=?,review_status=?
                               WHERE id=?""",
                            (confidence, rationale, review_status, row_id),
                        )
                    else:
                        row_id = int(conn.execute(
                            """INSERT INTO av_countermeasure_mappings(
                                   km_release_id,av_id,cm_id,effect,confidence,rationale,review_status
                               ) VALUES(?,?,?,?,?,?,?)""",
                            (release_id, av_id, cm_id, effect, confidence, rationale, review_status),
                        ).lastrowid)
            except sqlite3.IntegrityError as exc:
                raise ValueError("동일한 공격 벡터·대응책·효과 매핑이 이미 존재합니다.") from exc
            return dict(conn.execute("SELECT * FROM av_countermeasure_mappings WHERE id=?", (row_id,)).fetchone())

    def delete_km_mapping(self, mapping_id: int) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            result = conn.execute("DELETE FROM av_countermeasure_mappings WHERE id=?", (int(mapping_id),))
            if result.rowcount == 0:
                raise LookupError("KM 매핑을 찾을 수 없습니다.")
            return {"ok": True}

    def save_vector_group(self, data: dict[str, Any]) -> dict[str, Any]:
        name = self._required_text(data, "name", "그룹 이름")
        description = clean_text(data.get("description"))
        with closing(self.connect()) as conn, conn:
            release_id = int(data.get("km_release_id") or self._active_km_release(conn)["id"])
            group_id = int(data["id"]) if data.get("id") is not None else None
            parent_id = int(data["parent_id"]) if data.get("parent_id") is not None else None
            if parent_id is not None:
                parent = conn.execute("SELECT * FROM vector_groups WHERE id=?", (parent_id,)).fetchone()
                if not parent or int(parent["km_release_id"]) != release_id:
                    raise ValueError("같은 KM 릴리스의 상위 그룹을 선택해 주세요.")
                if group_id == parent_id:
                    raise ValueError("그룹 자신을 상위 그룹으로 지정할 수 없습니다.")
                cursor = parent_id
                while cursor is not None:
                    if cursor == group_id:
                        raise ValueError("그룹 계층에 순환 관계를 만들 수 없습니다.")
                    ancestor = conn.execute("SELECT parent_id FROM vector_groups WHERE id=?", (cursor,)).fetchone()
                    cursor = int(ancestor["parent_id"]) if ancestor and ancestor["parent_id"] is not None else None
            try:
                if group_id is None:
                    group_id = int(conn.execute(
                        "INSERT INTO vector_groups(km_release_id,name,description,parent_id) VALUES(?,?,?,?)",
                        (release_id, name, description, parent_id),
                    ).lastrowid)
                else:
                    result = conn.execute(
                        """UPDATE vector_groups SET km_release_id=?,name=?,description=?,parent_id=? WHERE id=?""",
                        (release_id, name, description, parent_id, group_id),
                    )
                    if result.rowcount == 0:
                        raise LookupError("벡터 그룹을 찾을 수 없습니다.")
            except sqlite3.IntegrityError as exc:
                raise ValueError("같은 KM 릴리스에 동일한 그룹 이름이 이미 존재합니다.") from exc
            return dict(conn.execute("SELECT * FROM vector_groups WHERE id=?", (group_id,)).fetchone())

    def set_vector_group_members(self, group_id: int, av_ids: list[str]) -> dict[str, Any]:
        if not isinstance(av_ids, list) or any(not clean_text(value) for value in av_ids):
            raise ValueError("공격 벡터 ID 목록 형식을 확인해 주세요.")
        normalized = [clean_text(value) for value in av_ids]
        if len(set(normalized)) != len(normalized):
            raise ValueError("공격 벡터 ID를 중복 지정할 수 없습니다.")
        with closing(self.connect()) as conn, conn:
            group = conn.execute("SELECT * FROM vector_groups WHERE id=?", (int(group_id),)).fetchone()
            if not group:
                raise LookupError("벡터 그룹을 찾을 수 없습니다.")
            if normalized:
                placeholders = ",".join("?" for _ in normalized)
                valid = {
                    row["id"] for row in conn.execute(
                        f"SELECT id FROM attack_vectors WHERE assessment_id IS NULL AND id IN ({placeholders})", normalized
                    )
                }
                unknown = sorted(set(normalized) - valid)
                if unknown:
                    raise ValueError("전역 KM 공격 벡터를 찾을 수 없습니다: " + ", ".join(unknown))
            conn.execute("DELETE FROM vector_group_members WHERE group_id=?", (int(group_id),))
            conn.executemany(
                "INSERT INTO vector_group_members(group_id,av_id) VALUES(?,?)",
                [(int(group_id), av_id) for av_id in normalized],
            )
            return {"group_id": int(group_id), "member_ids": sorted(normalized)}

    def import_km_mappings(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        if not isinstance(rows, list):
            raise ValueError("KM 매핑 가져오기 데이터는 행 목록이어야 합니다.")
        result: dict[str, Any] = {"processed": len(rows), "created": 0, "updated": 0, "errors": []}
        seen: set[tuple[Any, str, str, str]] = set()
        for index, row in enumerate(rows, 1):
            try:
                if not isinstance(row, dict):
                    raise ValueError("행은 객체 형식이어야 합니다.")
                effect = clean_text(row.get("effect")).upper()
                release_id = row.get("km_release_id")
                with closing(self.connect()) as conn:
                    actual_release = int(release_id or self._active_km_release(conn)["id"])
                key = (actual_release, clean_text(row.get("av_id")), clean_text(row.get("cm_id")), effect)
                if key in seen:
                    raise ValueError("가져오기 파일 안에 중복된 매핑이 있습니다.")
                seen.add(key)
                with closing(self.connect()) as conn:
                    existed = conn.execute(
                        """SELECT 1 FROM av_countermeasure_mappings
                           WHERE km_release_id=? AND av_id=? AND cm_id=? AND effect=?""",
                        (actual_release, key[1], key[2], effect),
                    ).fetchone() is not None
                self.save_km_mapping(row)
                result["updated" if existed else "created"] += 1
            except (ValueError, LookupError, TypeError) as exc:
                result["errors"].append({"row": index, "error": str(exc)})
        return result

    def km_mapping_context(self, av_id: str, cm_id: str) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            release = self._active_km_release(conn)
            av = conn.execute(
                "SELECT * FROM attack_vectors WHERE id=? AND assessment_id IS NULL", (clean_text(av_id),)
            ).fetchone()
            cm = conn.execute(
                "SELECT * FROM countermeasures WHERE id=? AND assessment_id IS NULL", (clean_text(cm_id),)
            ).fetchone()
            if not av or not cm:
                raise LookupError("전역 KM 공격 벡터 또는 대응책을 찾을 수 없습니다.")
            mappings = [
                dict(row) for row in conn.execute(
                    """SELECT * FROM av_countermeasure_mappings
                       WHERE km_release_id=? AND av_id=? AND cm_id=? ORDER BY effect""",
                    (release["id"], av["id"], cm["id"]),
                )
            ]
            return {
                "release": dict(release),
                "attack_vector": dict(av),
                "countermeasure": dict(cm),
                "mappings": mappings,
            }

    @staticmethod
    def _require_case_scoped_analysis(
        conn: sqlite3.Connection, assessment_id: int,
    ) -> None:
        if conn.execute(
            """SELECT 1 FROM shopping_carts
               WHERE assessment_id=? AND context_status='LEGACY_AGGREGATED'
               LIMIT 1""",
            (assessment_id,),
        ).fetchone():
            raise ValueError(
                "기존 Target 집계형 결과는 읽기 전용입니다. "
                "Attack Case별 Entry/Target을 다시 지정·확정해 주세요."
            )

    @classmethod
    def _require_crra(
        cls, conn: sqlite3.Connection, assessment_id: int, owner_id: str | None = None,
    ) -> sqlite3.Row:
        cls._require_owned_assessment(conn, assessment_id, owner_id)
        cls._require_case_scoped_analysis(conn, assessment_id)
        settings = conn.execute("SELECT * FROM crra_settings WHERE assessment_id=?", (assessment_id,)).fetchone()
        if not settings:
            raise ValueError("CRRA를 먼저 시작해 주세요.")
        return settings

    @staticmethod
    def _matrix_rows(conn: sqlite3.Connection, assessment_id: int, require_confirmed: bool = False) -> list[dict[str, Any]]:
        matrix = conn.execute(
            "SELECT * FROM susceptibility_matrices WHERE assessment_id=?", (assessment_id,)
        ).fetchone()
        if not matrix or (require_confirmed and matrix["status"] != "CONFIRMED"):
            raise ValueError("확정된 위협 민감도 매트릭스가 필요합니다.")
        data = load_json(matrix["data_json"], {})
        rows = data.get("rows", []) if isinstance(data, dict) else []
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("위협 민감도 매트릭스 데이터 형식이 올바르지 않습니다.")
        return rows

    @staticmethod
    def _reset_crra_scores(conn: sqlite3.Connection, assessment_id: int, step: int = 2) -> None:
        conn.execute("DELETE FROM crra_solutions WHERE assessment_id=?", (assessment_id,))
        conn.execute(
            """UPDATE crra_countermeasures SET cost_score=NULL,cost_reason='',prevent_count=0,
               detect_count=0,respond_count=0,utility=NULL,uc_ratio=NULL,selected=0,selection_reason=''
               WHERE assessment_id=?""",
            (assessment_id,),
        )
        conn.execute(
            "UPDATE crra_settings SET current_step=?,status='DRAFT',gap_reason='' WHERE assessment_id=?",
            (step, assessment_id),
        )
        conn.execute(
            "UPDATE assessments SET crra_current_step=?,crra_confirmed=0,updated_at=? WHERE id=?",
            (step, now_iso(), assessment_id),
        )

    @staticmethod
    def _rank_crra_countermeasures(rows: list[dict[str, Any]], strategy: str) -> list[dict[str, Any]]:
        infinity = float("inf")

        def key(row: dict[str, Any]) -> tuple[Any, ...]:
            utility = float(row["utility"]) if row.get("utility") is not None else float("-inf")
            ratio = float(row["uc_ratio"]) if row.get("uc_ratio") is not None else float("-inf")
            cost = float(row["cost_score"]) if row.get("cost_score") is not None else infinity
            if strategy == "MAX_UTILITY":
                return (-utility, -ratio, cost, row["cm_id"])
            if strategy == "LEAST_COST":
                return (cost, -utility, -ratio, row["cm_id"])
            return (-ratio, -utility, cost, row["cm_id"])

        ranked = sorted(rows, key=key)
        for rank, row in enumerate(ranked, 1):
            row["rank"] = rank
            row["uc_ratio_display"] = round(float(row["uc_ratio"]), 2) if row.get("uc_ratio") is not None else None
        return ranked

    def crra_workspace(
        self, assessment_id: int, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            self._ensure_attack_vector_catalog_ids(conn)
            assessment = self._require_owned_assessment(
                conn,
                assessment_id,
                owner_id,
                "a.id,a.km_release_id,a.external_llm_allowed,a.crra_current_step,a.crra_confirmed",
            )
            settings_row = conn.execute("SELECT * FROM crra_settings WHERE assessment_id=?", (assessment_id,)).fetchone()
            settings = dict(settings_row) if settings_row else None
            matrix = conn.execute("SELECT data_json,status FROM susceptibility_matrices WHERE assessment_id=?", (assessment_id,)).fetchone()
            matrix_rows = []
            matrix_status = None
            if matrix:
                matrix_rows = load_json(matrix["data_json"], {}).get("rows", [])
                matrix_status = matrix["status"]
                attack_vectors_by_id = {
                    str(row["id"]): dict(row)
                    for row in conn.execute("SELECT id,catalog_id,name FROM attack_vectors")
                }
                for row in matrix_rows:
                    if isinstance(row, dict):
                        attack_vector = attack_vectors_by_id.get(
                            str(row.get("attack_vector_id", row.get("av_id", "")))
                        )
                        if attack_vector:
                            row["attack_vector_catalog_id"] = str(attack_vector["catalog_id"])
                            row["attack_vector_name"] = str(attack_vector["name"])
            vectors = [
                dict(row) for row in conn.execute(
                    """SELECT v.*,av.catalog_id AS av_catalog_id,
                              av.name AS av_name,av.description AS av_description,av.source AS av_source
                       FROM crra_vectors v JOIN attack_vectors av ON av.id=v.av_id
                       WHERE v.assessment_id=? ORDER BY v.rank,v.av_id""",
                    (assessment_id,),
                )
            ]
            for vector in vectors:
                vector["selected"] = bool(vector["selected"])
            mapping_items = [
                dict(row) for row in conn.execute(
                    """SELECT mi.*,av.catalog_id AS av_catalog_id,
                              av.name AS av_name,av.description AS av_description,
                              av.source AS av_source,av.reference_url AS av_reference_url,
                              cm.name AS cm_name,cm.description AS cm_description,
                              cm.source AS cm_source,cm.reference_url AS cm_reference_url,
                              cm.assessment_id AS cm_assessment_id,
                              cv.risk_score AS av_risk_score,cv.rank AS av_rank,
                              cv.selection_reason AS av_selection_reason,
                              km.rationale AS km_rationale,km.review_status AS km_review_status
                       FROM crra_mapping_items mi
                       JOIN attack_vectors av ON av.id=mi.av_id
                       JOIN countermeasures cm ON cm.id=mi.cm_id
                       JOIN crra_vectors cv
                         ON cv.assessment_id=mi.assessment_id AND cv.av_id=mi.av_id
                       LEFT JOIN av_countermeasure_mappings km
                         ON mi.item_source LIKE 'KM:%'
                        AND km.id=CAST(SUBSTR(mi.item_source,4) AS INTEGER)
                       WHERE mi.assessment_id=?
                       ORDER BY cv.rank,mi.av_id,cm.name,mi.effect,mi.id""",
                    (assessment_id,),
                )
            ]
            cm_rows = [
                dict(row) for row in conn.execute(
                    """SELECT cc.*,cm.name AS cm_name,cm.description AS cm_description,cm.source AS cm_source,
                              cm.reference_url AS cm_reference_url,cm.assessment_id AS cm_assessment_id
                       FROM crra_countermeasures cc JOIN countermeasures cm ON cm.id=cc.cm_id
                       WHERE cc.assessment_id=?""",
                    (assessment_id,),
                )
            ]
            countermeasures = self._rank_crra_countermeasures(
                cm_rows, settings["strategy"] if settings else "BANG_FOR_BUCK"
            )
            for cm in countermeasures:
                cm["selected"] = bool(cm["selected"])
            solution_row = conn.execute("SELECT * FROM crra_solutions WHERE assessment_id=?", (assessment_id,)).fetchone()
            solution = None
            if solution_row:
                solution = dict(solution_row)
                solution["data"] = load_json(solution.pop("data_json"), {})
                catalog_by_id = {
                    str(row["id"]): str(row["catalog_id"])
                    for row in conn.execute("SELECT id,catalog_id FROM attack_vectors")
                }
                for row in solution["data"].get("rows", []):
                    if isinstance(row, dict):
                        row["av_catalog_id"] = catalog_by_id.get(
                            str(row.get("av_id", row.get("attack_vector_id", ""))),
                            str(row.get("av_catalog_id", "")),
                        )
            return {
                "assessment": self._assessment_dict(assessment),
                "settings": settings,
                "matrix_status": matrix_status,
                "matrix_rows": matrix_rows,
                "vectors": vectors,
                "mapping_items": mapping_items,
                "countermeasures": countermeasures,
                "solution": solution,
            }

    def initialize_crra(
        self, assessment_id: int, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            assessment = self._require_owned_assessment(conn, assessment_id, owner_id)
            self._require_case_scoped_analysis(conn, assessment_id)
            rows = self._matrix_rows(conn, assessment_id, require_confirmed=True)
            if not assessment["matrix_confirmed"]:
                raise ValueError("확정된 위협 민감도 매트릭스가 필요합니다.")
            existing = conn.execute("SELECT 1 FROM crra_settings WHERE assessment_id=?", (assessment_id,)).fetchone()
            if existing and int(assessment["crra_current_step"]) > 0:
                return self.crra_workspace(assessment_id, owner_id)
            conn.execute("DELETE FROM crra_settings WHERE assessment_id=?", (assessment_id,))
            conn.execute(
                "INSERT INTO crra_settings(assessment_id,current_step,status,min_total) VALUES(?,1,'DRAFT',1)",
                (assessment_id,),
            )
            seen: set[str] = set()
            for fallback_rank, row in enumerate(rows, 1):
                av_id = clean_text(row.get("attack_vector_id"))
                if not av_id or av_id in seen:
                    raise ValueError("매트릭스 공격 벡터 ID가 비어 있거나 중복되었습니다.")
                seen.add(av_id)
                if not conn.execute("SELECT 1 FROM attack_vectors WHERE id=?", (av_id,)).fetchone():
                    raise ValueError(f"매트릭스 공격 벡터를 찾을 수 없습니다: {av_id}")
                risk_score = row.get("representative_score")
                try:
                    numeric_risk = float(risk_score) if risk_score is not None else None
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"매트릭스 위험 점수가 올바르지 않습니다: {av_id}") from exc
                rank_value = row.get("rank", fallback_rank)
                if isinstance(rank_value, bool):
                    raise ValueError("매트릭스 순위가 올바르지 않습니다.")
                try:
                    rank = int(rank_value)
                except (TypeError, ValueError) as exc:
                    raise ValueError("매트릭스 순위가 올바르지 않습니다.") from exc
                conn.execute(
                    """INSERT INTO crra_vectors(assessment_id,av_id,selected,selection_reason,risk_score,rank)
                       VALUES(?,?,1,'매트릭스 확정 결과에서 자동 선택',?,?)""",
                    (assessment_id, av_id, numeric_risk, rank),
                )
            conn.execute(
                "UPDATE assessments SET crra_current_step=1,crra_confirmed=0,updated_at=? WHERE id=?",
                (now_iso(), assessment_id),
            )
        return self.crra_workspace(assessment_id, owner_id)

    def save_crra_vector_selection(
        self, assessment_id: int, data: dict[str, Any], owner_id: str | None = None,
    ) -> dict[str, Any]:
        vector_ids = data.get("vector_ids")
        reasons = data.get("reasons") or {}
        if not isinstance(vector_ids, list) or not isinstance(reasons, dict):
            raise ValueError("선택 공격 벡터와 선택 근거 형식을 확인해 주세요.")
        normalized = [clean_text(value) for value in vector_ids]
        if any(not value for value in normalized) or len(normalized) != len(set(normalized)):
            raise ValueError("선택 공격 벡터 ID는 비어 있거나 중복될 수 없습니다.")
        with closing(self.connect()) as conn, conn:
            self._require_crra(conn, assessment_id, owner_id)
            available = {
                row["av_id"] for row in conn.execute("SELECT av_id FROM crra_vectors WHERE assessment_id=?", (assessment_id,))
            }
            unknown = sorted(set(normalized) - available)
            if unknown:
                raise ValueError("매트릭스에 없는 공격 벡터를 선택할 수 없습니다: " + ", ".join(unknown))
            if available and not normalized:
                raise ValueError("공격 벡터를 하나 이상 선택해 주세요.")
            selected = set(normalized)
            for av_id in available:
                reason = clean_text(reasons.get(av_id))
                conn.execute(
                    "UPDATE crra_vectors SET selected=?,selection_reason=? WHERE assessment_id=? AND av_id=?",
                    (int(av_id in selected), reason, assessment_id, av_id),
                )
            conn.execute("DELETE FROM crra_mapping_items WHERE assessment_id=?", (assessment_id,))
            conn.execute("DELETE FROM crra_countermeasures WHERE assessment_id=?", (assessment_id,))
            conn.execute("DELETE FROM crra_solutions WHERE assessment_id=?", (assessment_id,))
            conn.execute(
                "UPDATE crra_settings SET current_step=1,status='DRAFT',gap_reason='' WHERE assessment_id=?",
                (assessment_id,),
            )
            conn.execute(
                "UPDATE assessments SET crra_current_step=1,crra_confirmed=0,updated_at=? WHERE id=?",
                (now_iso(), assessment_id),
            )
        return self.crra_workspace(assessment_id, owner_id)

    def generate_crra_mappings(
        self, assessment_id: int, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            self._require_crra(conn, assessment_id, owner_id)
            assessment = conn.execute("SELECT km_release_id FROM assessments WHERE id=?", (assessment_id,)).fetchone()
            selected = [
                row["av_id"] for row in conn.execute(
                    "SELECT av_id FROM crra_vectors WHERE assessment_id=? AND selected=1", (assessment_id,)
                )
            ]
            for av_id in selected:
                for mapping in conn.execute(
                    """SELECT * FROM av_countermeasure_mappings
                       WHERE km_release_id=? AND av_id=? ORDER BY id""",
                    (assessment["km_release_id"], av_id),
                ):
                    conn.execute(
                        """INSERT OR IGNORE INTO crra_mapping_items(
                               assessment_id,av_id,cm_id,effect,confidence,review_status,decision_reason,item_source
                           ) VALUES(?,?,?,?,?,'UNREVIEWED','',?)""",
                        (assessment_id, av_id, mapping["cm_id"], mapping["effect"], mapping["confidence"], f"KM:{mapping['id']}"),
                    )
            conn.execute(
                """INSERT OR IGNORE INTO crra_countermeasures(assessment_id,cm_id)
                   SELECT DISTINCT assessment_id,cm_id FROM crra_mapping_items WHERE assessment_id=?""",
                (assessment_id,),
            )
            self._reset_crra_scores(conn, assessment_id, step=2)
        return self.crra_workspace(assessment_id, owner_id)

    def add_crra_mapping(
        self, assessment_id: int, data: dict[str, Any], owner_id: str | None = None,
    ) -> dict[str, Any]:
        av_id = self._required_text(data, "av_id", "공격 벡터 ID")
        effect = self._validate_enum(data.get("effect"), {"PREVENT", "DETECT", "RESPOND"}, "효과")
        confidence = self._validate_enum(data.get("confidence"), {"HIGH", "MODERATE", "LOW"}, "신뢰도")
        reason = self._required_text(data, "reason", "추가 근거")
        with closing(self.connect()) as conn, conn:
            self._require_crra(conn, assessment_id, owner_id)
            if not conn.execute(
                "SELECT 1 FROM crra_vectors WHERE assessment_id=? AND av_id=? AND selected=1",
                (assessment_id, av_id),
            ).fetchone():
                raise ValueError("선택된 공격 벡터에만 대응책 매핑을 추가할 수 있습니다.")
            cm_id = clean_text(data.get("cm_id"))
            if cm_id:
                cm = conn.execute("SELECT * FROM countermeasures WHERE id=?", (cm_id,)).fetchone()
                if not cm or (cm["assessment_id"] is not None and int(cm["assessment_id"]) != assessment_id):
                    raise ValueError("이 평가에서 사용할 수 있는 대응책을 찾을 수 없습니다.")
            else:
                cm_data = data.get("countermeasure")
                if not isinstance(cm_data, dict):
                    raise ValueError("기존 대응책 ID 또는 새 대응책 정보를 입력해 주세요.")
                name = self._required_text(cm_data, "name", "대응책 이름")
                description = self._required_text(cm_data, "description", "대응책 설명")
                source = self._required_text(cm_data, "source", "대응책 출처")
                cm_id = f"CUSTOM-CM-{assessment_id}-{uuid.uuid4().hex[:6].upper()}"
                conn.execute(
                    """INSERT INTO countermeasures(id,name,description,source,reference_url,assessment_id)
                       VALUES(?,?,?,?,?,?)""",
                    (cm_id, name, description, source, clean_text(cm_data.get("reference_url")), assessment_id),
                )
            try:
                item_id = int(conn.execute(
                    """INSERT INTO crra_mapping_items(
                           assessment_id,av_id,cm_id,effect,confidence,review_status,decision_reason,item_source
                       ) VALUES(?,?,?,?,?,'UNREVIEWED',?,'MANUAL')""",
                    (assessment_id, av_id, cm_id, effect, confidence, reason),
                ).lastrowid)
            except sqlite3.IntegrityError as exc:
                raise ValueError("동일한 공격 벡터·대응책·효과 매핑이 이미 존재합니다.") from exc
            conn.execute(
                "INSERT OR IGNORE INTO crra_countermeasures(assessment_id,cm_id) VALUES(?,?)",
                (assessment_id, cm_id),
            )
            self._reset_crra_scores(conn, assessment_id, step=2)
        return self.crra_workspace(assessment_id, owner_id)

    def review_crra_mapping(
        self, item_id: int, data: dict[str, Any], owner_id: str | None = None,
    ) -> dict[str, Any]:
        status = self._validate_enum(data.get("status"), {"INCLUDED", "EXCLUDED"}, "검토 상태")
        reason = self._required_text(data, "reason", "검토 근거")
        effect = data.get("effect")
        confidence = data.get("confidence")
        with closing(self.connect()) as conn, conn:
            item = self._require_owned_crra_mapping(conn, int(item_id), owner_id)
            normalized_effect = (
                self._validate_enum(effect, {"PREVENT", "DETECT", "RESPOND"}, "효과")
                if effect is not None else item["effect"]
            )
            normalized_confidence = (
                self._validate_enum(confidence, {"HIGH", "MODERATE", "LOW"}, "신뢰도")
                if confidence is not None else item["confidence"]
            )
            try:
                conn.execute(
                    """UPDATE crra_mapping_items SET effect=?,confidence=?,review_status=?,decision_reason=?
                       WHERE id=?""",
                    (normalized_effect, normalized_confidence, status, reason, int(item_id)),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("변경한 효과와 동일한 매핑 항목이 이미 존재합니다.") from exc
            self._reset_crra_scores(conn, int(item["assessment_id"]), step=2)
            assessment_id = int(item["assessment_id"])
        return self.crra_workspace(assessment_id, owner_id)

    def review_crra_mappings_batch(
        self,
        assessment_id: int,
        reviews: Any,
        owner_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate and save the complete CRRA 2.3 review as one transaction."""
        if not isinstance(reviews, list) or len(reviews) > 500:
            raise ValueError("전체 CRRA 대응책 판정 목록 형식을 확인해 주세요.")
        normalized: list[dict[str, Any]] = []
        seen: set[int] = set()
        for review in reviews:
            if not isinstance(review, dict):
                raise ValueError("각 CRRA 대응책 판정은 객체 형식이어야 합니다.")
            item_id = review.get("item_id", review.get("mapping_id"))
            alias = review.get("mapping_id")
            if (
                review.get("item_id") is not None
                and alias is not None
                and review.get("item_id") != alias
            ):
                raise ValueError("CRRA 대응책 항목 ID가 서로 일치하지 않습니다.")
            if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id <= 0:
                raise ValueError("판정할 CRRA 대응책 항목 ID를 확인해 주세요.")
            if item_id in seen:
                raise ValueError("중복된 CRRA 대응책 판정이 있습니다.")
            seen.add(item_id)
            raw_status = review.get("status")
            if not isinstance(raw_status, str):
                raise ValueError("CRRA 검토 상태가 올바르지 않습니다.")
            status = raw_status.strip().upper()
            if status not in {"UNREVIEWED", "INCLUDED", "EXCLUDED"}:
                raise ValueError("CRRA 검토 상태가 올바르지 않습니다.")
            raw_effect = review.get("effect")
            if not isinstance(raw_effect, str):
                raise ValueError("CRRA 대응 효과가 올바르지 않습니다.")
            effect = raw_effect.strip().upper()
            if effect not in {"PREVENT", "DETECT", "RESPOND"}:
                raise ValueError("CRRA 대응 효과가 올바르지 않습니다.")
            raw_confidence = review.get("confidence")
            if not isinstance(raw_confidence, str):
                raise ValueError("CRRA 효과 신뢰도가 올바르지 않습니다.")
            confidence = raw_confidence.strip().upper()
            if confidence not in {"HIGH", "MODERATE", "LOW"}:
                raise ValueError("CRRA 효과 신뢰도가 올바르지 않습니다.")
            raw_reason = review.get("reason", "")
            if not isinstance(raw_reason, str):
                raise ValueError("CRRA 판단 근거 형식을 확인해 주세요.")
            reason = raw_reason.strip()
            if len(reason) > 10_000:
                raise ValueError("CRRA 판단 근거는 10,000자 이내로 입력해 주세요.")
            if status != "UNREVIEWED" and not reason:
                raise ValueError("포함 또는 제외 판정에는 판단 근거가 필요합니다.")
            expected = review.get("expected")
            normalized_expected: dict[str, str] | None = None
            if expected is not None:
                if not isinstance(expected, dict):
                    raise ValueError("CRRA 저장 기준값 형식을 확인해 주세요.")
                expected_status_raw = expected.get("status")
                expected_effect_raw = expected.get("effect")
                expected_confidence_raw = expected.get("confidence")
                expected_reason_raw = expected.get("reason")
                if not all(isinstance(value, str) for value in (
                    expected_status_raw, expected_effect_raw,
                    expected_confidence_raw, expected_reason_raw,
                )):
                    raise ValueError("CRRA 저장 기준값이 완전하지 않습니다.")
                expected_status = expected_status_raw.strip().upper()
                expected_effect = expected_effect_raw.strip().upper()
                expected_confidence = expected_confidence_raw.strip().upper()
                if expected_status not in {"UNREVIEWED", "INCLUDED", "EXCLUDED"}:
                    raise ValueError("CRRA 저장 기준 검토 상태가 올바르지 않습니다.")
                if expected_effect not in {"PREVENT", "DETECT", "RESPOND"}:
                    raise ValueError("CRRA 저장 기준 대응 효과가 올바르지 않습니다.")
                if expected_confidence not in {"HIGH", "MODERATE", "LOW"}:
                    raise ValueError("CRRA 저장 기준 신뢰도가 올바르지 않습니다.")
                normalized_expected = {
                    "status": expected_status,
                    "effect": expected_effect,
                    "confidence": expected_confidence,
                    "reason": expected_reason_raw.strip(),
                }
            normalized.append({
                "item_id": item_id,
                "status": status,
                "effect": effect,
                "confidence": confidence,
                "reason": reason,
                "expected": normalized_expected,
            })

        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._require_crra(conn, assessment_id, owner_id)
                current_rows = conn.execute(
                    "SELECT * FROM crra_mapping_items WHERE assessment_id=? ORDER BY id",
                    (assessment_id,),
                ).fetchall()
                expected_ids = {int(row["id"]) for row in current_rows}
                if seen != expected_ids or len(normalized) != len(current_rows):
                    raise ValueError(
                        "현재 평가의 모든 CRRA 대응책 매핑 판정을 한 번에 보내 주세요."
                    )
                current_by_id = {int(row["id"]): row for row in current_rows}

                stale_ids: list[int] = []
                for review in normalized:
                    expected = review["expected"]
                    if expected is None:
                        continue
                    current = current_by_id[review["item_id"]]
                    if (
                        str(current["review_status"]) != expected["status"]
                        or str(current["effect"]) != expected["effect"]
                        or str(current["confidence"]) != expected["confidence"]
                        or str(current["decision_reason"]).strip() != expected["reason"]
                    ):
                        stale_ids.append(review["item_id"])
                if stale_ids:
                    raise ValueError(
                        "다른 화면에서 CRRA 대응책 판정이 변경되었습니다. "
                        "최신 내용을 다시 불러온 뒤 저장해 주세요 "
                        f"(항목: {', '.join(str(value) for value in stale_ids[:10])})."
                    )

                # Validate unique P/D/R effects before writing the AV-CM pair.
                desired_keys: dict[tuple[str, str, str], int] = {}
                for review in normalized:
                    current = current_by_id[review["item_id"]]
                    key = (str(current["av_id"]), str(current["cm_id"]), review["effect"])
                    prior = desired_keys.get(key)
                    if prior is not None:
                        raise ValueError(
                            "동일한 공격 벡터·대응책·효과 판정이 중복되었습니다 "
                            f"(항목 {prior}, {review['item_id']})."
                        )
                    desired_keys[key] = review["item_id"]

                changed_reviews = [
                    review for review in normalized
                    if (
                        str(current_by_id[review["item_id"]]["review_status"]) != review["status"]
                        or str(current_by_id[review["item_id"]]["effect"]) != review["effect"]
                        or str(current_by_id[review["item_id"]]["confidence"]) != review["confidence"]
                        or str(current_by_id[review["item_id"]]["decision_reason"]).strip()
                        != review["reason"]
                    )
                ]
                effect_changed_ids = [
                    review["item_id"] for review in changed_reviews
                    if str(current_by_id[review["item_id"]]["effect"]) != review["effect"]
                ]
                # Delete changed effects first so effect swaps remain atomic.
                if effect_changed_ids:
                    placeholders = ",".join("?" for _ in effect_changed_ids)
                    conn.execute(
                        f"DELETE FROM crra_mapping_items WHERE assessment_id=? AND id IN ({placeholders})",
                        (assessment_id, *effect_changed_ids),
                    )
                for review in changed_reviews:
                    current = current_by_id[review["item_id"]]
                    if review["item_id"] in effect_changed_ids:
                        conn.execute(
                            """INSERT INTO crra_mapping_items(
                                   id,assessment_id,av_id,cm_id,effect,confidence,
                                   review_status,decision_reason,item_source
                               ) VALUES(?,?,?,?,?,?,?,?,?)""",
                            (
                                review["item_id"], assessment_id, current["av_id"], current["cm_id"],
                                review["effect"], review["confidence"], review["status"],
                                review["reason"], current["item_source"],
                            ),
                        )
                    else:
                        conn.execute(
                            """UPDATE crra_mapping_items
                               SET confidence=?,review_status=?,decision_reason=?
                               WHERE id=? AND assessment_id=?""",
                            (
                                review["confidence"], review["status"], review["reason"],
                                review["item_id"], assessment_id,
                            ),
                        )
                if changed_reviews:
                    self._reset_crra_scores(conn, assessment_id, step=2)
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        workspace = self.crra_workspace(assessment_id, owner_id)
        reviewed_count = sum(review["status"] != "UNREVIEWED" for review in normalized)
        return {
            "ok": True,
            "assessment_id": assessment_id,
            "saved_count": len(normalized),
            "changed_count": len(changed_reviews),
            "reviewed_count": reviewed_count,
            "unreviewed_count": len(normalized) - reviewed_count,
            "workspace": workspace,
        }

    def complete_crra_mapping_review(
        self, assessment_id: int, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            self._require_crra(conn, assessment_id, owner_id)
            unreviewed = conn.execute(
                "SELECT COUNT(*) AS count FROM crra_mapping_items WHERE assessment_id=? AND review_status='UNREVIEWED'",
                (assessment_id,),
            ).fetchone()["count"]
            if unreviewed:
                raise ValueError("검토하지 않은 대응책 매핑이 남아 있습니다.")
            conn.execute(
                "UPDATE crra_settings SET current_step=4,status='DRAFT' WHERE assessment_id=?", (assessment_id,)
            )
            conn.execute(
                "UPDATE assessments SET crra_current_step=4,crra_confirmed=0,updated_at=? WHERE id=?",
                (now_iso(), assessment_id),
            )
        return self.crra_workspace(assessment_id, owner_id)

    @staticmethod
    def _positive_number(value: Any, label: str) -> float:
        if isinstance(value, bool):
            raise ValueError(f"{label}은 0보다 큰 숫자여야 합니다.")
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label}은 0보다 큰 숫자여야 합니다.") from exc
        if not math.isfinite(number) or number <= 0:
            raise ValueError(f"{label}은 0보다 큰 숫자여야 합니다.")
        return number

    def score_crra(
        self, assessment_id: int, data: dict[str, Any], owner_id: str | None = None,
    ) -> dict[str, Any]:
        prevent_weight = self._positive_number(data.get("prevent_weight"), "예방 가중치")
        respond_weight = self._positive_number(data.get("respond_weight"), "대응 가중치")
        strategy = self._validate_enum(
            data.get("strategy"), {"BANG_FOR_BUCK", "MAX_UTILITY", "LEAST_COST"}, "선정 전략"
        )
        costs = data.get("costs")
        if not isinstance(costs, dict):
            raise ValueError("대응책별 비용과 근거를 입력해 주세요.")
        with closing(self.connect()) as conn, conn:
            self._require_crra(conn, assessment_id, owner_id)
            if conn.execute(
                "SELECT 1 FROM crra_mapping_items WHERE assessment_id=? AND review_status='UNREVIEWED' LIMIT 1",
                (assessment_id,),
            ).fetchone():
                raise ValueError("모든 대응책 매핑을 먼저 검토해 주세요.")
            included = [
                dict(row) for row in conn.execute(
                    """SELECT av_id,cm_id,effect FROM crra_mapping_items
                       WHERE assessment_id=? AND review_status='INCLUDED'""",
                    (assessment_id,),
                )
            ]
            cm_ids = sorted({row["cm_id"] for row in included})
            if set(costs) != set(cm_ids):
                missing = sorted(set(cm_ids) - set(costs))
                extra = sorted(set(costs) - set(cm_ids))
                details = []
                if missing:
                    details.append("누락: " + ", ".join(missing))
                if extra:
                    details.append("불필요: " + ", ".join(extra))
                raise ValueError("포함된 모든 대응책의 비용만 정확히 입력해 주세요. " + "; ".join(details))
            parsed_costs: dict[str, tuple[float, str]] = {}
            for cm_id in cm_ids:
                entry = costs.get(cm_id)
                if not isinstance(entry, dict):
                    raise ValueError(f"{cm_id} 비용 입력 형식을 확인해 주세요.")
                score_value = entry.get("score")
                if isinstance(score_value, bool):
                    raise ValueError(f"{cm_id} 비용은 1~5 정수여야 합니다.")
                try:
                    score = float(score_value)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"{cm_id} 비용은 1~5 정수여야 합니다.") from exc
                if not math.isfinite(score) or score not in {1.0, 2.0, 3.0, 4.0, 5.0}:
                    raise ValueError(f"{cm_id} 비용은 1~5 정수여야 합니다.")
                reason = clean_text(entry.get("reason"))
                if not reason:
                    raise ValueError(f"{cm_id} 비용 산정 근거를 입력해 주세요.")
                parsed_costs[cm_id] = (score, reason)

            counts: dict[str, dict[str, set[str]]] = {
                cm_id: {"PREVENT": set(), "DETECT": set(), "RESPOND": set()} for cm_id in cm_ids
            }
            for row in included:
                counts[row["cm_id"]][row["effect"]].add(row["av_id"])
            conn.execute(
                """UPDATE crra_countermeasures SET cost_score=NULL,cost_reason='',prevent_count=0,
                   detect_count=0,respond_count=0,utility=NULL,uc_ratio=NULL,selected=0,selection_reason=''
                   WHERE assessment_id=?""",
                (assessment_id,),
            )
            for cm_id in cm_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO crra_countermeasures(assessment_id,cm_id) VALUES(?,?)",
                    (assessment_id, cm_id),
                )
                prevent_count = len(counts[cm_id]["PREVENT"])
                detect_count = len(counts[cm_id]["DETECT"])
                respond_count = len(counts[cm_id]["RESPOND"])
                utility = prevent_count * prevent_weight + respond_count * respond_weight
                cost_score, cost_reason = parsed_costs[cm_id]
                ratio = utility / cost_score * 100.0
                conn.execute(
                    """UPDATE crra_countermeasures SET cost_score=?,cost_reason=?,prevent_count=?,detect_count=?,
                       respond_count=?,utility=?,uc_ratio=? WHERE assessment_id=? AND cm_id=?""",
                    (
                        cost_score, cost_reason, prevent_count, detect_count, respond_count,
                        utility, ratio, assessment_id, cm_id,
                    ),
                )
            conn.execute("DELETE FROM crra_solutions WHERE assessment_id=?", (assessment_id,))
            conn.execute(
                """UPDATE crra_settings SET current_step=4,status='DRAFT',prevent_weight=?,respond_weight=?,
                   strategy=?,gap_reason='' WHERE assessment_id=?""",
                (prevent_weight, respond_weight, strategy, assessment_id),
            )
            conn.execute(
                "UPDATE assessments SET crra_current_step=4,crra_confirmed=0,updated_at=? WHERE id=?",
                (now_iso(), assessment_id),
            )
        return self.crra_workspace(assessment_id, owner_id)

    @staticmethod
    def _nonnegative_integer(value: Any, label: str) -> int:
        if isinstance(value, bool):
            raise ValueError(f"{label}은 0 이상의 정수여야 합니다.")
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label}은 0 이상의 정수여야 합니다.") from exc
        if not math.isfinite(number) or number < 0 or not number.is_integer():
            raise ValueError(f"{label}은 0 이상의 정수여야 합니다.")
        return int(number)

    @staticmethod
    def _coverage_counts(
        coverage: dict[str, dict[str, set[str]]], av_id: str, selected: set[str]
    ) -> dict[str, int]:
        mapped = coverage.get(av_id, {})
        applicable = {cm_id for cm_id in selected if cm_id in mapped}
        return {
            "total": len(applicable),
            "prevent": sum(1 for cm_id in applicable if "PREVENT" in mapped[cm_id]),
            "detect": sum(1 for cm_id in applicable if "DETECT" in mapped[cm_id]),
            "respond": sum(1 for cm_id in applicable if "RESPOND" in mapped[cm_id]),
        }

    @staticmethod
    def _criteria_met(counts: dict[str, int], minimums: dict[str, int]) -> bool:
        return (
            counts["total"] >= minimums["total"]
            and counts["prevent"] >= minimums["prevent"]
            and counts["respond"] >= minimums["respond"]
        )

    def generate_crra_solution(
        self, assessment_id: int, data: dict[str, Any], owner_id: str | None = None,
    ) -> dict[str, Any]:
        minimums = {
            "total": self._nonnegative_integer(data.get("min_total", 1), "최소 전체 대응책 수"),
            "prevent": self._nonnegative_integer(data.get("min_prevent", 0), "최소 예방 대응책 수"),
            "respond": self._nonnegative_integer(data.get("min_respond", 0), "최소 대응 대응책 수"),
        }
        explicit = data.get("selected_countermeasure_ids") if "selected_countermeasure_ids" in data else None
        if explicit is not None and not isinstance(explicit, list):
            raise ValueError("선택 대응책 ID는 목록이어야 합니다.")
        with closing(self.connect()) as conn, conn:
            self._ensure_attack_vector_catalog_ids(conn)
            settings = self._require_crra(conn, assessment_id, owner_id)
            if int(settings["current_step"]) < 4:
                raise ValueError("대응책 매핑 검토와 비용·효용 산정을 먼저 완료해 주세요.")
            vectors = [
                dict(row) for row in conn.execute(
                    """SELECT v.*,av.catalog_id AS av_catalog_id,av.name AS av_name FROM crra_vectors v
                       JOIN attack_vectors av ON av.id=v.av_id
                       WHERE v.assessment_id=? AND v.selected=1
                       ORDER BY CASE WHEN v.risk_score IS NULL THEN 1 ELSE 0 END,v.risk_score DESC,v.rank,v.av_id""",
                    (assessment_id,),
                )
            ]
            cm_rows = [
                dict(row) for row in conn.execute(
                    """SELECT cc.*,cm.name AS cm_name,cm.description AS cm_description,cm.source AS cm_source
                       FROM crra_countermeasures cc JOIN countermeasures cm ON cm.id=cc.cm_id
                       WHERE cc.assessment_id=? AND cc.cost_score IS NOT NULL""",
                    (assessment_id,),
                )
            ]
            ranked = self._rank_crra_countermeasures(cm_rows, settings["strategy"])
            rank_by_cm = {row["cm_id"]: row["rank"] for row in ranked}
            available = set(rank_by_cm)
            mapping_rows = [
                dict(row) for row in conn.execute(
                    """SELECT mi.*,cm.name AS cm_name FROM crra_mapping_items mi
                       JOIN countermeasures cm ON cm.id=mi.cm_id
                       WHERE mi.assessment_id=? AND mi.review_status='INCLUDED'
                       ORDER BY mi.id""",
                    (assessment_id,),
                )
            ]
            coverage: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
            for row in mapping_rows:
                coverage[row["av_id"]][row["cm_id"]].add(row["effect"])

            if explicit is not None:
                normalized = [clean_text(value) for value in explicit]
                if any(not value for value in normalized) or len(normalized) != len(set(normalized)):
                    raise ValueError("선택 대응책 ID는 비어 있거나 중복될 수 없습니다.")
                unknown = sorted(set(normalized) - available)
                if unknown:
                    raise ValueError("산정되지 않은 대응책을 선택할 수 없습니다: " + ", ".join(unknown))
                selected: set[str] = set(normalized)
                selection_source = "USER"
            else:
                selected = set()
                ordered_ids = [row["cm_id"] for row in ranked]
                for vector in vectors:
                    av_id = vector["av_id"]
                    while not self._criteria_met(self._coverage_counts(coverage, av_id, selected), minimums):
                        current = self._coverage_counts(coverage, av_id, selected)
                        candidates = []
                        for cm_id in ordered_ids:
                            if cm_id in selected or cm_id not in coverage.get(av_id, {}):
                                continue
                            effects = coverage[av_id][cm_id]
                            improves = (
                                current["total"] < minimums["total"]
                                or (current["prevent"] < minimums["prevent"] and "PREVENT" in effects)
                                or (current["respond"] < minimums["respond"] and "RESPOND" in effects)
                            )
                            if improves:
                                candidates.append(cm_id)
                        if not candidates:
                            break
                        selected.add(candidates[0])
                # Remove redundant low-ranked countermeasures without reducing coverage.
                def capped_signature(chosen: set[str]) -> tuple[tuple[int, int, int], ...]:
                    signature = []
                    for current_vector in vectors:
                        counts = self._coverage_counts(coverage, current_vector["av_id"], chosen)
                        signature.append(
                            (
                                min(counts["total"], minimums["total"]),
                                min(counts["prevent"], minimums["prevent"]),
                                min(counts["respond"], minimums["respond"]),
                            )
                        )
                    return tuple(signature)

                baseline_signature = capped_signature(selected)
                for cm_id in sorted(selected, key=lambda value: rank_by_cm[value], reverse=True):
                    trial = selected - {cm_id}
                    if capped_signature(trial) == baseline_signature:
                        selected = trial
                selection_source = "AUTO_GREEDY"

            solution_rows: list[dict[str, Any]] = []
            for vector in vectors:
                av_id = vector["av_id"]
                counts = self._coverage_counts(coverage, av_id, selected)
                gaps = []
                if counts["total"] < minimums["total"]:
                    gaps.append({"criterion": "TOTAL", "required": minimums["total"], "actual": counts["total"]})
                if counts["prevent"] < minimums["prevent"]:
                    gaps.append({"criterion": "PREVENT", "required": minimums["prevent"], "actual": counts["prevent"]})
                if counts["respond"] < minimums["respond"]:
                    gaps.append({"criterion": "RESPOND", "required": minimums["respond"], "actual": counts["respond"]})
                selected_mappings = [
                    {
                        "mapping_item_id": row["id"], "cm_id": row["cm_id"], "cm_name": row["cm_name"],
                        "effect": row["effect"], "confidence": row["confidence"],
                    }
                    for row in mapping_rows if row["av_id"] == av_id and row["cm_id"] in selected
                ]
                solution_rows.append(
                    {
                        "av_id": av_id,
                        "av_catalog_id": vector["av_catalog_id"],
                        "av_name": vector["av_name"],
                        "risk_score": vector["risk_score"],
                        "risk_rank": vector["rank"],
                        "selected_mappings": selected_mappings,
                        "effect_counts": counts,
                        "met": not gaps,
                        "gaps": gaps,
                    }
                )
            selected_cms = [
                {
                    "cm_id": row["cm_id"], "cm_name": row["cm_name"], "description": row["cm_description"],
                    "source": row["cm_source"], "cost_score": row["cost_score"], "utility": row["utility"],
                    "uc_ratio": row["uc_ratio"], "uc_ratio_display": row["uc_ratio_display"], "rank": row["rank"],
                }
                for row in ranked if row["cm_id"] in selected
            ]
            solution_data = {
                "assessment_id": assessment_id,
                "strategy": settings["strategy"],
                "selection_source": selection_source,
                "criteria": minimums,
                "rows": solution_rows,
                "selected_countermeasures": selected_cms,
                "selected_countermeasure_ids": [row["cm_id"] for row in selected_cms],
                "total_cost": sum(float(row["cost_score"]) for row in selected_cms),
                "has_gaps": any(not row["met"] for row in solution_rows),
            }
            conn.execute(
                "UPDATE crra_countermeasures SET selected=0,selection_reason='' WHERE assessment_id=?", (assessment_id,)
            )
            for cm_id in selected:
                conn.execute(
                    """UPDATE crra_countermeasures SET selected=1,selection_reason=?
                       WHERE assessment_id=? AND cm_id=?""",
                    ("사용자 선택" if explicit is not None else "결정적 greedy 및 중복 제거 결과", assessment_id, cm_id),
                )
            conn.execute(
                """INSERT INTO crra_solutions(assessment_id,data_json,status,updated_at)
                   VALUES(?,?,'DRAFT',?) ON CONFLICT(assessment_id) DO UPDATE SET
                   data_json=excluded.data_json,status='DRAFT',updated_at=excluded.updated_at""",
                (assessment_id, dump_json(solution_data), now_iso()),
            )
            conn.execute(
                """UPDATE crra_settings SET current_step=5,status='DRAFT',min_total=?,min_prevent=?,
                   min_respond=?,gap_reason='' WHERE assessment_id=?""",
                (minimums["total"], minimums["prevent"], minimums["respond"], assessment_id),
            )
            conn.execute(
                "UPDATE assessments SET crra_current_step=5,crra_confirmed=0,updated_at=? WHERE id=?",
                (now_iso(), assessment_id),
            )
        return self.crra_workspace(assessment_id, owner_id)

    def confirm_crra_solution(
        self, assessment_id: int, gap_reason: str = "", owner_id: str | None = None,
    ) -> dict[str, Any]:
        reason = clean_text(gap_reason)
        with closing(self.connect()) as conn, conn:
            self._require_crra(conn, assessment_id, owner_id)
            solution = conn.execute("SELECT * FROM crra_solutions WHERE assessment_id=?", (assessment_id,)).fetchone()
            if not solution:
                raise ValueError("CRRA 대응책 방안을 먼저 생성해 주세요.")
            data = load_json(solution["data_json"], {})
            has_gaps = bool(data.get("has_gaps")) or any(
                not bool(row.get("met")) for row in data.get("rows", []) if isinstance(row, dict)
            )
            if has_gaps and not reason:
                raise ValueError("충족하지 못한 대응책 기준이 있으므로 잔여 위험 수용 근거를 입력해 주세요.")
            data["gap_reason"] = reason
            conn.execute(
                "UPDATE crra_solutions SET data_json=?,status='CONFIRMED',updated_at=? WHERE assessment_id=?",
                (dump_json(data), now_iso(), assessment_id),
            )
            conn.execute(
                "UPDATE crra_settings SET status='CONFIRMED',current_step=5,gap_reason=? WHERE assessment_id=?",
                (reason, assessment_id),
            )
            conn.execute(
                "UPDATE assessments SET crra_current_step=5,crra_confirmed=1,updated_at=? WHERE id=?",
                (now_iso(), assessment_id),
            )
        return self.crra_workspace(assessment_id, owner_id)

    def crra_mapping_batch_context(
        self,
        assessment_id: int,
        mapping_ids: Any = None,
        owner_id: str | None = None,
    ) -> dict[str, Any]:
        """Build one shared Scope plus compact per-row CRRA review evidence."""
        requested_ids: list[int] | None = None
        if mapping_ids is not None:
            if not isinstance(mapping_ids, list):
                raise ValueError("mapping_ids 값은 목록이어야 합니다.")
            requested_ids = []
            for value in mapping_ids:
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    raise ValueError("CRRA 매핑 항목 ID 형식을 확인해 주세요.")
                requested_ids.append(value)
            if len(requested_ids) != len(set(requested_ids)):
                raise ValueError("mapping_ids에 중복된 값이 있습니다.")
            if not requested_ids:
                raise ValueError("LLM 초안을 만들 CRRA 매핑 항목을 하나 이상 선택해 주세요.")

        with closing(self.connect()) as conn, conn:
            self._ensure_attack_vector_catalog_ids(conn)
            assessment = self._require_owned_assessment(conn, assessment_id, owner_id)
            self._require_crra(conn, assessment_id, owner_id)
            if not assessment["external_llm_allowed"]:
                raise ValueError("이 평가에서는 외부 LLM 전송을 허용하지 않았습니다.")
            all_rows = [
                dict(row) for row in conn.execute(
                    """SELECT mi.*,av.catalog_id AS av_catalog_id,
                              av.name AS av_name,av.description AS av_description,
                              av.source AS av_source,av.reference_url AS av_reference_url,
                              cm.name AS cm_name,cm.description AS cm_description,
                              cm.source AS cm_source,cm.reference_url AS cm_reference_url,
                              cv.risk_score AS av_risk_score,cv.rank AS av_rank,
                              cv.selection_reason AS av_selection_reason,
                              km.id AS km_mapping_id,km.rationale AS km_rationale,
                              km.review_status AS km_review_status
                       FROM crra_mapping_items mi
                       JOIN attack_vectors av ON av.id=mi.av_id
                       JOIN countermeasures cm ON cm.id=mi.cm_id
                       JOIN crra_vectors cv
                         ON cv.assessment_id=mi.assessment_id AND cv.av_id=mi.av_id
                       LEFT JOIN av_countermeasure_mappings km
                         ON mi.item_source LIKE 'KM:%'
                        AND km.id=CAST(SUBSTR(mi.item_source,4) AS INTEGER)
                       WHERE mi.assessment_id=?
                       ORDER BY mi.av_id,cm.name,mi.effect,mi.id""",
                    (assessment_id,),
                )
            ]
            rows = all_rows
            available_ids = {int(row["id"]) for row in all_rows}
            if requested_ids is not None:
                unknown = sorted(set(requested_ids) - available_ids)
                if unknown:
                    raise LookupError(
                        "이 평가에서 선택한 CRRA 매핑 항목을 찾을 수 없습니다: "
                        + ", ".join(str(value) for value in unknown)
                    )
                requested = set(requested_ids)
                rows = [row for row in rows if int(row["id"]) in requested]
                order = {item_id: index for index, item_id in enumerate(requested_ids)}
                rows.sort(key=lambda row: order[int(row["id"])])

            matrix_row = conn.execute(
                "SELECT data_json,status FROM susceptibility_matrices WHERE assessment_id=?",
                (assessment_id,),
            ).fetchone()
            matrix_data = load_json(matrix_row["data_json"], {}) if matrix_row else {}
            matrix_rows = matrix_data.get("rows", []) if isinstance(matrix_data, dict) else []
            carts = matrix_data.get("carts", []) if isinstance(matrix_data, dict) else []
            row_by_av = {
                clean_text(row.get("attack_vector_id")): row
                for row in matrix_rows if isinstance(row, dict)
            }
            node_names = {
                str(row["id"]): str(row["name"])
                for row in conn.execute(
                    "SELECT id,name FROM dfd_nodes WHERE assessment_id=?", (assessment_id,)
                )
            }
            case_path_nodes: dict[int, list[dict[str, Any]]] = {}
            for path_row in conn.execute(
                """SELECT acn.attack_case_id,acn.node_id,acn.role,acn.sequence_order,
                          n.name AS node_name
                   FROM attack_case_nodes acn
                   JOIN attack_cases ac ON ac.id=acn.attack_case_id
                   JOIN dfd_nodes n
                     ON n.assessment_id=ac.assessment_id AND n.id=acn.node_id
                   WHERE ac.assessment_id=?
                   ORDER BY acn.attack_case_id,acn.sequence_order""",
                (assessment_id,),
            ):
                case_path_nodes.setdefault(int(path_row["attack_case_id"]), []).append({
                    "node_id": path_row["node_id"],
                    "node_name": path_row["node_name"],
                    "role": path_row["role"],
                })
            compact_carts: list[dict[str, Any]] = []
            for cart in carts if isinstance(carts, list) else []:
                if not isinstance(cart, dict):
                    continue
                entry_id = clean_text(cart.get("entry_node_id"))
                entry_ids = [
                    clean_text(value) for value in cart.get("entry_node_ids", [])
                    if clean_text(value)
                ] or ([entry_id] if entry_id else [])
                target_id = clean_text(cart.get("target_node_id"))
                compact_carts.append({
                    "cart_id": cart.get("id"),
                    "attack_case_id": cart.get("attack_case_id"),
                    "attack_case_name": clean_text(cart.get("attack_case_name", cart.get("name"))),
                    "entry_node_id": entry_id,
                    "entry_node_name": node_names.get(entry_id, entry_id),
                    "entry_node_ids": entry_ids,
                    "entry_node_names": [node_names.get(value, value) for value in entry_ids],
                    "target_node_id": target_id,
                    "target_node_name": node_names.get(target_id, target_id),
                    "intended_effect": clean_text(cart.get("intended_effect")),
                    "path_mode": clean_text(cart.get("path_mode")),
                    "path_nodes": case_path_nodes.get(int(cart["attack_case_id"]), [])
                    if isinstance(cart.get("attack_case_id"), int) else [],
                    "rationale": clean_text(cart.get("rationale")),
                })
            cart_by_id = {str(cart["cart_id"]): cart for cart in compact_carts}

            mapping_items: list[dict[str, Any]] = []
            for row in rows:
                matrix_context = row_by_av.get(str(row["av_id"]), {})
                cells = matrix_context.get("cells", {}) if isinstance(matrix_context, dict) else {}
                applicable_cases = [
                    {**cart, "risk": cells.get(cart_id)}
                    for cart_id, cart in cart_by_id.items()
                    if isinstance(cells, dict)
                    and isinstance(cells.get(cart_id), dict)
                    and bool(cells[cart_id].get("included"))
                ]
                mapping_items.append({
                    # mapping_id remains an alias used by the 2.3 frontend.
                    "item_id": int(row["id"]),
                    "mapping_id": int(row["id"]),
                    "av_id": row["av_id"],
                    "cm_id": row["cm_id"],
                    "attack_vector": {
                        "id": row["av_id"],
                        "catalog_id": row["av_catalog_id"],
                        "name": row["av_name"],
                        "description": row["av_description"],
                        "source": row["av_source"],
                        "reference_url": row["av_reference_url"],
                        "risk_score": row["av_risk_score"],
                        "rank": row["av_rank"],
                        "selection_reason": row["av_selection_reason"],
                    },
                    "countermeasure": {
                        "id": row["cm_id"],
                        "name": row["cm_name"],
                        "description": row["cm_description"],
                        "source": row["cm_source"],
                        "reference_url": row["cm_reference_url"],
                    },
                    "current_effect": row["effect"],
                    "current_confidence": row["confidence"],
                    "current_status": row["review_status"],
                    "current_reason": row["decision_reason"],
                    "item_source": row["item_source"],
                    "pair_effect_rows": [
                        {"item_id": int(peer["id"]), "current_effect": peer["effect"]}
                        for peer in all_rows
                        if peer["av_id"] == row["av_id"] and peer["cm_id"] == row["cm_id"]
                    ],
                    "km_evidence": {
                        "mapping_id": row["km_mapping_id"],
                        "rationale": row["km_rationale"],
                        "review_status": row["km_review_status"],
                    } if row["km_mapping_id"] is not None else None,
                    "applicable_attack_cases": applicable_cases,
                })
            release = conn.execute(
                "SELECT id,name FROM km_releases WHERE id=?",
                (int(assessment["km_release_id"]),),
            ).fetchone()
            assessment_only_cm_count = len({
                str(row["cm_id"]) for row in all_rows
                if not str(row["item_source"] or "").startswith("KM:")
            })
            return {
                "assessment": {
                    "id": assessment_id,
                    "external_llm_allowed": bool(assessment["external_llm_allowed"]),
                    "evaluation_target": assessment["evaluation_target"],
                    "scope_in": assessment["scope_in"],
                    "scope_out": assessment["scope_out"],
                    "threat_range": assessment["threat_range"],
                    "lifecycle_phase": assessment["lifecycle_phase"],
                    "actor_type": assessment["actor_type"],
                    "actor_motivation": assessment["actor_motivation"],
                    "actor_intent": assessment["actor_intent"],
                    "actor_capabilities": assessment["actor_capabilities"],
                    "technical_info": assessment["technical_info"],
                    "scope_profile": load_json(assessment["scope_profile_json"], {}),
                },
                "countermeasure_scope": {
                    "policy": (
                        "평가에 고정된 KM 릴리스의 AV-대응책 매핑 후보와 "
                        "이 평가에서 사용자가 직접 추가한 대응책 관계를 검토한다."
                    ),
                    "km_release_id": int(assessment["km_release_id"]),
                    "km_release_name": str(release["name"]) if release else "",
                    "assessment_only_countermeasure_count": assessment_only_cm_count,
                },
                "matrix": {
                    "status": matrix_row["status"] if matrix_row else None,
                    "risk_model_id": matrix_data.get("risk_model_id")
                    if isinstance(matrix_data, dict) else None,
                },
                "mapping_items": mapping_items,
            }

    def crra_mapping_context(
        self, assessment_id: int, av_id: str, cm_id: str, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            assessment = self._require_owned_assessment(conn, assessment_id, owner_id)
            if not assessment["external_llm_allowed"]:
                raise ValueError("이 평가에서는 외부 LLM 전송을 허용하지 않았습니다.")
            av = conn.execute("SELECT * FROM attack_vectors WHERE id=?", (clean_text(av_id),)).fetchone()
            cm = conn.execute("SELECT * FROM countermeasures WHERE id=?", (clean_text(cm_id),)).fetchone()
            if not av or (av["assessment_id"] is not None and int(av["assessment_id"]) != assessment_id):
                raise LookupError("이 평가에서 사용할 수 있는 공격 벡터를 찾을 수 없습니다.")
            if not cm or (cm["assessment_id"] is not None and int(cm["assessment_id"]) != assessment_id):
                raise LookupError("이 평가에서 사용할 수 있는 대응책을 찾을 수 없습니다.")
            mappings = [
                dict(row) for row in conn.execute(
                    """SELECT * FROM crra_mapping_items
                       WHERE assessment_id=? AND av_id=? AND cm_id=? ORDER BY effect,id""",
                    (assessment_id, av["id"], cm["id"]),
                )
            ]
            if not mappings:
                raise LookupError("이 평가의 CRRA 매핑을 찾을 수 없습니다.")
            cost = conn.execute(
                "SELECT * FROM crra_countermeasures WHERE assessment_id=? AND cm_id=?", (assessment_id, cm["id"])
            ).fetchone()
            return {
                "assessment": {
                    "external_llm_allowed": bool(assessment["external_llm_allowed"]),
                    "evaluation_target": assessment["evaluation_target"],
                    "scope_in": assessment["scope_in"],
                    "scope_out": assessment["scope_out"],
                    "threat_range": assessment["threat_range"],
                    "lifecycle_phase": assessment["lifecycle_phase"],
                    "actor_type": assessment["actor_type"],
                    "actor_motivation": assessment["actor_motivation"],
                    "actor_intent": assessment["actor_intent"],
                    "actor_capabilities": assessment["actor_capabilities"],
                    "technical_info": assessment["technical_info"],
                    "scope_profile": load_json(assessment["scope_profile_json"], {}),
                },
                "attack_vector": dict(av),
                "countermeasure": dict(cm),
                "mappings": mappings,
                "cost_and_utility": dict(cost) if cost else None,
            }

    def workspace(
        self, assessment_id: int, owner_id: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as conn, conn:
            self._ensure_attack_vector_catalog_ids(conn)
            assessment = conn.execute(
                """SELECT a.*,k.name AS km_release_name,rm.name AS risk_model_name
                   FROM assessments a JOIN km_releases k ON k.id=a.km_release_id
                   LEFT JOIN risk_models rm ON rm.id=a.risk_model_id
                   WHERE a.id=? AND a.owner_id=?""",
                (assessment_id, self._owner_id(owner_id)),
            ).fetchone()
            if not assessment:
                raise LookupError("평가를 찾을 수 없습니다.")
            nodes = []
            for row in conn.execute(
                """SELECT n.*,at.name AS asset_type_name,at.group_name
                   FROM dfd_nodes n JOIN asset_types at ON at.id=n.asset_type_id
                   WHERE n.assessment_id=? ORDER BY n.rowid""",
                (assessment_id,),
            ):
                node = dict(row)
                node["properties"] = load_json(node.pop("properties_json"), {})
                node["is_entry"] = bool(node["is_entry"])
                node["is_target"] = bool(node["is_target"])
                nodes.append(node)
            edges = []
            for row in conn.execute(
                "SELECT * FROM dfd_edges WHERE assessment_id=? ORDER BY rowid",
                (assessment_id,),
            ):
                edge = dict(row)
                edge["source"] = edge["source_node_id"]
                edge["target"] = edge["target_node_id"]
                edge["properties"] = load_json(edge.pop("properties_json"), {})
                edges.append(edge)
            boundaries = [dict(row) for row in conn.execute("SELECT * FROM trust_boundaries WHERE assessment_id=? ORDER BY rowid", (assessment_id,))]
            attack_cases = []
            for row in conn.execute(
                """SELECT ac.*,
                          en.name AS entry_node_name,tn.name AS target_node_name
                   FROM attack_cases ac
                   LEFT JOIN dfd_nodes en
                     ON en.assessment_id=ac.assessment_id AND en.id=ac.entry_node_id
                   LEFT JOIN dfd_nodes tn
                     ON tn.assessment_id=ac.assessment_id AND tn.id=ac.target_node_id
                   WHERE ac.assessment_id=? ORDER BY ac.sort_order,ac.id""",
                (assessment_id,),
            ):
                attack_case = dict(row)
                attack_case["actor_snapshot"] = load_json(
                    attack_case.pop("actor_snapshot_json"), {}
                )
                attack_case["path_edge_ids"] = load_json(
                    attack_case.pop("path_edge_ids_json"), []
                )
                attack_case["entry_node_ids"] = load_json(
                    attack_case.pop("entry_node_ids_json"),
                    [attack_case["entry_node_id"]] if attack_case.get("entry_node_id") else [],
                )
                attack_case["legacy_entry_node_ids"] = load_json(
                    attack_case.pop("legacy_entry_node_ids_json"), []
                )
                case_nodes = [
                    dict(case_node) for case_node in conn.execute(
                        """SELECT acn.node_id,acn.sequence_order,acn.role,n.name
                           FROM attack_case_nodes acn
                           LEFT JOIN dfd_nodes n
                             ON n.assessment_id=? AND n.id=acn.node_id
                           WHERE acn.attack_case_id=?
                           ORDER BY acn.sequence_order,acn.node_id""",
                        (assessment_id, attack_case["id"]),
                    )
                ]
                attack_case["path_nodes"] = case_nodes
                attack_case["path_node_ids"] = [item["node_id"] for item in case_nodes]
                attack_cases.append(attack_case)
            candidates = []
            for row in conn.execute(
                """SELECT cv.*,av.catalog_id AS attack_vector_catalog_id,
                          av.name AS attack_vector_name,av.description AS attack_vector_description,
                          av.source,av.source_identifier,av.reference_url,av.prerequisite,
                          ac.name AS attack_case_name,ac.intended_effect,ac.rationale,
                          ac.path_mode,ac.status AS attack_case_status
                   FROM candidate_vectors cv JOIN attack_vectors av ON av.id=cv.attack_vector_id
                   LEFT JOIN attack_cases ac ON ac.id=cv.attack_case_id
                   WHERE cv.assessment_id=? ORDER BY cv.target_node_id,av.id""",
                (assessment_id,),
            ):
                candidate = dict(row)
                for field in ["entry_node_ids_json", "related_node_ids_json", "path_node_ids_json", "mapping_evidence_json"]:
                    candidate[field.removesuffix("_json")] = load_json(candidate.pop(field), [])
                candidates.append(candidate)
            carts = []
            for cart_row in conn.execute(
                """SELECT sc.*,ac.name AS attack_case_name,ac.intended_effect,
                          ac.rationale,ac.path_mode,ac.path_rationale,
                          ac.status AS attack_case_status,
                          ac.entry_node_ids_json AS attack_case_entry_node_ids_json,
                          ac.actor_snapshot_json AS attack_case_actor_snapshot_json,
                          ac.path_edge_ids_json AS attack_case_path_edge_ids_json
                   FROM shopping_carts sc
                   LEFT JOIN attack_cases ac ON ac.id=sc.attack_case_id
                   WHERE sc.assessment_id=? ORDER BY sc.id""",
                (assessment_id,),
            ):
                cart = dict(cart_row)
                cart["actor_snapshot"] = load_json(
                    cart.pop("attack_case_actor_snapshot_json", None), {}
                )
                cart["entry_node_ids"] = load_json(
                    cart.pop("attack_case_entry_node_ids_json", None),
                    [cart["entry_node_id"]] if cart.get("entry_node_id") else [],
                )
                cart["path_edge_ids"] = load_json(
                    cart.pop("attack_case_path_edge_ids_json", None), []
                )
                cart["path_node_ids"] = [
                    str(case_node["node_id"])
                    for case_node in conn.execute(
                        """SELECT node_id FROM attack_case_nodes
                           WHERE attack_case_id=? ORDER BY sequence_order,node_id""",
                        (cart["attack_case_id"],),
                    )
                ] if cart.get("attack_case_id") is not None else []
                cart["items"] = []
                for item_row in conn.execute(
                    """SELECT ci.*,av.catalog_id AS attack_vector_catalog_id,
                              av.name AS attack_vector_name,av.description AS attack_vector_description,
                              av.source AS attack_vector_source,
                              av.source_identifier AS attack_vector_source_id,
                              av.reference_url,av.prerequisite
                       FROM cart_items ci JOIN attack_vectors av ON av.id=ci.attack_vector_id
                       WHERE ci.cart_id=? ORDER BY av.id""",
                    (cart["id"],),
                ):
                    item = dict(item_row)
                    for field, default in [
                        ("related_entry_ids_json", []), ("related_node_ids_json", []), ("mapping_evidence_json", []),
                        ("llm_plausibility_json", None), ("factor_values_json", {}), ("factor_reasons_json", {}),
                        ("llm_risk_json", None), ("calculation_trace_json", {}),
                    ]:
                        item[field.removesuffix("_json")] = load_json(item.pop(field), default)
                    cart["items"].append(item)
                carts.append(cart)
            matrix_row = conn.execute("SELECT * FROM susceptibility_matrices WHERE assessment_id=?", (assessment_id,)).fetchone()
            matrix = None
            if matrix_row:
                matrix = dict(matrix_row)
                matrix["data"] = load_json(matrix.pop("data_json"), {})
                attack_vectors_by_id = {
                    str(row["id"]): dict(row)
                    for row in conn.execute("SELECT id,catalog_id,name FROM attack_vectors")
                }
                for row in matrix["data"].get("rows", []):
                    if isinstance(row, dict):
                        attack_vector = attack_vectors_by_id.get(
                            str(row.get("attack_vector_id", row.get("av_id", "")))
                        )
                        if attack_vector:
                            row["attack_vector_catalog_id"] = str(attack_vector["catalog_id"])
                            row["attack_vector_name"] = str(attack_vector["name"])
            path_findings = self._threat_model_path_findings(nodes, edges)
            manual_cases = [
                case for case in attack_cases
                if case.get("case_kind") == "EXPLICIT" and case.get("path_mode") == "MANUAL"
            ]
            if manual_cases:
                manual_entry_ids = {
                    str(entry_id)
                    for case in manual_cases
                    for entry_id in case.get("entry_node_ids", [case["entry_node_id"]])
                }
                manual_target_ids = {str(case["target_node_id"]) for case in manual_cases}
                # Keep accepted MANUAL cases separate from DFD path gaps.
                path_findings["unreachable_entries"] = [
                    item for item in path_findings["unreachable_entries"]
                    if str(item["node_id"]) not in manual_entry_ids
                ]
                path_findings["unreachable_targets"] = [
                    item for item in path_findings["unreachable_targets"]
                    if str(item["node_id"]) not in manual_target_ids
                ]
                path_findings["manual_cases"] = [
                    {
                        "attack_case_id": case["id"],
                        "name": case["name"],
                        "entry_node_id": case["entry_node_id"],
                        "entry_node_ids": case.get("entry_node_ids", [case["entry_node_id"]]),
                        "target_node_id": case["target_node_id"],
                        "path_rationale": case["path_rationale"],
                    }
                    for case in manual_cases
                ]
            attack_vector_catalog = [
                dict(row) for row in conn.execute(
                    """SELECT id,catalog_id,name,source,source_identifier,reference_url
                       FROM attack_vectors
                       WHERE assessment_id IS NULL OR assessment_id=?
                       ORDER BY catalog_id""",
                    (assessment_id,),
                )
            ]
            return {
                "assessment": self._assessment_dict(assessment),
                "nodes": nodes,
                "edges": edges,
                "boundaries": boundaries,
                "threat_model_path_findings": path_findings,
                "attack_cases": attack_cases,
                "candidates": candidates,
                "carts": carts,
                "attack_vector_catalog": attack_vector_catalog,
                "risk_models": self._risk_models(
                    conn, assessment["risk_model_id"], assessment_id
                ),
                "risk_reference_approaches": RISK_REFERENCE_APPROACHES,
                "matrix": matrix,
            }
