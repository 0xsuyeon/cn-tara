"""Build reviewable DFD proposals from Kubernetes manifests."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, datetime
from itertools import chain
from pathlib import PurePosixPath
from typing import Any, Iterable

import yaml


MAPPER_VERSION = "cntara-manifest-dfd-v5"

# Limits include JSON request overhead.
MAX_FILES = 50
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 1_500_000
MAX_DOCUMENTS = 500
MAX_RESOURCES = 2_000
MAX_YAML_TOKENS = 200_000
MAX_YAML_ALIASES = 50
MAX_NESTING_DEPTH = 64
MAX_SCALAR_CHARS = 200_000
MAX_RESULT_RECORDS = 500
MAX_PROPOSAL_NODES = 400
MAX_PROPOSAL_EDGES = 1_200
MAX_SELECTOR_BACKENDS = 250
MAX_ELEMENT_RESOURCE_REFS = 100
MAX_ELEMENT_EVIDENCE_ITEMS = 100
MAX_ELEMENT_EVIDENCE_CHARS = 2_048
MAX_PROPOSAL_BYTES = 1_000_000
MAX_PROJECTION_MEMBERS = 100
MAX_DFD_NODE_NAME_CHARS = 80
MAX_DFD_NODE_DESCRIPTION_CHARS = 500

# Generated layers are replaced on apply; manual elements remain separate.
PLATFORM_GENERATED_LAYER_ID = "manifest-platform"
LOGICAL_GENERATED_LAYER_ID = "manifest-logical-system"

_ALLOWED_SUFFIXES = {".yaml", ".yml", ".json"}
_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}

_WORKLOAD_KINDS = {
    "Pod",
    "ReplicationController",
    "Deployment",
    "ReplicaSet",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
}

# Built-in kinds are matched with their API groups.
_BUILTIN_KIND_GROUPS: dict[str, set[str]] = {
    "Namespace": {""},
    "Pod": {""},
    "ReplicationController": {""},
    "Service": {""},
    "PersistentVolumeClaim": {""},
    "ConfigMap": {""},
    "Secret": {""},
    "Deployment": {"apps"},
    "ReplicaSet": {"apps"},
    "StatefulSet": {"apps"},
    "DaemonSet": {"apps"},
    "Job": {"batch"},
    "CronJob": {"batch"},
    "Ingress": {"networking.k8s.io", "extensions"},
}

_NAMESPACED_KINDS = set(_BUILTIN_KIND_GROUPS) - {"Namespace"}


@dataclass(frozen=True)
class _Source:
    file: str
    document: int
    line: int
    item: int | None = None

    def public(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "file": self.file,
            "document": self.document,
            "line": self.line,
        }
        if self.item is not None:
            value["item"] = self.item
        return value


@dataclass(frozen=True)
class _Resource:
    api_version: str
    group: str
    kind: str
    namespace: str
    name: str
    document: dict[str, Any]
    source: _Source

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.kind, self.namespace, self.name)

    @property
    def ref(self) -> str:
        if self.kind == "Namespace":
            return f"Namespace/{self.name}"
        return f"{self.kind}/{self.namespace}/{self.name}"

    def evidence(self) -> dict[str, Any]:
        return {
            "api_version": self.api_version,
            "kind": self.kind,
            "namespace": self.namespace,
            "name": self.name,
            "source": self.source.public(),
        }


class _RecordSink:
    """Deduplicate and cap secret-safe warning/unresolved records."""

    def __init__(self) -> None:
        self._records: list[dict[str, Any]] = []
        self._keys: set[str] = set()
        self._truncated = False

    def add(
        self,
        code: str,
        message: str,
        *,
        resource: str | None = None,
        source: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        record: dict[str, Any] = {"code": code, "message": message}
        if resource:
            record["resource"] = resource
        if source:
            record["source"] = source
        if details:
            record["details"] = details
        key = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if key in self._keys:
            return
        if len(self._records) >= MAX_RESULT_RECORDS:
            self._truncated = True
            return
        self._keys.add(key)
        self._records.append(record)

    def result(self) -> list[dict[str, Any]]:
        records = sorted(
            self._records,
            key=lambda item: (
                str(item.get("code", "")),
                str(item.get("resource", "")),
                json.dumps(item.get("source", {}), sort_keys=True),
            ),
        )
        if self._truncated:
            records.append(
                {
                    "code": "RECORDS_TRUNCATED",
                    "message": f"세부 경고가 {MAX_RESULT_RECORDS}개를 넘어 나머지를 생략했습니다.",
                }
            )
        return records


def _clean_filename(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Manifest 파일 이름을 확인해 주세요.")
    normalized = value.strip().replace("\\", "/")
    name = PurePosixPath(normalized).name
    if not name or name in {".", ".."} or len(name) > 255:
        raise ValueError("Manifest 파일 이름을 확인해 주세요.")
    suffix = PurePosixPath(name).suffix.lower()
    if suffix not in _ALLOWED_SUFFIXES:
        raise ValueError(f"지원하지 않는 Manifest 파일 형식입니다: {name}")
    return name


def _prepare_files(files: list[dict[str, Any]]) -> tuple[list[tuple[str, str]], str]:
    if not isinstance(files, list) or not files:
        raise ValueError("Manifest 파일을 하나 이상 선택해 주세요.")
    if len(files) > MAX_FILES:
        raise ValueError(f"Manifest 파일은 최대 {MAX_FILES}개까지 처리할 수 있습니다.")

    prepared: list[tuple[str, str]] = []
    names: set[str] = set()
    total_bytes = 0
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("Manifest 파일 목록 형식을 확인해 주세요.")
        name = _clean_filename(item.get("name"))
        if name in names:
            raise ValueError(f"같은 이름의 Manifest 파일이 두 개 이상 있습니다: {name}")
        content = item.get("content")
        if not isinstance(content, str):
            raise ValueError(f"Manifest 파일 내용이 문자열이 아닙니다: {name}")
        if "\x00" in content:
            raise ValueError(f"Manifest 파일에 허용되지 않는 NUL 문자가 있습니다: {name}")
        encoded_size = len(content.encode("utf-8"))
        if encoded_size <= 0:
            raise ValueError(f"비어 있는 Manifest 파일입니다: {name}")
        if encoded_size > MAX_FILE_BYTES:
            raise ValueError(f"Manifest 파일 하나의 크기는 {MAX_FILE_BYTES}바이트를 넘을 수 없습니다: {name}")
        total_bytes += encoded_size
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError(f"Manifest 파일 전체 크기는 {MAX_TOTAL_BYTES}바이트를 넘을 수 없습니다.")
        names.add(name)
        prepared.append((name, content))

    # File-order-independent source digest.
    digest = hashlib.sha256()
    for name, content in sorted(prepared, key=lambda pair: pair[0]):
        digest.update(name.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(content.encode("utf-8"))
        digest.update(b"\x00")
    return prepared, digest.hexdigest()


def _scan_yaml_limits(name: str, content: str) -> None:
    aliases = 0
    depth = 0
    tokens_seen = 0
    try:
        for token in yaml.scan(content, Loader=yaml.SafeLoader):
            tokens_seen += 1
            if tokens_seen > MAX_YAML_TOKENS:
                raise ValueError(f"Manifest YAML 토큰 수가 한도를 넘었습니다: {name}")
            token_name = token.__class__.__name__
            if token_name == "AliasToken":
                aliases += 1
                if aliases > MAX_YAML_ALIASES:
                    raise ValueError(f"Manifest YAML 별칭(alias)이 너무 많습니다: {name}")
            if token_name in {
                "BlockMappingStartToken",
                "BlockSequenceStartToken",
                "FlowMappingStartToken",
                "FlowSequenceStartToken",
            }:
                depth += 1
                if depth > MAX_NESTING_DEPTH:
                    raise ValueError(f"Manifest YAML 중첩 깊이가 너무 큽니다: {name}")
            elif token_name in {"BlockEndToken", "FlowMappingEndToken", "FlowSequenceEndToken"}:
                depth = max(0, depth - 1)
            value = getattr(token, "value", None)
            if isinstance(value, str) and len(value) > MAX_SCALAR_CHARS:
                raise ValueError(f"Manifest YAML 문자열 하나가 너무 큽니다: {name}")
    except ValueError:
        raise
    except (yaml.YAMLError, RecursionError) as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f"{name}:{getattr(mark, 'line', 0) + 1}:{getattr(mark, 'column', 0) + 1}"
        raise ValueError(f"Manifest YAML/JSON 형식을 확인해 주세요: {location}") from None


def _validate_loaded_tree(value: Any) -> None:
    count = 0
    visiting: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > MAX_YAML_TOKENS:
            raise ValueError("Manifest 구조가 너무 큽니다.")
        if depth > MAX_NESTING_DEPTH:
            raise ValueError("Manifest 구조의 중첩 깊이가 너무 큽니다.")
        if isinstance(item, dict):
            identity = id(item)
            if identity in visiting:
                raise ValueError("순환 YAML 별칭은 지원하지 않습니다.")
            visiting.add(identity)
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("Manifest 객체의 필드 이름은 문자열이어야 합니다.")
                if len(key) > MAX_SCALAR_CHARS:
                    raise ValueError("Manifest 필드 이름이 너무 큽니다.")
                visit(child, depth + 1)
            visiting.remove(identity)
            return
        if isinstance(item, list):
            identity = id(item)
            if identity in visiting:
                raise ValueError("순환 YAML 별칭은 지원하지 않습니다.")
            visiting.add(identity)
            for child in item:
                visit(child, depth + 1)
            visiting.remove(identity)
            return
        if item is None or isinstance(item, (bool, int, float, str, date, datetime)):
            if isinstance(item, str) and len(item) > MAX_SCALAR_CHARS:
                raise ValueError("Manifest 문자열 하나가 너무 큽니다.")
            return
        raise ValueError(f"Manifest에 지원하지 않는 YAML 값 형식이 있습니다: {type(item).__name__}")

    visit(value, 0)


def _parse_documents(
    prepared: list[tuple[str, str]], warnings: _RecordSink,
) -> tuple[list[tuple[dict[str, Any], _Source]], int]:
    flattened: list[tuple[dict[str, Any], _Source]] = []
    document_count = 0

    def collect(document: Any, source: _Source, depth: int = 0) -> None:
        if document is None:
            return
        if not isinstance(document, dict):
            warnings.add(
                "NON_OBJECT_DOCUMENT",
                "Kubernetes 객체가 아닌 YAML 문서를 건너뛰었습니다.",
                source=source.public(),
            )
            return
        metadata = document.get("metadata")
        mal_metadata = metadata if isinstance(metadata, dict) else {}
        lang_id = str(mal_metadata.get("langID") or "")
        if isinstance(document.get("assets"), dict) and (
            lang_id.startswith("org.mal-lang.")
            or bool(mal_metadata.get("malVersion"))
            or bool(mal_metadata.get("MAL-Toolbox Version"))
        ):
            raise ValueError(
                f"{source.file}은 Kubernetes Manifest가 아니라 containerLang/MAL 모델 "
                "인스턴스입니다. apiVersion·kind·metadata가 포함된 원본 Kubernetes "
                "YAML/JSON을 선택해 주세요."
            )
        kind = document.get("kind")
        if isinstance(kind, str) and kind.endswith("List") and isinstance(document.get("items"), list):
            if depth >= 4:
                raise ValueError("중첩된 Kubernetes List 깊이가 너무 큽니다.")
            for index, child in enumerate(document["items"], 1):
                collect(
                    child,
                    _Source(source.file, source.document, source.line, index),
                    depth + 1,
                )
            return
        if not isinstance(kind, str) or not kind.strip():
            warnings.add(
                "MISSING_KIND",
                "kind가 없는 YAML 문서를 건너뛰었습니다.",
                source=source.public(),
            )
            return
        flattened.append((document, source))
        if len(flattened) > MAX_RESOURCES:
            raise ValueError(f"Kubernetes 객체는 최대 {MAX_RESOURCES}개까지 처리할 수 있습니다.")

    for name, content in prepared:
        _scan_yaml_limits(name, content)
        try:
            documents = list(yaml.safe_load_all(content))
            composed = list(yaml.compose_all(content, Loader=yaml.SafeLoader))
        except (yaml.YAMLError, RecursionError) as exc:
            mark = getattr(exc, "problem_mark", None)
            location = f"{name}:{getattr(mark, 'line', 0) + 1}:{getattr(mark, 'column', 0) + 1}"
            raise ValueError(f"Manifest YAML/JSON 형식을 확인해 주세요: {location}") from None
        document_count += len(documents)
        if document_count > MAX_DOCUMENTS:
            raise ValueError(f"Manifest YAML 문서는 최대 {MAX_DOCUMENTS}개까지 처리할 수 있습니다.")
        for index, document in enumerate(documents, 1):
            _validate_loaded_tree(document)
            line = 1
            if index - 1 < len(composed) and composed[index - 1] is not None:
                line = int(composed[index - 1].start_mark.line) + 1
            collect(document, _Source(name, index, line))
    if document_count == 0 or not flattened:
        raise ValueError("처리할 Kubernetes Manifest 객체를 찾을 수 없습니다.")
    return flattened, document_count


def _api_group(api_version: str) -> str:
    return api_version.split("/", 1)[0] if "/" in api_version else ""


def _normalize_resources(
    documents: list[tuple[dict[str, Any], _Source]], warnings: _RecordSink,
) -> list[_Resource]:
    resources: list[_Resource] = []
    identities: set[tuple[str, str, str]] = set()
    unsupported: set[tuple[str, str]] = set()
    collisions: set[tuple[str, str]] = set()

    for document, source in documents:
        kind = str(document.get("kind") or "").strip()
        api_version_value = document.get("apiVersion")
        if not isinstance(api_version_value, str) or not api_version_value.strip():
            warnings.add(
                "MISSING_API_VERSION",
                "apiVersion이 없는 객체를 건너뛰었습니다.",
                resource=kind or None,
                source=source.public(),
            )
            continue
        api_version = api_version_value.strip()
        group = _api_group(api_version)
        allowed_groups = _BUILTIN_KIND_GROUPS.get(kind)
        if allowed_groups is None:
            marker = (group, kind)
            if marker not in unsupported:
                unsupported.add(marker)
                warnings.add(
                    "UNSUPPORTED_KIND",
                    "현재 DFD 초안 규칙에서 지원하지 않는 Kubernetes 종류를 건너뛰었습니다.",
                    resource=f"{api_version}/{kind}",
                )
            continue
        if group not in allowed_groups:
            marker = (group, kind)
            if marker not in collisions:
                collisions.add(marker)
                warnings.add(
                    "NON_BUILTIN_GROUP",
                    "기본 Kubernetes 종류와 이름이 같지만 API 그룹이 달라 Custom Resource로 처리하고 건너뛰었습니다.",
                    resource=f"{api_version}/{kind}",
                )
            continue
        metadata = document.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        name_value = metadata.get("name")
        if not isinstance(name_value, str) or not name_value.strip():
            warnings.add(
                "MISSING_RESOURCE_NAME",
                "metadata.name이 없는 Kubernetes 객체를 건너뛰었습니다.",
                resource=kind,
                source=source.public(),
            )
            continue
        name = name_value.strip()
        if len(name) > 512:
            raise ValueError(f"Kubernetes 객체 이름이 너무 깁니다: {kind}")
        if kind == "Namespace":
            namespace = ""
        else:
            namespace_value = metadata.get("namespace")
            namespace = namespace_value.strip() if isinstance(namespace_value, str) and namespace_value.strip() else "default"
        resource = _Resource(api_version, group, kind, namespace, name, document, source)
        if resource.key in identities:
            raise ValueError(f"같은 Kubernetes 객체가 두 번 이상 선언되어 있습니다: {resource.ref}")
        identities.add(resource.key)
        resources.append(resource)

    if not resources:
        raise ValueError("지원되는 Kubernetes Manifest 객체를 찾을 수 없습니다.")
    return sorted(resources, key=lambda item: (item.namespace, item.kind, item.name, item.api_version))


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _pod_template(resource: _Resource) -> tuple[dict[str, Any], dict[str, Any]]:
    spec = _mapping(resource.document.get("spec"))
    if resource.kind == "Pod":
        return _mapping(resource.document.get("metadata")), spec
    if resource.kind == "CronJob":
        template = _mapping(
            _mapping(_mapping(spec.get("jobTemplate")).get("spec")).get("template")
        )
    else:
        template = _mapping(spec.get("template"))
    return _mapping(template.get("metadata")), _mapping(template.get("spec"))


def _owner_keys(resource: _Resource) -> list[tuple[str, str, str]]:
    metadata = _mapping(resource.document.get("metadata"))
    owners = []
    for owner in _sequence(metadata.get("ownerReferences")):
        owner = _mapping(owner)
        kind = _string(owner.get("kind"))
        name = _string(owner.get("name"))
        api_version = _string(owner.get("apiVersion"))
        allowed_groups = _BUILTIN_KIND_GROUPS.get(kind)
        if (
            kind
            and name
            and api_version
            and allowed_groups is not None
            and _api_group(api_version) in allowed_groups
        ):
            owners.append((kind, resource.namespace, name))
    return owners


def _stable_id(prefix: str, *parts: Any) -> str:
    canonical = "\x1f".join(str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:20]}"


def _resource_collector(
    source_digest: str,
    refs: Iterable[dict[str, Any]],
    *,
    confidence: str,
    evidence: Iterable[str],
    **extra: Any,
) -> dict[str, Any]:
    unique_refs: dict[str, dict[str, Any]] = {}
    for ref in refs:
        key = json.dumps(ref, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        unique_refs.setdefault(key, ref)
        if len(unique_refs) > MAX_ELEMENT_RESOURCE_REFS:
            raise ValueError(
                f"DFD 요소 하나의 Manifest 출처가 {MAX_ELEMENT_RESOURCE_REFS}개를 넘습니다. "
                "입력 범위 또는 namespace를 나눠 주세요."
            )
    evidence_items: set[str] = set()
    for item in evidence:
        text = str(item).strip()
        if not text:
            continue
        if len(text) > MAX_ELEMENT_EVIDENCE_CHARS:
            raise ValueError("DFD 관계 근거 문자열이 너무 큽니다.")
        evidence_items.add(text)
        if len(evidence_items) > MAX_ELEMENT_EVIDENCE_ITEMS:
            raise ValueError(
                f"DFD 요소 하나의 관계 근거가 {MAX_ELEMENT_EVIDENCE_ITEMS}개를 넘습니다. "
                "입력 범위 또는 namespace를 나눠 주세요."
            )
    collector = {
        "source": "kubernetes_manifest",
        "mapper_version": MAPPER_VERSION,
        "source_digest": source_digest,
        "confidence": confidence,
        "resource_refs": [unique_refs[key] for key in sorted(unique_refs)],
        "evidence": sorted(evidence_items),
    }
    collector.update(extra)
    return collector


def _node(
    node_id: str,
    name: str,
    asset_type_id: str,
    dfd_kind: str,
    description: str,
    properties: dict[str, Any],
    *,
    layer: int,
) -> dict[str, Any]:
    bounded_name = str(name or "").strip()
    if len(bounded_name) > MAX_DFD_NODE_NAME_CHARS:
        bounded_name = bounded_name[: MAX_DFD_NODE_NAME_CHARS - 1].rstrip() + "…"
    bounded_description = str(description or "").strip()
    if len(bounded_description) > MAX_DFD_NODE_DESCRIPTION_CHARS:
        bounded_description = bounded_description[: MAX_DFD_NODE_DESCRIPTION_CHARS - 1].rstrip() + "…"
    return {
        "id": node_id,
        "name": bounded_name,
        "asset_type_id": asset_type_id,
        "dfd_kind": dfd_kind,
        "x": 0,
        "y": 0,
        "width": 170,
        "height": 64,
        "description": bounded_description,
        "properties": {**properties, "layout_layer": layer},
        "is_entry": False,
        "is_target": False,
        "entry_reason": "",
        "target_reason": "",
    }


def _layout_proposal_nodes(nodes: Iterable[dict[str, Any]]) -> None:
    """Apply a deterministic compact layout after all projections are built."""

    layer_x = {0: 70, 1: 410, 2: 760}
    grouped: dict[int, list[dict[str, Any]]] = {0: [], 1: [], 2: []}
    for value in nodes:
        grouped.setdefault(int(_mapping(value.get("properties")).get("layout_layer", 1)), []).append(value)
    for layer, layer_nodes in grouped.items():
        for index, value in enumerate(
            sorted(
                layer_nodes,
                key=lambda item: (
                    str(_mapping(_mapping(item.get("properties")).get("kubernetes")).get("namespace", "")),
                    str(_mapping(_mapping(item.get("properties")).get("kubernetes")).get("name", "")),
                    str(item.get("name", "")),
                    str(item.get("id", "")),
                ),
            )
        ):
            value["x"] = layer_x.get(layer, 410)
            value["y"] = 70 + index * 105


def _sanitize_image_ref(value: Any) -> str:
    image = _string(value)
    # Remove schemes and registry credentials while preserving OCI digests.
    if "://" in image:
        _, image = image.split("://", 1)
    first_slash = image.find("/")
    authority_end = len(image) if first_slash < 0 else first_slash
    userinfo_at = image.find("@", 0, authority_end)
    digest_only_without_path = (
        first_slash < 0
        and bool(
            re.fullmatch(
                r"[^@]+@(?:sha256:[0-9A-Fa-f]{64}|sha384:[0-9A-Fa-f]{96}|sha512:[0-9A-Fa-f]{128})",
                image,
            )
        )
    )
    if userinfo_at >= 0 and not digest_only_without_path:
        image = image[userinfo_at + 1 :]
    return image[:1_024]


def _image_registry(image: str) -> tuple[str, bool]:
    first = image.split("/", 1)[0]
    if "/" in image and ("." in first or ":" in first or first == "localhost"):
        return first.lower(), True
    return "implicit-default", False


def _container_inventory(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for category, field in (
        ("init", "initContainers"),
        ("app", "containers"),
        ("ephemeral", "ephemeralContainers"),
    ):
        for container in _sequence(pod_spec.get(field)):
            container = _mapping(container)
            ports = []
            for port in _sequence(container.get("ports")):
                port = _mapping(port)
                number = port.get("containerPort")
                if isinstance(number, int) and 0 < number <= 65_535:
                    ports.append(
                        {
                            "port": number,
                            "protocol": _string(port.get("protocol")) or "TCP",
                            "name": _string(port.get("name")),
                        }
                    )
            result.append(
                {
                    "category": category,
                    "name": _string(container.get("name")) or "unnamed",
                    "image": _sanitize_image_ref(container.get("image")),
                    "ports": sorted(ports, key=lambda item: (item["port"], item["protocol"], item["name"])),
                }
            )
    return result


def _selector_matches(selector: dict[str, Any], labels: dict[str, Any]) -> bool:
    if not selector:
        return False
    return all(isinstance(value, (str, int, float, bool)) and str(labels.get(key)) == str(value) for key, value in selector.items())


def _ingress_backends(resource: _Resource) -> list[dict[str, Any]]:
    spec = _mapping(resource.document.get("spec"))
    tls_hosts = {
        str(host)
        for tls in _sequence(spec.get("tls"))
        for host in _sequence(_mapping(tls).get("hosts"))
        if isinstance(host, str)
    }
    results: list[dict[str, Any]] = []

    def add_backend(backend: Any, host: str = "", path: str = "") -> None:
        backend = _mapping(backend)
        service = _mapping(backend.get("service"))
        name = _string(service.get("name")) or _string(backend.get("serviceName"))
        port_value: Any = _mapping(service.get("port")).get("number")
        if port_value is None:
            port_value = _mapping(service.get("port")).get("name")
        if port_value is None:
            port_value = backend.get("servicePort")
        if not name:
            return
        results.append(
            {
                "service_name": name,
                "host": host,
                "path": path,
                "port": str(port_value) if port_value is not None else "",
                "protocol": (
                    "HTTPS (Ingress 외부 구간; backend 미확인)"
                    if host and host in tls_hosts
                    else "HTTP (Ingress 외부 구간; backend 미확인)"
                ),
            }
        )

    add_backend(spec.get("defaultBackend") or spec.get("backend"))
    for rule in _sequence(spec.get("rules")):
        rule = _mapping(rule)
        host = _string(rule.get("host"))
        http = _mapping(rule.get("http"))
        for path_record in _sequence(http.get("paths")):
            path_record = _mapping(path_record)
            add_backend(path_record.get("backend"), host, _string(path_record.get("path")))
    return results


def _service_protocols(resource: _Resource) -> list[str]:
    protocols = []
    spec = _mapping(resource.document.get("spec"))
    for port in _sequence(spec.get("ports")):
        port = _mapping(port)
        protocol = _string(port.get("appProtocol")) or _string(port.get("protocol")) or "TCP"
        number = port.get("port")
        protocols.append(f"{protocol}/{number}" if isinstance(number, int) else protocol)
    return sorted(set(protocols))


def _active_catalog_flow_templates(
    flow_templates: Iterable[dict[str, Any]], dfd_level: int,
) -> list[dict[str, Any]]:
    """Normalize unique, active flow templates for one catalog view."""
    if dfd_level not in {0, 1}:
        raise ValueError("DFD catalog level must be 0 or 1")
    by_id: dict[str, dict[str, Any] | None] = {}
    for raw in flow_templates:
        if not isinstance(raw, dict):
            continue
        try:
            level = int(raw.get("level"))
        except (TypeError, ValueError):
            continue
        if (
            level != dfd_level
            or not bool(raw.get("active", True))
        ):
            continue
        template_id = str(raw.get("id", "")).strip()
        name = str(raw.get("name", "")).strip()
        source = str(raw.get("source_asset_type_id", "")).strip()
        target = str(raw.get("target_asset_type_id", "")).strip()
        auto_instantiation = bool(raw.get("auto_instantiation"))
        condition_key = str(raw.get("condition_key", "")).strip()
        if not template_id or not name or not source or not target:
            continue
        normalized = {
            "id": template_id,
            "name": name,
            "level": level,
            "km_release_id": raw.get("km_release_id"),
            "auto_instantiation": auto_instantiation,
            "condition_key": condition_key,
            "source_asset_type_id": source,
            "target_asset_type_id": target,
            "review_status": str(raw.get("review_status", "")).strip().upper(),
            "active": True,
            "notes": str(raw.get("notes", "")).strip(),
            "sort_order": raw.get("sort_order"),
        }
        by_id[template_id] = normalized if template_id not in by_id else None
    return sorted(
        (value for value in by_id.values() if value is not None),
        key=lambda value: (
            value.get("sort_order") if isinstance(value.get("sort_order"), int) else 1_000_000,
            value["id"],
        ),
    )


def _approved_flow_templates(
    flow_templates: Iterable[dict[str, Any]], dfd_level: int,
) -> list[dict[str, Any]]:
    """Return only the approved subset of active catalog flows."""

    return [
        flow
        for flow in _active_catalog_flow_templates(flow_templates, dfd_level)
        if flow["review_status"] == "APPROVED"
    ]


def _approved_flow_template_index(
    flow_templates: Iterable[dict[str, Any]],
    dfd_level: int,
    satisfied_conditions: Iterable[str] = (),
) -> dict[tuple[str, str], dict[str, Any]]:
    """Index eligible templates when each endpoint pair is unambiguous."""

    satisfied = {str(value).strip() for value in satisfied_conditions if str(value).strip()}
    indexed: dict[tuple[str, str], dict[str, Any] | None] = {}
    for normalized in _approved_flow_templates(flow_templates, dfd_level):
        if normalized["auto_instantiation"] and (
            not normalized["condition_key"] or normalized["condition_key"] not in satisfied
        ):
            continue
        key = (
            normalized["source_asset_type_id"],
            normalized["target_asset_type_id"],
        )
        indexed[key] = normalized if key not in indexed else None
    return {key: value for key, value in indexed.items() if value is not None}


def _catalog_element_index(
    element_templates: Iterable[dict[str, Any]],
    dfd_level: int,
) -> dict[str, dict[str, Any]]:
    """Return one release-scoped catalog element per asset type."""

    if dfd_level not in {0, 1}:
        raise ValueError("DFD catalog level must be 0 or 1")
    indexed: dict[str, dict[str, Any] | None] = {}
    for raw in element_templates:
        if not isinstance(raw, dict):
            continue
        try:
            level = int(raw.get("level"))
        except (TypeError, ValueError):
            continue
        asset_type_id = str(raw.get("asset_type_id", "")).strip()
        name = str(raw.get("name", "")).strip()
        if level != dfd_level or not asset_type_id or not name:
            continue
        normalized = {
            "km_release_id": raw.get("km_release_id"),
            "level": level,
            "asset_type_id": asset_type_id,
            "name": name,
            "dfd_kind": str(raw.get("dfd_kind", "")).strip(),
            "group_name": str(raw.get("group_name", "")).strip(),
            "description": str(raw.get("description", "")).strip(),
            "parent_asset_type_id": str(raw.get("parent_asset_type_id", "")).strip() or None,
            "parent_name": str(raw.get("parent_name", "")).strip() or None,
            "sort_order": raw.get("sort_order"),
        }
        indexed[asset_type_id] = normalized if asset_type_id not in indexed else None
    return {key: value for key, value in indexed.items() if value is not None}


def _level1_manifest_nodes(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    unresolved: _RecordSink,
) -> list[dict[str, Any]]:
    """Create Level 1 nodes from statically declared containers and storage."""

    volume_store_ids = {
        str(edge.get("source", ""))
        for edge in edges
        if any(
            marker in str(
                _mapping(_mapping(edge.get("properties")).get("collector")).get("relation", "")
            )
            for marker in ("pvc-volume", "config-volume", "secret-volume", "config-projected", "secret-projected")
        )
    }
    result: list[dict[str, Any]] = []
    raw_workloads: dict[str, dict[str, Any]] = {}

    for raw in nodes:
        asset_type_id = str(raw.get("asset_type_id", ""))
        if asset_type_id == "P.6":
            raw_workloads[str(raw.get("id", ""))] = raw
            kubernetes = _mapping(_mapping(raw.get("properties")).get("kubernetes"))
            workload_name = str(kubernetes.get("name") or raw.get("name") or "workload")
            namespace = str(kubernetes.get("namespace") or "default")
            workload_kind = str(kubernetes.get("kind") or "Workload")
            containers = _sequence(kubernetes.get("containers"))
            generated_container_ids: set[str] = set()
            for index, container_value in enumerate(containers):
                container = _mapping(container_value)
                category = str(container.get("category") or "app")
                container_name = str(container.get("name") or f"container-{index + 1}")
                node_id = _stable_id(
                    "mnode",
                    "container",
                    namespace,
                    workload_kind,
                    workload_name,
                    category,
                    container_name,
                )
                if node_id in generated_container_ids:
                    raise ValueError(
                        f"같은 workload에 중복된 container 이름이 있습니다: "
                        f"{workload_kind}/{namespace}/{workload_name} ({category}/{container_name})"
                    )
                generated_container_ids.add(node_id)
                properties = dict(raw.get("properties") or {})
                properties["layout_layer"] = 1
                properties["kubernetes"] = {
                    "kind": "ContainerTemplate",
                    "namespace": namespace,
                    "name": container_name,
                    "category": category,
                    "image": str(container.get("image") or ""),
                    "ports": _sequence(container.get("ports")),
                    "service_account": str(kubernetes.get("service_account") or "default"),
                    "workload_kind": workload_kind,
                    "workload_name": workload_name,
                }
                result.append(
                    _node(
                        node_id,
                        container_name,
                        "P.6.1",
                        "process",
                        f"{workload_kind} {namespace}/{workload_name}의 {category} container template",
                        properties,
                        layer=1,
                    )
                )
            continue
        if asset_type_id in {"D.1", "D.3", "D.4"}:
            result.append(raw)
            continue
        if asset_type_id == "GEN-DATA" and str(raw.get("id", "")) in volume_store_ids:
            projected = dict(raw)
            projected["asset_type_id"] = "D.3"
            projected["dfd_kind"] = "data_store"
            properties = dict(projected.get("properties") or {})
            properties["layout_layer"] = 2
            projected["properties"] = properties
            result.append(projected)

    hostpath_flow_candidates = False
    for host in [node for node in result if node.get("asset_type_id") == "D.4"]:
        kubernetes = _mapping(_mapping(host.get("properties")).get("kubernetes"))
        for mount_value in _sequence(kubernetes.get("mounts")):
            mount = _mapping(mount_value)
            workload_id = str(mount.get("workload_node_id") or "")
            workload = raw_workloads.get(workload_id)
            if not workload:
                continue
            workload_k8s = _mapping(_mapping(workload.get("properties")).get("kubernetes"))
            namespace = str(workload_k8s.get("namespace") or "default")
            workload_kind = str(workload_k8s.get("kind") or "Workload")
            workload_name = str(workload_k8s.get("name") or workload.get("name") or "workload")
            volume_name = str(mount.get("volume_name") or "hostpath")
            manager_id = _stable_id("mnode", "hostpath-manager", namespace, workload_kind, workload_name)
            if not any(str(item.get("id")) == manager_id for item in result):
                manager_properties = {
                    "collector": {
                        **_mapping(_mapping(host.get("properties")).get("collector")),
                        "confidence": "DECLARED_ARCHITECTURE",
                        "evidence": ["hostPath volume declaration"],
                    },
                    "kubernetes": {
                        "kind": "KubeletVolumeManager",
                        "namespace": namespace,
                        "workload_kind": workload_kind,
                        "workload_name": workload_name,
                    },
                }
                result.append(
                    _node(
                        manager_id,
                        "Kubelet Volume Manager",
                        "P.8",
                        "process",
                        "hostPath volume을 준비하는 node-side volume manager",
                        manager_properties,
                        layer=2,
                    )
                )
            volume_id = _stable_id(
                "mnode", "volume", namespace, workload_kind, workload_name, volume_name
            )
            if not any(str(item.get("id")) == volume_id for item in result):
                volume_properties = {
                    "collector": {
                        **_mapping(_mapping(host.get("properties")).get("collector")),
                        "confidence": "DECLARED_REFERENCE",
                        "evidence": [f"hostPath volume={volume_name}"],
                    },
                    "kubernetes": {
                        "kind": "Volume",
                        "source_kind": "hostPath",
                        "namespace": namespace,
                        "name": volume_name,
                        "path": str(kubernetes.get("path") or ""),
                        "workload_kind": workload_kind,
                        "workload_name": workload_name,
                        "read_only": bool(mount.get("read_only")),
                    },
                }
                result.append(
                    _node(
                        volume_id,
                        f"Volume {volume_name}",
                        "D.3",
                        "data_store",
                        "workload에 선언된 hostPath-backed volume",
                        volume_properties,
                        layer=2,
                    )
                )
            hostpath_flow_candidates = True

    if hostpath_flow_candidates:
        unresolved.add(
            "LEVEL1_HOSTPATH_FLOWS_REQUIRE_REVIEW",
            "hostPath 구성요소는 확인했지만 mount 성공과 실제 파일 I/O 방향은 Manifest만으로 증명되지 않아 Level 1 흐름을 연결하지 않았습니다.",
        )
    return result


def _catalog_node_id(template: dict[str, Any]) -> str:
    return _stable_id(
        "mnode",
        "platform-catalog",
        template.get("km_release_id"),
        template.get("level"),
        template.get("asset_type_id"),
    )


def _catalog_edge_id(flow: dict[str, Any]) -> str:
    return _stable_id(
        "medge",
        "platform-catalog",
        flow.get("km_release_id"),
        flow.get("level"),
        flow.get("id"),
    )


def _projection_member(node: dict[str, Any], *, entry_candidate: bool) -> dict[str, Any]:
    """Return a bounded, secret-safe description of one detected instance."""

    properties = _mapping(node.get("properties"))
    kubernetes = _mapping(properties.get("kubernetes"))
    registry = _mapping(properties.get("registry"))
    member: dict[str, Any] = {
        "id": str(node.get("id", "")),
        "name": str(node.get("name", "")),
    }
    for key in (
        "kind",
        "namespace",
        "name",
        "category",
        "workload_kind",
        "workload_name",
        "source_kind",
        "path",
    ):
        value = kubernetes.get(key)
        if isinstance(value, (str, int, float, bool)) and str(value).strip():
            member[key] = value
    if "read_only" in kubernetes:
        member["read_only"] = bool(kubernetes.get("read_only"))
    if registry:
        member.update(
            {
                "kind": "ImageRegistry",
                "host": str(registry.get("host", "")),
                "explicit": bool(registry.get("explicit")),
            }
        )
        images = sorted({str(value) for value in _sequence(registry.get("images")) if str(value)})
        member["image_count"] = len(images)
        member["images"] = images[:20]
        if len(images) > 20:
            member["images_truncated"] = True
    if entry_candidate:
        member["entry_candidate"] = True
    return member


def _aggregate_collectors(
    collectors: Iterable[dict[str, Any]],
    source_digest: str,
    *,
    detection_status: str,
    replacement_key: str,
) -> dict[str, Any]:
    """Merge provenance without allowing a large bundle to inflate one node."""

    unique_refs: dict[str, dict[str, Any]] = {}
    evidence: set[str] = set()
    confidences: set[str] = set()
    entry_candidate = False
    entry_reasons: set[str] = set()
    caveats: set[str] = set()
    for collector in collectors:
        if not isinstance(collector, dict):
            continue
        confidence = str(collector.get("confidence", "")).strip()
        if confidence:
            confidences.add(confidence)
        entry_candidate = entry_candidate or bool(collector.get("entry_candidate"))
        for key, sink in (("entry_candidate_reason", entry_reasons), ("caveat", caveats)):
            value = str(collector.get(key, "")).strip()
            if value:
                sink.add(value)
        for ref in _sequence(collector.get("resource_refs")):
            if not isinstance(ref, dict):
                continue
            canonical = json.dumps(ref, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            unique_refs.setdefault(canonical, ref)
        for value in _sequence(collector.get("evidence")):
            text = str(value).strip()
            if text:
                evidence.add(text[:MAX_ELEMENT_EVIDENCE_CHARS])

    ref_keys = sorted(unique_refs)
    evidence_values = sorted(evidence)
    result: dict[str, Any] = {
        "source": "kubernetes_manifest",
        "mapper_version": MAPPER_VERSION,
        "source_digest": source_digest,
        "confidence": next(iter(confidences)) if len(confidences) == 1 else "MIXED" if confidences else "VERIFIED_CONDITION",
        "detection_status": detection_status,
        "resource_count": len(ref_keys),
        "resource_refs": [unique_refs[key] for key in ref_keys[:MAX_ELEMENT_RESOURCE_REFS]],
        "evidence_count": len(evidence_values),
        "evidence": evidence_values[:MAX_ELEMENT_EVIDENCE_ITEMS],
        "generated_layer_id": PLATFORM_GENERATED_LAYER_ID,
        "replacement_key": replacement_key,
    }
    if len(ref_keys) > MAX_ELEMENT_RESOURCE_REFS:
        result["resource_refs_truncated"] = True
    if len(evidence_values) > MAX_ELEMENT_EVIDENCE_ITEMS:
        result["evidence_truncated"] = True
    if entry_candidate:
        result["entry_candidate"] = True
    if entry_reasons:
        result["entry_candidate_reason"] = " / ".join(sorted(entry_reasons))
    if caveats:
        result["caveat"] = " / ".join(sorted(caveats))
    return result


def _project_to_catalog(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    element_templates: Iterable[dict[str, Any]],
    flow_templates: Iterable[dict[str, Any]],
    dfd_level: int,
    satisfied_flow_conditions: Iterable[str],
    source_digest: str,
    warnings: _RecordSink,
    unresolved: _RecordSink,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Project manifest evidence onto the reusable platform view."""

    elements = _catalog_element_index(element_templates, dfd_level)
    if not elements:
        raise ValueError("선택한 KM 릴리스에 사용할 DFD 요소 카탈로그가 없습니다.")
    active_flows = _active_catalog_flow_templates(flow_templates, dfd_level)
    approved_flows = {flow["id"]: flow for flow in active_flows if flow["review_status"] == "APPROVED"}
    satisfied = {str(value).strip() for value in satisfied_flow_conditions if str(value).strip()}

    candidate_nodes = _level1_manifest_nodes(nodes, edges, unresolved) if dfd_level == 1 else list(nodes)
    public_target_ids = {
        str(edge.get("target", ""))
        for edge in edges
        if _mapping(_mapping(edge.get("properties")).get("collector")).get("relation")
        == "declared-public-flow"
    }
    incident_collectors: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        collector = _mapping(_mapping(edge.get("properties")).get("collector"))
        for endpoint in (str(edge.get("source", "")), str(edge.get("target", ""))):
            if endpoint:
                incident_collectors.setdefault(endpoint, []).append(collector)

    members_by_type: dict[str, list[dict[str, Any]]] = {}
    for node in candidate_nodes:
        asset_type_id = str(node.get("asset_type_id", ""))
        if asset_type_id in elements:
            members_by_type.setdefault(asset_type_id, []).append(node)

    # Conditions are supplied only by a future live/API collector or an
    # equally explicit verifier. The Manifest HTTP endpoint supplies none.
    condition_flows = [
        flow
        for flow in approved_flows.values()
        if flow["auto_instantiation"]
        and flow["condition_key"]
        and flow["condition_key"] in satisfied
    ]
    condition_assets: dict[str, set[str]] = {}
    for flow in condition_flows:
        for asset_type_id in (flow["source_asset_type_id"], flow["target_asset_type_id"]):
            if asset_type_id in elements:
                members_by_type.setdefault(asset_type_id, [])
                condition_assets.setdefault(asset_type_id, set()).add(flow["condition_key"])

    projected_nodes: list[dict[str, Any]] = []
    projected_id_by_type: dict[str, str] = {}
    raw_to_projected: dict[str, str] = {}
    node_status_by_type: dict[str, str] = {}
    for asset_type_id in sorted(
        members_by_type,
        key=lambda value: (
            elements[value].get("sort_order")
            if isinstance(elements[value].get("sort_order"), int)
            else 1_000_000,
            value,
        ),
    ):
        template = elements[asset_type_id]
        member_nodes = sorted(members_by_type[asset_type_id], key=lambda item: str(item.get("id", "")))
        node_id = _catalog_node_id(template)
        projected_id_by_type[asset_type_id] = node_id
        for member_node in member_nodes:
            raw_to_projected[str(member_node.get("id", ""))] = node_id

        all_collectors: list[dict[str, Any]] = []
        members = []
        for member_node in member_nodes:
            raw_id = str(member_node.get("id", ""))
            all_collectors.append(_mapping(_mapping(member_node.get("properties")).get("collector")))
            all_collectors.extend(incident_collectors.get(raw_id, []))
            members.append(
                _projection_member(member_node, entry_candidate=raw_id in public_target_ids)
            )
        member_map = {
            json.dumps(member, ensure_ascii=False, sort_keys=True, separators=(",", ":")): member
            for member in members
        }
        member_keys = sorted(member_map)
        conditions = sorted(condition_assets.get(asset_type_id, set()))
        detection_status = "DECLARED_IN_MANIFEST" if member_nodes else "EVIDENCE_CONDITION_SATISFIED"
        node_status_by_type[asset_type_id] = detection_status
        if conditions:
            all_collectors.append(
                {
                    "confidence": "VERIFIED_CONDITION",
                    "evidence": [f"evidence condition satisfied: {condition}" for condition in conditions],
                }
            )
        replacement_key = f"catalog:{template.get('km_release_id')}:{dfd_level}:{asset_type_id}"
        collector = _aggregate_collectors(
            all_collectors,
            source_digest,
            detection_status=detection_status,
            replacement_key=replacement_key,
        )
        collector["member_count"] = len(member_keys)
        if any(bool(member.get("entry_candidate")) for member in member_map.values()):
            collector["entry_candidate"] = True
            collector["entry_candidate_reason"] = (
                "이 자산 유형에 속한 일부 워크로드에 Ingress, LoadBalancer 또는 NodePort 선언이 있습니다. "
                "실제 외부 도달성은 운영 환경에서 확인해야 합니다."
            )
        properties = {
            "catalog": {
                "km_release_id": template.get("km_release_id"),
                "level": template["level"],
                "element_template_id": asset_type_id,
                "match_basis": "MANIFEST_EVIDENCE_TO_PLATFORM_ASSET_TYPE",
            },
            "collector": collector,
            "manifest_projection": {
                "mode": "PLATFORM_ASSET_TYPE",
                "member_count": len(member_keys),
                "members": [member_map[key] for key in member_keys[:MAX_PROJECTION_MEMBERS]],
                "members_truncated": len(member_keys) > MAX_PROJECTION_MEMBERS,
                "activation_conditions": conditions,
            },
        }
        dfd_kind = template["dfd_kind"] or "process"
        layer = 0 if dfd_kind == "external" else 2 if dfd_kind == "data_store" else 1
        projected_node = _node(
            node_id,
            template["name"],
            asset_type_id,
            dfd_kind,
            template["description"] or f"Manifest 근거가 확인된 {template['name']} 플랫폼 자산 유형",
            properties,
            layer=layer,
        )
        projected_node["asset_type_name"] = template["name"]
        projected_nodes.append(projected_node)

    edge_buckets: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        source_id = raw_to_projected.get(str(edge.get("source", "")))
        target_id = raw_to_projected.get(str(edge.get("target", "")))
        catalog = _mapping(_mapping(edge.get("properties")).get("catalog"))
        flow_id = str(catalog.get("flow_template_id", "")).strip()
        flow = approved_flows.get(flow_id)
        if not source_id or not target_id or not flow:
            continue
        if (
            projected_id_by_type.get(flow["source_asset_type_id"]) != source_id
            or projected_id_by_type.get(flow["target_asset_type_id"]) != target_id
        ):
            continue
        edge_buckets.setdefault(flow_id, []).append(edge)

    projected_edges: list[dict[str, Any]] = []
    flow_candidates: list[dict[str, Any]] = []
    status_by_flow: dict[str, str] = {}

    def projected_flow(flow: dict[str, Any], raw_edges: Iterable[dict[str, Any]], status: str) -> dict[str, Any]:
        raw_values = list(raw_edges)
        collectors = [
            _mapping(_mapping(edge.get("properties")).get("collector")) for edge in raw_values
        ]
        if status == "EVIDENCE_SATISFIED":
            collectors.append(
                {
                    "confidence": "VERIFIED_CONDITION",
                    "evidence": [f"evidence condition satisfied: {flow['condition_key']}"],
                }
            )
        replacement_key = f"catalog-flow:{flow.get('km_release_id')}:{dfd_level}:{flow['id']}"
        collector = _aggregate_collectors(
            collectors,
            source_digest,
            detection_status=status,
            replacement_key=replacement_key,
        )
        collector["relation"] = "catalog-platform-flow"
        protocols = sorted(
            {
                part.strip()
                for edge in raw_values
                for part in str(edge.get("protocol", "")).split(",")
                if part.strip()
            }
        )
        data_types = sorted({str(edge.get("data_type", "")).strip() for edge in raw_values if str(edge.get("data_type", "")).strip()})
        requires_confirmation = status == "CONFIRMATION_REQUIRED"
        return {
            "id": _catalog_edge_id(flow),
            "source": projected_id_by_type[flow["source_asset_type_id"]],
            "target": projected_id_by_type[flow["target_asset_type_id"]],
            "name": flow["name"],
            "protocol": ", ".join(protocols),
            "data_type": " / ".join(data_types),
            "properties": {
                "collector": collector,
                "catalog": {
                    "km_release_id": flow.get("km_release_id"),
                    "level": dfd_level,
                    "flow_template_id": flow["id"],
                    "match_basis": (
                        "SATISFIED_EVIDENCE_CONDITION"
                        if not requires_confirmation
                        else "DECLARED_RELATION_REQUIRES_CONFIRMATION"
                    ),
                    "requires_user_confirmation": requires_confirmation,
                    "condition_key": flow["condition_key"],
                    "proposal_status": status,
                },
            },
        }

    for flow_id, raw_values in sorted(edge_buckets.items()):
        flow = approved_flows[flow_id]
        if flow["auto_instantiation"] and flow["condition_key"] in satisfied:
            status_by_flow[flow_id] = "EVIDENCE_SATISFIED"
            projected_edges.append(projected_flow(flow, raw_values, "EVIDENCE_SATISFIED"))
        else:
            status_by_flow[flow_id] = "CONFIRMATION_CANDIDATE"
            flow_candidates.append(projected_flow(flow, raw_values, "CONFIRMATION_REQUIRED"))

    for flow in condition_flows:
        if (
            flow["source_asset_type_id"] not in projected_id_by_type
            or flow["target_asset_type_id"] not in projected_id_by_type
        ):
            continue
        if flow["id"] in status_by_flow:
            continue
        status_by_flow[flow["id"]] = "EVIDENCE_SATISFIED"
        projected_edges.append(projected_flow(flow, [], "EVIDENCE_SATISFIED"))

    omitted_nodes = sum(
        1 for node in candidate_nodes if str(node.get("asset_type_id", "")) not in elements
    )
    catalog_raw_edges = sum(1 for edge in edges if _mapping(_mapping(edge.get("properties")).get("catalog")))
    represented_raw_edges = sum(len(values) for values in edge_buckets.values())
    omitted_edges = len(edges) - represented_raw_edges
    if omitted_nodes or omitted_edges:
        warnings.add(
            "CATALOG_PROJECTION_OMITTED_UNPROVEN_ITEMS",
            "저장된 DFD 요소·흐름과 근거가 정확히 맞지 않는 Manifest 항목은 자동 초안에서 제외했습니다.",
            details={
                "nodes": omitted_nodes,
                "edges": omitted_edges,
                "catalog_edges_seen": catalog_raw_edges,
                "level": dfd_level,
            },
        )
    if "D.1" in projected_id_by_type and any(
        _mapping(_mapping(edge.get("properties")).get("collector")).get("relation") == "image-supply"
        for edge in edges
    ):
        image_flow_ids = [
            flow["id"]
            for flow in active_flows
            if flow.get("condition_key") == "IMAGE_REFERENCE_AND_CONTAINERD"
        ]
        unresolved.add(
            "IMAGE_RUNTIME_FLOW_NOT_PROVEN",
            "컨테이너 이미지 참조는 확인했지만 실제 containerd 이미지 요청·응답은 Manifest만으로 증명되지 않아 연결하지 않았습니다.",
            details={
                "required_condition": "IMAGE_REFERENCE_AND_CONTAINERD",
                "candidate_flow_ids": image_flow_ids,
            },
        )

    _layout_proposal_nodes(projected_nodes)
    projected_edges.sort(key=lambda edge: edge["id"])
    flow_candidates.sort(key=lambda edge: edge["id"])

    platform_template = {
        "km_release_id": next(
            (template.get("km_release_id") for template in elements.values()), None
        ),
        "level": dfd_level,
        "operative": False,
        "description": (
            "선택한 수준의 전체 플랫폼 참조 모델입니다. 감지되지 않은 요소와 흐름은 "
            "회색 안내용이며 위협 경로 계산에 사용하면 안 됩니다."
        ),
        "elements": [
            {
                "id": _catalog_node_id(template),
                "asset_type_id": template["asset_type_id"],
                "name": template["name"],
                "dfd_kind": template["dfd_kind"],
                "group_name": template["group_name"],
                "description": template["description"],
                "parent_asset_type_id": template["parent_asset_type_id"],
                "parent_name": template["parent_name"],
                "sort_order": template["sort_order"],
                "detection_status": node_status_by_type.get(template["asset_type_id"], "NOT_DETECTED"),
            }
            for template in sorted(
                elements.values(),
                key=lambda value: (
                    value.get("sort_order") if isinstance(value.get("sort_order"), int) else 1_000_000,
                    value["asset_type_id"],
                ),
            )
        ],
        "flows": [
            {
                "id": _catalog_edge_id(flow),
                "flow_template_id": flow["id"],
                "name": flow["name"],
                "source": _catalog_node_id(elements[flow["source_asset_type_id"]]),
                "target": _catalog_node_id(elements[flow["target_asset_type_id"]]),
                "source_asset_type_id": flow["source_asset_type_id"],
                "target_asset_type_id": flow["target_asset_type_id"],
                "review_status": flow["review_status"],
                "auto_instantiation": flow["auto_instantiation"],
                "condition_key": flow["condition_key"],
                "notes": flow["notes"],
                "sort_order": flow["sort_order"],
                "detection_status": status_by_flow.get(flow["id"], "REFERENCE_ONLY"),
            }
            for flow in active_flows
            if flow["source_asset_type_id"] in elements and flow["target_asset_type_id"] in elements
        ],
    }
    return projected_nodes, projected_edges, flow_candidates, platform_template


def _project_to_logical_system(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    element_templates: Iterable[dict[str, Any]],
    dfd_level: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Project logical workloads and their declared data references."""

    elements = _catalog_element_index(element_templates, dfd_level)
    projected_nodes: list[dict[str, Any]] = []
    for raw_node in nodes:
        node = {**raw_node}
        properties = dict(_mapping(raw_node.get("properties")))
        collector = dict(_mapping(properties.get("collector")))
        node_id = str(raw_node.get("id", ""))
        asset_type_id = str(raw_node.get("asset_type_id", ""))
        replacement_key = f"logical-node:{node_id}"
        collector.update(
            {
                "generated_layer_id": LOGICAL_GENERATED_LAYER_ID,
                "detection_status": "DECLARED_IN_MANIFEST",
                "replacement_key": replacement_key,
            }
        )
        properties["collector"] = collector
        properties["manifest_projection"] = {
            "mode": "LOGICAL_RESOURCE_INSTANCE",
            "replacement_key": replacement_key,
            "member_count": 1,
            "members": [
                _projection_member(
                    raw_node,
                    entry_candidate=bool(collector.get("entry_candidate")),
                )
            ],
        }
        template = elements.get(asset_type_id)
        if template:
            properties["catalog"] = {
                "km_release_id": template.get("km_release_id"),
                "level": dfd_level,
                "element_template_id": asset_type_id,
                "match_basis": "MANIFEST_LOGICAL_RESOURCE_INSTANCE",
            }
            node["asset_type_name"] = template["name"]
        node["properties"] = properties
        projected_nodes.append(node)

    included_edges: list[dict[str, Any]] = []
    flow_candidates: list[dict[str, Any]] = []
    for raw_edge in edges:
        edge = {**raw_edge}
        properties = dict(_mapping(raw_edge.get("properties")))
        collector = dict(_mapping(properties.get("collector")))
        catalog = dict(_mapping(properties.get("catalog")))
        relation = str(collector.get("relation", ""))
        edge_id = str(raw_edge.get("id", ""))
        needs_confirmation = relation == "image-supply"
        # Image references remain node evidence until the runtime path is verified.
        if needs_confirmation:
            continue
        replacement_key = f"logical-edge:{edge_id}"
        collector.update(
            {
                "generated_layer_id": LOGICAL_GENERATED_LAYER_ID,
                "detection_status": (
                    "CONFIRMATION_REQUIRED"
                    if needs_confirmation
                    else "DECLARED_CONFIGURATION"
                ),
                "replacement_key": replacement_key,
                "requires_user_confirmation": needs_confirmation,
            }
        )
        properties["collector"] = collector
        if catalog:
            catalog.update(
                {
                    "match_basis": "DECLARED_KUBERNETES_RELATION",
                    "requires_user_confirmation": needs_confirmation,
                    "proposal_status": (
                        "CONFIRMATION_REQUIRED"
                        if needs_confirmation
                        else "DECLARED_CONFIGURATION"
                    ),
                }
            )
            properties["catalog"] = catalog
        edge["properties"] = properties
        included_edges.append(edge)

    projected_nodes.sort(key=lambda item: str(item.get("id", "")))
    grouped_nodes: dict[str, list[dict[str, Any]]] = {
        "external": [],
        "process": [],
        "data_store": [],
    }
    for node in projected_nodes:
        grouped_nodes.setdefault(str(node.get("dfd_kind", "process")), []).append(node)
    for kind_nodes in grouped_nodes.values():
        kind_nodes.sort(
            key=lambda item: (
                str(_mapping(_mapping(item.get("properties")).get("kubernetes")).get("namespace", "")),
                str(item.get("name", "")),
                str(item.get("id", "")),
            )
        )
    start_y = 390
    row_gap = 105
    for index, node in enumerate(grouped_nodes.get("external", [])):
        node["x"] = 60
        node["y"] = start_y + index * row_gap
    process_nodes = grouped_nodes.get("process", [])
    process_columns = 4 if len(process_nodes) > 18 else 3
    for index, node in enumerate(process_nodes):
        node["x"] = 310 + (index % process_columns) * 210
        node["y"] = start_y + (index // process_columns) * row_gap
    store_x = 310 + process_columns * 210 + 90
    for index, node in enumerate(grouped_nodes.get("data_store", [])):
        node["x"] = store_x
        node["y"] = start_y + index * row_gap
    included_edges.sort(key=lambda item: str(item.get("id", "")))
    flow_candidates.sort(key=lambda item: str(item.get("id", "")))
    return projected_nodes, included_edges, flow_candidates


def _build_proposal(
    resources: list[_Resource],
    source_digest: str,
    warnings: _RecordSink,
    unresolved: _RecordSink,
    *,
    flow_templates: Iterable[dict[str, Any]] = (),
    dfd_level: int = 0,
    satisfied_flow_conditions: Iterable[str] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    nodes: dict[str, dict[str, Any]] = {}
    node_semantic_keys: dict[tuple[str, str, str], str] = {}
    edges: dict[str, dict[str, Any]] = {}
    approved_flow_templates = _approved_flow_template_index(
        flow_templates,
        dfd_level,
        satisfied_flow_conditions,
    )

    resource_by_key = {resource.key: resource for resource in resources}
    workload_resources = [resource for resource in resources if resource.kind in _WORKLOAD_KINDS]
    workload_keys = {resource.key for resource in workload_resources}
    top_workloads = [
        resource
        for resource in workload_resources
        if not any(owner in workload_keys for owner in _owner_keys(resource))
    ]

    workload_models: list[dict[str, Any]] = []
    for resource in sorted(top_workloads, key=lambda item: (item.namespace, item.kind, item.name)):
        template_meta, pod_spec = _pod_template(resource)
        labels = _mapping(template_meta.get("labels"))
        containers = _container_inventory(pod_spec)
        node_id = _stable_id("mnode", "workload", resource.kind, resource.namespace, resource.name)
        collector = _resource_collector(
            source_digest,
            [resource.evidence()],
            confidence="DECLARED",
            evidence=["top-level workload declaration"],
        )
        nodes[node_id] = _node(
            node_id,
            f"{resource.name}",
            "P.6",
            "process",
            f"{resource.kind} 워크로드 ({resource.namespace})",
            {
                "collector": collector,
                "kubernetes": {
                    "kind": resource.kind,
                    "namespace": resource.namespace,
                    "name": resource.name,
                    "service_account": _string(pod_spec.get("serviceAccountName")) or "default",
                    "containers": containers,
                },
            },
            layer=1,
        )
        if len(nodes) > MAX_PROPOSAL_NODES:
            raise ValueError(
                f"DFD 초안 노드가 {MAX_PROPOSAL_NODES}개를 넘습니다. 입력 범위 또는 namespace를 나눠 주세요."
            )
        node_semantic_keys[("workload", resource.namespace, resource.name)] = node_id
        workload_models.append(
            {
                "resource": resource,
                "node_id": node_id,
                "labels": labels,
                "pod_spec": pod_spec,
                "containers": containers,
            }
        )

    data_resources = {
        (resource.kind, resource.namespace, resource.name): resource
        for resource in resources
        if resource.kind in {"PersistentVolumeClaim", "ConfigMap", "Secret"}
    }

    def ensure_store(
        kind: str,
        namespace: str,
        name: str,
        *,
        reference: _Resource | None = None,
        host_path: str = "",
    ) -> str:
        semantic = (kind, namespace, name)
        existing = node_semantic_keys.get(semantic)
        if existing:
            return existing
        declared = data_resources.get((kind, namespace, name))
        refs = [declared.evidence()] if declared else ([reference.evidence()] if reference else [])
        confidence = "DECLARED_RESOURCE" if declared else "REFERENCED"
        evidence = ["manifest data-store declaration"] if declared else ["workload reference; referenced object not supplied"]
        if kind == "PersistentVolumeClaim":
            asset_type_id, display, description = "D.3", f"PVC {name}", "Kubernetes PersistentVolumeClaim"
        elif kind == "HostPath":
            asset_type_id, display, description = "D.4", f"HostPath {host_path or name}", "노드의 호스트 파일 시스템 경로"
            confidence = "DECLARED_REFERENCE"
            evidence = ["workload hostPath volume declaration"]
        elif kind == "Secret":
            asset_type_id, display, description = "GEN-DATA", f"Secret {name}", "Kubernetes Secret (값은 수집하지 않음)"
        else:
            asset_type_id, display, description = "GEN-DATA", f"ConfigMap {name}", "Kubernetes ConfigMap (값은 수집하지 않음)"
        node_id = _stable_id("mnode", "store", kind, namespace, name)
        kubernetes: dict[str, Any] = {"kind": kind, "namespace": namespace, "name": name, "declared": bool(declared)}
        if kind == "HostPath":
            kubernetes["path"] = host_path
        elif declared and kind == "Secret":
            document = declared.document
            kubernetes["secret_type"] = _string(document.get("type")) or "Opaque"
            kubernetes["data_keys"] = sorted(
                set(_mapping(document.get("data"))) | set(_mapping(document.get("stringData")))
            )
        elif declared and kind == "ConfigMap":
            document = declared.document
            kubernetes["data_keys"] = sorted(
                set(_mapping(document.get("data"))) | set(_mapping(document.get("binaryData")))
            )
        elif declared and kind == "PersistentVolumeClaim":
            spec = _mapping(declared.document.get("spec"))
            requests = _mapping(_mapping(spec.get("resources")).get("requests"))
            kubernetes.update(
                {
                    "access_modes": sorted(str(item) for item in _sequence(spec.get("accessModes"))),
                    "storage_class": _string(spec.get("storageClassName")),
                    "requested_storage": _string(requests.get("storage")),
                }
            )
        nodes[node_id] = _node(
            node_id,
            display,
            asset_type_id,
            "data_store",
            description,
            {
                "collector": _resource_collector(
                    source_digest,
                    refs,
                    confidence=confidence,
                    evidence=evidence,
                ),
                "kubernetes": kubernetes,
            },
            layer=2,
        )
        if len(nodes) > MAX_PROPOSAL_NODES:
            raise ValueError(
                f"DFD 초안 노드가 {MAX_PROPOSAL_NODES}개를 넘습니다. 입력 범위 또는 namespace를 나눠 주세요."
            )
        node_semantic_keys[semantic] = node_id
        if not declared and kind in {"PersistentVolumeClaim", "ConfigMap", "Secret"}:
            unresolved.add(
                "REFERENCED_RESOURCE_NOT_SUPPLIED",
                "워크로드가 참조하지만 입력 Manifest에 해당 객체 선언이 없습니다.",
                resource=f"{kind}/{namespace}/{name}",
                source=reference.source.public() if reference else None,
            )
        return node_id

    def add_edge(
        source: str,
        target: str,
        relation: str,
        name: str,
        *,
        protocol: str = "",
        data_type: str = "",
        refs: Iterable[dict[str, Any]] = (),
        confidence: str = "DECLARED_REFERENCE",
        evidence: Iterable[str] = (),
    ) -> None:
        edge_id = _stable_id("medge", relation, source, target)
        if edge_id in edges:
            collector = edges[edge_id]["properties"]["collector"]
            merged = _resource_collector(
                source_digest,
                chain(collector.get("resource_refs", []), refs),
                confidence=collector.get("confidence", confidence),
                evidence=chain(collector.get("evidence", []), evidence),
                relation=relation,
            )
            collector["resource_refs"] = merged["resource_refs"]
            collector["evidence"] = merged["evidence"]
            if protocol:
                protocols = {part.strip() for part in str(edges[edge_id].get("protocol", "")).split(",") if part.strip()}
                protocols.add(protocol)
                edges[edge_id]["protocol"] = ", ".join(sorted(protocols))
            return
        source_asset_type = str(nodes.get(source, {}).get("asset_type_id", ""))
        target_asset_type = str(nodes.get(target, {}).get("asset_type_id", ""))
        flow_template = approved_flow_templates.get((source_asset_type, target_asset_type))
        properties: dict[str, Any] = {
            "collector": _resource_collector(
                source_digest,
                refs,
                confidence=confidence,
                evidence=evidence,
                relation=relation,
            )
        }
        if flow_template:
            properties["catalog"] = {
                "km_release_id": flow_template.get("km_release_id"),
                "level": flow_template["level"],
                "flow_template_id": flow_template["id"],
                "match_basis": "EXACT_DIRECTED_ASSET_TYPES",
                "requires_user_confirmation": not flow_template["auto_instantiation"],
                "condition_key": flow_template["condition_key"],
            }
        edges[edge_id] = {
            "id": edge_id,
            "source": source,
            "target": target,
            "name": flow_template["name"] if flow_template else name,
            "protocol": protocol,
            "data_type": data_type,
            "properties": properties,
        }
        if len(edges) > MAX_PROPOSAL_EDGES:
            raise ValueError(
                f"DFD 초안 데이터 흐름이 {MAX_PROPOSAL_EDGES}개를 넘습니다. "
                "입력 범위 또는 namespace를 나눠 주세요."
            )

    # Workload relations to registries and referenced stores.
    registry_nodes: dict[str, str] = {}
    registry_images: dict[str, set[str]] = {}
    for model in workload_models:
        resource: _Resource = model["resource"]
        workload_node = model["node_id"]
        pod_spec: dict[str, Any] = model["pod_spec"]

        for container in model["containers"]:
            image = container.get("image") or ""
            if not image:
                continue
            registry, explicit = _image_registry(image)
            registry_images.setdefault(registry, set()).add(image)
            registry_node = registry_nodes.get(registry)
            if not registry_node:
                registry_node = _stable_id("mnode", "registry", registry)
                registry_nodes[registry] = registry_node
                nodes[registry_node] = _node(
                    registry_node,
                    f"Image Registry {registry}" if explicit else "기본 Image Registry (확인 필요)",
                    "D.1",
                    "data_store",
                    "컨테이너 이미지를 제공하는 Registry",
                    {
                        "collector": _resource_collector(
                            source_digest,
                            [resource.evidence()],
                            confidence="DECLARED_REFERENCE" if explicit else "INFERRED",
                            evidence=["container image reference"],
                        ),
                        "registry": {"host": registry, "explicit": explicit, "images": []},
                    },
                    layer=0,
                )
                if len(nodes) > MAX_PROPOSAL_NODES:
                    raise ValueError(
                        f"DFD 초안 노드가 {MAX_PROPOSAL_NODES}개를 넘습니다. 입력 범위 또는 namespace를 나눠 주세요."
                    )
            if not explicit:
                unresolved.add(
                    "IMPLICIT_IMAGE_REGISTRY",
                    "이미지 주소에 Registry 호스트가 없어 실제 Registry 또는 mirror를 확인해야 합니다.",
                    resource=resource.ref,
                    source=resource.source.public(),
                )
            add_edge(
                registry_node,
                workload_node,
                "image-supply",
                "컨테이너 이미지 공급",
                data_type="Container image",
                refs=[resource.evidence()],
                confidence="DECLARED_REFERENCE",
                evidence=[f"image={image}"],
            )

        containers = [
            _mapping(container)
            for field in ("initContainers", "containers", "ephemeralContainers")
            for container in _sequence(pod_spec.get(field))
        ]
        mounts: dict[str, list[bool]] = {}
        for container in containers:
            for mount in _sequence(container.get("volumeMounts")):
                mount = _mapping(mount)
                volume_name = _string(mount.get("name"))
                if volume_name:
                    mounts.setdefault(volume_name, []).append(bool(mount.get("readOnly")))

        for volume in _sequence(pod_spec.get("volumes")):
            volume = _mapping(volume)
            volume_name = _string(volume.get("name"))
            if not volume_name or volume_name not in mounts:
                continue
            all_read_only = bool(mounts[volume_name]) and all(mounts[volume_name])
            pvc = _mapping(volume.get("persistentVolumeClaim"))
            config_map = _mapping(volume.get("configMap"))
            secret = _mapping(volume.get("secret"))
            host_path = _mapping(volume.get("hostPath"))
            store_relations: list[tuple[str, str, str, bool, str]] = []
            claim_name = _string(pvc.get("claimName"))
            if claim_name:
                store_relations.append(("PersistentVolumeClaim", claim_name, "Persistent volume data", all_read_only or bool(pvc.get("readOnly")), "pvc-volume"))
            config_name = _string(config_map.get("name"))
            if config_name:
                store_relations.append(("ConfigMap", config_name, "Configuration data", True, "config-volume"))
            secret_name = _string(secret.get("secretName"))
            if secret_name:
                store_relations.append(("Secret", secret_name, "Secret data", True, "secret-volume"))
            path = _string(host_path.get("path"))
            if path:
                store_relations.append(("HostPath", path, "Host file data", all_read_only, "hostpath-volume"))
            for projected in _sequence(_mapping(volume.get("projected")).get("sources")):
                projected = _mapping(projected)
                projected_cm = _string(_mapping(projected.get("configMap")).get("name"))
                projected_secret = _string(_mapping(projected.get("secret")).get("name"))
                if projected_cm:
                    store_relations.append(("ConfigMap", projected_cm, "Projected configuration", True, "config-projected"))
                if projected_secret:
                    store_relations.append(("Secret", projected_secret, "Projected secret", True, "secret-projected"))

            for kind, store_name, data_type, read_only, relation in store_relations:
                store_node = ensure_store(
                    kind,
                    resource.namespace,
                    store_name,
                    reference=resource,
                    host_path=store_name if kind == "HostPath" else "",
                )
                if kind == "HostPath":
                    host_kubernetes = _mapping(_mapping(nodes[store_node].get("properties")).get("kubernetes"))
                    host_mount_records = host_kubernetes.setdefault("mounts", [])
                    mount_record = {
                        "workload_node_id": workload_node,
                        "workload": resource.ref,
                        "volume_name": volume_name,
                        "read_only": bool(read_only),
                    }
                    if mount_record not in host_mount_records:
                        host_mount_records.append(mount_record)
                if read_only:
                    add_edge(
                        store_node,
                        workload_node,
                        f"{relation}-read",
                        "데이터 읽기",
                        data_type=data_type,
                        refs=[resource.evidence()],
                        confidence="DECLARED_REFERENCE",
                        evidence=[f"volume={volume_name}", "read-only mount declaration"],
                    )
                elif kind in {"PersistentVolumeClaim", "HostPath"}:
                    unresolved.add(
                        "VOLUME_FLOW_DIRECTION_UNKNOWN",
                        "쓰기 가능한 volume mount는 실제 읽기·쓰기 방향을 Manifest만으로 확정할 수 없어 흐름을 만들지 않았습니다.",
                        resource=resource.ref,
                        source=resource.source.public(),
                        details={
                            "workload": resource.ref,
                            "store": f"{kind}/{resource.namespace}/{store_name}",
                            "volume": volume_name,
                        },
                    )

        def add_reference(kind: str, name: str, relation: str, data_type: str) -> None:
            if not name:
                return
            store_node = ensure_store(kind, resource.namespace, name, reference=resource)
            add_edge(
                store_node,
                workload_node,
                relation,
                "설정·자격 정보 제공",
                data_type=data_type,
                refs=[resource.evidence()],
                confidence="DECLARED_REFERENCE",
                evidence=["workload value reference"],
            )

        for container in containers:
            for env_from in _sequence(container.get("envFrom")):
                env_from = _mapping(env_from)
                add_reference("ConfigMap", _string(_mapping(env_from.get("configMapRef")).get("name")), "config-env", "Configuration data")
                add_reference("Secret", _string(_mapping(env_from.get("secretRef")).get("name")), "secret-env", "Secret data")
            for env in _sequence(container.get("env")):
                value_from = _mapping(_mapping(env).get("valueFrom"))
                add_reference("ConfigMap", _string(_mapping(value_from.get("configMapKeyRef")).get("name")), "config-env", "Configuration data")
                add_reference("Secret", _string(_mapping(value_from.get("secretKeyRef")).get("name")), "secret-env", "Secret data")
        for pull_secret in _sequence(pod_spec.get("imagePullSecrets")):
            add_reference("Secret", _string(_mapping(pull_secret).get("name")), "registry-credential", "Image pull credential")

    omitted_data_resources = sorted(
        key for key in data_resources if key not in node_semantic_keys
    )
    if omitted_data_resources:
        counts: dict[str, int] = {}
        for kind, _namespace, _name in omitted_data_resources:
            counts[kind] = counts.get(kind, 0) + 1
        warnings.add(
            "UNREFERENCED_DATA_RESOURCES_OMITTED",
            "워크로드 참조가 확인되지 않은 저장소 객체는 DFD가 복잡해지지 않도록 초안에서 제외했습니다.",
            details={"counts": counts, "total": len(omitted_data_resources)},
        )

    for registry, node_id in registry_nodes.items():
        nodes[node_id]["properties"]["registry"]["images"] = sorted(registry_images.get(registry, set()))

    services = [resource for resource in resources if resource.kind == "Service"]
    services_by_key = {(resource.namespace, resource.name): resource for resource in services}
    service_backends: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for service in services:
        spec = _mapping(service.document.get("spec"))
        service_type = _string(spec.get("type")) or "ClusterIP"
        if service_type == "ExternalName":
            unresolved.add(
                "EXTERNAL_NAME_CALLER_UNKNOWN",
                "ExternalName Service는 외부 대상을 선언하지만 호출 워크로드가 Manifest만으로 확인되지 않습니다.",
                resource=service.ref,
                source=service.source.public(),
            )
            service_backends[(service.namespace, service.name)] = []
            continue
        selector = _mapping(spec.get("selector"))
        if not selector:
            unresolved.add(
                "SERVICE_SELECTOR_MISSING",
                "Service selector가 없어 대상 워크로드를 Manifest만으로 확인할 수 없습니다.",
                resource=service.ref,
                source=service.source.public(),
            )
            service_backends[(service.namespace, service.name)] = []
            continue
        matches = [
            model
            for model in workload_models
            if model["resource"].namespace == service.namespace
            and _selector_matches(selector, model["labels"])
        ]
        if len(matches) > MAX_SELECTOR_BACKENDS:
            raise ValueError(
                f"Service selector 하나가 {MAX_SELECTOR_BACKENDS}개가 넘는 워크로드와 일치합니다: {service.ref}. "
                "입력 범위 또는 namespace를 나눠 주세요."
            )
        service_backends[(service.namespace, service.name)] = matches
        if not matches:
            unresolved.add(
                "SERVICE_BACKEND_UNRESOLVED",
                "Service selector와 일치하는 입력 워크로드를 찾을 수 없습니다.",
                resource=service.ref,
                source=service.source.public(),
            )
        for model in matches:
            workload_properties = _mapping(nodes.get(model["node_id"], {}).get("properties"))
            kubernetes = _mapping(workload_properties.get("kubernetes"))
            attached_services = kubernetes.setdefault("services", [])
            service_record = {
                "namespace": service.namespace,
                "name": service.name,
                "type": service_type,
                "protocols": _service_protocols(service),
                "source": service.source.public(),
            }
            if service_record not in attached_services:
                attached_services.append(service_record)

    exposure_by_workload: dict[str, dict[str, Any]] = {}

    def record_exposure(
        model: dict[str, Any],
        resource: _Resource,
        description: str,
        protocols: Iterable[str],
    ) -> None:
        record = exposure_by_workload.setdefault(
            model["node_id"], {"refs": [], "evidence": [], "protocols": set()}
        )
        record["refs"].append(resource.evidence())
        record["evidence"].append(description)
        record["protocols"].update(item for item in protocols if item)
        if len({json.dumps(ref, sort_keys=True) for ref in record["refs"]}) > MAX_ELEMENT_RESOURCE_REFS:
            raise ValueError(
                f"워크로드 하나의 공개 경로 출처가 {MAX_ELEMENT_RESOURCE_REFS}개를 넘습니다. "
                "입력 범위 또는 namespace를 나눠 주세요."
            )
        if len(set(record["evidence"])) > MAX_ELEMENT_EVIDENCE_ITEMS:
            raise ValueError(
                f"워크로드 하나의 공개 경로 근거가 {MAX_ELEMENT_EVIDENCE_ITEMS}개를 넘습니다. "
                "입력 범위 또는 namespace를 나눠 주세요."
            )

    for service in services:
        spec = _mapping(service.document.get("spec"))
        service_type = _string(spec.get("type")) or "ClusterIP"
        if service_type not in {"LoadBalancer", "NodePort"}:
            continue
        backends = service_backends.get((service.namespace, service.name), [])
        if not backends:
            unresolved.add(
                "PUBLIC_SERVICE_BACKEND_UNRESOLVED",
                "공개 Service의 대상 워크로드를 확인할 수 없습니다.",
                resource=service.ref,
                source=service.source.public(),
            )
            continue
        for model in backends:
            record_exposure(
                model,
                service,
                f"Service {service_type} {service.namespace}/{service.name}",
                _service_protocols(service),
            )

    ingresses = [resource for resource in resources if resource.kind == "Ingress"]
    for ingress in ingresses:
        backends = _ingress_backends(ingress)
        if not backends:
            unresolved.add(
                "INGRESS_BACKEND_MISSING",
                "Ingress에서 참조하는 Service backend를 찾을 수 없습니다.",
                resource=ingress.ref,
                source=ingress.source.public(),
            )
        for backend in backends:
            service = services_by_key.get((ingress.namespace, backend["service_name"]))
            if not service:
                unresolved.add(
                    "INGRESS_SERVICE_NOT_SUPPLIED",
                    "Ingress가 참조하는 Service가 입력 Manifest에 없습니다.",
                    resource=f"Service/{ingress.namespace}/{backend['service_name']}",
                    source=ingress.source.public(),
                )
                continue
            matches = service_backends.get((service.namespace, service.name), [])
            if not matches:
                unresolved.add(
                    "INGRESS_BACKEND_UNRESOLVED",
                    "Ingress Service와 연결되는 워크로드를 확인할 수 없습니다.",
                    resource=ingress.ref,
                    source=ingress.source.public(),
                )
                continue
            endpoint = "/".join(part for part in (backend["host"], backend["path"]) if part) or "default backend"
            for model in matches:
                record_exposure(
                    model,
                    ingress,
                    f"Ingress {ingress.namespace}/{ingress.name} ({endpoint})",
                    [backend["protocol"]],
                )

    if exposure_by_workload:
        for workload_node, record in exposure_by_workload.items():
            collector = _mapping(_mapping(nodes[workload_node].get("properties")).get("collector"))
            collector["entry_candidate"] = True
            collector["entry_candidate_reason"] = (
                "Ingress, LoadBalancer 또는 NodePort가 이 워크로드를 대상으로 선언합니다. "
                "실제 외부 도달성은 운영 환경에서 확인해야 합니다."
            )
            collector["declared_exposures"] = sorted(set(record["evidence"]))
        exposure_refs = [ref for record in exposure_by_workload.values() for ref in record["refs"]]
        external_id = _stable_id("mnode", "external", "declared-public-client")
        nodes[external_id] = _node(
            external_id,
            "외부 사용자/시스템",
            "GEN-EXT",
            "external",
            "Manifest에 선언된 공개 경로의 외부 통신 주체",
            {
                "collector": _resource_collector(
                    source_digest,
                    exposure_refs,
                    confidence="DECLARED_EXPOSURE",
                    evidence=["Ingress, LoadBalancer 또는 NodePort 선언"],
                    entry_candidate=True,
                    entry_candidate_reason="Manifest에 공개 경로가 선언되어 있어 진입 지점 후보로 제안되었습니다.",
                    caveat="실제 DNS, Load Balancer, 방화벽, Ingress Controller와 Endpoint 상태를 확인해야 합니다.",
                )
            },
            layer=0,
        )
        if len(nodes) > MAX_PROPOSAL_NODES:
            raise ValueError(
                f"DFD 초안 노드가 {MAX_PROPOSAL_NODES}개를 넘습니다. 입력 범위 또는 namespace를 나눠 주세요."
            )
        warnings.add(
            "DECLARED_EXPOSURE_REQUIRES_VALIDATION",
            "Manifest의 공개 경로는 실제 외부 도달성을 보장하지 않습니다. 진입 지점 지정 전에 운영 상태를 확인해 주세요.",
        )
        for workload_node, record in sorted(exposure_by_workload.items()):
            add_edge(
                external_id,
                workload_node,
                "declared-public-flow",
                "외부 요청",
                protocol=", ".join(sorted(record["protocols"])),
                data_type="External request",
                refs=record["refs"],
                confidence="DECLARED_EXPOSURE",
                evidence=record["evidence"],
            )

    # Namespace does not imply a trust boundary.
    _layout_proposal_nodes(nodes.values())

    return (
        sorted(nodes.values(), key=lambda item: item["id"]),
        sorted(edges.values(), key=lambda item: item["id"]),
        [],
    )


def build_manifest_proposal(
    files: list[dict[str, Any]],
    *,
    element_templates: Iterable[dict[str, Any]] = (),
    flow_templates: Iterable[dict[str, Any]] = (),
    dfd_level: int = 0,
    satisfied_flow_conditions: Iterable[str] = (),
    strict_catalog: bool = False,
    projection_mode: str = "platform",
) -> dict[str, Any]:
    """Build a DFD proposal from YAML or JSON manifest text."""

    element_templates = tuple(element_templates)
    flow_templates = tuple(flow_templates)
    projection_mode = str(projection_mode or "platform").strip().lower()
    if projection_mode not in {"platform", "logical"}:
        raise ValueError("Manifest DFD 투영 방식은 platform 또는 logical이어야 합니다.")
    if projection_mode == "logical" and not strict_catalog:
        raise ValueError("logical 투영에는 DFD 요소 카탈로그가 필요합니다.")
    satisfied_flow_conditions = tuple(
        sorted({str(value).strip() for value in satisfied_flow_conditions if str(value).strip()})
    )
    prepared, source_digest = _prepare_files(files)
    warnings = _RecordSink()
    unresolved = _RecordSink()
    documents, document_count = _parse_documents(prepared, warnings)
    resources = _normalize_resources(documents, warnings)
    nodes, edges, boundaries = _build_proposal(
        resources,
        source_digest,
        warnings,
        unresolved,
        flow_templates=flow_templates,
        dfd_level=dfd_level,
        satisfied_flow_conditions=satisfied_flow_conditions,
    )
    public_exposure_candidate_count = sum(
        1
        for edge in edges
        if _mapping(_mapping(edge.get("properties")).get("collector")).get("relation")
        == "declared-public-flow"
    )
    flow_candidates: list[dict[str, Any]] = []
    platform_template: dict[str, Any] | None = None
    if strict_catalog:
        if projection_mode == "logical":
            has_image_references = any(
                _mapping(_mapping(edge.get("properties")).get("collector")).get("relation")
                == "image-supply"
                for edge in edges
            )
            # Build the platform reference without mixing its issues into the logical view.
            _, _, _, platform_template = _project_to_catalog(
                nodes,
                edges,
                element_templates=element_templates,
                flow_templates=flow_templates,
                dfd_level=dfd_level,
                satisfied_flow_conditions=satisfied_flow_conditions,
                source_digest=source_digest,
                warnings=_RecordSink(),
                unresolved=_RecordSink(),
            )
            nodes, edges, flow_candidates = _project_to_logical_system(
                nodes,
                edges,
                element_templates=element_templates,
                dfd_level=dfd_level,
            )
            if has_image_references:
                unresolved.add(
                    "IMAGE_RUNTIME_FLOW_NOT_PROVEN",
                    "이미지 참조는 Registry와 워크로드의 근거로 보관했지만, 실제 registry/mirror와 containerd 전송 경로는 Manifest만으로 확인할 수 없어 선을 만들지 않았습니다.",
                    details={"required_condition": "IMAGE_REFERENCE_AND_CONTAINERD"},
                )
        else:
            nodes, edges, flow_candidates, platform_template = _project_to_catalog(
                nodes,
                edges,
                element_templates=element_templates,
                flow_templates=flow_templates,
                dfd_level=dfd_level,
                satisfied_flow_conditions=satisfied_flow_conditions,
                source_digest=source_digest,
                warnings=warnings,
                unresolved=unresolved,
            )

    namespace_counts: dict[str, int] = {}
    declared_namespaces = {
        resource.name for resource in resources if resource.kind == "Namespace"
    }
    for resource in resources:
        if resource.namespace:
            namespace_counts[resource.namespace] = namespace_counts.get(resource.namespace, 0) + 1
    namespace_names = sorted(set(namespace_counts) | declared_namespaces)
    namespaces = [
        {
            "name": name,
            "resource_count": namespace_counts.get(name, 0),
            "system": name in _SYSTEM_NAMESPACES,
        }
        for name in namespace_names
    ]
    warning_records = warnings.result()
    unresolved_records = unresolved.result()
    workload_resources = [resource for resource in resources if resource.kind in _WORKLOAD_KINDS]
    workload_keys = {resource.key for resource in workload_resources}
    workload_count = sum(
        1 for resource in workload_resources if not any(owner in workload_keys for owner in _owner_keys(resource))
    )
    top_workload_resources = [
        resource
        for resource in workload_resources
        if not any(owner in workload_keys for owner in _owner_keys(resource))
    ]
    container_count = sum(
        len(_container_inventory(_pod_template(resource)[1]))
        for resource in top_workload_resources
    )
    summary = {
        "input_files": len(prepared),
        "documents": document_count,
        "resources": len(resources),
        "namespaces": len(namespaces),
        "workloads": workload_count,
        "containers": container_count,
        "services": sum(1 for resource in resources if resource.kind == "Service"),
        "public_exposure_candidates": public_exposure_candidate_count,
        "nodes": len(nodes),
        "edges": len(edges),
        "catalog_matched_flows": sum(
            1 for edge in edges if isinstance(_mapping(edge.get("properties")).get("catalog"), dict)
        ),
        "catalog_level": dfd_level if strict_catalog else None,
        "catalog_projection": bool(strict_catalog),
        "projection_mode": (
            "LOGICAL_SYSTEM" if strict_catalog and projection_mode == "logical"
            else "PLATFORM_ASSET_TYPES" if strict_catalog
            else "RAW"
        ),
        "projected_asset_types": (
            len({str(node.get("asset_type_id", "")) for node in nodes})
            if strict_catalog
            else None
        ),
        "confirmation_candidate_flows": len(flow_candidates),
        "warnings": len(warning_records),
        "unresolved": len(unresolved_records),
    }
    result = {
        "source_digest": source_digest,
        "mapper_version": MAPPER_VERSION,
        "namespaces": namespaces,
        "summary": summary,
        "nodes": nodes,
        "edges": edges,
        "boundaries": boundaries,
        "warnings": warning_records,
        "unresolved": unresolved_records,
    }
    if strict_catalog:
        result["flow_candidates"] = flow_candidates
        result["platform_template"] = platform_template
        result["apply_strategy"] = {
            "mode": "REPLACE_GENERATED_LAYER",
            "layer_id": (
                LOGICAL_GENERATED_LAYER_ID
                if projection_mode == "logical"
                else PLATFORM_GENERATED_LAYER_ID
            ),
            "preserve_manual": True,
            "candidate_field": "flow_candidates",
        }
    result_bytes = len(
        json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    if result_bytes > MAX_PROPOSAL_BYTES:
        raise ValueError(
            f"생성된 DFD 초안이 {MAX_PROPOSAL_BYTES}바이트를 넘습니다. "
            "입력 범위 또는 namespace를 나눠 주세요."
        )
    return result


__all__ = ["build_manifest_proposal"]
