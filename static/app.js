const DFD_SELECTION = globalThis.CNTARA_DFD_SELECTION;
if (!DFD_SELECTION) throw new Error("DFD selection helpers failed to load.");
const RISK_CALCULATION = globalThis.CNTARA_RISK_CALCULATION;
if (!RISK_CALCULATION) throw new Error("Risk calculation helpers failed to load.");

const THEME_STORAGE_KEY = "cntara-theme";
const THEME_OPTIONS = ["DARK", "LIGHT", "AUTO"];
const ASSESSMENT_TEXT_LIMITS = Object.freeze({
  name: { label: "평가 이름", max: 60 },
  evaluation_target: { label: "대상 시스템 또는 서비스명", max: 100 },
  scope_in: { label: "포함 범위", max: 800 },
  scope_out: { label: "제외 범위", max: 400 },
  technical_info: { label: "가정 및 참고사항", max: 1200 },
  actor_notes: { label: "위협 행위자 참고사항", max: 500 },
});
const DFD_NODE_TEXT_LIMITS = Object.freeze({
  name: { label: "표시 이름", max: 80 },
  description: { label: "설명", max: 500 },
});
const CUSTOM_ATTACK_VECTOR_TEXT_LIMITS = Object.freeze({
  name: { label: "공격 벡터 이름", max: 200 },
  description: { label: "공격 벡터 설명", max: 2000 },
  prerequisite: { label: "선행조건", max: 1000 },
  source: { label: "출처", max: 200 },
  referenceUrl: { label: "참조 링크", max: 2000 },
  reason: { label: "추가 이유", max: 1000 },
});
const systemDarkTheme = window.matchMedia("(prefers-color-scheme: dark)");

function isModalDismissButton(button) {
  return [...button.attributes].some((attribute) => attribute.name.startsWith("data-close"));
}

function standardizeModalDismissActions(root = document) {
  const backdrops = [];
  if (root?.matches?.(".modal-backdrop")) backdrops.push(root);
  root?.querySelectorAll?.(".modal-backdrop").forEach((backdrop) => backdrops.push(backdrop));

  backdrops.forEach((backdrop) => {
    const dismissButtons = [...backdrop.querySelectorAll("button")].filter(isModalDismissButton);
    if (!dismissButtons.length) return;

    dismissButtons.forEach((button) => {
      button.textContent = "닫기";
      button.setAttribute("aria-label", "닫기");
    });

    const footer = backdrop.querySelector(".modal-footer, .cart-modal-footer, .risk-drawer-footer");
    const keeper = dismissButtons[0];
    if (footer && !footer.contains(keeper)) {
      const primaryAction = footer.querySelector('button[type="submit"], .btn.primary, .btn.danger');
      keeper.classList.remove("small", "primary", "danger");
      keeper.classList.add("btn");
      footer.insertBefore(keeper, primaryAction || null);
    }
    dismissButtons.slice(1).forEach((button) => button.remove());
  });
}

function initializeModalDismissConventions() {
  standardizeModalDismissActions(document);
  const observer = new MutationObserver((records) => {
    records.forEach((record) => {
      record.addedNodes.forEach((node) => {
        if (node.nodeType === Node.ELEMENT_NODE) standardizeModalDismissActions(node);
      });
    });
  });
  observer.observe(document.body, { childList: true });
}

function savedThemeMode() {
  try {
    const value = String(localStorage.getItem(THEME_STORAGE_KEY) || "AUTO").toUpperCase();
    return THEME_OPTIONS.includes(value) ? value : "AUTO";
  } catch {
    return "AUTO";
  }
}

function resolvedThemeMode(mode) {
  const normalized = THEME_OPTIONS.includes(String(mode).toUpperCase()) ? String(mode).toUpperCase() : "AUTO";
  return normalized === "AUTO" ? (systemDarkTheme.matches ? "dark" : "light") : normalized.toLowerCase();
}

function themeModeIconSvg(mode) {
  const normalized = THEME_OPTIONS.includes(String(mode).toUpperCase()) ? String(mode).toUpperCase() : "AUTO";
  if (normalized === "LIGHT") {
    return `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3.75"></circle><path d="M12 2.25v2.1M12 19.65v2.1M2.25 12h2.1M19.65 12h2.1M5.1 5.1l1.48 1.48M17.42 17.42l1.48 1.48M18.9 5.1l-1.48 1.48M6.58 17.42 5.1 18.9"></path></svg>`;
  }
  if (normalized === "DARK") {
    return `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.15 15.25A8.35 8.35 0 0 1 8.75 3.85 8.36 8.36 0 1 0 20.15 15.25Z"></path><path class="theme-icon-spark" d="m17.55 4.2.38.9.9.38-.9.38-.38.9-.38-.9-.9-.38.9-.38.38-.9Z"></path></svg>`;
  }
  return `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3.75" width="18" height="13.5" rx="1.75"></rect><path d="M8.25 20.25h7.5M12 17.25v3"></path></svg>`;
}

function syncThemeControls(normalized, resolved) {
  const modeLabel = normalized[0] + normalized.slice(1).toLowerCase();
  const resolvedLabel = resolved === "dark" ? "Dark" : "Light";
  $$('[data-theme-current]').forEach((label) => { label.textContent = modeLabel; });
  $$('[data-theme-current-icon]').forEach((icon) => { icon.innerHTML = themeModeIconSvg(normalized); });
  $$('.theme-switcher .runtime-menu').forEach((trigger) => {
    trigger.title = normalized === "AUTO"
      ? `Auto: 시스템 설정에 따라 ${resolvedLabel} 적용 중`
      : `${modeLabel} 모드 적용 중`;
  });
  $$('[data-theme-option]').forEach((button) => {
    const selected = button.dataset.themeOption === normalized;
    button.classList.toggle("selected", selected);
    button.setAttribute("aria-checked", selected ? "true" : "false");
  });
}

function applyThemeMode(mode, persist = true) {
  const normalized = THEME_OPTIONS.includes(String(mode).toUpperCase()) ? String(mode).toUpperCase() : "AUTO";
  const resolved = resolvedThemeMode(normalized);
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themeMode = normalized.toLowerCase();
  document.documentElement.style.colorScheme = resolved;
  if (persist) {
    try { localStorage.setItem(THEME_STORAGE_KEY, normalized); } catch { /* 브라우저 저장소가 막혀도 현재 테마는 적용한다. */ }
  }
  syncThemeControls(normalized, resolved);
}

function initializeTheme() {
  applyThemeMode(savedThemeMode(), false);
  systemDarkTheme.addEventListener?.("change", () => {
    if (savedThemeMode() === "AUTO") applyThemeMode("AUTO", false);
  });
  window.addEventListener("pageshow", () => applyThemeMode(savedThemeMode(), false));
  window.addEventListener("storage", (event) => {
    if (event.key === THEME_STORAGE_KEY) applyThemeMode(savedThemeMode(), false);
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) applyThemeMode(savedThemeMode(), false);
  });
}

const state = {
  bootstrap: null,
  assessments: [],
  assessmentId: null,
  workspace: null,
  step: 1,
  activeTargetId: null,
  activeCartId: null,
  activeReviewItemId: null,
  activeRiskItemId: null,
  activeCrraMappingId: null,
  selected: null,
  selectedNodeIds: [],
  connectionMode: false,
  connectionSource: null,
  dfdZoom: 1,
  dfdCatalogLevel: 0,
  dfdShowReferenceFlows: false,
  dfdView: "MODEL",
  dfdFocusMode: false,
  dfdPanMode: false,
  dfdViewportX: 0,
  dfdViewportY: 0,
  dfdPendingFlow: null,
  sideNavCollapsed: false,
  scopeBriefExpanded: false,
  reviewContextExpanded: false,
  dfdScrollLeft: 0,
  dfdScrollTop: 0,
  catalogResults: [],
  attackVectorCatalog: [],
  catalogLoading: false,
  catalogLoadedAssessmentId: null,
  catalogSearchRequestId: 0,
  catalogSearchTimer: null,
  cartFilters: {},
  cartSelections: {},
  cartCatalogQuery: "",
  reviewDrafts: {},
  riskDrafts: {},
  riskDraftModelId: null,
  riskModelChoosing: false,
  riskModelSelectionId: null,
  riskModelWeightDrafts: {},
  activeRiskDrawerItemId: null,
  llm: { enabled: false },
  dfdDirty: false,
  dfdSemanticDirty: false,
  dfdLayoutDirty: false,
  attackCaseDrafts: [],
  attackCasesDirty: false,
  activeAttackCaseDraftId: null,
  attackCaseRoleMode: "entry",
  attackCaseSourceAssessmentId: null,
  manifestReviewSummary: null,
  phase: "ctsa",
  crraStep: 1,
  crra: null,
  crraUiDirty: false,
  crraLlmSuggestions: {},
  crraMappingDrafts: {},
  crraMappingDraftAssessmentId: null,
  crraMappingBatchLoading: false,
  crraMappingBatchSaving: false,
  crraMappingBatchError: "",
  crraMappingFilter: "ALL",
  dfdHistory: [],
  dfdRedoHistory: [],
  dfdClipboard: null,
  crraMappingQuery: "",
  kmMode: false,
  km: null,
  kmTab: "catalog",
  kmSearch: "",
  sessionExpired: false,
  assessmentSearch: "",
  candidatePage: 1,
};

let dfdGridResizeObserver = null;
let dfdGridResizeFrame = null;
let themeOutsideListenerBound = false;
let attackCasePickerDismissBound = false;
let dfdFocusEscapeBound = false;
let dfdPanKeyboardBound = false;
let dfdSpacePanHeld = false;

function disconnectDfdGridResizeObserver() {
  dfdGridResizeObserver?.disconnect();
  dfdGridResizeObserver = null;
  if (dfdGridResizeFrame !== null && typeof cancelAnimationFrame === "function") {
    cancelAnimationFrame(dfdGridResizeFrame);
  }
  dfdGridResizeFrame = null;
}

function scheduleDfdCanvasViewportSync(scrollArea) {
  if (dfdGridResizeFrame !== null || typeof requestAnimationFrame !== "function") return;
  dfdGridResizeFrame = requestAnimationFrame(() => {
    dfdGridResizeFrame = null;
    if (scrollArea?.isConnected) syncDfdCanvasViewport(scrollArea);
  });
}

const STEPS = [
  [1, "사이버 위협 모델 수립"],
  [2, "후보 공격 벡터 식별"],
  [3, "쇼핑 카트 구성"],
  [4, "공격 벡터 타당성 검토"],
  [5, "공격 벡터 위험 평가"],
  [6, "위협 민감도 매트릭스"],
];

const CRRA_STEPS = [
  [1, "대응할 공격 벡터 선정"],
  [2, "대응책 불러오기"],
  [3, "대응책 후보 검토"],
  [4, "대응책 비용 및 효과 평가"],
  [5, "최종 대응책 조합 선정"],
];

const EFFECT_OPTIONS = [
  ["PREVENT", "P 예방"],
  ["DETECT", "D 탐지"],
  ["RESPOND", "R 대응"],
];

const CONFIDENCE_OPTIONS = [
  ["HIGH", "H 높음"],
  ["MODERATE", "M 중간"],
  ["LOW", "L 낮음"],
];

const REORDER_STRATEGIES = [
  ["BANG_FOR_BUCK", "비용 대비 효용 우선"],
  ["MAX_UTILITY", "효용이 큰 대응책 우선"],
  ["LEAST_COST", "비용이 낮은 대응책 우선"],
];

const LLM_PROVIDERS = {
  groq: {
    label: "Groq",
    mark: "G",
    description: "빠른 추론을 위한 OpenAI 호환 API",
    keyPlaceholder: "gsk_...",
    modelPlaceholder: "openai/gpt-oss-20b",
    defaultModel: "openai/gpt-oss-20b",
  },
  gemini: {
    label: "Google Gemini",
    mark: "G",
    description: "Google AI에서 제공하는 Gemini API",
    keyPlaceholder: "AIza...",
    modelPlaceholder: "예: gemini-2.5-flash",
    defaultModel: "gemini-2.5-flash",
    notice: {
      title: "Gemini 무료 티어 사용 전 확인",
      body: "무료 티어의 데이터 처리 조건은 유료 서비스와 다를 수 있습니다. 실제 기밀 시스템 구조, 취약점, 자격 증명 등 민감한 보안 자료는 전송하지 말고, 사용 전에 Google AI의 현재 데이터 사용 및 유료 정책을 별도로 확인하세요.",
    },
  },
  openai: {
    label: "OpenAI GPT",
    mark: "O",
    description: "OpenAI API에서 제공하는 GPT 모델",
    keyPlaceholder: "sk-...",
    modelPlaceholder: "예: gpt-5-mini",
  },
  anthropic: {
    label: "Anthropic Claude",
    mark: "A",
    description: "Anthropic API에서 제공하는 Claude 모델",
    keyPlaceholder: "sk-ant-...",
    modelPlaceholder: "예: claude-sonnet 계열 모델 ID",
  },
};

const SCOPE_OPTION_FALLBACKS = {
  lifecycle_phases: [["DESIGN", "설계"], ["DEVELOPMENT", "개발"], ["DEPLOYMENT", "배포"], ["OPERATION", "운영"], ["RETIREMENT", "폐기"], ["OTHER", "기타"]],
  threat_ranges: [["EXTERNAL_NETWORK", "외부 네트워크"], ["APPLICATION_API", "애플리케이션 및 API"], ["IDENTITY_CREDENTIAL", "ID 및 자격 증명"], ["KUBERNETES_CONTROL_PLANE", "Kubernetes 제어 영역"], ["CONTAINER_WORKLOAD", "컨테이너 워크로드"], ["SOFTWARE_SUPPLY_CHAIN", "소프트웨어 공급망"], ["DATA_COMPROMISE", "데이터 침해"], ["AVAILABILITY_DISRUPTION", "가용성 저해"], ["INSIDER", "내부자"], ["OTHER", "기타"]],
  actor_types: [["EXTERNAL", "외부 공격자"], ["INSIDER", "내부자"], ["SUPPLY_CHAIN", "공급망 공격자"], ["THIRD_PARTY_OPERATOR", "제3자 운영자"], ["UNKNOWN", "아직 모름"], ["OTHER", "기타"]],
  capability_tags: [["NETWORK", "네트워크"], ["WEB_API", "웹 및 API"], ["CREDENTIAL", "자격 증명"], ["CLOUD_IAM", "Cloud IAM"], ["KUBERNETES", "Kubernetes"], ["CONTAINER_RUNTIME", "컨테이너 런타임"], ["SOFTWARE_SUPPLY_CHAIN", "소프트웨어 공급망"], ["SOCIAL_ENGINEERING", "사회공학"], ["PHYSICAL", "물리적 접근"], ["OTHER", "기타"]],
  attack_objectives: [["EXFILTRATE", "정보 또는 데이터 반출"], ["DEGRADE", "성능 또는 기능 저하"], ["DISRUPT", "운영 방해"], ["DENY", "서비스 이용 차단"], ["DESTROY", "데이터 또는 시스템 파괴"], ["DECEIVE", "정보 또는 상태 기만"], ["OTHER", "기타"]],
  knowledge_states: [["KNOWN", "알려짐"], ["UNKNOWN", "아직 모름"], ["NOT_AVAILABLE", "자료 없음"]],
  modeling_methods: [["MANUAL_DFD", "DFD 직접 작성"]],
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function compact(value, fallback = "-") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function textList(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string" && item.trim()) : [];
}

function scopeOptions(group) {
  const configured = state.bootstrap?.scope_brief_options?.[group];
  if (Array.isArray(configured) && configured.length) return configured;
  return (SCOPE_OPTION_FALLBACKS[group] || []).map(([code, label]) => ({ code, label }));
}

function scopeOptionLabel(group, code, fallback = "-") {
  return scopeOptions(group).find((item) => item.code === code)?.label || fallback;
}

function scopeCodeLabels(group, codes, fallback = "-") {
  const labels = textList(codes).map((code) => scopeOptionLabel(group, code, code));
  return labels.length ? labels.join(", ") : fallback;
}

function legacyCodes(group, value) {
  const text = String(value ?? "");
  return scopeOptions(group).filter((item) => text.includes(item.label)).map((item) => item.code);
}

function assessmentScopeProfile(assessment = state.workspace?.assessment || {}) {
  const stored = assessment.scope_profile;
  if (stored && Number(stored.schema_version) === 1) {
    const actor = stored.actor && typeof stored.actor === "object" ? stored.actor : {};
    return {
      structured: true,
      lifecycle_phase_code: String(stored.lifecycle_phase_code || "OPERATION"),
      threat_range_codes: textList(stored.threat_range_codes),
      actor: {
        actor_type_code: String(actor.actor_type_code || ""),
        intent_knowledge_state: String(actor.intent_knowledge_state || ""),
        objective_codes: textList(actor.objective_codes),
        capability_knowledge_state: String(actor.capability_knowledge_state || ""),
        capability_codes: textList(actor.capability_codes),
        notes: String(actor.notes || ""),
      },
    };
  }
  const lifecycle = scopeOptions("lifecycle_phases").find((item) => item.label === assessment.lifecycle_phase)?.code || "OPERATION";
  const objectives = legacyCodes("attack_objectives", assessment.actor_intent);
  const intentText = String(assessment.actor_intent || "");
  const intentState = objectives.length ? "KNOWN" : intentText.includes("자료 없음") ? "NOT_AVAILABLE" : intentText.includes("아직 모름") ? "UNKNOWN" : "";
  const capabilities = legacyCodes("capability_tags", assessment.actor_capabilities);
  return {
    structured: false,
    lifecycle_phase_code: lifecycle,
    threat_range_codes: legacyCodes("threat_ranges", assessment.threat_range),
    actor: {
      actor_type_code: legacyCodes("actor_types", assessment.actor_type)[0] || "",
      intent_knowledge_state: intentState,
      objective_codes: objectives,
      capability_knowledge_state: capabilities.length ? "KNOWN" : "UNKNOWN",
      capability_codes: capabilities,
      notes: String(assessment.actor_motivation || ""),
    },
  };
}

function scopeBriefDisplay(assessment = state.workspace?.assessment || {}) {
  const profile = assessmentScopeProfile(assessment);
  if (!profile.structured) {
    return {
      lifecycle: compact(assessment.lifecycle_phase),
      threatRanges: compact(assessment.threat_range, "설정 필요"),
      actorType: compact(assessment.actor_type, "설정 필요"),
      objectives: compact(assessment.actor_intent, "설정 필요"),
      capabilities: compact(assessment.actor_capabilities, "아직 모름"),
      actorNotes: compact(assessment.actor_motivation),
    };
  }
  const actor = profile.actor;
  return {
    lifecycle: scopeOptionLabel("lifecycle_phases", profile.lifecycle_phase_code),
    threatRanges: scopeCodeLabels("threat_ranges", profile.threat_range_codes, "설정 필요"),
    actorType: scopeOptionLabel("actor_types", actor.actor_type_code, "설정 필요"),
    objectives: actor.intent_knowledge_state === "KNOWN"
      ? scopeCodeLabels("attack_objectives", actor.objective_codes, "설정 필요")
      : scopeOptionLabel("knowledge_states", actor.intent_knowledge_state, "설정 필요"),
    capabilities: actor.capability_knowledge_state === "KNOWN"
      ? scopeCodeLabels("capability_tags", actor.capability_codes, "아직 모름")
      : scopeOptionLabel("knowledge_states", actor.capability_knowledge_state, "아직 모름"),
    actorNotes: compact(actor.notes),
  };
}

function llmEnabledForAssessment() {
  return Boolean(state.llm.enabled && state.workspace?.assessment?.external_llm_allowed);
}

function llmProviderLabel(config = state.llm) {
  const provider = String(config?.provider || "").toLowerCase();
  if (LLM_PROVIDERS[provider]) return LLM_PROVIDERS[provider].label;
  if (provider) return provider;
  return "외부 LLM";
}

function llmProviderId(config = state.llm) {
  if (!config?.enabled) return "groq";
  const provider = String(config?.provider || "").toLowerCase();
  if (LLM_PROVIDERS[provider]) return provider;
  return "groq";
}

function formatDuration(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) return "일정 시간";
  if (value % 3600 === 0) return `${value / 3600}시간`;
  if (value >= 3600) return `${Math.floor(value / 3600)}시간 ${Math.ceil((value % 3600) / 60)}분`;
  if (value % 60 === 0) return `${value / 60}분`;
  return `${Math.ceil(value / 60)}분`;
}

function llmMemoryNotice(config = state.llm) {
  const idleTimeout = formatDuration(config?.idle_timeout_seconds);
  return `API 키는 현재 브라우저 세션용으로 서버 메모리에만 보관됩니다. 다른 사용자와 공유되지 않으며, ${idleTimeout} 동안 사용하지 않거나 서버가 재시작되면 자동 폐기됩니다.`;
}

function renderSessionExpired(result = {}) {
  disconnectDfdGridResizeObserver();
  if (state.sessionExpired) return;
  state.sessionExpired = true;
  state.llm = { enabled: false };
  $$(".modal-backdrop").forEach((modal) => modal.remove());
  const message = result?.error || "오랫동안 사용하지 않아 현재 브라우저 세션이 만료되었습니다.";
  $("#app").innerHTML = `<div class="boot-screen session-expired-screen">
    <div class="brand-mark">↻</div>
    <h1>브라우저 세션이 만료되었습니다</h1>
    <p>${escapeHtml(message)}<br>이 세션의 API 키 연결은 종료되었습니다. 새 개인 세션에서 API 키를 다시 연결해 주세요.</p>
    <button class="btn primary" id="restart-session">새 개인 세션 시작</button>
  </div>`;
  $("#restart-session").onclick = () => window.location.replace("/");
}

function llmSuggestionSource(suggestion) {
  const meta = suggestion?._llm;
  if (!meta?.provider && !meta?.model) return '<div class="small-text muted">이전 LLM 설정에서 생성된 추천</div>';
  const provider = llmProviderLabel({ provider: meta.provider });
  const generated = meta.generated_at ? `, ${new Date(meta.generated_at).toLocaleString("ko-KR")}` : "";
  return `<div class="small-text muted">${escapeHtml(provider)} ${escapeHtml(meta.model || "모델 미상")}${escapeHtml(generated)}</div>`;
}

function randomId(prefix) {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}

function toast(message, error = false) {
  if (state.sessionExpired) return;
  const el = $("#toast");
  el.textContent = message;
  el.className = `toast show${error ? " error" : ""}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.className = "toast"; }, 3200);
}

async function api(path, options = {}) {
  const request = {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers: { ...(options.headers || {}) },
  };
  if (options.body && typeof options.body !== "string") {
    request.body = JSON.stringify(options.body);
    request.headers["Content-Type"] = "application/json";
  }
  const response = await fetch(path, request);
  let result = null;
  try { result = await response.json(); } catch { result = null; }
  if (response.status === 401) {
    renderSessionExpired(result);
    throw new Error(result?.error || "브라우저 세션이 만료되었습니다.");
  }
  if (response.status === 409 && ["LLM_SESSION_EXPIRED", "LLM_NOT_CONFIGURED"].includes(result?.code)) {
    state.llm = {
      ...state.llm,
      enabled: false,
      verified: false,
      expired: result.code === "LLM_SESSION_EXPIRED",
    };
    try {
      const statusResponse = await fetch("/api/llm/status", { credentials: "same-origin", cache: "no-store" });
      if (statusResponse.ok) state.llm = await statusResponse.json();
    } catch {
      // 상태 조회가 실패해도 API 키 재연결 화면은 계속 제공한다.
    }
    showLlmConfigModal();
    throw new Error(result?.error || "AI 추천 연결이 종료되었습니다. 본인의 API 키를 다시 연결해 주세요.");
  }
  if (!response.ok) throw new Error(result?.error || `요청에 실패했습니다. (${response.status})`);
  return result;
}

async function initialize() {
  try {
    [state.bootstrap, state.assessments, state.llm] = await Promise.all([
      api("/api/bootstrap"), api("/api/assessments"), api("/api/llm/status"),
    ]);
    const params = new URLSearchParams(window.location.search);
    if (params.get("readme") === "1") {
      renderReadmePage();
      return;
    }
    const requestedAssessment = Number(params.get("assessment"));
    if (requestedAssessment && state.assessments.some((assessment) => assessment.id === requestedAssessment)) {
      await openAssessment(requestedAssessment);
      const requestedStep = Number(params.get("step"));
      if (requestedStep >= 1 && requestedStep <= 6 && canAccess(requestedStep)) {
        state.step = requestedStep;
        renderWorkspace();
      }
    } else {
      renderDashboard();
    }
  } catch (error) {
    if (state.sessionExpired) return;
    $("#app").innerHTML = `<div class="boot-screen"><div class="brand-mark">!</div><strong>${escapeHtml(error.message)}</strong><button class="btn" id="retry-initialize">다시 시도</button></div>`;
    $("#retry-initialize").onclick = () => location.reload();
  }
}

function statusLabel(assessment) {
  if (assessment.legacy_case_review_required) return ["Attack Case 재확인 필요", "orange"];
  if (assessment.crra_confirmed || String(assessment.crra_status || "").toUpperCase() === "CONFIRMED") return ["TARA 분석 완료", "green"];
  const crraStep = Number(assessment.crra_current_step || 0);
  if (crraStep > 0) return [`CRRA ${Math.min(5, crraStep)}/5`, "orange"];
  if (assessment.matrix_confirmed) return ["CTSA 완료, CRRA 시작 전", "green"];
  if (assessment.current_step >= 6) return ["민감도 매트릭스", "blue"];
  if (assessment.current_step >= 5) return ["위험 평가", "orange"];
  if (assessment.threat_model_confirmed) return [`CTSA ${assessment.current_step}/6`, "blue"];
  return ["DFD 작성 중", ""];
}

function homeBrandMarkup(mark = "CN", title = "CloudTARA", subtitle = "Cloud-Native TARA", heading = false) {
  const semanticTitle = heading ? '<h1 class="visually-hidden">CloudTARA</h1>' : '<strong class="visually-hidden">CloudTARA</strong>';
  return `<a href="/" class="brand brand-home" data-home-link aria-label="CloudTARA 평가 목록으로 이동"><img class="brand-logo" src="/static/cloudtara-icon.png?v=1" alt="CloudTARA">${semanticTitle}</a>`;
}

function themeSwitcherMarkup(id) {
  const current = savedThemeMode();
  const label = current[0] + current.slice(1).toLowerCase();
  const resolved = resolvedThemeMode(current);
  const resolvedLabel = resolved === "dark" ? "Dark" : "Light";
  const title = current === "AUTO" ? `Auto: 시스템 설정에 따라 ${resolvedLabel} 적용 중` : `${label} 모드 적용 중`;
  return `<div class="theme-switcher" id="${id}"><button class="runtime-menu" type="button" aria-haspopup="menu" aria-expanded="false" aria-controls="${id}-menu" title="${title}"><span class="theme-mode-icon" data-theme-current-icon>${themeModeIconSvg(current)}</span><strong data-theme-current>${label}</strong><span class="runtime-chevron" aria-hidden="true"></span></button><div class="theme-menu" id="${id}-menu" role="menu" hidden>${THEME_OPTIONS.map((option) => `<button type="button" role="menuitemradio" aria-checked="${option === current ? "true" : "false"}" class="${option === current ? "selected" : ""}" data-theme-option="${option}"><span class="theme-mode-icon" aria-hidden="true">${themeModeIconSvg(option)}</span><span>${option[0] + option.slice(1).toLowerCase()}</span></button>`).join("")}</div></div>`;
}

function bindThemeSwitcher(id) {
  const root = $(`#${id}`);
  if (!root) return;
  const trigger = $(".runtime-menu", root);
  const menu = $(".theme-menu", root);
  const close = () => { menu.hidden = true; trigger.setAttribute("aria-expanded", "false"); };
  trigger.onclick = () => {
    const opening = menu.hidden;
    menu.hidden = !opening;
    trigger.setAttribute("aria-expanded", opening ? "true" : "false");
    if (opening) $("[data-theme-option].selected", menu)?.focus();
  };
  $$('[data-theme-option]', menu).forEach((button) => button.onclick = () => {
    applyThemeMode(button.dataset.themeOption);
    close();
    trigger.focus();
  });
  root.onkeydown = (event) => { if (event.key === "Escape") { close(); trigger.focus(); } };
  root.onfocusout = (event) => { if (!root.contains(event.relatedTarget)) close(); };
  if (!themeOutsideListenerBound) {
    document.addEventListener("pointerdown", (event) => {
      $$(".theme-switcher").forEach((switcher) => {
        if (switcher.contains(event.target)) return;
        const otherMenu = $(".theme-menu", switcher);
        const otherTrigger = $(".runtime-menu", switcher);
        if (otherMenu) otherMenu.hidden = true;
        otherTrigger?.setAttribute("aria-expanded", "false");
      });
    });
    themeOutsideListenerBound = true;
  }
}

function renderReadmePage() {
  disconnectDfdGridResizeObserver();
  const ctsaSteps = [
    ["1.1", "사이버 위협 모델 수립", "분석 범위를 정리하고 DFD를 작성합니다. Attack Case마다 Entry Point, Intended Target, 의도한 효과와 선정 근거를 기록합니다."],
    ["1.2", "후보 공격 벡터 식별", "Attack Case의 방향성 경로에 포함된 DFD 구성요소와 KM 매핑을 대조해 후보 공격 벡터를 찾습니다."],
    ["1.3", "쇼핑 카트 구성", "Attack Case별 후보 목록을 검토합니다. 잘못 포함된 항목은 빼고 누락된 항목은 KM 또는 평가 전용 항목으로 추가합니다."],
    ["1.4", "공격 벡터 타당성 검토", "각 후보가 현재 평가 맥락에서 성립하는지 판정합니다. 판단 근거는 필요한 경우 기록할 수 있습니다."],
    ["1.5", "공격 벡터 위험 평가", "선택한 계산기의 척도로 타당한 공격 벡터의 요인값을 정합니다. 점수는 저장된 계산식과 가중치로 계산합니다."],
    ["1.6", "위협 민감도 매트릭스", "공격 벡터별 위험 점수와 쇼핑 카트 포함 관계를 표로 확인하고 CTSA 결과를 확정합니다."],
  ];
  const crraSteps = [
    ["2.1", "대응할 공격 벡터 선택", "확정된 CTSA 결과에서 대응책 분석에 포함할 공격 벡터를 고릅니다."],
    ["2.2", "KM 대응책 불러오기", "선택한 공격 벡터에 연결된 대응책과 연결 근거를 KM에서 불러옵니다."],
    ["2.3", "대응책 후보 검토", "공격 벡터와 대응책의 연결을 포함 또는 제외로 판정하고 예방, 탐지, 대응 효과와 신뢰도를 확인합니다."],
    ["2.4", "대응책 비용 및 효과 평가", "포함한 대응책의 비용 점수와 효과 범위를 저장하고 정해진 계산 규칙으로 우선순위를 구합니다."],
    ["2.5", "최종 대응책 조합 선정", "선택 기준에 따라 대응책 조합을 만들고 각 공격 벡터의 기준 충족 여부를 확인한 뒤 결과를 확정합니다."],
  ];
  const stepMarkup = (steps) => steps.map(([number, title, body]) => `<article class="readme-step"><span>${number}</span><div><h3>${title}</h3><p>${body}</p></div></article>`).join("");
  $("#app").innerHTML = `<div class="readme-page">
    <header class="dashboard-hero">${homeBrandMarkup("CN", "CloudTARA", "Cloud-Native MITRE TARA", true)}<div class="dashboard-header-actions"><button class="btn ghost-dark small" id="readme-home">평가 목록</button><span class="dashboard-action-divider" aria-hidden="true"></span>${themeSwitcherMarkup("readme-theme")}</div></header>
    <main class="readme-main">
      <header class="readme-intro"><span>README</span><h2>CloudTARA 안내</h2><p>CloudTARA는 MITRE TARA 절차에 따라 클라우드 네이티브 시스템의 공격 벡터와 대응책을 검토하고 결과를 저장하는 도구입니다.</p></header>
      <section class="readme-section"><h2>MITRE TARA</h2><p>TARA는 평가 대상에 적용될 수 있는 공격 벡터를 식별하고, 타당성과 위험을 검토한 뒤 대응책을 분석하는 방법론입니다. 절차는 공격 벡터를 다루는 CTSA와 대응책을 다루는 CRRA로 나뉩니다.</p><p>CloudTARA는 공격 벡터 후보 자료로 MITRE ATT&amp;CK 기법을 사용합니다. ATT&amp;CK 사용은 이 도구의 구현 방식이며 TARA 방법론 자체가 특정 공격 기법 목록을 요구하는 것은 아닙니다.</p></section>
      <section class="readme-section"><div class="readme-section-title"><div><span>CTSA</span><h2>Cyber Threat Susceptibility Analysis</h2></div><p>공격 벡터를 식별하고 타당성과 위험을 평가합니다.</p></div><div class="readme-steps">${stepMarkup(ctsaSteps)}</div></section>
      <section class="readme-section"><div class="readme-section-title"><div><span>CRRA</span><h2>Cyber Risk Remediation Analysis</h2></div><p>대응책 후보를 검토하고 적용할 조합을 정합니다.</p></div><div class="readme-steps">${stepMarkup(crraSteps)}</div></section>
      <section class="readme-section"><h2>도구와 사용자의 역할</h2><div class="readme-role-grid"><article><h3>CloudTARA</h3><p>DFD 경로와 KM 매핑을 이용해 후보를 조회하고, 계산 규칙을 적용하며, 입력과 검토 이력을 SQLite DB에 저장합니다.</p></article><article><h3>사용자</h3><p>평가 범위와 DFD를 확인하고 Attack Case를 정의합니다. 후보, 판정 근거, 위험 요인값과 대응책 조합을 검토하고 최종 결과를 확정합니다.</p></article><article><h3>LLM</h3><p>설정한 경우에만 타당성, 위험 요인값, 대응책 연결 판정의 초안을 만듭니다. 계산식과 최종 판정은 바꾸지 않으며 사용자가 저장하기 전에는 결과로 확정되지 않습니다.</p></article></div></section>
      <section class="readme-section"><h2>주요 용어</h2><dl class="readme-terms"><div><dt>Entry Point</dt><dd>공격자가 공격 경로를 시작하는 지점입니다. 앞선 단계에서 침해된 구성요소가 다음 단계의 Entry Point가 될 수도 있습니다.</dd></div><div><dt>Intended Target</dt><dd>공격자가 의도한 효과를 일으키려는 대상입니다.</dd></div><div><dt>Attack Case</dt><dd>Entry Point, Intended Target, 의도한 효과와 근거를 묶은 평가 단위입니다.</dd></div><div><dt>Attack Vector</dt><dd>Entry Point에서 Intended Target에 영향을 주기 위해 사용할 수 있는 공격 방법입니다.</dd></div><div><dt>Shopping Cart</dt><dd>한 Attack Case에서 검토할 후보 공격 벡터의 목록입니다.</dd></div><div><dt>KM</dt><dd>DFD 자산 유형과 공격 벡터, 공격 벡터와 대응책의 연결 정보를 관리하는 지식 카탈로그입니다.</dd></div></dl></section>
      <footer class="readme-source"><strong>기준 문서</strong><span>MITRE, Threat Assessment and Remediation Analysis (TARA) Training Workshop, PR-20-0272, 2020.</span></footer>
    </main>
  </div>`;
  bindHomeNavigation();
  $("#readme-home").onclick = () => goHome();
  bindThemeSwitcher("readme-theme");
  history.replaceState(null, "", "/?readme=1");
  window.scrollTo(0, 0);
}

function confirmHomeNavigation() {
  if (state.crraMappingBatchLoading || state.crraMappingBatchSaving) {
    toast("CRRA 일괄 작업이 끝난 뒤 이동해 주세요.", true);
    return false;
  }
  const unsaved = [];
  if (state.dfdDirty) unsaved.push("DFD 변경사항");
  if (state.attackCasesDirty) unsaved.push("Attack Case 변경사항");
  if (state.workspace && state.phase === "ctsa" && state.step === 4 && reviewDraftIsDirty()) unsaved.push("공격 벡터 판정 입력");
  if (state.workspace && state.phase === "ctsa" && state.step === 5 && riskDraftIsDirty()) unsaved.push("위험 평가 입력");
  if (state.workspace && state.phase === "crra" && state.crraUiDirty) unsaved.push("CRRA 입력");
  if (!unsaved.length) return true;
  return window.confirm(`아직 저장하지 않은 내용이 있습니다.\n\n${unsaved.map((item) => `• ${item}`).join("\n")}\n\n저장하지 않고 평가 목록으로 이동할까요?`);
}

async function goHome() {
  if (!confirmHomeNavigation()) return false;
  try {
    const assessments = await api("/api/assessments");
    state.assessments = assessments;
    state.assessmentId = null;
    state.workspace = null;
    state.activeTargetId = null;
    state.activeCartId = null;
    state.activeReviewItemId = null;
    state.activeRiskItemId = null;
    state.activeCrraMappingId = null;
    state.phase = "ctsa";
    state.step = 1;
    state.crraStep = 1;
    state.crra = null;
    state.crraUiDirty = false;
    state.crraLlmSuggestions = {};
    resetCrraMappingDrafts();
    state.kmMode = false;
    state.dfdDirty = false;
    state.dfdSemanticDirty = false;
    state.dfdLayoutDirty = false;
    state.attackCaseDrafts = [];
    state.attackCasesDirty = false;
    state.activeAttackCaseDraftId = null;
    state.attackCaseSourceAssessmentId = null;
    state.dfdFocusMode = false;
    state.dfdPanMode = false;
    state.dfdViewportX = 0;
    state.dfdViewportY = 0;
    state.dfdPendingFlow = null;
    state.dfdView = "MODEL";
    state.sideNavCollapsed = false;
    state.connectionMode = false;
    state.connectionSource = null;
    state.catalogResults = [];
    state.attackVectorCatalog = [];
    state.catalogLoading = false;
    state.catalogLoadedAssessmentId = null;
    state.candidatePage = 1;
    state.reviewDrafts = {};
    state.riskDrafts = {};
    state.riskDraftModelId = null;
    state.riskModelChoosing = false;
    state.riskModelSelectionId = null;
    state.riskModelWeightDrafts = {};
    state.activeRiskDrawerItemId = null;
    clearDfdSelection();
    history.replaceState(null, "", "/");
    renderDashboard();
    return true;
  } catch (error) {
    toast(error.message, true);
    return false;
  }
}

function bindHomeNavigation() {
  $$('[data-home-link]').forEach((link) => {
    link.onclick = (event) => {
      if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || event.button !== 0) return;
      event.preventDefault();
      goHome();
    };
  });
}

function renderDashboard() {
  disconnectDfdGridResizeObserver();
  const kmAdminButton = `<button class="btn ghost-dark small" id="km-admin">KM 관리</button>`;
  const legacyClaimButton = state.bootstrap?.legacy_claim_available === true
    ? '<button class="btn small" id="claim-legacy-assessments">기존 평가 가져오기</button>'
    : "";
  const cards = state.assessments.map((assessment) => {
    const [label, color] = statusLabel(assessment);
    const scope = scopeBriefDisplay(assessment);
    return `<article class="card assessment-card" data-assessment-card="${assessment.id}">
      <div class="assessment-card-top">
        <span class="badge ${color}">${label}</span>
        <details class="assessment-card-menu" data-assessment-menu>
          <summary aria-label="${escapeHtml(assessment.name)} 평가 메뉴" title="평가 메뉴">•••</summary>
          <div class="assessment-card-menu-popover">
            <button type="button" data-manage-assessment="${assessment.id}">이름 변경 및 복제</button>
            <div class="assessment-card-menu-separator" aria-hidden="true"></div>
            <button type="button" class="danger" data-delete-assessment="${assessment.id}">평가 삭제</button>
          </div>
        </details>
      </div>
      <h3>${escapeHtml(assessment.name)}</h3>
      <p>${escapeHtml(assessment.evaluation_target)}<br>${escapeHtml(scope.actorType)}, ${escapeHtml(scope.lifecycle)}</p>
      <div class="card-footer"><span class="small-text muted">평가 #${assessment.id}</span><button class="btn primary small" type="button" data-open-assessment="${assessment.id}">열기</button></div>
    </article>`;
  }).join("");
  $("#app").innerHTML = `<div class="dashboard">
    <header class="dashboard-hero app-global-header">
      ${homeBrandMarkup("CN", "CloudTARA", "Cloud-Native MITRE TARA", true)}
      <div class="dashboard-header-actions"><button class="header-link" id="readme-button">README</button>${kmAdminButton.replace('class="btn ghost-dark small"', 'class="header-link"')}<button class="header-link" id="llm-settings">내 API키 설정</button><span class="dashboard-action-divider" aria-hidden="true"></span>${themeSwitcherMarkup("dashboard-theme")}</div>
    </header>
    <main class="dashboard-main">
      <div class="welcome"><div><h2>평가 목록</h2></div><button class="btn primary dashboard-new-assessment" id="new-assessment">+ 새 평가</button></div>
      <div class="dashboard-session-row">${legacyClaimButton}</div>
      ${state.assessments.length ? `<div class="assessment-list-toolbar"><input id="assessment-search" type="search" aria-label="평가 검색" value="${escapeHtml(state.assessmentSearch)}" placeholder="평가 이름이나 대상 검색"><span id="assessment-search-count">${state.assessments.length}개</span></div>` : ""}
      <section class="assessment-grid">
        ${cards || '<div class="assessment-empty"><strong>평가가 없습니다.</strong><span>오른쪽 위의 새 평가 버튼을 눌러 시작하세요.</span></div>'}
        <div class="assessment-filter-empty" id="assessment-filter-empty" hidden>검색 조건에 맞는 평가가 없습니다.</div>
      </section>
    </main>
  </div>`;
  bindHomeNavigation();
  $("#new-assessment").onclick = showAssessmentModal;
  if ($("#empty-new-assessment")) $("#empty-new-assessment").onclick = showAssessmentModal;
  $("#llm-settings").onclick = showLlmConfigModal;
  bindThemeSwitcher("dashboard-theme");
  $("#readme-button").onclick = renderReadmePage;
  if ($("#km-admin")) $("#km-admin").onclick = openKmAdmin;
  if ($("#claim-legacy-assessments")) $("#claim-legacy-assessments").onclick = claimLegacyAssessments;
  $$('[data-open-assessment]').forEach((button) => button.onclick = () => openAssessment(Number(button.dataset.openAssessment)));
  const closeAssessmentMenus = (except = null) => {
    $$('[data-assessment-menu][open]').forEach((menu) => { if (menu !== except) menu.removeAttribute("open"); });
  };
  $$('[data-assessment-menu]').forEach((menu) => {
    menu.ontoggle = () => { if (menu.open) closeAssessmentMenus(menu); };
    menu.onkeydown = (event) => {
      if (event.key !== "Escape" || !menu.open) return;
      menu.removeAttribute("open");
      $("summary", menu)?.focus();
    };
  });
  $$('[data-manage-assessment]').forEach((button) => button.onclick = () => {
    const returnFocus = $("summary", button.closest("[data-assessment-menu]"));
    closeAssessmentMenus();
    showAssessmentManageModal(Number(button.dataset.manageAssessment), returnFocus);
  });
  $$('[data-delete-assessment]').forEach((button) => button.onclick = () => {
    const returnFocus = $("summary", button.closest("[data-assessment-menu]"));
    closeAssessmentMenus();
    showAssessmentDeleteModal(Number(button.dataset.deleteAssessment), returnFocus);
  });
  $(".dashboard").onclick = (event) => { if (!event.target.closest("[data-assessment-menu]")) closeAssessmentMenus(); };
  const search = $("#assessment-search");
  if (search) {
    search.oninput = () => { state.assessmentSearch = search.value; applyAssessmentSearch(); };
    applyAssessmentSearch();
  }
}

function applyAssessmentSearch() {
  const query = String(state.assessmentSearch || "").trim().toLocaleLowerCase("ko-KR");
  const cards = $$('[data-assessment-card]');
  let visible = 0;
  cards.forEach((card) => {
    const matches = !query || card.textContent.toLocaleLowerCase("ko-KR").includes(query);
    card.hidden = !matches;
    if (matches) visible += 1;
  });
  const count = $("#assessment-search-count");
  if (count) count.textContent = query ? `${visible}/${cards.length}개` : `${cards.length}개`;
  const empty = $("#assessment-filter-empty");
  if (empty) empty.hidden = visible > 0 || !query;
}

function showAssessmentManageModal(assessmentId, returnFocus = null) {
  const assessment = state.assessments.find((item) => Number(item.id) === Number(assessmentId));
  if (!assessment) { toast("평가를 찾을 수 없습니다.", true); return; }
  $("#assessment-manage-modal")?.remove();
  const [status, color] = statusLabel(assessment);
  const copySuffix = " 복사본";
  const copyName = `${assessment.name.slice(0, ASSESSMENT_TEXT_LIMITS.name.max - copySuffix.length)}${copySuffix}`;
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="assessment-manage-modal">
    <div class="modal assessment-manage-modal" role="dialog" aria-modal="true" aria-labelledby="assessment-manage-title">
      <div class="modal-header"><div><h2 id="assessment-manage-title">평가 관리</h2><p>평가 #${assessment.id}, ${escapeHtml(assessment.evaluation_target)}</p></div><button class="btn small" type="button" data-close-assessment-manage>닫기</button></div>
      <div class="modal-body assessment-manage-body">
        <div class="assessment-manage-summary"><span class="badge ${color}">${escapeHtml(status)}</span><strong>${escapeHtml(assessment.name)}</strong></div>
        <section class="assessment-manage-section"><div><strong>평가 이름 변경</strong><p>분석 내용은 그대로 유지되고 목록에 표시되는 이름만 바뀝니다.</p></div><form id="assessment-rename-form"><input id="assessment-rename-name" maxlength="${ASSESSMENT_TEXT_LIMITS.name.max}" value="${escapeHtml(assessment.name)}" required><button class="btn primary" type="submit">이름 저장</button></form></section>
        <section class="assessment-manage-section"><div><strong>새 평가로 복제</strong><p>Scope Brief와 DFD만 복사합니다. 공격 벡터 검토, 위험 평가와 CRRA 결과는 복사하지 않습니다.</p></div><form id="assessment-duplicate-form"><input id="assessment-duplicate-name" maxlength="${ASSESSMENT_TEXT_LIMITS.name.max}" value="${escapeHtml(copyName)}" required><button class="btn" type="submit">Scope와 DFD 복제</button></form></section>
        <div class="form-error hidden" id="assessment-manage-error" role="alert"></div>
      </div>
      <div class="modal-footer"><button class="btn" type="button" data-close-assessment-manage>닫기</button></div>
    </div>
  </div>`);
  const modal = $("#assessment-manage-modal");
  const close = () => { modal.remove(); returnFocus?.focus(); };
  $$('[data-close-assessment-manage]', modal).forEach((button) => button.onclick = close);
  modal.onkeydown = (event) => { if (event.key === "Escape") close(); };
  const errorBox = $("#assessment-manage-error", modal);
  const showError = (error) => {
    errorBox.textContent = error.message || String(error);
    errorBox.classList.remove("hidden");
  };
  $("#assessment-rename-form", modal).onsubmit = async (event) => {
    event.preventDefault();
    const name = $("#assessment-rename-name", modal).value.trim();
    if (!name) return;
    const submit = event.submitter || $('button[type="submit"]', event.currentTarget);
    if (submit.disabled) return;
    submit.disabled = true;
    try {
      await api(`/api/assessments/${assessment.id}`, { method: "PUT", body: { name } });
      state.assessments = await api("/api/assessments");
      close(); renderDashboard(); toast("평가 이름을 변경했습니다.");
    } catch (error) { submit.disabled = false; showError(error); }
  };
  $("#assessment-duplicate-form", modal).onsubmit = async (event) => {
    event.preventDefault();
    const name = $("#assessment-duplicate-name", modal).value.trim();
    if (!name) return;
    const submit = event.submitter || $('button[type="submit"]', event.currentTarget);
    if (submit.disabled) return;
    submit.disabled = true;
    try {
      await api(`/api/assessments/${assessment.id}/duplicate`, { method: "POST", body: { name } });
      state.assessments = await api("/api/assessments");
      close(); renderDashboard(); toast("Scope Brief와 DFD를 새 평가로 복제했습니다.");
    } catch (error) { submit.disabled = false; showError(error); }
  };
  $("#assessment-rename-name", modal).focus();
}

function showAssessmentDeleteModal(assessmentId, returnFocus = null) {
  const assessment = state.assessments.find((item) => Number(item.id) === Number(assessmentId));
  if (!assessment) { toast("평가를 찾을 수 없습니다.", true); return; }
  $("#assessment-delete-modal")?.remove();
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="assessment-delete-modal">
    <div class="modal assessment-delete-modal" role="dialog" aria-modal="true" aria-labelledby="assessment-delete-title">
      <div class="modal-header"><div><h2 id="assessment-delete-title">평가 삭제</h2><p>평가 #${assessment.id}, ${escapeHtml(assessment.evaluation_target)}</p></div><button class="btn small" type="button" data-close-assessment-delete>닫기</button></div>
      <div class="modal-body assessment-delete-body">
        <div class="notice warning"><div>!</div><div><strong>${escapeHtml(assessment.name)}</strong><br>DFD, 공격 벡터 검토, 위험 평가와 CRRA 결과가 모두 영구 삭제되며 복구할 수 없습니다.</div></div>
        <div class="form-field"><label class="required" for="assessment-delete-confirm">삭제하려면 평가 이름을 그대로 입력하세요</label><input id="assessment-delete-confirm" autocomplete="off" placeholder="${escapeHtml(assessment.name)}"><span class="input-help">대소문자와 띄어쓰기를 포함해 현재 평가 이름과 같아야 합니다.</span></div>
        <div class="form-error hidden" id="assessment-delete-error" role="alert"></div>
      </div>
      <div class="modal-footer"><button class="btn" type="button" data-close-assessment-delete>취소</button><button class="btn danger" id="assessment-delete-button" type="button" disabled>이 평가 영구 삭제</button></div>
    </div>
  </div>`);
  const modal = $("#assessment-delete-modal");
  const close = () => { modal.remove(); returnFocus?.focus(); };
  $$('[data-close-assessment-delete]', modal).forEach((button) => button.onclick = close);
  modal.onkeydown = (event) => { if (event.key === "Escape") close(); };
  const confirmInput = $("#assessment-delete-confirm", modal);
  const deleteButton = $("#assessment-delete-button", modal);
  const errorBox = $("#assessment-delete-error", modal);
  confirmInput.oninput = () => {
    deleteButton.disabled = confirmInput.value.trim() !== assessment.name.trim();
    errorBox.classList.add("hidden");
  };
  deleteButton.onclick = async () => {
    const confirmName = confirmInput.value.trim();
    if (confirmName !== assessment.name.trim()) return;
    deleteButton.disabled = true;
    try {
      await api(`/api/assessments/${assessment.id}`, { method: "DELETE", body: { confirm_name: confirmName } });
      state.assessments = await api("/api/assessments");
      close(); renderDashboard(); toast("평가를 삭제했습니다.");
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.classList.remove("hidden");
      deleteButton.disabled = confirmInput.value.trim() !== assessment.name.trim();
    }
  };
  confirmInput.focus();
}

async function claimLegacyAssessments() {
  const code = window.prompt("서버 터미널에 표시된 일회용 기존 평가 가져오기 코드를 입력하세요.");
  if (!code?.trim()) return;
  try {
    const result = await api("/api/session/claim-legacy", { method: "POST", body: { code: code.trim() } });
    state.assessments = await api("/api/assessments");
    state.bootstrap.legacy_claim_available = false;
    renderDashboard();
    const count = Number(result?.claimed_count ?? result?.count);
    toast(Number.isFinite(count) ? `기존 평가 ${count}개를 현재 브라우저로 가져왔습니다.` : "기존 평가를 현재 브라우저로 가져왔습니다.");
  } catch (error) {
    toast(error.message, true);
  }
}

function updateLlmProviderFields(resetModel = false) {
  const provider = $("#llm-provider").value;
  const meta = LLM_PROVIDERS[provider] || LLM_PROVIDERS.groq;
  const modelChoice = $("#llm-model-choice");
  const customModel = $("#llm-custom-model");
  const defaultOption = $("#llm-provider-default-model");
  const defaultModel = String(meta.defaultModel || "");
  $("#llm-provider-mark").textContent = meta.mark;
  $("#llm-provider-name").textContent = meta.label;
  $("#llm-provider-description").textContent = meta.description;
  $("#llm-api-key").placeholder = meta.keyPlaceholder;
  customModel.placeholder = meta.modelPlaceholder;
  defaultOption.value = defaultModel;
  defaultOption.textContent = defaultModel ? `${defaultModel} (${meta.label} 기본)` : "공급자 기본 모델";
  defaultOption.disabled = !defaultModel;
  defaultOption.hidden = !defaultModel;
  if (resetModel) {
    modelChoice.value = defaultModel || "__custom__";
    customModel.value = "";
  } else if (!defaultModel || modelChoice.value !== defaultModel) {
    modelChoice.value = "__custom__";
  }
  const custom = modelChoice.value === "__custom__";
  $("#llm-custom-model-field").classList.toggle("hidden", !custom);
  customModel.required = custom;
  const providerNotice = $("#llm-provider-notice");
  providerNotice.classList.toggle("hidden", !meta.notice);
  $("#llm-provider-notice-title").textContent = meta.notice?.title || "";
  $("#llm-provider-notice-body").textContent = meta.notice?.body || "";
}

function showLlmConfigModal() {
  $("#llm-config-modal")?.remove();
  const currentProvider = llmProviderId();
  const currentMeta = LLM_PROVIDERS[currentProvider];
  const defaultModel = String(currentMeta.defaultModel || "");
  const currentModel = String(state.llm?.model || defaultModel);
  const useCustomModel = !defaultModel || currentModel !== defaultModel;
  const providerOptions = Object.entries(LLM_PROVIDERS).map(([provider, meta]) => `<option value="${escapeHtml(provider)}" ${currentProvider === provider ? "selected" : ""}>${escapeHtml(meta.label)}</option>`).join("");
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="llm-config-modal">
    <div class="modal llm-config-modal" role="dialog" aria-modal="true" aria-labelledby="llm-config-title">
      <div class="modal-header"><div><h2 id="llm-config-title">내 API 키 연결</h2><div class="small-text muted">현재 브라우저 세션에서만 사용할 본인의 API 키를 연결합니다.</div></div><button class="btn small" data-close-llm>닫기</button></div>
      <form id="llm-config-form" autocomplete="off">
        <div class="modal-body">
          <div class="llm-provider-card">
            <div class="llm-provider-mark" id="llm-provider-mark">${escapeHtml(currentMeta.mark)}</div>
            <div><strong id="llm-provider-name">${escapeHtml(currentMeta.label)}</strong><span id="llm-provider-description">${escapeHtml(currentMeta.description)}</span></div>
            <span class="badge blue">내 세션 전용</span>
          </div>
          <div class="form-grid llm-config-fields">
            <div class="form-field full"><label class="required">서비스</label><select id="llm-provider">${providerOptions}</select></div>
            <div class="form-field full"><label class="required" for="llm-api-key">API 키</label><div class="llm-api-key-field"><input id="llm-api-key" name="cntara-llm-api-key-entry" type="password" value="" autocomplete="new-password" autocapitalize="none" spellcheck="false" data-lpignore="true" data-1p-ignore="true" placeholder="${escapeHtml(currentMeta.keyPlaceholder)}" aria-describedby="llm-api-key-help" required><button class="btn small" id="llm-api-key-visibility" type="button" aria-controls="llm-api-key" aria-pressed="false">보기</button></div><span class="input-help" id="llm-api-key-help">기존 연결 키는 다시 표시하지 않습니다. 변경하려면 새 API 키 전체를 입력하세요. 브라우저 저장소와 CloudTARA DB에는 저장하지 않으며, 연결 성공 후 입력란을 즉시 비웁니다.</span></div>
            <div class="form-field full"><label class="required">모델</label><select id="llm-model-choice"><option id="llm-provider-default-model" value="${escapeHtml(defaultModel)}" ${useCustomModel ? "" : "selected"} ${defaultModel ? "" : "disabled hidden"}>${escapeHtml(defaultModel ? `${defaultModel} (${currentMeta.label} 기본)` : "공급자 기본 모델")}</option><option value="__custom__" ${useCustomModel ? "selected" : ""}>직접 입력</option></select></div>
            <div class="form-field full ${useCustomModel ? "" : "hidden"}" id="llm-custom-model-field"><label class="required">모델 ID 직접 입력</label><input id="llm-custom-model" value="${escapeHtml(useCustomModel ? currentModel : "")}" placeholder="${escapeHtml(currentMeta.modelPlaceholder)}"></div>
          </div>
          <div class="notice warning llm-privacy-note ${currentMeta.notice ? "" : "hidden"}" id="llm-provider-notice"><div>!</div><div><strong id="llm-provider-notice-title">${escapeHtml(currentMeta.notice?.title || "")}</strong><span id="llm-provider-notice-body">${escapeHtml(currentMeta.notice?.body || "")}</span></div></div>
          <div class="notice success llm-privacy-note"><div>🔒</div><div><strong>API 키는 사용자마다 분리됩니다.</strong>${escapeHtml(llmMemoryNotice())} 이 화면의 ‘연결 해제’를 누르면 즉시 폐기할 수 있습니다.</div></div>
          <div class="notice info llm-privacy-note"><div>ⓘ</div><div><strong>추천을 요청할 때만 정보가 전송됩니다.</strong>평가에서 외부 LLM 사용을 허용한 경우에도 사용자가 추천 버튼을 눌러야 전송됩니다. 최종 판정과 입력값은 사용자가 확인합니다.</div></div>
          <div class="form-error hidden" id="llm-config-error" role="alert"></div>
        </div>
        <div class="modal-footer llm-modal-footer">${state.llm?.enabled ? '<button type="button" class="btn danger" id="llm-modal-clear">내 API 키 연결 해제</button>' : ""}<span></span><button class="btn primary" id="llm-config-submit" type="submit">이 세션에 연결하고 확인</button></div>
      </form>
    </div>
  </div>`);

  $$('[data-close-llm]').forEach((button) => button.onclick = () => $("#llm-config-modal")?.remove());
  const apiKeyInput = $("#llm-api-key");
  const visibilityButton = $("#llm-api-key-visibility");
  // Always start with an empty replacement key.
  apiKeyInput.value = "";
  visibilityButton.onclick = () => {
    const reveal = apiKeyInput.type === "password";
    apiKeyInput.type = reveal ? "text" : "password";
    visibilityButton.textContent = reveal ? "숨기기" : "보기";
    visibilityButton.setAttribute("aria-pressed", reveal ? "true" : "false");
    apiKeyInput.focus();
  };
  $("#llm-provider").onchange = () => {
    apiKeyInput.value = "";
    apiKeyInput.type = "password";
    visibilityButton.textContent = "보기";
    visibilityButton.setAttribute("aria-pressed", "false");
    updateLlmProviderFields(true);
    apiKeyInput.focus();
  };
  $("#llm-model-choice").onchange = (event) => {
    const custom = event.target.value === "__custom__";
    $("#llm-custom-model-field").classList.toggle("hidden", !custom);
    $("#llm-custom-model").required = custom;
    if (custom) $("#llm-custom-model").focus();
  };
  updateLlmProviderFields(false);
  $("#llm-config-form").onsubmit = submitLlmConfig;
  if ($("#llm-modal-clear")) $("#llm-modal-clear").onclick = clearLlmConfig;
  apiKeyInput.focus();
}

function assessmentCreationReady(form) {
  if (!form) return false;
  const data = new FormData(form);
  const hasText = (name) => Boolean(String(data.get(name) || "").trim());
  const withinLimits = Object.entries(ASSESSMENT_TEXT_LIMITS).every(([name, rule]) => {
    const field = form.elements[name];
    return !field || String(field.value || "").length <= rule.max;
  });
  if (!withinLimits) return false;
  if (!hasText("name") || !hasText("evaluation_target") || !hasText("scope_in")) return false;
  if (!data.getAll("threat_range_codes").length || !data.get("actor_type_code") || !data.get("intent_knowledge_state")) return false;
  if (data.get("intent_knowledge_state") === "KNOWN" && !data.getAll("objective_codes").length) return false;
  if (data.get("capability_knowledge_state") === "KNOWN" && !data.getAll("capability_codes").length) return false;
  return true;
}

function syncAssessmentCreateButton(form) {
  const button = form?.querySelector('button[type="submit"]');
  if (!button) return;
  button.disabled = !assessmentCreationReady(form);
  button.setAttribute("aria-disabled", button.disabled ? "true" : "false");
}

function bindCharacterCounters(container) {
  if (!container) return;
  $$('[data-character-count][maxlength]', container).forEach((field) => {
    const counter = document.createElement("span");
    counter.className = "input-help character-count";
    field.parentElement?.append(counter);
    const update = () => {
      const current = String(field.value || "").length;
      const maximum = Number(field.maxLength);
      counter.textContent = `${current.toLocaleString("ko-KR")} / ${maximum.toLocaleString("ko-KR")}자`;
      counter.classList.toggle("at-limit", current >= maximum);
    };
    field.addEventListener("input", update);
    update();
  });
}

function validateAssessmentTextLengths(form, fail) {
  for (const [name, rule] of Object.entries(ASSESSMENT_TEXT_LIMITS)) {
    const field = form?.elements?.[name];
    if (!field) continue;
    if (String(field.value || "").length > rule.max) {
      fail(`${rule.label}은(는) ${rule.max.toLocaleString("ko-KR")}자 이내로 입력해 주세요.`, field);
      return false;
    }
  }
  return true;
}

async function submitLlmConfig(event) {
  event.preventDefault();
  const apiKeyInput = $("#llm-api-key");
  const provider = $("#llm-provider").value;
  const modelChoice = $("#llm-model-choice").value;
  const model = (modelChoice === "__custom__" ? $("#llm-custom-model").value : modelChoice).trim();
  const apiKey = apiKeyInput.value.trim();
  if (!apiKey || !model) { toast("API 키와 모델을 입력해 주세요.", true); return; }
  const submit = $("#llm-config-submit");
  const errorBox = $("#llm-config-error");
  errorBox.classList.add("hidden");
  errorBox.textContent = "";
  submit.disabled = true;
  submit.textContent = "연결 확인 중…";
  try {
    const configuration = { provider, api_key: apiKey, model, verify: true };
    await api("/api/llm/config", { method: "POST", body: configuration });
    apiKeyInput.value = "";
    state.llm = await api("/api/llm/status");
    $("#llm-config-modal")?.remove();
    if (state.workspace) renderWorkspace(); else renderDashboard();
    toast(`${llmProviderLabel()}를 현재 브라우저 세션에 연결했습니다.`);
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.classList.remove("hidden");
    submit.disabled = false;
    submit.textContent = "다시 연결 확인";
    errorBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

async function clearLlmConfig() {
  if (!window.confirm("현재 브라우저 세션의 API 키를 서버 메모리에서 즉시 폐기할까요? 평가 데이터와 기존 추천 결과는 삭제되지 않습니다.")) return;
  const apiKeyInput = $("#llm-api-key");
  if (apiKeyInput) apiKeyInput.value = "";
  try {
    await api("/api/llm/config", { method: "POST", body: { clear: true } });
    state.llm = await api("/api/llm/status");
    $("#llm-config-modal")?.remove();
    if (state.workspace) renderWorkspace(); else renderDashboard();
    toast("현재 브라우저 세션의 API 키 연결을 해제했습니다.");
  } catch (error) {
    $("#llm-config-modal")?.remove();
    toast(error.message, true);
  }
}

function showAssessmentModal() {
  const release = state.bootstrap.km_releases[0];
  const profile = initialScopeProfile();
  const lifecycleOptions = scopeOptions("lifecycle_phases").map((item) => `<option value="${escapeHtml(item.code)}" ${item.code === profile.lifecycle_phase_code ? "selected" : ""}>${escapeHtml(item.label)}</option>`).join("");
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="assessment-modal">
    <div class="modal assessment-create-modal" role="dialog" aria-modal="true" aria-labelledby="assessment-create-title">
      <div class="modal-header"><div><h2 id="assessment-create-title">새 TARA 평가</h2><p>평가 이름과 Scope Brief를 함께 설정합니다. 생성 후에도 수정할 수 있습니다.</p></div></div>
      <form id="assessment-form">
        <div class="modal-body scope-editor-body">
          <div class="fixed-context-card"><span class="badge blue">고정</span><div><strong>CloudTARA</strong><span>생성 후 DFD를 직접 작성하거나 Manifest로 초안을 만들 수 있습니다.</span></div></div>
          <section class="scope-editor-section assessment-create-scope-section">
            <div class="scope-section-heading"><span>1</span><div><strong>평가 대상과 분석 범위</strong><p>평가 이름을 정하고 DFD에 포함할 범위를 짧게 설정합니다.</p></div></div>
            <div class="form-grid">
              <div class="form-field"><label class="required">평가 이름</label><input name="name" maxlength="${ASSESSMENT_TEXT_LIMITS.name.max}" data-character-count placeholder="예: 주문 서비스 운영 평가" required autofocus></div>
              <div class="form-field"><label class="required">대상 시스템 또는 서비스명</label><input name="evaluation_target" maxlength="${ASSESSMENT_TEXT_LIMITS.evaluation_target.max}" data-character-count placeholder="예: prod 주문 서비스" required></div>
              <div class="form-field compact-field"><label>생명주기 단계</label><select name="lifecycle_phase_code">${lifecycleOptions}</select></div>
              <div class="form-field full"><label class="required">포함 범위</label><textarea name="scope_in" maxlength="${ASSESSMENT_TEXT_LIMITS.scope_in.max}" data-character-count placeholder="예: 외부 Ingress부터 주문 API, 결제 호출, 주문 DB까지" required></textarea><span class="input-help">DFD에 포함할 시스템, 인터페이스와 데이터의 경계를 적습니다.</span></div>
              <div class="form-field full"><label>제외 범위 (선택)</label><textarea name="scope_out" maxlength="${ASSESSMENT_TEXT_LIMITS.scope_out.max}" data-character-count placeholder="예: 클라우드 제공자 내부 운영 영역"></textarea></div>
              <details class="scope-extra full"><summary>가정 및 참고사항 <span>선택</span></summary><div class="form-field"><textarea name="technical_info" maxlength="${ASSESSMENT_TEXT_LIMITS.technical_info.max}" data-character-count placeholder="예: 서비스 간 통신은 mTLS가 적용된 것으로 가정"></textarea></div></details>
            </div>
          </section>
          ${scopeThreatProfileSection(profile)}
          <label class="check-card scope-llm-option"><input type="checkbox" name="external_llm_allowed" value="1"><span><strong>이 평가에서 외부 LLM 추천 허용 (선택)</strong><span>추천 버튼을 누를 때만 평가 맥락이 본인이 연결한 LLM 서버로 전송됩니다.</span></span></label>
          <div class="create-km-note">지식 카탈로그: <strong>${escapeHtml(release.name)}</strong></div>
          <div class="form-error hidden" id="assessment-form-error"></div>
        </div>
        <div class="modal-footer"><button type="button" class="btn" data-close-modal>취소</button><button class="btn primary" type="submit" disabled aria-disabled="true">평가 생성</button></div>
      </form>
    </div>
  </div>`);
  $$('[data-close-modal]').forEach((button) => button.onclick = () => $("#assessment-modal")?.remove());
  const form = $("#assessment-form");
  bindScopeProfileFields(form);
  bindCharacterCounters(form);
  form.addEventListener("input", () => syncAssessmentCreateButton(form));
  form.addEventListener("change", () => syncAssessmentCreateButton(form));
  syncAssessmentCreateButton(form);
  form.onsubmit = async (event) => {
    event.preventDefault();
    const errorBox = $("#assessment-form-error");
    const fail = (message, field = null) => {
      errorBox.textContent = message;
      errorBox.classList.remove("hidden");
      field?.setAttribute?.("aria-invalid", "true");
      field?.focus?.({ preventScroll: true });
      errorBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
    };
    const name = String(form.elements.name.value || "").trim();
    const evaluationTarget = String(form.elements.evaluation_target.value || "").trim();
    const scopeIn = String(form.elements.scope_in.value || "").trim();
    if (!name) { fail("평가 이름을 입력해 주세요."); form.elements.name.focus(); return; }
    if (!validateAssessmentTextLengths(form, fail)) return;
    const parsed = readScopeProfileForm(form, fail);
    if (!parsed) return;
    const submitButton = form.querySelector('button[type="submit"]');
    submitButton.disabled = true;
    const { formData, profile: scopeProfile } = parsed;
    const body = {
      name,
      evaluation_target: evaluationTarget,
      scope_in: scopeIn,
      scope_out: String(formData.get("scope_out") || "").trim(),
      technical_info: String(formData.get("technical_info") || "").trim(),
      external_llm_allowed: formData.has("external_llm_allowed"),
      modeling_method: "MANUAL_DFD",
      scope_profile: scopeProfile,
      km_release_id: release.id,
    };
    let createdAssessment = null;
    try {
      createdAssessment = await api("/api/assessments", { method: "POST", body });
      state.assessments = await api("/api/assessments");
      const opened = await openAssessment(createdAssessment.id);
      if (!opened) throw new Error("생성된 평가 화면을 열지 못했습니다.");
      $("#assessment-modal")?.remove();
    } catch (error) {
      if (createdAssessment) {
        fail(`평가는 생성되었지만 화면을 열지 못했습니다. 이 창을 닫고 평가 목록을 새로고침해 주세요. (${error.message})`);
      } else {
        submitButton.disabled = false;
        fail(error.message);
      }
    }
  };
}

function mergeAttackVectorCatalog(entries = []) {
  const catalog = new Map();
  [
    ...(Array.isArray(state.attackVectorCatalog) ? state.attackVectorCatalog : []),
    ...(Array.isArray(entries) ? entries : []),
  ].forEach((item) => {
    const key = String(item?.id ?? item?.attack_vector_id ?? item?.av_id ?? "");
    if (!key) return;
    catalog.set(key, { ...(catalog.get(key) || {}), ...item });
  });
  state.attackVectorCatalog = [...catalog.values()];
}

function hydrateWorkspaceAttackVectorIds(workspace) {
  const catalog = Array.isArray(workspace?.attack_vector_catalog) ? workspace.attack_vector_catalog : [];
  const byInternalId = new Map();
  const bySourceId = new Map();
  const byName = new Map();
  catalog.forEach((item) => {
    const catalogId = String(item?.catalog_id ?? item?.attack_vector_catalog_id ?? "").trim();
    if (!/^AV-\d{6}$/.test(catalogId)) return;
    const internalId = String(item?.id ?? item?.attack_vector_id ?? "").trim();
    const sourceId = String(item?.source_identifier ?? item?.attack_vector_source_id ?? "").trim();
    const name = String(item?.name ?? item?.attack_vector_name ?? "").trim();
    if (internalId) byInternalId.set(internalId, catalogId);
    if (sourceId) bySourceId.set(sourceId, catalogId);
    if (name) byName.set(name, catalogId);
  });
  const hydrate = (item) => {
    if (!item) return;
    const explicit = String(item.attack_vector_catalog_id ?? item.av_catalog_id ?? item.catalog_id ?? item.public_id ?? "").trim();
    if (/^AV-\d{6}$/.test(explicit)) {
      item.attack_vector_catalog_id = explicit;
      return;
    }
    const internalId = String(item.attack_vector_id ?? item.attack_vector_internal_id ?? item.id ?? "").trim();
    const sourceId = String(item.attack_vector_source_id ?? item.source_identifier ?? item.external_id ?? "").trim();
    const name = String(item.attack_vector_name ?? item.name ?? "").trim();
    const catalogId = byInternalId.get(internalId) || bySourceId.get(sourceId || internalId) || byName.get(name);
    if (catalogId) item.attack_vector_catalog_id = catalogId;
  };
  (workspace?.candidates || []).forEach(hydrate);
  (workspace?.carts || []).forEach((cart) => (cart?.items || []).forEach(hydrate));
  (workspace?.matrix?.data?.rows || []).forEach(hydrate);
}

function assignWorkspace(workspace) {
  hydrateWorkspaceAttackVectorIds(workspace);
  state.workspace = workspace;
  mergeAttackVectorCatalog(workspace?.attack_vector_catalog);
  return workspace;
}

async function openAssessment(id, options = {}) {
  try {
    state.assessmentId = id;
    const [workspace, catalogResults] = await Promise.all([
      api(`/api/assessments/${id}/workspace`),
      api(`/api/catalog/attack-vectors?assessment_id=${id}&q=`).catch(() => []),
    ]);
    assignWorkspace(workspace);
    (state.workspace.nodes || []).forEach((node) => {
      if (!dfdNodeUsesManualSize(node)) applyAutomaticDfdNodeSize(node);
    });
    const legacyReconfirmation = (state.workspace.attack_cases || []).some((item) => (
      String(item.status || "").toUpperCase() === "LEGACY_REVIEW_REQUIRED"
    )) || (state.workspace.carts || []).some((item) => (
      String(item.context_status || "").toUpperCase() === "LEGACY_AGGREGATED"
    ));
    const forceDfd = Number(options.step) === 1 || legacyReconfirmation;
    state.step = forceDfd ? 1 : Math.max(1, Math.min(6, Number(state.workspace.assessment.current_step || 1)));
    state.phase = forceDfd ? "ctsa" : Number(state.workspace.assessment.crra_current_step || 0) > 0 || state.workspace.assessment.crra_confirmed ? "crra" : "ctsa";
    state.crraStep = Math.max(1, Math.min(5, Number(state.workspace.assessment.crra_current_step || 1)));
    state.crra = null;
    state.crraLlmSuggestions = {};
    resetCrraMappingDrafts();
    state.kmMode = false;
    state.activeTargetId = null;
    state.activeCartId = state.workspace.carts[0]?.id || null;
    state.activeReviewItemId = null;
    state.activeRiskItemId = null;
    state.activeCrraMappingId = null;
    clearDfdSelection();
    state.dfdDirty = false;
    state.dfdSemanticDirty = false;
    state.dfdLayoutDirty = false;
    loadAttackCaseDrafts(true);
    state.connectionMode = false;
    state.connectionSource = null;
    state.dfdZoom = 0.9;
    const storedDfdLevels = new Set((state.workspace.nodes || [])
      .map((node) => Number(node?.properties?.catalog?.level))
      .filter((level) => level === 0 || level === 1));
    state.dfdCatalogLevel = storedDfdLevels.size === 1 ? [...storedDfdLevels][0] : 0;
    state.dfdShowReferenceFlows = false;
    state.dfdFocusMode = false;
    state.dfdPanMode = false;
    state.dfdViewportX = 0;
    state.dfdViewportY = 0;
    state.dfdPendingFlow = null;
    state.dfdView = "MODEL";
    state.sideNavCollapsed = false;
    state.scopeBriefExpanded = !state.workspace.assessment.scope_ready;
    state.dfdScrollLeft = 0;
    state.dfdScrollTop = 0;
    state.catalogResults = Array.isArray(catalogResults) ? catalogResults : [];
    mergeAttackVectorCatalog(state.catalogResults);
    state.catalogLoading = false;
    state.catalogLoadedAssessmentId = id;
    state.candidatePage = 1;
    state.cartFilters = {};
    state.cartSelections = {};
    state.cartCatalogQuery = "";
    state.reviewDrafts = {};
    state.riskDrafts = {};
    state.riskDraftModelId = null;
    state.riskModelChoosing = false;
    state.riskModelSelectionId = null;
    state.riskModelWeightDrafts = {};
    state.activeRiskDrawerItemId = null;
    state.manifestReviewSummary = null;
    resetDfdHistory();
    if (state.phase === "crra" && state.workspace.assessment.matrix_confirmed) await reloadCrra();
    renderWorkspace();
    if (forceDfd && options.openManifest) showManifestCollectorModal();
    return true;
  } catch (error) { toast(error.message, true); return false; }
}

function canAccess(step) {
  const workspace = state.workspace;
  if (step === 1) return true;
  if ((workspace.attack_cases || []).some((item) => String(item.status || "").toUpperCase() === "LEGACY_REVIEW_REQUIRED")
      || (workspace.carts || []).some((item) => String(item.context_status || "").toUpperCase() === "LEGACY_AGGREGATED")) return false;
  if (step === 2) return Boolean(workspace.assessment.threat_model_confirmed);
  if (step === 3) return workspace.carts.length > 0 && Number(workspace.assessment.current_step || 1) >= 3;
  if (step === 4) return workspace.carts.length > 0 && workspace.carts.every((cart) => cart.status !== "DRAFT");
  if (step === 5) return workspace.carts.length > 0 && workspace.carts.every((cart) => cart.status === "REVIEWED");
  if (step === 6) return Boolean(workspace.matrix) || riskComplete();
  return false;
}

function crraSettings() { return state.crra?.settings || state.crra?.crra || {}; }

function canAccessCrra(step) {
  if ((state.workspace?.attack_cases || []).some((item) => String(item.status || "").toUpperCase() === "LEGACY_REVIEW_REQUIRED")
      || (state.workspace?.carts || []).some((item) => String(item.context_status || "").toUpperCase() === "LEGACY_AGGREGATED")) return false;
  if (!state.workspace?.assessment?.matrix_confirmed) return false;
  if (step === 1) return true;
  const current = Number(crraSettings().current_step ?? state.workspace.assessment.crra_current_step ?? 0);
  if (step === 2) return current >= 1;
  if (step === 3) return current >= 2;
  if (step === 4) return current >= 4;
  if (step === 5) {
    const countermeasures = scoringCountermeasures();
    const scoringComplete = countermeasures.length === 0 || countermeasures.every((item) => item.cost_score !== null && item.cost_score !== undefined);
    return current >= 5 || (current >= 4 && scoringComplete);
  }
  return false;
}

function showValidationSummary(messages, selectors = []) {
  const body = $("#step-content .page-body") || $("#step-content");
  if (!body) return;
  $("#step-validation-summary")?.remove();
  body.insertAdjacentHTML("afterbegin", `<div class="validation-summary" id="step-validation-summary" role="alert"><strong>확인이 필요한 항목</strong><ul>${messages.map((message) => `<li>${escapeHtml(message)}</li>`).join("")}</ul></div>`);
  selectors.forEach((selector) => $$(selector).forEach((element) => {
    const isPreciseTarget = element.matches("input, select, textarea, button, [role='button']");
    if (!isPreciseTarget) return;
    element.classList.add("validation-target");
    if (element.matches("input, select, textarea")) element.setAttribute("aria-invalid", "true");
    if (element.matches("[data-review-status]")) {
      const error = $(`[data-review-status-error="${element.dataset.reviewStatus}"]`);
      if (error) error.classList.remove("hidden");
    }
  }));
  $("#step-validation-summary")?.scrollIntoView({ behavior: "smooth", block: "center" });
}

function ctsaBlockingStep(targetStep) {
  const workspace = state.workspace;
  const legacy = (workspace.attack_cases || []).some((item) => String(item.status || "").toUpperCase() === "LEGACY_REVIEW_REQUIRED")
    || (workspace.carts || []).some((item) => String(item.context_status || "").toUpperCase() === "LEGACY_AGGREGATED");
  if (legacy || (targetStep > 1 && !workspace.assessment.threat_model_confirmed)) return 1;
  if (targetStep > 2 && (!workspace.carts.length || Number(workspace.assessment.current_step || 1) < 3)) return 2;
  if (targetStep > 3 && workspace.carts.some((cart) => cart.status === "DRAFT")) return 3;
  if (targetStep > 4 && workspace.carts.some((cart) => cart.status !== "REVIEWED")) return 4;
  if (targetStep > 5 && !riskComplete()) return 5;
  return null;
}

function explainCtsaBlock(targetStep) {
  const blockingStep = ctsaBlockingStep(targetStep);
  if (!blockingStep) return false;
  const workspace = state.workspace;
  const messages = [];
  const selectors = [];
  state.phase = "ctsa";
  state.step = blockingStep;
  if (blockingStep === 1) {
    const missingScope = textList(workspace.assessment.scope_missing_fields);
    if (missingScope.length) messages.push(`Scope Brief 미입력: ${missingScope.join(", ")}`);
    if (!(workspace.nodes || []).length) messages.push("DFD 구성요소가 없습니다.");
    if (!(workspace.edges || []).length) messages.push("DFD 데이터 흐름이 없습니다.");
    loadAttackCaseDrafts();
    const caseDrafts = state.attackCaseDrafts;
    const incompleteCases = caseDrafts.filter((item, index) => attackCaseDraftErrors(item, index).length > 0);
    if (!caseDrafts.length) messages.push("Attack Case가 없습니다.");
    if (incompleteCases.length) messages.push(`Entry Point, Intended Target 또는 근거가 비어 있는 Attack Case: ${incompleteCases.length}개`);
    if (!messages.length) messages.push("DFD와 Attack Case를 저장하고 확정해야 합니다.");
    state.dfdView = missingScope.length || !(workspace.nodes || []).length || !(workspace.edges || []).length ? "MODEL" : "CASES";
    selectors.push(".scope-brief", ".attack-case-builder", "#confirm-threat-model");
  } else if (blockingStep === 2) {
    messages.push("후보 공격 벡터를 확인한 뒤 식별 완료를 눌러 주세요.");
    selectors.push(".candidate-summary-bar", "#complete-candidate-identification");
  } else if (blockingStep === 3) {
    const incomplete = workspace.carts.filter((cart) => cart.status === "DRAFT");
    state.activeCartId = incomplete[0]?.id || state.activeCartId;
    messages.push(...incomplete.map((cart) => `${shoppingCartLabel(cart)}: 구성을 완료하지 않았습니다.`));
    selectors.push("#complete-cart", ".cart-compose-layout");
  } else if (blockingStep === 4) {
    const incomplete = workspace.carts.filter((cart) => cart.status !== "REVIEWED");
    state.activeCartId = incomplete[0]?.id || state.activeCartId;
    incomplete.forEach((cart, cartIndex) => {
      const unresolved = cart.items.filter((item) => reviewDraftFor(item).status === "UNREVIEWED");
      if (unresolved.length) {
        messages.push(`${shoppingCartLabel(cart)}: 검토 상태를 선택하지 않은 항목 ${unresolved.length}개`);
        if (cartIndex === 0) selectors.push(...unresolved.map((item) => `[data-review-status="${item.id}"]`));
      } else {
        messages.push(`${shoppingCartLabel(cart)}: 입력한 검토 결과를 저장해 주세요.`);
        if (cartIndex === 0) selectors.push("#save-cart-reviews");
      }
    });
  } else if (blockingStep === 5) {
    const model = selectedRiskModel();
    if (!model) messages.push("위험 계산기를 선택하지 않았습니다.");
    const incomplete = workspace.carts.filter((cart) => !model || !cartRiskComplete(cart));
    state.activeCartId = incomplete[0]?.id || state.activeCartId;
    let hasMissingValues = false;
    let hasUnsavedValues = false;
    if (model) incomplete.forEach((cart) => {
      const missingCount = riskPlausibleItems(cart).filter((item) => !riskDraftCompleteness(riskDraftFor(item, model), model).valuesComplete).length;
      const unsavedCount = riskPlausibleItems(cart).filter((item) => (
        riskDraftCompleteness(riskDraftFor(item, model), model).valuesComplete
        && riskCartNeedsSave({ ...cart, items: [item] }, model)
      )).length;
      if (missingCount) {
        hasMissingValues = true;
        messages.push(`${shoppingCartLabel(cart)}: 평가값이 비어 있는 공격 벡터 ${missingCount}개`);
      }
      if (unsavedCount) {
        hasUnsavedValues = true;
        messages.push(`${shoppingCartLabel(cart)}: 입력은 끝났지만 저장되지 않은 공격 벡터 ${unsavedCount}개`);
      }
    });
    if (!hasMissingValues && hasUnsavedValues) selectors.push("#save-cart-risks");
  }
  renderWorkspace();
  showValidationSummary(messages, selectors);
  if (blockingStep === 5) {
    $$('[data-risk-factor-value]').filter((field) => !field.value).forEach((field) => {
      field.classList.add("validation-target");
      field.setAttribute("aria-invalid", "true");
    });
  }
  return true;
}

function explainCrraBlock(targetStep) {
  if (!state.workspace.assessment.matrix_confirmed) {
    state.phase = "ctsa";
    state.step = 6;
    renderWorkspace();
    showValidationSummary(["위협 민감도 매트릭스를 확정해야 CRRA를 시작할 수 있습니다."], ["#confirm-matrix"]);
    return true;
  }
  const current = Number(crraSettings().current_step ?? state.workspace.assessment.crra_current_step ?? 0);
  let blockingStep = null;
  const messages = [];
  const selectors = [];
  if (targetStep > 1 && current < 1) {
    blockingStep = 1;
    messages.push("대응할 공격 벡터 선택을 저장해야 합니다.");
    selectors.push("#crra-save-vectors");
  } else if (targetStep > 2 && current < 2) {
    blockingStep = 2;
    messages.push("KM에서 대응책 후보를 불러와야 합니다.");
    selectors.push("#crra-generate-mappings");
  } else if (targetStep > 3 && current < 4) {
    blockingStep = 3;
    const unreviewed = crraMappings().filter((item) => String(item.review_status || "UNREVIEWED").toUpperCase() === "UNREVIEWED");
    if (crraMappingDraftIsDirty()) messages.push("저장하지 않은 대응책 후보 판정이 있습니다.");
    if (unreviewed.length) messages.push(`미검토 대응책 후보가 ${unreviewed.length}개 남았습니다.`);
    if (!messages.length) messages.push("대응책 후보 검토를 완료해야 합니다.");
    selectors.push(...unreviewed.map((item) => `[data-crra-batch-status="${item.id}"]`));
  } else if (targetStep > 4 && !canAccessCrra(5)) {
    blockingStep = 4;
    const missing = scoringCountermeasures().filter((item) => item.cost_score === null || item.cost_score === undefined);
    messages.push(...(missing.length ? missing.map((item) => `${countermeasureId(item)}: 비용 점수와 판단 근거를 입력해야 합니다.`) : ["대응책 비용 및 효과 평가 결과를 저장해야 합니다."]));
    selectors.push(...missing.map((item) => `[data-crra-cost-group="${countermeasureId(item)}"]`), "#crra-score");
  }
  if (!blockingStep) return false;
  state.phase = "crra";
  state.crraStep = blockingStep;
  renderWorkspace();
  showValidationSummary(messages, selectors);
  return true;
}

function renderWorkspace() {
  closeRiskDrawer();
  const assessment = state.workspace.assessment;
  const stepNav = STEPS.map(([number, name]) => {
    const accessible = canAccess(number);
    return `<button class="step-link ${state.phase === "ctsa" && state.step === number ? "active" : ""} ${accessible ? "" : "locked"}" data-step="${number}" aria-disabled="${accessible ? "false" : "true"}" ${accessible ? "" : "disabled"} title="${accessible ? `CTSA 1.${number} 단계로 이동` : "이전 단계 완료 후 활성화됩니다"}">
      <span class="step-no">1.${number}</span><span class="step-name">${name}</span>
    </button>`;
  }).join("");
  const crraNav = CRRA_STEPS.map(([number, name]) => {
    const accessible = canAccessCrra(number);
    return `<button class="step-link ${state.phase === "crra" && state.crraStep === number ? "active" : ""} ${accessible ? "" : "locked"}" data-crra-step="${number}" aria-disabled="${accessible ? "false" : "true"}" ${accessible ? "" : "disabled"} title="${accessible ? `CRRA 2.${number} 단계로 이동` : "이전 단계 완료 후 활성화됩니다"}">
      <span class="step-no">2.${number}</span><span class="step-name">${name}</span>
    </button>`;
  }).join("");
  const sideNavCollapsed = state.sideNavCollapsed;
  const llmConnectionLabel = state.llm?.enabled
    ? `${llmProviderLabel()} · ${compact(state.llm.model, "모델 설정됨")}`
    : state.llm?.expired ? "API 키 만료" : "연결 안 됨";
  const sideNavToggle = `<button class="side-nav-toggle" id="side-nav-toggle" type="button" aria-controls="workspace-step-menu" aria-expanded="${sideNavCollapsed ? "false" : "true"}" aria-label="${sideNavCollapsed ? "단계 메뉴 열기" : "단계 메뉴 접기"}" title="${sideNavCollapsed ? "단계 메뉴 열기" : "단계 메뉴 접기"}"><span class="side-nav-toggle-icon" aria-hidden="true"><i></i><b>${sideNavCollapsed ? "›" : "‹"}</b></span></button>`;
  $("#app").innerHTML = `<div class="app-shell ${sideNavCollapsed ? "side-nav-collapsed" : ""}">
    <header class="topbar">
      ${homeBrandMarkup()}
      <div class="assessment-title">${escapeHtml(assessment.name)}</div>
      <div class="topbar-actions">${themeSwitcherMarkup("workspace-theme")}</div>
    </header>
    <div class="workspace-shell">
      <aside class="side-nav" id="workspace-step-menu"><div class="nav-section-label">CTSA 단계</div>${stepNav}
        <div class="nav-divider"></div><div class="nav-section-label">CRRA 단계</div>${crraNav}
        <div class="nav-divider"></div>
        <div class="nav-meta"><span>이 평가에 적용된 지식 카탈로그</span><strong>${escapeHtml(assessment.km_release_name)}</strong><div class="workspace-llm-setting"><span>LLM</span><strong>${escapeHtml(llmConnectionLabel)}</strong><button type="button" class="btn small" id="workspace-llm-settings">${state.llm?.enabled ? "API 키 변경" : "API 키 설정"}</button></div></div>
      </aside>
      ${sideNavToggle}
      <main class="main-content" id="step-content"></main>
    </div>
  </div>`;
  bindHomeNavigation();
  $("#step-content").addEventListener("toggle", (event) => {
    if (event.target instanceof HTMLDetailsElement && event.target.classList.contains("scope-brief")) {
      state.scopeBriefExpanded = event.target.open;
    }
    if (event.target instanceof HTMLDetailsElement && event.target.classList.contains("review-context-card")) {
      state.reviewContextExpanded = event.target.open;
    }
  }, true);
  $("#step-content").addEventListener("click", (event) => {
    const editButton = event.target.closest?.("[data-edit-scope]");
    if (!editButton) return;
    event.preventDefault();
    showScopeBriefModal();
  });
  $("#step-content").addEventListener("wheel", (event) => {
    const tableScroller = event.target.closest?.(".review-table-wrap, .risk-table-scroll, .matrix-full-scroll");
    if (!tableScroller || event.ctrlKey || Math.abs(event.deltaY) <= Math.abs(event.deltaX)) return;
    const movingDown = event.deltaY > 0;
    const canScrollDown = tableScroller.scrollTop + tableScroller.clientHeight < tableScroller.scrollHeight - 1;
    const canScrollUp = tableScroller.scrollTop > 1;
    if ((movingDown && canScrollDown) || (!movingDown && canScrollUp)) return;
    const pageBody = tableScroller.closest(".page-body");
    if (!pageBody || pageBody.scrollHeight <= pageBody.clientHeight) return;
    pageBody.scrollTop += event.deltaY;
    event.preventDefault();
  }, { passive: false });
  bindThemeSwitcher("workspace-theme");
  $("#workspace-llm-settings")?.addEventListener("click", showLlmConfigModal);
  $("#side-nav-toggle").onclick = () => {
    const scrollX = window.scrollX;
    const scrollY = window.scrollY;
    state.sideNavCollapsed = !state.sideNavCollapsed;
    renderWorkspace();
    window.scrollTo(scrollX, scrollY);
    $("#side-nav-toggle")?.focus({ preventScroll: true });
  };
  $$('[data-step]').forEach((button) => button.onclick = async () => {
    if (button.disabled) return;
    const nextStep = Number(button.dataset.step);
    if (!canAccess(nextStep)) return;
    if (state.phase === "crra") {
      if (!confirmCrraDraftDiscard()) return;
      if (Number(state.crraStep) === 3) resetCrraMappingDrafts();
    }
    if (state.phase === "ctsa" && state.step === 4 && nextStep !== 4 && !confirmReviewDraftDiscard()) return;
    if (state.phase === "ctsa" && state.step === 5 && nextStep !== 5 && !confirmRiskDraftDiscard()) return;
    if (state.step === 1 && nextStep !== 1 && (state.dfdDirty || state.attackCasesDirty)) {
      if (!window.confirm("저장하지 않은 DFD 또는 Attack Case 변경사항이 있습니다. 변경을 취소하고 다른 단계로 이동할까요?")) return;
      await reloadWorkspace();
      state.dfdDirty = false;
      state.dfdSemanticDirty = false;
      state.dfdLayoutDirty = false;
      resetDfdHistory();
      loadAttackCaseDrafts(true);
      state.connectionMode = false;
      state.connectionSource = null;
    }
    state.phase = "ctsa"; state.step = nextStep;
    clearDfdSelection(); renderWorkspace();
  });
  $$('[data-crra-step]').forEach((button) => button.onclick = async () => {
    if (button.disabled) return;
    const nextCrraStep = Number(button.dataset.crraStep);
    if (!canAccessCrra(nextCrraStep)) return;
    if (state.phase === "crra" && nextCrraStep !== Number(state.crraStep)) {
      if (!confirmCrraDraftDiscard()) return;
      if (Number(state.crraStep) === 3) resetCrraMappingDrafts();
    }
    if (state.phase === "ctsa" && state.step === 4 && !confirmReviewDraftDiscard()) return;
    if (state.phase === "ctsa" && state.step === 5 && !confirmRiskDraftDiscard()) return;
    if (state.phase === "ctsa" && state.step === 1 && (state.dfdDirty || state.attackCasesDirty)) {
      if (!window.confirm("저장하지 않은 DFD 또는 Attack Case 변경사항이 있습니다. 변경을 취소하고 CRRA로 이동할까요?")) return;
      await reloadWorkspace();
      state.dfdDirty = false;
      state.dfdSemanticDirty = false;
      state.dfdLayoutDirty = false;
      loadAttackCaseDrafts(true);
      state.connectionMode = false;
      state.connectionSource = null;
    }
    await openCrraStep(nextCrraStep);
  });
  renderStep();
}

function renderStep() {
  const isCtsaStep = state.phase === "ctsa";
  const isDfdStep = state.phase === "ctsa" && state.step === 1;
  const isRiskWorkbench = state.phase === "ctsa" && Number(state.step) === 5 && Boolean(selectedRiskModel()) && !state.riskModelChoosing;
  const isTableStep = state.phase === "ctsa" && ([4, 6].includes(Number(state.step)) || isRiskWorkbench);
  if (!isDfdStep) {
    disconnectDfdGridResizeObserver();
  }
  const isDfdFocusMode = isDfdStep && state.dfdFocusMode;
  $(".app-shell")?.classList.toggle("dfd-focus-mode", isDfdFocusMode);
  $("#step-content").classList.toggle("ctsa-workspace", isCtsaStep);
  $("#step-content").classList.toggle("dfd-main-content", isDfdStep);
  $("#step-content").classList.toggle("dfd-focus-mode", isDfdFocusMode);
  $("#step-content").classList.toggle("table-workspace", isTableStep);
  if (state.phase === "crra") renderCrraStep();
  else if (state.step === 1) renderDfdStep();
  else if (state.step === 2) renderCandidatesStep();
  else if (state.step === 3) renderCartsStep();
  else if (state.step === 4) renderReviewStep();
  else if (state.step === 5) renderRiskStep();
  else renderMatrixStep();
}

function scopeProfileChoices(group, name, selected = [], includeCodes = null) {
  const selectedCodes = new Set(textList(selected));
  const allowed = includeCodes ? new Set(includeCodes) : null;
  return `<div class="profile-option-grid">${scopeOptions(group).filter((item) => !allowed || allowed.has(item.code)).map((item) => `<label class="profile-choice"><input type="checkbox" name="${escapeHtml(name)}" value="${escapeHtml(item.code)}" ${selectedCodes.has(item.code) ? "checked" : ""}><span>${escapeHtml(item.label)}</span></label>`).join("")}</div>`;
}

function threatRangeChoices(selected = []) {
  const technical = ["EXTERNAL_NETWORK", "APPLICATION_API", "IDENTITY_CREDENTIAL", "KUBERNETES_CONTROL_PLANE", "CONTAINER_WORKLOAD", "SOFTWARE_SUPPLY_CHAIN"];
  const concerns = ["DATA_COMPROMISE", "AVAILABILITY_DISRUPTION", "OTHER"];
  return `<div class="threat-range-groups"><div><span>기술 및 공격 표면</span>${scopeProfileChoices("threat_ranges", "threat_range_codes", selected, technical)}</div><div><span>보호 대상</span>${scopeProfileChoices("threat_ranges", "threat_range_codes", selected, concerns)}</div></div>`;
}

function initialScopeProfile() {
  return {
    schema_version: 1,
    lifecycle_phase_code: "OPERATION",
    threat_range_codes: [],
    actor: {
      actor_type_code: "",
      intent_knowledge_state: "",
      objective_codes: [],
      capability_knowledge_state: "UNKNOWN",
      capability_codes: [],
      notes: "",
    },
  };
}

function scopeThreatProfileSection(profile, legacyNotice = "") {
  const actor = profile?.actor && typeof profile.actor === "object" ? profile.actor : {};
  const intentState = String(actor.intent_knowledge_state || "");
  const capabilityState = String(actor.capability_knowledge_state || "UNKNOWN");
  const actorOptions = scopeOptions("actor_types").map((item) => `<option value="${escapeHtml(item.code)}" ${item.code === actor.actor_type_code ? "selected" : ""}>${escapeHtml(item.label)}</option>`).join("");
  const knowledgeOptions = scopeOptions("knowledge_states").map((item) => `<option value="${escapeHtml(item.code)}" ${item.code === intentState ? "selected" : ""}>${escapeHtml(item.label)}</option>`).join("");
  const capabilityOptions = scopeOptions("knowledge_states").map((item) => `<option value="${escapeHtml(item.code)}" ${item.code === capabilityState ? "selected" : ""}>${escapeHtml(item.label)}</option>`).join("");
  return `<section class="scope-editor-section">
    <div class="scope-section-heading"><span>2</span><div><strong>고려할 위협과 행위자</strong><p>선택값은 평가 맥락이며 공격 벡터를 자동 확정하지 않습니다.</p></div></div>
    ${legacyNotice}
    <div class="form-field full"><label class="required">분석할 위협 범위</label>${threatRangeChoices(profile?.threat_range_codes)}</div>
    <div class="form-grid scope-actor-row">
      <div class="form-field"><label class="required">주 위협 행위자</label><select name="actor_type_code" required><option value="">선택하세요</option>${actorOptions}</select></div>
      <div class="form-field"><label class="required">공격 목표 파악 상태</label><select name="intent_knowledge_state" required><option value="">선택하세요</option>${knowledgeOptions}</select></div>
      <div class="form-field full objective-options ${intentState === "KNOWN" ? "" : "hidden"}"><label class="required">공격 목표</label>${scopeProfileChoices("attack_objectives", "objective_codes", actor.objective_codes)}</div>
    </div>
    <details class="scope-extra"><summary>위협 행위자 정보 더 넣기 <span>선택</span></summary><div class="scope-extra-body"><div class="form-field compact-field"><label>역량 정보 상태</label><select name="capability_knowledge_state">${capabilityOptions}</select></div><div class="form-field capability-options ${capabilityState === "KNOWN" ? "" : "hidden"}"><label>알고 있는 역량</label>${scopeProfileChoices("capability_tags", "capability_codes", actor.capability_codes)}<span class="input-help">점수로 계산하지 않고 타당성 검토의 설명 맥락으로만 사용합니다.</span></div><div class="form-field"><label>행위자 관련 메모</label><textarea name="actor_notes" maxlength="${ASSESSMENT_TEXT_LIMITS.actor_notes.max}" data-character-count placeholder="확인된 정보나 불확실성만 간단히 기록">${escapeHtml(actor.notes)}</textarea></div></div></details>
  </section>`;
}

function bindScopeProfileFields(form) {
  const objectiveSection = $(".objective-options", form);
  const intentSelect = form.elements.intent_knowledge_state;
  if (objectiveSection && intentSelect) {
    intentSelect.onchange = (event) => objectiveSection.classList.toggle("hidden", event.target.value !== "KNOWN");
  }
  const capabilitySection = $(".capability-options", form);
  const capabilitySelect = form.elements.capability_knowledge_state;
  if (capabilitySection && capabilitySelect) {
    capabilitySelect.onchange = (event) => capabilitySection.classList.toggle("hidden", event.target.value !== "KNOWN");
  }
}

function readScopeProfileForm(form, fail) {
  const formData = new FormData(form);
  const evaluationTarget = String(formData.get("evaluation_target") || "").trim();
  const scopeIn = String(formData.get("scope_in") || "").trim();
  const threatRanges = formData.getAll("threat_range_codes");
  const intentState = String(formData.get("intent_knowledge_state") || "");
  const objectives = intentState === "KNOWN" ? formData.getAll("objective_codes") : [];
  const capabilityState = String(formData.get("capability_knowledge_state") || "UNKNOWN");
  const capabilities = capabilityState === "KNOWN" ? formData.getAll("capability_codes") : [];
  if (!evaluationTarget) { fail("대상 시스템 또는 서비스명을 입력하세요.", form.elements.evaluation_target); return null; }
  if (!scopeIn) { fail("DFD에 포함할 범위를 입력하세요.", form.elements.scope_in); return null; }
  if (!threatRanges.length) { fail("위협 범위를 하나 이상 선택하세요.", $('[name="threat_range_codes"]', form)); return null; }
  if (!formData.get("actor_type_code")) { fail("주 위협 행위자를 선택하세요.", form.elements.actor_type_code); return null; }
  if (!intentState) { fail("공격 목표 파악 상태를 선택하세요.", form.elements.intent_knowledge_state); return null; }
  if (intentState === "KNOWN" && !objectives.length) { fail("알고 있는 공격 목표를 하나 이상 선택하세요.", $('[name="objective_codes"]', form)); return null; }
  if (capabilityState === "KNOWN" && !capabilities.length) { fail("알고 있는 역량을 선택하거나 정보 상태를 아직 모름으로 바꾸세요.", $('[name="capability_codes"]', form)); return null; }
  return {
    formData,
    profile: {
      schema_version: 1,
      lifecycle_phase_code: String(formData.get("lifecycle_phase_code") || "OPERATION"),
      threat_range_codes: threatRanges,
      actor: {
        actor_type_code: String(formData.get("actor_type_code")),
        intent_knowledge_state: intentState,
        objective_codes: objectives,
        capability_knowledge_state: capabilityState,
        capability_codes: capabilities,
        notes: String(formData.get("actor_notes") || "").trim(),
      },
    },
  };
}

function showScopeBriefModal() {
  const assessment = state.workspace.assessment;
  if (assessment.threat_model_confirmed && state.dfdDirty) {
    toast("변경한 DFD를 먼저 저장한 뒤 Scope Brief를 수정해 주세요.", true);
    return;
  }
  const profile = assessmentScopeProfile(assessment);
  const legacyValues = [assessment.threat_range, assessment.actor_type, assessment.actor_intent, assessment.actor_capabilities].filter((value) => String(value || "").trim());
  const legacyNotice = !profile.structured && legacyValues.length
    ? `<div class="notice warning scope-legacy-note"><div>!</div><div><strong>기존 자유 입력값을 표준 선택값으로 정리하세요.</strong>${escapeHtml(legacyValues.join(", "))}</div></div>`
    : "";
  const lifecycleOptions = scopeOptions("lifecycle_phases").map((item) => `<option value="${escapeHtml(item.code)}" ${item.code === profile.lifecycle_phase_code ? "selected" : ""}>${escapeHtml(item.label)}</option>`).join("");
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="scope-brief-modal">
    <div class="modal scope-editor-modal">
      <div class="modal-header"><div><h2>Scope Brief 편집</h2><p>DFD와 공격 벡터 검토에 필요한 최소 맥락만 설정합니다.</p></div><button class="btn small" data-close-scope>닫기</button></div>
      <form id="scope-brief-form">
        <div class="modal-body scope-editor-body">
          <section class="scope-editor-section">
            <div class="scope-section-heading"><span>1</span><div><strong>대상과 분석 범위</strong><p>Cloud-Native 도메인은 고정입니다.</p></div></div>
            <div class="form-grid">
              <div class="form-field"><label class="required">대상 시스템 또는 서비스명</label><input name="evaluation_target" maxlength="${ASSESSMENT_TEXT_LIMITS.evaluation_target.max}" data-character-count value="${escapeHtml(assessment.evaluation_target)}" required></div>
              <div class="form-field"><label>생명주기 단계</label><select name="lifecycle_phase_code">${lifecycleOptions}</select></div>
              <div class="form-field full"><label class="required">포함 범위</label><textarea name="scope_in" maxlength="${ASSESSMENT_TEXT_LIMITS.scope_in.max}" data-character-count placeholder="예: 외부 Ingress부터 주문 API, 결제 호출, 주문 DB까지" required>${escapeHtml(assessment.scope_in || "")}</textarea><span class="input-help">DFD에 포함할 시스템, 인터페이스와 데이터를 적습니다. 현재 구성요소는 ${state.workspace.nodes.length}개입니다.</span></div>
              <div class="form-field full"><label>제외 범위 (선택)</label><textarea name="scope_out" maxlength="${ASSESSMENT_TEXT_LIMITS.scope_out.max}" data-character-count placeholder="예: 클라우드 제공자 내부 운영 영역">${escapeHtml(assessment.scope_out || "")}</textarea></div>
              <details class="scope-extra full"><summary>가정 및 참고사항 <span>선택</span></summary><div class="form-field"><textarea name="technical_info" maxlength="${ASSESSMENT_TEXT_LIMITS.technical_info.max}" data-character-count placeholder="예: 서비스 간 통신은 mTLS가 적용된 것으로 가정">${escapeHtml(assessment.technical_info || "")}</textarea></div></details>
            </div>
          </section>
          ${scopeThreatProfileSection(profile, legacyNotice)}
          <label class="check-card scope-llm-option"><input type="checkbox" name="external_llm_allowed" value="1" ${assessment.external_llm_allowed ? "checked" : ""}><span><strong>이 평가에서 외부 LLM 추천 허용 (선택)</strong><span>추천 버튼을 누를 때만 평가 맥락이 본인이 연결한 LLM 서버로 전송됩니다.</span></span></label>
          <div class="form-error hidden" id="scope-form-error"></div>
        </div>
        <div class="modal-footer"><button type="button" class="btn" data-close-scope>취소</button><button class="btn primary" type="submit">Scope Brief 저장</button></div>
      </form>
    </div>
  </div>`);
  $$('[data-close-scope]').forEach((button) => button.onclick = () => $("#scope-brief-modal")?.remove());
  const form = $("#scope-brief-form");
  bindScopeProfileFields(form);
  bindCharacterCounters(form);
  form.onsubmit = async (event) => {
    event.preventDefault();
    const errorBox = $("#scope-form-error");
    const fail = (message, field = null) => {
      $$(".validation-target", form).forEach((element) => element.classList.remove("validation-target"));
      $$('[aria-invalid="true"]', form).forEach((element) => element.removeAttribute("aria-invalid"));
      errorBox.textContent = message;
      errorBox.classList.remove("hidden");
      const target = field?.matches?.('input[type="checkbox"], input[type="radio"]')
        ? field.closest(".profile-option-grid")
        : field;
      target?.classList.add("validation-target");
      field?.setAttribute?.("aria-invalid", "true");
      field?.focus?.({ preventScroll: true });
      errorBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
    };
    if (!validateAssessmentTextLengths(form, fail)) return;
    const parsed = readScopeProfileForm(form, fail);
    if (!parsed) return;
    const { formData, profile: nextProfile } = parsed;
    const nextLegacy = {
      lifecycle_phase: scopeOptionLabel("lifecycle_phases", nextProfile.lifecycle_phase_code, "운영"),
      threat_range: scopeCodeLabels("threat_ranges", nextProfile.threat_range_codes, ""),
      actor_type: scopeOptionLabel("actor_types", nextProfile.actor.actor_type_code, ""),
      actor_motivation: nextProfile.actor.notes.trim(),
      actor_intent: nextProfile.actor.intent_knowledge_state === "KNOWN"
        ? scopeCodeLabels("attack_objectives", nextProfile.actor.objective_codes, "")
        : scopeOptionLabel("knowledge_states", nextProfile.actor.intent_knowledge_state, ""),
      actor_capabilities: nextProfile.actor.capability_knowledge_state === "KNOWN"
        ? scopeCodeLabels("capability_tags", nextProfile.actor.capability_codes, "")
        : scopeOptionLabel("knowledge_states", nextProfile.actor.capability_knowledge_state, ""),
    };
    const contextChanged = String(formData.get("evaluation_target")).trim() !== String(assessment.evaluation_target || "").trim()
      || String(formData.get("scope_in")).trim() !== String(assessment.scope_in || "").trim()
      || String(formData.get("scope_out")).trim() !== String(assessment.scope_out || "").trim()
      || String(formData.get("technical_info")).trim() !== String(assessment.technical_info || "").trim()
      || Object.entries(nextLegacy).some(([field, value]) => value !== String(assessment[field] || "").trim());
    if (assessment.threat_model_confirmed && contextChanged && !window.confirm("Scope Brief를 바꾸면 기존 타당성 판단, 위험 점수, 민감도 매트릭스와 CRRA 분석 결과가 초기화됩니다. 계속할까요?")) return;
    const payload = {
      evaluation_target: String(formData.get("evaluation_target") || "").trim(),
      scope_in: String(formData.get("scope_in") || "").trim(),
      scope_out: String(formData.get("scope_out") || "").trim(),
      technical_info: String(formData.get("technical_info") || "").trim(),
      external_llm_allowed: formData.has("external_llm_allowed"),
      scope_profile: nextProfile,
    };
    try {
      const saved = await api(`/api/assessments/${state.assessmentId}`, { method: "PUT", body: payload });
      if (assessment.threat_model_confirmed) await reloadWorkspace();
      else state.workspace.assessment = { ...state.workspace.assessment, ...saved };
      state.scopeBriefExpanded = false;
      $("#scope-brief-modal")?.remove();
      renderWorkspace();
      toast("Scope Brief를 저장했습니다.");
    } catch (error) { fail(error.message); }
  };
}

function scopeStrip() {
  const assessment = state.workspace.assessment;
  const display = scopeBriefDisplay(assessment);
  const ready = Boolean(assessment.scope_ready);
  const missing = textList(assessment.scope_missing_fields);
  return `<details class="scope-brief" ${state.scopeBriefExpanded ? "open" : ""}>
    <summary class="scope-brief-summary">
      <span class="scope-brief-title">Scope Brief</span>
      <span class="badge ${ready ? "green" : "orange"}">${ready ? "설정 완료" : "설정 필요"}</span>
      <strong class="scope-brief-target">${escapeHtml(compact(assessment.evaluation_target, "평가 대상 미입력"))}</strong>
      <span class="scope-brief-meta">${escapeHtml(display.actorType)}, ${escapeHtml(display.lifecycle)}</span>
      <span class="scope-brief-toggle"><span class="scope-show-label">펼치기</span><span class="scope-hide-label">접기</span><span class="scope-chevron">⌄</span></span>
    </summary>
    <div class="scope-strip-header"><p>${ready ? "후속 검토에 적용되는 범위입니다." : `미입력 항목: ${escapeHtml(missing.join(", ") || "필수 맥락")}`}</p><button type="button" class="btn small" data-edit-scope>범위 및 위협 프로필</button></div>
    <div class="scope-strip">
      <div class="scope-item"><span>대상과 생명주기</span><strong>${escapeHtml(assessment.evaluation_target)}, ${escapeHtml(display.lifecycle)}</strong></div>
      <div class="scope-item"><span>포함 범위</span><strong>${escapeHtml(compact(assessment.scope_in, "설정 필요"))}</strong></div>
      <div class="scope-item"><span>제외 범위</span><strong>${escapeHtml(compact(assessment.scope_out, "없음"))}</strong></div>
      <div class="scope-item"><span>위협 범위</span><strong>${escapeHtml(display.threatRanges)}</strong></div>
      <div class="scope-item"><span>행위자와 공격 목표</span><strong>${escapeHtml(display.actorType)}, ${escapeHtml(display.objectives)}</strong></div>
      <div class="scope-item"><span>알려진 행위자 역량</span><strong>${escapeHtml(display.capabilities)}</strong></div>
    </div>
  </details>`;
}

function pageHeader(title, description, actions = "") {
  return `<div class="page-header"><div><h1>${title}</h1><p>${description}</p></div><div class="page-actions">${actions}</div></div><div class="workspace-scope-brief">${scopeStrip()}</div>`;
}

function assetById(id) { return state.bootstrap.asset_types.find((asset) => asset.id === id); }
function nodeById(id) { return state.workspace.nodes.find((node) => node.id === id); }
function cartById(id) { return state.workspace.carts.find((cart) => Number(cart.id) === Number(id)); }

function workspaceNodeById(id) {
  return (state.workspace?.nodes || []).find((node) => String(node.id) === String(id));
}

function attackCaseObjectiveOptions() {
  const profile = assessmentScopeProfile();
  const selectedCodes = new Set(profile.actor.objective_codes || []);
  const configured = scopeOptions("attack_objectives");
  const selected = configured.filter((option) => selectedCodes.has(option.code));
  const other = configured.find((option) => option.code === "OTHER") || { code: "OTHER", label: "직접 입력" };
  const result = selected.filter((option) => option.code !== "OTHER");
  if (!result.some((option) => option.code === other.code)) result.push(other);
  return result;
}

function normalizeAttackCaseDraft(raw, index) {
  const options = scopeOptions("attack_objectives");
  const rawEffect = String(raw?.intended_effect || raw?.effect || "").trim();
  const explicitCode = String(raw?.intended_effect_code || raw?.effect_code || "").trim();
  const matching = options.find((option) => option.code === explicitCode || option.label === rawEffect);
  const code = matching?.code || (rawEffect ? "OTHER" : attackCaseObjectiveOptions()[0]?.code || "OTHER");
  const effect = matching && matching.code !== "OTHER" ? matching.label : rawEffect;
  const persistedId = raw?.id ?? raw?.attack_case_id ?? null;
  const storedEntryIds = Array.isArray(raw?.entry_node_ids)
    ? raw.entry_node_ids
    : (raw?.entry_node_id ? [raw.entry_node_id] : []);
  const entryNodeIds = [...new Set(storedEntryIds.map((value) => String(value || "").trim()).filter(Boolean))];
  return {
    draftKey: persistedId === null || persistedId === undefined || persistedId === ""
      ? randomId("attack-case")
      : `attack-case-${persistedId}`,
    id: persistedId,
    name: String(raw?.name || raw?.attack_case_name || `Attack Case ${index + 1}`).trim(),
    target_node_id: raw?.target_node_id ?? "",
    entry_node_id: entryNodeIds[0] || "",
    entry_node_ids: entryNodeIds,
    entry_search: "",
    target_search: "",
    intended_effect_code: code,
    intended_effect: effect,
    rationale: String(raw?.rationale || raw?.selection_rationale || raw?.reason || "").trim(),
    path_mode: String(raw?.path_mode || ""),
    path_node_ids: Array.isArray(raw?.path_node_ids) ? [...raw.path_node_ids] : [],
    manual_path_confirmed: String(raw?.path_mode || "").toUpperCase() === "MANUAL",
  };
}

function loadAttackCaseDrafts(force = false) {
  const assessmentId = String(state.assessmentId ?? state.workspace?.assessment?.id ?? "");
  if (!force && state.attackCaseSourceAssessmentId === assessmentId) return;
  const stored = Array.isArray(state.workspace?.attack_cases) ? state.workspace.attack_cases : [];
  state.attackCaseDrafts = stored.map(normalizeAttackCaseDraft);
  state.attackCasesDirty = false;
  state.attackCaseSourceAssessmentId = assessmentId;
  state.activeAttackCaseDraftId = state.attackCaseDrafts[0]?.draftKey || null;
}

function attackCaseDraftByKey(key) {
  return state.attackCaseDrafts.find((item) => String(item.draftKey) === String(key));
}

function attackCaseRolesForNode(nodeId) {
  const key = String(nodeId ?? "");
  return {
    isEntry: state.attackCaseDrafts.some((item) => (item.entry_node_ids || []).some((entryId) => String(entryId) === key)),
    isTarget: state.attackCaseDrafts.some((item) => String(item.target_node_id ?? "") === key),
  };
}

function storedAttackCaseById(id) {
  return (state.workspace?.attack_cases || []).find((item) => String(item.id ?? item.attack_case_id) === String(id));
}

function cartAttackCase(cart) {
  if (!cart) return null;
  return storedAttackCaseById(cart.attack_case_id)
    || (state.workspace?.attack_cases || []).find((item) => (
      String(item.entry_node_id ?? "") === String(cart.entry_node_id ?? "")
      && String(item.target_node_id ?? "") === String(cart.target_node_id ?? "")
    )) || null;
}

function cartCaseEndpoints(cart) {
  const attackCase = cartAttackCase(cart);
  const entryIds = Array.isArray(cart?.entry_node_ids) && cart.entry_node_ids.length
    ? cart.entry_node_ids
    : Array.isArray(attackCase?.entry_node_ids) && attackCase.entry_node_ids.length
      ? attackCase.entry_node_ids
      : [cart?.entry_node_id ?? attackCase?.entry_node_id].filter((value) => value !== null && value !== undefined && value !== "");
  return {
    entryId: entryIds[0] ?? null,
    entryIds,
    targetId: cart?.target_node_id ?? attackCase?.target_node_id ?? null,
  };
}

function cartCaseLabel(cart, fallback = "Attack Case") {
  const endpoints = cartCaseEndpoints(cart);
  if (endpoints.entryId !== null && endpoints.entryId !== undefined && endpoints.targetId !== null && endpoints.targetId !== undefined) {
    const attackCase = cartAttackCase(cart);
    const caseName = compact(cart?.attack_case_name ?? attackCase?.name, "");
    const entryLabel = endpoints.entryIds.map((id) => nodeDisplayName(id, "진입 지점")).join(", ");
    const routeLabel = `${entryLabel} → ${nodeDisplayName(endpoints.targetId, "공격 대상")}`;
    const casePrefix = caseName && caseName !== routeLabel ? `${caseName}, ` : "";
    const legacy = String(cart?.context_status || "").toUpperCase() === "LEGACY_AGGREGATED"
      ? ", 기존 집계 재확인 필요"
      : "";
    return `${casePrefix}${routeLabel}${legacy}`;
  }
  return dfdDisplayName(cart?.attack_case_name || cart?.name, fallback);
}

function shoppingCartLabel(cart, fallback = "공격 대상") {
  const targetId = cartCaseEndpoints(cart).targetId;
  if (targetId !== null && targetId !== undefined && String(targetId).trim()) {
    return nodeDisplayName(targetId, fallback);
  }
  return dfdDisplayName(cart?.name, fallback);
}

function cartCaseEffect(cart) {
  const attackCase = cartAttackCase(cart);
  return compact(cart?.intended_effect ?? attackCase?.intended_effect, "미입력");
}

function cartCaseRationale(cart) {
  const attackCase = cartAttackCase(cart);
  return compact(cart?.rationale ?? attackCase?.rationale, "-");
}

function dfdDisplayName(value, fallback = "") {
  return DFD_SELECTION.displayName(value, fallback);
}

function dfdKindLabel(kind, fallback = "구성요소") {
  if (kind === "process") return "프로세스";
  if (kind === "data_store") return "데이터 저장소";
  if (kind === "external") return "외부 엔터티";
  return fallback;
}

function assetDisplayName(assetOrId, fallback = "구성요소") {
  const asset = assetOrId && typeof assetOrId === "object" ? assetOrId : assetById(assetOrId);
  if (!asset) return dfdDisplayName(assetOrId, fallback);
  return dfdDisplayName(asset.name, dfdKindLabel(asset.dfd_kind, fallback));
}

function nodeDisplayName(nodeOrId, fallback = "구성요소") {
  const node = nodeOrId && typeof nodeOrId === "object" ? nodeOrId : nodeById(nodeOrId);
  if (!node) return dfdDisplayName(nodeOrId, fallback);
  const asset = assetById(node.asset_type_id);
  const typeName = dfdDisplayName(node.asset_type_name, assetDisplayName(asset, dfdKindLabel(node.dfd_kind, fallback)));
  return dfdDisplayName(node.name, typeName);
}

function edgeDisplayName(edge, fallback = "") {
  return dfdDisplayName(edge?.name, fallback);
}

function dfdCatalogLevelState() {
  const levels = new Set((state.workspace?.nodes || [])
    .map((node) => Number(node?.properties?.catalog?.level))
    .filter((level) => Number.isInteger(level) && (level === 0 || level === 1)));
  return {
    level: levels.size === 1 ? [...levels][0] : levels.size === 0 ? Number(state.dfdCatalogLevel ?? 0) : null,
    mixed: levels.size > 1,
  };
}

function currentDfdCatalogLevel() {
  const level = dfdCatalogLevelState().level;
  return level === 1 ? 1 : 0;
}

function dfdCatalogAssets(level = currentDfdCatalogLevel()) {
  if (level !== 0 && level !== 1) return [];
  const elements = Array.isArray(state.bootstrap?.dfd_catalog_elements) ? state.bootstrap.dfd_catalog_elements : [];
  const allowed = new Set(elements
    .filter((element) => Number(element?.level) === Number(level))
    .map((element) => String(element?.asset_type_id || ""))
    .filter(Boolean));
  const assets = (state.bootstrap?.asset_types || []).filter((asset) => allowed.has(String(asset.id)));
  return assets;
}

function dfdElementCatalogMetadata(assetTypeId, level = currentDfdCatalogLevel()) {
  const matches = (state.bootstrap?.dfd_catalog_elements || []).filter((element) => (
    Number(element?.level) === Number(level)
    && String(element?.asset_type_id || "") === String(assetTypeId || "")
  ));
  if (matches.length !== 1) return null;
  const element = matches[0];
  return {
    km_release_id: element.km_release_id,
    level: Number(element.level),
    element_template_id: element.asset_type_id,
    match_basis: "CATALOG_PALETTE_SELECTION",
  };
}

function flowTemplateFor(sourceNode, targetNode) {
  return DFD_SELECTION.selectFlowTemplate(
    state.bootstrap?.dfd_flow_templates || [],
    state.bootstrap?.dfd_catalog_elements || [],
    sourceNode,
    targetNode,
  );
}

function flowTemplateCatalog(template) {
  return DFD_SELECTION.flowCatalogMetadata(template);
}

function clearCatalogMetadata(item) {
  if (!item?.properties?.catalog) return false;
  item.properties = { ...item.properties };
  delete item.properties.catalog;
  return true;
}

function clearNodeAndIncidentEdgeCatalogMetadata(node) {
  clearCatalogMetadata(node);
  state.workspace.edges.forEach((edge) => {
    if (String(edge.source) === String(node.id) || String(edge.target) === String(node.id)) clearCatalogMetadata(edge);
  });
}

function selectedDfdNodeIds() {
  const nodes = state.workspace?.nodes || [];
  const validById = new Map(nodes.map((node) => [String(node.id), node.id]));
  const candidates = [...(Array.isArray(state.selectedNodeIds) ? state.selectedNodeIds : [])];
  if (state.selected?.type === "node") candidates.push(state.selected.id);
  const seen = new Set();
  return candidates.reduce((result, id) => {
    const key = String(id ?? "");
    if (!key || seen.has(key) || !validById.has(key)) return result;
    seen.add(key);
    result.push(validById.get(key));
    return result;
  }, []);
}

function selectedDfdNodeIdSet() {
  return new Set(selectedDfdNodeIds().map((id) => String(id)));
}

function setDfdNodeSelection(ids) {
  state.selectedNodeIds = [];
  const seen = new Set();
  (Array.isArray(ids) ? ids : []).forEach((id) => {
    const node = nodeById(id) || state.workspace?.nodes?.find((item) => String(item.id) === String(id));
    const key = String(node?.id ?? "");
    if (!node || seen.has(key)) return;
    seen.add(key);
    state.selectedNodeIds.push(node.id);
  });
  state.selected = state.selectedNodeIds.length === 1 ? { type: "node", id: state.selectedNodeIds[0] } : null;
}

function setSingleDfdSelection(type, id) {
  if (type === "node") { setDfdNodeSelection([id]); return; }
  state.selectedNodeIds = [];
  state.selected = id === undefined || id === null ? null : { type, id };
}

function clearDfdSelection() {
  state.selected = null;
  state.selectedNodeIds = [];
}

function hasDfdSelection() {
  return selectedDfdNodeIds().length > 0 || Boolean(state.selected);
}

function reachableDfdNodeIdsFromEntries() {
  const nodes = state.workspace?.nodes || [];
  const edges = state.workspace?.edges || [];
  const nodeIds = new Set(nodes.map((node) => String(node.id)));
  const reachable = new Set(nodes.filter((node) => node.is_entry).map((node) => String(node.id)));
  const outgoing = new Map();
  edges.forEach((edge) => {
    const source = String(edge.source ?? "");
    const target = String(edge.target ?? "");
    if (!nodeIds.has(source) || !nodeIds.has(target)) return;
    if (!outgoing.has(source)) outgoing.set(source, []);
    outgoing.get(source).push(target);
  });
  const queue = [...reachable];
  for (let index = 0; index < queue.length; index += 1) {
    (outgoing.get(queue[index]) || []).forEach((target) => {
      if (reachable.has(target)) return;
      reachable.add(target);
      queue.push(target);
    });
  }
  return reachable;
}

function hasDownstreamResults() {
  return Boolean(state.workspace?.matrix || state.workspace?.assessment?.matrix_confirmed || state.workspace?.assessment?.crra_current_step || state.workspace?.assessment?.crra_confirmed
    || state.workspace?.carts?.some((cart) => cart.items.some((item) => item.risk_score !== null && item.risk_score !== undefined)));
}

function confirmCartChange(cart, message) {
  if (cart?.status === "DRAFT" && !hasDownstreamResults()) return true;
  const consequence = hasDownstreamResults()
    ? "기존 위험 평가, 민감도 매트릭스와 대응책 분석 결과가 초기화됩니다."
    : "이 쇼핑 카트의 구성 완료 및 타당성 검토 상태를 다시 확인해야 합니다.";
  return window.confirm(`${message}\n\n${consequence}\n계속할까요?`);
}

function markDfdDirty(kind = "semantic") {
  state.dfdDirty = true;
  if (kind === "layout") state.dfdLayoutDirty = true;
  else state.dfdSemanticDirty = true;
  recordDfdHistory();
  if (kind === "layout") return;
  const confirmButton = $("#confirm-threat-model");
  if (confirmButton) {
    confirmButton.disabled = false;
    confirmButton.textContent = "확정 완료";
  }
}

function dfdHistorySnapshot() {
  return JSON.parse(JSON.stringify({
    nodes: state.workspace?.nodes || [],
    edges: state.workspace?.edges || [],
    boundaries: state.workspace?.boundaries || [],
  }));
}

function dfdHistoryKey(snapshot) { return JSON.stringify(snapshot); }

function resetDfdHistory() {
  state.dfdHistory = [dfdHistorySnapshot()];
  state.dfdRedoHistory = [];
  state.dfdClipboard = null;
}

function recordDfdHistory() {
  if (!state.workspace) return;
  const snapshot = dfdHistorySnapshot();
  const current = state.dfdHistory[state.dfdHistory.length - 1];
  if (current && dfdHistoryKey(current) === dfdHistoryKey(snapshot)) return;
  state.dfdHistory.push(snapshot);
  if (state.dfdHistory.length > 60) state.dfdHistory.shift();
  state.dfdRedoHistory = [];
}

function restoreDfdHistorySnapshot(snapshot) {
  if (!snapshot || !state.workspace) return;
  state.workspace.nodes = JSON.parse(JSON.stringify(snapshot.nodes));
  state.workspace.edges = JSON.parse(JSON.stringify(snapshot.edges));
  state.workspace.boundaries = JSON.parse(JSON.stringify(snapshot.boundaries));
  state.dfdDirty = true;
  state.dfdSemanticDirty = true;
  clearDfdSelection();
}

function undoDfd() {
  if (state.dfdHistory.length < 2) { toast("실행 취소할 변경이 없습니다."); return; }
  state.dfdRedoHistory.push(state.dfdHistory.pop());
  restoreDfdHistorySnapshot(state.dfdHistory[state.dfdHistory.length - 1]);
  renderDfdStepAndFocus();
}

function redoDfd() {
  const snapshot = state.dfdRedoHistory.pop();
  if (!snapshot) { toast("다시 실행할 변경이 없습니다."); return; }
  state.dfdHistory.push(snapshot);
  restoreDfdHistorySnapshot(snapshot);
  renderDfdStepAndFocus();
}

function copyDfdSelection() {
  const selectedIds = new Set(selectedDfdNodeIds().map(String));
  if (!selectedIds.size) { toast("복사할 구성요소를 선택해 주세요."); return; }
  state.dfdClipboard = {
    nodes: state.workspace.nodes.filter((node) => selectedIds.has(String(node.id))).map((node) => JSON.parse(JSON.stringify(node))),
    edges: state.workspace.edges.filter((edge) => selectedIds.has(String(edge.source)) && selectedIds.has(String(edge.target))).map((edge) => JSON.parse(JSON.stringify(edge))),
  };
  toast(`구성요소 ${selectedIds.size}개를 복사했습니다.`);
}

function pasteDfdSelection() {
  if (!state.dfdClipboard?.nodes?.length) { toast("붙여넣을 구성요소가 없습니다."); return; }
  const idMap = new Map();
  const nodes = state.dfdClipboard.nodes.map((source) => {
    const id = randomId("node");
    idMap.set(String(source.id), id);
    return { ...JSON.parse(JSON.stringify(source)), id, x: Number(source.x) + 32, y: Number(source.y) + 32 };
  });
  const edges = state.dfdClipboard.edges.map((source) => ({
    ...JSON.parse(JSON.stringify(source)),
    id: randomId("edge"),
    source: idMap.get(String(source.source)),
    target: idMap.get(String(source.target)),
  }));
  state.workspace.nodes.push(...nodes);
  state.workspace.edges.push(...edges);
  state.dfdClipboard = { nodes: nodes.map((node) => JSON.parse(JSON.stringify(node))), edges: edges.map((edge) => JSON.parse(JSON.stringify(edge))) };
  setDfdNodeSelection(nodes.map((node) => node.id));
  markDfdDirty();
  renderDfdStepAndFocus();
}

function markAttackCasesDirty() {
  state.attackCasesDirty = true;
  const button = $("#confirm-threat-model");
  if (button) {
    button.disabled = false;
    button.textContent = "확정 완료";
  }
}

function toggleDfdFocusMode() {
  state.dfdFocusMode = !state.dfdFocusMode;
  $(".app-shell")?.classList.toggle("dfd-focus-mode", state.dfdFocusMode);
  $("#step-content")?.classList.toggle("dfd-focus-mode", state.dfdFocusMode);
  renderDfdStep();
  focusDfdCanvas();
}

const DFD_PLATFORM_COLUMNS = {
  0: {
    "E.1": 0, "E.2": 0,
    "P.1": 1,
    "P.2": 2,
    "P.3": 3, "P.4": 3,
    "P.5": 4,
    "P.7": 5, "P.6": 5,
    "D.1": 6, "D.4": 6,
  },
  1: {
    "E.1": 0, "E.2": 0,
    "P.1": 1,
    "P.2": 2,
    "P.3.1": 3, "P.3.2": 3, "P.4.1": 3, "P.4.2": 3, "P.4.3": 3,
    "P.5.1": 4, "P.5.2": 4,
    "P.5.3": 5, "P.5.4": 5,
    "P.5.5": 6, "P.5.6": 6, "P.8": 6,
    "P.7": 7, "P.6.1": 7,
    "D.1": 8, "D.2": 8, "D.3": 8, "D.4": 8, "DB.1": 8,
  },
};

const DFD_SHORT_LABELS = {
  "P.3.1": "Service 상태 감시",
  "P.3.2": "Service 트래픽 전달",
  "P.4.1": "Pod 수명주기",
  "P.4.2": "상태 보고",
  "P.4.3": "CRI Client",
  "P.5.1": "CRI/gRPC API",
  "P.5.2": "Metrics",
  "P.5.3": "Containerd Services",
  "P.5.4": "Metadata",
  "P.5.5": "Snapshotter",
  "P.5.6": "Containerd Shim",
  "P.6.1": "Container",
  "P.8": "Volume Manager",
  "DB.1": "BoltDB",
};

function dfdCanvasNodeLabel(node) {
  const fullName = nodeDisplayName(node);
  if (logicalManifestInstance(node)) return fullName;
  const shortName = DFD_SHORT_LABELS[String(node?.asset_type_id || "")];
  if (!shortName) return fullName;
  const assetName = assetDisplayName(node?.asset_type_id, fullName);
  return hasManifestEvidence(node) || fullName === assetName ? shortName : fullName;
}

function compactDfdCanvasLabel(value, limit = 22) {
  const text = String(value || "");
  return text.length > limit ? `${text.slice(0, Math.max(1, limit - 1))}…` : text;
}

function dfdNodeUsesManualSize(node) {
  return node?.properties?.layout?.manual_size === true;
}

function setDfdNodeManualSize(node, manual) {
  if (!node) return;
  const properties = node.properties && typeof node.properties === "object" ? { ...node.properties } : {};
  const layout = properties.layout && typeof properties.layout === "object" && !Array.isArray(properties.layout)
    ? { ...properties.layout }
    : {};
  if (manual) layout.manual_size = true;
  else delete layout.manual_size;
  if (Object.keys(layout).length) properties.layout = layout;
  else delete properties.layout;
  node.properties = properties;
}

function applyAutomaticDfdNodeSize(node) {
  if (!node) return { width: 172, height: 66, lines: [""] };
  const size = DFD_SELECTION.automaticNodeSize(dfdCanvasNodeLabel(node));
  node.width = size.width;
  node.height = size.height;
  return size;
}

function dfdNodeLabelLayout(value, width, height) {
  const maxChars = Math.max(8, Math.floor((Number(width || 150) - 30) / 7.5));
  const maxLines = Math.max(1, Math.floor((Number(height || 64) - 42) / 16));
  const lines = DFD_SELECTION.wrapLabel(value, maxChars, maxLines);
  const lineHeight = 16;
  const totalHeight = lines.length * lineHeight + 15;
  const firstBaseline = Math.max(17, (Number(height || 64) - totalHeight) / 2 + 12);
  return { lines, lineHeight, firstBaseline, typeBaseline: firstBaseline + lines.length * lineHeight + 1 };
}

function dfdNodeLabelMarkup(value, width, height) {
  const layout = dfdNodeLabelLayout(value, width, height);
  return `<text class="node-label" x="${width / 2}" y="${layout.firstBaseline}">${layout.lines.map((line, index) => `<tspan x="${width / 2}" dy="${index === 0 ? 0 : layout.lineHeight}">${escapeHtml(line)}</tspan>`).join("")}</text>`;
}

function nodeResizeHandlesMarkup(width, height) {
  const handles = [
    ["nw", 0, 0, "왼쪽 위"],
    ["ne", width, 0, "오른쪽 위"],
    ["se", width, height, "오른쪽 아래"],
    ["sw", 0, height, "왼쪽 아래"],
  ];
  return `<g class="node-resize-handles" aria-label="구성요소 크기 조절점">${handles.map(([direction, x, y, label]) => `<rect class="node-resize-handle" data-node-resize-handle="${direction}" x="${x - 5}" y="${y - 5}" width="10" height="10" rx="1"><title>${label} 방향으로 크기 조절</title></rect>`).join("")}</g>`;
}

function nodeConnectionPortsMarkup(width, height) {
  const ports = [
    ["left", -10, 10, 20, Math.max(20, height - 20), 0, height / 2],
    ["right", width - 10, 10, 20, Math.max(20, height - 20), width, height / 2],
    ["top", 10, -10, Math.max(20, width - 20), 20, width / 2, 0],
    ["bottom", 10, height - 10, Math.max(20, width - 20), 20, width / 2, height],
  ];
  return `<g class="node-connection-ports" aria-label="데이터 흐름 연결점">${ports.map(([side, x, y, hitWidth, hitHeight, cx, cy]) => `<g class="node-connection-port" data-connection-handle="${side}"><rect class="node-connection-hit" x="${x}" y="${y}" width="${hitWidth}" height="${hitHeight}"></rect><circle class="node-connection-handle" cx="${cx}" cy="${cy}" r="5"></circle><path class="node-connection-plus" d="M ${cx - 2.5} ${cy} H ${cx + 2.5} M ${cx} ${cy - 2.5} V ${cy + 2.5}"></path><title>여기서 끌어 데이터 흐름 연결</title></g>`).join("")}</g>`;
}

function dfdCatalogNode(node) {
  const level = Number(node?.properties?.catalog?.level);
  return level === 0 || level === 1;
}

function logicalManifestInstance(item) {
  return item?.properties?.manifest_projection?.mode === "LOGICAL_RESOURCE_INSTANCE";
}

function manifestGeneratedItem(item) {
  const collector = item?.properties?.collector;
  return Boolean(collector && typeof collector === "object" && (
    collector.generated === true
    || collector.generated_layer_id === "manifest-platform"
    || collector.generated_layer_id === "manifest-logical-system"
  ));
}

function hasManifestEvidence(item) {
  const collector = item?.properties?.collector;
  return Boolean(collector && typeof collector === "object" && (
    collector.source_type === "kubernetes_manifest"
    || collector.source === "kubernetes_manifest"
    || collector.generated_layer_id === "manifest-platform"
    || collector.generated_layer_id === "manifest-logical-system"
  ));
}

function platformCatalogSortOrder(node, level) {
  const entry = (state.bootstrap?.dfd_catalog_elements || []).find((item) => (
    Number(item?.level) === Number(level)
    && String(item?.asset_type_id || "") === String(node?.asset_type_id || "")
  ));
  return Number(entry?.sort_order ?? 9999);
}

function catalogReferenceNodes(level = currentDfdCatalogLevel()) {
  const columns = DFD_PLATFORM_COLUMNS[level] || DFD_PLATFORM_COLUMNS[0];
  const assets = dfdCatalogAssets(level);
  const grouped = new Map();
  assets.forEach((asset) => {
    const column = Number(columns[String(asset.id)] ?? 9);
    if (!grouped.has(column)) grouped.set(column, []);
    grouped.get(column).push(asset);
  });
  const maxRows = Math.max(1, ...[...grouped.values()].map((items) => items.length));
  const result = [];
  grouped.forEach((items, column) => {
    items.sort((left, right) => (
      platformCatalogSortOrder({ asset_type_id: left.id }, level) - platformCatalogSortOrder({ asset_type_id: right.id }, level)
      || assetDisplayName(left).localeCompare(assetDisplayName(right), "ko")
    ));
    const columnHeight = (items.length - 1) * 104;
    const availableHeight = (maxRows - 1) * 104;
    const startY = 104 + Math.max(0, (availableHeight - columnHeight) / 2);
    items.forEach((asset, index) => result.push({
      id: `reference:${level}:${asset.id}`,
      name: assetDisplayName(asset),
      asset_type_id: asset.id,
      asset_type_name: asset.name,
      dfd_kind: asset.dfd_kind,
      x: 70 + column * 216,
      y: startY + index * 104,
      width: 172,
      height: 66,
      description: asset.description || "",
    }));
  });
  return result;
}

function autoLayoutDfd(options = {}) {
  const level = currentDfdCatalogLevel();
  const requestedIds = options.nodeIds ? new Set(options.nodeIds.map((id) => String(id))) : null;
  const nodes = (state.workspace?.nodes || []).filter((node) => !requestedIds || requestedIds.has(String(node.id)));
  if (!nodes.length) return 0;
  const layoutNodeIds = new Set(nodes.map((node) => String(node.id)));
  const layoutEdges = (state.workspace?.edges || []).filter((edge) => layoutNodeIds.has(String(edge.source)) && layoutNodeIds.has(String(edge.target)));
  if (layoutEdges.length) {
    const preferredColumns = DFD_PLATFORM_COLUMNS[level] || {};
    const levelById = DFD_SELECTION.layeredLayoutColumns(nodes, layoutEdges, { preferredColumns });
    const levels = new Map();
    nodes.forEach((node) => {
      if (!dfdNodeUsesManualSize(node)) applyAutomaticDfdNodeSize(node);
      const levelIndex = Number(levelById[String(node.id)] || 0);
      if (!levels.has(levelIndex)) levels.set(levelIndex, []);
      levels.get(levelIndex).push(node);
    });
    [...levels.entries()].sort((left, right) => left[0] - right[0]).forEach(([column, items]) => {
      items.sort((left, right) => (
        platformCatalogSortOrder(left, level) - platformCatalogSortOrder(right, level)
        || Number(left.y || 0) - Number(right.y || 0)
        || nodeDisplayName(left).localeCompare(nodeDisplayName(right), "ko")
      ));
      items.forEach((node, row) => {
        node.x = 70 + column * 235;
        node.y = 90 + row * 122;
      });
    });
    state.dfdZoom = options.keepZoom ? state.dfdZoom : 0.9;
    state.dfdViewportX = 0;
    state.dfdViewportY = 0;
    state.dfdScrollLeft = 0;
    state.dfdScrollTop = 0;
    return nodes.length;
  }
  const references = new Map(catalogReferenceNodes(level).map((node) => [String(node.asset_type_id), node]));
  const duplicateCounts = new Map();
  const platformNodes = nodes.filter((node) => !logicalManifestInstance(node));
  platformNodes.sort((left, right) => platformCatalogSortOrder(left, level) - platformCatalogSortOrder(right, level));
  platformNodes.forEach((node, index) => {
    const key = String(node.asset_type_id || "");
    const duplicateIndex = duplicateCounts.get(key) || 0;
    duplicateCounts.set(key, duplicateIndex + 1);
    const reference = references.get(key);
    node.x = reference ? reference.x : 70 + (index % 5) * 216;
    node.y = reference ? reference.y + duplicateIndex * 76 : 104 + Math.floor(index / 5) * 104;
    if (!dfdNodeUsesManualSize(node)) applyAutomaticDfdNodeSize(node);
  });
  const logicalNodes = nodes.filter(logicalManifestInstance);
  const byKind = { external: [], process: [], data_store: [] };
  logicalNodes.forEach((node) => {
    const kind = Object.hasOwn(byKind, node.dfd_kind) ? node.dfd_kind : "process";
    byKind[kind].push(node);
  });
  Object.values(byKind).forEach((items) => items.sort((left, right) => (
    String(left?.properties?.kubernetes?.namespace || "").localeCompare(String(right?.properties?.kubernetes?.namespace || ""), "ko")
    || nodeDisplayName(left).localeCompare(nodeDisplayName(right), "ko")
  )));
  const startY = 390;
  byKind.external.forEach((node, index) => {
    node.x = 60; node.y = startY + index * 105;
    if (!dfdNodeUsesManualSize(node)) applyAutomaticDfdNodeSize(node);
  });
  const columns = byKind.process.length > 18 ? 4 : 3;
  byKind.process.forEach((node, index) => {
    node.x = 310 + (index % columns) * 210;
    node.y = startY + Math.floor(index / columns) * 105;
    if (!dfdNodeUsesManualSize(node)) applyAutomaticDfdNodeSize(node);
  });
  const storeX = 310 + columns * 210 + 90;
  byKind.data_store.forEach((node, index) => {
    node.x = storeX; node.y = startY + index * 105;
    if (!dfdNodeUsesManualSize(node)) applyAutomaticDfdNodeSize(node);
  });
  state.dfdZoom = options.keepZoom ? state.dfdZoom : 0.9;
  state.dfdViewportX = 0;
  state.dfdViewportY = 0;
  state.dfdScrollLeft = 0;
  state.dfdScrollTop = 0;
  return nodes.length;
}

function manifestRunSummaryMarkup() {
  const summary = state.manifestReviewSummary;
  if (!summary) return "";
  const issueCount = summary.issues.length;
  return `<details class="manifest-run-summary">
    <summary><span class="badge blue">Manifest 반영</span><strong>DFD 초안</strong><span>논리 구성요소 ${summary.nodes}개, 선언 기반 흐름 ${summary.edges}개</span>${issueCount ? `<span class="manifest-review-count">확인 필요 ${issueCount}</span>` : '<span class="badge green">확인 사항 없음</span>'}</summary>
    ${issueCount ? `<div><p>자동 확정하지 않은 내용입니다. 필요할 때만 확인하세요.</p><ul>${summary.issues.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>` : ""}
  </details>`;
}

function legacyManifestNoticeMarkup() {
  const legacyCount = (state.workspace?.nodes || []).filter((node) => (
    manifestGeneratedItem(node)
    && node?.properties?.manifest_projection?.mode !== "LOGICAL_RESOURCE_INSTANCE"
  )).length;
  if (!legacyCount) return "";
  return `<div class="legacy-manifest-notice"><span><strong>이전 방식의 Manifest 초안입니다.</strong> 다시 분석하면 상위 워크로드와 참조 저장소를 논리 구성요소로 그려 줍니다.</span><button type="button" class="btn small" id="refresh-legacy-manifest">Manifest 다시 분석</button></div>`;
}

function dfdPaletteMarkup() {
  const groups = new Map();
  manualDfdAssetChoices().forEach((asset) => {
    const groupName = asset.group_name || "일반";
    if (!groups.has(groupName)) groups.set(groupName, []);
    groups.get(groupName).push(asset);
  });
  const tools = `<div class="palette-group palette-tool-group">
    <h4>연결 및 경계</h4>
    <div class="palette-node palette-tool" role="button" tabindex="0" draggable="true" data-dfd-tool="flow" title="캔버스로 끌어 놓은 뒤 화살표 양쪽 끝을 구성요소에 연결하세요."><span class="palette-icon palette-flow-icon" aria-hidden="true">→</span><span><strong>데이터 흐름</strong><small>양쪽 끝을 요소에 연결</small></span></div>
    <div class="palette-node palette-tool" role="button" tabindex="0" draggable="true" data-dfd-tool="boundary" title="캔버스로 끌어 놓기"><span class="palette-icon palette-boundary-icon" aria-hidden="true">▭</span><span><strong>신뢰 경계</strong><small>영역을 묶어 경계 표시</small></span></div>
  </div>`;
  const content = [...groups.entries()].map(([groupName, assets]) => `
    <div class="palette-group">
      <h4>${escapeHtml(groupName)}</h4>
      ${assets.map((asset) => `<div class="palette-node" draggable="true" data-asset-id="${escapeHtml(asset.id)}" title="캔버스로 끌어 놓기"><span class="palette-icon" aria-hidden="true">${asset.dfd_kind === "external" ? "↗" : asset.dfd_kind === "data_store" ? "▱" : "◇"}</span><span>${escapeHtml(assetDisplayName(asset))}</span></div>`).join("")}
    </div>`).join("");
  return `<aside class="palette" aria-label="DFD 구성요소 팔레트"><div class="panel-title palette-title"><span>DFD 구성요소</span><button class="btn small palette-add-button" id="add-dfd-node" type="button" title="DFD 구성요소 추가">＋ 추가</button></div>${tools}${content || '<div class="empty-panel">사용 가능한 요소가 없습니다.</div>'}</aside>`;
}

function attackCaseEffectText(item) {
  if (item.intended_effect_code === "OTHER") return String(item.intended_effect || "").trim();
  return scopeOptionLabel("attack_objectives", item.intended_effect_code, item.intended_effect || "");
}

function attackCaseEntryIds(item) {
  const values = Array.isArray(item?.entry_node_ids)
    ? item.entry_node_ids
    : [item?.entry_node_id].filter(Boolean);
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
}

function attackCaseRoutes(item) {
  if (!item?.target_node_id) return [];
  return attackCaseEntryIds(item).map((entryId) => ({
    entryId,
    route: String(entryId) === String(item.target_node_id)
      ? []
      : shortestDfdPath(entryId, item.target_node_id),
  }));
}

function attackCaseDraftErrors(item, index) {
  const errors = [];
  const entryIds = attackCaseEntryIds(item);
  if (!entryIds.length || entryIds.some((id) => !workspaceNodeById(id))) errors.push("진입 지점을 하나 이상 선택하세요.");
  if (!workspaceNodeById(item.target_node_id)) errors.push("공격 대상을 선택하세요.");
  if (item.target_node_id && entryIds.includes(String(item.target_node_id))) errors.push("한 Case의 Entry Point와 Intended Target은 달라야 합니다.");
  const routes = attackCaseRoutes(item);
  const missingRoutes = routes.filter((entry) => !entry.route.length);
  if (entryIds.length && workspaceNodeById(item.target_node_id) && missingRoutes.length && !item.manual_path_confirmed) errors.push("방향 경로가 없는 Entry Point가 있어 수동 경로 확인이 필요합니다.");
  if (missingRoutes.length && item.manual_path_confirmed && !String(item.rationale || "").trim()) errors.push("DFD에 없는 경로의 근거를 입력하세요.");
  const identity = `${[...entryIds].sort().join("\u001f")}\u0000${String(item.target_node_id)}\u0000${attackCaseEffectText(item)}`;
  if (entryIds.length && item.target_node_id && state.attackCaseDrafts.some((other, otherIndex) => otherIndex < index && `${[...attackCaseEntryIds(other)].sort().join("\u001f")}\u0000${String(other.target_node_id)}\u0000${attackCaseEffectText(other)}` === identity)) errors.push("같은 Entry Point 목록 → Intended Target의 Case가 이미 있습니다.");
  return errors;
}

function attackCaseEndpointNodes(item, role) {
  const entryIds = attackCaseEntryIds(item);
  const excluded = new Set(role === "entry" ? [String(item.target_node_id || "")] : entryIds);
  const targetId = String(item.target_node_id || "");
  return [...(state.workspace?.nodes || [])]
    .filter((node) => !excluded.has(String(node.id)))
    .sort((left, right) => {
      if (role !== "entry" || !targetId) return nodeDisplayName(left).localeCompare(nodeDisplayName(right), "ko");
      const leftReachable = shortestDfdPath(left.id, targetId).length ? 0 : 1;
      const rightReachable = shortestDfdPath(right.id, targetId).length ? 0 : 1;
      return leftReachable - rightReachable || nodeDisplayName(left).localeCompare(nodeDisplayName(right), "ko");
    });
}

function attackCaseEndpointPicker(item, role) {
  const entryIds = attackCaseEntryIds(item);
  const selectedIds = role === "entry" ? entryIds : [String(item.target_node_id || "")].filter(Boolean);
  const selectedNames = selectedIds.map((id) => nodeDisplayName(id)).filter(Boolean);
  const disabled = role === "target" && !entryIds.length;
  const summary = selectedNames.length
    ? (role === "entry" && selectedNames.length > 1 ? `${selectedNames[0]} 외 ${selectedNames.length - 1}개` : selectedNames[0])
    : "검색하여 선택";
  const nodes = attackCaseEndpointNodes(item, role);
  const query = String(item[`${role}_search`] || "");
  const options = nodes.map((node) => {
    const nodeId = String(node.id);
    const selected = selectedIds.includes(nodeId);
    const routeMissing = role === "entry" && item.target_node_id && !shortestDfdPath(node.id, item.target_node_id).length;
    const control = role === "entry"
      ? `<input type="checkbox" data-case-entry="${escapeHtml(item.draftKey)}" value="${escapeHtml(nodeId)}" ${selected ? "checked" : ""}>`
      : `<input type="radio" name="case-target-${escapeHtml(item.draftKey)}" data-case-target-option="${escapeHtml(item.draftKey)}" value="${escapeHtml(nodeId)}" ${selected ? "checked" : ""}>`;
    return `<label class="attack-case-picker-option ${selected ? "selected" : ""}" data-case-picker-option data-search-text="${escapeHtml(`${nodeDisplayName(node)} ${nodeId}`.toLocaleLowerCase("ko"))}">${control}<span>${escapeHtml(nodeDisplayName(node))}</span>${routeMissing ? '<small>방향 경로 없음</small>' : ""}</label>`;
  }).join("");
  return `<details class="attack-case-picker ${disabled ? "disabled" : ""}" data-case-picker="${role}" data-case-key="${escapeHtml(item.draftKey)}" ${disabled ? 'aria-disabled="true"' : ""}>
    <summary><span class="attack-case-picker-value ${selectedNames.length ? "" : "placeholder"}">${escapeHtml(summary)}</span><span class="attack-case-picker-caret" aria-hidden="true">⌄</span></summary>
    <div class="attack-case-picker-menu"><input type="search" data-case-picker-search="${role}" data-case-key="${escapeHtml(item.draftKey)}" value="${escapeHtml(query)}" placeholder="구성요소 이름 검색" autocomplete="off"><div class="attack-case-picker-options" role="${role === "entry" ? "group" : "radiogroup"}">${options || '<div class="attack-case-picker-empty">선택할 구성요소가 없습니다.</div>'}</div><div class="attack-case-picker-no-result" hidden>검색 결과가 없습니다.</div></div>
  </details>`;
}

function attackCaseCardMarkup(item, index) {
  const entryIds = attackCaseEntryIds(item);
  const routes = attackCaseRoutes(item);
  const completeEndpoints = entryIds.length && workspaceNodeById(item.target_node_id) && !entryIds.includes(String(item.target_node_id));
  const errors = attackCaseDraftErrors(item, index);
  const effectOptions = attackCaseObjectiveOptions();
  const missingRoutes = routes.filter((entry) => !entry.route.length);
  const routeMarkup = completeEndpoints
    ? `<div class="attack-case-route ${missingRoutes.length ? "warning" : "valid"}"><strong>DFD 방향 경로</strong><div class="attack-case-route-list">${routes.map((entry) => `<span>${escapeHtml(entry.route.length ? nodePathLabel(entry.route) : `${nodeDisplayName(entry.entryId)} → ${nodeDisplayName(item.target_node_id)} (DFD 경로 없음)`)}</span>`).join("")}</div><small>후보 AV를 찾는 구성요소 범위이며 실제 공격 가능성의 증명은 아닙니다.</small>${missingRoutes.length ? `<label><input type="checkbox" data-case-manual-path="${escapeHtml(item.draftKey)}" ${item.manual_path_confirmed ? "checked" : ""}> DFD 외 경로가 존재함을 별도 근거로 확인</label>` : ""}</div>`
    : `<div class="attack-case-route pending"><strong>경로 대기 중</strong><span>Entry Point를 하나 이상 고른 뒤 Intended Target을 선택하세요.</span></div>`;
  return `<article class="attack-case-card ${errors.length ? "incomplete" : "complete"}" data-attack-case-card="${escapeHtml(item.draftKey)}">
    <div class="attack-case-card-head"><div><span class="attack-case-number">${index + 1}</span><strong>Attack Case ${index + 1}</strong><span class="badge ${errors.length ? "orange" : "green"}">${errors.length ? "입력 필요" : "확정 가능"}</span></div><button type="button" class="btn small danger" data-remove-attack-case="${escapeHtml(item.draftKey)}">삭제</button></div>
    <div class="attack-case-endpoints">
      <div class="form-field"><label class="required">1. Entry Point <span class="label-note">복수 선택 가능</span></label>${attackCaseEndpointPicker(item, "entry")}<span class="input-help">검색한 구성요소를 하나 이상 선택합니다.</span></div>
      <div class="attack-case-arrow" aria-hidden="true">→</div>
      <div class="form-field"><label class="required">2. Intended Target <span class="label-note">단일 선택</span></label>${attackCaseEndpointPicker(item, "target")}<span class="input-help">Entry Point를 고른 다음 하나를 선택합니다.</span></div>
    </div>
    ${routeMarkup}
    <details class="attack-case-context" ${item.rationale || item.intended_effect_code === "OTHER" || missingRoutes.length ? "open" : ""}><summary>평가 맥락 추가 <span>선택 사항${missingRoutes.length ? ", DFD 외 경로 근거는 필수" : ""}</span></summary><div class="attack-case-details">
      <div class="form-field"><label>공격 목적/예상 효과</label><select data-case-effect="${escapeHtml(item.draftKey)}">${effectOptions.map((option) => `<option value="${escapeHtml(option.code)}" ${option.code === item.intended_effect_code ? "selected" : ""}>${escapeHtml(option.label)}</option>`).join("")}</select><span class="input-help">비워 보내면 Scope Brief의 공격 의도를 적용합니다.</span></div>
      <div class="form-field ${item.intended_effect_code === "OTHER" ? "" : "hidden"}" data-case-custom-effect-wrap="${escapeHtml(item.draftKey)}"><label>직접 입력</label><input data-case-custom-effect="${escapeHtml(item.draftKey)}" value="${escapeHtml(item.intended_effect || "")}" placeholder="예: 호스트 자격 증명 탈취"></div>
      <div class="form-field rationale"><label class="${missingRoutes.length ? "required" : ""}">선정 근거${missingRoutes.length ? "" : " (선택)"}</label><textarea data-case-rationale="${escapeHtml(item.draftKey)}" placeholder="DFD 경로 외에 남길 평가 근거가 있을 때 입력합니다.">${escapeHtml(item.rationale || "")}</textarea></div>
    </div></details>
    ${errors.length ? `<div class="attack-case-errors">${errors.map((error) => `<span>${escapeHtml(error)}</span>`).join("")}</div>` : ""}
  </article>`;
}

function attackCaseBuilderMarkup() {
  const scope = scopeBriefDisplay();
  const cards = state.attackCaseDrafts.map(attackCaseCardMarkup).join("");
  const complete = state.attackCaseDrafts.filter((item, index) => !attackCaseDraftErrors(item, index).length).length;
  const legacyCount = (state.workspace?.attack_cases || []).filter((item) => String(item.status || "").toUpperCase() === "LEGACY_REVIEW_REQUIRED").length;
  const legacyNotice = legacyCount
    ? `<div class="notice warning attack-case-legacy-notice"><div>!</div><div><strong>이전 Target 집계형 결과 ${legacyCount}개를 읽기 전용으로 보존했습니다.</strong>각 항목의 Entry Point와 의도한 효과를 확인한 뒤 Attack Case 전체를 다시 확정해야 다음 단계로 진행할 수 있습니다.</div></div>`
    : "";
  return `<section class="attack-case-builder" id="attack-case-builder">
    <div class="attack-case-builder-head"><div><span class="section-kicker">DFD 작성 후</span><h2>Attack Case별 Entry / Target 지정</h2><p>각 Case에서 Entry Point를 하나 이상 고른 뒤 Intended Target을 선택하세요.</p></div><button type="button" class="btn" id="add-attack-case">+ Attack Case 추가</button></div>
    ${legacyNotice}
    <div class="attack-case-actor"><span>Scope 위협 행위자</span><strong>${escapeHtml(scope.actorType)}</strong><span>Scope 공격 목표</span><strong>${escapeHtml(scope.objectives)}</strong><em>모든 Case에 현재 Scope Brief가 자동 적용됩니다.</em></div>
    <div class="attack-case-workbench">${attackCaseDfdPreviewMarkup()}<div class="attack-case-list">${cards || emptyState("Attack Case가 없습니다", "DFD를 완성한 뒤 평가할 Entry → Target 조합을 추가하세요.")}</div></div>
    <div class="attack-case-builder-footer"><span>${complete}/${state.attackCaseDrafts.length}개 입력 완료</span><button type="button" class="btn primary" id="confirm-threat-model">확정 완료</button></div>
  </section>`;
}

function attackCaseDfdPreviewMarkup() {
  if (!state.attackCaseDrafts.length || !state.workspace.nodes.length) return "";
  const active = attackCaseDraftByKey(state.activeAttackCaseDraftId) || state.attackCaseDrafts[0];
  state.activeAttackCaseDraftId = active.draftKey;
  const entries = new Set(attackCaseEntryIds(active).map(String));
  const target = String(active.target_node_id || "");
  const canvasWidth = Math.max(760, ...state.workspace.nodes.map((node) => Number(node.x) + Number(node.width || 172) + 50));
  const canvasHeight = Math.max(440, ...state.workspace.nodes.map((node) => Number(node.y) + Number(node.height || 70) + 50));
  const offsets = edgeCurveOffsets(state.workspace.edges);
  const edges = state.workspace.edges.map((edge, index) => {
    const source = workspaceNodeById(edge.source); const destination = workspaceNodeById(edge.target);
    if (!source || !destination) return "";
    return `<path d="${edgeCurveGeometry(source, destination, offsets[index]).path}" marker-end="url(#case-arrow)"></path>`;
  }).join("");
  const nodes = state.workspace.nodes.map((node) => {
    const width = Number(node.width || 172); const height = Number(node.height || 70);
    const classes = [entries.has(String(node.id)) ? "is-entry" : "", target === String(node.id) ? "is-target" : ""].filter(Boolean).join(" ");
    return `<g class="case-preview-node ${classes}" data-case-preview-node="${escapeHtml(node.id)}" transform="translate(${Number(node.x)},${Number(node.y)})" role="button" tabindex="0"><rect width="${width}" height="${height}" rx="9"></rect><text x="${width / 2}" y="${height / 2 + 5}">${escapeHtml(compactDfdCanvasLabel(nodeDisplayName(node), 24))}</text></g>`;
  }).join("");
  const options = state.attackCaseDrafts.map((item, index) => `<option value="${escapeHtml(item.draftKey)}" ${item.draftKey === active.draftKey ? "selected" : ""}>Attack Case ${index + 1}</option>`).join("");
  return `<aside class="attack-case-dfd-preview"><div class="attack-case-preview-head"><div><strong>DFD에서 역할 지정</strong><span>구성요소를 클릭하면 현재 역할로 지정됩니다.</span></div><select id="case-preview-active" aria-label="DFD에 표시할 Attack Case">${options}</select></div><div class="case-role-mode" role="group" aria-label="지정할 역할"><button type="button" class="btn ${state.attackCaseRoleMode === "entry" ? "primary" : ""}" data-case-role-mode="entry">Entry Point</button><button type="button" class="btn ${state.attackCaseRoleMode === "target" ? "primary" : ""}" data-case-role-mode="target">Intended Target</button></div><div class="attack-case-preview-canvas"><svg viewBox="0 0 ${canvasWidth} ${canvasHeight}" preserveAspectRatio="xMidYMid meet"><defs><marker id="case-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker></defs><g class="case-preview-edges">${edges}</g>${nodes}</svg></div><div class="case-preview-legend"><span><i class="entry"></i>Entry Point ${entries.size}</span><span><i class="target"></i>Intended Target ${target ? 1 : 0}</span></div></aside>`;
}

function rerenderDfdAtAttackCase(key, reopenPicker = null) {
  const page = $(".dfd-page-body");
  const scrollTop = page?.scrollTop || 0;
  const windowScroll = { x: window.scrollX, y: window.scrollY };
  const pickerRequest = typeof reopenPicker === "string" ? { role: reopenPicker } : reopenPicker;
  state.activeAttackCaseDraftId = key;
  renderDfdStep();
  const nextPage = $(".dfd-page-body");
  const restoreViewport = () => {
    if (nextPage) nextPage.scrollTop = scrollTop;
    window.scrollTo(windowScroll.x, windowScroll.y);
  };
  restoreViewport();
  if (typeof requestAnimationFrame === "function") requestAnimationFrame(restoreViewport);
  if (pickerRequest?.role) {
    const picker = $$('[data-case-picker]').find((element) => (
      element.dataset.casePicker === pickerRequest.role && element.dataset.caseKey === String(key)
    ));
    if (picker && !picker.classList.contains("disabled")) {
      picker.open = true;
      const search = picker.querySelector('[data-case-picker-search]');
      search?.dispatchEvent(new Event("input"));
      const options = picker.querySelector(".attack-case-picker-options");
      const restore = () => {
        if (options && Number.isFinite(Number(pickerRequest.optionsScrollTop))) {
          options.scrollTop = Number(pickerRequest.optionsScrollTop);
        }
        const selectedInput = pickerRequest.focusValue
          ? $$('[data-case-entry]', picker).find((entry) => String(entry.value) === String(pickerRequest.focusValue))
          : null;
        (selectedInput || search)?.focus({ preventScroll: true });
        if (options && Number.isFinite(Number(pickerRequest.optionsScrollTop))) {
          options.scrollTop = Number(pickerRequest.optionsScrollTop);
        }
        restoreViewport();
      };
      restore();
      if (typeof requestAnimationFrame === "function") requestAnimationFrame(restore);
    }
  }
}

function bindAttackCaseBuilder() {
  if (!attackCasePickerDismissBound) {
    document.addEventListener("pointerdown", (event) => {
      $$('[data-case-picker][open]').forEach((picker) => {
        if (!picker.contains(event.target)) picker.open = false;
      });
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      const openPickers = $$('[data-case-picker][open]');
      if (!openPickers.length) return;
      openPickers.forEach((picker) => { picker.open = false; });
      openPickers[0].querySelector("summary")?.focus();
      event.preventDefault();
    });
    attackCasePickerDismissBound = true;
  }
  $("#case-preview-active")?.addEventListener("change", (event) => rerenderDfdAtAttackCase(event.target.value));
  $$('[data-case-role-mode]').forEach((button) => button.onclick = () => {
    state.attackCaseRoleMode = button.dataset.caseRoleMode;
    rerenderDfdAtAttackCase(state.activeAttackCaseDraftId);
  });
  const selectPreviewNode = (nodeId) => {
    const item = attackCaseDraftByKey(state.activeAttackCaseDraftId) || state.attackCaseDrafts[0];
    if (!item || !workspaceNodeById(nodeId)) return;
    if (state.attackCaseRoleMode === "target") {
      item.target_node_id = String(nodeId);
      item.entry_node_ids = attackCaseEntryIds(item).filter((id) => String(id) !== String(nodeId));
      item.entry_node_id = item.entry_node_ids[0] || "";
    } else {
      if (String(item.target_node_id || "") === String(nodeId)) item.target_node_id = "";
      const entries = new Set(attackCaseEntryIds(item));
      if (entries.has(String(nodeId))) entries.delete(String(nodeId)); else entries.add(String(nodeId));
      item.entry_node_ids = [...entries];
      item.entry_node_id = item.entry_node_ids[0] || "";
    }
    item.manual_path_confirmed = false;
    markAttackCasesDirty();
    rerenderDfdAtAttackCase(item.draftKey);
  };
  $$('[data-case-preview-node]').forEach((node) => {
    node.onclick = () => selectPreviewNode(node.dataset.casePreviewNode);
    node.onkeydown = (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      selectPreviewNode(node.dataset.casePreviewNode);
    };
  });
  $("#add-attack-case")?.addEventListener("click", () => {
    const firstEffect = attackCaseObjectiveOptions()[0] || { code: "OTHER", label: "" };
    const item = normalizeAttackCaseDraft({
      name: `Attack Case ${state.attackCaseDrafts.length + 1}`,
      intended_effect_code: firstEffect.code,
      intended_effect: firstEffect.code === "OTHER" ? "" : firstEffect.label,
    }, state.attackCaseDrafts.length);
    state.attackCaseDrafts.push(item);
    markAttackCasesDirty();
    rerenderDfdAtAttackCase(item.draftKey);
  });
  $$('[data-remove-attack-case]').forEach((button) => button.onclick = () => {
    const item = attackCaseDraftByKey(button.dataset.removeAttackCase);
    if (!item) return;
    if ((item.id || attackCaseEntryIds(item).length || item.target_node_id || item.rationale) && !window.confirm("이 Attack Case를 삭제할까요?")) return;
    const removedIndex = state.attackCaseDrafts.indexOf(item);
    const previousActiveKey = state.activeAttackCaseDraftId;
    state.attackCaseDrafts = state.attackCaseDrafts.filter((entry) => entry !== item);
    const nextActive = attackCaseDraftByKey(previousActiveKey)
      || state.attackCaseDrafts[removedIndex]
      || state.attackCaseDrafts[removedIndex - 1]
      || state.attackCaseDrafts[0]
      || null;
    markAttackCasesDirty();
    rerenderDfdAtAttackCase(nextActive?.draftKey || null);
  });
  $$('[data-case-target-option]').forEach((input) => input.onchange = () => {
    const item = attackCaseDraftByKey(input.dataset.caseTargetOption);
    if (!item) return;
    item.target_node_id = input.value;
    item.target_search = "";
    item.entry_node_ids = attackCaseEntryIds(item).filter((entryId) => String(entryId) !== String(item.target_node_id));
    item.entry_node_id = item.entry_node_ids[0] || "";
    item.manual_path_confirmed = false;
    markAttackCasesDirty();
    rerenderDfdAtAttackCase(item.draftKey);
  });
  $$('[data-case-entry]').forEach((input) => input.onchange = () => {
    const item = attackCaseDraftByKey(input.dataset.caseEntry);
    if (!item) return;
    const optionsScrollTop = input.closest(".attack-case-picker-options")?.scrollTop || 0;
    const selected = new Set(attackCaseEntryIds(item));
    if (input.checked) selected.add(String(input.value));
    else selected.delete(String(input.value));
    item.entry_node_ids = [...selected];
    item.entry_node_id = item.entry_node_ids[0] || "";
    if (item.entry_node_ids.includes(String(item.target_node_id))) item.target_node_id = "";
    item.manual_path_confirmed = false;
    markAttackCasesDirty();
    rerenderDfdAtAttackCase(item.draftKey, { role: "entry", optionsScrollTop, focusValue: input.value });
  });
  $$('[data-case-picker-search]').forEach((input) => input.oninput = () => {
    const item = attackCaseDraftByKey(input.dataset.caseKey);
    if (item) item[`${input.dataset.casePickerSearch}_search`] = input.value;
    const menu = input.closest(".attack-case-picker-menu");
    const query = input.value.trim().toLocaleLowerCase("ko");
    const options = [...(menu?.querySelectorAll('[data-case-picker-option]') || [])];
    let visible = 0;
    options.forEach((option) => {
      const match = !query || String(option.dataset.searchText || "").includes(query);
      option.hidden = !match;
      if (match) visible += 1;
    });
    const noResult = menu?.querySelector(".attack-case-picker-no-result");
    if (noResult) noResult.hidden = visible > 0;
  });
  $$('[data-case-picker]').forEach((picker) => {
    const summary = picker.querySelector("summary");
    if (picker.classList.contains("disabled")) summary.onclick = (event) => event.preventDefault();
    picker.ontoggle = () => {
      if (!picker.open) return;
      $$('[data-case-picker]').forEach((other) => { if (other !== picker) other.open = false; });
      const search = picker.querySelector('[data-case-picker-search]');
      search?.dispatchEvent(new Event("input"));
      setTimeout(() => search?.focus({ preventScroll: true }), 0);
    };
    picker.onfocusout = () => setTimeout(() => {
      if (!picker.contains(document.activeElement)) picker.open = false;
    }, 0);
  });
  $$('[data-case-effect]').forEach((select) => select.onchange = () => {
    const item = attackCaseDraftByKey(select.dataset.caseEffect);
    if (!item) return;
    item.intended_effect_code = select.value;
    item.intended_effect = select.value === "OTHER" ? "" : scopeOptionLabel("attack_objectives", select.value, "");
    markAttackCasesDirty();
    rerenderDfdAtAttackCase(item.draftKey);
  });
  $$('[data-case-custom-effect]').forEach((input) => input.oninput = () => { const item = attackCaseDraftByKey(input.dataset.caseCustomEffect); if (item) { item.intended_effect = input.value; markAttackCasesDirty(); } });
  $$('[data-case-rationale]').forEach((input) => input.oninput = () => { const item = attackCaseDraftByKey(input.dataset.caseRationale); if (item) { item.rationale = input.value; markAttackCasesDirty(); } });
  $$('[data-case-manual-path]').forEach((input) => input.onchange = () => { const item = attackCaseDraftByKey(input.dataset.caseManualPath); if (item) { item.manual_path_confirmed = input.checked; markAttackCasesDirty(); } });
}

function renderAttackCaseStep() {
  loadAttackCaseDrafts();
  const alreadyConfirmed = state.workspace.assessment.threat_model_confirmed && !state.dfdSemanticDirty && !state.attackCasesDirty;
  $("#step-content").innerHTML = `${pageHeader("1.1 사이버 위협 모델 수립", "저장한 DFD를 기준으로 Attack Case를 정의합니다.", `<button class="btn" id="edit-dfd">DFD 수정</button>`)}
    <div class="page-body attack-case-page">${attackCaseBuilderMarkup()}</div>`;
  bindAttackCaseBuilder();
  $("#edit-dfd").onclick = () => { state.dfdView = "MODEL"; renderDfdStep(); };
  const confirmButton = $("#confirm-threat-model");
  if (alreadyConfirmed && confirmButton) {
    confirmButton.disabled = false;
    confirmButton.textContent = "후보 공격 벡터로 이동";
    confirmButton.onclick = () => {
      state.step = 2;
      state.candidatePage = 1;
      renderWorkspace();
    };
  } else if (confirmButton) {
    confirmButton.onclick = confirmThreatModel;
  }
}

function renderDfdStep() {
  if (state.dfdView === "CASES") {
    renderAttackCaseStep();
    return;
  }
  const previousScrollArea = $(".canvas-scroll-area");
  if (previousScrollArea) {
    state.dfdScrollLeft = previousScrollArea.scrollLeft;
    state.dfdScrollTop = previousScrollArea.scrollTop;
  }
  loadAttackCaseDrafts();
  const connectionGuide = state.connectionMode
    ? state.connectionSource
      ? `<strong>출발: ${escapeHtml(nodeDisplayName(state.connectionSource))}</strong><span>연결할 도착 요소를 선택하세요.</span>`
      : `<strong>데이터 흐름 연결</strong><span>먼저 출발 요소를 선택하세요.</span>`
    : "";
  const zoomLabel = state.dfdZoom === null ? "화면 맞춤" : `${Math.round(state.dfdZoom * 100)}%`;
  const handIcon = `<svg class="canvas-hand-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M8.2 11V5.8a1.4 1.4 0 0 1 2.8 0V10 4.6a1.4 1.4 0 0 1 2.8 0V10 5.4a1.4 1.4 0 0 1 2.8 0v5.1-3.3a1.4 1.4 0 0 1 2.8 0v6.2c0 4.2-2.7 7.1-6.8 7.1h-1.1c-2.4 0-4.1-1-5.5-2.8l-3-3.8a1.5 1.5 0 0 1 2.2-2l3 2.4V11Z"/></svg>`;
  $("#step-content").innerHTML = `${pageHeader("1.1 사이버 위협 모델 수립", "구성요소와 데이터 흐름을 확인한 뒤 다음 화면에서 Attack Case를 정의합니다.", `<button class="btn collector-launch" id="manifest-collector">Manifest 분석</button><button class="btn primary" id="save-dfd">DFD 저장 후 다음</button>`)}
    <div class="page-body dfd-page-body">${legacyManifestNoticeMarkup()}${manifestRunSummaryMarkup()}${state.connectionMode ? `<div class="workflow-guide is-active">${connectionGuide}</div>` : ""}<div class="dfd-layout">
      ${dfdPaletteMarkup()}
      <section class="canvas-wrap ${state.dfdPanMode ? "pan-mode" : ""}">
        <div class="canvas-command-bar">
          <div class="canvas-zoom-toolbar" aria-label="DFD 보기 및 편집 설정"><button class="btn small" id="dfd-zoom-out" aria-label="축소">−</button><strong>${zoomLabel}</strong><button class="btn small" id="dfd-zoom-in" aria-label="확대">＋</button><button class="btn small" id="dfd-zoom-fit">화면 맞춤</button><span class="canvas-toolbar-divider" aria-hidden="true"></span><button class="btn small canvas-pan-toggle ${state.dfdPanMode ? "primary" : ""}" id="dfd-pan-mode" type="button" aria-pressed="${state.dfdPanMode ? "true" : "false"}" title="켜면 캔버스를 드래그해 이동합니다. Space+드래그 또는 마우스 가운데 버튼도 사용할 수 있습니다.">${handIcon}<span>화면 이동</span></button><button class="btn small" id="auto-layout-dfd" type="button">자동 정렬</button><span class="canvas-toolbar-divider" aria-hidden="true"></span><button class="btn small dfd-focus-toggle" id="dfd-focus-toggle" type="button" aria-pressed="${state.dfdFocusMode ? "true" : "false"}">${state.dfdFocusMode ? "전체 화면 종료" : "DFD 전체 화면"}</button></div>
        </div>
        <div class="canvas-scroll-area">${dfdSvg()}</div>
        ${state.workspace.nodes.length ? "" : '<div class="canvas-hint">왼쪽 요소를 끌어 놓거나 Manifest를 분석해 DFD를 구성할 수 있습니다.</div>'}
      </section>
      <aside class="inspector"><div class="panel-title"><span>속성</span></div><div class="inspector-body">${inspectorMarkup()}</div></aside>
    </div></div>`;
  const collectorSelected = state.selected?.type === "node"
    ? nodeById(state.selected.id)
    : state.selected?.type === "edge"
      ? state.workspace.edges.find((item) => item.id === state.selected.id)
      : null;
  const collectorBadge = collectorInspectorBadge(collectorSelected);
  if (collectorBadge) $(".inspector-body")?.insertAdjacentHTML("afterbegin", collectorBadge);
  const scrollArea = $(".canvas-scroll-area");
  syncDfdCanvasViewport(scrollArea);
  disconnectDfdGridResizeObserver();
  if (typeof ResizeObserver === "function") {
    dfdGridResizeObserver = new ResizeObserver(() => scheduleDfdCanvasViewportSync(scrollArea));
    dfdGridResizeObserver.observe(scrollArea.closest(".canvas-wrap") || scrollArea);
  }
  scrollArea.scrollLeft = state.dfdScrollLeft;
  scrollArea.scrollTop = state.dfdScrollTop;
  scrollArea.onscroll = () => {
    state.dfdScrollLeft = scrollArea.scrollLeft;
    state.dfdScrollTop = scrollArea.scrollTop;
  };
  $("#dfd-pan-mode").onclick = () => {
    state.dfdPanMode = !state.dfdPanMode;
    if (state.dfdPanMode) {
      state.connectionMode = false;
      state.connectionSource = null;
    }
    renderDfdStepAndFocus();
  };
  $("#manifest-collector").onclick = showManifestCollectorModal;
  $("#add-dfd-node").onclick = showDfdNodeModal;
  if ($("#refresh-legacy-manifest")) $("#refresh-legacy-manifest").onclick = showManifestCollectorModal;
  $("#auto-layout-dfd").onclick = () => {
    const count = autoLayoutDfd();
    if (!count) { toast("정렬할 DFD 구성요소가 없습니다."); return; }
    markDfdDirty();
    renderDfdStep();
    toast(`DFD 구성요소 ${count}개를 정렬했습니다.`);
  };
  $("#dfd-focus-toggle").onclick = toggleDfdFocusMode;
  $("#save-dfd").onclick = async () => {
    if (state.dfdPendingFlow) {
      toast("작성 중인 데이터 흐름의 양쪽 끝을 연결하거나 Esc로 취소해 주세요.", true);
      focusDfdCanvas();
      return;
    }
    if (!(await saveDfd(false))) return;
    state.dfdView = "CASES";
    renderDfdStep();
    toast("DFD를 저장했습니다. Attack Case를 지정해 주세요.");
  };
  // 툴바 이벤트를 캔버스 세부 이벤트보다 먼저 연결한다.
  bindDfdEvents();
}

function syncDfdCanvasViewport(scrollArea = $(".canvas-scroll-area")) {
  const canvas = scrollArea?.querySelector("#dfd-canvas");
  const background = canvas?.querySelector(".canvas-background");
  const nominalWidth = Number(canvas?.dataset.workspaceWidth);
  const nominalHeight = Number(canvas?.dataset.workspaceHeight);
  const viewportWidth = scrollArea?.clientWidth;
  const viewportHeight = scrollArea?.clientHeight;
  if (!scrollArea || !canvas || !background
      || !nominalWidth || !nominalHeight || !viewportWidth || !viewportHeight) return;

  let logicalWidth;
  let logicalHeight;
  let renderedWidth;
  let renderedHeight;
  if (state.dfdZoom === null) {
    const scale = Math.min(viewportWidth / nominalWidth, viewportHeight / nominalHeight);
    if (!Number.isFinite(scale) || scale <= 0) return;
    logicalWidth = viewportWidth / scale;
    logicalHeight = viewportHeight / scale;
    renderedWidth = viewportWidth;
    renderedHeight = viewportHeight;
  } else {
    const zoom = Math.max(0.5, Math.min(2, Number(state.dfdZoom) || 1));
    logicalWidth = Math.max(nominalWidth, viewportWidth / zoom);
    logicalHeight = Math.max(nominalHeight, viewportHeight / zoom);
    renderedWidth = logicalWidth * zoom;
    renderedHeight = logicalHeight * zoom;
  }

  const viewportX = Number.isFinite(Number(state.dfdViewportX)) ? Number(state.dfdViewportX) : 0;
  const viewportY = Number.isFinite(Number(state.dfdViewportY)) ? Number(state.dfdViewportY) : 0;
  const viewBox = `${viewportX} ${viewportY} ${logicalWidth} ${logicalHeight}`;
  const width = `${Math.round(renderedWidth * 1000) / 1000}px`;
  const height = `${Math.round(renderedHeight * 1000) / 1000}px`;
  const backgroundWidth = String(logicalWidth);
  const backgroundHeight = String(logicalHeight);
  if (canvas.getAttribute("viewBox") !== viewBox) canvas.setAttribute("viewBox", viewBox);
  if (canvas.style.width !== width) canvas.style.width = width;
  if (canvas.style.height !== height) canvas.style.height = height;
  if (background.getAttribute("width") !== backgroundWidth) background.setAttribute("width", backgroundWidth);
  if (background.getAttribute("height") !== backgroundHeight) background.setAttribute("height", backgroundHeight);
  if (background.getAttribute("x") !== String(viewportX)) background.setAttribute("x", String(viewportX));
  if (background.getAttribute("y") !== String(viewportY)) background.setAttribute("y", String(viewportY));
}

function collectorProposal(response) {
  const source = response?.proposal && typeof response.proposal === "object" ? response.proposal : (response || {});
  return {
    ...source,
    run_id: source.run_id ?? response?.run_id ?? "",
    summary: source.summary ?? response?.summary ?? null,
    namespaces: Array.isArray(source.namespaces) ? source.namespaces : [],
    nodes: Array.isArray(source.nodes) ? source.nodes : [],
    edges: Array.isArray(source.edges) ? source.edges : [],
    flow_candidates: Array.isArray(source.flow_candidates) ? source.flow_candidates : [],
    boundaries: Array.isArray(source.boundaries) ? source.boundaries : [],
    platform_template: source.platform_template && typeof source.platform_template === "object" ? source.platform_template : null,
    apply_strategy: source.apply_strategy && typeof source.apply_strategy === "object" ? source.apply_strategy : null,
    warnings: Array.isArray(source.warnings) ? source.warnings : [],
    unresolved: Array.isArray(source.unresolved) ? source.unresolved : [],
  };
}

function collectorItemId(item) {
  const value = item?.id ?? item?.node_id ?? item?.edge_id ?? item?.boundary_id;
  return value === undefined || value === null ? "" : String(value);
}

function collectorEdgeEndpoint(edge, side) {
  const camel = side === "source" ? "sourceNodeId" : "targetNodeId";
  const snake = side === "source" ? "source_node_id" : "target_node_id";
  const value = edge?.[side] ?? edge?.[snake] ?? edge?.[camel];
  if (value && typeof value === "object") return String(value.id ?? value.cell ?? value.node_id ?? "");
  return value === undefined || value === null ? "" : String(value);
}

function collectorMessageText(item) {
  if (typeof item === "string" || typeof item === "number") return String(item);
  if (!item || typeof item !== "object") return "확인할 수 없는 항목";
  const detail = item.message ?? item.detail ?? item.reason ?? item.description ?? item.name;
  if (detail) return String(detail);
  try { return JSON.stringify(item); } catch (_) { return "확인할 수 없는 항목"; }
}

function collectorEvidenceText(item) {
  const collector = item?.properties?.collector || {};
  const provenance = item?.properties?.provenance || {};
  const evidenceValue = item?.evidence ?? collector.evidence;
  const evidence = Array.isArray(evidenceValue) ? evidenceValue[0] : evidenceValue;
  const firstRef = Array.isArray(collector.resource_refs) ? collector.resource_refs[0] : null;
  const refSource = firstRef?.source && typeof firstRef.source === "object" ? firstRef.source : {};
  const source = refSource.file ?? item?.source_file ?? item?.source ?? evidence?.source_file ?? evidence?.source ?? evidence?.file ?? provenance.source_file ?? provenance.source ?? provenance.file;
  const line = refSource.line ?? item?.source_line ?? item?.line ?? evidence?.source_line ?? evidence?.line ?? provenance.source_line ?? provenance.line;
  const location = source ? `${source}${line ? `:${line}` : ""}` : "";
  if (typeof evidence === "string" && location) return `${evidence}, ${location}`;
  if (typeof evidence === "string") return evidence;
  return location;
}

function collectorNamespaceLabel(namespace) {
  if (typeof namespace === "string") return namespace;
  return String(namespace?.name ?? namespace?.namespace ?? "default");
}

function collectorEntryCandidate(item) {
  return Boolean(item?.properties?.collector?.entry_candidate);
}

function collectorNodeTypeDisplayName(node) {
  const requested = String(node?.asset_type_id ?? node?.asset_type?.id ?? "");
  const asset = assetById(requested);
  const fallback = dfdKindLabel(node?.dfd_kind ?? node?.kind, "구성요소");
  return dfdDisplayName(node?.asset_type_name, assetDisplayName(asset || requested, fallback));
}

function collectorNodeDisplayName(node, fallback = "구성요소") {
  return dfdDisplayName(node?.name, collectorNodeTypeDisplayName(node) || fallback);
}

function collectorSummaryNote(summary) {
  if (typeof summary === "string") return summary;
  if (!summary || typeof summary !== "object") return "";
  const preferred = summary.message ?? summary.description ?? summary.note;
  if (preferred) return String(preferred);
  const labels = {
    input_files: "입력 파일",
    documents: "문서",
    resources: "Kubernetes 객체",
    workloads: "워크로드",
    containers: "Container",
    services: "Service",
    public_exposure_candidates: "공개 경로 후보",
  };
  const entries = Object.entries(summary)
    .filter(([key]) => key in labels)
    .filter(([, value]) => ["string", "number", "boolean"].includes(typeof value))
    .slice(0, 6)
    .map(([key, value]) => `${labels[key]} ${value}`);
  return entries.join(", ");
}

function collectorProposedEdges(proposal) {
  const result = [];
  const seen = new Set();
  [...(proposal.edges || []), ...(proposal.flow_candidates || [])].forEach((edge) => {
    const id = collectorItemId(edge);
    const key = id || `${collectorEdgeEndpoint(edge, "source")}\u0000${collectorEdgeEndpoint(edge, "target")}\u0000${edge?.name || ""}`;
    if (!key || seen.has(key)) return;
    seen.add(key);
    result.push(edge);
  });
  return result;
}

function collectorProjectionMembers(item) {
  const projection = item?.properties?.manifest_projection;
  return projection && Array.isArray(projection.members) ? projection.members : [];
}

function collectorMemberLabel(member) {
  if (!member || typeof member !== "object") return "";
  const kind = String(member.kind || member.workload_kind || "Resource");
  const namespace = String(member.namespace || "default");
  const name = String(member.name || member.workload_name || member.category || "");
  return name ? `${kind} ${namespace}/${name}` : kind;
}

function collectorReviewMarkup(proposal) {
  const logicalProjection = proposal?.summary?.projection_mode === "LOGICAL_SYSTEM"
    || proposal.nodes.some(logicalManifestInstance);
  const existingNodes = new Map(state.workspace.nodes.map((item) => [String(item.id), item]));
  const existingEdges = new Map(state.workspace.edges.map((item) => [String(item.id), item]));
  const existingBoundaryIds = new Set(state.workspace.boundaries.map((item) => String(item.id)));
  const proposedNodeNames = new Map(proposal.nodes.map((node) => [collectorItemId(node), collectorNodeDisplayName(node)]));
  const nodeName = (id) => proposedNodeNames.get(id) || (nodeById(id) ? nodeDisplayName(nodeById(id)) : "알 수 없음");
  const summaryNote = collectorSummaryNote(proposal.summary);
  const namespaces = proposal.namespaces.map(collectorNamespaceLabel).filter(Boolean);

  const nodes = proposal.nodes.map((node, index) => {
    const id = collectorItemId(node);
    const existing = id ? existingNodes.get(id) : null;
    const duplicate = Boolean(existing);
    const refreshable = duplicate && existing?.properties?.collector?.generated === true;
    const invalid = !id;
    const disabled = invalid || (duplicate && !refreshable);
    const source = collectorEvidenceText(node);
    const type = collectorNodeTypeDisplayName(node);
    const members = collectorProjectionMembers(node).map(collectorMemberLabel).filter(Boolean);
    const memberCount = Number(node?.properties?.manifest_projection?.member_count ?? members.length);
    const memberSummary = members.length ? members.slice(0, 3).join(", ") : source;
    const itemDetail = logicalManifestInstance(node)
      ? [type, memberSummary].filter(Boolean).join(", ")
      : `${type}${memberCount ? `, Manifest 리소스 ${memberCount}개` : ""}${memberSummary ? `, ${memberSummary}` : ""}`;
    return `<label class="collector-review-item ${disabled ? "is-disabled" : ""}">
      <input type="checkbox" data-collector-node-index="${index}" ${disabled ? "disabled" : "checked"}>
      <span class="collector-review-copy"><strong>${escapeHtml(collectorNodeDisplayName(node, "ID 없는 구성요소"))}</strong><span>${escapeHtml(itemDetail)}</span></span>
      ${collectorEntryCandidate(node) ? '<span class="badge blue">진입 후보</span>' : ""}
      ${node.is_target ? '<span class="badge orange">대상 제안 (미적용)</span>' : ""}
      ${refreshable ? '<span class="badge green">근거 갱신</span>' : duplicate ? '<span class="badge green">이미 있음</span>' : ""}
      ${invalid ? '<span class="badge red">ID 없음</span>' : ""}
    </label>`;
  }).join("") || '<p class="collector-empty">제안된 구성요소가 없습니다.</p>';

  const proposedEdges = collectorProposedEdges(proposal);
  const edges = proposedEdges.map((edge, index) => {
    const id = collectorItemId(edge);
    const sourceId = collectorEdgeEndpoint(edge, "source");
    const targetId = collectorEdgeEndpoint(edge, "target");
    const existing = id ? existingEdges.get(id) : null;
    const duplicate = Boolean(existing);
    const refreshable = duplicate && existing?.properties?.collector?.generated === true;
    const invalid = !id || !sourceId || !targetId;
    const disabled = invalid || (duplicate && !refreshable);
    const reviewRequired = proposal.flow_candidates.includes(edge) || !DFD_SELECTION.collectorEdgeSelectedByDefault(edge);
    const evidence = collectorEvidenceText(edge);
    return `<label class="collector-review-item ${disabled ? "is-disabled" : ""}">
      <input type="checkbox" data-collector-edge-index="${index}" ${disabled ? "disabled" : reviewRequired ? "" : "checked"}>
      <span class="collector-review-copy"><strong>${escapeHtml(nodeName(sourceId))} → ${escapeHtml(nodeName(targetId))}</strong><span>${escapeHtml(edgeDisplayName(edge, "데이터 흐름"))}${evidence ? `, ${escapeHtml(evidence)}` : ""}</span></span>
      ${reviewRequired && !disabled ? '<span class="badge orange">확인 후 선택</span>' : ""}
      ${refreshable ? '<span class="badge green">근거 갱신</span>' : duplicate ? '<span class="badge green">이미 있음</span>' : ""}
      ${invalid ? '<span class="badge red">연결 확인 필요</span>' : ""}
    </label>`;
  }).join("") || '<p class="collector-empty">제안된 데이터 흐름이 없습니다.</p>';

  const boundaries = proposal.boundaries.map((boundary, index) => {
    const id = collectorItemId(boundary);
    const duplicate = id && existingBoundaryIds.has(id);
    const invalid = !id;
    return `<label class="collector-review-item ${duplicate || invalid ? "is-disabled" : ""}">
      <input type="checkbox" data-collector-boundary-index="${index}" ${duplicate || invalid ? "disabled" : ""}>
      <span class="collector-review-copy"><strong>${escapeHtml(boundary.name || id || "ID 없는 경계")}</strong><span>자동 확정하지 않습니다. 검토 후 필요할 때만 선택하세요.</span></span>
      ${duplicate ? '<span class="badge green">이미 있음</span>' : '<span class="badge orange">기본 제외</span>'}
    </label>`;
  }).join("") || '<p class="collector-empty">제안된 경계가 없습니다. 신뢰 경계는 DFD에서 직접 추가할 수 있습니다.</p>';

  const warnings = proposal.warnings.length ? `<details class="collector-issue-summary"><summary>분석 참고 ${proposal.warnings.length}건 <span>펼쳐보기</span></summary><ul>${proposal.warnings.map((item) => `<li>${escapeHtml(collectorMessageText(item))}</li>`).join("")}</ul></details>` : "";
  const unresolved = proposal.unresolved.length ? `<details class="collector-issue-summary"><summary>자동 확정하지 않은 항목 ${proposal.unresolved.length}건 <span>펼쳐보기</span></summary><ul>${proposal.unresolved.map((item) => `<li>${escapeHtml(collectorMessageText(item))}</li>`).join("")}</ul></details>` : "";

  return `<div class="collector-summary-grid">
      <div><strong>${proposal.nodes.length}</strong><span>${logicalProjection ? "논리 구성요소" : "플랫폼 요소"}</span></div>
      <div><strong>${proposal.edges.length}</strong><span>선언 기반 흐름</span></div>
      <div><strong>${proposal.flow_candidates.length}</strong><span>검토할 흐름</span></div>
      <div><strong>${proposal.warnings.length + proposal.unresolved.length}</strong><span>참고 사항</span></div>
    </div>
    ${summaryNote ? `<p class="collector-summary-note">${escapeHtml(summaryNote)}</p>` : ""}
    ${namespaces.length ? `<div class="collector-namespaces"><span>발견된 Namespace</span><div class="chip-list">${namespaces.map((item) => `<span class="chip">${escapeHtml(item)}</span>`).join("")}</div></div>` : ""}
    ${warnings}${unresolved}
    <div class="notice info collector-decision-note"><div><strong>${logicalProjection ? "상위 워크로드를 논리 구성요소로 만든 DFD 초안입니다." : "Manifest 근거를 플랫폼 DFD에 반영한 초안입니다."}</strong>${logicalProjection ? "Pod 복제본마다 상자를 만들지 않습니다. Manifest만으로 알 수 없는 서비스 호출, 진입 지점과 공격 대상은 적용 후 직접 보완하세요." : "확인되지 않은 흐름, 진입 지점과 공격 대상은 자동 확정하지 않습니다."}</div></div>
    <section class="collector-review-section"><div class="collector-section-heading"><strong>${logicalProjection ? "DFD 초안 구성요소" : "활성화할 플랫폼 요소"}</strong><span>${logicalProjection ? "Deployment와 Job 같은 상위 워크로드 및 실제로 참조된 저장소를 제안합니다." : "Manifest에서 확인된 리소스는 요소 속성에 묶어 보관됩니다."}</span></div><div class="collector-review-list">${nodes}</div></section>
    <section class="collector-review-section"><div class="collector-section-heading"><strong>데이터 흐름</strong><span>Manifest 선언으로 방향을 정할 수 있는 흐름만 포함하며, 확인이 필요한 후보는 기본 선택하지 않습니다.</span></div><div class="collector-review-list">${edges}</div></section>
    <details class="collector-boundary-review"><summary>경계 제안 ${proposal.boundaries.length}개 검토 <span>선택 사항</span></summary><div class="collector-review-list">${boundaries}</div></details>`;
}

function collectorSelection(modal, proposal) {
  const ids = (selector, items) => new Set(
    $$(selector, modal)
      .filter((input) => input.checked && !input.disabled)
      .map((input) => collectorItemId(items[Number(input.dataset.collectorNodeIndex ?? input.dataset.collectorEdgeIndex ?? input.dataset.collectorBoundaryIndex)]))
      .filter(Boolean),
  );
  return {
    nodeIds: ids("[data-collector-node-index]", proposal.nodes),
    edgeIds: ids("[data-collector-edge-index]", collectorProposedEdges(proposal)),
    boundaryIds: ids("[data-collector-boundary-index]", proposal.boundaries),
  };
}

function collectorAssetFor(node) {
  const requested = String(node.asset_type_id ?? node.asset_type?.id ?? "");
  const exact = assetById(requested);
  if (exact) return exact;
  const fallbackId = node.dfd_kind === "external" ? "GEN-EXT" : node.dfd_kind === "data_store" ? "GEN-DATA" : "GEN-PROC";
  return assetById(fallbackId) || state.bootstrap.asset_types[0];
}

function collectorProperties(item, runId) {
  const properties = item?.properties && typeof item.properties === "object" && !Array.isArray(item.properties) ? { ...item.properties } : {};
  const provenance = properties.provenance && typeof properties.provenance === "object" && !Array.isArray(properties.provenance) ? properties.provenance : {};
  const existing = properties.collector && typeof properties.collector === "object" && !Array.isArray(properties.collector) ? properties.collector : {};
  properties.provenance = {
    ...provenance,
    collection_run_id: /^\d+$/.test(String(runId || "")) ? Number(runId) : String(runId || provenance.collection_run_id || ""),
  };
  properties.collector = {
    ...existing,
    generated: true,
    source_type: "kubernetes_manifest",
    generated_layer_id: String(existing.generated_layer_id || "manifest-platform"),
    run_id: String(runId || existing.run_id || ""),
    replacement_key: String(existing.replacement_key || properties?.manifest_projection?.replacement_key || collectorItemId(item)),
    evidence: item?.evidence ?? existing.evidence ?? null,
    confidence: item?.confidence ?? provenance.confidence ?? existing.confidence ?? null,
    suggested_target: Boolean(item?.is_target || existing.suggested_target),
  };
  return properties;
}

function mergeManifestProposal(proposal, selection) {
  const runId = proposal.run_id;
  const logicalProjection = proposal?.summary?.projection_mode === "LOGICAL_SYSTEM"
    || proposal.nodes.some(logicalManifestInstance);
  const previousGeneratedNodes = state.workspace.nodes.filter(manifestGeneratedItem);
  const previousGeneratedEdges = state.workspace.edges.filter(manifestGeneratedItem);
  const previousGeneratedBoundaries = state.workspace.boundaries.filter(manifestGeneratedItem);
  const previousEdgeCurveByReplacementKey = new Map();
  const ambiguousPreviousEdgeReplacementKeys = new Set();
  const previousEdgeCurveById = new Map();
  previousGeneratedEdges.forEach((edge) => {
    const curveOffset = DFD_SELECTION.explicitEdgeCurveOffset(edge);
    if (curveOffset === null) return;
    const replacementKey = String(
      edge?.properties?.collector?.replacement_key
      || edge?.properties?.manifest_projection?.replacement_key
      || "",
    );
    if (replacementKey && !ambiguousPreviousEdgeReplacementKeys.has(replacementKey)) {
      if (previousEdgeCurveByReplacementKey.has(replacementKey)) {
        previousEdgeCurveByReplacementKey.delete(replacementKey);
        ambiguousPreviousEdgeReplacementKeys.add(replacementKey);
      } else {
        previousEdgeCurveByReplacementKey.set(replacementKey, curveOffset);
      }
    }
    previousEdgeCurveById.set(String(edge.id), curveOffset);
  });
  const previousDecisions = new Map(previousGeneratedNodes.map((node) => {
    const replacementKey = String(node?.properties?.collector?.replacement_key || node?.properties?.manifest_projection?.replacement_key || node.id);
    return [replacementKey, {
      is_entry: Boolean(node.is_entry),
      is_target: Boolean(node.is_target),
      entry_reason: String(node.entry_reason || ""),
      target_reason: String(node.target_reason || ""),
    }];
  }));
  const previousDecisionByCatalogKey = new Map();
  previousGeneratedNodes.forEach((node) => {
    const level = Number(node?.properties?.catalog?.level);
    const key = `${level}:${String(node.asset_type_id || "")}`;
    const current = previousDecisionByCatalogKey.get(key) || { entries: [], targets: [] };
    if (node.is_entry) current.entries.push(String(node.entry_reason || ""));
    if (node.is_target) current.targets.push(String(node.target_reason || ""));
    previousDecisionByCatalogKey.set(key, current);
  });
  state.workspace.nodes = state.workspace.nodes.filter((item) => !manifestGeneratedItem(item));
  state.workspace.edges = state.workspace.edges.filter((item) => !manifestGeneratedItem(item));
  state.workspace.boundaries = state.workspace.boundaries.filter((item) => !manifestGeneratedItem(item));
  state.workspace.nodes.forEach((node) => {
    if (node?.properties?.collector?.attached_to_manual !== true) return;
    node.properties = { ...(node.properties || {}) };
    delete node.properties.collector;
    delete node.properties.manifest_projection;
  });
  const nodeIds = new Set(state.workspace.nodes.map((item) => String(item.id)));
  const edgeIds = new Set(state.workspace.edges.map((item) => String(item.id)));
  const boundaryIds = new Set(state.workspace.boundaries.map((item) => String(item.id)));
  const selectedProposalNodes = proposal.nodes.filter((node) => selection.nodeIds.has(collectorItemId(node)));
  const result = {
    nodes: 0,
    edges: 0,
    boundaries: 0,
    updated: 0,
    skipped: 0,
    removedNodes: previousGeneratedNodes.length,
    removedEdges: previousGeneratedEdges.length,
    removedBoundaries: previousGeneratedBoundaries.length,
  };
  const addedNodeIds = [];
  const endpointMap = new Map();
  const selectedNodeByCatalogKey = new Map();
  const selectedNodeByReplacementKey = new Map();
  const manualCatalogNodes = new Map();
  state.workspace.nodes.forEach((node) => {
    const level = Number(node?.properties?.catalog?.level);
    if (level !== 0 && level !== 1) return;
    const key = `${level}:${String(node.asset_type_id || "")}`;
    if (!manualCatalogNodes.has(key)) manualCatalogNodes.set(key, node);
    else manualCatalogNodes.set(key, null);
  });

  selectedProposalNodes.forEach((node) => {
    const id = collectorItemId(node);
    if (!id) { result.skipped += 1; return; }
    const asset = collectorAssetFor(node);
    if (!asset) { result.skipped += 1; return; }
    const logicalNode = logicalManifestInstance(node);
    const proposalNodeLevel = Number(node?.properties?.catalog?.level ?? proposal?.summary?.catalog_level ?? state.dfdCatalogLevel);
    const matchingManual = logicalNode ? null : manualCatalogNodes.get(`${proposalNodeLevel}:${String(asset.id)}`);
    if (matchingManual) {
      const attachedProperties = collectorProperties(node, runId);
      const replacementKey = String(attachedProperties.collector.replacement_key || id);
      attachedProperties.collector = { ...attachedProperties.collector, generated: false, attached_to_manual: true };
      delete attachedProperties.collector.generated_layer_id;
      matchingManual.properties = { ...(matchingManual.properties || {}), ...attachedProperties };
      endpointMap.set(id, String(matchingManual.id));
      selectedNodeByCatalogKey.set(`${proposalNodeLevel}:${String(asset.id)}`, String(matchingManual.id));
      selectedNodeByReplacementKey.set(replacementKey, String(matchingManual.id));
      result.updated += 1;
      return;
    }
    if (nodeIds.has(id)) { result.skipped += 1; return; }
    const index = result.nodes;
    const hasX = node.x !== undefined && node.x !== null && Number.isFinite(Number(node.x));
    const hasY = node.y !== undefined && node.y !== null && Number.isFinite(Number(node.y));
    const properties = collectorProperties(node, runId);
    const replacementKey = String(properties.collector.replacement_key || id);
    const groupedDecision = logicalNode ? null : previousDecisionByCatalogKey.get(`${proposalNodeLevel}:${String(asset.id)}`);
    const decision = previousDecisions.get(replacementKey) || (groupedDecision && !(groupedDecision.entries.length && groupedDecision.targets.length) ? {
      is_entry: groupedDecision.entries.length > 0,
      is_target: groupedDecision.targets.length > 0,
      entry_reason: groupedDecision.entries.find(Boolean) || "",
      target_reason: groupedDecision.targets.find(Boolean) || "",
    } : {});
    state.workspace.nodes.push({
      ...node,
      id,
      name: String(node.name || id),
      asset_type_id: asset.id,
      asset_type_name: node.asset_type_name || asset.name,
      dfd_kind: asset.dfd_kind,
      x: hasX ? Number(node.x) : 70 + (index % 4) * 190,
      y: hasY ? Number(node.y) : 104 + Math.floor(index / 4) * 105,
      width: Number(node.width || 172),
      height: Number(node.height || 66),
      description: String(node.description || ""),
      properties,
      is_entry: Boolean(decision.is_entry),
      is_target: Boolean(decision.is_target),
      entry_reason: String(decision.entry_reason || ""),
      target_reason: String(decision.target_reason || ""),
    });
    nodeIds.add(id);
    endpointMap.set(id, id);
    selectedNodeByReplacementKey.set(replacementKey, id);
    if (!logicalNode) selectedNodeByCatalogKey.set(`${proposalNodeLevel}:${String(asset.id)}`, id);
    addedNodeIds.push(id);
    result.nodes += 1;
  });

  collectorProposedEdges(proposal).filter((edge) => selection.edgeIds.has(collectorItemId(edge))).forEach((edge) => {
    const id = collectorItemId(edge);
    const source = endpointMap.get(collectorEdgeEndpoint(edge, "source")) || collectorEdgeEndpoint(edge, "source");
    const target = endpointMap.get(collectorEdgeEndpoint(edge, "target")) || collectorEdgeEndpoint(edge, "target");
    if (!id || !nodeIds.has(source) || !nodeIds.has(target)) { result.skipped += 1; return; }
    if (edgeIds.has(id)) { result.skipped += 1; return; }
    const properties = collectorProperties(edge, runId);
    const replacementKey = String(properties?.collector?.replacement_key || "");
    const previousCurveOffset = ambiguousPreviousEdgeReplacementKeys.has(replacementKey)
      ? undefined
      : previousEdgeCurveByReplacementKey.has(replacementKey)
      ? previousEdgeCurveByReplacementKey.get(replacementKey)
      : previousEdgeCurveById.get(id);
    if (previousCurveOffset !== undefined) {
      const layout = properties.layout && typeof properties.layout === "object" && !Array.isArray(properties.layout)
        ? properties.layout
        : {};
      properties.layout = { ...layout, curve_offset: previousCurveOffset };
    }
    state.workspace.edges.push({
      ...edge,
      id,
      source,
      target,
      name: String(edge.name || ""),
      protocol: String(edge.protocol || ""),
      data_type: String(edge.data_type ?? edge.dataType ?? ""),
      properties,
    });
    edgeIds.add(id);
    result.edges += 1;
  });

  proposal.boundaries.filter((boundary) => selection.boundaryIds.has(collectorItemId(boundary))).forEach((boundary) => {
    const id = collectorItemId(boundary);
    if (!id || boundaryIds.has(id)) { result.skipped += 1; return; }
    state.workspace.boundaries.push({
      ...boundary,
      id,
      name: String(boundary.name || "검토된 경계"),
      x: Number(boundary.x ?? 30),
      y: Number(boundary.y ?? 30),
      width: Math.max(80, Number(boundary.width ?? 360)),
      height: Math.max(80, Number(boundary.height ?? 240)),
    });
    boundaryIds.add(id);
    result.boundaries += 1;
  });
  const replacedEndpointIds = new Map();
  previousGeneratedNodes.forEach((node) => {
    const replacementKey = String(node?.properties?.collector?.replacement_key || node?.properties?.manifest_projection?.replacement_key || node.id);
    const level = Number(node?.properties?.catalog?.level);
    const replacement = selectedNodeByReplacementKey.get(replacementKey)
      || (logicalManifestInstance(node) ? null : selectedNodeByCatalogKey.get(`${level}:${String(node.asset_type_id || "")}`));
    if (replacement) replacedEndpointIds.set(String(node.id), replacement);
  });
  state.workspace.edges.forEach((edge) => {
    edge.source = replacedEndpointIds.get(String(edge.source)) || edge.source;
    edge.target = replacedEndpointIds.get(String(edge.target)) || edge.target;
  });
  const retainedNodeIds = new Set(state.workspace.nodes.map((node) => String(node.id)));
  state.workspace.edges = state.workspace.edges.filter((edge) => (
    retainedNodeIds.has(String(edge.source)) && retainedNodeIds.has(String(edge.target))
  ));
  const proposalLevel = Number(proposal?.summary?.catalog_level ?? proposal?.platform_template?.level);
  if (proposalLevel === 0 || proposalLevel === 1) {
    state.dfdCatalogLevel = proposalLevel;
  }
  if (result.nodes + result.edges + result.boundaries + result.updated > 0) {
    state.dfdShowReferenceFlows = false;
  }
  if (!logicalProjection) autoLayoutDfd({ nodeIds: addedNodeIds, keepZoom: false });
  return result;
}

function collectorEvidenceItems(item) {
  const value = item?.properties?.collector?.evidence ?? item?.evidence;
  return (Array.isArray(value) ? value : value ? [value] : [])
    .map((entry) => typeof entry === "string" ? entry : collectorMessageText(entry))
    .map((entry) => String(entry).trim())
    .filter(Boolean);
}

function collectorResourceLabels(item) {
  const members = collectorProjectionMembers(item).map(collectorMemberLabel).filter(Boolean);
  if (members.length) return members;
  const refs = item?.properties?.collector?.resource_refs;
  return (Array.isArray(refs) ? refs : []).map((ref) => {
    if (!ref || typeof ref !== "object") return "";
    const name = collectorMemberLabel(ref);
    const source = ref.source && typeof ref.source === "object" ? ref.source : {};
    const location = source.file ? `${source.file}${source.line ? `:${source.line}` : ""}` : "";
    return [name, location].filter(Boolean).join(", ");
  }).filter(Boolean);
}

function collectorInspectorBadge(item) {
  const meta = item?.properties?.collector;
  if (!meta || typeof meta !== "object") return "";
  const evidence = collectorEvidenceItems(item);
  const resources = collectorResourceLabels(item);
  const confidence = meta.confidence ? String(meta.confidence) : "";
  const entryNote = meta.entry_candidate ? ", 진입 후보는 사용자가 직접 지정" : "";
  const targetNote = meta.suggested_target ? ", 공격 대상 제안은 자동 적용하지 않음" : "";
  const resourceCount = Number(item?.properties?.manifest_projection?.member_count ?? resources.length);
  const isFlow = item?.source !== undefined && item?.target !== undefined;
  const nodeDescription = logicalManifestInstance(item)
    ? "이 상자는 Manifest에서 확인한 상위 워크로드 또는 참조 저장소를 나타냅니다."
    : "이 상자는 개별 리소스가 아니라 저장된 플랫폼 DFD 요소입니다.";
  return `<div class="collector-inspector-note"><div><span class="badge blue">Manifest 근거</span>${confidence ? `<span class="badge">${escapeHtml(confidence)}</span>` : ""}${resourceCount ? `<span class="badge green">리소스 ${resourceCount}개</span>` : ""}</div><p>${isFlow ? "이 흐름은 선택한 Manifest 근거로 평가에 포함되었습니다." : nodeDescription}${entryNote}${targetNote}</p>
    ${resources.length ? `<details><summary>발견된 Manifest 리소스</summary><ul>${resources.map((resource) => `<li>${escapeHtml(resource)}</li>`).join("")}</ul></details>` : ""}
    ${evidence.length ? `<details><summary>매핑 근거</summary><ul>${evidence.map((entry) => `<li>${escapeHtml(entry)}</li>`).join("")}</ul></details>` : ""}
  </div>`;
}

function showManifestCollectorModal() {
  $("#manifest-collector-modal")?.remove();
  if (dfdCatalogLevelState().mixed) {
    toast("기본 구성과 상세 구성 요소가 섞여 있습니다. 한 구성 수준으로 정리한 뒤 Manifest를 다시 분석해 주세요.", true);
    return;
  }
  const hasStoredCatalog = state.workspace.nodes.some((node) => dfdCatalogNode(node) || manifestGeneratedItem(node));
  const manifestDfdLevel = hasStoredCatalog ? currentDfdCatalogLevel() : 0;
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="manifest-collector-modal">
    <div class="modal manifest-collector-modal" role="dialog" aria-modal="true" aria-labelledby="manifest-collector-title">
      <div class="modal-header"><div><h2 id="manifest-collector-title">Manifest로 DFD 초안 만들기</h2><p>Deployment와 Job 같은 상위 워크로드를 배치하고 확인 가능한 관계만 연결합니다.</p></div><button type="button" class="btn small" data-close-collector>닫기</button></div>
      <div class="modal-body collector-modal-body">
        <section class="collector-upload-panel">
          <div class="form-field"><label class="required" for="collector-files">Kubernetes Manifest 원본</label><input id="collector-files" type="file" accept=".yaml,.yml,.json,application/json" multiple><span class="input-help">각 객체에 apiVersion, kind, metadata가 있는 YAML, YML 또는 JSON을 선택하세요. 파일당 1MB, 합계 1.5MB 이하만 분석합니다.</span></div>
          <button type="button" class="btn primary" id="collector-analyze" disabled>Manifest 분석</button>
        </section>
        <div id="collector-file-list" class="collector-file-list">선택된 파일이 없습니다.</div>
        <div class="notice warning collector-safety-note"><div><strong>민감정보를 확인하세요.</strong>Secret의 실제 값이나 운영 자격 증명은 제거한 복사본을 올리세요. 호출 방향, 공격 대상과 신뢰 경계는 자동 확정하지 않습니다.</div></div>
        <div id="collector-status" class="collector-status" aria-live="polite"></div>
        <div id="collector-result" class="collector-result" hidden></div>
      </div>
      <div class="modal-footer"><span class="collector-footer-help">적용하면 이전 Manifest 자동 초안만 교체하고 직접 만든 요소는 유지합니다.</span><button type="button" class="btn" data-close-collector>취소</button><button type="button" class="btn primary" id="collector-apply" disabled>선택 내용으로 교체</button></div>
    </div>
  </div>`);

  const modal = $("#manifest-collector-modal");
  const input = $("#collector-files", modal);
  const analyzeButton = $("#collector-analyze", modal);
  const applyButton = $("#collector-apply", modal);
  const fileList = $("#collector-file-list", modal);
  const status = $("#collector-status", modal);
  const resultPanel = $("#collector-result", modal);
  let preview = null;

  const close = () => modal.remove();
  $$('[data-close-collector]', modal).forEach((button) => button.onclick = close);

  input.onchange = () => {
    const files = [...input.files];
    const invalid = files.filter((file) => !/\.(?:ya?ml|json)$/i.test(file.name));
    const oversized = files.filter((file) => file.size > 1_000_000);
    const total = files.reduce((sum, file) => sum + file.size, 0);
    const valid = files.length > 0 && files.length <= 50 && !invalid.length && !oversized.length && total <= 1_500_000;
    analyzeButton.disabled = !valid;
    applyButton.disabled = true;
    preview = null;
    resultPanel.hidden = true;
    status.textContent = invalid.length
      ? "YAML, YML, JSON 파일만 선택해 주세요."
      : files.length > 50
        ? "파일은 한 번에 최대 50개까지 선택할 수 있습니다."
        : oversized.length
          ? "파일 하나의 크기는 1MB 이하여야 합니다."
          : total > 1_500_000
          ? "파일 합계가 1.5MB를 넘습니다. 범위를 나누어 분석해 주세요."
          : "";
    status.classList.toggle("error", !valid && files.length > 0);
    fileList.innerHTML = files.length
      ? files.map((file) => `<span class="chip">${escapeHtml(file.name)} (${Math.max(1, Math.ceil(file.size / 1024))}KB)</span>`).join("")
      : "선택된 파일이 없습니다.";
  };

  analyzeButton.onclick = async () => {
    const files = [...input.files];
    if (!files.length) return;
    analyzeButton.disabled = true;
    applyButton.disabled = true;
    status.classList.remove("error");
    status.textContent = "Manifest를 분석하고 DFD 초안을 만드는 중입니다…";
    resultPanel.hidden = true;
    try {
      const payloadFiles = await Promise.all(files.map(async (file) => ({ name: file.name, content: await file.text() })));
      preview = collectorProposal(await api(`/api/assessments/${state.assessmentId}/manifest/preview`, { method: "POST", body: { files: payloadFiles, dfd_level: manifestDfdLevel, projection_mode: "logical" } }));
      if (!preview.run_id) throw new Error("분석 실행 ID를 받지 못했습니다. 다시 시도해 주세요.");
      resultPanel.innerHTML = collectorReviewMarkup(preview);
      resultPanel.hidden = false;
      status.textContent = "분석이 끝났습니다. 포함할 항목을 확인해 주세요.";
      applyButton.disabled = false;
    } catch (error) {
      status.textContent = error.message;
      status.classList.add("error");
    } finally {
      analyzeButton.disabled = false;
    }
  };

  applyButton.onclick = async () => {
    if (!preview?.run_id) return;
    const selection = collectorSelection(modal, preview);
    applyButton.disabled = true;
    analyzeButton.disabled = true;
    status.classList.remove("error");
    status.textContent = "선택한 초안을 캔버스에 추가하는 중입니다…";
    try {
      const merged = mergeManifestProposal(preview, selection);
      const changed = merged.nodes + merged.edges + merged.boundaries + merged.updated
        + merged.removedNodes + merged.removedEdges + merged.removedBoundaries;
      if (changed) markDfdDirty();
      state.manifestReviewSummary = {
        level: Number(preview?.summary?.catalog_level ?? preview?.platform_template?.level ?? currentDfdCatalogLevel()),
        nodes: merged.nodes + merged.updated,
        edges: merged.edges,
        issues: [...preview.warnings, ...preview.unresolved].map(collectorMessageText),
      };
      clearDfdSelection();
      close();
      renderDfdStep();
      toast(changed
        ? `Manifest 근거로 논리 구성요소 ${merged.nodes + merged.updated}개와 선언 기반 흐름 ${merged.edges}개를 반영했습니다. 기존 자동 초안은 교체했고 직접 만든 요소는 유지했습니다.`
        : "반영할 DFD 초안 구성요소가 없습니다. 직접 만든 DFD는 유지했습니다.");
    } catch (error) {
      status.textContent = error.message;
      status.classList.add("error");
      applyButton.disabled = false;
      analyzeButton.disabled = false;
    }
  };
}

function edgeEndpoints(source, target) {
  const sourceCenter = { x: Number(source.x) + Number(source.width || 150) / 2, y: Number(source.y) + Number(source.height || 64) / 2 };
  const targetCenter = { x: Number(target.x) + Number(target.width || 150) / 2, y: Number(target.y) + Number(target.height || 64) / 2 };
  const dx = targetCenter.x - sourceCenter.x;
  const dy = targetCenter.y - sourceCenter.y;
  const length = Math.hypot(dx, dy) || 1;
  const sourceScale = 1 / Math.max(Math.abs(dx) / (Number(source.width || 150) / 2), Math.abs(dy) / (Number(source.height || 64) / 2), 1);
  const targetScale = 1 / Math.max(Math.abs(dx) / (Number(target.width || 150) / 2), Math.abs(dy) / (Number(target.height || 64) / 2), 1);
  return {
    sx: sourceCenter.x + dx * sourceScale,
    sy: sourceCenter.y + dy * sourceScale,
    tx: targetCenter.x - dx * targetScale - (dx / length) * 7,
    ty: targetCenter.y - dy * targetScale - (dy / length) * 7,
  };
}

function edgeCurveOffsets(edges) {
  const items = Array.isArray(edges) ? edges : [];
  const automatic = DFD_SELECTION.automaticEdgeCurveOffsets(items);
  return items.map((edge, index) => DFD_SELECTION.explicitEdgeCurveOffset(edge) ?? automatic[index] ?? 0);
}

function edgeCurveGeometry(source, target, offset = 0) {
  const { sx, sy, tx, ty } = edgeEndpoints(source, target);
  return DFD_SELECTION.quadraticCurveGeometry({ x: sx, y: sy }, { x: tx, y: ty }, offset);
}

function setEdgeCurveOffset(edge, value) {
  edge.properties = edge.properties && typeof edge.properties === "object" ? { ...edge.properties } : {};
  const layout = edge.properties.layout && typeof edge.properties.layout === "object" ? { ...edge.properties.layout } : {};
  if (value === null) {
    delete layout.curve_offset;
    if (Object.keys(layout).length) edge.properties.layout = layout;
    else delete edge.properties.layout;
    return;
  }
  layout.curve_offset = Math.max(-180, Math.min(180, Number(value) || 0));
  edge.properties.layout = layout;
}

function setEdgeLabelT(edge, value) {
  edge.properties = edge.properties && typeof edge.properties === "object" ? { ...edge.properties } : {};
  const layout = edge.properties.layout && typeof edge.properties.layout === "object" ? { ...edge.properties.layout } : {};
  if (value === null) {
    delete layout.label_t;
    if (Object.keys(layout).length) edge.properties.layout = layout;
    else delete edge.properties.layout;
    return;
  }
  layout.label_t = Math.max(0.05, Math.min(0.95, Number(value) || 0.5));
  edge.properties.layout = layout;
}

function dfdEdgeLabelWidth(text) {
  return Math.min(220, Math.max(54, String(text || "").length * 7.2 + 16));
}

function dfdEdgeLabelAt(geometry, text, t) {
  const point = DFD_SELECTION.quadraticCurvePoint(geometry, t);
  return { x: point.x, y: point.y - 6, width: dfdEdgeLabelWidth(text) };
}

function applyEdgeLabelPosition(group, position) {
  const label = group?.querySelector(".edge-label");
  if (!label || !position) return;
  label.setAttribute("x", position.x);
  label.setAttribute("y", position.y);
  const background = group.querySelector(".edge-label-background");
  if (background) {
    const width = Number(background.dataset.labelWidth || position.width || 80);
    background.setAttribute("x", position.x - width / 2);
    background.setAttribute("y", position.y - 14);
  }
}

function applyEdgeGeometry(group, geometry, edge = null) {
  if (!group || !geometry) return;
  group.querySelectorAll(".edge-hit-area, .edge-line").forEach((path) => path.setAttribute("d", geometry.path));
  const manualT = DFD_SELECTION.explicitEdgeLabelT(edge);
  const visibleName = edge ? edgeDisplayName(edge) : "";
  applyEdgeLabelPosition(group, manualT === null
    ? { x: geometry.mx, y: geometry.my - 6, width: dfdEdgeLabelWidth(visibleName) }
    : dfdEdgeLabelAt(geometry, visibleName, manualT));
}

function dfdRectanglesForLabelAvoidance(nodes) {
  return (nodes || []).map((node) => ({
    left: Number(node.x) - 8,
    right: Number(node.x) + Number(node.width || 150) + 8,
    top: Number(node.y) - 8,
    bottom: Number(node.y) + Number(node.height || 64) + 8,
  }));
}

function dfdLabelBoxesOverlap(left, right) {
  return !(left.right < right.left || left.left > right.right || left.bottom < right.top || left.top > right.bottom);
}

function placeDfdEdgeLabel(geometry, text, occupied) {
  const width = dfdEdgeLabelWidth(text);
  const dx = Number(geometry.tx) - Number(geometry.sx);
  const dy = Number(geometry.ty) - Number(geometry.sy);
  const length = Math.hypot(dx, dy) || 1;
  const tangent = { x: dx / length, y: dy / length };
  const normal = { x: -dy / length, y: dx / length };
  const normalOffsets = [0, 24, -24, 48, -48, 72, -72, 96, -96];
  const tangentOffsets = [0, 34, -34, 68, -68];
  let fallback = { x: geometry.mx, y: geometry.my - 6, width };
  for (const normalOffset of normalOffsets) {
    for (const tangentOffset of tangentOffsets) {
      const x = geometry.mx + normal.x * normalOffset + tangent.x * tangentOffset;
      const y = geometry.my - 6 + normal.y * normalOffset + tangent.y * tangentOffset;
      const box = { left: x - width / 2, right: x + width / 2, top: y - 14, bottom: y + 5 };
      if (!occupied.some((other) => dfdLabelBoxesOverlap(box, other))) {
        occupied.push(box);
        return { x, y, width };
      }
      fallback = { x, y, width };
    }
  }
  occupied.push({ left: fallback.x - width / 2, right: fallback.x + width / 2, top: fallback.y - 14, bottom: fallback.y + 5 });
  return fallback;
}

function pendingDfdFlowMarkup() {
  const draft = state.dfdPendingFlow;
  if (!draft) return "";
  const x1 = Number(draft.x1);
  const y1 = Number(draft.y1);
  const x2 = Number(draft.x2);
  const y2 = Number(draft.y2);
  if (![x1, y1, x2, y2].every(Number.isFinite)) return "";
  const midpointX = (x1 + x2) / 2;
  const midpointY = (y1 + y2) / 2 - 12;
  const sourceAttached = draft.sourceId ? " is-attached" : "";
  const targetAttached = draft.targetId ? " is-attached" : "";
  return `<g class="pending-flow-draft" data-pending-flow="true">
    <path class="pending-flow-line" d="M ${x1} ${y1} L ${x2} ${y2}" marker-end="url(#draft-arrow)"></path>
    <circle class="pending-flow-endpoint${sourceAttached}" data-pending-flow-endpoint="source" cx="${x1}" cy="${y1}" r="10"><title>출발점을 구성요소에 연결</title></circle>
    <circle class="pending-flow-endpoint${targetAttached}" data-pending-flow-endpoint="target" cx="${x2}" cy="${y2}" r="10"><title>도착점을 구성요소에 연결</title></circle>
    <text class="pending-flow-help" x="${midpointX}" y="${midpointY}" text-anchor="middle">양쪽 끝을 구성요소에 연결 · Esc 취소</text>
  </g>`;
}

function boundaryResizeHandlesMarkup(boundary) {
  const x = Number(boundary.x);
  const y = Number(boundary.y);
  const width = Number(boundary.width);
  const height = Number(boundary.height);
  const handles = [
    ["nw", x, y, "왼쪽 위"],
    ["n", x + width / 2, y, "위"],
    ["ne", x + width, y, "오른쪽 위"],
    ["e", x + width, y + height / 2, "오른쪽"],
    ["se", x + width, y + height, "오른쪽 아래"],
    ["s", x + width / 2, y + height, "아래"],
    ["sw", x, y + height, "왼쪽 아래"],
    ["w", x, y + height / 2, "왼쪽"],
  ];
  return `<g class="boundary-resize-handles" aria-label="신뢰 경계 크기 조절점">${handles.map(([direction, cx, cy, label]) => `<circle class="boundary-resize-handle" data-boundary-resize-handle="${direction}" cx="${cx}" cy="${cy}" r="6"><title>${label} 방향으로 크기 조절</title></circle>`).join("")}</g>`;
}

function dfdSvg() {
  const level = currentDfdCatalogLevel();
  const catalogReferences = catalogReferenceNodes(level);
  const activeByAssetType = new Map();
  state.workspace.nodes.forEach((node) => {
    // Keep logical workloads separate from the P.6 platform reference.
    if (logicalManifestInstance(node)) return;
    if (Number(node?.properties?.catalog?.level) !== level) return;
    if (!activeByAssetType.has(String(node.asset_type_id))) activeByAssetType.set(String(node.asset_type_id), node);
  });
  const inactiveReferences = state.dfdShowReferenceFlows
    ? catalogReferences.filter((node) => !activeByAssetType.has(String(node.asset_type_id)))
    : [];
  const sceneNodes = [...state.workspace.nodes, ...inactiveReferences];
  const canvasWidth = Math.max(980, ...sceneNodes.map((node) => Number(node.x) + Number(node.width || 150) + 70), ...state.workspace.boundaries.map((boundary) => Number(boundary.x) + Number(boundary.width || 0) + 70));
  const canvasHeight = Math.max(620, ...sceneNodes.map((node) => Number(node.y) + Number(node.height || 64) + 70), ...state.workspace.boundaries.map((boundary) => Number(boundary.y) + Number(boundary.height || 0) + 70));
  const selectedNodeIds = selectedDfdNodeIdSet();
  const multipleNodesSelected = selectedNodeIds.size > 1;
  const referenceByAssetType = new Map(catalogReferences.map((node) => [String(node.asset_type_id), activeByAssetType.get(String(node.asset_type_id)) || node]));
  const activeFlowTemplateIds = new Set(state.workspace.edges
    .map((edge) => String(edge?.properties?.catalog?.flow_template_id || ""))
    .filter(Boolean));
  const referenceRoutes = state.dfdShowReferenceFlows ? (state.bootstrap?.dfd_flow_templates || [])
    .filter((flow) => Number(flow?.level) === level
      && flow?.active === true
      && String(flow?.review_status || "").toUpperCase() === "APPROVED"
      && !activeFlowTemplateIds.has(String(flow.id)))
    .map((flow) => {
      const source = referenceByAssetType.get(String(flow.source_asset_type_id));
      const target = referenceByAssetType.get(String(flow.target_asset_type_id));
      return source && target ? { flow, source, target } : null;
    }).filter(Boolean) : [];
  const referenceRoutingInputs = referenceRoutes.map(({ flow, source, target }) => ({
    ...flow,
    source: source.id ?? flow.source_asset_type_id,
    target: target.id ?? flow.target_asset_type_id,
  }));
  const combinedReferenceOffsets = DFD_SELECTION.automaticEdgeCurveOffsets([
    ...state.workspace.edges,
    ...referenceRoutingInputs,
  ]);
  const referenceCurveOffsets = combinedReferenceOffsets.slice(state.workspace.edges.length);
  const referenceEdges = referenceRoutes.map(({ flow, source, target }, index) => {
    const curveOffset = referenceCurveOffsets[index] || 0;
    const geometry = edgeCurveGeometry(source, target, curveOffset);
    return `<path class="reference-edge" data-reference-source-id="${escapeHtml(source.id)}" data-reference-target-id="${escapeHtml(target.id)}" data-curve-offset="${curveOffset}" d="${geometry.path}" marker-end="url(#reference-arrow)"><title>${escapeHtml(edgeDisplayName(flow, "기준 흐름"))} (평가에 미포함)</title></path>`;
  }).join("");
  const referenceNodes = inactiveReferences.map((node) => {
    const width = Number(node.width || 172); const height = Number(node.height || 66);
    const kind = dfdKindLabel(node.dfd_kind);
    const visibleName = DFD_SHORT_LABELS[String(node.asset_type_id)] || node.name;
    const shapeLines = node.dfd_kind === "data_store" ? `<line x1="8" y1="12" x2="${width - 8}" y2="12"></line><line x1="8" y1="${height - 12}" x2="${width - 8}" y2="${height - 12}"></line>` : "";
    return `<g class="reference-node" data-reference-asset-id="${escapeHtml(node.asset_type_id)}" transform="translate(${node.x},${node.y})" role="button" tabindex="0" aria-label="${escapeHtml(node.name)} 기준 요소를 평가에 포함"><title>${escapeHtml(node.name)} 클릭 시 평가에 포함</title><rect width="${width}" height="${height}" rx="${node.dfd_kind === "external" ? 24 : 8}"></rect>${shapeLines}<text class="reference-node-label" x="${width / 2}" y="${height / 2}">${escapeHtml(compactDfdCanvasLabel(visibleName))}</text><text class="reference-node-type" x="${width / 2}" y="${height / 2 + 17}">${escapeHtml(kind)} (미포함)</text></g>`;
  }).join("");
  const boundaries = state.workspace.boundaries.map((boundary) => {
    const x = Number(boundary.x);
    const y = Number(boundary.y);
    const width = Number(boundary.width);
    const height = Number(boundary.height);
    const selected = state.selected?.type === "boundary" && String(state.selected.id) === String(boundary.id);
    return `<g class="boundary ${selected ? "selected" : ""}" data-boundary-id="${escapeHtml(boundary.id)}">
      <rect class="boundary-shape" x="${x}" y="${y}" width="${width}" height="${height}" rx="8"></rect>
      <rect class="boundary-hit-area" x="${x}" y="${y}" width="${width}" height="${height}" rx="8"></rect>
      <text class="boundary-label" x="${x + 9}" y="${y + 17}">${escapeHtml(boundary.name)}</text>
    </g>`;
  }).join("");
  const selectedBoundary = state.selected?.type === "boundary"
    ? state.workspace.boundaries.find((boundary) => String(boundary.id) === String(state.selected.id))
    : null;
  const boundarySelectionOverlay = selectedBoundary
    ? `<g class="boundary-selection-overlay" data-boundary-id="${escapeHtml(selectedBoundary.id)}">${boundaryResizeHandlesMarkup(selectedBoundary)}</g>`
    : "";
  const activeCurveOffsets = edgeCurveOffsets(state.workspace.edges);
  const occupiedEdgeLabels = dfdRectanglesForLabelAvoidance(sceneNodes);
  const edges = state.workspace.edges.map((edge, index) => {
    const source = nodeById(edge.source); const target = nodeById(edge.target);
    if (!source || !target) return "";
    const geometry = edgeCurveGeometry(source, target, activeCurveOffsets[index]);
    const visibleName = edgeDisplayName(edge);
    const manualLabelT = DFD_SELECTION.explicitEdgeLabelT(edge);
    const label = visibleName
      ? manualLabelT === null
        ? placeDfdEdgeLabel(geometry, visibleName, occupiedEdgeLabels)
        : dfdEdgeLabelAt(geometry, visibleName, manualLabelT)
      : null;
    if (label && manualLabelT !== null) {
      occupiedEdgeLabels.push({ left: label.x - label.width / 2, right: label.x + label.width / 2, top: label.y - 14, bottom: label.y + 5 });
    }
    return `<g data-edge-id="${escapeHtml(edge.id)}"><path class="edge-hit-area" d="${geometry.path}"></path><path class="edge-line ${state.selected?.type === "edge" && state.selected.id === edge.id ? "selected" : ""}" d="${geometry.path}" marker-end="url(#arrow)"></path>${label ? `<g class="edge-label-group" data-edge-label="true"><rect class="edge-label-background" data-label-width="${label.width}" x="${label.x - label.width / 2}" y="${label.y - 14}" width="${label.width}" height="18" rx="4"></rect><text class="edge-label" x="${label.x}" y="${label.y}" text-anchor="middle">${escapeHtml(visibleName)}</text></g>` : ""}</g>`;
  }).join("");
  const nodes = state.workspace.nodes.map((node, index) => {
    const selected = selectedNodeIds.has(String(node.id));
    const width = Number(node.width || 150); const height = Number(node.height || 64);
    const fullName = nodeDisplayName(node);
    const visibleName = dfdCanvasNodeLabel(node);
    const visibleType = dfdDisplayName(node.asset_type_name, assetDisplayName(node.asset_type_id, dfdKindLabel(node.dfd_kind)));
    const projectionCount = Number(node?.properties?.manifest_projection?.member_count || 0);
    const secondaryLabel = logicalManifestInstance(node)
      ? visibleType
      : projectionCount
      ? `Manifest 근거 ${projectionCount}개`
      : visibleType === fullName ? dfdKindLabel(node.dfd_kind) : visibleType;
    const fill = node.dfd_kind === "external" ? "#f3f0ff" : node.dfd_kind === "data_store" ? "#eef9f5" : "#f1f6ff";
    const shape = `<rect class="node-shape" width="${width}" height="${height}" rx="${node.dfd_kind === "external" ? Math.min(24, height / 2) : 8}" style="fill:${fill}"></rect>${node.dfd_kind === "data_store" ? `<line class="node-store-rule node-store-rule-top" x1="8" y1="12" x2="${width - 8}" y2="12" stroke="#5b8a7b"/><line class="node-store-rule node-store-rule-bottom" x1="8" y1="${height - 12}" x2="${width - 8}" y2="${height - 12}" stroke="#5b8a7b"/>` : ""}`;
    const roles = attackCaseRolesForNode(node.id);
    const entryBadge = roles.isEntry ? `<rect x="5" y="5" width="29" height="15" rx="7" fill="#1d63d8"></rect><text class="node-badge" x="19.5" y="15.5">진입</text>` : "";
    const targetBadge = roles.isTarget ? `<rect x="${width - 37}" y="5" width="32" height="15" rx="7" fill="#cf4550"></rect><text class="node-badge" x="${width - 21}" y="15.5">대상</text>` : "";
    const evidenceClass = hasManifestEvidence(node) ? "manifest-evidence" : "";
    const textLayout = dfdNodeLabelLayout(visibleName, width, height);
    const typeLimit = Math.max(16, Math.floor((width - 24) / 6.5));
    const connectionPorts = nodeConnectionPortsMarkup(width, height);
    const resizeHandles = selected && !multipleNodesSelected ? nodeResizeHandlesMarkup(width, height) : "";
    const textClipId = `dfd-node-text-${index}`;
    return `<g class="node-group ${evidenceClass} ${selected ? "selected" : ""} ${selected && multipleNodesSelected ? "multi-selected" : ""}" data-node-id="${escapeHtml(node.id)}" transform="translate(${node.x},${node.y})"><title>${escapeHtml(fullName)}</title><clipPath id="${textClipId}"><rect x="6" y="6" width="${Math.max(1, width - 12)}" height="${Math.max(1, height - 12)}" rx="${node.dfd_kind === "external" ? Math.min(18, height / 2) : 5}"></rect></clipPath>${shape}${entryBadge}${targetBadge}<g class="node-text-content" clip-path="url(#${textClipId})">${dfdNodeLabelMarkup(visibleName, width, height)}<text class="node-type" x="${width / 2}" y="${textLayout.typeBaseline}">${escapeHtml(compactDfdCanvasLabel(secondaryLabel, typeLimit))}</text></g>${connectionPorts}${resizeHandles}</g>`;
  }).join("");
  const zoom = state.dfdZoom === null ? null : Math.max(0.5, Math.min(2, Number(state.dfdZoom) || 1));
  const viewportX = Number.isFinite(Number(state.dfdViewportX)) ? Number(state.dfdViewportX) : 0;
  const viewportY = Number.isFinite(Number(state.dfdViewportY)) ? Number(state.dfdViewportY) : 0;
  const sizing = zoom === null ? "" : ` style="width:${Math.round(canvasWidth * zoom)}px;height:${Math.round(canvasHeight * zoom)}px"`;
  return `<svg class="dfd-canvas ${zoom === null ? "fit" : "zoomed"}" id="dfd-canvas" data-workspace-width="${canvasWidth}" data-workspace-height="${canvasHeight}" viewBox="${viewportX} ${viewportY} ${canvasWidth} ${canvasHeight}" preserveAspectRatio="xMinYMin meet" tabindex="0" role="group" aria-label="DFD 캔버스. 빈 공간을 드래그하면 여러 구성요소를 선택할 수 있습니다."${sizing}>
    <defs><pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse"><rect width="20" height="20" fill="white"/><path d="M 20 0 L 0 0 0 20" fill="none" stroke="#e8edf4" stroke-width="1"/></pattern><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#73839a"/></marker><marker id="draft-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#2166d1"/></marker><marker id="reference-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#bcc6d4"/></marker></defs>
    <rect class="canvas-background" x="${viewportX}" y="${viewportY}" width="${canvasWidth}" height="${canvasHeight}" fill="url(#grid)"></rect>${boundaries}${referenceEdges}${edges}<path id="dfd-connection-preview" class="dfd-connection-preview" d="" marker-end="url(#arrow)" visibility="hidden"></path>${referenceNodes}${nodes}${pendingDfdFlowMarkup()}${boundarySelectionOverlay}
    <rect id="dfd-marquee" class="dfd-marquee" x="0" y="0" width="0" height="0" visibility="hidden"></rect>
  </svg>`;
}

function inspectorMarkup() {
  const selectedNodeIds = selectedDfdNodeIds();
  if (selectedNodeIds.length > 1) {
    const selectedNodes = selectedNodeIds.map((id) => nodeById(id)).filter(Boolean);
    const entryCount = selectedNodes.filter((node) => attackCaseRolesForNode(node.id).isEntry).length;
    const targetCount = selectedNodes.filter((node) => attackCaseRolesForNode(node.id).isTarget).length;
    return `<div class="multi-selection-panel"><span class="multi-selection-count">${selectedNodes.length}</span><strong>개 구성요소 선택됨</strong><p>선택한 요소를 함께 이동하거나 삭제할 수 있습니다. 속성을 바꾸려면 요소 하나만 선택하세요.</p><div class="multi-selection-meta"><span>진입 ${entryCount}</span><span>대상 ${targetCount}</span></div><button type="button" class="btn danger" id="delete-multi-selection">선택 ${selectedNodes.length}개 삭제</button></div>`;
  }
  if (!state.selected) return `<div class="empty-panel">구성요소, 데이터 흐름 또는 신뢰 경계를 선택하세요.<span>빈 공간을 드래그하면 여러 요소를 묶어서 선택할 수 있습니다.</span></div>`;
  if (state.selected.type === "node") {
    const node = nodeById(state.selected.id);
    if (!node) return "";
    const catalogAssets = dfdCatalogAssets();
    const currentAsset = assetById(node.asset_type_id);
    const selectableAssets = currentAsset && !catalogAssets.some((asset) => asset.id === currentAsset.id) ? [currentAsset, ...catalogAssets] : catalogAssets;
    const options = selectableAssets.map((asset) => `<option value="${escapeHtml(asset.id)}" ${asset.id === node.asset_type_id ? "selected" : ""}>${escapeHtml(assetDisplayName(asset))}</option>`).join("");
    const roles = attackCaseRolesForNode(node.id);
    const roleLabels = [roles.isEntry ? "Entry" : "", roles.isTarget ? "Target" : ""].filter(Boolean);
    return `<div class="notice info inspector-warning"><div>ⓘ</div><div><strong>Case에서 계산되는 역할: ${escapeHtml(roleLabels.join(" + ") || "없음")}</strong>Entry/Target은 아래 Attack Case Builder에서 Case별로 지정합니다.</div></div><div class="form-field"><label for="node-name">표시 이름</label><textarea id="node-name" rows="3" maxlength="${DFD_NODE_TEXT_LIMITS.name.max}" data-character-count>${escapeHtml(nodeDisplayName(node))}</textarea><span class="input-help">Enter로 줄을 나눌 수 있습니다. 캔버스 요소를 더블 클릭해 바로 편집할 수도 있습니다.</span><button type="button" class="btn small node-auto-size" id="node-auto-size" ${dfdNodeUsesManualSize(node) ? "" : "disabled"}>내용에 맞게 자동 크기</button></div>
      <div class="form-field"><label>자산 유형</label><select id="node-asset">${options}</select></div>
      <div class="form-field"><label>설명</label><textarea id="node-description" maxlength="${DFD_NODE_TEXT_LIMITS.description.max}" data-character-count>${escapeHtml(node.description || "")}</textarea></div>`;
  }
  if (state.selected.type === "edge") {
    const edge = state.workspace.edges.find((item) => item.id === state.selected.id);
    if (!edge) return "";
    const edgeIndex = state.workspace.edges.indexOf(edge);
    const automaticOffset = DFD_SELECTION.automaticEdgeCurveOffsets(state.workspace.edges)[edgeIndex] || 0;
    const explicitOffset = DFD_SELECTION.explicitEdgeCurveOffset(edge);
    const explicitLabelT = DFD_SELECTION.explicitEdgeLabelT(edge);
    const curveOffset = explicitOffset ?? automaticOffset;
    const curveMode = explicitOffset === null ? "자동" : "수동";
    return `<div class="notice info"><div>→</div><div><strong>${escapeHtml(nodeDisplayName(edge.source))} → ${escapeHtml(nodeDisplayName(edge.target))}</strong>이 방향으로 후보 검색에 사용됩니다.</div></div><div class="form-field"><label>데이터 흐름 이름</label><input id="edge-name" value="${escapeHtml(edgeDisplayName(edge))}"></div><div class="form-field"><label>프로토콜</label><input id="edge-protocol" value="${escapeHtml(edge.protocol || "")}" placeholder="HTTPS, gRPC"></div><div class="form-field"><label>데이터</label><textarea id="edge-data">${escapeHtml(edge.data_type || "")}</textarea></div><div class="form-field edge-curve-control"><label for="edge-curve">선 휨 <output id="edge-curve-value">${curveMode} ${Math.round(curveOffset)}</output></label><input id="edge-curve" type="range" min="-180" max="180" step="1" value="${curveOffset}"><span class="input-help">겹치는 양방향 또는 평행 흐름은 자동으로 분리됩니다. 슬라이더로 이 선만 조정할 수 있습니다.</span><div class="edge-curve-actions"><button type="button" class="btn small" id="edge-curve-auto" ${explicitOffset === null ? "disabled" : ""}>자동 분리</button><button type="button" class="btn small" id="edge-curve-straight">직선으로</button></div></div><div class="form-field edge-label-control"><label>라벨 위치</label><span class="input-help">캔버스에서 라벨을 잡아 데이터 흐름 선을 따라 옮길 수 있습니다.</span><button type="button" class="btn small" id="edge-label-auto" ${explicitLabelT === null ? "disabled" : ""}>자동 배치로 복원</button></div>`;
  }
  const boundary = state.workspace.boundaries.find((item) => item.id === state.selected.id);
  if (!boundary) return "";
  return `<div class="form-field"><label>신뢰 경계 이름</label><input id="boundary-name" value="${escapeHtml(boundary.name)}"></div><p class="input-help boundary-resize-help">선택된 경계에 표시된 8개 조절점을 끌어 원하는 방향으로 크기를 조절할 수 있습니다.</p>`;
}

function dfdNodeById(id) {
  return nodeById(id)
    || state.workspace.nodes.find((node) => String(node.id) === String(id))
    || catalogReferenceNodes(currentDfdCatalogLevel()).find((node) => String(node.id) === String(id));
}

function svgPoint(event, clampToCanvas = false) {
  const svg = $("#dfd-canvas");
  const point = svg.createSVGPoint(); point.x = event.clientX; point.y = event.clientY;
  const transformed = point.matrixTransform(svg.getScreenCTM().inverse());
  if (!clampToCanvas) return transformed;
  const viewBox = svg.viewBox.baseVal;
  return {
    x: Math.min(viewBox.x + viewBox.width, Math.max(viewBox.x, transformed.x)),
    y: Math.min(viewBox.y + viewBox.height, Math.max(viewBox.y, transformed.y)),
  };
}

function captureDfdSelection() {
  return {
    selected: state.selected ? { ...state.selected } : null,
    selectedNodeIds: [...selectedDfdNodeIds()],
  };
}

function restoreDfdSelection(snapshot) {
  state.selected = snapshot?.selected ? { ...snapshot.selected } : null;
  state.selectedNodeIds = [...(snapshot?.selectedNodeIds || [])];
}

function focusDfdCanvas() {
  $("#dfd-canvas")?.focus({ preventScroll: true });
}

function renderDfdStepAndFocus() {
  renderDfdStep();
  focusDfdCanvas();
}

function syncDfdNodeSelectionClasses(canvas, ids = selectedDfdNodeIds(), preview = false) {
  const selectedIds = new Set(ids.map((id) => String(id)));
  const multiple = selectedIds.size > 1;
  $$("[data-node-id]", canvas).forEach((group) => {
    const selected = selectedIds.has(String(group.dataset.nodeId));
    group.classList.toggle("selected", selected);
    group.classList.toggle("multi-selected", selected && multiple);
    group.classList.toggle("marquee-preview", selected && preview);
  });
}

function updateDfdNodePositions(canvas, ids) {
  const selectedIds = new Set(ids.map((id) => String(id)));
  $$("[data-node-id]", canvas).forEach((group) => {
    if (!selectedIds.has(String(group.dataset.nodeId))) return;
    const node = dfdNodeById(group.dataset.nodeId);
    if (node) group.setAttribute("transform", `translate(${node.x},${node.y})`);
  });
}

function updateDfdEdgesForNodes(canvas, ids) {
  const movedIds = new Set(ids.map((id) => String(id)));
  const groups = new Map($$("[data-edge-id]", canvas).map((group) => [String(group.dataset.edgeId), group]));
  const curveOffsets = edgeCurveOffsets(state.workspace.edges);
  state.workspace.edges.forEach((edge, index) => {
    if (!movedIds.has(String(edge.source)) && !movedIds.has(String(edge.target))) return;
    const source = dfdNodeById(edge.source);
    const target = dfdNodeById(edge.target);
    const group = groups.get(String(edge.id));
    if (!source || !target || !group) return;
    applyEdgeGeometry(group, edgeCurveGeometry(source, target, curveOffsets[index]), edge);
  });
  $$(".reference-edge[data-reference-source-id][data-reference-target-id]", canvas).forEach((path) => {
    if (!movedIds.has(String(path.dataset.referenceSourceId)) && !movedIds.has(String(path.dataset.referenceTargetId))) return;
    const source = dfdNodeById(path.dataset.referenceSourceId);
    const target = dfdNodeById(path.dataset.referenceTargetId);
    if (!source || !target) return;
    const geometry = edgeCurveGeometry(source, target, Number(path.dataset.curveOffset) || 0);
    path.setAttribute("d", geometry.path);
  });
}

function manualDfdAssetChoices() {
  const result = [];
  const seen = new Set();
  const add = (asset) => {
    if (!asset || seen.has(String(asset.id))) return;
    seen.add(String(asset.id));
    result.push(asset);
  };
  ["GEN-EXT", "GEN-PROC", "GEN-DATA"].forEach((id) => add(assetById(id)));
  dfdCatalogAssets(currentDfdCatalogLevel()).forEach(add);
  add(assetById("D.3"));
  return result;
}

function visibleDfdCanvasCenter() {
  const scrollArea = $(".canvas-scroll-area");
  const canvas = $("#dfd-canvas");
  const matrix = canvas?.getScreenCTM?.();
  if (!scrollArea || !canvas || !matrix) return { x: 100, y: 390 };
  const rect = scrollArea.getBoundingClientRect();
  const point = canvas.createSVGPoint();
  point.x = rect.left + rect.width / 2;
  point.y = rect.top + rect.height / 2;
  try {
    const transformed = point.matrixTransform(matrix.inverse());
    return { x: transformed.x, y: transformed.y };
  } catch (_) {
    return { x: 100, y: 390 };
  }
}

function startPendingDfdFlow(point = visibleDfdCanvasCenter()) {
  const centerX = Number(point?.x) || 100;
  const centerY = Number(point?.y) || 100;
  state.dfdPendingFlow = {
    x1: centerX - 70,
    y1: centerY,
    x2: centerX + 70,
    y2: centerY,
    sourceId: null,
    targetId: null,
  };
  state.dfdPanMode = false;
  state.connectionMode = false;
  state.connectionSource = null;
  clearDfdSelection();
  renderDfdStepAndFocus();
  toast("화살표 양쪽 끝을 각각 DFD 구성요소에 연결하세요.");
}

function addTrustBoundaryAt(point = visibleDfdCanvasCenter()) {
  const width = 430;
  const height = 280;
  const centerX = Number(point?.x) || width / 2 + 20;
  const centerY = Number(point?.y) || height / 2 + 20;
  const boundary = {
    id: randomId("boundary"),
    name: "신뢰 경계",
    x: centerX - width / 2,
    y: centerY - height / 2,
    width,
    height,
  };
  state.workspace.boundaries.push(boundary);
  markDfdDirty();
  setSingleDfdSelection("boundary", boundary.id);
  renderDfdStepAndFocus();
}

function nextManualDfdNodePosition(width = 172, height = 66) {
  const center = visibleDfdCanvasCenter();
  let x = Math.max(10, center.x - width / 2);
  let y = Math.max(10, center.y - height / 2);
  const overlaps = (node) => (
    x < Number(node.x) + Number(node.width || 150) + 12
    && x + width + 12 > Number(node.x)
    && y < Number(node.y) + Number(node.height || 64) + 12
    && y + height + 12 > Number(node.y)
  );
  for (let attempt = 0; attempt < 16 && state.workspace.nodes.some(overlaps); attempt += 1) {
    x += 28;
    y += 28;
  }
  return { x, y };
}

function showDfdNodeModal() {
  $("#add-dfd-node-modal")?.remove();
  const assets = manualDfdAssetChoices();
  if (!assets.length) {
    toast("추가할 수 있는 DFD 구성요소 유형이 없습니다.", true);
    return;
  }
  const defaultAsset = assets.find((asset) => asset.id === "GEN-PROC")
    || assets.find((asset) => asset.id === "P.6")
    || assets[0];
  const options = assets.map((asset) => (
    `<option value="${escapeHtml(asset.id)}" ${asset.id === defaultAsset.id ? "selected" : ""}>${escapeHtml(dfdKindLabel(asset.dfd_kind))}: ${escapeHtml(assetDisplayName(asset))}</option>`
  )).join("");
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="add-dfd-node-modal">
    <div class="modal dfd-node-modal" role="dialog" aria-modal="true" aria-labelledby="add-dfd-node-title">
      <div class="modal-header"><div><h2 id="add-dfd-node-title">DFD 구성요소 추가</h2><p>유형을 고르고 화면에 표시할 짧은 이름을 입력하세요.</p></div><button type="button" class="btn small" data-close-dfd-node>닫기</button></div>
      <form id="add-dfd-node-form">
        <div class="modal-body form-grid">
          <div class="form-field"><label class="required" for="add-dfd-node-type">유형</label><select id="add-dfd-node-type" required>${options}</select></div>
          <div class="form-field"><label class="required" for="add-dfd-node-name">표시 이름</label><textarea id="add-dfd-node-name" rows="2" maxlength="${DFD_NODE_TEXT_LIMITS.name.max}" data-character-count required>${escapeHtml(assetDisplayName(defaultAsset).slice(0, DFD_NODE_TEXT_LIMITS.name.max))}</textarea><span class="input-help">Enter로 도형 안의 줄바꿈을 지정할 수 있습니다.</span></div>
          <div class="form-field full"><label for="add-dfd-node-description">설명</label><textarea id="add-dfd-node-description" maxlength="${DFD_NODE_TEXT_LIMITS.description.max}" data-character-count placeholder="이 구성요소의 역할이나 범위를 간단히 적으세요."></textarea></div>
        </div>
        <div class="modal-footer"><button type="button" class="btn" data-close-dfd-node>취소</button><button type="submit" class="btn primary">캔버스에 추가</button></div>
      </form>
    </div>
  </div>`);
  const modal = $("#add-dfd-node-modal");
  const typeInput = $("#add-dfd-node-type", modal);
  const nameInput = $("#add-dfd-node-name", modal);
  const descriptionInput = $("#add-dfd-node-description", modal);
  bindCharacterCounters($("#add-dfd-node-form", modal));
  let suggestedName = nameInput.value;
  const close = () => modal.remove();
  $$('[data-close-dfd-node]', modal).forEach((button) => button.onclick = close);
  typeInput.onchange = () => {
    const asset = assetById(typeInput.value);
    if (!asset) return;
    if (!nameInput.value.trim() || nameInput.value === suggestedName) {
      suggestedName = assetDisplayName(asset).slice(0, DFD_NODE_TEXT_LIMITS.name.max);
      nameInput.value = suggestedName;
      nameInput.dispatchEvent(new Event("input"));
    }
  };
  $("#add-dfd-node-form", modal).onsubmit = (event) => {
    event.preventDefault();
    const asset = assetById(typeInput.value);
    const name = nameInput.value.trim();
    if (!asset || !name) return;
    const position = nextManualDfdNodePosition();
    const catalog = dfdElementCatalogMetadata(asset.id, currentDfdCatalogLevel());
    const node = {
      id: randomId("node"),
      name,
      asset_type_id: asset.id,
      asset_type_name: asset.name,
      dfd_kind: asset.dfd_kind,
      x: position.x,
      y: position.y,
      width: 172,
      height: 66,
      description: String(descriptionInput.value.trim() || asset.description || "").slice(0, DFD_NODE_TEXT_LIMITS.description.max),
      properties: catalog ? { catalog } : {},
      is_entry: false,
      is_target: false,
      entry_reason: "",
      target_reason: "",
    };
    applyAutomaticDfdNodeSize(node);
    state.workspace.nodes.push(node);
    markDfdDirty();
    setSingleDfdSelection("node", node.id);
    close();
    renderDfdStepAndFocus();
    toast(`${name} 구성요소를 추가했습니다.`);
  };
  nameInput.focus();
  nameInput.select();
}

function activateCatalogReference(assetTypeId) {
  const asset = assetById(assetTypeId);
  if (!asset) return;
  const level = currentDfdCatalogLevel();
  const alreadyActive = state.workspace.nodes.find((node) => (
    String(node.asset_type_id) === String(asset.id)
    && Number(node?.properties?.catalog?.level) === level
  ));
  if (alreadyActive) {
    setSingleDfdSelection("node", alreadyActive.id);
    renderDfdStepAndFocus();
    return;
  }
  const reference = catalogReferenceNodes(level).find((node) => String(node.asset_type_id) === String(asset.id));
  const catalog = dfdElementCatalogMetadata(asset.id, level);
  const node = {
    id: randomId("node"),
    name: String(asset.name || "").slice(0, DFD_NODE_TEXT_LIMITS.name.max),
    asset_type_id: asset.id,
    asset_type_name: asset.name,
    dfd_kind: asset.dfd_kind,
    x: Number(reference?.x ?? 70),
    y: Number(reference?.y ?? 104),
    width: 172,
    height: 66,
    description: String(asset.description || "").slice(0, DFD_NODE_TEXT_LIMITS.description.max),
    properties: catalog ? { catalog } : {},
    is_entry: false,
    is_target: false,
    entry_reason: "",
    target_reason: "",
  };
  state.workspace.nodes.push(node);
  setSingleDfdSelection("node", node.id);
  markDfdDirty();
  renderDfdStepAndFocus();
}

function bindDfdEvents() {
  if (!dfdFocusEscapeBound) {
    document.addEventListener("keydown", (event) => {
      if (event.defaultPrevented || event.key !== "Escape" || !state.dfdFocusMode) return;
      if ($(".modal-backdrop") || state.connectionMode || state.connectionSource || state.dfdPendingFlow || hasDfdSelection()) return;
      event.preventDefault();
      toggleDfdFocusMode();
    });
    dfdFocusEscapeBound = true;
  }
  if (!dfdPanKeyboardBound) {
    const editableTarget = (target) => Boolean(target?.closest?.("input, textarea, select, button, [contenteditable='true']"));
    document.addEventListener("keydown", (event) => {
      if (event.code !== "Space" || event.repeat || editableTarget(event.target) || !$("#dfd-canvas")) return;
      dfdSpacePanHeld = true;
      $("#dfd-canvas")?.closest(".canvas-wrap")?.classList.add("space-pan-ready");
      event.preventDefault();
    });
    document.addEventListener("keyup", (event) => {
      if (event.code !== "Space") return;
      dfdSpacePanHeld = false;
      $("#dfd-canvas")?.closest(".canvas-wrap")?.classList.remove("space-pan-ready");
    });
    window.addEventListener("blur", () => {
      dfdSpacePanHeld = false;
      $("#dfd-canvas")?.closest(".canvas-wrap")?.classList.remove("space-pan-ready");
    });
    dfdPanKeyboardBound = true;
  }
  $$('.palette-node[data-asset-id]').forEach((item) => {
    item.ondragstart = (event) => {
      event.dataTransfer.effectAllowed = "copy";
      event.dataTransfer.setData("asset-id", item.dataset.assetId);
    };
  });
  const activatePaletteTool = (tool, point) => {
    if (tool === "flow") startPendingDfdFlow(point);
    else if (tool === "boundary") addTrustBoundaryAt(point);
  };
  $$('[data-dfd-tool]').forEach((item) => {
    item.ondragstart = (event) => {
      event.dataTransfer.effectAllowed = "copy";
      event.dataTransfer.setData("dfd-tool", item.dataset.dfdTool);
    };
    item.onclick = () => activatePaletteTool(item.dataset.dfdTool, visibleDfdCanvasCenter());
    item.onkeydown = (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      activatePaletteTool(item.dataset.dfdTool, visibleDfdCanvasCenter());
    };
  });
  const canvas = $("#dfd-canvas");
  const scrollArea = canvas.closest(".canvas-scroll-area");
  canvas.closest(".canvas-wrap")?.classList.toggle("space-pan-ready", dfdSpacePanHeld);
  $$('[data-reference-asset-id]', canvas).forEach((item) => {
    item.onclick = () => activateCatalogReference(item.dataset.referenceAssetId);
    item.onkeydown = (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      activateCatalogReference(item.dataset.referenceAssetId);
    };
  });
  const dragThreshold = 4;
  const autoScrollableKinds = new Set(["node", "boundary", "connection-handle", "pending-flow-endpoint"]);
  let gesture = null;

  const hasModifier = (event) => event.shiftKey || event.ctrlKey || event.metaKey;
  const distanceFromStart = (event, active) => Math.hypot(event.clientX - active.startClientX, event.clientY - active.startClientY);
  const capturePointer = (event) => {
    try { canvas.setPointerCapture(event.pointerId); } catch (_) { /* Pointer capture is best effort. */ }
  };
  const releasePointer = (active) => {
    try { if (canvas.hasPointerCapture(active.pointerId)) canvas.releasePointerCapture(active.pointerId); } catch (_) { /* Canvas may already be replaced. */ }
  };
  const completeGesture = (active, render = true) => {
    gesture = null;
    active.scrollArea?.classList.remove("is-panning");
    canvas.closest(".canvas-wrap")?.classList.remove("is-dragging");
    releasePointer(active);
    if (render) renderDfdStepAndFocus();
  };
  const clearConnectionHandlePreview = () => {
    const preview = $("#dfd-connection-preview", canvas);
    if (preview) {
      preview.setAttribute("d", "");
      preview.setAttribute("visibility", "hidden");
    }
    $$(".node-group.connection-target", canvas).forEach((group) => group.classList.remove("connection-target"));
  };
  const connectionTargetAt = (clientX, clientY) => {
    const elements = typeof document.elementsFromPoint === "function"
      ? document.elementsFromPoint(clientX, clientY)
      : [document.elementFromPoint(clientX, clientY)];
    return elements.map((element) => element?.closest?.("[data-node-id]")).find(Boolean) || null;
  };
  const updatePendingFlowDom = (draft) => {
    const group = $("[data-pending-flow]", canvas);
    if (!group || !draft) return;
    const line = group.querySelector(".pending-flow-line");
    const source = group.querySelector('[data-pending-flow-endpoint="source"]');
    const target = group.querySelector('[data-pending-flow-endpoint="target"]');
    const help = group.querySelector(".pending-flow-help");
    line?.setAttribute("d", `M ${draft.x1} ${draft.y1} L ${draft.x2} ${draft.y2}`);
    source?.setAttribute("cx", draft.x1); source?.setAttribute("cy", draft.y1);
    target?.setAttribute("cx", draft.x2); target?.setAttribute("cy", draft.y2);
    help?.setAttribute("x", (Number(draft.x1) + Number(draft.x2)) / 2);
    help?.setAttribute("y", (Number(draft.y1) + Number(draft.y2)) / 2 - 12);
  };
  const updateBoundaryDom = (group, boundary) => {
    if (!group || !boundary) return;
    const x = Number(boundary.x);
    const y = Number(boundary.y);
    const width = Number(boundary.width);
    const height = Number(boundary.height);
    const matchingGroups = $$('[data-boundary-id]', canvas)
      .filter((candidate) => String(candidate.dataset.boundaryId) === String(boundary.id));
    matchingGroups.forEach((candidate) => {
      candidate.querySelectorAll(".boundary-shape, .boundary-hit-area").forEach((shape) => {
        shape.setAttribute("x", x);
        shape.setAttribute("y", y);
        shape.setAttribute("width", width);
        shape.setAttribute("height", height);
      });
      const label = candidate.querySelector(".boundary-label");
      label?.setAttribute("x", x + 9);
      label?.setAttribute("y", y + 17);
      candidate.querySelectorAll("[data-boundary-resize-handle]").forEach((handle) => {
        const direction = handle.dataset.boundaryResizeHandle;
        const cx = direction.includes("w") ? x : direction.includes("e") ? x + width : x + width / 2;
        const cy = direction.includes("n") ? y : direction.includes("s") ? y + height : y + height / 2;
        handle.setAttribute("cx", cx);
        handle.setAttribute("cy", cy);
      });
    });
  };
  const updateNodeSizeDom = (group, node) => {
    if (!group || !node) return;
    const width = Number(node.width || 150);
    const height = Number(node.height || 64);
    group.setAttribute("transform", `translate(${Number(node.x)},${Number(node.y)})`);
    const shape = group.querySelector(".node-shape");
    shape?.setAttribute("width", width);
    shape?.setAttribute("height", height);
    shape?.setAttribute("rx", node.dfd_kind === "external" ? Math.min(24, height / 2) : 8);
    const topRule = group.querySelector(".node-store-rule-top");
    const bottomRule = group.querySelector(".node-store-rule-bottom");
    topRule?.setAttribute("x2", width - 8);
    bottomRule?.setAttribute("x2", width - 8);
    bottomRule?.setAttribute("y1", height - 12);
    bottomRule?.setAttribute("y2", height - 12);
    group.querySelectorAll("[data-node-resize-handle]").forEach((handle) => {
      const direction = handle.dataset.nodeResizeHandle;
      handle.setAttribute("x", (direction.includes("w") ? 0 : width) - 5);
      handle.setAttribute("y", (direction.includes("n") ? 0 : height) - 5);
    });
  };
  const cancelGesture = () => {
    if (!gesture) return;
    const active = gesture;
    gesture = null;
    active.scrollArea?.classList.remove("is-panning");
    canvas.closest(".canvas-wrap")?.classList.remove("is-dragging");
    if (active.kind === "pan") {
      releasePointer(active);
      focusDfdCanvas();
      return;
    }
    if (active.kind === "node" && active.origins) DFD_SELECTION.applyGroupMove(state.workspace.nodes, active.origins, 0, 0);
    if (active.kind === "boundary" && active.boundary) {
      active.boundary.x = active.origin.x;
      active.boundary.y = active.origin.y;
    }
    if (active.kind === "boundary-resize" && active.boundary) {
      active.boundary.x = active.origin.x;
      active.boundary.y = active.origin.y;
      active.boundary.width = active.origin.width;
      active.boundary.height = active.origin.height;
    }
    if (active.kind === "node-resize" && active.node) {
      active.node.x = active.origin.x;
      active.node.y = active.origin.y;
      active.node.width = active.origin.width;
      active.node.height = active.origin.height;
    }
    if (active.kind === "edge" && active.edge) setEdgeCurveOffset(active.edge, active.originalExplicitOffset);
    if (active.kind === "edge-label" && active.edge) setEdgeLabelT(active.edge, active.originalExplicitLabelT);
    if (active.kind === "connection-handle") clearConnectionHandlePreview();
    if (active.kind === "pending-flow-endpoint") {
      state.dfdPendingFlow = active.originalDraft;
      clearConnectionHandlePreview();
    }
    restoreDfdSelection(active.selectionBefore);
    releasePointer(active);
    renderDfdStepAndFocus();
  };

  canvas.ondragover = (event) => event.preventDefault();
  canvas.ondrop = (event) => {
    event.preventDefault();
    const tool = event.dataTransfer.getData("dfd-tool");
    if (tool) {
      activatePaletteTool(tool, svgPoint(event, false));
      return;
    }
    const asset = assetById(event.dataTransfer.getData("asset-id"));
    if (!asset) return;
    const point = svgPoint(event, true);
    const catalog = dfdElementCatalogMetadata(asset.id);
    const node = { id: randomId("node"), name: String(asset.name || "").slice(0, DFD_NODE_TEXT_LIMITS.name.max), asset_type_id: asset.id, asset_type_name: asset.name, dfd_kind: asset.dfd_kind, x: Math.max(10, point.x - 75), y: Math.max(10, point.y - 32), width: 150, height: 64, description: String(asset.description || "").slice(0, DFD_NODE_TEXT_LIMITS.description.max), properties: catalog ? { catalog } : {}, is_entry: false, is_target: false, entry_reason: "", target_reason: "" };
    applyAutomaticDfdNodeSize(node);
    state.workspace.nodes.push(node);
    setSingleDfdSelection("node", node.id);
    markDfdDirty();
    renderDfdStep();
  };

  canvas.onpointerdown = (event) => {
    const panRequested = state.dfdPanMode || dfdSpacePanHeld || event.button === 1;
    if ((!panRequested && event.button !== 0) || event.isPrimary === false || gesture) return;
    focusDfdCanvas();
    const resizeHandle = event.target.closest?.("[data-boundary-resize-handle]");
    const nodeResizeHandle = event.target.closest?.("[data-node-resize-handle]");
    const connectionHandle = event.target.closest?.("[data-connection-handle]");
    const pendingFlowEndpoint = event.target.closest?.("[data-pending-flow-endpoint]");
    const edgeLabel = event.target.closest?.("[data-edge-label]");
    const nodeGroup = event.target.closest?.("[data-node-id]");
    const edgeGroup = event.target.closest?.("[data-edge-id]");
    const boundaryGroup = resizeHandle?.closest?.("[data-boundary-id]")
      || (event.target.classList?.contains("boundary-hit-area") ? event.target.closest("[data-boundary-id]") : null);
    const base = {
      pointerId: event.pointerId,
      startClientX: event.clientX,
      startClientY: event.clientY,
      startPoint: svgPoint(event, true),
      modifier: hasModifier(event),
      moved: false,
      selectionBefore: captureDfdSelection(),
      nodeIdsBefore: selectedDfdNodeIds(),
    };

    if (panRequested) {
      const viewBox = canvas.viewBox.baseVal;
      gesture = {
        ...base,
        kind: "pan",
        scrollArea,
        origin: { x: viewBox.x, y: viewBox.y, width: viewBox.width, height: viewBox.height },
      };
    } else if (nodeResizeHandle && nodeGroup) {
      const node = nodeById(nodeGroup.dataset.nodeId);
      if (!node) return;
      setSingleDfdSelection("node", node.id);
      gesture = {
        ...base,
        kind: "node-resize",
        node,
        group: nodeGroup,
        handle: nodeResizeHandle.dataset.nodeResizeHandle || "se",
        origin: { x: Number(node.x), y: Number(node.y), width: Number(node.width || 150), height: Number(node.height || 64) },
      };
    } else if (connectionHandle && nodeGroup) {
      const sourceId = nodeGroup.dataset.nodeId;
      const preview = $("#dfd-connection-preview", canvas);
      if (preview) {
        preview.setAttribute("d", `M ${base.startPoint.x} ${base.startPoint.y} L ${base.startPoint.x} ${base.startPoint.y}`);
        preview.setAttribute("visibility", "visible");
      }
      gesture = { ...base, kind: "connection-handle", sourceId, preview };
    } else if (pendingFlowEndpoint && state.dfdPendingFlow) {
      gesture = {
        ...base,
        kind: "pending-flow-endpoint",
        role: pendingFlowEndpoint.dataset.pendingFlowEndpoint,
        draft: state.dfdPendingFlow,
        originalDraft: { ...state.dfdPendingFlow },
      };
    } else if (edgeLabel && edgeGroup) {
      const edge = state.workspace.edges.find((item) => String(item.id) === String(edgeGroup.dataset.edgeId));
      const source = edge ? dfdNodeById(edge.source) : null;
      const target = edge ? dfdNodeById(edge.target) : null;
      if (!edge || !source || !target) return;
      const edgeIndex = state.workspace.edges.indexOf(edge);
      gesture = {
        ...base,
        kind: "edge-label",
        edge,
        edgeId: edgeGroup.dataset.edgeId,
        group: edgeGroup,
        geometry: edgeCurveGeometry(source, target, edgeCurveOffsets(state.workspace.edges)[edgeIndex]),
        originalExplicitLabelT: DFD_SELECTION.explicitEdgeLabelT(edge),
      };
    } else if (state.connectionMode) {
      if (!nodeGroup) return;
      gesture = { ...base, kind: "connection", nodeId: nodeGroup.dataset.nodeId };
    } else if (nodeGroup) {
      const nodeId = nodeGroup.dataset.nodeId;
      const selectedBefore = new Set(base.nodeIdsBefore.map((id) => String(id)));
      const dragIds = selectedBefore.has(String(nodeId))
        ? base.nodeIdsBefore
        : base.modifier ? [...base.nodeIdsBefore, nodeId] : [nodeId];
      gesture = { ...base, kind: "node", nodeId, dragIds, origins: DFD_SELECTION.snapshotNodePositions(state.workspace.nodes, dragIds) };
    } else if (resizeHandle && boundaryGroup) {
      const boundary = state.workspace.boundaries.find((item) => String(item.id) === String(boundaryGroup.dataset.boundaryId));
      if (!boundary) return;
      boundaryGroup.classList.add("selected");
      gesture = {
        ...base,
        kind: "boundary-resize",
        boundary,
        group: boundaryGroup,
        handle: resizeHandle.dataset.boundaryResizeHandle || "se",
        origin: { x: Number(boundary.x), y: Number(boundary.y), width: Number(boundary.width), height: Number(boundary.height) },
      };
    } else if (boundaryGroup) {
      const boundary = state.workspace.boundaries.find((item) => String(item.id) === String(boundaryGroup.dataset.boundaryId));
      if (!boundary) return;
      gesture = { ...base, kind: "boundary", boundary, group: boundaryGroup, origin: { x: Number(boundary.x), y: Number(boundary.y) } };
    } else if (edgeGroup) {
      const edge = state.workspace.edges.find((item) => String(item.id) === String(edgeGroup.dataset.edgeId));
      if (!edge) return;
      const edgeIndex = state.workspace.edges.indexOf(edge);
      const source = dfdNodeById(edge.source);
      const target = dfdNodeById(edge.target);
      const sourceCenter = { x: Number(source.x) + Number(source.width || 150) / 2, y: Number(source.y) + Number(source.height || 64) / 2 };
      const targetCenter = { x: Number(target.x) + Number(target.width || 150) / 2, y: Number(target.y) + Number(target.height || 64) / 2 };
      const dx = targetCenter.x - sourceCenter.x;
      const dy = targetCenter.y - sourceCenter.y;
      const length = Math.max(1, Math.hypot(dx, dy));
      gesture = {
        ...base,
        kind: "edge",
        edge,
        edgeId: edgeGroup.dataset.edgeId,
        group: edgeGroup,
        source,
        target,
        startOffset: edgeCurveOffsets(state.workspace.edges)[edgeIndex] || 0,
        originalExplicitOffset: DFD_SELECTION.explicitEdgeCurveOffset(edge),
        normal: { x: -dy / length, y: dx / length },
      };
    } else if (event.target.classList?.contains("canvas-background") || event.target === canvas) {
      gesture = { ...base, kind: "background", candidateIds: base.nodeIdsBefore };
    } else return;

    capturePointer(event);
    event.preventDefault();
  };

  canvas.onpointermove = (event) => {
    if (!gesture || event.pointerId !== gesture.pointerId) return;
    const active = gesture;
    if (active.kind === "connection") return;
    if (!active.moved && distanceFromStart(event, active) < dragThreshold) return;
    active.moved = true;
    canvas.closest(".canvas-wrap")?.classList.add("is-dragging");
    if (active.kind === "pan") {
      active.scrollArea.classList.add("is-panning");
      const rect = canvas.getBoundingClientRect();
      const scaleX = active.origin.width / Math.max(1, rect.width);
      const scaleY = active.origin.height / Math.max(1, rect.height);
      const nextX = active.origin.x - (event.clientX - active.startClientX) * scaleX;
      const nextY = active.origin.y - (event.clientY - active.startClientY) * scaleY;
      state.dfdViewportX = nextX;
      state.dfdViewportY = nextY;
      canvas.setAttribute("viewBox", `${nextX} ${nextY} ${active.origin.width} ${active.origin.height}`);
      const background = canvas.querySelector(".canvas-background");
      if (background) {
        background.setAttribute("x", nextX);
        background.setAttribute("y", nextY);
        background.setAttribute("width", active.origin.width);
        background.setAttribute("height", active.origin.height);
      }
      event.preventDefault();
      return;
    }
    if (autoScrollableKinds.has(active.kind)) {
      const scrollDelta = DFD_SELECTION.dragAutoScrollDelta(
        { x: event.clientX, y: event.clientY },
        scrollArea.getBoundingClientRect(),
      );
      if (scrollDelta.x || scrollDelta.y) {
        scrollArea.scrollLeft += scrollDelta.x;
        scrollArea.scrollTop += scrollDelta.y;
        state.dfdScrollLeft = scrollArea.scrollLeft;
        state.dfdScrollTop = scrollArea.scrollTop;
      }
    }
    const unconstrainedMove = active.kind === "node" || active.kind === "boundary"
      || active.kind === "boundary-resize" || active.kind === "node-resize";
    const point = svgPoint(event, !unconstrainedMove);

    if (active.kind === "pending-flow-endpoint") {
      const xKey = active.role === "source" ? "x1" : "x2";
      const yKey = active.role === "source" ? "y1" : "y2";
      const idKey = active.role === "source" ? "sourceId" : "targetId";
      active.draft[xKey] = point.x;
      active.draft[yKey] = point.y;
      active.draft[idKey] = null;
      updatePendingFlowDom(active.draft);
      $$(".node-group.connection-target", canvas).forEach((group) => group.classList.remove("connection-target"));
      connectionTargetAt(event.clientX, event.clientY)?.classList.add("connection-target");
      event.preventDefault();
      return;
    } else if (active.kind === "connection-handle") {
      if (active.preview) {
        active.preview.setAttribute("d", `M ${active.startPoint.x} ${active.startPoint.y} L ${point.x} ${point.y}`);
        active.preview.setAttribute("visibility", "visible");
      }
      $$(".node-group.connection-target", canvas).forEach((group) => group.classList.remove("connection-target"));
      const targetGroup = connectionTargetAt(event.clientX, event.clientY);
      if (targetGroup && String(targetGroup.dataset.nodeId) !== String(active.sourceId)) targetGroup.classList.add("connection-target");
      event.preventDefault();
      return;
    } else if (active.kind === "edge-label") {
      const labelT = DFD_SELECTION.nearestQuadraticCurveT(active.geometry, point);
      setEdgeLabelT(active.edge, labelT);
      active.changed = true;
      setSingleDfdSelection("edge", active.edgeId);
      applyEdgeLabelPosition(active.group, dfdEdgeLabelAt(active.geometry, edgeDisplayName(active.edge), labelT));
    } else if (active.kind === "edge") {
      const deltaX = point.x - active.startPoint.x;
      const deltaY = point.y - active.startPoint.y;
      const offset = active.startOffset + deltaX * active.normal.x + deltaY * active.normal.y;
      setEdgeCurveOffset(active.edge, offset);
      active.changed = true;
      setSingleDfdSelection("edge", active.edgeId);
      applyEdgeGeometry(active.group, edgeCurveGeometry(active.source, active.target, offset), active.edge);
    } else if (active.kind === "node") {
      setDfdNodeSelection(active.dragIds);
      const movement = DFD_SELECTION.applyGroupMove(state.workspace.nodes, active.origins, point.x - active.startPoint.x, point.y - active.startPoint.y);
      active.changed = movement.moved;
      syncDfdNodeSelectionClasses(canvas);
      updateDfdNodePositions(canvas, active.dragIds);
      updateDfdEdgesForNodes(canvas, active.dragIds);
    } else if (active.kind === "node-resize") {
      const result = DFD_SELECTION.applyNodeResizeFromHandle(
        active.node,
        active.origin,
        active.handle,
        point.x - active.startPoint.x,
        point.y - active.startPoint.y,
      );
      active.changed = result.resized;
      updateNodeSizeDom(active.group, active.node);
      updateDfdEdgesForNodes(canvas, [active.node.id]);
    } else if (active.kind === "boundary") {
      active.boundary.x = Math.max(0, active.origin.x + point.x - active.startPoint.x);
      active.boundary.y = Math.max(0, active.origin.y + point.y - active.startPoint.y);
      active.changed = active.boundary.x !== active.origin.x || active.boundary.y !== active.origin.y;
      updateBoundaryDom(active.group, active.boundary);
    } else if (active.kind === "boundary-resize") {
      const result = DFD_SELECTION.applyBoundaryResizeFromHandle(
        active.boundary,
        active.origin,
        active.handle,
        point.x - active.startPoint.x,
        point.y - active.startPoint.y,
      );
      active.changed = result.resized;
      updateBoundaryDom(active.group, active.boundary);
    } else if (active.kind === "background") {
      const rect = DFD_SELECTION.normalizeRect(active.startPoint, point);
      const hits = DFD_SELECTION.nodeIdsInRect(state.workspace.nodes, rect);
      active.candidateIds = active.modifier ? [...new Set([...active.nodeIdsBefore, ...hits].map((id) => String(id)))] : hits;
      const marquee = $("#dfd-marquee");
      marquee.setAttribute("x", rect.x); marquee.setAttribute("y", rect.y);
      marquee.setAttribute("width", rect.width); marquee.setAttribute("height", rect.height);
      marquee.setAttribute("visibility", "visible");
      syncDfdNodeSelectionClasses(canvas, active.candidateIds, true);
    }
    event.preventDefault();
  };

  canvas.onpointerup = (event) => {
    if (!gesture || event.pointerId !== gesture.pointerId) return;
    const active = gesture;
    if (active.kind === "pan") {
      completeGesture(active, false);
      focusDfdCanvas();
      return;
    }
    if (active.kind === "connection") {
      if (distanceFromStart(event, active) < dragThreshold) {
        gesture = null;
        releasePointer(active);
        handleConnectionClick(active.nodeId);
        focusDfdCanvas();
      } else completeGesture(active, false);
      return;
    }
    if (active.kind === "connection-handle") {
      const targetGroup = connectionTargetAt(event.clientX, event.clientY);
      const targetId = targetGroup?.dataset?.nodeId;
      clearConnectionHandlePreview();
      gesture = null;
      releasePointer(active);
      if (targetId && String(targetId) !== String(active.sourceId)) {
        createDfdConnection(active.sourceId, targetId);
        renderDfdStepAndFocus();
        toast("데이터 흐름을 추가했습니다.");
      } else {
        focusDfdCanvas();
      }
      return;
    }
    if (active.kind === "pending-flow-endpoint") {
      const draft = active.draft;
      const nodeGroup = connectionTargetAt(event.clientX, event.clientY);
      const nodeId = nodeGroup?.dataset?.nodeId || null;
      const idKey = active.role === "source" ? "sourceId" : "targetId";
      const otherIdKey = active.role === "source" ? "targetId" : "sourceId";
      const xKey = active.role === "source" ? "x1" : "x2";
      const yKey = active.role === "source" ? "y1" : "y2";
      const node = nodeId ? nodeById(nodeId) : null;
      clearConnectionHandlePreview();
      gesture = null;
      releasePointer(active);
      if (node && String(nodeId) !== String(draft[otherIdKey] || "")) {
        draft[idKey] = nodeId;
        draft[xKey] = Number(node.x) + Number(node.width || 150) / 2;
        draft[yKey] = Number(node.y) + Number(node.height || 64) / 2;
      } else if (node && String(nodeId) === String(draft[otherIdKey] || "")) {
        draft[idKey] = null;
        toast("출발점과 도착점은 서로 다른 구성요소에 연결해 주세요.", true);
      }
      if (draft.sourceId && draft.targetId) {
        if (createDfdConnection(draft.sourceId, draft.targetId)) {
          state.dfdPendingFlow = null;
          toast("데이터 흐름을 추가했습니다.");
        } else {
          if (!nodeById(draft.sourceId)) draft.sourceId = null;
          if (!nodeById(draft.targetId)) draft.targetId = null;
          toast("연결할 구성요소를 다시 확인해 주세요.", true);
        }
      }
      renderDfdStepAndFocus();
      return;
    }
    if (active.kind === "node-resize") {
      setSingleDfdSelection("node", active.node.id);
      if (active.changed) {
        setDfdNodeManualSize(active.node, true);
        markDfdDirty();
      }
    } else if (active.kind === "node") {
      if (active.moved) {
        const changed = active.origins.some((origin) => {
          const node = dfdNodeById(origin.id);
          return node && (Number(node.x) !== Number(origin.x) || Number(node.y) !== Number(origin.y));
        });
        setDfdNodeSelection(active.dragIds);
        if (changed) markDfdDirty();
      } else if (active.modifier) {
        const selected = new Set(active.nodeIdsBefore.map((id) => String(id)));
        if (selected.has(String(active.nodeId))) selected.delete(String(active.nodeId));
        else selected.add(String(active.nodeId));
        setDfdNodeSelection([...selected]);
      } else setSingleDfdSelection("node", active.nodeId);
    } else if (active.kind === "boundary" || active.kind === "boundary-resize") {
      setSingleDfdSelection("boundary", active.boundary.id);
      if (active.changed) markDfdDirty();
    } else if (active.kind === "edge-label") {
      if (active.moved && active.changed) markDfdDirty("layout");
      else setSingleDfdSelection("edge", active.edgeId);
    } else if (active.kind === "edge") {
      if (active.moved && active.changed) markDfdDirty("layout");
      else setSingleDfdSelection("edge", active.edgeId);
    } else if (active.kind === "background") {
      if (active.moved) setDfdNodeSelection(active.candidateIds);
      else if (!active.modifier) clearDfdSelection();
      else restoreDfdSelection(active.selectionBefore);
    }
    completeGesture(active);
  };

  canvas.onpointercancel = cancelGesture;
  canvas.onauxclick = (event) => { if (event.button === 1) event.preventDefault(); };
  canvas.onlostpointercapture = (event) => {
    if (gesture && event.pointerId === gesture.pointerId) cancelGesture();
  };
  canvas.ondblclick = (event) => {
    if (event.target.closest?.("[data-node-resize-handle], [data-connection-handle]")) return;
    const group = event.target.closest?.("[data-node-id]");
    const node = group ? nodeById(group.dataset.nodeId) : null;
    if (!group || !node || group.querySelector(".node-inline-editor")) return;
    event.preventDefault();
    event.stopPropagation();
    setSingleDfdSelection("node", node.id);
    group.classList.add("selected", "inline-editing");
    const width = Number(node.width || 150);
    const height = Number(node.height || 64);
    const foreignObject = document.createElementNS("http://www.w3.org/2000/svg", "foreignObject");
    foreignObject.setAttribute("class", "node-inline-editor");
    foreignObject.setAttribute("x", "8");
    foreignObject.setAttribute("y", "8");
    foreignObject.setAttribute("width", Math.max(70, width - 16));
    foreignObject.setAttribute("height", Math.max(42, height - 16));
    const editor = document.createElementNS("http://www.w3.org/1999/xhtml", "textarea");
    editor.setAttribute("maxlength", String(DFD_NODE_TEXT_LIMITS.name.max));
    editor.setAttribute("aria-label", "DFD 구성요소 표시 이름 편집");
    editor.value = String(node.name || nodeDisplayName(node));
    foreignObject.appendChild(editor);
    group.appendChild(foreignObject);
    let finished = false;
    const finish = (commit) => {
      if (finished) return;
      finished = true;
      const nextName = editor.value.trim();
      if (commit && nextName && nextName !== String(node.name || "")) {
        node.name = nextName;
        if (!dfdNodeUsesManualSize(node)) applyAutomaticDfdNodeSize(node);
        markDfdDirty();
      }
      renderDfdStepAndFocus();
    };
    editor.onpointerdown = (pointerEvent) => pointerEvent.stopPropagation();
    editor.ondblclick = (doubleClickEvent) => doubleClickEvent.stopPropagation();
    editor.onkeydown = (keyEvent) => {
      if (keyEvent.key === "Escape") { keyEvent.preventDefault(); finish(false); }
      else if (keyEvent.key === "Enter" && (keyEvent.ctrlKey || keyEvent.metaKey)) { keyEvent.preventDefault(); finish(true); }
    };
    editor.onblur = () => finish(true);
    editor.focus();
    editor.select();
  };
  canvas.onkeydown = (event) => {
    if (event.key === "Escape") {
      if (!hasDfdSelection() && !state.connectionMode && !state.connectionSource && !state.dfdPendingFlow && state.dfdFocusMode) {
        event.preventDefault();
        toggleDfdFocusMode();
        return;
      }
      if (!hasDfdSelection() && !state.connectionMode && !state.connectionSource && !state.dfdPendingFlow) return;
      event.preventDefault();
      state.connectionMode = false;
      state.connectionSource = null;
      state.dfdPendingFlow = null;
      clearDfdSelection();
      renderDfdStepAndFocus();
    } else if (event.key === "Delete" || event.key === "Backspace") {
      if (!hasDfdSelection()) return;
      event.preventDefault();
      requestDeleteSelection();
    } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "z") {
      event.preventDefault();
      if (event.shiftKey) redoDfd(); else undoDfd();
    } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "y") {
      event.preventDefault();
      redoDfd();
    } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "c") {
      event.preventDefault();
      copyDfdSelection();
    } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "v") {
      event.preventDefault();
      pasteDfdSelection();
    } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "a") {
      event.preventDefault();
      setDfdNodeSelection(state.workspace.nodes.map((node) => node.id));
      renderDfdStepAndFocus();
    }
  };

  $("#dfd-zoom-out").onclick = () => { state.dfdZoom = Math.max(0.5, Number(state.dfdZoom ?? 1) - 0.15); renderDfdStep(); };
  $("#dfd-zoom-in").onclick = () => { state.dfdZoom = Math.min(2, Number(state.dfdZoom ?? 0.85) + 0.15); renderDfdStep(); };
  $("#dfd-zoom-fit").onclick = () => {
    state.dfdZoom = null;
    state.dfdViewportX = 0;
    state.dfdViewportY = 0;
    renderDfdStep();
    const scrollArea = $(".canvas-scroll-area");
    scrollArea.scrollLeft = 0; scrollArea.scrollTop = 0;
    state.dfdScrollLeft = 0; state.dfdScrollTop = 0;
  };
  bindInspector();
}

function handleConnectionClick(nodeId) {
  if (!state.connectionSource) {
    state.connectionSource = nodeId;
    setSingleDfdSelection("node", nodeId);
    toast("이제 도착 구성요소를 선택하세요.");
    renderDfdStep();
    return;
  }
  if (String(state.connectionSource) === String(nodeId)) { toast("다른 구성요소를 선택해 주세요.", true); return; }
  createDfdConnection(state.connectionSource, nodeId);
  state.connectionSource = null;
  clearDfdSelection();
  renderDfdStep();
  toast("데이터 흐름을 추가했습니다. 다음 흐름의 출발 요소를 선택하거나 Esc로 종료하세요.");
}

function createDfdConnection(sourceId, targetId) {
  if (!sourceId || !targetId || String(sourceId) === String(targetId)) return false;
  const sourceNode = nodeById(sourceId);
  const targetNode = nodeById(targetId);
  if (!sourceNode || !targetNode) return false;
  const template = flowTemplateFor(sourceNode, targetNode);
  const catalog = flowTemplateCatalog(template);
  state.workspace.edges.push({
    id: randomId("edge"),
    source: sourceId,
    target: targetId,
    name: template?.name || "",
    protocol: "",
    data_type: "",
    properties: catalog ? { catalog } : {},
  });
  markDfdDirty();
  return true;
}

function bindInspector() {
  bindCharacterCounters($(".inspector-body"));
  if (selectedDfdNodeIds().length > 1) {
    $("#delete-multi-selection").onclick = requestDeleteSelection;
    return;
  }
  if (!state.selected) return;
  if (state.selected.type === "node") {
    const node = nodeById(state.selected.id);
    $("#node-name").oninput = (event) => {
      node.name = event.target.value;
      if (!dfdNodeUsesManualSize(node)) applyAutomaticDfdNodeSize(node);
      markDfdDirty();
    };
    $("#node-name").onchange = renderDfdStep;
    $("#node-auto-size").onclick = () => {
      setDfdNodeManualSize(node, false);
      applyAutomaticDfdNodeSize(node);
      markDfdDirty();
      renderDfdStepAndFocus();
    };
    $("#node-asset").onchange = (event) => {
      const asset = assetById(event.target.value);
      if (String(node.asset_type_id) !== String(asset.id)) clearNodeAndIncidentEdgeCatalogMetadata(node);
      node.asset_type_id = asset.id;
      node.asset_type_name = asset.name;
      node.dfd_kind = asset.dfd_kind;
      const catalog = dfdElementCatalogMetadata(asset.id);
      if (catalog) node.properties = { ...(node.properties || {}), catalog };
      markDfdDirty();
      renderDfdStep();
    };
    $("#node-description").oninput = (event) => { node.description = event.target.value; markDfdDirty(); };
  } else if (state.selected.type === "edge") {
    const edge = state.workspace.edges.find((item) => item.id === state.selected.id);
    $("#edge-name").oninput = (event) => { edge.name = event.target.value; markDfdDirty(); };
    $("#edge-name").onchange = renderDfdStep;
    $("#edge-protocol").oninput = (event) => { edge.protocol = event.target.value; markDfdDirty(); };
    $("#edge-data").oninput = (event) => { edge.data_type = event.target.value; markDfdDirty(); };
    $("#edge-curve").oninput = (event) => {
      setEdgeCurveOffset(edge, Number(event.target.value));
      markDfdDirty("layout");
      $("#edge-curve-value").textContent = `수동 ${Math.round(Number(event.target.value))}`;
      $("#edge-curve-auto").disabled = false;
      const edgeIndex = state.workspace.edges.indexOf(edge);
      const source = dfdNodeById(edge.source);
      const target = dfdNodeById(edge.target);
      const group = $$("[data-edge-id]", $("#dfd-canvas")).find((item) => String(item.dataset.edgeId) === String(edge.id));
      if (source && target && group) applyEdgeGeometry(group, edgeCurveGeometry(source, target, edgeCurveOffsets(state.workspace.edges)[edgeIndex]), edge);
    };
    $("#edge-curve-auto").onclick = () => { setEdgeCurveOffset(edge, null); markDfdDirty("layout"); renderDfdStepAndFocus(); };
    $("#edge-curve-straight").onclick = () => { setEdgeCurveOffset(edge, 0); markDfdDirty("layout"); renderDfdStepAndFocus(); };
    $("#edge-label-auto").onclick = () => { setEdgeLabelT(edge, null); markDfdDirty("layout"); renderDfdStepAndFocus(); };
  } else {
    const boundary = state.workspace.boundaries.find((item) => item.id === state.selected.id);
    $("#boundary-name").oninput = (event) => { boundary.name = event.target.value; markDfdDirty(); };
    $("#boundary-name").onchange = renderDfdStep;
  }
}

function requestDeleteSelection() {
  const nodeIds = selectedDfdNodeIds();
  if (nodeIds.length) {
    const plan = DFD_SELECTION.nodeDeletionPlan(state.workspace.nodes, state.workspace.edges, nodeIds);
    if (!plan.nodeIds.length) return;
    const firstNode = dfdNodeById(plan.nodeIds[0]);
    const subject = plan.nodeIds.length === 1 ? `‘${firstNode ? nodeDisplayName(firstNode) : "선택한 구성요소"}’` : `선택한 구성요소 ${plan.nodeIds.length}개`;
    const details = [`연결된 데이터 흐름 ${plan.edgeIds.length}개`];
    if (plan.entryCount) details.push(`진입 지점 ${plan.entryCount}개`);
    if (plan.targetCount) details.push(`공격 대상 ${plan.targetCount}개`);
    if (window.confirm(`${subject}를 삭제할까요?\n${details.join(", ")}도 함께 정리됩니다.`)) deleteSelected();
    return;
  }
  if (!state.selected) return;
  const selectedName = state.selected.type === "edge" ? "선택한 데이터 흐름" : "선택한 신뢰 경계";
  if (window.confirm(`${selectedName}를 삭제할까요?`)) deleteSelected();
}

function deleteSelected() {
  const nodeIds = selectedDfdNodeIds();
  let changed = false;
  if (nodeIds.length) {
    const result = DFD_SELECTION.removeNodes(state.workspace, nodeIds);
    if (!result.plan.nodeIds.length) return;
    state.workspace.nodes = result.nodes;
    state.workspace.edges = result.edges;
    state.workspace.boundaries = result.boundaries;
    const deletedIds = new Set(result.plan.nodeIds.map((id) => String(id)));
    let affectedAttackCase = false;
    state.attackCaseDrafts.forEach((item) => {
      const affected = attackCaseEntryIds(item).some((entryId) => deletedIds.has(String(entryId))) || deletedIds.has(String(item.target_node_id));
      if (!affected) return;
      item.entry_node_ids = attackCaseEntryIds(item).filter((entryId) => !deletedIds.has(String(entryId)));
      item.entry_node_id = item.entry_node_ids[0] || "";
      if (deletedIds.has(String(item.target_node_id))) item.target_node_id = "";
      item.manual_path_confirmed = false;
      affectedAttackCase = true;
    });
    if (affectedAttackCase) markAttackCasesDirty();
    if (state.connectionSource && deletedIds.has(String(state.connectionSource))) {
      state.connectionSource = null;
      state.connectionMode = false;
    }
    if (state.dfdPendingFlow) {
      if (deletedIds.has(String(state.dfdPendingFlow.sourceId || ""))) state.dfdPendingFlow.sourceId = null;
      if (deletedIds.has(String(state.dfdPendingFlow.targetId || ""))) state.dfdPendingFlow.targetId = null;
    }
    changed = true;
  } else if (state.selected?.type === "edge") {
    const before = state.workspace.edges.length;
    state.workspace.edges = state.workspace.edges.filter((edge) => String(edge.id) !== String(state.selected.id));
    changed = state.workspace.edges.length !== before;
  } else if (state.selected?.type === "boundary") {
    const before = state.workspace.boundaries.length;
    state.workspace.boundaries = state.workspace.boundaries.filter((boundary) => String(boundary.id) !== String(state.selected.id));
    changed = state.workspace.boundaries.length !== before;
  }
  if (!changed) return;
  markDfdDirty();
  clearDfdSelection();
  renderDfdStepAndFocus();
}

async function saveDfd(showToast = true) {
  if (state.workspace.assessment.threat_model_confirmed && !state.dfdDirty) {
    if (showToast) toast("저장할 DFD 변경사항이 없습니다.");
    return true;
  }
  const layoutOnly = state.dfdLayoutDirty && !state.dfdSemanticDirty;
  if (state.workspace.assessment.threat_model_confirmed && state.dfdDirty && layoutOnly) {
    try {
      await api(`/api/assessments/${state.assessmentId}/dfd/edge-layout`, {
        method: "PUT",
        body: {
          edges: state.workspace.edges.map((edge) => ({
            id: edge.id,
            curve_offset: DFD_SELECTION.explicitEdgeCurveOffset(edge),
            label_t: DFD_SELECTION.explicitEdgeLabelT(edge),
          })),
        },
      });
      assignWorkspace(await api(`/api/assessments/${state.assessmentId}/workspace`));
      state.dfdDirty = false;
      state.dfdSemanticDirty = false;
      state.dfdLayoutDirty = false;
      if (showToast) toast("데이터 흐름의 선과 라벨 배치를 저장했습니다.");
      if (showToast) renderWorkspace();
      return true;
    } catch (error) { toast(error.message, true); return false; }
  }
  let resetDownstream = false;
  if (state.workspace.assessment.threat_model_confirmed && state.dfdDirty) {
    resetDownstream = window.confirm("DFD를 변경하면 기존 후보, 쇼핑 카트, 위험 평가와 매트릭스가 초기화됩니다. 변경한 DFD로 다시 진행할까요?");
    if (!resetDownstream) return false;
  }
  try {
    await api(`/api/assessments/${state.assessmentId}/dfd`, { method: "PUT", body: { nodes: state.workspace.nodes, edges: state.workspace.edges, boundaries: state.workspace.boundaries, reset_downstream: resetDownstream } });
    assignWorkspace(await api(`/api/assessments/${state.assessmentId}/workspace`));
    state.dfdDirty = false;
    state.dfdSemanticDirty = false;
    state.dfdLayoutDirty = false;
    resetDfdHistory();
    if (showToast) toast("DFD를 저장했습니다.");
    if (showToast) renderWorkspace();
    return true;
  } catch (error) { toast(error.message, true); return false; }
}

async function confirmThreatModel() {
  if (!state.attackCaseDrafts.length) {
    toast("Attack Case를 하나 이상 추가해 주세요.", true);
    $("#attack-case-builder")?.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  const invalid = state.attackCaseDrafts
    .map((item, index) => ({ item, errors: attackCaseDraftErrors(item, index) }))
    .filter((result) => result.errors.length);
  if (invalid.length) {
    toast(`입력이 완료되지 않은 Attack Case가 ${invalid.length}개 있습니다.`, true);
    $(`[data-attack-case-card="${invalid[0].item.draftKey}"]`)?.scrollIntoView({ behavior: "smooth", block: "center" });
    return;
  }
  let resetDownstream = false;
  if (state.workspace.assessment.threat_model_confirmed && state.attackCasesDirty) {
    resetDownstream = window.confirm("Attack Case를 변경하면 기존 후보, 쇼핑 카트, 위험 평가와 매트릭스가 초기화됩니다. 변경한 Case로 다시 진행할까요?");
    if (!resetDownstream) return;
  }
  if (!(await saveDfd(false))) return;
  const actor = assessmentScopeProfile().actor;
  const attackCases = state.attackCaseDrafts.map((item, index) => {
    const routes = attackCaseRoutes(item);
    const hasMissingRoute = routes.some((entry) => !entry.route.length);
    const entryNodeIds = attackCaseEntryIds(item);
    return {
      ...(item.id === null || item.id === undefined || item.id === "" ? {} : { id: item.id }),
      name: item.name || `Attack Case ${index + 1}`,
      entry_node_id: entryNodeIds[0],
      entry_node_ids: entryNodeIds,
      target_node_id: item.target_node_id,
      intended_effect: attackCaseEffectText(item),
      rationale: String(item.rationale).trim(),
      path_mode: hasMissingRoute ? "MANUAL" : "DIRECTED",
      ...(hasMissingRoute ? { manual_path_confirmed: true, path_rationale: String(item.rationale).trim() } : {}),
      actor_snapshot: actor,
    };
  });
  const button = $("#confirm-threat-model");
  if (button) { button.disabled = true; button.textContent = "확정 중"; }
  try {
    assignWorkspace(await api(`/api/assessments/${state.assessmentId}/confirm-threat-model`, { method: "POST", body: { attack_cases: attackCases, reset_downstream: resetDownstream } }));
    state.attackCasesDirty = false;
    loadAttackCaseDrafts(true);
    state.step = 2; state.candidatePage = 1; state.activeTargetId = state.workspace.carts[0]?.target_node_id || null; toast("DFD와 Attack Case를 확정하고 Case별 후보를 생성했습니다."); renderWorkspace();
  } catch (error) { toast(error.message, true); renderDfdStep(); }
}

function targetTabs(targetIds, active) {
  return `<div class="tabs">${targetIds.map((id) => `<button class="tab ${id === active ? "active" : ""}" data-target-tab="${escapeHtml(id)}">${escapeHtml(nodeDisplayName(id, "공격 대상"))}</button>`).join("")}</div>`;
}

function mappingEvidenceMarkup(entry) {
  const evidence = entry.mapping_evidence || [];
  const displayId = attackVectorCatalogId(entry);
  const labels = [...new Set(evidence.map((item) => {
    const nodeName = dfdDisplayName(item.node_name, nodeDisplayName(item.node_id));
    const assetName = assetDisplayName(item.asset_type_id, "");
    return `${nodeName}${assetName ? ` (${assetName})` : ""}${displayId ? ` → ${displayId}` : ""}`;
  }))];
  return labels.length ? `<div class="evidence-list">${labels.map((label) => `<span>${escapeHtml(label)}</span>`).join("")}</div>` : '<span class="muted small-text">사용자 추가</span>';
}

function uniquePush(items, value) {
  if (value == null || value === "") return;
  if (!items.some((item) => String(item) === String(value))) items.push(value);
}

function mergeCandidateGroups(candidates) {
  const groups = new Map();
  candidates.forEach((candidate, index) => {
    const caseKey = candidate.attack_case_id ?? candidate.target_node_id ?? "legacy";
    const key = `${String(caseKey)}\u0000${String(candidate.attack_vector_id || candidate.id || `candidate-${index}`)}`;
    if (!groups.has(key)) {
      groups.set(key, {
        ...candidate,
        target_node_ids: [],
        entry_node_ids: [],
        mapping_evidence: [],
      });
    }
    const group = groups.get(key);
    group.attack_case_id = candidate.attack_case_id ?? group.attack_case_id;
    uniquePush(group.target_node_ids, candidate.target_node_id);
    uniquePush(group.entry_node_ids, candidate.entry_node_id);
    (Array.isArray(candidate.entry_node_ids) ? candidate.entry_node_ids : []).forEach((id) => uniquePush(group.entry_node_ids, id));
    (Array.isArray(candidate.mapping_evidence) ? candidate.mapping_evidence : []).forEach((evidence) => {
      const evidenceWithTarget = { ...evidence, target_node_id: candidate.target_node_id };
      const evidenceKey = [
        evidenceWithTarget.entry_node_id,
        evidenceWithTarget.node_id,
        evidenceWithTarget.node_name,
        evidenceWithTarget.asset_type_id,
        evidenceWithTarget.attack_vector_id,
        evidenceWithTarget.target_node_id,
      ].map((value) => String(value ?? "")).join("|");
      const duplicate = group.mapping_evidence.some((existing) => [
        existing.entry_node_id,
        existing.node_id,
        existing.node_name,
        existing.asset_type_id,
        existing.attack_vector_id,
        existing.target_node_id,
      ].map((value) => String(value ?? "")).join("|") === evidenceKey);
      if (!duplicate) group.mapping_evidence.push(evidenceWithTarget);
    });
  });
  return [...groups.values()];
}

function labeledChips(items, label, className = "") {
  const values = items.map((item) => `${label}: ${item}`);
  return `<div class="chip-list candidate-meta-group">${values.length ? values.map((item) => `<span class="chip ${className}">${escapeHtml(item)}</span>`).join("") : '<span class="muted small-text">없음</span>'}</div>`;
}

function shortestDfdPath(sourceId, targetId) {
  const source = String(sourceId || "");
  const target = String(targetId || "");
  if (!source || !target) return [];
  if (source === target) return [source];
  const outgoing = new Map();
  (state.workspace?.edges || []).forEach((edge) => {
    const edgeSource = String(edge.source ?? edge.source_node_id ?? "");
    const edgeTarget = String(edge.target ?? edge.target_node_id ?? "");
    if (!edgeSource || !edgeTarget) return;
    if (!outgoing.has(edgeSource)) outgoing.set(edgeSource, []);
    uniquePush(outgoing.get(edgeSource), edgeTarget);
  });
  const queue = [[source]];
  const visited = new Set([source]);
  while (queue.length) {
    const path = queue.shift();
    const current = path[path.length - 1];
    for (const next of outgoing.get(current) || []) {
      if (visited.has(next)) continue;
      const nextPath = [...path, next];
      if (next === target) return nextPath;
      visited.add(next);
      queue.push(nextPath);
    }
  }
  return [];
}

function pathThroughNode(entryId, throughId, targetId) {
  if (!entryId || !targetId) return [];
  if (!throughId || String(throughId) === String(entryId) || String(throughId) === String(targetId)) {
    return shortestDfdPath(entryId, targetId);
  }
  const entryToThrough = shortestDfdPath(entryId, throughId);
  const throughToTarget = shortestDfdPath(throughId, targetId);
  if (entryToThrough.length && throughToTarget.length) return [...entryToThrough, ...throughToTarget.slice(1)];
  return shortestDfdPath(entryId, targetId);
}

function nodePathLabel(nodeIds) {
  return nodeIds.map((id) => nodeDisplayName(id)).join(" → ");
}

function candidatePathDetails(candidate) {
  const evidence = Array.isArray(candidate.mapping_evidence) ? candidate.mapping_evidence : [];
  const labels = [...new Set(evidence.map((item) => {
    const entryId = item.entry_node_id || candidate.entry_node_ids?.[0];
    const targetId = item.target_node_id || candidate.target_node_ids?.[0] || candidate.target_node_id;
    const path = pathThroughNode(entryId, item.node_id, targetId);
    if (path.length) return nodePathLabel(path);
    return "";
  }).filter(Boolean))];
  if (!labels.length) return '<div class="small-text muted">DFD에서 확인 가능한 후보 생성 경로 없음</div>';
  return `<details class="candidate-paths"><summary>후보 생성 경로 ${labels.length}개 보기</summary><div class="candidate-path-list">${labels.map((label) => `<div><code>${escapeHtml(label)}</code></div>`).join("")}</div></details>`;
}

const CANDIDATE_PAGE_SIZE = 15;

function candidatePageNumbers(currentPage, totalPages) {
  if (totalPages <= 7) return Array.from({ length: totalPages }, (_, index) => index + 1);
  const pages = new Set([1, totalPages, currentPage - 1, currentPage, currentPage + 1]);
  return [...pages].filter((page) => page >= 1 && page <= totalPages).sort((left, right) => left - right);
}

function candidatePaginationMarkup(totalItems, currentPage, totalPages) {
  if (totalPages <= 1) return "";
  const start = (currentPage - 1) * CANDIDATE_PAGE_SIZE + 1;
  const end = Math.min(totalItems, currentPage * CANDIDATE_PAGE_SIZE);
  const pages = candidatePageNumbers(currentPage, totalPages);
  let previous = 0;
  const pageButtons = pages.map((page) => {
    const gap = previous && page - previous > 1 ? '<span class="candidate-page-gap" aria-hidden="true">…</span>' : "";
    previous = page;
    return `${gap}<button type="button" class="btn small candidate-page-number ${page === currentPage ? "active" : ""}" data-candidate-page="${page}" ${page === currentPage ? 'aria-current="page"' : ""}>${page}</button>`;
  }).join("");
  return `<div class="candidate-pagination"><span>${start}–${end} / ${totalItems}개</span><nav aria-label="후보 공격 벡터 페이지"><button type="button" class="btn small" data-candidate-page="${currentPage - 1}" ${currentPage === 1 ? "disabled" : ""}>이전</button>${pageButtons}<button type="button" class="btn small" data-candidate-page="${currentPage + 1}" ${currentPage === totalPages ? "disabled" : ""}>다음</button></nav></div>`;
}

function renderCandidatesStep() {
  const targetIds = state.workspace.carts.map((cart) => cart.target_node_id);
  const targetIdSet = new Set(targetIds.map(String));
  const candidates = state.workspace.candidates.filter((candidate) => targetIdSet.has(String(candidate.target_node_id)));
  const mergedCandidates = mergeCandidateGroups(candidates);
  const totalPages = Math.max(1, Math.ceil(mergedCandidates.length / CANDIDATE_PAGE_SIZE));
  state.candidatePage = Math.max(1, Math.min(totalPages, Number(state.candidatePage) || 1));
  const pageStart = (state.candidatePage - 1) * CANDIDATE_PAGE_SIZE;
  const visibleCandidates = mergedCandidates.slice(pageStart, pageStart + CANDIDATE_PAGE_SIZE);
  const caseNames = state.workspace.carts.map((cart) => cartCaseLabel(cart));
  const skippedEntries = Array.isArray(state.workspace?.threat_model_path_findings?.unreachable_entries)
    ? state.workspace.threat_model_path_findings.unreachable_entries
    : [];
  const skippedEntryNames = skippedEntries.map((item) => dfdDisplayName(item?.name, nodeDisplayName(item?.node_id))).filter(Boolean);
  const skippedEntryNotice = skippedEntryNames.length
    ? `<div class="notice warning path-gap-notice"><div>!</div><div><strong>미연결 진입 지점: ${escapeHtml(skippedEntryNames.join(", "))}</strong>공격 대상까지 이어지는 데이터 흐름이 없어 후보와 근거 계산에서 제외했습니다.</div><button type="button" class="btn small" id="review-path-gaps">DFD에서 연결</button></div>`
    : "";
  const rows = visibleCandidates.map((candidate) => {
    const targetLabels = candidate.target_node_ids.map((id) => nodeDisplayName(id, "공격 대상"));
    const entryLabels = candidate.entry_node_ids.map((id) => nodeDisplayName(id, "진입 지점"));
    const candidateCart = candidate.attack_case_id === null || candidate.attack_case_id === undefined
      ? null
      : state.workspace.carts.find((cart) => String(cart.attack_case_id ?? "") === String(candidate.attack_case_id));
    return `<tr><td><div class="attack-vector-identity"><span class="vector-id">${escapeHtml(attackVectorCatalogId(candidate))}</span><span class="vector-name">${escapeHtml(candidate.attack_vector_name)}</span></div><span class="badge blue">${escapeHtml(attackVectorSourceName(candidate))}</span></td><td><div class="candidate-decision-description">${escapeHtml(candidate.attack_vector_description)}</div>${candidateCart ? `<div class="candidate-case-label">${escapeHtml(cartCaseLabel(candidateCart))}</div>` : ""}<div class="candidate-meta">${labeledChips(targetLabels, "대상", "target-chip")}${labeledChips(entryLabels, "진입", "entry-chip")}</div>${candidatePathDetails(candidate)}</td></tr>`;
  }).join("");
  const pagination = candidatePaginationMarkup(mergedCandidates.length, state.candidatePage, totalPages);
  const identificationComplete = Number(state.workspace.assessment.current_step || 1) >= 3;
  const headerActions = `<button class="btn" id="complete-candidate-identification" ${identificationComplete ? "disabled" : ""}>${identificationComplete ? "식별 완료됨" : "식별 완료"}</button><button class="btn primary" id="go-carts" ${identificationComplete ? "" : "disabled"}>쇼핑 카트 확인</button>`;
  $("#step-content").innerHTML = `${pageHeader("1.2 후보 공격 벡터 식별", "Attack Case별 후보와 KM 매핑 근거를 확인합니다.", headerActions)}<div class="page-body">${skippedEntryNotice}<div class="candidate-summary-bar"><div><span class="summary-label">Attack Case</span>${chips(caseNames)}</div><strong>후보 ${mergedCandidates.length}개</strong></div><div class="candidate-reading-guide"><strong>목록 읽는 법</strong><span><b>대상</b>은 이 공격 벡터가 적용되는 Intended Target, <b>진입</b>은 해당 Case의 Entry Point입니다. ‘후보 생성 경로’를 열면 두 요소 사이에서 KM 매핑에 사용된 DFD 경로를 확인할 수 있습니다.</span></div><div class="card candidate-list-card"><div class="card-header"><h2>후보 공격 벡터</h2><span class="count-pill">${mergedCandidates.length}</span></div><div class="card-body">${mergedCandidates.length ? `<table class="data-table candidate-vector-table"><thead><tr><th>공격 벡터</th><th>적용 자산과 선정 근거</th></tr></thead><tbody>${rows}</tbody></table>${pagination}` : emptyState("검색된 후보가 없습니다", "KM 매핑 후보가 없습니다. 쇼핑 카트에서 직접 추가할 수 있습니다.")}</div></div></div>`;
  $("#review-path-gaps")?.addEventListener("click", () => {
    state.step = 1;
    renderWorkspace();
  });
  $$('[data-candidate-page]').forEach((button) => button.onclick = () => {
    if (button.disabled) return;
    state.candidatePage = Number(button.dataset.candidatePage);
    renderCandidatesStep();
    $(".candidate-list-card")?.scrollIntoView({ block: "start" });
  });
  $("#complete-candidate-identification").onclick = async () => {
    const button = $("#complete-candidate-identification");
    button.disabled = true;
    button.textContent = "완료 처리 중";
    try {
      await api(`/api/assessments/${state.assessmentId}/complete-candidate-identification`, { method: "POST", body: {} });
      await reloadWorkspace();
      renderWorkspace();
      toast("후보 공격 벡터 식별을 완료했습니다. 쇼핑 카트를 확인할 수 있습니다.");
    } catch (error) {
      button.disabled = false;
      button.textContent = "식별 완료";
      toast(error.message, true);
    }
  };
  $("#go-carts").onclick = () => {
    if (!canAccess(3)) { explainCtsaBlock(3); return; }
    state.step = 3;
    state.activeCartId = state.workspace.carts[0]?.id;
    state.cartCatalogQuery = "";
    renderWorkspace();
  };
}

function chips(items) { return `<div class="chip-list">${items.length ? items.map((item) => `<span class="chip">${escapeHtml(item)}</span>`).join("") : '<span class="muted small-text">없음</span>'}</div>`; }
function emptyState(title, text) { return `<div class="empty-state"><div class="empty-icon">◇</div><h3>${escapeHtml(title)}</h3><p>${escapeHtml(text)}</p></div>`; }

function cartTabs(mode = "review") {
  if (!state.activeCartId && state.workspace.carts.length) state.activeCartId = state.workspace.carts[0].id;
  return `<div class="tabs cart-tabs">${state.workspace.carts.map((cart) => {
    const isActive = Number(cart.id) === Number(state.activeCartId);
    const reviewed = cart.items.filter((item) => (
      state.reviewDrafts[String(item.id)]?.status || item.review_status
    ) !== "UNREVIEWED").length;
    const hasDraft = cart.items.some((item) => state.reviewDrafts[String(item.id)]?.dirty);
    const stateText = mode === "compose"
      ? (cart.status === "DRAFT" ? "구성 중" : "구성 완료")
      : isActive ? "검토 중" : hasDraft ? `${reviewed}/${cart.items.length} 변경됨` : cart.status === "REVIEWED" ? "검토 완료" : cart.status === "READY" ? `${reviewed}/${cart.items.length} 검토` : "구성 중";
    const stateClass = mode === "compose"
      ? (cart.status === "DRAFT" ? "draft" : "complete")
      : isActive ? "in-progress" : cart.status === "REVIEWED" ? "complete" : cart.status === "READY" ? "in-progress" : "draft";
    return `<button class="tab ${isActive ? "active" : ""}" data-cart-tab="${cart.id}" title="${escapeHtml(cartCaseLabel(cart))}"><span>${escapeHtml(shoppingCartLabel(cart))}</span><span class="tab-state ${stateClass}">${escapeHtml(stateText)}</span></button>`;
  }).join("")}</div>`;
}

function bindCartTabs(render) { $$('[data-cart-tab]').forEach((button) => button.onclick = () => { state.activeCartId = Number(button.dataset.cartTab); render(); }); }

function cartFilterState(cartId) {
  const key = String(cartId);
  const stored = state.cartFilters[key];
  if (!stored || typeof stored !== "object") {
    state.cartFilters[key] = { entry: "__ALL__", source: "__ALL__", search: "" };
  }
  return state.cartFilters[key];
}

function cartSelectionSet(cartId) {
  const key = String(cartId);
  if (!(state.cartSelections[key] instanceof Set)) state.cartSelections[key] = new Set();
  return state.cartSelections[key];
}

function cartItemEntryIds(item) {
  return Array.isArray(item?.related_entry_ids) ? item.related_entry_ids : [];
}

function cartItemNodeIds(item) {
  return Array.isArray(item?.related_node_ids) ? item.related_node_ids : [];
}

function attackVectorCatalogId(item) {
  const explicit = String(item?.attack_vector_catalog_id ?? item?.av_catalog_id ?? item?.catalog_id ?? item?.public_id ?? "").trim();
  if (/^AV-\d{6}$/.test(explicit)) return explicit;
  const internalId = String(item?.attack_vector_id ?? item?.attack_vector_internal_id ?? item?.id ?? "").trim();
  const sourceId = String(item?.attack_vector_source_id ?? item?.source_identifier ?? item?.external_id ?? "").trim();
  const name = String(item?.attack_vector_name ?? item?.name ?? "").trim();
  const knownEntries = [
    ...(Array.isArray(state.workspace?.attack_vector_catalog) ? state.workspace.attack_vector_catalog : []),
    ...(Array.isArray(state.attackVectorCatalog) ? state.attackVectorCatalog : []),
    ...(Array.isArray(state.catalogResults) ? state.catalogResults : []),
    ...(Array.isArray(state.km?.attack_vectors) ? state.km.attack_vectors : []),
  ];
  const known = knownEntries.find((candidate) => {
    const candidateInternalId = String(candidate?.id ?? candidate?.attack_vector_id ?? candidate?.attack_vector_internal_id ?? "").trim();
    const candidateSourceId = String(candidate?.source_identifier ?? candidate?.attack_vector_source_id ?? candidate?.external_id ?? "").trim();
    const candidateName = String(candidate?.name ?? candidate?.attack_vector_name ?? "").trim();
    return (internalId && candidateInternalId === internalId)
      || ((sourceId || internalId) && candidateSourceId === (sourceId || internalId))
      || (name && candidateName === name);
  });
  const knownCatalogId = known?.catalog_id ?? known?.attack_vector_catalog_id ?? known?.av_catalog_id;
  if (/^AV-\d{6}$/.test(String(knownCatalogId ?? "").trim())) return String(knownCatalogId).trim();
  return /^AV-\d{6}$/.test(internalId) ? internalId : "";
}

function attackVectorExternalId(item) {
  const explicit = item?.attack_vector_source_id ?? item?.source_identifier ?? item?.external_id;
  if (explicit) return String(explicit);
  const sourceId = String(item?.attack_vector_id ?? item?.av_id ?? item?.id ?? "");
  const catalogId = attackVectorCatalogId(item);
  return /^(?:T\d|CAPEC-|CVE-|CWE-)/i.test(sourceId) && sourceId !== catalogId ? sourceId : "";
}

function attackVectorSourceName(item) {
  const value = compact(item?.attack_vector_source ?? item?.source, "");
  return ["평가 한정", "CloudTARA 사용자 등록"].includes(value) || !value
    ? "출처 미입력"
    : value;
}

function safeHttpUrl(value) {
  try {
    const parsed = new URL(String(value || ""));
    return ["http:", "https:"].includes(parsed.protocol) ? parsed.href : "";
  } catch (_) {
    return "";
  }
}

function cartEntryOptions(cart) {
  const ids = [];
  cart.items.forEach((item) => cartItemEntryIds(item).forEach((id) => uniquePush(ids, id)));
  return ids
    .map((id) => ({ id, name: nodeDisplayName(id, "진입 지점") }))
    .sort((left, right) => left.name.localeCompare(right.name, "ko"));
}

function vectorPrerequisiteMarkup(item) {
  const prerequisite = compact(item?.prerequisite, "");
  if (!prerequisite) return "";
  return `<details class="vector-prerequisite"><summary>선행조건 보기</summary><p>${escapeHtml(prerequisite)}</p></details>`;
}

function cartItemSearchText(item) {
  const evidence = (Array.isArray(item?.mapping_evidence) ? item.mapping_evidence : []).flatMap((entry) => [
    nodeDisplayName(entry?.entry_node_id, ""),
    nodeDisplayName(entry?.node_id, ""),
    assetDisplayName(entry?.asset_type_id, ""),
  ]);
  return [
    item?.attack_vector_id,
    item?.attack_vector_catalog_id,
    item?.attack_vector_name,
    item?.attack_vector_description,
    item?.prerequisite,
    item?.addition_reason,
    item?.attack_vector_source,
    ...cartItemEntryIds(item).map((id) => nodeDisplayName(id, "")),
    ...cartItemNodeIds(item).map((id) => nodeDisplayName(id, "")),
    ...evidence,
  ].filter(Boolean).join(" ").toLocaleLowerCase("ko-KR");
}

function cartItemMatchesFilters(item, filters) {
  const entries = cartItemEntryIds(item).map(String);
  const entryMatches = filters.entry === "__ALL__"
    || (filters.entry === "__NONE__" ? entries.length === 0 : entries.includes(String(filters.entry)));
  const sourceMatches = filters.source === "__ALL__" || attackVectorSourceName(item) === filters.source;
  const query = String(filters.search || "").trim().toLocaleLowerCase("ko-KR");
  return entryMatches && sourceMatches && (!query || cartItemSearchText(item).includes(query));
}

function cartSourceMarkup(item) {
  const source = attackVectorSourceName(item);
  const referenceUrl = safeHttpUrl(item?.reference_url);
  return `<span class="source-reference"><span class="badge blue">${escapeHtml(source)}</span>${referenceUrl ? `<a href="${escapeHtml(referenceUrl)}" target="_blank" rel="noopener noreferrer" aria-label="${escapeHtml(source)} 원문 보기">원문 보기 ↗</a>` : ""}</span>`;
}

function cartVectorDisplayId(item) {
  return attackVectorCatalogId(item);
}

function cartItemRowMarkup(item, selected) {
  const evidence = Array.isArray(item.mapping_evidence) && item.mapping_evidence.length ? mappingEvidenceMarkup(item) : "";
  const displayId = cartVectorDisplayId(item);
  const editAction = item.item_source === "MANUAL_CUSTOM"
    ? `<button class="btn small cart-custom-edit" type="button" data-edit-custom-vector="${escapeHtml(item.id)}">수정</button>`
    : "";
  const rowActions = editAction ? `<div class="cart-item-row-actions">${editAction}</div>` : "";
  return `<tr data-cart-item-row data-cart-item-id="${escapeHtml(item.id)}" data-attack-vector-catalog-id="${escapeHtml(displayId)}">
    <td class="cart-select-cell"><input type="checkbox" class="cart-row-checkbox" aria-label="${escapeHtml(item.attack_vector_name)} 선택" ${selected ? "checked" : ""}></td>
    <td><div class="attack-vector-identity"><span class="vector-id">${escapeHtml(displayId)}</span><span class="vector-name">${escapeHtml(item.attack_vector_name)}</span></div>${rowActions}</td>
    <td class="small-text"><div>${escapeHtml(item.attack_vector_description)}</div>${vectorPrerequisiteMarkup(item)}</td>
    <td>${chips(cartItemEntryIds(item).map((id) => nodeDisplayName(id, "진입 지점")))}</td>
    <td>${chips(cartItemNodeIds(item).map((id) => nodeDisplayName(id)))}${evidence}</td>
    <td class="cart-source-cell">${cartSourceMarkup(item)}</td>
  </tr>`;
}

function catalogResultsMarkup(cart) {
  const results = Array.isArray(state.catalogResults) ? state.catalogResults : [];
  if (state.catalogLoading && !results.length) return `<div class="catalog-loading small-text muted">KM 전체 목록을 불러오는 중입니다.</div>`;
  if (!results.length) return `<div class="small-text muted">${state.cartCatalogQuery ? "검색 결과가 없습니다." : "등록된 KM 공격 벡터가 없습니다."}</div>`;
  const included = new Set(cart.items.map((item) => String(item.attack_vector_id)));
  const resultLabel = state.cartCatalogQuery ? `검색 결과 ${results.length}개` : `전체 KM ${results.length}개`;
  return `<div class="catalog-result-summary"><strong>${escapeHtml(resultLabel)}</strong><span>스크롤하여 전체 항목을 확인할 수 있습니다.</span></div>` + results.map((vector) => {
    const alreadyIncluded = included.has(String(vector.id));
    const source = attackVectorSourceName(vector);
    return `<div class="catalog-result-item"><span class="catalog-result-copy"><strong>${escapeHtml(attackVectorCatalogId(vector))} - ${escapeHtml(vector.name)}</strong>${vector.description ? `<small>${escapeHtml(vector.description)}</small>` : ""}<small class="catalog-result-source">출처: ${escapeHtml(source)}</small></span><button class="btn small primary" data-add-vector="${escapeHtml(vector.id)}" ${alreadyIncluded ? "disabled" : ""}>${alreadyIncluded ? "담김" : "+ 추가"}</button></div>`;
  }).join("");
}

function renderCartsStep() {
  const cart = cartById(state.activeCartId) || state.workspace.carts[0];
  if (!cart) return;
  state.activeCartId = cart.id;
  const filters = cartFilterState(cart.id);
  const selected = cartSelectionSet(cart.id);
  const cartItemIds = new Set(cart.items.map((item) => String(item.id)));
  [...selected].forEach((id) => { if (!cartItemIds.has(String(id))) selected.delete(String(id)); });
  const entryOptions = cartEntryOptions(cart);
  const hasNoEntryItems = cart.items.some((item) => cartItemEntryIds(item).length === 0);
  const validEntryFilters = new Set(["__ALL__", ...entryOptions.map((entry) => String(entry.id))]);
  if (hasNoEntryItems) validEntryFilters.add("__NONE__");
  if (!validEntryFilters.has(String(filters.entry))) filters.entry = "__ALL__";
  const sourceOptions = [...new Set(cart.items.map(attackVectorSourceName))].sort((left, right) => left.localeCompare(right, "ko"));
  if (!["__ALL__", ...sourceOptions].includes(filters.source)) filters.source = "__ALL__";
  const entryOptionMarkup = entryOptions.map((entry) => `<option value="${escapeHtml(entry.id)}" ${String(filters.entry) === String(entry.id) ? "selected" : ""}>${escapeHtml(entry.name)}</option>`).join("");
  const sourceOptionMarkup = sourceOptions.map((source) => `<option value="${escapeHtml(source)}" ${filters.source === source ? "selected" : ""}>${escapeHtml(source)}</option>`).join("");
  const rows = cart.items.map((item) => cartItemRowMarkup(item, selected.has(String(item.id)))).join("");
  const cartEmptyMessage = cart.items.length
    ? "조건에 맞는 공격 벡터가 없습니다."
    : "이 공격 대상에 검증된 KM 자산–공격 벡터 매핑이 없습니다. KM을 검색하거나 평가 전용 항목을 추가해 주세요.";
  const allReady = state.workspace.carts.every((item) => item.status !== "DRAFT");
  const incompleteCarts = state.workspace.carts.filter((item) => item.status === "DRAFT");
  const gate = allReady ? "" : `<div class="workflow-gate"><strong>다음 단계로 이동하려면 모든 쇼핑 카트의 구성을 완료해 주세요.</strong><span>남은 쇼핑 카트: ${escapeHtml(incompleteCarts.map((item) => shoppingCartLabel(item)).join(", "))}</span></div>`;
  $("#step-content").innerHTML = `${pageHeader("1.3 쇼핑 카트 구성", "Attack Case별 후보를 확인하고 누락된 공격 벡터를 추가합니다.", `<button class="btn primary" id="go-review" aria-disabled="${allReady ? "false" : "true"}">타당성 검토로 이동</button>`)}<div class="page-body cart-compose">${cartTabs("compose")}${gate}<div class="split-view cart-compose-layout"><div><div class="card"><div class="card-header"><div><h2>${escapeHtml(dfdDisplayName(cart.name, "공격 대상"))}</h2><div class="small-text muted">${escapeHtml(dfdDisplayName(cart.description, `${nodeDisplayName(cart.target_node_id, "공격 대상")} 공격 대상의 후보 공격 벡터`))}</div></div><span class="badge ${cart.status === "DRAFT" ? "orange" : "green"}">${cart.status === "DRAFT" ? "구성 중" : "구성 완료"}</span></div><div class="card-body"><div class="table-toolbar"><div class="filter-group"><button class="btn small" id="btn-batch-delete">선택 항목 삭제</button></div><div class="filter-group"><select id="filter-entrypoint" class="select-sm" aria-label="진입 지점 필터"><option value="__ALL__" ${filters.entry === "__ALL__" ? "selected" : ""}>전체 진입 지점</option>${entryOptionMarkup}${hasNoEntryItems ? `<option value="__NONE__" ${filters.entry === "__NONE__" ? "selected" : ""}>진입 지점 없음</option>` : ""}</select><select id="filter-source" class="select-sm" aria-label="출처 필터"><option value="__ALL__" ${filters.source === "__ALL__" ? "selected" : ""}>전체 출처</option>${sourceOptionMarkup}</select><input type="search" id="table-search" class="input-sm" value="${escapeHtml(filters.search)}" placeholder="검색" aria-label="공격 벡터 검색"></div></div><div class="cart-table-wrap"><table class="data-table" id="vector-table"><thead><tr><th class="cart-select-cell"><input type="checkbox" id="select-all-vectors" title="현재 보이는 항목 전체 선택" aria-label="현재 보이는 항목 전체 선택"></th><th>공격 벡터</th><th>설명</th><th>진입 지점</th><th>관련 구성요소</th><th>출처</th></tr></thead><tbody id="vector-table-body">${rows}<tr id="cart-filter-empty-row" hidden><td colspan="6"><div class="cart-filter-empty">${escapeHtml(cartEmptyMessage)}</div></td></tr></tbody></table></div></div></div></div><aside class="card sticky-card attack-vector-add-card"><div class="card-header"><h3>공격 벡터 추가</h3></div><div class="card-body"><p class="attack-vector-add-guide">추가할 항목의 유형을 선택하세요.</p><div class="attack-vector-add-actions"><button class="btn primary" type="button" id="open-catalog-modal"><strong>KM에서 추가하기</strong><span>전체 KM을 조회·검색하여 선택</span></button><button class="btn" type="button" id="open-custom-modal"><strong>새로운 항목 추가하기</strong><span>현재 평가에 새 공격 벡터 작성</span></button></div><div class="nav-divider"></div><button class="btn success" style="width:100%" id="complete-cart" ${cart.status !== "DRAFT" ? "disabled" : ""}>구성 완료</button></div></aside></div></div>`;
  const cartHeading = $(".cart-compose-layout > div > .card .card-header h2");
  const cartDescription = $(".cart-compose-layout > div > .card .card-header .small-text");
  if (cartHeading) cartHeading.textContent = shoppingCartLabel(cart);
  if (cartDescription) cartDescription.textContent = `의도한 효과: ${cartCaseEffect(cart)}`;
  const pageDescription = $("#step-content > .page-header p");
  if (pageDescription) pageDescription.textContent = "Attack Case별 후보를 확인하고 누락된 공격 벡터를 추가합니다.";
  bindCartTabs(() => renderCartsStep());
  $("#filter-entrypoint").onchange = (event) => { filters.entry = event.target.value; applyCartFilters(cart); };
  $("#filter-source").onchange = (event) => { filters.source = event.target.value; applyCartFilters(cart); };
  $("#table-search").oninput = (event) => { filters.search = event.target.value; applyCartFilters(cart); };
  $("#select-all-vectors").onchange = (event) => {
    $$('[data-cart-item-row]').filter((row) => !row.hidden).forEach((row) => {
      const id = String(row.dataset.cartItemId);
      if (event.target.checked) selected.add(id); else selected.delete(id);
      $(".cart-row-checkbox", row).checked = event.target.checked;
    });
    updateCartSelectionControls();
  };
  $("#vector-table-body").onchange = (event) => {
    if (!event.target.classList.contains("cart-row-checkbox")) return;
    const row = event.target.closest("[data-cart-item-row]");
    const id = String(row.dataset.cartItemId);
    if (event.target.checked) selected.add(id); else selected.delete(id);
    updateCartSelectionControls();
  };
  $("#vector-table-body").onclick = (event) => {
    const button = event.target.closest("[data-edit-custom-vector]");
    if (!button) return;
    showEditCustomVectorModal(cart.id, button.dataset.editCustomVector);
  };
  $("#btn-batch-delete").onclick = () => deleteSelectedCartItems(cart);
  $("#open-catalog-modal").onclick = () => showCatalogBrowserModal(cart.id);
  $("#open-custom-modal").onclick = () => showCustomVectorModal(cart.id);
  $("#complete-cart").onclick = async () => { try { await api(`/api/carts/${cart.id}/complete`, { method: "POST", body: {} }); await reloadWorkspace(); toast("쇼핑 카트 구성을 완료했습니다."); renderWorkspace(); } catch (error) { toast(error.message, true); } };
  $("#go-review").onclick = () => { if (allReady) { state.step = 4; renderWorkspace(); } else explainCtsaBlock(4); };
  applyCartFilters(cart);
}

function visibleCartItemIds() {
  return $$('[data-cart-item-row]').filter((row) => !row.hidden).map((row) => String(row.dataset.cartItemId));
}

function updateCartSelectionControls() {
  const visibleIds = visibleCartItemIds();
  const selected = cartSelectionSet(state.activeCartId);
  const selectedCount = visibleIds.filter((id) => selected.has(id)).length;
  const selectAll = $("#select-all-vectors");
  if (selectAll) {
    selectAll.disabled = visibleIds.length === 0;
    selectAll.checked = visibleIds.length > 0 && selectedCount === visibleIds.length;
    selectAll.indeterminate = selectedCount > 0 && selectedCount < visibleIds.length;
  }
  const deleteButton = $("#btn-batch-delete");
  if (deleteButton) deleteButton.textContent = selectedCount ? `선택 항목 삭제 (${selectedCount})` : "선택 항목 삭제";
}

function applyCartFilters(cart) {
  const filters = cartFilterState(cart.id);
  const selected = cartSelectionSet(cart.id);
  let visibleCount = 0;
  $$('[data-cart-item-row]').forEach((row) => {
    const item = cart.items.find((candidate) => String(candidate.id) === String(row.dataset.cartItemId));
    const visible = Boolean(item && cartItemMatchesFilters(item, filters));
    row.hidden = !visible;
    if (!visible) {
      selected.delete(String(row.dataset.cartItemId));
      const checkbox = $(".cart-row-checkbox", row);
      if (checkbox) checkbox.checked = false;
    } else {
      visibleCount += 1;
    }
  });
  const emptyRow = $("#cart-filter-empty-row");
  if (emptyRow) emptyRow.hidden = visibleCount > 0;
  updateCartSelectionControls();
}

async function deleteSelectedCartItems(cart) {
  const selected = cartSelectionSet(cart.id);
  const visibleIds = new Set(visibleCartItemIds());
  const items = cart.items.filter((item) => visibleIds.has(String(item.id)) && selected.has(String(item.id)));
  if (!items.length) { toast("삭제할 항목을 선택해 주세요.", true); return; }
  const message = `선택한 ${items.length}개 공격 벡터를 쇼핑 카트에서 삭제합니다.`;
  const confirmed = cart?.status === "DRAFT" && !hasDownstreamResults()
    ? window.confirm(`${message}\n계속할까요?`)
    : confirmCartChange(cart, message);
  if (!confirmed) return;
  try {
    await api(`/api/carts/${cart.id}/items`, { method: "DELETE", body: { item_ids: items.map((item) => item.id) } });
    selected.clear();
    await reloadWorkspace();
    renderCartsStep();
    toast(`선택한 ${items.length}개 항목을 삭제했습니다.`);
  } catch (error) { toast(error.message, true); }
}

function bindCatalogResultButtons(cartId) {
  $$('[data-add-vector]', $("#catalog-results-container") || document).forEach((button) => {
    button.onclick = () => {
      $("#catalog-browser-modal")?.remove();
      showCatalogAddModal(cartId, button.dataset.addVector);
    };
  });
}

function showCatalogBrowserModal(cartId) {
  const cart = cartById(cartId);
  if (!cart) { toast("쇼핑 카트를 찾을 수 없습니다.", true); return; }
  $("#catalog-browser-modal")?.remove();
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop cart-vector-modal catalog-browser-modal" id="catalog-browser-modal"><div class="cart-modal-window catalog-browser-window" role="dialog" aria-modal="true" aria-labelledby="catalog-browser-title"><div class="cart-modal-header"><div><h3 id="catalog-browser-title">KM에서 공격 벡터 추가</h3><span>공용 KM만 표시됩니다. AV ID·이름·설명·출처를 입력하면 바로 검색됩니다.</span></div><button class="btn small" type="button" data-close-catalog-browser>닫기</button></div><div class="cart-modal-body"><div class="catalog-browser-search"><div class="catalog-search-row"><input type="search" id="catalog-query" value="${escapeHtml(state.cartCatalogQuery)}" maxlength="200" placeholder="AV ID, 이름, 설명, 출처 검색" aria-label="KM 공격 벡터 검색" autocomplete="off"></div><span class="input-help">검색 버튼 없이 입력 후 250ms 뒤 결과가 갱신됩니다.</span></div><div id="catalog-results-container" class="catalog-result-box" aria-live="polite">${catalogResultsMarkup(cart)}</div></div></div></div>`);
  const close = () => {
    clearTimeout(state.catalogSearchTimer);
    state.catalogSearchTimer = null;
    state.catalogSearchRequestId += 1;
    $("#catalog-browser-modal")?.remove();
  };
  $$('[data-close-catalog-browser]').forEach((button) => button.onclick = close);
  $("#catalog-query").oninput = () => scheduleCatalogSearch(cart.id);
  $("#catalog-query").onkeydown = (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    clearTimeout(state.catalogSearchTimer);
    state.catalogSearchTimer = null;
    searchCatalog(cart.id);
  };
  bindCatalogResultButtons(cart.id);
  searchCatalog(cart.id);
  $("#catalog-query")?.focus({ preventScroll: true });
}

function renderCatalogResults(cartId) {
  if (Number(state.activeCartId) !== Number(cartId)) return;
  const cart = cartById(cartId);
  const container = $("#catalog-results-container");
  if (!cart || !container) return;
  container.innerHTML = catalogResultsMarkup(cart);
  bindCatalogResultButtons(cartId);
}

function scheduleCatalogSearch(cartId) {
  clearTimeout(state.catalogSearchTimer);
  state.cartCatalogQuery = $("#catalog-query")?.value.trim() || "";
  state.catalogSearchTimer = setTimeout(() => {
    state.catalogSearchTimer = null;
    searchCatalog(cartId);
  }, 250);
}

async function searchCatalog(cartId) {
  const input = $("#catalog-query");
  const query = input?.value.trim() || "";
  const requestId = state.catalogSearchRequestId + 1;
  state.catalogSearchRequestId = requestId;
  state.cartCatalogQuery = query;
  state.catalogLoading = true;
  renderCatalogResults(cartId);
  try {
    const results = await api(`/api/catalog/attack-vectors?assessment_id=${state.assessmentId}&q=${encodeURIComponent(query)}`);
    if (requestId !== state.catalogSearchRequestId) return;
    if (($("#catalog-query")?.value.trim() || "") !== query) return;
    state.catalogResults = Array.isArray(results) ? results : [];
    if (!query) {
      state.attackVectorCatalog = [...state.catalogResults];
      state.catalogLoadedAssessmentId = state.assessmentId;
    }
    renderCatalogResults(state.activeCartId);
  } catch (error) {
    if (requestId !== state.catalogSearchRequestId) return;
    if (($("#catalog-query")?.value.trim() || "") !== query) return;
    state.catalogResults = [];
    renderCatalogResults(state.activeCartId);
    toast(error.message, true);
  } finally {
    if (requestId !== state.catalogSearchRequestId) return;
    state.catalogLoading = false;
    renderCatalogResults(state.activeCartId);
  }
}

function cartRelatedNodePickerMarkup(prefix, cart, selectedNodeIds = null) {
  const targetId = String(cart?.target_node_id || "");
  const initiallySelected = new Set(
    Array.isArray(selectedNodeIds) ? selectedNodeIds.map(String) : (targetId ? [targetId] : []),
  );
  const options = (state.workspace?.nodes || []).map((node) => {
    const nodeId = String(node.id);
    const selected = initiallySelected.has(nodeId);
    const searchText = `${nodeDisplayName(node)} ${nodeId}`.toLocaleLowerCase("ko-KR");
    return `<label class="attack-case-picker-option ${selected ? "selected" : ""}" data-related-node-option data-search-text="${escapeHtml(searchText)}"><input type="checkbox" name="${escapeHtml(prefix)}-node-id" value="${escapeHtml(nodeId)}" ${selected ? "checked" : ""}><span>${escapeHtml(nodeDisplayName(node))}</span></label>`;
  }).join("");
  return `<details class="attack-case-picker cart-related-node-picker" id="${escapeHtml(prefix)}-node-picker"><summary><span class="attack-case-picker-value">${escapeHtml(nodeDisplayName(targetId))}</span><span class="attack-case-picker-caret" aria-hidden="true">⌄</span></summary><div class="attack-case-picker-menu"><input type="search" id="${escapeHtml(prefix)}-node-search" placeholder="구성요소 이름 검색" autocomplete="off"><div class="attack-case-picker-options" role="group">${options}</div><div class="attack-case-picker-no-result" hidden>검색 결과가 없습니다.</div></div></details><span class="input-help">검색 후 여러 구성요소를 선택할 수 있습니다.</span>`;
}

function customVectorFieldsMarkup(prefix, cart, item = null) {
  const value = (field) => escapeHtml(item?.[field] || "");
  return `<div class="form-group"><label for="${prefix}-name">이름 <span class="required-mark">*</span></label><input type="text" id="${prefix}-name" class="form-control" maxlength="${CUSTOM_ATTACK_VECTOR_TEXT_LIMITS.name.max}" data-character-count value="${value("attack_vector_name")}" placeholder="예: 신뢰되지 않은 컨테이너 이미지 배포" required></div>
    <div class="form-group"><label for="${prefix}-description">설명 <span class="required-mark">*</span></label><textarea id="${prefix}-description" class="form-control" maxlength="${CUSTOM_ATTACK_VECTOR_TEXT_LIMITS.description.max}" data-character-count placeholder="예: 신뢰되지 않은 컨테이너 이미지를 배포해 워크로드에서 악성 코드를 실행한다." required>${value("attack_vector_description")}</textarea></div>
    <div class="form-group"><label for="${prefix}-prerequisite">선행조건 (선택)</label><textarea id="${prefix}-prerequisite" class="form-control" maxlength="${CUSTOM_ATTACK_VECTOR_TEXT_LIMITS.prerequisite.max}" data-character-count placeholder="예: 공격자가 이미지 저장소에 이미지를 등록하거나 참조 경로를 변경할 수 있음">${value("prerequisite")}</textarea><span class="input-help">확인된 조건만 입력하며, 알 수 없으면 비워 둡니다.</span></div>
    <div class="form-group"><label>관련 DFD 구성요소 <span class="required-mark">*</span></label>${cartRelatedNodePickerMarkup(prefix, cart, item?.related_node_ids)}</div>
    <div class="form-group"><label for="${prefix}-source">출처 <span class="required-mark">*</span></label><input type="text" id="${prefix}-source" class="form-control" maxlength="${CUSTOM_ATTACK_VECTOR_TEXT_LIMITS.source.max}" data-character-count value="${value("attack_vector_source")}" placeholder="예: MITRE ATT&CK T1204.003, CAPEC-100, CVE-2025-XXXX, 위협 보고서" required></div>
    <div class="form-group"><label for="${prefix}-reference-url">참조 링크 (선택)</label><input type="url" id="${prefix}-reference-url" class="form-control" maxlength="${CUSTOM_ATTACK_VECTOR_TEXT_LIMITS.referenceUrl.max}" data-character-count value="${value("reference_url")}" placeholder="예: https://attack.mitre.org/techniques/T1204/003/"></div>
    <div class="form-group"><label for="${prefix}-reason">추가 이유 <span class="required-mark">*</span></label><textarea id="${prefix}-reason" class="form-control" maxlength="${CUSTOM_ATTACK_VECTOR_TEXT_LIMITS.reason.max}" data-character-count placeholder="예: 현재 KM 후보에는 없지만 선택한 DFD 구성요소의 공격 경로에 적용되므로 추가" required>${value("addition_reason")}</textarea></div>`;
}

function customVectorPayload(prefix) {
  return {
    name: $(`#${prefix}-name`).value,
    description: $(`#${prefix}-description`).value,
    prerequisite: $(`#${prefix}-prerequisite`).value.trim(),
    node_ids: selectedCartRelatedNodeIds(prefix),
    source: $(`#${prefix}-source`).value.trim(),
    reference_url: $(`#${prefix}-reference-url`).value.trim(),
    reason: $(`#${prefix}-reason`).value,
  };
}

function selectedCartRelatedNodeIds(prefix) {
  return $$(`input[name="${prefix}-node-id"]:checked`).map((input) => input.value);
}

function bindCartRelatedNodePicker(prefix) {
  const picker = $(`#${prefix}-node-picker`);
  if (!picker) return;
  const update = () => {
    const selected = selectedCartRelatedNodeIds(prefix);
    $$('[data-related-node-option]', picker).forEach((option) => {
      option.classList.toggle("selected", Boolean($("input", option)?.checked));
    });
    const summary = $(".attack-case-picker-value", picker);
    if (summary) {
      summary.textContent = selected.length
        ? (selected.length === 1 ? nodeDisplayName(selected[0]) : `${nodeDisplayName(selected[0])} 외 ${selected.length - 1}개`)
        : "검색하여 선택";
      summary.classList.toggle("placeholder", selected.length === 0);
    }
  };
  $$("input[type='checkbox']", picker).forEach((input) => input.onchange = update);
  const search = $(`#${prefix}-node-search`);
  if (search) search.oninput = () => {
    const query = search.value.trim().toLocaleLowerCase("ko-KR");
    let visible = 0;
    $$('[data-related-node-option]', picker).forEach((option) => {
      const matches = !query || String(option.dataset.searchText || "").includes(query);
      option.hidden = !matches;
      if (matches) visible += 1;
    });
    const noResult = $(".attack-case-picker-no-result", picker);
    if (noResult) noResult.hidden = visible > 0;
  };
  update();
}

function showCatalogAddModal(cartId, vectorId) {
  const vector = state.catalogResults.find((item) => item.id === vectorId);
  const cart = cartById(cartId);
  if (!vector || !cart) { toast("추가할 공격 벡터를 찾을 수 없습니다.", true); return; }
  $("#add-vector-modal")?.remove();
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop cart-vector-modal" id="add-vector-modal"><div class="cart-modal-window" role="dialog" aria-modal="true" aria-labelledby="add-vector-title"><div class="cart-modal-header"><h3 id="add-vector-title">공격 벡터 추가</h3><button class="btn small" type="button" data-close-add-vector>닫기</button></div><form id="add-vector-form"><div class="cart-modal-body"><div class="notice info"><div>+</div><div><strong>${escapeHtml(attackVectorCatalogId(vector))} ${escapeHtml(vector.name)}</strong><span>${escapeHtml(vector.description)}</span><small>출처: ${escapeHtml(attackVectorSourceName(vector))}</small></div></div><div class="form-group"><label>관련 DFD 구성요소 <span class="required-mark">*</span></label>${cartRelatedNodePickerMarkup("add", cart)}</div><div class="form-group"><label for="add-reason">추가 이유 <span class="required-mark">*</span></label><textarea id="add-reason" class="form-control" placeholder="예: 현재 KM 후보에는 없지만 선택한 DFD 구성요소의 공격 경로에 적용되므로 추가" required></textarea></div></div><div class="cart-modal-footer"><button class="btn primary" type="submit">추가</button></div></form></div></div>`);
  $$('[data-close-add-vector]').forEach((button) => button.onclick = () => $("#add-vector-modal")?.remove());
  bindCartRelatedNodePicker("add");
  $("#add-vector-form").onsubmit = async (event) => {
    event.preventDefault();
    if (!confirmCartChange(cart, "이 쇼핑 카트에 공격 벡터를 추가합니다.")) return;
    const submit = $('button[type="submit"]', event.currentTarget);
    submit.disabled = true;
    try {
      const nodeIds = selectedCartRelatedNodeIds("add");
      if (!nodeIds.length) throw new Error("관련 DFD 구성요소를 하나 이상 선택해 주세요.");
      await api(`/api/carts/${cartId}/items/catalog`, { method: "POST", body: { attack_vector_id: vectorId, node_ids: nodeIds, reason: $("#add-reason").value } });
      $("#add-vector-modal")?.remove();
      await reloadWorkspace();
      renderCartsStep();
      toast("공격 벡터를 추가했습니다.");
    } catch (error) { submit.disabled = false; toast(error.message, true); }
  };
}

function showCustomVectorModal(cartId) {
  const cart = cartById(cartId);
  if (!cart) { toast("쇼핑 카트를 찾을 수 없습니다.", true); return; }
  $("#custom-modal")?.remove();
  const publishOption = state.bootstrap?.km_admin_enabled
    ? `<fieldset class="custom-vector-scope"><legend>등록 범위</legend><label><input type="radio" name="custom-scope" value="assessment" checked><span><strong>현재 평가에만 추가</strong><small>다른 평가의 KM 검색 결과에는 나타나지 않습니다.</small></span></label><label><input type="radio" name="custom-scope" value="km"><span><strong>공용 KM에도 등록</strong><small>현재 자산 유형의 공격 벡터로 등록되어 이후 평가에서도 검색됩니다.</small></span></label></fieldset>`
    : `<div class="custom-vector-scope-note"><strong>현재 평가에만 추가됩니다.</strong><span>공용 KM 등록은 KM 관리 모드에서 사용할 수 있습니다.</span></div>`;
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop cart-vector-modal" id="custom-modal"><div class="cart-modal-window" role="dialog" aria-modal="true" aria-labelledby="custom-modal-title"><div class="cart-modal-header"><div><h3 id="custom-modal-title">새로운 공격 벡터 추가</h3><span>AV ID는 출처와 무관하게 자동 발급되며, 이 평가에서만 사용됩니다.</span></div><button class="btn small" type="button" data-close-custom-modal>닫기</button></div><form id="custom-vector-form"><div class="cart-modal-body">${publishOption}${customVectorFieldsMarkup("custom", cart)}</div><div class="cart-modal-footer"><button type="submit" class="btn primary">추가</button></div></form></div></div>`);
  const close = () => $("#custom-modal")?.remove();
  $$('[data-close-custom-modal]').forEach((button) => button.onclick = close);
  bindCartRelatedNodePicker("custom");
  bindCharacterCounters($("#custom-vector-form"));
  $("#custom-vector-form").onsubmit = async (event) => {
    event.preventDefault();
    if (!confirmCartChange(cart, "이 쇼핑 카트에 평가 한정 공격 벡터를 추가합니다.")) return;
    const submit = $('button[type="submit"]', event.currentTarget);
    submit.disabled = true;
    try {
      const publishToKm = $('input[name="custom-scope"]:checked')?.value === "km";
      const payload = customVectorPayload("custom");
      if (!payload.node_ids.length) throw new Error("관련 DFD 구성요소를 하나 이상 선택해 주세요.");
      await api(`/api/carts/${cartId}/items/custom`, { method: "POST", body: { ...payload, publish_to_km: publishToKm } });
      close();
      if (publishToKm) {
        state.catalogResults = [];
        state.catalogLoadedAssessmentId = null;
        state.cartCatalogQuery = "";
      }
      await reloadWorkspace();
      renderCartsStep();
      toast(publishToKm ? "공격 벡터를 공용 KM과 현재 쇼핑 카트에 등록했습니다." : "현재 평가에 공격 벡터를 추가했습니다.");
    } catch (error) { submit.disabled = false; toast(error.message, true); }
  };
}

function showEditCustomVectorModal(cartId, itemId) {
  const cart = cartById(cartId);
  const item = cart?.items.find((candidate) => String(candidate.id) === String(itemId));
  if (!cart || !item || item.item_source !== "MANUAL_CUSTOM") {
    toast("수정할 평가 전용 공격 벡터를 찾을 수 없습니다.", true);
    return;
  }
  $("#edit-custom-modal")?.remove();
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop cart-vector-modal" id="edit-custom-modal"><div class="cart-modal-window" role="dialog" aria-modal="true" aria-labelledby="edit-custom-modal-title"><div class="cart-modal-header"><div><h3 id="edit-custom-modal-title">공격 벡터 수정</h3><span>${escapeHtml(cartVectorDisplayId(item))} · 현재 평가에서 직접 추가한 항목</span></div></div><form id="edit-custom-vector-form"><div class="cart-modal-body">${customVectorFieldsMarkup("edit-custom", cart, item)}</div><div class="cart-modal-footer"><button type="button" class="btn danger" data-delete-edit-custom>삭제</button><button type="button" class="btn" data-close-edit-custom>닫기</button><button type="submit" class="btn primary">저장</button></div></form></div></div>`);
  const close = () => $("#edit-custom-modal")?.remove();
  $$('[data-close-edit-custom]').forEach((button) => button.onclick = close);
  bindCartRelatedNodePicker("edit-custom");
  bindCharacterCounters($("#edit-custom-vector-form"));
  $("[data-delete-edit-custom]").onclick = async (event) => {
    const message = `${cartVectorDisplayId(item)} 공격 벡터를 현재 평가에서 삭제합니다.`;
    const confirmed = cart.status === "DRAFT" && !hasDownstreamResults()
      ? window.confirm(`${message}\n계속할까요?`)
      : confirmCartChange(cart, message);
    if (!confirmed) return;
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await api(`/api/carts/${cart.id}/items`, { method: "DELETE", body: { item_ids: [item.id] } });
      close();
      await reloadWorkspace();
      renderCartsStep();
      toast("공격 벡터를 삭제했습니다.");
    } catch (error) {
      button.disabled = false;
      toast(error.message, true);
    }
  };
  $("#edit-custom-vector-form").onsubmit = async (event) => {
    event.preventDefault();
    if (!confirmCartChange(cart, "직접 추가한 공격 벡터의 내용을 수정합니다.")) return;
    const submit = $('button[type="submit"]', event.currentTarget);
    submit.disabled = true;
    try {
      const payload = customVectorPayload("edit-custom");
      if (!payload.node_ids.length) throw new Error("관련 DFD 구성요소를 하나 이상 선택해 주세요.");
      await api(`/api/cart-items/${item.id}/custom`, { method: "PUT", body: payload });
      close();
      await reloadWorkspace();
      renderCartsStep();
      toast("공격 벡터를 수정했습니다.");
    } catch (error) {
      submit.disabled = false;
      toast(error.message, true);
    }
  };
}

function reviewKorean(status) { return status === "PLAUSIBLE" ? "타당함" : status === "ELIMINATED" ? "제외" : "미검토"; }
function isInformationGapDraftText(value) {
  const text = String(value ?? "").trim().replace(/[.!?]+$/u, "").replace(/\s+/g, " ");
  return /^판단 정보(?:가)? 부족(?:합니다)?$/u.test(text);
}

function visibleLlmMissingInformation(_value) {
  // Do not reapply legacy missing-information payloads.
  return [];
}

function plausibilitySuggestionIsActionable(suggestion) {
  if (!suggestion || typeof suggestion !== "object") return false;
  const status = String(suggestion.status || "").toUpperCase();
  const reason = String(suggestion.reason || "").trim();
  return ["PLAUSIBLE", "ELIMINATED"].includes(status) && Boolean(reason) && !isInformationGapDraftText(reason);
}

function plausibilitySuggestionFor(item) {
  return plausibilitySuggestionIsActionable(item?.llm_plausibility) ? item.llm_plausibility : null;
}

function reviewDraftFor(item) {
  const key = String(item.id);
  const savedStatus = String(item.review_status || "UNREVIEWED");
  const savedReason = String(item.decision_reason || "");
  let draft = state.reviewDrafts[key];
  if (!draft || (!draft.dirty && (draft.savedStatus !== savedStatus || draft.savedReason !== savedReason))) {
    draft = { status: savedStatus, reason: savedReason, savedStatus, savedReason, source: "SAVED", dirty: false };
    state.reviewDrafts[key] = draft;
  }
  return draft;
}

function updateReviewDraft(item, values) {
  const draft = reviewDraftFor(item);
  if (values.status !== undefined) draft.status = String(values.status);
  if (values.reason !== undefined) draft.reason = String(values.reason);
  if (values.source) draft.source = values.source;
  draft.dirty = draft.status !== draft.savedStatus || draft.reason.trim() !== draft.savedReason.trim();
  return draft;
}

function reviewDraftIsDirty() {
  return Object.values(state.reviewDrafts || {}).some((draft) => draft?.dirty);
}

function confirmReviewDraftDiscard() {
  return !reviewDraftIsDirty() || window.confirm("저장하지 않은 판정 내용이 있습니다. 변경을 취소하고 이동할까요?");
}

function reviewStatusOptions(status) {
  return [
    ["UNREVIEWED", "미검토"],
    ["PLAUSIBLE", "타당함"],
    ["ELIMINATED", "제외"],
  ].map(([value, label]) => `<option value="${value}" ${status === value ? "selected" : ""}>${label}</option>`).join("");
}

function reviewContextMarkup(cart) {
  const assessment = state.workspace.assessment;
  const scope = scopeBriefDisplay(assessment);
  const endpoints = cartCaseEndpoints(cart);
  const items = [
    ["Attack Case", cartCaseLabel(cart)],
    ["Entry Point", nodeDisplayName(endpoints.entryId, "진입 지점")],
    ["Intended Target", nodeDisplayName(endpoints.targetId, "공격 대상")],
    ["의도한 효과", cartCaseEffect(cart)],
    ["Case 선정 근거", cartCaseRationale(cart)],
    ["위협 행위자", scope.actorType],
    ["알려진 행위자 역량", scope.capabilities],
    ["가정 및 참고사항", compact(assessment.technical_info, scope.actorNotes)],
  ];
  return `<details class="card review-context-card" ${state.reviewContextExpanded ? "open" : ""}><summary class="review-context-summary"><div><strong>평가 맥락</strong><span>${escapeHtml(shoppingCartLabel(cart))}: ${escapeHtml(cartCaseLabel(cart))}</span></div><span class="review-context-toggle"><span class="review-context-open-label">보기</span><span class="review-context-close-label">접기</span><i aria-hidden="true">⌄</i></span></summary><div class="review-context-grid">${items.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(compact(value, "아직 모름"))}</strong></div>`).join("")}</div></details>`;
}

function renderReviewStep() {
  const cart = cartById(state.activeCartId) || state.workspace.carts[0];
  if (!cart) return;
  state.activeCartId = cart.id;
  const drafts = new Map(cart.items.map((item) => [String(item.id), reviewDraftFor(item)]));
  const reviewedCount = cart.items.filter((item) => drafts.get(String(item.id)).status !== "UNREVIEWED").length;
  const allReviewed = state.workspace.carts.every((item) => item.status === "REVIEWED");
  const pendingCarts = state.workspace.carts.filter((item) => item.status !== "REVIEWED");
  const gate = allReviewed ? "" : `<div class="workflow-gate"><strong>모든 쇼핑 카트의 타당성 검토가 끝나야 위험 평가로 이동할 수 있습니다.</strong><span>남은 쇼핑 카트: ${escapeHtml(pendingCarts.map((item) => shoppingCartLabel(item)).join(", "))}</span></div>`;
  const rows = cart.items.map((item) => {
    const draft = drafts.get(String(item.id));
    const llmSuggestion = plausibilitySuggestionFor(item);
    const entryNames = item.related_entry_ids.map((id) => nodeDisplayName(id)).join(", ") || "없음";
    const relatedNames = item.related_node_ids.map((id) => nodeDisplayName(id)).join(", ") || "없음";
    const llmBadge = draft.source === "LLM"
      ? '<span class="badge purple">LLM 초안 적용</span>'
      : llmSuggestion ? '<span class="badge purple">LLM 초안 있음</span>' : "";
    const missing = draft.source === "LLM"
      ? visibleLlmMissingInformation(draft.missingInformation)
      : visibleLlmMissingInformation(llmSuggestion?.missing_information);
    return `<tr data-review-row="${item.id}" class="${draft.dirty ? "is-dirty" : ""}">
      <td class="review-vector-cell"><div class="vector-id">${escapeHtml(cartVectorDisplayId(item))}</div><div class="vector-name">${escapeHtml(item.attack_vector_name)}</div><div class="review-row-badges"><span class="badge blue">${escapeHtml(attackVectorSourceName(item))}</span>${llmBadge}</div><details><summary>매핑 근거</summary><div><b>진입 지점</b> ${escapeHtml(entryNames)}<br><b>관련 구성요소</b> ${escapeHtml(relatedNames)}</div></details></td>
      <td class="review-description-cell"><div>${escapeHtml(item.attack_vector_description || "-")}</div>${vectorPrerequisiteMarkup(item)}</td>
      <td><select class="review-status-select status-${draft.status.toLowerCase()}" data-review-status="${item.id}" aria-label="${escapeHtml(item.attack_vector_name)} 검토 상태">${reviewStatusOptions(draft.status)}</select><div class="form-error review-status-error hidden" data-review-status-error="${item.id}">검토 상태를 선택해 주세요.</div>${missing.length ? `<div class="review-missing-info">추가 확인: ${escapeHtml(missing.join(", "))}</div>` : ""}</td>
      <td><textarea class="review-reason-input" data-review-reason="${item.id}" rows="3" maxlength="10000" placeholder="필요한 경우 판정 이유를 입력하세요. (선택)">${escapeHtml(draft.reason)}</textarea><div class="form-error hidden" data-review-error="${item.id}"></div></td>
    </tr>`;
  }).join("");
  const table = cart.items.length
    ? `<div class="review-table-wrap"><table class="data-table review-bulk-table"><colgroup><col class="review-col-vector"><col class="review-col-description"><col class="review-col-status"><col class="review-col-reason"></colgroup><thead><tr><th>공격 벡터</th><th>설명</th><th>검토 상태</th><th>판단 근거 <span class="optional-mark">(선택)</span></th></tr></thead><tbody>${rows}</tbody></table></div>`
    : emptyState("검토할 공격 벡터가 없습니다", "빈 쇼핑카트도 전체 저장하면 검토 완료로 처리됩니다.");
  const llmDisabled = !cart.items.length || !llmEnabledForAssessment();
  $("#step-content").innerHTML = `${pageHeader("1.4 공격 벡터 타당성 검토", "쇼핑 카트의 공격 벡터를 검토하고 결과를 저장합니다.", `<button class="btn primary" id="go-risk" aria-disabled="${allReviewed ? "false" : "true"}">위험 평가로 이동</button>`)}<div class="page-body review-bulk-page">
    ${reviewContextMarkup(cart)}
    <div class="review-cart-toolbar"><div class="review-cart-tabs-wrap">${cartTabs()}</div><div class="review-bulk-assist"><div class="review-bulk-status" role="group" aria-label="검토 상태 일괄 설정"><button class="btn" type="button" data-review-set-all="PLAUSIBLE">전체 타당함</button><button class="btn" type="button" data-review-set-all="ELIMINATED">전체 제외</button></div><button class="btn" id="llm-review-cart" ${llmDisabled ? "disabled title='LLM 설정과 평가별 허용이 필요합니다.'" : ""}>LLM 초안 받기</button><p>초안과 일괄 설정은 저장 전에 항목별로 수정할 수 있습니다.</p></div></div>
    ${gate}
    <section class="card review-table-card"><div class="card-header"><div><h2>${escapeHtml(shoppingCartLabel(cart))}</h2><div class="small-text muted">공격 벡터 ${cart.items.length}개, 입력 ${reviewedCount}개. ${escapeHtml(cartCaseLabel(cart))}</div></div><strong class="review-progress-count">${reviewedCount}/${cart.items.length}</strong></div>${table}<div class="review-bulk-actions"><span>검토 상태를 모두 선택하면 저장할 수 있습니다. 판단 근거는 선택입니다.</span><button class="btn primary" id="save-cart-reviews">전체 저장</button></div></section>
  </div>`;

  $$('[data-cart-tab]').forEach((button) => button.onclick = () => {
    state.activeCartId = Number(button.dataset.cartTab);
    renderReviewStep();
  });
  $$('[data-review-status]').forEach((select) => select.onchange = () => {
    const item = cart.items.find((entry) => Number(entry.id) === Number(select.dataset.reviewStatus));
    if (!item) return;
    updateReviewDraft(item, { status: select.value, source: "USER" });
    select.className = `review-status-select status-${select.value.toLowerCase()}`;
    select.removeAttribute("aria-invalid");
    $(`[data-review-status-error="${item.id}"]`)?.classList.add("hidden");
    select.closest("tr")?.classList.toggle("is-dirty", reviewDraftFor(item).dirty);
    const count = cart.items.filter((entry) => reviewDraftFor(entry).status !== "UNREVIEWED").length;
    const progress = $(".review-progress-count");
    if (progress) progress.textContent = `${count}/${cart.items.length}`;
  });
  $$('[data-review-reason]').forEach((textarea) => textarea.oninput = () => {
    const item = cart.items.find((entry) => Number(entry.id) === Number(textarea.dataset.reviewReason));
    if (!item) return;
    updateReviewDraft(item, { reason: textarea.value, source: "USER" });
    textarea.closest("tr")?.classList.toggle("is-dirty", reviewDraftFor(item).dirty);
    $(`[data-review-error="${item.id}"]`)?.classList.add("hidden");
  });
  $("#save-cart-reviews").onclick = () => saveCartReviews(cart);
  $("#llm-review-cart").onclick = () => requestCartPlausibility(cart);
  $$('[data-review-set-all]').forEach((button) => button.onclick = () => {
    const status = button.dataset.reviewSetAll;
    cart.items.forEach((item) => updateReviewDraft(item, { status, source: "USER" }));
    $$('[data-review-status]').forEach((select) => {
      select.value = status;
      select.className = `review-status-select status-${status.toLowerCase()}`;
      select.removeAttribute("aria-invalid");
      $(`[data-review-status-error="${select.dataset.reviewStatus}"]`)?.classList.add("hidden");
      select.closest("tr")?.classList.add("is-dirty");
    });
    const progress = $(".review-progress-count");
    if (progress) progress.textContent = `${cart.items.length}/${cart.items.length}`;
    toast(status === "PLAUSIBLE" ? "모든 항목을 타당함으로 설정했습니다." : "모든 항목을 제외로 설정했습니다.");
  });
  $("#go-risk").onclick = () => {
    if (!allReviewed) { explainCtsaBlock(5); return; }
    if (!confirmReviewDraftDiscard()) return;
    state.step = 5;
    renderWorkspace();
  };
}

async function saveCartReviews(cart) {
  const unresolved = cart.items.filter((item) => reviewDraftFor(item).status === "UNREVIEWED");
  if (unresolved.length) {
    showValidationSummary(
      [`${shoppingCartLabel(cart)}: 검토 상태를 선택하지 않은 항목 ${unresolved.length}개`],
      unresolved.map((item) => `[data-review-status="${item.id}"]`),
    );
    return;
  }
  const reviews = cart.items.map((item) => {
    const draft = reviewDraftFor(item);
    return { item_id: Number(item.id), status: draft.status, reason: draft.reason.trim() };
  });
  const changed = cart.items.some((item) => reviewDraftFor(item).dirty);
  if (changed && hasDownstreamResults() && !window.confirm("판정을 변경하면 기존 위험 평가, 민감도 매트릭스와 대응책 분석 결과가 초기화됩니다. 계속할까요?")) return;
  const button = $("#save-cart-reviews");
  button.disabled = true;
  button.textContent = "전체 저장 중...";
  try {
    const result = await api(`/api/carts/${cart.id}/reviews`, { method: "PUT", body: { reviews } });
    cart.items.forEach((item) => delete state.reviewDrafts[String(item.id)]);
    await reloadWorkspace();
    renderReviewStep();
    toast(result.cart_status === "REVIEWED" ? "전체 판정을 저장하고 쇼핑카트 검토를 완료했습니다." : "전체 입력값을 저장했습니다. 미검토 항목을 마저 판정해 주세요.");
  } catch (error) {
    button.disabled = false;
    button.textContent = "현재 쇼핑카트 전체 저장";
    toast(error.message, true);
  }
}

async function requestCartPlausibility(cart) {
  if (reviewDraftIsDirty() && !window.confirm("현재 입력 중인 값을 LLM 초안으로 덮어쓸까요?")) return;
  if (!window.confirm("현재 쇼핑카트의 모든 공격 벡터, DFD 구성요소와 평가 맥락이 설정된 외부 LLM에 전송됩니다. 초안을 요청할까요?")) return;
  const button = $("#llm-review-cart");
  button.disabled = true;
  button.textContent = "전체 초안 생성 중...";
  try {
    const result = await api(`/api/carts/${cart.id}/llm/plausibility`, { method: "POST", body: {} });
    await reloadWorkspace();
    const refreshedCart = cartById(cart.id);
    let appliedCount = 0;
    (result.suggestions || []).forEach((suggestion) => {
      const item = refreshedCart?.items.find((entry) => Number(entry.id) === Number(suggestion.item_id));
      if (!item) return;
      const draft = reviewDraftFor(item);
      if (!plausibilitySuggestionIsActionable(suggestion)) {
        draft.status = draft.savedStatus;
        draft.reason = draft.savedReason;
        draft.source = "SAVED";
        draft.missingInformation = [];
        draft.dirty = false;
        return;
      }
      draft.status = suggestion.status;
      draft.reason = suggestion.reason || "";
      draft.source = "LLM";
      draft.missingInformation = visibleLlmMissingInformation(suggestion.missing_information);
      draft.dirty = draft.status !== draft.savedStatus || draft.reason.trim() !== draft.savedReason.trim();
      appliedCount += 1;
    });
    renderReviewStep();
    toast(appliedCount === (result.suggestions || []).length
      ? "모든 공격 벡터의 LLM 초안을 입력했습니다. 확인한 뒤 저장하세요."
      : "확정 판정이 있는 LLM 초안만 입력했습니다. 나머지는 사용자가 직접 선택해 주세요.");
  } catch (error) {
    button.disabled = false;
    button.textContent = "LLM 초안 받기";
    toast(error.message, true);
  }
}

function selectedRiskModel() { return state.workspace.risk_models.find((model) => model.id === state.workspace.assessment.risk_model_id); }
function formatRiskNumber(value, decimals = null) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  if (Number.isInteger(decimals) && decimals >= 0) {
    return number.toLocaleString("ko-KR", { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
  }
  return number.toLocaleString("ko-KR", { maximumFractionDigits: 6 });
}

function riskBasisMeta(basis) {
  if (basis === "PR20_EXPLICIT") return { label: "원문 명시식", color: "green" };
  if (basis === "CNTARA_DERIVED") return { label: "CloudTARA 도출식", color: "orange" };
  if (basis === "ASSESSMENT_CUSTOM") return { label: "평가별 사용자 정의", color: "purple" };
  return { label: compact(basis, "계산 근거 미표시"), color: "" };
}

function riskRoundingLabel(decimals) {
  const places = Number(decimals);
  if (!Number.isInteger(places) || places < 0) return "반올림 방식 미정";
  return places === 0 ? "정수로 반올림" : `소수점 이하 ${places}자리로 반올림`;
}

function riskBandsLabel(model) {
  const bands = Array.isArray(model?.bands) ? model.bands : [];
  if (!bands.length) return "등급 구간 없음";
  return bands.map((band) => `${compact(band.label, "등급")} ${formatRiskNumber(band.min)}–${formatRiskNumber(band.max)}`).join(", ");
}

function riskModelSummaryMarkup(model) {
  const basis = riskBasisMeta(model.basis);
  const hasRange = model.score_min !== null && model.score_min !== undefined && model.score_max !== null && model.score_max !== undefined
    && Number.isFinite(Number(model.score_min)) && Number.isFinite(Number(model.score_max));
  return `<details class="risk-model-card selected-model">
    <summary class="risk-model-heading"><div><h3>${escapeHtml(model.name)}</h3><p>${escapeHtml(compact(model.formula_text, model.description))}</p></div><div class="risk-model-heading-actions"><span class="badge ${basis.color}">${escapeHtml(basis.label)}</span><span class="risk-model-toggle">계산 기준 보기</span></div></summary>
    <dl class="risk-model-meta">
      <div class="wide"><dt>계산식</dt><dd class="risk-formula">${escapeHtml(compact(model.formula_text, "계산식 정보 없음"))}</dd></div>
      <div><dt>점수 범위</dt><dd>${hasRange ? `${formatRiskNumber(model.score_min)}–${formatRiskNumber(model.score_max)}` : "범위 미정"}</dd></div>
      <div><dt>반올림</dt><dd>${escapeHtml(riskRoundingLabel(model.decimals))}</dd></div>
      <div><dt>위험 등급</dt><dd class="${Array.isArray(model.bands) && model.bands.length ? "" : "no-risk-bands"}">${escapeHtml(riskBandsLabel(model))}</dd></div>
      <div class="wide"><dt>근거</dt><dd>${escapeHtml(compact(model.source_note, "출처 정보 없음"))}</dd></div>
    </dl>
  </details>`;
}

function riskModelSourceLabel(model) {
  const id = riskModelBaseId(model).toUpperCase();
  let source = "CloudTARA에서 정의한 계산 기준";
  if (id.includes("P66")) source = "MITRE TARA Training Workshop (2020), p.66";
  else if (id.includes("STANDARD")) source = "MITRE TARA Training Workshop (2020), p.121";
  else if (id.includes("CIA")) source = "MITRE TARA Training Workshop (2020), p.122";
  else if (id.includes("MISSION")) source = "MITRE TARA Training Workshop (2020), p.123";
  else if (id.includes("VXE")) source = "MITRE TARA Training Workshop (2020), p.124";
  if (model?.basis === "ASSESSMENT_CUSTOM") return `${source} 기반, 이 평가에서 조정`;
  return source;
}

function riskCalculatorInfoMarkup(model) {
  const hasRange = model.score_min !== null && model.score_min !== undefined && model.score_max !== null && model.score_max !== undefined
    && Number.isFinite(Number(model.score_min)) && Number.isFinite(Number(model.score_max));
  const factors = model.factors.map((factor) => escapeHtml(factor.name)).join(", ");
  return `<section class="risk-calculator-definition">
    <dl class="risk-calculator-facts">
      <div class="wide"><dt>평가 항목</dt><dd>${factors || "등록된 항목 없음"}</dd></div>
      <div><dt>점수 범위</dt><dd>${hasRange ? `${formatRiskNumber(model.score_min)}–${formatRiskNumber(model.score_max)}` : "별도 범위 없음"}</dd></div>
      <div><dt>반올림</dt><dd>${escapeHtml(riskRoundingLabel(model.decimals))}</dd></div>
      <div><dt>위험 등급</dt><dd>${escapeHtml(riskBandsLabel(model))}</dd></div>
    </dl>
    <div class="risk-calculator-formula"><span>계산식</span><code>${escapeHtml(compact(model.formula_text, "계산식 정보 없음"))}</code></div>
    <p class="risk-calculator-source"><span>출처</span>${escapeHtml(riskModelSourceLabel(model))}</p>
  </section>`;
}

function riskModelBaseId(model) {
  return String(model?.formula?.base_model_id || model?.id || "");
}

function riskModelDisplayName(model) {
  const id = riskModelBaseId(model).toUpperCase();
  if (id.includes("STANDARD")) return "Standard";
  if (id.includes("CIA")) return "CIA";
  if (id.includes("MISSION")) return "Mission";
  if (id.includes("VXE")) return "V×E";
  if (id.includes("P66") || model?.model_kind === "CUSTOM" || model?.basis === "ASSESSMENT_CUSTOM") return "Custom";
  return compact(model?.name, "Risk Calculator");
}

function riskModelFriendlyName(model) {
  const kind = riskModelDisplayName(model);
  if (kind === "Standard") return "기본 위험 평가";
  if (kind === "CIA") return "보안 피해별 평가";
  if (kind === "Mission") return "업무 및 임무 영향 평가";
  if (kind === "V×E") return "취약성과 노출 정도 평가";
  if (kind === "Custom") return "평가 기준 직접 설정";
  return compact(model?.name, "위험 평가");
}

function riskModelOfficialName(model) {
  const kind = riskModelDisplayName(model);
  if (kind === "V×E") return "Vulnerability × Exposure Risk Calculator";
  return `${kind} Risk Calculator`;
}

function riskModelPlainDescription(model) {
  const kind = riskModelDisplayName(model);
  if (kind === "Standard") return "공격이 성공할 가능성과 성공했을 때의 피해 정도를 평가합니다.";
  if (kind === "CIA") return "공격 피해를 정보 유출, 정보 변경, 서비스 중단으로 나누어 평가합니다.";
  if (kind === "Mission") return "공격이 업무나 임무 수행 능력에 미치는 영향을 평가합니다.";
  if (kind === "V×E") return "공격 가능성을 시스템의 취약성과 공격자의 접근 가능성으로 나누어 평가합니다.";
  if (model?.basis === "ASSESSMENT_CUSTOM" && !model?.formula?.base_model_id) return "이 평가에 맞게 직접 정한 항목, 척도와 중요도로 평가합니다.";
  if (kind === "Custom") return "평가 목적에 맞는 여러 항목과 중요도를 사용해 위험을 평가합니다.";
  return compact(model?.description, "선택한 기준으로 위험을 평가합니다.");
}

function riskModelScaleLabel(model) {
  const values = (model?.factors || []).flatMap((factor) => (factor.levels || []).map((level) => Number(level.value))).filter(Number.isFinite);
  if (!values.length) return "사용자 정의";
  return `${Math.min(...values)}–${Math.max(...values)}`;
}

const RISK_ADJUSTABLE_FACTORS = {
  "PR20-P66-WEIGHTED-SUM-V1": ["locality", "confidentiality", "availability", "prior_use", "stealth"],
  "CNTARA-PR20-CIA-V1": ["confidentiality", "integrity", "availability"],
  "CNTARA-PR20-VXE-V1": ["vulnerability", "exposure"],
};

function riskAdjustableFactorCodes(model) {
  return RISK_ADJUSTABLE_FACTORS[riskModelBaseId(model)] || [];
}

function riskFactorPlainDescription(factor) {
  const descriptions = {
    likelihood: "공격이 성공할 가능성",
    impact: "공격 성공으로 발생하는 전체 피해",
    confidentiality: "정보가 허가 없이 노출되는 영향",
    integrity: "정보나 설정이 허가 없이 변경되는 영향",
    availability: "시스템이나 서비스를 사용할 수 없게 되는 영향",
    mission_impact: "업무나 임무 수행 능력에 미치는 영향",
    vulnerability: "시스템이 해당 공격에 취약한 정도",
    exposure: "공격자가 시스템에 접근하기 쉬운 정도",
    locality: "공격 영향이 퍼지는 범위",
    prior_use: "공격이 이전에 사용된 근거",
    stealth: "공격을 탐지하기 어려운 정도",
  };
  return descriptions[factor?.code] || compact(factor?.question, "이 항목이 위험에 미치는 영향");
}

function riskModelSourceForSelection(model, current) {
  return current && riskModelBaseId(current) === model?.id ? current : model;
}

function riskWeightDraftFor(model, current) {
  const codes = riskAdjustableFactorCodes(model);
  if (!codes.length) return {};
  if (!state.riskModelWeightDrafts[model.id]) {
    const source = riskModelSourceForSelection(model, current);
    state.riskModelWeightDrafts[model.id] = Object.fromEntries(codes.map((code) => {
      const factor = source?.factors?.find((item) => item.code === code) || model.factors.find((item) => item.code === code);
      return [code, Number((Number(factor?.weight || 0) * 100).toFixed(6))];
    }));
  }
  return state.riskModelWeightDrafts[model.id];
}

function riskWeightTotal(model, current) {
  return Object.values(riskWeightDraftFor(model, current)).reduce((sum, value) => sum + Number(value || 0), 0);
}

function riskWeightsEqual(leftModel, rightModel) {
  if (!leftModel || !rightModel || riskModelBaseId(leftModel) !== rightModel.id) return false;
  const draft = riskWeightDraftFor(rightModel, leftModel);
  return riskAdjustableFactorCodes(rightModel).every((code) => {
    const factor = leftModel.factors.find((item) => item.code === code);
    return factor && Math.abs(Number(draft[code]) / 100 - Number(factor.weight)) < 1e-9;
  });
}

function riskSelectionMatchesCurrent(current, selected) {
  if (!current || !selected || riskModelBaseId(current) !== selected.id) return false;
  return riskAdjustableFactorCodes(selected).length
    ? riskWeightsEqual(current, selected)
    : current.id === selected.id;
}

function riskWeightSettingsMarkup(model, current) {
  const codes = riskAdjustableFactorCodes(model);
  if (!codes.length) {
    return `<div class="risk-weight-fixed"><strong>기본 계산 구조를 사용합니다.</strong><p>이 계산기는 별도로 조정할 하위 가중치가 없습니다. 평가 항목의 척도와 계산 방법은 상세 기준에서 확인할 수 있습니다.</p></div>`;
  }
  const draft = riskWeightDraftFor(model, current);
  const fixedRows = model.factors.filter((factor) => !codes.includes(factor.code)).map((factor) => (
    `<div class="risk-weight-row fixed"><span><strong>${escapeHtml(factor.name)}</strong><small>${escapeHtml(riskFactorPlainDescription(factor))}</small></span><span>고정 구조</span></div>`
  )).join("");
  const rows = codes.map((code) => {
    const factor = model.factors.find((item) => item.code === code);
    return `<label class="risk-weight-row"><span><strong>${escapeHtml(factor?.name || code)}</strong><small>${escapeHtml(riskFactorPlainDescription(factor))}</small></span><span class="risk-weight-input"><input type="number" min="0" max="100" step="1" inputmode="decimal" value="${escapeHtml(draft[code])}" data-risk-weight="${escapeHtml(code)}"><em>%</em></span></label>`;
  }).join("");
  const total = riskWeightTotal(model, current);
  return `<div class="risk-weight-editor"><div class="risk-weight-editor-head"><div><strong>평가 항목 중요도</strong><p>값이 클수록 해당 항목이 최종 점수에 더 크게 반영됩니다.</p></div><button type="button" class="btn small" data-risk-weight-reset>기본값으로 되돌리기</button></div>${fixedRows}${rows}<div class="risk-weight-total ${Math.abs(total - 100) < 1e-7 ? "valid" : "invalid"}"><span>조정 항목 합계</span><strong data-risk-weight-total>${formatRiskNumber(total, 0)}%</strong></div><p class="risk-weight-error" data-risk-weight-error ${Math.abs(total - 100) < 1e-7 ? "hidden" : ""}>중요도 합계가 100%가 되도록 조정해 주세요.</p></div>`;
}

function riskSelectionGuideMarkup() {
  return `<details class="risk-selection-guide"><summary>어떤 방식을 선택해야 할지 모르겠어요</summary><div><p>아래 안내는 MITRE의 환경별 권고가 아니라 각 계산기가 측정하는 기준을 풀어쓴 설명입니다.</p><dl><div><dt>성공 가능성과 전체 피해</dt><dd>기본 위험 평가</dd></div><div><dt>정보 유출·변경·서비스 중단을 분리</dt><dd>보안 피해별 평가</dd></div><div><dt>업무나 임무 수행 영향</dt><dd>업무 및 임무 영향 평가</dd></div><div><dt>취약성과 접근 가능성을 분리</dt><dd>취약성과 노출 정도 평가</dd></div><div><dt>조직 고유 평가 기준</dt><dd>평가 기준 직접 설정</dd></div></dl></div></details>`;
}

function riskModelChooserMarkup(models, selectedModel = null) {
  const selectedId = state.riskModelSelectionId || riskModelBaseId(selectedModel) || "";
  const cards = models.map((model) => {
    const selected = selectedId === model.id;
    const factors = model.factors.map((factor) => `<span>${escapeHtml(factor.name)}</span>`).join("");
    return `<button type="button" class="risk-choice-card ${selected ? "selected" : ""}" data-risk-model-option="${escapeHtml(model.id)}" role="radio" aria-checked="${selected ? "true" : "false"}">
      <div class="risk-choice-heading"><div><span>${escapeHtml(riskModelFriendlyName(model))}</span><h3>${escapeHtml(riskModelOfficialName(model))}</h3></div></div>
      <p>${escapeHtml(riskModelPlainDescription(model))}</p>
      <div class="risk-choice-factors"><strong>${model.factors.length}개 평가 항목</strong><div>${factors}</div></div>
      <div class="risk-choice-scale"><span>입력 척도</span><strong>${escapeHtml(riskModelScaleLabel(model))}</strong></div>
      <span class="risk-choice-check" aria-hidden="true">${selected ? "선택됨" : "선택"}</span>
    </button>`;
  }).join("");
  const chosen = models.find((model) => model.id === selectedId);
  const current = riskSelectionMatchesCurrent(selectedModel, chosen);
  const warnings = selectedModel && chosen ? riskModelChangeWarning() : [];
  const warning = warnings.length
    ? `<p class="risk-choice-warning" data-risk-change-warning ${current ? "hidden" : ""}>계산기를 변경하면 ${escapeHtml(warnings.join(", "))}이 초기화됩니다.</p>`
    : "";
  const settings = chosen
    ? `<section class="risk-choice-settings"><div class="risk-choice-settings-title"><div><span>선택한 위험 평가 방식</span><h3>${escapeHtml(riskModelFriendlyName(chosen))}</h3><p>${escapeHtml(riskModelOfficialName(chosen))}</p></div><button type="button" class="btn" data-risk-model-info="${escapeHtml(chosen.id)}">상세 기준 보기</button></div>${riskWeightSettingsMarkup(chosen, selectedModel)}</section>`
    : "";
  const totalValid = !chosen || !riskAdjustableFactorCodes(chosen).length || Math.abs(riskWeightTotal(chosen, selectedModel) - 100) < 1e-7;
  const footer = chosen
    ? `<div class="risk-choice-footer"><div><span>현재 평가 전체에 적용</span><strong>${escapeHtml(riskModelFriendlyName(chosen))}</strong><p>모든 쇼핑카트의 공격 벡터에 같은 계산 기준을 사용합니다.</p>${warning}</div><div><button type="button" class="btn primary" data-risk-model-confirm ${totalValid ? "" : "disabled"}>${current ? "평가로 돌아가기" : "이 방식으로 평가 시작"}</button></div></div>`
    : `<div class="risk-choice-footer empty"><p>계산기를 하나 선택하면 평가를 시작할 수 있습니다.</p><button type="button" class="btn primary" disabled>이 계산기로 평가 시작</button></div>`;
  return `<section class="risk-chooser"><div class="risk-chooser-head"><div><span>Risk Calculator</span><h2>무엇을 기준으로 위험을 평가하시겠습니까?</h2><p>위험도를 판단할 기준을 선택한 뒤 평가 항목의 중요도를 확인해 주세요.</p></div><button type="button" class="btn" data-risk-model-custom>평가 항목과 척도 직접 설정</button></div>${riskSelectionGuideMarkup()}<div class="risk-choice-grid" role="radiogroup" aria-label="위험 계산기">${cards}</div>${settings}${footer}</section>`;
}

function renderRiskModelSelection() {
  const current = selectedRiskModel();
  const models = state.workspace.risk_models.filter((model) => (
    (model.active !== false || model.id === state.workspace.assessment.risk_model_id)
    && !model.formula?.base_model_id
  ));
  const plausibleCount = state.workspace.carts.reduce((total, cart) => total + riskPlausibleItems(cart).length, 0);
  $("#step-content").innerHTML = pageHeader("1.5 위험 계산기 선택", "공격 벡터 위험 평가에 적용할 계산 규칙을 먼저 선택합니다.")
    + `<div class="page-body risk-calculator-selection-page"><div class="risk-choice-context"><div><span>적용 범위</span><strong>쇼핑카트 ${state.workspace.carts.length}개</strong></div><div><span>평가 대상</span><strong>타당한 공격 벡터 ${plausibleCount}개</strong></div><p>계산 방식과 중요도는 평가 단위로 저장되며 모든 쇼핑카트에 동일하게 적용됩니다.</p></div>${riskModelChooserMarkup(models, current)}</div>`;
  bindRiskModelSelection(models, current);
}

function bindRiskModelSelection(models, current) {
  $$('[data-risk-model-option]').forEach((card) => card.onclick = () => {
    state.riskModelSelectionId = card.dataset.riskModelOption;
    delete state.riskModelWeightDrafts[card.dataset.riskModelOption];
    renderRiskModelSelection();
  });
  $("[data-risk-model-custom]")?.addEventListener("click", () => showCustomRiskModelModal());
  $("[data-risk-model-info]")?.addEventListener("click", (event) => {
    const model = models.find((item) => item.id === event.currentTarget.dataset.riskModelInfo);
    showRiskCalculatorInfo(model);
  });
  const chosen = models.find((item) => item.id === (state.riskModelSelectionId || riskModelBaseId(current)));
  $$('[data-risk-weight]').forEach((input) => input.oninput = () => {
    if (!chosen) return;
    const draft = riskWeightDraftFor(chosen, current);
    draft[input.dataset.riskWeight] = input.value === "" ? 0 : Number(input.value);
    const total = riskWeightTotal(chosen, current);
    const valid = Math.abs(total - 100) < 1e-7;
    const totalElement = $("[data-risk-weight-total]");
    if (totalElement) totalElement.textContent = formatRiskNumber(total, Number.isInteger(total) ? 0 : 1) + "%";
    totalElement?.closest(".risk-weight-total")?.classList.toggle("valid", valid);
    totalElement?.closest(".risk-weight-total")?.classList.toggle("invalid", !valid);
    const error = $("[data-risk-weight-error]");
    if (error) error.hidden = valid;
    const confirm = $("[data-risk-model-confirm]");
    if (confirm) {
      confirm.disabled = !valid;
      confirm.textContent = riskSelectionMatchesCurrent(current, chosen) ? "평가로 돌아가기" : "이 방식으로 평가 시작";
    }
    const warning = $("[data-risk-change-warning]");
    if (warning) warning.hidden = riskSelectionMatchesCurrent(current, chosen);
  });
  $("[data-risk-weight-reset]")?.addEventListener("click", () => {
    if (!chosen) return;
    state.riskModelWeightDrafts[chosen.id] = Object.fromEntries(riskAdjustableFactorCodes(chosen).map((code) => {
      const factor = chosen.factors.find((item) => item.code === code);
      return [code, Number((Number(factor?.weight || 0) * 100).toFixed(6))];
    }));
    renderRiskModelSelection();
  });
  $("[data-risk-model-confirm]")?.addEventListener("click", async () => {
    const value = state.riskModelSelectionId || riskModelBaseId(current);
    if (!value) return;
    const selected = models.find((item) => item.id === value);
    if (!selected) return;
    if (riskSelectionMatchesCurrent(current, selected)) {
      state.riskModelChoosing = false;
      state.riskModelSelectionId = null;
      state.riskModelWeightDrafts = {};
      renderRiskStep();
      return;
    }
    const adjustable = riskAdjustableFactorCodes(selected);
    const draft = riskWeightDraftFor(selected, current);
    const changedWeights = adjustable.some((code) => {
      const factor = selected.factors.find((item) => item.code === code);
      return Math.abs(Number(draft[code]) / 100 - Number(factor?.weight)) >= 1e-9;
    });
    if (changedWeights) await handleTailoredRiskModelSelection(selected, draft);
    else await handleRiskModelSelection({ target: { value, disabled: false } });
  });
}

function riskReferenceApproachesMarkup() {
  const approaches = state.workspace?.risk_reference_approaches || state.bootstrap?.risk_reference_approaches || [];
  if (!Array.isArray(approaches) || !approaches.length) return "";
  const cards = approaches.map((approach) => `<article class="risk-reference-card" aria-disabled="true">
    <div class="risk-reference-head"><h4>${escapeHtml(approach.name)}</h4><span class="badge">선택 불가</span></div>
    <div class="risk-reference-meta"><span>${escapeHtml(compact(approach.source, "출처 미정"))}</span><strong>${escapeHtml(compact(approach.status, "추가 정의 필요"))}</strong></div>
    <p>${escapeHtml(compact(approach.reason, "계산 규칙이 완성되지 않아 참고용으로만 표시합니다."))}</p>
  </article>`).join("");
  return `<details class="risk-reference-section">
    <summary class="risk-reference-title"><div><h3>다른 위험 평가 접근법 참고</h3><p>계산 규칙이 완전하지 않아 현재 선택할 수 없는 접근법입니다.</p></div><span class="count-pill">${approaches.length}</span></summary>
    <div class="risk-reference-grid">${cards}</div>
  </details>`;
}

function cartRiskComplete(cart) {
  return cart.items.filter((item) => item.review_status === "PLAUSIBLE").every((item) => (
    item.risk_score !== null
    && item.risk_score !== undefined
    && ["USER_REVIEWED", "USER_MODIFIED"].includes(String(item.risk_review_status || ""))
  ));
}
function riskComplete() { return Boolean(selectedRiskModel()) && state.workspace.carts.length > 0 && state.workspace.carts.every((cart) => cart.status === "REVIEWED" && cartRiskComplete(cart)); }

function riskInputsComplete(model) {
  return Boolean(model) && state.workspace.carts.length > 0 && state.workspace.carts.every((cart) => (
    cart.status === "REVIEWED"
    && riskPlausibleItems(cart).every((item) => riskDraftCompleteness(riskDraftFor(item, model), model).valuesComplete)
  ));
}

function riskCartNeedsSave(cart, model) {
  return riskPlausibleItems(cart).some((item) => {
    const draft = riskDraftFor(item, model);
    return draft.dirty
      || item.risk_score === null
      || item.risk_score === undefined
      || !["USER_REVIEWED", "USER_MODIFIED"].includes(String(item.risk_review_status || ""));
  });
}

function riskCartSavePayload(cart, model) {
  return {
    model_id: model.id,
    items: riskPlausibleItems(cart).map((item) => {
      const draft = riskDraftFor(item, model);
      return {
        item_id: Number(item.id),
        values: { ...draft.values },
        reasons: Object.fromEntries(model.factors.map((factor) => [
          factor.code,
          String(draft.reasons[factor.code] || "").trim(),
        ])),
      };
    }),
  };
}

function riskPlausibleItems(cart) {
  return (cart?.items || []).filter((item) => item.review_status === "PLAUSIBLE");
}

function riskValueForFactor(factor, value) {
  if (value === "" || value === null || value === undefined || typeof value === "boolean") return "";
  return factor.levels.find((level) => Number(level.value) === Number(value))?.value ?? "";
}

function riskMapsEqual(left, right, factors, trim = false) {
  return factors.every((factor) => {
    const leftValue = String(left?.[factor.code] ?? "");
    const rightValue = String(right?.[factor.code] ?? "");
    return trim ? leftValue.trim() === rightValue.trim() : leftValue === rightValue;
  });
}

function riskSuggestionIsActionable(suggestion) {
  if (!suggestion || typeof suggestion !== "object") return false;
  const status = String(suggestion.information_status || "RECOMMENDED").toUpperCase();
  const qualitative = suggestion.qualitative_value;
  const reason = String(suggestion.reason || "").trim();
  return status === "RECOMMENDED"
    && typeof qualitative === "string"
    && Boolean(qualitative.trim())
    && suggestion.value !== null
    && suggestion.value !== undefined
    && suggestion.value !== ""
    && typeof suggestion.value !== "boolean"
    && Number.isFinite(Number(suggestion.value))
    && Boolean(reason)
    && !isInformationGapDraftText(reason);
}

function riskDraftFor(item, model) {
  if (!model) return null;
  if (state.riskDraftModelId !== model.id) {
    state.riskDrafts = {};
    state.riskDraftModelId = model.id;
  }
  const key = String(item.id);
  const savedValues = Object.fromEntries(model.factors.map((factor) => [factor.code, riskValueForFactor(factor, item.factor_values?.[factor.code])]));
  const savedReasons = Object.fromEntries(model.factors.map((factor) => [factor.code, String(item.factor_reasons?.[factor.code] || "")]));
  let draft = state.riskDrafts[key];
  const baselineChanged = draft && (
    !riskMapsEqual(draft.savedValues, savedValues, model.factors)
    || !riskMapsEqual(draft.savedReasons, savedReasons, model.factors, true)
  );
  if (!draft || draft.modelId !== model.id || (!draft.dirty && baselineChanged)) {
    const hasFinalScore = item.risk_score !== null && item.risk_score !== undefined;
    const initialValues = { ...savedValues };
    const initialReasons = { ...savedReasons };
    const sourceByFactor = {};
    if (hasFinalScore) {
      model.factors.forEach((factor) => {
        const suggestion = riskOriginalSuggestion(item, factor.code);
        if (!suggestion) return;
        const sameValue = suggestion.value !== null && suggestion.value !== undefined
          && Number(savedValues[factor.code]) === Number(suggestion.value);
        sourceByFactor[factor.code] = sameValue ? "LLM" : "MODIFIED";
      });
    } else {
      model.factors.forEach((factor) => {
        const suggestion = riskOriginalSuggestion(item, factor.code);
        if (!suggestion) return;
        const suggestedValue = riskValueForFactor(factor, suggestion.value);
        if (suggestedValue === "") return;
        initialValues[factor.code] = suggestedValue;
        initialReasons[factor.code] = String(suggestion.reason || "");
        sourceByFactor[factor.code] = "LLM";
      });
    }
    draft = {
      itemId: Number(item.id),
      modelId: model.id,
      values: initialValues,
      reasons: initialReasons,
      savedValues,
      savedReasons,
      sourceByFactor,
      missingInformation: visibleLlmMissingInformation(item.llm_risk?.missing_information),
      dirty: false,
    };
    recalculateRiskDraft(draft, model);
    state.riskDrafts[key] = draft;
  }
  return draft;
}

function recalculateRiskDraft(draft, model) {
  draft.dirty = !riskMapsEqual(draft.values, draft.savedValues, model.factors)
    || !riskMapsEqual(draft.reasons, draft.savedReasons, model.factors, true);
  return draft;
}

function riskOriginalSuggestion(item, factorCode) {
  const suggestion = item?.llm_risk?.factors?.[factorCode];
  return riskSuggestionIsActionable(suggestion) ? suggestion : null;
}

function riskSourceAfterManualChange(item, factor, draft) {
  const suggestion = riskOriginalSuggestion(item, factor.code);
  if (!suggestion) return "MODIFIED";
  const sameValue = suggestion.value !== null && suggestion.value !== undefined
    && Number(draft.values[factor.code]) === Number(suggestion.value);
  return sameValue ? "LLM" : "MODIFIED";
}

function updateRiskDraft(item, model, factorCode, patch, source = "MANUAL") {
  const factor = model.factors.find((entry) => String(entry.code) === String(factorCode));
  const draft = riskDraftFor(item, model);
  if (!factor || !draft) return null;
  const previousValue = riskValueForFactor(factor, draft.values[factor.code]);
  if (Object.prototype.hasOwnProperty.call(patch, "value")) draft.values[factor.code] = riskValueForFactor(factor, patch.value);
  if (Object.prototype.hasOwnProperty.call(patch, "reason")) draft.reasons[factor.code] = String(patch.reason || "");
  if (
    source !== "LLM"
    && Object.prototype.hasOwnProperty.call(patch, "value")
    && !Object.prototype.hasOwnProperty.call(patch, "reason")
    && String(previousValue) !== String(draft.values[factor.code])
  ) {
    draft.reasons[factor.code] = "";
  }
  draft.sourceByFactor[factor.code] = source === "LLM" ? "LLM" : riskSourceAfterManualChange(item, factor, draft);
  return recalculateRiskDraft(draft, model);
}

function riskDraftIsDirty(cartId = null) {
  const itemIds = cartId == null
    ? null
    : new Set(riskPlausibleItems(cartById(cartId)).map((item) => String(item.id)));
  return Object.entries(state.riskDrafts || {}).some(([itemId, draft]) => draft?.dirty && (!itemIds || itemIds.has(itemId)));
}

function confirmRiskDraftDiscard() {
  if (!riskDraftIsDirty()) return true;
  if (!window.confirm("아직 저장하지 않은 위험 평가 입력이 있습니다. 변경을 취소하고 이동할까요?")) return false;
  state.riskDrafts = {};
  state.riskDraftModelId = null;
  closeRiskDrawer();
  return true;
}

function riskDraftCompleteness(draft, model) {
  const missingValues = model.factors.filter((factor) => riskValueForFactor(factor, draft?.values?.[factor.code]) === "").map((factor) => factor.code);
  const missingReasons = model.factors.filter((factor) => !String(draft?.reasons?.[factor.code] || "").trim()).map((factor) => factor.code);
  return {
    missingValues,
    missingReasons,
    valuesComplete: missingValues.length === 0,
    complete: missingValues.length === 0,
  };
}

function riskPreviewFor(draft, model) {
  try {
    return RISK_CALCULATION.evaluateModel(model, draft?.values || {});
  } catch (error) {
    return { complete: false, score: null, riskLevel: null, error: error.message };
  }
}

function riskRowStatus(item, model, draft) {
  if (!draft) return { code: "UNASSESSED", label: "미평가" };
  const labels = {
    UNASSESSED: "미평가",
    LLM_COMPLETED: "LLM 평가 완료",
    USER_REVIEWED: "사용자 검토 완료",
    USER_MODIFIED: "사용자 수정됨",
    NEEDS_REVIEW: "검토 필요",
  };
  const stored = String(item.risk_review_status || "");
  const hasIgnoredSuggestion = model.factors.some((factor) => {
    const raw = item?.llm_risk?.factors?.[factor.code];
    return raw && !riskSuggestionIsActionable(raw);
  });
  if (!draft.dirty && hasIgnoredSuggestion && (item.risk_score === null || item.risk_score === undefined)) {
    return { code: "NEEDS_REVIEW", label: "검토 필요" };
  }
  if (!draft.dirty && labels[stored]) return { code: stored, label: labels[stored] };
  const completeness = riskDraftCompleteness(draft, model);
  const unresolvedMissingInformation = textList(draft.missingInformation).length > 0
    && Object.values(draft.sourceByFactor || {}).includes("LLM");
  if (!completeness.complete || unresolvedMissingInformation) return { code: "NEEDS_REVIEW", label: "검토 필요" };
  const sources = Object.values(draft.sourceByFactor || {});
  if (sources.includes("MODIFIED")) {
    const hasLlmOriginal = model.factors.some((factor) => Boolean(riskOriginalSuggestion(item, factor.code)));
    return hasLlmOriginal
      ? { code: "USER_MODIFIED", label: "사용자 수정됨" }
      : { code: "USER_REVIEWED", label: "사용자 검토 완료" };
  }
  if (sources.includes("LLM")) return { code: "LLM_COMPLETED", label: "LLM 평가 완료" };
  if (labels[stored]) return { code: stored, label: labels[stored] };
  return item.risk_score !== null && item.risk_score !== undefined
    ? { code: "USER_REVIEWED", label: "사용자 검토 완료" }
    : { code: "UNASSESSED", label: "미평가" };
}

function riskBatchSuggestionCoverage(items, suggestions) {
  const expectedItems = Array.isArray(items) ? items : [];
  const expectedById = new Map(expectedItems.map((item) => [Number(item.id), item]));
  const receivedCounts = new Map();
  const usableSuggestions = [];
  const unknownItemIds = [];
  let invalidItemCount = 0;
  (Array.isArray(suggestions) ? suggestions : []).forEach((suggestion) => {
    const itemId = Number(suggestion?.item_id);
    if (!suggestion || typeof suggestion !== "object" || !Number.isSafeInteger(itemId)) {
      invalidItemCount += 1;
      return;
    }
    if (!expectedById.has(itemId)) {
      unknownItemIds.push(itemId);
      return;
    }
    const count = (receivedCounts.get(itemId) || 0) + 1;
    receivedCounts.set(itemId, count);
    if (count === 1) usableSuggestions.push(suggestion);
  });
  const missingItems = expectedItems.filter((item) => !receivedCounts.has(Number(item.id)));
  const duplicateItemIds = [...receivedCounts.entries()].filter(([, count]) => count > 1).map(([itemId]) => itemId);
  return {
    expectedCount: expectedItems.length,
    usableSuggestions,
    missingItems,
    duplicateItemIds,
    unknownItemIds,
    invalidItemCount,
    complete: missingItems.length === 0
      && duplicateItemIds.length === 0
      && unknownItemIds.length === 0
      && invalidItemCount === 0
      && usableSuggestions.length === expectedItems.length,
  };
}

function riskBatchRequestFailureMessage(error) {
  const message = compact(error?.message, "LLM 위험 평가 요청에 실패했습니다.");
  if (message.includes("모든 공격 벡터 위험 평가를 반환하지 않았습니다")) {
    return "일부 공격 벡터의 LLM 응답이 누락되어 초안을 적용하지 않았습니다. 현재 입력은 유지됩니다. LLM 초안 받기를 다시 눌러 주세요.";
  }
  if (message.includes("응답도 최대 토큰 한도에서 잘렸습니다")) {
    return `${message} 안내된 공격 벡터는 직접 평가하거나 계산기 요인 설명을 줄인 뒤 다시 시도하세요.`;
  }
  if (message.includes("최대 호출 횟수에 도달했습니다")) {
    return `${message} 현재 평가표의 입력은 그대로 유지됩니다. 항목 또는 요인을 줄인 뒤 다시 시도하세요.`;
  }
  return message;
}

function riskStatusBadgeMarkup(status) {
  return `<span class="risk-row-status status-${status.code.toLowerCase()}">${escapeHtml(status.label)}</span>`;
}

function riskFactorOptions(factor, selected) {
  return `<option value="">선택</option>${factor.levels.map((level) => `<option value="${escapeHtml(level.value)}" ${Number(selected) === Number(level.value) && selected !== "" ? "selected" : ""}>${escapeHtml(level.label)} (${escapeHtml(formatRiskNumber(level.value))})</option>`).join("")}`;
}

function riskFactorInputState(item, factor, draft) {
  const reason = String(draft?.reasons?.[factor.code] || "").trim();
  const source = draft?.sourceByFactor?.[factor.code];
  if (!reason) return { label: "근거 없음 (선택)", className: "optional" };
  if (source === "MODIFIED") return { label: "사용자 수정", className: "modified" };
  if (source === "LLM") return { label: "LLM 근거", className: "llm" };
  if (riskOriginalSuggestion(item, factor.code)) return { label: "근거 있음 (LLM 원본)", className: "ready" };
  return { label: "근거 있음", className: "ready" };
}

function riskScoreCellMarkup(item, model, draft) {
  const preview = riskPreviewFor(draft, model);
  const confirmedStatus = ["USER_REVIEWED", "USER_MODIFIED"].includes(String(item.risk_review_status || ""));
  const hasOldScore = item.risk_score !== null && item.risk_score !== undefined;
  const useSaved = !draft?.dirty && hasOldScore && confirmedStatus;
  const score = useSaved ? item.risk_score : preview.score;
  const level = useSaved ? item.risk_level : preview.riskLevel;
  if (score === null || score === undefined) return `<div class="risk-score-preview pending"><strong>—</strong><span>${preview.error ? "계산식 확인 필요" : "요인 선택 필요"}</span></div>`;
  const label = useSaved ? "확정 점수" : hasOldScore && !confirmedStatus ? "이전 점수, 재검토 필요" : "예상 점수";
  return `<div class="risk-score-preview ${useSaved ? "saved" : hasOldScore && !confirmedStatus ? "stale" : "draft"}"><strong>${escapeHtml(formatRiskNumber(score, Number(model.decimals)))}</strong><span>${label}${level ? ` (${escapeHtml(level)})` : ""}</span></div>`;
}

function riskCartStats(cart, model) {
  const items = riskPlausibleItems(cart);
  if (!model) {
    const saved = items.filter((item) => (
      item.risk_score !== null
      && item.risk_score !== undefined
      && ["USER_REVIEWED", "USER_MODIFIED"].includes(String(item.risk_review_status || ""))
    )).length;
    return { total: items.length, saved, complete: 0, dirty: 0 };
  }
  const saved = items.filter((item) => (
    item.risk_score !== null
    && item.risk_score !== undefined
    && ["USER_REVIEWED", "USER_MODIFIED"].includes(String(item.risk_review_status || ""))
    && !riskDraftFor(item, model)?.dirty
  )).length;
  const complete = items.filter((item) => riskDraftCompleteness(riskDraftFor(item, model), model).complete).length;
  const dirty = items.filter((item) => riskDraftFor(item, model)?.dirty).length;
  return { total: items.length, saved, complete, dirty };
}

function riskFactorCellMarkup(item, factor, draft) {
  return '<td class="risk-factor-cell" data-risk-factor-cell="' + escapeHtml(factor.code) + '">'
    + '<select class="risk-factor-compact-select" data-risk-factor-value data-item-id="' + item.id + '" data-factor-code="' + escapeHtml(factor.code) + '" aria-label="' + escapeHtml(item.attack_vector_name) + ' ' + escapeHtml(factor.name) + '">'
    + riskFactorOptions(factor, draft.values[factor.code]) + '</select></td>';
}

function riskReasonSummaryData(model, draft) {
  const reasons = model.factors.map((factor) => ({
    name: factor.name,
    text: String(draft.reasons[factor.code] || "").replace(/\s+/g, " ").trim(),
  })).filter((entry) => entry.text);
  if (!reasons.length) return { count: 0, summary: "입력된 판단 근거가 없습니다.", remainder: "" };
  const visible = reasons.slice(0, 2).map((entry) => `${entry.name}: ${entry.text}`).join(" / ");
  const summary = visible.length > 130 ? `${visible.slice(0, 127).trim()}…` : visible;
  const hiddenCount = Math.max(0, reasons.length - 2);
  return { count: reasons.length, summary, remainder: hiddenCount ? `외 ${hiddenCount}개` : "" };
}

function riskReasonCellMarkup(item, model, draft, status) {
  const reasonSummary = riskReasonSummaryData(model, draft);
  const reasonCount = reasonSummary.count ? `${reasonSummary.count}개 작성` : "선택 입력 없음";
  return `<td class="risk-reasons-cell"><div class="risk-reason-summary-head"><span data-risk-status-cell>${riskStatusBadgeMarkup(status)}</span><span class="risk-reason-count" data-risk-reason-count>${reasonCount}</span></div><p class="risk-reason-summary" data-risk-reason-summary>${escapeHtml(reasonSummary.summary)}</p><div class="risk-reason-summary-actions"><span data-risk-reason-remainder>${escapeHtml(reasonSummary.remainder)}</span><button type="button" class="btn small" data-open-risk-drawer="${item.id}">근거 보기</button></div></td>`;
}

function riskTableRowMarkup(item, model) {
  const draft = riskDraftFor(item, model);
  const status = riskRowStatus(item, model, draft);
  const description = compact(item.attack_vector_description, "설명 없음");
  const reference = item.reference_url
    ? ' href="' + escapeHtml(item.reference_url) + '" target="_blank" rel="noopener noreferrer"'
    : "";
  return '<tr data-risk-table-row="' + item.id + '" class="risk-table-row status-' + status.code.toLowerCase() + (draft.dirty ? ' is-dirty' : '') + '">'
    + '<td class="risk-sticky-col risk-vector-column"><a class="vector-id"' + reference + '>' + escapeHtml(cartVectorDisplayId(item)) + '</a><strong>' + escapeHtml(item.attack_vector_name) + '</strong><span title="' + escapeHtml(description) + '">' + escapeHtml(description) + '</span></td>'
    + model.factors.map((factor) => riskFactorCellMarkup(item, factor, draft)).join("")
    + '<td class="risk-score-cell" data-risk-score-cell>' + riskScoreCellMarkup(item, model, draft) + '</td>'
    + riskReasonCellMarkup(item, model, draft, status) + '</tr>';
}

function riskBulkTableMarkup(cart, model) {
  const items = riskPlausibleItems(cart);
  if (!items.length) return emptyState("평가할 공격 벡터가 없습니다", "이 쇼핑카트에는 타당함으로 확정된 공격 벡터가 없습니다.");
  const minWidth = 320 + model.factors.length * 170 + 110 + 260;
  const factorHeaders = model.factors.map((factor) => '<th class="risk-factor-header" title="' + escapeHtml(factor.question) + '"><strong>' + escapeHtml(factor.name) + '</strong><span>가중치 ' + escapeHtml(formatRiskNumber(factor.weight)) + '</span></th>').join("");
  return '<div class="risk-table-scroll" id="risk-table-scroll"><table class="data-table risk-bulk-table" style="min-width:' + minWidth + 'px"><thead><tr>'
    + '<th class="risk-sticky-col risk-vector-column">공격 벡터</th>'
    + factorHeaders + '<th class="risk-score-cell">위험 점수</th><th class="risk-reasons-header">판단 근거 <span>(선택)</span></th>'
    + '</tr></thead><tbody>' + items.map((item) => riskTableRowMarkup(item, model)).join("") + '</tbody></table></div>';
}

function riskCartOptionMarkup(cart, model) {
  const stats = riskCartStats(cart, model);
  const dirty = stats.dirty ? ", 변경 " + stats.dirty : "";
  return '<option value="' + cart.id + '"' + (Number(cart.id) === Number(state.activeCartId) ? " selected" : "") + '>'
    + escapeHtml(shoppingCartLabel(cart)) + ' (저장 ' + stats.saved + '/' + stats.total + escapeHtml(dirty) + ')</option>';
}

function riskModelOptionMarkup(model, selectedModel) {
  const basis = riskBasisMeta(model.basis);
  return '<option value="' + escapeHtml(model.id) + '"' + (selectedModel?.id === model.id ? " selected" : "") + (model.active === false ? " disabled" : "") + '>'
    + escapeHtml(model.name) + ' (' + model.factors.length + '개 요인, ' + escapeHtml(basis.label) + (model.active === false ? ", 이전 버전" : "") + ')</option>';
}

function riskToolbarMarkup(cart, model) {
  const items = riskPlausibleItems(cart);
  const stats = riskCartStats(cart, model);
  const llmDisabled = !model || !items.length;
  const hasLlmResult = items.some((item) => item.llm_risk && Object.keys(item.llm_risk?.factors || {}).length);
  const llmLabel = hasLlmResult ? "LLM 평가 다시 실행" : "LLM 평가 초안 생성";
  const llmTitle = !state.llm?.enabled
    ? "API 키를 연결한 뒤 평가 초안을 생성할 수 있습니다."
    : !state.workspace?.assessment?.external_llm_allowed
      ? "Scope Brief에서 외부 LLM 사용을 허용한 뒤 실행할 수 있습니다."
      : "현재 쇼핑카트 전체의 평가 초안을 생성합니다.";
  return '<section class="card risk-workbench-toolbar"><div class="risk-toolbar-selects">'
    + '<label><span>쇼핑카트</span><select id="risk-cart-select">' + state.workspace.carts.map((entry) => riskCartOptionMarkup(entry, model)).join("") + '</select></label>'
    + '<div class="risk-current-model"><span>현재 계산기 <em>평가 공통</em></span><strong>' + escapeHtml(model ? riskModelFriendlyName(model) : "선택되지 않음") + '</strong><small>' + escapeHtml(model ? riskModelOfficialName(model) : "") + '</small></div></div>'
    + '<div class="risk-toolbar-summary"><span id="risk-progress-summary">입력 ' + stats.complete + '/' + stats.total + ', 저장 ' + stats.saved + '/' + stats.total + '</span>'
    + '<div class="risk-llm-progress" id="risk-llm-progress" role="status" aria-live="polite" hidden><i aria-hidden="true"></i><span>초안을 생성하고 있습니다.</span></div></div>'
    + '<div class="risk-toolbar-actions"><button type="button" class="btn" id="risk-change-calculator">계산기 변경</button><button type="button" class="btn" id="risk-open-calculator"' + (model ? "" : " disabled") + '>계산 기준</button>'
    + '<button type="button" class="btn llm-risk-action" id="llm-risk-cart" title="' + escapeHtml(llmTitle) + '"' + (llmDisabled ? " disabled" : "") + '>' + escapeHtml(llmLabel) + '</button></div></section>';
}

function renderRiskStep() {
  const cart = cartById(state.activeCartId) || state.workspace.carts[0];
  if (!cart) return;
  state.activeCartId = cart.id;
  const model = selectedRiskModel();
  if (!model || state.riskModelChoosing) {
    $("#step-content")?.classList.remove("table-workspace");
    state.riskModelChoosing = true;
    renderRiskModelSelection();
    return;
  }
  $("#step-content")?.classList.add("table-workspace");
  riskPlausibleItems(cart).forEach((item) => riskDraftFor(item, model));
  const table = riskBulkTableMarkup(cart, model);
  const stats = riskCartStats(cart, model);
  const inputsComplete = riskInputsComplete(model);
  const headerAction = '<button class="btn primary" id="go-matrix" aria-disabled="' + (inputsComplete ? "false" : "true") + '">' + (riskComplete() ? "민감도 매트릭스 생성" : "저장 후 매트릭스 생성") + '</button>';
  const dirtyText = stats.dirty ? ', 변경 ' + stats.dirty + '개' : "";
  $("#step-content").innerHTML = pageHeader("1.5 공격 벡터 위험 평가", "타당한 공격 벡터의 요인값을 정하고 점수를 저장합니다.", headerAction)
    + '<div class="page-body risk-workbench-page">' + reviewContextMarkup(cart) + riskToolbarMarkup(cart, model)
    + '<section class="card risk-bulk-card"><div class="card-header"><div><h2>' + escapeHtml(shoppingCartLabel(cart)) + '</h2>'
    + '<div class="small-text muted">' + escapeHtml(cartCaseLabel(cart)) + '</div></div><span class="count-pill">' + stats.saved + '/' + stats.total + ' 저장</span></div>'
    + table + '<div class="risk-sticky-actions"><span id="risk-save-summary">' + stats.complete + '/' + stats.total + '개 입력 완료' + dirtyText + '</span>'
    + '<button type="button" class="btn primary" id="save-cart-risks"' + (!model || !stats.total ? " disabled" : "") + '>현재 쇼핑카트 전체 저장</button></div></section></div>';
  bindRiskWorkbench(cart, model);
}

function bindRiskWorkbench(cart, model) {
  $("#risk-cart-select").onchange = (event) => {
    closeRiskDrawer();
    state.activeCartId = Number(event.target.value);
    renderRiskStep();
  };
  $("#risk-change-calculator")?.addEventListener("click", () => {
    if (!confirmRiskDraftDiscard()) return;
    state.riskModelChoosing = true;
    state.riskModelSelectionId = model?.id || null;
    renderRiskModelSelection();
  });
  $("#risk-open-calculator")?.addEventListener("click", () => showRiskCalculatorInfo(model));
  $("#llm-risk-cart")?.addEventListener("click", () => {
    if (!state.llm?.enabled) {
      showLlmConfigModal();
      return;
    }
    if (!state.workspace?.assessment?.external_llm_allowed) {
      showScopeBriefModal();
      toast("Scope Brief에서 ‘외부 LLM 추천 허용’을 선택해 주세요.", true);
      return;
    }
    requestCartRiskSuggestions(cart, model);
  });
  $("#save-cart-risks")?.addEventListener("click", () => saveCartRisks(cart, model));
  $$("[data-risk-factor-value]").forEach((select) => select.onchange = () => {
    const item = riskPlausibleItems(cart).find((entry) => Number(entry.id) === Number(select.dataset.itemId));
    if (!item || !model) return;
    updateRiskDraft(item, model, select.dataset.factorCode, { value: select.value });
    refreshRiskTableRow(item, model);
  });
  $$("[data-open-risk-drawer]").forEach((button) => button.onclick = () => openRiskDrawer(Number(button.dataset.openRiskDrawer), button.dataset.focusFactor || ""));
  $("#go-matrix").onclick = async () => {
    if (!riskInputsComplete(model)) { explainCtsaBlock(6); return; }
    const button = $("#go-matrix");
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    button.textContent = "저장 및 생성 중…";
    try {
      for (const pendingCart of state.workspace.carts) {
        if (riskCartNeedsSave(pendingCart, model)) {
          await api("/api/carts/" + pendingCart.id + "/risks", { method: "PUT", body: riskCartSavePayload(pendingCart, model) });
        }
      }
      state.riskDrafts = {};
      state.riskDraftModelId = null;
      await reloadWorkspace();
      if (!riskComplete()) {
        renderRiskStep();
        explainCtsaBlock(6);
        return;
      }
      await api("/api/assessments/" + state.assessmentId + "/matrix", { method: "POST", body: {} });
      await reloadWorkspace();
      state.step = 6;
      renderWorkspace();
      toast("위협 민감도 매트릭스를 생성했습니다.");
    } catch (error) {
      button.disabled = false;
      button.removeAttribute("aria-busy");
      button.textContent = "저장 후 매트릭스 생성";
      toast(error.message, true);
    }
  };
}

function refreshRiskProgress(cart, model) {
  if (!cart || !model) return;
  const stats = riskCartStats(cart, model);
  const progress = $("#risk-progress-summary");
  if (progress) progress.textContent = "입력 " + stats.complete + "/" + stats.total + ", 저장 " + stats.saved + "/" + stats.total;
  const saveSummary = $("#risk-save-summary");
  if (saveSummary) saveSummary.textContent = stats.complete + "/" + stats.total + "개 입력" + (stats.dirty ? ", 변경 " + stats.dirty + "개" : "");
  const count = $(".risk-bulk-card .card-header .count-pill");
  if (count) count.textContent = stats.saved + "/" + stats.total + " 저장";
  const option = $("#risk-cart-select option:checked");
  if (option) option.textContent = shoppingCartLabel(cart) + " (저장 " + stats.saved + "/" + stats.total + (stats.dirty ? ", 변경 " + stats.dirty : "") + ")";
  const matrixButton = $("#go-matrix");
  if (matrixButton) {
    const ready = riskInputsComplete(model);
    matrixButton.setAttribute("aria-disabled", ready ? "false" : "true");
    matrixButton.textContent = riskComplete() ? "민감도 매트릭스 생성" : "저장 후 매트릭스 생성";
  }
}

function refreshRiskTableRow(item, model) {
  const row = document.querySelector('[data-risk-table-row="' + item.id + '"]');
  if (!row) return;
  const draft = riskDraftFor(item, model);
  const status = riskRowStatus(item, model, draft);
  row.className = "risk-table-row status-" + status.code.toLowerCase() + (draft.dirty ? " is-dirty" : "");
  $$("[data-risk-factor-value]", row).forEach((select) => {
    const factor = model.factors.find((entry) => String(entry.code) === String(select.dataset.factorCode));
    if (!factor) return;
    select.value = String(draft.values[factor.code] ?? "");
    const cell = select.closest("[data-risk-factor-cell]");
    cell?.classList.remove("has-error");
    select.classList.remove("validation-target");
    select.removeAttribute("aria-invalid");
  });
  const scoreCell = $("[data-risk-score-cell]", row);
  if (scoreCell) scoreCell.innerHTML = riskScoreCellMarkup(item, model, draft);
  const statusCell = $("[data-risk-status-cell]", row);
  if (statusCell) statusCell.innerHTML = riskStatusBadgeMarkup(status);
  const summaryData = riskReasonSummaryData(model, draft);
  const reasonSummary = $("[data-risk-reason-summary]", row);
  if (reasonSummary) reasonSummary.textContent = summaryData.summary;
  const reasonCount = $("[data-risk-reason-count]", row);
  if (reasonCount) reasonCount.textContent = summaryData.count ? `${summaryData.count}개 작성` : "선택 입력 없음";
  const reasonRemainder = $("[data-risk-reason-remainder]", row);
  if (reasonRemainder) reasonRemainder.textContent = summaryData.remainder;
  refreshRiskProgress(cartById(state.activeCartId), model);
  refreshOpenRiskDrawerSummary(item, model);
}

function riskFactorDraftStateMarkup(item, factor, draft) {
  const inputState = riskFactorInputState(item, factor, draft);
  return '<span class="risk-drawer-factor-state ' + inputState.className + '">' + escapeHtml(inputState.label) + '</span>';
}

function riskOriginalRecommendationMarkup(item, factor) {
  const suggestion = riskOriginalSuggestion(item, factor.code);
  if (!suggestion) return '<div class="risk-llm-original empty"><strong>적용 가능한 LLM 원본 추천 없음</strong><span>사용자가 평가값과 판단 근거를 직접 입력해 주세요.</span></div>';
  const level = factor.levels.find((entry) => suggestion.value !== null && suggestion.value !== undefined && Number(entry.value) === Number(suggestion.value));
  const qualitative = compact(suggestion.qualitative_value, level?.label || "추천값");
  const numeric = " (" + formatRiskNumber(suggestion.value) + ")";
  return '<div class="risk-llm-original">'
    + llmSuggestionSource(item.llm_risk)
    + '<div><span class="badge purple">LLM 원본 추천</span><strong>' + escapeHtml(qualitative + numeric) + '</strong></div>'
    + '<p>' + escapeHtml(suggestion.reason) + '</p>'
    + '<small>사용자 수정 후에도 이 원본 추천은 그대로 보존됩니다.</small>'
    + '</div>';
}

function riskDrawerFactorMarkup(item, factor, draft, index) {
  const levels = factor.levels.map((level) => '<li><strong>' + escapeHtml(level.label) + ' (' + escapeHtml(formatRiskNumber(level.value)) + ')</strong><span>' + escapeHtml(compact(level.description, "설명 없음")) + '</span></li>').join("");
  return '<section class="risk-drawer-factor" data-risk-drawer-factor="' + escapeHtml(factor.code) + '">'
    + '<div class="risk-drawer-factor-head"><span class="risk-factor-number">' + (index + 1) + '</span><div><div><h3>' + escapeHtml(factor.name) + '</h3><span>가중치 ' + escapeHtml(formatRiskNumber(factor.weight)) + (factor.factor_group ? ", " + escapeHtml(factor.factor_group) : "") + '</span></div><p>' + escapeHtml(factor.question) + '</p></div>'
    + riskFactorDraftStateMarkup(item, factor, draft) + '</div>'
    + '<div class="risk-drawer-fields"><label><span>평가값</span><select data-risk-drawer-value data-factor-code="' + escapeHtml(factor.code) + '">' + riskFactorOptions(factor, draft.values[factor.code]) + '</select></label>'
    + '<label><span>판단 근거 <em>선택</em></span><textarea rows="4" maxlength="10000" data-risk-drawer-reason data-factor-code="' + escapeHtml(factor.code) + '" placeholder="이 평가값을 선택한 이유를 입력하세요. (선택)">' + escapeHtml(draft.reasons[factor.code] || "") + '</textarea></label></div>'
    + '<details class="risk-level-guide"><summary>평가 척도</summary><ul>' + levels + '</ul></details></section>';
}

function riskDrawerMarkup(item, model) {
  const draft = riskDraftFor(item, model);
  const status = riskRowStatus(item, model, draft);
  const missing = visibleLlmMissingInformation(item.llm_risk?.missing_information);
  return '<div class="modal-backdrop risk-drawer-backdrop" id="risk-drawer-backdrop"><aside class="risk-detail-drawer" role="dialog" aria-modal="true" aria-labelledby="risk-drawer-title">'
    + '<header class="risk-drawer-header"><div><span class="vector-id">' + escapeHtml(cartVectorDisplayId(item)) + '</span><h2 id="risk-drawer-title">요인별 판단 근거</h2><p>' + escapeHtml(item.attack_vector_name) + '</p></div><button type="button" class="btn small" data-close-risk-drawer>닫기</button></header>'
    + '<div class="risk-drawer-summary"><p>' + escapeHtml(compact(item.attack_vector_description, "설명 없음")) + '</p><div data-risk-drawer-score>' + riskScoreCellMarkup(item, model, draft) + '</div><div data-risk-drawer-status>' + riskStatusBadgeMarkup(status) + '</div></div>'
    + (missing.length ? '<div class="notice warning risk-drawer-missing"><div>!</div><div><strong>추가 확인이 필요한 정보</strong>' + escapeHtml(missing.join(", ")) + '</div></div>' : "")
    + '<div class="risk-drawer-body">' + model.factors.map((factor, index) => riskDrawerFactorMarkup(item, factor, draft, index)).join("") + '</div>'
    + '<footer class="risk-drawer-footer"><span>변경 내용은 전체 저장 전까지 확정되지 않습니다.</span><button type="button" class="btn primary" data-close-risk-drawer>닫기</button></footer>'
    + '</aside></div>';
}

function closeRiskDrawer() {
  $("#risk-drawer-backdrop")?.remove();
  state.activeRiskDrawerItemId = null;
  document.removeEventListener("keydown", handleRiskDrawerKeydown);
}

function handleRiskDrawerKeydown(event) {
  if (event.key === "Escape") closeRiskDrawer();
}

function openRiskDrawer(itemId, focusFactorCode = "") {
  closeRiskDrawer();
  const model = selectedRiskModel();
  const cart = cartById(state.activeCartId);
  const item = riskPlausibleItems(cart).find((entry) => Number(entry.id) === Number(itemId));
  if (!item || !model) return;
  state.activeRiskDrawerItemId = item.id;
  document.body.insertAdjacentHTML("beforeend", riskDrawerMarkup(item, model));
  $$("[data-close-risk-drawer]").forEach((button) => button.onclick = closeRiskDrawer);
  $$("[data-risk-drawer-value]").forEach((select) => select.onchange = () => {
    updateRiskDraft(item, model, select.dataset.factorCode, { value: select.value });
    refreshRiskTableRow(item, model);
    refreshOpenRiskDrawerFactor(item, model, select.dataset.factorCode);
  });
  $$("[data-risk-drawer-reason]").forEach((textarea) => textarea.oninput = () => {
    updateRiskDraft(item, model, textarea.dataset.factorCode, { reason: textarea.value });
    refreshRiskTableRow(item, model);
    refreshOpenRiskDrawerFactor(item, model, textarea.dataset.factorCode);
  });
  document.addEventListener("keydown", handleRiskDrawerKeydown);
  const focusBlock = focusFactorCode
    ? $$("[data-risk-drawer-factor]").find((block) => block.dataset.riskDrawerFactor === focusFactorCode)
    : null;
  if (focusBlock) {
    focusBlock.scrollIntoView({ block: "start" });
    $("[data-risk-drawer-reason]", focusBlock)?.focus();
  } else {
    $("[data-close-risk-drawer]")?.focus();
  }
}

function refreshOpenRiskDrawerSummary(item, model) {
  if (Number(state.activeRiskDrawerItemId) !== Number(item.id)) return;
  const drawer = $("#risk-drawer-backdrop");
  if (!drawer) return;
  const draft = riskDraftFor(item, model);
  const score = $("[data-risk-drawer-score]", drawer);
  if (score) score.innerHTML = riskScoreCellMarkup(item, model, draft);
  const status = $("[data-risk-drawer-status]", drawer);
  if (status) status.innerHTML = riskStatusBadgeMarkup(riskRowStatus(item, model, draft));
}

function refreshOpenRiskDrawerFactor(item, model, factorCode) {
  const block = $$("[data-risk-drawer-factor]", $("#risk-drawer-backdrop") || document).find((entry) => entry.dataset.riskDrawerFactor === String(factorCode));
  const factor = model.factors.find((entry) => String(entry.code) === String(factorCode));
  if (!block || !factor) return;
  const draft = riskDraftFor(item, model);
  const stateEl = $(".risk-drawer-factor-state", block);
  if (stateEl) stateEl.outerHTML = riskFactorDraftStateMarkup(item, factor, draft);
}

function showRiskCalculatorInfo(model) {
  if (!model) return;
  $("#risk-calculator-info-modal")?.remove();
  document.body.insertAdjacentHTML("beforeend", '<div class="modal-backdrop" id="risk-calculator-info-modal"><div class="modal risk-calculator-info-modal" role="dialog" aria-modal="true"><div class="modal-header"><div><h2>' + escapeHtml(riskModelFriendlyName(model)) + '</h2><p>' + escapeHtml(riskModelOfficialName(model)) + '</p></div><button type="button" class="btn small" data-close-risk-calculator>닫기</button></div><div class="modal-body">' + riskCalculatorInfoMarkup(model) + '</div></div></div>');
  $$("[data-close-risk-calculator]").forEach((button) => button.onclick = () => $("#risk-calculator-info-modal")?.remove());
}

function riskModelChangeWarning() {
  const warnings = [];
  if (riskDraftIsDirty()) warnings.push("저장하지 않은 위험 평가 입력");
  if (state.workspace.carts.some((cart) => cart.items.some((item) => item.risk_score !== null && item.risk_score !== undefined))) warnings.push("저장된 위험 점수");
  if (state.workspace.matrix || state.workspace.assessment.matrix_confirmed) warnings.push("민감도 매트릭스");
  if (state.workspace.assessment.crra_current_step || state.workspace.assessment.crra_confirmed) warnings.push("대응책 분석 결과");
  return warnings;
}

function confirmRiskModelChange() {
  const warnings = riskModelChangeWarning();
  return !warnings.length || window.confirm("위험 계산기를 바꾸면 다음 내용이 초기화됩니다.\n\n• " + warnings.join("\n• ") + "\n\n계속할까요?");
}

async function handleRiskModelSelection(event) {
  const nextModelId = event.target.value;
  const currentModelId = state.workspace.assessment.risk_model_id || "";
  if (!nextModelId) return;
  if (nextModelId === "__CUSTOM__") {
    event.target.value = currentModelId;
    showCustomRiskModelModal();
    return;
  }
  if (nextModelId === currentModelId) return;
  if (!confirmRiskModelChange()) {
    event.target.value = currentModelId;
    return;
  }
  event.target.disabled = true;
  try {
    closeRiskDrawer();
    await api("/api/assessments/" + state.assessmentId + "/risk-model", { method: "POST", body: { model_id: nextModelId } });
    state.riskDrafts = {};
    state.riskDraftModelId = null;
    await reloadWorkspace();
    state.riskModelChoosing = false;
    state.riskModelSelectionId = null;
    state.riskModelWeightDrafts = {};
    renderRiskStep();
    toast("위험 계산기를 변경했습니다.");
  } catch (error) {
    event.target.disabled = false;
    event.target.value = currentModelId;
    toast(error.message, true);
  }
}

async function handleTailoredRiskModelSelection(model, percentageWeights) {
  if (!model || !riskAdjustableFactorCodes(model).length) return;
  const total = Object.values(percentageWeights || {}).reduce((sum, value) => sum + Number(value || 0), 0);
  if (Math.abs(total - 100) >= 1e-7) {
    toast("평가 항목 중요도의 합계가 100%가 되어야 합니다.", true);
    return;
  }
  if (!confirmRiskModelChange()) return;
  const button = $("[data-risk-model-confirm]");
  if (button) {
    button.disabled = true;
    button.textContent = "설정 저장 중…";
  }
  try {
    await api("/api/assessments/" + state.assessmentId + "/tailored-risk-model", {
      method: "PUT",
      body: {
        model_id: model.id,
        weights: Object.fromEntries(riskAdjustableFactorCodes(model).map((code) => [code, Number(percentageWeights[code]) / 100])),
      },
    });
    closeRiskDrawer();
    state.riskDrafts = {};
    state.riskDraftModelId = null;
    await reloadWorkspace();
    state.riskModelChoosing = false;
    state.riskModelSelectionId = null;
    state.riskModelWeightDrafts = {};
    renderRiskStep();
    toast("조정한 계산 기준을 평가 전체에 적용했습니다.");
  } catch (error) {
    if (button) {
      button.disabled = false;
      button.textContent = "이 방식으로 평가 시작";
    }
    toast(error.message, true);
  }
}

function riskValidationIssues(cart, model) {
  const issues = [];
  riskPlausibleItems(cart).forEach((item) => {
    const draft = riskDraftFor(item, model);
    const completeness = riskDraftCompleteness(draft, model);
    model.factors.forEach((factor) => {
      if (completeness.missingValues.includes(factor.code)) issues.push({ item, factor, type: "value" });
    });
  });
  return issues;
}

function showRiskValidationIssues(issues) {
  $$(".risk-factor-cell").forEach((element) => element.classList.remove("has-error"));
  $$('[data-risk-factor-value]').forEach((field) => {
    field.classList.remove("validation-target");
    field.removeAttribute("aria-invalid");
  });
  issues.forEach((issue) => {
    const row = document.querySelector('[data-risk-table-row="' + issue.item.id + '"]');
    const cell = $$("[data-risk-factor-cell]", row || document).find((entry) => entry.dataset.riskFactorCell === String(issue.factor.code));
    cell?.classList.add("has-error");
    const field = $("[data-risk-factor-value]", cell || document);
    field?.classList.add("validation-target");
    field?.setAttribute("aria-invalid", "true");
  });
}

async function saveCartRisks(cart, model) {
  if (!cart || !model) return;
  const items = riskPlausibleItems(cart);
  const issues = riskValidationIssues(cart, model);
  showRiskValidationIssues(issues);
  if (issues.length) {
    const first = issues[0];
    toast("평가값이 선택되지 않은 요인이 " + issues.length + "개 있습니다.", true);
    const row = document.querySelector('[data-risk-table-row="' + first.item.id + '"]');
    const select = $$("[data-risk-factor-value]", row || document).find((entry) => entry.dataset.factorCode === String(first.factor.code));
    select?.focus();
    return;
  }
  const hasDownstream = Boolean(state.workspace.matrix || state.workspace.assessment.matrix_confirmed || state.workspace.assessment.crra_current_step || state.workspace.assessment.crra_confirmed);
  if (hasDownstream && items.some((item) => riskDraftFor(item, model).dirty) && !window.confirm("위험 평가를 변경하면 기존 민감도 매트릭스와 대응책 분석 결과가 초기화됩니다. 계속할까요?")) return;
  const payload = riskCartSavePayload(cart, model);
  const button = $("#save-cart-risks");
  button.disabled = true;
  button.textContent = "전체 저장 중…";
  try {
    await api("/api/carts/" + cart.id + "/risks", { method: "PUT", body: payload });
    items.forEach((item) => delete state.riskDrafts[String(item.id)]);
    closeRiskDrawer();
    await reloadWorkspace();
    renderRiskStep();
    toast("현재 쇼핑카트의 위험 평가를 한 번에 저장했습니다.");
  } catch (error) {
    button.disabled = false;
    button.textContent = "현재 쇼핑카트 전체 저장";
    toast(error.message, true);
  }
}

async function requestCartRiskSuggestions(cart, model) {
  if (!cart || !model) return;
  if (riskDraftIsDirty(cart.id) && !window.confirm("현재 쇼핑카트에 저장하지 않은 입력이 있습니다. 새 LLM 추천으로 덮어쓸까요?")) return;
  if (!window.confirm(`현재 쇼핑카트의 평가 데이터가 ${llmProviderLabel()}로 전송됩니다. LLM 평가 초안을 생성할까요?`)) return;
  const button = $("#llm-risk-cart");
  const cartSelect = $("#risk-cart-select");
  const progress = $("#risk-llm-progress");
  const requestedModelId = model.id;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  button.textContent = "LLM 일괄 평가 중…";
  if (progress) progress.hidden = false;
  if (cartSelect) cartSelect.disabled = true;
  try {
    const result = await api("/api/carts/" + cart.id + "/llm/risk", { method: "POST", body: {} });
    await reloadWorkspace();
    const refreshedCart = cartById(cart.id);
    const refreshedModel = selectedRiskModel();
    if (!refreshedCart || !refreshedModel || refreshedModel.id !== requestedModelId) {
      state.riskDrafts = {};
      state.riskDraftModelId = null;
      renderRiskStep();
      toast("계산기가 변경되어 이전 계산기용 LLM 응답은 적용하지 않았습니다.", true);
      return;
    }
    const plausibleItems = riskPlausibleItems(refreshedCart);
    const coverage = riskBatchSuggestionCoverage(plausibleItems, result?.suggestions);
    if (!coverage.complete) {
      const missing = coverage.missingItems.slice(0, 4).map((item) => compact(item.attack_vector_id, item.id));
      const remainder = coverage.missingItems.length - missing.length;
      const missingText = missing.length ? ` 누락: ${missing.join(", ")}${remainder > 0 ? ` 외 ${remainder}개` : ""}.` : "";
      throw new Error(`LLM 응답의 공격 벡터 구성이 현재 평가표와 일치하지 않아 초안을 적용하지 않았습니다.${missingText} LLM 초안 받기를 다시 눌러 주세요.`);
    }
    let ignoredCount = 0;
    coverage.usableSuggestions.forEach((suggestion) => {
      const item = plausibleItems.find((entry) => Number(entry.id) === Number(suggestion.item_id));
      if (!item) return;
      const draft = riskDraftFor(item, refreshedModel);
      refreshedModel.factors.forEach((factor) => {
        const recommended = suggestion.factors?.[factor.code];
        const suggestedValue = riskSuggestionIsActionable(recommended)
          ? riskValueForFactor(factor, recommended.value)
          : "";
        if (!recommended || suggestedValue === "") {
          if (recommended) ignoredCount += 1;
          draft.values[factor.code] = draft.savedValues[factor.code] ?? "";
          draft.reasons[factor.code] = draft.savedReasons[factor.code] ?? "";
          delete draft.sourceByFactor[factor.code];
          return;
        }
        draft.values[factor.code] = suggestedValue;
        draft.reasons[factor.code] = String(recommended.reason || "");
        draft.sourceByFactor[factor.code] = "LLM";
      });
      draft.missingInformation = visibleLlmMissingInformation(suggestion.missing_information);
      recalculateRiskDraft(draft, refreshedModel);
    });
    state.activeCartId = refreshedCart.id;
    renderRiskStep();
    if (ignoredCount) {
      toast("적용 가능한 LLM 추천만 평가표에 채웠습니다. 빈 요인은 사용자가 직접 선택해 주세요.", true);
    } else {
      toast("LLM 원본 추천을 보존하고 모든 행에 초안을 채웠습니다. 검토 후 전체 저장하세요.");
    }
  } catch (error) {
    button.disabled = false;
    button.removeAttribute("aria-busy");
    button.textContent = riskPlausibleItems(cart).some((item) => item.llm_risk && Object.keys(item.llm_risk?.factors || {}).length) ? "LLM 평가 다시 실행" : "LLM 평가 초안 생성";
    if (progress) progress.hidden = true;
    if (cartSelect) cartSelect.disabled = false;
    const message = riskBatchRequestFailureMessage(error);
    toast(message, true);
  }
}

function inferRiskFactorGroup(factor) {
  if (factor?.factor_group) return String(factor.factor_group);
  const code = String(factor?.code || "").toLowerCase();
  return ["confidentiality", "integrity", "availability", "impact", "mission_impact"].includes(code) ? "IMPACT" : "LIKELIHOOD";
}

function customRiskLevelLines(levels) {
  return (Array.isArray(levels) ? levels : []).map((level) => [
    String(level.label || "").replaceAll("|", "/"),
    String(level.value ?? ""),
    String(level.description || "").replaceAll("|", "/"),
  ].join(" | ")).join("\n");
}

function customRiskFactorEditorMarkup(factor, index) {
  return '<article class="custom-risk-factor" data-custom-risk-factor><div class="custom-risk-factor-head"><strong>요인 <span data-custom-factor-order>' + (index + 1) + '</span></strong><div>'
    + '<button type="button" class="btn small" data-custom-factor-up title="위로 이동">↑</button><button type="button" class="btn small" data-custom-factor-down title="아래로 이동">↓</button><button type="button" class="btn small danger" data-custom-factor-remove>삭제</button></div></div>'
    + '<div class="custom-risk-factor-grid"><label><span>코드</span><input data-custom-factor-code value="' + escapeHtml(factor.code || "") + '" maxlength="64" pattern="[a-z][a-z0-9_]*" title="영문 소문자로 시작하고 영문, 숫자와 밑줄만 사용할 수 있습니다." required></label>'
    + '<label><span>이름</span><input data-custom-factor-name value="' + escapeHtml(factor.name || "") + '" maxlength="160" required></label>'
    + '<label><span>요인 그룹</span><input data-custom-factor-group value="' + escapeHtml(inferRiskFactorGroup(factor)) + '" maxlength="100" placeholder="LIKELIHOOD 또는 IMPACT" required></label>'
    + '<label><span>중요도 (%)</span><input data-custom-factor-weight type="number" min="0" max="100" step="1" value="' + escapeHtml(Number((Number(factor.weight ?? 0) * 100).toFixed(6))) + '" required></label>'
    + '<label class="wide"><span>평가 질문</span><textarea data-custom-factor-question rows="2" maxlength="1000" required>' + escapeHtml(factor.question || "") + '</textarea></label>'
    + '<label class="wide"><span>척도: 한 줄에 <code>라벨 | 숫자 | 설명</code> (2~20개)</span><textarea data-custom-factor-levels rows="5" required>' + escapeHtml(customRiskLevelLines(factor.levels)) + '</textarea></label></div></article>';
}

function refreshCustomRiskFactorOrder() {
  $$("[data-custom-risk-factor]", $("#custom-risk-model-modal") || document).forEach((factor, index) => {
    const order = $("[data-custom-factor-order]", factor);
    if (order) order.textContent = String(index + 1);
    $("[data-custom-factor-up]", factor).disabled = index === 0;
    $("[data-custom-factor-down]", factor).disabled = index === $$("[data-custom-risk-factor]", $("#custom-risk-model-modal") || document).length - 1;
  });
}

function customRiskTemplateModel() {
  const models = state.workspace.risk_models.filter((model) => model.active !== false);
  const selected = selectedRiskModel();
  return (selected?.basis === "ASSESSMENT_CUSTOM" && !selected?.formula?.base_model_id ? selected : null)
    || models.find((model) => String(model.id).includes("P66"))
    || models[0]
    || { name: "사용자 정의 위험 계산기", factors: [] };
}

function showCustomRiskModelModal() {
  $("#custom-risk-model-modal")?.remove();
  const template = customRiskTemplateModel();
  const editingCustom = template?.basis === "ASSESSMENT_CUSTOM" || template?.model_kind === "CUSTOM";
  const factors = (template.factors || []).map((factor) => ({
    code: factor.code,
    name: factor.name,
    factor_group: inferRiskFactorGroup(factor),
    question: factor.question,
    weight: factor.weight,
    levels: factor.levels,
  }));
  const modalDescription = editingCustom
    ? "현재 평가의 사용자 정의 계산기를 편집합니다. 요인을 추가, 삭제 또는 정렬하고 각 척도를 바꿀 수 있습니다."
    : "현재 계산기의 요인, 가중치와 척도를 시작점으로 복제합니다.";
  document.body.insertAdjacentHTML("beforeend", '<div class="modal-backdrop" id="custom-risk-model-modal"><div class="modal custom-risk-model-modal" role="dialog" aria-modal="true" aria-labelledby="custom-risk-model-title"><div class="modal-header"><div><h2 id="custom-risk-model-title">사용자 정의 계산기 설정</h2><p>' + escapeHtml(modalDescription) + '</p></div><button type="button" class="btn small" data-close-custom-risk>닫기</button></div>'
    + '<form id="custom-risk-model-form"><div class="modal-body"><div class="form-field"><label class="required" for="custom-risk-name">계산기 이름</label><input id="custom-risk-name" value="' + escapeHtml(editingCustom ? template.name : template.name + " 사용자 정의") + '" maxlength="120" required></div>'
    + '<div class="custom-risk-help"><strong>평가 항목 중요도</strong><span>각 항목의 중요도 합계가 100%가 되도록 설정해 주세요. 항목 이름, 질문과 척도도 이 화면에서 바꿀 수 있습니다.</span></div>'
    + '<div id="custom-risk-factor-list">' + factors.map((factor, index) => customRiskFactorEditorMarkup(factor, index)).join("") + '</div>'
    + '<div class="custom-risk-summary"><button type="button" class="btn" id="custom-risk-add-factor">평가 항목 추가</button><strong>중요도 합계 <span id="custom-risk-weight-total">100%</span></strong></div><div class="form-error hidden" id="custom-risk-error"></div></div>'
    + '<div class="modal-footer"><button type="button" class="btn" data-close-custom-risk>취소</button><button type="submit" class="btn primary">저장하고 적용</button></div></form></div></div>');
  const close = () => $("#custom-risk-model-modal")?.remove();
  $$("[data-close-custom-risk]").forEach((button) => button.onclick = close);
  $("#custom-risk-add-factor").onclick = () => {
    const list = $("#custom-risk-factor-list");
    const index = $$("[data-custom-risk-factor]", list).length;
    const baseLevels = factors[0]?.levels || [
      { label: "낮음", value: 1, description: "낮은 수준" },
      { label: "중간", value: 2, description: "중간 수준" },
      { label: "높음", value: 3, description: "높은 수준" },
    ];
    list.insertAdjacentHTML("beforeend", customRiskFactorEditorMarkup({ code: "factor_" + (index + 1), name: "새 위험 요인", factor_group: "LIKELIHOOD", question: "이 요인을 어떻게 평가할까요?", weight: 0, levels: baseLevels }, index));
    refreshCustomRiskFactorOrder();
    refreshCustomRiskWeightTotal();
  };
  $("#custom-risk-factor-list").onclick = (event) => {
    const factor = event.target.closest("[data-custom-risk-factor]");
    if (!factor) return;
    if (event.target.closest("[data-custom-factor-remove]")) factor.remove();
    else if (event.target.closest("[data-custom-factor-up]") && factor.previousElementSibling) factor.parentElement.insertBefore(factor, factor.previousElementSibling);
    else if (event.target.closest("[data-custom-factor-down]") && factor.nextElementSibling) factor.parentElement.insertBefore(factor.nextElementSibling, factor);
    else return;
    refreshCustomRiskFactorOrder();
    refreshCustomRiskWeightTotal();
  };
  $("#custom-risk-factor-list").addEventListener("input", (event) => {
    if (event.target.matches("[data-custom-factor-weight]")) refreshCustomRiskWeightTotal();
  });
  $("#custom-risk-model-form").onsubmit = submitCustomRiskModel;
  refreshCustomRiskFactorOrder();
  refreshCustomRiskWeightTotal();
}

function refreshCustomRiskWeightTotal() {
  const total = $$('[data-custom-factor-weight]', $("#custom-risk-model-modal") || document)
    .reduce((sum, input) => sum + Number(input.value || 0), 0);
  const output = $("#custom-risk-weight-total");
  if (!output) return;
  output.textContent = formatRiskNumber(total, Number.isInteger(total) ? 0 : 1) + "%";
  output.classList.toggle("invalid", Math.abs(total - 100) >= 1e-7);
}

function parseCustomRiskLevels(text, factorName) {
  const rows = String(text || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (rows.length < 2) throw new Error("'" + factorName + "' 척도를 두 개 이상 입력해 주세요.");
  if (rows.length > 20) throw new Error("'" + factorName + "' 척도는 20개 이하로 입력해 주세요.");
  const seenValues = new Set();
  const seenLabels = new Set();
  return rows.map((row) => {
    const parts = row.split("|").map((part) => part.trim());
    const label = parts[0] || "";
    const description = parts.slice(2).join(" | ").trim();
    if (parts.length < 3 || !label || !description) throw new Error("'" + factorName + "' 척도는 설명을 포함한 '라벨 | 숫자 | 설명' 형식이어야 합니다.");
    if (label.length > 160 || description.length > 1000) throw new Error("'" + factorName + "' 척도 라벨은 160자, 설명은 1,000자 이하여야 합니다.");
    const value = Number(parts[1]);
    if (!Number.isFinite(value)) throw new Error("'" + factorName + "' 척도 숫자를 확인해 주세요.");
    if (seenValues.has(String(value))) throw new Error("'" + factorName + "'에 중복된 척도 숫자가 있습니다.");
    if (seenLabels.has(label.toLocaleLowerCase())) throw new Error("'" + factorName + "'에 중복된 척도 라벨이 있습니다.");
    seenValues.add(String(value));
    seenLabels.add(label.toLocaleLowerCase());
    return { label, value, description };
  });
}

function collectCustomRiskModel() {
  const factors = $$("[data-custom-risk-factor]", $("#custom-risk-model-modal")).map((row) => {
    const name = $("[data-custom-factor-name]", row).value.trim();
    const code = $("[data-custom-factor-code]", row).value.trim().toLowerCase();
    const factorGroup = $("[data-custom-factor-group]", row).value.trim();
    const question = $("[data-custom-factor-question]", row).value.trim();
    const weightPercent = Number($("[data-custom-factor-weight]", row).value);
    if (!code || !name || !factorGroup || !question) throw new Error("모든 요인의 코드, 이름, 그룹과 질문을 입력해 주세요.");
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(code)) throw new Error("'" + name + "' 코드는 영문 소문자로 시작하고 영문, 숫자와 밑줄만 사용할 수 있습니다.");
    if (name.length > 160 || factorGroup.length > 100 || question.length > 1000) throw new Error("'" + name + "'의 이름, 그룹과 질문 길이를 확인해 주세요.");
    if (!Number.isFinite(weightPercent) || weightPercent < 0 || weightPercent > 100) throw new Error("'" + name + "' 중요도는 0% 이상 100% 이하의 숫자여야 합니다.");
    const weight = weightPercent / 100;
    return { code, name, factor_group: factorGroup, question, weight, levels: parseCustomRiskLevels($("[data-custom-factor-levels]", row).value, name) };
  });
  if (!factors.length) throw new Error("위험 요인을 한 개 이상 추가해 주세요.");
  if (factors.length > 50) throw new Error("위험 요인은 50개 이하로 구성해 주세요.");
  const codes = factors.map((factor) => factor.code);
  if (new Set(codes).size !== codes.length) throw new Error("위험 요인 코드는 서로 달라야 합니다.");
  if (!factors.some((factor) => factor.weight > 0)) throw new Error("0보다 큰 가중치가 하나 이상 필요합니다.");
  if (Math.abs(factors.reduce((sum, factor) => sum + factor.weight, 0) - 1) >= 1e-9) throw new Error("평가 항목 중요도의 합계가 100%가 되어야 합니다.");
  return { name: $("#custom-risk-name").value.trim(), factors, normalized_weights: true };
}

async function submitCustomRiskModel(event) {
  event.preventDefault();
  const errorBox = $("#custom-risk-error");
  errorBox.classList.add("hidden");
  let payload;
  try {
    payload = collectCustomRiskModel();
    if (!payload.name) throw new Error("계산기 이름을 입력해 주세요.");
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.classList.remove("hidden");
    return;
  }
  if (!confirmRiskModelChange()) return;
  const submit = $('button[type="submit"]', event.currentTarget);
  submit.disabled = true;
  submit.textContent = "저장 중…";
  try {
    await api("/api/assessments/" + state.assessmentId + "/custom-risk-model", { method: "PUT", body: payload });
    $("#custom-risk-model-modal")?.remove();
    closeRiskDrawer();
    state.riskDrafts = {};
    state.riskDraftModelId = null;
    await reloadWorkspace();
    state.riskModelChoosing = false;
    state.riskModelSelectionId = null;
    state.riskModelWeightDrafts = {};
    renderRiskStep();
    toast("사용자 정의 계산기를 저장하고 현재 평가에 적용했습니다.");
  } catch (error) {
    submit.disabled = false;
    submit.textContent = "저장하고 적용";
    errorBox.textContent = error.message;
    errorBox.classList.remove("hidden");
  }
}

function matrixScoresEqual(left, right) {
  const leftNumber = Number(left);
  const rightNumber = Number(right);
  if (!Number.isFinite(leftNumber) || !Number.isFinite(rightNumber)) return false;
  const tolerance = Number.EPSILON * Math.max(1, Math.abs(leftNumber), Math.abs(rightNumber)) * 4;
  return Math.abs(leftNumber - rightNumber) <= tolerance;
}

function matrixCartCellMarkup(row, cart, decimals, highlightRepresentative = true) {
  const cell = row?.cells?.[String(cart.id)];
  if (!cell?.included) return '<td class="matrix-cart-cell is-empty" aria-label="미포함"><span>–</span></td>';
  const hasScore = cell.score !== null && cell.score !== undefined && Number.isFinite(Number(cell.score));
  const representative = hasScore && matrixScoresEqual(cell.score, row.representative_score);
  const highlighted = representative && highlightRepresentative;
  const score = hasScore ? formatRiskNumber(cell.score, decimals) : "–";
  const label = hasScore
    ? `${shoppingCartLabel(cart)} 위험 점수 ${score}`
    : `${shoppingCartLabel(cart)}에 포함되었으나 점수가 없습니다.`;
  return `<td class="matrix-cart-cell${highlighted ? " is-representative" : ""}"><span class="matrix-cart-value" title="${escapeHtml(label)}"><strong class="matrix-cart-score" aria-label="${escapeHtml(label)}">${escapeHtml(score)}</strong></span></td>`;
}

function matrixTableMarkup(data, model) {
  const carts = Array.isArray(data?.carts) ? data.carts : [];
  const rows = [...(Array.isArray(data?.rows) ? data.rows : [])].sort((left, right) => (
    Number(right.representative_score) - Number(left.representative_score)
    || String(left.attack_vector_id || "").localeCompare(String(right.attack_vector_id || ""))
  ));
  if (!rows.length) return emptyState("매트릭스에 표시할 공격 벡터가 없습니다", "타당함으로 확정된 공격 벡터가 없어 빈 매트릭스로 생성되었습니다.");
  const decimals = Number.isInteger(Number(model?.decimals)) ? Number(model.decimals) : null;
  const cartCount = Math.max(1, carts.length);
  const minWidth = 320 + 110 + cartCount * 160;
  const cartCountClass = carts.length === 1 ? " one-cart" : "";
  const cartHeaders = carts.length
    ? carts.map((cart) => `<th class="matrix-cart-header" scope="col" title="${escapeHtml(`${cartCaseLabel(cart)}, 의도한 효과: ${cartCaseEffect(cart)}`)}"><span>쇼핑카트</span><strong>${escapeHtml(shoppingCartLabel(cart))}</strong></th>`).join("")
    : '<th class="matrix-cart-header" scope="col">쇼핑카트 없음</th>';
  const body = rows.map((row) => {
    const cartCells = carts.length
      ? carts.map((cart) => matrixCartCellMarkup(row, cart, decimals, true)).join("")
      : '<td class="matrix-cart-cell" aria-label="쇼핑카트 없음"></td>';
    return `<tr><th class="matrix-key-cell matrix-vector-column" scope="row"><span class="vector-id">${escapeHtml(attackVectorCatalogId(row))}</span><strong>${escapeHtml(vectorName(row))}</strong></th><td class="matrix-key-cell matrix-score-column"><strong>${escapeHtml(formatRiskNumber(row.representative_score, decimals))}</strong></td>${cartCells}</tr>`;
  }).join("");
  return `<div class="matrix-wrap matrix-full-scroll"><table class="matrix matrix-full-table${cartCountClass}" style="min-width:${minWidth}px"><thead><tr><th class="matrix-key-header matrix-vector-column" scope="col">공격 벡터</th><th class="matrix-key-header matrix-score-column" scope="col">대표 위험 점수</th>${cartHeaders}</tr></thead><tbody>${body}</tbody></table></div>`;
}

function renderMatrixStep() {
  const matrix = state.workspace.matrix;
  const data = matrix?.data;
  const model = data ? state.workspace.risk_models.find((item) => item.id === data.risk_model_id) : null;
  const matrixContent = data
    ? `<section class="card matrix-full-card"><div class="card-header matrix-full-card-header"><div><h2>위협 민감도 매트릭스</h2><div class="small-text muted">${escapeHtml(model?.name || data?.risk_model_id || "-")}</div></div><div class="matrix-header-meta"><span>공격 벡터 <strong>${escapeHtml(Array.isArray(data.rows) ? data.rows.length : 0)}</strong></span><span>쇼핑카트 <strong>${escapeHtml(Array.isArray(data.carts) ? data.carts.length : 0)}</strong></span><span class="matrix-representative-note"><i aria-hidden="true"></i>하늘색으로 표시된 쇼핑카트별 최고 점수를 대표 위험 점수로 사용합니다.</span></div></div>${matrixTableMarkup(data, model)}</section>`
    : emptyState("매트릭스가 아직 생성되지 않았습니다", "모든 쇼핑 카트의 위험 평가를 완료한 후 생성할 수 있습니다.");
  const confirmed = matrix?.status === "CONFIRMED";
  const actions = !data
    ? `<button class="btn primary" id="generate-matrix">매트릭스 생성</button>`
    : confirmed
      ? `<button class="btn primary" id="start-crra">CRRA 시작</button>`
      : `<button class="btn primary" id="confirm-matrix">전체 매트릭스 확정</button>`;
  $("#step-content").innerHTML = `${pageHeader("1.6 위협 민감도 매트릭스", "공격 벡터별 위험 점수와 쇼핑카트별 평가 결과를 확인합니다.", actions)}<div class="page-body matrix-full-page">${matrixContent}</div>`;
  if ($("#generate-matrix")) $("#generate-matrix").onclick = generateMatrix;
  if ($("#confirm-matrix")) $("#confirm-matrix").onclick = confirmMatrix;
  if ($("#start-crra")) $("#start-crra").onclick = startCrra;
}

async function generateMatrix() { try { await api(`/api/assessments/${state.assessmentId}/matrix`, { method: "POST", body: {} }); await reloadWorkspace(); renderWorkspace(); } catch (error) { toast(error.message, true); } }
async function confirmMatrix() { try { await api(`/api/assessments/${state.assessmentId}/matrix/confirm`, { method: "POST", body: {} }); await reloadWorkspace(); renderMatrixStep(); toast("위협 민감도 매트릭스를 확정했습니다."); } catch (error) { toast(error.message, true); } }

function crraInternalNotice() {
  if (Number(state.crraStep) !== 1) return "";
  return `<div class="crra-method-strip"><strong>CRRA 진행 순서</strong><span>CloudTARA에서는 대응할 공격 벡터 선택부터 최종 대응책 조합까지 5개 화면으로 나누어 진행합니다.</span></div>`;
}

function crraMatrixRows() {
  const crra = state.crra || {};
  if (Array.isArray(crra.matrix_rows)) return crra.matrix_rows;
  if (Array.isArray(crra.matrix?.data?.rows)) return crra.matrix.data.rows;
  if (Array.isArray(crra.matrix?.rows)) return crra.matrix.rows;
  return state.workspace?.matrix?.data?.rows || [];
}

function crraVectors() { return Array.isArray(state.crra?.vectors) ? state.crra.vectors : []; }
function crraMappings() { return Array.isArray(state.crra?.mapping_items) ? state.crra.mapping_items : Array.isArray(state.crra?.mappings) ? state.crra.mappings : []; }
function crraCountermeasures() { return Array.isArray(state.crra?.countermeasures) ? state.crra.countermeasures : []; }
function crraSolution() { return state.crra?.solution || null; }

function vectorId(item) { return String(item?.attack_vector_id ?? item?.av_id ?? item?.id ?? ""); }
function vectorCatalogId(item) { return attackVectorCatalogId(item) || vectorId(item); }
function vectorName(item) {
  const explicit = item?.attack_vector_name || item?.av_name || item?.name;
  if (explicit) return explicit;
  const internalId = vectorId(item);
  const catalogId = attackVectorCatalogId(item);
  const known = [
    ...(Array.isArray(state.attackVectorCatalog) ? state.attackVectorCatalog : []),
    ...(Array.isArray(state.catalogResults) ? state.catalogResults : []),
    ...(Array.isArray(state.km?.attack_vectors) ? state.km.attack_vectors : []),
  ].find((candidate) => (
    String(candidate?.id ?? candidate?.attack_vector_id ?? candidate?.av_id ?? "") === internalId
    || String(candidate?.catalog_id ?? candidate?.attack_vector_catalog_id ?? candidate?.av_catalog_id ?? "") === catalogId
  ));
  return known?.name || catalogId || internalId;
}
function countermeasureId(item) { return String(item?.countermeasure_id ?? item?.cm_id ?? item?.id ?? ""); }
function countermeasureName(item) { return item?.countermeasure_name || item?.cm_name || item?.name || countermeasureId(item); }

function normalizeEffect(value) {
  const effect = String(value || "").toUpperCase();
  if (effect === "P") return "PREVENT";
  if (effect === "D") return "DETECT";
  if (effect === "R") return "RESPOND";
  return effect;
}

function effectLabel(value) {
  const effect = normalizeEffect(value);
  return effect === "PREVENT" ? "P 예방" : effect === "DETECT" ? "D 탐지" : effect === "RESPOND" ? "R 대응" : compact(value, "미지정");
}

function normalizeConfidence(value) {
  const confidence = String(value || "").toUpperCase();
  if (confidence === "H") return "HIGH";
  if (confidence === "M") return "MODERATE";
  if (confidence === "L") return "LOW";
  return confidence;
}

function confidenceLabel(value) {
  const confidence = normalizeConfidence(value);
  return confidence === "HIGH" ? "H 높음" : confidence === "MODERATE" ? "M 중간" : confidence === "LOW" ? "L 낮음" : compact(value, "미지정");
}

function crraReviewLabel(value) {
  const status = String(value || "UNREVIEWED").toUpperCase();
  return status === "INCLUDED" ? "포함" : status === "EXCLUDED" ? "제외" : "미검토";
}

function kmReviewLabel(value) {
  return String(value || "REVIEW_REQUIRED").toUpperCase() === "APPROVED" ? "승인" : "검토 필요";
}

function optionsMarkup(options, selected, placeholder = null) {
  const current = String(selected || "").toUpperCase();
  return `${placeholder === null ? "" : `<option value="">${escapeHtml(placeholder)}</option>`}${options.map(([value, label]) => `<option value="${value}" ${current === value ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}`;
}

async function reloadCrra() {
  state.crra = await api(`/api/assessments/${state.assessmentId}/crra`);
  return state.crra;
}

async function startCrra() {
  try {
    await api(`/api/assessments/${state.assessmentId}/crra/initialize`, { method: "POST", body: {} });
    await Promise.all([reloadWorkspace(), reloadCrra()]);
    state.phase = "crra";
    state.crraStep = 1;
    renderWorkspace();
    toast("CRRA 작업 공간을 시작했습니다.");
  } catch (error) { toast(error.message, true); }
}

async function openCrraStep(step) {
  if (!canAccessCrra(step)) return;
  try {
    if (!state.crra) await api(`/api/assessments/${state.assessmentId}/crra/initialize`, { method: "POST", body: {} });
    await reloadCrra();
    state.phase = "crra";
    state.crraStep = step;
    renderWorkspace();
  } catch (error) { toast(error.message, true); }
}

function renderCrraStep() {
  state.crraUiDirty = Number(state.crraStep) === 3 && crraMappingDraftIsDirty();
  if (!state.crra) {
    $("#step-content").innerHTML = `${pageHeader("CRRA", "대응책 분석 정보를 불러오고 있습니다.")}<div class="page-body">${emptyState("CRRA 준비 중", "잠시 후 다시 시도해 주세요.")}</div>`;
    return;
  }
  if (state.crraStep === 1) renderCrraVectorsStep();
  else if (state.crraStep === 2) renderCrraInitialMappingsStep();
  else if (state.crraStep === 3) renderCrraAmendMappingsStep();
  else if (state.crraStep === 4) renderCrraScoringStep();
  else renderCrraSolutionStep();
  const content = $("#step-content");
  if (Number(state.crraStep) !== 3) {
    content?.addEventListener("input", () => { state.crraUiDirty = true; });
    content?.addEventListener("change", () => { state.crraUiDirty = true; });
  }
}

function confirmCrraDraftDiscard() {
  if (state.crraMappingBatchLoading || state.crraMappingBatchSaving) {
    toast("CRRA 일괄 작업이 끝난 뒤 다른 단계로 이동해 주세요.", true);
    return false;
  }
  const dirty = state.crraUiDirty || (Number(state.crraStep) === 3 && crraMappingDraftIsDirty());
  return !dirty || window.confirm("저장하거나 계산하지 않은 변경사항이 있습니다. 변경을 취소하고 이동할까요?");
}

function renderCrraVectorsStep() {
  const matrixRows = [...crraMatrixRows()].sort((a, b) => Number(a.rank || 9999) - Number(b.rank || 9999));
  const saved = new Map(crraVectors().map((item) => [vectorId(item), item]));
  const rows = matrixRows.map((row, index) => {
    const id = vectorId(row);
    const displayId = vectorCatalogId(row);
    const vector = saved.get(id);
    const selected = vector ? vector.selected !== false : true;
    const score = row.representative_score ?? row.risk_score ?? vector?.risk_score;
    const rank = row.rank ?? vector?.rank ?? index + 1;
    return `<tr><td><input type="checkbox" data-crra-vector value="${escapeHtml(id)}" ${selected ? "checked" : ""} aria-label="${escapeHtml(displayId)} 선택"></td><td><span class="matrix-rank">${escapeHtml(rank)}</span></td><td><div class="vector-id">${escapeHtml(displayId)}</div><div class="vector-name">${escapeHtml(vectorName(row))}</div></td><td><strong>${escapeHtml(formatRiskNumber(score))}</strong>${row.risk_level ? `<div class="small-text muted">${escapeHtml(row.risk_level)}</div>` : ""}</td><td><input class="crra-reason-input" data-crra-vector-reason="${escapeHtml(id)}" value="${escapeHtml(vector?.selection_reason || "")}" placeholder="포함하거나 제외한 이유 (선택)"></td></tr>`;
  }).join("");
  const warning = matrixRows.length > 25 ? `<div class="notice warning"><div>!</div><div><strong>검토 대상이 ${matrixRows.length}개입니다.</strong>PR-20은 한 평가에서 25개를 넘으면 검토가 어려울 수 있다고 안내합니다. 우선순위를 확인해 분석 범위를 조정해 주세요.</div></div>` : "";
  $("#step-content").innerHTML = `${pageHeader("2.1 대응할 공격 벡터 선택", "CTSA 결과에서 대응책 분석에 포함할 공격 벡터를 고릅니다.", `<button class="btn" id="crra-toggle-vectors">전체 선택 전환</button><button class="btn primary" id="crra-save-vectors">저장하고 다음으로</button>`)}<div class="page-body">${crraInternalNotice()}${warning}<div class="card"><div class="card-header"><div><h2>공격 벡터</h2><div class="small-text muted">CTSA 위험 점수와 순위를 표시합니다.</div></div><span class="count-pill">${matrixRows.length}개</span></div><div class="card-body">${matrixRows.length ? `<table class="data-table crra-vector-table"><thead><tr><th>포함</th><th>순위</th><th>공격 벡터</th><th>위험 점수</th><th>선택 메모</th></tr></thead><tbody>${rows}</tbody></table>` : emptyState("대응할 공격 벡터가 없습니다", "확정 매트릭스가 비어 있습니다.")}</div></div></div>`;
  $("#crra-toggle-vectors").onclick = () => {
    const boxes = $$('[data-crra-vector]');
    const selectAll = boxes.some((box) => !box.checked);
    boxes.forEach((box) => { box.checked = selectAll; });
  };
  $("#crra-save-vectors").onclick = saveCrraVectors;
}

async function saveCrraVectors() {
  const vectorIds = $$('[data-crra-vector]').filter((box) => box.checked).map((box) => box.value);
  if (crraMatrixRows().length > 0 && !vectorIds.length) { toast("대응 대상으로 검토할 공격 벡터를 하나 이상 선택해 주세요.", true); return; }
  const reasons = {};
  $$('[data-crra-vector-reason]').forEach((input) => { if (input.value.trim()) reasons[input.dataset.crraVectorReason] = input.value.trim(); });
  try {
    await api(`/api/assessments/${state.assessmentId}/crra/vectors`, { method: "POST", body: { vector_ids: vectorIds, reasons } });
    await Promise.all([reloadWorkspace(), reloadCrra()]);
    resetCrraMappingDrafts();
    state.crraStep = 2;
    renderWorkspace();
    toast("대응할 공격 벡터를 저장했습니다.");
  } catch (error) { toast(error.message, true); }
}

function includedMapping(item) { return String(item.review_status || item.status || "UNREVIEWED").toUpperCase() !== "EXCLUDED"; }

function renderCrraInitialMappingsStep() {
  const mappings = crraMappings();
  const selectedVectors = crraVectors().filter((item) => item.selected !== false);
  const mappedIds = new Set(mappings.filter(includedMapping).map(vectorId));
  const gaps = selectedVectors.filter((item) => !mappedIds.has(vectorId(item)));
  const canContinue = mappings.length > 0 || gaps.length > 0 || Number(crraSettings().current_step || 0) >= 2;
  const rows = mappings.map((item) => `<tr><td><div class="vector-id">${escapeHtml(vectorCatalogId(item))}</div><div class="vector-name">${escapeHtml(vectorName(item))}</div></td><td><div class="vector-id">${escapeHtml(countermeasureId(item))}</div><div class="vector-name">${escapeHtml(countermeasureName(item))}</div></td><td><div class="mapping-badge-stack"><span class="badge blue">${escapeHtml(effectLabel(item.effect))}</span><span class="badge">${escapeHtml(confidenceLabel(item.confidence))}</span></div></td><td><span class="badge ${includedMapping(item) ? "blue" : "red"}">${escapeHtml(crraReviewLabel(item.review_status))}</span><div class="small-text muted">출처: ${escapeHtml(compact(item.item_source || item.source, "KM"))}</div></td></tr>`).join("");
  const gapMarkup = gaps.length ? `<div class="notice warning"><div>!</div><div><strong>KM에 연결된 대응책이 없는 공격 벡터 ${gaps.length}개</strong>${escapeHtml(gaps.map((item) => `${vectorCatalogId(item)} ${vectorName(item)}`).join(", "))}<br>다음 화면에서 이 평가에만 쓸 대응책을 직접 추가하거나, 미연결 상태로 남겨 최종 검토할 수 있습니다.</div></div>` : `<div class="notice success"><div>✓</div><div><strong>대응책 후보를 불러왔습니다.</strong>선택한 모든 공격 벡터에 하나 이상의 대응책 후보가 연결되어 있습니다.</div></div>`;
  $("#step-content").innerHTML = `${pageHeader("2.2 KM 대응책 불러오기", "선택한 공격 벡터에 연결된 대응책 후보를 조회합니다.", `<button class="btn primary" id="crra-generate-mappings">${mappings.length ? "다시 불러오기" : "대응책 불러오기"}</button><button class="btn" id="crra-go-amend" aria-disabled="${canContinue ? "false" : "true"}">후보 검토로 이동</button>`)}<div class="page-body">${crraInternalNotice()}${mappings.length || gaps.length ? gapMarkup : ""}<div class="card"><div class="card-header"><div><h2>대응책 후보</h2><div class="small-text muted">공격 벡터, 대응책과 효과 조합을 한 행으로 표시합니다.</div></div><span class="count-pill">${mappings.length}개</span></div><div class="card-body">${mappings.length ? `<table class="data-table crra-initial-mapping-table"><thead><tr><th>공격 벡터</th><th>대응책</th><th>효과 및 신뢰도</th><th>검토 상태 및 출처</th></tr></thead><tbody>${rows}</tbody></table>` : emptyState("불러온 대응책이 없습니다", "대응책 불러오기를 눌러 KM 후보를 조회합니다.")}</div></div></div>`;
  $("#crra-generate-mappings").onclick = generateCrraMappings;
  if ($("#crra-go-amend")) $("#crra-go-amend").onclick = () => { if (!canContinue) { explainCrraBlock(3); return; } state.crraStep = 3; renderWorkspace(); };
}

async function generateCrraMappings() {
  try {
    await api(`/api/assessments/${state.assessmentId}/crra/mappings/generate`, { method: "POST", body: {} });
    await Promise.all([reloadWorkspace(), reloadCrra()]);
    resetCrraMappingDrafts();
    renderWorkspace();
    toast("KM에서 대응책 후보를 불러왔습니다.");
  } catch (error) { toast(error.message, true); }
}

function mappingSuggestion(item) {
  return state.crraLlmSuggestions[String(item.id)] || item.llm_mapping || item.llm_suggestion || null;
}

function renderCrraAmendMappingsStep() {
  const mappings = crraMappings();
  ensureCrraMappingDrafts(mappings);
  const stats = crraMappingDraftStats(mappings);
  const savedUnreviewed = mappings.filter((item) => String(item.review_status || "UNREVIEWED").toUpperCase() === "UNREVIEWED").length;
  const busy = state.crraMappingBatchLoading || state.crraMappingBatchSaving;
  const llmLimitExceeded = mappings.length > 200;
  const llmDisabled = busy || !mappings.length || llmLimitExceeded || !llmEnabledForAssessment();
  const completeDisabled = busy || savedUnreviewed > 0 || crraMappingDraftIsDirty();
  const rows = mappings.map(crraMappingRowMarkup).join("");
  const table = mappings.length
    ? `<div class="crra-batch-table-wrap"><table class="data-table crra-batch-table"><colgroup><col class="crra-col-av"><col class="crra-col-cm"><col class="crra-col-status"><col class="crra-col-effect"><col class="crra-col-confidence"><col class="crra-col-reason"></colgroup><thead><tr><th>공격 벡터</th><th>대응책 및 출처</th><th>검토 상태</th><th>효과</th><th>신뢰도</th><th>판단 근거</th></tr></thead><tbody>${rows}</tbody></table></div>`
    : emptyState("검토할 대응책 연결이 없습니다", "대응책을 직접 추가하거나 이전 화면에서 KM 후보를 불러와 주세요.");
  const progress = state.crraMappingBatchLoading
    ? `<div class="crra-batch-progress" role="status" aria-live="polite"><i aria-hidden="true"></i><span>LLM이 모든 대응책 후보의 초안을 생성 중입니다. 응답 누락이나 잘림은 서버가 작은 묶음으로 보정합니다.</span></div>`
    : state.crraMappingBatchSaving
      ? `<div class="crra-batch-progress" role="status" aria-live="polite"><i aria-hidden="true"></i><span>모든 검토값을 하나의 트랜잭션으로 저장 중입니다.</span></div>`
      : "";
  const batchError = state.crraMappingBatchError
    ? `<div class="notice error crra-batch-error"><div>!</div><div><strong>일괄 작업을 완료하지 못했습니다.</strong>${escapeHtml(state.crraMappingBatchError)}</div></div>`
    : "";
  const llmLimitNotice = llmLimitExceeded
    ? `<div class="notice warning crra-batch-error"><div>!</div><div><strong>LLM 초안은 최대 200개 행까지 지원합니다.</strong>현재 ${mappings.length}개입니다. CRRA 분석 범위나 후보 관계를 조정하세요. 수동 검토와 저장은 500개까지 가능합니다.</div></div>`
    : "";
  const completeHelp = savedUnreviewed
    ? `<div class="step-gate-help">전체 저장 후에도 미검토 ${savedUnreviewed}개가 남아 있습니다. 모두 포함 또는 제외로 저장하면 2.4로 이동할 수 있습니다.</div>`
    : crraMappingDraftIsDirty()
      ? `<div class="step-gate-help">변경한 초안을 전체 저장해야 다음 단계로 이동할 수 있습니다.</div>`
      : "";
  $("#step-content").innerHTML = `${pageHeader("2.3 대응책 후보 검토", "공격 벡터와 대응책의 연결을 검토하고 결과를 저장합니다.", `<button class="btn" id="crra-add-mapping" ${busy ? "disabled" : ""}>대응책 추가</button><button class="btn primary" id="crra-complete-mappings" aria-disabled="${completeDisabled ? "true" : "false"}">2.4로 이동</button>`)}<div class="page-body crra-batch-page">
    ${crraMappingContextMarkup(mappings)}
    <div class="notice info crra-method-guide"><div>i</div><div><strong>대응 효과와 신뢰도 기준</strong><span><b>P 예방</b> 공격에 필요한 조건 제거</span><span><b>D 탐지</b> 공격 발생, 진행 또는 가능성 판별</span><span><b>R 대응</b> 성공 가능성 또는 영향 감소</span><span><b>H</b> 공학적 검증, <b>M</b> 전문가 판단, <b>L</b> 개연성은 있으나 미확인</span></div></div>
    <section class="card crra-batch-card"><div class="crra-batch-toolbar"><div class="crra-batch-summary" aria-live="polite"><strong data-crra-stat="reviewed">${stats.reviewed}/${stats.total} 판정</strong><span data-crra-stat="detail">미검토 ${stats.unreviewed}, 포함 ${stats.included}, 제외 ${stats.excluded}, 변경 ${stats.dirty}</span></div><div class="crra-batch-filters"><input id="crra-mapping-search" type="search" value="${escapeHtml(state.crraMappingQuery || "")}" placeholder="공격 벡터 또는 대응책 검색" aria-label="대응책 후보 검색"><select id="crra-mapping-filter" aria-label="검토 상태 필터"><option value="ALL" ${(state.crraMappingFilter || "ALL") === "ALL" ? "selected" : ""}>전체</option><option value="UNREVIEWED" ${state.crraMappingFilter === "UNREVIEWED" ? "selected" : ""}>미검토</option><option value="INCLUDED" ${state.crraMappingFilter === "INCLUDED" ? "selected" : ""}>포함</option><option value="EXCLUDED" ${state.crraMappingFilter === "EXCLUDED" ? "selected" : ""}>제외</option><option value="DIRTY" ${state.crraMappingFilter === "DIRTY" ? "selected" : ""}>변경됨</option></select><span id="crra-mapping-visible-count">${mappings.length}/${mappings.length}개 표시</span></div><div class="crra-batch-llm"><button class="btn" id="llm-crra-mappings" ${llmDisabled ? `disabled title='${llmLimitExceeded ? "LLM 전체 판정은 최대 200개 행까지 지원합니다." : "LLM 설정과 평가별 허용이 필요합니다."}'` : ""}>LLM 초안 받기</button><p>저장 전에 수정할 수 있습니다.</p></div></div>${progress}${batchError}${llmLimitNotice}${table}<footer class="crra-batch-footer"><span>판정한 항목에는 근거가 필요합니다.</span><button class="btn primary" id="save-crra-mappings" ${busy || !mappings.length ? "disabled" : ""}>${state.crraMappingBatchSaving ? "저장 중" : "전체 저장"}</button></footer></section>${completeHelp}</div>`;

  applyCrraMappingFilters(mappings);
  $$('[data-crra-batch-status]').forEach((select) => select.onchange = () => updateCrraMappingInput(mappings, select.dataset.crraBatchStatus, { status: select.value }, select));
  $$('[data-crra-batch-effect]').forEach((select) => select.onchange = () => updateCrraMappingInput(mappings, select.dataset.crraBatchEffect, { effect: select.value }, select));
  $$('[data-crra-batch-confidence]').forEach((select) => select.onchange = () => updateCrraMappingInput(mappings, select.dataset.crraBatchConfidence, { confidence: select.value }, select));
  $$('[data-crra-batch-reason]').forEach((textarea) => textarea.oninput = () => updateCrraMappingInput(mappings, textarea.dataset.crraBatchReason, { reason: textarea.value }, textarea));
  $("#crra-mapping-search").oninput = (event) => { state.crraMappingQuery = event.target.value; applyCrraMappingFilters(mappings); };
  $("#crra-mapping-filter").onchange = (event) => { state.crraMappingFilter = event.target.value; applyCrraMappingFilters(mappings); };
  $("#llm-crra-mappings").onclick = requestCrraMappingBatchSuggestions;
  $("#save-crra-mappings").onclick = saveCrraMappingBatch;
  $("#crra-add-mapping").onclick = () => {
    if (crraMappingDraftIsDirty()) { toast("대응책을 추가하기 전에 현재 변경사항을 전체 저장해 주세요.", true); $("#save-crra-mappings")?.focus(); return; }
    showCrraMappingModal();
  };
  $("#crra-complete-mappings").onclick = () => {
    const blocked = crraMappingDraftIsDirty() || crraMappings().some((item) => String(item.review_status || "UNREVIEWED").toUpperCase() === "UNREVIEWED");
    if (blocked) { explainCrraBlock(4); return; }
    completeCrraMappings();
  };
}

async function saveCrraMapping(button) {
  const row = button.closest('[data-crra-mapping-row]');
  const id = row.dataset.crraMappingRow;
  const status = row.querySelector('[data-map-status]').value;
  const effect = row.querySelector('[data-map-effect]').value;
  const confidence = row.querySelector('[data-map-confidence]').value;
  const reason = row.querySelector('[data-map-reason]').value.trim();
  if (!["INCLUDED", "EXCLUDED"].includes(status)) { toast("검토 상태를 포함 또는 제외로 선택해 주세요.", true); return; }
  if (!reason) { toast("포함 또는 제외 판단 근거를 입력하세요.", true); return; }
  if (status === "INCLUDED" && (!effect || !confidence)) { toast("포함할 연결의 대응 효과와 신뢰도를 선택해 주세요.", true); return; }
  try {
    await api(`/api/crra/mappings/${encodeURIComponent(id)}`, { method: "PUT", body: { status, reason, effect: effect || undefined, confidence: confidence || undefined } });
    await Promise.all([reloadWorkspace(), reloadCrra()]);
    state.crraUiDirty = false;
    state.activeCrraMappingId = String(crraMappings().find((item) => !["INCLUDED", "EXCLUDED"].includes(String(item.review_status || "").toUpperCase()))?.id ?? id);
    renderWorkspace();
    toast("대응책 연결 검토값을 저장했습니다.");
  } catch (error) { toast(error.message, true); }
}

async function requestCrraMappingSuggestion(button) {
  if (!confirmCrraDraftDiscard()) return;
  if (!window.confirm("공격 벡터, 대응책과 평가 맥락을 설정된 외부 LLM에 보내 효과와 신뢰도 제안을 받을까요?")) return;
  const row = button.closest('[data-crra-mapping-row]');
  const item = crraMappings().find((entry) => String(entry.id) === row.dataset.crraMappingRow);
  try {
    toast("LLM에 대응 효과와 신뢰도 제안을 요청하고 있습니다.");
    const result = await api(`/api/assessments/${state.assessmentId}/crra/llm/mapping`, { method: "POST", body: { attack_vector_id: vectorId(item), countermeasure_id: countermeasureId(item) } });
    state.crraLlmSuggestions[String(item.id)] = result?.suggestion || result;
    await reloadCrra();
    renderWorkspace();
    toast("제안을 받았습니다. 입력란에 적용한 뒤 검토값을 저장해 주세요.");
  } catch (error) { toast(error.message, true); }
}

function applyCrraMappingSuggestion(button) {
  const row = button.closest('[data-crra-mapping-row]');
  const item = crraMappings().find((entry) => String(entry.id) === row.dataset.crraMappingRow);
  const suggestion = mappingSuggestion(item);
  if (!suggestion) return;
  row.querySelector('[data-map-status]').value = "INCLUDED";
  row.querySelector('[data-map-effect]').value = normalizeEffect(suggestion.effect);
  row.querySelector('[data-map-confidence]').value = normalizeConfidence(suggestion.confidence);
  row.querySelector('[data-map-reason]').value = suggestion.reason || suggestion.rationale || "";
  toast("제안을 입력란에 채웠습니다. 내용을 확인한 뒤 검토값을 저장해 주세요.");
}

function resetCrraMappingDrafts() {
  state.crraMappingDrafts = {};
  state.crraMappingDraftAssessmentId = null;
  state.crraMappingBatchLoading = false;
  state.crraMappingBatchSaving = false;
  state.crraMappingBatchError = "";
  state.crraMappingFilter = "ALL";
  state.crraMappingQuery = "";
}

function savedCrraMappingValues(item) {
  return {
    status: String(item?.review_status || "UNREVIEWED").toUpperCase(),
    effect: normalizeEffect(item?.effect),
    confidence: normalizeConfidence(item?.confidence),
    reason: String(item?.decision_reason || item?.reason || ""),
  };
}

function crraMappingDraftFor(item) {
  const key = String(item.id);
  const saved = savedCrraMappingValues(item);
  let draft = state.crraMappingDrafts[key];
  const savedChanged = draft && (
    draft.savedStatus !== saved.status || draft.savedEffect !== saved.effect
    || draft.savedConfidence !== saved.confidence || draft.savedReason !== saved.reason
  );
  if (!draft || (!draft.dirty && savedChanged)) {
    draft = {
      ...saved,
      savedStatus: saved.status,
      savedEffect: saved.effect,
      savedConfidence: saved.confidence,
      savedReason: saved.reason,
      source: "SAVED",
      dirty: false,
    };
    state.crraMappingDrafts[key] = draft;
  }
  return draft;
}

function ensureCrraMappingDrafts(mappings) {
  const assessmentKey = String(state.assessmentId ?? "");
  if (state.crraMappingDraftAssessmentId !== assessmentKey) {
    resetCrraMappingDrafts();
    state.crraMappingDraftAssessmentId = assessmentKey;
  }
  const currentIds = new Set(mappings.map((item) => String(item.id)));
  Object.keys(state.crraMappingDrafts).forEach((id) => {
    if (!currentIds.has(id)) delete state.crraMappingDrafts[id];
  });
  mappings.forEach(crraMappingDraftFor);
}

function updateCrraMappingDraft(item, values, source = "USER") {
  const draft = crraMappingDraftFor(item);
  if (values.status !== undefined) draft.status = String(values.status).toUpperCase();
  if (values.effect !== undefined) draft.effect = normalizeEffect(values.effect);
  if (values.confidence !== undefined) draft.confidence = normalizeConfidence(values.confidence);
  if (values.reason !== undefined) draft.reason = String(values.reason);
  draft.source = source;
  draft.dirty = draft.status !== draft.savedStatus
    || draft.effect !== draft.savedEffect
    || draft.confidence !== draft.savedConfidence
    || draft.reason.trim() !== draft.savedReason.trim();
  state.crraUiDirty = crraMappingDraftIsDirty();
  return draft;
}

function crraMappingDraftIsDirty() {
  return Object.values(state.crraMappingDrafts || {}).some((draft) => Boolean(draft?.dirty));
}

function crraMappingDraftStats(mappings) {
  const drafts = mappings.map(crraMappingDraftFor);
  return {
    total: mappings.length,
    reviewed: drafts.filter((draft) => ["INCLUDED", "EXCLUDED"].includes(draft.status)).length,
    included: drafts.filter((draft) => draft.status === "INCLUDED").length,
    excluded: drafts.filter((draft) => draft.status === "EXCLUDED").length,
    unreviewed: drafts.filter((draft) => draft.status === "UNREVIEWED").length,
    dirty: drafts.filter((draft) => draft.dirty).length,
    llm: drafts.filter((draft) => draft.source === "LLM").length,
  };
}

function crraMappingStatusOptions(status) {
  return [
    ["UNREVIEWED", "미검토"],
    ["INCLUDED", "포함"],
    ["EXCLUDED", "제외"],
  ].map(([value, label]) => `<option value="${value}" ${status === value ? "selected" : ""}>${label}</option>`).join("");
}

function normalizeCrraBatchSuggestions(mappings, suggestions) {
  if (!Array.isArray(suggestions)) throw new Error("LLM 일괄 판정 응답에 suggestions 배열이 없습니다.");
  const expected = new Set(mappings.map((item) => String(item.id)));
  const normalized = new Map();
  suggestions.forEach((suggestion) => {
    const id = String(suggestion?.item_id ?? suggestion?.mapping_id ?? "");
    const status = String(suggestion?.status || "").toUpperCase();
    const effect = normalizeEffect(suggestion?.effect);
    const confidence = normalizeConfidence(suggestion?.confidence);
    const reason = String(suggestion?.reason || suggestion?.rationale || "").trim();
    if (!expected.has(id) || normalized.has(id)) throw new Error("LLM 응답의 대응책 후보 구성이 현재 표와 일치하지 않습니다.");
    if (!["INCLUDED", "EXCLUDED"].includes(status) || !EFFECT_OPTIONS.some(([value]) => value === effect)
      || !CONFIDENCE_OPTIONS.some(([value]) => value === confidence) || !reason) {
      throw new Error("LLM 응답에 포함 또는 제외 판정, P/D/R, 신뢰도 또는 판단 근거가 누락되었습니다.");
    }
    normalized.set(id, { status, effect, confidence, reason, provenance: suggestion._llm || null });
  });
  if (normalized.size !== expected.size) throw new Error("LLM이 모든 대응책 후보를 판정하지 않아 초안을 적용하지 않았습니다.");
  return normalized;
}

function crraMappingContextMarkup(mappings) {
  const assessment = state.workspace?.assessment || {};
  const scope = scopeBriefDisplay(assessment);
  const releases = Array.isArray(state.bootstrap?.km_releases) ? state.bootstrap.km_releases : [];
  const release = releases.find((item) => Number(item.id) === Number(assessment.km_release_id)) || releases[0];
  const releaseName = compact(release?.name, "현재 고정 KM 릴리스");
  const scopeIn = compact(assessment.system_scope, compact(assessment.scope_in, "아직 모름"));
  const scopeOut = compact(assessment.scope_out, "별도 제외 범위 없음");
  const items = [
    ["평가 대상", compact(assessment.evaluation_target, assessment.name)],
    ["시스템 범위", `포함: ${scopeIn} / 제외: ${scopeOut}`],
    ["수명주기", scope.lifecycle],
    ["위협 범위", scope.threatRanges],
    ["위협 행위자", scope.actorType],
    ["공격 목표", scope.objectives],
    ["알려진 행위자 역량", scope.capabilities],
    ["기술 정보 및 가정", compact(assessment.technical_info, scope.actorNotes)],
    ["검토할 대응책 범위", `${releaseName}의 매핑 후보 + 이 평가에서 직접 추가한 대응책 관계`],
  ];
  return `<section class="card review-context-card crra-mapping-context"><div class="card-header"><div><h2>평가 맥락</h2><div class="small-text muted">이 맥락과 KM 근거를 기준으로 각 공격 벡터–대응책–효과 행을 판정합니다.</div></div></div><div class="review-context-grid">${items.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(compact(value, "아직 모름"))}</strong></div>`).join("")}</div><div id="crra-coverage-summary">${crraMappingCoverageMarkup(mappings)}</div></section>`;
}

function crraMappingCoverageMarkup(mappings) {
  const selectedVectors = crraVectors().filter((item) => item.selected !== false);
  const includedIds = new Set(mappings.filter((item) => crraMappingDraftFor(item).status === "INCLUDED").map(vectorId));
  const pendingIds = new Set(mappings.filter((item) => crraMappingDraftFor(item).status === "UNREVIEWED").map(vectorId));
  const pending = selectedVectors.filter((item) => !includedIds.has(vectorId(item)) && pendingIds.has(vectorId(item)));
  const gaps = selectedVectors.filter((item) => !includedIds.has(vectorId(item)) && !pendingIds.has(vectorId(item)));
  const confirmedCount = selectedVectors.length - pending.length - gaps.length;
  return `<div class="crra-coverage-summary"><div class="crra-coverage-ok"><strong>포함 대응책 확보 AV ${confirmedCount}개</strong><span>사용자가 포함으로 판정한 관계가 있습니다.</span></div>${pending.length ? `<div class="crra-coverage-pending"><strong>판정 대기 AV ${pending.length}개</strong><span>${escapeHtml(pending.map((item) => `${vectorCatalogId(item)} ${vectorName(item)}`).join(", "))}</span></div>` : ""}${gaps.length ? `<div class="crra-coverage-gap"><strong>대응 공백 AV ${gaps.length}개</strong><span>${escapeHtml(gaps.map((item) => `${vectorCatalogId(item)} ${vectorName(item)}`).join(", "))}</span></div>` : ""}</div>`;
}

function crraMappingApplicableCaseLabels(item) {
  const matrixRow = crraMatrixRows().find((row) => vectorId(row) === vectorId(item));
  const cells = matrixRow?.cells && typeof matrixRow.cells === "object" ? matrixRow.cells : {};
  const carts = Array.isArray(state.workspace?.carts) ? state.workspace.carts : [];
  const names = carts
    .filter((cart) => cells[String(cart.id)]?.included)
    .map((cart) => {
      const attackCase = cartAttackCase(cart);
      const pathIds = Array.isArray(attackCase?.path_node_ids) ? attackCase.path_node_ids : [];
      const path = pathIds.map((id) => nodeDisplayName(id)).filter(Boolean).join(" → ");
      return `${cartCaseLabel(cart)}${path ? `, 경로: ${path}` : ""}`;
    });
  return names.length ? names.join(", ") : "확정 매트릭스에서 적용 Attack Case 없음";
}

function crraMappingEvidenceMarkup(item) {
  const vector = crraVectors().find((entry) => vectorId(entry) === vectorId(item)) || {};
  const risk = item.av_risk_score ?? vector.risk_score;
  const rank = item.av_rank ?? vector.rank;
  const selectionReason = compact(item.av_selection_reason, vector.selection_reason);
  const rows = [
    ["AV 설명", compact(item.av_description, vector.av_description)],
    ["2.1 선택 근거", selectionReason],
    ["적용 Attack Case", crraMappingApplicableCaseLabels(item)],
    ["KM 매핑 근거", item.km_rationale],
  ];
  const riskMeta = [
    Number.isFinite(Number(rank)) ? `위험 순위 ${Number(rank)}` : "",
    risk !== null && risk !== undefined && Number.isFinite(Number(risk)) ? `위험 점수 ${formatRiskNumber(risk)}` : "",
  ].filter(Boolean).join(", ");
  return `${riskMeta ? `<div class="crra-row-risk">${escapeHtml(riskMeta)}</div>` : ""}<details class="crra-row-evidence"><summary>판정 근거 자료</summary><dl>${rows.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(compact(value, "기재 없음"))}</dd></div>`).join("")}</dl></details>`;
}

function crraMappingRowMarkup(item) {
  const draft = crraMappingDraftFor(item);
  const disabled = state.crraMappingBatchLoading || state.crraMappingBatchSaving ? "disabled" : "";
  const source = String(item.item_source || "KM").startsWith("KM") ? "KM" : "사용자 추가";
  const description = compact(item.cm_description, "대응책 설명 없음");
  const llmBadge = `<span class="badge purple crra-llm-draft-badge ${draft.source === "LLM" ? "" : "hidden"}" data-crra-draft-source="${escapeHtml(item.id)}">LLM 초안</span>`;
  return `<tr data-crra-batch-row="${escapeHtml(item.id)}" class="${draft.dirty ? "is-dirty" : ""}">
    <td class="crra-batch-vector"><div class="vector-id">${escapeHtml(vectorCatalogId(item))}</div><div class="vector-name">${escapeHtml(vectorName(item))}</div>${llmBadge}${crraMappingEvidenceMarkup(item)}</td>
    <td class="crra-batch-countermeasure"><div class="vector-id">${escapeHtml(countermeasureId(item))}</div><div class="vector-name">${escapeHtml(countermeasureName(item))}</div><div class="review-row-badges"><span class="badge ${source === "KM" ? "blue" : "orange"}">${source}</span><span class="small-text muted">${escapeHtml(compact(item.cm_source, "출처 미기재"))}</span></div><details><summary>대응책 설명</summary><p>${escapeHtml(description)}</p></details></td>
    <td><select class="crra-batch-select" data-crra-batch-status="${escapeHtml(item.id)}" aria-label="${escapeHtml(vectorCatalogId(item))} ${escapeHtml(countermeasureName(item))} 포함 여부" ${disabled}>${crraMappingStatusOptions(draft.status)}</select></td>
    <td><select class="crra-batch-select" data-crra-batch-effect="${escapeHtml(item.id)}" aria-label="${escapeHtml(countermeasureName(item))} 대응 효과" ${disabled}>${optionsMarkup(EFFECT_OPTIONS, draft.effect, "효과 선택")}</select></td>
    <td><select class="crra-batch-select" data-crra-batch-confidence="${escapeHtml(item.id)}" aria-label="${escapeHtml(countermeasureName(item))} 신뢰도" ${disabled}>${optionsMarkup(CONFIDENCE_OPTIONS, draft.confidence, "신뢰도 선택")}</select></td>
    <td class="crra-batch-reason-cell"><textarea data-crra-batch-reason="${escapeHtml(item.id)}" rows="3" maxlength="10000" placeholder="판정, 효과와 신뢰도 근거" ${disabled}>${escapeHtml(draft.reason)}</textarea><div class="form-error hidden" data-crra-batch-error="${escapeHtml(item.id)}"></div></td>
  </tr>`;
}

function crraMappingMatchesFilter(item, draft) {
  const filter = String(state.crraMappingFilter || "ALL");
  if (filter === "DIRTY" && !draft.dirty) return false;
  if (["UNREVIEWED", "INCLUDED", "EXCLUDED"].includes(filter) && draft.status !== filter) return false;
  const query = String(state.crraMappingQuery || "").trim().toLowerCase();
  if (!query) return true;
  return [vectorId(item), vectorCatalogId(item), vectorName(item), countermeasureId(item), countermeasureName(item), item.cm_description, item.cm_source]
    .some((value) => String(value || "").toLowerCase().includes(query));
}

function applyCrraMappingFilters(mappings) {
  let visible = 0;
  mappings.forEach((item) => {
    const row = $(`[data-crra-batch-row="${item.id}"]`);
    const show = crraMappingMatchesFilter(item, crraMappingDraftFor(item));
    row?.classList.toggle("hidden", !show);
    if (show) visible += 1;
  });
  const count = $("#crra-mapping-visible-count");
  if (count) count.textContent = `${visible}/${mappings.length}개 표시`;
}

function refreshCrraMappingBatchChrome(mappings) {
  const stats = crraMappingDraftStats(mappings);
  const reviewed = $('[data-crra-stat="reviewed"]');
  const detail = $('[data-crra-stat="detail"]');
  if (reviewed) reviewed.textContent = `${stats.reviewed}/${stats.total} 판정`;
  if (detail) detail.textContent = `미검토 ${stats.unreviewed}, 포함 ${stats.included}, 제외 ${stats.excluded}, 변경 ${stats.dirty}`;
  const coverage = $("#crra-coverage-summary");
  if (coverage) coverage.innerHTML = crraMappingCoverageMarkup(mappings);
  const complete = $("#crra-complete-mappings");
  if (complete) {
    complete.setAttribute("aria-disabled", crraMappingDraftIsDirty() || mappings.some((item) => String(item.review_status || "UNREVIEWED").toUpperCase() === "UNREVIEWED") ? "true" : "false");
  }
  mappings.forEach((item) => {
    const draft = crraMappingDraftFor(item);
    $(`[data-crra-batch-row="${item.id}"]`)?.classList.toggle("is-dirty", draft.dirty);
    $(`[data-crra-draft-source="${item.id}"]`)?.classList.toggle("hidden", draft.source !== "LLM");
  });
  state.crraUiDirty = crraMappingDraftIsDirty();
  applyCrraMappingFilters(mappings);
}

function updateCrraMappingInput(mappings, id, values, control) {
  const item = mappings.find((entry) => String(entry.id) === String(id));
  if (!item) return;
  updateCrraMappingDraft(item, values, "USER");
  const error = $(`[data-crra-batch-error="${item.id}"]`);
  error?.classList.add("hidden");
  control?.classList.remove("validation-target");
  control?.removeAttribute("aria-invalid");
  refreshCrraMappingBatchChrome(mappings);
}

function validateCrraMappingReviews(mappings) {
  $$('[data-crra-batch-status], [data-crra-batch-effect], [data-crra-batch-confidence], [data-crra-batch-reason]').forEach((control) => {
    control.classList.remove("validation-target");
    control.removeAttribute("aria-invalid");
  });
  $$('[data-crra-batch-error]').forEach((box) => box.classList.add("hidden"));
  const errors = new Map();
  const reviews = mappings.map((item) => {
    const draft = crraMappingDraftFor(item);
    const review = {
      item_id: Number(item.id),
      status: draft.status,
      effect: draft.effect,
      confidence: draft.confidence,
      reason: draft.reason.trim(),
      expected: {
        status: draft.savedStatus,
        effect: draft.savedEffect,
        confidence: draft.savedConfidence,
        reason: draft.savedReason.trim(),
      },
    };
    if (!["UNREVIEWED", "INCLUDED", "EXCLUDED"].includes(review.status)) errors.set(String(item.id), { message: "검토 상태를 선택해 주세요.", field: "status" });
    else if (!EFFECT_OPTIONS.some(([value]) => value === review.effect)) errors.set(String(item.id), { message: "P/D/R 효과를 선택해 주세요.", field: "effect" });
    else if (!CONFIDENCE_OPTIONS.some(([value]) => value === review.confidence)) errors.set(String(item.id), { message: "효과 신뢰도를 선택해 주세요.", field: "confidence" });
    else if (review.status !== "UNREVIEWED" && !review.reason) errors.set(String(item.id), { message: "포함 또는 제외 판정에는 판단 근거가 필요합니다.", field: "reason" });
    else if (review.reason.length > 10000) errors.set(String(item.id), { message: "판단 근거는 10,000자 이내로 입력해 주세요.", field: "reason" });
    return review;
  });
  const itemById = new Map(mappings.map((item) => [Number(item.id), item]));
  const relationKeys = new Map();
  reviews.forEach((review) => {
    const item = itemById.get(review.item_id);
    const key = `${vectorId(item)}\u0000${countermeasureId(item)}\u0000${review.effect}`;
    const previous = relationKeys.get(key);
    if (previous !== undefined) {
      errors.set(String(previous), { message: "같은 AV–대응책에 동일한 효과 행이 중복됩니다.", field: "effect" });
      errors.set(String(review.item_id), { message: "같은 AV–대응책에 동일한 효과 행이 중복됩니다.", field: "effect" });
    } else relationKeys.set(key, review.item_id);
  });
  if (!errors.size) return reviews;
  state.crraMappingFilter = "ALL";
  state.crraMappingQuery = "";
  const filter = $("#crra-mapping-filter");
  const search = $("#crra-mapping-search");
  if (filter) filter.value = "ALL";
  if (search) search.value = "";
  applyCrraMappingFilters(mappings);
  const fieldAttribute = { status: "status", effect: "effect", confidence: "confidence", reason: "reason" };
  errors.forEach((error, id) => {
    const control = $(`[data-crra-batch-${fieldAttribute[error.field]}="${id}"]`);
    control?.classList.add("validation-target");
    control?.setAttribute("aria-invalid", "true");
    const box = $(`[data-crra-batch-error="${id}"]`);
    if (box) { box.textContent = error.message; box.classList.remove("hidden"); }
  });
  const firstId = errors.keys().next().value;
  const firstError = errors.get(firstId);
  const firstControl = $(`[data-crra-batch-${fieldAttribute[firstError.field]}="${firstId}"]`);
  firstControl?.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
  firstControl?.focus({ preventScroll: true });
  toast(`저장할 수 없는 항목이 ${errors.size}개 있습니다.`, true);
  return null;
}

function crraMappingHasDownstreamResults() {
  const settings = crraSettings();
  if (Number(settings.current_step || 0) >= 4 || crraSolution()) return true;
  return crraCountermeasures().some((item) => item.cost_score !== null && item.cost_score !== undefined);
}

async function saveCrraMappingBatch() {
  const mappings = crraMappings();
  const reviews = validateCrraMappingReviews(mappings);
  if (!reviews) return;
  if (crraMappingDraftIsDirty() && crraMappingHasDownstreamResults()
      && !window.confirm("이 판정을 변경하면 기존 CRRA 비용 및 효용 점수와 최종 대응책 조합이 초기화됩니다. 계속할까요?")) return;
  state.crraMappingBatchSaving = true;
  state.crraMappingBatchError = "";
  renderCrraAmendMappingsStep();
  try {
    const result = await api(`/api/assessments/${state.assessmentId}/crra/mappings/reviews`, { method: "PUT", body: { reviews } });
    if (result?.workspace) state.crra = result.workspace;
    let refreshError = null;
    try {
      await reloadWorkspace();
      if (!result?.workspace) await reloadCrra();
    } catch (error) {
      refreshError = error;
    }
    resetCrraMappingDrafts();
    state.crraUiDirty = false;
    renderWorkspace();
    const unreviewed = Number(result?.unreviewed_count ?? crraMappings().filter((item) => String(item.review_status).toUpperCase() === "UNREVIEWED").length);
    if (refreshError) {
      toast(`모든 검토값은 DB에 저장됐지만 최신 화면을 다시 불러오지 못했습니다. 화면을 새로고침해 주세요. (${refreshError.message})`, true);
    } else {
      toast(unreviewed ? `전체 입력값을 저장했습니다. 미검토 ${unreviewed}개를 마저 판정해 주세요.` : "모든 대응책 후보 판정을 한 번에 저장했습니다.");
    }
  } catch (error) {
    state.crraMappingBatchSaving = false;
    state.crraMappingBatchError = error.message;
    renderCrraAmendMappingsStep();
    toast(error.message, true);
  }
}

async function requestCrraMappingBatchSuggestions() {
  const mappings = crraMappings();
  if (!mappings.length) return;
  if (crraMappingDraftIsDirty() && !window.confirm("현재 입력 중인 값을 LLM 전체 초안으로 덮어쓸까요?")) return;
  if (!window.confirm("모든 공격 벡터–대응책 관계와 평가 Scope, 위험 점수, Attack Case 경로가 설정된 외부 LLM에 전송됩니다. 전체 초안을 요청할까요?")) return;
  state.crraMappingBatchLoading = true;
  state.crraMappingBatchError = "";
  renderCrraAmendMappingsStep();
  try {
    const result = await api(`/api/assessments/${state.assessmentId}/crra/llm/mappings`, { method: "POST", body: {} });
    const suggestions = normalizeCrraBatchSuggestions(mappings, result?.suggestions);
    mappings.forEach((item) => {
      const suggestion = suggestions.get(String(item.id));
      updateCrraMappingDraft(item, suggestion, "LLM");
      state.crraLlmSuggestions[String(item.id)] = { ...suggestion, _llm: suggestion.provenance };
    });
    state.crraMappingBatchLoading = false;
    state.crraMappingBatchError = "";
    renderCrraAmendMappingsStep();
    toast("모든 대응책 후보의 LLM 초안을 채웠습니다. 확인한 뒤 저장하세요.");
  } catch (error) {
    state.crraMappingBatchLoading = false;
    state.crraMappingBatchError = error.message;
    renderCrraAmendMappingsStep();
    toast(error.message, true);
  }
}

async function ensureKm() {
  if (!state.km) state.km = await api("/api/km");
  return state.km;
}

async function showCrraMappingModal() {
  try { await ensureKm(); } catch (error) { toast(error.message, true); return; }
  $("#crra-mapping-modal")?.remove();
  const vectors = crraVectors().filter((item) => item.selected !== false);
  const cms = Array.isArray(state.km?.countermeasures) ? state.km.countermeasures : [];
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="crra-mapping-modal"><div class="modal"><div class="modal-header"><div><h2>평가 전용 대응책 연결 추가</h2><div class="small-text muted">여기서 추가한 내용은 현재 평가에만 적용되며 공용 KM은 바뀌지 않습니다.</div></div><button class="btn small" data-close-crra-mapping>닫기</button></div><form id="crra-mapping-form"><div class="modal-body form-grid">
    <div class="form-field"><label class="required">공격 벡터</label><select id="crra-new-av">${vectors.map((item) => `<option value="${escapeHtml(vectorId(item))}">${escapeHtml(vectorCatalogId(item))} ${escapeHtml(vectorName(item))}</option>`).join("")}</select></div>
    <div class="form-field"><label class="required">기존 KM 대응책</label><select id="crra-new-cm">${cms.map((item) => `<option value="${escapeHtml(countermeasureId(item))}">${escapeHtml(countermeasureId(item))} ${escapeHtml(countermeasureName(item))}</option>`).join("")}</select></div>
    <label class="check-card full"><input type="checkbox" id="crra-custom-cm"><span><strong>이 평가에만 쓸 새 대응책 입력</strong><span>공용 KM에 없는 대응책이 필요할 때 선택합니다. KM 반영은 별도 검토가 필요합니다.</span></span></label>
    <div class="form-field hidden" data-custom-cm-field><label class="required">새 대응책 이름</label><input id="crra-custom-cm-name"></div><div class="form-field hidden" data-custom-cm-field><label class="required">출처</label><input id="crra-custom-cm-source" value="평가 한정"></div><div class="form-field full hidden" data-custom-cm-field><label class="required">새 대응책 설명</label><textarea id="crra-custom-cm-description"></textarea><div class="input-help">평가 전용 ID는 저장할 때 CloudTARA가 자동으로 만듭니다.</div></div>
    <div class="form-field"><label class="required">대응 효과</label><select id="crra-new-effect">${optionsMarkup(EFFECT_OPTIONS, "", "효과 선택")}</select></div><div class="form-field"><label class="required">신뢰도</label><select id="crra-new-confidence">${optionsMarkup(CONFIDENCE_OPTIONS, "", "신뢰도 선택")}</select></div>
    <div class="form-field full"><label class="required">추가 근거</label><textarea id="crra-new-reason" placeholder="이 공격 벡터에 해당 대응책을 연결하는 이유"></textarea></div>
  </div><div class="modal-footer"><button type="button" class="btn" data-close-crra-mapping>취소</button><button class="btn primary" type="submit">대응책 연결 추가</button></div></form></div></div>`);
  $$('[data-close-crra-mapping]').forEach((button) => button.onclick = () => $("#crra-mapping-modal")?.remove());
  $("#crra-custom-cm").onchange = (event) => {
    $$('[data-custom-cm-field]').forEach((field) => field.classList.toggle("hidden", !event.target.checked));
    $("#crra-new-cm").disabled = event.target.checked;
  };
  $("#crra-mapping-form").onsubmit = addCrraMapping;
}

async function addCrraMapping(event) {
  event.preventDefault();
  const custom = $("#crra-custom-cm").checked;
  const body = {
    av_id: $("#crra-new-av").value,
    effect: $("#crra-new-effect").value,
    confidence: $("#crra-new-confidence").value,
    reason: $("#crra-new-reason").value.trim(),
  };
  if (!body.effect || !body.confidence || !body.reason) { toast("대응 효과, 신뢰도와 추가 근거를 입력해 주세요.", true); return; }
  if (custom) {
    const name = $("#crra-custom-cm-name").value.trim();
    const description = $("#crra-custom-cm-description").value.trim();
    const source = $("#crra-custom-cm-source").value.trim();
    if (!name || !description || !source) { toast("새 대응책의 이름, 설명과 출처를 입력해 주세요.", true); return; }
    body.countermeasure = { name, description, source };
  } else body.cm_id = $("#crra-new-cm").value;
  try {
    await api(`/api/assessments/${state.assessmentId}/crra/mappings`, { method: "POST", body });
    $("#crra-mapping-modal")?.remove();
    await Promise.all([reloadWorkspace(), reloadCrra()]);
    resetCrraMappingDrafts();
    renderWorkspace();
    toast("평가 전용 대응책 연결을 추가했습니다.");
  } catch (error) { toast(error.message, true); }
}

async function completeCrraMappings() {
  if (crraMappingDraftIsDirty()) { toast("변경한 대응책 후보 판정을 먼저 전체 저장해 주세요.", true); return; }
  try {
    await api(`/api/assessments/${state.assessmentId}/crra/mappings/complete`, { method: "POST", body: {} });
    await Promise.all([reloadWorkspace(), reloadCrra()]);
    state.crraStep = 4;
    renderWorkspace();
    toast("대응책 후보 검토를 마쳤습니다.");
  } catch (error) { toast(error.message, true); }
}

function scoringCountermeasures() {
  const included = crraMappings().filter((item) => String(item.review_status || "").toUpperCase() === "INCLUDED");
  const includedIds = new Set(included.map(countermeasureId));
  const scored = crraCountermeasures().filter((item) => includedIds.has(countermeasureId(item)));
  if (scored.length || includedIds.size === 0) return scored;
  const result = new Map();
  included.forEach((item) => {
    const id = countermeasureId(item);
    if (!result.has(id)) result.set(id, { countermeasure_id: id, name: countermeasureName(item), cost_score: null, cost_reason: "" });
  });
  return [...result.values()];
}

function renderCrraScoringStep() {
  const settings = crraSettings();
  const countermeasures = scoringCountermeasures();
  const noVectors = crraVectors().filter((item) => item.selected !== false).length === 0;
  const preventWeight = settings.prevent_weight ?? 1;
  const respondWeight = settings.respond_weight ?? 1;
  const strategy = String(settings.strategy || "BANG_FOR_BUCK").toUpperCase();
  const costRows = countermeasures.map((item, index) => {
    const id = countermeasureId(item);
    const cost = item.cost_score ?? item.cost;
    const costLabels = ["", "매우 낮음", "낮음", "중간", "높음", "매우 높음"];
    const scale = [1, 2, 3, 4, 5].map((value) => `<label class="crra-cost-choice"><input type="radio" name="crra-cost-${index}" value="${value}" aria-label="${escapeHtml(countermeasureName(item))} 비용 ${costLabels[value]} ${value}점" ${Number(cost) === value ? "checked" : ""}><span><strong>${value}</strong>${costLabels[value]}</span></label>`).join("");
    return `<tr><td><div class="vector-id">${escapeHtml(id)}</div><div class="vector-name">${escapeHtml(countermeasureName(item))}</div></td><td><div class="crra-cost-scale" data-crra-cost-group="${escapeHtml(id)}" role="group" aria-label="${escapeHtml(countermeasureName(item))} 비용 점수">${scale}</div></td><td><input data-crra-cost-reason="${escapeHtml(id)}" value="${escapeHtml(item.cost_reason || "")}" placeholder="이 비용 점수를 선택한 근거"></td></tr>`;
  }).join("");
  const ranked = countermeasures.filter((item) => item.rank !== null && item.rank !== undefined && item.cost_score !== null && item.cost_score !== undefined && item.utility !== null && item.utility !== undefined).sort((a, b) => Number(a.rank) - Number(b.rank));
  const resultRows = ranked.map((item) => `<tr><td><span class="matrix-rank">${escapeHtml(item.rank)}</span></td><td><div class="vector-id">${escapeHtml(countermeasureId(item))}</div><div class="vector-name">${escapeHtml(countermeasureName(item))}</div></td><td><div class="crra-effect-counts"><span class="badge blue">P 예방 ${escapeHtml(item.prevent_count ?? 0)}</span><span class="badge">D 탐지 ${escapeHtml(item.detect_count ?? 0)}</span><span class="badge green">R 대응 ${escapeHtml(item.respond_count ?? 0)}</span></div></td><td><strong>${escapeHtml(formatRiskNumber(item.utility))}</strong></td><td>${escapeHtml(formatRiskNumber(item.cost_score ?? item.cost))}</td><td><strong>${escapeHtml(formatRiskNumber(item.uc_ratio, 2))}</strong></td></tr>`).join("");
  const canGoSolution = ranked.length > 0 || (countermeasures.length === 0 && Number(settings.current_step || 0) >= 4);
  const emptyCostMessage = noVectors
    ? emptyState("평가할 대응책이 없습니다", "매트릭스가 비어 있습니다. 계산값을 저장한 뒤 빈 대응 효과표까지 진행할 수 있습니다.")
    : emptyState("포함된 대응책이 없습니다", "이전 화면에서 모든 대응책 연결을 제외했습니다. 빈 계산 결과를 저장한 뒤 미충족 항목을 검토할 수 있습니다.");
  $("#step-content").innerHTML = `${pageHeader("2.4 대응책 비용 및 효과 평가", "대응책의 비용 점수를 저장하고 우선순위를 계산합니다.", `<button class="btn primary" id="crra-score">계산 및 저장</button><button class="btn" id="crra-go-solution" aria-disabled="${canGoSolution ? "false" : "true"}">대응책 조합으로 이동</button>`)}<div class="page-body">${crraInternalNotice()}<div class="notice info"><div>i</div><div><strong>효용 = 예방 건수 × 예방 가중치 + 대응 건수 × 대응 가중치</strong>탐지 효과와 신뢰도는 연결 정보로 보존하지만 이 계산에는 넣지 않습니다. 비용은 금액이 아니라 1점부터 5점까지의 수명주기 비용 점수입니다.</div></div><div class="card"><div class="card-header"><div><h2>가중치와 정렬 기준</h2><div class="small-text muted">가중치는 0보다 큰 값입니다.</div></div></div><div class="card-body"><div class="crra-score-config"><div class="form-field"><label>예방(P) 가중치</label><input id="crra-prevent-weight" type="number" min="0.1" step="0.1" value="${escapeHtml(preventWeight)}"></div><div class="form-field"><label>대응(R) 가중치</label><input id="crra-respond-weight" type="number" min="0.1" step="0.1" value="${escapeHtml(respondWeight)}"></div><div class="form-field"><label>정렬 기준</label><select id="crra-reorder-strategy">${optionsMarkup(REORDER_STRATEGIES, strategy)}</select></div></div></div></div><div class="card"><div class="card-header"><div><h2>비용 점수</h2><div class="small-text muted">1 매우 낮음, 2 낮음, 3 중간, 4 높음, 5 매우 높음</div></div><span class="count-pill">${countermeasures.length}개</span></div><div class="card-body">${costRows ? `<table class="data-table crra-cost-table"><thead><tr><th>대응책</th><th>비용 점수</th><th>판단 근거</th></tr></thead><tbody>${costRows}</tbody></table>` : emptyCostMessage}</div></div>${ranked.length ? `<div class="card"><div class="card-header"><div><h2>우선순위 결과</h2><div class="small-text muted">비용 대비 효용은 소수점 둘째 자리까지 표시합니다.</div></div></div><div class="card-body"><table class="data-table crra-ranked-table"><thead><tr><th>순위</th><th>대응책</th><th>효과 범위</th><th>효용</th><th>비용</th><th>비용 대비 효용</th></tr></thead><tbody>${resultRows}</tbody></table></div></div>` : ""}</div>`;
  $("#crra-score").onclick = scoreCrraCountermeasures;
  if ($("#crra-go-solution")) $("#crra-go-solution").onclick = () => { if (!canGoSolution) { explainCrraBlock(5); return; } state.crraStep = 5; renderWorkspace(); };
}

async function scoreCrraCountermeasures() {
  const preventWeight = Number($("#crra-prevent-weight").value);
  const respondWeight = Number($("#crra-respond-weight").value);
  $$("#crra-prevent-weight, #crra-respond-weight, [data-crra-cost-group], [data-crra-cost-reason]").forEach((control) => {
    control.classList.remove("validation-target");
    control.removeAttribute("aria-invalid");
  });
  if (!Number.isFinite(preventWeight) || preventWeight <= 0 || !Number.isFinite(respondWeight) || respondWeight <= 0) {
    const invalidWeights = [$("#crra-prevent-weight"), $("#crra-respond-weight")].filter((input) => !Number.isFinite(Number(input?.value)) || Number(input?.value) <= 0);
    invalidWeights.forEach((input) => { input.classList.add("validation-target"); input.setAttribute("aria-invalid", "true"); });
    invalidWeights[0]?.focus();
    toast("P/R 가중치는 0보다 큰 숫자로 입력해 주세요.", true);
    return;
  }
  const costs = {};
  const invalidControls = [];
  for (const group of $$('[data-crra-cost-group]')) {
    const id = group.dataset.crraCostGroup;
    const score = Number(group.querySelector('input[type="radio"]:checked')?.value);
    const reasonInput = $$('[data-crra-cost-reason]').find((input) => input.dataset.crraCostReason === id);
    const reason = reasonInput?.value.trim() || "";
    if (!Number.isInteger(score) || score < 1 || score > 5) invalidControls.push(group);
    if (!reason && reasonInput) invalidControls.push(reasonInput);
    costs[id] = { score, reason };
  }
  if (invalidControls.length) {
    invalidControls.forEach((control) => { control.classList.add("validation-target"); control.setAttribute("aria-invalid", "true"); });
    invalidControls[0].scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
    if (invalidControls[0].matches("input, select, textarea")) invalidControls[0].focus({ preventScroll: true });
    toast("비용 점수 또는 판단 근거가 비어 있는 항목을 확인해 주세요.", true);
    return;
  }
  try {
    await api(`/api/assessments/${state.assessmentId}/crra/score`, { method: "POST", body: { prevent_weight: preventWeight, respond_weight: respondWeight, strategy: $("#crra-reorder-strategy").value, costs } });
    await Promise.all([reloadWorkspace(), reloadCrra()]);
    renderWorkspace();
    toast("대응책의 비용 및 효용 점수와 우선순위를 저장했습니다.");
  } catch (error) { toast(error.message, true); }
}

function solutionData() { return crraSolution()?.data || crraSolution() || {}; }

function selectedSolutionIds() {
  const data = solutionData();
  if (Array.isArray(data.selected_countermeasure_ids)) return data.selected_countermeasure_ids.map(String);
  return crraCountermeasures().filter((item) => item.selected).map(countermeasureId);
}

function effectSummaryForCountermeasure(cmId) {
  const mappings = crraMappings().filter((item) => countermeasureId(item) === String(cmId) && includedMapping(item));
  const counts = { PREVENT: 0, DETECT: 0, RESPOND: 0 };
  mappings.forEach((item) => { const effect = normalizeEffect(item.effect); if (Object.hasOwn(counts, effect)) counts[effect] += 1; });
  return { mappings, counts };
}

function effectSummaryMarkup(cmId) {
  const { mappings, counts } = effectSummaryForCountermeasure(cmId);
  if (!mappings.length) return `<span class="muted">연결 없음</span>`;
  const details = mappings.map((item) => `<span><strong>${escapeHtml(vectorCatalogId(item))}</strong>, ${escapeHtml(effectLabel(item.effect))}, ${escapeHtml(confidenceLabel(item.confidence))}</span>`).join("");
  return `<details class="crra-effect-details"><summary>연결 ${mappings.length}개, 예방 ${counts.PREVENT}, 탐지 ${counts.DETECT}, 대응 ${counts.RESPOND}</summary><div>${details}</div></details>`;
}

function renderCrraSolutionStep() {
  const settings = crraSettings();
  const solution = crraSolution();
  const data = solutionData();
  const countermeasures = scoringCountermeasures().filter((item) => item.cost_score !== null && item.cost_score !== undefined).sort((a, b) => Number(a.rank || 9999) - Number(b.rank || 9999));
  const selectedIds = new Set(selectedSolutionIds());
  const solutionRows = Array.isArray(data.rows) ? data.rows : Array.isArray(solution?.rows) ? solution.rows : [];
  const confirmed = Boolean(state.workspace.assessment.crra_confirmed || String(solution?.status || settings.status || "").toUpperCase() === "CONFIRMED");
  const savedCriteria = data.criteria || {};
  const criteria = {
    min_total: Number(savedCriteria.total ?? savedCriteria.min_total ?? settings.min_total ?? 1),
    min_prevent: Number(savedCriteria.prevent ?? savedCriteria.min_prevent ?? settings.min_prevent ?? 0),
    min_respond: Number(savedCriteria.respond ?? savedCriteria.min_respond ?? settings.min_respond ?? 0),
  };
  const selectionRows = countermeasures.map((item) => `<tr><td><label class="solution-select"><input type="checkbox" data-solution-cm value="${escapeHtml(countermeasureId(item))}" ${selectedIds.has(countermeasureId(item)) ? "checked" : ""}><span class="matrix-rank">${escapeHtml(item.rank ?? "-")}</span></label></td><td><div class="vector-id">${escapeHtml(countermeasureId(item))}</div><div class="vector-name">${escapeHtml(countermeasureName(item))}</div></td><td><div class="crra-metric-summary"><span>효용 <strong>${escapeHtml(formatRiskNumber(item.utility))}</strong></span><span>비용 <strong>${escapeHtml(formatRiskNumber(item.cost_score ?? item.cost))}</strong></span><span>비용 대비 효용 <strong>${escapeHtml(formatRiskNumber(item.uc_ratio, 2))}</strong></span></div></td><td class="crra-effect-summary">${effectSummaryMarkup(countermeasureId(item))}</td></tr>`).join("");
  const coverageRows = solutionRows.map((row) => {
    const met = Boolean(row.met ?? row.satisfied);
    const counts = row.effect_counts || {};
    const gaps = Array.isArray(row.gaps) ? row.gaps : row.gap ? [row.gap] : [];
    const criterionLabels = { TOTAL: "전체 대응책", PREVENT: "예방(P)", RESPOND: "대응(R)" };
    const gapText = gaps.map((gap) => typeof gap === "string" ? gap : gap?.criterion ? `${criterionLabels[gap.criterion] || gap.criterion} ${gap.actual ?? "-"}/${gap.required ?? "-"}` : gap?.message || JSON.stringify(gap)).join(", ");
    return `<tr><td><div class="vector-id">${escapeHtml(vectorCatalogId(row))}</div><div class="vector-name">${escapeHtml(vectorName(row))}</div></td><td>${escapeHtml(formatRiskNumber(row.risk_score ?? row.representative_score))}</td><td><div class="crra-effect-counts"><span class="badge">전체 ${escapeHtml(row.total_count ?? counts.total ?? 0)}</span><span class="badge blue">P 예방 ${escapeHtml(row.prevent_count ?? counts.prevent ?? 0)}</span><span class="badge green">R 대응 ${escapeHtml(row.respond_count ?? counts.respond ?? 0)}</span></div></td><td><span class="badge ${met ? "green" : "red"}">${met ? "기준 충족" : "기준 미충족"}</span>${gapText ? `<div class="small-text muted crra-gap-detail">${escapeHtml(gapText)}</div>` : ""}</td></tr>`;
  }).join("");
  const hasGaps = Boolean(data.has_gaps ?? solutionRows.some((row) => !(row.met ?? row.satisfied)));
  const totalCost = data.total_cost ?? solution?.total_cost;
  const noVectors = crraVectors().filter((item) => item.selected !== false).length === 0;
  const emptySelectionMessage = noVectors ? emptyState("선택할 대응책이 없습니다", "확정 매트릭스에 공격 벡터가 없어 빈 조합으로 진행합니다.") : emptyState("계산된 대응책이 없습니다", "포함한 대응책과 비용 점수를 확인하세요.");
  const emptyCoverageMessage = noVectors ? emptyState("대응 효과표에 표시할 항목이 없습니다", "확정 매트릭스가 비어 있어 총 비용 점수 0의 빈 결과를 확정할 수 있습니다.") : emptyState("아직 계산된 조합이 없습니다", "선택 기준을 확인하고 대응책 조합을 계산해 주세요.");
  $("#step-content").innerHTML = `${pageHeader("2.5 최종 대응책 조합", "대응책 조합과 공격 벡터별 기준 충족 여부를 확인합니다.", `<button class="btn primary" id="crra-generate-solution">${solution ? "현재 선택으로 다시 계산" : "대응책 조합 만들기"}</button>${solution ? `<button class="btn success" id="crra-confirm-solution" ${confirmed ? "disabled" : ""}>${confirmed ? "TARA 분석 완료" : "최종 결과 확정"}</button>` : ""}`)}<div class="page-body">${crraInternalNotice()}<div class="card"><div class="card-header"><div><h2>대응책 선택 기준</h2><div class="small-text muted">공격 벡터마다 필요한 최소 대응책 수입니다.</div></div></div><div class="card-body"><div class="crra-solution-config"><div class="form-field"><label>공격 벡터당 최소 대응책</label><input id="crra-min-total" type="number" min="0" step="1" value="${criteria.min_total}"></div><div class="form-field"><label>그중 최소 예방(P) 대응책</label><input id="crra-min-prevent" type="number" min="0" step="1" value="${criteria.min_prevent}"></div><div class="form-field"><label>그중 최소 대응(R) 대응책</label><input id="crra-min-respond" type="number" min="0" step="1" value="${criteria.min_respond}"></div></div></div></div><div class="card"><div class="card-header"><div><h2>대응책 조합 검토</h2><div class="small-text muted">체크박스를 바꾼 뒤 현재 선택으로 다시 계산할 수 있습니다.</div></div><span class="count-pill">선택 ${selectedIds.size}/${countermeasures.length}</span></div><div class="card-body">${selectionRows ? `<table class="data-table solution-cm-table"><thead><tr><th>선택 및 순위</th><th>대응책</th><th>계산값</th><th>연결 효과</th></tr></thead><tbody>${selectionRows}</tbody></table>` : emptySelectionMessage}</div></div>${solution ? `<div class="card solution-card"><div class="card-header"><div><h2>대응책 효과표</h2><div class="small-text muted">각 대응책 비용은 한 번만 합산합니다.</div></div><div class="solution-total"><span>총 비용 점수</span><strong>${escapeHtml(formatRiskNumber(totalCost))}</strong></div></div><div class="card-body">${coverageRows ? `<table class="data-table crra-coverage-table"><thead><tr><th>공격 벡터</th><th>위험 점수</th><th>선택 효과</th><th>기준 충족 여부</th></tr></thead><tbody>${coverageRows}</tbody></table>` : emptyCoverageMessage}<div class="form-field gap-reason-field"><label>${hasGaps ? "미충족 기준 처리 사유 (필수)" : "최종 검토 메모 (선택)"}</label><textarea id="crra-gap-reason" placeholder="추가 대응책 검토, 기준 조정, 잔여 위험 수용 등">${escapeHtml(settings.gap_reason || "")}</textarea></div></div></div>` : ""}</div>`;
  $("#crra-generate-solution").onclick = generateCrraSolution;
  if ($("#crra-confirm-solution")) $("#crra-confirm-solution").onclick = () => confirmCrraSolution(hasGaps);
}

async function generateCrraSolution() {
  const values = [$("#crra-min-total"), $("#crra-min-prevent"), $("#crra-min-respond")].map((input) => Number(input.value));
  if (values.some((value) => !Number.isInteger(value) || value < 0)) { toast("선택 기준은 0 이상의 정수로 입력해 주세요.", true); return; }
  const body = { min_total: values[0], min_prevent: values[1], min_respond: values[2] };
  if (crraSolution()) body.selected_countermeasure_ids = $$('[data-solution-cm]').filter((box) => box.checked).map((box) => box.value);
  try {
    await api(`/api/assessments/${state.assessmentId}/crra/solution`, { method: "POST", body });
    await Promise.all([reloadWorkspace(), reloadCrra()]);
    renderWorkspace();
    toast("대응책 조합과 기준 충족 여부를 계산했습니다.");
  } catch (error) { toast(error.message, true); }
}

async function confirmCrraSolution(hasGaps) {
  const gapReason = $("#crra-gap-reason")?.value.trim() || "";
  if (hasGaps && !gapReason) { toast("미충족 기준을 처리하거나 잔여 위험으로 수용할 사유를 입력해 주세요.", true); return; }
  try {
    await api(`/api/assessments/${state.assessmentId}/crra/solution/confirm`, { method: "POST", body: { gap_reason: gapReason } });
    await Promise.all([reloadWorkspace(), reloadCrra()]);
    state.assessments = await api("/api/assessments");
    renderWorkspace();
    toast("최종 대응책 효과표를 확정했습니다.");
  } catch (error) { toast(error.message, true); }
}

function kmAttackVectors() { return Array.isArray(state.km?.attack_vectors) ? state.km.attack_vectors : []; }
function kmCountermeasures() { return Array.isArray(state.km?.countermeasures) ? state.km.countermeasures : []; }
function kmMappings() { return Array.isArray(state.km?.mappings) ? state.km.mappings : []; }
function kmVectorGroups() { return Array.isArray(state.km?.vector_groups) ? state.km.vector_groups : []; }
function kmAssetTypes() { return Array.isArray(state.km?.asset_types) ? state.km.asset_types : (state.bootstrap?.asset_types || []); }
function kmAssetMappings() { return Array.isArray(state.km?.asset_mappings) ? state.km.asset_mappings : []; }
function kmAdminCanWrite() { return state.bootstrap?.km_admin_enabled === true; }

async function openKmAdmin() {
  try {
    state.km = await api("/api/km");
    state.kmMode = true;
    state.kmTab = "asset-mappings";
    state.kmSearch = "";
    renderKmAdmin();
  } catch (error) { toast(error.message, true); }
}

async function reloadKm() { state.km = await api("/api/km"); }

function kmMatches(item, query) {
  if (!query) return true;
  return Object.values(item || {}).some((value) => typeof value === "string" && value.toLowerCase().includes(query));
}

function renderKmAdmin() {
  const release = state.km?.release;
  const releaseName = typeof release === "string" ? release : release?.name || state.bootstrap?.km_releases?.[0]?.name || "Cloud-Native KM";
  const canWrite = kmAdminCanWrite();
  const tabMarkup = state.kmTab === "asset-mappings" ? kmAssetMappingsMarkup()
    : state.kmTab === "catalog" ? kmCatalogMarkup()
      : state.kmTab === "mappings" ? kmMappingsMarkup() : kmGroupsMarkup();
  $("#app").innerHTML = `<div class="app-shell km-admin-shell">
    <header class="topbar">
      ${homeBrandMarkup()}
      <div class="assessment-title">KM 관리</div>
      <div class="topbar-actions"><button class="btn ghost-dark small" id="km-dashboard">평가 목록</button><span class="dashboard-action-divider" aria-hidden="true"></span>${themeSwitcherMarkup("km-theme")}</div>
    </header>
    <main class="km-admin-main">
      <div class="km-admin-heading">
        <div><h1>KM 관리 <span>ADMIN</span></h1><p>DFD 자산에서 공격 벡터 후보를 만들고, 검토된 대응책까지 이어지는 공용 지식을 확인합니다.</p></div>
        <div class="km-release-chip"><span>사용 중인 카탈로그</span><strong>${escapeHtml(releaseName)}</strong></div>
      </div>
      <section class="km-access-banner ${canWrite ? "editable" : "readonly"}">
        <div class="km-access-icon" aria-hidden="true">${canWrite ? "AD" : "RO"}</div>
        <div><strong>${canWrite ? "관리자 편집 모드" : "안전한 읽기 전용"}</strong><span>${canWrite ? "여기서 저장한 변경은 모든 평가와 사용자에게 공통으로 적용됩니다." : "현재 서버에서는 공용 KM을 조회하고 연결 CSV를 내려받을 수 있습니다. 편집은 서버 운영자가 별도로 관리자 모드를 연 경우에만 가능합니다."}</span></div>
        <span class="badge ${canWrite ? "green" : "blue"}">${canWrite ? "편집 가능" : "조회 전용"}</span>
      </section>
      <section class="km-summary-grid" aria-label="KM 현황">
        <div><span>DFD 자산 유형</span><strong>${kmAssetTypes().length}</strong></div>
        <div><span>자산별 공격 벡터 연결</span><strong>${kmAssetMappings().length}</strong></div>
        <div><span>공격 벡터와 대응책</span><strong>${kmAttackVectors().length} / ${kmCountermeasures().length}</strong></div>
        <div><span>대응책 연결 근거</span><strong>${kmMappings().length}</strong></div>
      </section>
      <div class="tabs km-tabs" role="tablist" aria-label="KM 관리 영역">
        <button class="tab ${state.kmTab === "asset-mappings" ? "active" : ""}" data-km-tab="asset-mappings" role="tab" aria-selected="${state.kmTab === "asset-mappings"}">자산별 공격 벡터</button>
        <button class="tab ${state.kmTab === "catalog" ? "active" : ""}" data-km-tab="catalog" role="tab" aria-selected="${state.kmTab === "catalog"}">공격 벡터와 대응책</button>
        <button class="tab ${state.kmTab === "mappings" ? "active" : ""}" data-km-tab="mappings" role="tab" aria-selected="${state.kmTab === "mappings"}">대응책 연결</button>
        <button class="tab ${state.kmTab === "groups" ? "active" : ""}" data-km-tab="groups" role="tab" aria-selected="${state.kmTab === "groups"}">공격 벡터 그룹</button>
      </div>
      <section id="km-tab-content">${tabMarkup}</section>
    </main>
  </div>`;
  bindHomeNavigation();
  $("#km-dashboard").onclick = () => goHome();
  bindThemeSwitcher("km-theme");
  $$('[data-km-tab]').forEach((button) => button.onclick = () => { state.kmTab = button.dataset.kmTab; state.kmSearch = ""; renderKmAdmin(); });
  bindKmAdminEvents();
}

function kmSearchToolbar(placeholder, actions = "") {
  return `<div class="km-toolbar"><div class="form-field km-search"><label>목록 검색</label><div><input id="km-search" value="${escapeHtml(state.kmSearch)}" placeholder="${escapeHtml(placeholder)}"><button class="btn small" id="km-search-apply">찾기</button><button class="btn small" id="km-search-clear">검색 지우기</button></div></div>${actions ? `<div class="km-toolbar-actions">${actions}</div>` : ""}</div>`;
}

function kmCatalogMarkup() {
  const canWrite = kmAdminCanWrite();
  const query = state.kmSearch.trim().toLowerCase();
  const vectors = kmAttackVectors().filter((item) => kmMatches(item, query));
  const countermeasures = kmCountermeasures().filter((item) => kmMatches(item, query));
  const avRows = vectors.map((item) => `<tr><td><div class="vector-id">${escapeHtml(attackVectorCatalogId(item))}</div><div class="vector-name">${escapeHtml(item.name)}</div></td><td class="small-text"><div>${escapeHtml(compact(item.description))}</div>${vectorPrerequisiteMarkup(item)}</td><td><span class="source-reference"><span class="badge blue">${escapeHtml(compact(item.source))}</span>${attackVectorExternalId(item) ? `<small>출처 원본 ID: ${escapeHtml(attackVectorExternalId(item))}</small>` : ""}</span></td>${canWrite ? `<td><button class="btn small" data-edit-km-av="${escapeHtml(item.id)}">수정</button></td>` : ""}</tr>`).join("");
  const cmRows = countermeasures.map((item) => `<tr><td><div class="vector-id">${escapeHtml(item.id)}</div><div class="vector-name">${escapeHtml(item.name)}</div></td><td class="small-text">${escapeHtml(compact(item.description))}</td><td><span class="badge green">${escapeHtml(compact(item.source))}</span></td>${canWrite ? `<td><button class="btn small" data-edit-km-cm="${escapeHtml(item.id)}">수정</button></td>` : ""}</tr>`).join("");
  const actions = canWrite ? `<button class="btn" id="km-add-av">+ 공격 벡터 추가</button><button class="btn primary" id="km-add-cm">+ 대응책 추가</button>` : "";
  const actionHeader = canWrite ? "<th></th>" : "";
  const tableClass = canWrite ? "data-table" : "data-table km-readonly-table";
  return `${kmSearchToolbar("ID, 이름, 설명 또는 출처로 찾기", actions)}<div class="km-two-column"><div class="card"><div class="card-header"><div><h2>공격 벡터</h2><div class="small-text muted">평가에서 후보로 불러올 공격 기법과 설명</div></div><span class="count-pill">${vectors.length}/${kmAttackVectors().length}</span></div><div class="card-body km-scroll-body">${avRows ? `<table class="${tableClass}"><thead><tr><th>ID 및 이름</th><th>설명</th><th>출처</th>${actionHeader}</tr></thead><tbody>${avRows}</tbody></table>` : emptyState("공격 벡터가 없습니다", "검색 조건을 바꿔 다시 확인해 주세요.")}</div></div><div class="card"><div class="card-header"><div><h2>대응책</h2><div class="small-text muted">공격 벡터에 연결할 예방, 탐지 및 대응 수단</div></div><span class="count-pill">${countermeasures.length}/${kmCountermeasures().length}</span></div><div class="card-body km-scroll-body">${cmRows ? `<table class="${tableClass}"><thead><tr><th>ID 및 이름</th><th>설명</th><th>출처</th>${actionHeader}</tr></thead><tbody>${cmRows}</tbody></table>` : emptyState("대응책이 없습니다", "검색 조건을 바꿔 다시 확인해 주세요.")}</div></div></div>`;
}

function kmMappingsMarkup() {
  const canWrite = kmAdminCanWrite();
  const query = state.kmSearch.trim().toLowerCase();
  const mappings = kmMappings().filter((item) => kmMatches(item, query));
  const rows = mappings.map((item) => `<tr><td><div class="vector-id">${escapeHtml(vectorCatalogId(item))}</div><div class="vector-name">${escapeHtml(vectorName(item))}</div></td><td><div class="vector-id">${escapeHtml(countermeasureId(item))}</div><div class="vector-name">${escapeHtml(countermeasureName(item))}</div></td><td><div class="mapping-badge-stack"><span class="badge blue">${escapeHtml(effectLabel(item.effect))}</span><span class="badge">${escapeHtml(confidenceLabel(item.confidence))}</span><span class="badge ${String(item.review_status).toUpperCase() === "APPROVED" ? "green" : "orange"}">${escapeHtml(kmReviewLabel(item.review_status))}</span></div></td><td class="small-text km-rationale-cell">${escapeHtml(compact(item.rationale))}</td>${canWrite ? `<td><div class="mapping-actions"><button class="btn small" data-edit-km-mapping="${escapeHtml(item.id)}">수정</button><button class="btn small danger" data-delete-km-mapping="${escapeHtml(item.id)}">삭제</button></div></td>` : ""}</tr>`).join("");
  const actions = `<button class="btn" id="km-export-mappings">연결 CSV 내려받기</button>${canWrite ? `<button class="btn" id="km-import-mappings">CSV로 가져오기</button><button class="btn primary" id="km-add-mapping">+ 대응책 연결 추가</button>` : ""}`;
  return `${kmSearchToolbar("공격 벡터, 대응책 또는 근거로 찾기", actions)}<details class="km-csv-guide"><summary>CSV 파일 형식 보기</summary><div>필수 열: <code>av_id, cm_id, effect, confidence, rationale, review_status</code><br>효과는 예방, 탐지 또는 대응으로 저장하며 검토 상태는 검토 필요 또는 승인입니다.</div></details><div class="card"><div class="card-header"><div><h2>공격 벡터와 대응책 연결</h2><div class="small-text muted">대응 효과, 신뢰도와 연결 근거를 관리합니다.</div></div><span class="count-pill">${mappings.length}/${kmMappings().length}</span></div><div class="card-body km-scroll-body">${rows ? `<table class="data-table km-mapping-table ${canWrite ? "" : "km-readonly-table"}"><thead><tr><th>공격 벡터</th><th>대응책</th><th>효과, 신뢰도와 상태</th><th>연결 근거</th>${canWrite ? "<th></th>" : ""}</tr></thead><tbody>${rows}</tbody></table>` : emptyState("등록된 대응책 연결이 없습니다", "검색 조건을 바꿔 다시 확인해 주세요.")}</div></div>`;
}

function kmGroupsMarkup() {
  const canWrite = kmAdminCanWrite();
  const query = state.kmSearch.trim().toLowerCase();
  const groups = kmVectorGroups().filter((item) => kmMatches(item, query));
  const allGroups = new Map(kmVectorGroups().map((item) => [String(item.id), item]));
  const rows = groups.map((item) => `<tr><td><div class="vector-id">#${escapeHtml(item.id)}</div><div class="vector-name">${escapeHtml(item.name)}</div></td><td class="small-text">${escapeHtml(compact(item.description))}</td><td>${escapeHtml(item.parent_id ? allGroups.get(String(item.parent_id))?.name || item.parent_id : "최상위")}</td><td>${escapeHtml(Array.isArray(item.member_ids) ? item.member_ids.length : item.member_count ?? 0)}개</td>${canWrite ? `<td><div class="mapping-actions"><button class="btn small" data-edit-km-group="${escapeHtml(item.id)}">수정</button><button class="btn small" data-members-km-group="${escapeHtml(item.id)}">포함 항목 관리</button></div></td>` : ""}</tr>`).join("");
  return `${kmSearchToolbar("그룹 이름 또는 설명으로 찾기", canWrite ? `<button class="btn primary" id="km-add-group">+ 공격 벡터 그룹 추가</button>` : "")}<div class="card"><div class="card-header"><div><h2>공격 벡터 그룹</h2><div class="small-text muted">공격 벡터를 목적이나 기술 영역에 따라 묶어 관리합니다.</div></div><span class="count-pill">${groups.length}/${kmVectorGroups().length}</span></div><div class="card-body km-scroll-body">${rows ? `<table class="data-table ${canWrite ? "" : "km-readonly-table"}"><thead><tr><th>그룹</th><th>설명</th><th>상위 그룹</th><th>포함 항목</th>${canWrite ? "<th></th>" : ""}</tr></thead><tbody>${rows}</tbody></table>` : emptyState("공격 벡터 그룹이 없습니다", "아직 등록된 그룹이 없습니다.")}</div></div>`;
}

function kmAssetMappingsMarkup() {
  const canWrite = kmAdminCanWrite();
  const query = state.kmSearch.trim().toLowerCase();
  const mappings = kmAssetMappings().filter((item) => kmMatches(item, query));
  const rows = mappings.map((item) => {
    const asset = kmAssetTypes().find((candidate) => String(candidate.id) === String(item.asset_type_id));
    const vector = kmAttackVectors().find((candidate) => String(candidate.id) === String(item.attack_vector_id));
    const assetName = dfdDisplayName(item.asset_type_name, assetDisplayName(asset || item.asset_type_id));
    const vectorName = item.attack_vector_name || vector?.name || item.attack_vector_id;
    const groupName = item.group_name || asset?.group_name || "기타";
    const dfdKind = item.dfd_kind || asset?.dfd_kind || "-";
    const action = canWrite ? `<td><div class="mapping-actions"><button class="btn small" data-edit-km-asset-mapping data-asset-type-id="${escapeHtml(item.asset_type_id)}" data-attack-vector-id="${escapeHtml(item.attack_vector_id)}">수정</button><button class="btn small danger" data-delete-km-asset-mapping data-asset-type-id="${escapeHtml(item.asset_type_id)}" data-attack-vector-id="${escapeHtml(item.attack_vector_id)}">삭제</button></div></td>` : "";
    return `<tr><td><div class="vector-name">${escapeHtml(assetName)}</div><div class="small-text muted">${escapeHtml(dfdDisplayName(groupName, "기타"))}, ${escapeHtml(dfdKind)}</div></td><td><div class="vector-id">${escapeHtml(attackVectorCatalogId(item) || attackVectorCatalogId(vector))}</div><div class="vector-name">${escapeHtml(vectorName)}</div></td><td class="small-text km-rationale-cell">${escapeHtml(dfdDisplayName(compact(item.mapping_note, "근거 메모 없음"), "근거 메모 없음"))}</td>${action}</tr>`;
  }).join("");
  const actions = canWrite ? `<button class="btn primary" id="km-add-asset-mapping">+ 자산 후보 연결 추가</button>` : "";
  return `${kmSearchToolbar("자산 유형, 공격 벡터 또는 연결 근거로 찾기", actions)}<div class="card"><div class="card-header"><div><h2>DFD 자산 유형–공격 벡터 연결</h2><div class="small-text muted">1.1 DFD 노드의 자산 유형을 기준으로 1.2 공격 벡터 초안 후보를 만드는 규칙입니다.</div></div><span class="count-pill">${mappings.length}/${kmAssetMappings().length}</span></div><div class="card-body km-scroll-body">${rows ? `<table class="data-table km-asset-mapping-table ${canWrite ? "" : "km-readonly-table"}"><thead><tr><th>DFD 자산 유형</th><th>공격 벡터 후보</th><th>연결 근거</th>${canWrite ? "<th></th>" : ""}</tr></thead><tbody>${rows}</tbody></table>` : emptyState("등록된 자산별 공격 벡터 연결이 없습니다", canWrite ? "첫 연결을 추가해 후보 생성 규칙을 만드세요." : "서버 운영자에게 KM 연결 규칙을 확인해 주세요.")}</div></div>`;
}

function bindKmAdminEvents() {
  if ($("#km-search-apply")) $("#km-search-apply").onclick = () => { state.kmSearch = $("#km-search").value; renderKmAdmin(); };
  if ($("#km-search")) $("#km-search").onkeydown = (event) => { if (event.key === "Enter") { state.kmSearch = event.currentTarget.value; renderKmAdmin(); } };
  if ($("#km-search-clear")) $("#km-search-clear").onclick = () => { state.kmSearch = ""; renderKmAdmin(); };
  if ($("#km-add-av")) $("#km-add-av").onclick = () => showKmEntityModal("attack-vector");
  if ($("#km-add-cm")) $("#km-add-cm").onclick = () => showKmEntityModal("countermeasure");
  $$('[data-edit-km-av]').forEach((button) => button.onclick = () => showKmEntityModal("attack-vector", kmAttackVectors().find((item) => String(item.id) === button.dataset.editKmAv)));
  $$('[data-edit-km-cm]').forEach((button) => button.onclick = () => showKmEntityModal("countermeasure", kmCountermeasures().find((item) => String(item.id) === button.dataset.editKmCm)));
  if ($("#km-add-mapping")) $("#km-add-mapping").onclick = () => showKmMappingModal();
  $$('[data-edit-km-mapping]').forEach((button) => button.onclick = () => showKmMappingModal(kmMappings().find((item) => String(item.id) === button.dataset.editKmMapping)));
  $$('[data-delete-km-mapping]').forEach((button) => button.onclick = () => deleteKmMapping(button.dataset.deleteKmMapping));
  if ($("#km-export-mappings")) $("#km-export-mappings").onclick = downloadKmMappingsCsv;
  if ($("#km-import-mappings")) $("#km-import-mappings").onclick = showKmImportModal;
  if ($("#km-add-group")) $("#km-add-group").onclick = () => showKmGroupModal();
  $$('[data-edit-km-group]').forEach((button) => button.onclick = () => showKmGroupModal(kmVectorGroups().find((item) => String(item.id) === button.dataset.editKmGroup)));
  $$('[data-members-km-group]').forEach((button) => button.onclick = () => showKmGroupMembersModal(kmVectorGroups().find((item) => String(item.id) === button.dataset.membersKmGroup)));
  if ($("#km-add-asset-mapping")) $("#km-add-asset-mapping").onclick = () => showKmAssetMappingModal();
  $$('[data-edit-km-asset-mapping]').forEach((button) => button.onclick = () => showKmAssetMappingModal(kmAssetMappings().find((item) => String(item.asset_type_id) === button.dataset.assetTypeId && String(item.attack_vector_id) === button.dataset.attackVectorId)));
  $$('[data-delete-km-asset-mapping]').forEach((button) => button.onclick = () => deleteKmAssetMapping(button.dataset.assetTypeId, button.dataset.attackVectorId));
}

function showKmAssetMappingModal(mapping = null) {
  if (!kmAdminCanWrite()) { toast("현재 서버의 KM은 읽기 전용입니다.", true); return; }
  const editing = Boolean(mapping);
  const selectedAssetId = String(mapping?.asset_type_id || "");
  const selectedVectorId = String(mapping?.attack_vector_id || "");
  const assetOptions = kmAssetTypes().map((item) => `<option value="${escapeHtml(item.id)}" ${selectedAssetId === String(item.id) ? "selected" : ""}>${escapeHtml(dfdDisplayName(compact(item.group_name, "기타"), "기타"))}: ${escapeHtml(assetDisplayName(item))}</option>`).join("");
  const vectorOptions = kmAttackVectors().map((item) => `<option value="${escapeHtml(item.id)}" ${selectedVectorId === String(item.id) ? "selected" : ""}>${escapeHtml(attackVectorCatalogId(item))} ${escapeHtml(item.name)}</option>`).join("");
  $("#km-asset-mapping-modal")?.remove();
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="km-asset-mapping-modal"><div class="modal"><div class="modal-header"><div><h2>자산별 공격 벡터 연결 ${editing ? "수정" : "등록"}</h2><div class="small-text muted">DFD에서 이 자산 유형을 사용하면 연결한 공격 벡터가 1.2 후보 초안에 포함됩니다.</div></div><button class="btn small" data-close-km-asset-mapping>닫기</button></div><form id="km-asset-mapping-form"><div class="modal-body form-grid"><div class="form-field"><label class="required">DFD 자산 유형</label><select id="km-asset-map-type" ${editing ? "disabled" : ""} required><option value="">자산 유형 선택</option>${assetOptions}</select></div><div class="form-field"><label class="required">공격 벡터 후보</label><select id="km-asset-map-vector" ${editing ? "disabled" : ""} required><option value="">공격 벡터 선택</option>${vectorOptions}</select></div><div class="form-field full"><label class="required">연결 근거</label><textarea id="km-asset-map-note" placeholder="이 자산 유형에 해당 공격 벡터가 적용되는 이유" required>${escapeHtml(dfdDisplayName(mapping?.mapping_note, ""))}</textarea><span class="input-help">Manifest나 DFD만으로 확정할 수 없는 공격 성공 여부가 아니라, 후보로 검토할 근거를 적습니다.</span></div></div><div class="modal-footer"><button type="button" class="btn" data-close-km-asset-mapping>취소</button><button class="btn primary" type="submit">연결 저장</button></div></form></div></div>`);
  $$('[data-close-km-asset-mapping]').forEach((button) => button.onclick = () => $("#km-asset-mapping-modal")?.remove());
  $("#km-asset-mapping-form").onsubmit = async (event) => {
    event.preventDefault();
    const body = {
      asset_type_id: selectedAssetId || $("#km-asset-map-type").value,
      attack_vector_id: selectedVectorId || $("#km-asset-map-vector").value,
      mapping_note: $("#km-asset-map-note").value.trim(),
    };
    if (!body.asset_type_id || !body.attack_vector_id || !body.mapping_note) { toast("자산 유형, 공격 벡터와 연결 근거를 입력해 주세요.", true); return; }
    try {
      await api("/api/km/asset-mappings", { method: "POST", body });
      $("#km-asset-mapping-modal")?.remove();
      await reloadKm();
      renderKmAdmin();
      toast("자산별 공격 벡터 연결을 저장했습니다.");
    } catch (error) { toast(error.message, true); }
  };
}

async function deleteKmAssetMapping(assetTypeId, attackVectorId) {
  if (!kmAdminCanWrite()) { toast("현재 서버의 KM은 읽기 전용입니다.", true); return; }
  const assetName = assetDisplayName(kmAssetTypes().find((item) => String(item.id) === String(assetTypeId)) || assetTypeId);
  const vector = kmAttackVectors().find((item) => String(item.id) === String(attackVectorId));
  const displayId = attackVectorCatalogId(vector || { id: attackVectorId });
  if (!window.confirm(`${assetName} 자산에서 ${displayId} 공격 벡터 후보 연결을 삭제할까요? 이후 후보 생성에서는 이 규칙이 사용되지 않습니다.`)) return;
  try {
    await api("/api/km/asset-mappings", { method: "DELETE", body: { asset_type_id: assetTypeId, attack_vector_id: attackVectorId } });
    await reloadKm();
    renderKmAdmin();
    toast("자산별 공격 벡터 연결을 삭제했습니다.");
  } catch (error) { toast(error.message, true); }
}

function showKmEntityModal(kind, entity = null) {
  const isVector = kind === "attack-vector";
  const title = isVector ? "공격 벡터" : "대응책";
  const editing = Boolean(entity);
  $("#km-entity-modal")?.remove();
  const prerequisiteField = isVector ? `<div class="form-field full"><label for="km-entity-prerequisite">선행조건 (선택)</label><textarea id="km-entity-prerequisite" maxlength="10000" placeholder="이 공격이 성립하기 전에 충족되어야 하는 조건">${escapeHtml(entity?.prerequisite || "")}</textarea><span class="input-help">확인된 조건만 입력하며, 알 수 없으면 비워 둡니다.</span></div>` : "";
  const catalogField = isVector && editing ? `<div class="form-field"><label>CloudTARA 공격 벡터 ID</label><input value="${escapeHtml(attackVectorCatalogId(entity))}" disabled><span class="input-help">사용자 화면과 보고서에 표시되는 통합 ID입니다.</span></div>` : "";
  const originalId = isVector ? attackVectorExternalId(entity) : entity?.id || "";
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="km-entity-modal"><div class="modal"><div class="modal-header"><h2>${title} ${editing ? "수정" : "등록"}</h2><button class="btn small" data-close-km-entity>닫기</button></div><form id="km-entity-form"><div class="modal-body form-grid">${catalogField}<div class="form-field"><label class="${isVector ? "" : "required"}">${isVector ? "출처 원본 ID (선택)" : "ID"}</label><input id="km-entity-id" value="${escapeHtml(originalId)}" ${editing ? "disabled" : ""} placeholder="${isVector ? "예: T1036.010, CAPEC-100, CVE-2026-1234" : ""}" ${isVector ? "" : "required"}>${isVector ? '<span class="input-help">원 지식원에 ID가 없으면 비워 두세요. CloudTARA AV ID는 저장할 때 자동으로 부여됩니다.</span>' : ""}</div><div class="form-field"><label class="required">이름</label><input id="km-entity-name" value="${escapeHtml(entity?.name || "")}" required></div><div class="form-field full"><label class="required">설명</label><textarea id="km-entity-description" required>${escapeHtml(entity?.description || "")}</textarea></div>${prerequisiteField}<div class="form-field"><label class="required">출처</label><input id="km-entity-source" value="${escapeHtml(entity?.source || (isVector ? "MITRE ATT&CK" : "CloudTARA KM"))}" ${isVector ? 'placeholder="예: MITRE ATT&CK, CAPEC, CVE, CWE, 위협 보고서"' : ""} required></div><div class="form-field"><label>참조 URL</label><input id="km-entity-url" type="url" placeholder="https://..." value="${escapeHtml(entity?.reference_url || "")}"></div></div><div class="modal-footer"><button type="button" class="btn" data-close-km-entity>취소</button><button class="btn primary" type="submit">저장</button></div></form></div></div>`);
  $$('[data-close-km-entity]').forEach((button) => button.onclick = () => $("#km-entity-modal")?.remove());
  $("#km-entity-form").onsubmit = async (event) => {
    event.preventDefault();
    const sourceIdentifier = $("#km-entity-id").value.trim();
    const body = { id: entity?.id || (isVector ? "" : sourceIdentifier), name: $("#km-entity-name").value.trim(), description: $("#km-entity-description").value.trim(), source: $("#km-entity-source").value.trim(), reference_url: $("#km-entity-url").value.trim() };
    if (isVector) body.source_identifier = sourceIdentifier;
    if (isVector) body.prerequisite = $("#km-entity-prerequisite").value.trim();
    if ((!isVector && !body.id) || !body.name || !body.description || !body.source) { toast(`${isVector ? "이름, 설명과 출처" : "ID, 이름, 설명과 출처"}를 입력해 주세요.`, true); return; }
    const base = isVector ? "/api/km/attack-vectors" : "/api/km/countermeasures";
    try {
      await api(editing ? `${base}/${encodeURIComponent(entity.id)}` : base, { method: editing ? "PUT" : "POST", body });
      $("#km-entity-modal")?.remove(); await reloadKm(); renderKmAdmin(); toast(`${title}을 저장했습니다.`);
    } catch (error) { toast(error.message, true); }
  };
}

function showKmMappingModal(mapping = null) {
  const editing = Boolean(mapping);
  const selectedAvId = vectorId(mapping);
  const selectedCmId = countermeasureId(mapping);
  const reviewStatus = String(mapping?.review_status || "REVIEW_REQUIRED").toUpperCase();
  $("#km-mapping-admin-modal")?.remove();
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="km-mapping-admin-modal"><div class="modal"><div class="modal-header"><div><h2>공격 벡터와 대응책 연결 ${editing ? "수정" : "등록"}</h2><div class="small-text muted">LLM 초안은 저장 전까지 입력값으로만 유지됩니다.</div></div><button class="btn small" data-close-km-mapping>닫기</button></div><form id="km-mapping-admin-form"><div class="modal-body form-grid"><div class="form-field"><label class="required">공격 벡터</label><select id="km-map-av" ${editing ? "disabled" : ""}>${kmAttackVectors().map((item) => `<option value="${escapeHtml(item.id)}" ${selectedAvId === String(item.id) ? "selected" : ""}>${escapeHtml(attackVectorCatalogId(item))} ${escapeHtml(item.name)}</option>`).join("")}</select></div><div class="form-field"><label class="required">대응책</label><select id="km-map-cm" ${editing ? "disabled" : ""}>${kmCountermeasures().map((item) => `<option value="${escapeHtml(item.id)}" ${selectedCmId === String(item.id) ? "selected" : ""}>${escapeHtml(item.id)} ${escapeHtml(item.name)}</option>`).join("")}</select></div><div class="form-field"><label class="required">대응 효과</label><select id="km-map-effect">${optionsMarkup(EFFECT_OPTIONS, normalizeEffect(mapping?.effect), "효과 선택")}</select></div><div class="form-field"><label class="required">신뢰도</label><select id="km-map-confidence">${optionsMarkup(CONFIDENCE_OPTIONS, normalizeConfidence(mapping?.confidence), "신뢰도 선택")}</select></div><div class="form-field"><label class="required">검토 상태</label><select id="km-map-review"><option value="REVIEW_REQUIRED" ${reviewStatus === "REVIEW_REQUIRED" ? "selected" : ""}>검토 필요</option><option value="APPROVED" ${reviewStatus === "APPROVED" ? "selected" : ""}>승인</option></select></div><div class="form-field km-llm-field"><label>선택 기능</label><button class="btn" type="button" id="km-map-llm" ${state.llm?.enabled ? "" : "disabled title='LLM 설정이 필요합니다.'"}>LLM 초안 받기</button></div><div class="form-field full"><label class="required">연결 근거</label><textarea id="km-map-rationale" placeholder="이 공격 벡터에 대응책을 연결하는 이유">${escapeHtml(mapping?.rationale || "")}</textarea></div><div class="form-field full hidden" id="km-map-llm-result"></div></div><div class="modal-footer"><button type="button" class="btn" data-close-km-mapping>취소</button><button class="btn primary" type="submit">연결 저장</button></div></form></div></div>`);
  $$('[data-close-km-mapping]').forEach((button) => button.onclick = () => $("#km-mapping-admin-modal")?.remove());
  $("#km-map-llm").onclick = requestKmMappingSuggestion;
  $("#km-mapping-admin-form").onsubmit = async (event) => {
    event.preventDefault();
    const body = { av_id: selectedAvId || $("#km-map-av").value, cm_id: selectedCmId || $("#km-map-cm").value, effect: $("#km-map-effect").value, confidence: $("#km-map-confidence").value, rationale: $("#km-map-rationale").value.trim(), review_status: $("#km-map-review").value };
    if (!body.av_id || !body.cm_id || !body.effect || !body.confidence || !body.rationale) { toast("공격 벡터, 대응책, 대응 효과, 신뢰도와 연결 근거를 입력해 주세요.", true); return; }
    try {
      await api(editing ? `/api/km/mappings/${encodeURIComponent(mapping.id)}` : "/api/km/mappings", { method: editing ? "PUT" : "POST", body });
      $("#km-mapping-admin-modal")?.remove(); await reloadKm(); renderKmAdmin(); toast("대응책 연결을 저장했습니다.");
    } catch (error) { toast(error.message, true); }
  };
}

async function requestKmMappingSuggestion() {
  const avId = $("#km-map-av")?.value;
  const cmId = $("#km-map-cm")?.value;
  if (!state.llm?.enabled) { toast("먼저 대시보드에서 LLM 연결을 설정해 주세요.", true); return; }
  if (!avId || !cmId) { toast("공격 벡터와 대응책을 먼저 선택해 주세요.", true); return; }
  if (!window.confirm("선택한 공용 KM 공격 벡터와 대응책 설명을 설정된 외부 LLM에 전송할까요? 제안은 자동 저장되지 않습니다.")) return;
  try {
    toast("LLM에 대응 효과와 신뢰도 제안을 요청하고 있습니다.");
    const result = await api("/api/km/llm/mapping", { method: "POST", body: { attack_vector_id: avId, countermeasure_id: cmId } });
    const suggestion = result?.suggestion || result || {};
    const effect = normalizeEffect(suggestion.effect);
    const confidence = normalizeConfidence(suggestion.confidence);
    if (!EFFECT_OPTIONS.some(([value]) => value === effect) || !CONFIDENCE_OPTIONS.some(([value]) => value === confidence)) throw new Error("LLM 제안의 효과 또는 신뢰도 형식이 올바르지 않습니다.");
    $("#km-map-effect").value = effect;
    $("#km-map-confidence").value = confidence;
    $("#km-map-rationale").value = compact(suggestion.reason || suggestion.rationale, "");
    $("#km-map-review").value = "REVIEW_REQUIRED";
    const resultBox = $("#km-map-llm-result");
    resultBox.classList.remove("hidden");
    resultBox.innerHTML = `<div class="llm-box">${llmSuggestionSource(suggestion)}<strong>${escapeHtml(effectLabel(effect))}, ${escapeHtml(confidenceLabel(confidence))}</strong><br>${escapeHtml(compact(suggestion.reason || suggestion.rationale, "근거 없음"))}<br><span>검토 상태는 ‘검토 필요’로 유지됩니다.</span></div>`;
    toast("제안을 입력란에 적용했습니다. 검토 후 저장해 주세요.");
  } catch (error) { toast(error.message, true); }
}

function csvCell(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function downloadKmMappingsCsv() {
  const headers = ["av_id", "cm_id", "effect", "confidence", "rationale", "review_status"];
  const rows = kmMappings().map((item) => [
    vectorId(item), countermeasureId(item), normalizeEffect(item.effect), normalizeConfidence(item.confidence),
    item.rationale || "", String(item.review_status || "REVIEW_REQUIRED").toUpperCase(),
  ]);
  const content = `\uFEFF${[headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n")}`;
  const url = URL.createObjectURL(new Blob([content], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `cntara-km-mappings-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function parseCsv(text) {
  const table = [];
  let row = [];
  let cell = "";
  let quoted = false;
  const source = String(text || "").replace(/^\uFEFF/, "");
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (quoted) {
      if (char === '"' && source[index + 1] === '"') { cell += '"'; index += 1; }
      else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"' && cell === "") quoted = true;
    else if (char === ",") { row.push(cell); cell = ""; }
    else if (char === "\n" || char === "\r") {
      if (char === "\r" && source[index + 1] === "\n") index += 1;
      row.push(cell); cell = "";
      if (row.some((value) => value.trim())) table.push(row);
      row = [];
    } else cell += char;
  }
  if (quoted) throw new Error("CSV 따옴표가 닫히지 않았습니다.");
  row.push(cell);
  if (row.some((value) => value.trim())) table.push(row);
  if (!table.length) return [];
  const headers = table.shift().map((value) => value.trim());
  const required = ["av_id", "cm_id", "effect", "confidence", "rationale", "review_status"];
  const missing = required.filter((name) => !headers.includes(name));
  if (missing.length) throw new Error(`필수 CSV 열이 없습니다: ${missing.join(", ")}`);
  return table.map((values) => Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ""])));
}

function showKmImportModal() {
  $("#km-import-modal")?.remove();
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="km-import-modal"><div class="modal"><div class="modal-header"><div><h2>대응책 연결 CSV 가져오기</h2><div class="small-text muted">정상 행만 저장하고, 반영하지 못한 행은 처리 결과에서 알려드립니다.</div></div><button class="btn small" data-close-km-import>닫기</button></div><form id="km-import-form"><div class="modal-body"><div class="notice info"><div>ⓘ</div><div><strong>필수 열</strong><code>av_id, cm_id, effect, confidence, rationale, review_status</code><br><span class="small-text">저장값: effect는 PREVENT/DETECT/RESPOND, confidence는 HIGH/MODERATE/LOW, review_status는 REVIEW_REQUIRED/APPROVED</span></div></div><div class="form-field"><label class="required">CSV 파일</label><input id="km-import-file" type="file" accept=".csv,text/csv" required><span class="input-help">‘연결 CSV 내려받기’ 파일을 양식으로 사용할 수 있습니다.</span></div><div id="km-import-result" class="hidden"></div></div><div class="modal-footer"><button type="button" class="btn" data-close-km-import>취소</button><button class="btn primary" type="submit">확인하고 가져오기</button></div></form></div></div>`);
  $$('[data-close-km-import]').forEach((button) => button.onclick = () => { $("#km-import-modal")?.remove(); renderKmAdmin(); });
  $("#km-import-form").onsubmit = async (event) => {
    event.preventDefault();
    const file = $("#km-import-file").files?.[0];
    if (!file) { toast("CSV 파일을 선택해 주세요.", true); return; }
    try {
      const parsed = parseCsv(await file.text());
      if (!parsed.length) throw new Error("가져올 데이터 행이 없습니다.");
      const rows = parsed.map((item) => ({
        av_id: compact(item.av_id, ""), cm_id: compact(item.cm_id, ""),
        effect: normalizeEffect(item.effect), confidence: normalizeConfidence(item.confidence),
        rationale: compact(item.rationale, ""), review_status: String(item.review_status || "REVIEW_REQUIRED").trim().toUpperCase(),
      }));
      const result = await api("/api/km/mappings/import", { method: "POST", body: { rows } });
      await reloadKm();
      const errors = Array.isArray(result?.errors) ? result.errors : [];
      const resultBox = $("#km-import-result");
      resultBox.classList.remove("hidden");
      resultBox.innerHTML = `<div class="notice ${errors.length ? "warning" : "success"}"><div>${errors.length ? "!" : "✓"}</div><div><strong>처리 ${escapeHtml(result?.processed ?? rows.length)}행, 생성 ${escapeHtml(result?.created ?? 0)}, 갱신 ${escapeHtml(result?.updated ?? 0)}, 오류 ${errors.length}</strong>${errors.length ? errors.slice(0, 8).map((item) => `<div class="small-text">${escapeHtml(item.row)}행: ${escapeHtml(item.error)}</div>`).join("") : "모든 행을 반영했습니다."}</div></div>`;
      toast(errors.length ? "일부 CSV 행을 반영하지 못했습니다. 처리 결과를 확인해 주세요." : "대응책 연결 CSV를 가져왔습니다.", Boolean(errors.length));
    } catch (error) { toast(error.message, true); }
  };
}

function showKmGroupModal(group = null) {
  const editing = Boolean(group);
  const parents = kmVectorGroups().filter((item) => !editing || String(item.id) !== String(group.id));
  $("#km-group-modal")?.remove();
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="km-group-modal"><div class="modal"><div class="modal-header"><h2>공격 벡터 그룹 ${editing ? "수정" : "등록"}</h2><button class="btn small" data-close-km-group>닫기</button></div><form id="km-group-form"><div class="modal-body form-grid"><div class="form-field"><label class="required">그룹 이름</label><input id="km-group-name" value="${escapeHtml(group?.name || "")}" required></div><div class="form-field"><label>상위 그룹</label><select id="km-group-parent"><option value="">최상위</option>${parents.map((item) => `<option value="${escapeHtml(item.id)}" ${String(group?.parent_id || "") === String(item.id) ? "selected" : ""}>${escapeHtml(item.name)}</option>`).join("")}</select></div><div class="form-field full"><label>설명</label><textarea id="km-group-description" placeholder="이 그룹으로 묶는 공격 벡터의 공통 특성">${escapeHtml(group?.description || "")}</textarea></div></div><div class="modal-footer"><button type="button" class="btn" data-close-km-group>취소</button><button class="btn primary" type="submit">그룹 저장</button></div></form></div></div>`);
  $$('[data-close-km-group]').forEach((button) => button.onclick = () => $("#km-group-modal")?.remove());
  $("#km-group-form").onsubmit = async (event) => {
    event.preventDefault();
    const parentValue = $("#km-group-parent").value;
    const body = { name: $("#km-group-name").value.trim(), description: $("#km-group-description").value.trim(), parent_id: parentValue ? Number(parentValue) : null };
    if (!body.name) { toast("그룹 이름을 입력해 주세요.", true); return; }
    try {
      await api(editing ? `/api/km/vector-groups/${encodeURIComponent(group.id)}` : "/api/km/vector-groups", { method: editing ? "PUT" : "POST", body });
      $("#km-group-modal")?.remove(); await reloadKm(); renderKmAdmin(); toast("공격 벡터 그룹을 저장했습니다.");
    } catch (error) { toast(error.message, true); }
  };
}

function showKmGroupMembersModal(group) {
  if (!group) return;
  const members = new Set((Array.isArray(group.member_ids) ? group.member_ids : []).map(String));
  $("#km-group-members-modal")?.remove();
  const rows = kmAttackVectors().map((item) => `<label class="check-card km-member-row"><input type="checkbox" data-km-group-member value="${escapeHtml(item.id)}" ${members.has(String(item.id)) ? "checked" : ""}><span><strong>${escapeHtml(attackVectorCatalogId(item))} ${escapeHtml(item.name)}</strong><span>${escapeHtml(compact(item.description))}</span></span></label>`).join("");
  document.body.insertAdjacentHTML("beforeend", `<div class="modal-backdrop" id="km-group-members-modal"><div class="modal"><div class="modal-header"><div><h2>${escapeHtml(group.name)} 포함 항목</h2><div class="small-text muted">이 그룹에 포함할 공용 KM 공격 벡터를 선택합니다.</div></div><button class="btn small" data-close-km-members>닫기</button></div><form id="km-group-members-form"><div class="modal-body"><div class="km-member-list">${rows || emptyState("공격 벡터가 없습니다", "먼저 KM 공격 벡터를 등록해 주세요.")}</div></div><div class="modal-footer"><button type="button" class="btn" data-close-km-members>취소</button><button class="btn primary" type="submit">선택 항목 저장</button></div></form></div></div>`);
  $$('[data-close-km-members]').forEach((button) => button.onclick = () => $("#km-group-members-modal")?.remove());
  $("#km-group-members-form").onsubmit = async (event) => {
    event.preventDefault();
    const attackVectorIds = $$('[data-km-group-member]').filter((box) => box.checked).map((box) => box.value);
    try {
      await api(`/api/km/vector-groups/${encodeURIComponent(group.id)}/members`, { method: "POST", body: { attack_vector_ids: attackVectorIds } });
      $("#km-group-members-modal")?.remove(); await reloadKm(); renderKmAdmin(); toast("그룹의 포함 항목을 저장했습니다.");
    } catch (error) { toast(error.message, true); }
  };
}

async function deleteKmMapping(id) {
  if (!window.confirm("이 공격 벡터–대응책 연결을 삭제할까요? 삭제 후 복구하려면 다시 등록해야 합니다.")) return;
  try { await api(`/api/km/mappings/${encodeURIComponent(id)}`, { method: "DELETE", body: {} }); await reloadKm(); renderKmAdmin(); toast("대응책 연결을 삭제했습니다."); } catch (error) { toast(error.message, true); }
}
async function reloadWorkspace() {
  assignWorkspace(await api(`/api/assessments/${state.assessmentId}/workspace`));
  const storedDfdLevels = new Set((state.workspace?.nodes || [])
    .map((node) => Number(node?.properties?.catalog?.level))
    .filter((level) => level === 0 || level === 1));
  if (storedDfdLevels.size === 1) {
    state.dfdCatalogLevel = [...storedDfdLevels][0];
  }
}

window.addEventListener("beforeunload", (event) => {
  const reviewDirty = state.phase === "ctsa" && state.step === 4 && reviewDraftIsDirty();
  const riskDirty = state.phase === "ctsa" && state.step === 5 && riskDraftIsDirty();
  const crraDirty = state.phase === "crra" && state.crraUiDirty;
  if (!state.dfdDirty && !state.attackCasesDirty && !reviewDirty && !riskDirty && !crraDirty) return;
  event.preventDefault();
  event.returnValue = "";
});

initializeTheme();
initializeModalDismissConventions();
initialize();
