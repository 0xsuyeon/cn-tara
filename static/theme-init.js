(() => {
  const key = "cntara-theme";
  let mode = "AUTO";
  try {
    const saved = String(localStorage.getItem(key) || "AUTO").toUpperCase();
    if (["DARK", "LIGHT", "AUTO"].includes(saved)) mode = saved;
  } catch {
    // 저장소가 제한되어도 시스템 테마로 시작한다.
  }
  const dark = mode === "DARK"
    || (mode === "AUTO" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  document.documentElement.dataset.themeMode = mode.toLowerCase();
  document.documentElement.style.colorScheme = dark ? "dark" : "light";
})();
