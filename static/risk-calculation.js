(function exposeRiskCalculation(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.CNTARA_RISK_CALCULATION = api;
})(typeof globalThis === "object" ? globalThis : this, function createRiskCalculation() {
  function finiteNumber(value) {
    if (value === "" || value === null || value === undefined || typeof value === "boolean") return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  // Match Python's round-half-to-even behavior.
  function roundHalfEven(value, decimals = 0) {
    const number = finiteNumber(value);
    const places = Number(decimals);
    if (number === null || !Number.isInteger(places) || places < 0 || places > 12) return null;
    if (number === 0) return number;
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, Math.abs(number), false);
    const high = view.getUint32(0, false);
    const low = view.getUint32(4, false);
    const exponentBits = (high >>> 20) & 0x7ff;
    const fraction = (BigInt(high & 0xfffff) << 32n) | BigInt(low);
    const mantissa = exponentBits === 0 ? fraction : (1n << 52n) | fraction;
    const binaryExponent = (exponentBits === 0 ? 1 - 1023 : exponentBits - 1023) - 52;
    let numerator = mantissa * (10n ** BigInt(places));
    let denominator = 1n;
    if (binaryExponent >= 0) numerator <<= BigInt(binaryExponent);
    else denominator <<= BigInt(-binaryExponent);
    let quotient = numerator / denominator;
    const remainder = numerator % denominator;
    const doubled = remainder * 2n;
    if (doubled > denominator || (doubled === denominator && quotient % 2n !== 0n)) quotient += 1n;
    const sign = number < 0 ? -1 : 1;
    return sign * Number(quotient) / (10 ** places);
  }

  function evaluateExpression(expression, values, factorNames = {}) {
    if (!expression || typeof expression !== "object" || Array.isArray(expression)) {
      throw new Error("위험 계산식이 올바르지 않습니다.");
    }
    if (Object.prototype.hasOwnProperty.call(expression, "factor")) {
      const code = String(expression.factor || "");
      const value = finiteNumber(values?.[code]);
      if (!code || value === null) throw new Error(`위험 요인 '${code || "알 수 없음"}' 값이 없습니다.`);
      return { value, trace: { type: "factor", code, name: factorNames[code] || code, value } };
    }
    const terms = expression.terms;
    if (!Array.isArray(terms) || !terms.length) throw new Error("위험 계산식의 항이 없습니다.");
    if (expression.op === "weighted_sum") {
      let value = 0;
      const traceTerms = terms.map((term) => {
        const weight = finiteNumber(term?.weight);
        if (weight === null) throw new Error("위험 계산식의 가중치가 올바르지 않습니다.");
        const child = evaluateExpression(term, values, factorNames);
        const subtotal = weight * child.value;
        value += subtotal;
        return { weight, value: child.value, subtotal, term: child.trace };
      });
      if (!Number.isFinite(value)) throw new Error("위험 점수를 계산할 수 없습니다.");
      return { value, trace: { type: "weighted_sum", terms: traceTerms, result: value } };
    }
    if (expression.op === "multiply") {
      let value = 1;
      const traceTerms = terms.map((term) => {
        const child = evaluateExpression(term, values, factorNames);
        value *= child.value;
        return { value: child.value, term: child.trace };
      });
      if (!Number.isFinite(value)) throw new Error("위험 점수를 계산할 수 없습니다.");
      return { value, trace: { type: "multiply", terms: traceTerms, result: value } };
    }
    throw new Error("지원하지 않는 위험 계산 방식입니다.");
  }

  function levelForScore(score, bands) {
    const number = finiteNumber(score);
    if (number === null || !Array.isArray(bands)) return null;
    const band = bands.find((candidate) => {
      const min = candidate?.min === null || candidate?.min === undefined ? -Infinity : finiteNumber(candidate.min);
      const max = candidate?.max === null || candidate?.max === undefined ? Infinity : finiteNumber(candidate.max);
      return min !== null && max !== null && min <= number && number <= max;
    });
    return band && String(band.label || "").trim() ? String(band.label).trim() : null;
  }

  function evaluateModel(model, values) {
    const factors = Array.isArray(model?.factors) ? model.factors : [];
    const normalized = {};
    const missing = [];
    const invalid = [];
    factors.forEach((factor) => {
      const code = String(factor?.code || "");
      const value = finiteNumber(values?.[code]);
      const levels = Array.isArray(factor?.levels) ? factor.levels : [];
      const allowed = levels.map((level) => finiteNumber(level?.value)).filter((entry) => entry !== null);
      if (!code || value === null) missing.push(code);
      else if (allowed.length && !allowed.some((entry) => entry === value)) invalid.push(code);
      else normalized[code] = value;
    });
    if (!factors.length || missing.length || invalid.length) {
      return { complete: false, missing, invalid, rawScore: null, score: null, riskLevel: null, trace: null };
    }
    const names = Object.fromEntries(factors.map((factor) => [factor.code, factor.name || factor.code]));
    let evaluated;
    if (model.formula && typeof model.formula === "object" && Object.keys(model.formula).length) {
      evaluated = evaluateExpression(model.formula, normalized, names);
    } else if (model.method === "weighted_sum") {
      const rawScore = factors.reduce((total, factor) => total + normalized[factor.code] * Number(factor.weight), 0);
      evaluated = { value: rawScore, trace: { type: "legacy_weighted_sum", result: rawScore } };
    } else if (model.method === "product") {
      const rawScore = factors.reduce((total, factor) => total * normalized[factor.code], 1);
      evaluated = { value: rawScore, trace: { type: "legacy_product", result: rawScore } };
    } else {
      throw new Error("지원하지 않는 위험 계산 방식입니다.");
    }
    const score = roundHalfEven(evaluated.value, Number(model.decimals || 0));
    return {
      complete: score !== null,
      missing: [],
      invalid: [],
      rawScore: evaluated.value,
      score,
      riskLevel: levelForScore(score, model.bands),
      trace: evaluated.trace,
    };
  }

  return { finiteNumber, roundHalfEven, evaluateExpression, levelForScore, evaluateModel };
});
