(function exposeDfdSelection(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.CNTARA_DFD_SELECTION = api;
})(typeof globalThis === "object" ? globalThis : this, function createDfdSelection() {
  const finite = (value, fallback = 0) => Number.isFinite(Number(value)) ? Number(value) : fallback;
  const key = (value) => String(value ?? "");
  const dfdReferencePrefix = /^\s*[\[(]?\s*(?:DF|DB|P|D|E)\s*\.\s*\d+(?:\s*\.\s*(?:\d+|\*))*\s*[\])]?\s*(?:[-\u2013\u2014:|\u00b7/_]\s*)?/i;

  function displayName(value, fallback = "") {
    const source = String(value ?? "").trim();
    const fallbackText = String(fallback ?? "").trim();
    if (!source) return fallbackText;
    const visible = source.replace(dfdReferencePrefix, "").trim();
    return visible || fallbackText;
  }

  function labelCharacterUnits(character) {
    const codePoint = String(character || "").codePointAt(0) || 0;
    const isWide = (
      (codePoint >= 0x1100 && codePoint <= 0x11ff)
      || (codePoint >= 0x2e80 && codePoint <= 0x9fff)
      || (codePoint >= 0xac00 && codePoint <= 0xd7af)
      || (codePoint >= 0xf900 && codePoint <= 0xfaff)
      || (codePoint >= 0xff01 && codePoint <= 0xff60)
      || (codePoint >= 0x1f300 && codePoint <= 0x1faff)
    );
    return isWide ? 2 : 1;
  }

  function labelTextUnits(value) {
    return Array.from(String(value ?? "")).reduce(
      (total, character) => total + labelCharacterUnits(character), 0,
    );
  }

  function splitLabelByUnits(value, maximumUnits) {
    const characters = Array.from(String(value ?? ""));
    const limit = Math.max(1, Math.floor(finite(maximumUnits, 1)));
    let used = 0;
    let splitIndex = 0;
    while (splitIndex < characters.length) {
      const next = labelCharacterUnits(characters[splitIndex]);
      if (splitIndex > 0 && used + next > limit) break;
      used += next;
      splitIndex += 1;
      if (used >= limit) break;
    }
    return [characters.slice(0, splitIndex).join(""), characters.slice(splitIndex).join("")];
  }

  function wrapLabel(value, requestedMaxChars = 22, requestedMaxLines = Infinity) {
    const maxChars = Math.max(4, Math.floor(finite(requestedMaxChars, 22)));
    const maxLines = Number.isFinite(Number(requestedMaxLines))
      ? Math.max(1, Math.floor(Number(requestedMaxLines)))
      : Infinity;
    const sourceLines = String(value ?? "").replace(/\r\n?/g, "\n").split("\n");
    const lines = [];
    const appendWrapped = (source) => {
      const text = String(source || "").trim();
      if (!text) { lines.push(""); return; }
      let current = "";
      const words = text.split(/\s+/).filter(Boolean);
      words.forEach((word) => {
        let remaining = word;
        if (current && labelTextUnits(current) + 1 + labelTextUnits(remaining) <= maxChars) {
          current += ` ${remaining}`;
          return;
        }
        if (current) { lines.push(current); current = ""; }
        while (labelTextUnits(remaining) > maxChars) {
          const [head, tail] = splitLabelByUnits(remaining, maxChars);
          lines.push(head);
          remaining = tail;
        }
        current = remaining;
      });
      if (current || !lines.length) lines.push(current);
    };
    sourceLines.forEach(appendWrapped);
    if (lines.length <= maxLines) return lines.length ? lines : [""];
    const visible = lines.slice(0, maxLines);
    const finalIndex = visible.length - 1;
    const finalLine = visible[finalIndex].replace(/…$/, "");
    const [truncated] = splitLabelByUnits(finalLine, Math.max(1, maxChars - 1));
    visible[finalIndex] = `${truncated}…`;
    return visible;
  }

  function automaticNodeSize(value, options = {}) {
    const minimumWidth = Math.max(80, finite(options.minWidth, 172));
    const maximumWidth = Math.max(minimumWidth, finite(options.maxWidth, 240));
    const minimumHeight = Math.max(48, finite(options.minHeight, 66));
    const characterWidth = Math.max(5, finite(options.characterWidth, 7.5));
    const horizontalPadding = Math.max(20, finite(options.horizontalPadding, 38));
    const lineHeight = Math.max(12, finite(options.lineHeight, 16));
    const verticalPadding = Math.max(28, finite(options.verticalPadding, 42));
    const explicitLines = String(value ?? "").replace(/\r\n?/g, "\n").split("\n");
    const longestLine = Math.max(1, ...explicitLines.map((line) => labelTextUnits(line.trim())));
    const width = Math.min(maximumWidth, Math.max(minimumWidth, longestLine * characterWidth + horizontalPadding));
    const maxChars = Math.max(4, Math.floor((width - horizontalPadding) / characterWidth));
    const lines = wrapLabel(value, maxChars);
    const height = Math.max(minimumHeight, verticalPadding + Math.max(1, lines.length) * lineHeight);
    return { width, height, lines, maxChars };
  }

  function catalogLevel(node) {
    const value = node?.properties?.catalog?.level;
    if (value === "" || value === null || value === undefined) return null;
    const level = Number(value);
    return Number.isInteger(level) && (level === 0 || level === 1) ? level : null;
  }

  function inferredFlowLevel(elements, sourceNode, targetNode) {
    const explicitLevels = [catalogLevel(sourceNode), catalogLevel(targetNode)].filter((level) => level !== null);
    if (explicitLevels.length) return new Set(explicitLevels).size === 1 ? explicitLevels[0] : null;

    const sourceType = key(sourceNode?.asset_type_id);
    const targetType = key(targetNode?.asset_type_id);
    if (!sourceType || !targetType) return null;
    const levelsFor = (assetTypeId) => new Set((Array.isArray(elements) ? elements : [])
      .filter((element) => key(element?.asset_type_id) === assetTypeId)
      .map((element) => Number(element?.level))
      .filter((level) => Number.isInteger(level) && (level === 0 || level === 1)));
    const sourceLevels = levelsFor(sourceType);
    const targetLevels = levelsFor(targetType);
    const shared = [...sourceLevels].filter((level) => targetLevels.has(level));
    return shared.length === 1 ? shared[0] : null;
  }

  function selectFlowTemplate(templates, elements, sourceNode, targetNode) {
    const sourceType = key(sourceNode?.asset_type_id);
    const targetType = key(targetNode?.asset_type_id);
    if (!sourceType || !targetType) return null;
    let candidates = (Array.isArray(templates) ? templates : []).filter((template) => (
      template?.active === true
      && String(template?.review_status || "").toUpperCase() === "APPROVED"
      && key(template?.source_asset_type_id) === sourceType
      && key(template?.target_asset_type_id) === targetType
    ));
    const sourceExplicitLevel = catalogLevel(sourceNode);
    const targetExplicitLevel = catalogLevel(targetNode);
    if (
      sourceExplicitLevel !== null
      && targetExplicitLevel !== null
      && sourceExplicitLevel !== targetExplicitLevel
    ) return null;
    const preferredLevel = inferredFlowLevel(elements, sourceNode, targetNode);
    if (preferredLevel !== null) {
      candidates = candidates.filter((template) => Number(template?.level) === preferredLevel);
    } else {
      const candidateLevels = new Set(candidates.map((template) => Number(template?.level)));
      if (candidateLevels.size > 1) return null;
    }
    const unique = new Map();
    candidates.forEach((template) => {
      const identity = [template.id, template.name, template.source_asset_type_id, template.target_asset_type_id].map(key).join("\u0000");
      if (!unique.has(identity)) unique.set(identity, template);
    });
    return unique.size === 1 ? [...unique.values()][0] : null;
  }

  function flowCatalogMetadata(template) {
    if (!template) return null;
    return {
      flow_template_id: template.id,
      km_release_id: template.km_release_id,
      level: template.level,
      match_basis: "MANUAL_EXACT_DIRECTED_ASSET_TYPES",
      requires_user_confirmation: false,
    };
  }

  function collectorEdgeSelectedByDefault(edge) {
    return edge?.properties?.catalog?.requires_user_confirmation !== true;
  }

  function explicitEdgeCurveOffset(edge, limit = 180) {
    const raw = edge?.properties?.layout?.curve_offset;
    if (raw === "" || raw === null || raw === undefined) return null;
    const value = Number(raw);
    if (!Number.isFinite(value)) return null;
    const maximum = Math.max(20, Math.abs(finite(limit, 180)));
    return Math.max(-maximum, Math.min(maximum, value));
  }

  function automaticEdgeCurveOffsets(edges, options = {}) {
    const list = Array.isArray(edges) ? edges : [];
    const spacing = Math.max(12, Math.min(80, finite(options.spacing, 34)));
    const bidirectionalGap = Math.max(16, Math.min(80, finite(options.bidirectionalGap, 30)));
    const offsets = list.map(() => 0);
    const pairs = new Map();

    list.forEach((edge, index) => {
      const source = key(edge?.source ?? edge?.source_node_id);
      const target = key(edge?.target ?? edge?.target_node_id);
      if (!source || !target) return;
      const pairKey = source <= target ? `${source}\u0000${target}` : `${target}\u0000${source}`;
      if (!pairs.has(pairKey)) pairs.set(pairKey, new Map());
      const directions = pairs.get(pairKey);
      const directionKey = `${source}\u0000${target}`;
      if (!directions.has(directionKey)) directions.set(directionKey, []);
      directions.get(directionKey).push(index);
    });

    pairs.forEach((directions) => {
      const bidirectional = directions.size > 1;
      directions.forEach((indices) => {
        if (bidirectional) {
          const localSpacing = Math.min(spacing, Math.max(14, 120 / Math.max(1, indices.length)));
          indices.forEach((index, position) => { offsets[index] = bidirectionalGap + position * localSpacing; });
          return;
        }
        const center = (indices.length - 1) / 2;
        indices.forEach((index, position) => { offsets[index] = (position - center) * spacing; });
      });
    });
    return offsets;
  }

  function quadraticCurveGeometry(start, end, requestedOffset = 0) {
    const sx = finite(start?.x);
    const sy = finite(start?.y);
    const tx = finite(end?.x);
    const ty = finite(end?.y);
    const dx = tx - sx;
    const dy = ty - sy;
    const length = Math.hypot(dx, dy) || 1;
    const offset = finite(requestedOffset);
    const cx = (sx + tx) / 2 + (-dy / length) * offset;
    const cy = (sy + ty) / 2 + (dx / length) * offset;
    const mx = (sx + 2 * cx + tx) / 4;
    const my = (sy + 2 * cy + ty) / 4;
    return { sx, sy, tx, ty, cx, cy, mx, my, offset, path: `M ${sx} ${sy} Q ${cx} ${cy} ${tx} ${ty}` };
  }

  function explicitEdgeLabelT(edge) {
    const raw = edge?.properties?.layout?.label_t;
    if (raw === null || raw === undefined || raw === "") return null;
    const value = Number(raw);
    if (!Number.isFinite(value)) return null;
    return Math.max(0.05, Math.min(0.95, value));
  }

  function quadraticCurvePoint(geometry, requestedT = 0.5) {
    const t = Math.max(0, Math.min(1, finite(requestedT)));
    const inverse = 1 - t;
    return {
      x: inverse * inverse * finite(geometry?.sx) + 2 * inverse * t * finite(geometry?.cx) + t * t * finite(geometry?.tx),
      y: inverse * inverse * finite(geometry?.sy) + 2 * inverse * t * finite(geometry?.cy) + t * t * finite(geometry?.ty),
      t,
    };
  }

  function nearestQuadraticCurveT(geometry, point, steps = 80) {
    const sampleCount = Math.max(20, Math.min(240, Math.round(finite(steps)) || 80));
    const px = finite(point?.x);
    const py = finite(point?.y);
    let nearestT = 0.5;
    let nearestDistance = Infinity;
    for (let index = 0; index <= sampleCount; index += 1) {
      const t = 0.05 + (index / sampleCount) * 0.9;
      const candidate = quadraticCurvePoint(geometry, t);
      const distance = (candidate.x - px) ** 2 + (candidate.y - py) ** 2;
      if (distance < nearestDistance) {
        nearestDistance = distance;
        nearestT = t;
      }
    }
    return nearestT;
  }

  function idSet(ids) {
    return new Set((Array.isArray(ids) ? ids : []).map(key).filter(Boolean));
  }

  function normalizeRect(start, end) {
    const startX = finite(start?.x);
    const startY = finite(start?.y);
    const endX = finite(end?.x);
    const endY = finite(end?.y);
    return {
      x: Math.min(startX, endX),
      y: Math.min(startY, endY),
      width: Math.abs(endX - startX),
      height: Math.abs(endY - startY),
    };
  }

  function nodeIdsInRect(nodes, rect) {
    const left = finite(rect?.x);
    const top = finite(rect?.y);
    const right = left + Math.max(0, finite(rect?.width));
    const bottom = top + Math.max(0, finite(rect?.height));
    return (Array.isArray(nodes) ? nodes : []).filter((node) => {
      const nodeLeft = Math.max(0, finite(node?.x));
      const nodeTop = Math.max(0, finite(node?.y));
      const nodeRight = nodeLeft + Math.max(0, finite(node?.width, 150));
      const nodeBottom = nodeTop + Math.max(0, finite(node?.height, 64));
      return nodeLeft <= right && nodeRight >= left && nodeTop <= bottom && nodeBottom >= top;
    }).map((node) => node.id);
  }

  function snapshotNodePositions(nodes, ids) {
    const selected = idSet(ids);
    return (Array.isArray(nodes) ? nodes : [])
      .filter((node) => selected.has(key(node?.id)))
      .map((node) => ({ id: node.id, x: Math.max(0, finite(node.x)), y: Math.max(0, finite(node.y)) }));
  }

  function applyGroupMove(nodes, origins, requestedDx, requestedDy) {
    const snapshots = Array.isArray(origins) ? origins : [];
    if (!snapshots.length) return { dx: 0, dy: 0, moved: false };
    const minimumX = Math.min(...snapshots.map((item) => Math.max(0, finite(item.x))));
    const minimumY = Math.min(...snapshots.map((item) => Math.max(0, finite(item.y))));
    const dx = Math.max(-minimumX, finite(requestedDx));
    const dy = Math.max(-minimumY, finite(requestedDy));
    const originById = new Map(snapshots.map((item) => [key(item.id), item]));
    (Array.isArray(nodes) ? nodes : []).forEach((node) => {
      const origin = originById.get(key(node?.id));
      if (!origin) return;
      node.x = Math.max(0, finite(origin.x) + dx);
      node.y = Math.max(0, finite(origin.y) + dy);
    });
    return { dx, dy, moved: Math.abs(dx) > 0 || Math.abs(dy) > 0 };
  }

  function dragAutoScrollDelta(point, rect, options = {}) {
    const edgeSize = Math.max(16, finite(options.edgeSize, 48));
    const maximumStep = Math.max(1, finite(options.maximumStep, 22));
    const clientX = finite(point?.x);
    const clientY = finite(point?.y);
    const left = finite(rect?.left);
    const top = finite(rect?.top);
    const right = finite(rect?.right, left + Math.max(0, finite(rect?.width)));
    const bottom = finite(rect?.bottom, top + Math.max(0, finite(rect?.height)));
    const axisDelta = (position, start, end) => {
      if (position < start + edgeSize) {
        return -maximumStep * Math.min(1, Math.max(0, (start + edgeSize - position) / edgeSize));
      }
      if (position > end - edgeSize) {
        return maximumStep * Math.min(1, Math.max(0, (position - (end - edgeSize)) / edgeSize));
      }
      return 0;
    };
    return {
      x: axisDelta(clientX, left, right),
      y: axisDelta(clientY, top, bottom),
    };
  }

  function applyBoundaryResize(boundary, origin, requestedDx, requestedDy, options = {}) {
    const result = applyBoundaryResizeFromHandle(boundary, origin, "se", requestedDx, requestedDy, options);
    return { width: result.width, height: result.height, resized: result.resized };
  }

  function applyBoundaryResizeFromHandle(boundary, origin, handle, requestedDx, requestedDy, options = {}) {
    if (!boundary || typeof boundary !== "object") return { x: 0, y: 0, width: 0, height: 0, resized: false };
    const minimumWidth = Math.max(1, finite(options.minWidth, 80));
    const minimumHeight = Math.max(1, finite(options.minHeight, 80));
    const originX = finite(origin?.x, finite(boundary.x));
    const originY = finite(origin?.y, finite(boundary.y));
    const originWidth = Math.max(minimumWidth, finite(origin?.width, minimumWidth));
    const originHeight = Math.max(minimumHeight, finite(origin?.height, minimumHeight));
    const direction = String(handle || "se").toLowerCase();
    const dx = finite(requestedDx);
    const dy = finite(requestedDy);
    let x = originX;
    let y = originY;
    let width = originWidth;
    let height = originHeight;
    if (direction.includes("w")) {
      x = Math.min(originX + originWidth - minimumWidth, originX + dx);
      width = originX + originWidth - x;
    } else if (direction.includes("e")) {
      width = Math.max(minimumWidth, originWidth + dx);
    }
    if (direction.includes("n")) {
      y = Math.min(originY + originHeight - minimumHeight, originY + dy);
      height = originY + originHeight - y;
    } else if (direction.includes("s")) {
      height = Math.max(minimumHeight, originHeight + dy);
    }
    boundary.x = x;
    boundary.y = y;
    boundary.width = width;
    boundary.height = height;
    return {
      x,
      y,
      width,
      height,
      resized: x !== originX || y !== originY || width !== originWidth || height !== originHeight,
    };
  }

  function applyNodeResizeFromHandle(node, origin, handle, requestedDx, requestedDy, options = {}) {
    const result = applyBoundaryResizeFromHandle(node, origin, handle, requestedDx, requestedDy, {
      minWidth: options.minWidth ?? 120,
      minHeight: options.minHeight ?? 56,
    });
    if (node && node.x < 0) {
      node.width = Math.max(options.minWidth ?? 120, node.width + node.x);
      node.x = 0;
    }
    if (node && node.y < 0) {
      node.height = Math.max(options.minHeight ?? 56, node.height + node.y);
      node.y = 0;
    }
    return {
      ...result,
      x: finite(node?.x),
      y: finite(node?.y),
      width: finite(node?.width),
      height: finite(node?.height),
      resized: finite(node?.x) !== finite(origin?.x)
        || finite(node?.y) !== finite(origin?.y)
        || finite(node?.width) !== finite(origin?.width)
        || finite(node?.height) !== finite(origin?.height),
    };
  }

  function nodeDeletionPlan(nodes, edges, ids) {
    const requested = idSet(ids);
    const selectedNodes = (Array.isArray(nodes) ? nodes : []).filter((node) => requested.has(key(node?.id)));
    const selectedIds = new Set(selectedNodes.map((node) => key(node.id)));
    const incidentEdges = (Array.isArray(edges) ? edges : []).filter((edge) => selectedIds.has(key(edge?.source)) || selectedIds.has(key(edge?.target)));
    return {
      nodeIds: selectedNodes.map((node) => node.id),
      edgeIds: incidentEdges.map((edge) => edge.id),
      entryCount: selectedNodes.filter((node) => Boolean(node.is_entry)).length,
      targetCount: selectedNodes.filter((node) => Boolean(node.is_target)).length,
    };
  }

  function removeNodes(graph, ids) {
    const source = graph && typeof graph === "object" ? graph : {};
    const plan = nodeDeletionPlan(source.nodes, source.edges, ids);
    const nodeIds = idSet(plan.nodeIds);
    return {
      ...source,
      nodes: (Array.isArray(source.nodes) ? source.nodes : []).filter((node) => !nodeIds.has(key(node?.id))),
      edges: (Array.isArray(source.edges) ? source.edges : []).filter((edge) => !nodeIds.has(key(edge?.source)) && !nodeIds.has(key(edge?.target))),
      boundaries: Array.isArray(source.boundaries) ? source.boundaries : [],
      plan,
    };
  }

  function layeredLayoutColumns(nodes, edges, options = {}) {
    const items = Array.isArray(nodes) ? nodes.filter((node) => key(node?.id)) : [];
    const nodeById = new Map(items.map((node) => [key(node.id), node]));
    const preferredColumns = options.preferredColumns && typeof options.preferredColumns === "object"
      ? options.preferredColumns
      : {};
    const preferredColumn = (node) => {
      const value = preferredColumns[key(node?.asset_type_id)];
      return Number.isInteger(Number(value)) && Number(value) >= 0 ? Number(value) : null;
    };
    const preferred = new Map(items.map((node) => [key(node.id), preferredColumn(node)]));
    if (items.length && items.every((node) => preferred.get(key(node.id)) !== null)) {
      return Object.fromEntries(items.map((node) => [key(node.id), preferred.get(key(node.id))]));
    }

    const outgoing = new Map(items.map((node) => [key(node.id), []]));
    const incomingCount = new Map(items.map((node) => [key(node.id), 0]));
    const seenEdges = new Set();
    (Array.isArray(edges) ? edges : []).forEach((edge) => {
      const source = key(edge?.source);
      const target = key(edge?.target);
      const edgeKey = `${source}\u0000${target}`;
      if (!nodeById.has(source) || !nodeById.has(target) || source === target || seenEdges.has(edgeKey)) return;
      seenEdges.add(edgeKey);
      outgoing.get(source).push(target);
      incomingCount.set(target, incomingCount.get(target) + 1);
    });
    const kindOrder = { external: 0, process: 1, data_store: 2 };
    const stableOrder = (left, right) => {
      const leftPreferred = preferred.get(key(left.id));
      const rightPreferred = preferred.get(key(right.id));
      return (leftPreferred ?? 999) - (rightPreferred ?? 999)
        || (kindOrder[key(left?.dfd_kind)] ?? 1) - (kindOrder[key(right?.dfd_kind)] ?? 1)
        || finite(left?.x) - finite(right?.x)
        || finite(left?.y) - finite(right?.y)
        || key(left?.id).localeCompare(key(right?.id));
    };
    items.sort(stableOrder);
    outgoing.forEach((targets) => targets.sort((left, right) => stableOrder(nodeById.get(left), nodeById.get(right))));

    const columns = new Map();
    const visitFrom = (rootIds, startColumn = 0) => {
      const queue = rootIds.map((id) => ({ id, column: startColumn }));
      for (let index = 0; index < queue.length; index += 1) {
        const current = queue[index];
        if (columns.has(current.id)) continue;
        columns.set(current.id, current.column);
        (outgoing.get(current.id) || []).forEach((target) => {
          if (!columns.has(target)) queue.push({ id: target, column: current.column + 1 });
        });
      }
    };
    const roots = items
      .filter((node) => incomingCount.get(key(node.id)) === 0)
      .map((node) => key(node.id));
    if (roots.length) visitFrom(roots);
    while (columns.size < items.length) {
      const next = items.find((node) => !columns.has(key(node.id)));
      if (!next) break;
      // Choose a stable structural root for cyclic components.
      visitFrom([key(next.id)]);
    }
    return Object.fromEntries(items.map((node) => [key(node.id), columns.get(key(node.id)) ?? 0]));
  }

  return Object.freeze({ displayName, wrapLabel, automaticNodeSize, inferredFlowLevel, selectFlowTemplate, flowCatalogMetadata, collectorEdgeSelectedByDefault, explicitEdgeCurveOffset, explicitEdgeLabelT, automaticEdgeCurveOffsets, quadraticCurveGeometry, quadraticCurvePoint, nearestQuadraticCurveT, normalizeRect, nodeIdsInRect, snapshotNodePositions, applyGroupMove, dragAutoScrollDelta, applyBoundaryResize, applyBoundaryResizeFromHandle, applyNodeResizeFromHandle, nodeDeletionPlan, removeNodes, layeredLayoutColumns });
});
