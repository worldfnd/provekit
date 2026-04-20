function splitTopLevel(str, delimiter) {
  const parts = [];
  let current = "";
  let inString = false;
  let stringDelimiter = "";
  let braceDepth = 0;
  let bracketDepth = 0;

  for (let index = 0; index < str.length; index += 1) {
    const char = str[index];

    if (inString) {
      current += char;
      if (char === stringDelimiter && str[index - 1] !== "\\") {
        inString = false;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      inString = true;
      stringDelimiter = char;
      current += char;
      continue;
    }

    if (char === "{") braceDepth += 1;
    if (char === "}") braceDepth -= 1;
    if (char === "[") bracketDepth += 1;
    if (char === "]") bracketDepth -= 1;

    if (char === delimiter && braceDepth === 0 && bracketDepth === 0) {
      parts.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  if (current.trim()) {
    parts.push(current);
  }

  return parts;
}

function parseInlineTable(raw) {
  const inner = raw.slice(1, -1).trim();
  if (!inner) {
    return {};
  }

  const result = {};
  for (const pair of splitTopLevel(inner, ",")) {
    const trimmed = pair.trim();
    if (!trimmed) {
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    const value = trimmed.slice(separatorIndex + 1).trim();
    result[key] = parseTomlValue(value);
  }

  return result;
}

function parseTomlArray(raw) {
  const inner = raw.slice(1, -1).trim();
  if (!inner) {
    return [];
  }

  return splitTopLevel(inner, ",")
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => parseTomlValue(value));
}

function parseTomlValue(raw) {
  if (raw.startsWith("{") && raw.endsWith("}")) {
    return parseInlineTable(raw);
  }

  if (raw.startsWith("[") && raw.endsWith("]")) {
    return parseTomlArray(raw);
  }

  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    return raw.slice(1, -1);
  }

  return raw;
}

function setNested(target, path, value) {
  let cursor = target;

  for (let index = 0; index < path.length - 1; index += 1) {
    const segment = path[index];
    const existing = cursor[segment];

    if (typeof existing !== "object" || existing === null || Array.isArray(existing)) {
      cursor[segment] = {};
    }

    cursor = cursor[segment];
  }

  cursor[path[path.length - 1]] = value;
}

export function parseSimpleToml(content) {
  const logicalLines = [];
  const rawLines = content.split("\n");
  let pendingLine = "";
  let arrayDepth = 0;

  for (const rawLine of rawLines) {
    const trimmed = rawLine.trim();
    if (!pendingLine && (!trimmed || trimmed.startsWith("#"))) {
      continue;
    }

    if (pendingLine) {
      if (trimmed.startsWith("#")) {
        continue;
      }
      pendingLine += ` ${trimmed}`;
      for (const char of trimmed) {
        if (char === "[") arrayDepth += 1;
        else if (char === "]") arrayDepth -= 1;
      }
      if (arrayDepth <= 0) {
        logicalLines.push(pendingLine);
        pendingLine = "";
        arrayDepth = 0;
      }
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex !== -1) {
      const value = trimmed.slice(separatorIndex + 1).trim();
      let valueDepth = 0;
      for (const char of value) {
        if (char === "[") valueDepth += 1;
        else if (char === "]") valueDepth -= 1;
      }
      if (valueDepth > 0) {
        pendingLine = trimmed;
        arrayDepth = valueDepth;
        continue;
      }
    }

    logicalLines.push(trimmed);
  }

  const result = {};
  let section = null;

  for (const line of logicalLines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const sectionMatch = trimmed.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      section = sectionMatch[1];
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    const value = parseTomlValue(trimmed.slice(separatorIndex + 1).trim());
    const path = section ? [section, ...key.split(".")] : key.split(".");
    setNested(result, path, value);
  }

  return result;
}
