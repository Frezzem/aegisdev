import type {
  FileScanResult,
  FindingCategory,
  Severity,
  UnicodeFinding,
} from "./types.js";

interface CodePointDefinition {
  name: string;
  category: FindingCategory;
  severity: Severity;
}

const ZERO_WIDTH = new Set([
  0x200b, // ZERO WIDTH SPACE
  0x200c, // ZERO WIDTH NON-JOINER
  0x200d, // ZERO WIDTH JOINER
  0x2060, // WORD JOINER
  0xfeff, // ZERO WIDTH NO-BREAK SPACE / BOM
  0x180e, // MONGOLIAN VOWEL SEPARATOR
]);

const BIDI = new Set([
  0x061c, // ARABIC LETTER MARK
  0x200e, // LEFT-TO-RIGHT MARK
  0x200f, // RIGHT-TO-LEFT MARK
  0x202a, // LEFT-TO-RIGHT EMBEDDING
  0x202b, // RIGHT-TO-LEFT EMBEDDING
  0x202c, // POP DIRECTIONAL FORMATTING
  0x202d, // LEFT-TO-RIGHT OVERRIDE
  0x202e, // RIGHT-TO-LEFT OVERRIDE
  0x2066, // LEFT-TO-RIGHT ISOLATE
  0x2067, // RIGHT-TO-LEFT ISOLATE
  0x2068, // FIRST STRONG ISOLATE
  0x2069, // POP DIRECTIONAL ISOLATE
]);

const INVISIBLE = new Set([
  0x00ad, // SOFT HYPHEN
  0x034f, // COMBINING GRAPHEME JOINER
  0x115f, // HANGUL CHOSEONG FILLER
  0x1160, // HANGUL JUNGSEONG FILLER
  0x17b4, // KHMER VOWEL INHERENT AQ
  0x17b5, // KHMER VOWEL INHERENT AA
  0x2800, // BRAILLE PATTERN BLANK
  0x3164, // HANGUL FILLER
  0xffa0, // HALFWIDTH HANGUL FILLER
  0x001b, // ESC — ANSI escape sequence introducer
]);

const NAMED: Record<number, CodePointDefinition> = {
  0x061c: { name: "阿拉伯字母标记 (ALM)", category: "bidi", severity: "high" },
  0x200b: { name: "零宽空格 (ZWSP)", category: "zero-width", severity: "medium" },
  0x200c: { name: "零宽不连字 (ZWNJ)", category: "zero-width", severity: "low" },
  0x200d: { name: "零宽连字 (ZWJ)", category: "zero-width", severity: "low" },
  0x2060: { name: "词连接符 (Word Joiner)", category: "zero-width", severity: "medium" },
  0xfeff: { name: "零宽不换行空格 (BOM)", category: "zero-width", severity: "medium" },
  0x180e: { name: "蒙古文元音分隔符", category: "zero-width", severity: "low" },
  0x200e: { name: "从左到右标记 (LRM)", category: "bidi", severity: "high" },
  0x200f: { name: "从右到左标记 (RLM)", category: "bidi", severity: "high" },
  0x202a: { name: "从左到右嵌入 (LRE)", category: "bidi", severity: "high" },
  0x202b: { name: "从右到左嵌入 (RLE)", category: "bidi", severity: "high" },
  0x202c: { name: "方向格式化结束 (PDF)", category: "bidi", severity: "high" },
  0x202d: { name: "从左到右覆盖 (LRO)", category: "bidi", severity: "high" },
  0x202e: { name: "从右到左覆盖 (RLO)", category: "bidi", severity: "high" },
  0x2066: { name: "从左到右隔离 (LRI)", category: "bidi", severity: "high" },
  0x2067: { name: "从右到左隔离 (RLI)", category: "bidi", severity: "high" },
  0x2068: { name: "首强隔离 (FSI)", category: "bidi", severity: "high" },
  0x2069: { name: "隔离结束 (PDI)", category: "bidi", severity: "high" },
  0x00ad: { name: "软连字符 (Soft Hyphen)", category: "invisible", severity: "medium" },
  0x034f: { name: "组合字素连接符 (CGJ)", category: "invisible", severity: "low" },
  0x115f: { name: "谚文字母填充符", category: "invisible", severity: "low" },
  0x1160: { name: "谚文元音填充符", category: "invisible", severity: "low" },
  0x17b4: { name: "高棉文隐藏元音", category: "invisible", severity: "low" },
  0x17b5: { name: "高棉文隐藏元音", category: "invisible", severity: "low" },
  0x2800: { name: "盲文空白字符", category: "invisible", severity: "medium" },
  0x3164: { name: "谚文填充符", category: "invisible", severity: "low" },
  0xffa0: { name: "半角谚文填充符", category: "invisible", severity: "low" },
  0x001b: { name: "ESC 控制字符 (ANSI 转义)", category: "invisible", severity: "high" },
};

const PAYLOAD_HIGH_RE =
  /(curl|wget|powershell|invoke-expression|iex\b|bash\b|\bsh\b|\.ssh|id_rsa|api[_-]?key|secret|token|exfiltrat|ignore\s+(all\s+)?(previous|prior)|system\s+prompt|rm\s+-rf|base64)/i;
const PAYLOAD_MEDIUM_RE =
  /(https?:\/\/|exec\b|eval\b|upload|post\b|send\b|read\b|instruction|assistant|tool_call)/i;

const MAX_FINDINGS_PER_FILE = 200;
const MAX_DECODED_LENGTH = 600;

export function classifyCodePoint(cp: number): CodePointDefinition | undefined {
  if (cp >= 0xe0000 && cp <= 0xe007f) {
    return {
      name: "Unicode Tag 隐藏指令 (ASCII 走私)",
      category: "tag",
      severity: "critical",
    };
  }
  if (cp >= 0xe0100 && cp <= 0xe01ef) {
    return {
      name: "变体选择符补充区 (隐藏数据)",
      category: "variation-selector",
      severity: "high",
    };
  }
  if (BIDI.has(cp)) {
    return NAMED[cp] ?? { name: "双向控制字符", category: "bidi", severity: "high" };
  }
  if (ZERO_WIDTH.has(cp)) {
    return (
      NAMED[cp] ?? { name: "零宽字符", category: "zero-width", severity: "medium" }
    );
  }
  if (INVISIBLE.has(cp)) {
    return (
      NAMED[cp] ?? { name: "不可见字符", category: "invisible", severity: "medium" }
    );
  }
  return undefined;
}

export function scanContent(
  text: string,
  file: string,
  languageHint = "plaintext",
): FileScanResult {
  const findings: UnicodeFinding[] = [];
  const lineStarts = computeLineStarts(text);
  let lineNumber = 1;
  let lineStart = 0;
  let lineIndex = 0;

  while (lineIndex <= text.length) {
    const newline = text.indexOf("\n", lineIndex);
    const lineEnd = newline === -1 ? text.length : newline;
    // Keep the CR out of findings/context on Windows files. Offsets before the
    // CR are unaffected, so deletion ranges remain correct.
    const line = text.slice(lineIndex, lineEnd).replace(/\r$/, "");
    lineStart = lineIndex;

    scanLine(text, line, file, lineNumber, lineStart, lineEnd, findings);
    if (findings.length >= MAX_FINDINGS_PER_FILE) {
      break;
    }

    if (newline === -1) {
      break;
    }
    lineIndex = newline + 1;
    lineNumber += 1;
  }

  // Decode tag payload only once per file; adjacent tag runs are grouped in
  // scanLine, so every finding already carries its own payload.
  const risk = aggregateRisk(findings);
  return {
    file,
    languageHint,
    size: text.length,
    findings,
    risk,
    sanitized: findings.some((f) => f.fixable) ? sanitizeText(text, findings) : undefined,
  };

  function scanLine(
    fullText: string,
    line: string,
    displayFile: string,
    lineNo: number,
    absoluteStart: number,
    _absoluteEnd: number,
    out: UnicodeFinding[],
  ): void {
    let i = 0;
    while (i < line.length) {
      const cp = line.codePointAt(i);
      if (cp === undefined) {
        break;
      }
      const width = cp > 0xffff ? 2 : 1;
      if (lineNo === 1 && absoluteStart === 0 && i === 0 && cp === 0xfeff) {
        // A UTF-8 BOM at the very start is a transport artifact, not a hidden
        // instruction. TextDecoder normally strips it before we get here.
        i += 1;
        continue;
      }
      const definition = classifyCodePoint(cp);

      if (definition?.category === "tag") {
        if (out.length >= MAX_FINDINGS_PER_FILE) {
          break;
        }
        const run = consumeRun(line, i, (c) => c >= 0xe0000 && c <= 0xe007f);
        const decoded = decodeTagPayload(line.slice(i, i + run.length));
        const payloadRisk = scorePayload(decoded);
        out.push(
          makeFinding({
            file: displayFile,
            line: lineNo,
            column: i + 1,
            index: absoluteStart + i,
            length: run.length,
            codePoint: cp,
            hex: hex(cp),
            name: definition.name,
            category: "tag",
            severity: "critical",
            context: renderContext(line),
            decoded,
            payloadRisk,
            message:
              payloadRisk === "high"
                ? "检测到 Unicode Tag 隐藏指令，且内容包含命令执行 / 凭据外泄特征。"
                : "检测到不可见的 Unicode Tag 字符，Agent 可能读取并执行其中的隐藏指令。",
          }),
        );
        i += run.length;
        continue;
      }

      if (definition) {
        if (out.length >= MAX_FINDINGS_PER_FILE) {
          break;
        }
        const category = definition.category;
        const run = consumeRun(
          line,
          i,
          (c) => classifyCodePoint(c)?.category === category,
        );
        const count = [...line.slice(i, i + run.length)].length;
        out.push(
          makeFinding({
            file: displayFile,
            line: lineNo,
            column: i + 1,
            index: absoluteStart + i,
            length: run.length,
            codePoint: cp,
            hex: hex(cp),
            name: count > 1 ? `${definition.name} ×${count}` : definition.name,
            category,
            severity: definition.severity,
            context: renderContext(line),
            message: describeInvisible(category),
          }),
        );
        i += run.length;
        continue;
      }

      i += width;
    }

    scanEscapes(line, lineNo, absoluteStart, displayFile, out);
    scanHomoglyphs(line, lineNo, absoluteStart, displayFile, out);
  }
}

function scanEscapes(
  line: string,
  lineNo: number,
  absoluteStart: number,
  file: string,
  out: UnicodeFinding[],
): void {
  const escapeRe = /\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})/g;
  const matches: Array<{
    index: number;
    length: number;
    cp: number;
    definition: CodePointDefinition;
  }> = [];
  let match: RegExpExecArray | null;
  while ((match = escapeRe.exec(line)) !== null) {
    const hexValue = match[1] ?? match[2] ?? match[3];
    if (!hexValue) {
      continue;
    }
    const cp = Number.parseInt(hexValue, 16);
    const definition = classifyCodePoint(cp);
    if (!definition) {
      continue;
    }
    matches.push({ index: match.index, length: match[0].length, cp, definition });
  }

  for (let i = 0; i < matches.length; ) {
    const first = matches[i]!;
    let end = i + 1;
    let combinedLength = first.length;
    let decoded = first.cp >= 0xe0000 && first.cp <= 0xe007f
      ? decodeTagPayload(String.fromCodePoint(first.cp))
      : "";

    while (end < matches.length) {
      const current = matches[end]!;
      const previous = matches[end - 1]!;
      if (
        previous.index + previous.length !== current.index ||
        current.definition.category !== first.definition.category
      ) {
        break;
      }
      combinedLength += current.length;
      if (current.cp >= 0xe0000 && current.cp <= 0xe007f) {
        decoded += decodeTagPayload(String.fromCodePoint(current.cp));
      }
      end += 1;
    }

    const count = end - i;
    out.push(
      makeFinding({
        file,
        line: lineNo,
        column: first.index + 1,
        index: absoluteStart + first.index,
        length: combinedLength,
        codePoint: first.cp,
        hex: hex(first.cp),
        name:
          count > 1
            ? `转义后的${first.definition.name} ×${count}`
            : `转义后的${first.definition.name}`,
        category: "escaped",
        severity: first.definition.severity,
        context: renderContext(line),
        decoded: decoded || undefined,
        payloadRisk: decoded ? scorePayload(decoded) : "none",
        message: "隐藏字符以转义序列形式写入配置，JSON / YAML 解析后仍会生效。",
      }),
    );
    if (out.length >= MAX_FINDINGS_PER_FILE) {
      break;
    }
    i = end;
  }
}

function scanHomoglyphs(
  line: string,
  lineNo: number,
  absoluteStart: number,
  file: string,
  out: UnicodeFinding[],
): void {
  // Mixed Latin + Cyrillic/Greek inside a single token is a classic way to
  // disguise commands (e.g. "cur1" or "npm" with a Cyrillic letter).
  const tokenRe = /[A-Za-z0-9_./:@\\\u0400-\u04ff\u0370-\u03ff-]{3,}/g;
  let match: RegExpExecArray | null;
  while ((match = tokenRe.exec(line)) !== null) {
    const token = match[0];
    if (!/[A-Za-z]/.test(token) || !/[\u0400-\u04ff\u0370-\u03ff]/.test(token)) {
      continue;
    }
    const hasLatin = /[A-Za-z]/.test(token);
    const hasConfusable = /[\u0400-\u04ff\u0370-\u03ff]/.test(token);
    if (!hasLatin || !hasConfusable) {
      continue;
    }
    out.push(
      makeFinding({
        file,
        line: lineNo,
        column: match.index + 1,
        index: absoluteStart + match.index,
        length: token.length,
        codePoint: token.codePointAt(0) ?? 0,
        hex: hex(token.codePointAt(0) ?? 0),
        name: "混合字符集令牌（疑似同形字伪装）",
        category: "homoglyph",
        severity: "high",
        context: renderContext(line),
        message: "令牌同时包含拉丁字母和西里尔 / 希腊字母，可能用于伪装命令或路径。",
        fixable: false,
      }),
    );
    if (out.length >= MAX_FINDINGS_PER_FILE) {
      break;
    }
  }
}

function describeInvisible(category: FindingCategory): string {
  switch (category) {
    case "bidi":
      return "双向文本控制字符可让配置文件在编辑器中显示的顺序与解析顺序不一致。";
    case "zero-width":
      return "零宽字符不可见，可拆分关键字以绕过关键词检测或隐藏内容。";
    case "variation-selector":
      return "补充区变体选择符可在看似正常的 emoji / 文本中夹带隐藏数据。";
    case "invisible":
      return "不可见字符可用于隐藏指令、拆分关键字或污染配置。";
    default:
      return "该字符在配置中可能隐藏内容或绕过检测。";
  }
}

export function sanitizeText(text: string, findings: UnicodeFinding[]): string {
  const ranges = findings
    .filter((finding) => finding.fixable)
    .map((finding) => [finding.index, finding.index + finding.length] as const)
    .sort((a, b) => b[0] - a[0]);

  let output = text;
  let lastStart = Number.POSITIVE_INFINITY;
  for (const [start, end] of ranges) {
    if (end > lastStart) {
      // Overlapping range (e.g. escaped and raw detection) — skip.
      continue;
    }
    output = output.slice(0, start) + output.slice(end);
    lastStart = start;
  }
  return output;
}

export function renderContext(line: string, maxLength = 240): string {
  let output = "";
  for (let i = 0; i < line.length; ) {
    const cp = line.codePointAt(i);
    if (cp === undefined) {
      break;
    }
    const width = cp > 0xffff ? 2 : 1;
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      // Collapse an entire invisible ASCII payload into one marker so the
      // surrounding JSON remains readable.
      let count = 0;
      let j = i;
      while (j < line.length) {
        const tagCp = line.codePointAt(j);
        if (tagCp === undefined || tagCp < 0xe0000 || tagCp > 0xe007f) {
          break;
        }
        count += 1;
        j += tagCp > 0xffff ? 2 : 1;
      }
      output += `⟨Tag 隐藏 ×${count}⟩`;
      i = j;
      continue;
    }
    const definition = classifyCodePoint(cp);
    if (definition) {
      if (definition.category === "zero-width") {
        let count = 1;
        let j = i + width;
        while (j < line.length) {
          const next = line.codePointAt(j);
          if (next === undefined || next !== cp) {
            break;
          }
          count += 1;
          j += next > 0xffff ? 2 : 1;
        }
        output += count > 1 ? `⟨U+${hex(cp)} ×${count}⟩` : `⟨U+${hex(cp)}⟩`;
        i = j;
        continue;
      }
      output += `⟨U+${hex(cp)}⟩`;
    } else if (cp === 0x09) {
      output += "  ";
    } else if (cp < 0x20) {
      output += `⟨U+${hex(cp)}⟩`;
    } else {
      output += line.slice(i, i + width);
    }
    if (output.length > maxLength * 2) {
      output += "…";
      break;
    }
    i += width;
  }
  const trimmed = output.trim();
  return trimmed.length > maxLength ? `${trimmed.slice(0, maxLength)}…` : trimmed;
}

export function aggregateRisk(findings: UnicodeFinding[]): Severity | "none" {
  if (findings.some((f) => f.severity === "critical")) {
    return "critical";
  }
  if (findings.some((f) => f.severity === "high")) {
    return "high";
  }
  if (findings.some((f) => f.severity === "medium")) {
    return "medium";
  }
  if (findings.some((f) => f.severity === "low")) {
    return "low";
  }
  return "none";
}

export function countSeverities(findings: UnicodeFinding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

export function severityRank(severity: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[severity];
}

export function hex(cp: number): string {
  return cp.toString(16).toUpperCase().padStart(4, "0");
}

interface FindingInput {
  file: string;
  line: number;
  column: number;
  index: number;
  length: number;
  codePoint: number;
  hex: string;
  name: string;
  category: FindingCategory;
  severity: Severity;
  context: string;
  message: string;
  decoded?: string;
  payloadRisk?: "high" | "medium" | "none";
  fixable?: boolean;
}

function makeFinding(input: FindingInput): UnicodeFinding {
  return {
    ...input,
    id: `${input.file}#${input.index}:${input.length}:${input.hex}`,
    fixable: input.fixable ?? true,
  };
}

function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === "\n") {
      starts.push(i + 1);
    }
  }
  return starts;
}

function consumeRun(
  line: string,
  start: number,
  predicate: (cp: number) => boolean,
): { length: number } {
  let i = start;
  while (i < line.length) {
    const cp = line.codePointAt(i);
    if (cp === undefined || !predicate(cp)) {
      break;
    }
    i += cp > 0xffff ? 2 : 1;
  }
  return { length: i - start };
}

export function decodeTagPayload(value: string): string {
  let decoded = "";
  for (const char of value) {
    const cp = char.codePointAt(0) ?? 0;
    if (cp < 0xe0000 || cp > 0xe007f) {
      continue;
    }
    const ascii = cp - 0xe0000;
    if (ascii === 0x7f) {
      continue; // cancel tag
    }
    if (ascii >= 0x20 && ascii <= 0x7e) {
      decoded += String.fromCharCode(ascii);
    }
  }
  const trimmed = decoded.trim();
  return trimmed.length > MAX_DECODED_LENGTH
    ? `${trimmed.slice(0, MAX_DECODED_LENGTH)}…`
    : trimmed;
}

export function scorePayload(payload: string): "high" | "medium" | "none" {
  if (!payload) {
    return "none";
  }
  if (PAYLOAD_HIGH_RE.test(payload)) {
    return "high";
  }
  if (PAYLOAD_MEDIUM_RE.test(payload)) {
    return "medium";
  }
  return "none";
}

// Kept exported for tests / future diagnostics.
export const __internal = { lineStarts: computeLineStarts, named: NAMED };
