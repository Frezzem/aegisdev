import type { Ecosystem, PackageRef } from "./types.js";

export class PackageInputError extends Error {}

const NPM_NAME_RE =
  /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;
const PYPI_NAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const SHELL_DANGER_RE = /[;&|`$(){}\n\r]/;
const NPM_MANAGERS = new Set(["npm", "pnpm", "yarn", "bun"]);
const PYPI_MANAGERS = new Set(["pip", "pip3", "python", "python3", "py", "uv", "poetry", "pdm"]);

const FLAGS_WITH_VALUE = new Set([
  "--registry",
  "--index-url",
  "-i",
  "--extra-index-url",
  "--trusted-host",
  "--target",
  "--prefix",
  "--cache",
  "--cache-dir",
  "--requirement",
  "-r",
  "--constraint",
  "-c",
  "--python",
  "-p",
  "--group",
  "-G",
  "--source",
]);

const BOOLEAN_FLAGS = new Set([
  "-D",
  "--save-dev",
  "--save",
  "--save-exact",
  "--no-save",
  "--pre",
  "--user",
  "--upgrade",
  "-U",
  "--force",
  "--no-cache-dir",
  "--quiet",
  "-q",
  "--yes",
  "-y",
  "--global",
  "-g",
  "--dev",
  "--optional",
  "--exact",
  "--no-lockfile",
  "--frozen-lockfile",
  "--verbose",
]);

/**
 * Parse a package name or an install command into a single, safe package
 * reference. The install command is rebuilt from validated components so a
 * pasted string can never smuggle extra shell commands into the terminal.
 */
export function parsePackageInput(input: string): PackageRef {
  const raw = input.trim();
  if (!raw) {
    throw new PackageInputError("请输入包名或 install 命令，例如 npm install lodash 或 pip install requests。");
  }
  if (raw.length > 300) {
    throw new PackageInputError("输入过长，请只提供单个包名或一条 install 命令。");
  }
  if (SHELL_DANGER_RE.test(raw)) {
    throw new PackageInputError("输入包含 Shell 特殊字符。为安全起见，Aegis 只解析单个包，不会拼接执行原始命令。");
  }

  const tokens = raw
    .replace(/^["'`]|["'`]$/g, "")
    .split(/\s+/)
    .filter(Boolean);

  if (tokens.length === 0) {
    throw new PackageInputError("未找到包名。");
  }

  const first = tokens[0]!.toLowerCase();
  let ecosystem: Ecosystem;
  let manager = "npm";
  let packageTokens: string[];

  if (NPM_MANAGERS.has(first)) {
    ecosystem = "npm";
    manager = first;
    packageTokens = parseCommandTail(tokens, 1, first, "add");
  } else if (PYPI_MANAGERS.has(first)) {
    ecosystem = "pypi";
    const parsed = parsePypiCommand(tokens);
    manager = parsed.manager;
    packageTokens = parsed.packages;
  } else {
    // Bare package name: default to npm, which is the dominant AI-generated
    // install target. PyPI users can type `pip install <name>`.
    ecosystem = "npm";
    packageTokens = parseCommandTail(tokens, 0, "npm", "install");
  }

  if (packageTokens.length === 0) {
    throw new PackageInputError("未找到要校验的包名。");
  }
  if (packageTokens.length > 1) {
    throw new PackageInputError(
      `一次只能校验一个包，检测到 ${packageTokens.length} 个。请逐个校验，避免漏检。`,
    );
  }

  const token = packageTokens[0]!;
  return ecosystem === "npm"
    ? buildNpmRef(token, manager, raw)
    : buildPypiRef(token, manager, raw);
}

function parseCommandTail(
  tokens: string[],
  start: number,
  manager: string,
  expectedVerb: string,
): string[] {
  let index = start;
  const verb = tokens[index]?.toLowerCase();
  if (verb && ["install", "i", "add", "ci"].includes(verb)) {
    index += 1;
  } else if (verb && verb === "remove") {
    throw new PackageInputError("只支持校验并安装依赖，不支持 remove。");
  } else if (start > 0) {
    // `npm foo` is not an install command.
    throw new PackageInputError(`无法识别 ${manager} 的子命令，请使用 ${manager} ${expectedVerb} <package>。`);
  }
  return collectPackages(tokens.slice(index));
}

function parsePypiCommand(tokens: string[]): { manager: string; packages: string[] } {
  const first = tokens[0]!.toLowerCase();
  if (first === "python" || first === "python3" || first === "py") {
    const mIndex = tokens.findIndex((t) => t === "-m");
    if (mIndex === -1 || tokens[mIndex + 1] !== "pip") {
      throw new PackageInputError("只支持 python -m pip install <package> 形式。");
    }
    const tail = tokens.slice(mIndex + 2);
    if (tail[0] !== "install") {
      throw new PackageInputError("只支持 python -m pip install <package>。");
    }
    return { manager: `${tokens[0]} -m pip`, packages: collectPackages(tail.slice(1)) };
  }
  if (first === "uv") {
    if (tokens[1] === "pip" && tokens[2] === "install") {
      return { manager: "uv pip", packages: collectPackages(tokens.slice(3)) };
    }
    if (tokens[1] === "add") {
      return { manager: "uv", packages: collectPackages(tokens.slice(2)) };
    }
    throw new PackageInputError("只支持 uv add 或 uv pip install <package>。");
  }
  if (first === "poetry" || first === "pdm") {
    if (tokens[1] !== "add") {
      throw new PackageInputError(`只支持 ${first} add <package>。`);
    }
    return { manager: first, packages: collectPackages(tokens.slice(2)) };
  }
  // pip / pip3
  const tail = tokens.slice(1);
  if (tail[0] !== "install") {
    throw new PackageInputError("只支持 pip install <package>。");
  }
  return { manager: "pip", packages: collectPackages(tail.slice(1)) };
}

function collectPackages(tokens: string[]): string[] {
  const packages: string[] = [];
  let skipNext = false;
  let flagsEnded = false;

  for (const token of tokens) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (!flagsEnded && token === "--") {
      flagsEnded = true;
      continue;
    }
    if (!flagsEnded && token.startsWith("-")) {
      if (token === "-e" || token === "--editable") {
        throw new PackageInputError("不支持可编辑安装 / 本地路径，请只校验 registry 中的已发布包。");
      }
      if (token.includes("=")) {
        continue;
      }
      if (FLAGS_WITH_VALUE.has(token)) {
        skipNext = true;
      } else if (!BOOLEAN_FLAGS.has(token)) {
        // Unknown flags are ignored, but an immediately following value could
        // be mistaken for a package. Refuse ambiguous input rather than verify
        // the wrong package.
        throw new PackageInputError(`无法安全解析参数 ${token}，请去掉该参数后只保留包名。`);
      }
      continue;
    }
    packages.push(token);
  }
  return packages;
}

function buildNpmRef(token: string, manager: string, raw: string): PackageRef {
  if (token.includes(":") || token.includes("/") && !token.startsWith("@")) {
    throw new PackageInputError("只支持 NPM registry 中的包名，不支持 URL 或本地路径。");
  }
  if (token.startsWith("@")) {
    const slash = token.indexOf("/");
    if (slash <= 1) {
      throw new PackageInputError("scope 包格式应为 @scope/package。");
    }
  }
  const at = token.indexOf("@", 1);
  const name = at === -1 ? token : token.slice(0, at);
  const versionSpec = at === -1 ? undefined : token.slice(at + 1);

  if (!NPM_NAME_RE.test(name)) {
    throw new PackageInputError(`无效的 NPM 包名：${name}`);
  }
  if (versionSpec !== undefined) {
    if (!versionSpec || !/^[A-Za-z0-9^~<>=*.+_-]+$/.test(versionSpec)) {
      throw new PackageInputError(`无法解析版本范围：${versionSpec}`);
    }
  }

  const version = versionSpec ? `@${versionSpec}` : "";
  const spec = `${name}${version}`;
  const prefix =
    manager === "pnpm" ? "pnpm add" : manager === "yarn" ? "yarn add" : manager === "bun" ? "bun add" : "npm install";

  return {
    ecosystem: "npm",
    name,
    versionSpec,
    exactVersion: versionSpec !== undefined && /^\d+\.\d+\.\d+(?:[-+].*)?$/.test(versionSpec),
    installCommand: `${prefix} ${quoteShellArg(spec)}`,
    manager: manager === "npm" ? "npm" : manager,
    raw,
    spec,
  };
}

function buildPypiRef(token: string, manager: string, raw: string): PackageRef {
  if (/^(?:git\+|https?:|file:|\.|\/)/i.test(token) || token.includes("@")) {
    throw new PackageInputError("只支持 PyPI registry 中的包名，不支持 URL、VCS 或本地路径。");
  }

  const extrasMatch = /^([A-Za-z0-9._-]+)(\[[A-Za-z0-9,._-]+\])?((?:===|==|~=|!=|<=|>=|<|>).*)?$/.exec(
    token,
  );
  if (!extrasMatch) {
    throw new PackageInputError(`无法解析 PyPI 包规格：${token}`);
  }
  const name = extrasMatch[1]!;
  const extras = extrasMatch[2] ?? "";
  const versionSpec = extrasMatch[3]?.replace(/^(===|==|~=|!=|<=|>=|<|>)/, "");
  const operator = extrasMatch[3]?.slice(0, extrasMatch[3].length - (versionSpec?.length ?? 0)) ?? "";

  if (!PYPI_NAME_RE.test(name)) {
    throw new PackageInputError(`无效的 PyPI 包名：${name}`);
  }
  if (versionSpec !== undefined && !/^[A-Za-z0-9.*+_-]+$/.test(versionSpec)) {
    throw new PackageInputError(`无法解析版本范围：${versionSpec}`);
  }

  const spec = `${name}${extras}${operator}${versionSpec ?? ""}`;
  const prefix =
    manager === "poetry" || manager === "pdm"
      ? `${manager} add`
      : manager === "uv"
        ? "uv add"
        : manager === "uv pip"
          ? "uv pip install"
          : manager.includes(" -m pip")
            ? `${manager} install`
            : "pip install";

  return {
    ecosystem: "pypi",
    name,
    versionSpec,
    exactVersion: operator === "==" && versionSpec !== undefined && !/[*]/.test(versionSpec),
    installCommand: `${prefix} ${quoteShellArg(spec)}`,
    manager,
    raw,
    spec,
  };
}

function quoteShellArg(value: string): string {
  // Package names/specs are validated above. Whitelisting the characters that
  // are safe in both POSIX shells and cmd.exe avoids any quoting ambiguity.
  if (/^[A-Za-z0-9@/._^~=*+-]+$/.test(value)) {
    return value;
  }
  return `"${value.replace(/["`$]/g, "")}"`;
}
