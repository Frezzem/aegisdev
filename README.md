# AegisDev

AegisDev 是一个面向 AI 编程场景的本地安全护栏（VS Code / Cursor 扩展，附带 CLI 与 MCP Server），在代码进入 Agent 上下文之前拦截风险，并提供提交前的本地大模型审查。

能力：

- **防幻觉包 / 供应链投毒**：安装依赖前核验 npm / PyPI 包是否真实存在、是否可信（幻觉包 / 抢注包 / 拼写混淆 / 已知漏洞）。
- **敏感信息与隐藏木马字符扫描**：基于正则 + 信息熵扫描硬编码密钥（Token / Key / 私钥），并检测 Unicode 隐藏字符、同形字伪装等木马字符。
- **基于本地模型的 Git Hook 智能审查与强制阻断**：用 Ollama / LM Studio 本地大模型审查代码 Diff（越权查询 / 数据过度暴露 / 前端伪鉴权），发现高危即阻断提交。

所有扫描与审查均在本机完成，代码内容不上传云端。遇到网络失败或数据源超时一律 `review` / `block`（Fail-close），不误放行。

当前版本：3.2.0。

> 团队成员接入请阅读 [《AegisDev V3.2 团队接入指南》](ONBOARDING.md)。

# 三端入口（一核多壳）

核心逻辑位于 `src/core/`（纯 Node，不含 VS Code 依赖），三端外壳复用同一套核心：

| 壳 | 入口 | 说明 |
| --- | --- | --- |
| IDE 插件 | `src/extension.ts` | VS Code / Cursor 扩展，Problems 红线 + Quick Fix + 安全面板 |
| CLI / Git Hook | `bin/aegis-cli.js` | `node bin/aegis-cli.js [--staged] [--json] <files...>`，发现高危项 `process.exit(1)`，供 CI/CD 兜底 |
| MCP Server | `src/mcp/server.ts` | stdio 协议，只暴露只读工具，日志走 stderr |

# 功能

# 依赖核验（Supply Chain Guard）

输入包名或安装命令，插件会查询公开 registry 和漏洞数据，给出风险分与结论。

支持：npm、pnpm、yarn、bun、pip、uv、poetry、pdm，以及裸包名（默认按 npm 处理）。

查询内容：NPM Registry / PyPI JSON API、下载量、OSV.dev 漏洞、GitHub 仓库 Star 数（可选）。

判定规则：

- 官方 registry 未收录：阻断
- 存在 Critical 漏洞：阻断
- 与热门包只差 1–2 个字符，且下载量低或包龄短：阻断
- 风险分 >= 70：阻断
- 风险分 35–69：建议复核
- registry 超时或返回异常：提示核验失败，不当作安全放行

「校验并安全安装」会先完成核验，再根据包名重新拼接安装命令，原始输入不会直接传给终端。缓存使用带 TTL 的 LRU（上限 500 条 / 10 分钟），避免常驻内存泄漏。

# 密钥扫描（Secret Scanner）

基于正则 + 信息熵（Shannon Entropy）扫描源码中的硬编码密钥：

- GitHub Token（`ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_`）
- AWS Access Key（`AKIA` / `ASIA`）
- OpenAI / Anthropic 风格 API Key（`sk-`）
- Stripe Key、Slack Token（`xox*`）、PEM 私钥头
- 通用敏感赋值（`password=`、`api_key=`、`token=` 等）
- 高熵随机串（>= 20 字符且熵 >= 4.5 bit/字符）

# 配置扫描（Agent Config Sanitizer）

扫描工作区中的 Agent 配置文件：`.mcp.json`、`*.mcp.json`、`.cursorrules`、`.clinerules`、`.windsurfrules`、`.cursor/`、`.claude/`、`.vscode/`、`.github/`、`.devcontainer/`、`CLAUDE.md`、`AGENTS.md`、`.aider.conf.yml`。

检测内容：

- Unicode Tag 字符（U+E0000–E007F），并解码其中隐藏的文本
- 双向控制符（RLO、LRO、PDF 等）
- 零宽字符、不可见填充符、变体选择符补充区
- 转义写法，如 `\u200b`、`\u{E0041}`
- 单个 token 中混用拉丁字母与西里尔 / 希腊字母（同形字伪装）

发现问题后可以：在编辑器中查看 Diagnostics 标记、用 Quick Fix 清理单个文件、在报告页查看解码后的隐藏内容、预览清理结果后再保存。同形字伪装不会自动删除，需要人工重写。

# 文本读取与编码（V2.5.2）

统一通过 `src/core/text.ts` 的 `readTextSafe` 读取文件，支持 BOM 探测：`FF FE` → UTF-16LE、`FE FF` → UTF-16BE、`EF BB BF` → UTF-8（剔除 BOM）、其它 → UTF-8。只有解码结果明显为二进制（残留大量 NUL / 替换符）时才跳过，不再因「含 0x00 字节」误杀 UTF-16 编码的文件。

# 编辑器集成

- 打开工作区后自动扫描一次（可关闭）
- 保存文件时对硬编码密钥（所有文件）与隐藏字符（Agent 配置）刷新诊断
- 状态栏显示风险数量
- 活动栏提供安全面板和最近结果
- 输出面板记录核验和扫描摘要

# 安装

# 从 Release 安装

下载 [最新版本](https://github.com/aphirer/aegisdev/releases/latest) 中的 `aegisdev-3.2.0.vsix`，然后执行：

```bash
code --install-extension aegisdev-3.2.0.vsix
```

也可以在 VS Code / Cursor 中打开扩展面板，选择 `...` → `Install from VSIX`。

# 从源码运行

需要 Node.js 20 或更高版本。

```bash
npm install
npm run build
npm test
```

在 VS Code 中打开本目录，按 `F5` 启动扩展开发主机。

> 注意：`tests/fixtures/leak.js` 中的 Token 为用于验证扫描器的假数据，请勿在公开仓库中移除该警告。

# 命令

| 命令 | 说明 |
| --- | --- |
| `Aegis: 校验依赖包（幻觉包 / 投毒包）` | 输入包名或安装命令，生成核验报告 |
| `Aegis: 校验并安全安装依赖` | 核验通过后执行安装命令 |
| `Aegis: 扫描 Agent 配置隐藏字符` | 扫描工作区中的 Agent 配置 |
| `Aegis: 扫描当前文件的隐藏字符` | 仅扫描当前编辑器文件（含密钥） |
| `Aegis: 打开 Aegis 安全面板` | 打开活动栏面板 |
| `Aegis: 打开最近一次安全报告` | 打开最近一次报告 |
| `Aegis: 打开 Aegis 设置` | 打开插件设置 |
| `Aegis: 查看运行日志` | 打开 AegisDev 输出面板 |

隐藏字符的「预览净化结果 / 净化文件 / 移除单处」通过报告页按钮与编辑器 Quick Fix 触发，不在命令面板中展示。

# 配置

所有 `aegis.*` 设置都是用户级设置，工作区里的 `.vscode/settings.json` 不能覆盖，避免仓库通过自身配置关闭扫描或加入白名单。

| 设置 | 默认值 | 说明 |
| --- | --- | --- |
| `aegis.requestTimeoutMs` | `2000` | 单个外部请求的超时时间 |
| `aegis.scanOnOpen` | `true` | 打开工作区后自动扫描 |
| `aegis.scanOnSave` | `true` | 保存文件时重新扫描 |
| `aegis.maxScanFiles` | `300` | 单次扫描的最大文件数 |
| `aegis.minWeeklyDownloads` | `100` | 低下载量阈值 |
| `aegis.typosquatGuard` | `true` | 检测拼写混淆 |
| `aegis.githubToken` | 空 | 可选的 GitHub Token，仅用于提高 API 速率上限 |
| `aegis.allowlist` | `[]` | 可信包，支持 `@company/*` |
| `aegis.blocklist` | `[]` | 强制阻断的包 |
| `aegis.npmRegistry` | `https://registry.npmjs.org` | NPM registry 地址 |

# CI / CD 集成

仓库内置 `templates/` 下的 GitHub Actions 与 GitLab CI 模板，可在 CI 流水线中运行 AegisDev 扫描，发现高危密钥 / 隐藏字符时阻断合并（Fail-close）。

| 模板 | 用途 |
| --- | --- |
| `templates/github-actions.yml` | GitHub Actions：checkout → 安装 Node → `npm ci` → 构建 → 全局安装 CLI → `aegis-scan . --ci-mode` |
| `templates/gitlab-ci.yml` | GitLab CI：`node:20-alpine` 镜像执行相同扫描，并把 `aegis-report.json` 作为 artifact 保留 |

启用方式：

- **GitHub**：把 `templates/github-actions.yml` 复制为 `.github/workflows/aegis-scan.yml`。
- **GitLab**：把 `templates/gitlab-ci.yml` 复制为仓库根目录的 `.gitlab-ci.yml`（或合并进现有配置）。

CI 扫描命令为 `aegis-scan . --ci-mode`：递归扫描整个仓库，自动忽略 `node_modules` / `dist` 等目录，并把机器可读结果写入 `aegis-report.json`。发现 `critical` / `high` 级发现时以退出码 `1` 阻断流水线。

> ⚠️ **CI 断网时因 Fail-close 会阻断流水线，需配置 allowlist。** AegisDev 的依赖核验在 registry 超时 / 网络失败时会返回 `review` / `block`（绝不 `allow`），因此若你的流水线还包含依赖核验步骤，断网环境会触发阻断；请把可信的内部 / 私有包加入 `aegis.allowlist`（支持 `@company/*`）。密钥 / 隐藏字符的文件扫描本身在本机完成，不依赖网络。

# 本地 AI 审查（--diff）

CLI 支持用本地大模型审查代码变更（越权查询 / 数据过度暴露 / 前端伪鉴权）：

```bash
node bin/aegis-cli.js --diff                       # 零配置：自动探测本地 Ollama / LM Studio
node bin/aegis-cli.js --diff --provider ollama     # 强制使用 Ollama
node bin/aegis-cli.js --diff --provider lmstudio   # 强制使用 LM Studio
node bin/aegis-cli.js --diff --model qwen2.5-coder # 指定模型
```

- 自动探测（默认）：并发 ping `localhost:11434/api/tags`（Ollama）与 `localhost:1234/v1/models`（LM Studio），谁可用就用谁，并自动获取已加载的模型 ID。
- 可用 `--provider auto|ollama|lmstudio|none` 显式指定（`none` 为纯本地模式，跳过 LLM 审查）。
- 可用 `--model` / `--url` 覆盖模型与地址；环境变量 `OLLAMA_MODEL`、`AEGIS_LLM_URL` 亦可。
- 未检测到任何本地大模型时，会以黄字提示并跳过 LLM 审查（不影响其他扫描）。

# 如何接入 Git Hook 保护团队仓库

用 `pre-commit` 钩子在每次提交前自动做 Diff 审查，发现高危漏洞就阻断提交。

> 前提：已执行过 `npm install && npm run build`（生成 `dist/`，CLI 依赖它）。

# 方式一：原生 Hook（零依赖）

直接把模板复制到项目的 `.git/hooks/` 目录并赋予可执行权限：

```bash
cp templates/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

之后每次 `git commit` 都会自动执行 `node bin/aegis-cli.js --diff`；发现漏洞时打印红字 `❌ 代码存在安全漏洞，提交被 AegisDev 阻断` 并以 `exit 1` 阻断提交。

# 方式二：Husky（推荐）

如果团队已经使用 [husky](https://typicode.github.io/husky/)，只需在 `.husky/pre-commit` 中加入一行：

```bash
# .husky/pre-commit
node bin/aegis-cli.js --diff
```

> 说明：`--diff` 为纯本地 LLM 审查（自动探测 Ollama / LM Studio）；未检测到本地大模型时会黄字跳过、不阻断提交，不影响正常开发流程。

# 网络与隐私

代码扫描、诊断和清理全部在本机完成，文件内容不会上传。

依赖核验只会向以下地址发送包名、版本等公开信息：

- `registry.npmjs.org` 或自定义 NPM registry
- `api.npmjs.org`
- `pypi.org`
- `pypistats.org`
- `api.osv.dev`
- `api.github.com`

插件不包含遥测、账号系统或云端存储。

# 当前限制

- 不做终端命令的实时拦截，需要主动运行核验命令。
- 不做 MCP 网关，也不会自动向大模型注入 System Prompt。
- 不做 AST 级越权检查或 LLM 红队审查（Reviewer 为占位接口，推至 V3.0）。
- PyPI 下载量来自第三方 pypistats，接口不可用时显示为未知。
- GitHub API 未认证时会限流，Star 数可能显示为未知。
- 私有 registry 的登录认证尚未接入，私有包建议加入 `aegis.allowlist`。
- 超过 1.5MB、二进制或无法读取的配置文件会被跳过，并在报告中提示。
- 同形字伪装需要人工处理。

# License

MIT
