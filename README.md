# AegisDev

AegisDev 是一个 VS Code / Cursor 扩展，用来在 AI 编程过程中处理两类风险：

- 安装依赖前，核验 npm / PyPI 包是否存在、是否可信。
- 读取或保存 Agent 配置时，扫描其中隐藏的 Unicode 字符。

当前版本：1.0.0。

## 功能

### 依赖核验

输入包名或安装命令，插件会查询公开的 registry 和漏洞数据，给出风险分与结论。

支持：

- npm、pnpm、yarn、bun
- pip、uv、poetry、pdm
- 裸包名（默认按 npm 处理）

查询内容：

- NPM Registry / PyPI JSON API：包是否存在、版本、发布时间、维护者、安装脚本
- NPM Downloads / pypistats：周下载量
- OSV.dev：当前版本的已知漏洞
- GitHub：仓库 Star 数（可选）

判定规则：

- 官方 registry 未收录：阻断
- 存在 Critical 漏洞：阻断
- 与热门包只差 1–2 个字符，且下载量低或包龄短：阻断
- 风险分 >= 70：阻断
- 风险分 35–69：建议复核
- registry 超时或返回异常：提示核验失败，不当作安全放行

「校验并安全安装」会先完成核验，再根据包名重新拼接安装命令。原始输入不会直接传给终端。

### 配置扫描

扫描工作区中的 Agent 配置文件：

- `.mcp.json`、`*.mcp.json`
- `.cursorrules`、`.clinerules`、`.windsurfrules`
- `.cursor/`、`.claude/`、`.vscode/`、`.github/`、`.devcontainer/`
- `CLAUDE.md`、`AGENTS.md`、`.aider.conf.yml`

检测内容：

- Unicode Tag 字符（U+E0000–E007F），并解码其中隐藏的文本
- 双向控制符（RLO、LRO、PDF 等）
- 零宽字符、不可见填充符
- 变体选择符补充区
- 转义写法，如 `\u200b`、`\u{E0041}`
- 单个 token 中混用拉丁字母与西里尔 / 希腊字母

发现问题后可以：

- 在编辑器中看到 Diagnostics 标记
- 使用 Quick Fix 清理单个文件
- 在报告页查看解码后的隐藏内容
- 预览清理结果，确认后再保存

同形字伪装不会自动删除，需要人工重写。

### 编辑器集成

- 打开工作区后自动扫描一次（可关闭）
- 保存 Agent 配置时刷新诊断
- 状态栏显示风险数量
- 活动栏提供安全面板和最近结果
- 输出面板记录核验和扫描摘要

## 安装

### 从 Release 安装

下载 [最新版本](https://github.com/Frezzem/aegisdev/releases/latest) 中的 `aegisdev-1.0.0.vsix`，然后执行：

```bash
code --install-extension aegisdev-1.0.0.vsix
```

也可以在 VS Code / Cursor 中打开扩展面板，选择 `...` → `Install from VSIX`。

### 从源码运行

需要 Node.js 20 或更高版本。

```bash
npm install
npm run build
```

在 VS Code 中打开本目录，按 `F5` 启动扩展开发主机。

## 命令

| 命令 | 说明 |
| --- | --- |
| `Aegis: 校验依赖包（幻觉包 / 投毒包）` | 输入包名或安装命令，生成核验报告 |
| `Aegis: 校验并安全安装依赖` | 核验通过后执行安装命令 |
| `Aegis: 扫描 Agent 配置隐藏字符` | 扫描工作区中的 Agent 配置 |
| `Aegis: 扫描当前文件的隐藏字符` | 仅扫描当前编辑器文件 |
| `Aegis: 打开 Aegis 安全面板` | 打开活动栏面板 |
| `Aegis: 打开最近一次安全报告` | 打开最近一次报告 |
| `Aegis: 打开 Aegis 设置` | 打开插件设置 |
| `Aegis: 查看运行日志` | 打开 AegisDev 输出面板 |

## 配置

所有 `aegis.*` 设置都是用户级设置，工作区里的 `.vscode/settings.json` 不能覆盖。这样可以避免仓库通过自己的配置关闭扫描或加入白名单。

| 设置 | 默认值 | 说明 |
| --- | --- | --- |
| `aegis.requestTimeoutMs` | `2000` | 单个外部请求的超时时间 |
| `aegis.scanOnOpen` | `true` | 打开工作区后自动扫描 |
| `aegis.scanOnSave` | `true` | 保存 Agent 配置时重新扫描 |
| `aegis.maxScanFiles` | `300` | 单次扫描的最大文件数 |
| `aegis.minWeeklyDownloads` | `100` | 低下载量阈值 |
| `aegis.typosquatGuard` | `true` | 检测拼写混淆 |
| `aegis.githubToken` | 空 | 可选的 GitHub Token，仅用于提高 API 速率上限 |
| `aegis.allowlist` | `[]` | 可信包，支持 `@company/*` |
| `aegis.blocklist` | `[]` | 强制阻断的包 |
| `aegis.npmRegistry` | `https://registry.npmjs.org` | NPM registry 地址 |

## 网络与隐私

代码扫描、诊断和清理全部在本机完成，文件内容不会上传。

依赖核验只会向以下地址发送包名、版本等公开信息：

- `registry.npmjs.org` 或自定义 NPM registry
- `api.npmjs.org`
- `pypi.org`
- `pypistats.org`
- `api.osv.dev`
- `api.github.com`

插件不包含遥测、账号系统或云端存储。

## 当前限制

- 不做终端命令的实时拦截，需要主动运行核验命令。
- 不做 MCP 网关，也不会自动向大模型注入 System Prompt。
- 不做 AST 级越权检查或 LLM 红队审查。
- PyPI 下载量来自第三方 pypistats，接口不可用时显示为未知。
- GitHub API 未认证时会限流，Star 数可能显示为未知。
- 私有 registry 的登录认证尚未接入，私有包建议加入 `aegis.allowlist`。
- 超过 1.5MB、二进制或无法读取的配置文件会被跳过，并在报告中提示。
- 同形字伪装需要人工处理。

## License

MIT
