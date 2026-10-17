# Changelog

## 1.0.0

- 支持 npm、pnpm、yarn、bun、pip、uv、poetry、pdm 包核验。
- 查询 NPM Registry、PyPI、下载量、OSV 和 GitHub。
- 根据包龄、下载量、漏洞、安装脚本和拼写混淆给出风险结论。
- 支持用户级 allowlist / blocklist。
- 支持核验后安装，安装命令由包名重新拼接。
- 扫描 `.mcp.json`、`.cursorrules`、`.claude` 等 Agent 配置。
- 检测 Tag 字符、双向控制符、零宽字符、转义隐藏字符和同形字。
- 解码 Tag 字符中的隐藏文本。
- 提供 Diagnostics、Quick Fix、清理预览和批量清理。
- 打开工作区自动扫描，保存配置时刷新诊断。
