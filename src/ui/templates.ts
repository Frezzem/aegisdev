import type {
  PackageReport,
  PackageSignal,
  ScanReport,
  Severity,
  UnicodeFinding,
  Verdict,
} from "../core/types.js";

export interface RenderOptions {
  nonce: string;
  cspSource: string;
  version: string;
}

export function renderReportHtml(
  report: PackageReport | ScanReport,
  options: RenderOptions,
): string {
  const body =
    report.kind === "package"
      ? renderPackageBody(report)
      : renderScanBody(report);
  return shell(body, options, report.kind === "package" ? "依赖包安全核验" : "Agent 配置扫描");
}

/* ------------------------------------------------------------------ */
/* Package report                                                      */
/* ------------------------------------------------------------------ */

function renderPackageBody(report: PackageReport): string {
  const { assessment, facts, ref } = report;
  const verdict = assessment.verdict;
  const scoreWidth = Math.max(assessment.score, 2);
  const installable = verdict !== "block";
  const generated = formatTime(report.generatedAt);

  return `
  <section class="verdict verdict-${verdict}">
    <div class="verdict-icon">${iconForVerdict(verdict)}</div>
    <div class="verdict-copy">
      <p class="eyebrow">${escapeHtml(ref.ecosystem === "npm" ? "NPM" : "PyPI")} · 供应链核验</p>
      <h1>${escapeHtml(assessment.headline)}</h1>
      <p>${escapeHtml(assessment.summary)}</p>
      <p class="subtle">核验耗时 ${report.durationMs} ms · ${generated}</p>
    </div>
    <div class="score-box" aria-label="风险分 ${assessment.score}">
      <strong>${assessment.score}</strong>
      <span>风险分</span>
      <div class="meter"><i class="meter-${verdict}" style="width:${scoreWidth}%"></i></div>
    </div>
  </section>

  <div class="split">
    <section class="card package-card">
      <div class="package-head">
        <div class="package-avatar">${escapeHtml(initials(ref.name))}</div>
        <div class="package-title">
          <div class="package-name">${escapeHtml(ref.name)}</div>
          <div class="package-version">${escapeHtml(facts.version ?? ref.versionSpec ?? "版本未知")}
            ${facts.requestedVersionMissing ? '<span class="tag tag-warn">指定版本不存在</span>' : ""}
          </div>
        </div>
        <span class="eco-badge">${escapeHtml(ref.ecosystem)}</span>
      </div>
      <p class="description">${escapeHtml(facts.description ?? "registry 未提供描述。")}</p>
      <dl class="meta">
        <div><dt>维护者</dt><dd>${facts.maintainers ?? "未知"}</dd></div>
        <div><dt>许可证</dt><dd>${escapeHtml(facts.license ?? "未知")}</dd></div>
        <div><dt>最新发布</dt><dd>${escapeHtml(facts.latestPublishedAt?.slice(0, 10) ?? "未知")}</dd></div>
        <div><dt>版本总数</dt><dd>${facts.latestVersionCount ?? "未知"}</dd></div>
      </dl>
      <div class="actions">
        ${
          installable
            ? `<button class="btn btn-primary" data-action="copyInstall">${iconCopy()} 复制安装命令</button>`
            : `<span class="blocked-note">${iconBlock()} Aegis 已阻止该安装命令</span>`
        }
        <button class="btn" data-action="recheck">${iconRefresh()} 重新核验</button>
        <button class="btn btn-ghost" data-action="openRegistry">打开 registry ${iconExternal()}</button>
      </div>
      <div class="command"><span>$</span><code>${escapeHtml(ref.installCommand)}</code></div>
    </section>

    <section class="card">
      <div class="card-head"><h2>核验信号</h2><span class="count">${assessment.signals.length}</span></div>
      <div class="signals">
        ${assessment.signals.map(renderSignal).join("")}
      </div>
    </section>
  </div>

  <section class="card">
    <div class="card-head"><h2>发现与建议</h2><span class="count">${assessment.evidence.length}</span></div>
    <div class="evidence">
      ${assessment.evidence.map(renderEvidence).join("")}
    </div>
  </section>

  <section class="sources">
    <span class="sources-label">数据源</span>
    ${report.sources.map(renderSource).join("")}
    <span class="sources-spacer"></span>
    <span class="privacy">${iconLock()} 仅发送包名与版本元数据，不上传代码</span>
  </section>`;
}

function renderSignal(signal: PackageSignal): string {
  const detail = signal.detail ? `<span class="signal-detail">${escapeHtml(signal.detail)}</span>` : "";
  return `<div class="signal">
    <span class="dot dot-${signal.status}" title="${escapeHtml(signal.status)}"></span>
    <span class="signal-label">${escapeHtml(signal.label)}</span>
    <span class="signal-value">${escapeHtml(signal.value)}</span>
    ${detail}
  </div>`;
}

function renderEvidence(item: { severity: Severity; title: string; detail: string }): string {
  return `<div class="evidence-item">
    <span class="sev sev-${item.severity}">${severityLabel(item.severity)}</span>
    <div>
      <div class="evidence-title">${escapeHtml(item.title)}</div>
      <p>${escapeHtml(item.detail)}</p>
    </div>
  </div>`;
}

function renderSource(source: { name: string; status: string; detail?: string; url?: string }): string {
  const detail = source.detail ? ` · ${escapeHtml(source.detail)}` : "";
  return `<span class="source source-${escapeHtml(source.status)}" title="${escapeHtml(source.url ?? "")}">
    <i></i>${escapeHtml(source.name)}${detail}
  </span>`;
}

/* ------------------------------------------------------------------ */
/* Scan report                                                         */
/* ------------------------------------------------------------------ */

function renderScanBody(report: ScanReport): string {
  const critical = report.verdict === "critical";
  const fixable = report.findings.filter((finding) => finding.fixable).length;
  const shown = report.findings.slice(0, 120);
  const affected = report.files.filter((file) => file.findings.length > 0);

  return `
  <section class="verdict verdict-${critical ? "block" : report.verdict === "review" ? "review" : "allow"}">
    <div class="verdict-icon">${critical ? iconBlock() : report.verdict === "review" ? iconWarn() : iconShieldCheck()}</div>
    <div class="verdict-copy">
      <p class="eyebrow">AGENT 信任边界 · ${report.scope === "file" ? "当前文件" : "工作区"} · 本地扫描</p>
      <h1>${escapeHtml(report.headline)}</h1>
      <p>${escapeHtml(report.summary)}</p>
      <p class="subtle">扫描 ${report.filesScanned} 个配置文件 · ${report.durationMs} ms · ${formatTime(report.scannedAt)}</p>
    </div>
    <div class="scan-counts">
      <div><strong>${report.counts.critical}</strong><span>严重</span></div>
      <div><strong>${report.counts.high}</strong><span>高危</span></div>
      <div><strong>${report.filesWithFindings}</strong><span>风险文件</span></div>
    </div>
  </section>

  <div class="toolbar">
    <button class="btn" data-action="rescan">${iconRefresh()} 重新扫描</button>
    ${
      fixable > 0
        ? `<button class="btn btn-primary" data-action="sanitizeAll">${iconSparkle()} 净化全部（${fixable} 处）</button>`
        : ""
    }
    <span class="toolbar-note">${iconLock()} 扫描全程在本地完成，文件内容不会离开此设备</span>
  </div>
  ${
    report.skippedFiles > 0
      ? `<div class="scan-warning">${iconWarn()} 有 ${report.skippedFiles} 个文件因超过 1.5MB、二进制或无法读取被跳过，未被判定为安全。请人工检查。</div>`
      : ""
  }

  ${
    affected.length === 0
      ? `<section class="card empty">
          <div class="empty-icon">${iconShieldCheck()}</div>
          <h2>配置干净</h2>
          <p>已检查 .mcp.json、.cursorrules、.claude、.vscode、.github 等 Agent 配置，未发现隐藏 Unicode 字符。</p>
        </section>`
      : affected
          .map((file) => {
            const fileFindings = file.findings;
            const visibleFindings = fileFindings.slice(0, 40);
            return `<section class="card file-card">
              <div class="file-head">
                <div class="file-title">
                  <span class="file-icon">${iconFile()}</span>
                  <code>${escapeHtml(file.file)}</code>
                </div>
                <div class="file-actions">
                  <span class="risk risk-${file.risk}">${riskLabel(file.risk)}</span>
                  ${
                    fileFindings.some((finding) => finding.fixable)
                      ? `<button class="btn btn-small" data-action="sanitizeFile" data-file="${escapeHtml(file.file)}">${iconSparkle()} 净化此文件</button>`
                      : ""
                  }
                </div>
              </div>
              <div class="findings">
                ${visibleFindings.map((finding) => renderFinding(finding)).join("")}
                ${
                  fileFindings.length > visibleFindings.length
                    ? `<p class="truncated">此文件另有 ${fileFindings.length - visibleFindings.length} 处发现未展开，可使用“净化此文件”一次清理。</p>`
                    : ""
                }
              </div>
            </section>`;
          })
          .join("")
  }

  ${
    report.findings.length > shown.length
      ? `<p class="truncated">仅展示前 ${shown.length} 处发现，共 ${report.findings.length} 处。请优先处理严重 / 高危项。</p>`
      : ""
  }

  <footer class="footer">
    <span>${iconShield()} AegisDev 扫描器</span>
    <span>支持 Tag 字符、双向控制符、零宽字符、变体选择符、转义隐藏字符与同形字检测</span>
  </footer>`;
}

function renderFinding(finding: UnicodeFinding): string {
  const decoded =
    finding.decoded && finding.decoded.length > 0
      ? `<div class="decoded"><span>解码出的隐藏内容</span><code>${escapeHtml(finding.decoded)}</code>${
          finding.payloadRisk === "high"
            ? '<span class="tag tag-danger">含命令执行 / 外泄特征</span>'
            : ""
        }</div>`
      : "";
  return `<article class="finding finding-${finding.severity}">
    <div class="finding-rail"><span class="sev sev-${finding.severity}">${severityLabel(finding.severity)}</span></div>
    <div class="finding-body">
      <div class="finding-head">
        <span class="finding-name">${escapeHtml(finding.name)}</span>
        <span class="finding-code">U+${escapeHtml(finding.hex)}</span>
        <span class="finding-pos">L${finding.line}:C${finding.column}</span>
        <button class="link-btn" data-action="openFinding" data-id="${escapeHtml(finding.id)}">打开位置 ${iconExternal()}</button>
      </div>
      <pre class="snippet">${escapeHtml(finding.context)}</pre>
      <p class="finding-msg">${escapeHtml(finding.message)}</p>
      ${decoded}
      <div class="finding-actions">
        ${
          finding.fixable
            ? `<button class="btn btn-small" data-action="fixFinding" data-id="${escapeHtml(finding.id)}">${iconSparkle()} 移除此处</button>`
            : `<span class="manual-note">需人工重写该令牌，自动删除会破坏配置内容</span>`
        }
      </div>
    </div>
  </article>`;
}

/* ------------------------------------------------------------------ */
/* Shared shell                                                        */
/* ------------------------------------------------------------------ */

function shell(body: string, options: RenderOptions, subtitle: string): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${options.cspSource} data:; style-src ${options.cspSource} 'unsafe-inline'; script-src 'nonce-${options.nonce}';">
<title>AegisDev · ${escapeHtml(subtitle)}</title>
<style>${STYLES}</style>
</head>
<body>
<div class="app">
  <header class="topbar">
    <div class="brand">
      <span class="brand-mark">${iconShield()}</span>
      <span class="brand-name">Aegis<span>Dev</span></span>
      <span class="brand-divider"></span>
      <span class="brand-sub">${escapeHtml(subtitle)}</span>
    </div>
    <div class="topbar-right">
      <span class="version">V${escapeHtml(options.version)}</span>
      <button class="icon-btn" data-action="openDashboard" title="打开安全面板">${iconGrid()}</button>
    </div>
  </header>
  <main>${body}</main>
</div>
<script nonce="${options.nonce}">
  const vscode = acquireVsCodeApi();
  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target.closest("[data-action]") : null;
    if (!target) return;
    const message = { type: target.dataset.action };
    if (target.dataset.id) message.id = target.dataset.id;
    if (target.dataset.file) message.file = target.dataset.file;
    vscode.postMessage(message);
  });
</script>
</body>
</html>`;
}

const STYLES = `
:root {
  color-scheme: light dark;
  --bg: var(--vscode-editor-background, #0b1220);
  --fg: var(--vscode-editor-foreground, #e5edf7);
  --muted: var(--vscode-descriptionForeground, #8b9bb4);
  --border: var(--vscode-panel-border, rgba(148, 163, 184, .22));
  --card: var(--vscode-sideBar-background, rgba(255, 255, 255, .035));
  --card-strong: var(--vscode-editorWidget-background, rgba(255, 255, 255, .055));
  --accent: #2dd4bf;
  --accent-strong: #14b8a6;
  --good: #34d399;
  --warn: #fbbf24;
  --bad: #fb7185;
  --critical: #f43f5e;
  --radius: 14px;
  --shadow: 0 12px 32px rgba(0, 0, 0, .18);
}
body.vscode-light { --shadow: 0 10px 28px rgba(15, 23, 42, .08); --card: rgba(248, 250, 252, .9); --card-strong: #fff; }
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background:
    radial-gradient(1200px 480px at 12% -10%, rgba(45, 212, 191, .13), transparent 60%),
    radial-gradient(900px 420px at 100% 0%, rgba(56, 189, 248, .08), transparent 55%),
    var(--bg);
  color: var(--fg);
  font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif);
  font-size: 13px;
  line-height: 1.55;
  min-height: 100vh;
}
.app { max-width: 1040px; margin: 0 auto; padding: 22px 26px 40px; }
.topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 4px 0 18px; }
.brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
.brand-mark { width: 28px; height: 28px; color: var(--accent); display: inline-flex; }
.brand-mark svg { width: 100%; height: 100%; }
.brand-name { font-size: 18px; font-weight: 750; letter-spacing: -.02em; }
.brand-name span { color: var(--accent); }
.brand-divider { width: 1px; height: 16px; background: var(--border); }
.brand-sub { color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.topbar-right { display: flex; align-items: center; gap: 10px; }
.version { color: var(--muted); font-size: 11px; border: 1px solid var(--border); padding: 2px 8px; border-radius: 999px; }
.icon-btn { width: 30px; height: 30px; display: inline-flex; align-items: center; justify-content: center; background: transparent; color: var(--muted); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; }
.icon-btn:hover { color: var(--fg); border-color: var(--accent); }
.icon-btn svg { width: 16px; height: 16px; }
.verdict { display: grid; grid-template-columns: 54px minmax(0, 1fr) auto; gap: 18px; align-items: center; padding: 22px 24px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--card); box-shadow: var(--shadow); position: relative; overflow: hidden; }
.verdict::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 3px; background: var(--accent); }
.verdict-block::before { background: var(--critical); }
.verdict-review::before { background: var(--warn); }
.verdict-allow::before { background: var(--good); }
.verdict-icon { width: 54px; height: 54px; border-radius: 14px; display: flex; align-items: center; justify-content: center; background: rgba(45, 212, 191, .1); color: var(--accent); }
.verdict-block .verdict-icon { background: rgba(244, 63, 94, .12); color: var(--bad); }
.verdict-review .verdict-icon { background: rgba(251, 191, 36, .12); color: var(--warn); }
.verdict-allow .verdict-icon { background: rgba(52, 211, 153, .12); color: var(--good); }
.verdict-icon svg { width: 30px; height: 30px; }
.eyebrow { margin: 0 0 4px; font-size: 10px; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); font-weight: 700; }
h1 { margin: 0 0 5px; font-size: 24px; line-height: 1.2; letter-spacing: -.025em; }
.verdict-copy p { margin: 0; color: var(--muted); max-width: 680px; }
.verdict-copy .subtle { margin-top: 7px; font-size: 11px; opacity: .8; }
.score-box { text-align: right; min-width: 88px; }
.score-box strong { display: block; font-size: 34px; line-height: 1; letter-spacing: -.04em; }
.score-box span { display: block; color: var(--muted); font-size: 10px; margin-top: 4px; }
.meter { width: 88px; height: 5px; border-radius: 99px; background: rgba(148, 163, 184, .18); overflow: hidden; margin-top: 9px; margin-left: auto; }
.meter i { display: block; height: 100%; border-radius: inherit; background: var(--accent); }
.meter-block { background: var(--critical); }
.meter-review { background: var(--warn); }
.meter-allow { background: var(--good); }
.scan-counts { display: flex; gap: 18px; text-align: center; }
.scan-counts div { min-width: 52px; }
.scan-counts strong { display: block; font-size: 25px; line-height: 1.1; }
.scan-counts span { color: var(--muted); font-size: 10px; }
.split { display: grid; grid-template-columns: minmax(0, 1.06fr) minmax(0, .94fr); gap: 16px; margin-top: 16px; align-items: start; }
.card { border: 1px solid var(--border); border-radius: var(--radius); background: var(--card); padding: 18px 20px; }
.package-head { display: flex; align-items: center; gap: 12px; }
.package-avatar { width: 46px; height: 46px; flex: none; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 15px; letter-spacing: -.03em; color: #052e2b; background: linear-gradient(135deg, #5eead4, #2dd4bf); }
.package-title { min-width: 0; flex: 1; }
.package-name { font-size: 17px; font-weight: 700; word-break: break-all; }
.package-version { color: var(--muted); font-size: 11px; margin-top: 2px; }
.eco-badge { text-transform: uppercase; font-size: 10px; letter-spacing: .08em; color: var(--accent); border: 1px solid rgba(45, 212, 191, .35); border-radius: 999px; padding: 2px 8px; }
.description { color: var(--muted); margin: 15px 0; min-height: 20px; }
.meta { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 14px; margin: 0; padding: 12px 0; border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); }
.meta div { display: flex; justify-content: space-between; gap: 8px; }
.meta dt { color: var(--muted); font-size: 11px; }
.meta dd { margin: 0; font-size: 11px; font-weight: 600; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 15px; align-items: center; }
.btn { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--border); background: transparent; color: var(--fg); font-family: inherit; font-size: 12px; font-weight: 600; padding: 7px 11px; border-radius: 8px; cursor: pointer; transition: border-color .15s ease, background .15s ease; }
.btn:hover { border-color: var(--accent); background: rgba(45, 212, 191, .08); }
.btn svg { width: 14px; height: 14px; }
.btn-primary { color: #042f2e; background: var(--accent); border-color: var(--accent); }
.btn-primary:hover { background: #5eead4; border-color: #5eead4; }
.btn-ghost { border-color: transparent; color: var(--muted); padding-left: 4px; }
.btn-small { font-size: 11px; padding: 5px 9px; }
.blocked-note { display: inline-flex; align-items: center; gap: 6px; color: var(--bad); font-weight: 700; font-size: 12px; }
.blocked-note svg { width: 15px; height: 15px; }
.command { display: flex; gap: 8px; align-items: center; margin-top: 12px; padding: 9px 11px; border-radius: 8px; background: rgba(0, 0, 0, .16); border: 1px solid var(--border); font-family: var(--vscode-editor-font-family, ui-monospace, monospace); font-size: 11px; overflow: auto; }
body.vscode-light .command { background: rgba(15, 23, 42, .04); }
.command span { color: var(--accent); }
.command code { white-space: nowrap; }
.card-head { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
h2 { font-size: 13px; margin: 0; letter-spacing: -.01em; }
.count { color: var(--muted); font-size: 10px; border: 1px solid var(--border); border-radius: 999px; padding: 0 6px; }
.signals { display: flex; flex-direction: column; }
.signal { display: grid; grid-template-columns: 8px 88px minmax(0, 1fr); gap: 8px; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--border); }
.signal:last-child { border-bottom: 0; }
.dot { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
.dot-good { background: var(--good); }
.dot-warn { background: var(--warn); }
.dot-bad { background: var(--bad); }
.dot-unknown { background: #64748b; }
.signal-label { color: var(--muted); font-size: 11px; }
.signal-value { font-size: 12px; font-weight: 650; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.signal-detail { grid-column: 3; color: var(--muted); font-size: 10px; margin-top: -5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.evidence { display: flex; flex-direction: column; gap: 2px; }
.evidence-item { display: grid; grid-template-columns: 48px minmax(0, 1fr); gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--border); }
.evidence-item:last-child { border-bottom: 0; }
.evidence-title { font-weight: 650; font-size: 12px; }
.evidence-item p { margin: 2px 0 0; color: var(--muted); font-size: 11px; }
.sev { display: inline-flex; align-items: center; justify-content: center; height: 20px; border-radius: 5px; font-size: 10px; font-weight: 700; letter-spacing: .03em; }
.sev-critical { background: rgba(244, 63, 94, .16); color: #fda4af; }
.sev-high { background: rgba(251, 113, 133, .14); color: #fda4af; }
.sev-medium { background: rgba(251, 191, 36, .14); color: #fcd34d; }
.sev-low { background: rgba(96, 165, 250, .14); color: #93c5fd; }
.sev-info { background: rgba(148, 163, 184, .14); color: #cbd5e1; }
body.vscode-light .sev-critical, body.vscode-light .sev-high { color: #be123c; }
body.vscode-light .sev-medium { color: #a16207; }
body.vscode-light .sev-low { color: #1d4ed8; }
body.vscode-light .sev-info { color: #475569; }
.sources { display: flex; flex-wrap: wrap; align-items: center; gap: 7px; margin-top: 16px; color: var(--muted); font-size: 10px; }
.sources-label { font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }
.source { display: inline-flex; align-items: center; gap: 5px; border: 1px solid var(--border); padding: 3px 7px; border-radius: 999px; }
.source i { width: 5px; height: 5px; border-radius: 50%; background: var(--good); }
.source-degraded i { background: var(--warn); }
.source-error i { background: var(--bad); }
.sources-spacer { flex: 1; }
.privacy { display: inline-flex; align-items: center; gap: 4px; color: var(--muted); }
.privacy svg { width: 12px; height: 12px; }
.toolbar { display: flex; gap: 8px; align-items: center; margin: 16px 0; flex-wrap: wrap; }
.toolbar-note { margin-left: auto; color: var(--muted); font-size: 10px; display: inline-flex; gap: 4px; align-items: center; }
.toolbar-note svg { width: 12px; height: 12px; }
.scan-warning { display: flex; align-items: center; gap: 7px; margin: -4px 0 16px; padding: 9px 12px; border: 1px solid rgba(251, 191, 36, .3); background: rgba(251, 191, 36, .08); color: var(--warn); border-radius: 8px; font-size: 11px; }
.scan-warning svg { width: 14px; height: 14px; flex: none; }
.file-card { padding: 0; margin-bottom: 14px; overflow: hidden; }
.file-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 16px; background: var(--card-strong); border-bottom: 1px solid var(--border); }
.file-title { display: flex; align-items: center; gap: 8px; min-width: 0; }
.file-title code { font-family: var(--vscode-editor-font-family, ui-monospace, monospace); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-icon { color: var(--accent); display: inline-flex; }
.file-icon svg { width: 14px; height: 14px; }
.file-actions { display: flex; align-items: center; gap: 8px; flex: none; }
.risk { font-size: 9px; font-weight: 700; letter-spacing: .05em; padding: 2px 7px; border-radius: 999px; text-transform: uppercase; }
.risk-critical { background: rgba(244, 63, 94, .16); color: #fda4af; }
.risk-high { background: rgba(251, 113, 133, .14); color: #fda4af; }
.risk-medium { background: rgba(251, 191, 36, .14); color: #fcd34d; }
.risk-low { background: rgba(96, 165, 250, .14); color: #93c5fd; }
.risk-none { background: rgba(52, 211, 153, .12); color: #6ee7b7; }
body.vscode-light .risk-critical, body.vscode-light .risk-high { color: #be123c; }
body.vscode-light .risk-medium { color: #a16207; }
body.vscode-light .risk-low { color: #1d4ed8; }
body.vscode-light .risk-none { color: #047857; }
.finding { display: grid; grid-template-columns: 52px minmax(0, 1fr); gap: 12px; padding: 14px 16px; border-bottom: 1px solid var(--border); }
.finding:last-child { border-bottom: 0; }
.finding-rail .sev { width: 44px; }
.finding-body { min-width: 0; }
.finding-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.finding-name { font-weight: 650; font-size: 12px; }
.finding-code { font-family: var(--vscode-editor-font-family, monospace); font-size: 10px; color: var(--accent); background: rgba(45, 212, 191, .08); padding: 1px 5px; border-radius: 4px; }
.finding-pos { color: var(--muted); font-size: 10px; }
.link-btn { margin-left: auto; border: 0; background: transparent; color: var(--muted); font-family: inherit; font-size: 10px; cursor: pointer; display: inline-flex; align-items: center; gap: 3px; padding: 2px 0; }
.link-btn:hover { color: var(--accent); }
.link-btn svg { width: 11px; height: 11px; }
.snippet { margin: 8px 0 4px; padding: 9px 10px; border-radius: 7px; background: rgba(0, 0, 0, .18); border: 1px solid var(--border); font-family: var(--vscode-editor-font-family, monospace); font-size: 11px; white-space: pre-wrap; word-break: break-all; line-height: 1.6; }
body.vscode-light .snippet { background: rgba(15, 23, 42, .04); }
.finding-msg { margin: 3px 0 0; color: var(--muted); font-size: 10px; }
.decoded { margin-top: 8px; padding: 8px 10px; border: 1px solid rgba(244, 63, 94, .28); background: rgba(244, 63, 94, .07); border-radius: 7px; }
.decoded span:first-child { display: block; color: var(--muted); font-size: 9px; letter-spacing: .06em; text-transform: uppercase; margin-bottom: 3px; }
.decoded code { font-family: var(--vscode-editor-font-family, monospace); font-size: 11px; color: #fecdd3; word-break: break-all; }
body.vscode-light .decoded code { color: #9f1239; }
.tag { display: inline-flex; align-items: center; border-radius: 999px; font-size: 9px; font-weight: 700; padding: 1px 7px; margin-left: 6px; }
.tag-danger { background: rgba(244, 63, 94, .18); color: #fda4af; }
.tag-warn { background: rgba(251, 191, 36, .16); color: #fcd34d; }
body.vscode-light .tag-danger { color: #be123c; }
body.vscode-light .tag-warn { color: #a16207; }
.finding-actions { margin-top: 8px; }
.manual-note { color: var(--muted); font-size: 10px; }
.empty { text-align: center; padding: 44px 20px; }
.empty-icon { width: 58px; height: 58px; margin: 0 auto 14px; color: var(--good); }
.empty-icon svg { width: 100%; height: 100%; }
.empty h2 { font-size: 17px; margin-bottom: 5px; }
.empty p { color: var(--muted); max-width: 560px; margin: 0 auto; }
.truncated { color: var(--muted); font-size: 11px; text-align: center; margin: 14px 0; }
.footer { display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; color: var(--muted); font-size: 10px; border-top: 1px solid var(--border); margin-top: 22px; padding-top: 14px; }
.footer span { display: inline-flex; align-items: center; gap: 5px; }
.footer svg { width: 12px; height: 12px; }
@media (max-width: 760px) {
  .app { padding: 16px; }
  .split { grid-template-columns: 1fr; }
  .verdict { grid-template-columns: 44px minmax(0, 1fr); }
  .score-box, .scan-counts { grid-column: 2; text-align: left; }
  .meter { margin-left: 0; }
  .scan-counts { text-align: left; }
  .brand-sub, .brand-divider { display: none; }
}
`;

/* ------------------------------------------------------------------ */
/* Tiny inline icon set                                                */
/* ------------------------------------------------------------------ */

const svg = (path: string, viewBox = "0 0 24 24"): string =>
  `<svg viewBox="${viewBox}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg>`;

function iconShield(): string {
  return svg('<path d="M12 3 20 6v6c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6z"/><path d="m8.6 12 2.2 2.2 4.6-5"/>');
}
function iconShieldCheck(): string {
  return iconShield();
}
function iconBlock(): string {
  return svg('<circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/>');
}
function iconWarn(): string {
  return svg('<path d="M10.3 4.3 2.8 17.5A1.7 1.7 0 0 0 4.3 20h15.4a1.7 1.7 0 0 0 1.5-2.5L13.7 4.3a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4"/><path d="M12 16.5h.01"/>');
}
function iconForVerdict(verdict: Verdict): string {
  return verdict === "block" ? iconBlock() : verdict === "review" ? iconWarn() : iconShieldCheck();
}
function iconRefresh(): string {
  return svg('<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>');
}
function iconCopy(): string {
  return svg('<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>');
}
function iconExternal(): string {
  return svg('<path d="M14 4h6v6"/><path d="M20 4 11 13"/><path d="M20 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h5"/>');
}
function iconLock(): string {
  return svg('<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>');
}
function iconSparkle(): string {
  return svg('<path d="m12 3 1.6 4.4L18 9l-4.4 1.6L12 15l-1.6-4.4L6 9l4.4-1.6z"/><path d="m18.5 14 .8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8z"/>');
}
function iconFile(): string {
  return svg('<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h4"/>');
}
function iconGrid(): string {
  return svg('<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>');
}

/* ------------------------------------------------------------------ */
/* Formatting helpers                                                  */
/* ------------------------------------------------------------------ */

function severityLabel(severity: Severity): string {
  return { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" }[severity];
}

function riskLabel(risk: Severity | "none"): string {
  return risk === "none" ? "安全" : severityLabel(risk);
}

function initials(name: string): string {
  return name.replace(/^@/, "").slice(0, 2).toUpperCase();
}

function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  return date.toLocaleString("zh-CN", { hour12: false });
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
