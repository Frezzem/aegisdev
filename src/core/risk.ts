import type {
  Assessment,
  Evidence,
  PackageFacts,
  PackageSignal,
  Severity,
  Verdict,
} from "./types.js";

export interface RiskPolicy {
  minWeeklyDownloads: number;
  typosquatGuard: boolean;
  allowlist: string[];
  blocklist: string[];
  now?: Date;
}

export const DEFAULT_POLICY: RiskPolicy = {
  minWeeklyDownloads: 100,
  typosquatGuard: true,
  allowlist: [],
  blocklist: [],
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "提示",
};

export function assessPackage(facts: PackageFacts, policy: Partial<RiskPolicy> = {}): Assessment {
  const resolved: RiskPolicy = { ...DEFAULT_POLICY, ...policy };
  const signals: PackageSignal[] = [];
  const evidence: Evidence[] = [];

  if (matchesPackageList(facts.name, resolved.blocklist)) {
    return {
      verdict: "block",
      score: 100,
      headline: "已被团队策略阻断",
      summary: `包 ${facts.name} 命中 Aegis 阻断名单（blocklist），不会允许安装。`,
      signals: [signal("policy", "策略命中", "阻断名单", "bad", "由工作区设置 aegis.blocklist 强制阻断")],
      evidence: [
        {
          severity: "critical",
          title: "命中阻断名单",
          detail: "该包在 aegis.blocklist 中。如为误报，请由安全负责人调整策略。",
        },
      ],
      allowlisted: false,
      blockedByPolicy: true,
    };
  }

  if (matchesPackageList(facts.name, resolved.allowlist)) {
    return {
      verdict: "allow",
      score: 0,
      headline: "企业白名单放行",
      summary: `包 ${facts.name} 命中团队白名单，已跳过外部核验。`,
      signals: [
        signal("policy", "策略命中", "企业白名单", "good", "由 aegis.allowlist 放行"),
      ],
      evidence: [
        {
          severity: "info",
          title: "企业白名单",
          detail: "该包由团队策略标记为可信。请确认白名单来自受控的仓库设置。",
        },
      ],
      allowlisted: true,
      blockedByPolicy: false,
    };
  }

  if (facts.lookupState === "error") {
    return {
      verdict: "review",
      score: 50,
      headline: "无法完成核验",
      summary:
        "官方 registry 请求失败（可能超时或网络不可用）。Aegis 不会把它当作“安全”放行，请稍后重试或人工核查。",
      signals: [
        signal("registry", "官方源", "请求失败", "unknown", facts.lookupError),
      ],
      evidence: [
        {
          severity: "high",
          title: "核验数据不完整",
          detail: `${facts.lookupError ?? "registry 请求失败"}。安全安装动作默认不会在核验失败时继续。`,
        },
      ],
      allowlisted: false,
      blockedByPolicy: false,
    };
  }

  if (!facts.found) {
    signals.push(signal("registry", "官方源", "未收录", "bad"));
    evidence.push({
      severity: "critical",
      title: "官方 registry 未收录该包",
      detail: `${facts.ecosystem === "npm" ? "NPM" : "PyPI"} registry 返回 404。AI 可能生成了不存在的“幻觉包”，安装后可能被攻击者抢注。`,
    });
    return {
      verdict: "block",
      score: 100,
      headline: "疑似幻觉包，已阻断",
      summary: "官方 registry 中不存在该包。请勿执行安装；让 AI 重新核对依赖名称。",
      signals,
      evidence,
      allowlisted: false,
      blockedByPolicy: false,
    };
  }

  signals.push(
    signal(
      "registry",
      "官方源",
      `已收录 · ${facts.version ?? "未知版本"}`,
      "good",
      facts.ecosystem === "npm" ? "NPM Registry" : "PyPI JSON API",
    ),
  );

  let score = 0;

  if (facts.requestedVersionMissing) {
    score += 35;
    evidence.push({
      severity: "medium",
      title: "指定版本不存在",
      detail: "请求的精确版本不在 registry 的版本列表中。请确认版本号，避免实际安装到其他版本。",
    });
  }

  /* ----------------------------- age ----------------------------- */
  const age = facts.ageDays;
  if (age === undefined) {
    signals.push(signal("age", "发布年龄", "未知", "unknown"));
    evidence.push({
      severity: "info",
      title: "无法确定发布年龄",
      detail: "registry 未返回可用的发布时间，年龄未参与风险评分。",
    });
  } else {
    const status = age >= 365 ? "good" : age >= 90 ? "warn" : "bad";
    signals.push(
      signal(
        "age",
        "发布年龄",
        age >= 365 ? `${(age / 365).toFixed(1)} 年` : `${age} 天`,
        status,
        `创建于 ${facts.createdAt?.slice(0, 10) ?? "未知日期"}`,
      ),
    );
    if (age < 14) {
      score += 35;
      evidence.push({
        severity: "critical",
        title: "包注册时间极短",
        detail: `该包仅创建 ${age} 天。攻击者常抢注 AI 刚刚“幻想”出的包名，并在短期内投毒。`,
      });
    } else if (age < 60) {
      score += 22;
      evidence.push({
        severity: "high",
        title: "新注册的包",
        detail: `该包创建仅 ${age} 天，尚未经过社区长期验证。`,
      });
    } else if (age < 180) {
      score += 10;
      evidence.push({
        severity: "medium",
        title: "较新的包",
        detail: `该包创建 ${age} 天，建议确认维护者与源码仓库。`,
      });
    } else if (age < 365) {
      score += 4;
    }
  }

  /* --------------------------- downloads -------------------------- */
  const downloads = facts.weeklyDownloads;
  if (downloads === undefined) {
    signals.push(
      signal("downloads", "周下载量", "未知", "unknown", facts.downloadsSource ?? "数据源不可用"),
    );
    evidence.push({
      severity: "low",
      title: "下载量不可用",
      detail: "未能获取下载量，风险评分未包含该信号。请结合源码仓库与包年龄判断。",
    });
  } else {
    const status =
      downloads >= 10_000
        ? "good"
        : downloads >= resolved.minWeeklyDownloads
          ? "warn"
          : "bad";
    signals.push(
      signal(
        "downloads",
        "周下载量",
        `${formatNumber(downloads)} / 周`,
        status,
        facts.downloadsSource,
      ),
    );
    if (downloads < resolved.minWeeklyDownloads) {
      score += downloads === 0 ? 32 : 26;
      evidence.push({
        severity: downloads === 0 ? "critical" : "high",
        title: downloads === 0 ? "周下载量为 0" : "下载量异常低",
        detail: `周下载量仅 ${formatNumber(downloads)}，低于团队阈值 ${formatNumber(resolved.minWeeklyDownloads)}。这是幻觉包 / 抢注包的典型特征。`,
      });
    } else if (downloads < Math.max(1_000, resolved.minWeeklyDownloads * 10)) {
      score += 8;
      evidence.push({
        severity: "medium",
        title: "下载量偏低",
        detail: `周下载量 ${formatNumber(downloads)}，建议确认是否为内部包或新项目。`,
      });
    }
  }

  /* ----------------------------- stars ---------------------------- */
  if (facts.stars === undefined) {
    signals.push(
      signal(
        "stars",
        "GitHub Stars",
        "未关联仓库",
        "unknown",
        facts.repositoryUrl ? "仓库未托管在 GitHub 或 API 不可用" : "registry 未声明源码仓库",
      ),
    );
  } else {
    const status = facts.stars >= 100 ? "good" : facts.stars >= 10 ? "warn" : "bad";
    signals.push(
      signal("stars", "GitHub Stars", formatNumber(facts.stars), status, facts.repositoryUrl),
    );
    if (facts.stars < 5) {
      score += 8;
      evidence.push({
        severity: "medium",
        title: "源码仓库关注度极低",
        detail: `GitHub 仓库仅有 ${facts.stars} 个 Star。请人工检查仓库是否为镜像或空壳。`,
      });
    } else if (facts.stars < 25) {
      score += 3;
    }
  }

  if (!facts.repositoryUrl) {
    score += facts.ecosystem === "npm" ? 6 : 3;
    evidence.push({
      severity: "low",
      title: "未声明源码仓库",
      detail: "无法核对源码、构建产物与发布者是否一致。",
    });
  }

  /* ------------------------- vulnerabilities ---------------------- */
  const vulns = facts.vulnerabilities;
  const criticalVulns = vulns.filter((v) => v.severity === "critical");
  const highVulns = vulns.filter((v) => v.severity === "high");
  if (vulns.length === 0) {
    signals.push(signal("vulns", "已知漏洞", "未发现", "good", "OSV.dev"));
  } else {
    const worst = criticalVulns.length > 0 ? "critical" : highVulns.length > 0 ? "high" : "medium";
    signals.push(
      signal(
        "vulns",
        "已知漏洞",
        `${vulns.length} 个${worst === "critical" ? " · 含严重" : worst === "high" ? " · 含高危" : ""}`,
        worst === "critical" || worst === "high" ? "bad" : "warn",
        "OSV.dev 查询当前版本",
      ),
    );
    if (criticalVulns.length > 0) {
      score += 45;
    } else if (highVulns.length > 0) {
      score += 25;
    } else {
      score += 8;
    }
    for (const vuln of vulns.slice(0, 5)) {
      evidence.push({
        severity: vuln.severity,
        title: `${SEVERITY_LABEL[vuln.severity]}漏洞 ${vuln.id}`,
        detail: vuln.summary || "OSV 未提供摘要，请查看漏洞详情。",
      });
    }
    if (vulns.length > 5) {
      evidence.push({
        severity: "info",
        title: `另有 ${vulns.length - 5} 个漏洞`,
        detail: "报告仅展示风险最高的 5 个，完整列表请查看 OSV 页面。",
      });
    }
  }

  /* --------------------------- typosquat -------------------------- */
  if (resolved.typosquatGuard && facts.typosquat) {
    const lowTrust = (downloads ?? 0) < 10_000 || (age ?? 0) < 180;
    score += lowTrust ? 50 : 15;
    signals.push(
      signal(
        "typosquat",
        "相似热门包",
        facts.typosquat.popularName,
        lowTrust ? "bad" : "warn",
        `编辑距离 ${facts.typosquat.distance}`,
      ),
    );
    evidence.push({
      severity: lowTrust ? "critical" : "high",
      title: "疑似抢注 / 拼写混淆",
      detail: `该包与热门包 ${facts.typosquat.popularName} 仅相差 ${facts.typosquat.distance} 个字符，且自身下载量 / 包龄不足以证明可信。请确认是否拼写错误。`,
    });
  } else if (resolved.typosquatGuard) {
    signals.push(signal("typosquat", "相似热门包", "未发现", "good"));
  }

  /* ----------------------- package metadata ---------------------- */
  if (facts.hasInstallScript) {
    score += 8;
    signals.push(
      signal("installScript", "安装脚本", "存在", "warn", "安装时会在本机执行代码"),
    );
    evidence.push({
      severity: "medium",
      title: "包含 install 生命周期脚本",
      detail: "该包在安装时会执行脚本。建议在隔离环境或容器中安装，并审阅脚本内容。",
    });
  } else {
    signals.push(signal("installScript", "安装脚本", "无", "good"));
  }

  if (facts.deprecated) {
    score += 10;
    signals.push(signal("deprecated", "维护状态", "已废弃", "bad"));
    evidence.push({
      severity: "medium",
      title: "包已被标记为废弃",
      detail: "registry 将该包标记为 deprecated，可能存在未修复的安全问题。",
    });
  } else {
    signals.push(signal("deprecated", "维护状态", "正常", "good"));
  }

  if (facts.maintainers !== undefined) {
    const onlyOneNewMaintainer = facts.maintainers <= 1 && (age ?? 0) < 180;
    signals.push(
      signal(
        "maintainers",
        "维护者",
        `${facts.maintainers} 人`,
        onlyOneNewMaintainer ? "warn" : "good",
      ),
    );
    if (onlyOneNewMaintainer) {
      score += 6;
      evidence.push({
        severity: "low",
        title: "新包仅有单一维护者",
        detail: "发布者数量为 1 且包龄较短，建议核对发布者身份。",
      });
    }
  }

  score = Math.min(100, score);

  let verdict: Verdict;
  if (criticalVulns.length > 0) {
    verdict = "block";
  } else if (highVulns.length > 0) {
    verdict = "review";
  } else if (facts.typosquat && ((downloads ?? 0) < 10_000 || (age ?? 0) < 180)) {
    verdict = "block";
  } else if (score >= 70) {
    verdict = "block";
  } else if (score >= 35) {
    verdict = "review";
  } else {
    verdict = "allow";
  }

  const headline =
    verdict === "block"
      ? "高风险，已阻断"
      : verdict === "review"
        ? "建议人工复核"
        : "可以安装";
  const summary =
    verdict === "block"
      ? "检测到多项高风险信号。请勿直接安装，先核对包名、源码仓库与发布者。"
      : verdict === "review"
        ? "存在需要确认的信号。确认包名与用途后，再决定是否安装。"
        : "未发现明显的供应链风险信号。仍建议锁定版本并保留 lockfile。";

  if (evidence.length === 0) {
    evidence.push({
      severity: "info",
      title: "未发现显著风险信号",
      detail: "包已收录、维护状态正常，未发现已知漏洞或拼写混淆。",
    });
  }

  return {
    verdict,
    score,
    headline,
    summary,
    signals,
    evidence,
    allowlisted: false,
    blockedByPolicy: false,
  };
}

export function matchesPackageList(name: string, list: string[]): boolean {
  const target = name.toLowerCase();
  for (const rawPattern of list) {
    const pattern = rawPattern.trim().toLowerCase();
    if (!pattern) {
      continue;
    }
    if (pattern === target) {
      return true;
    }
    if (pattern.endsWith("/*")) {
      const scope = pattern.slice(0, -1);
      if (target.startsWith(scope)) {
        return true;
      }
    }
  }
  return false;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

function signal(
  key: string,
  label: string,
  value: string,
  status: PackageSignal["status"],
  detail?: string,
): PackageSignal {
  return { key, label, value, status, detail };
}
