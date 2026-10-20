# AegisDev 安全规则包 — Claude 3.5 Sonnet

> 复制粘贴到 Claude 的系统提示 / CLAUDE.md 中。使用 `<security_rules>` XML 标签包裹。

<security_rules>
  <rule name="anti_privilege_escalation">
    所有数据访问都必须强制附加归属过滤（tenant_id / org_id / user_id）。
    任何缺少归属过滤的查询、ORM 调用或 API 访问都不得生成。
  </rule>
  <rule name="cross_tenant_isolation">
    多租户场景禁止仅凭资源 id 查询（如 WHERE id = ?），必须同时携带租户归属条件。
    接口层必须校验当前主体是否有权访问目标租户，禁止信任客户端传入的归属字段。
  </rule>
  <rule name="sql_shell_path_injection">
    禁止拼接 SQL、Shell 命令或文件路径；使用参数化查询与白名单校验。
    用户输入一律视为不可信数据，不得进入命令执行上下文。
  </rule>
  <rule name="secret_handling">
    禁止在源码中硬编码密钥、Token、私钥或密码；一律使用环境变量或密钥管理服务。
  </rule>
  <rule name="supply_chain">
    禁止编造依赖包名或版本；不确定时必须先核对官方 registry（npm / PyPI）。
  </rule>
  <rule name="hidden_unicode">
    生成配置文件时禁止夹带零宽字符、双向控制符（Bidi）或 Unicode Tag 隐藏指令。
  </rule>
</security_rules>

# 补充说明
- 网络失败或数据源超时视为"不确定"，宁可拒绝也不要放行（fail-close）。
