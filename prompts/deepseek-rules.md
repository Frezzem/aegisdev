# AegisDev 安全规则包 — DeepSeek Coder (Few-Shot)

> 复制粘贴到 DeepSeek 的规则或系统提示中。用正反例（Few-Shot）强化防越权。

# 核心红线：防越权（强制 tenant_id 归属过滤）
任何数据库 / API 访问都必须强制附加 tenant_id 过滤，未过滤的代码一律禁止生成。

# 反例
```python
# 反例 1：SQL 字符串拼接，且缺少租户归属过滤
query = "SELECT * FROM orders WHERE id = " + str(order_id)
cursor.execute(query)

# 反例 2：仅凭 id 查询，跨租户风险
@app.get("/orders/{order_id}")
def get_order(order_id: int):
    return db.query(Order).filter(Order.id == order_id).first()
```

# 正例
```python
# 正例 1：参数化查询 + 强制 tenant_id 过滤
cursor.execute(
    "SELECT * FROM orders WHERE tenant_id = %s AND id = %s",
    (current_tenant_id, order_id),
)

# 正例 2：归属校验，杜绝跨租户访问
@app.get("/orders/{order_id}")
def get_order(order_id: int):
    return (
        db.query(Order)
        .filter(Order.tenant_id == current_tenant_id, Order.id == order_id)
        .first()
    )
```

# 依赖安全
- 禁止编造依赖包；不确定时必须先核对官方 registry（npm / PyPI），再给出包名与版本。
- 安装命令必须来自核对过的包名，禁止拼接用户原始输入。

# 密钥与注入
- 禁止硬编码密钥 / Token / 私钥；用环境变量或密钥管理服务。
- 禁止拼接 SQL / Shell / 路径；用参数化查询与白名单。
- 生成配置文件时禁止夹带零宽字符、双向控制符或 Unicode Tag 隐藏指令。
