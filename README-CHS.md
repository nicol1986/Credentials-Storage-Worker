# safepass v1.2

部署在 **Cloudflare Workers** 上的加密密码保险库（单文件实现）。凭据在浏览器端用主密码派生的密钥做 AES-GCM 加密，**后端只存储密文**，服务器永远看不到明文。

> v1.2 相对 v1.1 的最大变化：**后端存储从 Workers KV 迁移到 D1（SQLite）**，读写强一致，并辅以前端「乐观更新」，从根上解决了旧版偶发的「保存后读不到 / 显示不出来」问题。

---

## v1.2 相对 v1.1 的变化

| 项目 | v1.1（KV） | v1.2（D1） |
| --- | --- | --- |
| 存储 | Workers KV（最终一致） | **D1 SQLite（强一致 + 事务）** |
| 写入后读取 | 可能因一致性延迟读到旧值 | 写后立刻能读到自己写的数据 |
| 列表读取 | `KV.list()` + 逐条 get，慢且有延迟 | `SELECT ...`，可排序/索引 |
| 返回结果 | POST/PUT 只返回 `{id, service}` | **返回完整记录**，前端直接更新本地 |
| 前端刷新 | 保存后盲刷全量列表 | **乐观更新**：用返回值就地更新 |
| 部署绑定 | KV ×2（`CREDENTIALS` + `LOG_KV`） | **仅需一个 D1 绑定 `DB`**（凭据与日志同库两张表） |

> 为什么能解决「保存异常」：旧版的「保存上了但显示不出来」本质是 KV 最终一致——写入成功后前端立刻重读，可能读到还没同步的旧值。v1.2 改为 D1 强一致 + 后端返回完整记录 + 前端用返回值就地刷新，不再依赖「立刻能读到」。

---

## 工作原理简述

1. 登录：前端把主密码 + `SALT` 通过 PBKDF2(SHA-256, 10 万次) 派生出 AES-GCM 256 位密钥；后端仅校验 `ACCESS_PASSWORD` 并签发 JWT。
2. 存储：每条用户名/密码在前端单独用该密钥加密，后端把**密文 JSON** 存进 D1 的 `credentials` 表（列：`username`/`password` 存的是密文的 JSON 字符串）。
3. 读取：后端从 D1 `SELECT` 返回，前端用本地密钥解密后展示。

> 解密密钥由 **主密码 + SALT** 决定。只要这两者不变，密文永远可解密。

---

## 一、手动部署（Dashboard 方式）

1. **登录 Cloudflare Dashboard** → **Workers & Pages** → **D1**（侧边栏）。
2. **创建数据库**：点击 *Create database*，名称 `safepass`，记下它的 **Database ID**。
3. **建表（必须）**：进入该数据库 → **Console**（SQL 控制台），执行下面的建表语句：

   ```sql
   CREATE TABLE IF NOT EXISTS credentials (
     id          TEXT PRIMARY KEY,
     service     TEXT NOT NULL,
     username    TEXT NOT NULL,   -- 存的是密文的 JSON 字符串
     password    TEXT NOT NULL,   -- 存的是密文的 JSON 字符串
     grp         TEXT NOT NULL DEFAULT '未分组',
     created_at  INTEGER NOT NULL
   );
   CREATE TABLE IF NOT EXISTS login_logs (
     id      INTEGER PRIMARY KEY AUTOINCREMENT,
     ip      TEXT,
     ts      INTEGER,
     status  TEXT
   );
   CREATE TABLE IF NOT EXISTS groups_meta (
     name        TEXT PRIMARY KEY,
     color       TEXT NOT NULL,
     sort_order  INTEGER NOT NULL DEFAULT 0
   );
   CREATE INDEX IF NOT EXISTS idx_credentials_grp ON credentials(grp);
   ```

4. **创建并配置 Worker**：
   - 新建 Worker（如 `safepass`），把本目录 `worker.js` 全量粘贴覆盖，保存（Deploy）。
   - Worker 详情 → **Settings → Variables and Secrets**：
     - **Secrets**：`ACCESS_PASSWORD`（登录主密码）、`JWT_SECRET`（随机长字符串）。
     - **Variables**（普通变量）：`SALT`（可选，建议自定义随机串）。
   - Worker 详情 → **Settings → D1 database bindings** → 添加绑定：
     - 变量名 `DB` → 选择刚创建的 `safepass` 数据库。
5. **重新 Deploy**，访问 Worker 地址即可使用。

---

## 二、手动部署（Wrangler CLI 方式）

1. **安装并登录**

   ```bash
   npm install -g wrangler
   wrangler login
   ```

2. **创建 D1 数据库并记录 id**

   ```bash
   wrangler d1 create safepass
   ```

3. **编写 migration 文件**（例如 `migrations/0001_init.sql`，内容即上方「建表语句」），然后执行：

   ```bash
   # 远程数据库（线上）
   wrangler d1 execute safepass --remote --file=./migrations/0001_init.sql
   # 本地调试可用 --local
   ```

4. **新建 `wrangler.toml`**（与 `worker.js` 同目录）：

   ```toml
   name = "safepass"
   main = "worker.js"
   compatibility_date = "2024-09-01"

   # SALT 是可选变量；敏感信息请务必用 secret 而不是写在这里
   [vars]
   SALT = "your-custom-salt-string"

   [[d1_databases]]
   binding = "DB"
   database_name = "safepass"
   database_id = "替换为上面的 Database ID"
   ```

5. **写入敏感 Secret**（交互式，不会进仓库）：

   ```bash
   wrangler secret put ACCESS_PASSWORD
   wrangler secret put JWT_SECRET
   ```

6. **部署**

   ```bash
   wrangler deploy
   ```

   本地预览：`wrangler dev`（会用到本地 D1，记得先 `wrangler d1 execute safepass --local --file=./migrations/0001_init.sql` 建本地表）。

---

## 三、环境变量 / 绑定一览

| 名称 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `ACCESS_PASSWORD` | Secret | 是 | 登录主密码 |
| `JWT_SECRET` | Secret | 是 | JWT 签名密钥（随机长字符串） |
| `SALT` | Variable | 否 | 密钥派生盐；不设则用内置默认值，**建议自定义** |
| `DB` | D1 binding | 是 | D1 数据库（含 `credentials` 与 `login_logs` 两张表） |

> v1.2 **不再需要任何 KV 命名空间**。

---

## 四、从 v1.1（KV）迁移旧数据

v1.2 换了存储引擎（KV → D1），但**密文格式完全没变**（仍是 `{iv, data}`），所以数据可以无缝迁移，走「前端导出/导入」即可：

1. 在 **v1.1 实例**上登录 → 点 **Export Backup**，下载 `safepass-backup-YYYY-MM-DD.json`（明文 JSON，含 `group`）。
2. 在 **v1.2 实例**上完成上述部署并登录 → 点 **Import Backup** → 选择文件。
3. 导入时前端会用**当前登录的主密码**重新加密每条记录，再写入 D1 的 `credentials` 表，`group` 一并保留。

> 备份文件是**明文**的，包含你的全部账号密码，妥善删除/保管，不要上传到公共位置。
>
> 若 v1.1 与 v1.2 使用**相同的主密码**，导入后解密内容一致；若换了主密码，导入会用新密码重新加密，旧实例的密文即失效，符合预期。

如果你希望**保留旧密文、不改主密码**地迁移，也可以写一个一次性脚本：用 Workers KV 绑定读取 v1.1 的 `CREDENTIALS`，逐条 `INSERT` 到 D1（密文原样搬，因为密钥未变仍可解密）。这属于进阶操作，按需自行实现。

---

## 四（补）、部署后常见问题排查

部署后若页面卡在 `Loading...` 或报错，按下面逐一排查：

| 现象 | 原因 | 解决 |
| --- | --- | --- |
| **登录即报 `env.DB.prepare is not a function`** | `env.DB` 绑定的不是 D1 数据库对象（可能绑成了 KV、或绑定类型选错） | Dashboard：Settings → **D1 database bindings**（不是 KV namespace），变量名 `DB`，选择你的 D1 数据库 |
| 任意接口返回 `{"error":"D1 绑定缺失..."}` | 完全没绑 D1，或变量名不是 `DB` | 同上，确保绑定类型是 **D1 database** |
| 列表/日志加载失败，日志出现 `no such table: credentials` | 表没建 | 进 D1 Console 手动跑一遍「建表语句」 |
| `showMessage` 出现 `Failed to process request` | 后端异常（如字段缺失/SQL 错误） | 打开 Cloudflare 该 Worker 的 **Logs / 实时日志**，看抛出的 `detail` 字段定位 |
| 能登录但保存报错 | `ACCESS_PASSWORD` / `JWT_SECRET` 未设为 Secret | 在 Variables and Secrets 里补上两个 Secret 后重新 Deploy |

> v1.2 已把后端真实错误以 `detail` 字段返回，并在 Cloudflare 侧 `console.error` 打印，排错时直接看 Worker 的实时日志即可。

---

## 五、安全提示

- `SALT` 建议自定义为足够随机的字符串，避免依赖代码内置默认值。
- `ACCESS_PASSWORD` / `JWT_SECRET` 务必用 **Secret** 存储，不要提交到代码或仓库。
- D1 是关系型库，v1.2 对写入用了参数化 SQL，避免 SQL 注入；但凭据密文仍由前端主密码保护，服务器侧仅存密文。
- 导出备份为明文 JSON，注意落盘安全。
- 本项目适合个人/小团队自托管，未做 rate-limit、防爆破等生产级加固，请勿直接承载极高敏感凭据。
- Cloudflare 免费套餐包含一定额度的 D1 存储与每日查询，个人使用通常足够；具体额度以官方最新文档为准。
