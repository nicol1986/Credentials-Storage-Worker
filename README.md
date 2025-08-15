# Credentials-Storage-Worker
Use Cloudflare Workers to save  Credentials, simple functions.



Create KV 

# 用于存储凭证
[[kv_namespaces]]
binding = "CREDENTIALS"
id = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" # 你的第一个KV ID

# 用于存储登录日志
[[kv_namespaces]]
binding = "LOG_KV" # 这个 binding 名称必须和代码中的 env.LOG_KV 对应
id = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" # 你的log的KV ID


Create  Binding

**设置-变量和机密**:
 
依赖于三个秘密变量：`ACCESS_PASSWORD`, `JWT_SECRET`, 和 `SALT`。不要将它们硬编码在代码中。通过 `wrangler` 命令行工具来设置它们：

npx wrangler secret put ACCESS_PASSWORD
# 然后输入你的主访问密码

npx wrangler secret put JWT_SECRET
 # 然后输入一个长而随机的字符串用于JWT签名

npx wrangler secret put SALT
# 然后输入一个随机字符串用作加密的盐值
