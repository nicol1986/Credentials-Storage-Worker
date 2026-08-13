export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/') return handleStaticHTML(request);
    if (url.pathname.startsWith('/api/')) return handleApiRequest(request, env);
    return new Response('Not Found', { status: 404 });
  }
};

/**
 * safepass v1.2 — 部署在 Cloudflare Workers 上的加密密码保险库
 *
 * 相比 v1.1 的变更 (changelog):
 *   - 后端存储从 Workers KV 迁移到 D1（SQLite），读写强一致、支持事务/索引
 *   - 凭据与登录日志统一存 D1（credentials / login_logs 两张表），不再依赖 KV
 *   - POST/PUT 返回写入后的完整记录，前端做乐观更新，解决「保存后读不到」的假象
 *   - 删除/导入也走乐观更新，操作后即时反映到界面
 *   - 部署方式变化：需绑定 D1 数据库（变量名 DB）并手动执行建表 SQL（见 README）
 *   - 新增 groups_meta 表存储分组颜色与顺序；前端「Manage Groups」可调整每个分组的颜色与排序
 *   - 每个分组下的条目以该分组颜色作底色（透明度 85%，即 15% 不透明，常量 ROW_TINT 可调）
 *   - 后端 catch 透出真实错误（detail 字段），并在 Cloudflare 侧 console.error，便于排错
 *
 * 注意：本文件同时包含前端页面与后端 API，单文件即可部署。
 */
function handleStaticHTML(request) {
  return new Response(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure Credential Storage</title>
          <style>
          :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --primary-light: #818cf8;
            --danger: #ef4444;
            --danger-dark: #dc2626;
            --success: #10b981;
            --bg-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --text: #1f2937;
            --text-muted: #6b7280;
            --border: #e5e7eb;
            --surface: #ffffff;
            --surface-soft: #f9fafb;
            --radius: 14px;
          }
          * { box-sizing: border-box; }
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'PingFang SC', 'Microsoft YaHei', sans-serif;
            min-height: 100vh;
            margin: 0;
            padding: 40px 16px;
            background: var(--bg-gradient);
            color: var(--text);
            font-size: 14px;
            line-height: 1.5;
          }
          .container {
            background: var(--surface);
            padding: 36px;
            border-radius: var(--radius);
            box-shadow: 0 20px 60px rgba(0,0,0,0.25);
            width: 100%;
            max-width: 1140px;
            margin: 0 auto;
            animation: fadeIn .35s ease;
          }
          @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
          .hidden { display: none !important; }
          h2 { margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.01em; }
          h3 { font-size: 16px; font-weight: 600; color: var(--text); margin: 0 0 12px; }
          p { color: var(--text-muted); margin: 6px 0; }

          /* Inputs */
          input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px 14px;
            margin: 8px 0;
            border: 1px solid var(--border);
            border-radius: 10px;
            font-size: 14px;
            transition: border-color .15s, box-shadow .15s;
            outline: none;
          }
          input[type="text"]:focus, input[type="password"]:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99,102,241,0.15);
          }

          /* Buttons */
          button {
            padding: 12px 18px;
            width: 100%;
            border: none;
            border-radius: 10px;
            font-size: 14px;
            font-weight: 600;
            color: #fff;
            background: var(--primary);
            cursor: pointer;
            transition: background .15s, transform .05s;
          }
          button:hover { background: var(--primary-dark); }
          button:active { transform: translateY(1px); }
          .logout-btn { background: var(--danger); width: auto; float: right; padding: 8px 16px; font-size: 13px; }
          .logout-btn:hover { background: var(--danger-dark); }
          .action-btn { padding: 6px 12px; width: auto; font-size: 12px; border-radius: 8px; margin-right: 6px; }
          .update-btn { background: var(--primary); }
          .update-btn:hover { background: var(--primary-dark); }
          .delete-btn { background: var(--danger); }
          .delete-btn:hover { background: var(--danger-dark); }
          #cancel-update-btn { background: #6b7280; width: auto; }
          #cancel-update-btn:hover { background: #4b5563; }
          .form-buttons { display: flex; gap: 10px; margin-top: 8px; }
          .form-buttons button { flex: 1; }

          /* Messages */
          .error { color: var(--danger); font-size: 13px; }
          .success { color: var(--success); font-size: 13px; }
          #save-message { margin: 8px 0; min-height: 18px; font-weight: 500; }

          /* Header */
          .header { overflow: hidden; padding-bottom: 16px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
          .header h2 { float: left; }

          /* Login */
          #login-section { max-width: 360px; margin: 40px auto; text-align: center; }
          #login-section .lock-icon {
            width: 64px; height: 64px; margin: 0 auto 16px;
            display: flex; align-items: center; justify-content: center;
            background: linear-gradient(135deg, var(--primary-light), var(--primary));
            border-radius: 50%; color: #fff;
          }

          /* Cards / sections */
          .card {
            background: var(--surface-soft);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
          }
          .section-title {
            display: flex; align-items: center; gap: 8px;
            margin: 32px 0 14px; font-size: 15px; font-weight: 700;
          }
          .section-title::before {
            content: ''; width: 4px; height: 16px; border-radius: 2px;
            background: var(--primary);
          }

          /* Toolbar (export / import) */
          .toolbar { display: flex; gap: 10px; margin-bottom: 4px; }
          .tool-btn { width: auto; padding: 8px 16px; font-size: 13px; }
          .tool-btn-secondary { background: #fff; color: var(--primary); border: 1px solid var(--primary); }
          .tool-btn-secondary:hover { background: #eef2ff; }
          .backup-note { font-size: 12px; color: var(--text-muted); margin: 4px 0 12px; }

          /* Filters (group / sort) */
          .toolbar-filters { margin-bottom: 12px; align-items: center; }
          .filter-label { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-muted); margin: 0; }
          .filter-select {
            width: auto; padding: 7px 10px; border: 1px solid var(--border);
            border-radius: 8px; font-size: 13px; background: #fff; color: var(--text); outline: none;
          }
          .filter-select:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99,102,241,0.15); }
          .group-row { cursor: pointer; user-select: none; }
          .group-row td { background: var(--surface-soft); font-weight: 700; color: var(--text); border-bottom: 2px solid var(--border); border-left: 4px solid var(--g, var(--primary)); }
          .group-toggle { display: inline-block; margin-right: 8px; font-size: 11px; color: var(--text-muted); transition: transform .15s; }
          .group-row.collapsed .group-toggle { transform: rotate(-90deg); }
          .group-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; vertical-align: middle; background: var(--g, #6366f1); }
          .group-name { display: inline-block; }
          .group-count { margin-left: 8px; font-size: 11px; font-weight: 600; }
          .group-tag { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 13px; font-weight: 400; }

          /* Tables */
          #credentials-container, #logs-container { overflow-x: auto; border-radius: 12px; }
          .data-table { width: 100%; border-collapse: collapse; margin-top: 6px; font-size: 13px; }
          .data-table th, .data-table td { padding: 12px 14px; text-align: left; border-bottom: 1px solid var(--border); }
          .data-table th { background: #f3f4f6; font-weight: 600; color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
          .data-table tbody tr:not(.cred-row):hover { background: var(--surface-soft); }
          .data-table tbody tr.cred-row:hover { filter: brightness(0.96); }
          .data-table td:nth-child(3), .data-table td:nth-child(4) { font-family: 'SFMono-Regular', Menlo, Consolas, monospace; }

          /* Logs */
          .log-status-success { color: var(--success); font-weight: 600; }
          .log-status-failure { color: var(--danger); font-weight: 600; }
          #logs-table th, #logs-table td { font-size: 12px; }

          @media (max-width: 520px) {
            .container { padding: 22px; }
            .action-btn { display: block; width: 100%; margin: 4px 0; }
          }
          .version-badge { text-align: center; margin-top: 20px; font-size: 12px; color: var(--text-muted); letter-spacing: .03em; }

          /* Modal (Manage Groups) */
          .modal { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.5); display: flex; align-items: center; justify-content: center; padding: 16px; z-index: 50; }
          .modal-card { background: var(--surface); border-radius: var(--radius); padding: 28px; width: 100%; max-width: 460px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-height: 85vh; overflow-y: auto; }
          .modal-card h3 { margin: 0; }
          #groups-editor-list { margin-top: 14px; display: flex; flex-direction: column; gap: 10px; }
          .ge-row { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; background: var(--surface-soft); }
          .ge-color { width: 34px; height: 34px; padding: 0; border: none; border-radius: 8px; background: none; cursor: pointer; }
          .ge-color::-webkit-color-swatch-wrapper { padding: 0; }
          .ge-color::-webkit-color-swatch { border: 1px solid var(--border); border-radius: 8px; }
          .ge-name { flex: 1; font-size: 14px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
          .ge-up, .ge-down { width: 30px; height: 30px; padding: 0; font-size: 14px; border-radius: 8px; border: 1px solid var(--border); background: #fff; color: var(--text); cursor: pointer; }
          .ge-up:hover, .ge-down:hover { background: var(--surface-soft); }
          .cancel-btn { background: #6b7280; }
          .cancel-btn:hover { background: #4b5563; }
          </style>
      </head>
        <body>
        <div class="container">
            <div id="login-section">
                <div class="lock-icon">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </div>
                <h2>Secure Credential Storage</h2>
                <p>Enter your master password to unlock stored credentials.</p>
                <input type="password" id="password" placeholder="Master password">
                <button id="login-btn">Unlock</button>
                <div id="login-error" class="error"></div>
            </div>
            <div id="app-section" class="hidden">
                <div class="header">
                    <h2>Stored Credentials</h2>
                    <button id="logout-btn" class="logout-btn">Log out</button>
                </div>

                <div class="section-title">Add / Edit Credential</div>
                <div class="card">
                    <h3 id="form-title">Add New Credential</h3>
                    <input type="hidden" id="credential-id">
                    <input type="text" id="service-name" placeholder="Service Name (e.g., Gmail)">
                    <input type="text" id="credential-group" placeholder="Group (e.g., Work, Personal)" list="group-suggestions">
                    <datalist id="group-suggestions"></datalist>
                    <input type="text" id="username" placeholder="Username / Email">
                    <input type="text" id="credential-password" placeholder="Password">
                    <div class="form-buttons">
                        <button id="save-btn">Save Credential</button>
                        <button id="cancel-update-btn" class="hidden">Cancel</button>
                    </div>
                    <div id="save-message"></div>
                </div>

                <div class="section-title">Saved Credentials</div>
                <div class="toolbar">
                    <button id="export-btn" class="tool-btn">Export Backup</button>
                    <button id="import-btn" class="tool-btn tool-btn-secondary">Import Backup</button>
                    <button id="manage-groups-btn" class="tool-btn tool-btn-secondary">Manage Groups</button>
                    <input type="file" id="import-file" accept="application/json,.json" class="hidden">
                </div>
                <p class="backup-note">Backup is saved as a plain-text JSON file on your device. Keep it safe.</p>
                <div class="toolbar toolbar-filters">
                    <label class="filter-label">Group
                        <select id="group-select" class="filter-select">
                            <option value="none">No grouping</option>
                            <option value="group">By group</option>
                        </select>
                    </label>
                    <label class="filter-label">Sort
                        <select id="sort-select" class="filter-select">
                            <option value="service-asc">Service A → Z</option>
                            <option value="service-desc">Service Z → A</option>
                            <option value="group">Group</option>
                            <option value="recent">Recently added</option>
                        </select>
                    </label>
                </div>
                <div id="credentials-container">
                    <table id="credentials-table" class="data-table">
                        <thead><tr><th>Service</th><th>Group</th><th>Username</th><th>Password</th><th>Actions</th></tr></thead>
                        <tbody id="credentials-list-body"></tbody>
                    </table>
                    <p id="no-credentials-message" class="hidden">No credentials saved yet.</p>
                </div>

                <div class="section-title">Recent Login History</div>
                <div id="logs-container">
                    <table id="logs-table" class="data-table">
                        <thead><tr><th>Time</th><th>IP Address</th><th>Status</th></tr></thead>
                        <tbody id="logs-list-body"></tbody>
                    </table>
                </div>
            </div>

            <div id="groups-modal" class="modal hidden">
                <div class="modal-card">
                    <h3>Manage Groups</h3>
                    <p class="backup-note">调整每个分组的颜色与顺序，点击 Save 后生效。</p>
                    <div id="groups-editor-list"></div>
                    <div class="form-buttons" style="margin-top: 16px;">
                        <button id="groups-save-btn">Save</button>
                        <button id="groups-cancel-btn" class="cancel-btn">Cancel</button>
                    </div>
                </div>
            </div>
        </div>
        <div class="version-badge">safepass v1.2 · D1 存储 · 本地加密 · 仅存密文</div>
        <script>
          const $ = id => document.getElementById(id);
          const loginSection = $('login-section'), appSection = $('app-section'), passwordInput = $('password');
          const loginBtn = $('login-btn'), loginError = $('login-error'), logoutBtn = $('logout-btn');
          const serviceNameInput = $('service-name'), usernameInput = $('username'), credentialPasswordInput = $('credential-password'), groupInput = $('credential-group'), groupSuggestions = $('group-suggestions');
          const saveBtn = $('save-btn'), saveMessage = $('save-message'), credentialIdInput = $('credential-id');
          const formTitle = $('form-title'), cancelUpdateBtn = $('cancel-update-btn');
          const credentialsTable = $('credentials-table'), credentialsListBody = $('credentials-list-body'), noCredentialsMessage = $('no-credentials-message');
          const logsListBody = $('logs-list-body');
          const exportBtn = $('export-btn'), importBtn = $('import-btn'), importFile = $('import-file');
          const groupSelect = $('group-select'), sortSelect = $('sort-select');
          let authToken = null, encryptionKey = null, currentEditingId = null;
          let allCredentials = [], currentSort = 'service-asc', currentGroupMode = 'none';
          let groupsMeta = {}; // name -> { color, sort_order }
          const collapsedGroups = new Set();
          const ROW_TINT = 0.15; // 底色透明度 85%（即 15% 不透明）；想要更深的 85% 不透明请改成 0.85

          // --- Core Functions (Auth, Crypto) ---
          async function login() {
              const password = passwordInput.value;
              if (!password) { loginError.textContent = 'Please enter a password'; return; }
              loginError.textContent = '';
              try {
                  const response = await fetch('/api/auth', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) });
                  const data = await response.json();
                  if (response.ok) {
                      authToken = data.token;
                      encryptionKey = await generateKey(password, data.salt);
                      loginSection.classList.add('hidden');
                      appSection.classList.remove('hidden');
                      loadGroups();
                      loadCredentials();
                      loadLoginLogs();
                  } else { loginError.textContent = data.error || 'Authentication failed'; }
              } catch (error) { loginError.textContent = 'Network error or invalid server response. Please try again.'; }
          }
          function logout() {
              authToken = null; encryptionKey = null;
              appSection.classList.add('hidden'); loginSection.classList.remove('hidden');
              passwordInput.value = ''; loginError.textContent = ''; credentialsListBody.innerHTML = '';
          }
          async function generateKey(password, salt) {
              const enc = new TextEncoder();
              const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
              return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
          }
          async function encryptData(text, key) {
              const enc = new TextEncoder();
              const iv = crypto.getRandomValues(new Uint8Array(12));
              const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(text));
              return { iv: Array.from(iv), data: Array.from(new Uint8Array(encrypted)) };
          }
          async function decryptData(encryptedData, key) {
              const iv = new Uint8Array(encryptedData.iv);
              const data = new Uint8Array(encryptedData.data);
              const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, data);
              return new TextDecoder().decode(decrypted);
          }
          
          // --- Credential Management ---
          async function saveOrUpdateCredential() {
              const service = serviceNameInput.value.trim();
              const username = usernameInput.value.trim();
              const password = credentialPasswordInput.value;
              const group = groupInput.value.trim() || '未分组';
              if (!service || !username || !password) { showMessage('Please fill all fields', 'error'); return; }
              try {
                  const encryptedUsername = await encryptData(username, encryptionKey);
                  const encryptedPassword = await encryptData(password, encryptionKey);
                  const isUpdating = !!currentEditingId;
                  const url = isUpdating ? \`/api/credentials/\${currentEditingId}\` : '/api/credentials';
                  const method = isUpdating ? 'PUT' : 'POST';
                  const response = await fetch(url, { method, headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${authToken}\` }, body: JSON.stringify({ service, username: encryptedUsername, password: encryptedPassword, group }) });
                  if (response.ok) {
                      const saved = await response.json();
                      showMessage(\`Credential \${isUpdating ? 'updated' : 'saved'} successfully!\`, 'success');
                      cancelUpdate();
                      // 乐观更新：用后端返回的完整记录更新本地列表，规避一致性导致的显示延迟
                      const idx = allCredentials.findIndex(c => c.id === saved.id);
                      if (idx >= 0) allCredentials[idx] = saved; else allCredentials.push(saved);
                      await renderCredentials();
                  } else {
                      const data = await response.json();
                      showMessage(data.error || 'Failed to save credential', 'error');
                  }
              } catch (error) {
                  showMessage('Network error during save. Please try again.', 'error');
              }
          }
          
          async function loadCredentials() {
              credentialsListBody.innerHTML = '<tr><td colspan="5">Loading...</td></tr>';
              noCredentialsMessage.classList.add('hidden'); credentialsTable.classList.remove('hidden');
              try {
                  const response = await fetch('/api/credentials', { headers: { 'Authorization': \`Bearer \${authToken}\` } });
                  if (response.ok) {
                      allCredentials = await response.json();
                      await renderCredentials();
                  } else {
                      const data = await response.json();
                      showMessage(data.error || 'Failed to load credentials', 'error');
                  }
              } catch (error) {
                  showMessage('Network error during load. Please try again.', 'error');
              }
          }

          async function renderCredentials() {
              credentialsListBody.innerHTML = '';
              if (!allCredentials || allCredentials.length === 0) {
                  credentialsTable.classList.add('hidden'); noCredentialsMessage.classList.remove('hidden'); return;
              }
              credentialsTable.classList.remove('hidden'); noCredentialsMessage.classList.add('hidden');

              const uniqueGroups = [...new Set(allCredentials.map(c => c.group || '未分组'))];
              groupSuggestions.innerHTML = '';
              for (const g of uniqueGroups) {
                  const opt = document.createElement('option');
                  opt.value = g; groupSuggestions.appendChild(opt);
              }

              const sorted = [...allCredentials].sort(compareCredentials);
              if (currentGroupMode === 'group') {
                  const buckets = {};
                  for (const c of sorted) {
                      const g = c.group || '未分组';
                      (buckets[g] = buckets[g] || []).push(c);
                  }
                  for (const g of orderedGroups(Object.keys(buckets))) {
                      const color = groupColor(g);
                      const header = credentialsListBody.insertRow();
                      header.className = 'group-row';
                      header.dataset.group = g;
                      header.style.setProperty('--g', color);
                      if (collapsedGroups.has(g)) header.classList.add('collapsed');
                      header.innerHTML = \`<td colspan="5"><span class="group-toggle">&#9662;</span><span class="group-dot"></span><span class="group-name">\${escapeHTML(g)}</span><span class="group-count" style="color:\${color};background:\${hexToRgba(color, 0.15)}">\${buckets[g].length}</span></td>\`;
                      header.addEventListener('click', () => toggleGroup(g));
                      for (const c of buckets[g]) await appendCredentialRow(c);
                  }
              } else {
                  for (const c of sorted) await appendCredentialRow(c);
              }
          }

          function compareCredentials(a, b) {
              const sa = (a.service || '').toString(), sb = (b.service || '').toString();
              if (currentSort === 'service-desc') return sb.localeCompare(sa, 'zh');
              if (currentSort === 'group') {
                  const ga = a.group || '未分组', gb = b.group || '未分组';
                  if (ga !== gb) return ga.localeCompare(gb, 'zh');
                  return sa.localeCompare(sb, 'zh');
              }
              if (currentSort === 'recent') return (b.createdAt || 0) - (a.createdAt || 0);
              return sa.localeCompare(sb, 'zh');
          }

          function groupColor(name) {
              if (groupsMeta[name] && groupsMeta[name].color) return groupsMeta[name].color;
              const palette = ['#6366f1', '#ec4899', '#f59e0b', '#10b981', '#3b82f6', '#ef4444', '#8b5cf6', '#14b8a6', '#f97316', '#0ea5e9'];
              let h = 0;
              for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
              return palette[h % palette.length];
          }
          function groupOrder(name) {
              return (groupsMeta[name] && typeof groupsMeta[name].sort_order === 'number') ? groupsMeta[name].sort_order : Number.MAX_SAFE_INTEGER;
          }
          // 按存储的 sort_order 排序分组；未配置的分组按名称追加在后
          function orderedGroups(names) {
              return [...names].sort((a, b) => {
                  const oa = groupOrder(a), ob = groupOrder(b);
                  if (oa !== ob) return oa - ob;
                  return a.localeCompare(b, 'zh');
              });
          }
          async function loadGroups() {
              try {
                  const r = await fetch('/api/groups', { headers: { 'Authorization': \`Bearer \${authToken}\` } });
                  if (r.ok) {
                      const list = await r.json();
                      groupsMeta = {};
                      (list || []).forEach(g => { groupsMeta[g.name] = { color: g.color, sort_order: g.sort_order ?? 0 }; });
                  }
              } catch (e) { /* 分组元数据可选，忽略错误 */ }
          }
          function hexToRgba(hex, a) {
              const n = parseInt(hex.slice(1), 16);
              return \`rgba(\${(n >> 16) & 255}, \${(n >> 8) & 255}, \${n & 255}, \${a})\`;
          }
          function toggleGroup(name) {
              const nowCollapsed = !collapsedGroups.has(name);
              if (nowCollapsed) collapsedGroups.add(name); else collapsedGroups.delete(name);
              credentialsListBody.querySelectorAll('.group-row').forEach(h => { if (h.dataset.group === name) h.classList.toggle('collapsed', nowCollapsed); });
              credentialsListBody.querySelectorAll('.cred-row').forEach(r => { if (r.dataset.group === name) r.style.display = nowCollapsed ? 'none' : ''; });
          }

          async function appendCredentialRow(cred) {
              const row = credentialsListBody.insertRow();
              const group = cred.group || '未分组';
              try {
                  if (!cred.username || !cred.password) {
                      row.innerHTML = \`<td colspan="5" class="error">Incomplete data for \${escapeHTML(cred.service)}</td>\`; return;
                  }
                  const username = await decryptData(cred.username, encryptionKey);
                  const password = await decryptData(cred.password, encryptionKey);
                  const escapedService = escapeHTML(cred.service);
                  const escapedGroup = escapeHTML(group);
                  const escapedUsername = escapeHTML(username);
                  const escapedPassword = escapeHTML(password);
                  const color = groupColor(group);
                  row.dataset.group = group;
                  row.classList.add('cred-row');
                  row.style.background = hexToRgba(color, ROW_TINT);
                  if (collapsedGroups.has(group)) row.style.display = 'none';
                  row.innerHTML = \`
                      <td>\${escapedService}</td><td><span class="group-tag" style="color:\${color};background:\${hexToRgba(color, 0.15)}">\${escapedGroup}</span></td><td>\${escapedUsername}</td><td>\${escapedPassword}</td>
                      <td>
                          <button class="action-btn update-btn" onclick="startUpdate('\${cred.id}', '\${escapedService}', '\${escapedUsername}', '\${escapedPassword}', '\${escapedGroup}')">Update</button>
                          <button class="action-btn delete-btn" onclick="deleteCredential('\${cred.id}')">Delete</button>
                      </td>
                  \`;
                  row.setAttribute('data-id', cred.id);
              } catch (error) {
                  row.innerHTML = \`<td>\${escapeHTML(cred.service || '')}</td><td colspan="4" class="error">Error decrypting data.</td>\`;
              }
          }
          
          async function deleteCredential(id) {
              if (!confirm('Are you sure you want to delete this credential?')) return;
              try {
                  const response = await fetch(\`/api/credentials/\${id}\`, { method: 'DELETE', headers: { 'Authorization': \`Bearer \${authToken}\` } });
                  if (response.ok) { 
                      showMessage('Credential deleted successfully!', 'success'); 
                      allCredentials = allCredentials.filter(c => c.id !== id);
                      await renderCredentials();
                  } else { 
                      const data = await response.json(); 
                      showMessage(data.error || 'Failed to delete credential', 'error'); 
                  }
              } catch (error) { 
                  showMessage('Network error during delete. Please try again.', 'error'); 
              }
          }
          
          function startUpdate(id, service, username, password, group) {
              currentEditingId = id;
              credentialIdInput.value = id;
              serviceNameInput.value = service;
              groupInput.value = group || '';
              usernameInput.value = username;
              credentialPasswordInput.value = password;
              formTitle.textContent = 'Update Credential';
              saveBtn.textContent = 'Confirm Update';
              cancelUpdateBtn.classList.remove('hidden');
              window.scrollTo({ top: 0, behavior: 'smooth' });
          }
          
          function cancelUpdate() {
              currentEditingId = null;
              credentialIdInput.value = ''; serviceNameInput.value = ''; groupInput.value = ''; usernameInput.value = ''; credentialPasswordInput.value = '';
              formTitle.textContent = 'Add New Credential';
              saveBtn.textContent = 'Save Credential';
              cancelUpdateBtn.classList.add('hidden');
          }

          // --- Login Log Functions ---
          async function loadLoginLogs() {
              logsListBody.innerHTML = '<tr><td colspan="3">Loading...</td></tr>';
              try {
                  const response = await fetch('/api/logs', { headers: { 'Authorization': \`Bearer \${authToken}\` } });
                  if (response.ok) { 
                      const logs = await response.json(); 
                      displayLoginLogs(logs); 
                  } else { 
                      logsListBody.innerHTML = '<tr><td colspan="3" class="error">Failed to load logs.</td></tr>'; 
                  }
              } catch (error) { 
                  logsListBody.innerHTML = '<tr><td colspan="3" class="error">Network error loading logs.</td></tr>'; 
              }
          }
          
          function displayLoginLogs(logs) {
              logsListBody.innerHTML = '';
              if (!logs || logs.length === 0) {
                  logsListBody.innerHTML = '<tr><td colspan="3">No login history found.</td></tr>'; return;
              }
              for (const log of logs) {
                  const row = logsListBody.insertRow();
                  const statusClass = log.status === 'success' ? 'log-status-success' : 'log-status-failure';
                  const formattedDate = new Date(log.timestamp).toLocaleString();
                  row.innerHTML = \`<td>\${formattedDate}</td><td>\${escapeHTML(log.ip)}</td><td><span class="\${statusClass}">\${escapeHTML(log.status)}</span></td>\`;
              }
          }
          
          // --- Backup (Export / Import) ---
          async function exportBackup() {
              try {
                  const response = await fetch('/api/credentials', { headers: { 'Authorization': \`Bearer \${authToken}\` } });
                  if (!response.ok) { showMessage('Failed to load credentials for export', 'error'); return; }
                  const creds = await response.json();
                  const out = [];
                  for (const c of creds) {
                      if (!c.username || !c.password) continue;
                      const username = await decryptData(c.username, encryptionKey);
                      const password = await decryptData(c.password, encryptionKey);
                      out.push({ service: c.service, group: c.group || '未分组', username, password });
                  }
                  const blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  const date = new Date().toISOString().slice(0, 10);
                  a.href = url; a.download = \`safepass-backup-\${date}.json\`;
                  document.body.appendChild(a); a.click(); a.remove();
                  URL.revokeObjectURL(url);
                  showMessage(\`Exported \${out.length} credential(s)\`, 'success');
              } catch (e) {
                  showMessage('Export failed: ' + e.message, 'error');
              }
          }
          function triggerImport() { importFile.click(); }
          async function importBackup(file) {
              try {
                  const text = await file.text();
                  const data = JSON.parse(text);
                  if (!Array.isArray(data)) throw new Error('Invalid backup file');
                  let count = 0;
                  for (const entry of data) {
                      if (!entry || !entry.service || entry.username === undefined || entry.password === undefined) continue;
                      const encUser = await encryptData(String(entry.username), encryptionKey);
                      const encPass = await encryptData(String(entry.password), encryptionKey);
                      const resp = await fetch('/api/credentials', {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${authToken}\` },
                          body: JSON.stringify({ service: entry.service, username: encUser, password: encPass, group: entry.group || '未分组' })
                      });
                      if (resp.ok) { count++; allCredentials.push(await resp.json()); }
                  }
                  showMessage(\`Imported \${count} credential(s)\`, 'success');
                  await renderCredentials();
              } catch (e) {
                  showMessage('Import failed: ' + e.message, 'error');
              }
          }

          // --- Utility and Event Listeners ---
          function showMessage(text, type) {
              saveMessage.textContent = text; saveMessage.className = type;
              setTimeout(() => { saveMessage.textContent = ''; saveMessage.className = ''; }, 3000);
          }
          function escapeHTML(str) {
            if (typeof str !== 'string') return '';
            return str.replace(/[&<>"']/g, match => ({'&': '&amp;','<': '&lt;','>': '&gt;','"': '&quot;',"'": '&#39;'}[match]));
          }
          loginBtn.addEventListener('click', login);
          passwordInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') login(); });
          logoutBtn.addEventListener('click', logout);
          saveBtn.addEventListener('click', saveOrUpdateCredential);
          cancelUpdateBtn.addEventListener('click', cancelUpdate);
          window.startUpdate = startUpdate; window.deleteCredential = deleteCredential;
          exportBtn.addEventListener('click', exportBackup);
          importBtn.addEventListener('click', triggerImport);
          importFile.addEventListener('change', (e) => {
              const file = e.target.files[0];
              if (file) importBackup(file);
              e.target.value = '';
          });
          groupSelect.addEventListener('change', () => { currentGroupMode = groupSelect.value; renderCredentials(); });
          sortSelect.addEventListener('change', () => { currentSort = sortSelect.value; renderCredentials(); });

          // --- Manage Groups (color & order) ---
          const manageGroupsBtn = $('manage-groups-btn'), groupsModal = $('groups-modal');
          const groupsEditorList = $('groups-editor-list'), groupsSaveBtn = $('groups-save-btn'), groupsCancelBtn = $('groups-cancel-btn');
          let editingGroups = [];
          function openGroupsEditor() {
              const names = new Set();
              (allCredentials || []).forEach(c => names.add(c.group || '未分组'));
              Object.keys(groupsMeta).forEach(n => names.add(n));
              editingGroups = orderedGroups([...names]).map(n => ({
                  name: n, color: groupColor(n), sort_order: groupOrder(n) === Number.MAX_SAFE_INTEGER ? 9999 : groupOrder(n)
              }));
              renderGroupsEditorList();
              groupsModal.classList.remove('hidden');
          }
          function renderGroupsEditorList() {
              groupsEditorList.innerHTML = '';
              editingGroups.forEach((g, i) => {
                  const row = document.createElement('div');
                  row.className = 'ge-row';
                  row.innerHTML = \`
                      <input type="color" class="ge-color" value="\${g.color}">
                      <span class="ge-name">\${escapeHTML(g.name)}</span>
                      <button class="ge-up" \${i === 0 ? 'disabled' : ''} title="Move up">&#9650;</button>
                      <button class="ge-down" \${i === editingGroups.length - 1 ? 'disabled' : ''} title="Move down">&#9660;</button>
                  \`;
                  row.querySelector('.ge-color').addEventListener('input', e => { g.color = e.target.value; });
                  row.querySelector('.ge-up').addEventListener('click', () => moveGroup(i, -1));
                  row.querySelector('.ge-down').addEventListener('click', () => moveGroup(i, 1));
                  groupsEditorList.appendChild(row);
              });
          }
          function moveGroup(i, dir) {
              const j = i + dir;
              if (j < 0 || j >= editingGroups.length) return;
              const t = editingGroups[i]; editingGroups[i] = editingGroups[j]; editingGroups[j] = t;
              renderGroupsEditorList();
          }
          async function saveGroups() {
              const payload = editingGroups.map((g, i) => ({ name: g.name, color: g.color, sort_order: i }));
              try {
                  const r = await fetch('/api/groups', {
                      method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${authToken}\` },
                      body: JSON.stringify(payload)
                  });
                  if (r.ok) {
                      groupsMeta = {};
                      payload.forEach(g => { groupsMeta[g.name] = { color: g.color, sort_order: g.sort_order }; });
                      groupsModal.classList.add('hidden');
                      showMessage('Groups updated', 'success');
                      await renderCredentials();
                  } else {
                      const d = await r.json().catch(() => ({}));
                      showMessage(d.error || 'Failed to save groups', 'error');
                  }
              } catch (e) { showMessage('Network error saving groups', 'error'); }
          }
          function cancelGroups() { groupsModal.classList.add('hidden'); }
          manageGroupsBtn.addEventListener('click', openGroupsEditor);
          groupsSaveBtn.addEventListener('click', saveGroups);
          groupsCancelBtn.addEventListener('click', cancelGroups);
        </script>
      </body>
      </html>
    `, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
  });
}

// --- 后端 API 代码 ---

async function handleApiRequest(request, env) {
  const url = new URL(request.url);

  if (url.pathname === '/api/auth' && request.method === 'POST') {
    return handleAuth(request, env);
  }

  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return jsonResponse({ error: 'Unauthorized: Missing token' }, 401);
  }

  const token = authHeader.substring(7);
  try {
    if (!(await verifyJwt(token, env.JWT_SECRET))) {
      return jsonResponse({ error: 'Invalid token' }, 401);
    }
  } catch (e) {
    return jsonResponse({ error: 'Token verification failed' }, 401);
  }

  if (url.pathname.startsWith('/api/credentials')) {
    const pathParts = url.pathname.split('/');
    const id = pathParts[3]; 

    switch (request.method) {
      case 'GET':
        return handleGetCredentials(request, env);
      case 'POST':
        return handlePostCredential(request, env);
      case 'PUT':
        if (id) return handleUpdateCredential(request, env, id);
        return jsonResponse({ error: 'Missing credential ID for PUT' }, 400);
      case 'DELETE':
        if (id) return handleDeleteCredential(request, env, id);
        return jsonResponse({ error: 'Missing credential ID for DELETE' }, 400);
      default:
        break;
    }
  }

  if (url.pathname === '/api/logs' && request.method === 'GET') {
      return handleGetLogs(request, env);
  }

  if (url.pathname === '/api/groups' && request.method === 'GET') {
      return handleGetGroups(request, env);
  }
  if (url.pathname === '/api/groups' && request.method === 'PUT') {
      return handlePutGroups(request, env);
  }

  return jsonResponse({ error: `API endpoint not found for ${request.method} ${url.pathname}` }, 404);
}

async function handleAuth(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'Unknown';
  try {
    const body = await request.json();
    if (body && body.password === env.ACCESS_PASSWORD) {
      await logLoginAttempt(env, { ip, timestamp: Date.now(), status: 'success' });
      const salt = env.SALT || 'default-credential-storage-salt';
      const token = await createJwt({ authorized: true }, env.JWT_SECRET);
      return jsonResponse({ token, salt });
    } else {
      await logLoginAttempt(env, { ip, timestamp: Date.now(), status: 'failure' });
      return jsonResponse({ error: 'Invalid password' }, 401);
    }
  } catch (e) {
    await logLoginAttempt(env, { ip, timestamp: Date.now(), status: 'failure' });
    return jsonResponse({ error: 'Invalid request body' }, 400);
  }
}

// 数据库行 -> 前端记录（密文以 JSON 字符串存储，需解析回对象）
function rowToCredential(row) {
  return {
    id: row.id,
    service: row.service,
    username: JSON.parse(row.username),
    password: JSON.parse(row.password),
    group: row.grp,
    createdAt: row.created_at,
  };
}

async function handleGetCredentials(request, env) {
  const { results } = await env.DB.prepare(
    'SELECT id, service, username, password, grp, created_at FROM credentials ORDER BY created_at DESC, id'
  ).all();
  return jsonResponse((results || []).map(rowToCredential));
}

async function handlePostCredential(request, env) {
  try {
    const { service, username, password, group } = await request.json();
    if (!service || !username || !password) return jsonResponse({ error: 'Missing required fields' }, 400);
    const id = crypto.randomUUID();
    const grp = group || '未分组';
    const createdAt = Date.now();
    await env.DB.prepare(
      'INSERT INTO credentials (id, service, username, password, grp, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(id, service, JSON.stringify(username), JSON.stringify(password), grp, createdAt).run();
    // 返回完整记录，便于前端乐观更新（无需重新全量拉取）
    return jsonResponse({ id, service, username, password, group: grp, createdAt }, 201);
  } catch (e) {
    return jsonResponse({ error: 'Failed to process request', detail: e.message }, 500);
  }
}

async function handleUpdateCredential(request, env, id) {
  try {
    const { service, username, password, group } = await request.json();
    if (!service || !username || !password) return jsonResponse({ error: 'Missing required fields' }, 400);
    const existing = await env.DB.prepare('SELECT created_at FROM credentials WHERE id = ?').bind(id).first();
    if (!existing) return jsonResponse({ error: 'Credential not found' }, 404);
    const grp = group || '未分组';
    await env.DB.prepare(
      'UPDATE credentials SET service = ?, username = ?, password = ?, grp = ? WHERE id = ?'
    ).bind(service, JSON.stringify(username), JSON.stringify(password), grp, id).run();
    return jsonResponse({ id, service, username, password, group: grp, createdAt: existing.created_at });
  } catch (e) {
    return jsonResponse({ error: 'Failed to process request', detail: e.message }, 500);
  }
}

async function handleDeleteCredential(request, env, id) {
  await env.DB.prepare('DELETE FROM credentials WHERE id = ?').bind(id).run();
  return new Response(null, { status: 204 });
}

async function handleGetLogs(request, env) {
  const { results } = await env.DB.prepare(
    'SELECT ip, ts, status FROM login_logs ORDER BY id DESC LIMIT 10'
  ).all();
  const logs = (results || []).map(r => ({ ip: r.ip, timestamp: r.ts, status: r.status }));
  return jsonResponse(logs);
}

async function handleGetGroups(request, env) {
  const { results } = await env.DB.prepare(
    'SELECT name, color, sort_order FROM groups_meta ORDER BY sort_order ASC, name ASC'
  ).all();
  return jsonResponse(results || []);
}

async function handlePutGroups(request, env) {
  try {
    const list = await request.json();
    if (!Array.isArray(list)) return jsonResponse({ error: 'Invalid body' }, 400);
    const stmts = [
      env.DB.prepare('DELETE FROM groups_meta'),
      ...list.map((g, i) => env.DB.prepare(
        'INSERT OR REPLACE INTO groups_meta (name, color, sort_order) VALUES (?, ?, ?)'
      ).bind(g.name, g.color, typeof g.sort_order === 'number' ? g.sort_order : i))
    ];
    await env.DB.batch(stmts);
    return jsonResponse({ ok: true });
  } catch (e) {
    return jsonResponse({ error: 'Failed to save groups', detail: e.message }, 500);
  }
}

async function logLoginAttempt(env, logEntry) {
  try {
    await env.DB.prepare(
      'INSERT INTO login_logs (ip, ts, status) VALUES (?, ?, ?)'
    ).bind(logEntry.ip, logEntry.timestamp, logEntry.status).run();
  } catch (e) {
    console.error('Failed to log login attempt:', e);
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' }});
}

function btoaUrl(str) { return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }
function atobUrl(str) { return atob(str.replace(/-/g, '+').replace(/_/g, '/')); }
async function createJwt(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = btoaUrl(JSON.stringify(header));
  const encodedPayload = btoaUrl(JSON.stringify(payload));
  const data = `${encodedHeader}.${encodedPayload}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const encodedSignature = btoaUrl(String.fromCharCode(...new Uint8Array(signature)));
  return `${data}.${encodedSignature}`;
}
async function verifyJwt(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [header, payload, signature] = parts;
  const data = `${header}.${payload}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  let signatureBytes;
  try {
    signatureBytes = new Uint8Array(atobUrl(signature).split('').map(c => c.charCodeAt(0)));
  } catch (e) { return false; }
  return await crypto.subtle.verify('HMAC', key, signatureBytes, new TextEncoder().encode(data));
}
