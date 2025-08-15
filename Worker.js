export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/') return handleStaticHTML(request);
    if (url.pathname.startsWith('/api/')) return handleApiRequest(request, env);
    return new Response('Not Found', { status: 404 });
  }
};

/**
 * 提供静态HTML页面 (已优化前端即时显示逻辑)
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
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f5f5f5; }
          .container { background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .hidden { display: none; }
          input, button { padding: 10px; margin: 5px 0; width: 100%; box-sizing: border-box; }
          button { background-color: #4CAF50; color: white; border: none; cursor: pointer; }
          button:hover { background-color: #45a049; }
          .error { color: red; }
          .success { color: green; }
          .logout-btn { background-color: #f44336; width: auto; float: right; }
          .logout-btn:hover { background-color: #da190b; }
          .header { overflow: hidden; padding-bottom: 10px; border-bottom: 1px solid #eee; margin-bottom: 20px; }
          #credentials-container, #logs-container { overflow-x: auto; }
          .data-table { width: 100%; border-collapse: collapse; margin-top: 15px; word-break: break-all; }
          .data-table th, .data-table td { border: 1px solid #ddd; padding: 12px; text-align: left; vertical-align: middle; }
          .data-table th { background-color: #f2f2f2; font-weight: bold; }
          .data-table tr:nth-child(even) { background-color: #f9f9f9; }
          .data-table tr:hover { background-color: #f1f1f1; }
          .action-btn { padding: 5px 10px; width: auto; font-size: 12px; border-radius: 4px; margin-right: 5px; }
          .update-btn { background-color: #2196F3; }
          .update-btn:hover { background-color: #0b7dda; }
          .delete-btn { background-color: #f44336; }
          .delete-btn:hover { background-color: #da190b; }
          .form-buttons { display: flex; gap: 10px; }
          #cancel-update-btn { background-color: #757575; }
          #cancel-update-btn:hover { background-color: #616161; }
          .log-status-success { color: #4CAF50; font-weight: bold; }
          .log-status-failure { color: #f44336; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
            <div id="login-section">
                <h2>Secure Credential Storage</h2>
                <p>Enter password to access stored credentials:</p>
                <input type="password" id="password" placeholder="Enter your password">
                <button id="login-btn">Login</button>
                <div id="login-error" class="error"></div>
            </div>
            <div id="app-section" class="hidden">
                <div class="header">
                    <h2>Stored Credentials</h2>
                    <button id="logout-btn" class="logout-btn">Logout</button>
                </div>
                <h3 id="form-title">Add New Credential</h3>
                <input type="hidden" id="credential-id">
                <input type="text" id="service-name" placeholder="Service Name (e.g., Gmail)">
                <input type="text" id="username" placeholder="Username">
                <input type="password" id="credential-password" placeholder="Password">
                <div class="form-buttons">
                    <button id="save-btn">Save Credential</button>
                    <button id="cancel-update-btn" class="hidden">Cancel Update</button>
                </div>
                <div id="save-message"></div>
                <h3>Saved Credentials</h3>
                <div id="credentials-container">
                    <table id="credentials-table" class="data-table">
                        <thead><tr><th>Service</th><th>Username</th><th>Password</th><th>Actions</th></tr></thead>
                        <tbody id="credentials-list-body"></tbody>
                    </table>
                    <p id="no-credentials-message" class="hidden">No credentials saved yet.</p>
                </div>
                <h3 style="margin-top: 40px;">Recent Login History</h3>
                <div id="logs-container">
                    <table id="logs-table" class="data-table">
                        <thead><tr><th>Time</th><th>IP Address</th><th>Status</th></tr></thead>
                        <tbody id="logs-list-body"></tbody>
                    </table>
                </div>
            </div>
        </div>
        <script>
          const $ = id => document.getElementById(id);
          const loginSection = $('login-section'), appSection = $('app-section'), passwordInput = $('password');
          const loginBtn = $('login-btn'), loginError = $('login-error'), logoutBtn = $('logout-btn');
          const serviceNameInput = $('service-name'), usernameInput = $('username'), credentialPasswordInput = $('credential-password');
          const saveBtn = $('save-btn'), saveMessage = $('save-message'), credentialIdInput = $('credential-id');
          const formTitle = $('form-title'), cancelUpdateBtn = $('cancel-update-btn');
          const credentialsTable = $('credentials-table'), credentialsListBody = $('credentials-list-body'), noCredentialsMessage = $('no-credentials-message');
          const logsListBody = $('logs-list-body');
          let authToken = null, encryptionKey = null, currentEditingId = null;

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
          
          // --- Credential Management (Logic updated for instant display) ---
          async function saveOrUpdateCredential() {
              const service = serviceNameInput.value.trim();
              const username = usernameInput.value.trim();
              const password = credentialPasswordInput.value;
              if (!service || !username || !password) { showMessage('Please fill all fields', 'error'); return; }
              try {
                  const encryptedUsername = await encryptData(username, encryptionKey);
                  const encryptedPassword = await encryptData(password, encryptionKey);
                  const isUpdating = !!currentEditingId;
                  const url = isUpdating ? \`/api/credentials/\${currentEditingId}\` : '/api/credentials';
                  const method = isUpdating ? 'PUT' : 'POST';
                  const response = await fetch(url, { method, headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${authToken}\` }, body: JSON.stringify({ service, username: encryptedUsername, password: encryptedPassword }) });
                  
                  if (response.ok) {
                      showMessage(\`Credential \${isUpdating ? 'updated' : 'saved'} successfully!\`, 'success');
                      
                      // *** OPTIMIZATION LOGIC START ***
                      if (isUpdating) {
                          // For updates, a full reload is reliable because the key list hasn't changed.
                          loadCredentials();
                      } else {
                          // For NEW credentials, we optimistically update the UI to avoid KV list delay.
                          const newCredData = await response.json(); // { id, service } from backend
                          addCredentialToTable({ id: newCredData.id, service, username, password });
                      }
                      // *** OPTIMIZATION LOGIC END ***

                      cancelUpdate();
                  } else { 
                      const data = await response.json();
                      showMessage(data.error || 'Failed to save credential', 'error');
                  }
              } catch (error) { 
                  showMessage('Network error during save. Please try again.', 'error'); 
              }
          }
          
          async function loadCredentials() {
              credentialsListBody.innerHTML = '<tr><td colspan="4">Loading...</td></tr>';
              noCredentialsMessage.classList.add('hidden'); credentialsTable.classList.remove('hidden');
              try {
                  const response = await fetch('/api/credentials', { headers: { 'Authorization': \`Bearer \${authToken}\` } });
                  if (response.ok) { 
                      const credentials = await response.json(); 
                      displayCredentials(credentials); 
                  } else { 
                      const data = await response.json(); 
                      showMessage(data.error || 'Failed to load credentials', 'error'); 
                  }
              } catch (error) { 
                  showMessage('Network error during load. Please try again.', 'error'); 
              }
          }

          function addCredentialToTable(cred, decrypted = true) {
              const row = credentialsListBody.insertRow(0); // Add to the top of the table
              const escapedService = escapeHTML(cred.service);
              const escapedUsername = escapeHTML(decrypted ? cred.username : 'decrypting...');
              const escapedPassword = escapeHTML(decrypted ? cred.password : 'decrypting...');

              row.innerHTML = \`
                  <td>\${escapedService}</td><td>\${escapedUsername}</td><td>\${escapedPassword}</td>
                  <td>
                      <button class="action-btn update-btn" onclick="startUpdate('\${cred.id}', '\${escapedService}', '\${escapedUsername}', '\${escapedPassword}')">Update</button>
                      <button class="action-btn delete-btn" onclick="deleteCredential('\${cred.id}')">Delete</button>
                  </td>
              \`;

              // If this is the first item, hide the "no credentials" message.
              noCredentialsMessage.classList.add('hidden');
              credentialsTable.classList.remove('hidden');
          }

          async function displayCredentials(credentials) {
              credentialsListBody.innerHTML = '';
              if (!credentials || credentials.length === 0) {
                  credentialsTable.classList.add('hidden'); noCredentialsMessage.classList.remove('hidden'); return;
              }
              credentialsTable.classList.remove('hidden'); noCredentialsMessage.classList.add('hidden');
              for (const cred of credentials) {
                  const row = credentialsListBody.insertRow();
                  try {
                      if (!cred.username || !cred.password) {
                          row.innerHTML = \`<td colspan="4" class="error">Incomplete data for \${escapeHTML(cred.service)}</td>\`; continue;
                      };
                      const username = await decryptData(cred.username, encryptionKey);
                      const password = await decryptData(cred.password, encryptionKey);
                      const escapedService = escapeHTML(cred.service);
                      const escapedUsername = escapeHTML(username);
                      const escapedPassword = escapeHTML(password);
                      row.innerHTML = \`
                          <td>\${escapedService}</td><td>\${escapedUsername}</td><td>\${escapedPassword}</td>
                          <td>
                              <button class="action-btn update-btn" onclick="startUpdate('\${cred.id}', '\${escapedService}', '\${escapedUsername}', '\${escapedPassword}')">Update</button>
                              <button class="action-btn delete-btn" onclick="deleteCredential('\${cred.id}')">Delete</button>
                          </td>
                      \`;
                  } catch (error) {
                      row.innerHTML = \`<td>\${escapeHTML(cred.service)}</td><td colspan="3" class="error">Error decrypting data.</td>\`;
                  }
              }
          }
          
          async function deleteCredential(id) {
              if (!confirm('Are you sure you want to delete this credential?')) return;
              try {
                  const response = await fetch(\`/api/credentials/\${id}\`, { method: 'DELETE', headers: { 'Authorization': \`Bearer \${authToken}\` } });
                  if (response.ok) { 
                      showMessage('Credential deleted successfully!', 'success'); 
                      loadCredentials(); // Full reload is fine after delete.
                  } else { 
                      const data = await response.json(); 
                      showMessage(data.error || 'Failed to delete credential', 'error'); 
                  }
              } catch (error) { 
                  showMessage('Network error during delete. Please try again.', 'error'); 
              }
          }
          
          function startUpdate(id, service, username, password) {
              currentEditingId = id;
              credentialIdInput.value = id;
              serviceNameInput.value = service;
              usernameInput.value = username;
              credentialPasswordInput.value = password;
              formTitle.textContent = 'Update Credential';
              saveBtn.textContent = 'Confirm Update';
              cancelUpdateBtn.classList.remove('hidden');
              window.scrollTo({ top: 0, behavior: 'smooth' });
          }
          
          function cancelUpdate() {
              currentEditingId = null;
              credentialIdInput.value = ''; serviceNameInput.value = ''; usernameInput.value = ''; credentialPasswordInput.value = '';
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
        </script>
      </body>
      </html>
    `, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
  });
}

// --- 后端 API 代码 (无需修改) ---

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

async function handleGetCredentials(request, env) {
  const { keys } = await env.CREDENTIALS.list();
  const credentials = await Promise.all(
    keys.map(async (key) => {
      const value = await env.CREDENTIALS.get(key.name, 'json');
      return value ? { id: key.name, ...value } : null;
    })
  );
  return jsonResponse(credentials.filter(c => c !== null));
}

async function handlePostCredential(request, env) {
  try {
    const { service, username, password } = await request.json();
    if (!service || !username || !password) return jsonResponse({ error: 'Missing required fields' }, 400);
    const id = crypto.randomUUID();
    await env.CREDENTIALS.put(id, JSON.stringify({ service, username, password }));
    return jsonResponse({ id, service }, 201);
  } catch (e) {
    return jsonResponse({ error: 'Failed to process request' }, 500);
  }
}

async function handleUpdateCredential(request, env, id) {
  try {
    const { service, username, password } = await request.json();
    if (!service || !username || !password) return jsonResponse({ error: 'Missing required fields' }, 400);
    const existing = await env.CREDENTIALS.get(id);
    if (!existing) return jsonResponse({ error: 'Credential not found' }, 404);
    await env.CREDENTIALS.put(id, JSON.stringify({ service, username, password }));
    return jsonResponse({ id, service });
  } catch (e) {
    return jsonResponse({ error: 'Failed to process request' }, 500);
  }
}

async function handleDeleteCredential(request, env, id) {
  await env.CREDENTIALS.delete(id);
  return new Response(null, { status: 204 });
}

async function handleGetLogs(request, env) {
    const logs = await env.LOG_KV.get('LOGIN_LOGS', 'json') || [];
    return jsonResponse(logs);
}

async function logLoginAttempt(env, logEntry) {
    try {
        const logsJson = await env.LOG_KV.get('LOGIN_LOGS') || '[]';
        const logs = JSON.parse(logsJson);
        logs.unshift(logEntry);
        const updatedLogs = logs.slice(0, 5);
        await env.LOG_KV.put('LOGIN_LOGS', JSON.stringify(updatedLogs));
    } catch (e) {
        console.error("Failed to log login attempt:", e);
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