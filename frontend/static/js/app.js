

const API = 'http://localhost:5000/api';
let sessionToken = null;
let pendingToken = null;
let currentUsername = null;

// ── INICIALIZACIÓN ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // logica de tabs
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
    });
  });

  // entrada con Enter
  document.getElementById('login-password').addEventListener('keydown', e => {
    if (e.key === 'Enter') loginStep1();
  });

  document.getElementById('totp-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') loginStep2();
  });
});

// login paso 1: validar credenciales
async function loginStep1() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  
  setError('login-error-1', '');

  if (!username || !password) {
    setError('login-error-1', '⚠ Completa usuario y contraseña');
    return;
  }

  showLoading('login-error-1', 'Verificando credenciales...');

  try {
    const res = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    hideLoading('login-error-1');

    if (data.ok) {
      pendingToken = data.pending_token;
      currentUsername = username;
      // Transición al paso 2FA
      document.getElementById('step-credentials').classList.remove('active');
      document.getElementById('step-2fa').classList.add('active');
      document.getElementById('totp-input').focus();
      toast('✓ Credenciales válidas — Ingresa tu código 2FA', 'info');
    } else {
      setError('login-error-1', `✗ ${data.error}`);
      shake('#step-credentials');
    }
  } catch (err) {
    hideLoading('login-error-1');
    setError('login-error-1', '✗ Error de conexión con el servidor');
  }
}

// autenticación paso 2: validar código 2FA
async function loginStep2() {
  const code = document.getElementById('totp-input').value.trim();
  setError('login-error-2', '');

  if (code.length !== 6) {
    setError('login-error-2', '⚠ El código debe tener 6 dígitos');
    return;
  }

  showLoading('login-error-2', 'Verificando código 2FA...');

  try {
    const res = await fetch(`${API}/auth/verify-2fa`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pending_token: pendingToken, totp_code: code })
    });
    const data = await res.json();

    hideLoading('login-error-2');

    if (data.ok) {
      sessionToken = data.session_token;
      currentUsername = data.username;
      toast(`✓ Bienvenido, ${data.name}`, 'success');
      showDashboard(data.username, data.name);
    } else {
      setError('login-error-2', `✗ ${data.error}`);
      document.getElementById('totp-input').value = '';
      shake('#step-2fa');
    }
  } catch (err) {
    hideLoading('login-error-2');
    setError('login-error-2', '✗ Error de conexión con el servidor');
  }
}

function backToStep1() {
  pendingToken = null;
  document.getElementById('step-2fa').classList.remove('active');
  document.getElementById('step-credentials').classList.add('active');
  document.getElementById('totp-input').value = '';
  setError('login-error-2', '');
}

// ── REGISTRO ──────────────────────────────────────────────────────
async function register() {
  const name = document.getElementById('reg-name').value.trim();
  const username = document.getElementById('reg-username').value.trim();
  const password = document.getElementById('reg-password').value;

  setError('reg-error', '');

  if (!name || !username || !password) {
    setError('reg-error', '⚠ Completa todos los campos');
    return;
  }

  try {
    const res = await fetch(`${API}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, name })
    });
    const data = await res.json();

    if (data.ok) {
      document.getElementById('qr-image').src = `data:image/png;base64,${data.qr_code}`;
      document.getElementById('totp-secret-display').textContent = data.totp_secret;
      document.getElementById('qr-section').classList.remove('hidden');
      toast('✓ Usuario registrado exitosamente', 'success');
    } else {
      setError('reg-error', `✗ ${data.error}`);
    }
  } catch (err) {
    setError('reg-error', '✗ Error de conexión');
  }
}

function switchToLogin() {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="login"]').classList.add('active');
  document.getElementById('tab-login').classList.add('active');
  document.getElementById('qr-section').classList.add('hidden');
}

// ── PARA DEMO: obtener código TOTP actual ─────────────────────────
async function fillCurrentTOTP() {
  // Llamar a un endpoint especial para demo que genera el código actual
  try {
    const res = await fetch(`${API}/auth/demo-totp?username=${currentUsername}`);
    const data = await res.json();
    if (data.code) {
      document.getElementById('totp-input').value = data.code;
      toast(`Código TOTP: ${data.code} (válido ~30s)`, 'info');
    }
  } catch (err) {
    toast('No disponible en producción', 'error');
  }
}

// tablero principal
function showDashboard(username, name) {
  document.getElementById('screen-login').classList.remove('active');
  document.getElementById('screen-dashboard').classList.add('active');
  document.getElementById('header-username').textContent = name || username;
  document.getElementById('header-avatar').textContent = (name || username)[0].toUpperCase();
}

function logout() {
  sessionToken = null;
  pendingToken = null;
  currentUsername = null;
  document.getElementById('screen-dashboard').classList.remove('active');
  document.getElementById('screen-login').classList.add('active');
  // resetemaos el login para que no quede con datos anteriores
  document.getElementById('login-username').value = '';
  document.getElementById('login-password').value = '';
  document.getElementById('step-credentials').classList.add('active');
  document.getElementById('step-2fa').classList.remove('active');
  toast('Sesión cerrada', 'info');
}

function switchPanel(btn) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(btn.dataset.panel).classList.add('active');

  if (btn.dataset.panel === 'panel-log') loadMessageLog();
}

function toggleTamperField() {
  const checked = document.getElementById('tamper-toggle').checked;
  const field = document.getElementById('tamper-field');
  const original = document.getElementById('msg-content').value;
  
  if (checked) {
    field.classList.remove('hidden');
    document.getElementById('tamper-content').value = original + ' [MODIFICADO]';
  } else {
    field.classList.add('hidden');
  }
}


async function sendMessage() {
  const tamperedContent = document.getElementById('tamper-content').value.trim();
  const content = document.getElementById('msg-content').value.trim();
  const tamper = document.getElementById('tamper-toggle').checked;

  if (!content) {
    toast('⚠ Escribe un mensaje primero', 'error');
    return;
  }

  const resultEl = document.getElementById('msg-result');
  resultEl.innerHTML = `
    <div class="system-label sistema-b">SISTEMA B (Receptor)</div>
    <div class="loading"><div class="spinner"></div> Procesando y verificando...</div>
  `;

  try {
    const res = await fetch(`${API}/messages/send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`
      },
      body: JSON.stringify({ content, tamper, tampered_content: tamperedContent })
    });
    const data = await res.json();

    if (!data.ok) {
      resultEl.innerHTML = `<div class="error-msg visible">${data.error}</div>`;
      return;
    }

    const v = data.verification_result;
    const accepted = data.accepted;
    const signed = data.signed_message;

    resultEl.innerHTML = `
      <div class="system-label sistema-b">SISTEMA B (Receptor)</div>
      <div class="verify-result">
        <div class="verify-badge ${accepted ? 'accepted' : 'rejected'}">
          <span class="badge-icon">${accepted ? '✓' : '✗'}</span>
          <div>
            <div>${accepted ? 'MENSAJE ACEPTADO' : 'MENSAJE RECHAZADO'}</div>
            <div style="font-size:12px;font-weight:400;opacity:0.8;margin-top:2px">
              ${accepted ? 'Integridad verificada — HMAC coincide' : 'Integridad comprometida — HMAC no coincide'}
            </div>
          </div>
        </div>

        <div class="verify-detail">
          <h4>Detalles del Mensaje</h4>
          <div class="detail-row"><span class="lbl">ID:</span><span class="val hash">${signed.id}</span></div>
          <div class="detail-row"><span class="lbl">Timestamp:</span><span class="val">${signed.timestamp}</span></div>
          <div class="detail-row"><span class="lbl">Contenido:</span><span class="val">${signed.payload.content}</span></div>
          ${tamper ? `<div class="detail-row"><span class="lbl" style="color:var(--red)">⚠ Alterado:</span><span class="val mismatch">Sí — payload modificado post-firma</span></div>` : ''}
        </div>

        <div class="verify-detail">
          <h4>Verificación HMAC-SHA256</h4>
          <div class="detail-row"><span class="lbl">Recibida:</span><span class="val hash">${v.signature_received ? v.signature_received.substring(0,32) + '...' : 'N/A'}</span></div>
          <div class="detail-row"><span class="lbl">Esperada:</span><span class="val hash">${v.signature_expected ? v.signature_expected.substring(0,32) + '...' : 'N/A'}</span></div>
          <div class="detail-row"><span class="lbl">Resultado:</span><span class="val ${v.match ? 'match' : 'mismatch'}">${v.match ? '✓ COINCIDEN' : '✗ NO COINCIDEN'}</span></div>
        </div>
      </div>
    `;

    toast(accepted ? '✓ Mensaje aceptado por Sistema B' : '✗ Mensaje rechazado — integridad comprometida', accepted ? 'success' : 'error');
  } catch (err) {
    resultEl.innerHTML = `<div class="error-msg visible">Error de conexión</div>`;
  }
}


async function loadMessageLog() {
  const el = document.getElementById('message-log-table');
  el.innerHTML = `<div class="loading"><div class="spinner"></div> Cargando...</div>`;

  try {
    const res = await fetch(`${API}/messages/log`, {
      headers: { 'Authorization': `Bearer ${sessionToken}` }
    });
    const data = await res.json();

    if (!data.messages || data.messages.length === 0) {
      el.innerHTML = `<div class="empty-state">No hay mensajes registrados aún.</div>`;
      return;
    }

    const rows = data.messages.map(m => `
      <tr>
        <td style="font-size:11px;color:var(--text-muted)">${m.timestamp.split('T')[1].split('.')[0]}</td>
        <td>${m.from}</td>
        <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${m.original_content}</td>
        <td style="font-size:10px;color:var(--accent)">${m.hash_preview}</td>
        <td>${m.tampered ? '<span style="color:var(--red);font-size:11px">Sí</span>' : '<span style="color:var(--green);font-size:11px">No</span>'}</td>
        <td><span class="status-pill ${m.verification.valid ? 'ok' : 'fail'}">${m.verification.valid ? '✓ Aceptado' : '✗ Rechazado'}</span></td>
      </tr>
    `).join('');

    el.innerHTML = `
      <table class="log-table">
        <thead><tr>
          <th>Hora</th><th>Origen</th><th>Contenido</th><th>Hash</th><th>Alterado</th><th>Estado</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `;
  } catch (err) {
    el.innerHTML = `<div class="error-msg visible">Error cargando registro</div>`;
  }
}


async function testIntactMessage() {
  document.querySelector('[data-panel="panel-messages"]').click();
  document.getElementById('msg-content').value = 'Mensaje de prueba — escenario íntegro. Este mensaje NO debe ser alterado.';
  document.getElementById('tamper-toggle').checked = false;
  setTimeout(() => sendMessage(), 300);
}

async function testTamperedMessage() {
  document.querySelector('[data-panel="panel-messages"]').click();
  document.getElementById('msg-content').value = 'Mensaje de prueba — escenario de alteración. Este mensaje SERÁ modificado.';
  document.getElementById('tamper-toggle').checked = true;
  setTimeout(() => sendMessage(), 300);
}


function setError(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  if (msg) {
    el.textContent = msg;
    el.classList.add('visible');
    el.style.display = 'block';
  } else {
    el.classList.remove('visible');
    el.style.display = 'none';
  }
}

function showLoading(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = `<div class="loading"><div class="spinner"></div>${msg}</div>`;
  el.classList.remove('visible');
  el.style.display = 'block';
}

function hideLoading(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.display = 'none';
}

function toast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  container.appendChild(t);
  setTimeout(() => t.remove(), 3100);
}

function formatTOTP(input) {
  input.value = input.value.replace(/\D/g, '').substring(0, 6);
}

function shake(selector) {
  const el = document.querySelector(selector);
  if (!el) return;
  el.style.animation = 'shake 0.4s ease';
  setTimeout(() => el.style.animation = '', 400);
}


const style = document.createElement('style');
style.textContent = `@keyframes shake {
  0%,100%{transform:translateX(0)}
  20%{transform:translateX(-8px)}
  40%{transform:translateX(8px)}
  60%{transform:translateX(-5px)}
  80%{transform:translateX(5px)}
}`;
document.head.appendChild(style);