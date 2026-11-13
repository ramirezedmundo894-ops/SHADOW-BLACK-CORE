const $ = (id) => document.getElementById(id);
let accessToken = '';
async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  const response = await fetch(path, {...options, headers});
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || `HTTP ${response.status}`);
  return body;
}
async function refreshAudit() {
  const data = await request('/api/evidence?limit=100');
  $('audit').textContent = JSON.stringify(data.entries, null, 2);
}
$('decision-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    frida_detected: form.has('frida_detected'),
    root_integrity_failed: form.has('root_integrity_failed'),
    jwt_validation_failures: Number(form.get('jwt_validation_failures')),
    grpc_tls_verified: form.has('grpc_tls_verified')
  };
  try {
    $('decision').textContent = JSON.stringify(await request('/api/decision', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
    }), null, 2);
    await refreshAudit();
  } catch (error) { $('decision').textContent = error.message; }
});
$('refresh').addEventListener('click', () => refreshAudit().catch((e) => $('audit').textContent = e.message));
$('verify').addEventListener('click', async () => {
  try { $('audit').textContent = JSON.stringify(await request('/api/evidence/verify'), null, 2); }
  catch (error) { $('audit').textContent = error.message; }
});
$('action-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const form = new FormData(event.currentTarget);
  try {
    const result = await request('/api/improvement-actions', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action: form.get('action'), test: form.get('test')})
    });
    $('action-result').textContent = JSON.stringify(result, null, 2);
    event.currentTarget.reset(); await refreshAudit();
  } catch (error) { $('action-result').textContent = error.message; }
});
$('use-token').addEventListener('click', () => {
  accessToken = $('access-token-input').value.trim();
  $('access-token-input').value = '';
  refreshAudit().catch((error) => $('audit').textContent = error.message);
});
$('clear-token').addEventListener('click', () => {
  accessToken = '';
  $('audit').textContent = 'Token olvidado; ingresa un access JWT para usar el panel.';
});
$('audit').textContent = 'Ingresa un access JWT para consultar evidencia.';
