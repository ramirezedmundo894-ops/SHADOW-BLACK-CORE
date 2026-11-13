async function load() {
  const [dashboardResponse, economicsResponse] = await Promise.all([
    fetch('/api/dashboard'), fetch('/api/economia-ataque')
  ]);
  if (!dashboardResponse.ok || !economicsResponse.ok) throw new Error('Dashboard API request failed');
  const data = await dashboardResponse.json();
  const economics = await economicsResponse.json();
  document.getElementById('stats').textContent = `Estado: ${data.status} · Tests registrados: ${data.total} · Cobertura: no configurada`;
  document.getElementById('tests').textContent = data.tests.length ? JSON.stringify(data.tests) : 'Sin resultados reales configurados.';
  document.getElementById('economia').textContent = economics.message;
}

document.getElementById('save').addEventListener('click', async () => {
  const response = await fetch('/api/accion-mejora', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: document.getElementById('accion').value, test: document.getElementById('test_rel').value})
  });
  const result = await response.json();
  alert(result.status === 'received_demo_only' ? 'Recibido en modo demo; no se guardó.' : 'No se pudo enviar.');
});

load().catch(error => { document.getElementById('stats').textContent = error.message; });
