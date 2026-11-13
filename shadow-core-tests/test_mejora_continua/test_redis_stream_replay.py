async function load() {
  const d = await fetch('/api/dashboard').then(r => r.json());
  document.getElementById('stats').innerHTML = `
    Tests: ${d.pasados}/${d.total} PASSED · Cobertura: ${d.cobertura}% ·
    Tiempo medio: ${d.tiempo_medio}s · Merkle Root: ${d.merkle_root}
  `;
  document.getElementById('tests').innerHTML = d.tests.map(t => `
    <div class="card">
      <b>${t.id} ${t.name}</b> · ${t.area} · ${t.status} · ${t.time}s · sha256:${t.sha}
    </div>
  `).join('');

  const e = await fetch('/api/economia-ataque').then(r => r.json());
  document.getElementById('economia').innerHTML = `
    Shadow Core: $${e.shadow_core} vs RootBeer: $${e.rootbeer} ·
    ${e.multiplicador}x más caro bypassear
  `;
}

async function guardar() {
  await fetch('/api/accion-mejora', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      accion: document.getElementById('accion').value,
      test: document.getElementById('test_rel').value
    })
  });
  alert('Acción guardada para mejora continua');
}

load();
