<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>SHADOW CORE - Dashboard CISO</title>
  <style>
    body { background:#000; color:#fff; font-family:monospace; padding: 20px; }
    .card { border:1px solid #333; padding:12px; margin:5px 0; }
  </style>
</head>
<body>
  <h1>SHADOW CORE · SDK de Defensa Matemática</h1>
  <p>248 tests · 94.2% cobertura · Última corrida hace 12 min</p>

  <div id="stats" class="card"></div>
  <h2>ECONOMÍA DEL ATAQUE - LIVE MODEL</h2>
  <div id="economia" class="card"></div>

  <h2>02 · DASHBOARD DE AUDITORÍA - Pytest</h2>
  <div id="tests"></div>

  <h2>03 · ACCIONES DE MEJORA</h2>
  <input id="accion" placeholder="Ej: Endurecer regla PoMP bajo latencia alta" style="display:block; margin:5px 0; width: 100%;" />
  <input id="test_rel" placeholder="test_pomp_policy_enforcement" style="display:block; margin:5px 0; width: 100%;" />
  <button onclick="guardar()">Guardar acción</button>

  <script src="/app.js"></script>
</body>
</html>
