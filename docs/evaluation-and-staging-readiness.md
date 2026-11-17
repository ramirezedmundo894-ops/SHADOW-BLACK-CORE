# Evaluación offline y preparación para staging

Estado: plan de trabajo, no autorización para tratar datos ni prueba de un entorno staging. No se cargaron datos reales, no se emitieron certificados y no se desplegó ningún servicio.

Este plan cubre dos frentes independientes: definir una evaluación con una verdad de referencia útil y cerrar las brechas de transporte/red antes de cualquier staging.

## 1. Evaluación offline: objetivo propuesto y puertas pendientes

### Lo que el repositorio hace hoy

- `shadow_core.model_evaluation` evalúa filas JSONL con solo `label` (booleano) y `probability` (número entre 0 y 1). Calcula métricas de clasificación, Brier e intervalos Wilson; no valida autorización, etiquetado, representatividad ni independencia de las muestras.
- La API actual entrega señales y una decisión determinista (`risk_score`/`action`). No existe en este flujo una probabilidad de un modelo candidato que se pueda tratar automáticamente como `probability`. No convertir `risk_score` en probabilidad ni presentar la evaluación de las reglas deterministas como evaluación de un modelo.
- No hay corpus real autorizado en el repositorio. Los ejemplos sintéticos comprueban el evaluador, no eficacia.

### Las tres etiquetas elegidas: tres evaluaciones separadas

Tomo tu selección de las tres como tres objetivos, no como una sola etiqueta positiva. Son resultados distintos y ocurren en unidades distintas; no los mezclaría en un único `label=true` ni sumaría sus conteos.

1. **Transacción no autorizada confirmada** — unidad: oportunidad de decisión de una transacción. `label=true` solo con adjudicación independiente de que la transacción no fue autorizada; `false` solo tras confirmación suficiente de que sí fue autorizada dentro de una ventana fijada previamente.
2. **Toma de cuenta confirmada** — unidad: episodio de cuenta y periodo definidos. `true` requiere adjudicación independiente de toma de cuenta; `false` requiere evidencia suficiente de ausencia durante la ventana acordada. No convertir automáticamente cada transacción del episodio en un caso independiente.
3. **Abuso de API confirmado** — unidad: sesión/episodio o secuencia de solicitudes, según una definición de abuso escrita antes de evaluar. `true` requiere revisión independiente con evidencia autorizada; `false` requiere observación suficiente del ámbito y periodo definidos.

Para cada objetivo hace falta una fuente de verdad autorizada, reglas de adjudicación y una ventana de seguimiento propias. Los casos dudosos, disputados o incompletos quedan fuera como no adjudicados, no como `false`. Un mismo evento puede aparecer en más de una evaluación solo si satisface independientemente cada definición; hay que separar por entidad/episodio para evitar fuga entre particiones. No comparar métricas de estos objetivos como si compartieran población o unidad.

Las etiquetas no pueden derivarse del puntaje o de la decisión que se evalúa: `Frida`, root, FFT, JWT, la regla de política, el bloqueo del sistema o la propia detección de abuso no son por sí solos verdad de referencia para medir ese mismo sistema. El evaluador actual acepta un `label` booleano por fila, así que la forma compatible es preparar tres conjuntos/evaluaciones independientes. Además, la API actual no produce una probabilidad de candidato con semántica calibrada para ninguno de estos tres objetivos: no convertir `risk_score` en `probability`. Primero habrá que definir/implementar el candidato probabilístico y su correspondencia con cada etiqueta.

### Corpus y protocolo

1. Preferir un conjunto de primera parte autorizado, minimizado y adjudicado; antes de extraerlo, documentar quién autoriza, propósito, ámbito, periodo, retención y límites. Si no existe autorización clara, limitarse a datos sintéticos.
2. Mantener los identificadores y la clave de agrupación fuera del JSONL analítico. Evitar que una misma persona, dispositivo, incidente o secuencia aparezca a ambos lados de la partición. Bloquear el holdout antes de ajustar el candidato o umbral.
3. Probar que el candidato produce una probabilidad con semántica explícita para esa etiqueta. Guardar solo `{label, probability}` por fila; la traza de procedencia y el manifiesto permanecen en almacenamiento protegido.
4. Una segunda persona revisa definición, adjudicación, partición y manifiesto antes del cálculo. Reportar tamaño, balance, incertidumbres y limitaciones; no tomar cambios de política o despliegue como consecuencia automática del informe.
5. CSE-CIC-IDS2018 no es un sustituto directo para este objetivo de transacciones: sus observaciones son flujos de red, no resultados adjudicados de transacciones bancarias. Solo reconsiderarlo si el objetivo cambia explícitamente a una etiqueta de red compatible y se revisa la calidad/procedencia de sus etiquetas.

El protocolo detallado existente sigue siendo la guía de manejo: [`evaluation-corpus-protocol.md`](evaluation-corpus-protocol.md); el manifiesto es una plantilla vacía, no prueba de autorización.

## 2. Endurecimiento previo a staging

### Hechos del estado local actual

`compose.yaml` es de desarrollo local. Publica proxy, Go, PostgreSQL y Redis en loopback, mantiene Python sin puerto de host y usa HTTP entre servicios. La configuración Go→PostgreSQL especifica `sslmode=disable`; Redis usa `redis://`. El proxy Rust valida upstreams `http://` y su servidor es HTTP; el cliente Python→Go y el servidor Go también están configurados para HTTP. Esto no es una configuración apta para staging ni equivale a mTLS.

### Objetivo de tráfico y control de red

| Salto | Estado actual | Criterio antes de staging |
|---|---|---|
| Cliente → entrada pública | No hay terminación TLS configurada en este Compose | TLS 1.2+ en un ingress controlado, nombres/certificados correctos, redirección o rechazo de HTTP y límites de tamaño/tiempo. Elegir dónde termina TLS y documentar cada salto de confianza. |
| Ingress → proxy Rust | HTTP local | TLS hasta el proxy, o un salto de red privado estrictamente aislado con la excepción documentada; no describirlo como cifrado extremo a extremo si se termina TLS antes. |
| Proxy Rust → Python y Go | HTTP y tokens internos | TLS con verificación de hostname/CA; mTLS con identidad separada por servicio si se exige autenticación mutua. El proxy hoy no acepta upstream HTTPS. |
| Python → Go | HTTP con token interno | TLS/mTLS y validación de identidad; cliente y servidor deben fallar de forma cerrada ante CA, nombre o certificado inválido. El cliente Go de Python hoy usa HTTP. |
| Go → PostgreSQL | `sslmode=disable` | TLS con validación de CA y hostname (`verify-full` o perfil equivalente); credencial de servicio limitada y rotada. |
| Go → Redis | `redis://` sin TLS | TLS con validación de servidor y, si se requiere, certificado de cliente; autenticación y ACL de mínimo privilegio. |
| Servicios → red | Compose local; no es política de cluster | Red de servicio privada; en staging, ingress solo al proxy; Python, Go, PostgreSQL y Redis sin IP/puerto público. Denegación por defecto entre servicios y egress allowlist documentada. |

Una malla de servicios o un ingress gestionado puede proporcionar parte de TLS/mTLS, pero debe documentarse qué componente valida cada identidad. No mezclar dos mecanismos a medias ni asumir que un bearer token reemplaza cifrado/autenticación de transporte.

### Orden de implementación recomendado

1. Decidir plataforma de staging, terminación TLS, CA/identidades, DNS, egress requerido, almacenamiento de secretos y propietario de rotación. No generar ni reutilizar secretos locales.
2. Incorporar configuración explícita y fail-closed para certificados/CA y nombres de servicio en Rust, Python, Go, PostgreSQL y Redis; no degradar silenciosamente a HTTP. Añadir pruebas negativas para certificado ausente, expirado, hostname incorrecto y CA no confiable, y prueba de rotación sin interrupción insegura.
3. Crear el manifiesto de red: único ingreso al proxy; conexiones internas solo por los pares y puertos necesarios; PostgreSQL/Redis no publicados; egress denegado salvo DNS, hora, observabilidad y destinos aprobados que realmente se necesiten.
4. Aplicar política de red del orquestador/plataforma elegida (network policy/firewall), identidades de servicio de mínimo privilegio y secretos en gestor de secretos. `.env.example` es solo para el desarrollo local.
5. Validar en un staging desechable y autorizado: escaneo de puertos desde fuera, TLS/cadena/hostname, pruebas de mTLS por identidad, denegación de tráfico lateral, egress esperado, rotación/revocación, health/readiness, límites/carga y recuperación. Registrar versión, configuración, resultados y excepciones.
6. Hacer revisión independiente de seguridad y amenaza antes de exponerlo. No migrar datos reales ni conectar usuarios hasta cerrar hallazgos y recibir autorización del responsable.

## 3. Puertas de salida y decisiones que faltan

- Evaluación: para cada una de las tres etiquetas, unidad exacta, fuente autorizada de verdad de referencia, definición de adjudicación y ventana de seguimiento; candidato que proveerá probabilidades con la semántica apropiada; autorización y partición independiente del corpus.
- Staging: plataforma, terminación TLS, estándar/autoridad de certificados, egress permitido y responsable de emitir/rotar/revocar identidades.

Hasta resolverlas, el resultado correcto es diseño/preparación local: no hay métricas de eficacia, pentest, mTLS configurado ni staging validado. La decisión de cambiar umbrales o desplegar sigue siendo separada.
