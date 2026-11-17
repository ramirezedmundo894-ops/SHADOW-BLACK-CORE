# SHADOW CORE

Defensa de riesgo para apps móviles bancarias: combinar análisis matemático, señales del servidor y políticas auditables para decidir si una operación se permite, se limita, requiere un reto o se rechaza. Es un proyecto en desarrollo y un prototipo local; no es un SDK bancario listo para producción ni una evaluación independiente de seguridad.

## Arquitectura y flujo

```text
Cliente móvil (Android pendiente)
  → proxy Rust local (allowlist/rate limit; Cloud Armor queda para GCP)
  → API Python/FastAPI: autenticación, validación y FFT
  → servicio Go: política determinista y TTL
  → PostgreSQL: decisión durable + outbox transaccional
  → Redis Streams: transporte de eventos versionados
```

1. La API valida la identidad/scope y el formato de las señales. Los datos declarados por el cliente no se consideran una raíz de confianza.
2. Para beaconing, FFT/Fourier rápida es el primer detector matemático: analiza muestras uniformes y devuelve una señal interpretable. Esta rama incluye una FFT radix‑2 y pruebas con muestras sintéticas.
3. Un prototipo transparente de correlación combina señales después de FFT. No está entrenado ni calibrado, no produce una probabilidad fiable y no tiene autoridad para decidir.
4. El servicio Go evalúa su política determinista versionada. Es la autoridad de decisión del flujo integrado. Las señales/correlación se registran para explicar el resultado; no sustituyen la política.
5. Go guarda la decisión y el evento pendiente en PostgreSQL en una transacción; un dispatcher publica el outbox en Redis Streams con entrega al menos una vez. Un consumer group de Go procesa esos eventos: el inbox PostgreSQL y el efecto SQL de proyección se confirman en una transacción antes del ACK. Los replays idénticos no repiten ese efecto; los sistemas externos a PostgreSQL siguen necesitando su propia idempotencia.

## Responsabilidad por tecnología

- Python/FastAPI: API y scopes; sesiones JWT/refresh del prototipo; endpoint FFT; correlación transparente; cliente opcional del servicio Go. La evidencia y otros datos locales preexistentes aún pueden usar SQLite; no usar ese SQLite como almacén compartido entre réplicas.
- Go: contrato `shadow.risk.v1`, política determinista, persistencia de decisiones/outbox, publicación Redis y consumer group con inbox PostgreSQL transaccional para la proyección SQL.
- Rust: proxy HTTP local con allowlist exacta, request-id, límites de cuerpo/tasa, saneamiento de headers y backends configurables. Cloud Armor sigue siendo una capa GCP pendiente.
- Android/Kotlin: cliente, integración de señales/atestación y pruebas de dispositivo pendientes.
- GCP/Kubernetes: Cloud Armor, IAM/Workload Identity, Cloud KMS, VPC Service Controls, Network Policies y despliegue GKE son etapas posteriores; el scaffold de infraestructura no equivale a configuración revisada o desplegable.

## Contrato de sesión

El access JWT dura 900 segundos (15 minutos) en riesgo normal y se reduce a 20 segundos cuando la política eleva el riesgo. El modo alto riesgo se asocia a la familia de refresh; los refresh tokens son de un solo uso y la reutilización revoca esa familia. El recorte a 20 segundos limita vigencia: **no es una reautenticación ni un step-up**. El prototipo no afirma validar un segundo factor. JWT/refresh del servidor siguen siendo una implementación local; una base SQLite no sirve como estado compartido multi-réplica.

### Proxy inverso Rust (desarrollo local)

`shadow-core-rust/` contiene un proxy HTTP mínimo. Por defecto escucha solo en `127.0.0.1:8080`; el `GET /health` es local y no depende de backends. Las demás rutas deben coincidir exactamente con el método y la ruta permitidos: `POST /api/auth/token`, `/api/auth/refresh`, `/api/auth/revoke`, `/api/attestation/challenges`, `/api/attestation/verify`, `/api/decision`, `/api/analysis/beaconing`, `/api/improvement-actions`; `GET /api/evidence` y `/api/evidence/verify`. No hay ruta catch-all. `POST /internal/v1/decision` solo se añade al allowlist si se configura el upstream Go y exige bearer token del proxy.

El proxy genera `X-Shadow-Request-Id`, reemplaza `X-Real-IP`, y solo reenvía un conjunto pequeño de headers, incluidos `Authorization` e `Idempotency-Key`; descarta headers de identidad internos y `X-Forwarded-For` enviados por el cliente. `X-Real-IP` entrante se considera únicamente cuando el socket remoto coincide con una IP listada exactamente en `SHADOW_TRUSTED_PROXIES`; por defecto la lista está vacía. No se admiten CIDR ni cadenas de proxies. El limitador es ventana fija, en memoria y por IP efectiva, no sincronizado entre procesos.

Variables de entorno:

| Variable | Predeterminado | Uso |
| --- | --- | --- |
| `SHADOW_PROXY_ADDR` | `127.0.0.1:8080` | Dirección local de escucha. |
| `SHADOW_PYTHON_UPSTREAM` | `http://127.0.0.1:8000` | Upstream HTTP Python; solo host y puerto, sin path. |
| `SHADOW_GO_UPSTREAM` | vacío | Upstream Go opcional; habilita la ruta interna. |
| `SHADOW_GO_PROXY_TOKEN` | vacío | Bearer requerido por el proxy en la ruta Go interna. |
| `SHADOW_GO_INTERNAL_TOKEN` | vacío | Token que el proxy agrega como header interno al llamar Go; requerido junto al upstream Go. |
| `SHADOW_TRUSTED_PROXIES` | vacío | Lista CSV de IP exactas cuyos `X-Real-IP` se confían. |
| `SHADOW_MAX_BODY_BYTES` | `1048576` | Máximo del cuerpo entrante y respuesta upstream en bytes. |
| `SHADOW_RATE_LIMIT_REQUESTS` | `120` | Solicitudes por IP y ventana fija. |
| `SHADOW_RATE_LIMIT_WINDOW_SECONDS` | `60` | Duración de ventana. |
| `SHADOW_RATE_LIMIT_MAX_CLIENTS` | `20000` | Tope de IPs en memoria. |

Ejecuta `cargo test` y `cargo build` dentro de `shadow-core-rust/`. El proxy está pensado para loopback/desarrollo: HTTP sin TLS, rate limit local no distribuido, sin mTLS, observabilidad/rotación de claves ni pruebas de carga. No lo expongas directamente a Internet ni lo presentes como proxy endurecido para producción; primero requiere revisión de seguridad, TLS en un borde confiable, políticas de red y pruebas operacionales.

## Estado real de esta rama

La rama `feat/real-api-jwt-play-integrity` parte del commit publicado `9591579`. Esta fase se publica en esa misma rama; no se abre PR, no se fusiona ni se despliega.

Implementado en el repositorio según el código de esta rama:

- API Python/FastAPI y flujo de autenticación, scopes, access/refresh JWT rotativos y revocación de familia en persistencia local.
- Endpoint de reto/verificación server-side para Google Play Integrity, pero los tests locales usan verificador falso; no acreditan una app Android, un dispositivo ni la integración real de Google.
- FFT radix‑2 para el análisis de muestras y flujo de señales FFT → correlación transparente → política Go.
- Servicio Go mínimo con contrato versionado y política determinista. PostgreSQL conserva la decisión y el outbox en transacción; Redis Streams transporta eventos versionados al menos una vez. El consumer group usa un inbox durable y confirma el efecto SQL de proyección antes del ACK; una prueba con PostgreSQL y Redis desechables verificó fallo/reintento, deduplicación y ACK. Esto no hace exactamente-una-vez a efectos externos a PostgreSQL. La prueba Compose end-to-end local atravesó proxy Rust, API Python/FFT y Go, y verificó una decisión `SHORT_TTL`/20 s, su fila en PostgreSQL y el evento versionado en Redis Streams. La señal de 5 Hz era sintética; no demuestra detección con tráfico real.

Aún no implementado o validado como sistema completo: Rust con TLS/operación de borde de producción, servicios Go adicionales/circuit breaker de producción, efectos de negocio distintos de la proyección SQL de referencia, cliente Android/Kotlin, IA entrenada/calibrada, Redis/PostgreSQL con alta disponibilidad, honeypot aislado, CAPTCHA integrado a un flujo real, mTLS gRPC de extremo a extremo, despliegue GKE/GCP, staging, pentest externo y certificación/auditoría. No afirmar tasas de detección, cobertura, costo de bypass ni superioridad comercial a partir del material promocional anterior.

La comparación funcional prudente de soluciones públicas está en [`COMPARATIVA_COMERCIAL.md`](COMPARATIVA_COMERCIAL.md); sus claims no se presentan como ensayos propios.

## Desarrollo y pruebas

Requisitos: Python 3.11 para la suite actual; Go para el servicio; Rust estable/Cargo para el proxy. Las pruebas no usan credenciales ni servicios externos.

### Evaluación offline de un modelo candidato

El proceso de autorización, minimización, adjudicación de etiquetas y partición segura está descrito en [`docs/evaluation-corpus-protocol.md`](docs/evaluation-corpus-protocol.md); la plantilla del manifiesto es [`docs/evaluation-corpus-manifest.example.yaml`](docs/evaluation-corpus-manifest.example.yaml). Ninguno de los dos sustituye la autorización ni aporta un corpus real.

`shadow_core.model_evaluation` calcula métricas sobre JSONL revisado (`label` booleana como verdad de referencia y `probability` entre 0 y 1). Cada fila admite solo esos dos campos, y el informe agrega matriz de confusión, precisión/recall, tasas de error y Brier y un intervalo de confianza Wilson del 95% para cada tasa binomial; una tasa indefinida queda como `null`. En conjuntos pequeños, los intervalos amplios dejan visible la incertidumbre. Su interpretación supone muestras independientes y representativas; no es garantía de rendimiento real. Ejemplo: `python -m shadow_core.model_evaluation /ruta/evaluacion.jsonl --threshold 0.5`. El umbral es solo una opción para este análisis offline, no una configuración operativa. Este módulo no entrena ni llama a un modelo, no está conectado a la API y no puede cambiar la política determinista. Sin un corpus etiquetado revisado no hay métricas de eficacia que reportar; las pruebas usan ejemplos sintéticos y solo verifican el cálculo.

```bash
# desde la raíz
PYTHONPATH="$PWD" uv run --python 3.11 --no-project \
  --with-requirements requirements.txt python -m pytest -q

# servicio y pruebas Go
(cd shadow-core-go && go test ./... && go build -o /tmp/shadow-core-go . && rm -f /tmp/shadow-core-go)

# proxy Rust
(cd shadow-core-rust && cargo test && cargo build)
```

Las pruebas de FFT usan señales sintéticas; no equivalen a detección validada en dispositivos o tráfico real. Las pruebas PostgreSQL/Redis de integración son optativas: usan solo los servicios indicados por variables `SHADOW_TEST_POSTGRES_DSN` y `SHADOW_TEST_REDIS_URL`; apuntarlas únicamente a una base/instancia desechable. Se ejecutaron aquí con un clúster temporal aislado de PostgreSQL 15 y Redis 7, además de la integración completa Compose local (PostgreSQL 16, Redis 7, Go, Python y proxy Rust). No se usaron datos de producción. Las pruebas de fallo/reintento cubren persistencia fallida con respuesta 503 sin publicar, Redis inaccesible conservando el outbox y recuperación al reabrir el store; una prueba con PostgreSQL/Redis reales inyecta un fallo después de `XADD` y verifica que un reintento puede duplicar la entrega con el mismo `event_id`. El script `scripts/test_compose_redis_restart.sh` también verificó que el worker publique una fila pendiente tras reiniciar Redis. El nuevo `scripts/test_compose_service_restarts.sh` usa su propio proyecto y volúmenes temporales, enlazados a puertos loopback: verificó persistencia al reiniciar el contenedor PostgreSQL, reconexión de Go tras reiniciar el proceso y recuperación del outbox cuando Redis estaba detenido durante el reinicio de Go. El evento pendiente apareció una vez en el stream aislado. La prueba confirmó que la base SQLite local no cambió y eliminó únicamente sus recursos desechables. Una prueba HTTP concurrente con 16 reintentos de la misma clave produjo una decisión, un outbox y un evento en una instancia Go. `scripts/test_compose_multi_replica_idempotency.sh` levanta una base limpia, verifica el arranque simultáneo de dos procesos Go en un proyecto y volúmenes independientes de loopback, y envía 32 solicitudes con la misma clave: todas devolvieron la misma decisión, PostgreSQL conservó una fila de decisión y una de outbox, el mismo UUID con cuerpo distinto devolvió 409 y Redis publicó el evento con un único `event_id`. El mismo script añade un smoke test de carga sintética acotada: 150 solicitudes únicas, a 5 solicitudes/s durante 30 segundos, entre dos procesos Go; registra latencias y comprueba PostgreSQL y Redis. En la ejecución local aislada, las 150 respondieron HTTP 200 y llegaron a ambos servicios; latencia p50 4,5 ms, p95 7,6 ms, máxima 17,9 ms en la ejecución más reciente. Es una medición puntual, no un benchmark de capacidad ni una prueba de alta disponibilidad o recuperación ante pérdida física. `scripts/test_compose_event_consumer.sh` también ejercita un consumer group real en servicios desechables: una falla SQL deja el evento pendiente, luego se reintenta y confirma antes del ACK; el replay del mismo `event_id` no repite la proyección. La entrega de Redis continúa siendo al menos una vez, y esta prueba no cubre efectos fuera de PostgreSQL ni producción.

### Integración local completa con Docker Compose

Docker Compose ejecuta el proxy Rust, la API Python/FastAPI con FFT, el servicio de política Go, PostgreSQL y Redis Streams. Requiere Docker Engine y el plugin `docker compose` (o el ejecutable compatible `docker-compose`). Los puertos publicados se enlazan a `127.0.0.1`; PostgreSQL, Redis y el estado aislado de la API usan volúmenes nombrados. Esta configuración es solo para desarrollo local.

```bash
cp .env.example .env
# Reemplaza los cinco valores por secretos aleatorios distintos, solo para esta máquina.
./scripts/e2e_compose.sh
```

El script construye/levanta la pila, comprueba el health del proxy y que la ruta interna rechace llamadas sin bearer, luego envía una señal 5 Hz sintética por Rust → Python/FFT → Go. Comprueba la decisión `SHORT_TTL`/20 s, su persistencia en PostgreSQL y la publicación del evento versionado en Redis Streams. La salida informa el UUID de prueba y un resumen de la decisión, no los secretos. Para probar recuperación con Redis detenido en la pila local existente, ejecuta `./scripts/test_compose_redis_restart.sh`; detiene Redis brevemente y limpia su fila/evento de prueba al terminar. Para probar reinicios reales de PostgreSQL y Go y la recuperación con Redis detenido, ejecuta `./scripts/test_compose_service_restarts.sh`: crea un proyecto Compose independiente con puertos loopback y volúmenes nuevos, y lo elimina al terminar; requiere `.env` local, pero no usa los volúmenes ni los puertos de la pila principal. Para probar idempotencia entre dos procesos Go, ejecuta `./scripts/test_compose_multi_replica_idempotency.sh`: usa otro proyecto, puertos loopback y volúmenes desechables; envía 32 solicitudes concurrentes con la misma clave y verifica una sola decisión/outbox y un `event_id` estable. Requiere `.env` local y elimina solo los recursos de ese proyecto. Para probar el consumer group Redis y su inbox idempotente, ejecuta `./scripts/test_compose_event_consumer.sh`: levanta PostgreSQL 16 y Redis 7 desechables en puertos loopback, prueba reintento ante fallo SQL, ACK y replay deduplicado, y elimina ambos contenedores; no toca el Compose principal ni el SQLite local.

El Compose enlaza únicamente `18080` (proxy), `18081` (Go), `54329` (PostgreSQL) y `16379` (Redis) a loopback; Python queda solo en la red interna de Compose. `SHADOW_CORE_DB` usa el volumen `shadow-api-data`, no el archivo preexistente `data/shadow-core.sqlite3`. Para detener los contenedores conservando las bases y streams locales: `sudo docker-compose down` (no agregar `-v` si quieres preservar los volúmenes).

La prueba sintética verifica el flujo de integración y persistencia de esta ejecución; no acredita calidad de detección con tráfico real, seguridad frente a atacantes, despliegue cloud ni comportamiento bajo carga. El proxy es HTTP sin TLS y su rate limit es local/no distribuido: no lo expongas a Internet.

El dispatcher es al menos una vez: si Redis acepta un evento y el proceso cae antes de marcarlo publicado en PostgreSQL, puede volver a aparecer en el stream. El consumer group de referencia usa `event_id` y una transacción PostgreSQL para deduplicar el efecto SQL de proyección antes de hacer ACK; los efectos externos requieren controles propios. PostgreSQL es requisito para iniciar Go; Redis no lo es: si Redis está temporalmente caído al iniciar, Go puede arrancar y atender health, mientras las decisiones siguen devolviendo error y sus eventos quedan en el outbox para reintento cuando Redis vuelva. Si PostgreSQL no está disponible, Go no puede aceptar decisiones. Reintentar una misma petición requiere repetir la misma cabecera `Idempotency-Key` UUID; usar una clave con otro cuerpo devuelve conflicto.

## Hoja de ruta

1. La integración local Rust → Python/FFT → Go → PostgreSQL/outbox → Redis Streams pasó pruebas sintéticas de extremo a extremo, reinicio y carga acotada. El consumer group Redis ya integra el inbox transaccional y se verificó en servicios desechables; siguen pendientes carga sostenida, alta disponibilidad, recuperación ante pérdida física y efectos externos idempotentes.
2. Revisar y ampliar contratos Rust/Go/Python y el modelo de amenazas; agregar TLS/mTLS y límites distribuidos antes de cualquier exposición externa. El plan de saltos de confianza, red y pruebas está en [`docs/evaluation-and-staging-readiness.md`](docs/evaluation-and-staging-readiness.md).
3. Construir cliente Android/Kotlin y validar atestación y señales en dispositivos/entorno de prueba autorizados.
4. El evaluador offline `shadow_core.model_evaluation` ya calcula métricas para probabilidades de un modelo candidato; faltan tres evaluaciones separadas (transacción no autorizada, toma de cuenta y abuso de API), sus fuentes/ventanas de adjudicación, un candidato probabilístico apropiado y un corpus autorizado y revisado. La propuesta de etiqueta y sus puertas están en [`docs/evaluation-and-staging-readiness.md`](docs/evaluation-and-staging-readiness.md). Entrenar/calibrar antes de usar IA para cualquier señal operacional; la política determinista sigue siendo autoridad.
5. Revisar controles GCP/Kubernetes, IAM, KMS, Cloud Armor, VPC Service Controls y costos; desplegar solo tras revisión explícita y evidencia de staging.
6. Auditoría externa y cualquier afirmación de cumplimiento solo con alcance y evidencia independientes.

## Alcance y seguridad

Los porcentajes, costos, comparativas comerciales y tendencias de la landing no se reproducen como resultados técnicos; la comparación del repositorio resume solo las descripciones públicas citadas y no es una evaluación independiente. Esta rama verifica comportamiento de código local con tests; no prueba ataques reales, eficacia contra Frida/Magisk, seguridad bancaria, resistencia frente a un atacante adaptativo ni cumplimiento certificado. No expongas los servicios ni uses datos/secretos reales. Revisa riesgos, privacidad, dependencias, gestión de claves, retención y recuperación antes de cualquier despliegue.
