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
5. Go guarda decisión y evento pendiente en PostgreSQL en una transacción. Un dispatcher publica en Redis Streams desde el outbox. El outbox es fuente durable; Redis es transporte al menos una vez, por lo que consumidores deben deduplicar por `event_id`.

## Responsabilidad por tecnología

- Python/FastAPI: API y scopes; sesiones JWT/refresh del prototipo; endpoint FFT; correlación transparente; cliente opcional del servicio Go. La evidencia y otros datos locales preexistentes aún pueden usar SQLite; no usar ese SQLite como almacén compartido entre réplicas.
- Go: contrato `shadow.risk.v1`, puntuación/reglas deterministas y respuesta de riesgo; persistencia de decisiones/outbox en PostgreSQL y publicación a Redis Streams.
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

Rama local `feat/real-api-jwt-play-integrity`; los cambios no se han publicado ni fusionado.

Implementado en el repositorio según el código de esta rama:

- API Python/FastAPI y flujo de autenticación, scopes, access/refresh JWT rotativos y revocación de familia en persistencia local.
- Endpoint de reto/verificación server-side para Google Play Integrity, pero los tests locales usan verificador falso; no acreditan una app Android, un dispositivo ni la integración real de Google.
- FFT radix‑2 para el análisis de muestras y flujo de señales FFT → correlación transparente → política Go.
- Servicio Go mínimo con contrato versionado y política determinista. PostgreSQL conserva la decisión y el outbox en transacción; Redis Streams transporta eventos versionados al menos una vez. Las pruebas de integración y una llamada end-to-end se ejecutaron contra instancias locales desechables PostgreSQL 15 y Redis 7; la configuración de Docker Compose existe, pero no se ejecutó aquí.

Aún no implementado o validado como sistema completo: Rust con TLS/operación de borde de producción, servicios Go adicionales/circuit breaker de producción, cliente Android/Kotlin, IA entrenada/calibrada, Redis/PostgreSQL con alta disponibilidad, honeypot aislado, CAPTCHA integrado a un flujo real, mTLS gRPC de extremo a extremo, despliegue GKE/GCP, staging, pentest externo y certificación/auditoría. No afirmar tasas de detección, cobertura, costo de bypass ni superioridad comercial a partir del material promocional anterior.

La comparación funcional prudente de soluciones públicas está en [`COMPARATIVA_COMERCIAL.md`](COMPARATIVA_COMERCIAL.md); sus claims no se presentan como ensayos propios.

## Desarrollo y pruebas

Requisitos: Python 3.11 para la suite actual; Go para el servicio; Rust estable/Cargo para el proxy. Las pruebas no usan credenciales ni servicios externos.

```bash
# desde la raíz
PYTHONPATH="$PWD" uv run --python 3.11 --no-project \
  --with-requirements requirements.txt python -m pytest -q

# servicio y pruebas Go
(cd shadow-core-go && go test ./... && go build -o /tmp/shadow-core-go . && rm -f /tmp/shadow-core-go)

# proxy Rust
(cd shadow-core-rust && cargo test && cargo build)
```

Las pruebas de FFT usan señales sintéticas; no equivalen a detección validada en dispositivos o tráfico real. Las pruebas PostgreSQL/Redis de integración son optativas: usan solo los servicios indicados por variables `SHADOW_TEST_POSTGRES_DSN` y `SHADOW_TEST_REDIS_URL`; apuntarlas únicamente a una base/instancia desechable. Se ejecutaron aquí con un clúster temporal aislado de PostgreSQL 15 y Redis 7, más una prueba end-to-end del servicio Go. No se tocaron datos de usuario. Docker no está disponible en este entorno, por lo que `compose.yaml` se revisó como configuración, no se levantó ni se validó en ejecución.

### Rebanada local con PostgreSQL y Redis

Docker Compose es la vía reproducible prevista. Requiere Docker Engine y el plugin `docker compose`; ambos no están disponibles en el entorno donde se hicieron estas pruebas. El archivo expone puertos solo en localhost y usa volúmenes locales; es para desarrollo, no producción.

```bash
cp .env.example .env
# Cambia ambos valores locales antes de iniciar; no reutilices esos secretos fuera del entorno de prueba.
docker compose -f compose.yaml up --build
```

Compose inicia PostgreSQL, Redis y el servicio Go; la migración se aplica al arrancar Go. Para conectar una API Python ejecutada en el host, configura `SHADOW_GO_POLICY_URL=http://127.0.0.1:18081` y el mismo `SHADOW_GO_INTERNAL_TOKEN` de `.env`; la URL debe ser accesible solo por la API confiable. Se puede comprobar `/health` en `http://127.0.0.1:18081/health`. No se debe afirmar que esta composición corre hasta ejecutar y observar `docker compose up` en una máquina con Docker.

El dispatcher es al menos una vez: si Redis acepta un evento y el proceso cae antes de marcarlo publicado en PostgreSQL, puede volver a aparecer en el stream. El evento conserva su `event_id`; consumidores deben aplicar idempotencia/deduplicación. Si PostgreSQL no está disponible, Go no entrega decisiones sensibles; si Redis no está disponible, responde con error y el evento persiste en outbox para reintento. Reintentar una misma petición requiere repetir la misma cabecera `Idempotency-Key` UUID; usar una clave con otro cuerpo devuelve conflicto.

## Hoja de ruta

1. La migración, idempotencia, outbox, transporte y error cerrado ya pasaron pruebas locales con PostgreSQL/Redis desechables; falta validar `compose.yaml` con Docker disponible y ampliar pruebas de concurrencia/recuperación.
2. Revisar y ampliar contratos Rust/Go/Python y modelo de amenazas; validar Compose con Docker disponible y sumar pruebas locales de integración reproducibles para el proxy.
3. Construir cliente Android/Kotlin y validar atestación y señales en dispositivos/entorno de prueba autorizados.
4. Evaluar FFT y modelos con corpus etiquetado, falsos positivos/negativos y revisión humana; entrenar/calibrar antes de usar IA para cualquier señal operacional. La política determinista sigue siendo autoridad.
5. Revisar controles GCP/Kubernetes, IAM, KMS, Cloud Armor, VPC Service Controls y costos; desplegar solo tras revisión explícita y evidencia de staging.
6. Auditoría externa y cualquier afirmación de cumplimiento solo con alcance y evidencia independientes.

## Alcance y seguridad

Los porcentajes, costos, comparativas comerciales y tendencias de la landing no se reproducen como resultados técnicos; la comparación del repositorio resume solo las descripciones públicas citadas y no es una evaluación independiente. Esta rama verifica comportamiento de código local con tests; no prueba ataques reales, eficacia contra Frida/Magisk, seguridad bancaria, resistencia frente a un atacante adaptativo ni cumplimiento certificado. No expongas los servicios ni uses datos/secretos reales. Revisa riesgos, privacidad, dependencias, gestión de claves, retención y recuperación antes de cualquier despliegue.
