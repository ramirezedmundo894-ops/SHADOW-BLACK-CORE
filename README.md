# SHADOW BLACK CORE

Proyecto de ciberseguridad en desarrollo. Este repositorio contiene un MVP local ejecutable: una política de riesgo determinista, una API FastAPI, un panel web sencillo y un registro SQLite encadenado por hashes.

## Funcionalidad implementada

- `POST /api/decision`: valida señales estructuradas, aplica reglas explícitas en `shadow_core/policy.py` y registra la decisión.
- `GET /api/evidence`: lista evidencia persistida.
- `GET /api/evidence/verify`: recalcula la cadena hash y detecta cambios en las entradas retenidas.
- `POST /api/improvement-actions`: valida y registra una acción de mejora.
- Panel web local para usar estos endpoints.

Las señales de integridad las aporta quien llama a la API. El proyecto **no** detecta Frida, Magisk/root ni verifica realmente TLS en el dispositivo; tampoco emite/revoca JWT, llama a Vertex AI, ni protege transacciones bancarias. Los umbrales son demostrativos y no están calibrados para producción.

## Ejecutar localmente

Requiere Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
python -m pip install -r requirements.txt
PYTHONPATH=.:shadow-core-dashboard uvicorn main:app --app-dir shadow-core-dashboard --host 127.0.0.1 --port 8080
```

Abre `http://127.0.0.1:8080/`. El ejemplo solo escucha en localhost. SQLite se guarda por defecto en `./data/shadow-core.sqlite3`; `SHADOW_CORE_DB` permite elegir otra ruta. No uses SQLite local como almacenamiento compartido en varias réplicas ni en un contenedor efímero.

## API

```bash
curl -s http://127.0.0.1:8080/api/decision \\
  -H 'Content-Type: application/json' \\
  -d '{"frida_detected":true,"root_integrity_failed":false,"jwt_validation_failures":0,"grpc_tls_verified":true}'

curl -s http://127.0.0.1:8080/api/evidence/verify
```

## Pruebas

```bash
PYTHONPATH=.:shadow-core-dashboard pytest -q shadow-core-tests shadow-core-dashboard/test_main.py
```

## Límites de la evidencia

SHA-256 encadenado permite detectar cambios en entradas retenidas al verificar desde el inicio. No equivale a firma digital ni almacenamiento inmutable: alguien con acceso de escritura puede reescribir la base y recalcular la cadena, y la eliminación del final requiere un anclaje externo para detectarse. Para garantías mayores se necesitarían claves protegidas, control de acceso, anclaje externo y retención verificable.

## Seguridad y despliegue

Esto es un MVP para aprendizaje y pruebas locales, no un producto bancario ni una herramienta de pentest. No expongas el API sin autenticación, autorización, límites, gestión de secretos, logging, revisión de privacidad y pruebas independientes. La infraestructura Terraform existente no forma parte del flujo ejecutable del MVP: requiere validación y revisión de costos/permisos, y no debe aplicarse a producción tal cual.
