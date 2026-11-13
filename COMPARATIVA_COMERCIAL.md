# Comparativa funcional pública: protección de apps móviles

Fecha de consulta indicada para esta comparación: 2026-11-13.

Esta tabla resume capacidades que cada proveedor describe públicamente en las páginas enlazadas. No es una prueba comparativa independiente, no evalúa versiones, planes, contratos, configuración, resultados de laboratorio o eficacia en una app concreta. Las descripciones son afirmaciones del proveedor, salvo RootBeer, cuya fuente es su repositorio público. No se asignan puntuaciones ni se ordenan productos. Precios: **cotización requerida/no comparados**.

| Solución | Alcance funcional descrito públicamente | Precio |
|---|---|---|
| Promon Shield for Mobile | Promon declara app shielding/RASP y protecciones frente a root, hooking y repackaging; describe una integración post-build. | Cotización requerida/no comparados |
| Guardsquare DexGuard | Guardsquare describe hardening/obfuscación y capacidades RASP para Android. | Cotización requerida/no comparados |
| Appdome Mobile App Security | Appdome describe defensas móviles integradas en CI/CD y capacidades para Android e iOS. | Cotización requerida/no comparados |
| Zimperium zDefend | Zimperium describe un SDK runtime con análisis/IA on-device, telemetría y respuestas configurables. | Cotización requerida/no comparados |
| RootBeer (open source) | Biblioteca OSS de menor alcance: busca indicios locales de root. Su propio proyecto limita explícitamente la cobertura; no es equivalente a una plataforma enterprise de protección móvil. | No comparados (proyecto OSS; soporte/servicios fuera de comparación) |
| SHADOW CORE (este repositorio) | Proyecto en desarrollo. Esta rama contiene backend Python/FastAPI, FFT con datos sintéticos, correlación prototipo no entrenada, política Go y persistencia/outbox PostgreSQL más transporte Redis, con pruebas locales desechables y end-to-end en esta rama. No es un SDK móvil comercial ni se afirma equivalencia con las soluciones anteriores. | No disponible; producto/precio no definidos |

## Cómo leerla

- Las características de las primeras cinco filas son descripciones públicas de cada fuente; no se han verificado mediante una prueba propia de sus productos.
- Los resultados de Shadow Core son pruebas de código local de esta rama, no evaluación de proveedor, pentest ni ensayo independiente. La FFT se prueba con señales sintéticas. La correlación de IA es un prototipo sin entrenamiento/calibración y no decide: la política determinista server-side conserva autoridad.
- No se comparan tasas de detección, rendimiento, costo de bypass, seguridad, certificaciones ni cobertura efectiva. Tampoco se evalúan ediciones/planes, configuración comercial o cláusulas de contrato.
- RootBeer se incluye como referencia OSS de detección local limitada, no como competidor enterprise equivalente.
- Persisten brechas en Rust, cliente Android/Kotlin y validación en dispositivo/staging/GCP; consultar el estado del repositorio en `README.md` antes de interpretar el alcance de Shadow Core. Una mención a infraestructura prevista no prueba que esté implementada o desplegada.

## Fuentes públicas

Consulta: 2026-11-13. Se citan páginas de producto/repositorio; sus contenidos y funciones pueden cambiar.

- Promon Shield for Mobile: <https://promon.co/software-security-solutions/app-shielding>
- Guardsquare DexGuard: <https://www.guardsquare.com/dexguard>
- Appdome Mobile App Security: <https://www.appdome.com/mobile-app-security/>
- Zimperium zDefend: <https://zimperium.com/maps/zdefend>
- RootBeer (repositorio del proyecto): <https://github.com/scottyab/rootbeer>
