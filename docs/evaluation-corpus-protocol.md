# Protocolo para un corpus de evaluación offline

## Propósito y límite

Este protocolo prepara evidencia para evaluar probabilidades de un candidato con `shadow_core.model_evaluation`. No autoriza recolectar datos, no constituye un pentest y no conecta el evaluador con la API. Hasta completar las revisiones indicadas, los datos sintéticos solo sirven para probar el cálculo.

## 1. Autorizar y definir el alcance

Antes de reunir datos, documentar quién autoriza el uso, el sistema y población cubiertos, el periodo, el propósito y las restricciones aplicables. Usar únicamente datos que el equipo pueda tratar legítimamente para esta evaluación. Si no hay autorización clara, detenerse y usar datos sintéticos.

Definir por adelantado:

- Qué evento significa `label=true`, quién adjudica el resultado y cuál es la ventana temporal para observarlo.
- Qué significa cada probabilidad, de qué versión de candidato procede y cuál es el umbral de análisis.
- Qué población y escenarios quedan fuera; cómo tratar etiquetas ambiguas, faltantes y duplicados.
- Qué métricas y segmentos se informarán y qué tamaño/calidad mínimos permiten interpretarlos.

No ajustar el umbral con el conjunto que luego se presenta como evaluación final. Si se explora o calibra con datos, reservar otra partición independiente para la evaluación final.

## 2. Minimizar y proteger

El archivo de evaluación admite exactamente `label` y `probability` por fila. No incluir nombres, identificadores, IP, texto de eventos, credenciales, secretos, características ni claves de unión. Extraer solo la etiqueta revisada y la probabilidad necesaria; los identificadores originales, si son imprescindibles para deduplicar o separar eventos, deben quedarse en una fuente protegida y fuera del archivo de evaluación.

Trabajar en almacenamiento local con acceso restringido y protección adecuada. No subir registros reales a repositorios públicos, chats, servicios externos ni ejemplos de documentación. Un dato sin nombre todavía puede ser identificable por contexto o rareza: revisar el riesgo de reidentificación, especialmente en grupos pequeños. Fijar antes una retención y eliminación seguras. Informar solo agregados que no expongan individuos o eventos.

## 3. Etiquetar sin contaminar la evaluación

La etiqueta de referencia debe provenir de revisión humana independiente del puntaje del candidato, con una definición escrita y evidencia autorizada. Cuando haya desacuerdo o falta de evidencia, marcar el caso como no adjudicado fuera del archivo analítico; no convertir la incertidumbre en `false`. Registrar el método de adjudicación y el acuerdo entre revisores en el manifiesto, no en cada fila.

Separar eventos relacionados antes de crear particiones. Si una misma persona, dispositivo, incidente o secuencia aparece en varias filas, no repartirla entre conjuntos como si fueran observaciones independientes. Guardar la partición y el criterio usados; impedir que datos o decisiones posteriores filtren información al conjunto reservado.

## 4. Preparar, revisar y ejecutar

1. Conservar la fuente autorizada en su ubicación protegida y crear una exportación mínima nueva; nunca editar la única copia de origen.
2. Revisar el archivo localmente. Confirmar que contiene JSONL válido y solo `label` booleana y `probability` finita entre 0 y 1; revisar conteos, duplicados y balance de clases sin revelar registros.
3. Una segunda persona verifica la definición de etiquetas, el manifiesto, la separación de particiones y que el conjunto final no se usó para elegir el umbral.
4. Ejecutar el evaluador offline sobre la copia aprobada. Conservar versión del candidato, configuración, hash del archivo, versión del evaluador, fecha y salida agregada junto al manifiesto.
5. Interpretar las tasas con sus intervalos Wilson del 95%. Son intervalos binomiales por fila: si hay eventos correlacionados o repetidos, la suposición de independencia puede fallar y esos intervalos no bastan; no presentar precisión aparente como certeza. Con muestras pequeñas o segmentos escasos, informar la limitación y no sacar conclusiones de eficacia.
6. Mantener separados el resultado offline y cualquier decisión operativa. No cambiar umbrales ni política determinista a partir de este informe; exigir una revisión y autorización aparte antes de proponer pruebas en otro entorno.

## 5. Manifiesto separado (no contiene filas)

Completar una copia de `evaluation-corpus-manifest.example.yaml` bajo acceso restringido. No guardar allí identificadores personales ni rutas que expongan datos sensibles. El manifiesto documenta procedencia y proceso; no demuestra por sí solo que la recolección, revisión o independencia hayan sido correctas.

## Lo que el código sí y no comprueba

El evaluador rechaza campos adicionales y valores malformados y entrega métricas agregadas. Eso ayuda a reducir exposición en el archivo de entrada, pero no verifica autorización, calidad de etiquetas, origen de datos, duplicados entre entidades, representatividad, independencia estadística ni que un revisor humano haya adjudicado cada etiqueta. Esas verificaciones son puertas de proceso y revisión, no resultados automáticos del CLI.
