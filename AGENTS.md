# Reglas para agentes

## Objetivo

Mantener este servidor simple, seguro y operable durante el concurso. La mejor
solución es el cambio correcto más pequeño, no la arquitectura más flexible.

## Antes de editar

- Leer el flujo completo y buscar todos los llamadores del código afectado.
- Reutilizar primero lo que ya existe en `control/`.
- Corregir la causa común, no añadir parches en cada endpoint.
- No modificar secretos ni datos reales de `.env`, `keys/`, `groups.json`,
  `users.json` o `data/`.

## Implementación

- Mantener Python 3 + stdlib + `openssl`; no añadir dependencias salvo petición
  explícita y necesidad demostrada.
- Preferir borrar, simplificar o usar stdlib antes que crear helpers, clases,
  capas, configuración o archivos nuevos.
- No crear abstracciones con una sola implementación ni código “para después”.
- Seguir los patrones y el idioma del archivo existente.
- Conservar validación, autenticación, autorización, firmas, límites y manejo de
  errores en toda frontera de confianza.
- Si una simplificación tiene un límite real, marcarlo como
  `# ponytail: <límite>; <cuándo reemplazarlo>`.

## Interfaz web

- Preservar el estilo y la estructura existentes de `index.html`.
- Evitar UI genérica de IA: gradientes decorativos, tarjetas innecesarias,
  iconos arbitrarios, texto inflado, métricas o testimonios inventados.
- Usar HTML semántico, controles nativos, foco visible, contraste suficiente y
  funcionamiento móvil antes que efectos visuales.
- Para rediseños o auditorías visuales, aplicar Hallmark; no rediseñar una
  pantalla cuando solo se pidió corregir un componente.

## Validación obligatoria

- Ejecutar `python3 test_server.py` después de cambios funcionales.
- Añadir solo la prueba mínima que habría fallado antes del arreglo.
- Revisar primero corrección, seguridad y pérdida de datos; después hacer una
  pasada Ponytail para eliminar sobreingeniería.
- No declarar terminado un cambio si la prueba falla o no pudo ejecutarse;
  informar el motivo exacto.

## Alcance

- No hacer refactors, formateos masivos ni cambios adyacentes no solicitados.
- No generar documentación, scaffolding o dependencias sin necesidad inmediata.
- No usar múltiples agentes para trabajo secuencial; delegar solo subtareas
  independientes y verificables.
