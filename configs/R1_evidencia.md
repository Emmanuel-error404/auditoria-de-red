# R1 — Cisco 7200

> Evidencia parcial; este archivo no es una copia de `show running-config`.

## Datos confirmados

- Modelo: Cisco 7200.
- IOS observado en el informe: 15.2(4)S6.
- Dirección de la interfaz hacia FortiGate: `10.20.79.1/30`.
- SSH operativo en el escaneo; la cuenta se introduce de forma interactiva en el auditor.
- El informe previo mostró SSH v2, VTY limitada a SSH, HTTP deshabilitado y timeout efectivo de 10 minutos.
- En una ejecución Apply se presentó como plan cambiar `enable secret` y agregar un banner MOTD.

La captura de Apply disponible resume resultados de todos los dispositivos (`PASS=23`, `FAIL=3`) pero no muestra toda la tabla POST de R1. Confirma el estado exacto de R1 en `report.json`/`report.html` local antes de afirmar que cada regla quedó aplicada.

## No incluido

No se reconstruye aquí la configuración completa del router. Un `show running-config` antiguo compartido durante el diseño mostraba interfaces apagadas y no corresponde tratarlo como la configuración final de esta topología. Añade un volcado actual solo después de sanitizarlo.
