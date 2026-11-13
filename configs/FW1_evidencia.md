# FW1 — FortiGate 7.0.9

> Evidencia parcial; este archivo no es un respaldo completo de FortiGate.

## Direccionamiento observado

| Interfaz | Dirección/estado | Uso |
|---|---|---|
| `port1` | DHCP externo; dirección omitida | Enlace externo existente, preservado. |
| `port2` | `10.20.79.2/30`, up | Tránsito al router R1. |
| `port3` | `10.20.98.1/24`, up | Gateway de LAN de gestión. |

En una captura temprana `port3` aparece temporalmente como `0.0.0.0`; una captura posterior muestra `10.20.98.1/24`. Ambas se conservan como evidencia cronológica saneada.

La ejecución Apply mostró como cambios preparados habilitar el pre-login banner y asignar hostname `FW1`. El resumen global fue `PASS=23`, `FAIL=3`, pero la evidencia compartida no incluye la tabla POST completa de FortiGate; consulta el reporte local para confirmar estados por control.

