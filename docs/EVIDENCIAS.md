# Evidencias incluidas

Las imágenes provienen de la demostración del laboratorio y están en [`imagenes/`](../imagenes/). Las capturas FortiGate se recortaron para omitir la dirección DHCP externa de port1. La captura Apply se recortó para excluir el listado de archivos personales.

| Archivo | Qué evidencia |
|---|---|
| `imagenes/06_topologia_gns3_original.png` | Topología GNS3 original. |
| `imagenes/02_kali_direccionamiento.png` | IP y ruta de Kali (`10.20.98.10/24`). |
| `imagenes/07_pruebas_ping.png` | Ping exitoso hacia FortiGate, SW1 y R1. |
| `imagenes/05_switch_vlan1.png` | VLAN 1 de SW1 (`10.20.98.2`). |
| `imagenes/03_...` y `imagenes/04_...` | FortiGate port2/port3 antes y después de asignar dirección a port3; port1 omitido. |
| `imagenes/01_apply_resumen_sanitizado.png` | Plan confirmado y conteo de una ejecución compartida. |

En esa ejecución mostrada se reportó `PASS=23`, `FAIL=3`, `NOT_EVALUATED=0`, `ERROR=0`. Es un resultado de una sola corrida, no una promesa de resultados futuros ni una validación integral de CIS.

No incluimos la captura original completa del escritorio porque revelaba nombres de archivos personales. Tampoco incluimos la captura de port1 con su asignación DHCP externa. Revisa también los informes HTML/JSON locales antes de decidir si se publican; pueden mostrar direcciones de administración y evidencia de configuración.
