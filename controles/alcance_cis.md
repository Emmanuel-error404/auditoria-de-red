# Alcance CIS usado por el auditor

## Interpretación de estados

- `PASS`: la evidencia obtenida coincide con el criterio automatizado codificado.
- `FAIL`: la evidencia obtenida no coincide con ese criterio.
- `NOT_EVALUATED`: no se pudo determinar el estado con la salida disponible.
- `ERROR`: fallo en la operación del escaneo; no debe interpretarse como un incumplimiento de configuración.
- SSH `PASS` solo significa que se pudo leer el equipo. No equivale a cumplir CIS.

## Cisco 7200 y Cisco vIOS L2

Referencia: **CIS Cisco IOS Benchmark v2.2**, Level 1. El documento está archivado y es genérico; se toma como referencia cercana, no como estándar exacto de Cisco IOS 15.2 o de la imagen vIOS L2.

| ID CIS | Título resumido | Evaluación en el script | Apply |
|---|---|---|---|
| 1.1.2.1 | Usuario local y contraseña cifrada | Comprueba usuarios locales y `secret`; no revela hashes en el informe. | No |
| 1.1.2.2 | SSH para acceso remoto | Comprueba SSH v2 y VTY con SSH. | No |
| 1.1.2.3 | Transporte SSH en VTY | Comprueba `transport input ssh`. | No |
| 1.1.2.4 | Timeout de sesiones | Comprueba timeout de hasta 10 minutos. | Sí, si `FAIL` |
| 1.1.3.3 | Banner MOTD | Comprueba presencia. | Sí, si `FAIL` |
| 1.1.4.1 | Enable secret | Comprueba presencia de un tipo cifrado reconocido. | Sí, si `FAIL`; solicita secreto nuevo |
| 1.2.2.5 | Prohibir servidor IP HTTP | Comprueba estado del servidor HTTP. | No |
| 1.2.3.6 | Timestamp de debug | Comprueba la línea de configuración. | No |
| 1.2.3.7 | Timestamp de logs | Comprueba la línea de configuración. | No |

## FortiGate 7.0.9

Referencia cercana: **CIS FortiGate 7.0.x Benchmark v1.2.0**, que Fortinet indica que fue probada con FortiOS 7.0.10. El equipo del laboratorio es 7.0.9, por lo que los resultados son orientativos para ese parche.

| ID CIS | Título resumido | Evaluación en el script | Apply |
|---|---|---|---|
| 1.1 | DNS configurado | Comprueba DNS primario. | No: requiere DNS aprobado |
| 2.1.1 | Pre-login banner | Comprueba estado. | Sí, si `FAIL` |
| 2.1.4 | Sincronización NTP | Comprueba NTP habilitado y sincronizado. | No: requiere servidor/alcance |
| 2.1.5 | Hostname | Comprueba nombre personalizado. | Sí, si `FAIL`; propone `FW1` |
| 2.2.2 | Umbral y duración de bloqueo admin | Comprueba 3 intentos o menos y 60 segundos o más. | Sí, si `FAIL`; propone 3/60 |
| 2.4.4 | Timeout inactivo admin | Comprueba timeout de hasta 5 minutos. | Sí, si `FAIL`; propone 5 |
| 2.4.5 | Canales administrativos cifrados | Busca HTTP/Telnet en `allowaccess`. | No: no cambia interfaces ni `port1` |
| 3.2 | Evitar servicio `ALL` en políticas | Busca `set service "ALL"`. | No: requiere revisar uso de cada política |

## Límites del modo Apply

Apply trabaja solo con los controles indicados como `Sí`. Hace un escaneo PRE nuevo y no usa un informe anterior como fuente de estado. Antes de configurar muestra las acciones y requiere escribir `APPLY`; respalda las secciones que modificará y ejecuta un POST. Si un cambio no pasa su verificación, intenta revertir ese control.

Las direcciones DNS, el NTP, los servicios por interfaz y la sustitución de `ALL` dependen de decisiones de diseño/operación. Permanecen manuales. En particular, FortiGate `port1` se conserva. El programa no guarda automáticamente la configuración de inicio.

## Fuentes

- [CIS Cisco IOS Benchmark v2.2](https://www.cisecurity.org/-/jssmedia/Project/cisecurity/cisecurity/data/media/files/uploads/2017/04/CIS_Cisco_IOS_Benchmark_v22.pdf)
- [CIS Fortinet Benchmarks](https://www.cisecurity.org/benchmark/fortinet)
- [Fortinet: ediciones FortiGate 7.0.x y versión de prueba](https://community.fortinet.com/fortigate-3/technical-tip-cis-benchmark-compliance-for-fortigate-200849)
- [FortiOS 7.0.9 CLI: configuración global](https://docs.fortinet.com/document/fortigate/7.0.9/cli-reference/1620/config-system-global)
- [FortiOS 7.0.9: sincronización de tiempo](https://docs.fortinet.com/document/fortigate/7.0.9/administration-guide/336196)
