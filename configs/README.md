# Configuraciones/evidencia de los dispositivos

Esta carpeta contiene una ficha por cada dispositivo de la práctica. Son resúmenes **parciales basados en capturas e informes compartidos**, no archivos de configuración completos.

- [R1 — Cisco 7200](R1_evidencia.md)
- [SW1 — Cisco vIOS L2](SW1_evidencia.md)
- [FW1 — FortiGate 7.0.9](FW1_evidencia.md)

No se recibieron volcados finales completos de `show running-config` para los Cisco ni exportación íntegra del FortiGate. Por esa razón no se fabrican `.cfg` ni se presenta la configuración PRE antigua del router como si fuese actual.

Si agregas configuraciones completas, guarda copias sanitizadas y documenta equipo, versión, fase y fecha. Elimina usuarios, hashes, secretos, PSK, certificados privados, comunidades SNMP, tokens y datos externos sensibles. Nunca subas directamente `reports/` o `backups/`.
