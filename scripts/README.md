# Scripts

## `auditor.py`

Auditor de un solo archivo que usa Netmiko para leer la configuración de R1, SW1 y FW1 y producir informes JSON, CSV y HTML con evidencia.

Ejecuta los comandos desde la raíz del repositorio para que las carpetas `reports/` y `backups/` queden en el nivel principal:

```bash
./venv/bin/python scripts/auditor.py --mode audit --phase PRE
./venv/bin/python scripts/auditor.py --mode plan --phase PRE
./venv/bin/python scripts/auditor.py --mode apply
```

`audit` y `plan` son de solo lectura. `apply` vuelve a auditar, enseña las acciones soportadas y requiere confirmación explícita. Los cambios se mantienen en running-config; el programa no ejecuta `write memory`.

El script usa las direcciones del laboratorio definidas en `DEVICES`. Las contraseñas nunca se configuran en el código; se solicitan con `getpass`.
