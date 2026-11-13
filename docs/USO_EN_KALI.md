# Guía de ejecución en Kali Linux

## 1. Preparar entorno

Abre la terminal en la raíz del repositorio. Si ya tienes un `venv` con Netmiko, puedes reutilizarlo. Para una instalación nueva:

```bash
python3 -m venv venv
./venv/bin/python -m pip install -r requirements.txt
```

## 2. Confirmar red y conectividad

La interfaz de Kali conectada al laboratorio es `eth0` (`10.20.98.10/24`). Muestra interfaz y rutas:

```bash
ip -br addr
ip route
```

Prueba los destinos del laboratorio:

```bash
ping -c 4 10.20.98.1
ping -c 4 10.20.98.2
ping -c 4 10.20.79.1
```

Los destinos son FortiGate port3, SW1 VLAN 1 y R1 respectivamente. Si R1 no responde, comprueba la ruta y las políticas de tránsito del laboratorio.

## 3. Audit Only (sin cambios)

```bash
./venv/bin/python scripts/auditor.py --mode audit --phase PRE
```

El programa solicita el usuario y contraseña SSH de R1, SW1 y FW1. La contraseña se lee de forma oculta y no se registra. Este modo consulta el estado y crea informes; no envía comandos de configuración.

## 4. Plan de sugerencias (sin cambios)

```bash
./venv/bin/python scripts/auditor.py --mode plan --phase PRE
```

Hace un nuevo escaneo y enumera una sugerencia para cada control fallido. Guarda `report.json`, `report.csv`, `report.html` y evidencia de lectura. No envía comandos de configuración.

## 5. Apply (modifica configuración activa)

```bash
./venv/bin/python scripts/auditor.py --mode apply
```

El modo Apply no toma decisiones a partir del informe antiguo: hace un PRE nuevo. Para un `enable secret` ausente pide una clave distinta por dispositivo Cisco, con mínimo 12 caracteres y confirmación. Después prepara los cambios compatibles, crea un respaldo local privado y presenta los dispositivos/controles. Escribe `APPLY` solo si aceptas el plan; cualquier otra respuesta cancela.

Apply intenta modificar solo controles fallidos con acción implementada. Tras enviar cambios hace POST, verifica esos controles y trata de revertir individualmente los que no pasen. Algunos controles quedan como revisión manual, según [alcance CIS](../controles/alcance_cis.md).

No se modifica FortiGate port1 ni se ejecuta `write memory`. Los cambios de Cisco quedan en running-config hasta que se guarden manualmente; conserva el respaldo local privado.

## 6. Abrir informes y comparar

Cada ejecución imprime una carpeta como `reports/20261113_142642`. Abre el HTML usando la ruta que te muestre la terminal:

```bash
xdg-open reports/<FECHA_HORA>/report.html
```

Apply produce PRE y POST en la misma ejecución. Para hacer otra auditoría POST independiente y compararla con ese informe:

```bash
./venv/bin/python scripts/auditor.py --mode audit --phase POST --compare-to reports/<CARPETA_APPLY>/report.json
```

Sustituye `<CARPETA_APPLY>` por el nombre real de la carpeta Apply. Los archivos de `reports/` y `backups/` pueden contener información sensible y se excluyen de Git.
