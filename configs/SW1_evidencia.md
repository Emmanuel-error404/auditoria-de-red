# SW1 — Cisco vIOS L2

> Evidencia parcial; este archivo no es una copia de `show running-config`.

## Datos confirmados

- Plataforma: Cisco vIOS L2, IOS 15.2.
- VLAN 1: `10.20.98.2/24`, estado `up/up` en la captura.
- La captura de `show vlan brief` ubica `Gi0/0` y `Gi0/1` en la VLAN 1.
- El informe posterior a la ejecución compartida muestra SSH v2, transporte VTY SSH, timeout efectivo de 10 minutos, enable secret y banner MOTD como `PASS`.
- El mismo informe muestra el servidor HTTP habilitado (`1.2.2.5`, `FAIL`).

## No incluido

La evidencia recibida no contiene un `show running-config` completo de SW1. No se inventan comandos ni los valores de configuración restantes. Agrega un volcado actual únicamente después de ocultar hashes, contraseñas, claves y datos que no deban publicarse.
