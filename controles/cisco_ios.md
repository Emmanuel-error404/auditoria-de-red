# Referencia Cisco IOS

## Selección

Se usa CIS Cisco IOS Benchmark v2.2, Level 1, porque es la referencia genérica archivada más cercana disponible para las imágenes del laboratorio (router Cisco 7200 y Cisco vIOS L2, IOS 15.2). No se presenta como un benchmark de versión/modelo exactos.

El script comprueba los nueve IDs indicados en [alcance_cis.md](alcance_cis.md). Apply cubre únicamente timeout VTY `1.1.2.4`, enable secret `1.1.4.1` y banner MOTD `1.1.3.3`, si cada uno resulta `FAIL`.

## Evidencias empleadas

- `show version`: versión/modelo observado.
- `show running-config`: usuarios locales (sin copiar hashes al informe), enable secret, banner, VTY y servicios/timestamps.
- `show ip ssh`: estado y versión SSH.
- `show ip http server status`: estado del servidor HTTP.

## Referencia

[CIS Cisco IOS Benchmark v2.2 (PDF)](https://www.cisecurity.org/-/jssmedia/Project/cisecurity/cisecurity/data/media/files/uploads/2017/04/CIS_Cisco_IOS_Benchmark_v22.pdf)
