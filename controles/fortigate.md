# Referencia FortiGate 7.0.x

## Selección de versión

El equipo del laboratorio informa FortiOS 7.0.9. La referencia próxima empleada es CIS FortiGate 7.0.x Benchmark v1.2.0: Fortinet indica que esa edición se redactó y probó con 7.0.10. El informe por ello identifica la diferencia y no presenta el resultado como validación exacta.

## Controles automatizados

El script lee DNS, configuración global, estado NTP, interfaces, políticas y estado/hostname del sistema. Evalúa los IDs `1.1`, `2.1.1`, `2.1.4`, `2.1.5`, `2.2.2`, `2.4.4`, `2.4.5` y `3.2`. La lista y los límites exactos están en [alcance_cis.md](alcance_cis.md).

Apply solo cubre pre-login banner, hostname, bloqueo de administradores y timeout inactivo. No cambia direcciones DNS, NTP, políticas ni interfaces. `port1` queda fuera de los cambios.

## Referencias

- [CIS Fortinet Benchmarks](https://www.cisecurity.org/benchmark/fortinet)
- [Fortinet: benchmark FortiGate 7.0.x y versión probada](https://community.fortinet.com/fortigate-3/technical-tip-cis-benchmark-compliance-for-fortigate-200849)
- [CLI FortiOS 7.0.9: `config system global`](https://docs.fortinet.com/document/fortigate/7.0.9/cli-reference/1620/config-system-global)
- [FortiOS 7.0.9: NTP](https://docs.fortinet.com/document/fortigate/7.0.9/administration-guide/336196)
