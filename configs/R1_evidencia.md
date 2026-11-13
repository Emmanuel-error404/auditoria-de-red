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

## Running config

R1#show running-config
Building configuration...

Current configuration : 1241 bytes
!
! Last configuration change at 19:27:45 UTC Fri Nov 13 2026 by auditor
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname R1
!
boot-start-marker
boot-end-marker
!
!
enable secret 5 $1$XPh/$kAiomueHgirPRv2C2L.ge0
!
no aaa new-model
no ip icmp rate-limit unreachable
!
!
!
!
!
!
no ip domain lookup
ip domain name lab.local
ip cef
no ipv6 cef
!
!
multilink bundle-name authenticated
!
!
!
!
!
!
!
username auditor privilege 15 secret 5 $1$qZ3H$veT3GnazpSeOSGC5ntAqI.
!
!
!
!
!
ip tcp synwait-time 5
ip ssh version 2
!
!
!
!
!
!
!
!
!
interface FastEthernet0/0
 description ENLACE_HACIA_FORTIGATE_PORT2
 ip address 10.20.79.1 255.255.255.252
 duplex full
!
interface GigabitEthernet1/0
 no ip address
 shutdown
 negotiation auto
!
ip forward-protocol nd
!
!
no ip http server
no ip http secure-server
ip route 10.20.98.0 255.255.255.0 10.20.79.2
!
!
!
!
control-plane
!
banner motd ^CAVISO: Acceso exclusivo a usuarios autorizados. La actividad puede ser supervisada.^C
!
line con 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line aux 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line vty 0 4
 login local
 transport input ssh
!
!
end
