# SW1 — Cisco vIOS L2

> Evidencia parcial; este archivo no es una copia de `show running-config`.

## Datos confirmados

- Plataforma: Cisco vIOS L2, IOS 15.2.
- VLAN 1: `10.20.98.2/24`, estado `up/up` en la captura.
- La captura de `show vlan brief` ubica `Gi0/0` y `Gi0/1` en la VLAN 1.
- El informe posterior a la ejecución compartida muestra SSH v2, transporte VTY SSH, timeout efectivo de 10 minutos, enable secret y banner MOTD como `PASS`.
- El mismo informe muestra el servidor HTTP habilitado (`1.2.2.5`, `FAIL`).

## Running config 
Switch#show running-config
Building configuration...

Current configuration : 2907 bytes
!
! Last configuration change at 19:27:12 UTC Fri Nov 13 2026 by auditor
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
service compress-config
!
hostname Switch
!
boot-start-marker
boot-end-marker
!
!
enable secret 5 $1$FAjo$lUfXoEzsTCXyIShX5A5iJ0
!
username auditor privilege 15 secret 5 $1$BlHZ$HUASuwG.mL7FVeNSBp7mu0
no aaa new-model
!
!
!
!
!
!
!
!
ip domain-name lab.local
ip cef
no ipv6 cef
!
!
!
spanning-tree mode pvst
spanning-tree extend system-id
!
!
!
!
!
!
!
!
!
!
!
!
!
!
!
interface GigabitEthernet0/0
 negotiation auto
!
interface GigabitEthernet0/1
 negotiation auto
!
interface Vlan1
 ip address 10.20.98.2 255.255.255.0
!
ip default-gateway 10.20.98.1
ip forward-protocol nd
!
ip http server
ip http secure-server
!
ip ssh version 2
ip ssh server algorithm encryption aes128-ctr aes192-ctr aes256-ctr
ip ssh client algorithm encryption aes128-ctr aes192-ctr aes256-ctr
!
!
!
!
!
!
control-plane
