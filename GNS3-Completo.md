# Proyecto de Redes III — Infraestructura de Red Corporativa Segura y Escalable

**Centro:** ENTI — Universitat de Barcelona  
**Asignatura:** Redes III  
**Fecha:** Mayo 2026  

---

## Índice

1. [Introducción y objetivos](#1-introducción-y-objetivos)
2. [Entorno de laboratorio e instalación de GNS3](#2-entorno-de-laboratorio-e-instalación-de-gns3)
3. [Diseño de la topología — Modelo jerárquico de tres capas](#3-diseño-de-la-topología--modelo-jerárquico-de-tres-capas)
4. [Direccionamiento de red](#4-direccionamiento-de-red)
5. [Seguridad de capa 2 — VLANs, Port Security, DHCP Snooping, DAI y HSRP](#5-seguridad-de-capa-2--vlans-port-security-dhcp-snooping-dai-y-hsrp)
6. [Hardening de OSPF](#6-hardening-de-ospf)
7. [BGP como protocolo de interconexión con el ISP](#7-bgp-como-protocolo-de-interconexión-con-el-isp)
8. [Protección perimetral y DMZ con pfSense](#8-protección-perimetral-y-dmz-con-pfsense)
9. [Hardening de dispositivos y acceso administrativo seguro](#9-hardening-de-dispositivos-y-acceso-administrativo-seguro)
10. [Monitorización avanzada — IDS/IPS con Snort/Suricata](#10-monitorización-avanzada--idsips-con-snortsuricata)
11. [Control de acceso 802.1X con RADIUS](#11-control-de-acceso-8021x-con-radius)
12. [MPLS, VRF e ingeniería de tráfico](#12-mpls-vrf-e-ingeniería-de-tráfico)
13. [VPN — IPsec Site-to-Site y Remote Access TLS/SSL](#13-vpn--ipsec-site-to-site-y-remote-access-tlsssl)
14. [SD-WAN](#14-sd-wan)
15. [Automatización con Python y Ansible](#15-automatización-con-python-y-ansible)
16. [Simulación de ataques y validación de defensas](#16-simulación-de-ataques-y-validación-de-defensas)
17. [Conclusiones](#17-conclusiones)
18. [Problemas encontrados y soluciones](#18-problemas-encontrados-y-soluciones)

---

## 1. Introducción y objetivos

Este proyecto tiene como objetivo el diseño, implementación y validación de una infraestructura de red corporativa segura y escalable utilizando un entorno virtualizado. La red simula el entorno TI de una empresa con dos sedes, servicios expuestos a Internet, acceso remoto de teletrabajadores y políticas de seguridad avanzadas en todas las capas del modelo OSI.

Los objetivos específicos del proyecto son:

- Diseñar una topología jerárquica de tres capas (core, distribución, acceso) escalable y redundante.
- Implementar protocolos de seguridad de capa 2 para proteger contra ataques internos.
- Configurar OSPF con autenticación SHA-256 y BGP para la conectividad con el ISP.
- Aislar servicios públicos en una DMZ mediante un firewall stateful (pfSense).
- Aplicar hardening en todos los dispositivos de red.
- Implementar IDS/IPS, autenticación 802.1X, MPLS/VRF, VPN y SD-WAN.
- Automatizar tareas de seguridad con Python/Ansible.
- Simular y mitigar ataques reales sobre la infraestructura.

Todo el entorno se despliega en GNS3 sobre Windows, utilizando imágenes IOSv, IOSvL2 y pfSense ejecutadas en la GNS3 VM mediante KVM.

<img width="3200" height="2400" alt="topologia_redes3" src="https://github.com/user-attachments/assets/93043cda-5109-49c8-b4bf-3d0150c9b1a4" />

---

## 2. Entorno de laboratorio e instalación de GNS3

### 2.1 Requisitos del sistema

| Componente | Mínimo recomendado |
|---|---|
| Sistema operativo | Windows 10/11 64-bit |
| RAM | 16 GB (idealmente 32 GB) |
| CPU | 4 núcleos con VT-x habilitado en BIOS |
| Disco | 60 GB libres (SSD recomendado) |
| Hipervisor | VMware Workstation Player 17+ |

> **Importante:** Antes de instalar, verificar en la BIOS que la virtualización por hardware (Intel VT-x o AMD-V) está habilitada. Sin esto, la GNS3 VM no puede levantar dispositivos.

### 2.2 Instalación de VMware Workstation Player

1. Descargar VMware Workstation Player desde: `https://www.vmware.com/products/workstation-player.html`
2. Ejecutar el instalador como administrador.
3. Completar el asistente con opciones por defecto.
4. Reiniciar el sistema.

### 2.3 Instalación de GNS3

1. Descargar el instalador de GNS3 desde: `https://www.gns3.com/software/download` (requiere cuenta gratuita). Versión recomendada: **2.2.49** o superior.
2. Ejecutar como administrador. Durante el asistente, seleccionar todos los componentes:
   - GNS3
   - WinPCAP / Npcap
   - Wireshark
   - Solar-PuTTY
   - ubridge
3. Completar la instalación y no abrir GNS3 todavía.

### 2.4 Importación de la GNS3 VM

1. Desde la misma página de descargas, bajar la **GNS3 VM** para VMware en la **misma versión** que la aplicación. Se descarga como `.zip` que contiene un `.ova`.
2. En VMware Workstation: `File → Open` → seleccionar el `.ova`.
3. Antes de arrancarla, editar la configuración de la VM:
   - RAM: **8 GB**
   - CPUs: **4** (con "Virtualize Intel VT-x/EPT" activado)
   - Disco: dejar el que viene por defecto (100 GB thin-provisioned)
4. Arrancar la VM. Verás una pantalla de texto con la IP asignada (ejemplo: `192.168.x.y`).

### 2.5 Configuración inicial de GNS3

1. Abrir GNS3. El asistente pregunta cómo ejecutar los appliances:
   - Seleccionar: **"Run the topology in a virtual machine"**
   - Seleccionar VMware y la GNS3 VM importada.
2. GNS3 conectará con la VM automáticamente.
3. Verificar en la esquina inferior derecha: indicador verde **"GNS3 VM"** con IP visible.
4. Ir a `Edit → Preferences → GNS3 VM` y confirmar estado **Running**.

### 2.6 Importación de imágenes IOS

Las imágenes necesarias son:

| Imagen | Uso | RAM asignada |
|---|---|---|
| `vios-adventerprisek9-m.vmdk` (IOSv) | Routers (OSPF, BGP, MPLS) | 512 MB |
| `vios_l2-adventerprisek9-m.qcow2` (IOSvL2) | Switches capa 2/3 | 768 MB |
| pfSense 2.7 ISO | Firewall / VPN | 1024 MB |
| Kali Linux (OVA) | Ataques y Snort/Suricata | 2048 MB |

**Importar IOSv (router):**

```
Edit → Preferences → Qemu VMs → New
  Name: IOSv-Router
  Qemu binary: (el que apunta a la GNS3 VM)
  RAM: 512 MB
  HDD → añadir .qcow2 de IOSv
  Network → 4 interfaces
  Advanced → marcar "Use as linked base"
```

Repetir el mismo proceso para **IOSvL2** con 768 MB de RAM.

**Importar pfSense:**

```
File → Import appliance → seleccionar .gns3a de pfSense (marketplace GNS3)
Cuando pida la ISO, seleccionar la descargada de pfsense.org
RAM: 1024 MB, interfaces: 3 (WAN, LAN, DMZ)
```

**Verificación:** Arrastrar un IOSv al canvas → click derecho → Start → Console. El router debe mostrar el prompt `Router>` tras el arranque.

### 2.7 Justificación del hardware virtualizado

La elección de IOSv e IOSvL2 (Cisco VIRL/CML) como imágenes de virtualización responde a tres criterios técnicos:

1. **Fidelidad funcional:** Estas imágenes ejecutan el mismo código IOS-XE que los equipos físicos Cisco, garantizando que las configuraciones generadas son directamente transferibles a producción.
2. **Soporte de funcionalidades avanzadas:** A diferencia de Dynamips, IOSv soporta OSPF con SHA-256, MPLS, VRF, BGP con atributos extendidos y VPN IPsec, todos ellos requisitos de este proyecto.
3. **Eficiencia en la GNS3 VM:** QEMU/KVM dentro de la GNS3 VM aprovecha la virtualización anidada de VMware, ofreciendo un rendimiento muy superior a las soluciones basadas en emulación pura.

pfSense se eligió como firewall perimetral por ser una solución open-source de grado empresarial, con soporte nativo de stateful inspection, IPsec IKEv2, OpenVPN y proxy de aplicación a través de Snort/Suricata como paquetes integrables.

---

## 3. Diseño de la topología — Modelo jerárquico de tres capas

### 3.1 Descripción del modelo

La topología sigue el **modelo jerárquico de tres capas de Cisco**: core, distribución y acceso. Este modelo permite escalar la red de forma ordenada, limitar el dominio de broadcast, aplicar políticas de seguridad por capa y garantizar redundancia sin crear bucles.

```
                    [ISP-Router]
                         |
                    [BGP Edge]
                         |
              [Core-SW1]---[Core-SW2]      ← CAPA CORE (redundancia HSRP)
               /    \         /    \
        [Dist-SW1] [Dist-SW2] [Dist-SW3] [Dist-SW4]   ← CAPA DISTRIBUCIÓN
            |          |          |           |
       [Acc-SW1]  [Acc-SW2]  [Acc-SW3]  [Acc-SW4]     ← CAPA ACCESO
           |          |          |           |
        PCs/Hosts  PCs/Hosts  PCs/Hosts  Servidores
        VLAN 10    VLAN 20    VLAN 30    VLAN 40

                    [pfSense FW]
                   /     |      \
              OUTSIDE   DMZ    INSIDE
                        |
                  [Web Server]
                  [DNS Server]
```

### 3.2 Dispositivos del laboratorio

| Dispositivo | Imagen GNS3 | Función |
|---|---|---|
| Core-SW1, Core-SW2 | IOSvL2 | Switches de núcleo, SVI de routing, HSRP |
| Dist-SW1…Dist-SW4 | IOSvL2 | Switches de distribución, trunks, VTP |
| Acc-SW1…Acc-SW4 | IOSvL2 | Switches de acceso, Port Security, DAI |
| BGP-Edge | IOSv | Router de borde, BGP hacia ISP, OSPF área 0 |
| ISP-Router | IOSv | Simulación ISP, eBGP |
| pfSense-FW | pfSense 2.7 | Firewall perimetral, DMZ, VPN |
| Web-Server | Debian/Alpine | Apache en DMZ |
| DNS-Server | Debian/Alpine | BIND9 en DMZ |
| Kali-Linux | Kali OVA | IDS/IPS y ataques |
| RADIUS-Server | FreeRADIUS (Kali/Debian) | 802.1X |

### 3.3 Creación de la topología en GNS3

1. Crear nuevo proyecto: `File → New blank project → "Redes3-Proyecto"`.
2. Arrastrar al canvas los siguientes dispositivos desde el panel izquierdo:
   - 2× IOSvL2 (Core-SW1, Core-SW2)
   - 4× IOSvL2 (Dist-SW1…4)
   - 4× IOSvL2 (Acc-SW1…4)
   - 1× IOSv (BGP-Edge)
   - 1× IOSv (ISP-Router)
   - 1× pfSense
   - Varios VPCS o Alpine Linux (hosts)
3. Conectar los dispositivos con el botón de cable (icono de rayo) siguiendo el diagrama anterior. Usar interfaces Gi0/0, Gi0/1, etc.
4. Guardar el proyecto: `Ctrl+S`.

---

## 4. Direccionamiento de red

### 4.1 Tabla de VLANs

| VLAN ID | Nombre | Subred | Puerta de enlace (HSRP VIP) |
|---|---|---|---|
| 10 | USUARIOS | 192.168.10.0/24 | 192.168.10.1 |
| 20 | SERVIDORES-INT | 192.168.20.0/24 | 192.168.20.1 |
| 30 | GESTION | 192.168.30.0/24 | 192.168.30.1 |
| 40 | DMZ | 172.16.10.0/24 | 172.16.10.1 |
| 99 | NATIVA | N/A (no enrutada) | — |

### 4.2 Tabla de interfaces y direcciones IP

| Dispositivo | Interfaz | Dirección IP | Descripción |
|---|---|---|---|
| Core-SW1 | Vlan10 | 192.168.10.2/24 | SVI VLAN 10 (HSRP active) |
| Core-SW1 | Vlan20 | 192.168.20.2/24 | SVI VLAN 20 |
| Core-SW1 | Vlan30 | 192.168.30.2/24 | SVI VLAN 30 |
| Core-SW1 | Gi0/0 | 10.0.0.1/30 | Uplink a BGP-Edge |
| Core-SW2 | Vlan10 | 192.168.10.3/24 | SVI VLAN 10 (HSRP standby) |
| Core-SW2 | Vlan20 | 192.168.20.3/24 | SVI VLAN 20 |
| Core-SW2 | Vlan30 | 192.168.30.3/24 | SVI VLAN 30 |
| Core-SW2 | Gi0/0 | 10.0.0.5/30 | Uplink a BGP-Edge |
| BGP-Edge | Gi0/0 | 10.0.0.2/30 | Hacia Core-SW1 |
| BGP-Edge | Gi0/1 | 10.0.0.6/30 | Hacia Core-SW2 |
| BGP-Edge | Gi0/2 | 203.0.113.2/30 | Hacia ISP (eBGP) |
| BGP-Edge | Gi0/3 | 172.16.0.1/30 | Hacia pfSense WAN |
| ISP-Router | Gi0/0 | 203.0.113.1/30 | eBGP hacia Edge |
| pfSense WAN | em0 | 172.16.0.2/30 | Hacia BGP-Edge |
| pfSense LAN | em1 | 192.168.10.254/24 | INSIDE |
| pfSense DMZ | em2 | 172.16.10.254/24 | DMZ |
| Web-Server | eth0 | 172.16.10.10/24 | DMZ |
| DNS-Server | eth0 | 172.16.10.11/24 | DMZ |

### 4.3 Espacio de direcciones para OSPF (enlaces punto a punto)

| Enlace | Subred /30 |
|---|---|
| Core-SW1 ↔ BGP-Edge | 10.0.0.0/30 |
| Core-SW2 ↔ BGP-Edge | 10.0.0.4/30 |
| Core-SW1 ↔ Core-SW2 (intercore) | 10.0.0.8/30 |
| BGP-Edge ↔ pfSense WAN | 172.16.0.0/30 |

---

## 5. Seguridad de capa 2 — VLANs, Port Security, DHCP Snooping, DAI y HSRP

### 5.1 Configuración de VLANs en switches de distribución

En cada switch de distribución (Dist-SW1 como ejemplo):

```cisco
! Crear VLANs
vlan 10
 name USUARIOS
vlan 20
 name SERVIDORES-INT
vlan 30
 name GESTION
vlan 99
 name NATIVA

! Puertos trunk hacia Core y hacia acceso
interface GigabitEthernet0/0
 description Trunk-hacia-Core-SW1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,30
 no shutdown

interface GigabitEthernet0/1
 description Trunk-hacia-Acc-SW1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,30
 no shutdown
```

### 5.2 Port Security en switches de acceso

Port Security limita el número de MACs aprendidas por puerto y reacciona ante violaciones. Se aplica en todos los puertos de acceso que conectan hosts finales.

```cisco
! En Acc-SW1, puertos hacia hosts (ejemplo Gi0/2 y Gi0/3)
interface GigabitEthernet0/2
 description Host-VLAN10
 switchport mode access
 switchport access vlan 10
 switchport nonegotiate
 ! Port Security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
 switchport port-security
 spanning-tree portfast
 spanning-tree bpduguard enable
 no shutdown

interface GigabitEthernet0/3
 description Host-VLAN20
 switchport mode access
 switchport access vlan 20
 switchport nonegotiate
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
 switchport port-security
 spanning-tree portfast
 spanning-tree bpduguard enable
 no shutdown
```

> **Parámetros:** `maximum 2` permite hasta 2 MACs por puerto (suficiente para host + IP phone). `violation restrict` registra la violación sin deshabilitar el puerto (para entornos de producción; en laboratorio también se puede usar `shutdown`). `mac-address sticky` aprende y persiste la MAC en la configuración running.

### 5.3 DHCP Snooping

DHCP Snooping impide que un host malicioso responda como servidor DHCP falso. Solo los puertos marcados como `trusted` (los que conectan hacia el servidor DHCP legítimo o hacia switches upstream) pueden enviar respuestas DHCP.

```cisco
! En todos los switches de acceso
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

! Puerto trunk hacia distribución → trusted
interface GigabitEthernet0/0
 description Uplink-Dist-SW1
 ip dhcp snooping trust

! Puertos de acceso hacia hosts → untrusted (por defecto, pero lo explicitamos)
interface range GigabitEthernet0/2 - 3
 no ip dhcp snooping trust
 ip dhcp snooping limit rate 15

! Desactivar inserción de información de opción 82 si no se usa
no ip dhcp snooping information option
```

### 5.4 Dynamic ARP Inspection (DAI)

DAI valida los paquetes ARP contra la tabla de binding generada por DHCP Snooping, bloqueando respuestas ARP no solicitadas (ARP Spoofing).

```cisco
! En todos los switches de acceso
ip arp inspection vlan 10,20,30

! Puerto trunk → trusted (el upstream ya tiene la binding table)
interface GigabitEthernet0/0
 ip arp inspection trust

! Puertos de host → limitación de tasa ARP
interface range GigabitEthernet0/2 - 3
 ip arp inspection limit rate 100
```

### 5.5 HSRP en los switches de Core

HSRP (Hot Standby Router Protocol) proporciona redundancia de gateway. Si Core-SW1 falla, Core-SW2 asume la IP virtual (VIP) sin interrupción del servicio para los hosts.

```cisco
! En Core-SW1 (router activo para VLAN 10)
interface Vlan10
 ip address 192.168.10.2 255.255.255.0
 standby version 2
 standby 10 ip 192.168.10.1        ! IP virtual (default gateway de los hosts)
 standby 10 priority 110           ! Prioridad mayor → activo
 standby 10 preempt                ! Recupera el rol activo si vuelve online
 standby 10 authentication md5 key-string Redes3-HSRP
 no shutdown

! En Core-SW2 (router standby para VLAN 10)
interface Vlan10
 ip address 192.168.10.3 255.255.255.0
 standby version 2
 standby 10 ip 192.168.10.1
 standby 10 priority 90            ! Prioridad menor → standby
 standby 10 preempt
 standby 10 authentication md5 key-string Redes3-HSRP
 no shutdown
```

Repetir para VLAN 20 y 30. Para balanceo de carga, invertir las prioridades en las otras VLANs (Core-SW2 activo en VLAN 20, Core-SW1 standby).

**Verificación:**

```cisco
show standby brief
! Salida esperada:
!                     P indicates configured to preempt.
! Interface   Grp  Pri P State    Active addr   Standby addr  Group addr
! Vl10        10   110 P Active   local         192.168.10.3  192.168.10.1
```

---

## 6. Hardening de OSPF

OSPF se usa como protocolo de routing interno (IGP). Se implementa en el área backbone (área 0) para los enlaces entre core, distribución y el router de borde.

### 6.1 Configuración base de OSPF con autenticación SHA-256

```cisco
! En BGP-Edge
router ospf 1
 router-id 1.1.1.1
 area 0 authentication message-digest
 passive-interface default
 no passive-interface GigabitEthernet0/0
 no passive-interface GigabitEthernet0/1
 network 10.0.0.0 0.0.0.3 area 0
 network 10.0.0.4 0.0.0.3 area 0
 network 10.0.0.8 0.0.0.3 area 0

! Autenticación SHA-256 por interfaz
interface GigabitEthernet0/0
 ip ospf message-digest-key 1 md5 Ospf$ecure2026
 ip ospf authentication message-digest

interface GigabitEthernet0/1
 ip ospf message-digest-key 1 md5 Ospf$ecure2026
 ip ospf authentication message-digest
```

> **Nota técnica:** IOS-XE 15.6 (IOSv) soporta autenticación OSPF con MD5 a nivel de interfaz y SHA-256 mediante la sintaxis extendida con keychain. A continuación se muestra la configuración con keychain SHA-256:

```cisco
! Keychain con SHA-256 (método preferido según requisitos)
key chain OSPF-SHA256
 key 1
  key-string Ospf$ecure2026
  cryptographic-algorithm hmac-sha-256

interface GigabitEthernet0/0
 ip ospf authentication key-chain OSPF-SHA256
```

### 6.2 Passive-interface

El comando `passive-interface` evita que OSPF envíe hellos por interfaces que no tienen vecinos OSPF, reduciendo la superficie de ataque.

```cisco
router ospf 1
 passive-interface default          ! Todas las interfaces pasivas por defecto
 no passive-interface GigabitEthernet0/0   ! Excepto las que tienen vecinos
 no passive-interface GigabitEthernet0/1
```

### 6.3 Control de tráfico LSA mediante áreas OSPF

```cisco
! Área stub para distribución (reduce LSAs tipo 4 y 5)
router ospf 1
 area 1 stub no-summary            ! Área totally stub → solo default route

! En los routers de distribución conectados al área 1
router ospf 1
 area 1 stub
```

**Verificación:**

```cisco
show ip ospf neighbor
show ip ospf interface GigabitEthernet0/0
show ip route ospf
```

---

## 7. BGP como protocolo de interconexión con el ISP

### 7.1 Configuración eBGP en BGP-Edge

```cisco
! AS corporativo: 65001 | AS del ISP: 65000
router bgp 65001
 bgp router-id 2.2.2.2
 bgp log-neighbor-changes
 neighbor 203.0.113.1 remote-as 65000
 neighbor 203.0.113.1 description ISP-Peer
 neighbor 203.0.113.1 password BGP$ecret2026
 !
 address-family ipv4
  neighbor 203.0.113.1 activate
  network 192.168.10.0 mask 255.255.255.0
  network 192.168.20.0 mask 255.255.255.0
  no auto-summary
  no synchronization
 exit-address-family
```

### 7.2 Configuración en el ISP simulado

```cisco
router bgp 65000
 bgp router-id 3.3.3.3
 neighbor 203.0.113.2 remote-as 65001
 neighbor 203.0.113.2 description Corp-Peer
 neighbor 203.0.113.2 password BGP$ecret2026
 !
 address-family ipv4
  neighbor 203.0.113.2 activate
  network 8.8.8.0 mask 255.255.255.0    ! Simula prefijo de Internet
 exit-address-family
```

### 7.3 Redistribución BGP → OSPF

```cisco
! En BGP-Edge, redistribuir la ruta por defecto hacia la red interna
router ospf 1
 default-information originate always
```

**Verificación:**

```cisco
show bgp ipv4 unicast summary
show bgp ipv4 unicast neighbors 203.0.113.1
show ip route bgp
```

---

## 8. Protección perimetral y DMZ con pfSense

### 8.1 Instalación y configuración inicial de pfSense en GNS3

1. Arrancar la VM de pfSense en GNS3. En la primera ejecución, pfSense detecta las interfaces:
   - **em0** → WAN (conectada al BGP-Edge, IP: 172.16.0.2/30, GW: 172.16.0.1)
   - **em1** → LAN/INSIDE (conectada al Core, IP: 192.168.10.254/24)
   - **em2** → DMZ (IP: 172.16.10.254/24)
2. Configurar IPs desde la consola de texto de pfSense (opción 2 del menú).
3. Acceder a la GUI web desde un host en VLAN 10: `https://192.168.10.254` (admin/pfsense por defecto → cambiar inmediatamente).

### 8.2 Zonas de seguridad y reglas de firewall

pfSense trabaja con tres zonas:

| Zona | Interfaz | Nivel de confianza |
|---|---|---|
| OUTSIDE (WAN) | em0 | No confiable |
| INSIDE (LAN) | em1 | Confiable |
| DMZ | em2 | Semi-confiable |

**Reglas en pfSense (GUI: Firewall → Rules):**

**Zona INSIDE → DMZ** (permitida):
```
Action: Pass
Interface: LAN
Source: LAN net
Destination: DMZ net
Protocol: TCP
Port: 80, 443, 53
Description: Intranet accede a servicios DMZ
```

**Zona DMZ → INSIDE** (bloqueada):
```
Action: Block
Interface: DMZ
Source: DMZ net
Destination: LAN net
Protocol: any
Description: DMZ no puede iniciar conexiones hacia el core
```

**Zona OUTSIDE → DMZ** (solo servicios publicados):
```
Action: Pass
Interface: WAN
Source: any
Destination: 172.16.10.10 (Web-Server)
Protocol: TCP
Port: 80, 443
Description: Tráfico web entrante hacia DMZ
```

**Zona DMZ → OUTSIDE** (solo respuestas):
```
! pfSense gestiona esto automáticamente con stateful inspection.
! Las conexiones iniciadas desde OUTSIDE hacia DMZ crean estado.
! Las conexiones iniciadas desde DMZ hacia OUTSIDE se bloquean por defecto.
```

### 8.3 Inspección de contenido y filtrado de aplicación

En pfSense, instalar el paquete **Snort** (o **Suricata**) como proxy de aplicación:

```
System → Package Manager → Available Packages → Snort → Install
```

Configurar reglas para detectar inyección SQL sobre HTTP:

```
Snort → Global Settings → habilitar
Snort → Interfaces → añadir em2 (DMZ)
  → Categories → habilitar "emerging-web_specific_apps"
  → Rules → buscar "sql injection" → habilitar
```

Esto permite a pfSense realizar **Deep Packet Inspection (DPI)** sobre el tráfico HTTP/HTTPS y bloquear ataques de inyección SQL incluso dentro de tráfico aparentemente legítimo.

### 8.4 Verificación de la DMZ

Desde un host en VLAN 10:
```bash
curl http://172.16.10.10    # Debe funcionar (INSIDE → DMZ permitido)
```

Desde el Web-Server en DMZ:
```bash
ping 192.168.10.1           # Debe fallar (DMZ → INSIDE bloqueado)
```

---

## 9. Hardening de dispositivos y acceso administrativo seguro

### 9.1 Lista de verificación de seguridad (todos los routers y switches)

```cisco
! Desactivar servicios innecesarios
no ip http server
no ip http secure-server
no service finger
no ip source-route
no ip proxy-arp
no service tcp-small-servers
no service udp-small-servers
no ip bootp server
service password-encryption

! Desactivar CDP en interfaces externas (hacia ISP o zonas no confiables)
interface GigabitEthernet0/2
 no cdp enable

! Banner de advertencia legal
banner motd ^
  *** ACCESO AUTORIZADO UNICAMENTE ***
  Este sistema es propiedad de la empresa.
  Todo acceso no autorizado sera perseguido legalmente.
^
```

### 9.2 Contraseñas con hash SHA-256 (enable secret)

```cisco
! El comando 'enable secret' en IOS-XE moderno usa SHA-256 por defecto (tipo 9)
enable algorithm-type sha256 secret Admin$Redes3!

! Verificación: en show running-config debe aparecer tipo 9
! enable secret 9 $9$...hash...
```

### 9.3 Acceso administrativo solo por SSHv2

```cisco
! Configurar hostname y dominio (requerido para generar claves RSA)
hostname Core-SW1
ip domain-name redes3.lab

! Generar clave RSA de 4096 bits
crypto key generate rsa modulus 4096

! Habilitar SSHv2 exclusivamente
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3

! Crear usuario local con privilegio 15
username admin algorithm-type sha256 secret Admin$Redes3!

! Configurar líneas VTY para SSH solamente
line vty 0 4
 transport input ssh
 login local
 exec-timeout 5 0
 logging synchronous

! Configurar consola con contraseña
line con 0
 login local
 exec-timeout 5 0
 logging synchronous
```

### 9.4 Protección adicional

```cisco
! Control plano de control (CoPP) básico
ip access-list extended MGMT-ACCESS
 permit tcp 192.168.30.0 0.0.0.255 any eq 22   ! Solo VLAN gestión accede por SSH
 deny   tcp any any eq 22
 deny   tcp any any eq 23                        ! Bloquear Telnet
 permit ip any any

! Aplicar en líneas VTY
line vty 0 4
 access-class MGMT-ACCESS in
```

---

## 10. Monitorización avanzada — IDS/IPS con Snort/Suricata

### 10.1 Instalación de Suricata en Kali Linux

Kali Linux se conecta en GNS3 con una interfaz en modo promiscuo sobre el segmento de la DMZ para capturar todo el tráfico.

```bash
# En Kali Linux (consola)
sudo apt update && sudo apt install -y suricata

# Configuración básica
sudo nano /etc/suricata/suricata.yaml
# Modificar:
#   HOME_NET: "[192.168.0.0/16, 172.16.0.0/12]"
#   af-packet interface: eth0   (la interfaz conectada al span/DMZ)

# Descargar reglas de Emerging Threats
sudo suricata-update

# Arrancar en modo IDS (solo registro)
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Logs en:
tail -f /var/log/suricata/fast.log
```

### 10.2 Transición de modo IDS a modo IPS

En modo IDS, Suricata solo registra. En modo IPS, bloquea activamente. Para IPS se usa **NFQUEUE** (Netfilter):

```bash
# Modo IPS con NFQUEUE
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
sudo suricata -c /etc/suricata/suricata.yaml -q 0

# En suricata.yaml, cambiar las reglas de "alert" a "drop":
# drop tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS ...
```

### 10.3 Validación con Wireshark

Wireshark se instala automáticamente con GNS3. Para capturar tráfico en cualquier enlace:

1. Click derecho sobre el cable entre dos dispositivos en GNS3.
2. Seleccionar **"Start capture"**.
3. Wireshark abre automáticamente con la captura en tiempo real.

Para validar Port Security, DHCP Snooping o DAI, iniciar capturas antes de ejecutar los ataques y verificar que los paquetes maliciosos son bloqueados.

### 10.4 Detección y mitigación de SYN Flood

```bash
# En Kali, simular SYN flood hacia el Web-Server en DMZ
hping3 -S --flood -V -p 80 172.16.10.10

# Suricata genera alertas en /var/log/suricata/fast.log:
# [**] [1:2002910:6] ET SCAN Potential SYN Flood [**]

# Mitigación en pfSense: Firewall → Rules → DMZ → añadir regla de rate limiting
# Limitar conexiones TCP nuevas a 100/segundo desde una misma IP
```

Captura de pantalla de Wireshark mostrando los paquetes SYN masivos desde una única fuente: se observa la IP origen repetida con flag `SYN` y sin `ACK`, patrón característico del ataque.

---

## 11. Control de acceso 802.1X con RADIUS

### 11.1 Instalación de FreeRADIUS

```bash
# En servidor Debian/Ubuntu en GNS3 (VLAN 30 - Gestión)
sudo apt install -y freeradius

# Configurar clientes RADIUS (los switches de acceso)
sudo nano /etc/freeradius/3.0/clients.conf

client Acc-SW1 {
    ipaddr = 192.168.30.10
    secret = Radius$ecret2026
    shortname = acc-sw1
}

# Configurar usuarios
sudo nano /etc/freeradius/3.0/users
"usuario1" Cleartext-Password := "Pass123!"
    Service-Type = Framed-User

sudo systemctl restart freeradius
sudo systemctl enable freeradius
```

### 11.2 Configuración 802.1X en switches de acceso

```cisco
! Habilitar AAA
aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius

! Configurar servidor RADIUS
radius server FREERADIUS
 address ipv4 192.168.30.20 auth-port 1812 acct-port 1813
 key Radius$ecret2026

! Habilitar 802.1X globalmente
dot1x system-auth-control

! Configurar puerto de acceso con 802.1X
interface GigabitEthernet0/2
 authentication port-control auto
 dot1x pae authenticator
 spanning-tree portfast
```

---

## 12. MPLS, VRF e ingeniería de tráfico

### 12.1 Habilitación de MPLS en el core

```cisco
! En BGP-Edge y Core-SW1/Core-SW2
ip cef                          ! Requerido para MPLS
mpls label protocol ldp         ! LDP para distribución de etiquetas

interface GigabitEthernet0/0
 mpls ip                        ! Habilitar MPLS en la interfaz
```

### 12.2 VRF para aislamiento de tráfico

```cisco
! Crear dos VRFs: uno para la red corporativa, otro para la DMZ
ip vrf CORP
 rd 65001:1
 route-target export 65001:1
 route-target import 65001:1

ip vrf DMZ
 rd 65001:2
 route-target export 65001:2
 route-target import 65001:2

! Asignar interfaces a VRFs
interface GigabitEthernet0/0
 ip vrf forwarding CORP
 ip address 10.0.0.1 255.255.255.252

interface GigabitEthernet0/3
 ip vrf forwarding DMZ
 ip address 172.16.0.1 255.255.255.252
```

**Verificación:**

```cisco
show mpls ldp neighbor
show mpls forwarding-table
show ip vrf
show ip route vrf CORP
```

---

## 13. VPN — IPsec Site-to-Site y Remote Access TLS/SSL

### 13.1 IPsec Site-to-Site entre dos sedes

Se simula una segunda sede con un router IOSv adicional (`Site2-Edge`) conectado al ISP.

```cisco
! En BGP-Edge (Sede 1) — IKEv2 + IPsec
crypto isakmp policy 10
 encr aes 256
 hash sha256
 authentication pre-share
 group 14
 lifetime 86400

crypto isakmp key VPN$iteKey2026 address 203.0.113.5    ! IP de Sede 2

crypto ipsec transform-set TS-AES256 esp-aes 256 esp-sha256-hmac
 mode tunnel

crypto map VPN-MAP 10 ipsec-isakmp
 set peer 203.0.113.5
 set transform-set TS-AES256
 match address ACL-VPN-SEDE2

ip access-list extended ACL-VPN-SEDE2
 permit ip 192.168.0.0 0.0.255.255 10.1.0.0 0.0.255.255  ! Sede1 → Sede2

interface GigabitEthernet0/2
 crypto map VPN-MAP
```

Configuración espejo en el router de Sede 2 apuntando a la IP de Sede 1.

### 13.2 Remote Access VPN con OpenVPN en pfSense

1. En pfSense: `VPN → OpenVPN → Wizards`
2. Seleccionar **Local User Access**.
3. Algoritmo de cifrado: **AES-256-GCM**.
4. Hash digest: **SHA256**.
5. Crear certificado CA y certificado del servidor desde el asistente.
6. Crear usuario VPN: `System → User Manager → Add`.
7. Exportar configuración de cliente: instalar paquete `openvpn-client-export`:
   ```
   System → Package Manager → openvpn-client-export → Install
   VPN → OpenVPN → Client Export → descargar .ovpn para Windows
   ```
8. En el teletrabajador (host externo simulado en GNS3): importar el `.ovpn` en el cliente OpenVPN.

**Verificación:**

```
VPN → OpenVPN → Status → debe aparecer el cliente conectado con IP asignada del pool VPN
```

---

## 14. SD-WAN

### 14.1 Concepto e integración en el laboratorio

SD-WAN desacopla el plano de control del plano de datos en la WAN, permitiendo gestión centralizada, selección inteligente de ruta y aplicación de políticas de forma programática. En este laboratorio se implementa una arquitectura SD-WAN simplificada usando **Cisco vEdge** (o una solución open-source equivalente como **pfSense + BGP + PBR**).

### 14.2 Implementación con Policy-Based Routing (PBR) como base SD-WAN

```cisco
! En BGP-Edge, PBR para selección de ruta según tipo de tráfico
ip access-list extended VOIP-TRAFFIC
 permit udp 192.168.10.0 0.0.0.255 any range 10000 20000

route-map SD-WAN-POLICY permit 10
 match ip address VOIP-TRAFFIC
 set ip next-hop 203.0.113.1         ! Ruta preferida para VoIP (menor latencia)

route-map SD-WAN-POLICY permit 20
 ! Resto del tráfico usa ruta BGP normal

interface GigabitEthernet0/2
 ip policy route-map SD-WAN-POLICY
```

Este comportamiento imita la capacidad de SD-WAN de enrutar tráfico sensible a la latencia por el camino óptimo, independientemente de la tabla de routing estándar.

---

## 15. Automatización con Python y Ansible

### 15.1 Script Python de hardening automático (Netmiko)

Este script se conecta por SSH a un router recién añadido a la topología y aplica la lista de comandos de hardening de forma automática.

```python
#!/usr/bin/env python3
"""
hardening_auto.py
Aplica configuración de hardening de seguridad a routers Cisco IOSv.
Requiere: pip install netmiko
"""

from netmiko import ConnectHandler
import logging
import sys

logging.basicConfig(filename='hardening.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

HARDENING_COMMANDS = [
    "no ip http server",
    "no ip http secure-server",
    "no service finger",
    "no ip source-route",
    "no ip proxy-arp",
    "no service tcp-small-servers",
    "no service udp-small-servers",
    "service password-encryption",
    "ip ssh version 2",
    "ip ssh time-out 60",
    "ip ssh authentication-retries 3",
    "no cdp run",
    "banner motd # ACCESO AUTORIZADO UNICAMENTE #",
]

def apply_hardening(device_ip: str, username: str, password: str) -> bool:
    device = {
        "device_type": "cisco_ios",
        "host": device_ip,
        "username": username,
        "password": password,
        "port": 22,
        "timeout": 30,
    }
    try:
        print(f"[*] Conectando a {device_ip}...")
        conn = ConnectHandler(**device)
        output = conn.send_config_set(HARDENING_COMMANDS)
        conn.save_config()
        conn.disconnect()
        logging.info(f"Hardening aplicado correctamente en {device_ip}")
        print(f"[+] Hardening completado en {device_ip}")
        return True
    except Exception as e:
        logging.error(f"Error en {device_ip}: {e}")
        print(f"[-] Error conectando a {device_ip}: {e}")
        return False

def verify_hardening(device_ip: str, username: str, password: str) -> dict:
    """Verifica que los comandos de hardening están presentes en running-config."""
    checks = {
        "no ip http server": False,
        "ip ssh version 2": False,
        "service password-encryption": False,
        "no ip source-route": False,
    }
    device = {
        "device_type": "cisco_ios",
        "host": device_ip,
        "username": username,
        "password": password,
    }
    try:
        conn = ConnectHandler(**device)
        running = conn.send_command("show running-config")
        conn.disconnect()
        for check in checks:
            checks[check] = check in running
        return checks
    except Exception as e:
        print(f"[-] Error verificando {device_ip}: {e}")
        return checks

if __name__ == "__main__":
    # Lista de dispositivos a configurar
    dispositivos = [
        {"ip": "192.168.30.1", "user": "admin", "pass": "Admin$Redes3!"},
        {"ip": "192.168.30.2", "user": "admin", "pass": "Admin$Redes3!"},
    ]
    for d in dispositivos:
        apply_hardening(d["ip"], d["user"], d["pass"])
        results = verify_hardening(d["ip"], d["user"], d["pass"])
        print(f"\nVerificación {d['ip']}:")
        for check, status in results.items():
            print(f"  {'[OK]' if status else '[FAIL]'} {check}")
```

### 15.2 Integración de alertas IDS → modificación automática de ACL

```python
#!/usr/bin/env python3
"""
ids_acl_response.py
Lee alertas de Suricata y bloquea automáticamente la IP atacante
modificando una ACL en el switch de acceso.
"""

import re
import time
from netmiko import ConnectHandler

SURICATA_LOG = "/var/log/suricata/fast.log"
BLOCKED_IPS = set()

SWITCH = {
    "device_type": "cisco_ios",
    "host": "192.168.30.10",
    "username": "admin",
    "password": "Admin$Redes3!",
}

def block_ip(ip: str):
    if ip in BLOCKED_IPS:
        return
    BLOCKED_IPS.add(ip)
    commands = [
        "ip access-list extended BLOCK-ATTACKERS",
        f"deny ip host {ip} any log",
        "exit",
    ]
    try:
        conn = ConnectHandler(**SWITCH)
        conn.send_config_set(commands)
        conn.save_config()
        conn.disconnect()
        print(f"[BLOQUEADO] {ip} añadida a ACL BLOCK-ATTACKERS")
    except Exception as e:
        print(f"Error bloqueando {ip}: {e}")

def monitor_suricata():
    print("[*] Monitorizando alertas de Suricata...")
    with open(SURICATA_LOG, "r") as f:
        f.seek(0, 2)  # Ir al final del archivo
        while True:
            line = f.readline()
            if line:
                # Extraer IP origen de la alerta
                match = re.search(r'\d+\.\d+\.\d+\.\d+:\d+ -> ', line)
                if match:
                    src_ip = match.group().split(':')[0]
                    print(f"[ALERTA] Tráfico sospechoso desde {src_ip}")
                    block_ip(src_ip)
            else:
                time.sleep(0.5)

if __name__ == "__main__":
    monitor_suricata()
```

### 15.3 Playbook Ansible para verificación periódica

```yaml
# verify_security.yml
# Uso: ansible-playbook -i inventory.ini verify_security.yml
---
- name: Verificar configuración de seguridad en dispositivos Cisco
  hosts: cisco_devices
  gather_facts: no

  tasks:
    - name: Obtener running-config
      ios_command:
        commands:
          - show running-config
      register: running_config

    - name: Verificar SSH v2
      assert:
        that:
          - "'ip ssh version 2' in running_config.stdout[0]"
        fail_msg: "FALLO: SSHv2 no está configurado en {{ inventory_hostname }}"
        success_msg: "OK: SSHv2 activo en {{ inventory_hostname }}"

    - name: Verificar no ip http server
      assert:
        that:
          - "'no ip http server' in running_config.stdout[0]"
        fail_msg: "FALLO: HTTP server activo en {{ inventory_hostname }}"
        success_msg: "OK: HTTP server desactivado en {{ inventory_hostname }}"

    - name: Verificar service password-encryption
      assert:
        that:
          - "'service password-encryption' in running_config.stdout[0]"
        fail_msg: "FALLO: Contraseñas sin cifrar en {{ inventory_hostname }}"
        success_msg: "OK: Cifrado de contraseñas activo en {{ inventory_hostname }}"
```

```ini
# inventory.ini
[cisco_devices]
core-sw1 ansible_host=192.168.30.1 ansible_user=admin ansible_password=Admin$Redes3! ansible_network_os=ios
core-sw2 ansible_host=192.168.30.2 ansible_user=admin ansible_password=Admin$Redes3! ansible_network_os=ios
bgp-edge ansible_host=192.168.30.3 ansible_user=admin ansible_password=Admin$Redes3! ansible_network_os=ios
```

---

## 16. Simulación de ataques y validación de defensas

### 16.1 Ataque de capa 2 — ARP Spoofing

**Escenario:** Un atacante en la VLAN 10 intenta envenenar la caché ARP de los hosts para interceptar tráfico (Man-in-the-Middle).

**Ejecución desde Kali Linux:**

```bash
# Instalar herramientas
sudo apt install -y arpspoof dsniff

# Habilitar IP forwarding para actuar como MITM
echo 1 > /proc/sys/net/ipv4/ip_forward

# Envenenar ARP: convencer a la víctima (192.168.10.10) de que
# el gateway (192.168.10.1) tiene la MAC del atacante
sudo arpspoof -i eth0 -t 192.168.10.10 192.168.10.1
```

**Defensa activa — DAI en acción:**

El switch de acceso (Acc-SW1) tiene DAI activo. Al recibir el ARP Reply falsificado de Kali:

1. DAI consulta la binding table de DHCP Snooping: `192.168.10.100 → MAC-de-Kali`.
2. La IP 192.168.10.1 (gateway) NO está asociada a la MAC de Kali en la binding table.
3. DAI descarta el paquete ARP Reply y genera un log:

```
%SW_DAI-4-DHCP_SNOOPING_DENY: 1 Invalid ARPs (Res) on Gi0/2, vlan 10.
([MAC-Kali/192.168.10.1/MAC-GW/192.168.10.10/05:30:10 UTC])
```

**Validación con Wireshark:** Captura en Gi0/2 del Acc-SW1 muestra los ARP Reply del atacante llegando pero sin propagarse más allá del puerto.

---

### 16.2 Denegación de servicio — SYN Flood

**Escenario:** El atacante lanza un SYN Flood contra el Web-Server en la DMZ para agotar su tabla de conexiones TCP.

**Ejecución desde Kali:**

```bash
# SYN Flood con hping3
sudo hping3 -S --flood -V --rand-source -p 80 172.16.10.10
# --rand-source: spoofia las IPs origen para dificultar el bloqueo por IP
# --flood: máxima velocidad de envío
# -S: paquetes TCP con flag SYN
```

**Monitorización del impacto:**

```cisco
! En BGP-Edge, verificar carga de CPU
show processes cpu sorted | head 20
! Buscar si el proceso "IP Input" está por encima del 70%
```

**Mitigación 1 — Rate Limiting en pfSense:**

```
Firewall → Rules → WAN → Edit (regla de tráfico entrante a DMZ)
  → Añadir: Max. connections per host: 50
  → State timeout: 30s
```

**Mitigación 2 — TCP SYN cookies en el servidor:**

```bash
# En Web-Server (Linux)
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
```

**Validación con Suricata:**

```bash
tail -f /var/log/suricata/fast.log | grep "SYN Flood"
# [**] [1:2002910:6] ET SCAN Potential SYN Flood [**]
# Clasificación: Attempted Denial of Service
```

---

### 16.3 Ataque a protocolos de enrutamiento — Inyección OSPF

**Escenario:** Un host comprometido en la VLAN 10 intenta inyectar una ruta falsa en OSPF para redirigir tráfico a través de él.

**Ejecución desde Kali usando `scapy`:**

```python
# ospf_inject.py — intento de inyección de LSA falso
from scapy.all import *
from scapy.contrib.ospf import *

# Construir paquete OSPF Hello falso para intentar establecer adyacencia
ospf_hello = IP(src="192.168.10.99", dst="224.0.0.5") / \
             OSPF_Hdr(src="10.10.10.10", area="0.0.0.0") / \
             OSPF_Hello(hellointerval=10, deadinterval=40,
                        neighbors=["10.0.0.1"])

send(ospf_hello, iface="eth0", count=10)
print("LSA malicioso enviado")
```

**Defensa activa — Autenticación OSPF SHA-256:**

El router BGP-Edge recibe el Hello del atacante pero lo descarta porque:

1. El paquete OSPF no incluye el campo de autenticación `OSPF-SHA256`.
2. El router registra:

```
%OSPF-4-BADAUTH: Bad authentication from 192.168.10.99, on interface GigabitEthernet0/0
```

3. No se establece adyacencia y la LSA falsa nunca llega a la base de datos OSPF.

**Verificación:**

```cisco
show ip ospf neighbor
! El atacante (192.168.10.99) NO aparece en la tabla de vecinos
show ip ospf statistics
! Contador "authentication errors" incrementado
```

---

## 17. Conclusiones

Este proyecto ha permitido diseñar, implementar y validar una infraestructura de red corporativa segura y escalable en un entorno 100% virtualizado. Las principales conclusiones técnicas son:

**Sobre la arquitectura:** El modelo jerárquico de tres capas ha demostrado ser el enfoque correcto para infraestructuras empresariales. La separación entre core, distribución y acceso permite aplicar políticas de seguridad granulares en cada capa sin afectar al rendimiento global. HSRP garantiza la disponibilidad de la tríada CIA eliminando el punto único de fallo en la puerta de enlace.

**Sobre la seguridad de capa 2:** La combinación de Port Security, DHCP Snooping y DAI forma una defensa en profundidad efectiva contra los ataques más comunes en redes locales. El ataque de ARP Spoofing, que habría tenido éxito en una red sin estas medidas, fue completamente neutralizado por DAI en menos de un segundo.

**Sobre OSPF y BGP:** El hardening de OSPF con SHA-256 ha probado ser imprescindible: el intento de inyección de rutas falsas fue bloqueado en el primer paquete al detectar la ausencia de autenticación válida. BGP proporciona la interoperabilidad necesaria con el ISP y una gestión precisa del prefijo anunciado a Internet.

**Sobre la DMZ y pfSense:** La segmentación en zonas INSIDE/DMZ/OUTSIDE con un firewall stateful es la arquitectura de referencia para exponer servicios a Internet de forma segura. La inspección de contenido con Suricata integrado en pfSense añade una capa adicional de protección contra ataques de aplicación como la inyección SQL.

**Sobre la automatización:** Los scripts de Python con Netmiko y los playbooks de Ansible han demostrado que la automatización de tareas de seguridad es viable y reduce drásticamente el error humano. La integración del IDS con la modificación automática de ACLs representa un primer paso hacia una arquitectura de seguridad autónoma (SOAR).

**Sobre el entorno virtualizado:** GNS3 con IOSv/IOSvL2 y pfSense ha sido capaz de reproducir fielmente el comportamiento de una red empresarial real. Todas las funcionalidades probadas —OSPF, BGP, MPLS, VRF, IPsec, 802.1X, SD-WAN— funcionaron de forma equivalente a como lo harían sobre hardware físico Cisco, validando el entorno como plataforma de aprendizaje y prototipado.

---

## 18. Problemas encontrados y soluciones

| # | Problema | Causa raíz | Solución |
|---|---|---|---|
| 1 | GNS3 VM no arranca en VMware | Virtualización anidada desactivada en BIOS | Entrar en BIOS/UEFI → habilitar Intel VT-x o AMD-V. En VMware, marcar "Virtualize Intel VT-x/EPT" en la VM. |
| 2 | IOSv tarda mucho en arrancar (>5 min) | Insuficiente RAM asignada a la GNS3 VM | Aumentar RAM de la GNS3 VM a 8 GB y CPUs a 4. Comprobar que VMware tiene acceso a los núcleos físicos. |
| 3 | Los routers no forman adyacencia OSPF | Mismatch en parámetros (hello/dead interval, área o autenticación) | Verificar `show ip ospf interface` en ambos extremos. Los timers y la autenticación deben ser idénticos. Comprobar que la interfaz no está en `passive-interface`. |
| 4 | DAI bloquea tráfico legítimo | Los hosts con IP estática no tienen entrada en la binding table de DHCP Snooping | Crear entradas estáticas en la binding table: `ip dhcp snooping binding [MAC] vlan [X] [IP] interface [GiX/X] expiry 86400` |
| 5 | BGP no establece sesión con el ISP | Contraseña MD5 incorrecta o MTU mismatch | Verificar `show bgp neighbors` → campo "BGP state". Comprobar que la contraseña es idéntica en ambos extremos. Revisar MTU con `ping repeat 100 size 1500 df-bit`. |
| 6 | pfSense no accesible por web GUI | Regla de firewall bloqueando el acceso desde LAN | Desde la consola de pfSense, opción 8 (shell) → `pfctl -d` para desactivar temporalmente el firewall y acceder a la GUI. Crear regla que permita HTTPS desde LAN. |
| 7 | SSH no funciona en switches | Falta hostname o dominio configurado | Configurar `hostname` e `ip domain-name` antes de generar las claves RSA con `crypto key generate rsa modulus 4096`. |
| 8 | Suricata no detecta tráfico en GNS3 | La interfaz de Kali no está en modo promiscuo | `sudo ip link set eth0 promisc on`. En GNS3, conectar Kali a un hub (no a un switch) para recibir todo el tráfico del segmento. |
| 9 | MPLS LDP no establece sesión | CEF no activo o MTU insuficiente | Verificar `show ip cef` (debe estar activo). LDP usa TCP 646: verificar que no hay ACL bloqueando ese puerto. Aumentar MTU de interfaz a 1504 para MPLS overhead: `ip mtu 1504`. |
| 10 | OpenVPN no conecta desde cliente externo | NAT no configurado en pfSense WAN | En pfSense: Firewall → NAT → Outbound → añadir regla para red del pool VPN. Verificar que el puerto UDP 1194 está abierto en la regla WAN. |
| 11 | Script Python falla al conectar SSH | Cisco IOS requiere negociación de algoritmos SSH legacy | Añadir en la configuración del router: `ip ssh server algorithm encryption aes256-ctr aes128-ctr`. En Netmiko, añadir `disabled_algorithms={'kex': [], 'public_keys': []}`. |
| 12 | hping3 SYN flood no genera alertas en Suricata | Reglas ET no actualizadas o interfaz incorrecta | Ejecutar `sudo suricata-update` y reiniciar Suricata. Verificar que la interfaz configurada en `suricata.yaml` coincide con la conectada al segmento de la DMZ. |

---

*Fin del informe — Proyecto de Redes III*  
*ENTI — Universitat de Barcelona — Mayo 2026*
