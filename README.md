# 02-arp-mitm
Ataque MitM mediante ARP Spoofing

## Objetivo del Laboratorio
Demostrar cómo un atacante puede interceptar el tráfico entre una
víctima y su gateway envenenando las tablas ARP de ambos, logrando
posicionarse como intermediario (Man-in-the-Middle) sin que la
víctima lo detecte.

---

## Objetivo del Script
Realizar un ataque ARP Spoofing bidireccional para interceptar,
leer y potencialmente modificar todo el tráfico entre la víctima
y el gateway.

### Parámetros

| Parámetro | Descripción | Default |
|-----------|-------------|---------|
| `-i` | Interfaz de red (ej: ens3) | Obligatorio |
| `-v` | IP de la víctima | Obligatorio |
| `-g` | IP del gateway | Obligatorio |
| `-t` | Intervalo de reenvío ARP (seg) | 2.0 |
| `-s` | Capturar tráfico interceptado | False |
| `-o` | Archivo de salida PCAP | captura_mitm.pcap |


### Requisitos
- Sistema operativo: Kali Linux / Ubuntu
- Python 3.8+
- Scapy: `pip3 install scapy`
- Privilegios root

## Topologia de red
<img width="512" height="356" alt="image" src="https://github.com/user-attachments/assets/d1368c9d-9307-4ca1-b260-40b8935e4a2d" />

| Dispositivo | Interfaz | IP |
|---|---|---|
| Ubuntu-Atacante | ens3 | 192.168.67.50/24 |
| SW-Core | e0/0 - e0/1 | — |
| Linux-Victima | ens3 | 192.168.67.60/24 |

## Funcionamiento del Script

1. Resuelve la MAC real de la víctima y el gateway mediante ARP
2. Habilita IP forwarding para mantener conectividad de la víctima
3. Envía ARP Reply falso a la víctima: *"El gateway soy yo"*
4. Envía ARP Reply falso al gateway: *"La víctima soy yo"*
5. Repite cada `interval` segundos para mantener el envenenamiento
6. Al detener con Ctrl+C restaura las tablas ARP correctas

## Uso

```bash
# Ataque básico
sudo python3 arp_mitm.py -i ens3 -v 192.168.67.60 -g 192.168.67.1

# Con captura de tráfico
sudo python3 arp_mitm.py -i ens3 -v 192.168.67.60 -g 192.168.67.1 -s -o trafico.pcap

# Con intervalo de reenvío personalizado
sudo python3 arp_mitm.py -i ens3 -v 192.168.67.60 -g 192.168.67.1 -t 1.0
```

### Verificar el ataque desde la víctima
```bash
# La MAC del gateway debe apuntar al atacante
arp -a

# El tráfico debe pasar por el atacante
traceroute 8.8.8.8
```

---

## Contramedidas

### En el switch Cisco
```cisco
! Dynamic ARP Inspection — valida ARP contra tabla DHCP Snooping
ip arp inspection vlan 1,10,20
!
! Puertos confiables (uplinks)
interface GigabitEthernet0/1
 ip arp inspection trust
!
! Límite de tasa en puertos de acceso
interface range FastEthernet0/1-24
 ip arp inspection limit rate 100
```

### En Linux (víctima)
```bash
# ARP estático para el gateway
sudo arp -s 192.168.67.1 AA:BB:CC:DD:EE:FF

# Verificar tabla ARP
arp -a
```

### Verificación de la contramedida
```cisco
show ip arp inspection
show ip arp inspection statistics
```
## Video demostrativo 
https://youtu.be/X6bmyiCtz58
