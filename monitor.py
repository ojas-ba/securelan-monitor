import queue
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from scapy.all import ARP, sniff

from serial_engine import SwitchSerialEngine


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _put_event(event_queue: queue.Queue, kind: str, data: Dict[str, Any]) -> None:
    payload = {"kind": kind, "data": data}
    event_queue.put(payload)


def _build_attack_event(attack_type: str, details: Dict[str, Any], severity: str = "HIGH") -> Dict[str, Any]:
    return {
        "timestamp": _utc_now_iso(),
        "attack_type": attack_type,
        "severity": severity,
        "details": details,
    }


def _drain_manual_commands(
    cmd_queue: queue.Queue,
    engine: SwitchSerialEngine,
    event_queue: queue.Queue,
    mac_threshold: int,
) -> None:
    while True:
        try:
            cmd_msg = cmd_queue.get_nowait()
        except queue.Empty:
            break

        action = str(cmd_msg.get("action", "")).strip().upper()
        if action:
            try:
                if action == "INJECT_MAC_FLOOD":
                    demo_current = mac_threshold + 5
                    attack_event = _build_attack_event(
                        attack_type="MAC_FLOOD",
                        details={
                            "current": demo_current,
                            "previous": 0,
                            "delta": demo_current,
                            "threshold": mac_threshold,
                            "trigger": "UI_BUTTON_SAFE_DEMO",
                            "note": "Synthetic trigger only. No packet flood generated.",
                        },
                    )
                    _put_event(event_queue, "ATTACK_EVENT", attack_event)

                    defense_rec = engine.send_command(
                        "port security max-mac-count 5",
                        source="AUTO",
                    )
                    _put_event(event_queue, "CMD_RECORD", defense_rec)

                elif action == "INJECT_ARP_SPOOF":
                    attack_event = _build_attack_event(
                        attack_type="ARP_SPOOF",
                        details={
                            "ip": "192.168.1.254",
                            "old_mac": "00:11:22:33:44:55",
                            "new_mac": "66:77:88:99:aa:bb",
                            "trigger": "UI_BUTTON_SAFE_DEMO",
                            "note": "Synthetic trigger only. No spoof packets generated.",
                        },
                    )
                    _put_event(event_queue, "ATTACK_EVENT", attack_event)

                    defense_rec = engine.send_command(
                        "ip arp inspection vlan 1",
                        source="AUTO",
                    )
                    _put_event(event_queue, "CMD_RECORD", defense_rec)
                else:
                    _put_event(
                        event_queue,
                        "ERROR_EVENT",
                        {
                            "timestamp": _utc_now_iso(),
                            "message": f"Unknown control action: {action}",
                        },
                    )
            except Exception as exc:
                _put_event(
                    event_queue,
                    "ERROR_EVENT",
                    {
                        "timestamp": _utc_now_iso(),
                        "message": f"Control action failed ({action}): {exc}",
                    },
                )
            continue

        command = str(cmd_msg.get("command", "")).strip()
        source = str(cmd_msg.get("source", "MANUAL"))
        if not command:
            continue

        try:
            record = engine.send_command(command, source=source)
            _put_event(event_queue, "CMD_RECORD", record)
        except Exception as exc:
            _put_event(
                event_queue,
                "ERROR_EVENT",
                {
                    "timestamp": _utc_now_iso(),
                    "message": f"Manual command failed ({command}): {exc}",
                },
            )


def _sniff_arp_batch(interface: str, timeout_sec: int) -> Any:
    return sniff(
        filter="arp and arp[6:2] == 2",
        iface=interface,
        timeout=timeout_sec,
        store=True,
    )


def monitor_loop(
    event_queue: queue.Queue,
    command_queue: queue.Queue,
    stop_event: threading.Event,
    config: Dict[str, Any],
    hmac_secret: bytes,
) -> None:
    serial_cfg = config["serial"]
    detection_cfg = config["detection"]
    arp_cfg = config["arp"]

    mac_poll_interval = int(detection_cfg.get("mac_poll_interval_sec", 15))
    mac_threshold = int(detection_cfg.get("mac_flood_threshold", 50))
    arp_interface = str(arp_cfg.get("interface", ""))
    arp_timeout = int(arp_cfg.get("sniff_timeout_sec", 2))

    engine = SwitchSerialEngine(serial_cfg=serial_cfg, hmac_secret=hmac_secret)
    prepared = False

    previous_mac_count: Optional[int] = None
    last_mac_poll = 0.0
    arp_map: Dict[str, str] = {}
    last_arp_packet: Dict[str, Any] = {}
    last_suspicious: Optional[Dict[str, Any]] = None
    last_arp_error = 0.0

    while not stop_event.is_set():
        try:
            if not engine.is_open():
                ok, msg = engine.open()
                if not ok:
                    _put_event(
                        event_queue,
                        "ERROR_EVENT",
                        {
                            "timestamp": _utc_now_iso(),
                            "message": msg,
                        },
                    )
                    time.sleep(2.0)
                    continue

                prepared = False

            if not prepared:
                startup_records = engine.login_and_prepare()
                for rec in startup_records:
                    _put_event(event_queue, "CMD_RECORD", rec)
                prepared = True

            _drain_manual_commands(command_queue, engine, event_queue, mac_threshold)

            now = time.time()
            if (now - last_mac_poll) >= mac_poll_interval:
                mac_rec = engine.send_command("show mac-address", source="SYSTEM")
                _put_event(event_queue, "CMD_RECORD", mac_rec)

                current_count = engine.parse_mac_count(mac_rec["output"])
                delta = 0 if previous_mac_count is None else current_count - previous_mac_count

                _put_event(
                    event_queue,
                    "MAC_METRIC",
                    {
                        "timestamp": _utc_now_iso(),
                        "current_mac_count": current_count,
                        "previous_mac_count": previous_mac_count if previous_mac_count is not None else 0,
                        "delta": delta,
                        "threshold": mac_threshold,
                    },
                )

                if previous_mac_count is not None and delta > mac_threshold:
                    attack_event = _build_attack_event(
                        attack_type="MAC_FLOOD",
                        details={
                            "current": current_count,
                            "previous": previous_mac_count,
                            "delta": delta,
                            "threshold": mac_threshold,
                        },
                    )
                    _put_event(event_queue, "ATTACK_EVENT", attack_event)

                    defense_rec = engine.send_command(
                        "port security max-mac-count 5",
                        source="AUTO",
                    )
                    _put_event(event_queue, "CMD_RECORD", defense_rec)

                previous_mac_count = current_count
                last_mac_poll = now

            if arp_interface:
                try:
                    packets = _sniff_arp_batch(arp_interface, timeout_sec=arp_timeout)
                    for pkt in packets:
                        if not pkt.haslayer(ARP):
                            continue

                        ip = str(pkt[ARP].psrc)
                        mac = str(pkt[ARP].hwsrc).lower()
                        old_mac = arp_map.get(ip)
                        last_arp_packet = {
                            "timestamp": _utc_now_iso(),
                            "ip": ip,
                            "mac": mac,
                        }

                        if old_mac and old_mac != mac:
                            last_suspicious = {
                                "timestamp": _utc_now_iso(),
                                "ip": ip,
                                "old_mac": old_mac,
                                "new_mac": mac,
                            }
                            attack_event = _build_attack_event(
                                attack_type="ARP_SPOOF",
                                details=last_suspicious,
                            )
                            _put_event(event_queue, "ATTACK_EVENT", attack_event)

                            defense_rec = engine.send_command(
                                "ip arp inspection vlan 1",
                                source="AUTO",
                            )
                            _put_event(event_queue, "CMD_RECORD", defense_rec)

                        arp_map[ip] = mac

                except Exception as exc:
                    # Throttle repetitive sniff errors so UI/audit stay readable.
                    if (time.time() - last_arp_error) > 10:
                        _put_event(
                            event_queue,
                            "ERROR_EVENT",
                            {
                                "timestamp": _utc_now_iso(),
                                "message": f"ARP sniff failed: {exc}",
                            },
                        )
                        last_arp_error = time.time()

            _put_event(
                event_queue,
                "ARP_METRIC",
                {
                    "timestamp": _utc_now_iso(),
                    "tracked_ip_count": len(arp_map),
                    "last_arp_packet": last_arp_packet,
                    "last_suspicious_mapping": last_suspicious,
                },
            )

            time.sleep(0.5)

        except Exception as exc:
            _put_event(
                event_queue,
                "ERROR_EVENT",
                {
                    "timestamp": _utc_now_iso(),
                    "message": f"Monitor loop error: {exc}",
                },
            )
            engine.close()
            prepared = False
            time.sleep(2.0)

    engine.close()
