import queue
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

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


CLI_ERROR_PATTERNS = [
    re.compile(r"invalid\s+input", flags=re.IGNORECASE),
    re.compile(r"incomplete\s+command", flags=re.IGNORECASE),
    re.compile(r"unknown\s+command", flags=re.IGNORECASE),
    re.compile(r"unrecognized\s+command", flags=re.IGNORECASE),
    re.compile(r"ambiguous\s+command", flags=re.IGNORECASE),
    re.compile(r"syntax\s+error", flags=re.IGNORECASE),
    re.compile(r"command\s+rejected", flags=re.IGNORECASE),
    re.compile(r"^\s*%\s*(error|invalid|incomplete|unknown)", flags=re.IGNORECASE | re.MULTILINE),
]


def _emit_error(event_queue: queue.Queue, message: str) -> None:
    _put_event(
        event_queue,
        "ERROR_EVENT",
        {
            "timestamp": _utc_now_iso(),
            "message": message,
        },
    )


def _output_indicates_cli_error(output: str) -> bool:
    if not output:
        return False
    return any(pattern.search(output) for pattern in CLI_ERROR_PATTERNS)


def _send_command_and_record(
    engine: SwitchSerialEngine,
    event_queue: queue.Queue,
    command: str,
    source: str,
    strict: bool = True,
) -> Dict[str, Any]:
    record = engine.send_command(command, source=source)
    _put_event(event_queue, "CMD_RECORD", record)

    if strict and _output_indicates_cli_error(str(record.get("output", ""))):
        raise RuntimeError(f"switch rejected command: {command}")

    return record


def _apply_vlan_quarantine(
    engine: SwitchSerialEngine,
    event_queue: queue.Queue,
    port: str,
    quarantine_vlan: int,
) -> bool:
    try:
        for command in [
            "configure terminal",
            f"vlan {quarantine_vlan} untagged {port}",
            "exit",
        ]:
            _send_command_and_record(engine, event_queue, command, source="AUTO_DEFENSE", strict=True)
        return True
    except Exception as exc:
        _emit_error(
            event_queue,
            f"Quarantine command sequence failed for {port} (VLAN {quarantine_vlan}): {exc}",
        )
        return False


def _normalize_mac(raw_mac: str) -> str:
    text = raw_mac.strip().lower().replace("-", ":")
    if not text:
        return ""

    if "." in text:
        collapsed = text.replace(".", "")
        if re.fullmatch(r"[0-9a-f]{12}", collapsed):
            return ":".join(collapsed[idx : idx + 2] for idx in range(0, 12, 2))

    if ":" in text:
        parts = text.split(":")
        if len(parts) == 6 and all(re.fullmatch(r"[0-9a-f]{1,2}", part or "") for part in parts):
            return ":".join(part.zfill(2) for part in parts)

    if re.fullmatch(r"[0-9a-f]{12}", text):
        return ":".join(text[idx : idx + 2] for idx in range(0, 12, 2))

    return text


def _normalize_port(raw_port: str) -> str:
    text = " ".join(raw_port.strip().lower().split())
    if not text:
        return ""

    if text.startswith("ethernet "):
        text = text.split(" ", 1)[1].strip()

    if re.fullmatch(r"e\d+/\d+/\d+", text):
        return f"e {text[1:]}"

    if re.fullmatch(r"e\s+\d+/\d+/\d+", text):
        return f"e {text.split()[-1]}"

    return text


def _port_to_interface_id(port: str) -> str:
    normalized = _normalize_port(port)
    if normalized.startswith("e "):
        return normalized[2:].strip()
    return normalized


def _extract_port_token(text: str) -> str:
    match = re.search(r"\be\s*\d+/\d+/\d+\b", text, flags=re.IGNORECASE)
    if not match:
        return ""
    return _normalize_port(match.group(0))


def _parse_show_arp(output: str) -> Dict[str, str]:
    arp_map: Dict[str, str] = {}

    for line in output.splitlines():
        text = line.strip()
        if not text or text.lower().startswith("ip address"):
            continue

        tokens = text.split()
        ip = ""
        mac = ""

        for idx, token in enumerate(tokens):
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", token):
                ip = token
                if idx + 1 < len(tokens):
                    mac = _normalize_mac(tokens[idx + 1])
                break

        if ip and len(mac) == 17:
            arp_map[ip] = mac

    return arp_map


def _parse_show_interfaces_brief(output: str) -> List[str]:
    active_ports: List[str] = []

    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue
        tokens = text.split()
        if len(tokens) < 2:
            continue

        port_token = tokens[0]
        link_token = tokens[1].lower()

        if not re.fullmatch(r"e\d+/\d+/\d+", port_token.lower()):
            continue
        if link_token != "up":
            continue

        active_ports.append(_normalize_port(port_token))

    return active_ports


def _parse_show_port_security_violations(output: str) -> List[Dict[str, Any]]:
    violations: List[Dict[str, Any]] = []

    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue

        tokens = text.split()
        if not tokens:
            continue

        port_token = tokens[0]
        if not re.fullmatch(r"e\d+/\d+/\d+", port_token.lower()):
            continue

        shutdown = any(
            token.lower() == "yes" or token.lower().startswith("shutdown")
            for token in tokens[1:]
        )

        violation_count = 0
        for token in tokens[1:]:
            if token.isdigit():
                violation_count = int(token)
                break

        attacker_mac = ""
        for token in reversed(tokens[1:]):
            normalized = _normalize_mac(token)
            if len(normalized) == 17 and normalized != "none":
                attacker_mac = normalized
                break

        if shutdown and violation_count > 0:
            violations.append(
                {
                    "port": _normalize_port(port_token),
                    "violation_count": violation_count,
                    "attacker_mac": attacker_mac,
                }
            )

    return violations


def _parse_show_mac_address_port(output: str, target_mac: str) -> str:
    expected_mac = _normalize_mac(target_mac)

    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue

        tokens = text.split()
        if len(tokens) < 2:
            continue

        first_mac = _normalize_mac(tokens[0])
        if len(first_mac) == 17 and first_mac == expected_mac:
            candidate = _extract_port_token(tokens[1])
            if candidate:
                return candidate

        if expected_mac and expected_mac in text.lower():
            candidate = _extract_port_token(text)
            if candidate:
                return candidate

    return ""


def _run_startup_baseline(
    engine: SwitchSerialEngine,
    event_queue: queue.Queue,
) -> Tuple[Dict[str, str], int]:
    def send_and_emit(command: str, source: str = "SYSTEM") -> Dict[str, Any]:
        return _send_command_and_record(engine, event_queue, command, source=source, strict=True)

    arp_record = _send_command_and_record(engine, event_queue, "show arp", source="SYSTEM", strict=False)
    arp_map = _parse_show_arp(arp_record.get("output", ""))
    _put_event(
        event_queue,
        "BASELINE_EVENT",
        {
            "timestamp": _utc_now_iso(),
            "arp_entries_loaded": len(arp_map),
            "step": "arp_map_preloaded",
        },
    )

    interfaces_record = _send_command_and_record(
        engine,
        event_queue,
        "show interfaces brief",
        source="SYSTEM",
        strict=False,
    )
    active_ports = _parse_show_interfaces_brief(interfaces_record.get("output", ""))

    ports_hardened = 0
    for port in active_ports:
        interface_id = _port_to_interface_id(port)
        for command in [
            "configure terminal",
            f"interface ethernet {interface_id}",
            "port security",
            "port security max-mac-count 1",
            "port security violation shutdown",
            "exit",
            "exit",
        ]:
            send_and_emit(command, source="SYSTEM")
        ports_hardened += 1

    _put_event(
        event_queue,
        "BASELINE_EVENT",
        {
            "timestamp": _utc_now_iso(),
            "ports_hardened": ports_hardened,
            "step": "port_hardening_complete",
        },
    )

    for command in [
        "configure terminal",
        "ip arp inspection vlan 1",
        "exit",
    ]:
        send_and_emit(command, source="SYSTEM")

    _put_event(
        event_queue,
        "BASELINE_EVENT",
        {
            "timestamp": _utc_now_iso(),
            "step": "dai_enabled",
        },
    )

    _put_event(
        event_queue,
        "BASELINE_EVENT",
        {
            "timestamp": _utc_now_iso(),
            "step": "hardening_complete",
            "arp_entries": len(arp_map),
            "ports_hardened": ports_hardened,
            "dai_enabled": True,
        },
    )
    return arp_map, ports_hardened


def _drain_manual_commands(
    cmd_queue: queue.Queue,
    engine: SwitchSerialEngine,
    event_queue: queue.Queue,
    quarantined_ports: List[str],
    quarantine_vlan: int,
    access_vlan: int,
) -> None:
    while True:
        try:
            cmd_msg = cmd_queue.get_nowait()
        except queue.Empty:
            break

        msg_type = str(cmd_msg.get("type", "")).strip().upper()
        if msg_type == "COMMAND":
            command = str(cmd_msg.get("command", "")).strip()
            if not command:
                continue
            try:
                record = _send_command_and_record(
                    engine,
                    event_queue,
                    command,
                    source="MANUAL",
                    strict=False,
                )
                if _output_indicates_cli_error(str(record.get("output", ""))):
                    _emit_error(event_queue, f"Manual command rejected by switch: {command}")
            except Exception as exc:
                _emit_error(event_queue, f"Manual command failed ({command}): {exc}")
            continue

        if msg_type == "RECOVER_PORT":
            raw_port = str(cmd_msg.get("port", "")).strip()
            normalized_port = _normalize_port(raw_port)
            if not normalized_port:
                _put_event(
                    event_queue,
                    "ERROR_EVENT",
                    {
                        "timestamp": _utc_now_iso(),
                        "message": "RECOVER_PORT rejected: missing or invalid port",
                    },
                )
                continue

            interface_id = _port_to_interface_id(normalized_port)
            try:
                for command in [
                    "configure terminal",
                    f"vlan {access_vlan} untagged {normalized_port}",
                    f"interface ethernet {interface_id}",
                    "enable",
                    "exit",
                    "exit",
                ]:
                    _send_command_and_record(engine, event_queue, command, source="MANUAL", strict=True)

                if normalized_port in quarantined_ports:
                    quarantined_ports.remove(normalized_port)

                _put_event(
                    event_queue,
                    "PORT_RECOVERY_EVENT",
                    {
                        "timestamp": _utc_now_iso(),
                        "port": normalized_port,
                        "action": "operator_authorized_recovery",
                        "recovered_to_vlan": access_vlan,
                        "released_from_vlan": quarantine_vlan,
                    },
                )
            except Exception as exc:
                _emit_error(
                    event_queue,
                    f"Port recovery failed ({normalized_port}): {exc}",
                )
            continue

        _put_event(
            event_queue,
            "ERROR_EVENT",
            {
                "timestamp": _utc_now_iso(),
                "message": f"Unknown command message type: {msg_type or '<empty>'}",
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
    network_cfg = config["network"]
    arp_cfg = config["arp"]

    poll_interval_sec = int(detection_cfg["poll_interval_sec"])
    quarantine_vlan = int(network_cfg["quarantine_vlan"])
    access_vlan = int(network_cfg.get("access_vlan", 1))
    arp_interface = str(arp_cfg.get("interface", ""))
    arp_timeout = int(arp_cfg.get("sniff_timeout_sec", 2))

    engine = SwitchSerialEngine(serial_cfg=serial_cfg, hmac_secret=hmac_secret)
    prepared = False
    hardening_done = False

    previous_mac_count: Optional[int] = None
    last_mac_poll = 0.0
    arp_map: Dict[str, str] = {}
    quarantined_ports: List[str] = []
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
                hardening_done = False

            if not prepared:
                startup_records = engine.login_and_prepare()
                for rec in startup_records:
                    _put_event(event_queue, "CMD_RECORD", rec)

                arp_map, _ = _run_startup_baseline(engine, event_queue)

                prepared = True
                hardening_done = True
                previous_mac_count = None
                quarantined_ports.clear()

            _drain_manual_commands(
                command_queue,
                engine,
                event_queue,
                quarantined_ports,
                quarantine_vlan,
                access_vlan,
            )

            now = time.time()
            if hardening_done and (now - last_mac_poll) >= poll_interval_sec:
                port_security_rec = engine.send_command("show port security", source="SYSTEM")
                _put_event(event_queue, "CMD_RECORD", port_security_rec)

                violations = _parse_show_port_security_violations(port_security_rec.get("output", ""))
                for violation in violations:
                    offending_port = violation["port"]
                    if offending_port in quarantined_ports:
                        continue

                    quarantine_ok = _apply_vlan_quarantine(
                        engine,
                        event_queue,
                        offending_port,
                        quarantine_vlan,
                    )
                    if quarantine_ok:
                        quarantined_ports.append(offending_port)
                        action_taken = f"port_quarantined_vlan{quarantine_vlan}"
                    else:
                        action_taken = "quarantine_failed"

                    attack_event = _build_attack_event(
                        attack_type="MAC_FLOOD",
                        severity="HIGH",
                        details={
                            "offending_port": offending_port,
                            "violation_count": int(violation.get("violation_count", 0)),
                            "attacker_mac": violation.get("attacker_mac", ""),
                            "action_taken": action_taken,
                            "quarantine_vlan": quarantine_vlan,
                        },
                    )
                    _put_event(event_queue, "ATTACK_EVENT", attack_event)

                mac_rec = engine.send_command("show mac-address", source="SYSTEM")
                _put_event(event_queue, "CMD_RECORD", mac_rec)

                current_count = engine.parse_mac_count(mac_rec.get("output", ""))
                delta = 0 if previous_mac_count is None else current_count - previous_mac_count
                _put_event(
                    event_queue,
                    "MAC_METRIC",
                    {
                        "timestamp": _utc_now_iso(),
                        "current_mac_count": current_count,
                        "previous_mac_count": previous_mac_count if previous_mac_count is not None else 0,
                        "delta": delta,
                        "threshold": 0,
                    },
                )
                previous_mac_count = current_count
                last_mac_poll = now

            if arp_interface:
                try:
                    packets = _sniff_arp_batch(arp_interface, timeout_sec=arp_timeout)
                    for pkt in packets:
                        if not pkt.haslayer(ARP):
                            continue

                        attacker_mac = _normalize_mac(str(pkt[ARP].hwsrc))
                        impersonated_ip = str(pkt[ARP].psrc)
                        victim_ip = str(pkt[ARP].pdst)
                        victim_mac = _normalize_mac(str(pkt[ARP].hwdst))
                        legitimate_mac = arp_map.get(impersonated_ip)

                        last_arp_packet = {
                            "timestamp": _utc_now_iso(),
                            "ip": impersonated_ip,
                            "mac": attacker_mac,
                        }

                        if legitimate_mac and legitimate_mac != attacker_mac:
                            lookup_rec = engine.send_command(
                                f"show mac-address {attacker_mac}",
                                source="SYSTEM",
                            )
                            _put_event(event_queue, "CMD_RECORD", lookup_rec)

                            attacker_port = _parse_show_mac_address_port(
                                lookup_rec.get("output", ""),
                                attacker_mac,
                            )

                            if attacker_port:
                                if attacker_port not in quarantined_ports:
                                    quarantine_ok = _apply_vlan_quarantine(
                                        engine,
                                        event_queue,
                                        attacker_port,
                                        quarantine_vlan,
                                    )
                                    if quarantine_ok:
                                        quarantined_ports.append(attacker_port)
                                        action_taken = f"port_quarantined_vlan{quarantine_vlan}"
                                    else:
                                        action_taken = "quarantine_failed"
                                else:
                                    action_taken = f"port_quarantined_vlan{quarantine_vlan}"
                            else:
                                action_taken = "attacker_port_not_found"
                                _emit_error(
                                    event_queue,
                                    "ARP spoof detected but attacker port lookup failed "
                                    f"for MAC {attacker_mac}",
                                )

                            last_suspicious = {
                                "timestamp": _utc_now_iso(),
                                "impersonated_ip": impersonated_ip,
                                "legitimate_mac": legitimate_mac,
                                "attacker_mac": attacker_mac,
                                "attacker_port": attacker_port,
                            }

                            attack_event = _build_attack_event(
                                attack_type="ARP_SPOOF",
                                details={
                                    "attacker_mac": attacker_mac,
                                    "attacker_port": attacker_port,
                                    "impersonated_ip": impersonated_ip,
                                    "victim_ip": victim_ip,
                                    "victim_mac": victim_mac,
                                    "legitimate_mac": legitimate_mac,
                                    "action_taken": action_taken,
                                    "quarantine_vlan": quarantine_vlan,
                                },
                            )
                            _put_event(event_queue, "ATTACK_EVENT", attack_event)

                        if not legitimate_mac:
                            arp_map[impersonated_ip] = attacker_mac

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
            hardening_done = False
            time.sleep(2.0)

    engine.close()
