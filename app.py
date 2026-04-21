import html
import json
import queue
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import yaml
from streamlit_autorefresh import st_autorefresh

import crypto_log
import db
from monitor import monitor_loop


CONFIG_PATH = "config.yaml"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    text = ts.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _format_ts(ts: str) -> str:
    parsed = _parse_iso(ts)
    if not parsed:
        return ts or "-"
    return parsed.strftime("%H:%M:%S")


def _normalize_port(raw_port: str) -> str:
    text = " ".join(raw_port.strip().lower().split())
    if not text:
        return ""
    if text.startswith("e") and not text.startswith("e ") and len(text) > 1 and text[1].isdigit():
        return f"e {text[1:]}"
    if text.startswith("e "):
        return f"e {text.split()[-1]}"
    return text


def _init_session_state(config: Dict[str, Any]) -> None:
    if "config" not in st.session_state:
        st.session_state.config = config

    if "db_conn" not in st.session_state:
        st.session_state.db_conn = db.init_db(config["db_path"])

    if "fernet" not in st.session_state:
        st.session_state.fernet = crypto_log.load_or_create_fernet(config["crypto"]["fernet_key_path"])

    if "hmac_secret" not in st.session_state:
        st.session_state.hmac_secret = crypto_log.load_or_create_hmac_secret(config["crypto"]["hmac_key_path"])

    if "event_queue" not in st.session_state:
        st.session_state.event_queue = queue.Queue()

    if "command_queue" not in st.session_state:
        st.session_state.command_queue = queue.Queue(maxsize=500)

    if "stop_event" not in st.session_state:
        st.session_state.stop_event = threading.Event()

    if "worker_thread" not in st.session_state:
        st.session_state.worker_thread = None

    if "command_records" not in st.session_state:
        st.session_state.command_records = []

    if "polling_records" not in st.session_state:
        st.session_state.polling_records = []

    if "live_events" not in st.session_state:
        st.session_state.live_events = []

    if "errors" not in st.session_state:
        st.session_state.errors = []

    if "mac_metric" not in st.session_state:
        st.session_state.mac_metric = {
            "current_mac_count": 0,
            "previous_mac_count": 0,
            "delta": 0,
            "threshold": 0,
            "timestamp": "",
        }

    if "arp_metric" not in st.session_state:
        st.session_state.arp_metric = {
            "tracked_ip_count": 0,
            "last_arp_packet": {},
            "last_suspicious_mapping": None,
            "timestamp": "",
        }

    if "hardening_status" not in st.session_state:
        st.session_state.hardening_status = {
            "done": False,
            "arp_entries": 0,
            "ports_hardened": 0,
            "dai_enabled": False,
            "step": "not_started",
        }

    if "quarantined_ports" not in st.session_state:
        st.session_state.quarantined_ports = []

    if "quarantine_details" not in st.session_state:
        st.session_state.quarantine_details = {}

    if "last_attack_details" not in st.session_state:
        st.session_state.last_attack_details = None

    if "switch_connected" not in st.session_state:
        st.session_state.switch_connected = False

    if "mock_data_seeded" not in st.session_state:
        st.session_state.mock_data_seeded = False


def _start_worker_if_needed() -> None:
    existing = st.session_state.worker_thread
    if existing and existing.is_alive():
        return

    st.session_state.stop_event.clear()
    t = threading.Thread(
        target=monitor_loop,
        args=(
            st.session_state.event_queue,
            st.session_state.command_queue,
            st.session_state.stop_event,
            st.session_state.config,
            st.session_state.hmac_secret,
        ),
        daemon=True,
        name="securelan-monitor-worker",
    )
    t.start()
    st.session_state.worker_thread = t


def _append_capped(items: List[Dict[str, Any]], value: Dict[str, Any], cap: int = 500) -> None:
    items.append(value)
    if len(items) > cap:
        del items[: len(items) - cap]


def _add_live_event(kind: str, data: Dict[str, Any]) -> None:
    entry = {
        "kind": kind,
        "timestamp": data.get("timestamp", _utc_now_iso()),
        "data": data,
    }
    _append_capped(st.session_state.live_events, entry)


def _write_audit(action_type: str, payload: Dict[str, Any], hmac_sig: str = "") -> None:
    conn = st.session_state.db_conn
    fernet = st.session_state.fernet

    timestamp = payload.get("timestamp", _utc_now_iso())
    prev_hash = db.get_last_audit_hash(conn)
    description, encrypted_blob, entry_hash = crypto_log.build_audit_values(
        fernet=fernet,
        prev_hash=prev_hash,
        timestamp=timestamp,
        action_type=action_type,
        description_data=payload,
        hmac_sig=hmac_sig,
    )

    db.insert_audit_log(
        conn=conn,
        timestamp=timestamp,
        action_type=action_type,
        description=description,
        encrypted_blob=encrypted_blob,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        hmac_sig=hmac_sig,
    )


def _drain_event_queue() -> int:
    conn = st.session_state.db_conn
    processed = 0

    def is_polling_record(record: Dict[str, Any]) -> bool:
        source = str(record.get("source", "")).upper()
        command_text = str(record.get("command", "")).lower()
        if source != "SYSTEM":
            return False
        return "show mac-address" in command_text or "show arp" in command_text

    def update_hardening_status(data: Dict[str, Any]) -> None:
        status = dict(st.session_state.hardening_status)
        step = str(data.get("step", "")).strip()

        if step == "arp_map_preloaded":
            status["arp_entries"] = int(data.get("arp_entries_loaded", status.get("arp_entries", 0)))
            status["step"] = step
            status["done"] = False
        elif step == "port_hardening_complete":
            status["ports_hardened"] = int(data.get("ports_hardened", status.get("ports_hardened", 0)))
            status["step"] = step
            status["done"] = False
        elif step == "dai_enabled":
            status["dai_enabled"] = True
            status["step"] = step
            status["done"] = False
        elif step == "hardening_complete":
            status["arp_entries"] = int(data.get("arp_entries", status.get("arp_entries", 0)))
            status["ports_hardened"] = int(data.get("ports_hardened", status.get("ports_hardened", 0)))
            status["dai_enabled"] = bool(data.get("dai_enabled", status.get("dai_enabled", False)))
            status["done"] = True
            status["step"] = step

        st.session_state.hardening_status = status

    def track_quarantine(attack_event: Dict[str, Any]) -> None:
        details = attack_event.get("details", {})
        port = details.get("offending_port") or details.get("attacker_port")
        if not port:
            return

        normalized_port = _normalize_port(str(port))
        if not normalized_port:
            return

        if normalized_port not in st.session_state.quarantined_ports:
            st.session_state.quarantined_ports.append(normalized_port)

        meta = dict(st.session_state.quarantine_details)
        meta[normalized_port] = {
            "attack_type": attack_event.get("attack_type", "UNKNOWN"),
            "since": attack_event.get("timestamp", _utc_now_iso()),
        }
        st.session_state.quarantine_details = meta

    def release_quarantine(port: str) -> None:
        normalized_port = _normalize_port(port)
        if normalized_port in st.session_state.quarantined_ports:
            st.session_state.quarantined_ports.remove(normalized_port)
        meta = dict(st.session_state.quarantine_details)
        meta.pop(normalized_port, None)
        st.session_state.quarantine_details = meta

    while processed < 200:
        try:
            msg = st.session_state.event_queue.get_nowait()
        except queue.Empty:
            break

        processed += 1
        kind = msg.get("kind", "")
        data = msg.get("data", {})

        try:
            if kind == "CMD_RECORD":
                if is_polling_record(data):
                    _append_capped(st.session_state.polling_records, data, cap=10)
                else:
                    _append_capped(st.session_state.command_records, data)
                    if str(data.get("source", "")).upper() == "MANUAL":
                        _add_live_event(
                            "MANUAL_ACTION",
                            {
                                "timestamp": data.get("timestamp", _utc_now_iso()),
                                "command": data.get("command", ""),
                                "source": "MANUAL",
                                "action_taken": "manual_command_executed",
                            },
                        )

                if str(data.get("source", "")).upper() == "SYSTEM":
                    st.session_state.switch_connected = True

                _write_audit("COMMAND", data, hmac_sig=data.get("hmac_sig", ""))

            elif kind == "ATTACK_EVENT":
                _add_live_event(kind, data)
                st.session_state.last_attack_details = data
                track_quarantine(data)
                db.insert_event(conn, data)
                _write_audit("ATTACK_EVENT", data)

            elif kind == "MAC_METRIC":
                st.session_state.mac_metric = data
                db.insert_mac_snapshot(
                    conn,
                    timestamp=data.get("timestamp", _utc_now_iso()),
                    mac_count=int(data.get("current_mac_count", 0)),
                    delta=int(data.get("delta", 0)),
                )

            elif kind == "ARP_METRIC":
                st.session_state.arp_metric = data

            elif kind == "BASELINE_EVENT":
                _add_live_event(kind, data)
                update_hardening_status(data)
                _write_audit("BASELINE_EVENT", data)

            elif kind == "PORT_RECOVERY_EVENT":
                _add_live_event(kind, data)
                release_quarantine(str(data.get("port", "")))
                _write_audit("PORT_RECOVERY", data)

            elif kind == "ERROR_EVENT":
                _append_capped(st.session_state.errors, data)
                _add_live_event(kind, data)
                message = str(data.get("message", "")).lower()
                if "serial" in message or "login" in message or "authentication" in message:
                    st.session_state.switch_connected = False
                _write_audit("ERROR_EVENT", data)

            else:
                _add_live_event(
                    kind,
                    {
                        "timestamp": _utc_now_iso(),
                        "message": f"Unknown event kind: {kind}",
                        "raw": data,
                    },
                )
                _write_audit(
                    "UNKNOWN_EVENT",
                    {
                        "timestamp": _utc_now_iso(),
                        "message": f"Unknown event kind: {kind}",
                        "raw": data,
                    },
                )
        except Exception as exc:
            err = {
                "timestamp": _utc_now_iso(),
                "message": f"Failed to process queue event ({kind}): {exc}",
            }
            _append_capped(st.session_state.errors, err)
            try:
                _write_audit("ERROR_EVENT", err)
            except Exception:
                # If audit write fails, keep UI alive and show sidebar error.
                pass

    return processed


def _build_status_card(title: str, value: str, sublabel: str, background: str, border: str) -> str:
    return (
        "<div style='padding:12px;border-radius:10px;"
        f"background:{background};border:1px solid {border};height:120px;'>"
        f"<div style='font-size:13px;font-weight:600;color:#222;'>{html.escape(title)}</div>"
        f"<div style='font-size:24px;font-weight:700;margin-top:8px;color:#111;'>{html.escape(value)}</div>"
        f"<div style='font-size:12px;margin-top:8px;color:#333;'>{html.escape(sublabel)}</div>"
        "</div>"
    )


def _event_style(kind: str) -> Dict[str, str]:
    if kind == "ATTACK_EVENT":
        return {"bg": "#ffe6e6", "border": "#cc0000"}
    if kind == "ERROR_EVENT":
        return {"bg": "#fff7da", "border": "#d6a000"}
    if kind == "BASELINE_EVENT":
        return {"bg": "#e8f7ea", "border": "#2f8f46"}
    if kind in {"PORT_RECOVERY_EVENT", "MANUAL_ACTION"}:
        return {"bg": "#e7f0ff", "border": "#2467d1"}
    return {"bg": "#f3f4f6", "border": "#7f8790"}


def _summarize_live_event(kind: str, data: Dict[str, Any]) -> Dict[str, str]:
    if kind == "ATTACK_EVENT":
        attack_type = str(data.get("attack_type", "UNKNOWN"))
        details = data.get("details", {})
        if attack_type == "MAC_FLOOD":
            port = details.get("offending_port", "-")
            count = details.get("violation_count", "-")
            action = details.get("action_taken", "-")
            return {"summary": f"MAC_FLOOD on {port} violations={count}", "action": str(action)}
        if attack_type == "ARP_SPOOF":
            src_ip = details.get("impersonated_ip", "-")
            src_mac = details.get("attacker_mac", "-")
            action = details.get("action_taken", "-")
            return {"summary": f"ARP_SPOOF {src_ip} via {src_mac}", "action": str(action)}
        return {"summary": attack_type, "action": "attack logged"}

    if kind == "BASELINE_EVENT":
        step = str(data.get("step", "baseline_update"))
        return {"summary": f"Baseline step: {step}", "action": "startup hardening"}

    if kind == "PORT_RECOVERY_EVENT":
        port = str(data.get("port", "-"))
        return {"summary": f"Port recovery for {port}", "action": str(data.get("action", "recovery"))}

    if kind == "MANUAL_ACTION":
        return {
            "summary": f"Manual command: {data.get('command', '')}",
            "action": str(data.get("action_taken", "manual")),
        }

    if kind == "ERROR_EVENT":
        return {"summary": str(data.get("message", "error")), "action": "check worker logs"}

    return {"summary": "Event recorded", "action": "logged"}


def _build_terminal(records: List[Dict[str, Any]], small: bool = False, force_gray: bool = False) -> str:
    source_color = {
        "SYSTEM": "#888888",
        "AUTO_DEFENSE": "#ff4444",
        "MANUAL": "#44aaff",
    }
    font_size = "12px" if small else "13px"
    lines: List[str] = []

    for rec in records:
        source = str(rec.get("source", "")).upper()
        color = "#888888" if force_gray else source_color.get(source, "#bbbbbb")
        hmac_short = str(rec.get("hmac_sig", ""))[:12]
        ts = _format_ts(str(rec.get("timestamp", "")))
        command = html.escape(str(rec.get("command", "")))
        lines.append(
            f"<div title='HMAC {html.escape(hmac_short)}' style='color:{color};font-size:{font_size};'>"
            f"[{html.escape(ts)}] [{html.escape(source)}] {command}</div>"
        )

    if not lines:
        lines.append("<div style='color:#888888;'>No records yet.</div>")

    return (
        "<div style='background-color:#1a1a1a;padding:10px;border-radius:8px;"
        "height:400px;overflow-y:auto;font-family:Courier New, monospace;'>"
        + "".join(lines)
        + "</div>"
    )


def _seed_mock_ui_data() -> bool:
    if st.session_state.mock_data_seeded:
        return False

    now = datetime.now(timezone.utc)
    conn = st.session_state.db_conn

    def ts(minutes_ago: int) -> str:
        return (now - timedelta(minutes=minutes_ago)).isoformat()

    st.session_state.switch_connected = True
    st.session_state.hardening_status = {
        "done": True,
        "arp_entries": 18,
        "ports_hardened": 6,
        "dai_enabled": True,
        "step": "hardening_complete",
    }

    st.session_state.command_records = []
    st.session_state.polling_records = []
    st.session_state.live_events = []
    st.session_state.errors = []

    baseline_events = [
        {"timestamp": ts(16), "step": "arp_map_preloaded", "arp_entries_loaded": 18},
        {"timestamp": ts(15), "step": "port_hardening_complete", "ports_hardened": 6},
        {"timestamp": ts(14), "step": "dai_enabled"},
        {
            "timestamp": ts(13),
            "step": "hardening_complete",
            "arp_entries": 18,
            "ports_hardened": 6,
            "dai_enabled": True,
        },
    ]
    for event in baseline_events:
        _add_live_event("BASELINE_EVENT", event)
        _write_audit("BASELINE_EVENT", event)

    command_records = [
        {
            "timestamp": ts(8),
            "source": "SYSTEM",
            "command": "show port security",
            "output": "Port security status fetched",
            "hmac_sig": "mock-hmac-system-001",
        },
        {
            "timestamp": ts(7),
            "source": "AUTO_DEFENSE",
            "command": "vlan 99 untagged e 1/1/3",
            "output": "Port moved to quarantine VLAN",
            "hmac_sig": "mock-hmac-auto-001",
        },
        {
            "timestamp": ts(5),
            "source": "MANUAL",
            "command": "show arp",
            "output": "ARP table displayed",
            "hmac_sig": "mock-hmac-manual-001",
        },
    ]
    for record in command_records:
        _append_capped(st.session_state.command_records, record)
        _write_audit("COMMAND", record, hmac_sig=record.get("hmac_sig", ""))

    polling_records = [
        {
            "timestamp": ts(4),
            "source": "SYSTEM",
            "command": "show arp",
            "output": "polling",
            "hmac_sig": "mock-hmac-poll-arp",
        },
        {
            "timestamp": ts(3),
            "source": "SYSTEM",
            "command": "show mac-address",
            "output": "polling",
            "hmac_sig": "mock-hmac-poll-mac",
        },
    ]
    for record in polling_records:
        _append_capped(st.session_state.polling_records, record, cap=10)

    mac_attack = {
        "timestamp": ts(7),
        "attack_type": "MAC_FLOOD",
        "severity": "HIGH",
        "details": {
            "offending_port": "e 1/1/3",
            "violation_count": 31,
            "attacker_mac": "de:ad:be:ef:00:10",
            "action_taken": "port_quarantined_vlan99",
            "quarantine_vlan": 99,
            "synthetic": True,
        },
    }
    arp_attack = {
        "timestamp": ts(2),
        "attack_type": "ARP_SPOOF",
        "severity": "HIGH",
        "details": {
            "attacker_mac": "de:ad:be:ef:00:20",
            "attacker_port": "e 1/1/3",
            "impersonated_ip": "192.168.1.1",
            "victim_ip": "192.168.1.10",
            "victim_mac": "00:11:22:33:44:55",
            "legitimate_mac": "00:11:22:aa:bb:cc",
            "action_taken": "port_quarantined_vlan99",
            "quarantine_vlan": 99,
            "synthetic": True,
        },
    }

    for event in [mac_attack, arp_attack]:
        _add_live_event("ATTACK_EVENT", event)
        db.insert_event(conn, event)
        _write_audit("ATTACK_EVENT", event)

    recovery_event = {
        "timestamp": ts(1),
        "port": "e 1/1/4",
        "action": "operator_authorized_recovery",
        "synthetic": True,
    }
    _add_live_event("PORT_RECOVERY_EVENT", recovery_event)
    _write_audit("PORT_RECOVERY", recovery_event)

    prev_count = 58
    for idx in range(20):
        count = 58 + idx * 2
        if idx in {9, 10}:
            count += 18
        snap_ts = ts(20 - idx)
        db.insert_mac_snapshot(
            conn,
            timestamp=snap_ts,
            mac_count=count,
            delta=count - prev_count,
        )
        prev_count = count

    st.session_state.mac_metric = {
        "timestamp": ts(0),
        "current_mac_count": prev_count,
        "previous_mac_count": prev_count - 2,
        "delta": 2,
        "threshold": 0,
    }
    st.session_state.arp_metric = {
        "timestamp": ts(0),
        "tracked_ip_count": 18,
        "last_arp_packet": {
            "timestamp": ts(0),
            "ip": "192.168.1.1",
            "mac": "de:ad:be:ef:00:20",
        },
        "last_suspicious_mapping": {
            "timestamp": ts(2),
            "impersonated_ip": "192.168.1.1",
            "legitimate_mac": "00:11:22:aa:bb:cc",
            "attacker_mac": "de:ad:be:ef:00:20",
            "attacker_port": "e 1/1/3",
        },
    }

    st.session_state.quarantined_ports = ["e 1/1/3"]
    st.session_state.quarantine_details = {
        "e 1/1/3": {
            "attack_type": "ARP_SPOOF",
            "since": ts(2),
        }
    }
    st.session_state.last_attack_details = arp_attack
    st.session_state.mock_data_seeded = True
    return True


def _render_network_status() -> None:
    st.subheader("NETWORK STATUS")

    config = st.session_state.config
    hardening = st.session_state.hardening_status
    mac_metric = st.session_state.mac_metric
    arp_metric = st.session_state.arp_metric

    active_thread = st.session_state.worker_thread and st.session_state.worker_thread.is_alive()
    switch_connected = bool(active_thread and st.session_state.switch_connected)

    if switch_connected:
        conn_value = "CONNECTED"
        conn_bg = "#e8f7ea"
        conn_border = "#2f8f46"
    else:
        conn_value = "DISCONNECTED"
        conn_bg = "#ffe6e6"
        conn_border = "#cc0000"

    if hardening.get("done"):
        hard_value = "HARDENED"
        hard_bg = "#e8f7ea"
        hard_border = "#2f8f46"
        hard_sub = (
            f"{int(hardening.get('ports_hardened', 0))} ports secured - "
            f"DAI {'active' if hardening.get('dai_enabled') else 'inactive'}"
        )
    elif hardening.get("step") != "not_started":
        hard_value = "HARDENING"
        hard_bg = "#fff7da"
        hard_border = "#d6a000"
        hard_sub = f"Current step: {hardening.get('step', 'running')}"
    else:
        hard_value = "NOT HARDENED"
        hard_bg = "#ffe6e6"
        hard_border = "#cc0000"
        hard_sub = "Startup hardening has not completed"

    mac_attack_active = any(
        st.session_state.quarantine_details.get(port, {}).get("attack_type") == "MAC_FLOOD"
        for port in st.session_state.quarantined_ports
    )
    if mac_attack_active:
        mac_status = "ATTACK DETECTED"
        mac_bg = "#ffe6e6"
        mac_border = "#cc0000"
    else:
        mac_status = "CLEAN"
        mac_bg = "#e8f7ea"
        mac_border = "#2f8f46"

    arp_attack_active = any(
        st.session_state.quarantine_details.get(port, {}).get("attack_type") == "ARP_SPOOF"
        for port in st.session_state.quarantined_ports
    )
    if arp_attack_active:
        arp_status = "ATTACK DETECTED"
        arp_bg = "#ffe6e6"
        arp_border = "#cc0000"
    else:
        arp_status = "CLEAN"
        arp_bg = "#e8f7ea"
        arp_border = "#2f8f46"

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            _build_status_card(
                "Switch Connection",
                conn_value,
                f"Serial port: {config['serial']['port']}",
                conn_bg,
                conn_border,
            ),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            _build_status_card("Hardening Status", hard_value, hard_sub, hard_bg, hard_border),
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            _build_status_card(
                "MAC Flood Status",
                mac_status,
                f"Current MAC count: {int(mac_metric.get('current_mac_count', 0))}",
                mac_bg,
                mac_border,
            ),
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            _build_status_card(
                "ARP Spoof Status",
                arp_status,
                f"Tracked mappings: {int(arp_metric.get('tracked_ip_count', 0))}",
                arp_bg,
                arp_border,
            ),
            unsafe_allow_html=True,
        )

    st.markdown("### MAC Count Chart")
    snapshots = db.get_recent_mac_snapshots(st.session_state.db_conn, limit=250)
    if snapshots:
        df = pd.DataFrame(snapshots)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df = df.dropna(subset=["timestamp"])

        fig = go.Figure()
        fig.add_trace(
            go.Scatter(
                x=df["timestamp"],
                y=df["mac_count"],
                mode="lines",
                name="MAC Count",
                line={"color": "#2563eb", "width": 2},
            )
        )

        recent_attacks = db.get_recent_events(st.session_state.db_conn, limit=250)
        marker_x: List[Any] = []
        marker_y: List[Any] = []
        for row in recent_attacks:
            attack_ts = pd.to_datetime(row.get("timestamp", ""), errors="coerce", utc=True)
            if pd.isna(attack_ts):
                continue
            eligible = df[df["timestamp"] <= attack_ts]
            if eligible.empty:
                continue
            marker_x.append(attack_ts)
            marker_y.append(int(eligible.iloc[-1]["mac_count"]))

        if marker_x:
            fig.add_trace(
                go.Scatter(
                    x=marker_x,
                    y=marker_y,
                    mode="markers",
                    name="Attack",
                    marker={"color": "#d90429", "size": 8},
                )
            )

        fig.update_layout(
            xaxis_title="Timestamp",
            yaxis_title="MAC count",
            margin={"l": 20, "r": 20, "t": 30, "b": 20},
            legend={"orientation": "h"},
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No MAC snapshots available yet.")

    st.markdown("### Event Feed")
    feed = st.session_state.live_events[-20:]
    if not feed:
        st.info("No events captured yet.")
    else:
        for idx, event in enumerate(reversed(feed)):
            kind = str(event.get("kind", "UNKNOWN"))
            data = event.get("data", {})
            ts = str(event.get("timestamp", ""))
            style = _event_style(kind)
            summary = _summarize_live_event(kind, data)
            line = (
                f"[{_format_ts(ts)}] {kind} | {summary['summary']} | {summary['action']}"
            )
            st.markdown(
                "<div style='padding:7px 10px;border-radius:6px;margin-bottom:4px;"
                f"background:{style['bg']};border-left:4px solid {style['border']};'>"
                f"{html.escape(line)}</div>",
                unsafe_allow_html=True,
            )
            with st.expander(f"Event details {len(feed) - idx}", expanded=False):
                st.json(data)


def _render_attack_timeline(last_attack: Optional[Dict[str, Any]]) -> None:
    st.markdown("#### Last Incident")
    if not last_attack:
        st.markdown("<i>No attacks detected - system monitoring</i>", unsafe_allow_html=True)
        return

    attack_type = str(last_attack.get("attack_type", ""))
    details = last_attack.get("details", {})

    if attack_type == "MAC_FLOOD":
        st.markdown(
            "\n".join(
                [
                    "1. Detection",
                    f"   Type: MAC_FLOOD | Port: {details.get('offending_port', '-')} | Violations: {details.get('violation_count', '-')}",
                    "2. Attacker Identified",
                    f"   MAC: {details.get('attacker_mac', '-')} | Port: {details.get('offending_port', '-')}",
                    "3. Defense Executed",
                    "   Command: port security violation shutdown (hardware active)",
                    "4. Port Quarantined",
                    f"   Port {details.get('offending_port', '-')} moved to VLAN {details.get('quarantine_vlan', '-')}",
                    "5. Audit Written",
                    "   Chain entry logged",
                ]
            )
        )
    elif attack_type == "ARP_SPOOF":
        st.markdown(
            "\n".join(
                [
                    "1. Detection",
                    "   Type: ARP_SPOOF | IP mapping changed",
                    "2. Attacker Identified",
                    (
                        f"   MAC: {details.get('attacker_mac', '-')} | "
                        f"Port: {details.get('attacker_port', '-') } | "
                        f"Impersonated IP: {details.get('impersonated_ip', '-') }"
                    ),
                    (
                        f"   Victim: {details.get('victim_ip', '-')} "
                        f"({details.get('victim_mac', '-')}) | "
                        f"Legitimate MAC: {details.get('legitimate_mac', '-') }"
                    ),
                    "3. Defense Executed",
                    f"   Command: vlan {details.get('quarantine_vlan', '-')} untagged {details.get('attacker_port', '-')}",
                    "4. Port Quarantined",
                    f"   Port {details.get('attacker_port', '-')} moved to VLAN {details.get('quarantine_vlan', '-')}",
                    "5. Audit Written",
                    "   Chain entry logged",
                ]
            )
        )
    else:
        st.json(last_attack)


def _render_attack_console() -> None:
    st.subheader("ATTACK CONSOLE")
    left_col, right_col = st.columns([3, 2])

    with left_col:
        st.markdown("#### Action Terminal")
        st.markdown(
            _build_terminal(st.session_state.command_records[-150:], small=False, force_gray=False),
            unsafe_allow_html=True,
        )

        with st.expander("Polling Log (last 10 polls)", expanded=False):
            st.markdown(
                _build_terminal(st.session_state.polling_records[-10:], small=True, force_gray=True),
                unsafe_allow_html=True,
            )

        st.markdown("#### Manual Command")
        command_text = st.text_input("Command", key="manual_command_text")
        if st.button("Run Command", key="run_command_button"):
            command = command_text.strip()
            if not command:
                st.warning("Command cannot be empty.")
            else:
                try:
                    st.session_state.command_queue.put_nowait({"type": "COMMAND", "command": command})
                    st.success(f"Queued command: {command}")
                except queue.Full:
                    st.error("Command queue is full. Wait and retry.")

    with right_col:
        _render_attack_timeline(st.session_state.last_attack_details)

        st.markdown("#### Quarantine Panel")
        if not st.session_state.quarantined_ports:
            st.info("No quarantined ports.")
        else:
            for port in list(st.session_state.quarantined_ports):
                meta = st.session_state.quarantine_details.get(port, {})
                attack_type = str(meta.get("attack_type", "UNKNOWN"))
                since = _format_ts(str(meta.get("since", "")))
                st.markdown(f"Port {port} - QUARANTINED")
                st.caption(f"Reason: {attack_type} | Since: {since}")

                button_key = "recover_" + port.replace(" ", "_").replace("/", "_")
                if st.button("Authorize Port Recovery", key=button_key):
                    try:
                        st.session_state.command_queue.put_nowait(
                            {"type": "RECOVER_PORT", "port": port}
                        )
                        st.success(f"Recovery queued for {port}")
                    except queue.Full:
                        st.error("Command queue is full. Wait and retry.")


def _render_audit_proof() -> None:
    st.subheader("AUDIT & PROOF")

    rows_asc = db.get_audit_rows(st.session_state.db_conn, limit=None, ascending=True)
    valid, message = crypto_log.verify_chain(rows_asc)
    checked_at = datetime.now().strftime("%H:%M:%S")
    if valid:
        st.markdown(
            "<div style='padding:10px;border-radius:8px;background:#e8f7ea;border:1px solid #2f8f46;'>"
            f"CHAIN INTEGRITY VERIFIED - {len(rows_asc)} entries - Last checked: {checked_at}"
            "</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            "<div style='padding:10px;border-radius:8px;background:#ffe6e6;border:1px solid #cc0000;'>"
            f"CHAIN INTEGRITY BROKEN - {html.escape(message)}"
            "</div>",
            unsafe_allow_html=True,
        )

    if st.button("Verify Now", key="verify_chain_button"):
        rows_asc = db.get_audit_rows(st.session_state.db_conn, limit=None, ascending=True)
        verified, verify_msg = crypto_log.verify_chain(rows_asc)
        if verified:
            st.success(verify_msg)
        else:
            st.error(verify_msg)

    st.markdown("### Audit Entries")
    rows_desc = db.get_audit_rows(st.session_state.db_conn, limit=300, ascending=False)
    if not rows_desc:
        st.info("No audit entries yet.")
        return

    for row in rows_desc:
        action_type = str(row.get("action_type", "UNKNOWN"))
        label_prefix = "[INFO]"
        if action_type == "ATTACK_EVENT":
            label_prefix = "[ALERT]"
        elif action_type in {"BASELINE_EVENT", "PORT_RECOVERY"}:
            label_prefix = "[SYSTEM]"
        elif action_type == "ERROR_EVENT":
            label_prefix = "[WARN]"
        elif action_type == "COMMAND":
            label_prefix = "[COMMAND]"

        label = f"{label_prefix} #{row['id']} {action_type} - {row['timestamp']}"
        with st.expander(label, expanded=False):
            prev_hash = str(row.get("prev_hash", ""))
            entry_hash = str(row.get("entry_hash", ""))
            st.write(f"Prev Hash: {prev_hash[:16]}... -> Entry Hash: {entry_hash[:16]}...")

            c1, c2 = st.columns(2)
            with c1:
                show_enc = st.button("View Encrypted Blob", key=f"show_enc_{row['id']}")
            with c2:
                show_dec = st.button("View Decrypted", key=f"show_dec_{row['id']}")

            if show_enc:
                st.code(str(row.get("encrypted_blob", "")), language="text")

            if show_dec:
                try:
                    decrypted = crypto_log.decrypt_text(
                        st.session_state.fernet,
                        str(row.get("encrypted_blob", "")),
                    )
                except Exception as exc:
                    decrypted = f"Decryption failed: {exc}"
                st.code(decrypted, language="json")


def main() -> None:
    st.set_page_config(page_title="SecureLAN Monitor", layout="wide")
    try:
        config = load_config()
    except Exception as exc:
        st.error(f"Failed to load config.yaml: {exc}")
        st.stop()

    if str(config.get("mode", "hardware")).lower() != "hardware":
        st.error("This build is hardware-only. Set mode: hardware in config.yaml.")
        st.stop()

    try:
        _init_session_state(config)
    except Exception as exc:
        st.error(f"Failed to initialize app state: {exc}")
        st.stop()
    _start_worker_if_needed()

    st_autorefresh(interval=int(config.get("streamlit_refresh_ms", 3000)), key="securelan-refresh")

    drained = _drain_event_queue()
    st.sidebar.write(f"Queue events processed this refresh: {drained}")

    if st.session_state.errors:
        st.sidebar.error(st.session_state.errors[-1].get("message", "Unknown worker error"))

    with st.sidebar.expander("UI Preview", expanded=False):
        st.caption("Load mock entries to preview the dashboard layout quickly.")
        if st.button("Load Mock Data", key="load_mock_ui_data"):
            if _seed_mock_ui_data():
                st.sidebar.success("Mock data loaded. UI pages now show sample content.")
                st.rerun()
            else:
                st.sidebar.info("Mock data is already loaded in this session.")

    page = st.sidebar.radio(
        "Pages",
        ["NETWORK STATUS", "ATTACK CONSOLE", "AUDIT & PROOF"],
    )

    st.title("SecureLAN Monitor")

    if page == "NETWORK STATUS":
        _render_network_status()
    elif page == "ATTACK CONSOLE":
        _render_attack_console()
    else:
        _render_audit_proof()


if __name__ == "__main__":
    main()
