import json
import queue
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
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

    if "live_events" not in st.session_state:
        st.session_state.live_events = []

    if "errors" not in st.session_state:
        st.session_state.errors = []

    if "mac_metric" not in st.session_state:
        st.session_state.mac_metric = {
            "current_mac_count": 0,
            "previous_mac_count": 0,
            "delta": 0,
            "threshold": int(config["detection"]["mac_flood_threshold"]),
            "timestamp": "",
        }

    if "arp_metric" not in st.session_state:
        st.session_state.arp_metric = {
            "tracked_ip_count": 0,
            "last_arp_packet": {},
            "last_suspicious_mapping": None,
            "timestamp": "",
        }


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
                _append_capped(st.session_state.command_records, data)
                _write_audit("COMMAND", data, hmac_sig=data.get("hmac_sig", ""))

            elif kind == "ATTACK_EVENT":
                _append_capped(st.session_state.live_events, data)
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

            elif kind == "ERROR_EVENT":
                _append_capped(st.session_state.errors, data)
                _write_audit("ERROR_EVENT", data)

            else:
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


def _render_live_monitor() -> None:
    cfg = st.session_state.config
    mac = st.session_state.mac_metric
    arp = st.session_state.arp_metric

    st.subheader("LIVE MONITOR")
    st.write(f"Current mode: {str(cfg.get('mode', 'hardware')).upper()}")
    st.write(f"Monitor status: {'RUNNING' if st.session_state.worker_thread and st.session_state.worker_thread.is_alive() else 'STOPPED'}")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**MAC Flood detector**")
        st.write(f"Current MAC count: {mac.get('current_mac_count', 0)}")
        st.write(f"Previous MAC count: {mac.get('previous_mac_count', 0)}")
        st.write(f"Delta: {mac.get('delta', 0)}")
        st.write(f"Threshold: {mac.get('threshold', 0)}")

    with col2:
        st.markdown("**ARP detector**")
        st.write(f"Tracked IP count: {arp.get('tracked_ip_count', 0)}")
        st.write(f"Last ARP packet: {json.dumps(arp.get('last_arp_packet', {}), indent=2)}")
        st.write(
            "Last suspicious mapping: "
            + json.dumps(arp.get("last_suspicious_mapping", {}), indent=2)
            if arp.get("last_suspicious_mapping")
            else "Last suspicious mapping: None"
        )

    snapshots = db.get_recent_mac_snapshots(st.session_state.db_conn, limit=120)
    if snapshots:
        df = pd.DataFrame(snapshots)
        fig = px.line(df, x="timestamp", y="mac_count", title="MAC Count Over Time")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No MAC snapshots yet.")

    st.markdown("**Last 10 events**")
    recent = db.get_recent_events(st.session_state.db_conn, limit=10)
    if recent:
        for row in recent:
            details = json.loads(row["details_json"])
            ts = row["timestamp"]
            attack_type = row["attack_type"]
            if attack_type == "MAC_FLOOD":
                line = (
                    f"[{ts}] MAC_FLOOD detected | current={details.get('current')} "
                    f"prev={details.get('previous')} delta={details.get('delta')} "
                    f"threshold={details.get('threshold')}"
                )
            elif attack_type == "ARP_SPOOF":
                line = (
                    f"[{ts}] ARP_SPOOF detected | ip={details.get('ip')} "
                    f"old_mac={details.get('old_mac')} new_mac={details.get('new_mac')}"
                )
            else:
                line = f"[{ts}] {attack_type} | details={details}"
            st.write(line)
    else:
        st.info("No attack events captured yet.")

    st.info("Demo buttons use synthetic triggers only. They do not generate real attack traffic.")

    c1, c2 = st.columns(2)
    if c1.button("Inject MAC Flood"):
        try:
            st.session_state.command_queue.put_nowait({"action": "INJECT_MAC_FLOOD", "source": "DEMO"})
            st.success("MAC flood demo trigger queued.")
        except queue.Full:
            st.error("Command queue is full. Wait a moment and try again.")

    if c2.button("Inject ARP Spoof"):
        try:
            st.session_state.command_queue.put_nowait({"action": "INJECT_ARP_SPOOF", "source": "DEMO"})
            st.success("ARP spoof demo trigger queued.")
        except queue.Full:
            st.error("Command queue is full. Wait a moment and try again.")


def _render_switch_console() -> None:
    st.subheader("SWITCH CONSOLE")

    recent_records = st.session_state.command_records[-40:]
    terminal_lines: List[str] = []
    for rec in recent_records:
        terminal_lines.append(f"[{rec['timestamp']}] {rec['source']} > {rec['command']}")
        terminal_lines.append(rec.get("output", ""))
        terminal_lines.append("")

    st.text_area(
        "Live serial terminal output",
        value="\n".join(terminal_lines),
        height=280,
        disabled=True,
    )

    with st.form("manual_command_form", clear_on_submit=True):
        command = st.text_input("Manual command")
        send = st.form_submit_button("Send")

    if send:
        cmd = command.strip()
        if cmd:
            try:
                st.session_state.command_queue.put_nowait({"command": cmd, "source": "MANUAL"})
                st.success(f"Queued command: {cmd}")
            except queue.Full:
                st.error("Command queue is full. Wait a moment and try again.")
        else:
            st.warning("Command cannot be empty.")

    if st.session_state.command_records:
        df = pd.DataFrame(st.session_state.command_records)
        st.dataframe(
            df[["timestamp", "source", "command", "output", "hmac_sig"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No command history yet.")

    col1, col2 = st.columns(2)
    if col1.button("Undo Last Command"):
        idx = next(
            (
                i
                for i in range(len(st.session_state.command_records) - 1, -1, -1)
                if st.session_state.command_records[i].get("source") == "MANUAL"
            ),
            None,
        )
        if idx is None:
            st.warning("No MANUAL command available to undo.")
        else:
            removed = st.session_state.command_records.pop(idx)
            _write_audit(
                "UNDO_COMMAND",
                {
                    "timestamp": _utc_now_iso(),
                    "removed_command": removed,
                    "note": "UI/DB undo only. No reverse switch command executed.",
                },
            )
            st.success("Last MANUAL command removed from UI history and logged.")

    if col2.button("Take Snapshot"):
        mac = st.session_state.mac_metric
        now = _utc_now_iso()
        db.insert_mac_snapshot(
            st.session_state.db_conn,
            timestamp=now,
            mac_count=int(mac.get("current_mac_count", 0)),
            delta=int(mac.get("delta", 0)),
        )
        _write_audit(
            "SNAPSHOT",
            {
                "timestamp": now,
                "mac_metric": st.session_state.mac_metric,
                "arp_metric": st.session_state.arp_metric,
            },
        )
        st.success("Snapshot stored.")


def _render_audit_trail() -> None:
    st.subheader("AUDIT TRAIL")

    rows_desc = db.get_audit_rows(st.session_state.db_conn, limit=300, ascending=False)
    if rows_desc:
        df = pd.DataFrame(rows_desc)
        st.dataframe(
            df[["timestamp", "action_type", "description", "prev_hash", "entry_hash"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No audit entries yet.")

    if st.button("Verify Chain"):
        rows_asc = db.get_audit_rows(st.session_state.db_conn, limit=None, ascending=True)
        valid, message = crypto_log.verify_chain(rows_asc)
        if valid:
            st.success(message)
        else:
            st.error(message)

    if rows_desc:
        st.markdown("**Selected entry inspector**")
        id_list = [row["id"] for row in rows_desc]
        selected_id = st.selectbox("Select audit id", id_list)
        selected = next(row for row in rows_desc if row["id"] == selected_id)

        st.text_area("Encrypted blob", selected["encrypted_blob"], height=130)

        try:
            decrypted = crypto_log.decrypt_text(st.session_state.fernet, selected["encrypted_blob"])
        except Exception as exc:
            decrypted = f"Decryption failed: {exc}"
        st.text_area("Decrypted plaintext", decrypted, height=180)

        if st.button("Demo Tamper Test"):
            rows_asc = db.get_audit_rows(st.session_state.db_conn, limit=None, ascending=True)
            if rows_asc:
                tampered = [dict(row) for row in rows_asc]
                tampered[0]["description"] = tampered[0]["description"] + "|tampered"
                valid, message = crypto_log.verify_chain(tampered)
                if not valid:
                    st.success(f"Tamper detected as expected: {message}")
                else:
                    st.error("Tamper demo unexpectedly passed.")


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

    page = st.sidebar.radio(
        "Pages",
        ["LIVE MONITOR", "SWITCH CONSOLE", "AUDIT TRAIL"],
    )

    st.title("SecureLAN Monitor")

    if page == "LIVE MONITOR":
        _render_live_monitor()
    elif page == "SWITCH CONSOLE":
        _render_switch_console()
    else:
        _render_audit_trail()


if __name__ == "__main__":
    main()
