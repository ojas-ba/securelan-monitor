import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import serial

from crypto_log import sign_command_hmac


PROMPT_RE = re.compile(r"(^|\n)[^\n]*[>#]\s*$")
LOGIN_RE = re.compile(r"login:|username:", re.IGNORECASE)
PASSWORD_RE = re.compile(r"password:", re.IGNORECASE)
AUTH_FAIL_RE = re.compile(
    r"login\s+failed|authentication\s+failed|invalid\s+password|access\s+denied|incorrect\s+password",
    re.IGNORECASE,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SwitchSerialEngine:
    def __init__(self, serial_cfg: Dict[str, Any], hmac_secret: bytes):
        self.serial_cfg = serial_cfg
        self.hmac_secret = hmac_secret
        self._ser: Optional[serial.Serial] = None
        self._lock = threading.RLock()
        self._history: List[Dict[str, Any]] = []

    def is_open(self) -> bool:
        return self._ser is not None and self._ser.is_open

    def open(self) -> Tuple[bool, str]:
        if self.is_open():
            return True, "Serial already open"

        try:
            self._ser = serial.Serial(
                port=self.serial_cfg["port"],
                baudrate=int(self.serial_cfg.get("baudrate", 9600)),
                timeout=float(self.serial_cfg.get("timeout", 2)),
            )
            return True, "Serial connection established"
        except Exception as exc:
            return False, f"Serial open failed: {exc}"

    def close(self) -> None:
        if self._ser and self._ser.is_open:
            self._ser.close()

    def _write(self, text: str) -> None:
        if not self._ser:
            raise RuntimeError("Serial is not initialized")
        self._ser.write(text.encode("utf-8"))
        self._ser.flush()

    def _read_until_prompt(self, timeout_sec: float = 4.0) -> str:
        if not self._ser:
            raise RuntimeError("Serial is not initialized")

        start = time.time()
        chunks: List[bytes] = []
        last_rx = start

        while (time.time() - start) < timeout_sec:
            waiting = self._ser.in_waiting if self._ser else 0
            if waiting > 0:
                chunk = self._ser.read(waiting)
                if chunk:
                    chunks.append(chunk)
                    last_rx = time.time()
                    text_so_far = b"".join(chunks).decode("utf-8", errors="ignore")
                    if PROMPT_RE.search(text_so_far) and (time.time() - last_rx) > 0.2:
                        break
            else:
                # Allow some idle time for prompt completion.
                if chunks and (time.time() - last_rx) > 0.4:
                    break
                time.sleep(0.05)

        return b"".join(chunks).decode("utf-8", errors="ignore")

    def _send_raw(self, text: str, timeout_sec: float = 4.0) -> str:
        self._write(text + "\r\n")
        return self._read_until_prompt(timeout_sec=timeout_sec)

    def login_and_prepare(self) -> List[Dict[str, Any]]:
        with self._lock:
            if not self.is_open():
                ok, msg = self.open()
                if not ok:
                    raise RuntimeError(msg)

            startup_output = self._read_until_prompt(timeout_sec=2.0)
            username = str(self.serial_cfg.get("username", "")).strip()
            password = str(self.serial_cfg.get("password", "")).strip()

            if LOGIN_RE.search(startup_output):
                if not username:
                    raise RuntimeError("Login prompt received but username is empty")
                startup_output = self._send_raw(username, timeout_sec=2.0)

            if PASSWORD_RE.search(startup_output):
                if not password:
                    raise RuntimeError("Password prompt received but password is empty")
                startup_output = self._send_raw(password, timeout_sec=3.0)

            if LOGIN_RE.search(startup_output) or PASSWORD_RE.search(startup_output):
                raise RuntimeError("Switch login did not complete")

            if AUTH_FAIL_RE.search(startup_output):
                raise RuntimeError("Authentication appears to have failed")

            records: List[Dict[str, Any]] = []
            records.append(
                {
                    "timestamp": _utc_now_iso(),
                    "source": "SYSTEM",
                    "command": "<login-sequence>",
                    "output": startup_output,
                    "hmac_sig": sign_command_hmac("<login-sequence>", self.hmac_secret),
                }
            )

            records.append(self.send_command("enable", source="SYSTEM"))
            records.append(self.send_command("skip-page-display", source="SYSTEM"))
            return records

    def send_command(self, command: str, source: str = "MANUAL", timeout_sec: float = 6.0) -> Dict[str, Any]:
        with self._lock:
            if not self.is_open():
                ok, msg = self.open()
                if not ok:
                    raise RuntimeError(msg)

            output = self._send_raw(command, timeout_sec=timeout_sec)
            record = {
                "timestamp": _utc_now_iso(),
                "source": source,
                "command": command,
                "output": output,
                "hmac_sig": sign_command_hmac(command, self.hmac_secret),
            }
            self._history.append(record)
            return record

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self._history)

    @staticmethod
    def parse_mac_count(command_output: str) -> int:
        mac_line_re = re.compile(
            r"((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})|((?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4})"
        )

        count = 0
        for line in command_output.splitlines():
            text = line.strip()
            if not text:
                continue
            if "mac" in text.lower() and "address" in text.lower():
                continue
            if PROMPT_RE.search(text):
                continue
            if mac_line_re.search(text):
                count += 1
        return count
