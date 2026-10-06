#!/usr/bin/env python3
"""
OTA firmware client (runs on the Raspberry Pi).

Subscribes to the manifest and chunk topics, collects the four chunks of an
update by index, and verifies them against the Merkle root in the manifest.

  * all four chunks (indices exactly 0..3) received before the timeout,
  * Merkle root computed from the chunks == root in the manifest,
  * reconstructed size == firmware_size in the manifest
      -> firmware_reconstructed.txt is written (chunks joined in index order)
  * any check fails
      -> update rejected, chunks cleared, reason logged, no output file

The verdict is also published to ota/status/<client_id> so the server can see it.

Example:
    python3 ota_client.py --broker 192.168.1.10
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import logging
import os
import re
import signal
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

# --------------------------------------------------------------------------- #
# Protocol constants (must match ota_server.py)
# --------------------------------------------------------------------------- #
NUM_CHUNKS = 4
QOS = 1
MANIFEST_TOPIC = "ota/firmware/manifest"
CHUNK_TOPIC_FILTER = "ota/firmware/+/chunk/+"
STATUS_TOPIC = "ota/status/{client_id}"
STATE_TOPIC = "ota/clients/{client_id}/state"

HEX_ROOT = re.compile(r"^[0-9a-f]{64}$")

log = logging.getLogger("ota_client")


# --------------------------------------------------------------------------- #
# Merkle tree (implemented independently of the server on purpose)
# --------------------------------------------------------------------------- #
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_root(chunks: list[bytes]) -> bytes:
    """Leaves are SHA256(chunk); parents are SHA256(left || right), in index order."""
    level = [sha256(c) for c in chunks]
    while len(level) > 1:
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


# --------------------------------------------------------------------------- #
# Update session state
# --------------------------------------------------------------------------- #
class UpdateRejected(Exception):
    """Raised when an update must be rejected; the message is the reason."""


class Session:
    """State of one update, identified by the update_id in every message."""

    def __init__(self, update_id: str, timeout: float):
        self.update_id = update_id
        self.started = time.monotonic()
        self.deadline = self.started + timeout
        self.manifest: dict | None = None
        self.chunks: dict[int, bytes] = {}       # stored by index, not arrival order
        self.chunk_versions: set[str] = set()
        self.duplicates_ignored = 0
        self.computed_root: str | None = None

    @property
    def version(self) -> str | None:
        if self.manifest:
            return self.manifest["firmware_version"]
        return next(iter(self.chunk_versions), None)


def validate_manifest(m: dict) -> None:
    version = m.get("firmware_version")
    if not isinstance(version, str) or not version or any(c in version for c in "/+#"):
        raise UpdateRejected(f"invalid manifest: bad firmware_version {version!r}")
    size = m.get("firmware_size")
    if not isinstance(size, int) or isinstance(size, bool) or size < NUM_CHUNKS:
        raise UpdateRejected(f"invalid manifest: bad firmware_size {size!r}")
    if m.get("chunk_count") != NUM_CHUNKS:
        raise UpdateRejected(f"invalid manifest: chunk_count must be {NUM_CHUNKS}, got {m.get('chunk_count')!r}")
    if str(m.get("hash_algorithm", "")).lower() not in ("sha256", "sha-256"):
        raise UpdateRejected(f"invalid manifest: unsupported hash_algorithm {m.get('hash_algorithm')!r}")
    root = m.get("merkle_root")
    if not isinstance(root, str) or not HEX_ROOT.match(root):
        raise UpdateRejected("invalid manifest: merkle_root must be 64 lowercase hex characters")
    entries = m.get("chunks")
    if not (isinstance(entries, list) and all(isinstance(e, dict) for e in entries)
            and [e.get("index") for e in entries] == list(range(NUM_CHUNKS))
            and all(isinstance(e.get("filename"), str) for e in entries)):
        raise UpdateRejected("invalid manifest: chunks list must describe indices 0..3 with filenames")


# --------------------------------------------------------------------------- #
# OTA client
# --------------------------------------------------------------------------- #
class OtaClient:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.client_id = args.client_id
        self.output = args.output
        self.history = args.history
        self.timeout = args.timeout
        self.lock = threading.Lock()
        self.sessions: dict[str, Session] = {}
        self.finished: set[str] = set()
        self.verdicts = 0
        self.stop = threading.Event()

        self.mqtt = make_mqtt_client(self.client_id)
        self.mqtt.on_connect = self.on_connect
        self.mqtt.on_disconnect = self.on_disconnect
        self.mqtt.on_message = self.on_message
        # If the Pi disappears, the broker tells everyone it is offline.
        self.mqtt.will_set(self.state_topic, self._state_payload("offline"), qos=QOS, retain=True)

    @property
    def state_topic(self) -> str:
        return STATE_TOPIC.format(client_id=self.client_id)

    def _state_payload(self, state: str) -> str:
        return json.dumps({"client_id": self.client_id, "state": state, "timeout": self.timeout})

    # ---- MQTT callbacks ---------------------------------------------------- #
    def on_connect(self, client, userdata, flags, rc, properties=None):
        if connect_failed(rc):
            log.error("Broker refused connection: %s", rc)
            return
        client.subscribe([(MANIFEST_TOPIC, QOS), (CHUNK_TOPIC_FILTER, QOS)])
        client.publish(self.state_topic, self._state_payload("online"), qos=QOS, retain=True)
        log.info("Connected to %s:%d as '%s', subscribed to %s and %s (QoS %d)",
                 self.args.broker, self.args.port, self.client_id, MANIFEST_TOPIC, CHUNK_TOPIC_FILTER, QOS)

    def on_disconnect(self, client, userdata, *args):
        if not self.stop.is_set():
            log.warning("Disconnected from broker, paho will reconnect automatically")

    def on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("payload is not a JSON object")
        except (UnicodeDecodeError, ValueError) as e:
            log.warning("Ignoring malformed message on %s: %s", msg.topic, e)
            return
        update_id = payload.get("update_id")
        if not isinstance(update_id, str) or not update_id:
            log.warning("Ignoring message without update_id on %s", msg.topic)
            return

        with self.lock:
            if update_id in self.finished:
                log.info("[%s] Ignoring late/duplicate message on %s (update already finished)",
                         update_id, msg.topic)
                return
            session = self.sessions.get(update_id) or self._new_session(update_id)
            try:
                if msg.topic == MANIFEST_TOPIC:
                    self._handle_manifest(session, payload)
                else:
                    self._handle_chunk(session, msg.topic, payload)
                self._try_complete(session)
            except UpdateRejected as e:
                self._reject(session, str(e))
            except Exception as e:  # never let a bad message kill the MQTT thread
                log.exception("[%s] Unexpected error", update_id)
                self._reject(session, f"malformed message: {e!r}")

    # ---- message handling (called with self.lock held) -------------------- #
    def _new_session(self, update_id: str) -> Session:
        session = Session(update_id, self.timeout)
        self.sessions[update_id] = session
        # The output file must only exist if *this* update is accepted. (A real
        # device would keep the old image in a separate A/B slot instead.)
        self._remove_output()
        log.info("[%s] New update started (timeout %.0fs)", update_id, self.timeout)
        return session

    def _handle_manifest(self, session: Session, manifest: dict) -> None:
        if manifest.get("type") != "manifest":
            raise UpdateRejected("message on manifest topic is not a manifest")
        if session.manifest is not None:
            if manifest == session.manifest:
                log.info("[%s] Duplicate manifest ignored", session.update_id)
                return
            raise UpdateRejected("conflicting manifest received for the same update")
        validate_manifest(manifest)
        version = manifest["firmware_version"]
        if session.chunk_versions - {version}:
            raise UpdateRejected(f"chunks for version(s) {sorted(session.chunk_versions)} "
                                 f"do not match manifest version {version}")
        session.manifest = manifest
        log.info("[%s] Manifest received: version=%s size=%d chunks=%d root=%s",
                 session.update_id, version, manifest["firmware_size"],
                 manifest["chunk_count"], manifest["merkle_root"])

    def _handle_chunk(self, session: Session, topic: str, chunk: dict) -> None:
        if chunk.get("type") != "chunk":
            raise UpdateRejected(f"message on {topic} is not a chunk")
        # topic: ota/firmware/<version>/chunk/<index>
        _, _, topic_version, _, topic_index = topic.split("/")
        index, version = chunk.get("index"), chunk.get("firmware_version")
        if not isinstance(index, int) or isinstance(index, bool):
            raise UpdateRejected(f"chunk index {index!r} is not an integer")
        if str(index) != topic_index or version != topic_version:
            raise UpdateRejected(f"chunk topic {topic} does not match payload (version={version}, index={index})")
        if not 0 <= index < NUM_CHUNKS:
            raise UpdateRejected(f"invalid chunk index {index}; expected indices 0..{NUM_CHUNKS - 1}")
        if session.manifest and version != session.manifest["firmware_version"]:
            raise UpdateRejected(f"chunk {index} has version {version}, manifest says "
                                 f"{session.manifest['firmware_version']}")
        if chunk.get("encoding") != "base64":
            raise UpdateRejected(f"chunk {index}: unsupported encoding {chunk.get('encoding')!r}")
        try:
            data = base64.b64decode(chunk.get("data", ""), validate=True)
        except (binascii.Error, TypeError, ValueError):
            raise UpdateRejected(f"chunk {index}: data is not valid base64") from None
        if not data:
            raise UpdateRejected(f"chunk {index} is empty")

        if index in session.chunks:
            if session.chunks[index] == data:
                session.duplicates_ignored += 1
                log.info("[%s] Duplicate chunk %d ignored", session.update_id, index)
                return
            raise UpdateRejected(f"conflicting duplicate: received two different chunks with index {index}")

        session.chunks[index] = data
        session.chunk_versions.add(version)
        log.info("[%s] Chunk %d received (%d bytes) - have %s", session.update_id, index,
                 len(data), sorted(session.chunks))

    def _try_complete(self, session: Session) -> None:
        if session.manifest is None or len(session.chunks) < NUM_CHUNKS:
            return
        manifest = session.manifest

        indices = sorted(session.chunks)
        if indices != list(range(NUM_CHUNKS)):
            raise UpdateRejected(f"received chunk indices {indices}, expected {list(range(NUM_CHUNKS))}")

        ordered = [session.chunks[i] for i in range(NUM_CHUNKS)]
        session.computed_root = merkle_root(ordered).hex()
        if session.computed_root != manifest["merkle_root"]:
            raise UpdateRejected(f"Merkle root mismatch: computed {session.computed_root}, "
                                 f"manifest {manifest['merkle_root']}")

        firmware = b"".join(ordered)
        if len(firmware) != manifest["firmware_size"]:
            raise UpdateRejected(f"size mismatch: reconstructed {len(firmware)} bytes, "
                                 f"manifest says {manifest['firmware_size']}")

        # Write atomically so a crash never leaves a half-written firmware file.
        tmp = self.output.with_name(self.output.name + ".part")
        with open(tmp, "wb") as f:
            f.write(firmware)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.output)
        self._finish(session, "ACCEPTED",
                     f"all {NUM_CHUNKS} chunks present, Merkle root and size match; wrote {self.output.name}",
                     received=indices)

    def _reject(self, session: Session, reason: str) -> None:
        received = sorted(session.chunks)
        session.chunks.clear()
        self._remove_output()
        self._finish(session, "REJECTED", reason, received)

    def _finish(self, session: Session, status: str, reason: str, received: list[int]) -> None:
        manifest = session.manifest or {}
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "client_id": self.client_id,
            "update_id": session.update_id,
            "firmware_version": session.version,
            "status": status,
            "reason": reason,
            "expected_root": manifest.get("merkle_root"),
            "computed_root": session.computed_root,
            "received_indices": received,
            "duplicates_ignored": session.duplicates_ignored,
            "elapsed_s": round(time.monotonic() - session.started, 2),
            "output_file_exists": self.output.exists(),
        }
        self.sessions.pop(session.update_id, None)
        self.finished.add(session.update_id)
        self.verdicts += 1

        if status == "ACCEPTED":
            log.info("[%s] UPDATE ACCEPTED (version %s): %s", session.update_id, session.version, reason)
        else:
            log.warning("[%s] UPDATE REJECTED: %s", session.update_id, reason)
        with open(self.history, "a") as f:
            f.write(json.dumps(record) + "\n")
        self.mqtt.publish(STATUS_TOPIC.format(client_id=self.client_id), json.dumps(record), qos=QOS)

    def _remove_output(self) -> None:
        for path in (self.output, self.output.with_name(self.output.name + ".part")):
            path.unlink(missing_ok=True)

    # ---- timeout handling -------------------------------------------------- #
    def check_timeouts(self) -> None:
        now = time.monotonic()
        with self.lock:
            for session in list(self.sessions.values()):
                if now < session.deadline:
                    continue
                if session.manifest is None:
                    reason = f"timeout after {self.timeout:.0f}s: manifest not received"
                else:
                    missing = [i for i in range(NUM_CHUNKS) if i not in session.chunks]
                    reason = f"timeout after {self.timeout:.0f}s: missing chunk(s) {missing}"
                self._reject(session, reason)

    # ---- main loop ------------------------------------------------------------ #
    def run(self) -> None:
        self.mqtt.connect(self.args.broker, self.args.port, keepalive=30)
        self.mqtt.loop_start()
        log.info("Waiting for OTA updates (Ctrl+C to stop)")
        try:
            while not self.stop.is_set():
                self.check_timeouts()
                if self.args.once and self.verdicts:
                    break
                self.stop.wait(0.2)
        finally:
            self.stop.set()
            info = self.mqtt.publish(self.state_topic, self._state_payload("offline"), qos=QOS, retain=True)
            info.wait_for_publish(5)
            self.mqtt.disconnect()
            self.mqtt.loop_stop()
            log.info("Client stopped")


def make_mqtt_client(client_id: str) -> mqtt.Client:
    """Create a paho client that works with both paho-mqtt 1.6 and 2.x."""
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    except AttributeError:  # paho-mqtt < 2.0
        return mqtt.Client(client_id=client_id)


def connect_failed(rc) -> bool:
    return rc.is_failure if hasattr(rc, "is_failure") else rc != 0


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OTA firmware client (MQTT subscriber, runs on the Pi).")
    p.add_argument("--broker", required=True, help="MQTT broker host/IP (the workstation)")
    p.add_argument("--port", type=int, default=1883)
    p.add_argument("--client-id", default=f"ota-client-{socket.gethostname()}")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="seconds from the first message of an update until it is rejected (default 10)")
    p.add_argument("--output", type=Path, default=Path("firmware_reconstructed.txt"))
    p.add_argument("--log-file", type=Path, default=Path("ota_client.log"))
    p.add_argument("--history", type=Path, default=Path("ota_history.jsonl"),
                   help="one JSON line per verdict (accepted/rejected + reason)")
    p.add_argument("--once", action="store_true", help="exit after the first verdict")
    return p.parse_args(argv)


def main(argv=None) -> None:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(args.log_file)],
    )
    client = OtaClient(args)
    signal.signal(signal.SIGTERM, lambda *_: client.stop.set())
    try:
        client.run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
