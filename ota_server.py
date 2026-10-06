#!/usr/bin/env python3
"""
OTA firmware server (runs on the workstation).

1. Reads firmware.txt and splits it into exactly four ordered, non-empty chunks.
2. Hashes every chunk with SHA-256 (leaves H0..H3) and builds a binary Merkle
   tree: H01 = SHA256(H0 || H1), H23 = SHA256(H2 || H3), root = SHA256(H01 || H23).
3. Writes a manifest (version, size, chunk count, Merkle root, chunk index/filename).
4. Publishes the manifest and the chunks over MQTT (QoS 1).

Besides the normal update, the server can run *scenarios* that deliberately
misbehave (drop, duplicate, reorder, delay, tamper, forge, replay) so the
verification on the Raspberry Pi can be evaluated. run.py runs all of them.

Example:
    python3 ota_server.py --broker localhost --scenario normal
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import paho.mqtt.client as mqtt

# --------------------------------------------------------------------------- #
# Protocol constants (must match ota_client.py)
# --------------------------------------------------------------------------- #
NUM_CHUNKS = 4
QOS = 1
MANIFEST_TOPIC = "ota/firmware/manifest"
CHUNK_TOPIC = "ota/firmware/{version}/chunk/{index}"
STATUS_TOPIC_FILTER = "ota/status/+"
DEVICE_STATE_TOPIC_FILTER = "ota/clients/+/state"

DEFAULT_VERSION = "1.0.0"

# Simulated attacker content (plain text, never executed).
ROLLBACK_VERSION = "0.9.0"
ROLLBACK_FIRMWARE = (
    b"=== SIMULATED FIRMWARE IMAGE ===\n"
    b"Firmware: aau-iot-sensor-node\n"
    b"Version: 0.9.0\n"
    b"NOTE: old release with a known vulnerability (CVE-SIM-0001).\n"
    b"[config]\nTELNET_DEBUG=enabled\nMQTT_TLS=disabled\n"
)
MALICIOUS_LINE = b"\n# injected by attacker: BACKDOOR_ENABLED=true, EXFIL_HOST=203.0.113.66\n"


# --------------------------------------------------------------------------- #
# Chunking and Merkle tree
# --------------------------------------------------------------------------- #
def split_into_chunks(data: bytes, n: int = NUM_CHUNKS) -> list[bytes]:
    """Split data into n ordered, non-empty byte chunks.

    Rule for sizes not divisible by n: with size = q*n + r, the first r chunks
    get q+1 bytes and the remaining chunks get q bytes, so chunk sizes differ by
    at most one byte. Example: 1027 bytes -> 257, 257, 257, 256.
    """
    if len(data) < n:
        raise ValueError(f"firmware must be at least {n} bytes to form {n} non-empty chunks")
    q, r = divmod(len(data), n)
    chunks, pos = [], 0
    for i in range(n):
        size = q + 1 if i < r else q
        chunks.append(data[pos:pos + size])
        pos += size
    return chunks


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_levels(chunks: list[bytes]) -> list[list[bytes]]:
    """Return every level of the Merkle tree, leaves first and root last.

    Leaves are SHA256(chunk). Each parent is SHA256(left || right) over the raw
    32-byte digests, combined in index order.
    """
    level = [sha256(c) for c in chunks]
    levels = [level]
    while len(level) > 1:
        if len(level) % 2:
            raise ValueError("number of nodes per level must be even")
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def merkle_root(chunks: list[bytes]) -> bytes:
    return merkle_levels(chunks)[-1][0]


# --------------------------------------------------------------------------- #
# Release (chunks + tree + manifest)
# --------------------------------------------------------------------------- #
def chunk_filename(index: int) -> str:
    return f"chunk_{index}.bin"


@dataclass
class Release:
    version: str
    firmware: bytes
    chunks: list[bytes]
    levels: list[list[bytes]]
    manifest: dict


def prepare_release(firmware: bytes, version: str, update_id: str) -> Release:
    chunks = split_into_chunks(firmware)
    levels = merkle_levels(chunks)
    manifest = {
        "type": "manifest",
        "update_id": update_id,
        "firmware_version": version,
        "firmware_size": len(firmware),
        "chunk_count": len(chunks),
        "hash_algorithm": "sha256",
        "merkle_root": levels[-1][0].hex(),
        "chunks": [{"index": i, "filename": chunk_filename(i)} for i in range(len(chunks))],
    }
    return Release(version, firmware, chunks, levels, manifest)


def write_release(release: Release, out_dir: Path) -> None:
    """Store the manifest and the chunk files on disk (server-side artefacts)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for i, chunk in enumerate(release.chunks):
        (out_dir / chunk_filename(i)).write_bytes(chunk)
    (out_dir / "manifest.json").write_text(json.dumps(release.manifest, indent=2) + "\n")


def describe_release(release: Release) -> str:
    leaves, parents, (root,) = release.levels
    lines = [f"Firmware version {release.version}, {len(release.firmware)} bytes"]
    for i, (chunk, h) in enumerate(zip(release.chunks, leaves)):
        lines.append(f"  C{i}: {len(chunk):5d} bytes   H{i}  = {h.hex()}")
    lines.append(f"  H01 = SHA256(H0||H1) = {parents[0].hex()}")
    lines.append(f"  H23 = SHA256(H2||H3) = {parents[1].hex()}")
    lines.append(f"  ROOT = SHA256(H01||H23) = {root.hex()}")
    return "\n".join(lines)


def chunk_payload(manifest: dict, index: int, data: bytes) -> dict:
    return {
        "type": "chunk",
        "update_id": manifest["update_id"],
        "firmware_version": manifest["firmware_version"],
        "index": index,
        "filename": chunk_filename(index),
        "encoding": "base64",
        "data": base64.b64encode(data).decode("ascii"),
    }


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Scenario:
    category: str      # baseline | network fault | attack
    expected: str      # ACCEPTED | REJECTED
    description: str


SCENARIOS: dict[str, Scenario] = {
    "normal": Scenario("baseline", "ACCEPTED",
                       "Manifest followed by chunks 0..3 in order."),
    "duplicate_chunk": Scenario("network fault", "ACCEPTED",
                                "Chunk 1 is delivered twice (QoS 1 redelivery); duplicate is ignored."),
    "reorder": Scenario("network fault", "ACCEPTED",
                        "Chunks arrive out of order (3, 1, 2, 0) and two of them before the manifest."),
    "delay_chunk": Scenario("network fault", "ACCEPTED",
                            "One chunk is delayed, but arrives before the client timeout."),
    "drop_chunk": Scenario("network fault", "REJECTED",
                           "One chunk is never sent; the client times out."),
    "late_chunk": Scenario("network fault", "REJECTED",
                           "One chunk arrives after the client timeout; it is ignored."),
    "invalid_index": Scenario("attack", "REJECTED",
                              "An extra chunk with index 4 is injected."),
    "tamper_chunk": Scenario("attack", "REJECTED",
                             "One byte of a chunk is modified in transit (same length)."),
    "conflicting_duplicate": Scenario("attack", "REJECTED",
                                      "A second, different copy of a chunk index is injected."),
    "size_mismatch": Scenario("attack", "REJECTED",
                              "Manifest firmware_size is altered; chunks and root are genuine."),
    "manifest_tamper": Scenario("attack", "REJECTED",
                                "Manifest Merkle root is replaced by the root of a malicious image; "
                                "genuine chunks are delivered."),
    "forged_update": Scenario("attack", "ACCEPTED",
                              "Attacker replaces manifest AND all chunks with a malicious image and "
                              "a correctly recomputed root (NOT detectable by Merkle alone)."),
    "rollback_replay": Scenario("attack", "ACCEPTED",
                                "Attacker replays an old, genuine release (v0.9.0) with its own valid "
                                "manifest (NOT detectable without version/rollback policy)."),
}


@dataclass
class Step:
    label: str
    topic: str
    payload: dict
    delay_before: float = 0.0


@dataclass
class Plan:
    scenario: str
    update_id: str
    release: Release
    steps: list[Step] = field(default_factory=list)


def build_plan(scenario: str, firmware: bytes, version: str = DEFAULT_VERSION, *,
               tamper_index: int = 2, delay: float = 3.0, late_delay: float = 15.0) -> Plan:
    """Build the list of MQTT messages that a scenario publishes."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}")
    if not 0 <= tamper_index < NUM_CHUNKS:
        raise ValueError(f"tamper index must be 0..{NUM_CHUNKS - 1}")

    update_id = uuid.uuid4().hex[:12]
    k = tamper_index

    # Attacks that replace the whole release.
    if scenario == "forged_update":
        firmware = firmware + MALICIOUS_LINE
    elif scenario == "rollback_replay":
        firmware, version = ROLLBACK_FIRMWARE, ROLLBACK_VERSION

    release = prepare_release(firmware, version, update_id)
    manifest = dict(release.manifest)
    chunks = list(release.chunks)

    def chunk_step(i: int, data: bytes | None = None, label: str = "", delay_before: float = 0.0,
                   index_override: int | None = None) -> Step:
        idx = i if index_override is None else index_override
        payload = chunk_payload(manifest, idx, chunks[i] if data is None else data)
        return Step(label or f"chunk {idx}", CHUNK_TOPIC.format(version=version, index=idx),
                    payload, delay_before)

    def manifest_step(label: str = "manifest") -> Step:
        return Step(label, MANIFEST_TOPIC, manifest)

    if scenario == "size_mismatch":
        manifest["firmware_size"] += 1
    elif scenario == "manifest_tamper":
        evil_root = merkle_root(split_into_chunks(firmware + MALICIOUS_LINE))
        manifest["merkle_root"] = evil_root.hex()

    if scenario == "duplicate_chunk":
        steps = [manifest_step(), chunk_step(0), chunk_step(1), chunk_step(1, label="chunk 1 (duplicate)"),
                 chunk_step(2), chunk_step(3)]
    elif scenario == "reorder":
        steps = [chunk_step(3), chunk_step(1), manifest_step(), chunk_step(2), chunk_step(0)]
    elif scenario in ("delay_chunk", "late_chunk"):
        wait = delay if scenario == "delay_chunk" else late_delay
        steps = [manifest_step()] + [chunk_step(i) for i in range(NUM_CHUNKS) if i != k]
        steps.append(chunk_step(k, label=f"chunk {k} (after {wait:.1f}s)", delay_before=wait))
    elif scenario == "drop_chunk":
        steps = [manifest_step()] + [chunk_step(i) for i in range(NUM_CHUNKS) if i != k]
    elif scenario == "invalid_index":
        steps = [manifest_step(), chunk_step(0), chunk_step(1),
                 chunk_step(3, label="chunk 4 (injected)", index_override=NUM_CHUNKS),
                 chunk_step(2), chunk_step(3)]
    elif scenario == "tamper_chunk":
        steps = [manifest_step()] + [
            chunk_step(i, flip_byte(chunks[i]), label=f"chunk {i} (tampered)") if i == k else chunk_step(i)
            for i in range(NUM_CHUNKS)]
    elif scenario == "conflicting_duplicate":
        others = [i for i in range(NUM_CHUNKS) if i != k]
        steps = [manifest_step(), chunk_step(k),
                 chunk_step(k, flip_byte(chunks[k]), label=f"chunk {k} (conflicting copy)")]
        steps += [chunk_step(i) for i in others]
    else:  # normal, size_mismatch, manifest_tamper, forged_update, rollback_replay
        steps = [manifest_step()] + [chunk_step(i) for i in range(NUM_CHUNKS)]

    return Plan(scenario, update_id, release, steps)


def flip_byte(data: bytes) -> bytes:
    """Return a copy of data with one byte in the middle changed (length preserved)."""
    pos = len(data) // 2
    return data[:pos] + bytes([data[pos] ^ 0x20]) + data[pos + 1:]


# --------------------------------------------------------------------------- #
# MQTT publisher
# --------------------------------------------------------------------------- #
def make_mqtt_client(client_id: str) -> mqtt.Client:
    """Create a paho client that works with both paho-mqtt 1.6 and 2.x."""
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    except AttributeError:  # paho-mqtt < 2.0
        return mqtt.Client(client_id=client_id)


def connect_failed(rc) -> bool:
    return rc.is_failure if hasattr(rc, "is_failure") else rc != 0


class OtaPublisher:
    """MQTT side of the server: publishes plans and listens for device verdicts."""

    def __init__(self, host: str, port: int = 1883, client_id: str = "ota-server"):
        self.host, self.port = host, port
        self.client = make_mqtt_client(client_id)
        self.connected = threading.Event()
        self.devices: dict[str, dict] = {}
        self.statuses: dict[str, dict] = {}
        self._cond = threading.Condition()
        self.client.on_connect = self._on_connect
        self.client.on_message = lambda *args: None
        self.client.message_callback_add(DEVICE_STATE_TOPIC_FILTER, self._on_device_state)
        self.client.message_callback_add(STATUS_TOPIC_FILTER, self._on_status)

    def connect(self, timeout: float = 10.0) -> None:
        self.client.connect(self.host, self.port, keepalive=30)
        self.client.loop_start()
        if not self.connected.wait(timeout):
            self.client.loop_stop()
            raise ConnectionError(f"could not connect to MQTT broker {self.host}:{self.port}")

    def close(self) -> None:
        self.client.disconnect()
        self.client.loop_stop()

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if connect_failed(rc):
            print(f"[server] broker refused connection: {rc}")
            return
        client.subscribe([(DEVICE_STATE_TOPIC_FILTER, QOS), (STATUS_TOPIC_FILTER, QOS)])
        self.connected.set()

    def _on_device_state(self, client, userdata, msg):
        try:
            state = json.loads(msg.payload)
        except ValueError:
            return
        with self._cond:
            self.devices[msg.topic.split("/")[2]] = state
            self._cond.notify_all()

    def _on_status(self, client, userdata, msg):
        try:
            status = json.loads(msg.payload)
        except ValueError:
            return
        with self._cond:
            self.statuses[status.get("update_id")] = status
            self._cond.notify_all()

    def wait_for_device(self, timeout: float = 5.0) -> dict | None:
        """Wait until an OTA client has announced itself as online (retained state)."""
        def online():
            return next((d for d in self.devices.values() if d.get("state") == "online"), None)
        with self._cond:
            self._cond.wait_for(online, timeout)
            return online()

    def wait_for_status(self, update_id: str, timeout: float) -> dict | None:
        with self._cond:
            self._cond.wait_for(lambda: update_id in self.statuses, timeout)
            return self.statuses.get(update_id)

    def publish_plan(self, plan: Plan, log=print) -> None:
        for step in plan.steps:
            if step.delay_before:
                log(f"[server]   ... waiting {step.delay_before:.1f}s")
                time.sleep(step.delay_before)
            info = self.client.publish(step.topic, json.dumps(step.payload), qos=QOS)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError(f"publish failed for {step.label}: rc={info.rc}")
            info.wait_for_publish(10)  # QoS 1: wait for the broker's PUBACK
            log(f"[server]   published {step.label:<28} -> {step.topic}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv=None) -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    p = argparse.ArgumentParser(description="OTA firmware server (MQTT publisher).")
    p.add_argument("--broker", default="localhost", help="MQTT broker host (default: localhost)")
    p.add_argument("--port", type=int, default=1883)
    p.add_argument("--firmware", type=Path, default=here / "firmware.txt")
    p.add_argument("--version", dest="fw_version", default=DEFAULT_VERSION, help="firmware version")
    p.add_argument("--out-dir", type=Path, default=here / "build",
                   help="where manifest.json and chunk files are written (default: ./build)")
    p.add_argument("--scenario", default="normal", choices=SCENARIOS)
    p.add_argument("--tamper-index", type=int, default=2, help="chunk index used by fault/attack scenarios")
    p.add_argument("--delay", type=float, default=3.0, help="delay for delay_chunk (seconds)")
    p.add_argument("--late-delay", type=float, default=None,
                   help="delay for late_chunk (default: client timeout + 3s)")
    p.add_argument("--no-wait", action="store_true",
                   help="publish without checking that a client is online / waiting for its verdict")
    p.add_argument("--list-scenarios", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.list_scenarios:
        for name, s in SCENARIOS.items():
            print(f"{name:<22} {s.category:<14} expect {s.expected:<9} {s.description}")
        return 0

    firmware = args.firmware.read_bytes()
    genuine = prepare_release(firmware, args.fw_version, update_id="")
    write_release(genuine, args.out_dir)
    print(f"[server] {describe_release(genuine)}")
    print(f"[server] manifest and chunks written to {args.out_dir}")

    pub = OtaPublisher(args.broker, args.port)
    pub.connect()
    print(f"[server] connected to broker {args.broker}:{args.port}")

    client_timeout = 10.0
    if not args.no_wait:
        device = pub.wait_for_device(timeout=5)
        if device is None:
            print("[server] ERROR: no OTA client online. Start ota_client.py on the Pi first "
                  "(or use --no-wait).")
            pub.close()
            return 1
        client_timeout = float(device.get("timeout", client_timeout))
        print(f"[server] device online: {device.get('client_id')} (timeout {client_timeout:.0f}s)")

    late_delay = args.late_delay if args.late_delay is not None else client_timeout + 3
    plan = build_plan(args.scenario, firmware, args.fw_version, tamper_index=args.tamper_index,
                      delay=args.delay, late_delay=late_delay)
    s = SCENARIOS[args.scenario]
    print(f"[server] scenario '{args.scenario}': {s.description}")
    print(f"[server] update_id={plan.update_id}")
    pub.publish_plan(plan)

    exit_code = 0
    if not args.no_wait:
        status = pub.wait_for_status(plan.update_id, timeout=client_timeout + 5)
        if status is None:
            print("[server] no verdict received from the device")
            exit_code = 2
        else:
            print(f"[server] device verdict: {status['status']} - {status['reason']}")
            print(f"[server] expected: {s.expected}")
    pub.close()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
