# OTA Firmware Integrity over MQTT with a Merkle Tree

A workstation splits `firmware.txt` into four chunks and builds a SHA-256 Merkle tree over them. It then publishes a manifest and the chunks over MQTT. A Raspberry Pi 4 receives the chunks, verifies them against the Merkle root and rebuilds the file. `firmware.txt` is a text file that stands in for firmware: it is never installed or executed.

| File | Runs on | Purpose |
|---|---|---|
| `ota_server.py` | workstation | Chunking, Merkle tree, manifest; publishes one update (or one test scenario) |
| `ota_client.py` | Raspberry Pi | Receives, verifies and either accepts (writes `firmware_reconstructed.txt`) or rejects |
| `run.py` | workstation | Orchestrator: runs every scenario against the Pi and collects the verdicts |
| `firmware.txt` | workstation | The simulated firmware (886 bytes) |

## 1. Setup

### Broker (workstation, macOS + Homebrew)

```bash
brew install mosquitto
```

Mosquitto 2.x only listens on localhost by default. To let the Pi connect, add these lines to `/opt/homebrew/etc/mosquitto/mosquitto.conf`:

```conf
listener 1883 0.0.0.0
allow_anonymous true
```

Then start it in the foreground, with verbose logging so the messages are visible:

```bash
mosquitto -c /opt/homebrew/etc/mosquitto/mosquitto.conf -v
```

To find the workstation's IP, which the Pi will use as `--broker`, run `ipconfig getifaddr en0`. If the macOS firewall asks, allow incoming connections for mosquitto.

### Python dependency

The scripts need `paho-mqtt` and work with version 1.6 or 2.x.

```bash
# workstation
python3 -m venv .venv && source .venv/bin/activate && pip install paho-mqtt

# Raspberry Pi (Raspberry Pi OS)
sudo apt install python3-paho-mqtt
git clone https://github.com/DesertSailor29/aau_iot_assignment.git
cd aau_iot_assignment
```

## 2. Running

**The start order matters:** broker → client → server. The client must be subscribed before anything is published, because the update messages are not retained. Both server scripts check that a client has announced itself as online and refuse to publish if none has.

1. **Pi:** `python3 ota_client.py --broker <workstation-IP>`
2. **Workstation, one normal update:** `python3 ota_server.py --broker localhost`
3. **Workstation, all experiments:** `python3 run.py --broker localhost`

### Useful options

| Script | Option | Meaning |
|---|---|---|
| `ota_client.py` | `--timeout 10` | Seconds from the first message of an update until it is rejected |
| `ota_client.py` | `--once` | Exit after the first verdict |
| `ota_client.py` | `--client-id` | Client name (default `ota-client-<hostname>`) |
| `ota_server.py` | `--scenario NAME` | Run one scenario (see `--list-scenarios`) |
| `ota_server.py` | `--version 1.0.0` | Firmware version written into the manifest |
| `ota_server.py` | `--tamper-index 2` | Which chunk the fault and attack scenarios target |
| `run.py` | `--scenarios a b c` | Run only some scenarios |

### Output files

| Where | File | Contents |
|---|---|---|
| Workstation | `build/manifest.json`, `build/chunk_0.bin` … `chunk_3.bin` | Server-side manifest and chunks |
| Workstation | `results/results.md`, `results/results.json` | Table of all experiment verdicts (from `run.py`) |
| Pi | `firmware_reconstructed.txt` | Only created when an update is accepted |
| Pi | `ota_client.log` | Full event log: every chunk, duplicate, timeout and verdict |
| Pi | `ota_history.jsonl` | One JSON line per verdict, including the rejection reason |

## 3. Design

### Chunking and Merkle tree

The file is split into exactly 4 ordered, non-empty chunks. With `size = 4q + r`, the first `r` chunks get `q+1` bytes and the rest get `q` bytes. `firmware.txt` is 886 bytes, so the chunks are 222, 222, 221 and 221 bytes.

The tree is built like this:

```
H_i  = SHA256(C_i)                 (leaves)
H01  = SHA256(H0 || H1)            H23 = SHA256(H2 || H3)
ROOT = SHA256(H01 || H23)
```

Here `||` means concatenating the raw 32-byte digests.

### MQTT topics

| Topic | Publisher | Subscriber | Content |
|---|---|---|---|
| `ota/firmware/manifest` | server | Pi | Manifest (JSON) |
| `ota/firmware/<version>/chunk/<index>` | server | Pi (`ota/firmware/+/chunk/+`) | One chunk (JSON) |
| `ota/status/<client_id>` | Pi | server / run.py | Verdict: ACCEPTED/REJECTED + reason |
| `ota/clients/<client_id>/state` | Pi (retained, last will) | server / run.py | `online` / `offline` |

### Payloads

All payloads are JSON. Chunk bytes are **base64**-encoded so that any binary data survives JSON.

```json
{"type": "manifest", "update_id": "3f2a9c1b7d4e", "firmware_version": "1.0.0",
 "firmware_size": 886, "chunk_count": 4, "hash_algorithm": "sha256",
 "merkle_root": "5a12ec62…aa62",
 "chunks": [{"index": 0, "filename": "chunk_0.bin"}, …]}

{"type": "chunk", "update_id": "3f2a9c1b7d4e", "firmware_version": "1.0.0", "index": 2,
 "filename": "chunk_2.bin", "encoding": "base64", "data": "…"}
```

Each chunk is tied to its version and index in two places: the topic and the payload. The client rejects a chunk if the two disagree. `update_id` is random for every publish, so messages from different update attempts are never mixed.

### Quality of Service: QoS 1 (at least once)

A lost chunk makes the whole update fail, so QoS 0 is not suitable. QoS 1 guarantees delivery between each client and the broker. Its only side effect is possible duplicates, and the client already handles those (see below), so the extra four-step handshake of QoS 2 is not needed.

### Duplicated, missing, delayed and reordered messages

- **Reordered:** chunks are stored in a dictionary keyed by `index`, not by arrival order. Chunks that arrive before the manifest are kept and checked once the manifest arrives.
- **Duplicated:** an identical copy of a chunk the client already has is ignored and not counted twice. A *different* chunk with the same index is treated as an attack, and the update is rejected.
- **Delayed:** the delay is accepted as long as the chunk arrives within `--timeout`, which is counted from the first message of the update.
- **Missing:** after the timeout the update is rejected with the missing indices listed. A chunk that arrives after the verdict is ignored.

### Verification on the Pi

Once the manifest and four chunks have arrived, the client checks that:

1. the indices are exactly `[0, 1, 2, 3]`;
2. the computed Merkle root equals the root in the manifest;
3. the reconstructed size equals `firmware_size`.

If all checks pass, the chunks are joined in index order and written atomically to `firmware_reconstructed.txt`. If any check fails, or a malformed message, an invalid index or a timeout occurs, the client:

- rejects the update and clears the received chunks;
- logs the reason;
- publishes the reason on `ota/status/<client_id>`;
- makes sure `firmware_reconstructed.txt` does not exist.

## 4. Experiment scenarios

`run.py` runs all of the scenarios below. The attacks are simulated by the server acting as a rogue publisher. This works because the broker accepts anonymous clients, so anyone on the LAN could publish to these topics.

| Scenario | Type | Expected | What happens |
|---|---|---|---|
| `normal` | baseline | ACCEPTED | Manifest, then chunks 0–3 |
| `duplicate_chunk` | network | ACCEPTED | Chunk 1 is sent twice |
| `reorder` | network | ACCEPTED | Chunks are sent as 3, 1, manifest, 2, 0 |
| `delay_chunk` | network | ACCEPTED | Chunk 2 arrives 3 s late, still within the timeout |
| `drop_chunk` | network | REJECTED | Chunk 2 is never sent, so the client times out |
| `late_chunk` | network | REJECTED | Chunk 2 arrives after the timeout and is ignored |
| `invalid_index` | attack | REJECTED | An extra chunk with index 4 is injected |
| `tamper_chunk` | attack | REJECTED | One byte of chunk 2 is changed, so the root mismatches |
| `conflicting_duplicate` | attack | REJECTED | A second, different chunk 2 is injected |
| `size_mismatch` | attack (manifest) | REJECTED | `firmware_size` in the manifest is altered |
| `manifest_tamper` | attack (manifest) | REJECTED | The manifest root is swapped for the root of a malicious image |
| `forged_update` | attack (manifest) | **ACCEPTED** | The manifest and all chunks are replaced consistently, so the attack is **not detected** |
| `rollback_replay` | attack (manifest) | **ACCEPTED** | An old genuine v0.9.0 release is replayed, so the attack is **not detected** |

The last two scenarios show the main limitation. A Merkle root only proves that the chunks match *the manifest*. It does not prove that the manifest comes from the legitimate vendor, or that the manifest is newer than the installed firmware. Fixing that needs further protection:

- a digital signature on the manifest, checked with a public key stored on the device;
- anti-rollback, i.e. a monotonic version counter;
- TLS and authentication/ACLs on the broker.
