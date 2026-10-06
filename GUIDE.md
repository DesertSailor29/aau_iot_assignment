# OTA Firmware Update over MQTT: What Was Built and How to Test It

This guide explains the code for Mini Project 1: what each part does and how the parts work together. It then walks through testing it on the workstation and the Raspberry Pi, with the exact commands to run.

---

## Part A: What was done

Four files make up the system:

| File | Runs on | Role in the assignment |
|---|---|---|
| `ota_server.py` | Workstation | Task 2 (chunking + Merkle tree + manifest) and task 3 (publishing over MQTT) |
| `ota_client.py` | Raspberry Pi | Task 4 (receive, verify, reconstruct or reject) |
| `run.py` | Workstation | Orchestrator: runs every test and attack scenario and collects the results (task 5/6 evidence) |
| `firmware.txt` | Both (the Pi uses it only for comparison) | The "firmware": an 886-byte text file that is never installed or executed |

There are also a `README.md`, with a short reference and the design decisions, and a `.gitignore`, which keeps generated files out of git.

The code was tested end to end on the workstation, with a local broker and the client running locally in place of the Pi. All 13 scenarios produced the expected verdict, and the rebuilt file was byte-identical to `firmware.txt`. The tests were run with paho-mqtt 2.1, the version pip installs on the Mac, and with 1.6.1, the version `apt` installs on Raspberry Pi OS.

---

## Part B: How it works

### B.1 The big picture

```
                         ┌──────────────────────────────┐
  Workstation            │  Mosquitto broker  :1883     │            Raspberry Pi 4
                         │  (runs on the workstation)   │
 ┌───────────────┐       │                              │       ┌──────────────────┐
 │ ota_server.py │──────▶│ ota/firmware/manifest        │──────▶│                  │
 │   or run.py   │──────▶│ ota/firmware/<ver>/chunk/<i> │──────▶│  ota_client.py   │
 │               │◀──────│ ota/status/<client_id>       │◀──────│                  │
 │               │◀──────│ ota/clients/<id>/state       │◀──────│                  │
 └───────────────┘       └──────────────────────────────┘       └──────────────────┘
   publisher of firmware                                          subscriber of firmware
   subscriber of verdicts                                         publisher of verdicts
```

| MQTT role | Who |
|---|---|
| Broker | Mosquitto on the workstation |
| Publisher (firmware) | `ota_server.py` / `run.py` on the workstation |
| Subscriber (firmware) | `ota_client.py` on the Pi |
| Publisher (feedback) | `ota_client.py`: verdicts plus its online/offline state |
| Subscriber (feedback) | `ota_server.py` / `run.py` |

### B.2 Step 1 on the server: splitting the file into four chunks

`split_into_chunks()` in `ota_server.py` divides the file into exactly 4 ordered, non-empty byte chunks.

**Rule when the size isn't divisible by 4:** write the size as `4q + r`. The first `r` chunks get `q + 1` bytes and the remaining chunks get `q` bytes, so no two chunks differ by more than one byte.

For `firmware.txt`, 886 = 4 × 221 + 2, which gives:

| Chunk | C0 | C1 | C2 | C3 |
|---|---|---|---|---|
| Size (bytes) | 222 | 222 | 221 | 221 |

A file smaller than 4 bytes is refused, because it can't form 4 non-empty chunks.

### B.3 Step 2 on the server: building the Merkle tree

```
                    ROOT = SHA256(H01 || H23)
                   /                          \
     H01 = SHA256(H0 || H1)          H23 = SHA256(H2 || H3)
        /            \                   /            \
 H0=SHA256(C0)  H1=SHA256(C1)    H2=SHA256(C2)  H3=SHA256(C3)
```

- The leaves are `SHA256(chunk)`.
- Each parent is SHA-256 over the two 32-byte child digests concatenated in index order (`||` means concatenation).
- The server prints the whole tree when it runs. The values for the current `firmware.txt` are:

```
C0:   222 bytes   H0  = 7faaad817271f06c6850c85494f4b0827addbac91b1567d27593901148fe7e72
C1:   222 bytes   H1  = 428b93cac22a8e90ed320c8d6ab99e9d87bf340a15870bb7b819a13b3281fc41
C2:   221 bytes   H2  = 375229b4189f1aa07ed48924a2b4f02bdf5f92c4d26e500fdf7508737eb275cd
C3:   221 bytes   H3  = c5fd3b1c1ed1c44da3ccaa157009b6a863ea18ca6759bffd022abb1d8b8dafdb
H01 = SHA256(H0||H1) = 29587a7005a5224f9765b787aa68f95210faee3bcc3af5e2e1b11a4352525914
H23 = SHA256(H2||H3) = bae996e7a0a59136483c5ae88db81bfa5e94ba4b065434b2ce8536ac14a3110b
ROOT = SHA256(H01||H23) = 5a12ec6252010791d3697731844aa4c54013010cade9fc1bda9155b77a61aa62
```

The client computes the root with its own code. It does not import the server's code, which mirrors a real device that verifies independently.

### B.4 Step 3 on the server: the manifest

The manifest is written to `build/manifest.json`, and the chunks are written to `build/chunk_0.bin` … `build/chunk_3.bin`:

```json
{
  "type": "manifest",
  "update_id": "3f2a9c1b7d4e",
  "firmware_version": "1.0.0",
  "firmware_size": 886,
  "chunk_count": 4,
  "hash_algorithm": "sha256",
  "merkle_root": "5a12ec6252010791d3697731844aa4c54013010cade9fc1bda9155b77a61aa62",
  "chunks": [
    {"index": 0, "filename": "chunk_0.bin"},
    {"index": 1, "filename": "chunk_1.bin"},
    {"index": 2, "filename": "chunk_2.bin"},
    {"index": 3, "filename": "chunk_3.bin"}
  ]
}
```

`update_id` is a new random value for every publish. It ties all the messages of one update attempt together, so messages from an earlier attempt are never mixed in. In `build/manifest.json` the field is empty, because a real ID is only generated when publishing.

### B.5 Step 4: publishing over MQTT

**Topics**

| Topic | Content | QoS | Retained |
|---|---|---|---|
| `ota/firmware/manifest` | Manifest JSON | 1 | no |
| `ota/firmware/<version>/chunk/<index>`, e.g. `ota/firmware/1.0.0/chunk/2` | One chunk | 1 | no |
| `ota/status/<client_id>` | Verdict of the Pi | 1 | no |
| `ota/clients/<client_id>/state` | `online` / `offline` (also used as the last will) | 1 | yes |

**Chunk payload:** JSON. Binary data is base64-encoded, because JSON cannot carry raw bytes.

```json
{"type": "chunk", "update_id": "3f2a9c1b7d4e", "firmware_version": "1.0.0",
 "index": 2, "filename": "chunk_2.bin", "encoding": "base64", "data": "W2Jvb3RdCkJP..."}
```

The version and index appear twice: in the topic and in the payload. The client rejects a chunk if they disagree.

**QoS 1 (at least once).** QoS 0 can silently lose a chunk, which would make every such update fail. QoS 1 guarantees delivery; its only drawback is that a message may arrive twice, and the client already ignores identical duplicates. QoS 2 (exactly once) would add a four-step handshake per message for no benefit. Note that QoS only covers each client↔broker hop, not the whole path.

**Start order:** broker → client (Pi) → server. The update messages are not retained, so a client that subscribes too late misses them. To enforce this, the Pi announces itself on `ota/clients/<id>/state`, and the server and `run.py` refuse to publish until they see a client that is online.

### B.6 Step 5 on the Pi: receiving and verifying

```
first message of a new update_id
        │   (old firmware_reconstructed.txt deleted, timeout clock starts)
        ▼
 ┌──────────────────────────────────────────────────────────┐
 │ collect: manifest + chunks, stored in a dict by INDEX    │
 │  • chunk before manifest  → kept, checked later          │
 │  • identical duplicate    → ignored ("Duplicate chunk")  │
 │  • different duplicate    → REJECT                       │
 │  • index not in 0..3      → REJECT                       │
 │  • topic/payload mismatch → REJECT                       │
 │  • bad JSON / base64 / empty chunk → REJECT              │
 └──────────────────────────────────────────────────────────┘
        │ manifest + 4 chunks present              │ timeout (default 10 s)
        ▼                                          ▼
 1. indices == [0,1,2,3] ?                       REJECT "missing chunk(s) [2]"
 2. computed Merkle root == manifest root ?
 3. len(joined chunks) == firmware_size ?
        │ all yes                     │ any no
        ▼                             ▼
   ACCEPTED                       REJECTED
   write firmware_reconstructed   clear chunks, make sure the
   .txt atomically (.part → rename)  output file does not exist
        │                             │
        └────── log to ota_client.log + ota_history.jsonl ──────┘
                and publish the verdict on ota/status/<client_id>
```

A message that arrives after its update has been decided, for example a chunk that comes in after the timeout, is logged as `Ignoring late/duplicate message` and has no effect.

### B.7 The orchestrator: `run.py`

`run.py` connects to the broker and waits until the Pi is online. It then runs each scenario below in turn: it publishes the scenario's messages and waits for the Pi's verdict on `ota/status/...`. At the end it prints a table and saves it to `results/results.md` and `results/results.json`.

| Scenario | Type | What is published | Expected | Why |
|---|---|---|---|---|
| `normal` | baseline | Manifest, then C0, C1, C2, C3 | ACCEPTED | Everything matches |
| `duplicate_chunk` | network | C1 is sent twice | ACCEPTED | The identical duplicate is ignored |
| `reorder` | network | C3, C1, manifest, C2, C0 | ACCEPTED | Chunks are stored by index |
| `delay_chunk` | network | C2 is sent 3 s late | ACCEPTED | It still arrives within the 10 s timeout |
| `drop_chunk` | network | C2 is never sent | REJECTED | Timeout: missing chunk(s) [2] |
| `late_chunk` | network | C2 is sent after 13 s | REJECTED | Timeout; the late chunk is ignored |
| `invalid_index` | attack | An extra "chunk 4" is injected | REJECTED | The index must be 0..3 |
| `tamper_chunk` | attack | One byte of C2 is flipped (same length) | REJECTED | Merkle root mismatch |
| `conflicting_duplicate` | attack | A second, different C2 is injected | REJECTED | Conflicting duplicate |
| `size_mismatch` | attack on the manifest | `firmware_size` is set to 887 | REJECTED | Size mismatch |
| `manifest_tamper` | attack on the manifest | The root is replaced by the root of a malicious image | REJECTED | Merkle root mismatch |
| `forged_update` | attack on the manifest | The manifest **and** all chunks are replaced by a malicious image with a correct root | **ACCEPTED** | **Not detected**: Merkle has no authenticity |
| `rollback_replay` | attack on the manifest | An old genuine v0.9.0 release with its own valid manifest | **ACCEPTED** | **Not detected**: there is no version policy |

The attacks are simulated by the workstation acting as a rogue publisher. This is realistic, because the broker allows anonymous clients, so any device on the LAN could publish to these topics.

**Answer to the main question, in short:** a Merkle root detects any change to a chunk, and any mismatch between the chunks and the manifest. It does not prove *who* created the manifest, and it does not prove that the update is *newer* than the installed firmware. An attacker who can replace the manifest can therefore install anything. Closing that gap requires:

- a digital signature on the manifest, checked with a public key built into the device;
- anti-rollback, i.e. a monotonic version counter;
- TLS with authentication and ACLs on the broker.

---

## Part C: Step-by-step test guide

You need two terminals on the workstation (three if you want to watch the raw traffic) and one SSH session on the Pi. Both devices must be on the same network.

> Wherever you see `<WS_IP>` below, replace it with the workstation's IP address from step 1.3, for example `192.168.1.23`.

### Step 1: Workstation: start the broker

**1.1 Install Mosquitto (skip this if it's already installed):**

```bash
brew install mosquitto
```

**1.2 Create a broker config that accepts connections from the network.** Mosquitto 2.x only listens on localhost by default, so the Pi could not connect without this.

```bash
printf 'listener 1883 0.0.0.0\nallow_anonymous true\n' > ~/mosquitto-ota.conf
```

**1.3 Note down the workstation's IP address. This is `<WS_IP>` from here on:**

```bash
ipconfig getifaddr en0
```

**1.4 Make sure nothing else is already using port 1883:**

```bash
brew services stop mosquitto 2>/dev/null; lsof -i :1883
```

The `lsof` command should print nothing.

**1.5 Start the broker in terminal 1 and leave it running.** `-v` shows every connection and message.

```bash
/opt/homebrew/sbin/mosquitto -c ~/mosquitto-ota.conf -v
```

You should see `Opening ipv4 listen socket on port 1883`. If macOS asks whether to allow incoming connections, click **Allow**.

### Step 2: Workstation: Python environment and pushing the code

In terminal 2:

```bash
cd "/Users/sebi/Documents/0Denmark/1Master/0_1. Semester/IoT&Cloud Sec/Assignments/1. Assigment/aau_iot_assignment"
python3 -m venv .venv
source .venv/bin/activate
pip install paho-mqtt
git push -u origin main
```

In every new terminal, run `source .venv/bin/activate` again before using the scripts.

### Step 3: Raspberry Pi: install and get the code

SSH into the Pi:

```bash
ssh <pi-user>@<pi-ip>
```

Then, on the Pi:

```bash
sudo apt update
sudo apt install -y git python3-paho-mqtt mosquitto-clients
git clone https://github.com/DesertSailor29/aau_iot_assignment.git
cd aau_iot_assignment
```

If you change the code later, update it on the Pi with `git pull`.

### Step 4: Basic MQTT check (task 1: publish/subscribe works)

**On the Pi,** subscribe and leave it running:

```bash
mosquitto_sub -h <WS_IP> -t test/hello -v
```

**On the workstation** (terminal 2), publish:

```bash
mosquitto_pub -h localhost -t test/hello -m "hello from the workstation"
```

The Pi should print `test/hello hello from the workstation`. Take a screenshot of both sides for the report, then stop `mosquitto_sub` on the Pi with **Ctrl+C**.

### Step 5 (optional, good for screenshots): watch all OTA traffic

In terminal 3 on the workstation:

```bash
mosquitto_sub -h localhost -t 'ota/#' -v
```

This prints every manifest, chunk, verdict and online/offline message as it passes through the broker.

### Step 6: Raspberry Pi: start the OTA client

On the Pi, inside `aau_iot_assignment`:

```bash
python3 ota_client.py --broker <WS_IP>
```

Expected output:

```
INFO    Waiting for OTA updates (Ctrl+C to stop)
INFO    Connected to <WS_IP>:1883 as 'ota-client-raspberrypi', subscribed to ota/firmware/manifest and ota/firmware/+/chunk/+ (QoS 1)
```

**Leave it running for all the following steps.**

### Step 7: Workstation: send one normal update

In terminal 2:

```bash
python3 ota_server.py --broker localhost
```

Expected output (shortened):

```
[server] Firmware version 1.0.0, 886 bytes
  C0:   222 bytes   H0  = 7faaad81...
  ...
  ROOT = SHA256(H01||H23) = 5a12ec62...
[server] device online: ota-client-raspberrypi (timeout 10s)
[server] scenario 'normal': Manifest followed by chunks 0..3 in order.
[server]   published manifest                     -> ota/firmware/manifest
[server]   published chunk 0                      -> ota/firmware/1.0.0/chunk/0
...
[server] device verdict: ACCEPTED - all 4 chunks present, Merkle root and size match; wrote firmware_reconstructed.txt
```

The Pi's log shows the manifest arriving, then each chunk, then `UPDATE ACCEPTED`.

**Verify on the Pi.** Open a second SSH session, or stop the client briefly. The two commands below should print `IDENTICAL` and two equal hashes:

```bash
cd ~/aau_iot_assignment
cmp firmware.txt firmware_reconstructed.txt && echo IDENTICAL
sha256sum firmware.txt firmware_reconstructed.txt
```

### Step 8: Workstation: try single scenarios by hand

The list of all scenarios:

```bash
python3 ota_server.py --list-scenarios
```

**A tampered chunk (should be rejected):**

```bash
python3 ota_server.py --broker localhost --scenario tamper_chunk
```

Expected: `device verdict: REJECTED - Merkle root mismatch: computed c909f8c4..., manifest 5a12ec62...`

Then check on the Pi that no output file was created:

```bash
ls -l firmware_reconstructed.txt     # -> No such file or directory
tail -n 1 ota_history.jsonl          # -> "status": "REJECTED", "reason": "Merkle root mismatch ..."
```

**More scenarios worth showing:**

```bash
python3 ota_server.py --broker localhost --scenario reorder           # ACCEPTED
python3 ota_server.py --broker localhost --scenario duplicate_chunk   # ACCEPTED, Pi logs "Duplicate chunk 1 ignored"
python3 ota_server.py --broker localhost --scenario drop_chunk        # REJECTED after 10 s: missing chunk(s) [2]
python3 ota_server.py --broker localhost --scenario manifest_tamper   # REJECTED: Merkle root mismatch
python3 ota_server.py --broker localhost --scenario forged_update     # ACCEPTED -> the attack is NOT detected
```

After `forged_update`, look at the end of the file on the Pi. The attacker's injected line is there, even though the update passed verification:

```bash
tail -n 2 firmware_reconstructed.txt
```

To target a different chunk, add `--tamper-index 0` (any index from 0 to 3).

### Step 9: Workstation: run all experiments at once

```bash
python3 run.py --broker localhost
```

This takes about one minute, because the two timeout scenarios each wait out the timeout. At the end it prints this table:

```
scenario               category       expected  actual       outcome       reason
---------------------------------------------------------------------------------
normal                 baseline       ACCEPTED  ACCEPTED     handled       all 4 chunks present, ...
duplicate_chunk        network fault  ACCEPTED  ACCEPTED     handled       ...
reorder                network fault  ACCEPTED  ACCEPTED     handled       ...
delay_chunk            network fault  ACCEPTED  ACCEPTED     handled       ...
drop_chunk             network fault  REJECTED  REJECTED     handled       timeout after 10s: missing chunk(s) [2]
late_chunk             network fault  REJECTED  REJECTED     handled       timeout after 10s: missing chunk(s) [2]
invalid_index          attack         REJECTED  REJECTED     detected      invalid chunk index 4; expected indices 0..3
tamper_chunk           attack         REJECTED  REJECTED     detected      Merkle root mismatch: ...
conflicting_duplicate  attack         REJECTED  REJECTED     detected      conflicting duplicate: ...
size_mismatch          attack         REJECTED  REJECTED     detected      size mismatch: reconstructed 886 bytes, manifest says 887
manifest_tamper        attack         REJECTED  REJECTED     detected      Merkle root mismatch: ...
forged_update          attack         ACCEPTED  ACCEPTED     NOT detected  all 4 chunks present, ...
rollback_replay        attack         ACCEPTED  ACCEPTED     NOT detected  all 4 chunks present, ...
```

The exit code is `0` if every verdict matched its expectation and `2` otherwise. The results are saved here:

```bash
cat results/results.md      # ready-made Markdown table for the report
```

Run only some scenarios:

```bash
python3 run.py --broker localhost --scenarios normal tamper_chunk forged_update
```

### Step 10: Collect the evidence for the report

**On the workstation:**
- `build/manifest.json`, `build/chunk_*.bin`
- `results/results.md`, `results/results.json`

**On the Pi:**
- `ota_client.log`: full event log
- `ota_history.jsonl`: one line per verdict

To copy the Pi's files to the workstation, run this in a workstation terminal:

```bash
scp <pi-user>@<pi-ip>:~/aau_iot_assignment/{ota_client.log,ota_history.jsonl} results/
```

**Suggested screenshots:**
- step 4 (pub/sub test);
- step 7: the server output plus the Pi log, and `cmp` printing `IDENTICAL`;
- step 8: `tamper_chunk` rejected, then `ls` showing no output file;
- step 8: `forged_update` accepted, plus `tail` showing the injected line;
- step 9: the final table.

### Step 11: Stop and reset

- **Pi:** stop the client with **Ctrl+C**. It publishes `offline` before it exits.
- **Workstation:** stop the broker in terminal 1 with **Ctrl+C**.

To start again with clean output files:

```bash
# Pi
rm -f firmware_reconstructed.txt ota_client.log ota_history.jsonl
# workstation
rm -rf build results
```

---

## Part D: Testing without the Pi (everything on the workstation)

Useful for checking a code change quickly. Use three terminals, all inside the repo folder with the venv activated:

```bash
# terminal 1: broker
/opt/homebrew/sbin/mosquitto -c ~/mosquitto-ota.conf -v

# terminal 2: client, run in a separate folder so its files don't mix with the server's
mkdir -p /tmp/fake-pi && cd /tmp/fake-pi
python3 "/Users/sebi/Documents/0Denmark/1Master/0_1. Semester/IoT&Cloud Sec/Assignments/1. Assigment/aau_iot_assignment/ota_client.py" --broker localhost

# terminal 3: experiments
python3 run.py --broker localhost
```

---

## Part E: Troubleshooting

| Symptom | Cause / fix |
|---|---|
| The Pi shows `Connection refused` or hangs on connect | The broker is only listening on localhost: check that you started it with `~/mosquitto-ota.conf` (step 1.5). Also check that the macOS firewall allows mosquitto and that `<WS_IP>` is correct. |
| `ERROR: no OTA client online. Start ota_client.py on the Pi first` | The client isn't running, or is connected to a different broker. Start step 6 first, and make sure it prints `Connected to ...`. |
| `could not connect to MQTT broker localhost:1883` | The broker isn't running on the workstation (step 1.5). |
| `ModuleNotFoundError: No module named 'paho'` | Workstation: run `source .venv/bin/activate`. Pi: run `sudo apt install python3-paho-mqtt`. |
| `[server] no verdict received from the device` | The client was stopped or disconnected during the update. Check the Pi's terminal. |
| `Address already in use` when starting the broker | Another Mosquitto is already running: `brew services stop mosquitto`, or `lsof -i :1883` to find it. |
| `run.py` exits with code 2 | At least one verdict differed from the expectation. Look for the `!!` line in the output. |
| The client's timeout is too short for a slow Wi-Fi | Start the client with `--timeout 20`. `run.py` reads the client's timeout automatically. |
