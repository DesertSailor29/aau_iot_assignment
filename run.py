#!/usr/bin/env python3
"""
Experiment orchestrator (runs on the workstation).

Runs every OTA scenario from ota_server.py against the Raspberry Pi client,
one after another, waits for the device's verdict on ota/status/<client_id>
and writes a results table (results/results.md + results/results.json).

Start order: broker -> ota_client.py on the Pi -> run.py

Example:
    python3 run.py --broker localhost
    python3 run.py --broker localhost --scenarios normal tamper_chunk forged_update
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import ota_server as srv


def parse_args(argv=None) -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    p = argparse.ArgumentParser(description="Run all OTA integrity experiments against the Pi client.")
    p.add_argument("--broker", default="localhost", help="MQTT broker host (default: localhost)")
    p.add_argument("--port", type=int, default=1883)
    p.add_argument("--firmware", type=Path, default=here / "firmware.txt")
    p.add_argument("--version", dest="fw_version", default=srv.DEFAULT_VERSION)
    p.add_argument("--scenarios", nargs="+", choices=srv.SCENARIOS, default=list(srv.SCENARIOS),
                   help="subset of scenarios to run (default: all)")
    p.add_argument("--tamper-index", type=int, default=2)
    p.add_argument("--delay", type=float, default=3.0, help="delay used by delay_chunk (seconds)")
    p.add_argument("--results-dir", type=Path, default=here / "results")
    p.add_argument("--out-dir", type=Path, default=here / "build")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    firmware = args.firmware.read_bytes()

    genuine = srv.prepare_release(firmware, args.fw_version, update_id="")
    srv.write_release(genuine, args.out_dir)
    print(srv.describe_release(genuine))
    print()

    pub = srv.OtaPublisher(args.broker, args.port, client_id="ota-orchestrator")
    pub.connect()
    device = pub.wait_for_device(timeout=5)
    if device is None:
        print("ERROR: no OTA client online. Start ota_client.py on the Raspberry Pi first.")
        pub.close()
        return 1
    client_timeout = float(device.get("timeout", 10))
    delay = min(args.delay, client_timeout / 2)
    print(f"Device online: {device.get('client_id')} (client timeout {client_timeout:.0f}s)\n")

    results = []
    for name in args.scenarios:
        scenario = srv.SCENARIOS[name]
        print(f"=== {name} [{scenario.category}] ===")
        print(f"    {scenario.description}")
        plan = srv.build_plan(name, firmware, args.fw_version, tamper_index=args.tamper_index,
                              delay=delay, late_delay=client_timeout + 3)
        started = time.monotonic()
        pub.publish_plan(plan, log=lambda line: print("   " + line))
        status = pub.wait_for_status(plan.update_id, timeout=client_timeout + 5)

        actual = status["status"] if status else "NO RESPONSE"
        reason = status["reason"] if status else "no verdict received from the device"
        if scenario.category == "attack":
            outcome = "detected" if actual == "REJECTED" else "NOT detected"
        else:
            outcome = "handled" if actual == scenario.expected else "unexpected"
        results.append({
            "scenario": name,
            "category": scenario.category,
            "description": scenario.description,
            "expected": scenario.expected,
            "actual": actual,
            "matches_expectation": actual == scenario.expected,
            "outcome": outcome,
            "reason": reason,
            "update_id": plan.update_id,
            "duration_s": round(time.monotonic() - started, 2),
            "device_status": status,
        })
        mark = "OK " if actual == scenario.expected else "!! "
        print(f"    {mark}device verdict: {actual} - {reason}\n")
        time.sleep(1)  # let late messages of this scenario drain before the next one

    pub.close()
    write_results(results, args.results_dir, device)
    print_table(results)
    print(f"\nResults written to {args.results_dir}/results.md and results.json")
    return 0 if all(r["matches_expectation"] for r in results) else 2


def print_table(results: list[dict]) -> None:
    header = f"{'scenario':<22} {'category':<14} {'expected':<9} {'actual':<12} {'outcome':<13} reason"
    print(header)
    print("-" * len(header))
    for r in results:
        print(f"{r['scenario']:<22} {r['category']:<14} {r['expected']:<9} {r['actual']:<12} "
              f"{r['outcome']:<13} {r['reason']}")


def write_results(results: list[dict], out_dir: Path, device: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    lines = [
        f"# OTA experiment results ({datetime.now():%Y-%m-%d %H:%M})",
        "",
        f"Device: `{device.get('client_id')}`, client timeout {device.get('timeout')}s",
        "",
        "| Scenario | Category | Expected | Device verdict | Outcome | Reason |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        reason = r["reason"].replace("|", "\\|")
        lines.append(f"| {r['scenario']} | {r['category']} | {r['expected']} | {r['actual']} | "
                     f"{r['outcome']} | {reason} |")
    (out_dir / "results.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
