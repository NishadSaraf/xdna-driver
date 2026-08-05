#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.
#
# Correlate the xdna command-lifecycle profiler markers from two sources and
# print a per-stage latency breakdown:
#
#   * Shim userspace stamps  (src/shim/prof.h -> $XDNA_PROF_LOG, default
#     /tmp/xdna_prof.log). Lines: "PROF <stage> seq=.. handle=.. t=<ns> tid=.."
#   * Kernel ftrace markers  (trace_amdxdna_debug_point name="prof").
#     Capture with the trace clock set to CLOCK_MONOTONIC so the timestamps
#     share a base with the userspace CLOCK_MONOTONIC stamps:
#
#       echo mono > /sys/kernel/tracing/trace_clock
#       echo 1    > /sys/kernel/tracing/events/amdxdna/amdxdna_debug_point/enable
#       echo 1    > /sys/kernel/tracing/tracing_on
#       # ... run the workload (with XDNA_PROF=1) ...
#       echo 0    > /sys/kernel/tracing/tracing_on
#       cat /sys/kernel/tracing/trace > /tmp/xdna_trace.txt
#
# Then:
#   tools/prof_report.py --shim /tmp/xdna_prof.log --trace /tmp/xdna_trace.txt
#
# For clean per-command attribution run the workload with a single outstanding
# command (e.g. xrt_test ... -o 1); with many in flight the async MSI-X marker
# (which carries no seq) is attributed by nearest-preceding timestamp.

import argparse
import re
import sys
from statistics import mean, median

# Canonical lifecycle order. (key, human label, layer)
STAGES = [
    ("shim_submit_enter",  "2  shim submission entered",  "shim"),
    ("exec_ioctl_call",    "3a shim exec-buf ioctl call",  "shim"),
    ("exec_ioctl_enter",   "3b kernel exec-buf ioctl entered", "kern"),
    ("job_pushed",         "4  job pushed",                "kern"),
    ("job_started",        "5  job started",               "kern"),
    ("cmd_submitted",      "6  cmd submitted (doorbell)",  "kern"),
    ("exec_ioctl_ret",     "6b shim exec-buf ioctl return", "shim"),
    ("msix_received",      "7  MSI-X received",            "kern"),
    ("workqueue_started",  "8  work queue resumed",        "kern"),
    ("job_done",           "9  job done (fence signaled)", "kern"),
    ("waiter_woken",       "10 waiting thread woken",      "kern"),
    ("wait_ioctl_return",  "11 wait ioctl returned",       "kern"),
    ("shim_wait_end",      "12 shim run wait ended",       "shim"),
]
STAGE_KEYS = [s[0] for s in STAGES]
STAGE_IDX = {k: i for i, (k, _, _) in enumerate(STAGES)}

# Pre-seq kernel markers that must inherit a seq from a following cmd_submitted
# within the same kernel task (pid).
PRE_SEQ_KERNEL = {"exec_ioctl_enter", "job_pushed", "job_started"}

SHIM_RE = re.compile(
    r"PROF\s+(\S+)\s+seq=(\d+)\s+handle=(\d+)\s+t=(\d+)\s+tid=(\d+)")

# Tolerant ftrace line matcher: "<comm>-<pid> [cpu] flags  <ts>: amdxdna_debug_point: prof:<num> <stage>"
TRACE_RE = re.compile(
    r"-(\d+)\s+\[\d+\]\s+\S+\s+(\d+\.\d+):\s+amdxdna_debug_point:\s+prof:(\d+)\s+(\S+)")


def ns(x):
    return int(round(x))


def parse_shim(path):
    """Return list of events: dict(stage, seq, handle, t_ns, tid)."""
    events = []
    with open(path) as f:
        for line in f:
            m = SHIM_RE.search(line)
            if not m:
                continue
            stage, seq, handle, t, tid = m.groups()
            events.append({
                "stage": stage, "seq": int(seq), "handle": int(handle),
                "t": int(t), "tid": int(tid), "src": "shim",
            })
    return events


def parse_trace(path):
    """Return list of events: dict(stage, number, t_ns, pid). number is seq or
    handle (0 for msix/pre-seq)."""
    events = []
    with open(path) as f:
        for line in f:
            m = TRACE_RE.search(line)
            if not m:
                continue
            pid, ts, number, stage = m.groups()
            events.append({
                "stage": stage, "number": int(number),
                "t": ns(float(ts) * 1e9), "pid": int(pid), "src": "kern",
            })
    return events


def build_records(shim_events, trace_events):
    """Correlate everything into per-seq records: {seq: {stage: t_ns}}."""
    records = {}          # seq -> {stage: t}
    handle_to_seq = {}    # cmd bo handle -> seq (from shim exec_ioctl_ret)

    # 1) Shim events: exec_ioctl_ret carries both handle and seq -> anchor.
    for e in shim_events:
        if e["stage"] == "exec_ioctl_ret" and e["handle"]:
            handle_to_seq[e["handle"]] = e["seq"]

    def put(seq, stage, t):
        rec = records.setdefault(seq, {})
        # keep the first occurrence of each stage per command
        rec.setdefault(stage, t)

    # 2) Shim events with a known seq (or resolvable via handle).
    for e in shim_events:
        seq = e["seq"]
        if not seq and e["handle"]:
            seq = handle_to_seq.get(e["handle"], 0)
        if seq:
            put(seq, e["stage"], e["t"])
        else:
            # shim_submit_enter / exec_ioctl_call: seq unknown, resolve by handle
            seq = handle_to_seq.get(e["handle"], 0)
            if seq:
                put(seq, e["stage"], e["t"])

    # 3) Kernel events. First, seq-bearing markers directly.
    kern_sorted = sorted(trace_events, key=lambda e: e["t"])
    for e in kern_sorted:
        st = e["stage"]
        if st in PRE_SEQ_KERNEL or st == "msix_received":
            continue
        if st == "exec_ioctl_enter":
            continue
        # cmd_submitted / workqueue_started / job_done / waiter_woken /
        # wait_ioctl_return all carry seq in 'number'.
        seq = e["number"]
        if seq:
            put(seq, st, e["t"])

    # 4) Pre-seq kernel markers: within a pid, attribute a run of
    #    exec_ioctl_enter/job_pushed/job_started to the seq of the following
    #    cmd_submitted in the same pid.
    by_pid = {}
    for e in kern_sorted:
        by_pid.setdefault(e["pid"], []).append(e)
    for pid, evs in by_pid.items():
        pending = []
        for e in evs:
            st = e["stage"]
            if st in PRE_SEQ_KERNEL:
                pending.append(e)
            elif st == "cmd_submitted":
                seq = e["number"]
                for pe in pending:
                    put(seq, pe["stage"], pe["t"])
                pending = []
        # leftover pending (no following submit) is dropped

    # 5) MSI-X: async IRQ, no seq. Attribute each to the command whose
    #    workqueue_started/waiter_woken most closely follows it.
    msix = [e for e in kern_sorted if e["stage"] == "msix_received"]
    # Build (t, seq) anchors from the earliest completion-side stamp per seq.
    anchors = []
    for seq, rec in records.items():
        cand = [rec[k] for k in ("workqueue_started", "waiter_woken", "job_done")
                if k in rec]
        if cand:
            anchors.append((min(cand), seq))
    anchors.sort()
    for me in msix:
        # nearest anchor at or after the msix timestamp
        best = None
        for at, seq in anchors:
            if at >= me["t"]:
                best = seq
                break
        if best is not None:
            records[best].setdefault("msix_received", me["t"])

    return records


def fmt_us(delta_ns):
    return f"{delta_ns / 1000.0:8.3f}"


def print_timeline(seq, rec):
    print(f"\n=== command seq={seq} ===")
    ordered = [(k, lbl) for (k, lbl, _) in STAGES if k in rec]
    if not ordered:
        print("  (no stamps)")
        return
    t0 = rec[ordered[0][0]]
    prev = None
    print(f"  {'stage':38} {'+prev(us)':>10} {'+start(us)':>11}")
    for k, lbl in ordered:
        t = rec[k]
        dprev = "" if prev is None else fmt_us(t - prev)
        print(f"  {lbl:38} {dprev:>10} {fmt_us(t - t0):>11}")
        prev = t


def print_aggregate(records):
    # Per adjacent-stage-pair deltas across all commands that have both.
    print("\n=== aggregate per-stage delta (us) across "
          f"{len(records)} command(s) ===")
    print(f"  {'transition':52} {'n':>4} {'mean':>9} {'median':>9} "
          f"{'min':>9} {'max':>9}")
    for i in range(len(STAGES) - 1):
        a_k, a_l, _ = STAGES[i]
        b_k, b_l, _ = STAGES[i + 1]
        deltas = []
        for rec in records.values():
            if a_k in rec and b_k in rec and rec[b_k] >= rec[a_k]:
                deltas.append((rec[b_k] - rec[a_k]) / 1000.0)
        if not deltas:
            continue
        label = f"{a_k} -> {b_k}"
        print(f"  {label:52} {len(deltas):>4} {mean(deltas):>9.3f} "
              f"{median(deltas):>9.3f} {min(deltas):>9.3f} {max(deltas):>9.3f}")

    # End-to-end (first to last captured stage) per command.
    e2e = []
    for rec in records.values():
        present = [rec[k] for k in STAGE_KEYS if k in rec]
        if len(present) >= 2:
            e2e.append((max(present) - min(present)) / 1000.0)
    if e2e:
        print(f"\n  end-to-end (stage2..12) n={len(e2e)} "
              f"mean={mean(e2e):.3f}us median={median(e2e):.3f}us "
              f"min={min(e2e):.3f}us max={max(e2e):.3f}us")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--shim", help="shim profiler log (XDNA_PROF_LOG)")
    ap.add_argument("--trace", help="kernel ftrace dump (trace_clock=mono)")
    ap.add_argument("--timeline", action="store_true",
                    help="print a per-command timeline in addition to aggregate")
    ap.add_argument("--limit", type=int, default=10,
                    help="max per-command timelines to print (default 10)")
    args = ap.parse_args()

    if not args.shim and not args.trace:
        ap.error("provide at least one of --shim / --trace")

    shim_events = parse_shim(args.shim) if args.shim else []
    trace_events = parse_trace(args.trace) if args.trace else []
    if not shim_events and not trace_events:
        print("No 'prof' markers found in the provided inputs.", file=sys.stderr)
        return 1

    records = build_records(shim_events, trace_events)
    if not records:
        print("No commands could be correlated.", file=sys.stderr)
        return 1

    if args.timeline:
        for n, seq in enumerate(sorted(records)):
            if n >= args.limit:
                print(f"\n... ({len(records) - args.limit} more commands omitted)")
                break
            print_timeline(seq, records[seq])

    print_aggregate(records)
    return 0


if __name__ == "__main__":
    sys.exit(main())
