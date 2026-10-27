#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Intel Corporation
"""Send the baseline linerate stream through a real TRex server, or summarize
a capture of it, to check that the field engine rewrites IP.dst."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from ipaddress import IPv4Address

from common import (
    PDN_IP,
    TREX_SRC_MAC,
    UE_COUNT,
    UE_IP_START,
    UPF_CORE_MAC,
    UPF_CORE_PORT,
)


def send(server: str, variant: str, duration: int, pps: int) -> None:
    """Send the stream built by baseline.DownlinkPerformanceBaselineTest."""
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from trex.stl.api import (
        STLVM,
        STLClient,
        STLFlowLatencyStats,
        STLPktBuilder,
        STLStream,
        STLTXCont,
    )

    end_ip = UE_IP_START + UE_COUNT - 1
    vm = STLVM()
    vm.var(
        name="dst",
        min_value=str(UE_IP_START),
        max_value=str(end_ip),
        size=4,
        op="random",
    )
    vm.write(fv_name="dst", pkt_offset="IP.dst")
    vm.fix_chksum()

    pkt = (
        Ether(dst=UPF_CORE_MAC, src=TREX_SRC_MAC)
        / IP(src=str(PDN_IP), id=0)
        / UDP(sport=10002, dport=10001, chksum=0)
    )
    flow_stats = STLFlowLatencyStats(pg_id=0) if variant == "latency" else None
    stream = STLStream(
        packet=STLPktBuilder(pkt=pkt, vm=vm),
        mode=STLTXCont(pps=pps),
        flow_stats=flow_stats,
    )
    print("VM instructions:", stream.to_json()["vm"]["instructions"])

    client = STLClient(server=server)
    client.connect()
    try:
        client.acquire(force=True)
        client.reset()
        client.set_port_attr(client.get_all_ports(), promiscuous=True)
        client.add_streams(stream, ports=[UPF_CORE_PORT])
        client.start(ports=[UPF_CORE_PORT], duration=duration)
        client.wait_on_traffic(ports=[UPF_CORE_PORT])
        stats = client.get_stats()
        print(f"TRex port {UPF_CORE_PORT} opackets:", stats[UPF_CORE_PORT]["opackets"])
        if flow_stats is not None:
            print(
                "Latency stats:", stats.get("latency", {}).get(0, {}).get("err_cntrs")
            )
    finally:
        client.reset()
        client.release()
        client.disconnect()


def analyze(pcap: str) -> int:
    """Summarize the destination IPs of the stream's packets in a capture."""
    from scapy.layers.inet import IP
    from scapy.utils import PcapReader

    first, last = UE_IP_START, UE_IP_START + UE_COUNT - 1
    dsts: Counter[str] = Counter()
    with PcapReader(pcap) as packets:
        for packet in packets:
            if IP in packet and packet[IP].src == str(PDN_IP):
                dsts[packet[IP].dst] += 1

    total = sum(dsts.values())
    in_range = sum(n for dst, n in dsts.items() if first <= IPv4Address(dst) <= last)
    print(f"{pcap}: {total} stream packets, {len(dsts)} distinct IP.dst values")
    print(f"  in UE range {first}-{last}: {in_range}")
    print(f"  127.0.0.1 (template default): {dsts['127.0.0.1']}")
    print(f"  other: {total - in_range - dsts['127.0.0.1']}")
    print("  most common:", dsts.most_common(5))
    return 0 if total else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    send_parser = commands.add_parser("send")
    send_parser.add_argument("--server", default="127.0.0.1")
    send_parser.add_argument("--variant", choices=("latency", "plain"), required=True)
    send_parser.add_argument("--duration", type=int, default=3)
    send_parser.add_argument("--pps", type=int, default=1_000)
    analyze_parser = commands.add_parser("analyze")
    analyze_parser.add_argument("pcap")
    args = parser.parse_args()

    if args.command == "send":
        send(args.server, args.variant, args.duration, args.pps)
    else:
        sys.exit(analyze(args.pcap))


if __name__ == "__main__":
    main()
