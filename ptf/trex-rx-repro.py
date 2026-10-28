#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Intel Corporation
"""Loop TRex's ports to each other and check whether its receive path keeps
up past the PTF config's mbuf pool sizes."""

from __future__ import annotations

import argparse
import json
import time

import yaml
from common import (
    GNB_IP,
    N3_IP,
    PDN_IP,
    TREX_RECEIVER_PORT,
    TREX_SENDER_PORT,
    TREX_SRC_MAC,
    UE_COUNT,
    UE_IP_START,
    UPF_ACCESS_MAC,
    UPF_CORE_MAC,
)

PTF_TREX_CONFIG = "/upf-tests/config/trex-cfg-for-ptf.yaml"
PG_ID = 0


def write_config(memory: str, out: str) -> None:
    """Write the PTF TRex config, adapted to veth ports on a small runner."""
    with open(PTF_TREX_CONFIG) as f:
        config = yaml.safe_load(f)
    port = config[0]
    port["interfaces"] = [
        "--vdev=net_af_packet0,iface=veth0",
        "--vdev=net_af_packet1,iface=veth1",
    ]
    # af_packet ports allow one core per interface pair, and the runner does
    # not have the testbed's thread IDs.
    port["c"] = 1
    port.pop("platform", None)
    if memory == "default":
        port.pop("memory", None)
    elif memory == "tiny":
        # A positive control: if TRex honors the memory section, pools a
        # sixteenth of the PTF sizes should starve the receive path.
        port["memory"] = {
            name: max(size // 16, 8) for name, size in port["memory"].items()
        }
    with open(out, "w") as f:
        yaml.safe_dump(config, f, sort_keys=False)
    print(yaml.safe_dump(config, sort_keys=False))


def build_stream(payload: str, pps: int):
    """Build baseline's downlink stream, or the GTP-U packet the UPF returns."""
    from pkt_utils import pkt_add_gtpu
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from trex.stl.api import (
        STLVM,
        STLFlowLatencyStats,
        STLPktBuilder,
        STLStream,
        STLTXCont,
    )

    pkt = (
        Ether(dst=UPF_CORE_MAC, src=TREX_SRC_MAC)
        / IP(src=str(PDN_IP), id=0)
        / UDP(sport=10002, dport=10001, chksum=0)
    )
    dst_field = "IP.dst"
    if payload == "gtpu":
        # What the UPF sends out of N3 for baseline's traffic (gtppsc is off
        # in ptf/config/upf.jsonc, so no PDU Session Container).
        pkt = pkt_add_gtpu(
            Ether(dst=TREX_SRC_MAC, src=UPF_ACCESS_MAC) / pkt[Ether].payload,
            out_ipv4_src=str(N3_IP),
            out_ipv4_dst=str(GNB_IP),
            teid=1,
        )
        dst_field = "IP:1.dst"

    vm = STLVM()
    vm.var(
        name="dst",
        min_value=str(UE_IP_START),
        max_value=str(UE_IP_START + UE_COUNT - 1),
        size=4,
        op="random",
    )
    vm.write(fv_name="dst", pkt_offset=dst_field)
    vm.fix_chksum()
    return STLStream(
        packet=STLPktBuilder(pkt=pkt, vm=vm),
        mode=STLTXCont(pps=pps),
        flow_stats=STLFlowLatencyStats(pg_id=PG_ID),
    )


def run(server: str, payload: str, runs: int, duration: int, pps: int) -> list[dict]:
    """Send the stream from the sender port and read the receiver's counters."""
    from trex.stl.api import STLClient

    client = STLClient(server=server)
    client.connect()
    results = []
    try:
        client.acquire(force=True)
        for attempt in range(1, runs + 1):
            client.reset()
            client.clear_stats()
            client.set_port_attr(client.get_all_ports(), promiscuous=True)
            client.add_streams(build_stream(payload, pps), ports=[TREX_SENDER_PORT])
            client.start(ports=[TREX_SENDER_PORT], duration=duration)
            client.wait_on_traffic(ports=[TREX_SENDER_PORT])
            # Let in-flight packets and latency samples arrive.
            time.sleep(2)

            stats = client.get_stats()
            xstats = client.get_xstats(TREX_RECEIVER_PORT)
            latency = stats.get("latency", {}).get(PG_ID, {})
            histogram = latency.get("latency", {}).get("histogram", {})
            result = {
                "payload": payload,
                "run": attempt,
                "sent": stats[TREX_SENDER_PORT]["opackets"],
                "received": stats[TREX_RECEIVER_PORT]["ipackets"],
                "ierrors": stats[TREX_RECEIVER_PORT]["ierrors"],
                "latency_samples": sum(histogram.values()),
                "latency_errors": latency.get("err_cntrs"),
                "rx_xstats": {
                    name: value
                    for name, value in xstats.items()
                    if value and ("rx" in name or "miss" in name or "err" in name)
                },
            }
            print(json.dumps(result))
            results.append(result)
    finally:
        client.reset()
        client.release()
        client.disconnect()
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    config_parser = commands.add_parser("config")
    config_parser.add_argument(
        "--memory", choices=("ptf", "default", "tiny"), required=True
    )
    config_parser.add_argument("--out", required=True)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--server", default="127.0.0.1")
    run_parser.add_argument("--payload", choices=("plain", "gtpu"), required=True)
    run_parser.add_argument("--runs", type=int, default=2)
    run_parser.add_argument("--duration", type=int, default=10)
    run_parser.add_argument("--pps", type=int, default=1_000)
    args = parser.parse_args()

    if args.command == "config":
        write_config(args.memory, args.out)
    else:
        run(args.server, args.payload, args.runs, args.duration, args.pps)


if __name__ == "__main__":
    main()
