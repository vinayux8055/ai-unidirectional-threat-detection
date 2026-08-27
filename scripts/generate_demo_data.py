from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def clipped_normal(rng: np.random.Generator, mean: float, std: float, rows: int, minimum: float = 0) -> np.ndarray:
    return np.clip(rng.normal(mean, std, rows), minimum, None)


def generate(rows: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    attack_types = np.array(["Normal", "DoS", "Reconnaissance", "Exploits", "Fuzzers", "Backdoor"])
    probabilities = np.array([0.58, 0.14, 0.10, 0.08, 0.07, 0.03])
    attack_cat = rng.choice(attack_types, size=rows, p=probabilities)
    label = (attack_cat != "Normal").astype(int)

    dos = attack_cat == "DoS"
    recon = attack_cat == "Reconnaissance"
    exploits = attack_cat == "Exploits"
    fuzzers = attack_cat == "Fuzzers"
    backdoor = attack_cat == "Backdoor"

    proto = rng.choice(["tcp", "udp", "icmp"], rows, p=[0.68, 0.26, 0.06])
    proto[dos & (rng.random(rows) < 0.45)] = "udp"
    service = rng.choice(["http", "https", "dns", "ssh", "ftp", "-"], rows)
    service[recon] = "-"
    state = rng.choice(["FIN", "CON", "INT", "REQ", "RST"], rows, p=[0.38, 0.27, 0.15, 0.12, 0.08])
    state[dos] = rng.choice(["INT", "REQ"], dos.sum())

    dur = clipped_normal(rng, 1.8, 1.1, rows, 0.001)
    dur[dos] = clipped_normal(rng, 0.25, 0.15, dos.sum(), 0.001)
    spkts = rng.poisson(18, rows) + 1
    spkts[dos] = rng.poisson(180, dos.sum()) + 20
    spkts[recon] = rng.poisson(3, recon.sum()) + 1
    smean = clipped_normal(rng, 520, 180, rows, 40)
    smean[recon] = clipped_normal(rng, 90, 35, recon.sum(), 20)
    smean[fuzzers] = clipped_normal(rng, 1250, 420, fuzzers.sum(), 60)
    sbytes = (spkts * smean * rng.uniform(0.82, 1.18, rows)).astype(int)
    rate = spkts / np.maximum(dur, 0.001)
    sttl = rng.choice([32, 64, 128, 255], rows, p=[0.04, 0.63, 0.28, 0.05])
    sttl[backdoor] = rng.choice([128, 255], backdoor.sum())
    sload = sbytes * 8 / np.maximum(dur, 0.001)
    sloss = rng.poisson(0.4, rows)
    sloss[dos] += rng.poisson(6, dos.sum())
    sinpkt = dur * 1000 / np.maximum(spkts, 1)
    sjit = clipped_normal(rng, 15, 9, rows)
    sjit[dos] = clipped_normal(rng, 2, 1.4, dos.sum())
    swin = rng.choice([0, 255, 1024, 8192], rows, p=[0.08, 0.28, 0.22, 0.42])
    src_port = rng.integers(1024, 65536, rows)
    dst_port = rng.choice([21, 22, 25, 53, 80, 443, 445, 3389, 8080], rows)
    dst_port[recon] = rng.integers(1, 65536, recon.sum())
    ct_dst_ltm = rng.poisson(3, rows) + 1
    ct_dst_ltm[dos] += rng.poisson(32, dos.sum())
    ct_src_dport_ltm = rng.poisson(2, rows) + 1
    ct_src_dport_ltm[recon] += rng.poisson(38, recon.sum())

    # Reverse fields exist only for the controlled bidirectional baseline.
    dpkts = np.maximum(0, (spkts * rng.uniform(0.45, 1.1, rows)).astype(int))
    dpkts[dos] = rng.poisson(2, dos.sum())
    dbytes = (dpkts * clipped_normal(rng, 480, 160, rows, 20)).astype(int)
    dttl = rng.choice([32, 64, 128, 255], rows)
    dload = dbytes * 8 / np.maximum(dur, 0.001)
    dloss = rng.poisson(0.3, rows)
    dinpkt = dur * 1000 / np.maximum(dpkts, 1)
    djit = clipped_normal(rng, 14, 8, rows)
    dwin = rng.choice([0, 255, 1024, 8192], rows)
    dmean = np.divide(dbytes, np.maximum(dpkts, 1))

    frame = pd.DataFrame(
        {
            "id": np.arange(1, rows + 1),
            "timestamp": pd.date_range("2026-01-01", periods=rows, freq="s").astype(str),
            "src_ip": [f"10.10.{a}.{b}" for a, b in zip(rng.integers(1, 20, rows), rng.integers(1, 255, rows))],
            "dst_ip": [f"172.16.{a}.{b}" for a, b in zip(rng.integers(1, 10, rows), rng.integers(1, 255, rows))],
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "service": service,
            "state": state,
            "dur": dur.round(6),
            "spkts": spkts,
            "sbytes": sbytes,
            "rate": rate.round(6),
            "sttl": sttl,
            "sload": sload.round(3),
            "sloss": sloss,
            "sinpkt": sinpkt.round(6),
            "sjit": sjit.round(6),
            "swin": swin,
            "smean": smean.round(3),
            "ct_dst_ltm": ct_dst_ltm,
            "ct_src_dport_ltm": ct_src_dport_ltm,
            "dpkts": dpkts,
            "dbytes": dbytes,
            "dttl": dttl,
            "dload": dload.round(3),
            "dloss": dloss,
            "dinpkt": dinpkt.round(6),
            "djit": djit.round(6),
            "dwin": dwin,
            "dmean": dmean.round(3),
            "attack_cat": attack_cat,
            "label": label,
        }
    )
    # Controlled imperfections exercise preprocessing without corrupting targets.
    for column in ["sload", "sinpkt", "service"]:
        indices = rng.choice(rows, size=max(1, rows // 250), replace=False)
        frame.loc[indices, column] = np.nan
    return frame


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a synthetic flow dataset for functional testing.")
    parser.add_argument("--rows", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "data" / "sample" / "demo_network_flows.csv")
    args = parser.parse_args()
    if args.rows < 200:
        parser.error("--rows must be at least 200")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    generate(args.rows, args.seed).to_csv(args.output, index=False)
    print(f"Created {args.output} with {args.rows:,} synthetic rows.")
    print("Important: use this file for functional demonstrations, not final accuracy claims.")


if __name__ == "__main__":
    main()

