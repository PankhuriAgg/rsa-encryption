#!/usr/bin/env python3
"""
cli.py  —  RSA Encryption CLI
==============================
Commands
--------
  keygen   Generate & display a keypair
  encrypt  Encrypt a message
  decrypt  Decrypt a message
  demo     Full round-trip (keygen → encrypt → decrypt) in one command
  stress   Stress-test: key-gen / enc / dec time across 1024–4096-bit keys

Usage examples
--------------
  python cli.py demo   --bits 2048 --impl both --message "Hello, IEEE!"
  python cli.py stress --bits 1024 2048 3072 4096 --impl both --runs 1
  python cli.py keygen --bits 2048 --impl scratch
"""

import argparse
import sys
import textwrap
import time

# ── pretty-print helpers ─────────────────────────────────────────────────────

BOLD  = "\033[1m"
GREEN = "\033[92m"
CYAN  = "\033[96m"
YELLOW= "\033[93m"
RED   = "\033[91m"
RESET = "\033[0m"
DIM   = "\033[2m"

def hdr(text: str):
    w = 70
    print(f"\n{BOLD}{CYAN}{'─'*w}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*w}{RESET}")

def kv(label: str, value, color=RESET):
    print(f"  {DIM}{label:<22}{RESET}{color}{value}{RESET}")

def ok(msg):  print(f"  {GREEN}✔  {msg}{RESET}")
def err(msg): print(f"  {RED}✘  {msg}{RESET}"); sys.exit(1)
def warn(msg):print(f"  {YELLOW}⚠  {msg}{RESET}")

def truncate(n: int, chars: int = 60) -> str:
    s = str(n)
    return s[:chars] + f"…  [{len(s)} digits]" if len(s) > chars else s

# ── subcommand implementations ───────────────────────────────────────────────

def cmd_keygen(args):
    from rsa_core import ScratchRSA, LibRSA
    impls = _resolve_impls(args.impl)

    for name, cls in impls:
        hdr(f"Key Generation  [{name.upper()}]  {args.bits}-bit")
        t0 = time.perf_counter()
        kp = cls.generate_keypair(args.bits)
        elapsed = (time.perf_counter() - t0) * 1000

        kv("Source",    kp.source,         CYAN)
        kv("Key bits",  kp.bit_size,        GREEN)
        kv("e (pub exp)", kp.e,             GREEN)
        kv("n (modulus)", truncate(kp.n),   YELLOW)
        kv("d (priv exp)", truncate(kp.d),  RED)
        kv("p",         truncate(kp.p),     DIM)
        kv("q",         truncate(kp.q),     DIM)
        kv("Keygen time", f"{elapsed:.1f} ms", GREEN)
        print()


def cmd_demo(args):
    from rsa_core import ScratchRSA, LibRSA
    impls = _resolve_impls(args.impl)
    msg = args.message

    for name, cls in impls:
        hdr(f"Full Demo  [{name.upper()}]  {args.bits}-bit")

        # — Key generation
        print(f"\n{BOLD}  [1/3] Key Generation{RESET}")
        t0 = time.perf_counter()
        kp = cls.generate_keypair(args.bits)
        kg_ms = (time.perf_counter() - t0) * 1000
        ok(f"Keypair generated in {kg_ms:.1f} ms")
        kv("n", truncate(kp.n), YELLOW)
        kv("e", kp.e, GREEN)
        kv("d", truncate(kp.d), RED)

        # — Encryption
        print(f"\n{BOLD}  [2/3] Encryption{RESET}")
        kv("Plaintext", f'"{msg}"', CYAN)
        t0 = time.perf_counter()
        if name == "scratch":
            ct, blen = cls.encrypt(msg, kp)
            enc_ms = (time.perf_counter() - t0) * 1000
            ok(f"Encrypted in {enc_ms:.3f} ms")
            kv("Ciphertext (int)", truncate(ct, 80), YELLOW)
            kv("Ciphertext (hex)", truncate(ct, 0)[:64] + "…", DIM)
        else:
            ct = cls.encrypt(msg, kp)
            enc_ms = (time.perf_counter() - t0) * 1000
            ok(f"Encrypted in {enc_ms:.3f} ms  [OAEP/SHA-256 padding]")
            kv("Ciphertext (hex)", ct.hex()[:80] + "…", YELLOW)

        # — Decryption
        print(f"\n{BOLD}  [3/3] Decryption{RESET}")
        t0 = time.perf_counter()
        if name == "scratch":
            recovered = cls.decrypt(ct, blen, kp)
        else:
            recovered = cls.decrypt(ct, kp)
        dec_ms = (time.perf_counter() - t0) * 1000
        ok(f"Decrypted in {dec_ms:.3f} ms")
        kv("Recovered",  f'"{recovered}"', GREEN)

        if recovered == msg:
            ok("Round-trip PASSED ✓")
        else:
            warn("Round-trip FAILED — plaintext mismatch!")

        # — Summary row
        print(f"\n{DIM}  {'Metric':<20} {'Value':>12}{RESET}")
        print(f"  {'─'*34}")
        for label, val in [
            ("Key generation", f"{kg_ms:.1f} ms"),
            ("Encryption",     f"{enc_ms:.3f} ms"),
            ("Decryption",     f"{dec_ms:.3f} ms"),
        ]:
            print(f"  {label:<20} {BOLD}{val:>12}{RESET}")
        print()


def cmd_stress(args):
    from rsa_core import ScratchRSA, LibRSA, BenchResult, benchmark_scratch, benchmark_library

    impls = _resolve_impls(args.impl)
    key_sizes = args.bits
    runs = args.runs
    msg = args.message

    total = len(key_sizes) * len(impls) * runs
    done  = 0

    hdr(f"Stress Test  —  {total} benchmark runs")
    print(f"  Key sizes : {key_sizes}")
    print(f"  Impls     : {[n for n,_ in impls]}")
    print(f"  Runs each : {runs}\n")

    # Collect results
    all_results: list[BenchResult] = []
    for bits in key_sizes:
        for name, cls in impls:
            for run in range(1, runs + 1):
                done += 1
                print(f"  [{done:>3}/{total}] {name:>8}  {bits}-bit  run {run}…", end="", flush=True)
                if name == "scratch":
                    r = benchmark_scratch(bits, msg)
                else:
                    r = benchmark_library(bits, msg)
                all_results.append(r)
                print(f"  keygen={r.keygen_ms:>8.1f} ms  "
                      f"enc={r.encrypt_ms:>7.3f} ms  "
                      f"dec={r.decrypt_ms:>7.3f} ms")

    # Summary table (averaged if runs > 1)
    hdr("Stress Test Results (averages)")
    col_w = [10, 10, 14, 12, 12]
    headers = ["Impl", "Key bits", "Keygen (ms)", "Enc (ms)", "Dec (ms)"]
    row_fmt = "  " + "  ".join(f"{{:<{w}}}" for w in col_w)
    print(BOLD + row_fmt.format(*headers) + RESET)
    print("  " + "─" * sum(col_w + [2*len(col_w)]))

    from itertools import groupby
    from statistics import mean

    def group_key(r): return (r.source, r.key_bits)
    sorted_res = sorted(all_results, key=group_key)
    for (src, bits), grp in groupby(sorted_res, key=group_key):
        grp = list(grp)
        kg  = mean(r.keygen_ms  for r in grp)
        enc = mean(r.encrypt_ms for r in grp)
        dec = mean(r.decrypt_ms for r in grp)
        color = CYAN if src == "scratch" else GREEN
        print(color + row_fmt.format(src, bits, f"{kg:.1f}", f"{enc:.3f}", f"{dec:.3f}") + RESET)

    # Speedup ratio
    hdr("Library vs. Scratch Speedup")
    scratch_map = {r.key_bits: r for r in all_results if r.source == "scratch"}
    lib_map     = {r.key_bits: r for r in all_results if r.source == "library"}
    for bits in key_sizes:
        if bits in scratch_map and bits in lib_map:
            s, l = scratch_map[bits], lib_map[bits]
            ratio = s.keygen_ms / max(l.keygen_ms, 0.001)
            print(f"  {bits}-bit  keygen speedup (lib/scratch): {BOLD}{ratio:.1f}×{RESET}")
    print()


# ── argument parser ──────────────────────────────────────────────────────────

def _resolve_impls(impl_arg: str):
    from rsa_core import ScratchRSA, LibRSA
    if impl_arg == "scratch":
        return [("scratch", ScratchRSA)]
    if impl_arg == "library":
        return [("library", LibRSA)]
    return [("scratch", ScratchRSA), ("library", LibRSA)]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rsa-cli",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            RSA Encryption CLI — NIT Jalandhar IEEE Paper Companion
            ─────────────────────────────────────────────────────────
            Commands: keygen | demo | stress
        """)
    )
    sub = p.add_subparsers(dest="command", required=True)

    # shared options factory
    def add_common(sp):
        sp.add_argument("--bits",  type=int, default=2048,
                        help="Key size in bits (default: 2048)")
        sp.add_argument("--impl",  choices=["scratch","library","both"],
                        default="both", help="Implementation to use")

    # keygen
    sp_kg = sub.add_parser("keygen", help="Generate and display a keypair")
    add_common(sp_kg)

    # demo
    sp_demo = sub.add_parser("demo",
        help="Full round-trip: keygen → encrypt → decrypt")
    add_common(sp_demo)
    sp_demo.add_argument("--message", "-m", default="Hello, IEEE 2025!",
                         help="Plaintext to encrypt")

    # stress
    sp_st = sub.add_parser("stress",
        help="Stress-test key sizes")
    sp_st.add_argument("--bits", nargs="+", type=int,
                       default=[1024, 2048, 3072, 4096],
                       help="Key sizes to test (default: 1024 2048 3072 4096)")
    sp_st.add_argument("--impl", choices=["scratch","library","both"],
                       default="both")
    sp_st.add_argument("--runs", type=int, default=1,
                       help="Runs per (key_size × impl) combination")
    sp_st.add_argument("--message", "-m", default="Benchmark payload",
                       help="Plaintext used during benchmark")

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    dispatch = {
        "keygen": cmd_keygen,
        "demo":   cmd_demo,
        "stress": cmd_stress,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
