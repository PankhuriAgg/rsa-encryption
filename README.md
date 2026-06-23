# RSA Encryption — From Scratch to Production

> Companion implementation for the IEEE paper:
> **"RSA Encryption: Mathematical Foundations, From-Scratch Implementation, and Performance Benchmarking"**
> — Pankhuri Aggarwal, NIT Jalandhar

---

## Live Demo

**[rsa-encryption.streamlit.app](https://rsa-encryption.streamlit.app)**

No installation needed — open the link and start encrypting.

---

## What This Is

Two complete RSA implementations, side by side:

| | `ScratchRSA` | `LibRSA` |
|---|---|---|
| **Prime generation** | Miller-Rabin (40 rounds) | OpenSSL (C-level) |
| **Modular inverse** | Extended Euclidean Algorithm | OpenSSL |
| **Padding** | None (textbook RSA) | PKCS#1 OAEP / SHA-256 |
| **Speed** | Pure Python | C extension (10–100×) |
| **Purpose** | Education / paper demo | Production-grade |

---

## Features

- **Live Demo** — generate real RSA keypairs, encrypt text, decrypt back, see the actual big-integer ciphertext and all key parameters (n, e, d, p, q)
- **Stress Test** — benchmark key sizes 1024 / 2048 / 3072 / 4096 bits with Plotly charts and CSV export
- **Theory Tab** — all paper equations rendered in LaTeX (Euler's theorem, Miller-Rabin, Extended Euclidean)
- **CLI** — full terminal interface with `keygen`, `demo`, and `stress` commands

---

## Project Structure

```
rsa-encryption/
├── app.py              # Streamlit UI (Live Demo + Stress Test + Theory)
├── cli.py              # Command-line interface
├── rsa_core.py         # Core RSA logic — ScratchRSA + LibRSA + benchmarks
├── requirements.txt    # Python dependencies
├── .streamlit/
│   └── config.toml     # Streamlit theme + server config
└── README.md
```

---

## Run Locally

```bash
# 1. Clone
git clone https://github.com/PankhuriAgg/rsa-encryption.git
cd rsa-encryption

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run Streamlit UI
streamlit run app.py

# 5. Or use the CLI
python3 cli.py demo --bits 2048 --impl both --message "Hello IEEE!"
python3 cli.py stress --bits 1024 2048 3072 4096 --impl both
python3 cli.py keygen --bits 4096 --impl scratch
```

---

## CLI Reference

```bash
# Full round-trip demo
python3 cli.py demo --bits 2048 --impl both --message "Your message"

# Key generation only
python3 cli.py keygen --bits 4096 --impl library

# Stress test (key size vs time)
python3 cli.py stress --bits 1024 2048 3072 4096 --impl both --runs 1
```

**`--impl` options:** `scratch` | `library` | `both`

---

## Benchmark Results (x86-64, Python 3.12.3)

| Key (bits) | Impl | Keygen (ms) | Encrypt (ms) | Decrypt (ms) |
|---|---|---|---|---|
| 1024 | Scratch | 255.4 | 0.059 | 4.383 |
| 1024 | Library | 755.5 | 193.4 | 16.94 |
| 2048 | Scratch | 5804.2 | 0.155 | 25.86 |
| 2048 | Library | 142.5 | 33.16 | 33.73 |
| 3072 | Scratch | 18175.7 | 0.308 | 82.08 |
| 3072 | Library | 430.8 | 57.17 | 59.81 |
| 4096 | Scratch | 67559.0 | 0.498 | 190.4 |
| 4096 | Library | 3643.3 | 83.79 | 88.63 |

---

## Mathematical Background

RSA encryption: $c = m^e \bmod n$

RSA decryption: $m = c^d \bmod n$

Correctness proof: $m^{ed} = m^{1 + k\phi(n)} \equiv m \pmod{n}$ (Euler's theorem)

See the Theory tab in the app or the accompanying IEEE paper for full derivations.

---

## Security Notice

`ScratchRSA` uses **no padding** and is **not constant-time**.
It is for educational purposes only — never use it for real data.
`LibRSA` (OAEP/SHA-256) is production-appropriate.

---

## License

MIT License — see [LICENSE](LICENSE)

---

