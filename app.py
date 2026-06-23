"""
app.py  —  RSA Encryption  ·  Streamlit UI
===========================================
Run with:  streamlit run app.py
"""

import time
import streamlit as st
import plotly.graph_objects as go
import pandas as pd

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="RSA Encryption",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ──────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* global */
html, body, [class*="css"] { font-family: 'Segoe UI', sans-serif; }

/* sidebar */
section[data-testid="stSidebar"] { background: #0f1b2d; }
section[data-testid="stSidebar"] * { color: #e0e8f5 !important; }
section[data-testid="stSidebar"] .stSelectbox label,
section[data-testid="stSidebar"] .stSlider label { font-weight: 600; }

/* metric cards */
div[data-testid="metric-container"] {
    background: #0f1b2d;
    border: 1px solid #1e3a5f;
    border-radius: 10px;
    padding: 12px 16px;
}

/* section headers */
.section-hdr {
    background: linear-gradient(90deg,#0f1b2d,#1a2e4a);
    border-left: 4px solid #2e75b6;
    border-radius: 6px;
    padding: 8px 16px;
    margin: 16px 0 10px 0;
    font-size: 1.05rem;
    font-weight: 700;
    color: #7fb8e8;
    letter-spacing: .5px;
}

/* key display box */
.key-box {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 10px 14px;
    font-family: 'Courier New', monospace;
    font-size: 0.78rem;
    color: #58a6ff;
    word-break: break-all;
    max-height: 130px;
    overflow-y: auto;
    line-height: 1.5;
}

/* ciphertext / plaintext */
.ct-box {
    background: #161b22;
    border: 1px solid #f0883e55;
    border-radius: 8px;
    padding: 10px 14px;
    font-family: 'Courier New', monospace;
    font-size: 0.8rem;
    color: #f0883e;
    word-break: break-all;
    max-height: 120px;
    overflow-y: auto;
}
.pt-box {
    background: #0d1117;
    border: 1px solid #3fb95055;
    border-radius: 8px;
    padding: 10px 14px;
    font-family: 'Courier New', monospace;
    font-size: 0.95rem;
    color: #3fb950;
    word-break: break-all;
}
.badge-scratch { background:#1e3a5f; color:#7fb8e8; border-radius:4px; padding:2px 8px; font-size:.8rem; }
.badge-lib     { background:#1e4a2e; color:#7fd89c; border-radius:4px; padding:2px 8px; font-size:.8rem; }
.warn-box      { background:#2d1f0e; border:1px solid #f0883e; border-radius:6px; padding:8px 12px; color:#f0883e; font-size:.85rem; margin:6px 0; }
</style>
""", unsafe_allow_html=True)

# ── Imports (deferred so Streamlit can render page first) ────────────────────
from rsa_core import (
    ScratchRSA, LibRSA,
    benchmark_scratch, benchmark_library,
    RSAKeyPair
)

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 RSA Encryption")
    st.markdown("---")
    tab_choice = st.radio(
        "Mode",
        ["Live Demo", "Stress Test", "Theory"],
        index=0,
    )
    st.markdown("---")
    impl_choice = st.selectbox(
        "Implementation",
        ["Both", "From Scratch", "Library (PyCryptodome)"],
        help="'From Scratch' = Miller-Rabin + Extended GCD\n'Library' = OAEP/SHA-256 via PyCryptodome"
    )
    key_bits = st.select_slider(
        "Key Size (bits)",
        options=[512, 1024, 2048, 3072, 4096],
        value=1024,
    )
    st.markdown("---")
    st.caption("Paper: *A Comprehensive Survey on Cryptographic Encryption Systems*, 2025")

# ─────────────────────────────────────────────────────────────────────────────
# ── TAB 1: LIVE DEMO ─────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
if tab_choice == "Live Demo":
    st.title("🔐 Live RSA Encryption & Decryption")
    st.caption(
        "Generate a real RSA keypair, encrypt any text, and decrypt it back — "
        "showing the actual big-integer ciphertext and all key parameters."
    )

    # ── Input ────────────────────────────────────────────────────────────────
    st.markdown('<div class="section-hdr">① Input</div>', unsafe_allow_html=True)
    col_msg, col_btn = st.columns([4, 1])
    with col_msg:
        plaintext = st.text_area(
            "Plaintext",
            value="Hello, IEEE 2025! RSA encryption demonstration.",
            height=80,
            label_visibility="collapsed",
        )
    with col_btn:
        st.write("")
        st.write("")
        run_btn = st.button("🚀 Run", use_container_width=True, type="primary")

    # Max message size hint
    max_bytes = (key_bits - 1) // 8
    lib_max   = key_bits // 8 - 66   # OAEP overhead ~66 bytes
    st.caption(
        f"*Scratch max: {max_bytes} bytes · Library (OAEP) max: {lib_max} bytes · "
        f"Your message: {len(plaintext.encode())} bytes*"
    )
    if len(plaintext.encode()) > lib_max:
        st.markdown(
            f'<div class="warn-box">⚠ Message exceeds OAEP limit for {key_bits}-bit key. '
            f'Shorten message or increase key size.</div>',
            unsafe_allow_html=True
        )

    if run_btn and plaintext:
        # ── Key generation ───────────────────────────────────────────────
        st.markdown('<div class="section-hdr">② Key Generation</div>', unsafe_allow_html=True)

        impls_to_run = []
        if impl_choice in ("Both", "From Scratch"):    impls_to_run.append(("scratch", ScratchRSA))
        if impl_choice in ("Both", "Library (PyCryptodome)"): impls_to_run.append(("library", LibRSA))

        keypairs = {}
        kg_times = {}

        cols = st.columns(len(impls_to_run))
        for i, (name, cls) in enumerate(impls_to_run):
            with cols[i]:
                badge = "badge-scratch" if name == "scratch" else "badge-lib"
                label = "From Scratch (Miller-Rabin)" if name == "scratch" else "Library (PyCryptodome OAEP)"
                st.markdown(f'<span class="{badge}">{label}</span>', unsafe_allow_html=True)

                with st.spinner(f"Generating {key_bits}-bit keypair…"):
                    t0 = time.perf_counter()
                    kp = cls.generate_keypair(key_bits)
                    kg_ms = (time.perf_counter() - t0) * 1000

                keypairs[name] = kp
                kg_times[name] = kg_ms

                st.metric("Keygen Time", f"{kg_ms:.1f} ms")

                with st.expander("View Key Parameters"):
                    st.markdown(f"**Public Exponent (e):** `{kp.e}`")
                    st.markdown("**Modulus (n):**")
                    st.markdown(f'<div class="key-box">{kp.n}</div>', unsafe_allow_html=True)
                    st.markdown("**Private Exponent (d):**")
                    st.markdown(f'<div class="key-box">{kp.d}</div>', unsafe_allow_html=True)
                    st.markdown(f"**Prime p:** `{str(kp.p)[:40]}…`")
                    st.markdown(f"**Prime q:** `{str(kp.q)[:40]}…`")

        # ── Encryption ───────────────────────────────────────────────────
        st.markdown('<div class="section-hdr">③ Encryption</div>', unsafe_allow_html=True)
        ciphertexts = {}
        blens = {}

        enc_cols = st.columns(len(impls_to_run))
        for i, (name, cls) in enumerate(impls_to_run):
            kp = keypairs[name]
            with enc_cols[i]:
                badge = "badge-scratch" if name == "scratch" else "badge-lib"
                label = "Scratch" if name == "scratch" else "Library"
                st.markdown(f'<span class="{badge}">{label}</span>', unsafe_allow_html=True)
                try:
                    t0 = time.perf_counter()
                    if name == "scratch":
                        ct, blen = cls.encrypt(plaintext, kp)
                        blens[name] = blen
                    else:
                        ct = cls.encrypt(plaintext, kp)
                    enc_ms = (time.perf_counter() - t0) * 1000

                    ciphertexts[name] = ct
                    st.metric("Encrypt Time", f"{enc_ms:.3f} ms")

                    st.markdown("**Ciphertext:**")
                    ct_display = str(ct) if name == "scratch" else ct.hex()
                    st.markdown(f'<div class="ct-box">{ct_display[:500]}{"…" if len(ct_display)>500 else ""}</div>',
                                unsafe_allow_html=True)
                    if name == "scratch":
                        st.caption(f"Integer: {ct.bit_length()} bits")
                    else:
                        st.caption(f"Bytes: {len(ct)} · Format: PKCS#1 OAEP / SHA-256")

                except ValueError as ve:
                    st.error(str(ve))
                    ciphertexts[name] = None

        # ── Decryption ───────────────────────────────────────────────────
        st.markdown('<div class="section-hdr">④ Decryption & Verification</div>',
                    unsafe_allow_html=True)

        dec_cols = st.columns(len(impls_to_run))
        for i, (name, cls) in enumerate(impls_to_run):
            kp = keypairs[name]
            ct = ciphertexts.get(name)
            with dec_cols[i]:
                badge = "badge-scratch" if name == "scratch" else "badge-lib"
                label = "Scratch" if name == "scratch" else "Library"
                st.markdown(f'<span class="{badge}">{label}</span>', unsafe_allow_html=True)
                if ct is None:
                    st.warning("Skipped (encryption failed)")
                    continue
                try:
                    t0 = time.perf_counter()
                    if name == "scratch":
                        recovered = cls.decrypt(ct, blens[name], kp)
                    else:
                        recovered = cls.decrypt(ct, kp)
                    dec_ms = (time.perf_counter() - t0) * 1000

                    st.metric("Decrypt Time", f"{dec_ms:.3f} ms")
                    st.markdown("**Recovered Plaintext:**")
                    st.markdown(f'<div class="pt-box">{recovered}</div>', unsafe_allow_html=True)

                    if recovered == plaintext:
                        st.success("✅ Round-trip verified — plaintext matches exactly")
                    else:
                        st.error("❌ Mismatch — decryption failed")

                except Exception as ex:
                    st.error(f"Decryption error: {ex}")

        # ── Timing summary ───────────────────────────────────────────────
        st.markdown('<div class="section-hdr">⑤ Timing Summary</div>', unsafe_allow_html=True)
        summary_rows = []
        for name, _ in impls_to_run:
            kp = keypairs.get(name)
            if kp:
                summary_rows.append({
                    "Implementation": "From Scratch" if name=="scratch" else "Library (PyCryptodome)",
                    "Key Bits": key_bits,
                    "Keygen (ms)": round(kg_times.get(name, 0), 2),
                })
        if summary_rows:
            st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)


# ─────────────────────────────────────────────────────────────────────────────
# ── TAB 2: STRESS TEST ───────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
elif tab_choice == "Stress Test":
    st.title("📊 RSA Stress Test — Key Size vs. Performance")
    st.caption(
        "Measures key generation, encryption, and decryption time across "
        "1024 / 2048 / 3072 / 4096-bit keys for both implementations."
    )

    # Config
    c1, c2, c3 = st.columns(3)
    with c1:
        sel_sizes = st.multiselect(
            "Key Sizes to Test",
            [512, 1024, 2048, 3072, 4096],
            default=[1024, 2048, 3072, 4096],
        )
    with c2:
        sel_runs = st.number_input("Runs per (key × impl)", min_value=1, max_value=5, value=1)
    with c3:
        bench_msg = st.text_input("Benchmark Message", value="Benchmark payload 2025")

    sel_impls = []
    if impl_choice in ("Both", "From Scratch"):
        sel_impls.append(("scratch", benchmark_scratch))
    if impl_choice in ("Both", "Library (PyCryptodome)"):
        sel_impls.append(("library", benchmark_library))

    if not sel_sizes:
        st.warning("Select at least one key size.")
        st.stop()

    run_stress = st.button("▶ Run Stress Test", type="primary")

    if run_stress:
        total = len(sel_sizes) * len(sel_impls) * sel_runs
        results = []
        progress = st.progress(0, text="Starting…")
        status   = st.empty()
        done = 0

        for bits in sorted(sel_sizes):
            for name, bench_fn in sel_impls:
                for run in range(sel_runs):
                    done += 1
                    status.markdown(f"`[{done}/{total}]` Running **{name}** — **{bits}-bit** (run {run+1})…")
                    r = bench_fn(bits, bench_msg)
                    results.append({
                        "Impl":       "Scratch" if name == "scratch" else "Library",
                        "Key Bits":   bits,
                        "Run":        run + 1,
                        "Keygen ms":  r.keygen_ms,
                        "Encrypt ms": r.encrypt_ms,
                        "Decrypt ms": r.decrypt_ms,
                    })
                    progress.progress(done / total, text=f"{done}/{total} done")

        status.empty()
        df = pd.DataFrame(results)

        # Average across runs
        df_avg = df.groupby(["Impl","Key Bits"], as_index=False)[
            ["Keygen ms","Encrypt ms","Decrypt ms"]
        ].mean().round(3)

        # ── Charts ───────────────────────────────────────────────────────
        colors = {"Scratch": "#2e75b6", "Library": "#3fb950"}

        def make_chart(metric: str, title: str) -> go.Figure:
            fig = go.Figure()
            for impl in df_avg["Impl"].unique():
                d = df_avg[df_avg["Impl"] == impl]
                fig.add_trace(go.Scatter(
                    x=d["Key Bits"], y=d[metric],
                    mode="lines+markers",
                    name=impl,
                    line=dict(color=colors.get(impl, "#aaa"), width=2.5),
                    marker=dict(size=8),
                ))
            fig.update_layout(
                title=title,
                xaxis_title="Key Size (bits)",
                yaxis_title="Time (ms)",
                template="plotly_dark",
                paper_bgcolor="#0f1b2d",
                plot_bgcolor="#0d1117",
                font=dict(family="Segoe UI", color="#e0e8f5"),
                legend=dict(bgcolor="#0f1b2d", bordercolor="#2e75b6", borderwidth=1),
                margin=dict(l=40, r=20, t=50, b=40),
                hovermode="x unified",
            )
            return fig

        st.markdown('<div class="section-hdr">Key Generation Time vs. Key Size</div>',
                    unsafe_allow_html=True)
        st.plotly_chart(make_chart("Keygen ms", "Key Generation Time"), use_container_width=True)

        c_enc, c_dec = st.columns(2)
        with c_enc:
            st.markdown('<div class="section-hdr">Encryption Time</div>', unsafe_allow_html=True)
            st.plotly_chart(make_chart("Encrypt ms", "Encryption Time"), use_container_width=True)
        with c_dec:
            st.markdown('<div class="section-hdr">Decryption Time</div>', unsafe_allow_html=True)
            st.plotly_chart(make_chart("Decrypt ms", "Decryption Time"), use_container_width=True)

        # ── Raw data table ───────────────────────────────────────────────
        st.markdown('<div class="section-hdr">Raw Results (averaged)</div>',
                    unsafe_allow_html=True)
        st.dataframe(df_avg, use_container_width=True, hide_index=True)

        # ── Speedup ──────────────────────────────────────────────────────
        if "Scratch" in df_avg["Impl"].values and "Library" in df_avg["Impl"].values:
            st.markdown('<div class="section-hdr">Library Speedup over Scratch (keygen)</div>',
                        unsafe_allow_html=True)
            s_df = df_avg[df_avg["Impl"]=="Scratch"][["Key Bits","Keygen ms"]].rename(columns={"Keygen ms":"Scratch ms"})
            l_df = df_avg[df_avg["Impl"]=="Library"][["Key Bits","Keygen ms"]].rename(columns={"Keygen ms":"Library ms"})
            su = s_df.merge(l_df, on="Key Bits")
            su["Speedup (×)"] = (su["Scratch ms"] / su["Library ms"]).round(1)
            st.dataframe(su, use_container_width=True, hide_index=True)

            fig_sp = go.Figure(go.Bar(
                x=su["Key Bits"].astype(str) + "-bit",
                y=su["Speedup (×)"],
                marker_color="#f0883e",
                text=su["Speedup (×)"].astype(str) + "×",
                textposition="outside",
            ))
            fig_sp.update_layout(
                title="Library Speedup over From-Scratch Implementation",
                xaxis_title="Key Size", yaxis_title="Speedup (×)",
                template="plotly_dark",
                paper_bgcolor="#0f1b2d", plot_bgcolor="#0d1117",
                font=dict(family="Segoe UI", color="#e0e8f5"),
                margin=dict(l=40, r=20, t=50, b=40),
            )
            st.plotly_chart(fig_sp, use_container_width=True)

        # ── Download ─────────────────────────────────────────────────────
        csv = df.to_csv(index=False).encode()
        st.download_button("⬇ Download Full Results CSV", csv,
                           "rsa_stress_results.csv", "text/csv")


# ─────────────────────────────────────────────────────────────────────────────
# ── TAB 3: THEORY ────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
else:
    st.title("📐 RSA — Mathematical Foundations")
    st.caption("Reference: *A Comprehensive Survey on Cryptographic Encryption Systems* — NIT Jalandhar")

    st.markdown("### Key Generation")
    st.latex(r"""
    \text{Select primes } p, q \quad\Rightarrow\quad
    n = p \cdot q, \quad
    \phi(n) = (p-1)(q-1)
    """)
    st.latex(r"""
    \text{Choose } e : \gcd(e,\phi(n))=1,\quad
    d \equiv e^{-1} \pmod{\phi(n)}
    """)

    st.markdown("### Encryption & Decryption")
    st.latex(r"c = m^e \pmod{n}")
    st.latex(r"m = c^d \pmod{n}")

    st.markdown("### Correctness (Euler's Theorem)")
    st.latex(r"m^{ed} \equiv m^{1+k\phi(n)} \equiv m \pmod{n}")

    st.markdown("### Miller-Rabin Primality Test")
    st.latex(r"""
    n - 1 = 2^r \cdot d \quad\text{(factor out 2s)}
    """)
    st.latex(r"""
    \text{Witness } a \in [2, n-2]: \quad
    a^d \not\equiv 1 \pmod{n} \;\wedge\;
    a^{2^j d} \not\equiv -1 \pmod{n}\;\forall j
    \;\Rightarrow\; n \text{ is composite}
    """)

    st.markdown("### Extended Euclidean Algorithm (for d)")
    st.latex(r"\gcd(e, \phi(n)) = e \cdot x + \phi(n) \cdot y = 1 \;\Rightarrow\; d = x \bmod \phi(n)")

    st.markdown("### Security Basis")
    st.info(
        "RSA's security rests on the **Integer Factorization Problem**: "
        "given n = p·q, recovering p and q requires sub-exponential time "
        "for classical algorithms (General Number Field Sieve: "
        "L_n[1/3, 1.923]).\n\n"
        "⚠ Shor's quantum algorithm breaks RSA in **polynomial time** O(n³), "
        "motivating migration to CRYSTALS-Kyber / CRYSTALS-Dilithium (NIST FIPS 203/204)."
    )

    st.markdown("### From-Scratch vs Library")
    comp_df = pd.DataFrame({
        "Property":       ["Algorithm","Padding","Prime gen","Speed","Security","Use"],
        "From Scratch":   ["Textbook RSA","None (raw modexp)","Miller-Rabin","Slow (pure Python)","Pedagogical only","Education / demo"],
        "Library":        ["RSA + OAEP","PKCS#1 OAEP / SHA-256","C-level (OpenSSL)","Fast (C extension)","Production-grade","Real deployments"],
    })
    st.dataframe(comp_df, use_container_width=True, hide_index=True)
