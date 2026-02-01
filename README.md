<div align="center">
  <img src="assets/logo.png" alt="HoneyBan Logo" width="200" height="auto" />
  <h1>HoneyBan</h1>
  <p>
    <strong>The eBPF-based Fail2Ban killer.</strong><br>
    Drop DDoS packets at the driver level. 0% CPU load. 100% Rust-free C.
  </p>

  <p>
    <a href="https://honeyban.com"><img src="https://img.shields.io/badge/website-honeyban.com-blue?style=flat-square" alt="Website"></a>
    <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
    <img src="https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square" alt="Platform">
    <img src="https://img.shields.io/badge/built%20with-eBPF%20%2F%20XDP-orange?style=flat-square" alt="eBPF">
  </p>

  <h3>
    <a href="#installation">Installation</a>
    <span> | </span>
    <a href="#how-it-works">How It Works</a>
    <span> | </span>
    <a href="#benchmark">Benchmarks</a>
  </h3>
</div>

---

## ⚡ Why HoneyBan?

Your server is probably using **Fail2Ban**. That's fine for 2010.
But in 2026, when a botnet hits you with **100k packets per second**, Fail2Ban dies. Why? Because it parses logs (slow) and uses `iptables` (slow).

**HoneyBan** runs in the Linux Kernel (eBPF/XDP). It drops malicious packets **before** they even touch your OS.

| Feature | Fail2Ban (Legacy) | HoneyBan (Next-Gen) |
| :--- | :--- | :--- |
| **Technology** | Python + Iptables | **C + eBPF / XDP** |
| **Blocking Speed** | ~200ms (Slow) | **~0.001ms (Instant)** |
| **CPU Load (DDoS)** | 🔥 100% (Server crash) | ❄️ **< 1% (Sleep mode)** |
| **Mechanism** | User-Space Log Parsing | **Kernel-Space Driver Hook** |

---

## 🚀 Quick Install (Ubuntu/Debian)

Don't waste time compiling. Get the binary and start protecting your VPS in 10 seconds.

```bash
curl -sL [https://honeyban.com/install.sh](https://honeyban.com/install.sh) | sudo bash
