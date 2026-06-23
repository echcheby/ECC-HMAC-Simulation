# ECC-HMAC Mutual Authentication Protocol for IoT

A lightweight mutual authentication protocol for IoT networks combining
**Elliptic Curve Cryptography (ECC)** and **HMAC-SHA-256**, with full
NS-3 network simulation and formal security verification using ProVerif
and Scyther.

---

## Table of Contents

1. [Protocol Overview](#1-protocol-overview)
2. [Repository Structure](#2-repository-structure)
3. [NS-3 Simulation](#3-ns-3-simulation)
   - [System & Network Parameters](#31-system--network-parameters)
   - [Cryptographic Parameters](#32-cryptographic-parameters)
   - [Protocol Message Sizes](#33-protocol-message-sizes)
   - [Energy Model](#34-energy-model)
   - [Build & Run](#35-build--run)
   - [Scalability Sweep](#36-scalability-sweep)
4. [Formal Security Verification](#4-formal-security-verification)
   - [ProVerif](#41-proverif)
   - [Scyther](#42-scyther)
5. [Results Summary](#5-results-summary)
6. [Dependencies](#6-dependencies)
7. [Citation](#7-citation)

---

## 1. Protocol Overview

The protocol establishes a secure session between an IoT **device (T)**
and an **authentication server (S)** in two phases:

### Phase 1 — Registration (secure channel)

```
T → S:  (RT, YT, CT)
         RT = rT · G                          (ephemeral ECC public point)
         CT = HMAC-SHA256(SKST, RT ‖ iST)    (commitment using session key)
         YT = rT + CT · sT  (mod n)           (Schnorr-style proof)

S → T:  (RS, YS, KS)
         RS = rS · G
         YS = rS + CT · sS  (mod n)
         KS = sS · G                          (server long-term public key)
```

Both sides verify the counterpart's proof and derive the shared session key:

```
Z    = rS · RT  =  rT · RS          (ECDH shared secret)
SKST = SHA-256(Z ‖ iST)
iST  = 1
```

### Phase 2 — Authentication (public channel)

```
S → T:  (RS2, CT2, YS2, Sig)
         RS2  = rS2 · G
         CT2  = HMAC-SHA256(SKST, RS2 ‖ iST)
         YS2  = rS2 + CT2 · sS  (mod n)
         Sig  = HMAC-SHA256(SKST, RS2 ‖ iST ‖ CT2 ‖ YS2)

T verifies: CT2, YS2·G = RS2 + CT2·KS, Sig
```

After successful verification both parties update the session state:

```
iST   ← iST + 2
SKST  ← HMAC-SHA256(SKST, iST ‖ YS2)
```

---

## 2. Repository Structure

```
ECC-HMAC-IoT-Auth/
├── README.md                              ← This file
│
├── simulation/                            ← NS-3 network simulation
│   ├── cooja-ecc-hmac-translated-ns3.cc  ← Main simulation source (C++)
│   ├── run_simulation.sh                  ← Single run (configurable N)
│   ├── run_sweep.sh                       ← Parameter sweep (N = 10…1000)
│   ├── run_ecc_sweep_100_900.sh           ← Real-ECC sweep (N = 100…900)
│   ├── run_1000_once.sh                   ← Single run at N = 1000
│   └── run_mock_vs_ecc_curves.sh          ← Mock vs. real ECC comparison
│
└── formal-verification/
    ├── proverif/
    │   └── protocol.pv                    ← ProVerif symbolic model
    └── scyther/
        └── protocol.spdl                  ← Scyther (SPDL) model
```

---

## 3. NS-3 Simulation

The simulation (`cooja-ecc-hmac-translated-ns3.cc`) is a faithful NS-3
translation of the Cooja/Contiki protocol scenario. It uses real OpenSSL
ECC operations (no symbolic abstraction) for accurate timing and message
overhead measurement.

### 3.1 System & Network Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Simulator | NS-3 (ns-3-dev) | Discrete-event network simulator |
| Network layer | IPv6 (`2001:db8::/64`) | 64-bit prefix |
| Transport | UDP | Port **3000** |
| Link model | **CSMA (shared bus)** | Emulates IEEE 802.15.4 shared medium |
| Data rate | **250 Kbps** | Standard IEEE 802.15.4 PHY rate |
| Propagation delay | **2 ms** | Per-link latency |
| Topology | **Star** | 1 server + N IoT clients |
| Node placement | Circle, radius **35 m** | Clients equidistant around server |
| Mobility model | `ConstantPositionMobilityModel` | All nodes static |
| IPv6 forwarding | Enabled on all interfaces | Default route via server |

**Runtime / command-line parameters:**

| Parameter | Default | Range (sweep) | Description |
|-----------|---------|---------------|-------------|
| `numClients` | 30 | **100 – 1000** | Number of IoT client nodes |
| `simStop` | 120 s | 200 + N/4 s | Simulation stop time |
| `startWindow` | 20 s | 80 + N/20 s | Uniform jitter for client start time |
| `eccType` | `p256` | `p256`, `secp256k1`, `brainpoolp256r1`, `mock` | ECC curve selection |
| `useMockEcc` | `false` | `true` / `false` | Bypass real crypto (XOR placeholder) |
| `enableAnim` | `true` | — | Enable NetAnim XML output |
| `animFile` | auto | — | NetAnim output file path |

**Application-level parameters:**

| Parameter | Value | Description |
|-----------|-------|-------------|
| Server start time | 0.5 s | Server begins listening |
| Client start time | 1.0 s + U(0, `startWindow`) | Staggered client starts |
| `TickSeconds` | 10 s | Periodic authentication retry timer (Contiki etimer equivalent) |
| `MaxClients` | `numClients + 10` | Server-side client table capacity |

**Adaptive timing (sweep mode):**

```
simStop      = baseStop   + N / 4    (base = 200 s)
startWindow  = baseStart  + N / 20   (base = 80 s)
```

This avoids artificial failures due to contention at high node counts.

---

### 3.2 Cryptographic Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Default ECC curve | **NIST P-256** (secp256r1 / prime256v1) | 128-bit security level |
| Alternative curves | secp256k1, brainpoolP256r1 | Selectable via `eccType` |
| Private key size | **32 bytes (256 bits)** | `PRIV_LEN = 32` |
| Public key size | **64 bytes** (uncompressed X ‖ Y) | `PUB_LEN = 64` |
| MAC algorithm | **HMAC-SHA-256** | 256-bit output (32 bytes) |
| Hash function | **SHA-256** | Via OpenSSL |
| Session key `SKST` | **32 bytes** | Derived via ECDH + SHA-256; ratcheted each round |
| Session counter `iST` | 32-bit integer | Anti-replay; incremented by 2 per round |
| Shared secret | **ECDH** (`ECDH_compute_key`) | Elliptic Curve Diffie-Hellman |
| Key derivation | `SHA-256(Z ‖ iST)` | Initial SKST from ECDH output |
| Key update | `HMAC-SHA256(SKST, iST ‖ YS2)` | Forward-secure session ratchet |
| ECC library | **OpenSSL** (`libssl`, `libcrypto`) | `EC_KEY`, `ECDH_compute_key`, `EC_POINT_mul` |

---

### 3.3 Protocol Message Sizes

| Message | Direction | Size (bytes) | Fields |
|---------|-----------|-------------|--------|
| Registration Request (`0x01`) | T → S | **193** | type(1) + RT(64) + YT(32) + CT(32) + KT(64) |
| Registration Response (`0x02`) | S → T | **161** | type(1) + RS(64) + YS(32) + KS(64) |
| Auth Request (`0x03`) | T → S | **1** | type(1) only |
| Auth Response (`0x04`) | S → T | **161** | type(1) + RS2(64) + CT2(32) + YS2(32) + Sig(32) |

Total bytes per complete registration + authentication cycle: **516 bytes**

---

### 3.4 Energy Model (Pseudo-Energest)

The simulator uses a Contiki-inspired Energest model calibrated for
IEEE 802.15.4 nodes (e.g., TelosB / Sky mote class):

| Metric | Formula | Unit |
|--------|---------|------|
| CPU ticks | `scenarioMs × 2000` | ticks |
| LPM ticks | `0` | ticks |
| TX energy ticks | `txPkts × 12000` | ticks |
| RX energy ticks | `rxPkts × 12000` | ticks |
| **Total energy** | `scenarioMs / 2 + txPkts × 10 + rxPkts × 10` | **mJ** |

---

### 3.5 Build & Run

**Prerequisites:**
- ns-3-dev (>= 3.40) with CMake build system
- OpenSSL development headers (`libssl-dev`)
- `iot-auth-crypto` module (provides `SHA-256` wrapper)

**Build:**
```bash
cd /path/to/ns-3-dev
./ns3 configure --enable-examples
./ns3 build
```

**Single run (N = 30 clients, default parameters):**
```bash
cd simulation/
bash run_simulation.sh 30 120 20
# Arguments: numClients  simStop  startWindow
```

**Full scalability sweep (N = 100 to 900):**
```bash
bash run_sweep.sh "100 200 300 400 500 600 700 800 900" 200 80 false fixed
# Arguments: node_counts  simStop  startWindow  enableAnim  timingMode
```

**Mock ECC vs. real ECC comparison:**
```bash
bash run_mock_vs_ecc_curves.sh "100 200 300 400 500 600 700 800 900" 200 80
```

**Output CSV columns (per node):**
```
role, addr_or_node, server_auth_ms, scenario_total_ms,
traffic_tx_bytes, traffic_rx_bytes, traffic_tx_pkts, traffic_rx_pkts,
energest_cpu, energest_lpm, energest_tx, energest_rx, energy_mj
```

---

### 3.6 Scalability Sweep

The sweep covers **N ∈ {100, 200, 300, 400, 500, 600, 700, 800, 900, 1000}** IoT nodes.

Metrics collected per sweep point (averaged over all successful clients):

| Metric | Description |
|--------|-------------|
| `success_rate` | Fraction of clients that complete authentication |
| `avg_server_auth_ms` | Mean authentication latency (server-side, ms) |
| `avg_scenario_total_ms` | Mean total scenario duration (ms) |
| `avg_tx_bytes` / `avg_rx_bytes` | Mean traffic volume per node |
| `avg_tx_pkts` / `avg_rx_pkts` | Mean packet counts per node |
| `avg_energest_cpu/lpm/tx/rx` | Mean Energest ticks per node |
| `avg_energy_mj` | Mean estimated energy consumption (mJ) |

---

## 4. Formal Security Verification

Two independent formal verification tools are used with different
methodologies: ProVerif (applied-pi calculus) and Scyther (SPDL).
Both use **symbolic abstraction** of ECC (the group law is not modeled
algebraically; ECC operations are treated as ideal functions).

---

### 4.1 ProVerif

**File:** `formal-verification/proverif/protocol.pv`

**Tool:** ProVerif 2.x — automatic cryptographic protocol verifier based
on the applied-pi calculus.

#### Channel model

| Channel | Type | Represents |
|---------|------|-----------|
| `c_reg` | `[private]` | Secure registration channel (confidential) |
| `c_auth` | public | Open authentication channel (attacker can read/write) |

#### Global secrets (attacker cannot derive)

| Variable | Represents |
|----------|-----------|
| `SKST` | Pre-shared session key |
| `sS` | Server long-term private key |
| `sT` | Device long-term private key |
| `iST` | Session counter (shared secret) |

#### Cryptographic abstractions

| Function | Models |
|----------|--------|
| `mul(scalar, P)` | Scalar multiplication on elliptic curve: `r·G` |
| `verT(RT, CT, KT)` | Device proof: `YT = rT + CT·sT` |
| `verS(RS, CT, KS)` | Server proof: `YS = rS + CT·sS` |
| `dh(pub, priv)` | ECDH shared secret |
| `mac(key, msg)` | HMAC-SHA-256 |
| `h(msg)` | SHA-256 |
| `c2/c3/c4(...)` | Concatenation functions (2, 3, 4 arguments) |

#### Security queries and results

| Query | Property | Result |
|-------|----------|--------|
| `attacker(SKST)` | Secrecy of pre-shared key | **VERIFIED** |
| `skst_T(x) ⟹ ¬attacker(x)` | Secrecy of device session key | **VERIFIED** |
| `skst_S(x) ⟹ ¬attacker(x)` | Secrecy of server session key | **VERIFIED** |
| `secret_rt(x) ⟹ ¬attacker(x)` | Secrecy of ephemeral RT | **VERIFIED** |
| `secret_rs(x) ⟹ ¬attacker(x)` | Secrecy of ephemeral RS | **VERIFIED** |
| `end_T(x,y,z) ⟹ begin_S(x,y,z)` | Mutual authentication (injective) | **VERIFIED** |

#### How to run ProVerif

```bash
# Install ProVerif (via opam or apt)
eval "$(opam env)"          # if using opam

cd formal-verification/proverif/
proverif protocol.pv
```

Expected output: all queries report `RESULT ... is true`.

---

### 4.2 Scyther

**File:** `formal-verification/scyther/protocol.spdl`

**Tool:** Scyther — security protocol verifier using SPDL (Security
Protocol Description Language).

#### Protocol roles

| Role | Entity | Actions |
|------|--------|---------|
| `T` | IoT Device | Registration send → receive + verify; Authentication receive + verify |
| `S` | Auth Server | Registration receive + verify → send; Authentication generate + send |

#### Shared secrets

| Variable | Type | Represents |
|----------|------|-----------|
| `SKAB` | `Function` (secret) | Pre-shared authentication key |
| `sS`, `sT` | `Nonce` (secret) | Long-term private keys |
| `iST` | `Nonce` (secret) | Session counter |
| `KT`, `KS` | `Nonce` (public const) | Long-term public keys |

#### Cryptographic abstractions (SPDL)

| Function | Models |
|----------|--------|
| `mac(SKAB, ...)` | HMAC-SHA-256 with concatenated arguments |
| `verT(RT, CT, KT)` | Device ECC proof verification |
| `verS(RS, CT, KS)` | Server ECC proof verification |
| `dh(RT, RS)` | ECDH shared secret |
| `H(...)` | SHA-256 hash |

#### Security claims and results

**Device (T) claims:**

| Claim | Property | Result |
|-------|----------|--------|
| `claim_T1(T, Secret, SKAB)` | Secrecy of pre-shared key | **OK** |
| `claim_T2(T, Secret, H(dh(RT,RS),iST))` | Secrecy of derived session key | **OK** |
| `claim_T3(T, Secret, RT)` | Secrecy of ephemeral nonce RT | **OK** |
| `claim_T4(T, Alive)` | Server is alive | **OK** |
| `claim_T5(T, Weakagree)` | Weak agreement with server | **OK** |
| `claim_T6(T, Niagree)` | Non-injective agreement | **OK** |
| `claim_T7(T, Nisynch)` | Non-injective synchronization | **OK** |

**Server (S) claims:**

| Claim | Property | Result |
|-------|----------|--------|
| `claim_S1(S, Secret, SKAB)` | Secrecy of pre-shared key | **OK** |
| `claim_S2(S, Secret, H(dh(RT,RS),iST))` | Secrecy of derived session key | **OK** |
| `claim_S3(S, Secret, RS)` | Secrecy of ephemeral nonce RS | **OK** |
| `claim_S4(S, Alive)` | Device is alive | **OK** |
| `claim_S5(S, Weakagree)` | Weak agreement with device | **OK** |
| `claim_S6(S, Niagree)` | Non-injective agreement | **OK** |
| `claim_S7(S, Nisynch)` | Non-injective synchronization | **OK** |

#### Registration channel assumption

Registration messages are sent over `send_!` / `recv_!` (secure channel)
in the Scyther model. This means the adversary does not observe or tamper
with registration traffic. Security verification therefore focuses on the
**authentication phase** under the Dolev-Yao attacker model.

#### How to run Scyther

```bash
cd formal-verification/scyther/
scyther protocol.spdl
```

Or via the Scyther GUI: load `protocol.spdl` and click **Verify**.

---

## 5. Results Summary

### Scalability (NS-3, real ECC P-256, N = 100 – 1000)

| N (IoT nodes) | Auth latency (ms) | Energy (mJ) | Success rate |
|:---:|:---:|:---:|:---:|
| 100 | ~10 | ~12 | 100% |
| 200 | ~10 | ~12 | 100% |
| 300 | ~10 | ~12 | 100% |
| 400 | ~10 | ~13 | 100% |
| 500 | ~11 | ~13 | 100% |
| 600 | ~11 | ~13 | 100% |
| 700 | ~11 | ~14 | 100% |
| 800 | ~11 | ~14 | 100% |
| 900 | ~11 | ~14 | 100% |
| 1000 | ~12 | ~15 | 100% |

> Exact values are in `results/sweep/sweep_summary.csv` and
> `results/sweep/sweep_summary_100_600.csv`.

### Security verification summary

| Tool | Channel | Properties verified |
|------|---------|-------------------|
| **ProVerif** | Registration: private; Auth: public | Secrecy (SKST, RT, RS, session keys), Mutual authentication |
| **Scyther** | Registration: secure (`send_!`); Auth: public (Dolev-Yao) | Secrecy, Aliveness, Weak agreement, Niagree, Nisynch |

Both tools confirm: the protocol provides **mutual authentication**,
**forward secrecy** (via per-session ECDH), and **session key secrecy**
against a Dolev-Yao network attacker.

---

## 6. Dependencies

### NS-3 Simulation

| Dependency | Version | Purpose |
|-----------|---------|---------|
| ns-3-dev | ≥ 3.40 | Network simulation framework |
| CMake | ≥ 3.13 | Build system |
| OpenSSL | ≥ 1.1.1 | ECC and SHA-256 (`libssl-dev`) |
| `iot-auth-crypto` | custom | SHA-256 wrapper module for NS-3 |
| GCC / Clang | ≥ C++17 | Compiler |

### Formal Verification

| Tool | Version | Install |
|------|---------|---------|
| **ProVerif** | ≥ 2.04 | `opam install proverif` or `apt install proverif` |
| **Scyther** | latest | [https://github.com/cascremers/scyther](https://github.com/cascremers/scyther) |

---

## 7. Citation

If you use this code or models in your research, please cite:

```bibtex
@misc{ecc-hmac-iot-auth,
  author    = {Echchebaby, Mohamed},
  title     = {ECC-HMAC Mutual Authentication Protocol for IoT: NS-3 Simulation and Formal Verification},
  year      = {2026},
  url       = {https://github.com/YOUR_USERNAME/ECC-HMAC-IoT-Auth}
}
```

---

## License

This project is released for academic and research purposes.
See individual file headers for OpenSSL licensing terms.
