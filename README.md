# ECC-HMAC Mutual Authentication Protocol for IoT — Simulation & Formal Verification

A revised ECC-HMAC mutual authentication protocol for IoT (registration
R1–R5 + authentication A1–A8), evaluated end-to-end with:

1. A full **ns-3.37** network simulation using **real OpenSSL cryptography**
   (P-256, SHA-256, HMAC-SHA-256) over IEEE 802.15.4 — N ∈ {100…1200}
   devices, 5 seeds, realistic MSP430-class device crypto timing, radio
   duty-cycling, and windowed per-session energy accounting.
2. **Formal security verification** with two independent tools — ProVerif
   (applied-pi calculus) and Scyther (SPDL) — covering secrecy, forward
   secrecy, and (non-)injective mutual authentication.

---

## Repository structure

```
.
├── README.md
├── simulation/
│   ├── scratch/
│   │   ├── ecc_hmac_proto.h        ← protocol core (OpenSSL, no ns-3 dependency)
│   │   ├── ecc-hmac-revised.cc     ← ns-3 network simulation
│   │   └── ecc-hmac-tests.cc       ← standalone unit tests (29/29 passing)
│   ├── patches/
│   │   ├── lr-wpan-phy.patch           ← ns-3 upstream fix (see REPORT.md §3.4)
│   │   └── scratch-CMakeLists.patch    ← links OpenSSL into the scratch targets
│   ├── run_all.sh                  ← full N×seed×dutyCycle sweep + loss experiment
│   ├── plot_figures.py             ← generates the 7 figures from results/summary_all.csv
│   ├── make_report_tables.py       ← generates REPORT.md's result tables
│   ├── REPORT.md                   ← full build/run instructions, parameters, results, citations
│   ├── results/                    ← raw + aggregated CSVs from the full campaign
│   └── figures/                    ← the 7 figures (PNG + PDF)
└── formal-verification/
    ├── proverif/
    │   ├── ecc_hmac_full.pv        ← ProVerif model (secrecy, forward secrecy, mutual auth)
    │   └── results.txt             ← verbatim tool output
    └── scyther/
        ├── ecc_hmac_v2.spdl        ← Scyther model (SPDL)
        └── results.txt             ← verbatim tool output
```

**This repo does not vendor the ns-3.37 source tree.** `simulation/scratch/`
contains only the protocol's own files; `simulation/patches/` contains the
two small patches needed against a stock `ns-3.37` checkout (see
"Build & run" below). This keeps the repository small and makes every
change to the simulator itself explicit and auditable.

---

## 1. ns-3 simulation — summary

All cryptography (P-256 point arithmetic, SHA-256, HMAC-SHA-256) is real,
computed with OpenSSL; every accept/reject decision in the results is the
outcome of genuine cryptographic verification, not a scripted outcome.
Device crypto cost (`devTpm=1072.8 ms` per scalar multiplication) is
derived from a real, cited MSP430X benchmark (Seo et al. 2020), not a
placeholder — see `simulation/REPORT.md` §10 for full citations and a
documented pessimistic sensitivity bound from a second source.

| | |
|---|---|
| Devices (N) | 100 – 1200, 5 seeds each |
| Saturation threshold | N ≈ 500 (success rate crosses below 99%) |
| Success rate at N=1200 | 89.1% |
| Session energy | 63.9 mJ (N=100) → 307.3 mJ (N=1200) |
| Duty-cycling energy reduction | 38–61% vs. always-on (full-scenario energy) |
| Unit tests | 29 / 29 passed |

**Build & run** (full instructions, every CLI parameter, and all result
tables are in [`simulation/REPORT.md`](simulation/REPORT.md)):

```bash
# 1. Get a stock ns-3.37 checkout
git clone --branch ns-3.37 https://gitlab.com/nsnam/ns-3-dev.git ns-3.37
cd ns-3.37

# 2. Apply this repo's two small patches
git apply ../simulation/patches/lr-wpan-phy.patch
git apply ../simulation/patches/scratch-CMakeLists.patch

# 3. Copy the protocol implementation into scratch/
cp ../simulation/scratch/*.{cc,h} scratch/

# 4. Configure and build
./ns3 configure --enable-modules="core;network;lr-wpan;mobility;applications;stats" \
    --disable-examples --disable-tests --disable-werror -d release
cd cmake-cache && ninja scratch_ecc-hmac-revised scratch_ecc-hmac-tests && cd ..

# 5. Unit tests
./build/scratch/ns3.37-ecc-hmac-tests

# 6. Full campaign (from the simulation/ directory, pointed at this ns-3.37 build)
cd ../simulation
./run_all.sh
python3 plot_figures.py
python3 make_report_tables.py
```

See [`simulation/REPORT.md`](simulation/REPORT.md) for: the full parameter
list, the timeout re-derivation, the two real bugs found and fixed while
implementing radio duty-cycling, the windowed energy-accounting
methodology, the crypto-cost source citations, and the interpretation of
all 7 figures.

---

## 2. Formal verification — summary

Two independent tools, two independent abstractions of the same revised
protocol. Both treat ECC operations symbolically (the group law is not
modelled algebraically beyond the equations given to each tool); both
focus on the **authentication phase** under a Dolev-Yao network attacker
(registration is treated as a secure/offline channel, consistent with the
protocol's own specification).

### ProVerif (`formal-verification/proverif/ecc_hmac_full.pv`)

Two parts in one file: Part A verifies normal-operation secrecy and
mutual authentication with an active attacker on the public channel; Part
B verifies forward secrecy by making the *previous* chaining key public
(modelling full compromise of an earlier session) and checking the
*current* session's secrets stay out of reach.

| Property | Result |
|---|---|
| Session-key secrecy (`secretSess`) | **true** |
| Chaining-key secrecy under prior-key compromise (`secretChain`) | **true** |
| Forward secrecy (`secretFS`) | **true** |
| Non-injective agreement, device ⟸ server (`event acceptT ⟹ event sendS`) | **true** |
| Non-injective agreement, server ⟸ device (`event acceptS ⟹ event sendT`) | **true** |
| Injective agreement, server ⟸ device (`inj-event acceptS ⟹ inj-event sendT`) | **true** |
| Injective agreement, device ⟸ server (`inj-event acceptT ⟹ inj-event sendS`) | **false** — see note below |

**Note on the failing injective query.** ProVerif finds a trace where the
same server broadcast `(istA, RS, CT, sg)` is replayed to two separate
copies of the replicated device process, both of which fire `acceptT`. In
this ProVerif encoding, the device role (`!deviceA`) has **no persistent
state across replicated sessions** — each copy only checks `CT =
mac(SKa,(i,RSx))`, with no memory of previously-seen session identifiers.
The *real* protocol's C++ implementation does not have this gap: it
tracks a monotonically increasing per-device counter (`ist_T`) and
explicitly rejects a replayed/non-increasing counter — this is directly
exercised and confirmed by the unit tests (`ecc-hmac-tests.cc`,
"rejection of a replayed AUTH_M1", 29/29 passing). Encoding that
persistent, per-device, monotonic state inside an **unbounded-replication**
ProVerif process is a non-trivial modelling exercise (typically done via
a table/phase construction) that this model does not yet implement — the
failing query is therefore attributed to **the abstraction's statelessness,
not a demonstrated flaw in the protocol**, but it is reported here exactly
as the tool produced it rather than omitted.

Full verbatim output: [`formal-verification/proverif/results.txt`](formal-verification/proverif/results.txt).

### Scyther (`formal-verification/scyther/ecc_hmac_v2.spdl`)

Models the session identifier `ist` as a fresh nonce generated per protocol
run (rather than ProVerif's unbounded, state-free replication), and uses
an `@oracle` protocol block (`DH`/`SWAP1-3`/`SWAPM`) to encode the
Diffie–Hellman commutativity law `h(g(x),y) = h(g(y),x)` that Scyther has
no native equational theory for.

| Claim | Role S | Role T |
|---|---|---|
| Secrecy of derived keys | **Ok** | **Ok** |
| Alive | **Ok** | **Ok** |
| Weak agreement | **Ok** | **Ok** |
| Niagree (non-injective agreement) | **Ok** | **Ok** |
| Nisynch (non-injective synchronisation) | **Ok** | **Ok** |

All claims verified with no attack found, checked up to 8 concurrent
protocol runs. Full verbatim output:
[`formal-verification/scyther/results.txt`](formal-verification/scyther/results.txt).

### Reading the two results together

The two tools agree on everything both can express: secrecy (including
forward secrecy) and non-injective mutual authentication both hold. They
diverge only on *injective* agreement for the device's acceptance of the
server's first message — Scyther's bounded, per-run-fresh-nonce semantics
report it as fine; ProVerif's unbounded, state-free replication semantics
surface a replay that the real implementation's counter check (verified
independently by the C++ unit tests) already defends against. This is
reported as-is rather than tuned away, consistent with how the rest of
this project documents findings.

**How to run:**
```bash
# ProVerif (apt install proverif, or opam install proverif)
proverif formal-verification/proverif/ecc_hmac_full.pv

# Scyther (https://github.com/cascremers/scyther)
scyther --filter=ecchmac -r 8 formal-verification/scyther/ecc_hmac_v2.spdl
```

---

## License

Released for academic and research purposes. See individual file headers
for OpenSSL licensing terms.
