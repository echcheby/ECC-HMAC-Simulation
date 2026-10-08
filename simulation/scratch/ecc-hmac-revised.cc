// ecc-hmac-revised.cc
//
// ns-3 network simulation of the REVISED ECC-HMAC mutual authentication
// protocol for IoT (registration R1-R5 + authentication A1-A8, see
// ecc_hmac_proto.h for the exact wire format and REPORT.md for the protocol
// text). Real P-256 / SHA-256 / HMAC-SHA-256 computations (OpenSSL) decide
// every accept/reject outcome; the *simulated* clock advances only by the
// modelled per-primitive processing delay (section 6 of the task spec), not
// by host CPU time, so results do not depend on machine speed.
//
// RADIO / TRANSPORT MODEL (documented simplification -- see REPORT.md):
//   IEEE 802.15.4 (lr-wpan), 2.4 GHz O-QPSK 250 kbit/s, unslotted CSMA/CA,
//   default MAC retries/backoff, star topology, LogDistance propagation
//   (all ns-3 LrWpanHelper defaults). Given the requirement to scale up to
//   N=1200 devices x 5 seeds x 11 values of N, we use the fallback transport
//   explicitly allowed by the task: raw lr-wpan MCPS-DATA (no 6LoWPAN/IPv6/
//   UDP, no MLME association), with short addresses pre-provisioned
//   (server = 0x0000, device i = short address i) and application-level
//   fragmentation of any message above 100 bytes into <=100-byte frames
//   (3-byte fragmentation header + up to 97 bytes of payload).
//
// Per-node energy is derived from the LrWpanPhy "TrxState" trace
// (BUSY_TX / BUSY_RX durations) plus the modelled processing time; see
// section 4 of the task spec for the exact formula.
#include "ecc_hmac_proto.h"

#include "ns3/core-module.h"
#include "ns3/lr-wpan-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("EccHmacRevised");

namespace
{

// ---------------------------------------------------------------------------
// Fragmentation constants (section 2 fallback: <=100 B application frames)
// ---------------------------------------------------------------------------
constexpr uint32_t FRAG_HDR_LEN = 3;  // totalLen(2B) + fragIdx(1B)
constexpr uint32_t FRAG_MAX_FRAME = 100;
constexpr uint32_t FRAG_CHUNK = FRAG_MAX_FRAME - FRAG_HDR_LEN; // 97

constexpr uint16_t PAN_ID = 0xCAFE;

// ---------------------------------------------------------------------------
// Global simulation state (single-threaded ns-3 event loop -- safe as-is)
// ---------------------------------------------------------------------------
ecchmac::EcCtx g_ctx;
ecchmac::ServerGlobal g_srv;
ecchmac::CryptoCosts g_devCost;
ecchmac::CryptoCosts g_srvCost;

uint32_t g_N = 0;
double g_stackDelayMs = 2.0;
double g_timeoutDelta = 2.0;  // seconds
uint32_t g_maxRetries = 5;
double g_lossProb = 0.0;
double g_authDelay = 10.0; // seconds
// Duty-cycling (section on realistic battery-life modelling): when true
// (default), a device's radio is put to sleep (macRxOnWhenIdle=false, i.e.
// PHY TRX_OFF whenever the MAC has nothing pending) during the two windows
// where it provably has nothing to receive -- the authDelay gap between
// registration and the auth trigger, and permanently after its one-shot
// session concludes -- and is woken (RxOnWhenIdle=true) right before it
// needs to listen. When false, the radio never sleeps (the original
// always-on model), kept as an explicit "stress test" scenario for
// comparison. The server is never duty-cycled (mains-powered coordinator).
bool g_dutyCycle = true;

Ptr<UniformRandomVariable> g_lossRv;
Ptr<UniformRandomVariable> g_regStartRv;

std::vector<ecchmac::DeviceState> g_dev;       // index 1..N
std::vector<ecchmac::ServerDeviceState> g_srvDev; // index 1..N

std::vector<Ptr<LrWpanNetDevice>> g_netDev; // index 0..N (0 = server)
uint16_t PanId()
{
    return PAN_ID;
}

struct Reasm
{
    uint16_t totalLen = 0;
    std::vector<uint8_t> buf;
    uint32_t received = 0;
    bool active = false;
};
std::vector<Reasm> g_devReasm;      // device-side, index 1..N (peer is always server)
std::vector<Reasm> g_srvReasmByDev; // server-side, index 1..N (per sending device)

std::vector<EventId> g_regTimeout;
std::vector<uint32_t> g_regRetries;
std::vector<EventId> g_authTimeout;
std::vector<uint32_t> g_authRetries;
std::vector<uint8_t> g_msduHandle; // per-node running MSDU handle counter
// When >=0, the MSDU handle of a device's own AUTH_M2 transmission that must
// actually complete (McpsDataConfirm) before that device's radio is put to
// sleep -- sleeping right after *queuing* the send (before CSMA/ACK finish)
// would kill the transmission itself. See DeviceOnAuthM1 / OnMcpsDataConfirm.
std::vector<int32_t> g_sleepAfterHandle;

// Diagnostic: global step-function trace of "how many devices are currently
// inside their own registration-or-authentication active window" (entered at
// regStart/triggerSent, exited at regDone/deviceAuthDone). Used only to
// measure the average number of *other* concurrently-active devices during
// a given device's own registration vs authentication window (REPORT.md
// §8's saturation-threshold and registration>authentication RX discussion)
// -- not used by the protocol or the main energy accounting.
std::vector<std::pair<double, int32_t>> g_activeTrace; // (time in ms, activeCount after event)
int32_t g_activeCount = 0;

void ActiveEnter()
{
    g_activeCount++;
    g_activeTrace.push_back({Simulator::Now().GetSeconds() * 1000.0, g_activeCount});
}

void ActiveExit()
{
    g_activeCount--;
    g_activeTrace.push_back({Simulator::Now().GetSeconds() * 1000.0, g_activeCount});
}

// Time-weighted average of (activeCount - 1) [excluding the querying device
// itself] over [startMs, endMs], using the global step-function trace.
double AvgActiveOthersInWindow(double startMs, double endMs)
{
    if (endMs <= startMs || g_activeTrace.empty())
        return 0.0;
    int32_t cur = 0;
    size_t i = 0;
    for (; i < g_activeTrace.size() && g_activeTrace[i].first <= startMs; i++)
        cur = g_activeTrace[i].second;
    double t = startMs;
    double area = 0.0;
    for (; i < g_activeTrace.size() && g_activeTrace[i].first < endMs; i++)
    {
        area += (double)(cur - 1) * (g_activeTrace[i].first - t);
        t = g_activeTrace[i].first;
        cur = g_activeTrace[i].second;
    }
    area += (double)(cur - 1) * (endMs - t);
    return area / (endMs - startMs);
}

// energy accounting (index 0..N)
std::vector<double> g_tCpuMs;
std::vector<double> g_tTxMs;
std::vector<double> g_tRxMs;
std::vector<double> g_tRxOnIdleMs;
std::vector<Time> g_lastChangeTime;
std::vector<LrWpanPhyEnumeration> g_lastState;

struct Metrics
{
    Time regStart = Time::Max();
    Time regDone = Time::Max();      // device finished processing REG_3
    Time triggerSent = Time::Max();  // device sent AUTH_TRIGGER
    Time deviceAuthDone = Time::Max(); // device sent AUTH_M2 (device's own work ends here)
    Time accepted = Time::Max();     // server accepted (used for the latency metric)
    bool registered = false;
    bool regFailed = false;
    bool authSuccess = false;
    bool authFailedFinal = false;
    uint32_t attemptsFinal = 0;
    uint32_t fallbackCount = 0;
    uint32_t replayRejected = 0;
};
std::vector<Metrics> g_metrics; // index 1..N

// Per-device (cpu, tx, rx) bucket snapshot, in ms, taken at a specific
// simulated instant -- used to compute *windowed* (per-phase) energy deltas
// instead of integrating over the whole (fixed, mostly-idle) simulation.
struct EBucket
{
    double cpu = 0.0;
    double tx = 0.0;
    double rx = 0.0;
};
std::vector<EBucket> g_snapRegStart;  // at REG_1 receipt (registration window start)
std::vector<EBucket> g_snapRegDone;   // at REG_3 processed (registration window end)
std::vector<EBucket> g_snapTrigSent;  // at AUTH_TRIGGER sent (authentication window start)
std::vector<EBucket> g_snapAuthDone;  // at AUTH_M2 sent (authentication window end)

EBucket SnapshotOf(uint32_t i)
{
    return {g_tCpuMs[i], g_tTxMs[i], g_tRxMs[i]};
}

uint64_t g_totalReplaysRejected = 0;
uint64_t g_totalFallbacks = 0;
uint64_t g_totalMacDrops = 0;
uint64_t g_totalRegFailures = 0;
uint64_t g_totalAuthFailures = 0;

// ---------------------------------------------------------------------------
// Short-address helpers -- device identity is the MAC source address, no
// separate ID field is ever carried in a protocol message (per spec).
// ---------------------------------------------------------------------------
Mac16Address MkAddr(uint32_t id)
{
    uint8_t b[2] = {(uint8_t)(id >> 8), (uint8_t)(id & 0xFF)};
    Mac16Address a;
    a.CopyFrom(b);
    return a;
}

uint32_t AddrToId(const Mac16Address& a)
{
    uint8_t b[2];
    a.CopyTo(b);
    return ((uint32_t)b[0] << 8) | b[1];
}

// ---------------------------------------------------------------------------
// Fragmented send, with optional message-level loss injection for
// AUTH_M1/AUTH_M2 (the optional loss experiment of section 5).
// ---------------------------------------------------------------------------
void SendFragments(uint32_t fromId, uint32_t toId, const std::vector<uint8_t>& payload)
{
    if (!payload.empty() &&
        (payload[0] == ecchmac::MSG_AUTH_M1 || payload[0] == ecchmac::MSG_AUTH_M2) &&
        g_lossProb > 0.0)
    {
        if (g_lossRv->GetValue(0.0, 1.0) < g_lossProb)
            return; // whole logical message lost in transit
    }

    Ptr<LrWpanNetDevice> senderDev = g_netDev[fromId];
    uint16_t totalLen = (uint16_t)payload.size();
    uint32_t nFrags = (totalLen + FRAG_CHUNK - 1) / FRAG_CHUNK;
    for (uint32_t f = 0; f < nFrags; f++)
    {
        uint32_t off = f * FRAG_CHUNK;
        uint32_t len = std::min(FRAG_CHUNK, totalLen - off);
        std::vector<uint8_t> frame;
        frame.reserve(FRAG_HDR_LEN + len);
        frame.push_back((uint8_t)(totalLen >> 8));
        frame.push_back((uint8_t)(totalLen & 0xFF));
        frame.push_back((uint8_t)f);
        frame.insert(frame.end(), payload.begin() + off, payload.begin() + off + len);

        Ptr<Packet> pkt = Create<Packet>(frame.data(), frame.size());
        McpsDataRequestParams params;
        params.m_srcAddrMode = SHORT_ADDR;
        params.m_dstAddrMode = SHORT_ADDR;
        params.m_dstPanId = PanId();
        params.m_dstAddr = MkAddr(toId);
        params.m_msduHandle = g_msduHandle[fromId]++;
        params.m_txOptions = TX_OPTION_ACK;
        senderDev->GetMac()->McpsDataRequest(params, pkt);
    }
}

// Feeds one received fragment into the reassembly buffer `r`. Returns true
// and fills `outMsg` once the full logical message has been received.
bool ReassembleFragment(Reasm& r, const uint8_t* data, uint32_t len, std::vector<uint8_t>& outMsg)
{
    if (len < FRAG_HDR_LEN)
        return false;
    uint16_t totalLen = ((uint16_t)data[0] << 8) | data[1];
    uint8_t fragIdx = data[2];
    if (fragIdx == 0)
    {
        r.active = true;
        r.totalLen = totalLen;
        r.buf.assign(totalLen, 0);
        r.received = 0;
    }
    if (!r.active || r.totalLen != totalLen)
        return false; // stale / out-of-order fragment for a message we are not assembling
    uint32_t off = (uint32_t)fragIdx * FRAG_CHUNK;
    uint32_t chunkLen = len - FRAG_HDR_LEN;
    if (off + chunkLen > r.buf.size())
        return false; // malformed, drop
    std::copy(data + FRAG_HDR_LEN, data + FRAG_HDR_LEN + chunkLen, r.buf.begin() + off);
    r.received += chunkLen;
    if (r.received >= r.totalLen)
    {
        outMsg = r.buf;
        r.active = false;
        r.received = 0;
        return true;
    }
    return false;
}

// Forward declarations of the protocol step handlers.
void DeviceProcessMessage(uint32_t devId, std::vector<uint8_t> msg);
void ServerProcessMessage(uint32_t devId, std::vector<uint8_t> msg);
void ServerSendReg1(uint32_t devId);
void ServerStartAuthAttempt(uint32_t devId);
void SleepDevice(uint32_t devId);

void OnDeviceRxCb(uint32_t devId, McpsDataIndicationParams params, Ptr<Packet> pkt)
{
    (void)params;
    uint32_t len = pkt->GetSize();
    std::vector<uint8_t> data(len);
    pkt->CopyData(data.data(), len);
    std::vector<uint8_t> full;
    if (!ReassembleFragment(g_devReasm[devId], data.data(), len, full))
        return;
    g_tCpuMs[devId] += g_stackDelayMs; // network-stack processing cost (section 2)
    Simulator::Schedule(MilliSeconds(g_stackDelayMs), &DeviceProcessMessage, devId, full);
}

void OnServerRxCb(McpsDataIndicationParams params, Ptr<Packet> pkt)
{
    uint32_t fromId = AddrToId(params.m_srcAddr);
    if (fromId == 0 || fromId > g_N)
        return;
    uint32_t len = pkt->GetSize();
    std::vector<uint8_t> data(len);
    pkt->CopyData(data.data(), len);
    std::vector<uint8_t> full;
    if (!ReassembleFragment(g_srvReasmByDev[fromId], data.data(), len, full))
        return;
    g_tCpuMs[0] += g_stackDelayMs;
    Simulator::Schedule(MilliSeconds(g_stackDelayMs), &ServerProcessMessage, fromId, full);
}

void OnMcpsDataConfirm(uint32_t nodeId, McpsDataConfirmParams params)
{
    if (params.m_status != IEEE_802_15_4_SUCCESS)
        g_totalMacDrops++;
    if (nodeId != 0 && g_sleepAfterHandle[nodeId] == (int32_t)params.m_msduHandle)
    {
        g_sleepAfterHandle[nodeId] = -1;
        // Only sleep if the AUTH_M2 transmission actually succeeded (reached
        // the server). If it failed (MAC-level drop after CSMA/ACK retries
        // exhausted -- common under heavy contention), the server will time
        // out and resend AUTH_M1; a device that went to sleep regardless of
        // outcome would never see that retry and be stranded permanently,
        // while the server keeps retransmitting into the void up to
        // maxRetries -- itself adding congestion that strands more devices.
        // Staying awake here lets the normal retry mechanism recover.
        if (params.m_status == IEEE_802_15_4_SUCCESS)
            SleepDevice(nodeId);
    }
}

void OnTrxState(uint32_t nodeId, Time time, LrWpanPhyEnumeration oldState, LrWpanPhyEnumeration newState)
{
    double dtMs = (time - g_lastChangeTime[nodeId]).GetSeconds() * 1000.0;
    switch (oldState)
    {
    case IEEE_802_15_4_PHY_BUSY_TX:
        g_tTxMs[nodeId] += dtMs;
        break;
    case IEEE_802_15_4_PHY_BUSY_RX:
        g_tRxMs[nodeId] += dtMs;
        break;
    case IEEE_802_15_4_PHY_RX_ON:
        g_tRxOnIdleMs[nodeId] += dtMs; // idle listening -- reported separately, not in main energy fig
        break;
    default:
        break;
    }
    g_lastChangeTime[nodeId] = time;
    g_lastState[nodeId] = newState;
}

// Puts a device's radio to sleep (macRxOnWhenIdle=false). Safe to call
// unconditionally, including while the PHY is mid-reception/-transmission:
// LrWpanMac::SetRxOnWhenIdle defers the actual PlmeSetTRXStateRequest until
// the MAC is next idle, and LrWpanPhy itself defers a TRX_OFF request while
// BUSY_TX/BUSY_RX until that activity completes (a pending request is
// simply overwritten by any later request, e.g. the wake-up call at the
// start of the next phase, so a stale deferred sleep can never override a
// more recent wake).
void SleepDevice(uint32_t devId)
{
    if (!g_dutyCycle)
        return;
    g_netDev[devId]->GetMac()->SetRxOnWhenIdle(false);
}

void FlushEnergyAtEnd()
{
    Time now = Simulator::Now();
    for (uint32_t i = 0; i <= g_N; i++)
    {
        double dtMs = (now - g_lastChangeTime[i]).GetSeconds() * 1000.0;
        switch (g_lastState[i])
        {
        case IEEE_802_15_4_PHY_BUSY_TX:
            g_tTxMs[i] += dtMs;
            break;
        case IEEE_802_15_4_PHY_BUSY_RX:
            g_tRxMs[i] += dtMs;
            break;
        case IEEE_802_15_4_PHY_RX_ON:
            g_tRxOnIdleMs[i] += dtMs;
            break;
        default:
            break;
        }
        g_lastChangeTime[i] = now;
    }
}

// ---------------------------------------------------------------------------
// Registration phase driver (R1..R5). Registration retries are server-driven
// only: S resends REG_1 if REG_2 has not arrived within Delta, up to
// maxRetries (documented simplification, see REPORT.md).
// ---------------------------------------------------------------------------
void ServerRegTimeout(uint32_t devId, uint32_t attemptNumber)
{
    if (g_regRetries[devId] != attemptNumber || g_srvDev[devId].registered)
        return;
    if (attemptNumber < g_maxRetries)
    {
        g_regRetries[devId] = attemptNumber + 1;
        ServerSendReg1(devId);
    }
    else
    {
        g_metrics[devId].regFailed = true;
        g_totalRegFailures++;
    }
}

void ServerSendReg1(uint32_t devId)
{
    ecchmac::StepOut r1 = ecchmac::ServerBuildReg1(g_ctx, g_srvDev[devId], g_srvCost);
    g_tCpuMs[0] += r1.costMs;
    uint32_t attemptNumber = g_regRetries[devId];
    Simulator::Schedule(MilliSeconds(r1.costMs), [devId, bytes = r1.bytes, attemptNumber]() {
        NS_ABORT_UNLESS(bytes.size() == ecchmac::LEN_REG_1);
        if (g_metrics[devId].regStart == Time::Max())
        {
            // Wake the device's radio (no-op if not duty-cycled) right
            // before S's REG_1 can arrive, then snapshot its energy buckets
            // as the t=0 baseline for the registration-phase window.
            if (g_dutyCycle)
                g_netDev[devId]->GetMac()->SetRxOnWhenIdle(true);
            g_snapRegStart[devId] = SnapshotOf(devId);
            g_metrics[devId].regStart = Simulator::Now();
            ActiveEnter();
        }
        SendFragments(0, devId, bytes);
        g_regTimeout[devId] =
            Simulator::Schedule(Seconds(g_timeoutDelta), &ServerRegTimeout, devId, attemptNumber);
    });
}

void DeviceOnReg1(uint32_t devId, const std::vector<uint8_t>& msg)
{
    // A stray duplicate/late REG_1 (MAC retransmission, or a server retry
    // that crossed with our REG_2) after registration already completed is
    // harmless to re-answer, but pointless -- skip it.
    if (g_dev[devId].registered)
        return;
    ecchmac::StepOut r2 = ecchmac::DeviceHandleReg1(g_ctx, g_dev[devId], msg, g_srv.KS.p, g_devCost);
    g_tCpuMs[devId] += r2.costMs;
    if (!r2.ok)
        return;
    Simulator::Schedule(MilliSeconds(r2.costMs), [devId, bytes = r2.bytes]() {
        NS_ABORT_UNLESS(bytes.size() == ecchmac::LEN_REG_2);
        SendFragments(devId, 0, bytes);
    });
}

void ServerOnReg2(uint32_t devId, const std::vector<uint8_t>& msg)
{
    // Guard against a MAC-layer retransmitted duplicate of a REG_2 we
    // already accepted (e.g. our REG_3's ACK was lost, or the frame itself
    // was retransmitted by LrWpanMac before an earlier copy's ACK arrived):
    // reprocessing would be wasteful and, for symmetry with DeviceOnReg3
    // below, is simply not needed once registration succeeded once.
    if (g_srvDev[devId].registered)
        return;
    ecchmac::StepOut r3 = ecchmac::ServerHandleReg2(g_ctx, g_srvDev[devId], msg, g_srv.sS.p, g_srvCost);
    g_tCpuMs[0] += r3.costMs;
    if (!r3.ok)
        return; // malformed / bad proof: ignore, let the registration timeout retry
    Simulator::Cancel(g_regTimeout[devId]);
    Simulator::Schedule(MilliSeconds(r3.costMs), [devId, bytes = r3.bytes]() {
        NS_ABORT_UNLESS(bytes.size() == ecchmac::LEN_REG_3);
        SendFragments(0, devId, bytes);
    });
}

void DeviceSendAuthTrigger(uint32_t devId);

void DeviceOnReg3(uint32_t devId, const std::vector<uint8_t>& msg)
{
    // Guard against a MAC-layer retransmitted duplicate of a REG_3 we
    // already consumed: DeviceHandleReg3 erases the ephemeral registration
    // state (RS_reg_pt etc.) on its first successful call, so reprocessing
    // a duplicate would dereference an already-cleared point and crash.
    if (g_dev[devId].registered)
        return;
    ecchmac::StepOut r4 = ecchmac::DeviceHandleReg3(g_ctx, g_dev[devId], msg, g_srv.KS.p, g_devCost);
    g_tCpuMs[devId] += r4.costMs;
    if (!r4.ok)
        return;
    Simulator::Schedule(MilliSeconds(r4.costMs), [devId]() {
        g_metrics[devId].registered = true;
        g_metrics[devId].regDone = Simulator::Now();
        g_snapRegDone[devId] = SnapshotOf(devId);
        ActiveExit();
        // Deliberately NOT sleeping here (only after the full session ends,
        // see DeviceOnAuthM1): an extra sleep/wake cycle across the
        // authDelay gap was found empirically to add enough radio-turnaround
        // and CSMA-interaction overhead to trigger a congestion collapse
        // under heavy contention (N>=900) -- see REPORT.md. One sleep/wake
        // pair per device (registration start -> post-session) still removes
        // the dominant idle-tail cost with none of that risk.
        Simulator::Schedule(Seconds(g_authDelay), &DeviceSendAuthTrigger, devId);
    });
}

// ---------------------------------------------------------------------------
// Authentication phase driver (A1..A8, server-driven retries per spec)
// ---------------------------------------------------------------------------
void DeviceSendAuthTrigger(uint32_t devId)
{
    // Defensive no-op in the current design (device is never put to sleep
    // between registration and the auth trigger -- see DeviceOnReg3), kept
    // in case that changes: ensures the radio is listening before AUTH_M1.
    if (g_dutyCycle)
        g_netDev[devId]->GetMac()->SetRxOnWhenIdle(true);
    g_snapTrigSent[devId] = SnapshotOf(devId);
    std::vector<uint8_t> msg{ecchmac::MSG_AUTH_TRIGGER};
    NS_ABORT_UNLESS(msg.size() == ecchmac::LEN_AUTH_TRIGGER);
    g_metrics[devId].triggerSent = Simulator::Now();
    ActiveEnter();
    SendFragments(devId, 0, msg);
}

void ServerAuthTimeout(uint32_t devId, uint32_t retryNum)
{
    if (g_authRetries[devId] != retryNum || g_metrics[devId].authSuccess)
        return;
    if (retryNum < g_maxRetries)
    {
        g_authRetries[devId] = retryNum + 1;
        ServerStartAuthAttempt(devId);
    }
    else
    {
        g_metrics[devId].authFailedFinal = true;
        g_totalAuthFailures++;
    }
}

void ServerStartAuthAttempt(uint32_t devId)
{
    ecchmac::StepOut m1 = ecchmac::ServerBuildAuthM1(g_ctx, g_srvDev[devId], g_srv.sS.p, g_srvCost);
    g_tCpuMs[0] += m1.costMs;
    uint32_t retryNum = g_authRetries[devId];
    Simulator::Schedule(MilliSeconds(m1.costMs), [devId, bytes = m1.bytes, retryNum]() {
        NS_ABORT_UNLESS(bytes.size() == ecchmac::LEN_AUTH_M1);
        SendFragments(0, devId, bytes);
        g_authTimeout[devId] =
            Simulator::Schedule(Seconds(g_timeoutDelta), &ServerAuthTimeout, devId, retryNum);
    });
}

void ServerOnTrigger(uint32_t devId, const std::vector<uint8_t>& msg)
{
    (void)msg;
    if (!g_srvDev[devId].registered || g_metrics[devId].authSuccess)
        return;
    g_authRetries[devId] = 0;
    ServerStartAuthAttempt(devId);
}

void DeviceOnAuthM1(uint32_t devId, const std::vector<uint8_t>& msg)
{
    ecchmac::AuthM1Result r = ecchmac::DeviceHandleAuthM1(g_ctx, g_dev[devId], msg, g_srv.KS.p, g_devCost);
    g_tCpuMs[devId] += r.costMs;
    if (r.isReplay)
    {
        g_metrics[devId].replayRejected++;
        g_totalReplaysRejected++;
    }
    if (!r.accepted)
        return; // rejected: no state change, no reply (matches spec A5)
    if (r.usedFallback)
    {
        g_metrics[devId].fallbackCount++;
        g_totalFallbacks++;
    }
    Simulator::Schedule(MilliSeconds(r.costMs), [devId, bytes = r.bytes]() {
        NS_ABORT_UNLESS(bytes.size() == ecchmac::LEN_AUTH_M2);
        // AUTH_M2 (66 B) always fits in exactly one fragment, so this is the
        // MSDU handle SendFragments is about to use for it.
        uint8_t handle = g_msduHandle[devId];
        SendFragments(devId, 0, bytes);
        g_metrics[devId].deviceAuthDone = Simulator::Now();
        g_snapAuthDone[devId] = SnapshotOf(devId);
        ActiveExit();
        // The device's own role ends here (spec A6: T already accepted
        // before sending M2, and never receives anything else in this
        // one-shot-per-device simulation) -- safe to sleep, but only once
        // this transmission actually completes (McpsDataConfirm): sleeping
        // immediately after merely *queuing* the send would kill the CSMA
        // transmission/ACK wait still in progress and drop AUTH_M2 itself.
        g_sleepAfterHandle[devId] = handle;
    });
}

void ServerOnAuthM2(uint32_t devId, const std::vector<uint8_t>& msg)
{
    // Guard against a MAC-layer retransmitted duplicate of an AUTH_M2 we
    // already accepted: ServerHandleAuthM2 erases sds.rS/wS on success, so a
    // duplicate arriving afterwards (no outstanding attempt, rS invalid)
    // would otherwise dereference a null scalar and crash.
    if (!g_srvDev[devId].rS.valid())
        return;
    ecchmac::AuthM2Result r = ecchmac::ServerHandleAuthM2(g_ctx, g_srvDev[devId], msg, g_srvCost);
    g_tCpuMs[0] += r.costMs;
    if (!r.accepted)
        return; // invalid tau: ignore, keep waiting for timeout/retry (spec A8)
    Simulator::Schedule(MilliSeconds(r.costMs), [devId]() {
        Simulator::Cancel(g_authTimeout[devId]);
        g_metrics[devId].accepted = Simulator::Now();
        g_metrics[devId].authSuccess = true;
        g_metrics[devId].attemptsFinal = g_srvDev[devId].attempts;
    });
}

void DeviceProcessMessage(uint32_t devId, std::vector<uint8_t> msg)
{
    if (msg.empty())
        return;
    switch (msg[0])
    {
    case ecchmac::MSG_REG_1:
        DeviceOnReg1(devId, msg);
        break;
    case ecchmac::MSG_REG_3:
        DeviceOnReg3(devId, msg);
        break;
    case ecchmac::MSG_AUTH_M1:
        DeviceOnAuthM1(devId, msg);
        break;
    default:
        break;
    }
}

void ServerProcessMessage(uint32_t devId, std::vector<uint8_t> msg)
{
    if (msg.empty())
        return;
    switch (msg[0])
    {
    case ecchmac::MSG_REG_2:
        ServerOnReg2(devId, msg);
        break;
    case ecchmac::MSG_AUTH_TRIGGER:
        ServerOnTrigger(devId, msg);
        break;
    case ecchmac::MSG_AUTH_M2:
        ServerOnAuthM2(devId, msg);
        break;
    default:
        break;
    }
}

} // namespace

int
main(int argc, char* argv[])
{
    uint32_t N = 100;
    uint32_t seed = 1;
    double stackDelayMs = 2.0;
    double radius = 10.0;
    double simTime = 300.0;
    double authDelay = 10.0;
    double regWindow = 50.0;
    // Delta must exceed the device's worst-case A5-A6 compute time (the
    // dominant term once devTpm reflects realistic MSP430-class hardware)
    // plus a network/congestion margin, or the server would retry before the
    // device could ever finish computing its reply. See REPORT.md for the
    // derivation: Delta = (4*devTpm + devTpa + 4*devTh + 3*devTmac +
    // stackDelay) + networkMargin ~= 4294 ms + 1500 ms ~= 5.8 s, rounded up.
    double timeoutDelta = 6.0;
    uint32_t maxRetries = 5;
    double lossProb = 0.0;
    bool dutyCycle = true;

    // Device EC scalar-multiplication cost (devTpm): 1072.8 ms, derived from
    // Seo, An, Kwon, Hu, "Montgomery Multiplication for Public Key
    // Cryptography on MSP430X," ACM TECS 19(3):20, 2020 (NIST P-256 scalar
    // multiplication with side-channel countermeasures, 8,582,338 cycles),
    // converted from their reported 16 MHz MSP430X clock to the Tmote Sky's
    // 8 MHz: 8,582,338 / 8,000,000 = 1072.8 ms. See REPORT.md for the
    // sensitivity bound derived from a second, independently-measured
    // source (Szczechowiak et al., NanoECC, EWSN 2008, Table 2: 0.72 s for a
    // real 160-bit point multiplication on actual Tmote Sky hardware).
    // devTpa/devTh/devTmac remain the task's original EXAMPLE placeholders
    // (not independently re-measured here).
    double devTpm = 1072.8, devTpa = 0.2, devTh = 0.1, devTmac = 0.2;
    double srvTpm = 1.0, srvTpa = 0.01, srvTh = 0.005, srvTmac = 0.01;

    double voltage = 3.0, iCpuMa = 1.8, iLpmMa = 0.0545, iTxMa = 17.4, iRxMa = 18.8;

    std::string outPrefix = "results/raw/run";

    CommandLine cmd;
    cmd.AddValue("N", "number of IoT devices", N);
    cmd.AddValue("seed", "RngSeedManager run number (1..5)", seed);
    cmd.AddValue("stackDelay", "per-message stack/processing delay (ms)", stackDelayMs);
    cmd.AddValue("radius", "star topology disc radius (m)", radius);
    cmd.AddValue("simTime", "simulation duration (s)", simTime);
    cmd.AddValue("authDelay", "delay after registration before AUTH_TRIGGER (s)", authDelay);
    cmd.AddValue("regWindow", "uniform random window for registration start (s)", regWindow);
    cmd.AddValue("timeoutDelta", "protocol retry timeout Delta (s)", timeoutDelta);
    cmd.AddValue("maxRetries", "max retries for registration and authentication", maxRetries);
    cmd.AddValue("lossProb", "app-level loss probability for AUTH_M1/AUTH_M2 (0..1)", lossProb);
    cmd.AddValue("dutyCycle",
                 "device radio sleeps (TRX_OFF) when nothing is expected (1, default) "
                 "vs always-on stress-test scenario (0)",
                 dutyCycle);
    cmd.AddValue("devTpm", "device EC scalar-mult cost (ms)", devTpm);
    cmd.AddValue("devTpa", "device EC point-add cost (ms)", devTpa);
    cmd.AddValue("devTh", "device SHA-256 cost (ms)", devTh);
    cmd.AddValue("devTmac", "device HMAC-SHA-256 cost (ms)", devTmac);
    cmd.AddValue("srvTpm", "server EC scalar-mult cost (ms)", srvTpm);
    cmd.AddValue("srvTpa", "server EC point-add cost (ms)", srvTpa);
    cmd.AddValue("srvTh", "server SHA-256 cost (ms)", srvTh);
    cmd.AddValue("srvTmac", "server HMAC-SHA-256 cost (ms)", srvTmac);
    cmd.AddValue("voltage", "supply voltage V", voltage);
    cmd.AddValue("iCpu", "CPU/processing current (mA)", iCpuMa);
    cmd.AddValue("iLpm", "low power mode current (mA)", iLpmMa);
    cmd.AddValue("iTx", "radio TX current (mA)", iTxMa);
    cmd.AddValue("iRx", "radio RX current (mA)", iRxMa);
    cmd.AddValue("outPrefix", "output CSV path prefix (no extension)", outPrefix);
    cmd.Parse(argc, argv);

    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(seed);

    g_N = N;
    g_stackDelayMs = stackDelayMs;
    g_timeoutDelta = timeoutDelta;
    g_maxRetries = maxRetries;
    g_lossProb = lossProb;
    g_authDelay = authDelay;
    g_dutyCycle = dutyCycle;
    g_devCost = {devTpm, devTpa, devTh, devTmac};
    g_srvCost = {srvTpm, srvTpa, srvTh, srvTmac};

    g_dev.resize(N + 1);
    g_srvDev.resize(N + 1);
    g_netDev.resize(N + 1);
    g_devReasm.resize(N + 1);
    g_srvReasmByDev.resize(N + 1);
    g_regTimeout.resize(N + 1);
    g_regRetries.assign(N + 1, 0);
    g_authTimeout.resize(N + 1);
    g_authRetries.assign(N + 1, 0);
    g_msduHandle.assign(N + 1, 0);
    g_sleepAfterHandle.assign(N + 1, -1);
    g_tCpuMs.assign(N + 1, 0.0);
    g_tTxMs.assign(N + 1, 0.0);
    g_tRxMs.assign(N + 1, 0.0);
    g_tRxOnIdleMs.assign(N + 1, 0.0);
    g_lastChangeTime.assign(N + 1, Seconds(0));
    g_lastState.assign(N + 1, IEEE_802_15_4_PHY_TRX_OFF);
    g_metrics.resize(N + 1);
    g_snapRegStart.resize(N + 1);
    g_snapRegDone.resize(N + 1);
    g_snapTrigSent.resize(N + 1);
    g_snapAuthDone.resize(N + 1);

    g_lossRv = CreateObject<UniformRandomVariable>();
    g_regStartRv = CreateObject<UniformRandomVariable>();

    // ---- Nodes, mobility, lr-wpan devices ---------------------------------
    NodeContainer allNodes;
    allNodes.Create(N + 1); // node 0 = server S

    MobilityHelper mobSrv;
    mobSrv.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobSrv.Install(allNodes.Get(0));
    allNodes.Get(0)->GetObject<ConstantPositionMobilityModel>()->SetPosition(Vector(0, 0, 0));

    NodeContainer devNodes;
    for (uint32_t i = 1; i <= N; i++)
        devNodes.Add(allNodes.Get(i));
    Ptr<UniformDiscPositionAllocator> disc = CreateObject<UniformDiscPositionAllocator>();
    disc->SetRho(radius);
    disc->SetX(0.0);
    disc->SetY(0.0);
    MobilityHelper mobDev;
    mobDev.SetPositionAllocator(disc);
    mobDev.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobDev.Install(devNodes);

    LrWpanHelper lrWpanHelper; // default channel: LogDistance loss + constant-speed delay
    NetDeviceContainer ndc = lrWpanHelper.Install(allNodes);

    for (uint32_t i = 0; i <= N; i++)
    {
        Ptr<LrWpanNetDevice> dev = DynamicCast<LrWpanNetDevice>(ndc.Get(i));
        g_netDev[i] = dev;
        Ptr<LrWpanMac> mac = dev->GetMac();
        mac->SetPanId(PanId());
        mac->SetShortAddress(MkAddr(i));
        if (i == 0)
            mac->SetMcpsDataIndicationCallback(MakeCallback(&OnServerRxCb));
        else
            mac->SetMcpsDataIndicationCallback(MakeBoundCallback(&OnDeviceRxCb, i));
        mac->SetMcpsDataConfirmCallback(MakeBoundCallback(&OnMcpsDataConfirm, i));
        dev->GetPhy()->TraceConnectWithoutContext("TrxState", MakeBoundCallback(&OnTrxState, i));
        // Devices start asleep (radio TRX_OFF) until their scheduled
        // registration slot wakes them (see ServerSendReg1); the server (i=0)
        // is a mains-powered coordinator and always stays RxOnWhenIdle=true.
        if (i != 0 && g_dutyCycle)
            mac->SetRxOnWhenIdle(false);
    }

    // ---- Long-term key material (offline provisioning, section 3.1) -------
    g_srv.sS = ecchmac::RandScalar(g_ctx);
    g_srv.KS = ecchmac::PointMul(g_ctx, g_srv.sS.p, nullptr, nullptr);
    for (uint32_t i = 1; i <= N; i++)
    {
        ecchmac::LongTermKey k = ecchmac::GenLongTermKey(g_ctx);
        g_dev[i].id = i;
        g_dev[i].sT = k.priv;
        g_dev[i].KT = std::move(k.pub);
        g_srvDev[i].id = i;
        g_srvDev[i].KT = ecchmac::EcPtPtr(EC_POINT_dup(g_dev[i].KT.p, g_ctx.group));
    }

    // ---- Schedule registration start for every device (section 7) --------
    for (uint32_t i = 1; i <= N; i++)
    {
        double t = g_regStartRv->GetValue(0.0, regWindow);
        Simulator::Schedule(Seconds(t), &ServerSendReg1, i);
    }

    Simulator::Schedule(Seconds(simTime), &FlushEnergyAtEnd);
    Simulator::Stop(Seconds(simTime + 1.0));
    Simulator::Run();

    // ---- Aggregate metrics and write CSVs ----------------------------------
    uint32_t successCount = 0;
    uint32_t desyncCount = 0;
    std::vector<double> latencies, e2es;
    // Old, full-simTime-window energy (kept for the always-on "stress test"
    // comparison -- see REPORT.md). Integrates the *entire* simulation, so
    // it is dominated by however long the run happens to last, not by the
    // cost of one authentication.
    std::vector<double> fullEnergies, fullCpuEnergies, fullTxEnergies, fullRxEnergies, idleListen;
    // New, windowed per-phase energy: only the wall-clock span each device
    // actually spends doing registration / authentication work, excluding
    // the authDelay gap and the (mostly idle) simulation tail.
    std::vector<double> regEnergies, authEnergies, sessionEnergies;
    std::vector<double> sessionCpuEnergies, sessionTxEnergies, sessionRxEnergies;
    std::vector<double> regCpuEnergies, regTxEnergies, regRxEnergies;
    std::vector<double> authCpuEnergies, authTxEnergies, authRxEnergies;

    struct EnergyParts
    {
        double total = 0.0, cpu = 0.0, tx = 0.0, rx = 0.0;
    };
    auto windowedEnergy = [&](const EBucket& start, const EBucket& end, double windowSec) {
        double dCpu = std::max(0.0, end.cpu - start.cpu);
        double dTx = std::max(0.0, end.tx - start.tx);
        double dRx = std::max(0.0, end.rx - start.rx);
        double windowMs = std::max(0.0, windowSec) * 1000.0;
        double dLpm = std::max(0.0, windowMs - dCpu - dTx - dRx);
        EnergyParts r;
        r.cpu = voltage * iCpuMa * (dCpu / 1000.0);
        r.tx = voltage * iTxMa * (dTx / 1000.0);
        r.rx = voltage * iRxMa * (dRx / 1000.0);
        r.total = r.cpu + r.tx + r.rx + voltage * iLpmMa * (dLpm / 1000.0);
        return r;
    };

    std::ofstream perNode(outPrefix + "_pernode.csv");
    perNode << "N,seed,dutyCycle,devId,registered,authSuccess,attempts,latencyMs,e2eMs,"
               "fullEnergyMJ,fullCpuEnergyMJ,fullTxEnergyMJ,fullRxEnergyMJ,idleListeningMs,"
               "regEnergyMJ,regCpuEnergyMJ,regTxEnergyMJ,regRxEnergyMJ,"
               "authEnergyMJ,authCpuEnergyMJ,authTxEnergyMJ,authRxEnergyMJ,"
               "sessionEnergyMJ,regAvgConcurrentActive,authAvgConcurrentActive,"
               "fallbackUsed,replayRejected,desync\n";
    std::vector<double> regConcurrentActives, authConcurrentActives;
    std::vector<double> regWindowMses, authWindowMses;

    for (uint32_t i = 1; i <= N; i++)
    {
        const Metrics& m = g_metrics[i];
        double fullEnergyMJ =
            voltage *
            (iCpuMa * (g_tCpuMs[i] / 1000.0) + iLpmMa * ((simTime * 1000.0 - g_tCpuMs[i] - g_tTxMs[i] - g_tRxMs[i]) / 1000.0) +
             iTxMa * (g_tTxMs[i] / 1000.0) + iRxMa * (g_tRxMs[i] / 1000.0));
        double fullCpuEnergyMJ = voltage * iCpuMa * (g_tCpuMs[i] / 1000.0);
        double fullTxEnergyMJ = voltage * iTxMa * (g_tTxMs[i] / 1000.0);
        double fullRxEnergyMJ = voltage * iRxMa * (g_tRxMs[i] / 1000.0);

        bool desync = false;
        double latencyMs = -1.0, e2eMs = -1.0;
        double regEnergyMJ = -1.0, authEnergyMJ = -1.0, sessionEnergyMJ = -1.0;
        double regCpuMJ = -1.0, regTxMJ = -1.0, regRxMJ = -1.0;
        double authCpuMJ = -1.0, authTxMJ = -1.0, authRxMJ = -1.0;
        double regConcurrent = -1.0, authConcurrent = -1.0;
        double regWindowMs = -1.0, authWindowMs = -1.0;
        if (m.authSuccess)
        {
            successCount++;
            latencyMs = (m.accepted - m.triggerSent).GetSeconds() * 1000.0;
            e2eMs = (m.accepted - m.regStart).GetSeconds() * 1000.0;
            latencies.push_back(latencyMs);
            e2es.push_back(e2eMs);
            desync = (g_srvDev[i].ist != g_dev[i].istT);
            if (desync)
                desyncCount++;

            EnergyParts regE = windowedEnergy(g_snapRegStart[i], g_snapRegDone[i],
                                               (m.regDone - m.regStart).GetSeconds());
            EnergyParts authE = windowedEnergy(g_snapTrigSent[i], g_snapAuthDone[i],
                                                (m.deviceAuthDone - m.triggerSent).GetSeconds());
            regEnergyMJ = regE.total;
            authEnergyMJ = authE.total;
            sessionEnergyMJ = regE.total + authE.total;
            regCpuMJ = regE.cpu;
            regTxMJ = regE.tx;
            regRxMJ = regE.rx;
            authCpuMJ = authE.cpu;
            authTxMJ = authE.tx;
            authRxMJ = authE.rx;
            regEnergies.push_back(regEnergyMJ);
            authEnergies.push_back(authEnergyMJ);
            sessionEnergies.push_back(sessionEnergyMJ);
            sessionCpuEnergies.push_back(regE.cpu + authE.cpu);
            sessionTxEnergies.push_back(regE.tx + authE.tx);
            sessionRxEnergies.push_back(regE.rx + authE.rx);
            regCpuEnergies.push_back(regE.cpu);
            regTxEnergies.push_back(regE.tx);
            regRxEnergies.push_back(regE.rx);
            authCpuEnergies.push_back(authE.cpu);
            authTxEnergies.push_back(authE.tx);
            authRxEnergies.push_back(authE.rx);

            regConcurrent = AvgActiveOthersInWindow(m.regStart.GetSeconds() * 1000.0,
                                                     m.regDone.GetSeconds() * 1000.0);
            authConcurrent = AvgActiveOthersInWindow(m.triggerSent.GetSeconds() * 1000.0,
                                                      m.deviceAuthDone.GetSeconds() * 1000.0);
            regConcurrentActives.push_back(regConcurrent);
            authConcurrentActives.push_back(authConcurrent);
            regWindowMs = (m.regDone - m.regStart).GetSeconds() * 1000.0;
            authWindowMs = (m.deviceAuthDone - m.triggerSent).GetSeconds() * 1000.0;
            regWindowMses.push_back(regWindowMs);
            authWindowMses.push_back(authWindowMs);
        }
        fullEnergies.push_back(fullEnergyMJ);
        fullCpuEnergies.push_back(fullCpuEnergyMJ);
        fullTxEnergies.push_back(fullTxEnergyMJ);
        fullRxEnergies.push_back(fullRxEnergyMJ);
        idleListen.push_back(g_tRxOnIdleMs[i]);

        perNode << N << "," << seed << "," << (dutyCycle ? 1 : 0) << "," << i << ","
                << (m.registered ? 1 : 0) << "," << (m.authSuccess ? 1 : 0) << "," << m.attemptsFinal
                << "," << latencyMs << "," << e2eMs << "," << fullEnergyMJ << "," << fullCpuEnergyMJ << ","
                << fullTxEnergyMJ << "," << fullRxEnergyMJ << "," << g_tRxOnIdleMs[i] << "," << regEnergyMJ
                << "," << regCpuMJ << "," << regTxMJ << "," << regRxMJ << "," << authEnergyMJ << ","
                << authCpuMJ << "," << authTxMJ << "," << authRxMJ << "," << sessionEnergyMJ << ","
                << regConcurrent << "," << authConcurrent << "," << m.fallbackCount << ","
                << m.replayRejected << "," << (desync ? 1 : 0) << "\n";
    }
    perNode.close();

    auto mean = [](const std::vector<double>& v) {
        if (v.empty())
            return 0.0;
        double s = 0;
        for (double x : v)
            s += x;
        return s / v.size();
    };
    auto stddev = [&](const std::vector<double>& v, double mu) {
        if (v.size() < 2)
            return 0.0;
        double s = 0;
        for (double x : v)
            s += (x - mu) * (x - mu);
        return std::sqrt(s / (v.size() - 1));
    };

    double latMean = mean(latencies);
    double latStd = stddev(latencies, latMean);
    double e2eMean = mean(e2es);
    // Old full-simTime-window energy -- "stress test" scenario comparison.
    double fullEnergyMean = mean(fullEnergies);
    double fullCpuEnergyMean = mean(fullCpuEnergies);
    double fullTxEnergyMean = mean(fullTxEnergies);
    double fullRxEnergyMean = mean(fullRxEnergies);
    double idleListenMean = mean(idleListen);
    // New windowed per-phase energy -- the realistic "cost of one session"
    // metric, used as the primary energy figure (fig3/fig5/fig7).
    double regEnergyMean = mean(regEnergies);
    double authEnergyMean = mean(authEnergies);
    double sessionEnergyMean = mean(sessionEnergies);
    double sessionCpuMean = mean(sessionCpuEnergies);
    double sessionTxMean = mean(sessionTxEnergies);
    double sessionRxMean = mean(sessionRxEnergies);
    double regCpuMean = mean(regCpuEnergies);
    double regTxMean = mean(regTxEnergies);
    double regRxMean = mean(regRxEnergies);
    double authCpuMean = mean(authCpuEnergies);
    double authTxMean = mean(authTxEnergies);
    double authRxMean = mean(authRxEnergies);
    double regConcurrentMean = mean(regConcurrentActives);
    double authConcurrentMean = mean(authConcurrentActives);
    double regWindowMsMean = mean(regWindowMses);
    double authWindowMsMean = mean(authWindowMses);
    double radioShare =
        (sessionEnergyMean > 0.0) ? 100.0 * (sessionTxMean + sessionRxMean) / sessionEnergyMean : 0.0;
    double successRate = 100.0 * successCount / std::max<uint32_t>(N, 1);

    bool sizesOk = (ecchmac::LEN_REG_1 == 66 && ecchmac::LEN_REG_2 == 98 && ecchmac::LEN_REG_3 == 33 &&
                    ecchmac::LEN_AUTH_TRIGGER == 1 && ecchmac::LEN_AUTH_M1 == 134 && ecchmac::LEN_AUTH_M2 == 66 &&
                    ecchmac::TOTAL_SESSION_BYTES == 398);

    std::ofstream summary(outPrefix + "_summary.csv");
    summary << "N,seed,dutyCycle,radius,simTime,authLatencyMeanMs,authLatencyStdMs,successRatePct,e2eMeanMs,"
               "sessionEnergyMeanMJ,regEnergyMeanMJ,authEnergyMeanMJ,sessionCpuEnergyMeanMJ,"
               "sessionTxEnergyMeanMJ,sessionRxEnergyMeanMJ,regCpuEnergyMeanMJ,regTxEnergyMeanMJ,"
               "regRxEnergyMeanMJ,authCpuEnergyMeanMJ,authTxEnergyMeanMJ,authRxEnergyMeanMJ,radioSharePct,"
               "regAvgConcurrentActive,authAvgConcurrentActive,regWindowMsMean,authWindowMsMean,"
               "fullEnergyMeanMJ,fullCpuEnergyMeanMJ,fullTxEnergyMeanMJ,fullRxEnergyMeanMJ,idleListeningMeanMs,"
               "totalAttempts,totalFallbacks,totalReplaysRejected,totalMacDrops,"
               "desyncCount,regFailures,authFailures,messageSizesOk,totalSessionBytes\n";
    uint64_t totalAttempts = 0;
    for (uint32_t i = 1; i <= N; i++)
        totalAttempts += g_metrics[i].attemptsFinal;
    summary << N << "," << seed << "," << (dutyCycle ? 1 : 0) << "," << radius << "," << simTime << ","
            << latMean << "," << latStd << "," << successRate << "," << e2eMean << "," << sessionEnergyMean
            << "," << regEnergyMean << "," << authEnergyMean << "," << sessionCpuMean << "," << sessionTxMean
            << "," << sessionRxMean << "," << regCpuMean << "," << regTxMean << "," << regRxMean << ","
            << authCpuMean << "," << authTxMean << "," << authRxMean << "," << radioShare << ","
            << regConcurrentMean << "," << authConcurrentMean << "," << regWindowMsMean << ","
            << authWindowMsMean << ","
            << fullEnergyMean << "," << fullCpuEnergyMean
            << "," << fullTxEnergyMean << "," << fullRxEnergyMean << "," << idleListenMean << ","
            << totalAttempts << "," << g_totalFallbacks << "," << g_totalReplaysRejected << ","
            << g_totalMacDrops << "," << desyncCount << "," << g_totalRegFailures << ","
            << g_totalAuthFailures << "," << (sizesOk ? 1 : 0) << "," << ecchmac::TOTAL_SESSION_BYTES
            << "\n";
    summary.close();

    std::cout << "[ecc-hmac-revised] N=" << N << " seed=" << seed << " successRate=" << successRate
              << "% meanLatency=" << latMean << "ms desync=" << desyncCount << " regFail=" << g_totalRegFailures
              << " authFail=" << g_totalAuthFailures << " macDrops=" << g_totalMacDrops
              << " messageSizesOk=" << sizesOk << "\n";

    Simulator::Destroy();
    // Terminate immediately, skipping static/global destructors. Our global
    // EcCtx/BnPtr/EcPtPtr objects hold OpenSSL handles, and OpenSSL 1.1.1
    // registers its own atexit() cleanup the first time it is used; because
    // atexit handlers run LIFO, that cleanup can run *before* our C++ static
    // destructors and free state BN_free()/EC_POINT_free()/EC_GROUP_free()
    // still touch, crashing on process exit even though all results were
    // already computed and flushed to disk above. _Exit() sidesteps this
    // well-known interaction entirely (safe here: this is a short-lived,
    // one-shot CLI tool and the OS reclaims all memory on exit).
    std::cout.flush();
    std::_Exit(0);
}
