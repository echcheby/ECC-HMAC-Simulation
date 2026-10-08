// ecc-hmac-tests.cc
//
// Standalone unit tests for the REVISED ECC-HMAC protocol state machine
// implemented in ecc_hmac_proto.h. These tests exercise the real OpenSSL
// P-256 / SHA-256 / HMAC-SHA-256 logic directly (no ns-3 Simulator, no
// network) by shuttling the byte-level messages between an in-memory
// DeviceState and ServerDeviceState exactly as the wire protocol defines.
//
// Build & run (from the ns-3.37 root):
//   ./ns3 build scratch_ecc-hmac-tests
//   ./ns3 run scratch/ecc-hmac-tests
//
// Required by the task spec (section 3.3):
//   - honest run succeeds
//   - a modified CT, c, YS or tau is rejected
//   - a replayed AUTH_M1 is rejected (ist <= ist_T)
//   - after dropping AUTH_M2, the next session succeeds through the
//     fallback (previous) key
#include "ecc_hmac_proto.h"

#include <iostream>

using namespace ecchmac;

static int g_pass = 0;
static int g_fail = 0;

static void Check(bool cond, const std::string& name)
{
    if (cond)
    {
        std::cout << "[PASS] " << name << std::endl;
        g_pass++;
    }
    else
    {
        std::cout << "[FAIL] " << name << std::endl;
        g_fail++;
    }
}

// Runs the full registration handshake between a fresh device and the
// server's per-device state. Returns true on success.
static bool RunRegistration(EcCtx& ctx,
                             DeviceState& ds,
                             ServerDeviceState& sds,
                             const ServerGlobal& srv,
                             const CryptoCosts& devCost,
                             const CryptoCosts& srvCost)
{
    StepOut r1 = ServerBuildReg1(ctx, sds, srvCost);
    if (r1.bytes.size() != LEN_REG_1)
        return false;
    StepOut r2 = DeviceHandleReg1(ctx, ds, r1.bytes, srv.KS.p, devCost);
    if (!r2.ok || r2.bytes.size() != LEN_REG_2)
        return false;
    StepOut r3 = ServerHandleReg2(ctx, sds, r2.bytes, srv.sS.p, srvCost);
    if (!r3.ok || r3.bytes.size() != LEN_REG_3)
        return false;
    StepOut r4 = DeviceHandleReg3(ctx, ds, r3.bytes, srv.KS.p, devCost);
    return r4.ok;
}

// Message-size assertions (validation item in section 10).
static void TestMessageSizes()
{
    Check(LEN_REG_1 == 66, "message size REG_1 == 66 bytes");
    Check(LEN_REG_2 == 98, "message size REG_2 == 98 bytes");
    Check(LEN_REG_3 == 33, "message size REG_3 == 33 bytes");
    Check(LEN_AUTH_TRIGGER == 1, "message size AUTH_TRIGGER == 1 byte");
    Check(LEN_AUTH_M1 == 134, "message size AUTH_M1 == 134 bytes");
    Check(LEN_AUTH_M2 == 66, "message size AUTH_M2 == 66 bytes");
    Check(TOTAL_SESSION_BYTES == 398, "total session overhead == 398 bytes");
}

int main()
{
    EcCtx ctx;
    ServerGlobal srv;
    srv.sS = RandScalar(ctx);
    srv.KS = PointMul(ctx, srv.sS.p, nullptr, nullptr);

    CryptoCosts devCost{20.0, 0.2, 0.1, 0.2};
    CryptoCosts srvCost{1.0, 0.01, 0.005, 0.01};

    TestMessageSizes();

    // ---- Test 1: honest run succeeds ------------------------------------
    {
        LongTermKey devKey = GenLongTermKey(ctx);
        DeviceState ds;
        ds.id = 1;
        ds.sT = devKey.priv;
        ds.KT = std::move(devKey.pub);

        ServerDeviceState sds;
        sds.id = 1;
        sds.KT = EcPtPtr(EC_POINT_dup(ds.KT.p, ctx.group));

        bool regOk = RunRegistration(ctx, ds, sds, srv, devCost, srvCost);
        Check(regOk, "honest registration succeeds");
        Check(ds.currentKey == sds.SK && !ds.currentKey.empty(),
              "honest registration derives matching SK_ST on both sides");

        StepOut m1 = ServerBuildAuthM1(ctx, sds, srv.sS.p, srvCost);
        AuthM1Result m2res = DeviceHandleAuthM1(ctx, ds, m1.bytes, srv.KS.p, devCost);
        Check(m2res.accepted, "honest AUTH_M1 accepted by device");
        AuthM2Result acc = ServerHandleAuthM2(ctx, sds, m2res.bytes, srvCost);
        Check(acc.accepted, "honest AUTH_M2 accepted by server (session established)");
        Check(sds.ist == ds.istT, "server ist and device istT are in sync after honest auth");
    }

    // ---- Test 2: modified CT / c / YS / tau are rejected -----------------
    {
        LongTermKey devKey = GenLongTermKey(ctx);
        DeviceState ds;
        ds.id = 2;
        ds.sT = devKey.priv;
        ds.KT = std::move(devKey.pub);
        ServerDeviceState sds;
        sds.id = 2;
        sds.KT = EcPtPtr(EC_POINT_dup(ds.KT.p, ctx.group));
        RunRegistration(ctx, ds, sds, srv, devCost, srvCost);

        // Tamper with CT (offset 1 + IST_LEN + POINT_LEN)
        {
            StepOut m1 = ServerBuildAuthM1(ctx, sds, srv.sS.p, srvCost);
            Bytes tampered = m1.bytes;
            tampered[1 + IST_LEN + POINT_LEN] ^= 0xFF; // flip a byte inside CT
            AuthM1Result r = DeviceHandleAuthM1(ctx, ds, tampered, srv.KS.p, devCost);
            Check(!r.accepted && r.rejectReason.rfind("bad_CT", 0) == 0,
                  "AUTH_M1 with modified CT is rejected");
        }

        // Tamper with c
        {
            StepOut m1 = ServerBuildAuthM1(ctx, sds, srv.sS.p, srvCost);
            Bytes tampered = m1.bytes;
            size_t cOff = 1 + IST_LEN + POINT_LEN + MAC_LEN;
            tampered[cOff] ^= 0xFF;
            AuthM1Result r = DeviceHandleAuthM1(ctx, ds, tampered, srv.KS.p, devCost);
            Check(!r.accepted, "AUTH_M1 with modified c is rejected");
        }

        // Tamper with YS
        {
            StepOut m1 = ServerBuildAuthM1(ctx, sds, srv.sS.p, srvCost);
            Bytes tampered = m1.bytes;
            size_t ysOff = 1 + IST_LEN + POINT_LEN + MAC_LEN + SCALAR_LEN;
            tampered[ysOff] ^= 0xFF;
            AuthM1Result r = DeviceHandleAuthM1(ctx, ds, tampered, srv.KS.p, devCost);
            Check(!r.accepted, "AUTH_M1 with modified YS is rejected");
        }

        // Honest AUTH_M1 -> get a valid AUTH_M2, then tamper with tau
        {
            StepOut m1 = ServerBuildAuthM1(ctx, sds, srv.sS.p, srvCost);
            AuthM1Result m2res = DeviceHandleAuthM1(ctx, ds, m1.bytes, srv.KS.p, devCost);
            Check(m2res.accepted, "setup: honest AUTH_M1 accepted before tau-tamper test");
            Bytes tampered = m2res.bytes;
            tampered.back() ^= 0xFF; // flip last byte of tau
            AuthM2Result acc = ServerHandleAuthM2(ctx, sds, tampered, srvCost);
            Check(!acc.accepted, "AUTH_M2 with modified tau is rejected (server keeps waiting)");
            // recover with the honest M2 so state stays consistent for later tests
            AuthM2Result acc2 = ServerHandleAuthM2(ctx, sds, m2res.bytes, srvCost);
            Check(acc2.accepted, "server accepts the honest AUTH_M2 after rejecting the tampered one");
        }
    }

    // ---- Test 3: replayed AUTH_M1 is rejected (ist <= ist_T) -------------
    {
        LongTermKey devKey = GenLongTermKey(ctx);
        DeviceState ds;
        ds.id = 3;
        ds.sT = devKey.priv;
        ds.KT = std::move(devKey.pub);
        ServerDeviceState sds;
        sds.id = 3;
        sds.KT = EcPtPtr(EC_POINT_dup(ds.KT.p, ctx.group));
        RunRegistration(ctx, ds, sds, srv, devCost, srvCost);

        StepOut m1 = ServerBuildAuthM1(ctx, sds, srv.sS.p, srvCost);
        AuthM1Result first = DeviceHandleAuthM1(ctx, ds, m1.bytes, srv.KS.p, devCost);
        Check(first.accepted, "setup: first AUTH_M1 accepted for replay test");
        ServerHandleAuthM2(ctx, sds, first.bytes, srvCost);

        // Replay the exact same AUTH_M1 bytes again.
        AuthM1Result replay = DeviceHandleAuthM1(ctx, ds, m1.bytes, srv.KS.p, devCost);
        Check(!replay.accepted && replay.isReplay,
              "replayed AUTH_M1 (same ist) is rejected as a replay");
    }

    // ---- Test 4: after dropping AUTH_M2, next session succeeds via fallback
    {
        LongTermKey devKey = GenLongTermKey(ctx);
        DeviceState ds;
        ds.id = 4;
        ds.sT = devKey.priv;
        ds.KT = std::move(devKey.pub);
        ServerDeviceState sds;
        sds.id = 4;
        sds.KT = EcPtPtr(EC_POINT_dup(ds.KT.p, ctx.group));
        RunRegistration(ctx, ds, sds, srv, devCost, srvCost);

        Bytes keyAtRegistration = ds.currentKey;

        // Attempt 1: device processes AUTH_M1 and rotates its key, but the
        // resulting AUTH_M2 is dropped in transit -- the server never sees
        // it and therefore never rotates its own SK.
        StepOut m1a = ServerBuildAuthM1(ctx, sds, srv.sS.p, srvCost);
        AuthM1Result r1 = DeviceHandleAuthM1(ctx, ds, m1a.bytes, srv.KS.p, devCost);
        Check(r1.accepted, "setup: attempt 1 AUTH_M1 accepted by device (before drop)");
        Check(ds.currentKey != keyAtRegistration, "device rotated its current key after attempt 1");
        Check(ds.hasPrevKey && ds.prevKey == keyAtRegistration,
              "device kept the registration key as its previous (fallback) key");
        // AUTH_M2 dropped here: ServerHandleAuthM2 is deliberately NOT called.
        Check(sds.SK == keyAtRegistration, "server SK unchanged after the dropped AUTH_M2");

        // Server times out and retries: A1 increments ist again and issues a
        // fresh AUTH_M1 using its still-old SK (== device's previous key).
        StepOut m1b = ServerBuildAuthM1(ctx, sds, srv.sS.p, srvCost);
        Check(sds.ist == 2, "server ist advanced to 2 on retry");
        AuthM1Result r2 = DeviceHandleAuthM1(ctx, ds, m1b.bytes, srv.KS.p, devCost);
        Check(r2.accepted, "retry AUTH_M1 accepted by device");
        Check(r2.usedFallback, "retry AUTH_M1 verified via the fallback (previous) key");
        AuthM2Result acc = ServerHandleAuthM2(ctx, sds, r2.bytes, srvCost);
        Check(acc.accepted, "server accepts AUTH_M2 on the retry -> session re-synchronised");
        Check(sds.ist == ds.istT, "server and device counters back in sync after fallback recovery");
    }

    std::cout << "\n==== " << g_pass << " passed, " << g_fail << " failed ====\n";
    return g_fail == 0 ? 0 : 1;
}
