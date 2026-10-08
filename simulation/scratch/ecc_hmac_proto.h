// ecc_hmac_proto.h
//
// Pure C++/OpenSSL implementation of the REVISED ECC-HMAC IoT authentication
// protocol (registration + authentication state machines) and of the P-256 /
// SHA-256 / HMAC-SHA-256 primitives it relies on.
//
// This header has NO ns-3 dependency on purpose: it is included both by the
// ns-3 network simulation (scratch/ecc-hmac-revised.cc), which wraps every
// call with simulated processing delay, and by the standalone unit tests
// (scratch/ecc-hmac-tests.cc), which exercise the state machine directly
// without any network/timing model.
//
// Every "cost" parameter (CryptoCosts&) is added to as real primitive
// operations execute: one Tpm per EC scalar multiplication, one Tpa per EC
// point addition/subtraction, one Th per SHA-256, one Tmac per HMAC-SHA-256.
// Scalar-only modular arithmetic (e.g. Y = r + c*s mod q) is treated as free,
// consistent with the worked example in the task's cost table (see REPORT.md).
#pragma once

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace ecchmac {

using Bytes = std::vector<uint8_t>;

// ---------------------------------------------------------------------------
// Message type tags (section 3 of the spec)
// ---------------------------------------------------------------------------
enum MsgType : uint8_t
{
    MSG_REG_1 = 0x01,
    MSG_REG_2 = 0x02,
    MSG_REG_3 = 0x03,
    MSG_AUTH_TRIGGER = 0x04,
    MSG_AUTH_M1 = 0x05,
    MSG_AUTH_M2 = 0x06,
};

constexpr size_t POINT_LEN = 33; // compressed P-256 point
constexpr size_t SCALAR_LEN = 32;
constexpr size_t MAC_LEN = 32;
constexpr size_t IST_LEN = 4;

constexpr size_t LEN_REG_1 = 1 + POINT_LEN + SCALAR_LEN;                         // 66
constexpr size_t LEN_REG_2 = 1 + POINT_LEN + SCALAR_LEN + SCALAR_LEN;            // 98
constexpr size_t LEN_REG_3 = 1 + SCALAR_LEN;                                     // 33
constexpr size_t LEN_AUTH_TRIGGER = 1;                                           // 1
constexpr size_t LEN_AUTH_M1 =
    1 + IST_LEN + POINT_LEN + MAC_LEN + SCALAR_LEN + SCALAR_LEN; // 134
constexpr size_t LEN_AUTH_M2 = 1 + POINT_LEN + MAC_LEN;          // 66
constexpr size_t TOTAL_SESSION_BYTES =
    LEN_REG_1 + LEN_REG_2 + LEN_REG_3 + LEN_AUTH_TRIGGER + LEN_AUTH_M1 + LEN_AUTH_M2; // 398

// ---------------------------------------------------------------------------
// Crypto cost accounting (section 6). Unit costs are ms per primitive op.
// ---------------------------------------------------------------------------
struct CryptoCosts
{
    double Tpm = 0.0;  // EC scalar multiplication (incl. ECDH)
    double Tpa = 0.0;  // EC point addition / subtraction
    double Th = 0.0;   // SHA-256
    double Tmac = 0.0; // HMAC-SHA-256
};

// Running accumulator for a single processing step; passed by pointer so
// standalone unit tests can pass nullptr and ignore timing altogether.
struct CostAcc
{
    const CryptoCosts* unit = nullptr;
    double totalMs = 0.0;
    void Pm()
    {
        if (unit)
            totalMs += unit->Tpm;
    }
    void Pa()
    {
        if (unit)
            totalMs += unit->Tpa;
    }
    void H()
    {
        if (unit)
            totalMs += unit->Th;
    }
    void Mac()
    {
        if (unit)
            totalMs += unit->Tmac;
    }
};

// ---------------------------------------------------------------------------
// EC context: P-256 group, order, generator, BN_CTX scratch space.
// ---------------------------------------------------------------------------
class EcCtx
{
  public:
    EC_GROUP* group;
    BIGNUM* order;
    const EC_POINT* generator;
    BN_CTX* bnctx;

    EcCtx()
    {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!group)
            throw std::runtime_error("EC_GROUP_new_by_curve_name failed");
        order = BN_new();
        EC_GROUP_get_order(group, order, nullptr);
        generator = EC_GROUP_get0_generator(group);
        bnctx = BN_CTX_new();
    }
    ~EcCtx()
    {
        BN_free(order);
        BN_CTX_free(bnctx);
        EC_GROUP_free(group);
    }
    EcCtx(const EcCtx&) = delete;
    EcCtx& operator=(const EcCtx&) = delete;
};

// ---------------------------------------------------------------------------
// Small RAII wrappers so the protocol code below can use plain value
// semantics without leaking OpenSSL objects.
// ---------------------------------------------------------------------------
struct BnPtr
{
    BIGNUM* p = nullptr;
    BnPtr() = default;
    explicit BnPtr(BIGNUM* v) : p(v)
    {
    }
    BnPtr(const BnPtr& o)
    {
        p = o.p ? BN_dup(o.p) : nullptr;
    }
    BnPtr& operator=(const BnPtr& o)
    {
        if (this != &o)
        {
            BN_free(p);
            p = o.p ? BN_dup(o.p) : nullptr;
        }
        return *this;
    }
    BnPtr(BnPtr&& o) noexcept : p(o.p)
    {
        o.p = nullptr;
    }
    BnPtr& operator=(BnPtr&& o) noexcept
    {
        if (this != &o)
        {
            BN_free(p);
            p = o.p;
            o.p = nullptr;
        }
        return *this;
    }
    ~BnPtr()
    {
        BN_free(p);
    }
    bool valid() const
    {
        return p != nullptr;
    }
};

struct EcPtPtr
{
    EC_POINT* p = nullptr;
    EcPtPtr() = default;
    explicit EcPtPtr(EC_POINT* v) : p(v)
    {
    }
    EcPtPtr(const EcPtPtr&) = delete;
    EcPtPtr& operator=(const EcPtPtr&) = delete;
    EcPtPtr(EcPtPtr&& o) noexcept : p(o.p)
    {
        o.p = nullptr;
    }
    EcPtPtr& operator=(EcPtPtr&& o) noexcept
    {
        if (this != &o)
        {
            if (p)
                EC_POINT_free(p);
            p = o.p;
            o.p = nullptr;
        }
        return *this;
    }
    ~EcPtPtr()
    {
        if (p)
            EC_POINT_free(p);
    }
    bool valid() const
    {
        return p != nullptr;
    }
};

// ---------------------------------------------------------------------------
// Primitive helpers
// ---------------------------------------------------------------------------
inline BnPtr RandScalar(EcCtx& ctx)
{
    BIGNUM* r = BN_new();
    do
    {
        BN_rand_range(r, ctx.order);
    } while (BN_is_zero(r));
    return BnPtr(r);
}

inline Bytes ScalarToBytes(const BIGNUM* s)
{
    Bytes out(SCALAR_LEN, 0);
    BN_bn2binpad(s, out.data(), (int)SCALAR_LEN);
    return out;
}

inline BnPtr BytesToScalar(const uint8_t* b, size_t len)
{
    if (len != SCALAR_LEN)
        return BnPtr(nullptr);
    return BnPtr(BN_bin2bn(b, (int)SCALAR_LEN, nullptr));
}

// scalar * P  (P = generator if pt == nullptr)
inline EcPtPtr PointMul(EcCtx& ctx, const BIGNUM* scalar, const EC_POINT* pt, CostAcc* cost)
{
    EC_POINT* r = EC_POINT_new(ctx.group);
    if (pt == nullptr)
        EC_POINT_mul(ctx.group, r, scalar, nullptr, nullptr, ctx.bnctx);
    else
        EC_POINT_mul(ctx.group, r, nullptr, pt, scalar, ctx.bnctx);
    if (cost)
        cost->Pm();
    return EcPtPtr(r);
}

inline EcPtPtr PointAdd(EcCtx& ctx, const EC_POINT* a, const EC_POINT* b, CostAcc* cost)
{
    EC_POINT* r = EC_POINT_new(ctx.group);
    EC_POINT_add(ctx.group, r, a, b, ctx.bnctx);
    if (cost)
        cost->Pa();
    return EcPtPtr(r);
}

inline EcPtPtr PointSub(EcCtx& ctx, const EC_POINT* a, const EC_POINT* b, CostAcc* cost)
{
    EC_POINT* negB = EC_POINT_dup(b, ctx.group);
    EC_POINT_invert(ctx.group, negB, ctx.bnctx);
    EC_POINT* r = EC_POINT_new(ctx.group);
    EC_POINT_add(ctx.group, r, a, negB, ctx.bnctx);
    EC_POINT_free(negB);
    if (cost)
        cost->Pa();
    return EcPtPtr(r);
}

inline bool PointsEqual(EcCtx& ctx, const EC_POINT* a, const EC_POINT* b)
{
    return EC_POINT_cmp(ctx.group, a, b, ctx.bnctx) == 0;
}

inline Bytes CompressPoint(EcCtx& ctx, const EC_POINT* pt)
{
    Bytes out(POINT_LEN);
    size_t n = EC_POINT_point2oct(ctx.group,
                                   pt,
                                   POINT_CONVERSION_COMPRESSED,
                                   out.data(),
                                   out.size(),
                                   ctx.bnctx);
    if (n != POINT_LEN)
        throw std::runtime_error("unexpected compressed point length");
    return out;
}

// Returns an invalid EcPtPtr (p == nullptr) if bytes do not decode to a valid
// point on the curve -- this implements the mandatory "RS is not a valid
// curve point" rejection check (A5-b).
inline EcPtPtr DecompressPoint(EcCtx& ctx, const uint8_t* b, size_t len)
{
    if (len != POINT_LEN)
        return EcPtPtr(nullptr);
    EC_POINT* pt = EC_POINT_new(ctx.group);
    if (EC_POINT_oct2point(ctx.group, pt, b, len, ctx.bnctx) != 1)
    {
        EC_POINT_free(pt);
        return EcPtPtr(nullptr);
    }
    if (EC_POINT_is_at_infinity(ctx.group, pt))
    {
        EC_POINT_free(pt);
        return EcPtPtr(nullptr);
    }
    return EcPtPtr(pt);
}

inline Bytes XCoord(EcCtx& ctx, const EC_POINT* pt)
{
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(ctx.group, pt, x, y, ctx.bnctx);
    Bytes out(SCALAR_LEN, 0);
    BN_bn2binpad(x, out.data(), (int)SCALAR_LEN);
    BN_free(x);
    BN_free(y);
    return out;
}

// Y = a + b*c mod q  -- pure scalar arithmetic, no EC operation, free of cost
// by design (see CryptoCosts comment at top of file).
inline BnPtr ScalarAddMul(EcCtx& ctx, const BIGNUM* a, const BIGNUM* b, const BIGNUM* c)
{
    BIGNUM* bc = BN_new();
    BN_mod_mul(bc, b, c, ctx.order, ctx.bnctx);
    BIGNUM* r = BN_new();
    BN_mod_add(r, a, bc, ctx.order, ctx.bnctx);
    BN_free(bc);
    return BnPtr(r);
}

inline Bytes Sha256(const Bytes& data, CostAcc* cost)
{
    Bytes out(32);
    SHA256(data.data(), data.size(), out.data());
    if (cost)
        cost->H();
    return out;
}

inline Bytes HmacSha256(const Bytes& key, const Bytes& data, CostAcc* cost)
{
    Bytes out(32);
    unsigned int outLen = 0;
    HMAC(EVP_sha256(), key.data(), (int)key.size(), data.data(), data.size(), out.data(), &outLen);
    if (cost)
        cost->Mac();
    return out;
}

inline Bytes U32BE(uint32_t v)
{
    return {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
}

inline uint32_t ReadU32BE(const uint8_t* b)
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

inline void Append(Bytes& out, const Bytes& in)
{
    out.insert(out.end(), in.begin(), in.end());
}

inline bool ConstTimeEq(const Bytes& a, const Bytes& b)
{
    if (a.size() != b.size())
        return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// ---------------------------------------------------------------------------
// Long-term key pair
// ---------------------------------------------------------------------------
struct LongTermKey
{
    BnPtr priv;
    EcPtPtr pub;
};

inline LongTermKey GenLongTermKey(EcCtx& ctx)
{
    LongTermKey k;
    k.priv = RandScalar(ctx);
    k.pub = PointMul(ctx, k.priv.p, nullptr, nullptr); // key generation itself is offline/free
    return k;
}

// ---------------------------------------------------------------------------
// Device (T) state -- section 3.1/3.2
// ---------------------------------------------------------------------------
struct DeviceState
{
    uint32_t id = 0;
    BnPtr sT;
    EcPtPtr KT;

    // registration ephemeral (kept only across R1 -> R3)
    BnPtr rT_reg;
    EcPtPtr RS_reg_pt;
    BnPtr CT_reg; // T's own random challenge sent in REG_2, needed to check REG_3

    bool registered = false;
    Bytes currentKey;
    Bytes prevKey;
    bool hasPrevKey = false;
    uint32_t istT = 0;
};

// ---------------------------------------------------------------------------
// Per-device state kept at the server (S) -- section 3.1/3.2
// ---------------------------------------------------------------------------
struct ServerDeviceState
{
    uint32_t id = 0;
    EcPtPtr KT; // device long-term public key, pre-provisioned at S

    // registration ephemeral
    BnPtr rS_reg;
    BnPtr CS_reg_sent;
    EcPtPtr RS_reg_pt;

    bool registered = false;
    Bytes SK;
    uint32_t ist = 0;

    // authentication ephemeral (current outstanding attempt)
    BnPtr rS;
    BnPtr wS;
    EcPtPtr RS_pt;
    uint32_t attempts = 0;
};

struct ServerGlobal
{
    BnPtr sS;
    EcPtPtr KS;
};

// ---------------------------------------------------------------------------
// Registration phase (R1..R5)
// ---------------------------------------------------------------------------
struct StepOut
{
    Bytes bytes;   // message to send (empty if none)
    double costMs; // modelled processing delay for this step
    bool ok;       // whether the step succeeded (checks passed)
};

// S -> T : REG_1
inline StepOut ServerBuildReg1(EcCtx& ctx, ServerDeviceState& sds, const CryptoCosts& cost)
{
    CostAcc acc{&cost};
    sds.rS_reg = RandScalar(ctx);
    EcPtPtr RS = PointMul(ctx, sds.rS_reg.p, nullptr, &acc);
    sds.RS_reg_pt = EcPtPtr(EC_POINT_dup(RS.p, ctx.group));
    sds.CS_reg_sent = RandScalar(ctx);

    Bytes msg;
    msg.push_back(MSG_REG_1);
    Append(msg, CompressPoint(ctx, RS.p));
    Append(msg, ScalarToBytes(sds.CS_reg_sent.p));
    return {msg, acc.totalMs, true};
}

// T handles REG_1, returns REG_2 (or ok=false on malformed input)
inline StepOut DeviceHandleReg1(EcCtx& ctx,
                                 DeviceState& ds,
                                 const Bytes& msg,
                                 const EC_POINT* /*KS unused here*/,
                                 const CryptoCosts& cost)
{
    CostAcc acc{&cost};
    if (msg.size() != LEN_REG_1 || msg[0] != MSG_REG_1)
        return {{}, 0.0, false};
    EcPtPtr RS = DecompressPoint(ctx, &msg[1], POINT_LEN);
    BnPtr CS = BytesToScalar(&msg[1 + POINT_LEN], SCALAR_LEN);
    if (!RS.valid() || !CS.valid())
        return {{}, 0.0, false};

    ds.rT_reg = RandScalar(ctx);
    EcPtPtr RT = PointMul(ctx, ds.rT_reg.p, nullptr, &acc); // Tpm
    BnPtr YT = ScalarAddMul(ctx, ds.rT_reg.p, CS.p, ds.sT.p); // free
    BnPtr CT = RandScalar(ctx);

    ds.RS_reg_pt = std::move(RS);
    ds.CT_reg = CT; // remember T's own challenge for the REG_3 check

    Bytes out;
    out.push_back(MSG_REG_2);
    Append(out, CompressPoint(ctx, RT.p));
    Append(out, ScalarToBytes(YT.p));
    Append(out, ScalarToBytes(CT.p));
    return {out, acc.totalMs, true};
}

// S handles REG_2, returns REG_3 (ok=false if the Schnorr-style proof fails)
inline StepOut ServerHandleReg2(EcCtx& ctx,
                                 ServerDeviceState& sds,
                                 const Bytes& msg,
                                 const BIGNUM* sS,
                                 const CryptoCosts& cost)
{
    CostAcc acc{&cost};
    if (msg.size() != LEN_REG_2 || msg[0] != MSG_REG_2)
        return {{}, 0.0, false};
    EcPtPtr RT = DecompressPoint(ctx, &msg[1], POINT_LEN);
    BnPtr YT = BytesToScalar(&msg[1 + POINT_LEN], SCALAR_LEN);
    BnPtr CT = BytesToScalar(&msg[1 + POINT_LEN + SCALAR_LEN], SCALAR_LEN);
    if (!RT.valid() || !YT.valid() || !CT.valid())
        return {{}, 0.0, false};

    // check YT.P == RT + CS.KT
    EcPtPtr lhs = PointMul(ctx, YT.p, nullptr, &acc);                    // Tpm
    EcPtPtr csKT = PointMul(ctx, sds.CS_reg_sent.p, sds.KT.p, &acc);     // Tpm
    EcPtPtr rhs = PointAdd(ctx, RT.p, csKT.p, &acc);                     // Tpa
    if (!PointsEqual(ctx, lhs.p, rhs.p))
        return {{}, acc.totalMs, false};

    BnPtr YS = ScalarAddMul(ctx, sds.rS_reg.p, CT.p, sS); // free

    // SK_ST = H(4 || x(rS.RT) || ist=0)
    EcPtPtr shared = PointMul(ctx, sds.rS_reg.p, RT.p, &acc); // Tpm (ECDH)
    Bytes in;
    in.push_back(0x04);
    Append(in, XCoord(ctx, shared.p));
    Append(in, U32BE(0));
    sds.SK = Sha256(in, &acc); // Th
    sds.ist = 0;
    sds.registered = true;

    Bytes out;
    out.push_back(MSG_REG_3);
    Append(out, ScalarToBytes(YS.p));
    return {out, acc.totalMs, true};
}

// T handles REG_3 -- no reply message, just local completion
inline StepOut DeviceHandleReg3(EcCtx& ctx,
                                 DeviceState& ds,
                                 const Bytes& msg,
                                 const EC_POINT* KS,
                                 const CryptoCosts& cost)
{
    CostAcc acc{&cost};
    if (msg.size() != LEN_REG_3 || msg[0] != MSG_REG_3)
        return {{}, 0.0, false};
    BnPtr YS = BytesToScalar(&msg[1], SCALAR_LEN);
    if (!YS.valid())
        return {{}, 0.0, false};

    EcPtPtr lhs = PointMul(ctx, YS.p, nullptr, &acc);                       // Tpm
    EcPtPtr ctKS = PointMul(ctx, ds.CT_reg.p, KS, &acc);                    // Tpm
    EcPtPtr rhs = PointAdd(ctx, ds.RS_reg_pt.p, ctKS.p, &acc);              // Tpa
    if (!PointsEqual(ctx, lhs.p, rhs.p))
        return {{}, acc.totalMs, false};

    EcPtPtr shared = PointMul(ctx, ds.rT_reg.p, ds.RS_reg_pt.p, &acc); // Tpm (ECDH)
    Bytes in;
    in.push_back(0x04);
    Append(in, XCoord(ctx, shared.p));
    Append(in, U32BE(0));
    ds.currentKey = Sha256(in, &acc); // Th
    ds.hasPrevKey = false;
    ds.istT = 0;
    ds.registered = true;

    // erase ephemeral registration secrets
    ds.rT_reg = BnPtr();
    ds.CT_reg = BnPtr();
    ds.RS_reg_pt = EcPtPtr();
    return {{}, acc.totalMs, true};
}

// ---------------------------------------------------------------------------
// Authentication phase (A1..A8)
// ---------------------------------------------------------------------------

// S: A1-A3, builds AUTH_M1. Always increments ist (every attempt, incl. retries).
inline StepOut ServerBuildAuthM1(EcCtx& ctx,
                                  ServerDeviceState& sds,
                                  const BIGNUM* sS,
                                  const CryptoCosts& cost)
{
    CostAcc acc{&cost};
    sds.ist += 1;
    sds.rS = RandScalar(ctx);
    sds.wS = RandScalar(ctx);
    EcPtPtr RS = PointMul(ctx, sds.rS.p, nullptr, &acc); // Tpm
    EcPtPtr WS = PointMul(ctx, sds.wS.p, nullptr, &acc); // Tpm
    sds.RS_pt = EcPtPtr(EC_POINT_dup(RS.p, ctx.group));

    Bytes istBytes = U32BE(sds.ist);
    Bytes ctIn;
    Append(ctIn, istBytes);
    Append(ctIn, CompressPoint(ctx, RS.p));
    Bytes CT = HmacSha256(sds.SK, ctIn, &acc); // Tmac

    Bytes hIn;
    hIn.push_back(0x00);
    Append(hIn, CompressPoint(ctx, WS.p));
    Append(hIn, istBytes);
    Append(hIn, CompressPoint(ctx, RS.p));
    Append(hIn, CT);
    Bytes c = Sha256(hIn, &acc); // Th
    BnPtr cScalar = BytesToScalar(c.data(), c.size());

    BnPtr YS = ScalarAddMul(ctx, sds.wS.p, cScalar.p, sS); // free

    Bytes out;
    out.push_back(MSG_AUTH_M1);
    Append(out, istBytes);
    Append(out, CompressPoint(ctx, RS.p));
    Append(out, CT);
    Append(out, c);
    Append(out, ScalarToBytes(YS.p));
    sds.attempts += 1;
    return {out, acc.totalMs, true};
}

struct AuthM1Result
{
    Bytes bytes;     // AUTH_M2 to send (empty if rejected)
    double costMs;
    bool accepted;
    bool isReplay;
    bool usedFallback;
    std::string rejectReason;
};

// T: A5-A6, handles AUTH_M1, produces AUTH_M2 (or rejects).
inline AuthM1Result DeviceHandleAuthM1(EcCtx& ctx,
                                        DeviceState& ds,
                                        const Bytes& msg,
                                        const EC_POINT* KS,
                                        const CryptoCosts& cost)
{
    CostAcc acc{&cost};
    AuthM1Result res{{}, 0.0, false, false, false, ""};
    if (msg.size() != LEN_AUTH_M1 || msg[0] != MSG_AUTH_M1)
    {
        res.rejectReason = "malformed";
        return res;
    }
    size_t off = 1;
    uint32_t ist = ReadU32BE(&msg[off]);
    off += IST_LEN;
    Bytes RSBytes(msg.begin() + off, msg.begin() + off + POINT_LEN);
    off += POINT_LEN;
    Bytes CT(msg.begin() + off, msg.begin() + off + MAC_LEN);
    off += MAC_LEN;
    BnPtr c = BytesToScalar(&msg[off], SCALAR_LEN);
    off += SCALAR_LEN;
    BnPtr YS = BytesToScalar(&msg[off], SCALAR_LEN);

    // (a) replay check -- counters never decrease
    if (ist <= ds.istT)
    {
        res.isReplay = true;
        res.rejectReason = "replay";
        res.costMs = acc.totalMs; // no crypto attempted
        return res;
    }

    // (b) RS must be a valid curve point
    EcPtPtr RS = DecompressPoint(ctx, RSBytes.data(), RSBytes.size());
    if (!RS.valid() || !c.valid() || !YS.valid())
    {
        res.rejectReason = "invalid_point";
        res.costMs = acc.totalMs;
        return res;
    }

    Bytes istBytes = U32BE(ist);

    // (c) check CT with current key, fallback to previous key on failure
    Bytes ctIn;
    Append(ctIn, istBytes);
    Append(ctIn, RSBytes);
    Bytes ctExpectedCur = HmacSha256(ds.currentKey, ctIn, &acc); // Tmac
    Bytes inputKey;
    bool usedFallback = false;
    if (ConstTimeEq(ctExpectedCur, CT))
    {
        inputKey = ds.currentKey;
    }
    else if (ds.hasPrevKey)
    {
        Bytes ctExpectedPrev = HmacSha256(ds.prevKey, ctIn, &acc); // Tmac (fallback)
        if (ConstTimeEq(ctExpectedPrev, CT))
        {
            inputKey = ds.prevKey;
            usedFallback = true;
        }
        else
        {
            res.rejectReason = "bad_CT";
            res.costMs = acc.totalMs;
            return res;
        }
    }
    else
    {
        res.rejectReason = "bad_CT_no_fallback";
        res.costMs = acc.totalMs;
        return res;
    }

    // (d) W' = YS.P - c.KS ; check c == H(0||W'||ist||RS||CT)
    EcPtPtr ysP = PointMul(ctx, YS.p, nullptr, &acc);   // Tpm
    EcPtPtr cKS = PointMul(ctx, c.p, KS, &acc);         // Tpm
    EcPtPtr Wp = PointSub(ctx, ysP.p, cKS.p, &acc);     // Tpa
    Bytes hIn;
    hIn.push_back(0x00);
    Append(hIn, CompressPoint(ctx, Wp.p));
    Append(hIn, istBytes);
    Append(hIn, RSBytes);
    Append(hIn, CT);
    Bytes cCheck = Sha256(hIn, &acc); // Th
    Bytes cBytes = ScalarToBytes(c.p);
    if (!ConstTimeEq(cCheck, cBytes))
    {
        res.rejectReason = "bad_schnorr";
        res.costMs = acc.totalMs;
        return res;
    }

    // All checks passed.
    ds.istT = ist;
    if (!usedFallback && ds.hasPrevKey)
        ds.hasPrevKey = false; // input key was current -> old previous key obsolete

    // A6: derive new key material
    BnPtr rT = RandScalar(ctx);
    EcPtPtr RT = PointMul(ctx, rT.p, nullptr, &acc);   // Tpm
    EcPtPtr Kdh = PointMul(ctx, rT.p, RS.p, &acc);     // Tpm (ECDH)
    Bytes RTBytes = CompressPoint(ctx, RT.p);

    Bytes in;
    Append(in, inputKey);
    Append(in, XCoord(ctx, Kdh.p));
    Append(in, istBytes);
    Append(in, RSBytes);
    Append(in, RTBytes);

    Bytes in1{0x01};
    Append(in1, in);
    Bytes SKp = Sha256(in1, &acc); // Th
    Bytes in2{0x02};
    Append(in2, in);
    Bytes Kc = Sha256(in2, &acc); // Th
    Bytes in3{0x03};
    Append(in3, in);
    Bytes SKsess = Sha256(in3, &acc); // Th
    (void)SKsess; // application session key, not otherwise used by this sim

    Bytes tauIn;
    Append(tauIn, istBytes);
    Append(tauIn, RSBytes);
    Append(tauIn, RTBytes);
    Bytes tau = HmacSha256(Kc, tauIn, &acc); // Tmac

    ds.prevKey = inputKey;
    ds.hasPrevKey = true;
    ds.currentKey = SKp;

    Bytes out;
    out.push_back(MSG_AUTH_M2);
    Append(out, RTBytes);
    Append(out, tau);

    res.bytes = out;
    res.accepted = true;
    res.usedFallback = usedFallback;
    res.costMs = acc.totalMs;
    return res;
}

struct AuthM2Result
{
    double costMs;
    bool accepted; // true = S accepts and rotates SK; false = ignore, keep waiting
};

// S: A8, handles AUTH_M2.
inline AuthM2Result ServerHandleAuthM2(EcCtx& ctx,
                                        ServerDeviceState& sds,
                                        const Bytes& msg,
                                        const CryptoCosts& cost)
{
    CostAcc acc{&cost};
    if (msg.size() != LEN_AUTH_M2 || msg[0] != MSG_AUTH_M2)
        return {acc.totalMs, false};
    EcPtPtr RT = DecompressPoint(ctx, &msg[1], POINT_LEN);
    Bytes tau(msg.begin() + 1 + POINT_LEN, msg.end());
    if (!RT.valid())
        return {acc.totalMs, false};

    EcPtPtr Kdh = PointMul(ctx, sds.rS.p, RT.p, &acc); // Tpm (ECDH)
    Bytes istBytes = U32BE(sds.ist);
    Bytes RSBytes = CompressPoint(ctx, sds.RS_pt.p);
    Bytes RTBytes = CompressPoint(ctx, RT.p);

    Bytes in;
    Append(in, sds.SK);
    Append(in, XCoord(ctx, Kdh.p));
    Append(in, istBytes);
    Append(in, RSBytes);
    Append(in, RTBytes);

    Bytes in1{0x01};
    Append(in1, in);
    Bytes SKp = Sha256(in1, &acc);
    Bytes in2{0x02};
    Append(in2, in);
    Bytes Kc = Sha256(in2, &acc);
    Bytes in3{0x03};
    Append(in3, in);
    Bytes SKsess = Sha256(in3, &acc);
    (void)SKsess;

    Bytes tauIn;
    Append(tauIn, istBytes);
    Append(tauIn, RSBytes);
    Append(tauIn, RTBytes);
    Bytes tauExpected = HmacSha256(Kc, tauIn, &acc);

    if (!ConstTimeEq(tauExpected, tau))
        return {acc.totalMs, false}; // invalid tau -> ignore, keep waiting

    sds.SK = SKp;
    sds.rS = BnPtr();
    sds.wS = BnPtr();
    return {acc.totalMs, true};
}

} // namespace ecchmac
