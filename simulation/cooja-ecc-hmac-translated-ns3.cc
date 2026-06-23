#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/iot-auth-crypto.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

namespace
{

constexpr uint16_t UDP_PORT = 3000;

constexpr uint8_t MSG_REG_REQ = 0x01;
constexpr uint8_t MSG_REG_RESP = 0x02;
constexpr uint8_t MSG_AUTH_REQ = 0x03;
constexpr uint8_t MSG_AUTH_RESP = 0x04;

constexpr uint32_t PRIV_LEN = 32;
constexpr uint32_t PUB_LEN = 64;
constexpr uint32_t AUTH_PAYLOAD_LEN = (PUB_LEN + PRIV_LEN + PRIV_LEN + PRIV_LEN);
constexpr uint32_t REG_REQ_LEN = (PUB_LEN + PRIV_LEN + PRIV_LEN + PUB_LEN);
constexpr uint32_t REG_RESP_LEN = (PUB_LEN + PRIV_LEN + PUB_LEN);

bool g_useMockEcc = false;
std::string g_eccType = "p256";

static int GetCurveNid()
{
    if (g_eccType == "secp256k1" || g_eccType == "k1")
    {
        return NID_secp256k1;
    }
    if (g_eccType == "brainpoolp256r1" || g_eccType == "bp256")
    {
        return NID_brainpoolP256r1;
    }
    return NID_X9_62_prime256v1;
}

using Priv32 = std::array<uint8_t, PRIV_LEN>;
using Pub64 = std::array<uint8_t, PUB_LEN>;

static const Priv32 k_sT = {0x20, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97,
                            0xa8, 0xb9, 0xca, 0xdb, 0xec, 0xfd, 0x0e, 0x1f,
                            0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97,
                            0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00, 0x11};

static const Priv32 k_sS = {0x10, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
                            0x9a, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x0f, 0x1e,
                            0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96};

static const Priv32 kSKSTInit = {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
                                 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
                                 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
                                 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0};

static void U32ToBe(uint32_t v, uint8_t out[4])
{
    out[0] = static_cast<uint8_t>(v >> 24);
    out[1] = static_cast<uint8_t>(v >> 16);
    out[2] = static_cast<uint8_t>(v >> 8);
    out[3] = static_cast<uint8_t>(v);
}

static bool CtEqual(const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t d = 0;
    for (size_t i = 0; i < len; ++i)
    {
        d |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return d == 0;
}

// Real ECC model over prime256v1 (secp256r1).
class MockEcc
{
  public:
    static bool ComputePublicKey(const Priv32& priv, Pub64& pub)
    {
                if (g_useMockEcc)
                {
                        std::memcpy(pub.data(), priv.data(), PRIV_LEN);
                        std::memcpy(pub.data() + PRIV_LEN, priv.data(), PRIV_LEN);
                        return true;
                }
        EC_GROUP* group = EC_GROUP_new_by_curve_name(GetCurveNid());
        if (!group)
        {
            return false;
        }

        BIGNUM* k = BN_bin2bn(priv.data(), PRIV_LEN, nullptr);
        EC_POINT* p = EC_POINT_new(group);
        bool ok = false;

        if (k && p && EC_POINT_mul(group, p, k, nullptr, nullptr, nullptr) == 1)
        {
            ok = PointToPub(group, p, pub);
        }

        EC_POINT_free(p);
        BN_free(k);
        EC_GROUP_free(group);
        return ok;
    }

    static bool MakeKey(Pub64& pub, Priv32& priv)
    {
        if (g_useMockEcc)
        {
            Ptr<UniformRandomVariable> rv = CreateObject<UniformRandomVariable>();
            for (uint32_t i = 0; i < PRIV_LEN; ++i)
            {
                priv[i] = static_cast<uint8_t>(rv->GetInteger(0, 255));
            }
            return ComputePublicKey(priv, pub);
        }
        if (!MakeKeypairForCurve(priv, pub))
        {
            return false;
        }
        return true;
    }

    static bool ScalarMulAdd(const Priv32& a, const Priv32& b, const Priv32& c, Priv32& out)
    {
        if (g_useMockEcc)
        {
            for (uint32_t i = 0; i < PRIV_LEN; ++i)
            {
                out[i] = static_cast<uint8_t>(a[i] ^ b[i] ^ c[i]);
            }
            return true;
        }
        EC_GROUP* group = EC_GROUP_new_by_curve_name(GetCurveNid());
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* order = BN_new();
        BIGNUM* A = BN_bin2bn(a.data(), PRIV_LEN, nullptr);
        BIGNUM* B = BN_bin2bn(b.data(), PRIV_LEN, nullptr);
        BIGNUM* C = BN_bin2bn(c.data(), PRIV_LEN, nullptr);
        BIGNUM* BC = BN_new();
        BIGNUM* R = BN_new();
        bool ok = false;

        if (group && ctx && order && A && B && C && BC && R &&
            EC_GROUP_get_order(group, order, ctx) == 1 &&
            BN_mod_mul(BC, B, C, order, ctx) == 1 &&
            BN_mod_add(R, A, BC, order, ctx) == 1 &&
            BN_bn2binpad(R, out.data(), PRIV_LEN) == static_cast<int>(PRIV_LEN))
        {
            ok = true;
        }

        BN_free(R);
        BN_free(BC);
        BN_free(C);
        BN_free(B);
        BN_free(A);
        BN_free(order);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return ok;
    }

    static bool PointMulGen(const Priv32& scalar, Pub64& out)
    {
        return ComputePublicKey(scalar, out);
    }

    static bool PointMulPub(const Pub64& pub, const Priv32& scalar, Pub64& out)
    {
        if (g_useMockEcc)
        {
            for (uint32_t i = 0; i < PRIV_LEN; ++i)
            {
                out[i] = static_cast<uint8_t>(pub[i] ^ scalar[i]);
                out[i + PRIV_LEN] = static_cast<uint8_t>(pub[i] ^ scalar[i]);
            }
            return true;
        }
        EC_GROUP* group = EC_GROUP_new_by_curve_name(GetCurveNid());
        EC_POINT* p = nullptr;
        EC_POINT* r = nullptr;
        BIGNUM* k = BN_bin2bn(scalar.data(), PRIV_LEN, nullptr);
        BN_CTX* ctx = BN_CTX_new();
        bool ok = false;

        if (group && k && ctx)
        {
            p = PubToPoint(group, pub);
            r = EC_POINT_new(group);
        }

        if (p && r && EC_POINT_mul(group, r, nullptr, p, k, ctx) == 1)
        {
            ok = PointToPub(group, r, out);
        }

        EC_POINT_free(r);
        EC_POINT_free(p);
        BN_free(k);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return ok;
    }

    static bool PointAdd(const Pub64& p1, const Pub64& p2, Pub64& out)
    {
        if (g_useMockEcc)
        {
            for (uint32_t i = 0; i < PUB_LEN; ++i)
            {
                out[i] = static_cast<uint8_t>(p1[i] ^ p2[i]);
            }
            return true;
        }
        EC_GROUP* group = EC_GROUP_new_by_curve_name(GetCurveNid());
        BN_CTX* ctx = BN_CTX_new();
        EC_POINT* a = nullptr;
        EC_POINT* b = nullptr;
        EC_POINT* r = nullptr;
        bool ok = false;

        if (group && ctx)
        {
            a = PubToPoint(group, p1);
            b = PubToPoint(group, p2);
            r = EC_POINT_new(group);
        }

        if (a && b && r && EC_POINT_add(group, r, a, b, ctx) == 1)
        {
            ok = PointToPub(group, r, out);
        }

        EC_POINT_free(r);
        EC_POINT_free(b);
        EC_POINT_free(a);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return ok;
    }

    static bool SharedSecret(const Pub64& pub, const Priv32& priv, Priv32& out)
    {
        if (g_useMockEcc)
        {
            for (uint32_t i = 0; i < PRIV_LEN; ++i)
            {
                out[i] = static_cast<uint8_t>(pub[i] ^ priv[i]);
            }
            return true;
        }
        if (!SharedSecretForCurve(pub, priv, out))
        {
            return false;
        }
        return true;
    }

  private:
    static EC_POINT* PubToPoint(const EC_GROUP* group, const Pub64& pub)
    {
        EC_POINT* p = EC_POINT_new(group);
        if (!p)
        {
            return nullptr;
        }

        uint8_t oct[65];
        oct[0] = 0x04;
        std::memcpy(oct + 1, pub.data(), PUB_LEN);
        if (EC_POINT_oct2point(group, p, oct, sizeof(oct), nullptr) != 1)
        {
            EC_POINT_free(p);
            return nullptr;
        }
        return p;
    }

    static bool PointToPub(const EC_GROUP* group, const EC_POINT* p, Pub64& pub)
    {
        uint8_t oct[65];
        size_t len = EC_POINT_point2oct(group, p, POINT_CONVERSION_UNCOMPRESSED, oct,
                                        sizeof(oct), nullptr);
        if (len != sizeof(oct) || oct[0] != 0x04)
        {
            return false;
        }
        std::memcpy(pub.data(), oct + 1, PUB_LEN);
        return true;
    }

    static bool MakeKeypairForCurve(Priv32& priv, Pub64& pub)
    {
        EC_KEY* key = EC_KEY_new_by_curve_name(GetCurveNid());
        if (!key)
        {
            return false;
        }

        bool ok = false;
        do
        {
            if (EC_KEY_generate_key(key) != 1)
            {
                break;
            }
            const BIGNUM* privBn = EC_KEY_get0_private_key(key);
            const EC_POINT* pubPoint = EC_KEY_get0_public_key(key);
            const EC_GROUP* group = EC_KEY_get0_group(key);
            if (!privBn || !pubPoint || !group)
            {
                break;
            }
            if (BN_bn2binpad(privBn, priv.data(), PRIV_LEN) != static_cast<int>(PRIV_LEN))
            {
                break;
            }
            if (!PointToPub(group, pubPoint, pub))
            {
                break;
            }
            ok = true;
        } while (false);

        EC_KEY_free(key);
        return ok;
    }

    static bool SharedSecretForCurve(const Pub64& peerPub, const Priv32& priv, Priv32& out)
    {
        EC_KEY* key = EC_KEY_new_by_curve_name(GetCurveNid());
        if (!key)
        {
            return false;
        }

        bool ok = false;
        BIGNUM* privBn = BN_bin2bn(priv.data(), PRIV_LEN, nullptr);
        if (!privBn)
        {
            EC_KEY_free(key);
            return false;
        }

        do
        {
            if (EC_KEY_set_private_key(key, privBn) != 1)
            {
                break;
            }
            const EC_GROUP* group = EC_KEY_get0_group(key);
            EC_POINT* point = PubToPoint(group, peerPub);
            if (!point)
            {
                break;
            }

            int secretLen = ECDH_compute_key(out.data(), out.size(), point, key, nullptr);
            EC_POINT_free(point);
            if (secretLen != static_cast<int>(out.size()))
            {
                break;
            }
            ok = true;
        } while (false);

        BN_free(privBn);
        EC_KEY_free(key);
        return ok;
    }
};

static bool PseudoHmacSha256(const uint8_t* key,
                             size_t keyLen,
                             const uint8_t* data,
                             size_t dataLen,
                             uint8_t out[PRIV_LEN])
{
    std::vector<uint8_t> blob;
    blob.reserve(keyLen + dataLen);
    blob.insert(blob.end(), key, key + keyLen);
    blob.insert(blob.end(), data, data + dataLen);
    return IotAuthCrypto::Sha256(blob.data(), blob.size(), out);
}

static bool Sha256(const uint8_t* data, size_t len, uint8_t out[PRIV_LEN])
{
    return IotAuthCrypto::Sha256(data, len, out);
}

struct MetricState
{
    uint64_t txBytes = 0;
    uint64_t rxBytes = 0;
    uint64_t txPkts = 0;
    uint64_t rxPkts = 0;
    bool scenarioStarted = false;
    Time scenarioStart = Seconds(0);
    bool authInflight = false;
    Time authStart = Seconds(0);
};

static void PrintCsvHeaderOnce(bool& printed)
{
    if (printed)
    {
        return;
    }
    std::cout << "CSV,role,addr_or_node,server_auth_ms,scenario_total_ms,traffic_tx_bytes,"
                 "traffic_rx_bytes,traffic_tx_pkts,traffic_rx_pkts,energest_cpu,energest_lpm,"
                 "energest_tx,energest_rx,energy_mj"
              << std::endl;
    printed = true;
}

static void BuildPseudoEnergest(const MetricState& st,
                                uint64_t scenarioMs,
                                uint64_t& cpu,
                                uint64_t& lpm,
                                uint64_t& tx,
                                uint64_t& rx,
                                uint64_t& energyMj)
{
    cpu = scenarioMs * 2000;
    lpm = 0;
    tx = st.txPkts * 12000;
    rx = st.rxPkts * 12000;
    energyMj = scenarioMs / 2 + st.txPkts * 10 + st.rxPkts * 10;
}

static std::string AddrToString(const Address& address)
{
    if (!Inet6SocketAddress::IsMatchingType(address))
    {
        return "unknown";
    }
    auto a6 = Inet6SocketAddress::ConvertFrom(address);
    std::ostringstream os;
    os << a6.GetIpv6();
    return os.str();
}

class CoojaTranslatedServerApp : public Application
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid =
            TypeId("ns3::CoojaTranslatedServerApp")
                .SetParent<Application>()
                .AddConstructor<CoojaTranslatedServerApp>()
                .AddAttribute("Port",
                              "UDP server port",
                              UintegerValue(UDP_PORT),
                              MakeUintegerAccessor(&CoojaTranslatedServerApp::m_port),
                              MakeUintegerChecker<uint16_t>())
                .AddAttribute("MaxClients",
                              "Maximum clients tracked",
                              UintegerValue(1000),
                              MakeUintegerAccessor(&CoojaTranslatedServerApp::m_maxClients),
                              MakeUintegerChecker<uint32_t>());
        return tid;
    }

  private:
    struct ClientState
    {
        bool inUse = false;
        bool registered = false;
        std::string key;
        uint32_t iST = 0;
        Priv32 skst = kSKSTInit;
        MetricState m;
    };

    void StartApplication() override
    {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), m_port));
        m_socket->SetRecvCallback(MakeCallback(&CoojaTranslatedServerApp::HandleRead, this));
        MockEcc::ComputePublicKey(k_sS, m_KS);
        PrintCsvHeaderOnce(m_csvHeaderPrinted);
    }

    void StopApplication() override
    {
        if (m_socket)
        {
            m_socket->Close();
            m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
        }
    }

    ClientState* FindOrAlloc(const Address& from)
    {
        std::string key = AddrToString(from);
        auto it = m_clients.find(key);
        if (it != m_clients.end())
        {
            return &it->second;
        }
        if (m_clients.size() >= m_maxClients)
        {
            return nullptr;
        }
        ClientState st;
        st.inUse = true;
        st.key = key;
        st.iST = 0;
        st.skst = kSKSTInit;
        auto r = m_clients.emplace(key, st);
        return &r.first->second;
    }

    void UpdateState(ClientState& st, const Priv32& YS)
    {
        uint8_t buf[4 + PRIV_LEN];
        uint8_t newKey[PRIV_LEN];
        st.iST += 2;
        U32ToBe(st.iST, buf);
        std::memcpy(buf + 4, YS.data(), PRIV_LEN);
        PseudoHmacSha256(st.skst.data(), PRIV_LEN, buf, sizeof(buf), newKey);
        std::memcpy(st.skst.data(), newKey, PRIV_LEN);
    }

    void DeriveSkst(ClientState& st, const Priv32& shared)
    {
        uint8_t buf[PRIV_LEN + 4];
        uint8_t istBe[4];
        U32ToBe(st.iST, istBe);
        std::memcpy(buf, shared.data(), PRIV_LEN);
        std::memcpy(buf + PRIV_LEN, istBe, 4);
        Sha256(buf, sizeof(buf), st.skst.data());
    }

    void HandleRegister(const Address& from, const uint8_t* payload, uint32_t len, uint32_t rxLen)
    {
        if (len != REG_REQ_LEN)
        {
            return;
        }

        ClientState* st = FindOrAlloc(from);
        if (!st)
        {
            return;
        }

        st->m.rxPkts += 1;
        st->m.rxBytes += rxLen;
        if (!st->m.scenarioStarted)
        {
            st->m.scenarioStarted = true;
            st->m.scenarioStart = Simulator::Now();
        }

        Pub64 RT;
        Priv32 YT;
        Priv32 CT;
        Pub64 KT;
        std::memcpy(RT.data(), payload, PUB_LEN);
        std::memcpy(YT.data(), payload + PUB_LEN, PRIV_LEN);
        std::memcpy(CT.data(), payload + PUB_LEN + PRIV_LEN, PRIV_LEN);
        std::memcpy(KT.data(), payload + PUB_LEN + PRIV_LEN + PRIV_LEN, PUB_LEN);

        Pub64 ysPoint;
        Pub64 ctKt;
        Pub64 rhs;
        MockEcc::PointMulGen(YT, ysPoint);
        MockEcc::PointMulPub(KT, CT, ctKt);
        MockEcc::PointAdd(RT, ctKt, rhs);
        if (!CtEqual(ysPoint.data(), rhs.data(), PUB_LEN))
        {
            return;
        }

        Pub64 RS;
        Priv32 rS;
        Priv32 YS;
        Priv32 shared;

        MockEcc::MakeKey(RS, rS);
        MockEcc::ScalarMulAdd(rS, CT, k_sS, YS);
        MockEcc::SharedSecret(RT, rS, shared);

        st->iST = 0;
        st->skst = kSKSTInit;
        DeriveSkst(*st, shared);
        st->iST = 1;
        st->registered = true;

        std::vector<uint8_t> resp(1 + REG_RESP_LEN, 0);
        resp[0] = MSG_REG_RESP;
        std::memcpy(resp.data() + 1, RS.data(), PUB_LEN);
        std::memcpy(resp.data() + 1 + PUB_LEN, YS.data(), PRIV_LEN);
        std::memcpy(resp.data() + 1 + PUB_LEN + PRIV_LEN, m_KS.data(), PUB_LEN);

        m_socket->SendTo(resp.data(), resp.size(), 0, from);
        st->m.txPkts += 1;
        st->m.txBytes += resp.size();
    }

    void HandleAuth(const Address& from, uint32_t rxLen)
    {
        std::string key = AddrToString(from);
        auto it = m_clients.find(key);
        if (it == m_clients.end() || !it->second.registered)
        {
            return;
        }
        ClientState& st = it->second;

        st.m.rxPkts += 1;
        st.m.rxBytes += rxLen;
        st.m.authInflight = true;
        st.m.authStart = Simulator::Now();

        Pub64 RS;
        Priv32 rS;
        Priv32 CT;
        Priv32 YS;
        Priv32 Sig;
        uint8_t dataCt[PUB_LEN + 4];
        uint8_t dataSig[PUB_LEN + 4 + PRIV_LEN + PRIV_LEN];
        uint8_t istBe[4];

        MockEcc::MakeKey(RS, rS);

        U32ToBe(st.iST, istBe);
        std::memcpy(dataCt, RS.data(), PUB_LEN);
        std::memcpy(dataCt + PUB_LEN, istBe, 4);
        PseudoHmacSha256(st.skst.data(), PRIV_LEN, dataCt, sizeof(dataCt), CT.data());

        MockEcc::ScalarMulAdd(rS, CT, k_sS, YS);

        std::memcpy(dataSig, RS.data(), PUB_LEN);
        std::memcpy(dataSig + PUB_LEN, istBe, 4);
        std::memcpy(dataSig + PUB_LEN + 4, CT.data(), PRIV_LEN);
        std::memcpy(dataSig + PUB_LEN + 4 + PRIV_LEN, YS.data(), PRIV_LEN);
        PseudoHmacSha256(st.skst.data(), PRIV_LEN, dataSig, sizeof(dataSig), Sig.data());

        std::vector<uint8_t> resp(1 + AUTH_PAYLOAD_LEN, 0);
        resp[0] = MSG_AUTH_RESP;
        std::memcpy(resp.data() + 1, RS.data(), PUB_LEN);
        std::memcpy(resp.data() + 1 + PUB_LEN, CT.data(), PRIV_LEN);
        std::memcpy(resp.data() + 1 + PUB_LEN + PRIV_LEN, YS.data(), PRIV_LEN);
        std::memcpy(resp.data() + 1 + PUB_LEN + PRIV_LEN + PRIV_LEN, Sig.data(), PRIV_LEN);

        m_socket->SendTo(resp.data(), resp.size(), 0, from);
        st.m.txPkts += 1;
        st.m.txBytes += resp.size();

        UpdateState(st, YS);

        uint64_t authMs = std::max<int64_t>(1, (Simulator::Now() - st.m.authStart).GetMilliSeconds());
        uint64_t scenMs = std::max<int64_t>(1, (Simulator::Now() - st.m.scenarioStart).GetMilliSeconds());
        uint64_t cpu, lpm, tx, rx, e;
        BuildPseudoEnergest(st.m, scenMs, cpu, lpm, tx, rx, e);

        std::cout << "CSV,server," << st.key << "," << authMs << "," << scenMs << "," << st.m.txBytes
                  << "," << st.m.rxBytes << "," << st.m.txPkts << "," << st.m.rxPkts << "," << cpu << ","
                  << lpm << "," << tx << "," << rx << "," << e << std::endl;

        st.m.authInflight = false;
    }

    void HandleRead(Ptr<Socket> socket)
    {
        Address from;
        Ptr<Packet> pkt = socket->RecvFrom(from);
        if (!pkt)
        {
            return;
        }

        uint32_t len = pkt->GetSize();
        if (len < 1)
        {
            return;
        }

        std::vector<uint8_t> buf(len);
        pkt->CopyData(buf.data(), len);

        uint8_t type = buf[0];
        if (type == MSG_REG_REQ)
        {
            HandleRegister(from, buf.data() + 1, len - 1, len);
            return;
        }
        if (type == MSG_AUTH_REQ && len == 1)
        {
            HandleAuth(from, len);
        }
    }

  private:
    Ptr<Socket> m_socket;
    uint16_t m_port = UDP_PORT;
    uint32_t m_maxClients = 100;
    Pub64 m_KS{};
    std::map<std::string, ClientState> m_clients;
    bool m_csvHeaderPrinted = false;
};

NS_OBJECT_ENSURE_REGISTERED(CoojaTranslatedServerApp);

static bool gClientCsvHeaderPrinted = false;

class CoojaTranslatedClientApp : public Application
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid =
            TypeId("ns3::CoojaTranslatedClientApp")
                .SetParent<Application>()
                .AddConstructor<CoojaTranslatedClientApp>()
                .AddAttribute("ServerAddress",
                              "Server IPv6 address",
                              AddressValue(),
                              MakeAddressAccessor(&CoojaTranslatedClientApp::m_serverAddress),
                              MakeAddressChecker())
                .AddAttribute("TickSeconds",
                              "Periodic timer like Contiki etimer",
                              UintegerValue(10),
                              MakeUintegerAccessor(&CoojaTranslatedClientApp::m_tickSeconds),
                              MakeUintegerChecker<uint32_t>());
        return tid;
    }

  private:
    void StartApplication() override
    {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), UDP_PORT));
        m_socket->SetRecvCallback(MakeCallback(&CoojaTranslatedClientApp::HandleRead, this));

        MockEcc::ComputePublicKey(k_sT, m_KT);

        m_registered = false;
        m_authDone = false;
        m_iST = 0;
        m_SKST = kSKSTInit;
        m_metric = {};

        ScheduleTick(Seconds(m_tickSeconds));
    }

    void StopApplication() override
    {
        if (m_tickEvent.IsPending())
        {
            Simulator::Cancel(m_tickEvent);
        }
        if (m_socket)
        {
            m_socket->Close();
            m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
        }
    }

    void ScheduleTick(Time d)
    {
        m_tickEvent = Simulator::Schedule(d, &CoojaTranslatedClientApp::OnTick, this);
    }

    void UpdateState(const Priv32& YS)
    {
        uint8_t buf[4 + PRIV_LEN];
        uint8_t newKey[PRIV_LEN];
        m_iST += 2;
        U32ToBe(m_iST, buf);
        std::memcpy(buf + 4, YS.data(), PRIV_LEN);
        PseudoHmacSha256(m_SKST.data(), PRIV_LEN, buf, sizeof(buf), newKey);
        std::memcpy(m_SKST.data(), newKey, PRIV_LEN);
    }

    void DeriveSkst(const Priv32& shared)
    {
        uint8_t buf[PRIV_LEN + 4];
        uint8_t istBe[4];
        U32ToBe(m_iST, istBe);
        std::memcpy(buf, shared.data(), PRIV_LEN);
        std::memcpy(buf + PRIV_LEN, istBe, 4);
        Sha256(buf, sizeof(buf), m_SKST.data());
    }

    void SendRegister()
    {
        Pub64 RT;
        Priv32 CT;
        Priv32 YT;
        uint8_t dataCt[PUB_LEN + 4];
        uint8_t istBe[4];

        if (!MockEcc::MakeKey(RT, m_rTPriv))
        {
            return;
        }

        U32ToBe(m_iST, istBe);
        std::memcpy(dataCt, RT.data(), PUB_LEN);
        std::memcpy(dataCt + PUB_LEN, istBe, 4);
        PseudoHmacSha256(m_SKST.data(), PRIV_LEN, dataCt, sizeof(dataCt), CT.data());
        m_regCT = CT;

        MockEcc::ScalarMulAdd(m_rTPriv, CT, k_sT, YT);

        std::vector<uint8_t> msg(1 + REG_REQ_LEN, 0);
        msg[0] = MSG_REG_REQ;
        std::memcpy(msg.data() + 1, RT.data(), PUB_LEN);
        std::memcpy(msg.data() + 1 + PUB_LEN, YT.data(), PRIV_LEN);
        std::memcpy(msg.data() + 1 + PUB_LEN + PRIV_LEN, CT.data(), PRIV_LEN);
        std::memcpy(msg.data() + 1 + PUB_LEN + PRIV_LEN + PRIV_LEN, m_KT.data(), PUB_LEN);

        m_socket->SendTo(msg.data(), msg.size(), 0, m_serverAddress);
        m_metric.txPkts += 1;
        m_metric.txBytes += msg.size();
        if (!m_metric.scenarioStarted)
        {
            m_metric.scenarioStarted = true;
            m_metric.scenarioStart = Simulator::Now();
        }
    }

    void SendAuthReq()
    {
        uint8_t req = MSG_AUTH_REQ;
        m_socket->SendTo(&req, 1, 0, m_serverAddress);
        m_metric.txPkts += 1;
        m_metric.txBytes += 1;
        m_metric.authInflight = true;
        m_metric.authStart = Simulator::Now();
    }

    void OnTick()
    {
        if (!m_authDone)
        {
            if (!m_registered)
            {
                SendRegister();
            }
            else
            {
                SendAuthReq();
            }
            ScheduleTick(Seconds(m_tickSeconds));
        }
    }

    void HandleRegisterResp(const uint8_t* payload, uint32_t len)
    {
        if (len != REG_RESP_LEN)
        {
            return;
        }

        Pub64 RS;
        Priv32 YS;
        Pub64 KSrx;
        std::memcpy(RS.data(), payload, PUB_LEN);
        std::memcpy(YS.data(), payload + PUB_LEN, PRIV_LEN);
        std::memcpy(KSrx.data(), payload + PUB_LEN + PRIV_LEN, PUB_LEN);
        m_KS = KSrx;

        Priv32 CT = m_regCT;
        Pub64 ysPoint;
        Pub64 ctKs;
        Pub64 rhs;
        MockEcc::PointMulGen(YS, ysPoint);
        MockEcc::PointMulPub(m_KS, CT, ctKs);
        MockEcc::PointAdd(RS, ctKs, rhs);
        if (!CtEqual(ysPoint.data(), rhs.data(), PUB_LEN))
        {
            return;
        }

        Priv32 shared;
        MockEcc::SharedSecret(RS, m_rTPriv, shared);
        DeriveSkst(shared);
        m_iST = 1;
        m_registered = true;
    }

    void HandleAuthResp(const uint8_t* payload, uint32_t len)
    {
        if (len != AUTH_PAYLOAD_LEN)
        {
            return;
        }

        Priv32 CT;
        Priv32 YS;
        Priv32 Sig;
        Pub64 RS;
        std::memcpy(RS.data(), payload, PUB_LEN);
        std::memcpy(CT.data(), payload + PUB_LEN, PRIV_LEN);
        std::memcpy(YS.data(), payload + PUB_LEN + PRIV_LEN, PRIV_LEN);
        std::memcpy(Sig.data(), payload + PUB_LEN + PRIV_LEN + PRIV_LEN, PRIV_LEN);

        uint8_t istBe[4];
        uint8_t dataCt[PUB_LEN + 4];
        uint8_t dataSig[PUB_LEN + 4 + PRIV_LEN + PRIV_LEN];
        Priv32 ctCalc;
        Priv32 sigCalc;

        U32ToBe(m_iST, istBe);
        std::memcpy(dataCt, RS.data(), PUB_LEN);
        std::memcpy(dataCt + PUB_LEN, istBe, 4);
        PseudoHmacSha256(m_SKST.data(), PRIV_LEN, dataCt, sizeof(dataCt), ctCalc.data());

        Pub64 ysPoint;
        Pub64 ctKs;
        Pub64 rhs;
        MockEcc::PointMulGen(YS, ysPoint);
        MockEcc::PointMulPub(m_KS, CT, ctKs);
        MockEcc::PointAdd(RS, ctKs, rhs);

        std::memcpy(dataSig, RS.data(), PUB_LEN);
        std::memcpy(dataSig + PUB_LEN, istBe, 4);
        std::memcpy(dataSig + PUB_LEN + 4, CT.data(), PRIV_LEN);
        std::memcpy(dataSig + PUB_LEN + 4 + PRIV_LEN, YS.data(), PRIV_LEN);
        PseudoHmacSha256(m_SKST.data(), PRIV_LEN, dataSig, sizeof(dataSig), sigCalc.data());

        if (!CtEqual(CT.data(), ctCalc.data(), PRIV_LEN) || !CtEqual(ysPoint.data(), rhs.data(), PUB_LEN) ||
            !CtEqual(Sig.data(), sigCalc.data(), PRIV_LEN))
        {
            return;
        }

        UpdateState(YS);
        m_authDone = true;

        uint64_t authMs = std::max<int64_t>(1, (Simulator::Now() - m_metric.authStart).GetMilliSeconds());
        uint64_t scenMs = std::max<int64_t>(1, (Simulator::Now() - m_metric.scenarioStart).GetMilliSeconds());
        uint64_t cpu, lpm, tx, rx, e;
        BuildPseudoEnergest(m_metric, scenMs, cpu, lpm, tx, rx, e);

        PrintCsvHeaderOnce(gClientCsvHeaderPrinted);
        std::cout << "CSV,client,node:" << GetNode()->GetId() << "," << authMs << "," << scenMs << ","
                  << m_metric.txBytes << "," << m_metric.rxBytes << "," << m_metric.txPkts << ","
                  << m_metric.rxPkts << "," << cpu << "," << lpm << "," << tx << "," << rx << "," << e
                  << std::endl;

        if (m_tickEvent.IsPending())
        {
            Simulator::Cancel(m_tickEvent);
        }
    }

    void HandleRead(Ptr<Socket> socket)
    {
        Address from;
        Ptr<Packet> pkt = socket->RecvFrom(from);
        if (!pkt)
        {
            return;
        }

        uint32_t len = pkt->GetSize();
        if (len < 1)
        {
            return;
        }

        std::vector<uint8_t> buf(len);
        pkt->CopyData(buf.data(), len);

        m_metric.rxPkts += 1;
        m_metric.rxBytes += len;

        if (buf[0] == MSG_REG_RESP)
        {
            HandleRegisterResp(buf.data() + 1, len - 1);
        }
        else if (buf[0] == MSG_AUTH_RESP)
        {
            HandleAuthResp(buf.data() + 1, len - 1);
        }
    }

  private:
    Ptr<Socket> m_socket;
    Address m_serverAddress;
    uint32_t m_tickSeconds = 10;
    EventId m_tickEvent;

    bool m_registered = false;
    bool m_authDone = false;
    uint32_t m_iST = 0;

    Priv32 m_SKST = kSKSTInit;
    Priv32 m_rTPriv{};
    Priv32 m_regCT{};
    Pub64 m_KT{};
    Pub64 m_KS{};

    MetricState m_metric;
};

NS_OBJECT_ENSURE_REGISTERED(CoojaTranslatedClientApp);

} // namespace

int main(int argc, char* argv[])
{
    uint32_t numClients = 30;
    double simStop = 120.0;
    double startWindow = 20.0;
    bool enableAnim = true;
    bool useMockEcc = false;
    std::string eccType = "p256";
    std::string animFile = "cooja-translated.xml";

    CommandLine cmd(__FILE__);
    cmd.AddValue("numClients", "Number of clients", numClients);
    cmd.AddValue("simStop", "Simulation stop time", simStop);
    cmd.AddValue("startWindow", "Start jitter window", startWindow);
    cmd.AddValue("enableAnim", "Enable NetAnim output", enableAnim);
    cmd.AddValue("useMockEcc", "Use mock ECC algebra instead of real P-256", useMockEcc);
    cmd.AddValue("eccType", "ECC type: p256|secp256k1|brainpoolp256r1|mock", eccType);
    cmd.AddValue("animFile", "NetAnim XML file", animFile);
    cmd.Parse(argc, argv);

    g_useMockEcc = useMockEcc;
    g_eccType = eccType;
    if (g_eccType == "mock")
    {
        g_useMockEcc = true;
    }

    NodeContainer server;
    server.Create(1);
    NodeContainer clients;
    clients.Create(numClients);
    NodeContainer all;
    all.Add(server);
    all.Add(clients);

    // CSMA bus — IEEE 802.15.4 parameters: 250 kbps, 2ms propagation delay.
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("250Kbps"));
    csma.SetChannelAttribute("Delay",    StringValue("2ms"));
    auto devs = csma.Install(all);

    InternetStackHelper internet;
    internet.Install(all);

    MobilityHelper mob;
    mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mob.Install(all);

    Ptr<MobilityModel> smm = server.Get(0)->GetObject<MobilityModel>();
    if (smm) smm->SetPosition(Vector(0.0, 0.0, 0.0));

    double radius = 35.0;
    for (uint32_t i = 0; i < numClients; ++i)
    {
        double a = (2.0 * M_PI * static_cast<double>(i)) /
                   static_cast<double>(std::max<uint32_t>(1, numClients));
        Ptr<MobilityModel> mm = clients.Get(i)->GetObject<MobilityModel>();
        if (mm) mm->SetPosition(Vector(radius * std::cos(a), radius * std::sin(a), 0.0));
    }

    Ipv6AddressHelper ipv6;
    ipv6.SetBase(Ipv6Address("2001:db8::"), Ipv6Prefix(64));
    auto ifs = ipv6.Assign(devs);
    for (uint32_t i = 0; i < ifs.GetN(); ++i) ifs.SetForwarding(i, true);
    ifs.SetDefaultRouteInAllNodes(0);
    Ipv6Address serverIp = ifs.GetAddress(0, 1);

    Ptr<CoojaTranslatedServerApp> s = CreateObject<CoojaTranslatedServerApp>();
    s->SetAttribute("MaxClients", UintegerValue(numClients + 10));
    server.Get(0)->AddApplication(s);
    s->SetStartTime(Seconds(0.5));
    s->SetStopTime(Seconds(simStop));

    Ptr<UniformRandomVariable> rv = CreateObject<UniformRandomVariable>();
    for (uint32_t i = 0; i < numClients; ++i)
    {
        Ptr<CoojaTranslatedClientApp> c = CreateObject<CoojaTranslatedClientApp>();
        c->SetAttribute("ServerAddress", AddressValue(Inet6SocketAddress(serverIp, UDP_PORT)));
        clients.Get(i)->AddApplication(c);
        double jitter = rv->GetValue(0.0, startWindow);
        c->SetStartTime(Seconds(1.0 + jitter));
        c->SetStopTime(Seconds(simStop));
    }

    std::unique_ptr<AnimationInterface> anim;
    if (enableAnim)
    {
        PacketMetadata::Enable();
        anim = std::make_unique<AnimationInterface>(animFile);
        anim->EnablePacketMetadata(true);
        anim->SetMobilityPollInterval(Seconds(1.0));
        anim->UpdateNodeDescription(server.Get(0)->GetId(), "Auth Server");
        for (uint32_t i = 0; i < numClients; ++i)
        {
            std::ostringstream os;
            os << "IoT-" << (i + 1);
            anim->UpdateNodeDescription(clients.Get(i)->GetId(), os.str());
        }
    }

    Simulator::Stop(Seconds(simStop));
    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
