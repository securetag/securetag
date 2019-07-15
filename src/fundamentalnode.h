// Copyright (c) 2014-2017 The SecureTag Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FUNDAMENTALNODE_H
#define FUNDAMENTALNODE_H

#include "key.h"
#include "validation.h"
#include "spork.h"

class CFundamentalnode;
class CFundamentalnodeBroadcast;
class CConnman;

static const int FUNDAMENTALNODE_CHECK_SECONDS               =   5;
static const int FUNDAMENTALNODE_MIN_MNB_SECONDS             =   5 * 60;
static const int FUNDAMENTALNODE_MIN_MNP_SECONDS             =  10 * 60;
static const int FUNDAMENTALNODE_SENTINEL_PING_MAX_SECONDS   =  60 * 60;
static const int FUNDAMENTALNODE_EXPIRATION_SECONDS          = 120 * 60;
static const int FUNDAMENTALNODE_NEW_START_REQUIRED_SECONDS  = 180 * 60;
static const CAmount FUNDAMENTALNODE_AMOUNT                  = 10000 * COIN;
static const CAmount FN_MAGIC_AMOUNT                         = 0.1234 *COIN;

static const int FUNDAMENTALNODE_POSE_BAN_MAX_SCORE          = 5;

//
// The Fundamentalnode Ping Class : Contains a different serialize method for sending pings from fundamentalnodes throughout the network
//

// sentinel version before implementation of nSentinelVersion in CFundamentalnodePing
#define DEFAULT_SENTINEL_VERSION 0x010001
// daemon version before implementation of nDaemonVersion in CFundamentalnodePing
#define DEFAULT_DAEMON_VERSION 120200

class CFundamentalnodePing
{
public:
    COutPoint fundamentalnodeOutpoint{};
    uint256 blockHash{};
    int64_t sigTime{}; //fnb message times
    std::vector<unsigned char> vchSig{};
    bool fSentinelIsCurrent = false; // true if last sentinel ping was current
    // MSB is always 0, other 3 bits corresponds to x.x.x version scheme
    uint32_t nSentinelVersion{DEFAULT_SENTINEL_VERSION};
    uint32_t nDaemonVersion{DEFAULT_DAEMON_VERSION};

    CFundamentalnodePing() = default;

    CFundamentalnodePing(const COutPoint& outpoint);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (nVersion == 70208 && (s.GetType() & SER_NETWORK)) {
            // converting from/to old format
            CTxIn txin{};
            if (ser_action.ForRead()) {
                READWRITE(txin);
                fundamentalnodeOutpoint = txin.prevout;
            } else {
                txin = CTxIn(fundamentalnodeOutpoint);
                READWRITE(txin);
            }
        } else {
            // using new format directly
            READWRITE(fundamentalnodeOutpoint);
        }
        READWRITE(blockHash);
        READWRITE(sigTime);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
        if(ser_action.ForRead() && s.size() == 0) {
            // TODO: drop this after migration to 70209
            fSentinelIsCurrent = false;
            nSentinelVersion = DEFAULT_SENTINEL_VERSION;
            nDaemonVersion = DEFAULT_DAEMON_VERSION;
            return;
        }
        READWRITE(fSentinelIsCurrent);
        READWRITE(nSentinelVersion);
        if(ser_action.ForRead() && s.size() == 0) {
            // TODO: drop this after migration to 70209
            nDaemonVersion = DEFAULT_DAEMON_VERSION;
            return;
        }
        if (!(nVersion == 70208 && (s.GetType() & SER_NETWORK))) {
            READWRITE(nDaemonVersion);
        }
    }

    uint256 GetHash() const;
    uint256 GetSignatureHash() const;

    bool IsExpired() const { return GetAdjustedTime() - sigTime > FUNDAMENTALNODE_NEW_START_REQUIRED_SECONDS; }

    bool Sign(const CKey& keyFundamentalnode, const CPubKey& pubKeyFundamentalnode);
    bool CheckSignature(const CPubKey& pubKeyFundamentalnode, int &nDos) const;
    bool SimpleCheck(int& nDos);
    bool CheckAndUpdate(CFundamentalnode* pfn, bool fFromNewBroadcast, int& nDos, CConnman& connman);
    void Relay(CConnman& connman);

    explicit operator bool() const;
};

inline bool operator==(const CFundamentalnodePing& a, const CFundamentalnodePing& b)
{
    return a.fundamentalnodeOutpoint == b.fundamentalnodeOutpoint && a.blockHash == b.blockHash;
}
inline bool operator!=(const CFundamentalnodePing& a, const CFundamentalnodePing& b)
{
    return !(a == b);
}
inline CFundamentalnodePing::operator bool() const
{
    return *this != CFundamentalnodePing();
}

struct fundamentalnode_info_t
{
    // Note: all these constructors can be removed once C++14 is enabled.
    // (in C++11 the member initializers wrongly disqualify this as an aggregate)
    fundamentalnode_info_t() = default;
    fundamentalnode_info_t(fundamentalnode_info_t const&) = default;

    fundamentalnode_info_t(int activeState, int protoVer, int64_t sTime) :
        nActiveState{activeState}, nProtocolVersion{protoVer}, sigTime{sTime} {}

    fundamentalnode_info_t(int activeState, int protoVer, int64_t sTime,
                      COutPoint const& outpnt, CService const& addr,
                      CPubKey const& pkCollAddr, CPubKey const& pkMN) :
        nActiveState{activeState}, nProtocolVersion{protoVer}, sigTime{sTime},
        outpoint{outpnt}, addr{addr},
        pubKeyCollateralAddress{pkCollAddr}, pubKeyFundamentalnode{pkMN} {}

    int nActiveState = 0;
    int nProtocolVersion = 0;
    int64_t sigTime = 0; //fnb message time

    COutPoint outpoint{};
    CService addr{};
    CPubKey pubKeyCollateralAddress{};
    CPubKey pubKeyFundamentalnode{};

    int64_t nLastDsq = 0; //the dsq count from the last dsq broadcast of this node
    int64_t nTimeLastChecked = 0;
    int64_t nTimeLastPaid = 0;
    int64_t nTimeLastPing = 0; //* not in CMN
    bool fInfoValid = false; //* not in CMN
};

//
// The Fundamentalnode Class. For managing the Darksend process. It contains the input of the 1000DRK, signature to prove
// it's the one who own that ip address and code for calculating the payment election.
//
class CFundamentalnode : public fundamentalnode_info_t
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

public:
    enum state {
        FUNDAMENTALNODE_PRE_ENABLED,
        FUNDAMENTALNODE_ENABLED,
        FUNDAMENTALNODE_EXPIRED,
        FUNDAMENTALNODE_OUTPOINT_SPENT,
        FUNDAMENTALNODE_UPDATE_REQUIRED,
        FUNDAMENTALNODE_SENTINEL_PING_EXPIRED,
        FUNDAMENTALNODE_NEW_START_REQUIRED,
        FUNDAMENTALNODE_POSE_BAN
    };

    enum CollateralStatus {
        COLLATERAL_OK,
        COLLATERAL_UTXO_NOT_FOUND,
        COLLATERAL_INVALID_AMOUNT,
        COLLATERAL_INVALID_PUBKEY
    };


    CFundamentalnodePing lastPing{};
    std::vector<unsigned char> vchSig{};

    uint256 nCollateralMinConfBlockHash{};
    int nBlockLastPaid{};
    int nPoSeBanScore{};
    int nPoSeBanHeight{};
    bool fAllowMixingTx{};
    bool fUnitTest = false;

    // KEEP TRACK OF GOVERNANCE ITEMS EACH FUNDAMENTALNODE HAS VOTE UPON FOR RECALCULATION
    std::map<uint256, int> mapGovernanceObjectsVotedOn;

    CFundamentalnode();
    CFundamentalnode(const CFundamentalnode& other);
    CFundamentalnode(const CFundamentalnodeBroadcast& fnb);
    CFundamentalnode(CService addrNew, COutPoint outpointNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyFundamentalnodeNew, int nProtocolVersionIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs);
        int nVersion = s.GetVersion();
        if (nVersion == 70208 && (s.GetType() & SER_NETWORK)) {
            // converting from/to old format
            CTxIn txin{};
            if (ser_action.ForRead()) {
                READWRITE(txin);
                outpoint = txin.prevout;
            } else {
                txin = CTxIn(outpoint);
                READWRITE(txin);
            }
        } else {
            // using new format directly
            READWRITE(outpoint);
        }
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyFundamentalnode);
        READWRITE(lastPing);
        READWRITE(vchSig);
        READWRITE(sigTime);
        READWRITE(nLastDsq);
        READWRITE(nTimeLastChecked);
        READWRITE(nTimeLastPaid);
        READWRITE(nActiveState);
        READWRITE(nCollateralMinConfBlockHash);
        READWRITE(nBlockLastPaid);
        READWRITE(nProtocolVersion);
        READWRITE(nPoSeBanScore);
        READWRITE(nPoSeBanHeight);
        READWRITE(fAllowMixingTx);
        READWRITE(fUnitTest);
        READWRITE(mapGovernanceObjectsVotedOn);
    }

    // CALCULATE A RANK AGAINST OF GIVEN BLOCK
    arith_uint256 CalculateScore(const uint256& blockHash) const;

    bool UpdateFromNewBroadcast(CFundamentalnodeBroadcast& fnb, CConnman& connman);

    static CollateralStatus CheckCollateral(const COutPoint& outpoint, const CPubKey& pubkey);
    static CollateralStatus CheckCollateral(const COutPoint& outpoint, const CPubKey& pubkey, int& nHeightRet);
    void Check(bool fForce = false);

    bool IsBroadcastedWithin(int nSeconds) { return GetAdjustedTime() - sigTime < nSeconds; }

    bool IsPingedWithin(int nSeconds, int64_t nTimeToCheckAt = -1)
    {
        if(!lastPing) return false;

        if(nTimeToCheckAt == -1) {
            nTimeToCheckAt = GetAdjustedTime();
        }
        return nTimeToCheckAt - lastPing.sigTime < nSeconds;
    }

    bool IsEnabled() const { return nActiveState == FUNDAMENTALNODE_ENABLED; }
    bool IsPreEnabled() const { return nActiveState == FUNDAMENTALNODE_PRE_ENABLED; }
    bool IsPoSeBanned() const { return nActiveState == FUNDAMENTALNODE_POSE_BAN; }
    // NOTE: this one relies on nPoSeBanScore, not on nActiveState as everything else here
    bool IsPoSeVerified() const { return nPoSeBanScore <= -FUNDAMENTALNODE_POSE_BAN_MAX_SCORE; }
    bool IsExpired() const { return nActiveState == FUNDAMENTALNODE_EXPIRED; }
    bool IsOutpointSpent() const { return nActiveState == FUNDAMENTALNODE_OUTPOINT_SPENT; }
    bool IsUpdateRequired() const { return nActiveState == FUNDAMENTALNODE_UPDATE_REQUIRED; }
    bool IsSentinelPingExpired() const { return nActiveState == FUNDAMENTALNODE_SENTINEL_PING_EXPIRED; }
    bool IsNewStartRequired() const { return nActiveState == FUNDAMENTALNODE_NEW_START_REQUIRED; }

    static bool IsValidStateForAutoStart(int nActiveStateIn)
    {
        return  nActiveStateIn == FUNDAMENTALNODE_ENABLED ||
                nActiveStateIn == FUNDAMENTALNODE_PRE_ENABLED ||
                nActiveStateIn == FUNDAMENTALNODE_EXPIRED ||
                nActiveStateIn == FUNDAMENTALNODE_SENTINEL_PING_EXPIRED;
    }

    bool IsValidForPayment() const
    {
        if(nActiveState == FUNDAMENTALNODE_ENABLED) {
            return true;
        }
        if(!sporkManager.IsSporkActive(SPORK_15_REQUIRE_SENTINEL_FLAG) &&
           (nActiveState == FUNDAMENTALNODE_SENTINEL_PING_EXPIRED)) {
            return true;
        }

        return false;
    }

    bool IsValidNetAddr();
    static bool IsValidNetAddr(CService addrIn);

    void IncreasePoSeBanScore() { if(nPoSeBanScore < FUNDAMENTALNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore++; }
    void DecreasePoSeBanScore() { if(nPoSeBanScore > -FUNDAMENTALNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore--; }
    void PoSeBan() { nPoSeBanScore = FUNDAMENTALNODE_POSE_BAN_MAX_SCORE; }

    fundamentalnode_info_t GetInfo() const;

    static std::string StateToString(int nStateIn);
    std::string GetStateString() const;
    std::string GetStatus() const;

    int GetLastPaidTime() const { return nTimeLastPaid; }
    int GetLastPaidBlock() const { return nBlockLastPaid; }
    void UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack);

    // KEEP TRACK OF EACH GOVERNANCE ITEM INCASE THIS NODE GOES OFFLINE, SO WE CAN RECALC THEIR STATUS
    void AddGovernanceVote(uint256 nGovernanceObjectHash);
    // RECALCULATE CACHED STATUS FLAGS FOR ALL AFFECTED OBJECTS
    void FlagGovernanceItemsAsDirty();

    void RemoveGovernanceObject(uint256 nGovernanceObjectHash);

    CFundamentalnode& operator=(CFundamentalnode const& from)
    {
        static_cast<fundamentalnode_info_t&>(*this)=from;
        lastPing = from.lastPing;
        vchSig = from.vchSig;
        nCollateralMinConfBlockHash = from.nCollateralMinConfBlockHash;
        nBlockLastPaid = from.nBlockLastPaid;
        nPoSeBanScore = from.nPoSeBanScore;
        nPoSeBanHeight = from.nPoSeBanHeight;
        fAllowMixingTx = from.fAllowMixingTx;
        fUnitTest = from.fUnitTest;
        mapGovernanceObjectsVotedOn = from.mapGovernanceObjectsVotedOn;
        return *this;
    }
};

inline bool operator==(const CFundamentalnode& a, const CFundamentalnode& b)
{
    return a.outpoint == b.outpoint;
}
inline bool operator!=(const CFundamentalnode& a, const CFundamentalnode& b)
{
    return !(a.outpoint == b.outpoint);
}


//
// The Fundamentalnode Broadcast Class : Contains a different serialize method for sending fundamentalnodes through the network
//

class CFundamentalnodeBroadcast : public CFundamentalnode
{
public:

    bool fRecovery;

    CFundamentalnodeBroadcast() : CFundamentalnode(), fRecovery(false) {}
    CFundamentalnodeBroadcast(const CFundamentalnode& fn) : CFundamentalnode(fn), fRecovery(false) {}
    CFundamentalnodeBroadcast(CService addrNew, COutPoint outpointNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyFundamentalnodeNew, int nProtocolVersionIn) :
        CFundamentalnode(addrNew, outpointNew, pubKeyCollateralAddressNew, pubKeyFundamentalnodeNew, nProtocolVersionIn), fRecovery(false) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (nVersion == 70208 && (s.GetType() & SER_NETWORK)) {
            // converting from/to old format
            CTxIn txin{};
            if (ser_action.ForRead()) {
                READWRITE(txin);
                outpoint = txin.prevout;
            } else {
                txin = CTxIn(outpoint);
                READWRITE(txin);
            }
        } else {
            // using new format directly
            READWRITE(outpoint);
        }
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyFundamentalnode);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
        READWRITE(sigTime);
        READWRITE(nProtocolVersion);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(lastPing);
        }
    }

    uint256 GetHash() const;
    uint256 GetSignatureHash() const;

    /// Create Fundamentalnode broadcast, needs to be relayed manually after that
    static bool Create(const COutPoint& outpoint, const CService& service, const CKey& keyCollateralAddressNew, const CPubKey& pubKeyCollateralAddressNew, const CKey& keyFundamentalnodeNew, const CPubKey& pubKeyFundamentalnodeNew, std::string &strErrorRet, CFundamentalnodeBroadcast &fnbRet);
    static bool Create(const std::string& strService, const std::string& strKey, const std::string& strTxHash, const std::string& strOutputIndex, std::string& strErrorRet, CFundamentalnodeBroadcast &fnbRet, bool fOffline = false);

    bool SimpleCheck(int& nDos);
    bool Update(CFundamentalnode* pfn, int& nDos, CConnman& connman);
    bool CheckOutpoint(int& nDos);

    bool Sign(const CKey& keyCollateralAddress);
    bool CheckSignature(int& nDos) const;
    void Relay(CConnman& connman) const;
};

class CFundamentalnodeVerification
{
public:
    COutPoint fundamentalnodeOutpoint1{};
    COutPoint fundamentalnodeOutpoint2{};
    CService addr{};
    int nonce{};
    int nBlockHeight{};
    std::vector<unsigned char> vchSig1{};
    std::vector<unsigned char> vchSig2{};

    CFundamentalnodeVerification() = default;

    CFundamentalnodeVerification(CService addr, int nonce, int nBlockHeight) :
        addr(addr),
        nonce(nonce),
        nBlockHeight(nBlockHeight)
    {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (nVersion == 70208 && (s.GetType() & SER_NETWORK)) {
            // converting from/to old format
            CTxIn txin1{};
            CTxIn txin2{};
            if (ser_action.ForRead()) {
                READWRITE(txin1);
                READWRITE(txin2);
                fundamentalnodeOutpoint1 = txin1.prevout;
                fundamentalnodeOutpoint2 = txin2.prevout;
            } else {
                txin1 = CTxIn(fundamentalnodeOutpoint1);
                txin2 = CTxIn(fundamentalnodeOutpoint2);
                READWRITE(txin1);
                READWRITE(txin2);
            }
        } else {
            // using new format directly
            READWRITE(fundamentalnodeOutpoint1);
            READWRITE(fundamentalnodeOutpoint2);
        }
        READWRITE(addr);
        READWRITE(nonce);
        READWRITE(nBlockHeight);
        READWRITE(vchSig1);
        READWRITE(vchSig2);
    }

    uint256 GetHash() const
    {
        // Note: doesn't match serialization

        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        // adding dummy values here to match old hashing format
        ss << fundamentalnodeOutpoint1 << uint8_t{} << 0xffffffff;
        ss << fundamentalnodeOutpoint2 << uint8_t{} << 0xffffffff;
        ss << addr;
        ss << nonce;
        ss << nBlockHeight;
        return ss.GetHash();
    }

    uint256 GetSignatureHash1(const uint256& blockHash) const
    {
        // Note: doesn't match serialization

        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << addr;
        ss << nonce;
        ss << blockHash;
        return ss.GetHash();
    }

    uint256 GetSignatureHash2(const uint256& blockHash) const
    {
        // Note: doesn't match serialization

        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << fundamentalnodeOutpoint1;
        ss << fundamentalnodeOutpoint2;
        ss << addr;
        ss << nonce;
        ss << blockHash;
        return ss.GetHash();
    }

    void Relay() const
    {
        CInv inv(MSG_FUNDAMENTALNODE_VERIFY, GetHash());
        g_connman->RelayInv(inv);
    }
};

#endif
