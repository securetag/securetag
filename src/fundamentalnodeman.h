// Copyright (c) 2014-2017 The SecureTag Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FUNDAMENTALNODEMAN_H
#define FUNDAMENTALNODEMAN_H

#include "fundamentalnode.h"
#include "sync.h"

class CFundamentalnodeMan;
class CConnman;

extern CFundamentalnodeMan fnodeman;

class CFundamentalnodeMan
{
public:
    typedef std::pair<arith_uint256, const CFundamentalnode*> score_pair_t;
    typedef std::vector<score_pair_t> score_pair_vec_t;
    typedef std::pair<int, const CFundamentalnode> rank_pair_t;
    typedef std::vector<rank_pair_t> rank_pair_vec_t;

private:
    static const std::string SERIALIZATION_VERSION_STRING;

    static const int DSEGFN_UPDATE_SECONDS        = 3 * 60 * 60;

    static const int LAST_PAID_SCAN_BLOCKS;

    static const int MIN_POSE_PROTO_VERSION     = 70203;
    static const int MAX_POSE_CONNECTIONS       = 10;
    static const int MAX_POSE_RANK              = 10;
    static const int MAX_POSE_BLOCKS            = 10;

    static const int MNB_RECOVERY_QUORUM_TOTAL      = 10;
    static const int MNB_RECOVERY_QUORUM_REQUIRED   = 6;
    static const int MNB_RECOVERY_MAX_ASK_ENTRIES   = 10;
    static const int MNB_RECOVERY_WAIT_SECONDS      = 60;
    static const int MNB_RECOVERY_RETRY_SECONDS     = 3 * 60 * 60;


    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    // Keep track of current block height
    int nCachedBlockHeight;

    // map to hold all MNs
    std::map<COutPoint, CFundamentalnode> mapFundamentalnodes;
    // who's asked for the Fundamentalnode list and the last time
    std::map<CService, int64_t> mAskedUsForFundamentalnodeList;
    // who we asked for the Fundamentalnode list and the last time
    std::map<CService, int64_t> mWeAskedForFundamentalnodeList;
    // which Fundamentalnodes we've asked for
    std::map<COutPoint, std::map<CService, int64_t> > mWeAskedForFundamentalnodeListEntry;

    // who we asked for the fundamentalnode verification
    std::map<CService, CFundamentalnodeVerification> mWeAskedForVerification;

    // these maps are used for fundamentalnode recovery from FUNDAMENTALNODE_NEW_START_REQUIRED state
    std::map<uint256, std::pair< int64_t, std::set<CService> > > mFnbRecoveryRequests;
    std::map<uint256, std::vector<CFundamentalnodeBroadcast> > mFnbRecoveryGoodReplies;
    std::list< std::pair<CService, uint256> > listScheduledFnbRequestConnections;
    std::map<CService, std::pair<int64_t, std::set<uint256> > > mapPendingMNB;
    std::map<CService, std::pair<int64_t, CFundamentalnodeVerification> > mapPendingMNV;
    CCriticalSection cs_mapPendingMNV;

    /// Set when fundamentalnodes are added, cleared when CGovernanceManager is notified
    bool fFundamentalnodesAdded;

    /// Set when fundamentalnodes are removed, cleared when CGovernanceManager is notified
    bool fFundamentalnodesRemoved;

    std::vector<uint256> vecDirtyGovernanceObjectHashes;

    int64_t nLastSentinelPingTime;

    friend class CFundamentalnodeSync;
    /// Find an entry
    CFundamentalnode* Find(const COutPoint& outpoint);

    bool GetFundamentalnodeScores(const uint256& nBlockHash, score_pair_vec_t& vecFundamentalnodeScoresRet, int nMinProtocol = 0);

    void SyncSingle(CNode* pnode, const COutPoint& outpoint, CConnman& connman);
    void SyncAll(CNode* pnode, CConnman& connman);

    void PushDsegFNInvs(CNode* pnode, const CFundamentalnode& fn);

public:
    // Keep track of all broadcasts I've seen
    std::map<uint256, std::pair<int64_t, CFundamentalnodeBroadcast> > mapSeenFundamentalnodeBroadcast;
    // Keep track of all pings I've seen
    std::map<uint256, CFundamentalnodePing> mapSeenFundamentalnodePing;
    // Keep track of all verifications I've seen
    std::map<uint256, CFundamentalnodeVerification> mapSeenFundamentalnodeVerification;
    // keep track of dsq count to prevent fundamentalnodes from gaming darksend queue
    int64_t nDsqCount;


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs);
        std::string strVersion;
        if(ser_action.ForRead()) {
            READWRITE(strVersion);
        }
        else {
            strVersion = SERIALIZATION_VERSION_STRING; 
            READWRITE(strVersion);
        }

        READWRITE(mapFundamentalnodes);
        READWRITE(mAskedUsForFundamentalnodeList);
        READWRITE(mWeAskedForFundamentalnodeList);
        READWRITE(mWeAskedForFundamentalnodeListEntry);
        READWRITE(mFnbRecoveryRequests);
        READWRITE(mFnbRecoveryGoodReplies);
        READWRITE(nLastSentinelPingTime);
        READWRITE(nDsqCount);

        READWRITE(mapSeenFundamentalnodeBroadcast);
        READWRITE(mapSeenFundamentalnodePing);
        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    CFundamentalnodeMan();

    /// Add an entry
    bool Add(CFundamentalnode &fn);

    /// Ask (source) node for fnb
    void AskForMN(CNode *pnode, const COutPoint& outpoint, CConnman& connman);
    void AskForFnb(CNode *pnode, const uint256 &hash);

    bool PoSeBan(const COutPoint &outpoint);
    bool AllowMixing(const COutPoint &outpoint);
    bool DisallowMixing(const COutPoint &outpoint);

    /// Check all Fundamentalnodes
    void Check();

    /// Check all Fundamentalnodes and remove inactive
    void CheckAndRemove(CConnman& connman);
    /// This is dummy overload to be used for dumping/loading fncache.dat
    void CheckAndRemove() {}

    /// Clear Fundamentalnode vector
    void Clear();

    /// Count Fundamentalnodes filtered by nProtocolVersion.
    /// Fundamentalnode nProtocolVersion should match or be above the one specified in param here.
    int CountFundamentalnodes(int nProtocolVersion = -1);
    /// Count enabled Fundamentalnodes filtered by nProtocolVersion.
    /// Fundamentalnode nProtocolVersion should match or be above the one specified in param here.
    int CountEnabled(int nProtocolVersion = -1);

    /// Count Fundamentalnodes by network type - NET_IPV4, NET_IPV6, NET_TOR
    // int CountByIP(int nNetworkType);

    void DsegUpdateFN(CNode* pnode, CConnman& connman);

    /// Versions of Find that are safe to use from outside the class
    bool Get(const COutPoint& outpoint, CFundamentalnode& fundamentalnodeRet);
    bool Has(const COutPoint& outpoint);

    bool GetFundamentalnodeInfo(const COutPoint& outpoint, fundamentalnode_info_t& fnInfoRet);
    bool GetFundamentalnodeInfo(const CPubKey& pubKeyFundamentalnode, fundamentalnode_info_t& fnInfoRet);
    bool GetFundamentalnodeInfo(const CScript& payee, fundamentalnode_info_t& fnInfoRet);

    /// Find an entry in the fundamentalnode list that is next to be paid
    bool GetNextFundamentalnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCountRet, fundamentalnode_info_t& fnInfoRet);
    /// Same as above but use current block height
    bool GetNextFundamentalnodeInQueueForPayment(bool fFilterSigTime, int& nCountRet, fundamentalnode_info_t& fnInfoRet);

    /// Find a random entry
    fundamentalnode_info_t FindRandomNotInVec(const std::vector<COutPoint> &vecToExclude, int nProtocolVersion = -1);

    std::map<COutPoint, CFundamentalnode> GetFullFundamentalnodeMap() { return mapFundamentalnodes; }

    bool GetFundamentalnodeRanks(rank_pair_vec_t& vecFundamentalnodeRanksRet, int nBlockHeight = -1, int nMinProtocol = 0);
    bool GetFundamentalnodeRank(const COutPoint &outpoint, int& nRankRet, int nBlockHeight = -1, int nMinProtocol = 0);

    void ProcessFundamentalnodeConnections(CConnman& connman);
    std::pair<CService, std::set<uint256> > PopScheduledFnbRequestConnection();
    void ProcessPendingFnbRequests(CConnman& connman);

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);

    void DoFullVerificationStep(CConnman& connman);
    void CheckSameAddr();
    bool SendVerifyRequest(const CAddress& addr, const std::vector<const CFundamentalnode*>& vSortedByAddr, CConnman& connman);
    void ProcessPendingFnvRequests(CConnman& connman);
    void SendVerifyReply(CNode* pnode, CFundamentalnodeVerification& fnv, CConnman& connman);
    void ProcessVerifyReply(CNode* pnode, CFundamentalnodeVerification& fnv);
    void ProcessVerifyBroadcast(CNode* pnode, const CFundamentalnodeVerification& fnv);

    /// Return the number of (unique) Fundamentalnodes
    int size() { return mapFundamentalnodes.size(); }

    std::string ToString() const;

    /// Perform complete check and only then update fundamentalnode list and maps using provided CFundamentalnodeBroadcast
    bool CheckFnbAndUpdateFundamentalnodeList(CNode* pfrom, CFundamentalnodeBroadcast fnb, int& nDos, CConnman& connman);
    bool IsFnbRecoveryRequested(const uint256& hash) { return mFnbRecoveryRequests.count(hash); }

    void UpdateLastPaid(const CBlockIndex* pindex);

    void AddDirtyGovernanceObjectHash(const uint256& nHash)
    {
        LOCK(cs);
        vecDirtyGovernanceObjectHashes.push_back(nHash);
    }

    std::vector<uint256> GetAndClearDirtyGovernanceObjectHashes()
    {
        LOCK(cs);
        std::vector<uint256> vecTmp = vecDirtyGovernanceObjectHashes;
        vecDirtyGovernanceObjectHashes.clear();
        return vecTmp;;
    }

    bool IsSentinelPingActive();
    void UpdateLastSentinelPingTime();
    bool AddGovernanceVote(const COutPoint& outpoint, uint256 nGovernanceObjectHash);
    void RemoveGovernanceObject(uint256 nGovernanceObjectHash);

    void CheckFundamentalnode(const CPubKey& pubKeyFundamentalnode, bool fForce);

    bool IsFundamentalnodePingedWithin(const COutPoint& outpoint, int nSeconds, int64_t nTimeToCheckAt = -1);
    void SetFundamentalnodeLastPing(const COutPoint& outpoint, const CFundamentalnodePing& fnp);

    void UpdatedBlockTip(const CBlockIndex *pindex);

    void WarnFundamentalnodeDaemonUpdates();

    /**
     * Called to notify CGovernanceManager that the fundamentalnode index has been updated.
     * Must be called while not holding the CFundamentalnodeMan::cs mutex
     */
    void NotifyFundamentalnodeUpdates(CConnman& connman);

};

#endif
