// Copyright (c) 2014-2017 The SecureTag Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activefundamentalnode.h"
#include "addrman.h"
#include "alert.h"
#include "clientversion.h"
#include "governance.h"
#include "fundamentalnode-payments.h"
#include "fundamentalnode-sync.h"
#include "fundamentalnodeman.h"
#include "messagesigner.h"
#include "netfulfilledman.h"
#include "netmessagemaker.h"
#ifdef ENABLE_WALLET
#include "privatesend-client.h"
#endif // ENABLE_WALLET
#include "script/standard.h"
#include "ui_interface.h"
#include "util.h"
#include "warnings.h"

/** Fundamentalnode manager */
CFundamentalnodeMan fnodeman;

const std::string CFundamentalnodeMan::SERIALIZATION_VERSION_STRING = "CFundamentalnodeMan-Version-8";
const int CFundamentalnodeMan::LAST_PAID_SCAN_BLOCKS = 100;

struct CompareLastPaidBlock
{
    bool operator()(const std::pair<int, const CFundamentalnode*>& t1,
                    const std::pair<int, const CFundamentalnode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->outpoint < t2.second->outpoint);
    }
};

struct CompareScoreMN
{
    bool operator()(const std::pair<arith_uint256, const CFundamentalnode*>& t1,
                    const std::pair<arith_uint256, const CFundamentalnode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->outpoint < t2.second->outpoint);
    }
};

struct CompareByAddr

{
    bool operator()(const CFundamentalnode* t1,
                    const CFundamentalnode* t2) const
    {
        return t1->addr < t2->addr;
    }
};

CFundamentalnodeMan::CFundamentalnodeMan():
    cs(),
    mapFundamentalnodes(),
    mAskedUsForFundamentalnodeList(),
    mWeAskedForFundamentalnodeList(),
    mWeAskedForFundamentalnodeListEntry(),
    mWeAskedForVerification(),
    mFnbRecoveryRequests(),
    mFnbRecoveryGoodReplies(),
    listScheduledFnbRequestConnections(),
    fFundamentalnodesAdded(false),
    fFundamentalnodesRemoved(false),
    vecDirtyGovernanceObjectHashes(),
    nLastSentinelPingTime(0),
    mapSeenFundamentalnodeBroadcast(),
    mapSeenFundamentalnodePing(),
    nDsqCount(0)
{}

bool CFundamentalnodeMan::Add(CFundamentalnode &fn)
{
    LOCK(cs);

    if (Has(fn.outpoint)) return false;

    LogPrint("fundamentalnode", "CFundamentalnodeMan::Add -- Adding new Fundamentalnode: addr=%s, %i now\n", fn.addr.ToString(), size() + 1);
    mapFundamentalnodes[fn.outpoint] = fn;
    fFundamentalnodesAdded = true;
    return true;
}

void CFundamentalnodeMan::AskForMN(CNode* pnode, const COutPoint& outpoint, CConnman& connman)
{
    if(!pnode) return;

    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    LOCK(cs);

    CService addrSquashed = Params().AllowMultiplePorts() ? (CService)pnode->addr : CService(pnode->addr, 0);
    auto it1 = mWeAskedForFundamentalnodeListEntry.find(outpoint);
    if (it1 != mWeAskedForFundamentalnodeListEntry.end()) {
        auto it2 = it1->second.find(addrSquashed);
        if (it2 != it1->second.end()) {
            if (GetTime() < it2->second) {
                // we've asked recently, should not repeat too often or we could get banned
                return;
            }
            // we asked this node for this outpoint but it's ok to ask again already
            LogPrintf("CFundamentalnodeMan::AskForMN -- Asking same peer %s for missing fundamentalnode entry again: %s\n", addrSquashed.ToString(), outpoint.ToStringShort());
        } else {
            // we already asked for this outpoint but not this node
            LogPrintf("CFundamentalnodeMan::AskForMN -- Asking new peer %s for missing fundamentalnode entry: %s\n", addrSquashed.ToString(), outpoint.ToStringShort());
        }
    } else {
        // we never asked any node for this outpoint
        LogPrintf("CFundamentalnodeMan::AskForMN -- Asking peer %s for missing fundamentalnode entry for the first time: %s\n", addrSquashed.ToString(), outpoint.ToStringShort());
    }
    mWeAskedForFundamentalnodeListEntry[outpoint][addrSquashed] = GetTime() + DSEGFN_UPDATE_SECONDS;

    if (pnode->GetSendVersion() == 70208) {
        connman.PushMessage(pnode, msgMaker.Make(NetMsgType::DSEGFN, CTxIn(outpoint)));
    } else {
        connman.PushMessage(pnode, msgMaker.Make(NetMsgType::DSEGFN, outpoint));
    }
}

bool CFundamentalnodeMan::AllowMixing(const COutPoint &outpoint)
{
    LOCK(cs);
    CFundamentalnode* pfn = Find(outpoint);
    if (!pfn) {
        return false;
    }
    nDsqCount++;
    pfn->nLastDsq = nDsqCount;
    pfn->fAllowMixingTx = true;

    return true;
}

bool CFundamentalnodeMan::DisallowMixing(const COutPoint &outpoint)
{
    LOCK(cs);
    CFundamentalnode* pfn = Find(outpoint);
    if (!pfn) {
        return false;
    }
    pfn->fAllowMixingTx = false;

    return true;
}

bool CFundamentalnodeMan::PoSeBan(const COutPoint &outpoint)
{
    LOCK(cs);
    CFundamentalnode* pfn = Find(outpoint);
    if (!pfn) {
        return false;
    }
    pfn->PoSeBan();

    return true;
}

void CFundamentalnodeMan::Check()
{
    LOCK2(cs_main, cs);

    LogPrint("fundamentalnode", "CFundamentalnodeMan::Check -- nLastSentinelPingTime=%d, IsSentinelPingActive()=%d\n", nLastSentinelPingTime, IsSentinelPingActive());

    for (auto& fnpair : mapFundamentalnodes) {
        // NOTE: internally it checks only every FUNDAMENTALNODE_CHECK_SECONDS seconds
        // since the last time, so expect some MNs to skip this
        fnpair.second.Check();
    }
}

void CFundamentalnodeMan::CheckAndRemove(CConnman& connman)
{
    if(!fundamentalnodeSync.IsFundamentalnodeListSynced()) return;

    LogPrintf("CFundamentalnodeMan::CheckAndRemove\n");

    {
        // Need LOCK2 here to ensure consistent locking order because code below locks cs_main
        // in CheckFnbAndUpdateFundamentalnodeList()
        LOCK2(cs_main, cs);

        Check();

        // Remove spent fundamentalnodes, prepare structures and make requests to reasure the state of inactive ones
        rank_pair_vec_t vecFundamentalnodeRanks;
        // ask for up to MNB_RECOVERY_MAX_ASK_ENTRIES fundamentalnode entries at a time
        int nAskForFnbRecovery = MNB_RECOVERY_MAX_ASK_ENTRIES;
        std::map<COutPoint, CFundamentalnode>::iterator it = mapFundamentalnodes.begin();
        while (it != mapFundamentalnodes.end()) {
            CFundamentalnodeBroadcast fnb = CFundamentalnodeBroadcast(it->second);
            uint256 hash = fnb.GetHash();
            // If collateral was spent ...
            if (it->second.IsOutpointSpent()) {
                LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckAndRemove -- Removing Fundamentalnode: %s  addr=%s  %i now\n", it->second.GetStateString(), it->second.addr.ToString(), size() - 1);

                // erase all of the broadcasts we've seen from this txin, ...
                mapSeenFundamentalnodeBroadcast.erase(hash);
                mWeAskedForFundamentalnodeListEntry.erase(it->first);

                // and finally remove it from the list
                it->second.FlagGovernanceItemsAsDirty();
                mapFundamentalnodes.erase(it++);
                fFundamentalnodesRemoved = true;
            } else {
                bool fAsk = (nAskForFnbRecovery > 0) &&
                            fundamentalnodeSync.IsSynced() &&
                            it->second.IsNewStartRequired() &&
                            !IsFnbRecoveryRequested(hash) &&
                            !IsArgSet("-connect");
                if(fAsk) {
                    // this fn is in a non-recoverable state and we haven't asked other nodes yet
                    std::set<CService> setRequested;
                    // calulate only once and only when it's needed
                    if(vecFundamentalnodeRanks.empty()) {
                        int nRandomBlockHeight = GetRandInt(nCachedBlockHeight);
                        GetFundamentalnodeRanks(vecFundamentalnodeRanks, nRandomBlockHeight);
                    }
                    bool fAskedForFnbRecovery = false;
                    // ask first MNB_RECOVERY_QUORUM_TOTAL fundamentalnodes we can connect to and we haven't asked recently
                    for(int i = 0; setRequested.size() < MNB_RECOVERY_QUORUM_TOTAL && i < (int)vecFundamentalnodeRanks.size(); i++) {
                        // avoid banning
                        if(mWeAskedForFundamentalnodeListEntry.count(it->first) && mWeAskedForFundamentalnodeListEntry[it->first].count(vecFundamentalnodeRanks[i].second.addr)) continue;
                        // didn't ask recently, ok to ask now
                        CService addr = vecFundamentalnodeRanks[i].second.addr;
                        setRequested.insert(addr);
                        listScheduledFnbRequestConnections.push_back(std::make_pair(addr, hash));
                        fAskedForFnbRecovery = true;
                    }
                    if(fAskedForFnbRecovery) {
                        LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckAndRemove -- Recovery initiated, fundamentalnode=%s\n", it->first.ToStringShort());
                        nAskForFnbRecovery--;
                    }
                    // wait for fnb recovery replies for MNB_RECOVERY_WAIT_SECONDS seconds
                    mFnbRecoveryRequests[hash] = std::make_pair(GetTime() + MNB_RECOVERY_WAIT_SECONDS, setRequested);
                }
                ++it;
            }
        }

        // proces replies for FUNDAMENTALNODE_NEW_START_REQUIRED fundamentalnodes
        LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckAndRemove -- mFnbRecoveryGoodReplies size=%d\n", (int)mFnbRecoveryGoodReplies.size());
        std::map<uint256, std::vector<CFundamentalnodeBroadcast> >::iterator itFnbReplies = mFnbRecoveryGoodReplies.begin();
        while(itFnbReplies != mFnbRecoveryGoodReplies.end()){
            if(mFnbRecoveryRequests[itFnbReplies->first].first < GetTime()) {
                // all nodes we asked should have replied now
                if(itFnbReplies->second.size() >= MNB_RECOVERY_QUORUM_REQUIRED) {
                    // majority of nodes we asked agrees that this fn doesn't require new fnb, reprocess one of new fnbs
                    LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckAndRemove -- reprocessing fnb, fundamentalnode=%s\n", itFnbReplies->second[0].outpoint.ToStringShort());
                    // mapSeenFundamentalnodeBroadcast.erase(itFnbReplies->first);
                    int nDos;
                    itFnbReplies->second[0].fRecovery = true;
                    CheckFnbAndUpdateFundamentalnodeList(NULL, itFnbReplies->second[0], nDos, connman);
                }
                LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckAndRemove -- removing fnb recovery reply, fundamentalnode=%s, size=%d\n", itFnbReplies->second[0].outpoint.ToStringShort(), (int)itFnbReplies->second.size());
                mFnbRecoveryGoodReplies.erase(itFnbReplies++);
            } else {
                ++itFnbReplies;
            }
        }
    }
    {
        // no need for cm_main below
        LOCK(cs);

        auto itFnbRequest = mFnbRecoveryRequests.begin();
        while(itFnbRequest != mFnbRecoveryRequests.end()){
            // Allow this fnb to be re-verified again after MNB_RECOVERY_RETRY_SECONDS seconds
            // if fn is still in FUNDAMENTALNODE_NEW_START_REQUIRED state.
            if(GetTime() - itFnbRequest->second.first > MNB_RECOVERY_RETRY_SECONDS) {
                mFnbRecoveryRequests.erase(itFnbRequest++);
            } else {
                ++itFnbRequest;
            }
        }

        // check who's asked for the Fundamentalnode list
        auto it1 = mAskedUsForFundamentalnodeList.begin();
        while(it1 != mAskedUsForFundamentalnodeList.end()){
            if((*it1).second < GetTime()) {
                mAskedUsForFundamentalnodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check who we asked for the Fundamentalnode list
        it1 = mWeAskedForFundamentalnodeList.begin();
        while(it1 != mWeAskedForFundamentalnodeList.end()){
            if((*it1).second < GetTime()){
                mWeAskedForFundamentalnodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check which Fundamentalnodes we've asked for
        auto it2 = mWeAskedForFundamentalnodeListEntry.begin();
        while(it2 != mWeAskedForFundamentalnodeListEntry.end()){
            auto it3 = it2->second.begin();
            while(it3 != it2->second.end()){
                if(it3->second < GetTime()){
                    it2->second.erase(it3++);
                } else {
                    ++it3;
                }
            }
            if(it2->second.empty()) {
                mWeAskedForFundamentalnodeListEntry.erase(it2++);
            } else {
                ++it2;
            }
        }

        auto it3 = mWeAskedForVerification.begin();
        while(it3 != mWeAskedForVerification.end()){
            if(it3->second.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS) {
                mWeAskedForVerification.erase(it3++);
            } else {
                ++it3;
            }
        }

        // NOTE: do not expire mapSeenFundamentalnodeBroadcast entries here, clean them on fnb updates!

        // remove expired mapSeenFundamentalnodePing
        std::map<uint256, CFundamentalnodePing>::iterator it4 = mapSeenFundamentalnodePing.begin();
        while(it4 != mapSeenFundamentalnodePing.end()){
            if((*it4).second.IsExpired()) {
                LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckAndRemove -- Removing expired Fundamentalnode ping: hash=%s\n", (*it4).second.GetHash().ToString());
                mapSeenFundamentalnodePing.erase(it4++);
            } else {
                ++it4;
            }
        }

        // remove expired mapSeenFundamentalnodeVerification
        std::map<uint256, CFundamentalnodeVerification>::iterator itv2 = mapSeenFundamentalnodeVerification.begin();
        while(itv2 != mapSeenFundamentalnodeVerification.end()){
            if((*itv2).second.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS){
                LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckAndRemove -- Removing expired Fundamentalnode verification: hash=%s\n", (*itv2).first.ToString());
                mapSeenFundamentalnodeVerification.erase(itv2++);
            } else {
                ++itv2;
            }
        }

        LogPrintf("CFundamentalnodeMan::CheckAndRemove -- %s\n", ToString());
    }

    if(fFundamentalnodesRemoved) {
        NotifyFundamentalnodeUpdates(connman);
    }
}

void CFundamentalnodeMan::Clear()
{
    LOCK(cs);
    mapFundamentalnodes.clear();
    mAskedUsForFundamentalnodeList.clear();
    mWeAskedForFundamentalnodeList.clear();
    mWeAskedForFundamentalnodeListEntry.clear();
    mapSeenFundamentalnodeBroadcast.clear();
    mapSeenFundamentalnodePing.clear();
    nDsqCount = 0;
    nLastSentinelPingTime = 0;
}

int CFundamentalnodeMan::CountFundamentalnodes(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? fnpayments.GetMinFundamentalnodePaymentsProto() : nProtocolVersion;

    for (const auto& fnpair : mapFundamentalnodes) {
        if(fnpair.second.nProtocolVersion < nProtocolVersion) continue;
        nCount++;
    }

    return nCount;
}

int CFundamentalnodeMan::CountEnabled(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? fnpayments.GetMinFundamentalnodePaymentsProto() : nProtocolVersion;

    for (const auto& fnpair : mapFundamentalnodes) {
        if(fnpair.second.nProtocolVersion < nProtocolVersion || !fnpair.second.IsEnabled()) continue;
        nCount++;
    }

    return nCount;
}

/* Only IPv4 fundamentalnodes are allowed in 12.1, saving this for later
int CFundamentalnodeMan::CountByIP(int nNetworkType)
{
    LOCK(cs);
    int nNodeCount = 0;

    for (const auto& fnpair : mapFundamentalnodes)
        if ((nNetworkType == NET_IPV4 && fnpair.second.addr.IsIPv4()) ||
            (nNetworkType == NET_TOR  && fnpair.second.addr.IsTor())  ||
            (nNetworkType == NET_IPV6 && fnpair.second.addr.IsIPv6())) {
                nNodeCount++;
        }

    return nNodeCount;
}
*/

void CFundamentalnodeMan::DsegUpdateFN(CNode* pnode, CConnman& connman)
{
    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    LOCK(cs);

    CService addrSquashed = Params().AllowMultiplePorts() ? (CService)pnode->addr : CService(pnode->addr, 0);
    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())) {
            auto it = mWeAskedForFundamentalnodeList.find(addrSquashed);
            if(it != mWeAskedForFundamentalnodeList.end() && GetTime() < (*it).second) {
                LogPrintf("CFundamentalnodeMan::DsegUpdate -- we already asked %s for the list; skipping...\n", addrSquashed.ToString());
                return;
            }
        }
    }

    if (pnode->GetSendVersion() == 70208) {
        connman.PushMessage(pnode, msgMaker.Make(NetMsgType::DSEGFN, CTxIn()));
    } else {
        connman.PushMessage(pnode, msgMaker.Make(NetMsgType::DSEGFN, COutPoint()));
    }
    int64_t askAgain = GetTime() + DSEGFN_UPDATE_SECONDS;
    mWeAskedForFundamentalnodeList[addrSquashed] = askAgain;

    LogPrint("fundamentalnode", "CFundamentalnodeMan::DsegUpdate -- asked %s for the list\n", pnode->addr.ToString());
}

CFundamentalnode* CFundamentalnodeMan::Find(const COutPoint &outpoint)
{
    LOCK(cs);
    auto it = mapFundamentalnodes.find(outpoint);
    return it == mapFundamentalnodes.end() ? NULL : &(it->second);
}

bool CFundamentalnodeMan::Get(const COutPoint& outpoint, CFundamentalnode& fundamentalnodeRet)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    auto it = mapFundamentalnodes.find(outpoint);
    if (it == mapFundamentalnodes.end()) {
        return false;
    }

    fundamentalnodeRet = it->second;
    return true;
}

bool CFundamentalnodeMan::GetFundamentalnodeInfo(const COutPoint& outpoint, fundamentalnode_info_t& fnInfoRet)
{
    LOCK(cs);
    auto it = mapFundamentalnodes.find(outpoint);
    if (it == mapFundamentalnodes.end()) {
        return false;
    }
    fnInfoRet = it->second.GetInfo();
    return true;
}

bool CFundamentalnodeMan::GetFundamentalnodeInfo(const CPubKey& pubKeyFundamentalnode, fundamentalnode_info_t& fnInfoRet)
{
    LOCK(cs);
    for (const auto& fnpair : mapFundamentalnodes) {
        if (fnpair.second.pubKeyFundamentalnode == pubKeyFundamentalnode) {
            fnInfoRet = fnpair.second.GetInfo();
            return true;
        }
    }
    return false;
}

bool CFundamentalnodeMan::GetFundamentalnodeInfo(const CScript& payee, fundamentalnode_info_t& fnInfoRet)
{
    LOCK(cs);
    for (const auto& fnpair : mapFundamentalnodes) {
        CScript scriptCollateralAddress = GetScriptForDestination(fnpair.second.pubKeyCollateralAddress.GetID());
        if (scriptCollateralAddress == payee) {
            fnInfoRet = fnpair.second.GetInfo();
            return true;
        }
    }
    return false;
}

bool CFundamentalnodeMan::Has(const COutPoint& outpoint)
{
    LOCK(cs);
    return mapFundamentalnodes.find(outpoint) != mapFundamentalnodes.end();
}

//
// Deterministically select the oldest/best fundamentalnode to pay on the network
//
bool CFundamentalnodeMan::GetNextFundamentalnodeInQueueForPayment(bool fFilterSigTime, int& nCountRet, fundamentalnode_info_t& fnInfoRet)
{
    return GetNextFundamentalnodeInQueueForPayment(nCachedBlockHeight, fFilterSigTime, nCountRet, fnInfoRet);
}

bool CFundamentalnodeMan::GetNextFundamentalnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCountRet, fundamentalnode_info_t& fnInfoRet)
{
    fnInfoRet = fundamentalnode_info_t();
    nCountRet = 0;

    if (!fundamentalnodeSync.IsWinnersListSynced()) {
        // without winner list we can't reliably find the next winner anyway
        return false;
    }

    // Need LOCK2 here to ensure consistent locking order because the GetBlockHash call below locks cs_main
    LOCK2(cs_main,cs);

    std::vector<std::pair<int, const CFundamentalnode*> > vecFundamentalnodeLastPaid;

    /*
        Make a vector with all of the last paid times
    */

    int nFnCount = CountFundamentalnodes();

    for (const auto& fnpair : mapFundamentalnodes) {
        if(!fnpair.second.IsValidForPayment()) continue;

        //check protocol version
        if(fnpair.second.nProtocolVersion < fnpayments.GetMinFundamentalnodePaymentsProto()) continue;

        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if(fnpayments.IsScheduled(fnpair.second, nBlockHeight)) continue;

        //it's too new, wait for a cycle
        if(fFilterSigTime && fnpair.second.sigTime + (nFnCount*2.6*60) > GetAdjustedTime()) continue;

        //make sure it has at least as many confirmations as there are fundamentalnodes
        if(GetUTXOConfirmations(fnpair.first) < nFnCount) continue;

        vecFundamentalnodeLastPaid.push_back(std::make_pair(fnpair.second.GetLastPaidBlock(), &fnpair.second));
    }

    nCountRet = (int)vecFundamentalnodeLastPaid.size();

    //when the network is in the process of upgrading, don't penalize nodes that recently restarted
    if(fFilterSigTime && nCountRet < nFnCount/3)
        return GetNextFundamentalnodeInQueueForPayment(nBlockHeight, false, nCountRet, fnInfoRet);

    // Sort them low to high
    sort(vecFundamentalnodeLastPaid.begin(), vecFundamentalnodeLastPaid.end(), CompareLastPaidBlock());

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight - 101)) {
        LogPrintf("CFundamentalnode::GetNextFundamentalnodeInQueueForPayment -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", nBlockHeight - 101);
        return false;
    }
    // Look at 1/10 of the oldest nodes (by last payment), calculate their scores and pay the best one
    //  -- This doesn't look at who is being paid in the +8-10 blocks, allowing for double payments very rarely
    //  -- 1/100 payments should be a double payment on mainnet - (1/(3000/10))*2
    //  -- (chance per block * chances before IsScheduled will fire)
    int nTenthNetwork = nFnCount/10;
    int nCountTenth = 0;
    arith_uint256 nHighest = 0;
    const CFundamentalnode *pBestFundamentalnode = NULL;
    for (const auto& s : vecFundamentalnodeLastPaid) {
        arith_uint256 nScore = s.second->CalculateScore(blockHash);
        if(nScore > nHighest){
            nHighest = nScore;
            pBestFundamentalnode = s.second;
        }
        nCountTenth++;
        if(nCountTenth >= nTenthNetwork) break;
    }
    if (pBestFundamentalnode) {
        fnInfoRet = pBestFundamentalnode->GetInfo();
    }
    return fnInfoRet.fInfoValid;
}

fundamentalnode_info_t CFundamentalnodeMan::FindRandomNotInVec(const std::vector<COutPoint> &vecToExclude, int nProtocolVersion)
{
    LOCK(cs);

    nProtocolVersion = nProtocolVersion == -1 ? fnpayments.GetMinFundamentalnodePaymentsProto() : nProtocolVersion;

    int nCountEnabled = CountEnabled(nProtocolVersion);
    int nCountNotExcluded = nCountEnabled - vecToExclude.size();

    LogPrintf("CFundamentalnodeMan::FindRandomNotInVec -- %d enabled fundamentalnodes, %d fundamentalnodes to choose from\n", nCountEnabled, nCountNotExcluded);
    if(nCountNotExcluded < 1) return fundamentalnode_info_t();

    // fill a vector of pointers
    std::vector<const CFundamentalnode*> vpFundamentalnodesShuffled;
    for (const auto& fnpair : mapFundamentalnodes) {
        vpFundamentalnodesShuffled.push_back(&fnpair.second);
    }

    FastRandomContext insecure_rand;
    // shuffle pointers
    std::random_shuffle(vpFundamentalnodesShuffled.begin(), vpFundamentalnodesShuffled.end(), insecure_rand);
    bool fExclude;

    // loop through
    for (const auto& pfn : vpFundamentalnodesShuffled) {
        if(pfn->nProtocolVersion < nProtocolVersion || !pfn->IsEnabled()) continue;
        fExclude = false;
        for (const auto& outpointToExclude : vecToExclude) {
            if(pfn->outpoint == outpointToExclude) {
                fExclude = true;
                break;
            }
        }
        if(fExclude) continue;
        // found the one not in vecToExclude
        LogPrint("fundamentalnode", "CFundamentalnodeMan::FindRandomNotInVec -- found, fundamentalnode=%s\n", pfn->outpoint.ToStringShort());
        return pfn->GetInfo();
    }

    LogPrint("fundamentalnode", "CFundamentalnodeMan::FindRandomNotInVec -- failed\n");
    return fundamentalnode_info_t();
}

bool CFundamentalnodeMan::GetFundamentalnodeScores(const uint256& nBlockHash, CFundamentalnodeMan::score_pair_vec_t& vecFundamentalnodeScoresRet, int nMinProtocol)
{
    vecFundamentalnodeScoresRet.clear();

    if (!fundamentalnodeSync.IsFundamentalnodeListSynced())
        return false;

    AssertLockHeld(cs);

    if (mapFundamentalnodes.empty())
        return false;

    // calculate scores
    for (const auto& fnpair : mapFundamentalnodes) {
        if (fnpair.second.nProtocolVersion >= nMinProtocol) {
            vecFundamentalnodeScoresRet.push_back(std::make_pair(fnpair.second.CalculateScore(nBlockHash), &fnpair.second));
        }
    }

    sort(vecFundamentalnodeScoresRet.rbegin(), vecFundamentalnodeScoresRet.rend(), CompareScoreMN());
    return !vecFundamentalnodeScoresRet.empty();
}

bool CFundamentalnodeMan::GetFundamentalnodeRank(const COutPoint& outpoint, int& nRankRet, int nBlockHeight, int nMinProtocol)
{
    nRankRet = -1;

    if (!fundamentalnodeSync.IsFundamentalnodeListSynced())
        return false;

    // make sure we know about this block
    uint256 nBlockHash = uint256();
    if (!GetBlockHash(nBlockHash, nBlockHeight)) {
        LogPrintf("CFundamentalnodeMan::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, nBlockHeight);
        return false;
    }

    LOCK(cs);

    score_pair_vec_t vecFundamentalnodeScores;
    if (!GetFundamentalnodeScores(nBlockHash, vecFundamentalnodeScores, nMinProtocol))
        return false;

    int nRank = 0;
    for (const auto& scorePair : vecFundamentalnodeScores) {
        nRank++;
        if(scorePair.second->outpoint == outpoint) {
            nRankRet = nRank;
            return true;
        }
    }

    return false;
}

bool CFundamentalnodeMan::GetFundamentalnodeRanks(CFundamentalnodeMan::rank_pair_vec_t& vecFundamentalnodeRanksRet, int nBlockHeight, int nMinProtocol)
{
    vecFundamentalnodeRanksRet.clear();

    if (!fundamentalnodeSync.IsFundamentalnodeListSynced())
        return false;

    // make sure we know about this block
    uint256 nBlockHash = uint256();
    if (!GetBlockHash(nBlockHash, nBlockHeight)) {
        LogPrintf("CFundamentalnodeMan::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, nBlockHeight);
        return false;
    }

    LOCK(cs);

    score_pair_vec_t vecFundamentalnodeScores;
    if (!GetFundamentalnodeScores(nBlockHash, vecFundamentalnodeScores, nMinProtocol))
        return false;

    int nRank = 0;
    for (const auto& scorePair : vecFundamentalnodeScores) {
        nRank++;
        vecFundamentalnodeRanksRet.push_back(std::make_pair(nRank, *scorePair.second));
    }

    return true;
}

void CFundamentalnodeMan::ProcessFundamentalnodeConnections(CConnman& connman)
{
    //we don't care about this for regtest
    if(Params().NetworkIDString() == CBaseChainParams::REGTEST) return;

    connman.ForEachNode(CConnman::AllNodes, [](CNode* pnode) {

        if(pnode->fFundamentalnode) {

            LogPrintf("Closing Fundamentalnode connection: peer=%d, addr=%s\n", pnode->id, pnode->addr.ToString());
            pnode->fDisconnect = true;
        }
    });
}

std::pair<CService, std::set<uint256> > CFundamentalnodeMan::PopScheduledFnbRequestConnection()
{
    LOCK(cs);
    if(listScheduledFnbRequestConnections.empty()) {
        return std::make_pair(CService(), std::set<uint256>());
    }

    std::set<uint256> setResult;

    listScheduledFnbRequestConnections.sort();
    std::pair<CService, uint256> pairFront = listScheduledFnbRequestConnections.front();

    // squash hashes from requests with the same CService as the first one into setResult
    std::list< std::pair<CService, uint256> >::iterator it = listScheduledFnbRequestConnections.begin();
    while(it != listScheduledFnbRequestConnections.end()) {
        if(pairFront.first == it->first) {
            setResult.insert(it->second);
            it = listScheduledFnbRequestConnections.erase(it);
        } else {
            // since list is sorted now, we can be sure that there is no more hashes left
            // to ask for from this addr
            break;
        }
    }
    return std::make_pair(pairFront.first, setResult);
}

void CFundamentalnodeMan::ProcessPendingFnbRequests(CConnman& connman)
{
    std::pair<CService, std::set<uint256> > p = PopScheduledFnbRequestConnection();
    if (!(p.first == CService() || p.second.empty())) {
        if (connman.IsFundamentalnodeOrDisconnectRequested(p.first)) return;
        mapPendingMNB.insert(std::make_pair(p.first, std::make_pair(GetTime(), p.second)));
        connman.AddPendingFundamentalnode(p.first);
    }

    std::map<CService, std::pair<int64_t, std::set<uint256> > >::iterator itPendingMNB = mapPendingMNB.begin();
    while (itPendingMNB != mapPendingMNB.end()) {
        bool fDone = connman.ForNode(itPendingMNB->first, [&](CNode* pnode) {
            // compile request vector
            std::vector<CInv> vToFetch;
            std::set<uint256>& setHashes = itPendingMNB->second.second;
            std::set<uint256>::iterator it = setHashes.begin();
            while(it != setHashes.end()) {
                if(*it != uint256()) {
                    vToFetch.push_back(CInv(MSG_FUNDAMENTALNODE_ANNOUNCE, *it));
                    LogPrint("fundamentalnode", "-- asking for fnb %s from addr=%s\n", it->ToString(), pnode->addr.ToString());
                }
                ++it;
            }

            // ask for data
            CNetMsgMaker msgMaker(pnode->GetSendVersion());
            connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
            return true;
        });

        int64_t nTimeAdded = itPendingMNB->second.first;
        if (fDone || (GetTime() - nTimeAdded > 15)) {
            if (!fDone) {
                LogPrint("fundamentalnode", "CFundamentalnodeMan::%s -- failed to connect to %s\n", __func__, itPendingMNB->first.ToString());
            }
            mapPendingMNB.erase(itPendingMNB++);
        } else {
            ++itPendingMNB;
        }
    }
    LogPrint("fundamentalnode", "%s -- mapPendingMNB size: %d\n", __func__, mapPendingMNB.size());
}

void CFundamentalnodeMan::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if(fLiteMode) return; // disable all SecureTag specific functionality

    if (strCommand == NetMsgType::MNANNOUNCE) { //Fundamentalnode Broadcast

        CFundamentalnodeBroadcast fnb;
        vRecv >> fnb;

        pfrom->setAskFor.erase(fnb.GetHash());

        if(!fundamentalnodeSync.IsBlockchainSynced()) return;

        LogPrint("fundamentalnode", "MNANNOUNCE -- Fundamentalnode announce, fundamentalnode=%s\n", fnb.outpoint.ToStringShort());

        int nDos = 0;

        if (CheckFnbAndUpdateFundamentalnodeList(pfrom, fnb, nDos, connman)) {
            // use announced Fundamentalnode as a peer
            connman.AddNewAddress(CAddress(fnb.addr, NODE_NETWORK), pfrom->addr, 2*60*60);
        } else if(nDos > 0) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), nDos);
        }

        if(fFundamentalnodesAdded) {
            NotifyFundamentalnodeUpdates(connman);
        }
    } else if (strCommand == NetMsgType::MNPING) { //Fundamentalnode Ping

        CFundamentalnodePing fnp;
        vRecv >> fnp;

        uint256 nHash = fnp.GetHash();

        pfrom->setAskFor.erase(nHash);

        if(!fundamentalnodeSync.IsBlockchainSynced()) return;

        LogPrint("fundamentalnode", "MNPING -- Fundamentalnode ping, fundamentalnode=%s\n", fnp.fundamentalnodeOutpoint.ToStringShort());

        // Need LOCK2 here to ensure consistent locking order because the CheckAndUpdate call below locks cs_main
        LOCK2(cs_main, cs);

        if(mapSeenFundamentalnodePing.count(nHash)) return; //seen
        mapSeenFundamentalnodePing.insert(std::make_pair(nHash, fnp));

        LogPrint("fundamentalnode", "MNPING -- Fundamentalnode ping, fundamentalnode=%s new\n", fnp.fundamentalnodeOutpoint.ToStringShort());

        // see if we have this Fundamentalnode
        CFundamentalnode* pfn = Find(fnp.fundamentalnodeOutpoint);

        if(pfn && fnp.fSentinelIsCurrent)
            UpdateLastSentinelPingTime();

        // too late, new MNANNOUNCE is required
        if(pfn && pfn->IsNewStartRequired()) return;

        int nDos = 0;
        if(fnp.CheckAndUpdate(pfn, false, nDos, connman)) return;

        if(nDos > 0) {
            // if anything significant failed, mark that node
            Misbehaving(pfrom->GetId(), nDos);
        } else if(pfn != NULL) {
            // nothing significant failed, fn is a known one too
            return;
        }

        // something significant is broken or fn is unknown,
        // we might have to ask for a fundamentalnode entry once
        AskForMN(pfrom, fnp.fundamentalnodeOutpoint, connman);

    } else if (strCommand == NetMsgType::DSEGFN) { //Get Fundamentalnode list or specific entry
        // Ignore such requests until we are fully synced.
        // We could start processing this after fundamentalnode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!fundamentalnodeSync.IsSynced()) return;

        COutPoint fundamentalnodeOutpoint;

        if (pfrom->nVersion == 70208) {
            CTxIn vin;
            vRecv >> vin;
            fundamentalnodeOutpoint = vin.prevout;
        } else {
            vRecv >> fundamentalnodeOutpoint;
        }

        LogPrint("fundamentalnode", "DSEGFN -- Fundamentalnode list, fundamentalnode=%s\n", fundamentalnodeOutpoint.ToStringShort());

        if(fundamentalnodeOutpoint.IsNull()) {
            SyncAll(pfrom, connman);
        } else {
            SyncSingle(pfrom, fundamentalnodeOutpoint, connman);
        }

    } else if (strCommand == NetMsgType::MNVERIFY) { // Fundamentalnode Verify

        // Need LOCK2 here to ensure consistent locking order because all functions below call GetBlockHash which locks cs_main
        LOCK2(cs_main, cs);

        CFundamentalnodeVerification fnv;
        vRecv >> fnv;

        pfrom->setAskFor.erase(fnv.GetHash());

        if(!fundamentalnodeSync.IsFundamentalnodeListSynced()) return;

        if(fnv.vchSig1.empty()) {
            // CASE 1: someone asked me to verify myself /IP we are using/
            SendVerifyReply(pfrom, fnv, connman);
        } else if (fnv.vchSig2.empty()) {
            // CASE 2: we _probably_ got verification we requested from some fundamentalnode
            ProcessVerifyReply(pfrom, fnv);
        } else {
            // CASE 3: we _probably_ got verification broadcast signed by some fundamentalnode which verified another one
            ProcessVerifyBroadcast(pfrom, fnv);
        }
    }
}

void CFundamentalnodeMan::SyncSingle(CNode* pnode, const COutPoint& outpoint, CConnman& connman)
{
    // do not provide any data until our node is synced
    if (!fundamentalnodeSync.IsSynced()) return;

    LOCK(cs);

    auto it = mapFundamentalnodes.find(outpoint);

    if(it != mapFundamentalnodes.end()) {
        if (it->second.addr.IsRFC1918() || it->second.addr.IsLocal()) return; // do not send local network fundamentalnode
        // NOTE: send fundamentalnode regardless of its current state, the other node will need it to verify old votes.
        LogPrint("fundamentalnode", "CFundamentalnodeMan::%s -- Sending Fundamentalnode entry: fundamentalnode=%s  addr=%s\n", __func__, outpoint.ToStringShort(), it->second.addr.ToString());
        PushDsegFNInvs(pnode, it->second);
        LogPrintf("CFundamentalnodeMan::%s -- Sent 1 Fundamentalnode inv to peer=%d\n", __func__, pnode->id);
    }
}

void CFundamentalnodeMan::SyncAll(CNode* pnode, CConnman& connman)
{
    // do not provide any data until our node is synced
    if (!fundamentalnodeSync.IsSynced()) return;

    // local network
    bool isLocal = (pnode->addr.IsRFC1918() || pnode->addr.IsLocal());

    CService addrSquashed = Params().AllowMultiplePorts() ? (CService)pnode->addr : CService(pnode->addr, 0);
    // should only ask for this once
    if(!isLocal && Params().NetworkIDString() == CBaseChainParams::MAIN) {
        LOCK2(cs_main, cs);
        auto it = mAskedUsForFundamentalnodeList.find(addrSquashed);
        if (it != mAskedUsForFundamentalnodeList.end() && it->second > GetTime()) {
            Misbehaving(pnode->GetId(), 34);
            LogPrintf("CFundamentalnodeMan::%s -- peer already asked me for the list, peer=%d\n", __func__, pnode->id);
            return;
        }
        int64_t askAgain = GetTime() + DSEGFN_UPDATE_SECONDS;
        mAskedUsForFundamentalnodeList[addrSquashed] = askAgain;
    }

    int nInvCount = 0;

    LOCK(cs);

    for (const auto& fnpair : mapFundamentalnodes) {
        if (fnpair.second.addr.IsRFC1918() || fnpair.second.addr.IsLocal()) continue; // do not send local network fundamentalnode
        // NOTE: send fundamentalnode regardless of its current state, the other node will need it to verify old votes.
        LogPrint("fundamentalnode", "CFundamentalnodeMan::%s -- Sending Fundamentalnode entry: fundamentalnode=%s  addr=%s\n", __func__, fnpair.first.ToStringShort(), fnpair.second.addr.ToString());
        PushDsegFNInvs(pnode, fnpair.second);
        nInvCount++;
    }

    connman.PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::SYNCSTATUSCOUNTFN, FUNDAMENTALNODE_SYNC_LIST, nInvCount));
    LogPrintf("CFundamentalnodeMan::%s -- Sent %d Fundamentalnode invs to peer=%d\n", __func__, nInvCount, pnode->id);
}

void CFundamentalnodeMan::PushDsegFNInvs(CNode* pnode, const CFundamentalnode& fn)
{
    AssertLockHeld(cs);

    CFundamentalnodeBroadcast fnb(fn);
    CFundamentalnodePing fnp = fnb.lastPing;
    uint256 hashMNB = fnb.GetHash();
    uint256 hashMNP = fnp.GetHash();
    pnode->PushInventory(CInv(MSG_FUNDAMENTALNODE_ANNOUNCE, hashMNB));
    pnode->PushInventory(CInv(MSG_FUNDAMENTALNODE_PING, hashMNP));
    mapSeenFundamentalnodeBroadcast.insert(std::make_pair(hashMNB, std::make_pair(GetTime(), fnb)));
    mapSeenFundamentalnodePing.insert(std::make_pair(hashMNP, fnp));
}

// Verification of fundamentalnodes via unique direct requests.

void CFundamentalnodeMan::DoFullVerificationStep(CConnman& connman)
{
    if(activeFundamentalnode.outpoint.IsNull()) return;
    if(!fundamentalnodeSync.IsSynced()) return;

    rank_pair_vec_t vecFundamentalnodeRanks;
    GetFundamentalnodeRanks(vecFundamentalnodeRanks, nCachedBlockHeight - 1, MIN_POSE_PROTO_VERSION);

    LOCK(cs);

    int nCount = 0;

    int nMyRank = -1;
    int nRanksTotal = (int)vecFundamentalnodeRanks.size();

    // send verify requests only if we are in top MAX_POSE_RANK
    rank_pair_vec_t::iterator it = vecFundamentalnodeRanks.begin();
    while(it != vecFundamentalnodeRanks.end()) {
        if(it->first > MAX_POSE_RANK) {
            LogPrint("fundamentalnode", "CFundamentalnodeMan::DoFullVerificationStep -- Must be in top %d to send verify request\n",
                        (int)MAX_POSE_RANK);
            return;
        }
        if(it->second.outpoint == activeFundamentalnode.outpoint) {
            nMyRank = it->first;
            LogPrint("fundamentalnode", "CFundamentalnodeMan::DoFullVerificationStep -- Found self at rank %d/%d, verifying up to %d fundamentalnodes\n",
                        nMyRank, nRanksTotal, (int)MAX_POSE_CONNECTIONS);
            break;
        }
        ++it;
    }

    // edge case: list is too short and this fundamentalnode is not enabled
    if(nMyRank == -1) return;

    // send verify requests to up to MAX_POSE_CONNECTIONS fundamentalnodes
    // starting from MAX_POSE_RANK + nMyRank and using MAX_POSE_CONNECTIONS as a step
    int nOffset = MAX_POSE_RANK + nMyRank - 1;
    if(nOffset >= (int)vecFundamentalnodeRanks.size()) return;

    std::vector<const CFundamentalnode*> vSortedByAddr;
    for (const auto& fnpair : mapFundamentalnodes) {
        vSortedByAddr.push_back(&fnpair.second);
    }

    sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

    it = vecFundamentalnodeRanks.begin() + nOffset;
    while(it != vecFundamentalnodeRanks.end()) {
        if(it->second.IsPoSeVerified() || it->second.IsPoSeBanned()) {
            LogPrint("fundamentalnode", "CFundamentalnodeMan::DoFullVerificationStep -- Already %s%s%s fundamentalnode %s address %s, skipping...\n",
                        it->second.IsPoSeVerified() ? "verified" : "",
                        it->second.IsPoSeVerified() && it->second.IsPoSeBanned() ? " and " : "",
                        it->second.IsPoSeBanned() ? "banned" : "",
                        it->second.outpoint.ToStringShort(), it->second.addr.ToString());
            nOffset += MAX_POSE_CONNECTIONS;
            if(nOffset >= (int)vecFundamentalnodeRanks.size()) break;
            it += MAX_POSE_CONNECTIONS;
            continue;
        }
        LogPrint("fundamentalnode", "CFundamentalnodeMan::DoFullVerificationStep -- Verifying fundamentalnode %s rank %d/%d address %s\n",
                    it->second.outpoint.ToStringShort(), it->first, nRanksTotal, it->second.addr.ToString());
        if(SendVerifyRequest(CAddress(it->second.addr, NODE_NETWORK), vSortedByAddr, connman)) {
            nCount++;
            if(nCount >= MAX_POSE_CONNECTIONS) break;
        }
        nOffset += MAX_POSE_CONNECTIONS;
        if(nOffset >= (int)vecFundamentalnodeRanks.size()) break;
        it += MAX_POSE_CONNECTIONS;
    }

    LogPrint("fundamentalnode", "CFundamentalnodeMan::DoFullVerificationStep -- Sent verification requests to %d fundamentalnodes\n", nCount);
}

// This function tries to find fundamentalnodes with the same addr,
// find a verified one and ban all the other. If there are many nodes
// with the same addr but none of them is verified yet, then none of them are banned.
// It could take many times to run this before most of the duplicate nodes are banned.

void CFundamentalnodeMan::CheckSameAddr()
{
    if(!fundamentalnodeSync.IsSynced() || mapFundamentalnodes.empty()) return;

    std::vector<CFundamentalnode*> vBan;
    std::vector<CFundamentalnode*> vSortedByAddr;

    {
        LOCK(cs);

        CFundamentalnode* pprevFundamentalnode = NULL;
        CFundamentalnode* pverifiedFundamentalnode = NULL;

        for (auto& fnpair : mapFundamentalnodes) {
            vSortedByAddr.push_back(&fnpair.second);
        }

        sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

        for (const auto& pfn : vSortedByAddr) {
            // check only (pre)enabled fundamentalnodes
            if(!pfn->IsEnabled() && !pfn->IsPreEnabled()) continue;
            // initial step
            if(!pprevFundamentalnode) {
                pprevFundamentalnode = pfn;
                pverifiedFundamentalnode = pfn->IsPoSeVerified() ? pfn : NULL;
                continue;
            }
            // second+ step
            if(pfn->addr == pprevFundamentalnode->addr) {
                if(pverifiedFundamentalnode) {
                    // another fundamentalnode with the same ip is verified, ban this one
                    vBan.push_back(pfn);
                } else if(pfn->IsPoSeVerified()) {
                    // this fundamentalnode with the same ip is verified, ban previous one
                    vBan.push_back(pprevFundamentalnode);
                    // and keep a reference to be able to ban following fundamentalnodes with the same ip
                    pverifiedFundamentalnode = pfn;
                }
            } else {
                pverifiedFundamentalnode = pfn->IsPoSeVerified() ? pfn : NULL;
            }
            pprevFundamentalnode = pfn;
        }
    }

    // ban duplicates
    for (auto& pfn : vBan) {
        LogPrintf("CFundamentalnodeMan::CheckSameAddr -- increasing PoSe ban score for fundamentalnode %s\n", pfn->outpoint.ToStringShort());
        pfn->IncreasePoSeBanScore();
    }
}

bool CFundamentalnodeMan::SendVerifyRequest(const CAddress& addr, const std::vector<const CFundamentalnode*>& vSortedByAddr, CConnman& connman)
{
    if(netfulfilledman.HasFulfilledRequest(addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        // we already asked for verification, not a good idea to do this too often, skip it
        LogPrint("fundamentalnode", "CFundamentalnodeMan::SendVerifyRequest -- too many requests, skipping... addr=%s\n", addr.ToString());
        return false;
    }

    if (connman.IsFundamentalnodeOrDisconnectRequested(addr)) return false;

    connman.AddPendingFundamentalnode(addr);
    // use random nonce, store it and require node to reply with correct one later
    CFundamentalnodeVerification fnv(addr, GetRandInt(2412699), nCachedBlockHeight - 1);
    LOCK(cs_mapPendingMNV);
    mapPendingMNV.insert(std::make_pair(addr, std::make_pair(GetTime(), fnv)));
    LogPrintf("CFundamentalnodeMan::SendVerifyRequest -- verifying node using nonce %d addr=%s\n", fnv.nonce, addr.ToString());
    return true;
}

void CFundamentalnodeMan::ProcessPendingFnvRequests(CConnman& connman)
{
    LOCK(cs_mapPendingMNV);

    std::map<CService, std::pair<int64_t, CFundamentalnodeVerification> >::iterator itPendingMNV = mapPendingMNV.begin();

    while (itPendingMNV != mapPendingMNV.end()) {
        bool fDone = connman.ForNode(itPendingMNV->first, [&](CNode* pnode) {
            netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request");
            // use random nonce, store it and require node to reply with correct one later
            mWeAskedForVerification[pnode->addr] = itPendingMNV->second.second;
            LogPrint("fundamentalnode", "-- verifying node using nonce %d addr=%s\n", itPendingMNV->second.second.nonce, pnode->addr.ToString());
            CNetMsgMaker msgMaker(pnode->GetSendVersion()); // TODO this gives a warning about version not being set (we should wait for VERSION exchange)
            connman.PushMessage(pnode, msgMaker.Make(NetMsgType::MNVERIFY, itPendingMNV->second.second));
            return true;
        });

        int64_t nTimeAdded = itPendingMNV->second.first;
        if (fDone || (GetTime() - nTimeAdded > 15)) {
            if (!fDone) {
                LogPrint("fundamentalnode", "CFundamentalnodeMan::%s -- failed to connect to %s\n", __func__, itPendingMNV->first.ToString());
            }
            mapPendingMNV.erase(itPendingMNV++);
        } else {
            ++itPendingMNV;
        }
    }
    LogPrint("fundamentalnode", "%s -- mapPendingMNV size: %d\n", __func__, mapPendingMNV.size());
}

void CFundamentalnodeMan::SendVerifyReply(CNode* pnode, CFundamentalnodeVerification& fnv, CConnman& connman)
{
    AssertLockHeld(cs_main);

    // only fundamentalnodes can sign this, why would someone ask regular node?
    if(!fFundamentalnodeMode) {
        // do not ban, malicious node might be using my IP
        // and trying to confuse the node which tries to verify it
        return;
    }

    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply")) {
        // peer should not ask us that often
        LogPrintf("FundamentalnodeMan::SendVerifyReply -- ERROR: peer already asked me recently, peer=%d\n", pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, fnv.nBlockHeight)) {
        LogPrintf("FundamentalnodeMan::SendVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", fnv.nBlockHeight, pnode->id);
        return;
    }

    std::string strError;

    if (sporkManager.IsSporkActive(SPORK_6_NEW_SIGS)) {
        uint256 hash = fnv.GetSignatureHash1(blockHash);

        if(!CHashSigner::SignHash(hash, activeFundamentalnode.keyFundamentalnode, fnv.vchSig1)) {
            LogPrintf("CFundamentalnodeMan::SendVerifyReply -- SignHash() failed\n");
            return;
        }

        if (!CHashSigner::VerifyHash(hash, activeFundamentalnode.pubKeyFundamentalnode, fnv.vchSig1, strError)) {
            LogPrintf("CFundamentalnodeMan::SendVerifyReply -- VerifyHash() failed, error: %s\n", strError);
            return;
        }
    } else {
        std::string strMessage = strprintf("%s%d%s", activeFundamentalnode.service.ToString(false), fnv.nonce, blockHash.ToString());

        if(!CMessageSigner::SignMessage(strMessage, fnv.vchSig1, activeFundamentalnode.keyFundamentalnode)) {
            LogPrintf("FundamentalnodeMan::SendVerifyReply -- SignMessage() failed\n");
            return;
        }

        if(!CMessageSigner::VerifyMessage(activeFundamentalnode.pubKeyFundamentalnode, fnv.vchSig1, strMessage, strError)) {
            LogPrintf("FundamentalnodeMan::SendVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
            return;
        }
    }

    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::MNVERIFY, fnv));
    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply");
}

void CFundamentalnodeMan::ProcessVerifyReply(CNode* pnode, CFundamentalnodeVerification& fnv)
{
    AssertLockHeld(cs_main);

    std::string strError;

    // did we even ask for it? if that's the case we should have matching fulfilled request
    if(!netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        LogPrintf("CFundamentalnodeMan::ProcessVerifyReply -- ERROR: we didn't ask for verification of %s, peer=%d\n", pnode->addr.ToString(), pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    // Received nonce for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nonce != fnv.nonce) {
        LogPrintf("CFundamentalnodeMan::ProcessVerifyReply -- ERROR: wrong nounce: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nonce, fnv.nonce, pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    // Received nBlockHeight for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nBlockHeight != fnv.nBlockHeight) {
        LogPrintf("CFundamentalnodeMan::ProcessVerifyReply -- ERROR: wrong nBlockHeight: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nBlockHeight, fnv.nBlockHeight, pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, fnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("FundamentalnodeMan::ProcessVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", fnv.nBlockHeight, pnode->id);
        return;
    }

    // we already verified this address, why node is spamming?
    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done")) {
        LogPrintf("CFundamentalnodeMan::ProcessVerifyReply -- ERROR: already verified %s recently\n", pnode->addr.ToString());
        Misbehaving(pnode->id, 20);
        return;
    }

    {
        LOCK(cs);

        CFundamentalnode* prealFundamentalnode = NULL;
        std::vector<CFundamentalnode*> vpFundamentalnodesToBan;

        uint256 hash1 = fnv.GetSignatureHash1(blockHash);
        std::string strMessage1 = strprintf("%s%d%s", pnode->addr.ToString(false), fnv.nonce, blockHash.ToString());

        for (auto& fnpair : mapFundamentalnodes) {
            if(CAddress(fnpair.second.addr, NODE_NETWORK) == pnode->addr) {
                bool fFound = false;
                if (sporkManager.IsSporkActive(SPORK_6_NEW_SIGS)) {
                    fFound = CHashSigner::VerifyHash(hash1, fnpair.second.pubKeyFundamentalnode, fnv.vchSig1, strError);
                    // we don't care about fnv with signature in old format
                } else {
                    fFound = CMessageSigner::VerifyMessage(fnpair.second.pubKeyFundamentalnode, fnv.vchSig1, strMessage1, strError);
                }
                if (fFound) {
                    // found it!
                    prealFundamentalnode = &fnpair.second;
                    if(!fnpair.second.IsPoSeVerified()) {
                        fnpair.second.DecreasePoSeBanScore();
                    }
                    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done");

                    // we can only broadcast it if we are an activated fundamentalnode
                    if(activeFundamentalnode.outpoint.IsNull()) continue;
                    // update ...
                    fnv.addr = fnpair.second.addr;
                    fnv.fundamentalnodeOutpoint1 = fnpair.second.outpoint;
                    fnv.fundamentalnodeOutpoint2 = activeFundamentalnode.outpoint;
                    // ... and sign it
                    std::string strError;

                    if (sporkManager.IsSporkActive(SPORK_6_NEW_SIGS)) {
                        uint256 hash2 = fnv.GetSignatureHash2(blockHash);

                        if(!CHashSigner::SignHash(hash2, activeFundamentalnode.keyFundamentalnode, fnv.vchSig2)) {
                            LogPrintf("FundamentalnodeMan::ProcessVerifyReply -- SignHash() failed\n");
                            return;
                        }

                        if(!CHashSigner::VerifyHash(hash2, activeFundamentalnode.pubKeyFundamentalnode, fnv.vchSig2, strError)) {
                            LogPrintf("FundamentalnodeMan::ProcessVerifyReply -- VerifyHash() failed, error: %s\n", strError);
                            return;
                        }
                    } else {
                        std::string strMessage2 = strprintf("%s%d%s%s%s", fnv.addr.ToString(false), fnv.nonce, blockHash.ToString(),
                                                fnv.fundamentalnodeOutpoint1.ToStringShort(), fnv.fundamentalnodeOutpoint2.ToStringShort());

                        if(!CMessageSigner::SignMessage(strMessage2, fnv.vchSig2, activeFundamentalnode.keyFundamentalnode)) {
                            LogPrintf("FundamentalnodeMan::ProcessVerifyReply -- SignMessage() failed\n");
                            return;
                        }

                        if(!CMessageSigner::VerifyMessage(activeFundamentalnode.pubKeyFundamentalnode, fnv.vchSig2, strMessage2, strError)) {
                            LogPrintf("FundamentalnodeMan::ProcessVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
                            return;
                        }
                    }

                    mWeAskedForVerification[pnode->addr] = fnv;
                    mapSeenFundamentalnodeVerification.insert(std::make_pair(fnv.GetHash(), fnv));
                    fnv.Relay();

                } else {
                    vpFundamentalnodesToBan.push_back(&fnpair.second);
                }
            }
        }
        // no real fundamentalnode found?...
        if(!prealFundamentalnode) {
            // this should never be the case normally,
            // only if someone is trying to game the system in some way or smth like that
            LogPrintf("CFundamentalnodeMan::ProcessVerifyReply -- ERROR: no real fundamentalnode found for addr %s\n", pnode->addr.ToString());
            Misbehaving(pnode->id, 20);
            return;
        }
        LogPrintf("CFundamentalnodeMan::ProcessVerifyReply -- verified real fundamentalnode %s for addr %s\n",
                    prealFundamentalnode->outpoint.ToStringShort(), pnode->addr.ToString());
        // increase ban score for everyone else
        for (const auto& pfn : vpFundamentalnodesToBan) {
            pfn->IncreasePoSeBanScore();
            LogPrint("fundamentalnode", "CFundamentalnodeMan::ProcessVerifyReply -- increased PoSe ban score for %s addr %s, new score %d\n",
                        prealFundamentalnode->outpoint.ToStringShort(), pnode->addr.ToString(), pfn->nPoSeBanScore);
        }
        if(!vpFundamentalnodesToBan.empty())
            LogPrintf("CFundamentalnodeMan::ProcessVerifyReply -- PoSe score increased for %d fake fundamentalnodes, addr %s\n",
                        (int)vpFundamentalnodesToBan.size(), pnode->addr.ToString());
    }
}

void CFundamentalnodeMan::ProcessVerifyBroadcast(CNode* pnode, const CFundamentalnodeVerification& fnv)
{
    AssertLockHeld(cs_main);

    std::string strError;

    if(mapSeenFundamentalnodeVerification.find(fnv.GetHash()) != mapSeenFundamentalnodeVerification.end()) {
        // we already have one
        return;
    }
    mapSeenFundamentalnodeVerification[fnv.GetHash()] = fnv;

    // we don't care about history
    if(fnv.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS) {
        LogPrint("fundamentalnode", "CFundamentalnodeMan::ProcessVerifyBroadcast -- Outdated: current block %d, verification block %d, peer=%d\n",
                    nCachedBlockHeight, fnv.nBlockHeight, pnode->id);
        return;
    }

    if(fnv.fundamentalnodeOutpoint1 == fnv.fundamentalnodeOutpoint2) {
        LogPrint("fundamentalnode", "CFundamentalnodeMan::ProcessVerifyBroadcast -- ERROR: same outpoints %s, peer=%d\n",
                    fnv.fundamentalnodeOutpoint1.ToStringShort(), pnode->id);
        // that was NOT a good idea to cheat and verify itself,
        // ban the node we received such message from
        Misbehaving(pnode->id, 100);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, fnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("CFundamentalnodeMan::ProcessVerifyBroadcast -- Can't get block hash for unknown block height %d, peer=%d\n", fnv.nBlockHeight, pnode->id);
        return;
    }

    int nRank;

    if (!GetFundamentalnodeRank(fnv.fundamentalnodeOutpoint2, nRank, fnv.nBlockHeight, MIN_POSE_PROTO_VERSION)) {
        LogPrint("fundamentalnode", "CFundamentalnodeMan::ProcessVerifyBroadcast -- Can't calculate rank for fundamentalnode %s\n",
                    fnv.fundamentalnodeOutpoint2.ToStringShort());
        return;
    }

    if(nRank > MAX_POSE_RANK) {
        LogPrint("fundamentalnode", "CFundamentalnodeMan::ProcessVerifyBroadcast -- Fundamentalnode %s is not in top %d, current rank %d, peer=%d\n",
                    fnv.fundamentalnodeOutpoint2.ToStringShort(), (int)MAX_POSE_RANK, nRank, pnode->id);
        return;
    }

    {
        LOCK(cs);

        CFundamentalnode* pfn1 = Find(fnv.fundamentalnodeOutpoint1);
        if(!pfn1) {
            LogPrintf("CFundamentalnodeMan::ProcessVerifyBroadcast -- can't find fundamentalnode1 %s\n", fnv.fundamentalnodeOutpoint1.ToStringShort());
            return;
        }

        CFundamentalnode* pfn2 = Find(fnv.fundamentalnodeOutpoint2);
        if(!pfn2) {
            LogPrintf("CFundamentalnodeMan::ProcessVerifyBroadcast -- can't find fundamentalnode2 %s\n", fnv.fundamentalnodeOutpoint2.ToStringShort());
            return;
        }

        if(pfn1->addr != fnv.addr) {
            LogPrintf("CFundamentalnodeMan::ProcessVerifyBroadcast -- addr %s does not match %s\n", fnv.addr.ToString(), pfn1->addr.ToString());
            return;
        }

        if (sporkManager.IsSporkActive(SPORK_6_NEW_SIGS)) {
            uint256 hash1 = fnv.GetSignatureHash1(blockHash);
            uint256 hash2 = fnv.GetSignatureHash2(blockHash);

            if(!CHashSigner::VerifyHash(hash1, pfn1->pubKeyFundamentalnode, fnv.vchSig1, strError)) {
                LogPrintf("FundamentalnodeMan::ProcessVerifyBroadcast -- VerifyHash() failed, error: %s\n", strError);
                return;
            }

            if(!CHashSigner::VerifyHash(hash2, pfn2->pubKeyFundamentalnode, fnv.vchSig2, strError)) {
                LogPrintf("FundamentalnodeMan::ProcessVerifyBroadcast -- VerifyHash() failed, error: %s\n", strError);
                return;
            }
        } else {
            std::string strMessage1 = strprintf("%s%d%s", fnv.addr.ToString(false), fnv.nonce, blockHash.ToString());
            std::string strMessage2 = strprintf("%s%d%s%s%s", fnv.addr.ToString(false), fnv.nonce, blockHash.ToString(),
                                    fnv.fundamentalnodeOutpoint1.ToStringShort(), fnv.fundamentalnodeOutpoint2.ToStringShort());

            if(!CMessageSigner::VerifyMessage(pfn1->pubKeyFundamentalnode, fnv.vchSig1, strMessage1, strError)) {
                LogPrintf("CFundamentalnodeMan::ProcessVerifyBroadcast -- VerifyMessage() for fundamentalnode1 failed, error: %s\n", strError);
                return;
            }

            if(!CMessageSigner::VerifyMessage(pfn2->pubKeyFundamentalnode, fnv.vchSig2, strMessage2, strError)) {
                LogPrintf("CFundamentalnodeMan::ProcessVerifyBroadcast -- VerifyMessage() for fundamentalnode2 failed, error: %s\n", strError);
                return;
            }
        }

        if(!pfn1->IsPoSeVerified()) {
            pfn1->DecreasePoSeBanScore();
        }
        fnv.Relay();

        LogPrintf("CFundamentalnodeMan::ProcessVerifyBroadcast -- verified fundamentalnode %s for addr %s\n",
                    pfn1->outpoint.ToStringShort(), pfn1->addr.ToString());

        // increase ban score for everyone else with the same addr
        int nCount = 0;
        for (auto& fnpair : mapFundamentalnodes) {
            if(fnpair.second.addr != fnv.addr || fnpair.first == fnv.fundamentalnodeOutpoint1) continue;
            fnpair.second.IncreasePoSeBanScore();
            nCount++;
            LogPrint("fundamentalnode", "CFundamentalnodeMan::ProcessVerifyBroadcast -- increased PoSe ban score for %s addr %s, new score %d\n",
                        fnpair.first.ToStringShort(), fnpair.second.addr.ToString(), fnpair.second.nPoSeBanScore);
        }
        if(nCount)
            LogPrintf("CFundamentalnodeMan::ProcessVerifyBroadcast -- PoSe score increased for %d fake fundamentalnodes, addr %s\n",
                        nCount, pfn1->addr.ToString());
    }
}

std::string CFundamentalnodeMan::ToString() const
{
    std::ostringstream info;

    info << "Fundamentalnodes: " << (int)mapFundamentalnodes.size() <<
            ", peers who asked us for Fundamentalnode list: " << (int)mAskedUsForFundamentalnodeList.size() <<
            ", peers we asked for Fundamentalnode list: " << (int)mWeAskedForFundamentalnodeList.size() <<
            ", entries in Fundamentalnode list we asked for: " << (int)mWeAskedForFundamentalnodeListEntry.size() <<
            ", nDsqCount: " << (int)nDsqCount;

    return info.str();
}

bool CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList(CNode* pfrom, CFundamentalnodeBroadcast fnb, int& nDos, CConnman& connman)
{
    // Need to lock cs_main here to ensure consistent locking order because the SimpleCheck call below locks cs_main
    LOCK(cs_main);

    {
        LOCK(cs);
        nDos = 0;
        LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- fundamentalnode=%s\n", fnb.outpoint.ToStringShort());

        uint256 hash = fnb.GetHash();
        if(mapSeenFundamentalnodeBroadcast.count(hash) && !fnb.fRecovery) { //seen
            LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- fundamentalnode=%s seen\n", fnb.outpoint.ToStringShort());
            // less then 2 pings left before this MN goes into non-recoverable state, bump sync timeout
            if(GetTime() - mapSeenFundamentalnodeBroadcast[hash].first > FUNDAMENTALNODE_NEW_START_REQUIRED_SECONDS - FUNDAMENTALNODE_MIN_MNP_SECONDS * 2) {
                LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- fundamentalnode=%s seen update\n", fnb.outpoint.ToStringShort());
                mapSeenFundamentalnodeBroadcast[hash].first = GetTime();
                fundamentalnodeSync.BumpAssetLastTime("CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList - seen");
            }
            // did we ask this node for it?
            if(pfrom && IsFnbRecoveryRequested(hash) && GetTime() < mFnbRecoveryRequests[hash].first) {
                LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- fnb=%s seen request\n", hash.ToString());
                if(mFnbRecoveryRequests[hash].second.count(pfrom->addr)) {
                    LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- fnb=%s seen request, addr=%s\n", hash.ToString(), pfrom->addr.ToString());
                    // do not allow node to send same fnb multiple times in recovery mode
                    mFnbRecoveryRequests[hash].second.erase(pfrom->addr);
                    // does it have newer lastPing?
                    if(fnb.lastPing.sigTime > mapSeenFundamentalnodeBroadcast[hash].second.lastPing.sigTime) {
                        // simulate Check
                        CFundamentalnode fnTemp = CFundamentalnode(fnb);
                        fnTemp.Check();
                        LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- fnb=%s seen request, addr=%s, better lastPing: %d min ago, projected fn state: %s\n", hash.ToString(), pfrom->addr.ToString(), (GetAdjustedTime() - fnb.lastPing.sigTime)/60, fnTemp.GetStateString());
                        if(fnTemp.IsValidStateForAutoStart(fnTemp.nActiveState)) {
                            // this node thinks it's a good one
                            LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- fundamentalnode=%s seen good\n", fnb.outpoint.ToStringShort());
                            mFnbRecoveryGoodReplies[hash].push_back(fnb);
                        }
                    }
                }
            }
            return true;
        }
        mapSeenFundamentalnodeBroadcast.insert(std::make_pair(hash, std::make_pair(GetTime(), fnb)));

        LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- fundamentalnode=%s new\n", fnb.outpoint.ToStringShort());

        if(!fnb.SimpleCheck(nDos)) {
            LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- SimpleCheck() failed, fundamentalnode=%s\n", fnb.outpoint.ToStringShort());
            return false;
        }

        // search Fundamentalnode list
        CFundamentalnode* pfn = Find(fnb.outpoint);
        if(pfn) {
            CFundamentalnodeBroadcast fnbOld = mapSeenFundamentalnodeBroadcast[CFundamentalnodeBroadcast(*pfn).GetHash()].second;
            if(!fnb.Update(pfn, nDos, connman)) {
                LogPrint("fundamentalnode", "CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- Update() failed, fundamentalnode=%s\n", fnb.outpoint.ToStringShort());
                return false;
            }
            if(hash != fnbOld.GetHash()) {
                mapSeenFundamentalnodeBroadcast.erase(fnbOld.GetHash());
            }
            return true;
        }
    }

    if(fnb.CheckOutpoint(nDos)) {
        Add(fnb);
        fundamentalnodeSync.BumpAssetLastTime("CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList - new");
        // if it matches our Fundamentalnode privkey...
        if(fFundamentalnodeMode && fnb.pubKeyFundamentalnode == activeFundamentalnode.pubKeyFundamentalnode) {
            fnb.nPoSeBanScore = -FUNDAMENTALNODE_POSE_BAN_MAX_SCORE;
            if(fnb.nProtocolVersion == PROTOCOL_VERSION) {
                // ... and PROTOCOL_VERSION, then we've been remotely activated ...
                LogPrintf("CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- Got NEW Fundamentalnode entry: fundamentalnode=%s  sigTime=%lld  addr=%s\n",
                            fnb.outpoint.ToStringShort(), fnb.sigTime, fnb.addr.ToString());
                activeFundamentalnode.ManageState(connman);
            } else {
                // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
                // but also do not ban the node we get this message from
                LogPrintf("CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", fnb.nProtocolVersion, PROTOCOL_VERSION);
                return false;
            }
        }
        fnb.Relay(connman);
    } else {
        LogPrintf("CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList -- Rejected Fundamentalnode entry: %s  addr=%s\n", fnb.outpoint.ToStringShort(), fnb.addr.ToString());
        return false;
    }

    return true;
}

void CFundamentalnodeMan::UpdateLastPaid(const CBlockIndex* pindex)
{
    LOCK(cs);

    if(fLiteMode || !fundamentalnodeSync.IsWinnersListSynced() || mapFundamentalnodes.empty()) return;

    static int nLastRunBlockHeight = 0;
    // Scan at least LAST_PAID_SCAN_BLOCKS but no more than fnpayments.GetStorageLimit()
    int nMaxBlocksToScanBack = std::max(LAST_PAID_SCAN_BLOCKS, nCachedBlockHeight - nLastRunBlockHeight);
    nMaxBlocksToScanBack = std::min(nMaxBlocksToScanBack, fnpayments.GetStorageLimit());

    LogPrint("fundamentalnode", "CFundamentalnodeMan::UpdateLastPaid -- nCachedBlockHeight=%d, nLastRunBlockHeight=%d, nMaxBlocksToScanBack=%d\n",
                            nCachedBlockHeight, nLastRunBlockHeight, nMaxBlocksToScanBack);

    for (auto& fnpair : mapFundamentalnodes) {
        fnpair.second.UpdateLastPaid(pindex, nMaxBlocksToScanBack);
    }

    nLastRunBlockHeight = nCachedBlockHeight;
}

void CFundamentalnodeMan::UpdateLastSentinelPingTime()
{
    LOCK(cs);
    nLastSentinelPingTime = GetTime();
}

bool CFundamentalnodeMan::IsSentinelPingActive()
{
    LOCK(cs);
    // Check if any fundamentalnodes have voted recently, otherwise return false
    return (GetTime() - nLastSentinelPingTime) <= FUNDAMENTALNODE_SENTINEL_PING_MAX_SECONDS;
}

bool CFundamentalnodeMan::AddGovernanceVote(const COutPoint& outpoint, uint256 nGovernanceObjectHash)
{
    LOCK(cs);
    CFundamentalnode* pfn = Find(outpoint);
    if(!pfn) {
        return false;
    }
    pfn->AddGovernanceVote(nGovernanceObjectHash);
    return true;
}

void CFundamentalnodeMan::RemoveGovernanceObject(uint256 nGovernanceObjectHash)
{
    LOCK(cs);
    for(auto& fnpair : mapFundamentalnodes) {
        fnpair.second.RemoveGovernanceObject(nGovernanceObjectHash);
    }
}

void CFundamentalnodeMan::CheckFundamentalnode(const CPubKey& pubKeyFundamentalnode, bool fForce)
{
    LOCK2(cs_main, cs);
    for (auto& fnpair : mapFundamentalnodes) {
        if (fnpair.second.pubKeyFundamentalnode == pubKeyFundamentalnode) {
            fnpair.second.Check(fForce);
            return;
        }
    }
}

bool CFundamentalnodeMan::IsFundamentalnodePingedWithin(const COutPoint& outpoint, int nSeconds, int64_t nTimeToCheckAt)
{
    LOCK(cs);
    CFundamentalnode* pfn = Find(outpoint);
    return pfn ? pfn->IsPingedWithin(nSeconds, nTimeToCheckAt) : false;
}

void CFundamentalnodeMan::SetFundamentalnodeLastPing(const COutPoint& outpoint, const CFundamentalnodePing& fnp)
{
    LOCK(cs);
    CFundamentalnode* pfn = Find(outpoint);
    if(!pfn) {
        return;
    }
    pfn->lastPing = fnp;
    if(fnp.fSentinelIsCurrent) {
        UpdateLastSentinelPingTime();
    }
    mapSeenFundamentalnodePing.insert(std::make_pair(fnp.GetHash(), fnp));

    CFundamentalnodeBroadcast fnb(*pfn);
    uint256 hash = fnb.GetHash();
    if(mapSeenFundamentalnodeBroadcast.count(hash)) {
        mapSeenFundamentalnodeBroadcast[hash].second.lastPing = fnp;
    }
}

void CFundamentalnodeMan::UpdatedBlockTip(const CBlockIndex *pindex)
{
    nCachedBlockHeight = pindex->nHeight;
    LogPrint("fundamentalnode", "CFundamentalnodeMan::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);

    CheckSameAddr();

    if(fFundamentalnodeMode) {
        // normal wallet does not need to update this every block, doing update on rpc call should be enough
        UpdateLastPaid(pindex);
    }
}

void CFundamentalnodeMan::WarnFundamentalnodeDaemonUpdates()
{
    LOCK(cs);

    static bool fWarned = false;

    if (fWarned || !size() || !fundamentalnodeSync.IsFundamentalnodeListSynced())
        return;

    int nUpdatedFundamentalnodes{0};

    for (const auto& fnpair : mapFundamentalnodes) {
        if (fnpair.second.lastPing.nDaemonVersion > CLIENT_VERSION) {
            ++nUpdatedFundamentalnodes;
        }
    }

    // Warn only when at least half of known fundamentalnodes already updated
    if (nUpdatedFundamentalnodes < size() / 2)
        return;

    std::string strWarning;
    if (nUpdatedFundamentalnodes != size()) {
        strWarning = strprintf(_("Warning: At least %d of %d fundamentalnodes are running on a newer software version. Please check latest releases, you might need to update too."),
                    nUpdatedFundamentalnodes, size());
    } else {
        // someone was postponing this update for way too long probably
        strWarning = strprintf(_("Warning: Every fundamentalnode (out of %d known ones) is running on a newer software version. Please check latest releases, it's very likely that you missed a major/critical update."),
                    size());
    }

    // notify GetWarnings(), called by Qt and the JSON-RPC code to warn the user
    SetMiscWarning(strWarning);
    // trigger GUI update
    uiInterface.NotifyAlertChanged(SerializeHash(strWarning), CT_NEW);
    // trigger cmd-line notification
    CAlert::Notify(strWarning);

    fWarned = true;
}

void CFundamentalnodeMan::NotifyFundamentalnodeUpdates(CConnman& connman)
{
    // Avoid double locking
    bool fFundamentalnodesAddedLocal = false;
    bool fFundamentalnodesRemovedLocal = false;
    {
        LOCK(cs);
        fFundamentalnodesAddedLocal = fFundamentalnodesAdded;
        fFundamentalnodesRemovedLocal = fFundamentalnodesRemoved;
    }
    /*
    if(fFundamentalnodesAddedLocal) {
        governance.CheckFundamentalnodeOrphanObjects(connman);
        governance.CheckFundamentalnodeOrphanVotes(connman);
    }
    */
    if(fFundamentalnodesRemovedLocal) {
        governance.UpdateCachesAndClean();
    }

    LOCK(cs);
    fFundamentalnodesAdded = false;
    fFundamentalnodesRemoved = false;
}
