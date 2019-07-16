// Copyright (c) 2014-2017 The SecureTag Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activefundamentalnode.h"
#include "checkpoints.h"
#include "governance.h"
#include "validation.h"
#include "fundamentalnode.h"
#include "fundamentalnode-payments.h"
#include "fundamentalnode-sync.h"
#include "fundamentalnodeman.h"
#include "netfulfilledman.h"
#include "netmessagemaker.h"
#include "spork.h"
#include "ui_interface.h"
#include "util.h"

class CFundamentalnodeSync;
CFundamentalnodeSync fundamentalnodeSync;

void CFundamentalnodeSync::Fail()
{
    nTimeLastFailure = GetTime();
    nRequestedFundamentalnodeAssets = FUNDAMENTALNODE_SYNC_FAILED;
}

void CFundamentalnodeSync::Reset()
{
    nRequestedFundamentalnodeAssets = FUNDAMENTALNODE_SYNC_INITIAL;
    nRequestedFundamentalnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    nTimeLastBumped = GetTime();
    nTimeLastFailure = 0;
}

void CFundamentalnodeSync::BumpAssetLastTime(const std::string& strFuncName)
{
    if(IsSynced() || IsFailed()) return;
    nTimeLastBumped = GetTime();
    LogPrint("fnsync", "CFundamentalnodeSync::BumpAssetLastTime -- %s\n", strFuncName);
}

std::string CFundamentalnodeSync::GetAssetName()
{
    switch(nRequestedFundamentalnodeAssets)
    {
        case(FUNDAMENTALNODE_SYNC_INITIAL):      return "FUNDAMENTALNODE_SYNC_INITIAL";
        case(FUNDAMENTALNODE_SYNC_WAITING):      return "FUNDAMENTALNODE_SYNC_WAITING";
        case(FUNDAMENTALNODE_SYNC_LIST):         return "FUNDAMENTALNODE_SYNC_LIST";
        case(FUNDAMENTALNODE_SYNC_MNW):          return "FUNDAMENTALNODE_SYNC_MNW";
        //case(FUNDAMENTALNODE_SYNC_GOVERNANCE):   return "FUNDAMENTALNODE_SYNC_GOVERNANCE";
        case(FUNDAMENTALNODE_SYNC_FAILED):       return "FUNDAMENTALNODE_SYNC_FAILED";
        case FUNDAMENTALNODE_SYNC_FINISHED:      return "FUNDAMENTALNODE_SYNC_FINISHED";
        default:                            return "UNKNOWN";
    }
}

void CFundamentalnodeSync::SwitchToNextAsset(CConnman& connman)
{
    switch(nRequestedFundamentalnodeAssets)
    {
        case(FUNDAMENTALNODE_SYNC_FAILED):
            throw std::runtime_error("Can't switch to next asset from failed, should use Reset() first!");
            break;
        case(FUNDAMENTALNODE_SYNC_INITIAL):
            nRequestedFundamentalnodeAssets = FUNDAMENTALNODE_SYNC_WAITING;
            LogPrintf("CFundamentalnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(FUNDAMENTALNODE_SYNC_WAITING):
            LogPrintf("CFundamentalnodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedFundamentalnodeAssets = FUNDAMENTALNODE_SYNC_LIST;
            LogPrintf("CFundamentalnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(FUNDAMENTALNODE_SYNC_LIST):
            LogPrintf("CFundamentalnodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedFundamentalnodeAssets = FUNDAMENTALNODE_SYNC_MNW;
            LogPrintf("CFundamentalnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(FUNDAMENTALNODE_SYNC_MNW):
            LogPrintf("CFundamentalnodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedFundamentalnodeAssets = FUNDAMENTALNODE_SYNC_FINISHED;
            uiInterface.NotifyAdditionalDataSyncProgressChanged(1);
            //try to activate our fundamentalnode if possible
            activeFundamentalnode.ManageState(connman);

            connman.ForEachNode(CConnman::AllNodes, [](CNode* pnode) {
                netfulfilledman.AddFulfilledRequest(pnode->addr, "full-sync");
            });
            LogPrintf("CFundamentalnodeSync::SwitchToNextAsset -- Sync has finished\n");

            break;
    }
    nRequestedFundamentalnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    BumpAssetLastTime("CFundamentalnodeSync::SwitchToNextAsset");
}

std::string CFundamentalnodeSync::GetSyncStatus()
{
    switch (fundamentalnodeSync.nRequestedFundamentalnodeAssets) {
        case FUNDAMENTALNODE_SYNC_INITIAL:       return _("Synchroning blockchain...");
        case FUNDAMENTALNODE_SYNC_WAITING:       return _("Synchronization pending...");
        case FUNDAMENTALNODE_SYNC_LIST:          return _("Synchronizing fundamentalnodes...");
        case FUNDAMENTALNODE_SYNC_MNW:           return _("Synchronizing fundamentalnode payments...");
        //case FUNDAMENTALNODE_SYNC_GOVERNANCE:    return _("Synchronizing governance objects...");
        case FUNDAMENTALNODE_SYNC_FAILED:        return _("Synchronization failed");
        case FUNDAMENTALNODE_SYNC_FINISHED:      return _("Synchronization finished");
        default:                            return "";
    }
}

void CFundamentalnodeSync::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == NetMsgType::SYNCSTATUSCOUNTFN) { //Sync status count

        //do not care about stats if sync process finished or failed
        if(IsSynced() || IsFailed()) return;

        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        LogPrintf("SYNCSTATUSCOUNTFN -- got inventory count: nItemID=%d  nCount=%d  peer=%d\n", nItemID, nCount, pfrom->id);
    }
}

void CFundamentalnodeSync::ProcessTick(CConnman& connman)
{
    static int nTick = 0;
    if(nTick++ % FUNDAMENTALNODE_SYNC_TICK_SECONDS != 0) return;

    // reset the sync process if the last call to this function was more than 60 minutes ago (client was in sleep mode)
    static int64_t nTimeLastProcess = GetTime();
    if(GetTime() - nTimeLastProcess > 60*60) {
        LogPrintf("CFundamentalnodeSync::ProcessTick -- WARNING: no actions for too long, restarting sync...\n");
        Reset();
        SwitchToNextAsset(connman);
        nTimeLastProcess = GetTime();
        return;
    }
    nTimeLastProcess = GetTime();

    // reset sync status in case of any other sync failure
    if(IsFailed()) {
        if(nTimeLastFailure + (1*60) < GetTime()) { // 1 minute cooldown after failed sync
            LogPrintf("CFundamentalnodeSync::ProcessTick -- WARNING: failed to sync, trying again...\n");
            Reset();
            SwitchToNextAsset(connman);
        }
        return;
    }

    // gradually request the rest of the votes after sync finished
    if(IsSynced()) {
        std::vector<CNode*> vNodesCopy = connman.CopyNodeVector(CConnman::FullyConnectedOnly);
        //governance.RequestGovernanceObjectVotes(vNodesCopy, connman);
        connman.ReleaseNodeVector(vNodesCopy);
        return;
    }

    // Calculate "progress" for LOG reporting / GUI notification
    double nSyncProgress = double(nRequestedFundamentalnodeAttempt + (nRequestedFundamentalnodeAssets - 1) * 8) / (8*4);
    LogPrintf("CFundamentalnodeSync::ProcessTick -- nTick %d nRequestedFundamentalnodeAssets %d nRequestedFundamentalnodeAttempt %d nSyncProgress %f\n", nTick, nRequestedFundamentalnodeAssets, nRequestedFundamentalnodeAttempt, nSyncProgress);
    uiInterface.NotifyAdditionalDataSyncProgressChanged(nSyncProgress);

    std::vector<CNode*> vNodesCopy = connman.CopyNodeVector(CConnman::FullyConnectedOnly);

    for (auto& pnode : vNodesCopy)
    {
        CNetMsgMaker msgMaker(pnode->GetSendVersion());

        // Don't try to sync any data from outbound "fundamentalnode" connections -
        // they are temporary and should be considered unreliable for a sync process.
        // Inbound connection this early is most likely a "fundamentalnode" connection
        // initiated from another node, so skip it too.
        if(pnode->fFundamentalnode || (fFundamentalnodeMode && pnode->fInbound)) continue;

        // QUICK MODE (REGTEST ONLY!)
        if(Params().NetworkIDString() == CBaseChainParams::REGTEST)
        {
            if(nRequestedFundamentalnodeAttempt <= 2) {
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETSPORKS)); //get current network sporks
            } else if(nRequestedFundamentalnodeAttempt < 4) {
                fnodeman.DsegUpdateFN(pnode, connman);
            } else if(nRequestedFundamentalnodeAttempt < 6) {
                //sync payment votes
                if(pnode->nVersion == 70208) {
                    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::FUNDAMENTALNODEPAYMENTSYNC, fnpayments.GetStorageLimit())); //sync payment votes
                } else {
                    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::FUNDAMENTALNODEPAYMENTSYNC)); //sync payment votes
                }
                //SendGovernanceSyncRequest(pnode, connman);
            } else {
                nRequestedFundamentalnodeAssets = FUNDAMENTALNODE_SYNC_FINISHED;
            }
            nRequestedFundamentalnodeAttempt++;
            connman.ReleaseNodeVector(vNodesCopy);
            return;
        }

        // NORMAL NETWORK MODE - TESTNET/MAINNET
        {
            if(netfulfilledman.HasFulfilledRequest(pnode->addr, "full-sync")) {
                // We already fully synced from this node recently,
                // disconnect to free this connection slot for another peer.
                pnode->fDisconnect = true;
                LogPrintf("CFundamentalnodeSync::ProcessTick -- disconnecting from recently synced peer=%d\n", pnode->id);
                continue;
            }

            // SPORK : ALWAYS ASK FOR SPORKS AS WE SYNC

            if(!netfulfilledman.HasFulfilledRequest(pnode->addr, "spork-sync")) {
                // always get sporks first, only request once from each peer
                netfulfilledman.AddFulfilledRequest(pnode->addr, "spork-sync");
                // get current network sporks
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETSPORKS));
                LogPrintf("CFundamentalnodeSync::ProcessTick -- nTick %d nRequestedFundamentalnodeAssets %d -- requesting sporks from peer=%d\n", nTick, nRequestedFundamentalnodeAssets, pnode->id);
            }

            // INITIAL TIMEOUT

            if(nRequestedFundamentalnodeAssets == FUNDAMENTALNODE_SYNC_WAITING) {
                if(GetTime() - nTimeLastBumped > FUNDAMENTALNODE_SYNC_TIMEOUT_SECONDS) {
                    // At this point we know that:
                    // a) there are peers (because we are looping on at least one of them);
                    // b) we waited for at least FUNDAMENTALNODE_SYNC_TIMEOUT_SECONDS since we reached
                    //    the headers tip the last time (i.e. since we switched from
                    //     FUNDAMENTALNODE_SYNC_INITIAL to FUNDAMENTALNODE_SYNC_WAITING and bumped time);
                    // c) there were no blocks (UpdatedBlockTip, NotifyHeaderTip) or headers (AcceptedBlockHeader)
                    //    for at least FUNDAMENTALNODE_SYNC_TIMEOUT_SECONDS.
                    // We must be at the tip already, let's move to the next asset.
                    SwitchToNextAsset(connman);
                }
            }

            // MNLIST : SYNC FUNDAMENTALNODE LIST FROM OTHER CONNECTED CLIENTS

            if(nRequestedFundamentalnodeAssets == FUNDAMENTALNODE_SYNC_LIST) {
                LogPrint("fundamentalnode", "CFundamentalnodeSync::ProcessTick -- nTick %d nRequestedFundamentalnodeAssets %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nRequestedFundamentalnodeAssets, nTimeLastBumped, GetTime(), GetTime() - nTimeLastBumped);
                // check for timeout first
                if(GetTime() - nTimeLastBumped > FUNDAMENTALNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CFundamentalnodeSync::ProcessTick -- nTick %d nRequestedFundamentalnodeAssets %d -- timeout\n", nTick, nRequestedFundamentalnodeAssets);
                    if (nRequestedFundamentalnodeAttempt == 0) {
                        LogPrintf("CFundamentalnodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // there is no way we can continue without fundamentalnode list, fail here and try later
                        Fail();
                        connman.ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // request from three peers max
                if (nRequestedFundamentalnodeAttempt > 2) {
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if(netfulfilledman.HasFulfilledRequest(pnode->addr, "fundamentalnode-list-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "fundamentalnode-list-sync");

                if (pnode->nVersion < fnpayments.GetMinFundamentalnodePaymentsProto()) continue;
                nRequestedFundamentalnodeAttempt++;

                fnodeman.DsegUpdateFN(pnode, connman);

                connman.ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // MNW : SYNC FUNDAMENTALNODE PAYMENT VOTES FROM OTHER CONNECTED CLIENTS

            if(nRequestedFundamentalnodeAssets == FUNDAMENTALNODE_SYNC_MNW) {
                LogPrint("fnpayments", "CFundamentalnodeSync::ProcessTick -- nTick %d nRequestedFundamentalnodeAssets %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nRequestedFundamentalnodeAssets, nTimeLastBumped, GetTime(), GetTime() - nTimeLastBumped);
                // check for timeout first
                // This might take a lot longer than FUNDAMENTALNODE_SYNC_TIMEOUT_SECONDS due to new blocks,
                // but that should be OK and it should timeout eventually.
                if(GetTime() - nTimeLastBumped > FUNDAMENTALNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CFundamentalnodeSync::ProcessTick -- nTick %d nRequestedFundamentalnodeAssets %d -- timeout\n", nTick, nRequestedFundamentalnodeAssets);
                    if (nRequestedFundamentalnodeAttempt == 0) {
                        LogPrintf("CFundamentalnodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // probably not a good idea to proceed without winner list
                        Fail();
                        connman.ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // check for data
                // if fnpayments already has enough blocks and votes, switch to the next asset
                // try to fetch data from at least two peers though
                if(nRequestedFundamentalnodeAttempt > 1 && fnpayments.IsEnoughData()) {
                    LogPrintf("CFundamentalnodeSync::ProcessTick -- nTick %d nRequestedFundamentalnodeAssets %d -- found enough data\n", nTick, nRequestedFundamentalnodeAssets);
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // request from three peers max
                if (nRequestedFundamentalnodeAttempt > 2) {
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if(netfulfilledman.HasFulfilledRequest(pnode->addr, "fundamentalnode-payment-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "fundamentalnode-payment-sync");

                if(pnode->nVersion < fnpayments.GetMinFundamentalnodePaymentsProto()) continue;
                nRequestedFundamentalnodeAttempt++;

                // ask node for all payment votes it has (new nodes will only return votes for future payments)
                //sync payment votes
                if(pnode->nVersion == 70208) {
                    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::FUNDAMENTALNODEPAYMENTSYNC, fnpayments.GetStorageLimit()));
                } else {
                    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::FUNDAMENTALNODEPAYMENTSYNC));
                }
                // ask node for missing pieces only (old nodes will not be asked)
                fnpayments.RequestLowDataPaymentBlocks(pnode, connman);

                connman.ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // GOVOBJ : SYNC GOVERNANCE ITEMS FROM OUR PEERS
            /*
            if(nRequestedFundamentalnodeAssets == FUNDAMENTALNODE_SYNC_GOVERNANCE) {
                LogPrint("gobject", "CFundamentalnodeSync::ProcessTick -- nTick %d nRequestedFundamentalnodeAssets %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nRequestedFundamentalnodeAssets, nTimeLastBumped, GetTime(), GetTime() - nTimeLastBumped);

                // check for timeout first
                if(GetTime() - nTimeLastBumped > FUNDAMENTALNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CFundamentalnodeSync::ProcessTick -- nTick %d nRequestedFundamentalnodeAssets %d -- timeout\n", nTick, nRequestedFundamentalnodeAssets);
                    if(nRequestedFundamentalnodeAttempt == 0) {
                        LogPrintf("CFundamentalnodeSync::ProcessTick -- WARNING: failed to sync %s\n", GetAssetName());
                        // it's kind of ok to skip this for now, hopefully we'll catch up later?
                    }
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request obj sync once from each peer, then request votes on per-obj basis
                if(netfulfilledman.HasFulfilledRequest(pnode->addr, "governance-sync")) {
                    int nObjsLeftToAsk = governance.RequestGovernanceObjectVotes(pnode, connman);
                    static int64_t nTimeNoObjectsLeft = 0;
                    // check for data
                    if(nObjsLeftToAsk == 0) {
                        static int nLastTick = 0;
                        static int nLastVotes = 0;
                        if(nTimeNoObjectsLeft == 0) {
                            // asked all objects for votes for the first time
                            nTimeNoObjectsLeft = GetTime();
                        }
                        // make sure the condition below is checked only once per tick
                        if(nLastTick == nTick) continue;
                        if(GetTime() - nTimeNoObjectsLeft > FUNDAMENTALNODE_SYNC_TIMEOUT_SECONDS &&
                            governance.GetVoteCount() - nLastVotes < std::max(int(0.0001 * nLastVotes), FUNDAMENTALNODE_SYNC_TICK_SECONDS)
                        ) {
                            // We already asked for all objects, waited for FUNDAMENTALNODE_SYNC_TIMEOUT_SECONDS
                            // after that and less then 0.01% or FUNDAMENTALNODE_SYNC_TICK_SECONDS
                            // (i.e. 1 per second) votes were recieved during the last tick.
                            // We can be pretty sure that we are done syncing.
                            LogPrintf("CFundamentalnodeSync::ProcessTick -- nTick %d nRequestedFundamentalnodeAssets %d -- asked for all objects, nothing to do\n", nTick, nRequestedFundamentalnodeAssets);
                            // reset nTimeNoObjectsLeft to be able to use the same condition on resync
                            nTimeNoObjectsLeft = 0;
                            SwitchToNextAsset(connman);
                            connman.ReleaseNodeVector(vNodesCopy);
                            return;
                        }
                        nLastTick = nTick;
                        nLastVotes = governance.GetVoteCount();
                    }
                    continue;
                }
                netfulfilledman.AddFulfilledRequest(pnode->addr, "governance-sync");

                if (pnode->nVersion < MIN_GOVERNANCE_PEER_PROTO_VERSION) continue;
                nRequestedFundamentalnodeAttempt++;

                SendGovernanceSyncRequest(pnode, connman);

                connman.ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }*/
        }
    }
    // looped through all nodes, release them
    connman.ReleaseNodeVector(vNodesCopy);
}

void CFundamentalnodeSync::SendGovernanceSyncRequest(CNode* pnode, CConnman& connman)
{
    CNetMsgMaker msgMaker(pnode->GetSendVersion());

    if(pnode->nVersion >= GOVERNANCE_FILTER_PROTO_VERSION) {
        CBloomFilter filter;
        filter.clear();

        connman.PushMessage(pnode, msgMaker.Make(NetMsgType::MNGOVERNANCESYNC, uint256(), filter));
    }
    else {
        connman.PushMessage(pnode, msgMaker.Make(NetMsgType::MNGOVERNANCESYNC, uint256()));
    }
}

void CFundamentalnodeSync::AcceptedBlockHeader(const CBlockIndex *pindexNew)
{
    LogPrint("fnsync", "CFundamentalnodeSync::AcceptedBlockHeader -- pindexNew->nHeight: %d\n", pindexNew->nHeight);

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block header arrives while we are still syncing blockchain
        BumpAssetLastTime("CFundamentalnodeSync::AcceptedBlockHeader");
    }
}

void CFundamentalnodeSync::NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint("fnsync", "CFundamentalnodeSync::NotifyHeaderTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CFundamentalnodeSync::NotifyHeaderTip");
    }
}

void CFundamentalnodeSync::UpdatedBlockTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint("fnsync", "CFundamentalnodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CFundamentalnodeSync::UpdatedBlockTip");
    }

    if (fInitialDownload) {
        // switched too early
        if (IsBlockchainSynced()) {
            Reset();
        }

        // no need to check any further while still in IBD mode
        return;
    }

    // Note: since we sync headers first, it should be ok to use this
    static bool fReachedBestHeader = false;
    bool fReachedBestHeaderNew = pindexNew->GetBlockHash() == pindexBestHeader->GetBlockHash();

    if (fReachedBestHeader && !fReachedBestHeaderNew) {
        // Switching from true to false means that we previousely stuck syncing headers for some reason,
        // probably initial timeout was not enough,
        // because there is no way we can update tip not having best header
        Reset();
        fReachedBestHeader = false;
        return;
    }

    fReachedBestHeader = fReachedBestHeaderNew;

    LogPrint("fnsync", "CFundamentalnodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d pindexBestHeader->nHeight: %d fInitialDownload=%d fReachedBestHeader=%d\n",
                pindexNew->nHeight, pindexBestHeader->nHeight, fInitialDownload, fReachedBestHeader);

    if (!IsBlockchainSynced() && fReachedBestHeader) {
        if (fLiteMode) {
            // nothing to do in lite mode, just finish the process immediately
            nRequestedFundamentalnodeAssets = FUNDAMENTALNODE_SYNC_FINISHED;
            return;
        }
        // Reached best header while being in initial mode.
        // We must be at the tip already, let's move to the next asset.
        SwitchToNextAsset(connman);
    }
}
