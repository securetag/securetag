// Copyright (c) 2014-2017 The SecureTag Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef FUNDAMENTALNODE_SYNC_H
#define FUNDAMENTALNODE_SYNC_H

#include "chain.h"
#include "net.h"

#include <univalue.h>

class CFundamentalnodeSync;

static const int FUNDAMENTALNODE_SYNC_FAILED          = -1;
static const int FUNDAMENTALNODE_SYNC_INITIAL         = 0; // sync just started, was reset recently or still in IDB
static const int FUNDAMENTALNODE_SYNC_WAITING         = 1; // waiting after initial to see if we can get more headers/blocks
static const int FUNDAMENTALNODE_SYNC_LIST            = 2;
static const int FUNDAMENTALNODE_SYNC_MNW             = 3;
static const int FUNDAMENTALNODE_SYNC_FINISHED        = 999;

static const int FUNDAMENTALNODE_SYNC_TICK_SECONDS    = 6;
static const int FUNDAMENTALNODE_SYNC_TIMEOUT_SECONDS = 30; // our blocks are 2.5 minutes so 30 seconds should be fine

static const int FUNDAMENTALNODE_SYNC_ENOUGH_PEERS    = 6;

extern CFundamentalnodeSync fundamentalnodeSync;

//
// CFundamentalnodeSync : Sync fundamentalnode assets in stages
//

class CFundamentalnodeSync
{
private:
    // Keep track of current asset
    int nRequestedFundamentalnodeAssets;
    // Count peers we've requested the asset from
    int nRequestedFundamentalnodeAttempt;

    // Time when current fundamentalnode asset sync started
    int64_t nTimeAssetSyncStarted;
    // ... last bumped
    int64_t nTimeLastBumped;
    // ... or failed
    int64_t nTimeLastFailure;

    void Fail();

public:
    CFundamentalnodeSync() { Reset(); }


    void SendGovernanceSyncRequest(CNode* pnode, CConnman& connman);

    bool IsFailed() { return nRequestedFundamentalnodeAssets == FUNDAMENTALNODE_SYNC_FAILED; }
    bool IsBlockchainSynced() { return nRequestedFundamentalnodeAssets > FUNDAMENTALNODE_SYNC_WAITING; }
    bool IsFundamentalnodeListSynced() { return nRequestedFundamentalnodeAssets > FUNDAMENTALNODE_SYNC_LIST; }
    bool IsWinnersListSynced() { return nRequestedFundamentalnodeAssets > FUNDAMENTALNODE_SYNC_MNW; }
    bool IsSynced() { return nRequestedFundamentalnodeAssets == FUNDAMENTALNODE_SYNC_FINISHED; }

    int GetAssetID() { return nRequestedFundamentalnodeAssets; }
    int GetAttempt() { return nRequestedFundamentalnodeAttempt; }
    void BumpAssetLastTime(const std::string& strFuncName);
    int64_t GetAssetStartTime() { return nTimeAssetSyncStarted; }
    std::string GetAssetName();
    std::string GetSyncStatus();

    void Reset();
    void SwitchToNextAsset(CConnman& connman);

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv);
    void ProcessTick(CConnman& connman);

    void AcceptedBlockHeader(const CBlockIndex *pindexNew);
    void NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman);
    void UpdatedBlockTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman);
};

#endif
