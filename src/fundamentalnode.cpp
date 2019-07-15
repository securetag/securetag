// Copyright (c) 2014-2017 The SecureTag Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activefundamentalnode.h"
#include "base58.h"
#include "clientversion.h"
#include "init.h"
#include "netbase.h"
#include "fundamentalnode.h"
#include "fundamentalnode-payments.h"
#include "fundamentalnode-sync.h"
#include "fundamentalnodeman.h"
#include "messagesigner.h"
#include "script/standard.h"
#include "util.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif // ENABLE_WALLET

#include <boost/lexical_cast.hpp>


CFundamentalnode::CFundamentalnode() :
    fundamentalnode_info_t{ FUNDAMENTALNODE_ENABLED, PROTOCOL_VERSION, GetAdjustedTime()},
    fAllowMixingTx(true)
{}

CFundamentalnode::CFundamentalnode(CService addr, COutPoint outpoint, CPubKey pubKeyCollateralAddress, CPubKey pubKeyFundamentalnode, int nProtocolVersionIn) :
    fundamentalnode_info_t{ FUNDAMENTALNODE_ENABLED, nProtocolVersionIn, GetAdjustedTime(),
                       outpoint, addr, pubKeyCollateralAddress, pubKeyFundamentalnode},
    fAllowMixingTx(true)
{}

CFundamentalnode::CFundamentalnode(const CFundamentalnode& other) :
    fundamentalnode_info_t{other},
    lastPing(other.lastPing),
    vchSig(other.vchSig),
    nCollateralMinConfBlockHash(other.nCollateralMinConfBlockHash),
    nBlockLastPaid(other.nBlockLastPaid),
    nPoSeBanScore(other.nPoSeBanScore),
    nPoSeBanHeight(other.nPoSeBanHeight),
    fAllowMixingTx(other.fAllowMixingTx),
    fUnitTest(other.fUnitTest)
{}

CFundamentalnode::CFundamentalnode(const CFundamentalnodeBroadcast& fnb) :
    fundamentalnode_info_t{ fnb.nActiveState, fnb.nProtocolVersion, fnb.sigTime,
                       fnb.outpoint, fnb.addr, fnb.pubKeyCollateralAddress, fnb.pubKeyFundamentalnode},
    lastPing(fnb.lastPing),
    vchSig(fnb.vchSig),
    fAllowMixingTx(true)
{}

//
// When a new fundamentalnode broadcast is sent, update our information
//
bool CFundamentalnode::UpdateFromNewBroadcast(CFundamentalnodeBroadcast& fnb, CConnman& connman)
{
    if(fnb.sigTime <= sigTime && !fnb.fRecovery) return false;

    pubKeyFundamentalnode = fnb.pubKeyFundamentalnode;
    sigTime = fnb.sigTime;
    vchSig = fnb.vchSig;
    nProtocolVersion = fnb.nProtocolVersion;
    addr = fnb.addr;
    nPoSeBanScore = 0;
    nPoSeBanHeight = 0;
    nTimeLastChecked = 0;
    int nDos = 0;
    if(!fnb.lastPing || (fnb.lastPing && fnb.lastPing.CheckAndUpdate(this, true, nDos, connman))) {
        lastPing = fnb.lastPing;
        fnodeman.mapSeenFundamentalnodePing.insert(std::make_pair(lastPing.GetHash(), lastPing));
    }
    // if it matches our Fundamentalnode privkey...
    if(fFundamentalnodeMode && pubKeyFundamentalnode == activeFundamentalnode.pubKeyFundamentalnode) {
        nPoSeBanScore = -FUNDAMENTALNODE_POSE_BAN_MAX_SCORE;
        if(nProtocolVersion == PROTOCOL_VERSION) {
            // ... and PROTOCOL_VERSION, then we've been remotely activated ...
            activeFundamentalnode.ManageState(connman);
        } else {
            // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
            // but also do not ban the node we get this message from
            LogPrintf("CFundamentalnode::UpdateFromNewBroadcast -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", nProtocolVersion, PROTOCOL_VERSION);
            return false;
        }
    }
    return true;
}

//
// Deterministically calculate a given "score" for a Fundamentalnode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
arith_uint256 CFundamentalnode::CalculateScore(const uint256& blockHash) const
{
    // Deterministically calculate a "score" for a Fundamentalnode based on any given (block)hash
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << outpoint << nCollateralMinConfBlockHash << blockHash;
    return UintToArith256(ss.GetHash());
}

CFundamentalnode::CollateralStatus CFundamentalnode::CheckCollateral(const COutPoint& outpoint, const CPubKey& pubkey)
{
    int nHeight;
    return CheckCollateral(outpoint, pubkey, nHeight);
}

CFundamentalnode::CollateralStatus CFundamentalnode::CheckCollateral(const COutPoint& outpoint, const CPubKey& pubkey, int& nHeightRet)
{
    AssertLockHeld(cs_main);

    Coin coin;
    if(!GetUTXOCoin(outpoint, coin)) {
        return COLLATERAL_UTXO_NOT_FOUND;
    }

    if(coin.out.nValue != FN_MAGIC_AMOUNT * COIN) {
        return COLLATERAL_INVALID_AMOUNT;
    }

    if(pubkey == CPubKey() || coin.out.scriptPubKey != GetScriptForDestination(pubkey.GetID())) {
        return COLLATERAL_INVALID_PUBKEY;
    }

    nHeightRet = coin.nHeight;
    return COLLATERAL_OK;
}

void CFundamentalnode::Check(bool fForce)
{
    AssertLockHeld(cs_main);
    LOCK(cs);

    if(ShutdownRequested()) return;

    if(!fForce && (GetTime() - nTimeLastChecked < FUNDAMENTALNODE_CHECK_SECONDS)) return;
    nTimeLastChecked = GetTime();

    LogPrint("fundamentalnode", "CFundamentalnode::Check -- Fundamentalnode %s is in %s state\n", outpoint.ToStringShort(), GetStateString());

    //once spent, stop doing the checks
    if(IsOutpointSpent()) return;
    
    int nHeight = 0;
    /*if(!fUnitTest) {
        Coin coin;
        if(!GetUTXOCoin(outpoint, coin)) {
            nActiveState = FUNDAMENTALNODE_OUTPOINT_SPENT;
            LogPrint("fundamentalnode", "CFundamentalnode::Check -- Failed to find Fundamentalnode UTXO, fundamentalnode=%s\n", outpoint.ToStringShort());
            return;
        }

        nHeight = chainActive.Height();
    }
    */
    if(IsPoSeBanned()) {
        if(nHeight < nPoSeBanHeight) return; // too early?
        // Otherwise give it a chance to proceed further to do all the usual checks and to change its state.
        // Fundamentalnode still will be on the edge and can be banned back easily if it keeps ignoring fnverify
        // or connect attempts. Will require few fnverify messages to strengthen its position in fn list.
        LogPrintf("CFundamentalnode::Check -- Fundamentalnode %s is unbanned and back in list now\n", outpoint.ToStringShort());
        DecreasePoSeBanScore();
    } else if(nPoSeBanScore >= FUNDAMENTALNODE_POSE_BAN_MAX_SCORE) {
        nActiveState = FUNDAMENTALNODE_POSE_BAN;
        // ban for the whole payment cycle
        nPoSeBanHeight = nHeight + fnodeman.size();
        LogPrintf("CFundamentalnode::Check -- Fundamentalnode %s is banned till block %d now\n", outpoint.ToStringShort(), nPoSeBanHeight);
        return;
    }

    int nActiveStatePrev = nActiveState;
    bool fOurFundamentalnode = fFundamentalnodeMode && activeFundamentalnode.pubKeyFundamentalnode == pubKeyFundamentalnode;

                   // fundamentalnode doesn't meet payment protocol requirements ...
    bool fRequireUpdate = nProtocolVersion < fnpayments.GetMinFundamentalnodePaymentsProto() ||
                   // or it's our own node and we just updated it to the new protocol but we are still waiting for activation ...
                   (fOurFundamentalnode && nProtocolVersion < PROTOCOL_VERSION);

    if(fRequireUpdate) {
        nActiveState = FUNDAMENTALNODE_UPDATE_REQUIRED;
        if(nActiveStatePrev != nActiveState) {
            LogPrint("fundamentalnode", "CFundamentalnode::Check -- Fundamentalnode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
        }
        return;
    }

    // keep old fundamentalnodes on start, give them a chance to receive updates...
    bool fWaitForPing = !fundamentalnodeSync.IsFundamentalnodeListSynced() && !IsPingedWithin(FUNDAMENTALNODE_MIN_MNP_SECONDS);

    if(fWaitForPing && !fOurFundamentalnode) {
        // ...but if it was already expired before the initial check - return right away
        if(IsExpired() || IsSentinelPingExpired() || IsNewStartRequired()) {
            LogPrint("fundamentalnode", "CFundamentalnode::Check -- Fundamentalnode %s is in %s state, waiting for ping\n", outpoint.ToStringShort(), GetStateString());
            return;
        }
    }

    // don't expire if we are still in "waiting for ping" mode unless it's our own fundamentalnode
    if(!fWaitForPing || fOurFundamentalnode) {

        if(!IsPingedWithin(FUNDAMENTALNODE_NEW_START_REQUIRED_SECONDS)) {
            nActiveState = FUNDAMENTALNODE_NEW_START_REQUIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint("fundamentalnode", "CFundamentalnode::Check -- Fundamentalnode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
            }
            return;
        }

        if(!IsPingedWithin(FUNDAMENTALNODE_EXPIRATION_SECONDS)) {
            nActiveState = FUNDAMENTALNODE_EXPIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint("fundamentalnode", "CFundamentalnode::Check -- Fundamentalnode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
            }
            return;
        }

        // part 1: expire based on securetagd ping
        bool fSentinelPingActive = fundamentalnodeSync.IsSynced() && fnodeman.IsSentinelPingActive();
        bool fSentinelPingExpired = fSentinelPingActive && !IsPingedWithin(FUNDAMENTALNODE_SENTINEL_PING_MAX_SECONDS);
        LogPrint("fundamentalnode", "CFundamentalnode::Check -- outpoint=%s, GetAdjustedTime()=%d, fSentinelPingExpired=%d\n",
                outpoint.ToStringShort(), GetAdjustedTime(), fSentinelPingExpired);

        if(fSentinelPingExpired) {
            nActiveState = FUNDAMENTALNODE_SENTINEL_PING_EXPIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint("fundamentalnode", "CFundamentalnode::Check -- Fundamentalnode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
            }
            return;
        }
    }

    // We require MNs to be in PRE_ENABLED until they either start to expire or receive a ping and go into ENABLED state
    // Works on mainnet/testnet only and not the case on regtest/devnet.
    if (Params().NetworkIDString() != CBaseChainParams::REGTEST && Params().NetworkIDString() != CBaseChainParams::DEVNET) {
        if (lastPing.sigTime - sigTime < FUNDAMENTALNODE_MIN_MNP_SECONDS) {
            nActiveState = FUNDAMENTALNODE_PRE_ENABLED;
            if (nActiveStatePrev != nActiveState) {
                LogPrint("fundamentalnode", "CFundamentalnode::Check -- Fundamentalnode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
            }
            return;
        }
    }

    if(!fWaitForPing || fOurFundamentalnode) {
        // part 2: expire based on sentinel info
        bool fSentinelPingActive = fundamentalnodeSync.IsSynced() && fnodeman.IsSentinelPingActive();
        bool fSentinelPingExpired = fSentinelPingActive && !lastPing.fSentinelIsCurrent;

        LogPrint("fundamentalnode", "CFundamentalnode::Check -- outpoint=%s, GetAdjustedTime()=%d, fSentinelPingExpired=%d\n",
                outpoint.ToStringShort(), GetAdjustedTime(), fSentinelPingExpired);

        if(fSentinelPingExpired) {
            nActiveState = FUNDAMENTALNODE_SENTINEL_PING_EXPIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint("fundamentalnode", "CFundamentalnode::Check -- Fundamentalnode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
            }
            return;
        }
    }

    nActiveState = FUNDAMENTALNODE_ENABLED; // OK
    if(nActiveStatePrev != nActiveState) {
        LogPrint("fundamentalnode", "CFundamentalnode::Check -- Fundamentalnode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
    }
}

bool CFundamentalnode::IsValidNetAddr()
{
    return IsValidNetAddr(addr);
}

bool CFundamentalnode::IsValidNetAddr(CService addrIn)
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkIDString() == CBaseChainParams::REGTEST ||
            (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}

fundamentalnode_info_t CFundamentalnode::GetInfo() const
{
    fundamentalnode_info_t info{*this};
    info.nTimeLastPing = lastPing.sigTime;
    info.fInfoValid = true;
    return info;
}

std::string CFundamentalnode::StateToString(int nStateIn)
{
    switch(nStateIn) {
        case FUNDAMENTALNODE_PRE_ENABLED:            return "PRE_ENABLED";
        case FUNDAMENTALNODE_ENABLED:                return "ENABLED";
        case FUNDAMENTALNODE_EXPIRED:                return "EXPIRED";
        case FUNDAMENTALNODE_OUTPOINT_SPENT:         return "OUTPOINT_SPENT";
        case FUNDAMENTALNODE_UPDATE_REQUIRED:        return "UPDATE_REQUIRED";
        case FUNDAMENTALNODE_SENTINEL_PING_EXPIRED:  return "SENTINEL_PING_EXPIRED";
        case FUNDAMENTALNODE_NEW_START_REQUIRED:     return "NEW_START_REQUIRED";
        case FUNDAMENTALNODE_POSE_BAN:               return "POSE_BAN";
        default:                                return "UNKNOWN";
    }
}

std::string CFundamentalnode::GetStateString() const
{
    return StateToString(nActiveState);
}

std::string CFundamentalnode::GetStatus() const
{
    // TODO: return smth a bit more human readable here
    return GetStateString();
}

void CFundamentalnode::UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack)
{
    if(!pindex) return;

    const CBlockIndex *BlockReading = pindex;

    CScript fnpayee = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    LOCK(cs_mapFundamentalnodeBlocks);

    for (int i = 0; BlockReading && BlockReading->nHeight > nBlockLastPaid && i < nMaxBlocksToScanBack; i++) {
        if(fnpayments.mapFundamentalnodeBlocks.count(BlockReading->nHeight) &&
           fnpayments.mapFundamentalnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(fnpayee, 2))
        {
            CBlock block;
            if(!ReadBlockFromDisk(block, BlockReading, Params().GetConsensus())) // shouldn't really happen
                continue;

            const auto& coinbaseTransaction = (BlockReading->nHeight > Params().GetConsensus().nLastPoWBlock ? block.vtx[1] : block.vtx[0]);

            CAmount nFundamentalnodePayment = GetFundamentalnodePayment(BlockReading->nHeight, BlockReading->nMint);

            for(const CTxOut &txout : coinbaseTransaction->vout)
                if(fnpayee == txout.scriptPubKey && nFundamentalnodePayment == txout.nValue) {
                    nBlockLastPaid = BlockReading->nHeight;
                    nTimeLastPaid = BlockReading->nTime;
                    LogPrint("fnpayments", "CFundamentalnode::UpdateLastPaidBlock -- searching for block with payment to %s -- found new %d\n", outpoint.ToStringShort(), nBlockLastPaid);
                    return;
                }
        }

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    // Last payment for this fundamentalnode wasn't found in latest fnpayments blocks
    // or it was found in fnpayments blocks but wasn't found in the blockchain.
    // LogPrint(BCLog::FUNDAMENTALNODE, "CFundamentalnode::UpdateLastPaidBlock -- searching for block with payment to %s -- keeping old %d\n", vin.prevout.ToString(), nBlockLastPaid);
}

#ifdef ENABLE_WALLET
bool CFundamentalnodeBroadcast::Create(const std::string& strService, const std::string& strKeyFundamentalnode, const std::string& strTxHash, const std::string& strOutputIndex, std::string& strErrorRet, CFundamentalnodeBroadcast &fnbRet, bool fOffline)
{
    COutPoint outpoint;
    CPubKey pubKeyCollateralAddressNew;
    CKey keyCollateralAddressNew;
    CPubKey pubKeyFundamentalnodeNew;
    CKey keyFundamentalnodeNew;

    auto Log = [&strErrorRet](std::string sErr)->bool
    {
        strErrorRet = sErr;
        LogPrintf("CFundamentalnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    };

    // Wait for sync to finish because fnb simply won't be relayed otherwise
    if (!fOffline && !fundamentalnodeSync.IsSynced())
        return Log("Sync in progress. Must wait until sync is complete to start Fundamentalnode");

    if (!CMessageSigner::GetKeysFromSecret(strKeyFundamentalnode, keyFundamentalnodeNew, pubKeyFundamentalnodeNew))
        return Log(strprintf("Invalid fundamentalnode key %s", strKeyFundamentalnode));

    if (!pwalletMain->GetFundamentalnodeOutpointAndKeys(outpoint, pubKeyCollateralAddressNew, keyCollateralAddressNew, strTxHash, strOutputIndex))
        return Log(strprintf("Could not allocate outpoint %s:%s for fundamentalnode %s", strTxHash, strOutputIndex, strService));

    CService service;
    if (!Lookup(strService.c_str(), service, 0, false))
        return Log(strprintf("Invalid address %s for fundamentalnode.", strService));
    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (service.GetPort() != mainnetDefaultPort)
            return Log(strprintf("Invalid port %u for fundamentalnode %s, only %d is supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort));
    } else if (service.GetPort() == mainnetDefaultPort)
        return Log(strprintf("Invalid port %u for fundamentalnode %s, %d is the only supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort));

    return Create(outpoint, service, keyCollateralAddressNew, pubKeyCollateralAddressNew, keyFundamentalnodeNew, pubKeyFundamentalnodeNew, strErrorRet, fnbRet);
}

bool CFundamentalnodeBroadcast::Create(const COutPoint& outpoint, const CService& service, const CKey& keyCollateralAddressNew, const CPubKey& pubKeyCollateralAddressNew, const CKey& keyFundamentalnodeNew, const CPubKey& pubKeyFundamentalnodeNew, std::string &strErrorRet, CFundamentalnodeBroadcast &fnbRet)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    LogPrint("fundamentalnode", "CFundamentalnodeBroadcast::Create -- pubKeyCollateralAddressNew = %s, pubKeyFundamentalnodeNew.GetID() = %s\n",
             CBitcoinAddress(pubKeyCollateralAddressNew.GetID()).ToString(),
             pubKeyFundamentalnodeNew.GetID().ToString());

    auto Log = [&strErrorRet,&fnbRet](std::string sErr)->bool
    {
        strErrorRet = sErr;
        LogPrintf("CFundamentalnodeBroadcast::Create -- %s\n", strErrorRet);
        fnbRet = CFundamentalnodeBroadcast();
        return false;
    };

    CFundamentalnodePing fnp(outpoint);
    if (!fnp.Sign(keyFundamentalnodeNew, pubKeyFundamentalnodeNew))
        return Log(strprintf("Failed to sign ping, fundamentalnode=%s", outpoint.ToStringShort()));

    fnbRet = CFundamentalnodeBroadcast(service, outpoint, pubKeyCollateralAddressNew, pubKeyFundamentalnodeNew, PROTOCOL_VERSION);

    if (!fnbRet.IsValidNetAddr())
        return Log(strprintf("Invalid IP address, fundamentalnode=%s", outpoint.ToStringShort()));

    fnbRet.lastPing = fnp;
    if (!fnbRet.Sign(keyCollateralAddressNew))
        return Log(strprintf("Failed to sign broadcast, fundamentalnode=%s", outpoint.ToStringShort()));

    return true;
}
#endif // ENABLE_WALLET

bool CFundamentalnodeBroadcast::SimpleCheck(int& nDos)
{
    nDos = 0;

    AssertLockHeld(cs_main);

    // make sure addr is valid
    if(!IsValidNetAddr()) {
        LogPrintf("CFundamentalnodeBroadcast::SimpleCheck -- Invalid addr, rejected: fundamentalnode=%s  addr=%s\n",
                    outpoint.ToStringShort(), addr.ToString());
        return false;
    }

    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CFundamentalnodeBroadcast::SimpleCheck -- Signature rejected, too far into the future: fundamentalnode=%s\n", outpoint.ToStringShort());
        nDos = 1;
        return false;
    }

    // empty ping or incorrect sigTime/unknown blockhash
    if(!lastPing || !lastPing.SimpleCheck(nDos)) {
        // one of us is probably forked or smth, just mark it as expired and check the rest of the rules
        nActiveState = FUNDAMENTALNODE_EXPIRED;
    }

    if(nProtocolVersion < fnpayments.GetMinFundamentalnodePaymentsProto()) {
        LogPrintf("CFundamentalnodeBroadcast::SimpleCheck -- outdated Fundamentalnode: fundamentalnode=%s  nProtocolVersion=%d\n", outpoint.ToStringShort(), nProtocolVersion);
        nActiveState = FUNDAMENTALNODE_UPDATE_REQUIRED;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    if(pubkeyScript.size() != 25) {
        LogPrintf("CFundamentalnodeBroadcast::SimpleCheck -- pubKeyCollateralAddress has the wrong size\n");
        nDos = 100;
        return false;
    }

    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubKeyFundamentalnode.GetID());

    if(pubkeyScript2.size() != 25) {
        LogPrintf("CFundamentalnodeBroadcast::SimpleCheck -- pubKeyFundamentalnode has the wrong size\n");
        nDos = 100;
        return false;
    }

    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(addr.GetPort() != mainnetDefaultPort) return false;
    } else if(addr.GetPort() == mainnetDefaultPort) return false;

    return true;
}

bool CFundamentalnodeBroadcast::Update(CFundamentalnode* pfn, int& nDos, CConnman& connman)
{
    nDos = 0;

    AssertLockHeld(cs_main);

    if(pfn->sigTime == sigTime && !fRecovery) {
        // mapSeenFundamentalnodeBroadcast in CFundamentalnodeMan::CheckFnbAndUpdateFundamentalnodeList should filter legit duplicates
        // but this still can happen if we just started, which is ok, just do nothing here.
        return false;
    }

    // this broadcast is older than the one that we already have - it's bad and should never happen
    // unless someone is doing something fishy
    if(pfn->sigTime > sigTime) {
        LogPrintf("CFundamentalnodeBroadcast::Update -- Bad sigTime %d (existing broadcast is at %d) for Fundamentalnode %s %s\n",
                      sigTime, pfn->sigTime, outpoint.ToStringShort(), addr.ToString());
        return false;
    }

    pfn->Check();

    // fundamentalnode is banned by PoSe
    if(pfn->IsPoSeBanned()) {
        LogPrintf("CFundamentalnodeBroadcast::Update -- Banned by PoSe, fundamentalnode=%s\n", outpoint.ToStringShort());
        return false;
    }

    // IsVnAssociatedWithPubkey is validated once in CheckOutpoint, after that they just need to match
    if(pfn->pubKeyCollateralAddress != pubKeyCollateralAddress) {
        LogPrintf("CFundamentalnodeBroadcast::Update -- Got mismatched pubKeyCollateralAddress and outpoint\n");
        nDos = 33;
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintf("CFundamentalnodeBroadcast::Update -- CheckSignature() failed, fundamentalnode=%s\n", outpoint.ToStringShort());
        return false;
    }

    // if ther was no fundamentalnode broadcast recently or if it matches our Fundamentalnode privkey...
    if(!pfn->IsBroadcastedWithin(FUNDAMENTALNODE_MIN_MNB_SECONDS) || (fFundamentalnodeMode && pubKeyFundamentalnode == activeFundamentalnode.pubKeyFundamentalnode)) {
        // take the newest entry
        LogPrintf("CFundamentalnodeBroadcast::Update -- Got UPDATED Fundamentalnode entry: addr=%s\n", addr.ToString());
        if(pfn->UpdateFromNewBroadcast(*this, connman)) {
            pfn->Check();
            Relay(connman);
        }
        fundamentalnodeSync.BumpAssetLastTime("CFundamentalnodeBroadcast::Update");
    }

    return true;
}

bool CFundamentalnodeBroadcast::CheckOutpoint(int& nDos)
{
    // we are a fundamentalnode with the same outpoint (i.e. already activated) and this fnb is ours (matches our Fundamentalnode privkey)
    // so nothing to do here for us
    if(fFundamentalnodeMode && outpoint == activeFundamentalnode.outpoint && pubKeyFundamentalnode == activeFundamentalnode.pubKeyFundamentalnode) {
        return false;
    }

    AssertLockHeld(cs_main);

    int nHeight;
    uint256 hashBlock;
    CTransactionRef tx2;
    GetTransaction(outpoint.hash, tx2, Params().GetConsensus(), hashBlock, true);

    int64_t nValueIn = 0;

    BOOST_FOREACH (const CTxIn& txin, tx2->vin) {
        // First try finding the previous transaction in database
        CTransactionRef txPrev;
        uint256 hashBlockPrev;
        if (!GetTransaction(txin.prevout.hash, txPrev, Params().GetConsensus(), hashBlockPrev, true)) {
            LogPrintf("CheckInputsAndAdd: failed to find STG fundamentalnode transaction \n");
            continue; // previous transaction not in main chain
        }

       nValueIn += txPrev->vout[txin.prevout.n].nValue;

    }

    if(nValueIn - tx2->vout[outpoint.n].nValue < FUNDAMENTALNODE_AMOUNT - FN_MAGIC_AMOUNT){
        LogPrintf("fundamentalnode", "CFundamentalnodeBroadcast::CheckOutpoint -- Fundamentalnode UTXO should have spent 10000 SECURETAG, fundamentalnode=%s\n", outpoint.ToStringShort());
        nDos = 33;
        return false;
    }

    if(chainActive.Height() - nHeight + 1 < Params().GetConsensus().nFundamentalnodeMinimumConfirmations) {
        LogPrintf("CFundamentalnodeBroadcast::CheckOutpoint -- Fundamentalnode UTXO must have at least %d confirmations, fundamentalnode=%s\n",
                Params().GetConsensus().nFundamentalnodeMinimumConfirmations, outpoint.ToStringShort());
        // UTXO is legit but has not enough confirmations.
        // Maybe we miss few blocks, let this fnb be checked again later.
        fnodeman.mapSeenFundamentalnodeBroadcast.erase(GetHash());
        return false;
    }

    LogPrint("fundamentalnode", "CFundamentalnodeBroadcast::CheckOutpoint -- Fundamentalnode UTXO verified\n");

    // Verify that sig time is legit, should be at least not earlier than the timestamp of the block
    // at which collateral became nFundamentalnodeMinimumConfirmations blocks deep.
    // NOTE: this is not accurate because block timestamp is NOT guaranteed to be 100% correct one.
    CBlockIndex* pRequiredConfIndex = chainActive[nHeight + Params().GetConsensus().nFundamentalnodeMinimumConfirmations - 1]; // block where tx got nFundamentalnodeMinimumConfirmations
    if(pRequiredConfIndex->GetBlockTime() > sigTime) {
        LogPrintf("CFundamentalnodeBroadcast::CheckOutpoint -- Bad sigTime %d (%d conf block is at %d) for Fundamentalnode %s %s\n",
                  sigTime, Params().GetConsensus().nFundamentalnodeMinimumConfirmations, pRequiredConfIndex->GetBlockTime(), outpoint.ToStringShort(), addr.ToString());
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintf("CFundamentalnodeBroadcast::CheckOutpoint -- CheckSignature() failed, fundamentalnode=%s\n", outpoint.ToStringShort());
        return false;
    }

    // remember the block hash when collateral for this fundamentalnode had minimum required confirmations
    nCollateralMinConfBlockHash = pRequiredConfIndex->GetBlockHash();

    return true;
}

uint256 CFundamentalnodeBroadcast::GetHash() const
{
    // Note: doesn't match serialization

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << outpoint << uint8_t{} << 0xffffffff; // adding dummy values here to match old hashing format
    ss << pubKeyCollateralAddress;
    ss << sigTime;
    return ss.GetHash();
}

uint256 CFundamentalnodeBroadcast::GetSignatureHash() const
{
    // TODO: replace with "return SerializeHash(*this);" after migration to 70209
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << outpoint;
    ss << addr;
    ss << pubKeyCollateralAddress;
    ss << pubKeyFundamentalnode;
    ss << sigTime;
    ss << nProtocolVersion;
    return ss.GetHash();
}

bool CFundamentalnodeBroadcast::Sign(const CKey& keyCollateralAddress)
{
    std::string strError;

    sigTime = GetAdjustedTime();

    if (sporkManager.IsSporkActive(SPORK_6_NEW_SIGS)) {
        uint256 hash = GetSignatureHash();

        if (!CHashSigner::SignHash(hash, keyCollateralAddress, vchSig)) {
            LogPrintf("CFundamentalnodeBroadcast::Sign -- SignHash() failed\n");
            return false;
        }

        if (!CHashSigner::VerifyHash(hash, pubKeyCollateralAddress, vchSig, strError)) {
            LogPrintf("CFundamentalnodeBroadcast::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    } else {
        std::string strMessage = addr.ToString(false) + boost::lexical_cast<std::string>(sigTime) +
                        pubKeyCollateralAddress.GetID().ToString() + pubKeyFundamentalnode.GetID().ToString() +
                        boost::lexical_cast<std::string>(nProtocolVersion);

        if (!CMessageSigner::SignMessage(strMessage, vchSig, keyCollateralAddress)) {
            LogPrintf("CFundamentalnodeBroadcast::Sign -- SignMessage() failed\n");
            return false;
        }

        if (!CMessageSigner::VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)) {
            LogPrintf("CFundamentalnodeBroadcast::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

bool CFundamentalnodeBroadcast::CheckSignature(int& nDos) const
{
    std::string strError = "";
    nDos = 0;

    if (sporkManager.IsSporkActive(SPORK_6_NEW_SIGS)) {
        uint256 hash = GetSignatureHash();

        if (!CHashSigner::VerifyHash(hash, pubKeyCollateralAddress, vchSig, strError)) {
            // maybe it's in old format
            std::string strMessage = addr.ToString(false) + boost::lexical_cast<std::string>(sigTime) +
                            pubKeyCollateralAddress.GetID().ToString() + pubKeyFundamentalnode.GetID().ToString() +
                            boost::lexical_cast<std::string>(nProtocolVersion);

            if (!CMessageSigner::VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)){
                // nope, not in old format either
                LogPrintf("CFundamentalnodeBroadcast::CheckSignature -- Got bad Fundamentalnode announce signature, error: %s\n", strError);
                nDos = 100;
                return false;
            }
        }
    } else {
        std::string strMessage = addr.ToString(false) + boost::lexical_cast<std::string>(sigTime) +
                        pubKeyCollateralAddress.GetID().ToString() + pubKeyFundamentalnode.GetID().ToString() +
                        boost::lexical_cast<std::string>(nProtocolVersion);

        if (!CMessageSigner::VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)){
            LogPrintf("CFundamentalnodeBroadcast::CheckSignature -- Got bad Fundamentalnode announce signature, error: %s\n", strError);
            nDos = 100;
            return false;
        }
    }

    return true;
}

void CFundamentalnodeBroadcast::Relay(CConnman& connman) const
{
    // Do not relay until fully synced
    if(!fundamentalnodeSync.IsSynced()) {
        LogPrint("fundamentalnode", "CFundamentalnodeBroadcast::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_FUNDAMENTALNODE_ANNOUNCE, GetHash());
    connman.RelayInv(inv);
}

uint256 CFundamentalnodePing::GetHash() const
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    if (sporkManager.IsSporkActive(SPORK_6_NEW_SIGS)) {
        // TODO: replace with "return SerializeHash(*this);" after migration to 70209
        ss << fundamentalnodeOutpoint;
        ss << blockHash;
        ss << sigTime;
        ss << fSentinelIsCurrent;
        ss << nSentinelVersion;
        ss << nDaemonVersion;
    } else {
        // Note: doesn't match serialization

        ss << fundamentalnodeOutpoint << uint8_t{} << 0xffffffff; // adding dummy values here to match old hashing format
        ss << sigTime;
    }
    return ss.GetHash();
}

uint256 CFundamentalnodePing::GetSignatureHash() const
{
    return GetHash();
}

CFundamentalnodePing::CFundamentalnodePing(const COutPoint& outpoint)
{
    LOCK(cs_main);
    if (!chainActive.Tip() || chainActive.Height() < 12) return;

    fundamentalnodeOutpoint = outpoint;
    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
    nDaemonVersion = CLIENT_VERSION;
}

bool CFundamentalnodePing::Sign(const CKey& keyFundamentalnode, const CPubKey& pubKeyFundamentalnode)
{
    std::string strError;

    sigTime = GetAdjustedTime();

    if (sporkManager.IsSporkActive(SPORK_6_NEW_SIGS)) {
        uint256 hash = GetSignatureHash();

        if (!CHashSigner::SignHash(hash, keyFundamentalnode, vchSig)) {
            LogPrintf("CFundamentalnodePing::Sign -- SignHash() failed\n");
            return false;
        }

        if (!CHashSigner::VerifyHash(hash, pubKeyFundamentalnode, vchSig, strError)) {
            LogPrintf("CFundamentalnodePing::Sign -- VerifyHash() failed, error: %s\n", strError);
            return false;
        }
    } else {
        std::string strMessage = CTxIn(fundamentalnodeOutpoint).ToString() + blockHash.ToString() +
                    boost::lexical_cast<std::string>(sigTime);

        if (!CMessageSigner::SignMessage(strMessage, vchSig, keyFundamentalnode)) {
            LogPrintf("CFundamentalnodePing::Sign -- SignMessage() failed\n");
            return false;
        }

        if (!CMessageSigner::VerifyMessage(pubKeyFundamentalnode, vchSig, strMessage, strError)) {
            LogPrintf("CFundamentalnodePing::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

bool CFundamentalnodePing::CheckSignature(const CPubKey& pubKeyFundamentalnode, int &nDos) const
{
    std::string strError = "";
    nDos = 0;

    if (sporkManager.IsSporkActive(SPORK_6_NEW_SIGS)) {
        uint256 hash = GetSignatureHash();

        if (!CHashSigner::VerifyHash(hash, pubKeyFundamentalnode, vchSig, strError)) {
            std::string strMessage = CTxIn(fundamentalnodeOutpoint).ToString() + blockHash.ToString() +
                        boost::lexical_cast<std::string>(sigTime);

            if (!CMessageSigner::VerifyMessage(pubKeyFundamentalnode, vchSig, strMessage, strError)) {
                LogPrintf("CFundamentalnodePing::CheckSignature -- Got bad Fundamentalnode ping signature, fundamentalnode=%s, error: %s\n", fundamentalnodeOutpoint.ToStringShort(), strError);
                nDos = 33;
                return false;
            }
        }
    } else {
        std::string strMessage = CTxIn(fundamentalnodeOutpoint).ToString() + blockHash.ToString() +
                    boost::lexical_cast<std::string>(sigTime);

        if (!CMessageSigner::VerifyMessage(pubKeyFundamentalnode, vchSig, strMessage, strError)) {
            LogPrintf("CFundamentalnodePing::CheckSignature -- Got bad Fundamentalnode ping signature, fundamentalnode=%s, error: %s\n", fundamentalnodeOutpoint.ToStringShort(), strError);
            nDos = 33;
            return false;
        }
    }

    return true;
}

bool CFundamentalnodePing::SimpleCheck(int& nDos)
{
    // don't ban by default
    nDos = 0;

    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CFundamentalnodePing::SimpleCheck -- Signature rejected, too far into the future, fundamentalnode=%s\n", fundamentalnodeOutpoint.ToStringShort());
        nDos = 1;
        return false;
    }

    {
        AssertLockHeld(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if (mi == mapBlockIndex.end()) {
            LogPrint("fundamentalnode", "CFundamentalnodePing::SimpleCheck -- Fundamentalnode ping is invalid, unknown block hash: fundamentalnode=%s blockHash=%s\n", fundamentalnodeOutpoint.ToStringShort(), blockHash.ToString());
            // maybe we stuck or forked so we shouldn't ban this node, just fail to accept this ping
            // TODO: or should we also request this block?
            return false;
        }
    }

    LogPrint("fundamentalnode", "CFundamentalnodePing::SimpleCheck -- Fundamentalnode ping verified: fundamentalnode=%s  blockHash=%s  sigTime=%d\n", fundamentalnodeOutpoint.ToStringShort(), blockHash.ToString(), sigTime);
    return true;
}

bool CFundamentalnodePing::CheckAndUpdate(CFundamentalnode* pfn, bool fFromNewBroadcast, int& nDos, CConnman& connman)
{
    AssertLockHeld(cs_main);

    // don't ban by default
    nDos = 0;

    if (!SimpleCheck(nDos)) {
        return false;
    }

    if (pfn == NULL) {
        LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate -- Couldn't find Fundamentalnode entry, fundamentalnode=%s\n", fundamentalnodeOutpoint.ToStringShort());
        return false;
    }

    if(!fFromNewBroadcast) {
        if (pfn->IsUpdateRequired()) {
            LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate -- fundamentalnode protocol is outdated, fundamentalnode=%s\n", fundamentalnodeOutpoint.ToStringShort());
            return false;
        }

        if (pfn->IsNewStartRequired()) {
            LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate -- fundamentalnode is completely expired, new start is required, fundamentalnode=%s\n", fundamentalnodeOutpoint.ToStringShort());
            return false;
        }
    }

    {
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if ((*mi).second && (*mi).second->nHeight < chainActive.Height() - 24) {
            LogPrintf("CFundamentalnodePing::CheckAndUpdate -- Fundamentalnode ping is invalid, block hash is too old: fundamentalnode=%s  blockHash=%s\n", fundamentalnodeOutpoint.ToStringShort(), blockHash.ToString());
            // nDos = 1;
            return false;
        }
    }

    LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate -- New ping: fundamentalnode=%s  blockHash=%s  sigTime=%d\n", fundamentalnodeOutpoint.ToStringShort(), blockHash.ToString(), sigTime);

    // LogPrintf("fnping - Found corresponding fn for outpoint: %s\n", fundamentalnodeOutpoint.ToStringShort());
    // update only if there is no known ping for this fundamentalnode or
    // last ping was more then FUNDAMENTALNODE_MIN_MNP_SECONDS-60 ago comparing to this one
    if (pfn->IsPingedWithin(FUNDAMENTALNODE_MIN_MNP_SECONDS - 60, sigTime)) {
        LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate -- Fundamentalnode ping arrived too early, fundamentalnode=%s\n", fundamentalnodeOutpoint.ToStringShort());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }

    if (!CheckSignature(pfn->pubKeyFundamentalnode, nDos)) return false;

    // so, ping seems to be ok

    // if we are still syncing and there was no known ping for this fn for quite a while
    // (NOTE: assuming that FUNDAMENTALNODE_EXPIRATION_SECONDS/2 should be enough to finish fn list sync)
    if(!fundamentalnodeSync.IsFundamentalnodeListSynced() && !pfn->IsPingedWithin(FUNDAMENTALNODE_EXPIRATION_SECONDS/2)) {
        // let's bump sync timeout
        LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate -- bumping sync timeout, fundamentalnode=%s\n", fundamentalnodeOutpoint.ToStringShort());
        fundamentalnodeSync.BumpAssetLastTime("CFundamentalnodePing::CheckAndUpdate");
    }

    // let's store this ping as the last one
    LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate -- Fundamentalnode ping accepted, fundamentalnode=%s\n", fundamentalnodeOutpoint.ToStringShort());
    pfn->lastPing = *this;

    // and update fnodeman.mapSeenFundamentalnodeBroadcast.lastPing which is probably outdated
    CFundamentalnodeBroadcast fnb(*pfn);
    uint256 hash = fnb.GetHash();
    if (fnodeman.mapSeenFundamentalnodeBroadcast.count(hash)) {
        fnodeman.mapSeenFundamentalnodeBroadcast[hash].second.lastPing = *this;
    }

    // force update, ignoring cache
    pfn->Check(true);
    // relay ping for nodes in ENABLED/EXPIRED/SENTINEL_PING_EXPIRED state only, skip everyone else
    if (!pfn->IsEnabled() && !pfn->IsExpired() && !pfn->IsSentinelPingExpired()) return false;

    LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate -- Fundamentalnode ping acceepted and relayed, fundamentalnode=%s\n", fundamentalnodeOutpoint.ToStringShort());
    Relay(connman);

    return true;
}

void CFundamentalnodePing::Relay(CConnman& connman)
{
    // Do not relay until fully synced
    if(!fundamentalnodeSync.IsSynced()) {
        LogPrint("fundamentalnode", "CFundamentalnodePing::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_FUNDAMENTALNODE_PING, GetHash());
    connman.RelayInv(inv);
}

void CFundamentalnode::AddGovernanceVote(uint256 nGovernanceObjectHash)
{
    if(mapGovernanceObjectsVotedOn.count(nGovernanceObjectHash)) {
        mapGovernanceObjectsVotedOn[nGovernanceObjectHash]++;
    } else {
        mapGovernanceObjectsVotedOn.insert(std::make_pair(nGovernanceObjectHash, 1));
    }
}

void CFundamentalnode::RemoveGovernanceObject(uint256 nGovernanceObjectHash)
{
    std::map<uint256, int>::iterator it = mapGovernanceObjectsVotedOn.find(nGovernanceObjectHash);
    if(it == mapGovernanceObjectsVotedOn.end()) {
        return;
    }
    mapGovernanceObjectsVotedOn.erase(it);
}

/**
*   FLAG GOVERNANCE ITEMS AS DIRTY
*
*   - When fundamentalnode come and go on the network, we must flag the items they voted on to recalc it's cached flags
*
*/
void CFundamentalnode::FlagGovernanceItemsAsDirty()
{
    std::vector<uint256> vecDirty;
    {
        std::map<uint256, int>::iterator it = mapGovernanceObjectsVotedOn.begin();
        while(it != mapGovernanceObjectsVotedOn.end()) {
            vecDirty.push_back(it->first);
            ++it;
        }
    }
    for(size_t i = 0; i < vecDirty.size(); ++i) {
        fnodeman.AddDirtyGovernanceObjectHash(vecDirty[i]);
    }
}
