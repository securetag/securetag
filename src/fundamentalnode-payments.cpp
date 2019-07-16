// Copyright (c) 2014-2017 The SecureTag Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activefundamentalnode.h"
#include "consensus/validation.h"
#include "governance-classes.h"
#include "fundamentalnode-payments.h"
#include "fundamentalnode-sync.h"
#include "fundamentalnodeman.h"
#include "messagesigner.h"
#include "netfulfilledman.h"
#include "netmessagemaker.h"
#include "spork.h"
#include "util.h"

#include <boost/lexical_cast.hpp>

/** Object for who's going to get paid on which blocks */
CFundamentalnodePayments fnpayments;

CCriticalSection cs_vecPayeesFN;
CCriticalSection cs_mapFundamentalnodeBlocks;
CCriticalSection cs_mapFundamentalnodePaymentVotes;

/**
* IsBlockValueValidFN
*
*   Determine if coinbase outgoing created money is the correct value
*
*   Why is this needed?
*   - In SecureTag some blocks are superblocks, which output much higher amounts of coins
*   - Otherblocks are 10% lower in outgoing value, so in total, no extra coins are created
*   - When non-superblocks are detected, the normal schedule should be maintained
*/

bool IsBlockValueValidFN(const CBlock& block, int nBlockHeight, CAmount expectedReward, CAmount actualReward, std::string& strErrorRet)
{
    strErrorRet = "";
    const auto& coinbaseTransaction = (nBlockHeight > Params().GetConsensus().nLastPoWBlock ? block.vtx[1] : block.vtx[0]);

    bool isBlockRewardValueMet = (actualReward <= expectedReward);
    if(fDebug) LogPrintf("actualReward %lld <= blockReward %lld\n", actualReward, expectedReward);

    // we are still using budgets, but we have no data about them anymore,
    // all we know is predefined budget cycle and window

    const Consensus::Params& consensusParams = Params().GetConsensus();

    if(nBlockHeight < consensusParams.nSuperblockStartBlock) {
        int nOffset = nBlockHeight % consensusParams.nBudgetPaymentsCycleBlocks;
        if(nBlockHeight >= consensusParams.nBudgetPaymentsStartBlock &&
            nOffset < consensusParams.nBudgetPaymentsWindowBlocks) {
            // NOTE: old budget system is disabled since 12.1
            if(fundamentalnodeSync.IsSynced()) {
                // no old budget blocks should be accepted here on mainnet,
                // testnet/devnet/regtest should produce regular blocks only
                LogPrint("gobject", "IsBlockValueValidFN -- WARNING: Client synced but old budget system is disabled, checking block value against block reward\n");
                if(!isBlockRewardValueMet) {
                    strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, old budgets are disabled",
                                            nBlockHeight, actualReward, expectedReward);
                }
                return isBlockRewardValueMet;
            }
            // when not synced, rely on online nodes (all networks)
            LogPrint("gobject", "IsBlockValueValidFN -- WARNING: Skipping old budget block value checks, accepting block\n");
            return true;
        }
        // LogPrint("gobject", "IsBlockValueValidFN -- Block is not in budget cycle window, checking block value against block reward\n");
        if(!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, block is not in old budget cycle window",
                                    nBlockHeight, actualReward, expectedReward);
        }
        return isBlockRewardValueMet;
    }

    // superblocks started

    CAmount nSuperblockMaxValue =  expectedReward + CSuperblock::GetPaymentsLimit(nBlockHeight);
    bool isSuperblockMaxValueMet = (actualReward <= nSuperblockMaxValue);

    LogPrint("gobject", "block.vtx[0]->GetValueOut() %lld <= nSuperblockMaxValue %lld\n", block.vtx[0]->GetValueOut(), nSuperblockMaxValue);

    if(!fundamentalnodeSync.IsSynced() || fLiteMode) {
        // not enough data but at least it must NOT exceed superblock max value
        if(CSuperblock::IsValidBlockHeight(nBlockHeight)) {
            if(fDebug) LogPrintf("IsBlockPayeeValidFN -- WARNING: Not enough data, checking superblock max bounds only\n");
            if(!isSuperblockMaxValueMet) {
                strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded superblock max value",
                                        nBlockHeight, actualReward, nSuperblockMaxValue);
            }
            return isSuperblockMaxValueMet;
        }
        if(!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, only regular blocks are allowed at this height",
                                    nBlockHeight, actualReward, expectedReward);
        }
        // it MUST be a regular block otherwise
        return isBlockRewardValueMet;
    }

    // we are synced, let's try to check as much data as we can

    if(sporkManager.IsSporkActive(SPORK_10_SUPERBLOCKS_ENABLED)) {
        if(CSuperblockManager::IsSuperblockTriggered(nBlockHeight)) {
            if(CSuperblockManager::IsValid(coinbaseTransaction, nBlockHeight, actualReward, expectedReward)) {
                LogPrint("gobject", "IsBlockValueValidFN -- Valid superblock at height %d: %s", nBlockHeight, block.vtx[0]->ToString());
                // all checks are done in CSuperblock::IsValid, nothing to do here
                return true;
            }

            // triggered but invalid? that's weird
            LogPrintf("IsBlockValueValidFN -- ERROR: Invalid superblock detected at height %d: %s", nBlockHeight, block.vtx[0]->ToString());
            // should NOT allow invalid superblocks, when superblocks are enabled
            strErrorRet = strprintf("invalid superblock detected at height %d", nBlockHeight);
            return false;
        }
        LogPrint("gobject", "IsBlockValueValidFN -- No triggered superblock detected at height %d\n", nBlockHeight);
        if(!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, no triggered superblock detected",
                                    nBlockHeight, actualReward, expectedReward);
        }
    } else {
        // should NOT allow superblocks at all, when superblocks are disabled
        LogPrint("gobject", "IsBlockValueValidFN -- Superblocks are disabled, no superblocks allowed\n");
        if(!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, superblocks are disabled",
                                    nBlockHeight, actualReward, expectedReward);
        }
    }

    // it MUST be a regular block
    return isBlockRewardValueMet;
}

bool IsBlockPayeeValidFN(const CTransactionRef& txNew, int nBlockHeight, CAmount expectedReward, CAmount actualReward)
{
    if(!fundamentalnodeSync.IsSynced() || fLiteMode) {
        //there is no budget data to use to check anything, let's just accept the longest chain
        if(fDebug) LogPrintf("IsBlockPayeeValidFN -- WARNING: Not enough data, skipping block payee checks\n");
        return true;
    }

    // we are still using budgets, but we have no data about them anymore,
    // we can only check fundamentalnode payments

    const Consensus::Params& consensusParams = Params().GetConsensus();

    if(nBlockHeight < consensusParams.nSuperblockStartBlock) {
        // NOTE: old budget system is disabled since 12.1 and we should never enter this branch
        // anymore when sync is finished (on mainnet). We have no old budget data but these blocks
        // have tons of confirmations and can be safely accepted without payee verification
        LogPrint("gobject", "IsBlockPayeeValidFN -- WARNING: Client synced but old budget system is disabled, accepting any payee\n");
        return true;
    }

    // superblocks started
    // SEE IF THIS IS A VALID SUPERBLOCK

    if(sporkManager.IsSporkActive(SPORK_10_SUPERBLOCKS_ENABLED)) {
        if(CSuperblockManager::IsSuperblockTriggered(nBlockHeight)) {
            if(CSuperblockManager::IsValid(txNew, nBlockHeight, expectedReward, actualReward)) {
                LogPrint("gobject", "IsBlockPayeeValidFN -- Valid superblock at height %d: %s", nBlockHeight, txNew->ToString());
                return true;
            }

            LogPrintf("IsBlockPayeeValidFN -- ERROR: Invalid superblock detected at height %d: %s", nBlockHeight, txNew->ToString());
            // should NOT allow such superblocks, when superblocks are enabled
            return false;
        }
        // continue validation, should pay MN
        LogPrint("gobject", "IsBlockPayeeValidFN -- No triggered superblock detected at height %d\n", nBlockHeight);
    } else {
        // should NOT allow superblocks at all, when superblocks are disabled
        LogPrint("gobject", "IsBlockPayeeValidFN -- Superblocks are disabled, no superblocks allowed\n");
    }

    // IF THIS ISN'T A SUPERBLOCK OR SUPERBLOCK IS INVALID, IT SHOULD PAY A FUNDAMENTALNODE DIRECTLY
    if(fnpayments.IsTransactionValid(txNew, nBlockHeight)) {
        LogPrint("fnpayments", "IsBlockPayeeValidFN -- Valid fundamentalnode payment at height %d: %s", nBlockHeight, txNew->ToString());
        return true;
    }

    if(sporkManager.IsSporkActive(SPORK_9_FUNDAMENTALNODE_PAYMENT_ENFORCEMENT)) {
        LogPrintf("IsBlockPayeeValidFN -- ERROR: Invalid fundamentalnode payment detected at height %d: %s", nBlockHeight, txNew->ToString());
        return false;
    }

    LogPrintf("IsBlockPayeeValidFN -- WARNING: Fundamentalnode payment enforcement is disabled, accepting any payee\n");
    return true;
}

std::string GetRequiredPaymentsStringFN(int nBlockHeight)
{
    // IF WE HAVE A ACTIVATED TRIGGER FOR THIS HEIGHT - IT IS A SUPERBLOCK, GET THE REQUIRED PAYEES
    /*if(CSuperblockManager::IsSuperblockTriggered(nBlockHeight)) {
        return CSuperblockManager::GetRequiredPaymentsString(nBlockHeight);
    }
    */
    // OTHERWISE, PAY FUNDAMENTALNODE
    return fnpayments.GetRequiredPaymentsStringFN(nBlockHeight);
}

void CFundamentalnodePayments::Clear()
{
    LOCK2(cs_mapFundamentalnodeBlocks, cs_mapFundamentalnodePaymentVotes);
    mapFundamentalnodeBlocks.clear();
    mapFundamentalnodePaymentVotes.clear();
}

bool CFundamentalnodePayments::UpdateLastVote(const CFundamentalnodePaymentVote& vote)
{
    LOCK(cs_mapFundamentalnodePaymentVotes);

    const auto it = mapFundamentalnodesLastVote.find(vote.fundamentalnodeOutpoint);
    if (it != mapFundamentalnodesLastVote.end()) {
        if (it->second == vote.nBlockHeight)
            return false;
        it->second = vote.nBlockHeight;
        return true;
    }

    //record this fundamentalnode voted
    mapFundamentalnodesLastVote.emplace(vote.fundamentalnodeOutpoint, vote.nBlockHeight);
    return true;
}

/**
*   FillBlockPayee
*
*   Fill Fundamentalnode ONLY payment block
*/

void CFundamentalnodePayments::FillBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutFundamentalnodeRet) const
{
    // make sure it's not filled yet
    txoutFundamentalnodeRet = CTxOut();

    CScript payee;

    if(!GetBlockPayeeFN(nBlockHeight, payee)) {
        // no fundamentalnode detected...
        int nCount = 0;
        fundamentalnode_info_t fnInfo;
        if(!fnodeman.GetNextFundamentalnodeInQueueForPayment(nBlockHeight, true, nCount, fnInfo)) {
            // ...and we can't calculate it on our own
            LogPrintf("CFundamentalnodePayments::FillBlockPayee -- Failed to detect fundamentalnode to pay\n");
            return;
        }
        // fill payee with locally calculated winner and hope for the best
        payee = GetScriptForDestination(fnInfo.pubKeyCollateralAddress.GetID());
    }

    // GET FUNDAMENTALNODE PAYMENT VARIABLES SETUP
    CAmount fundamentalnodePayment = GetFundamentalnodePayment(nBlockHeight, blockReward);
    
    txoutFundamentalnodeRet = CTxOut(fundamentalnodePayment, payee);
    txNew.vout.push_back(txoutFundamentalnodeRet);

    CTxDestination address1;
    ExtractDestination(payee, address1);
    CBitcoinAddress address2(address1);

    LogPrintf("CFundamentalnodePayments::FillBlockPayee -- Fundamentalnode payment %lld to %s\n", fundamentalnodePayment, address2.ToString());
}

int CFundamentalnodePayments::GetMinFundamentalnodePaymentsProto() const {
    return sporkManager.IsSporkActive(SPORK_12_FUNDAMENTALNODE_PAY_UPDATED_NODES)
            ? MIN_FUNDAMENTALNODE_PAYMENT_PROTO_VERSION_2
            : MIN_FUNDAMENTALNODE_PAYMENT_PROTO_VERSION_1;
}

void CFundamentalnodePayments::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if(fLiteMode) return; // disable all SecureTag specific functionality

    if (strCommand == NetMsgType::FUNDAMENTALNODEPAYMENTSYNC) { //Fundamentalnode Payments Request Sync

        if(pfrom->nVersion < GetMinFundamentalnodePaymentsProto()) {
            LogPrint("fnpayments", "FUNDAMENTALNODEPAYMENTSYNC -- peer=%d using obsolete version %i\n", pfrom->id, pfrom->nVersion);
            connman.PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", GetMinFundamentalnodePaymentsProto())));
            return;
        }

        // Ignore such requests until we are fully synced.
        // We could start processing this after fundamentalnode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!fundamentalnodeSync.IsSynced()) return;

        // DEPRECATED, should be removed on next protocol bump
        if(pfrom->nVersion == 70208) {
            int nCountNeeded;
            vRecv >> nCountNeeded;
        }

        if(netfulfilledman.HasFulfilledRequest(pfrom->addr, NetMsgType::FUNDAMENTALNODEPAYMENTSYNC)) {
            LOCK(cs_main);
            // Asking for the payments list multiple times in a short period of time is no good
            LogPrintf("FUNDAMENTALNODEPAYMENTSYNC -- peer already asked me for the list, peer=%d\n", pfrom->id);
            Misbehaving(pfrom->GetId(), 20);
            return;
        }
        netfulfilledman.AddFulfilledRequest(pfrom->addr, NetMsgType::FUNDAMENTALNODEPAYMENTSYNC);

        Sync(pfrom, connman);
        LogPrintf("FUNDAMENTALNODEPAYMENTSYNC -- Sent Fundamentalnode payment votes to peer=%d\n", pfrom->id);

    } else if (strCommand == NetMsgType::FUNDAMENTALNODEPAYMENTVOTE) { // Fundamentalnode Payments Vote for the Winner

        CFundamentalnodePaymentVote vote;
        vRecv >> vote;

        if(pfrom->nVersion < GetMinFundamentalnodePaymentsProto()) {
            LogPrint("fnpayments", "FUNDAMENTALNODEPAYMENTVOTE -- peer=%d using obsolete version %i\n", pfrom->id, pfrom->nVersion);
            connman.PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", GetMinFundamentalnodePaymentsProto())));
            return;
        }

        uint256 nHash = vote.GetHash();

        pfrom->setAskFor.erase(nHash);

        // TODO: clear setAskFor for MSG_FUNDAMENTALNODE_PAYMENT_BLOCK too

        // Ignore any payments messages until fundamentalnode list is synced
        if(!fundamentalnodeSync.IsFundamentalnodeListSynced()) return;

        {
            LOCK(cs_mapFundamentalnodePaymentVotes);

            auto res = mapFundamentalnodePaymentVotes.emplace(nHash, vote);

            // Avoid processing same vote multiple times if it was already verified earlier
            if(!res.second && res.first->second.IsVerified()) {
                LogPrint("fnpayments", "FUNDAMENTALNODEPAYMENTVOTE -- hash=%s, nBlockHeight=%d/%d seen\n",
                            nHash.ToString(), vote.nBlockHeight, nCachedBlockHeight);
                return;
            }

            // Mark vote as non-verified when it's seen for the first time,
            // AddOrUpdatePaymentVote() below should take care of it if vote is actually ok
            res.first->second.MarkAsNotVerified();
        }

        int nFirstBlock = nCachedBlockHeight - GetStorageLimit();
        if(vote.nBlockHeight < nFirstBlock || vote.nBlockHeight > nCachedBlockHeight+20) {
            LogPrint("fnpayments", "FUNDAMENTALNODEPAYMENTVOTE -- vote out of range: nFirstBlock=%d, nBlockHeight=%d, nHeight=%d\n", nFirstBlock, vote.nBlockHeight, nCachedBlockHeight);
            return;
        }

        std::string strError = "";
        if(!vote.IsValid(pfrom, nCachedBlockHeight, strError, connman)) {
            LogPrint("fnpayments", "FUNDAMENTALNODEPAYMENTVOTE -- invalid message, error: %s\n", strError);
            return;
        }

        fundamentalnode_info_t fnInfo;
        if(!fnodeman.GetFundamentalnodeInfo(vote.fundamentalnodeOutpoint, fnInfo)) {
            // fn was not found, so we can't check vote, some info is probably missing
            LogPrintf("FUNDAMENTALNODEPAYMENTVOTE -- fundamentalnode is missing %s\n", vote.fundamentalnodeOutpoint.ToStringShort());
            fnodeman.AskForMN(pfrom, vote.fundamentalnodeOutpoint, connman);
            return;
        }

        int nDos = 0;
        if(!vote.CheckSignature(fnInfo.pubKeyFundamentalnode, nCachedBlockHeight, nDos)) {
            if(nDos) {
                LOCK(cs_main);
                LogPrintf("FUNDAMENTALNODEPAYMENTVOTE -- ERROR: invalid signature\n");
                Misbehaving(pfrom->GetId(), nDos);
            } else {
                // only warn about anything non-critical (i.e. nDos == 0) in debug mode
                LogPrint("fnpayments", "FUNDAMENTALNODEPAYMENTVOTE -- WARNING: invalid signature\n");
            }
            // Either our info or vote info could be outdated.
            // In case our info is outdated, ask for an update,
            fnodeman.AskForMN(pfrom, vote.fundamentalnodeOutpoint, connman);
            // but there is nothing we can do if vote info itself is outdated
            // (i.e. it was signed by a fn which changed its key),
            // so just quit here.
            return;
        }

        if(!UpdateLastVote(vote)) {
            LogPrintf("FUNDAMENTALNODEPAYMENTVOTE -- fundamentalnode already voted, fundamentalnode=%s\n", vote.fundamentalnodeOutpoint.ToStringShort());
            return;
        }

        CTxDestination address1;
        ExtractDestination(vote.payee, address1);
        CBitcoinAddress address2(address1);

        LogPrint("fnpayments", "FUNDAMENTALNODEPAYMENTVOTE -- vote: address=%s, nBlockHeight=%d, nHeight=%d, prevout=%s, hash=%s new\n",
                    address2.ToString(), vote.nBlockHeight, nCachedBlockHeight, vote.fundamentalnodeOutpoint.ToStringShort(), nHash.ToString());

        if(AddOrUpdatePaymentVote(vote)){
            vote.Relay(connman);
            fundamentalnodeSync.BumpAssetLastTime("FUNDAMENTALNODEPAYMENTVOTE");
        }
    }
}

uint256 CFundamentalnodePaymentVote::GetHash() const
{
    // Note: doesn't match serialization

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << *(CScriptBase*)(&payee);
    ss << nBlockHeight;
    ss << fundamentalnodeOutpoint;
    return ss.GetHash();
}

uint256 CFundamentalnodePaymentVote::GetSignatureHash() const
{
    return SerializeHash(*this);
}

bool CFundamentalnodePaymentVote::Sign()
{
    std::string strError;

    if (sporkManager.IsSporkActive(SPORK_6_NEW_SIGS)) {
        uint256 hash = GetSignatureHash();

        if(!CHashSigner::SignHash(hash, activeFundamentalnode.keyFundamentalnode, vchSig)) {
            LogPrintf("CFundamentalnodePaymentVote::Sign -- SignHash() failed\n");
            return false;
        }

        if (!CHashSigner::VerifyHash(hash, activeFundamentalnode.pubKeyFundamentalnode, vchSig, strError)) {
            LogPrintf("CFundamentalnodePaymentVote::Sign -- VerifyHash() failed, error: %s\n", strError);
            return false;
        }
    } else {
        std::string strMessage = fundamentalnodeOutpoint.ToStringShort() +
                    boost::lexical_cast<std::string>(nBlockHeight) +
                    ScriptToAsmStr(payee);

        if(!CMessageSigner::SignMessage(strMessage, vchSig, activeFundamentalnode.keyFundamentalnode)) {
            LogPrintf("CFundamentalnodePaymentVote::Sign -- SignMessage() failed\n");
            return false;
        }

        if(!CMessageSigner::VerifyMessage(activeFundamentalnode.pubKeyFundamentalnode, vchSig, strMessage, strError)) {
            LogPrintf("CFundamentalnodePaymentVote::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

bool CFundamentalnodePayments::GetBlockPayeeFN(int nBlockHeight, CScript& payeeRet) const
{
    LOCK(cs_mapFundamentalnodeBlocks);

    auto it = mapFundamentalnodeBlocks.find(nBlockHeight);
    return it != mapFundamentalnodeBlocks.end() && it->second.GetBestPayee(payeeRet);
}

// Is this fundamentalnode scheduled to get paid soon?
// -- Only look ahead up to 8 blocks to allow for propagation of the latest 2 blocks of votes
bool CFundamentalnodePayments::IsScheduled(const fundamentalnode_info_t& fnInfo, int nNotBlockHeight) const
{
    LOCK(cs_mapFundamentalnodeBlocks);

    if(!fundamentalnodeSync.IsFundamentalnodeListSynced()) return false;

    CScript fnpayee;
    fnpayee = GetScriptForDestination(fnInfo.pubKeyCollateralAddress.GetID());

    CScript payee;
    for(int64_t h = nCachedBlockHeight; h <= nCachedBlockHeight + 8; h++){
        if(h == nNotBlockHeight) continue;
        if(GetBlockPayeeFN(h, payee) && fnpayee == payee) {
            return true;
        }
    }

    return false;
}

bool CFundamentalnodePayments::AddOrUpdatePaymentVote(const CFundamentalnodePaymentVote& vote)
{
    uint256 blockHash = uint256();
    if(!GetBlockHash(blockHash, vote.nBlockHeight - 101)) return false;

    uint256 nVoteHash = vote.GetHash();

    if(HasVerifiedPaymentVote(nVoteHash)) return false;

    LOCK2(cs_mapFundamentalnodeBlocks, cs_mapFundamentalnodePaymentVotes);

    mapFundamentalnodePaymentVotes[nVoteHash] = vote;

    auto it = mapFundamentalnodeBlocks.emplace(vote.nBlockHeight, CFundamentalnodeBlockPayees(vote.nBlockHeight)).first;
    it->second.AddPayee(vote);

    LogPrint("fnpayments", "CFundamentalnodePayments::AddOrUpdatePaymentVote -- added, hash=%s\n", nVoteHash.ToString());

    return true;
}

bool CFundamentalnodePayments::HasVerifiedPaymentVote(const uint256& hashIn) const
{
    LOCK(cs_mapFundamentalnodePaymentVotes);
    const auto it = mapFundamentalnodePaymentVotes.find(hashIn);
    return it != mapFundamentalnodePaymentVotes.end() && it->second.IsVerified();
}

void CFundamentalnodeBlockPayees::AddPayee(const CFundamentalnodePaymentVote& vote)
{
    LOCK(cs_vecPayeesFN);

    uint256 nVoteHash = vote.GetHash();

    for (auto& payee : vecPayeesFN) {
        if (payee.GetPayee() == vote.payee) {
            payee.AddVoteHash(nVoteHash);
            return;
        }
    }
    CFundamentalnodePayee payeeNew(vote.payee, nVoteHash);
    vecPayeesFN.push_back(payeeNew);
}

bool CFundamentalnodeBlockPayees::GetBestPayee(CScript& payeeRet) const
{
    LOCK(cs_vecPayeesFN);

    if(vecPayeesFN.empty()) {
        LogPrint("fnpayments", "CFundamentalnodeBlockPayees::GetBestPayee -- ERROR: couldn't find any payee\n");
        return false;
    }

    int nVotes = -1;
    for (const auto& payee : vecPayeesFN) {
        if (payee.GetVoteCount() > nVotes) {
            payeeRet = payee.GetPayee();
            nVotes = payee.GetVoteCount();
        }
    }

    return (nVotes > -1);
}

bool CFundamentalnodeBlockPayees::HasPayeeWithVotes(const CScript& payeeIn, int nVotesReq) const
{
    LOCK(cs_vecPayeesFN);

    for (const auto& payee : vecPayeesFN) {
        if (payee.GetVoteCount() >= nVotesReq && payee.GetPayee() == payeeIn) {
            return true;
        }
    }

    LogPrint("fnpayments", "CFundamentalnodeBlockPayees::HasPayeeWithVotes -- ERROR: couldn't find any payee with %d+ votes\n", nVotesReq);
    return false;
}

bool CFundamentalnodeBlockPayees::IsTransactionValid(const CTransactionRef& txNew) const
{
    LOCK(cs_vecPayeesFN);

    int nMaxSignatures = 0;
    std::string strPayeesPossible = "";

    CAmount nFundamentalnodePayment = GetFundamentalnodePayment(nBlockHeight, GetBlockSubsidy(nBlockHeight, Params().GetConsensus()));

    //require at least FNPAYMENTS_SIGNATURES_REQUIRED signatures

    for (const auto& payee : vecPayeesFN) {
        if (payee.GetVoteCount() >= nMaxSignatures) {
            nMaxSignatures = payee.GetVoteCount();
        }
    }

    // if we don't have at least FNPAYMENTS_SIGNATURES_REQUIRED signatures on a payee, approve whichever is the longest chain
    if(nMaxSignatures < FNPAYMENTS_SIGNATURES_REQUIRED) return true;

    for (const auto& payee : vecPayeesFN) {
        if (payee.GetVoteCount() >= FNPAYMENTS_SIGNATURES_REQUIRED) {
            for (const auto& txout : txNew->vout) {
                if (payee.GetPayee() == txout.scriptPubKey && nFundamentalnodePayment == txout.nValue) {
                    LogPrint("fnpayments", "CFundamentalnodeBlockPayees::IsTransactionValid -- Found required payment\n");
                    return true;
                }
            }

            CTxDestination address1;
            ExtractDestination(payee.GetPayee(), address1);
            CBitcoinAddress address2(address1);

            if(strPayeesPossible == "") {
                strPayeesPossible = address2.ToString();
            } else {
                strPayeesPossible += "," + address2.ToString();
            }
        }
    }

    LogPrintf("CFundamentalnodeBlockPayees::IsTransactionValid -- ERROR: Missing required payment, possible payees: '%s', amount: %f SECURETAG\n", strPayeesPossible, (float)nFundamentalnodePayment/COIN);
    return false;
}

std::string CFundamentalnodeBlockPayees::GetRequiredPaymentsStringFN() const
{
    LOCK(cs_vecPayeesFN);

    std::string strRequiredPayments = "";

    for (const auto& payee : vecPayeesFN)
    {
        CTxDestination address1;
        ExtractDestination(payee.GetPayee(), address1);
        CBitcoinAddress address2(address1);

        if (!strRequiredPayments.empty())
            strRequiredPayments += ", ";

        strRequiredPayments += strprintf("%s:%d", address2.ToString(), payee.GetVoteCount());
    }

    if (strRequiredPayments.empty())
        return "Unknown";

    return strRequiredPayments;
}

std::string CFundamentalnodePayments::GetRequiredPaymentsStringFN(int nBlockHeight)
{
    LOCK(cs_mapFundamentalnodeBlocks);

    if(mapFundamentalnodeBlocks.count(nBlockHeight)){
        return mapFundamentalnodeBlocks[nBlockHeight].GetRequiredPaymentsStringFN();
    }

    return "Unknown";
}


bool CFundamentalnodePayments::IsTransactionValid(const CTransactionRef& txNew, int nBlockHeight)
{
    LOCK(cs_mapFundamentalnodeBlocks);

    if(mapFundamentalnodeBlocks.count(nBlockHeight)){
        return mapFundamentalnodeBlocks[nBlockHeight].IsTransactionValid(txNew);
    }

    return true;
}

void CFundamentalnodePayments::CheckAndRemove()
{
    if(!fundamentalnodeSync.IsBlockchainSynced()) return;

    LOCK2(cs_mapFundamentalnodeBlocks, cs_mapFundamentalnodePaymentVotes);

    int nLimit = GetStorageLimit();

    std::map<uint256, CFundamentalnodePaymentVote>::iterator it = mapFundamentalnodePaymentVotes.begin();
    while(it != mapFundamentalnodePaymentVotes.end()) {
        CFundamentalnodePaymentVote vote = (*it).second;

        if(nCachedBlockHeight - vote.nBlockHeight > nLimit) {
            LogPrint("fnpayments", "CFundamentalnodePayments::CheckAndRemove -- Removing old Fundamentalnode payment: nBlockHeight=%d\n", vote.nBlockHeight);
            mapFundamentalnodePaymentVotes.erase(it++);
            mapFundamentalnodeBlocks.erase(vote.nBlockHeight);
        } else {
            ++it;
        }
    }
    LogPrintf("CFundamentalnodePayments::CheckAndRemove -- %s\n", ToString());
}

bool CFundamentalnodePaymentVote::IsValid(CNode* pnode, int nValidationHeight, std::string& strError, CConnman& connman) const
{
    fundamentalnode_info_t fnInfo;

    if(!fnodeman.GetFundamentalnodeInfo(fundamentalnodeOutpoint, fnInfo)) {
        strError = strprintf("Unknown fundamentalnode=%s", fundamentalnodeOutpoint.ToStringShort());
        // Only ask if we are already synced and still have no idea about that Fundamentalnode
        if(fundamentalnodeSync.IsFundamentalnodeListSynced()) {
            fnodeman.AskForMN(pnode, fundamentalnodeOutpoint, connman);
        }

        return false;
    }

    int nMinRequiredProtocol;
    if(nBlockHeight >= nValidationHeight) {
        // new votes must comply SPORK_10_FUNDAMENTALNODE_PAY_UPDATED_NODES rules
        nMinRequiredProtocol = fnpayments.GetMinFundamentalnodePaymentsProto();
    } else {
        // allow non-updated fundamentalnodes for old blocks
        nMinRequiredProtocol = MIN_FUNDAMENTALNODE_PAYMENT_PROTO_VERSION_1;
    }

    if(fnInfo.nProtocolVersion < nMinRequiredProtocol) {
        strError = strprintf("Fundamentalnode protocol is too old: nProtocolVersion=%d, nMinRequiredProtocol=%d", fnInfo.nProtocolVersion, nMinRequiredProtocol);
        return false;
    }

    // Only fundamentalnodes should try to check fundamentalnode rank for old votes - they need to pick the right winner for future blocks.
    // Regular clients (miners included) need to verify fundamentalnode rank for future block votes only.
    if(!fFundamentalnodeMode && nBlockHeight < nValidationHeight) return true;

    int nRank;

    if(!fnodeman.GetFundamentalnodeRank(fundamentalnodeOutpoint, nRank, nBlockHeight - 101, nMinRequiredProtocol)) {
        LogPrint("fnpayments", "CFundamentalnodePaymentVote::IsValid -- Can't calculate rank for fundamentalnode %s\n",
                    fundamentalnodeOutpoint.ToStringShort());
        return false;
    }

    if(nRank > FNPAYMENTS_SIGNATURES_TOTAL) {
        // It's common to have fundamentalnodes mistakenly think they are in the top 10
        // We don't want to print all of these messages in normal mode, debug mode should print though
        strError = strprintf("Fundamentalnode %s is not in the top %d (%d)", fundamentalnodeOutpoint.ToStringShort(), FNPAYMENTS_SIGNATURES_TOTAL, nRank);
        // Only ban for new fnw which is out of bounds, for old fnw MN list itself might be way too much off
        if(nRank > FNPAYMENTS_SIGNATURES_TOTAL*2 && nBlockHeight > nValidationHeight) {
            LOCK(cs_main);
            strError = strprintf("Fundamentalnode %s is not in the top %d (%d)", fundamentalnodeOutpoint.ToStringShort(), FNPAYMENTS_SIGNATURES_TOTAL*2, nRank);
            LogPrintf("CFundamentalnodePaymentVote::IsValid -- Error: %s\n", strError);
            Misbehaving(pnode->GetId(), 20);
        }
        // Still invalid however
        return false;
    }

    return true;
}

bool CFundamentalnodePayments::ProcessBlock(int nBlockHeight, CConnman& connman)
{
    // DETERMINE IF WE SHOULD BE VOTING FOR THE NEXT PAYEE

    if(fLiteMode || !fFundamentalnodeMode) return false;

    // We have little chances to pick the right winner if winners list is out of sync
    // but we have no choice, so we'll try. However it doesn't make sense to even try to do so
    // if we have not enough data about fundamentalnodes.
    if(!fundamentalnodeSync.IsFundamentalnodeListSynced()) return false;

    int nRank;

    if (!fnodeman.GetFundamentalnodeRank(activeFundamentalnode.outpoint, nRank, nBlockHeight - 101, GetMinFundamentalnodePaymentsProto())) {
        LogPrint("fnpayments", "CFundamentalnodePayments::ProcessBlock -- Unknown Fundamentalnode\n");
        return false;
    }

    if (nRank > FNPAYMENTS_SIGNATURES_TOTAL) {
        LogPrint("fnpayments", "CFundamentalnodePayments::ProcessBlock -- Fundamentalnode not in the top %d (%d)\n", FNPAYMENTS_SIGNATURES_TOTAL, nRank);
        return false;
    }


    // LOCATE THE NEXT FUNDAMENTALNODE WHICH SHOULD BE PAID

    LogPrintf("CFundamentalnodePayments::ProcessBlock -- Start: nBlockHeight=%d, fundamentalnode=%s\n", nBlockHeight, activeFundamentalnode.outpoint.ToStringShort());

    // pay to the oldest MN that still had no payment but its input is old enough and it was active long enough
    int nCount = 0;
    fundamentalnode_info_t fnInfo;

    if (!fnodeman.GetNextFundamentalnodeInQueueForPayment(nBlockHeight, true, nCount, fnInfo)) {
        LogPrintf("CFundamentalnodePayments::ProcessBlock -- ERROR: Failed to find fundamentalnode to pay\n");
        return false;
    }

    LogPrintf("CFundamentalnodePayments::ProcessBlock -- Fundamentalnode found by GetNextFundamentalnodeInQueueForPayment(): %s\n", fnInfo.outpoint.ToStringShort());


    CScript payee = GetScriptForDestination(fnInfo.pubKeyCollateralAddress.GetID());

    CFundamentalnodePaymentVote voteNew(activeFundamentalnode.outpoint, nBlockHeight, payee);

    CTxDestination address1;
    ExtractDestination(payee, address1);
    CBitcoinAddress address2(address1);

    LogPrintf("CFundamentalnodePayments::ProcessBlock -- vote: payee=%s, nBlockHeight=%d\n", address2.ToString(), nBlockHeight);

    // SIGN MESSAGE TO NETWORK WITH OUR FUNDAMENTALNODE KEYS

    LogPrintf("CFundamentalnodePayments::ProcessBlock -- Signing vote\n");
    if (voteNew.Sign()) {
        LogPrintf("CFundamentalnodePayments::ProcessBlock -- AddOrUpdatePaymentVote()\n");

        if (AddOrUpdatePaymentVote(voteNew)) {
            voteNew.Relay(connman);
            return true;
        }
    }

    return false;
}

void CFundamentalnodePayments::CheckBlockVotes(int nBlockHeight)
{
    if (!fundamentalnodeSync.IsWinnersListSynced()) return;

    CFundamentalnodeMan::rank_pair_vec_t fns;
    if (!fnodeman.GetFundamentalnodeRanks(fns, nBlockHeight - 101, GetMinFundamentalnodePaymentsProto())) {
        LogPrintf("CFundamentalnodePayments::CheckBlockVotes -- nBlockHeight=%d, GetFundamentalnodeRanks failed\n", nBlockHeight);
        return;
    }

    std::string debugStr;

    debugStr += strprintf("CFundamentalnodePayments::CheckBlockVotes -- nBlockHeight=%d,\n  Expected voting MNs:\n", nBlockHeight);

    LOCK2(cs_mapFundamentalnodeBlocks, cs_mapFundamentalnodePaymentVotes);

    int i{0};
    for (const auto& fn : fns) {
        CScript payee;
        bool found = false;

        const auto it = mapFundamentalnodeBlocks.find(nBlockHeight);
        if (it != mapFundamentalnodeBlocks.end()) {
            for (const auto& p : it->second.vecPayeesFN) {
                for (const auto& voteHash : p.GetVoteHashes()) {
                    const auto itVote = mapFundamentalnodePaymentVotes.find(voteHash);
                    if (itVote == mapFundamentalnodePaymentVotes.end()) {
                        debugStr += strprintf("    - could not find vote %s\n",
                                              voteHash.ToString());
                        continue;
                    }
                    if (itVote->second.fundamentalnodeOutpoint == fn.second.outpoint) {
                        payee = itVote->second.payee;
                        found = true;
                        break;
                    }
                }
            }
        }

        if (found) {
            CTxDestination address1;
            ExtractDestination(payee, address1);
            CBitcoinAddress address2(address1);

            debugStr += strprintf("    - %s - voted for %s\n",
                                  fn.second.outpoint.ToStringShort(), address2.ToString());
        } else {
            mapFundamentalnodesDidNotVote.emplace(fn.second.outpoint, 0).first->second++;

            debugStr += strprintf("    - %s - no vote received\n",
                                  fn.second.outpoint.ToStringShort());
        }

        if (++i >= FNPAYMENTS_SIGNATURES_TOTAL) break;
    }

    if (mapFundamentalnodesDidNotVote.empty()) {
        LogPrint("fnpayments", "%s", debugStr);
        return;
    }

    debugStr += "  Fundamentalnodes which missed a vote in the past:\n";
    for (const auto& item : mapFundamentalnodesDidNotVote) {
        debugStr += strprintf("    - %s: %d\n", item.first.ToStringShort(), item.second);
    }

    LogPrint("fnpayments", "%s", debugStr);
}

void CFundamentalnodePaymentVote::Relay(CConnman& connman) const
{
    // Do not relay until fully synced
    if(!fundamentalnodeSync.IsSynced()) {
        LogPrint("fnpayments", "CFundamentalnodePayments::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_FUNDAMENTALNODE_PAYMENT_VOTE, GetHash());
    connman.RelayInv(inv);
}

bool CFundamentalnodePaymentVote::CheckSignature(const CPubKey& pubKeyFundamentalnode, int nValidationHeight, int &nDos) const
{
    // do not ban by default
    nDos = 0;
    std::string strError = "";

    if (sporkManager.IsSporkActive(SPORK_6_NEW_SIGS)) {
        uint256 hash = GetSignatureHash();

        if (!CHashSigner::VerifyHash(hash, pubKeyFundamentalnode, vchSig, strError)) {
            // could be a signature in old format
            std::string strMessage = fundamentalnodeOutpoint.ToStringShort() +
                        boost::lexical_cast<std::string>(nBlockHeight) +
                        ScriptToAsmStr(payee);
            if(!CMessageSigner::VerifyMessage(pubKeyFundamentalnode, vchSig, strMessage, strError)) {
                // nope, not in old format either
                // Only ban for future block vote when we are already synced.
                // Otherwise it could be the case when MN which signed this vote is using another key now
                // and we have no idea about the old one.
                if(fundamentalnodeSync.IsFundamentalnodeListSynced() && nBlockHeight > nValidationHeight) {
                    nDos = 20;
                }
                return error("CFundamentalnodePaymentVote::CheckSignature -- Got bad Fundamentalnode payment signature, fundamentalnode=%s, error: %s",
                            fundamentalnodeOutpoint.ToStringShort(), strError);
            }
        }
    } else {
        std::string strMessage = fundamentalnodeOutpoint.ToStringShort() +
                    boost::lexical_cast<std::string>(nBlockHeight) +
                    ScriptToAsmStr(payee);

        if (!CMessageSigner::VerifyMessage(pubKeyFundamentalnode, vchSig, strMessage, strError)) {
            // Only ban for future block vote when we are already synced.
            // Otherwise it could be the case when MN which signed this vote is using another key now
            // and we have no idea about the old one.
            if(fundamentalnodeSync.IsFundamentalnodeListSynced() && nBlockHeight > nValidationHeight) {
                nDos = 20;
            }
            return error("CFundamentalnodePaymentVote::CheckSignature -- Got bad Fundamentalnode payment signature, fundamentalnode=%s, error: %s",
                        fundamentalnodeOutpoint.ToStringShort(), strError);
        }
    }

    return true;
}

std::string CFundamentalnodePaymentVote::ToString() const
{
    std::ostringstream info;

    info << fundamentalnodeOutpoint.ToStringShort() <<
            ", " << nBlockHeight <<
            ", " << ScriptToAsmStr(payee) <<
            ", " << (int)vchSig.size();

    return info.str();
}

// Send only votes for future blocks, node should request every other missing payment block individually
void CFundamentalnodePayments::Sync(CNode* pnode, CConnman& connman) const
{
    LOCK(cs_mapFundamentalnodeBlocks);

    if(!fundamentalnodeSync.IsWinnersListSynced()) return;

    int nInvCount = 0;

    for(int h = nCachedBlockHeight; h < nCachedBlockHeight + 20; h++) {
        const auto it = mapFundamentalnodeBlocks.find(h);
        if(it != mapFundamentalnodeBlocks.end()) {
            for (const auto& payee : it->second.vecPayeesFN) {
                std::vector<uint256> vecVoteHashes = payee.GetVoteHashes();
                for (const auto& hash : vecVoteHashes) {
                    if(!HasVerifiedPaymentVote(hash)) continue;
                    pnode->PushInventory(CInv(MSG_FUNDAMENTALNODE_PAYMENT_VOTE, hash));
                    nInvCount++;
                }
            }
        }
    }

    LogPrintf("CFundamentalnodePayments::Sync -- Sent %d votes to peer=%d\n", nInvCount, pnode->id);
    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::SYNCSTATUSCOUNTFN, FUNDAMENTALNODE_SYNC_MNW, nInvCount));
}

// Request low data/unknown payment blocks in batches directly from some node instead of/after preliminary Sync.
void CFundamentalnodePayments::RequestLowDataPaymentBlocks(CNode* pnode, CConnman& connman) const
{
    if(!fundamentalnodeSync.IsFundamentalnodeListSynced()) return;

    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    LOCK2(cs_main, cs_mapFundamentalnodeBlocks);

    std::vector<CInv> vToFetch;
    int nLimit = GetStorageLimit();

    const CBlockIndex *pindex = chainActive.Tip();

    while(nCachedBlockHeight - pindex->nHeight < nLimit) {
        const auto it = mapFundamentalnodeBlocks.find(pindex->nHeight);
        if(it == mapFundamentalnodeBlocks.end()) {
            // We have no idea about this block height, let's ask
            vToFetch.push_back(CInv(MSG_FUNDAMENTALNODE_PAYMENT_BLOCK, pindex->GetBlockHash()));
            // We should not violate GETDATA rules
            if(vToFetch.size() == MAX_INV_SZ) {
                LogPrintf("CFundamentalnodePayments::RequestLowDataPaymentBlocks -- asking peer=%d for %d blocks\n", pnode->id, MAX_INV_SZ);
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
                // Start filling new batch
                vToFetch.clear();
            }
        }
        if(!pindex->pprev) break;
        pindex = pindex->pprev;
    }

    auto it = mapFundamentalnodeBlocks.begin();

    while(it != mapFundamentalnodeBlocks.end()) {
        int nTotalVotes = 0;
        bool fFound = false;
        for (const auto& payee : it->second.vecPayeesFN) {
            if(payee.GetVoteCount() >= FNPAYMENTS_SIGNATURES_REQUIRED) {
                fFound = true;
                break;
            }
            nTotalVotes += payee.GetVoteCount();
        }
        // A clear winner (FNPAYMENTS_SIGNATURES_REQUIRED+ votes) was found
        // or no clear winner was found but there are at least avg number of votes
        if(fFound || nTotalVotes >= (FNPAYMENTS_SIGNATURES_TOTAL + FNPAYMENTS_SIGNATURES_REQUIRED)/2) {
            // so just move to the next block
            ++it;
            continue;
        }
        // DEBUG
        DBG (
            // Let's see why this failed
            for (const auto& payee : it->second.vecPayeesFN) {
                CTxDestination address1;
                ExtractDestination(payee.GetPayee(), address1);
                CBitcoinAddress address2(address1);
                printf("payee %s votes %d\n", address2.ToString().c_str(), payee.GetVoteCount());
            }
            printf("block %d votes total %d\n", it->first, nTotalVotes);
        )
        // END DEBUG
        // Low data block found, let's try to sync it
        uint256 hash;
        if(GetBlockHash(hash, it->first)) {
            vToFetch.push_back(CInv(MSG_FUNDAMENTALNODE_PAYMENT_BLOCK, hash));
        }
        // We should not violate GETDATA rules
        if(vToFetch.size() == MAX_INV_SZ) {
            LogPrintf("CFundamentalnodePayments::RequestLowDataPaymentBlocks -- asking peer=%d for %d payment blocks\n", pnode->id, MAX_INV_SZ);
            connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
            // Start filling new batch
            vToFetch.clear();
        }
        ++it;
    }
    // Ask for the rest of it
    if(!vToFetch.empty()) {
        LogPrintf("CFundamentalnodePayments::RequestLowDataPaymentBlocks -- asking peer=%d for %d payment blocks\n", pnode->id, vToFetch.size());
        connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
    }
}

std::string CFundamentalnodePayments::ToString() const
{
    std::ostringstream info;

    info << "Votes: " << (int)mapFundamentalnodePaymentVotes.size() <<
            ", Blocks: " << (int)mapFundamentalnodeBlocks.size();

    return info.str();
}

bool CFundamentalnodePayments::IsEnoughData() const
{
    float nAverageVotes = (FNPAYMENTS_SIGNATURES_TOTAL + FNPAYMENTS_SIGNATURES_REQUIRED) / 2;
    int nStorageLimit = GetStorageLimit();
    return GetBlockCount() > nStorageLimit && GetVoteCount() > nStorageLimit * nAverageVotes;
}

int CFundamentalnodePayments::GetStorageLimit() const
{
    return std::max(int(fnodeman.size() * nStorageCoeff), nMinBlocksToStore);
}

void CFundamentalnodePayments::UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman)
{
    if(!pindex) return;

    nCachedBlockHeight = pindex->nHeight;
    LogPrint("fnpayments", "CFundamentalnodePayments::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);

    int nFutureBlock = nCachedBlockHeight + 10;

    CheckBlockVotes(nFutureBlock - 1);
    ProcessBlock(nFutureBlock, connman);
}
void AdjustFundamentalnodePayment(CMutableTransaction &tx, const CTxOut &txoutFundamentalnodePayment)
{
    auto it = std::find(std::begin(tx.vout), std::end(tx.vout), txoutFundamentalnodePayment);

    if(it != std::end(tx.vout))
    {
        long fnPaymentOutIndex = std::distance(std::begin(tx.vout), it);
        auto fundamentalnodePayment = tx.vout[fnPaymentOutIndex].nValue;
        // For the special transaction the vout of MNpayefnt is the first.
        long i = tx.vout.size() - 2;
        tx.vout[i].nValue -= fundamentalnodePayment; // last vout is fn payment.
    }
}
