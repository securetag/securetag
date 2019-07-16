    // Copyright (c) 2014-2017 The SecureTag Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FUNDAMENTALNODE_PAYMENTS_H
#define FUNDAMENTALNODE_PAYMENTS_H

#include "util.h"
#include "core_io.h"
#include "key.h"
#include "fundamentalnode.h"
#include "net_processing.h"
#include "utilstrencodings.h"

class CFundamentalnodePayments;
class CFundamentalnodePaymentVote;
class CFundamentalnodeBlockPayees;

static const int FNPAYMENTS_SIGNATURES_REQUIRED         = 6;
static const int FNPAYMENTS_SIGNATURES_TOTAL            = 10;

//! minimum peer version that can receive and send fundamentalnode payment messages,
//  vote for fundamentalnode and be elected as a payment winner
// V1 - Last protocol version before update
// V2 - Newest protocol version
static const int MIN_FUNDAMENTALNODE_PAYMENT_PROTO_VERSION_1 = 70210;
static const int MIN_FUNDAMENTALNODE_PAYMENT_PROTO_VERSION_2 = 70211;

extern CCriticalSection cs_vecPayeesFN;
extern CCriticalSection cs_mapFundamentalnodeBlocks;
extern CCriticalSection cs_mapFundamentalnodePayeeVotes;

extern CFundamentalnodePayments fnpayments;

/// TODO: all 4 functions do not belong here really, they should be refactored/moved somewhere (main.cpp ?)
bool IsBlockValueValidFN(const CBlock& block, int nBlockHeight, CAmount expectedReward, CAmount actualReward, std::string& strErrorRet);
bool IsBlockPayeeValidFN(const CTransactionRef& txNew, int nBlockHeight, CAmount expectedReward, CAmount actualReward);
void AdjustFundamentalnodePayment(CMutableTransaction &tx, const CTxOut& txoutFundamentalnodePayment);
std::string GetRequiredPaymentsStringFN(int nBlockHeight);

class CFundamentalnodePayee
{
private:
    CScript scriptPubKey;
    std::vector<uint256> vecVoteHashes;

public:
    CFundamentalnodePayee() :
        scriptPubKey(),
        vecVoteHashes()
        {}

    CFundamentalnodePayee(CScript payee, uint256 hashIn) :
        scriptPubKey(payee),
        vecVoteHashes()
    {
        vecVoteHashes.push_back(hashIn);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CScriptBase*)(&scriptPubKey));
        READWRITE(vecVoteHashes);
    }

    CScript GetPayee() const { return scriptPubKey; }

    void AddVoteHash(uint256 hashIn) { vecVoteHashes.push_back(hashIn); }
    std::vector<uint256> GetVoteHashes() const { return vecVoteHashes; }
    int GetVoteCount() const { return vecVoteHashes.size(); }
};

// Keep track of votes for payees from fundamentalnodes
class CFundamentalnodeBlockPayees
{
public:
    int nBlockHeight;
    std::vector<CFundamentalnodePayee> vecPayeesFN;

    CFundamentalnodeBlockPayees() :
        nBlockHeight(0),
        vecPayeesFN()
        {}
    CFundamentalnodeBlockPayees(int nBlockHeightIn) :
        nBlockHeight(nBlockHeightIn),
        vecPayeesFN()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBlockHeight);
        READWRITE(vecPayeesFN);
    }

    void AddPayee(const CFundamentalnodePaymentVote& vote);
    bool GetBestPayee(CScript& payeeRet) const;
    bool HasPayeeWithVotes(const CScript& payeeIn, int nVotesReq) const;

    bool IsTransactionValid(const CTransactionRef& txNew) const;

    std::string GetRequiredPaymentsStringFN() const;
};

// vote for the winning payment
class CFundamentalnodePaymentVote
{
public:
    COutPoint fundamentalnodeOutpoint;

    int nBlockHeight;
    CScript payee;
    std::vector<unsigned char> vchSig;

    CFundamentalnodePaymentVote() :
        fundamentalnodeOutpoint(),
        nBlockHeight(0),
        payee(),
        vchSig()
        {}

    CFundamentalnodePaymentVote(COutPoint outpoint, int nBlockHeight, CScript payee) :
        fundamentalnodeOutpoint(outpoint),
        nBlockHeight(nBlockHeight),
        payee(payee),
        vchSig()
        {}

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
        READWRITE(nBlockHeight);
        READWRITE(*(CScriptBase*)(&payee));
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
    }

    uint256 GetHash() const;
    uint256 GetSignatureHash() const;

    bool Sign();
    bool CheckSignature(const CPubKey& pubKeyFundamentalnode, int nValidationHeight, int &nDos) const;

    bool IsValid(CNode* pnode, int nValidationHeight, std::string& strError, CConnman& connman) const;
    void Relay(CConnman& connman) const;

    bool IsVerified() const { return !vchSig.empty(); }
    void MarkAsNotVerified() { vchSig.clear(); }

    std::string ToString() const;
};

//
// Fundamentalnode Payments Class
// Keeps track of who should get paid for which blocks
//

class CFundamentalnodePayments
{
private:
    // fundamentalnode count times nStorageCoeff payments blocks should be stored ...
    const float nStorageCoeff;
    // ... but at least nMinBlocksToStore (payments blocks)
    const int nMinBlocksToStore;

    // Keep track of current block height
    int nCachedBlockHeight;

public:
    std::map<uint256, CFundamentalnodePaymentVote> mapFundamentalnodePaymentVotes;
    std::map<int, CFundamentalnodeBlockPayees> mapFundamentalnodeBlocks;
    std::map<COutPoint, int> mapFundamentalnodesLastVote;
    std::map<COutPoint, int> mapFundamentalnodesDidNotVote;

    CFundamentalnodePayments() : nStorageCoeff(1.25), nMinBlocksToStore(6000) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(mapFundamentalnodePaymentVotes);
        READWRITE(mapFundamentalnodeBlocks);
    }

    void Clear();

    bool AddOrUpdatePaymentVote(const CFundamentalnodePaymentVote& vote);
    bool HasVerifiedPaymentVote(const uint256& hashIn) const;
    bool ProcessBlock(int nBlockHeight, CConnman& connman);
    void CheckBlockVotes(int nBlockHeight);

    void Sync(CNode* node, CConnman& connman) const;
    void RequestLowDataPaymentBlocks(CNode* pnode, CConnman& connman) const;
    void CheckAndRemove();

    bool GetBlockPayeeFN(int nBlockHeight, CScript& payeeRet) const;
    bool IsTransactionValid(const CTransactionRef& txNew, int nBlockHeight);
    bool IsScheduled(const fundamentalnode_info_t& fnInfo, int nNotBlockHeight) const;

    bool UpdateLastVote(const CFundamentalnodePaymentVote& vote);

    int GetMinFundamentalnodePaymentsProto() const;
    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);
    std::string GetRequiredPaymentsStringFN(int nBlockHeight);
    void FillBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutFundamentalnodeRet) const;
    std::string ToString() const;

    int GetBlockCount() const { return mapFundamentalnodeBlocks.size(); }
    int GetVoteCount() const { return mapFundamentalnodePaymentVotes.size(); }

    bool IsEnoughData() const;
    int GetStorageLimit() const;

    void UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman);
};


#endif
