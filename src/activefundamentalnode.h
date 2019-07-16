// Copyright (c) 2014-2017 The SecureTag Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ACTIVEFUNDAMENTALNODE_H
#define ACTIVEFUNDAMENTALNODE_H

#include "chainparams.h"
#include "key.h"
#include "net.h"
#include "primitives/transaction.h"

class CActiveFundamentalnode;

static const int ACTIVE_FUNDAMENTALNODE_INITIAL          = 0; // initial state
static const int ACTIVE_FUNDAMENTALNODE_SYNC_IN_PROCESS  = 1;
static const int ACTIVE_FUNDAMENTALNODE_INPUT_TOO_NEW    = 2;
static const int ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE      = 3;
static const int ACTIVE_FUNDAMENTALNODE_STARTED          = 4;

extern CActiveFundamentalnode activeFundamentalnode;

// Responsible for activating the Fundamentalnode and pinging the network
class CActiveFundamentalnode
{
public:
    enum fundamentalnode_type_enum_t {
        FUNDAMENTALNODE_UNKNOWN = 0,
        FUNDAMENTALNODE_REMOTE  = 1
    };

private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    fundamentalnode_type_enum_t eType;

    bool fPingerEnabled;

    /// Ping Fundamentalnode
    bool SendFundamentalnodePing(CConnman& connman);

    //  sentinel ping data
    int64_t nSentinelPingTime;
    uint32_t nSentinelVersion;

public:
    // Keys for the active Fundamentalnode
    CPubKey pubKeyFundamentalnode;
    CKey keyFundamentalnode;

    // Initialized while registering Fundamentalnode
    COutPoint outpoint;
    CService service;

    int nState; // should be one of ACTIVE_FUNDAMENTALNODE_XXXX
    std::string strNotCapableReason;


    CActiveFundamentalnode()
        : eType(FUNDAMENTALNODE_UNKNOWN),
          fPingerEnabled(false),
          pubKeyFundamentalnode(),
          keyFundamentalnode(),
          outpoint(),
          service(),
          nState(ACTIVE_FUNDAMENTALNODE_INITIAL)
    {}

    /// Manage state of active Fundamentalnode
    void ManageState(CConnman& connman);

    std::string GetStateString() const;
    std::string GetStatus() const;
    std::string GetTypeString() const;

    bool UpdateSentinelPing(int version);

private:
    void ManageStateInitial(CConnman& connman);
    void ManageStateRemote();
};

#endif
