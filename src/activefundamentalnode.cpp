// Copyright (c) 2014-2017 The SecureTag Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activefundamentalnode.h"
#include "fundamentalnode.h"
#include "fundamentalnode-sync.h"
#include "fundamentalnodeman.h"
#include "netbase.h"
#include "protocol.h"

// Keep track of the active Fundamentalnode
CActiveFundamentalnode activeFundamentalnode;

void CActiveFundamentalnode::ManageState(CConnman& connman)
{
    LogPrint("fundamentalnode", "CActiveFundamentalnode::ManageState -- Start\n");
    if(!fFundamentalnodeMode) {
        LogPrint("fundamentalnode", "CActiveFundamentalnode::ManageState -- Not a fundamentalnode, returning\n");
        return;
    }

    if(Params().NetworkIDString() != CBaseChainParams::REGTEST && !fundamentalnodeSync.IsBlockchainSynced()) {
        nState = ACTIVE_FUNDAMENTALNODE_SYNC_IN_PROCESS;
        LogPrintf("CActiveFundamentalnode::ManageState -- %s: %s\n", GetStateString(), GetStatus());
        return;
    }

    if(nState == ACTIVE_FUNDAMENTALNODE_SYNC_IN_PROCESS) {
        nState = ACTIVE_FUNDAMENTALNODE_INITIAL;
    }

    LogPrint("fundamentalnode", "CActiveFundamentalnode::ManageState -- status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);

    if(eType == FUNDAMENTALNODE_UNKNOWN) {
        ManageStateInitial(connman);
    }

    if(eType == FUNDAMENTALNODE_REMOTE) {
        ManageStateRemote();
    }

    SendFundamentalnodePing(connman);
}

std::string CActiveFundamentalnode::GetStateString() const
{
    switch (nState) {
        case ACTIVE_FUNDAMENTALNODE_INITIAL:         return "INITIAL";
        case ACTIVE_FUNDAMENTALNODE_SYNC_IN_PROCESS: return "SYNC_IN_PROCESS";
        case ACTIVE_FUNDAMENTALNODE_INPUT_TOO_NEW:   return "INPUT_TOO_NEW";
        case ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE:     return "NOT_CAPABLE";
        case ACTIVE_FUNDAMENTALNODE_STARTED:         return "STARTED";
        default:                                return "UNKNOWN";
    }
}

std::string CActiveFundamentalnode::GetStatus() const
{
    switch (nState) {
        case ACTIVE_FUNDAMENTALNODE_INITIAL:         return "Node just started, not yet activated";
        case ACTIVE_FUNDAMENTALNODE_SYNC_IN_PROCESS: return "Sync in progress. Must wait until sync is complete to start Fundamentalnode";
        case ACTIVE_FUNDAMENTALNODE_INPUT_TOO_NEW:   return strprintf("Fundamentalnode input must have at least %d confirmations", Params().GetConsensus().nFundamentalnodeMinimumConfirmations);
        case ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE:     return "Not capable fundamentalnode: " + strNotCapableReason;
        case ACTIVE_FUNDAMENTALNODE_STARTED:         return "Fundamentalnode successfully started";
        default:                                return "Unknown";
    }
}

std::string CActiveFundamentalnode::GetTypeString() const
{
    std::string strType;
    switch(eType) {
    case FUNDAMENTALNODE_REMOTE:
        strType = "REMOTE";
        break;
    default:
        strType = "UNKNOWN";
        break;
    }
    return strType;
}

bool CActiveFundamentalnode::SendFundamentalnodePing(CConnman& connman)
{
    if(!fPingerEnabled) {
        LogPrint("fundamentalnode", "CActiveFundamentalnode::SendFundamentalnodePing -- %s: fundamentalnode ping service is disabled, skipping...\n", GetStateString());
        return false;
    }

    if(!fnodeman.Has(outpoint)) {
        strNotCapableReason = "Fundamentalnode not in fundamentalnode list";
        nState = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
        LogPrintf("CActiveFundamentalnode::SendFundamentalnodePing -- %s: %s\n", GetStateString(), strNotCapableReason);
        return false;
    }

    CFundamentalnodePing fnp(outpoint);
    fnp.nSentinelVersion = nSentinelVersion;
    fnp.fSentinelIsCurrent =
            (abs(GetAdjustedTime() - nSentinelPingTime) < FUNDAMENTALNODE_SENTINEL_PING_MAX_SECONDS);
    if(!fnp.Sign(keyFundamentalnode, pubKeyFundamentalnode)) {
        LogPrintf("CActiveFundamentalnode::SendFundamentalnodePing -- ERROR: Couldn't sign Fundamentalnode Ping\n");
        return false;
    }

    // Update lastPing for our fundamentalnode in Fundamentalnode list
    if(fnodeman.IsFundamentalnodePingedWithin(outpoint, FUNDAMENTALNODE_MIN_MNP_SECONDS, fnp.sigTime)) {
        LogPrintf("CActiveFundamentalnode::SendFundamentalnodePing -- Too early to send Fundamentalnode Ping\n");
        return false;
    }

    fnodeman.SetFundamentalnodeLastPing(outpoint, fnp);

    LogPrintf("CActiveFundamentalnode::SendFundamentalnodePing -- Relaying ping, collateral=%s\n", outpoint.ToStringShort());
    fnp.Relay(connman);

    return true;
}

bool CActiveFundamentalnode::UpdateSentinelPing(int version)
{
    nSentinelVersion = version;
    nSentinelPingTime = GetAdjustedTime();

    return true;
}

void CActiveFundamentalnode::ManageStateInitial(CConnman& connman)
{
    LogPrint("fundamentalnode", "CActiveFundamentalnode::ManageStateInitial -- status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);

    // Check that our local network configuration is correct
    if (!fListen) {
        // listen option is probably overwritten by smth else, no good
        nState = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
        strNotCapableReason = "Fundamentalnode must accept connections from outside. Make sure listen configuration option is not overwritten by some another parameter.";
        LogPrintf("CActiveFundamentalnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // First try to find whatever local address is specified by externalip option
    bool fFoundLocal = GetLocal(service) && CFundamentalnode::IsValidNetAddr(service);
    if(!fFoundLocal) {
        bool empty = true;
        // If we have some peers, let's try to find our local address from one of them
        connman.ForEachNodeContinueIf(CConnman::AllNodes, [&fFoundLocal, &empty, this](CNode* pnode) {
            empty = false;
            if (pnode->addr.IsIPv4())
                fFoundLocal = GetLocal(service, &pnode->addr) && CFundamentalnode::IsValidNetAddr(service);
            return !fFoundLocal;
        });
        // nothing and no live connections, can't do anything for now
        if (empty) {
            nState = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
            strNotCapableReason = "Can't detect valid external address. Will retry when there are some connections available.";
            LogPrintf("CActiveFundamentalnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
    }

    if(!fFoundLocal) {
        nState = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
        strNotCapableReason = "Can't detect valid external address. Please consider using the externalip configuration option if problem persists. Make sure to use IPv4 address only.";
        LogPrintf("CActiveFundamentalnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(service.GetPort() != mainnetDefaultPort) {
            nState = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Invalid port: %u - only %d is supported on mainnet.", service.GetPort(), mainnetDefaultPort);
            LogPrintf("CActiveFundamentalnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
    } else if(service.GetPort() == mainnetDefaultPort) {
        nState = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
        strNotCapableReason = strprintf("Invalid port: %u - %d is only supported on mainnet.", service.GetPort(), mainnetDefaultPort);
        LogPrintf("CActiveFundamentalnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // Check socket connectivity
    LogPrintf("CActiveFundamentalnode::ManageStateInitial -- Checking inbound connection to '%s'\n", service.ToString());
    SOCKET hSocket;
    bool fConnected = ConnectSocket(service, hSocket, nConnectTimeout) && IsSelectableSocket(hSocket);
    CloseSocket(hSocket);

    if (!fConnected) {
        nState = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
        strNotCapableReason = "Could not connect to " + service.ToString();
        LogPrintf("CActiveFundamentalnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // Default to REMOTE
    eType = FUNDAMENTALNODE_REMOTE;

    LogPrint("fundamentalnode", "CActiveFundamentalnode::ManageStateInitial -- End status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);
}

void CActiveFundamentalnode::ManageStateRemote()
{
    LogPrint("fundamentalnode", "CActiveFundamentalnode::ManageStateRemote -- Start status = %s, type = %s, pinger enabled = %d, pubKeyFundamentalnode.GetID() = %s\n", 
             GetStatus(), GetTypeString(), fPingerEnabled, pubKeyFundamentalnode.GetID().ToString());

    fnodeman.CheckFundamentalnode(pubKeyFundamentalnode, true);
    fundamentalnode_info_t infoFn;
    if(fnodeman.GetFundamentalnodeInfo(pubKeyFundamentalnode, infoFn)) {
        if(infoFn.nProtocolVersion != PROTOCOL_VERSION) {
            nState = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
            strNotCapableReason = "Invalid protocol version";
            LogPrintf("CActiveFundamentalnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if(service != infoFn.addr) {
            nState = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
            strNotCapableReason = "Broadcasted IP doesn't match our external address. Make sure you issued a new broadcast if IP of this fundamentalnode changed recently.";
            LogPrintf("CActiveFundamentalnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if(!CFundamentalnode::IsValidStateForAutoStart(infoFn.nActiveState)) {
            nState = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Fundamentalnode in %s state", CFundamentalnode::StateToString(infoFn.nActiveState));
            LogPrintf("CActiveFundamentalnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if(nState != ACTIVE_FUNDAMENTALNODE_STARTED) {
            LogPrintf("CActiveFundamentalnode::ManageStateRemote -- STARTED!\n");
            outpoint = infoFn.outpoint;
            service = infoFn.addr;
            fPingerEnabled = true;
            nState = ACTIVE_FUNDAMENTALNODE_STARTED;
        }
    }
    else {
        nState = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
        strNotCapableReason = "Fundamentalnode not in fundamentalnode list";
        LogPrintf("CActiveFundamentalnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
    }
}
