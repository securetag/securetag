#include "fundamentalnodelist.h"
#include "ui_fundamentalnodelist.h"

#include "activefundamentalnode.h"
#include "clientmodel.h"
#include "clientversion.h"
#include "init.h"
#include "guiutil.h"
#include "fundamentalnode-sync.h"
#include "fundamentalnodeconfig.h"
#include "fundamentalnodeman.h"
#include "qrdialog.h"
#include "sync.h"
#include "wallet/wallet.h"
#include "walletmodel.h"

#include <QTimer>
#include <QMessageBox>

int GetOffsetFromUtcFN()
{
#if QT_VERSION < 0x050200
    const QDateTime dateTime1 = QDateTime::currentDateTime();
    const QDateTime dateTime2 = QDateTime(dateTime1.date(), dateTime1.time(), Qt::UTC);
    return dateTime1.secsTo(dateTime2);
#else
    return QDateTime::currentDateTime().offsetFromUtc();
#endif
}

FundamentalnodeList::FundamentalnodeList(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FundamentalnodeList),
    clientModel(0),
    walletModel(0)
{
    ui->setupUi(this);

    ui->startButton->setEnabled(false);

    int colufnAliasWidth = 100;
    int colufnAddressWidth = 200;
    int colufnProtocolWidth = 60;
    int colufnStatusWidth = 80;
    int colufnActiveWidth = 130;
    int colufnLastSeenWidth = 130;

    ui->tableWidgetMyFundamentalnodes->setColumnWidth(0, colufnAliasWidth);
    ui->tableWidgetMyFundamentalnodes->setColumnWidth(1, colufnAddressWidth);
    ui->tableWidgetMyFundamentalnodes->setColumnWidth(2, colufnProtocolWidth);
    ui->tableWidgetMyFundamentalnodes->setColumnWidth(3, colufnStatusWidth);
    ui->tableWidgetMyFundamentalnodes->setColumnWidth(4, colufnActiveWidth);
    ui->tableWidgetMyFundamentalnodes->setColumnWidth(5, colufnLastSeenWidth);

    ui->tableWidgetFundamentalnodes->setColumnWidth(0, colufnAddressWidth);
    ui->tableWidgetFundamentalnodes->setColumnWidth(1, colufnProtocolWidth);
    ui->tableWidgetFundamentalnodes->setColumnWidth(2, colufnStatusWidth);
    ui->tableWidgetFundamentalnodes->setColumnWidth(3, colufnActiveWidth);
    ui->tableWidgetFundamentalnodes->setColumnWidth(4, colufnLastSeenWidth);

    ui->tableWidgetMyFundamentalnodes->setContextMenuPolicy(Qt::CustomContextMenu);

    QAction *startAliasAction = new QAction(tr("Start alias"), this);
    contextMenu = new QMenu();
    contextMenu->addAction(startAliasAction);
    connect(ui->tableWidgetMyFundamentalnodes, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(showContextMenu(const QPoint&)));
    connect(ui->tableWidgetMyFundamentalnodes, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(on_QRButton_clicked()));
    connect(startAliasAction, SIGNAL(triggered()), this, SLOT(on_startButton_clicked()));

    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(updateNodeList()));
    connect(timer, SIGNAL(timeout()), this, SLOT(updateMyNodeList()));
    timer->start(1000);

    fFilterUpdated = false;
    nTimeFilterUpdated = GetTime();
    updateNodeList();
}

FundamentalnodeList::~FundamentalnodeList()
{
    delete ui;
}

void FundamentalnodeList::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model) {
        // try to update list when fundamentalnode count changes
        connect(clientModel, SIGNAL(strFundamentalnodesChanged(QString)), this, SLOT(updateNodeList()));
    }
}

void FundamentalnodeList::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
}

void FundamentalnodeList::showContextMenu(const QPoint &point)
{
    QTableWidgetItem *item = ui->tableWidgetMyFundamentalnodes->itemAt(point);
    if(item) contextMenu->exec(QCursor::pos());
}

void FundamentalnodeList::StartAlias(std::string strAlias)
{
    std::string strStatusHtml;
    strStatusHtml += "<center>Alias: " + strAlias;

    for (const auto& fne : fundamentalnodeConfig.getEntries()) {
        if(fne.getAlias() == strAlias) {
            std::string strError;
            CFundamentalnodeBroadcast fnb;

            bool fSuccess = CFundamentalnodeBroadcast::Create(fne.getIp(), fne.getPrivKey(), fne.getTxHash(), fne.getOutputIndex(), strError, fnb);

            int nDoS;
            if (fSuccess && !fnodeman.CheckFnbAndUpdateFundamentalnodeList(NULL, fnb, nDoS, *g_connman)) {
                strError = "Failed to verify MNB";
                fSuccess = false;
            }

            if(fSuccess) {
                strStatusHtml += "<br>Successfully started fundamentalnode.";
                fnodeman.NotifyFundamentalnodeUpdates(*g_connman);
            } else {
                strStatusHtml += "<br>Failed to start fundamentalnode.<br>Error: " + strError;
            }
            break;
        }
    }
    strStatusHtml += "</center>";

    QMessageBox msg;
    msg.setText(QString::fromStdString(strStatusHtml));
    msg.exec();

    updateMyNodeList(true);
}

void FundamentalnodeList::StartAll(std::string strCommand)
{
    int nCountSuccessful = 0;
    int nCountFailed = 0;
    std::string strFailedHtml;

    for (const auto& fne : fundamentalnodeConfig.getEntries()) {
        std::string strError;
        CFundamentalnodeBroadcast fnb;

        int32_t nOutputIndex = 0;
        if(!ParseInt32(fne.getOutputIndex(), &nOutputIndex)) {
            continue;
        }

        COutPoint outpoint = COutPoint(uint256S(fne.getTxHash()), nOutputIndex);

        if(strCommand == "start-missing" && fnodeman.Has(outpoint)) continue;

        bool fSuccess = CFundamentalnodeBroadcast::Create(fne.getIp(), fne.getPrivKey(), fne.getTxHash(), fne.getOutputIndex(), strError, fnb);

        int nDoS;
        if (fSuccess && !fnodeman.CheckFnbAndUpdateFundamentalnodeList(NULL, fnb, nDoS, *g_connman)) {
            strError = "Failed to verify MNB";
            fSuccess = false;
        }

        if(fSuccess) {
            nCountSuccessful++;
            fnodeman.NotifyFundamentalnodeUpdates(*g_connman);
        } else {
            nCountFailed++;
            strFailedHtml += "\nFailed to start " + fne.getAlias() + ". Error: " + strError;
        }
    }

    std::string returnObj;
    returnObj = strprintf("Successfully started %d fundamentalnodes, failed to start %d, total %d", nCountSuccessful, nCountFailed, nCountFailed + nCountSuccessful);
    if (nCountFailed > 0) {
        returnObj += strFailedHtml;
    }

    QMessageBox msg;
    msg.setText(QString::fromStdString(returnObj));
    msg.exec();

    updateMyNodeList(true);
}

void FundamentalnodeList::updateMyFundamentalnodeInfo(QString strAlias, QString strAddr, const COutPoint& outpoint)
{
    bool fOldRowFound = false;
    int nNewRow = 0;

    for(int i = 0; i < ui->tableWidgetMyFundamentalnodes->rowCount(); i++) {
        if(ui->tableWidgetMyFundamentalnodes->item(i, 0)->text() == strAlias) {
            fOldRowFound = true;
            nNewRow = i;
            break;
        }
    }

    if(nNewRow == 0 && !fOldRowFound) {
        nNewRow = ui->tableWidgetMyFundamentalnodes->rowCount();
        ui->tableWidgetMyFundamentalnodes->insertRow(nNewRow);
    }

    fundamentalnode_info_t infoFn;
    bool fFound = fnodeman.GetFundamentalnodeInfo(outpoint, infoFn);

    QTableWidgetItem *aliasItem = new QTableWidgetItem(strAlias);
    QTableWidgetItem *addrItem = new QTableWidgetItem(fFound ? QString::fromStdString(infoFn.addr.ToString()) : strAddr);
    QTableWidgetItem *protocolItem = new QTableWidgetItem(QString::number(fFound ? infoFn.nProtocolVersion : -1));
    QTableWidgetItem *statusItem = new QTableWidgetItem(QString::fromStdString(fFound ? CFundamentalnode::StateToString(infoFn.nActiveState) : "MISSING"));
    QTableWidgetItem *activeSecondsItem = new QTableWidgetItem(QString::fromStdString(DurationToDHMS(fFound ? (infoFn.nTimeLastPing - infoFn.sigTime) : 0)));
    QTableWidgetItem *lastSeenItem = new QTableWidgetItem(QString::fromStdString(DateTimeStrFormat("%Y-%m-%d %H:%M",
                                                                                                   fFound ? infoFn.nTimeLastPing + GetOffsetFromUtcFN() : 0)));
    QTableWidgetItem *pubkeyItem = new QTableWidgetItem(QString::fromStdString(fFound ? CBitcoinAddress(infoFn.pubKeyCollateralAddress.GetID()).ToString() : ""));

    ui->tableWidgetMyFundamentalnodes->setItem(nNewRow, 0, aliasItem);
    ui->tableWidgetMyFundamentalnodes->setItem(nNewRow, 1, addrItem);
    ui->tableWidgetMyFundamentalnodes->setItem(nNewRow, 2, protocolItem);
    ui->tableWidgetMyFundamentalnodes->setItem(nNewRow, 3, statusItem);
    ui->tableWidgetMyFundamentalnodes->setItem(nNewRow, 4, activeSecondsItem);
    ui->tableWidgetMyFundamentalnodes->setItem(nNewRow, 5, lastSeenItem);
    ui->tableWidgetMyFundamentalnodes->setItem(nNewRow, 6, pubkeyItem);
}

void FundamentalnodeList::updateMyNodeList(bool fForce)
{
    TRY_LOCK(cs_myfnlist, fLockAcquired);
    if(!fLockAcquired) {
        return;
    }
    static int64_t nTimeMyListUpdated = 0;

    // automatically update my fundamentalnode list only once in MY_FUNDAMENTALNODELIST_UPDATE_SECONDS seconds,
    // this update still can be triggered manually at any time via button click
    int64_t nSecondsTillUpdate = nTimeMyListUpdated + MY_FUNDAMENTALNODELIST_UPDATE_SECONDS - GetTime();
    ui->secondsLabel->setText(QString::number(nSecondsTillUpdate));

    if(nSecondsTillUpdate > 0 && !fForce) return;
    nTimeMyListUpdated = GetTime();

    // Find selected row
    QItemSelectionModel* selectionModel = ui->tableWidgetMyFundamentalnodes->selectionModel();
    QModelIndexList selected = selectionModel->selectedRows();
    int nSelectedRow = selected.count() ? selected.at(0).row() : 0;

    ui->tableWidgetMyFundamentalnodes->setSortingEnabled(false);
    for (const auto& fne : fundamentalnodeConfig.getEntries()) {
        int32_t nOutputIndex = 0;
        if(!ParseInt32(fne.getOutputIndex(), &nOutputIndex)) {
            continue;
        }

        updateMyFundamentalnodeInfo(QString::fromStdString(fne.getAlias()), QString::fromStdString(fne.getIp()), COutPoint(uint256S(fne.getTxHash()), nOutputIndex));
    }
    ui->tableWidgetMyFundamentalnodes->selectRow(nSelectedRow);
    ui->tableWidgetMyFundamentalnodes->setSortingEnabled(true);

    // reset "timer"
    ui->secondsLabel->setText("0");
}

void FundamentalnodeList::updateNodeList()
{
    TRY_LOCK(cs_fnlist, fLockAcquired);
    if(!fLockAcquired) {
        return;
    }

    static int64_t nTimeListUpdated = GetTime();

    // to prevent high cpu usage update only once in FUNDAMENTALNODELIST_UPDATE_SECONDS seconds
    // or FUNDAMENTALNODELIST_FILTER_COOLDOWN_SECONDS seconds after filter was last changed
    int64_t nSecondsToWait = fFilterUpdated
                            ? nTimeFilterUpdated - GetTime() + FUNDAMENTALNODELIST_FILTER_COOLDOWN_SECONDS
                            : nTimeListUpdated - GetTime() + FUNDAMENTALNODELIST_UPDATE_SECONDS;

    if(fFilterUpdated) ui->countLabel->setText(QString::fromStdString(strprintf("Please wait... %d", nSecondsToWait)));
    if(nSecondsToWait > 0) return;

    nTimeListUpdated = GetTime();
    fFilterUpdated = false;

    QString strToFilter;
    ui->countLabel->setText("Updating...");
    ui->tableWidgetFundamentalnodes->setSortingEnabled(false);
    ui->tableWidgetFundamentalnodes->clearContents();
    ui->tableWidgetFundamentalnodes->setRowCount(0);
    std::map<COutPoint, CFundamentalnode> mapFundamentalnodes = fnodeman.GetFullFundamentalnodeMap();
    int offsetFromUtc = GetOffsetFromUtcFN();

    for (const auto& fnpair : mapFundamentalnodes)
    {
        CFundamentalnode fn = fnpair.second;
        // populate list
        // Address, Protocol, Status, Active Seconds, Last Seen, Pub Key
        QTableWidgetItem *addressItem = new QTableWidgetItem(QString::fromStdString(fn.addr.ToString()));
        QTableWidgetItem *protocolItem = new QTableWidgetItem(QString::number(fn.nProtocolVersion));
        QTableWidgetItem *statusItem = new QTableWidgetItem(QString::fromStdString(fn.GetStatus()));
        QTableWidgetItem *activeSecondsItem = new QTableWidgetItem(QString::fromStdString(DurationToDHMS(fn.lastPing.sigTime - fn.sigTime)));
        QTableWidgetItem *lastSeenItem = new QTableWidgetItem(QString::fromStdString(DateTimeStrFormat("%Y-%m-%d %H:%M", fn.lastPing.sigTime + offsetFromUtc)));
        QTableWidgetItem *pubkeyItem = new QTableWidgetItem(QString::fromStdString(CBitcoinAddress(fn.pubKeyCollateralAddress.GetID()).ToString()));

        if (strCurrentFilter != "")
        {
            strToFilter =   addressItem->text() + " " +
                            protocolItem->text() + " " +
                            statusItem->text() + " " +
                            activeSecondsItem->text() + " " +
                            lastSeenItem->text() + " " +
                            pubkeyItem->text();
            if (!strToFilter.contains(strCurrentFilter)) continue;
        }

        ui->tableWidgetFundamentalnodes->insertRow(0);
        ui->tableWidgetFundamentalnodes->setItem(0, 0, addressItem);
        ui->tableWidgetFundamentalnodes->setItem(0, 1, protocolItem);
        ui->tableWidgetFundamentalnodes->setItem(0, 2, statusItem);
        ui->tableWidgetFundamentalnodes->setItem(0, 3, activeSecondsItem);
        ui->tableWidgetFundamentalnodes->setItem(0, 4, lastSeenItem);
        ui->tableWidgetFundamentalnodes->setItem(0, 5, pubkeyItem);
    }

    ui->countLabel->setText(QString::number(ui->tableWidgetFundamentalnodes->rowCount()));
    ui->tableWidgetFundamentalnodes->setSortingEnabled(true);
}

void FundamentalnodeList::on_filterLineEdit_textChanged(const QString &strFilterIn)
{
    strCurrentFilter = strFilterIn;
    nTimeFilterUpdated = GetTime();
    fFilterUpdated = true;
    ui->countLabel->setText(QString::fromStdString(strprintf("Please wait... %d", FUNDAMENTALNODELIST_FILTER_COOLDOWN_SECONDS)));
}

void FundamentalnodeList::on_startButton_clicked()
{
    std::string strAlias;
    {
        LOCK(cs_myfnlist);
        // Find selected node alias
        QItemSelectionModel* selectionModel = ui->tableWidgetMyFundamentalnodes->selectionModel();
        QModelIndexList selected = selectionModel->selectedRows();

        if(selected.count() == 0) return;

        QModelIndex index = selected.at(0);
        int nSelectedRow = index.row();
        strAlias = ui->tableWidgetMyFundamentalnodes->item(nSelectedRow, 0)->text().toStdString();
    }

    // Display message box
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm fundamentalnode start"),
        tr("Are you sure you want to start fundamentalnode %1?").arg(QString::fromStdString(strAlias)),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if(retval != QMessageBox::Yes) return;

    WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();

    if(encStatus == walletModel->Locked || encStatus == walletModel->UnlockedForMixingOnly) {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());

        if(!ctx.isValid()) return; // Unlock wallet was cancelled

        StartAlias(strAlias);
        return;
    }

    StartAlias(strAlias);
}

void FundamentalnodeList::on_startAllButton_clicked()
{
    // Display message box
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm all fundamentalnodes start"),
        tr("Are you sure you want to start ALL fundamentalnodes?"),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if(retval != QMessageBox::Yes) return;

    WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();

    if(encStatus == walletModel->Locked || encStatus == walletModel->UnlockedForMixingOnly) {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());

        if(!ctx.isValid()) return; // Unlock wallet was cancelled

        StartAll();
        return;
    }

    StartAll();
}

void FundamentalnodeList::on_startMissingButton_clicked()
{

    if(!fundamentalnodeSync.IsFundamentalnodeListSynced()) {
        QMessageBox::critical(this, tr("Command is not available right now"),
            tr("You can't use this command until fundamentalnode list is synced"));
        return;
    }

    // Display message box
    QMessageBox::StandardButton retval = QMessageBox::question(this,
        tr("Confirm missing fundamentalnodes start"),
        tr("Are you sure you want to start MISSING fundamentalnodes?"),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if(retval != QMessageBox::Yes) return;

    WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();

    if(encStatus == walletModel->Locked || encStatus == walletModel->UnlockedForMixingOnly) {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());

        if(!ctx.isValid()) return; // Unlock wallet was cancelled

        StartAll("start-missing");
        return;
    }

    StartAll("start-missing");
}

void FundamentalnodeList::on_tableWidgetMyFundamentalnodes_itemSelectionChanged()
{
    if(ui->tableWidgetMyFundamentalnodes->selectedItems().count() > 0) {
        ui->startButton->setEnabled(true);
    }
}

void FundamentalnodeList::on_UpdateButton_clicked()
{
    updateMyNodeList(true);
}

void FundamentalnodeList::on_QRButton_clicked()
{
    std::string strAlias;
    {
        LOCK(cs_myfnlist);
        // Find selected node alias
        QItemSelectionModel* selectionModel = ui->tableWidgetMyFundamentalnodes->selectionModel();
        QModelIndexList selected = selectionModel->selectedRows();

        if(selected.count() == 0) return;

        QModelIndex index = selected.at(0);
        int nSelectedRow = index.row();
        strAlias = ui->tableWidgetMyFundamentalnodes->item(nSelectedRow, 0)->text().toStdString();
    }

    ShowQRCode(strAlias);
}

void FundamentalnodeList::ShowQRCode(std::string strAlias) {

    if(!walletModel || !walletModel->getOptionsModel())
        return;

    // Get private key for this alias
    std::string strMNPrivKey = "";
    std::string strCollateral = "";
    std::string strIP = "";
    CFundamentalnode fn;
    bool fFound = false;

    for (const auto& fne : fundamentalnodeConfig.getEntries()) {
        if (strAlias != fne.getAlias()) {
            continue;
        }
        else {
            strMNPrivKey = fne.getPrivKey();
            strCollateral = fne.getTxHash() + "-" + fne.getOutputIndex();
            strIP = fne.getIp();
            fFound = fnodeman.Get(COutPoint(uint256S(fne.getTxHash()), atoi(fne.getOutputIndex())), fn);
            break;
        }
    }

    // Title of popup window
    QString strWindowtitle = tr("Additional information for Fundamentalnode %1").arg(QString::fromStdString(strAlias));

    // Title above QR-Code
    QString strQRCodeTitle = tr("Fundamentalnode Private Key");

    // Create dialog text as HTML
    QString strHTML = "<html><font face='verdana, arial, helvetica, sans-serif'>";
    strHTML += "<b>" + tr("Alias") +            ": </b>" + GUIUtil::HtmlEscape(strAlias) + "<br>";
    strHTML += "<b>" + tr("Private Key") +      ": </b>" + GUIUtil::HtmlEscape(strMNPrivKey) + "<br>";
    strHTML += "<b>" + tr("Collateral") +       ": </b>" + GUIUtil::HtmlEscape(strCollateral) + "<br>";
    strHTML += "<b>" + tr("IP") +               ": </b>" + GUIUtil::HtmlEscape(strIP) + "<br>";
    if (fFound) {
        strHTML += "<b>" + tr("Protocol") +     ": </b>" + QString::number(fn.nProtocolVersion) + "<br>";
        strHTML += "<b>" + tr("Version") +      ": </b>" + (fn.lastPing.nDaemonVersion > DEFAULT_DAEMON_VERSION ? GUIUtil::HtmlEscape(FormatVersion(fn.lastPing.nDaemonVersion)) : tr("Unknown")) + "<br>";
        strHTML += "<b>" + tr("Sentinel") +     ": </b>" + (fn.lastPing.nSentinelVersion > DEFAULT_SENTINEL_VERSION ? GUIUtil::HtmlEscape(SafeIntVersionToString(fn.lastPing.nSentinelVersion)) : tr("Unknown")) + "<br>";
        strHTML += "<b>" + tr("Status") +       ": </b>" + GUIUtil::HtmlEscape(CFundamentalnode::StateToString(fn.nActiveState)) + "<br>";
        strHTML += "<b>" + tr("Payee") +        ": </b>" + GUIUtil::HtmlEscape(CBitcoinAddress(fn.pubKeyCollateralAddress.GetID()).ToString()) + "<br>";
        strHTML += "<b>" + tr("Active") +       ": </b>" + GUIUtil::HtmlEscape(DurationToDHMS(fn.lastPing.sigTime - fn.sigTime)) + "<br>";
        strHTML += "<b>" + tr("Last Seen") +    ": </b>" + GUIUtil::HtmlEscape(DateTimeStrFormat("%Y-%m-%d %H:%M", fn.lastPing.sigTime + GetOffsetFromUtcFN())) + "<br>";
    }

    // Open QR dialog
    QRDialog *dialog = new QRDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModel(walletModel->getOptionsModel());
    dialog->setInfo(strWindowtitle, QString::fromStdString(strMNPrivKey), strHTML, strQRCodeTitle);
    dialog->show();
}
