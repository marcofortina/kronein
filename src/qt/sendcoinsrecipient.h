// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SENDCOINSRECIPIENT_H
#define BITCOIN_QT_SENDCOINSRECIPIENT_H

#include <consensus/amount.h>
#include <serialize.h>

#include <string>

#include <QString>

class SendCoinsRecipient
{
public:
    explicit SendCoinsRecipient() : amount(0), fSubtractFeeFromAmount(false) { }
    explicit SendCoinsRecipient(const QString &addr, const QString &_label, const CAmount& _amount, const QString &_message):
        address(addr), label(_label), amount(_amount), message(_message), fSubtractFeeFromAmount(false) {}

    QString address;
    QString label;
    CAmount amount;
    QString message;

    bool fSubtractFeeFromAmount; // memory only

    SERIALIZE_METHODS(SendCoinsRecipient, obj)
    {
        std::string address_str, label_str, message_str;

        SER_WRITE(obj, address_str = obj.address.toStdString());
        SER_WRITE(obj, label_str = obj.label.toStdString());
        SER_WRITE(obj, message_str = obj.message.toStdString());

        READWRITE(address_str, label_str, obj.amount, message_str);

        SER_READ(obj, obj.address = QString::fromStdString(address_str));
        SER_READ(obj, obj.label = QString::fromStdString(label_str));
        SER_READ(obj, obj.message = QString::fromStdString(message_str));
    }
};

#endif // BITCOIN_QT_SENDCOINSRECIPIENT_H
