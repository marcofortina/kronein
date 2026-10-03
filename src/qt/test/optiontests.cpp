// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/args.h>
#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/test/optiontests.h>

#include <QDataStream>
#include <QIODevice>
#include <QTest>

OptionTests::OptionTests(interfaces::Node&)
{
    gArgs.LockSettings([&](common::Settings& s) { m_previous_settings = s; });
}

void OptionTests::init()
{
    // reset args
    gArgs.LockSettings([&](common::Settings& s) { s = m_previous_settings; });
    gArgs.ClearPathCache();
}

void OptionTests::extractFilter()
{
    QString filter = QString("Partially Signed Transaction (Binary) (*.psbt)");
    QCOMPARE(GUIUtil::ExtractFirstSuffixFromFilter(filter), "psbt");

    filter = QString("Image (*.png *.jpg)");
    QCOMPARE(GUIUtil::ExtractFirstSuffixFromFilter(filter), "png");
}

void OptionTests::atomicUnit()
{
    // Renaming the displayed unit must not migrate persisted settings or
    // change wallet/RPC amount scaling.
    const auto unit{BitcoinUnit::SAT};
    QByteArray encoded;
    QDataStream out{&encoded, QIODevice::WriteOnly};
    out << unit;
    QCOMPARE(encoded, QByteArray(1, char{3}));
    QDataStream in{encoded};
    BitcoinUnit decoded{BitcoinUnit::BTC};
    in >> decoded;
    QCOMPARE(decoded, unit);
    QCOMPARE(BitcoinUnits::factor(unit), qint64{1});
    QCOMPARE(BitcoinUnits::decimals(unit), 0);
    QCOMPARE(BitcoinUnits::shortName(unit), QString{"KNE atomic units"});
    QCOMPARE(BitcoinUnits::formatWithUnit(unit, 1), QString{"1 KNE atomic units"});
    CAmount amount{0};
    QVERIFY(BitcoinUnits::parse(unit, "100000000", &amount));
    QCOMPARE(amount, COIN);
    QCOMPARE(BitcoinUnits::factor(BitcoinUnit::BTC), qint64{COIN});
}
