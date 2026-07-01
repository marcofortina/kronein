// Copyright (c) 2013-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <key.h>
#include <key_io.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/bip32.h>
#include <util/strencodings.h>

#include <string>
#include <vector>

namespace {

struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    explicit TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.emplace_back();
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

TestVector test1 =
  TestVector("000102030405060708090a0b0c0d0e0f")
    ("KpubTJ2LfK8fYD2LVrFcjKHnjzXkYRUmXHNqMArCZjaeqjEThwX1aLdBuyu75qM4aBpSuysbikTZEA1C5ywU8TugtsvuhPGBvChLThZ76G4tjfX",
     "KprvX52zFobmhqU3HNB9dHknNrb1zPeH7peyywvbmMB3HPhUq9Bs2oJwNBadEZhm4JQNzSyfDoSQaretHTkKqE53GqvpugXxkgBjhaxN3sXu9uq",
     0x80000000)
    ("KpubTLHkf2S8dU9KeTPKw5ARd2drsF37uMrr2nH6XpxmovRk5DpBzaAH38FWs6umKViyvCAAayzyxo5H4Nuc5Ve4xmPdu24SqWbYydgfPt432iS",
     "KprvX7JQFWuEo6b2RyJrq3dRFth8KDCdVu8zfZMVjSZAFatmCRV3T2r2VKw31q46U1nLhVsMb6mGyDVm1Dn3UpME4v1LyZD6zdtdQbbDV4zTTRV",
     1)
    ("KpubTNTsroz22B2PUuRmfL4JDmXWvd2DuPb8y6ww86jakZDxJmKKiNaazh9kHBNLjSSKsunDNQT65PZkegeRYpoxeRDaCDuJK9bpcNDSgrGSzW4",
     "KprvX9UXTJT8BoU6GRMJZJXHrdanNbBjVvsHbt2LKiKyCDgyRxzBAqGLStqGRtFA4wZP9ad3PvMi3vTB9AJGcA9Cr5VnVLAq4PfV5Pub1xFDBTZ",
     0x80000002)
    ("KpubTR59uLosj3soM5DruvTfamZf9mtkAwB8JeBcNS2jvRbPicWSX8R1u8hfqCZBBJseERswynRhTL8j71niFvMVhsNQn7sSQ6fWL48an5gryjL",
     "KprvXC5oVqGytgKW8b9PotvfDdcvbk4FmUTGwRG1a3d8N64QqpBHyb6mMLPByvTn3B4sf3eRzPJdULH5NN32CB4PyAwSqwjPDKuRgfeoebFzukd",
     2)
    ("KpubTTJYjmvpuXYnRYhacBfkUGiyEbBUoXVKk84udPZDEsA15i8oau7P6iAbWXYZb72Nhk187nueW52qfS8iMDnhRTqfguRdEHZLLk3RvdskH81",
     "KprvXEKCLGPw59zVD4d7WA8k78nEgZLzQ4mUNu9Jq19bgXd2Cuof3Mo8Yur7fEsEVqUJiqn8cJYCP9jEqYwUPbbkAZXVFBpUmQj8qe7yA2M7pN6",
     1000000000)
    ("KpubTV2KDTY52evywtV2ijEUmyiy2pknd2JMYNTTsfwMSwYVnqYC7KN3MpKf9MTWSN76BSHfd8qT3GjSFrXjT5HYGiznZSqi2m8y9hfMAs2vzuv",
     "KprvXG2xox1BCHNgjQQZchhUQqnEUnvJDZaWB9Xs5HXjtc1Wv3D3Zn3np21BJ6eSQkbPLFBPPfX9ECGMqiwqvfcUHXB2agahtKUr7ygKuDAWNLx",
     0);

TestVector test2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    ("KpubTJ2LfK8fYD2LVTkwqUN5CCFWncdCCudf2kdvrgKUp7MKzvYCkVQ8Lt4hRwS3HSBQpY7PdR7idEWSomfhFepr2nvrZKTekhBzn5EDNAbhmQL",
     "KprvX52zFobmhqU3GygUjSq4q4JnEanhoSuofXiL4HusFmpM88D4Cx5so5kDadUpEoxUEVj5y5trrxh5NzURseTjtDFbN6cCu26UGqabQsBDzVc",
     0)
    ("KpubTMJ5w2pd2DrR1jMEyFjxFzf39aNSut7wavPJ2VLvtXDHgtzBKkkCVidx1QPw5XBr2rbZVe7U2KMQxw6P8oXGNPb8qNCKf3LNuZLsoKVZY19",
     "KprvX8JjXXHjBrJ7oFGmsECwtriJbYXxWRQ6DhThE6wKLBgJp6f2nDRwwvKUA8kcssoJe9xus6JbJ87CjW7FRvxnpSQzNH2GHWGDQFV9n7faNEj",
     0xFFFFFFFF)
    ("KpubTNT9Bdr9Q82XBbZRPhjbjLLbYKbMTNHdg5TpwtFhYFyg9CDdweAWhnRYcne3qFnwpNX79Uy5KXn1dbxiui1P6Y3mNSpP1mbPmwcUeD33Eep",
     "KprvX9Tnn8KFZkUDy7UxHgCbNCPrzHks3uZnJrYE9Vr5yvShGPtVQ6rG9z74mVEbc8XnYPHoe7WEM8cKAjr2AJZvPjrYo1Fc41zUC2pgYaGj8GQ",
     1)
    ("KpubTRG7beq5ZmKiHDEZTMtAhHGpsrTrZZCtzWxgnwv2r9L7p25oF9hDbgovTaqBd8VEQYyez84Jxf5qiQDjpcSLMsWfxj2EEK2bhiHRtaVe5io",
     "KprvXCGmC9JBjPmR4jA6MLMAL9L6KpdNA6V3dJ35zZWRHoo8wDkehcNy3tVScHSDdqjUrLeWPQackgHXVSdBDC6JQDfqvmnQu7xrfqFR2E4otd4",
     0xFFFFFFFE)
    ("KpubTSS9WcmSBAHRaAUABqhi4ny1nawDcXqQ2DgaKfcSgubNGNQjLpdE8DB26ExgpW1gMzdHnd821GQhN3P8WVYr5ED8EdLinc81ZwN1RXrK2Ef",
     "KprvXDSo77EYLnj8MgPh5pAhhf2HEZ6jD57YezkyXHCq8a4PPa5aoHJyaQrYEzAcGG7mPuwChEMc93s7JZiYj8zo64M1kiKj3KzV1RFw62SthX2",
     2)
    ("KpubTToBU3ywhLbfKRf3uuqQ3YLzBeUKrrkUgPJTjSxwKhSxLZkJWTYzJn82Ae2xx5NNt3qX4YdRtyRgrUSdLbEkPV4hsoAoiyQkFEZC6EojB79",
     "KprvXEoq4YT3ry3N6waaotJPgQQFdcdqTQ2dKANrw4ZKmMuyTmR9xvEjkyoYKPqcRHCqSDnvyyzRb9hoM7c4TTN2935jZZqE6k8ChnbVAZ8QTSQ",
     0);

TestVector test3 =
  TestVector("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
    ("KpubTJ2LfK8fYD2LUXD7MrrsQBWYfFxHxmnvk6QVFyM35oS7yAmUQde6J9JDuvy272m3zcsFTQzj1uLJF5Jc6MsHT8azgZMsVFdqZnjutg79meR",
     "KprvX52zFobmhqU3G38eFqKs33Zp7E7oZK55NsUtTawRXTu96NSKs6KqkLyk4dCzBqBoKCPqY1axmPRnje5k75cAfgkqtPAr6TSSZZEx4phsM3a",
      0x80000000)
    ("KpubTLPYQGxoDaPgg4JWb1CNTSGDMcZg7dCq9aeS5D2t27MVEBtvz8QxNc5wDeoXqPMoBzN6ENkTrrXnsYEx2boU2NrwMfJm378e3y6pZ4TpWfY",
     "KprvX7QBzmRuPCqPTaE3UyfN6JKUoajBiAUynMiqGpdGTmpWMPZnSb6hpomTNPZLXnWimM3FYxNqR84FPBitgJBvRSxUKX5tqciFgaCc2Amputy",
      0);

TestVector test4 =
  TestVector("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")
    ("KpubTJ2LfK8fYD2LWaigCbDgCvySHVYTt2CfzE6tdi2cxLGop4aocYErWMrKc4Dh8UM7a9zoc6Duxg733x5jWZtCXzSuSyex3ZbeUPR8yQfMLTY",
     "KprvX52zFobmhqU3J6eD6Zgfqo2hjThyUZUpd1BHqKd1PzjpwGFf4zvbxZXqknV7CZaytfMTeCU6hidZNei2mAs5kWREPd2t9LL6qh76pznkJWc",
     0x80000000)
    ("KpubTMBT3hFKuy8n9Tjopv9TDL5CjRRjbKjDjXiYygCbbnLnJbdvAsfaeQXfmeVTA6iEzFmAZ8cXZc3HasmoDMLbdJVwVJ5uvNh2XByBmqkSurR",
     "KprvX8C6eBiS5baUvyfLitcSrC8UBPbFBs1NNJnxBHnz3SooRoJmdLML6cDBvLQMFNmLreNuAmeL2AjeKJu8NYXim9JAF1LZMFn6px8uZrFjABs",
     0x80000001)
    ("KpubTPK8hgeLRhBNpcbSyC4MKCf3uMbp6FS2PTmNkRioFySE5gxS3N9HsXVYfbFz1HLva3NXSuYe24PGZN6hfx9kLbSJq5vxt7AyPcL5qU84Niq",
     "KprvXAKnJB7SbKd5c8WysAXLx4iKMKmKgniB2Eqmx3KBhduFCtdHVpq3KjB4pJNSJmoAwQn1MNUHnoqX2GiqmUUr3XmPVM3aTJ2RgdgbfR6Ro9A",
     0);

const std::vector<std::string> TEST5 = {
    "KpubTJ2LfK8fYD2LUWA5ELwatKz9aLsCHgBDwSRs7qdcMffsaqFYKhHbX8ktd9PeK4ACePhgKTRQR5LiDiFmRSGFU3Tfo4LVdsRmavbBXT9fzAq",
    "KprvX52zFobmhqU3G25c8KQaXC3R2K2htDTNaDWGKTDzoL8ti2vPn9yLyLSQn5fEY98EoEwivPovDdoA89WB3zckRmBhhr24ZMgkUPEqm8G14Vz",
    "KpubTJ2LfK8fYD2LUWA5ELwatKz9aLsCHgBDwSRs7qdcMffsaqFYKhHbX8ktdHAd1yxL46QarjkE3Ppi2zes5tj84rqAwccvcUBMZYcjVuVYtRS",
    "KprvX52zFobmhqU3G25c8KQaXC3R2K2htDTNaDWGKTDzoL8ti2vPn9yLyLSQn62LvoojeMxaxHdJNe5FRZ75CEEaK1F1RcJYm9NJdgjVjrBo2ea",
    "KpubTJ2LfK8fYD2LUWA5ELwatKz9aLsCHgBDwSRs7qdcMffsaqFYKhHbX8ktdBLPVHcEVpNuTH17KexiB2rYLYsy7kJYahQbt27faaba25SaF2U",
    "KprvX52zFobmhqU3G25c8KQaXC3R2K2htDTNaDWGKTDzoL8ti2vPn9yLyLSQmzC7Q7Te65vuYptBeuDFZbJkStPRMtiP4h6E2hJceiiLG1yhTpN",
    "KprvX53R5Y5s6vvLLEBXnafdhdTeajuCdWBX4VZM1qGHvokruN3ouUJ1RnZUCWmBKjLesFECigaV4R9sbFAeKaJEnzmRj4m6peVyZqPfXoFd4gY",
    "KpubTJ2mV3ckwJUdYiFztcCe4mQP8mjh2xuNRiUwpDfuV9HqnANxT1cFyasx3qKKjAbsqZNF8XCrCV7EiZWdjTdqGRfnfs5RSnP4K1ooHZun2Lj",
    "KprvX52zFobmmdVC7g4sGZx5nyj2TAeGR4svxvAn5tLpJgBnuBjW7PAbZ2UeW9Fg19g5kZSGVQubkxMBkwyWHT6SYoLj4ubdtTgPgsx7E3c3aTP",
    "KpubTJ2LfK8fc13VLA9LNbV6A7fm1CUkpXbnL96NtGkRs1immz4eevUr6po8MTopQawJisaJuFXxu2JYtGKVhLS32EF61huxWbZUS4NEykzcMVu",
    "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
    "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
    "KprvX52zFobmhqU3G25c8KQaXC3R2K2htDTNaDWGKTDzoL8ti2vPn9yLyLSQmxFNDt1cEfFgR1JUkKbFcGhyXmmhiBsWH427nYcif4hwk3RzMMf",
    "KprvX52zFobmhqU3G25c8KQaXC3R2K2htDTNaDWGKTDzoL8ti2vPn9yLyLSQmzC7Q7Te65vuYptBeuDFZbJfv22WpsTbbyqEmqbHxRgxUHMdYdm",
    "KpubTJ2LfK8fYD2LUWA5ELwatKz9aLsCHgBDwSRs7qdcMffsaqFYKhHbX8ktdDH8fX4GMF48b6apEEai8MTKFfVgmT9RNLUi8AoZaEbxW8ZNSuR",
    "KprvX52zFobmhqU3HNB9dHknNrb1zPeH7peyywvbmMB3HPhUq9Bs2oJwNBadEZhm4JQNzSyfDoSQaretHTkKqE53GqvpugXxkgBjhaxN3sXu9up"
};

void RunTest(const TestVector& test)
{
    std::vector<std::byte> seed{ParseHex<std::byte>(test.strHexMaster)};
    CExtKey key;
    CExtPubKey pubkey;
    key.SetSeed(seed);
    pubkey = key.Neuter();
    for (const TestDerivation &derive : test.vDerive) {
        unsigned char data[74];
        key.Encode(data);
        pubkey.Encode(data);

        // Test private key
        BOOST_CHECK(EncodeExtKey(key) == derive.prv);
        BOOST_CHECK(DecodeExtKey(derive.prv) == key); //ensure a base58 decoded key also matches

        // Test public key
        BOOST_CHECK(EncodeExtPubKey(pubkey) == derive.pub);
        BOOST_CHECK(DecodeExtPubKey(derive.pub) == pubkey); //ensure a base58 decoded pubkey also matches

        // Derive new keys
        CExtKey keyNew;
        BOOST_CHECK(key.Derive(keyNew, derive.nChild));
        CExtPubKey pubkeyNew = keyNew.Neuter();
        if (!(derive.nChild & 0x80000000)) {
            // Compare with public derivation
            CExtPubKey pubkeyNew2;
            BOOST_CHECK(pubkey.Derive(pubkeyNew2, derive.nChild));
            BOOST_CHECK(pubkeyNew == pubkeyNew2);
        }
        key = keyNew;
        pubkey = pubkeyNew;
    }
}

}  // namespace

BOOST_FIXTURE_TEST_SUITE(bip32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip32_test1) {
    RunTest(test1);
}

BOOST_AUTO_TEST_CASE(bip32_test2) {
    RunTest(test2);
}

BOOST_AUTO_TEST_CASE(bip32_test3) {
    RunTest(test3);
}

BOOST_AUTO_TEST_CASE(bip32_test4) {
    RunTest(test4);
}

BOOST_AUTO_TEST_CASE(bip32_test5) {
    for (const auto& str : TEST5) {
        auto dec_extkey = DecodeExtKey(str);
        auto dec_extpubkey = DecodeExtPubKey(str);
        BOOST_CHECK_MESSAGE(!dec_extkey.key.IsValid(), "Decoding '" + str + "' as xprv should fail");
        BOOST_CHECK_MESSAGE(!dec_extpubkey.pubkey.IsValid(), "Decoding '" + str + "' as xpub should fail");
    }
}

BOOST_AUTO_TEST_CASE(bip32_max_depth) {
    CExtKey key_parent{DecodeExtKey(test1.vDerive[0].prv)}, key_child;
    CExtPubKey pubkey_parent{DecodeExtPubKey(test1.vDerive[0].pub)}, pubkey_child;

    // We can derive up to the 255th depth..
    for (auto i = 0; i++ < 255;) {
        BOOST_CHECK(key_parent.Derive(key_child, 0));
        std::swap(key_parent, key_child);
        BOOST_CHECK(pubkey_parent.Derive(pubkey_child, 0));
        std::swap(pubkey_parent, pubkey_child);
    }

    // But trying to derive a non-existent 256th depth will fail!
    BOOST_CHECK(key_parent.nDepth == 255 && pubkey_parent.nDepth == 255);
    BOOST_CHECK(!key_parent.Derive(key_child, 0));
    BOOST_CHECK(!pubkey_parent.Derive(pubkey_child, 0));
}

BOOST_AUTO_TEST_CASE(parse_hd_keypath_index_bounds)
{
    for (const std::string prefix : {"", "m/", "m/0/"}) {
        for (const std::string suffix : {"", "'"}) {
            std::vector<uint32_t> keypath;
            BOOST_REQUIRE(ParseHDKeypath(prefix + "2147483647" + suffix, keypath));
            BOOST_CHECK_EQUAL(keypath.back(), suffix.empty() ? 0x7fffffffU : 0xffffffffU);
            for (const std::string number : {"2147483648", "4294967295", "4294967296"}) {
                keypath.clear();
                BOOST_CHECK(!ParseHDKeypath(prefix + number + suffix, keypath));
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
