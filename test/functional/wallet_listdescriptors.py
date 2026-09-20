#!/usr/bin/env python3
# Copyright (c) 2014-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the listdescriptors RPC."""

from test_framework.blocktools import (
    TIME_GENESIS_BLOCK,
)
from test_framework.descriptors import (
    descsum_create,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_not_equal,
    assert_equal,
    assert_raises_rpc_error,
)


class ListDescriptorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # do not create any wallet by default
    def init_wallet(self, *, node):
        return

    def run_test(self):
        node = self.nodes[0]
        assert_raises_rpc_error(-18, 'No wallet is loaded.', node.listdescriptors)

        self.log.info('Test the command for empty descriptors wallet.')
        node.createwallet(wallet_name='w2', blank=True)
        assert_equal(0, len(node.get_wallet_rpc('w2').listdescriptors()['descriptors']))

        self.log.info('Test the command for a default descriptors wallet.')
        node.createwallet(wallet_name='w3')
        result = node.get_wallet_rpc('w3').listdescriptors()
        assert_equal("w3", result['wallet_name'])
        assert_equal(2, len(result['descriptors']))
        assert_equal(2, len([d for d in result['descriptors'] if d['active']]))
        assert_equal(1, len([d for d in result['descriptors'] if d['internal']]))
        for item in result['descriptors']:
            assert_not_equal(item['desc'], '')
            assert item['next_index'] == 0
            assert item['range'] == [0, 0]
            assert item['timestamp'] is not None

        self.log.info('Test that descriptor strings are returned in lexicographically sorted order.')
        descriptor_strings = [descriptor['desc'] for descriptor in result['descriptors']]
        assert_equal(descriptor_strings, sorted(descriptor_strings))

        self.log.info('Test descriptors with hardened derivations are listed in importable form.')
        xprv = 'KrprvXJ7sdXeAaebXkSzAQiQJd974hZJWFgc6MN9J9PrS1ymfQzC6CR7GXPkA4o35ucUNvFyuEHhUx9QRiL4FsacfcQKThxfuJ43yihRVYZYaDyf'
        xpub_acc = 'KrpubTd5it8f4gBSvhDhxpSzvdCNEFYpPpeqhvm4xas2fWr55cLxBG1VoFPPMMpWffWsjUp3ETMWmLDC6V4frqsfNgsiTy5QmS4bW2cmuesA9mpb'
        hardened_path = '/86h/1h/0h'
        wallet = node.get_wallet_rpc('w2')
        private_desc = descsum_create('tr(' + xprv + hardened_path + '/0/*)')
        public_desc = 'tr([80002067/86h/1h/0h]KrpubTeLgo3HeAz2S6nHuXmEouMPgW3A8NTBNY84Wyb3yNogiRJvoh5oMn4SePfSoXYDpWm2yWTNVnzQi9SZpSKDpbDHWWRMHGFYyKUxrmrHHxf6/0/*)#gdt5tdj9'
        wallet.importdescriptors([{
            'desc': private_desc,
            'timestamp': TIME_GENESIS_BLOCK,
        }])
        expected = {
            'wallet_name': 'w2',
            'descriptors': [
                {'desc': public_desc,
                 'timestamp': TIME_GENESIS_BLOCK,
                 'active': False,
                 'range': [0, 0],
                 'next_index': 0},
            ],
        }
        assert_equal(expected, wallet.listdescriptors())
        assert_equal(expected, wallet.listdescriptors(False))

        self.log.info('Test list private descriptors')
        expected_private = {
            'wallet_name': 'w2',
            'descriptors': [
                {'desc': private_desc,
                 'timestamp': TIME_GENESIS_BLOCK,
                 'active': False,
                 'range': [0, 0],
                 'next_index': 0},
            ],
        }
        assert_equal(expected_private, wallet.listdescriptors(True))

        self.log.info("Test listdescriptors with encrypted wallet")
        wallet.encryptwallet("pass")
        assert_equal(expected, wallet.listdescriptors())

        self.log.info('Test list private descriptors with encrypted wallet')
        assert_raises_rpc_error(-13, 'Please enter the wallet passphrase with walletpassphrase first.', wallet.listdescriptors, True)
        wallet.walletpassphrase(passphrase="pass", timeout=1000000)
        assert_equal(expected_private, wallet.listdescriptors(True))

        self.log.info('Test list private descriptors with watch-only wallet')
        node.createwallet(wallet_name='watch-only', disable_private_keys=True)
        watch_only_wallet = node.get_wallet_rpc('watch-only')
        watch_only_wallet.importdescriptors([{
            'desc': descsum_create('tr(' + xpub_acc + ')'),
            'timestamp': TIME_GENESIS_BLOCK,
        }])
        assert_raises_rpc_error(-4, 'Can\'t get private descriptor string for watch-only wallets', watch_only_wallet.listdescriptors, True)

        self.log.info('Test a non-active non-range Taproot descriptor')
        node.createwallet(wallet_name='w4', blank=True)
        wallet = node.get_wallet_rpc('w4')
        private_desc = descsum_create('tr(' + node.get_deterministic_priv_key().key + ')')
        public_desc = node.getdescriptorinfo(private_desc)['descriptor']
        wallet.importdescriptors([{
            'desc': private_desc,
            'timestamp': TIME_GENESIS_BLOCK,
        }])
        expected = {
            'wallet_name': 'w4',
            'descriptors': [
                {'active': False,
                 'desc': public_desc,
                 'timestamp': TIME_GENESIS_BLOCK},
            ],
        }
        assert_equal(expected, wallet.listdescriptors())

        self.log.info('Test taproot descriptor do not have mixed hardened derivation marker')
        node.createwallet(wallet_name='w5', disable_private_keys=True)
        wallet = node.get_wallet_rpc('w5')
        wallet.importdescriptors([{
            'desc': "tr([1dce71b2/48'/1'/0'/2']KrpubTfNcai4scACLe1zibJogwiZo7hVh2tKjDLVJ82qSGzycmyqrFQQnzFWi1SiioBoZfvjxuqs2dKyqtjsUBauCNHBH4ntBn7jZAi4iPSszqsz/0/*,and_v(v:pk([c658b283/48'/1'/0'/2']KrpubTg4KVS6b3rurF7ZToA1kUq15DxHVWtsXbgGWBTmSdrAc5N5zXL9iiHDCp8bk6PmQzsC9FmGoqMntwqCHwyF25rPeWFDXDVUy9FHA9Eg1RGh/0/*),older(65535)))#dg6zj06z",
            'timestamp': TIME_GENESIS_BLOCK,
        }])
        expected = {
            'wallet_name': 'w5',
            'descriptors': [
                {'active': False,
                 'desc': 'tr([1dce71b2/48h/1h/0h/2h]KrpubTfNcai4scACLe1zibJogwiZo7hVh2tKjDLVJ82qSGzycmyqrFQQnzFWi1SiioBoZfvjxuqs2dKyqtjsUBauCNHBH4ntBn7jZAi4iPSszqsz/0/*,and_v(v:pk([c658b283/48h/1h/0h/2h]KrpubTg4KVS6b3rurF7ZToA1kUq15DxHVWtsXbgGWBTmSdrAc5N5zXL9iiHDCp8bk6PmQzsC9FmGoqMntwqCHwyF25rPeWFDXDVUy9FHA9Eg1RGh/0/*),older(65535)))#84ya796j',
                 'timestamp': TIME_GENESIS_BLOCK,
                 'range': [0, 0],
                 'next_index': 0},
            ]
        }
        assert_equal(expected, wallet.listdescriptors())

        self.log.info('Test descriptor with missing private keys')
        node.createwallet(wallet_name='w6', blank=True)
        wallet = node.get_wallet_rpc('w6')

        expected_descs = {
            descsum_create('tr(' + node.get_deterministic_priv_key().key +
                ',{pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)' +
                ',pk([d34db33f/44h/0h/0h]KrpubTX7E33B4R29pw93b5wkY3ue6kf3UmUFtTSTH9QpmmL7u5CUfq6gBBuxML4Eov9RNfbmZLFHSXrWCyApiZif8p1AiwyGxrXuBi6M3jbkjJdo/0)})'),
            descsum_create('tr(03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,pk(musig(KrprvXJ7sdXeAaebXjupwAdJ7ipsW8NfBswZwSMcgrToSYYgf5vQdfVPDVff81ccahpy5ojveTRvvwKXrvgfuT2VHybX4B7M838J4NChS5UVMrPi,KrpubTX7E33B4R29pxAhLUBwraLmiEKFQrZN4FWKgSoqfoTpirEU7d4h8iArQnw5TLRkj4RNdrsQoH3jQXcDXeewvmP5gptr767NCtGvzmXn78Qb)/7/8/*))'),
            descsum_create('tr(03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,pk(musig(KrprvXJ7sdXeAaebXjupwAdJ7ipsW8NfBswZwSMcgrToSYYgf5vQdfVPDVff81ccahpy5ojveTRvvwKXrvgfuT2VHybX4B7M838J4NChS5UVMrPi/10,KrpubTX7E33B4R29pxAhLUBwraLmiEKFQrZN4FWKgSoqfoTpirEU7d4h8iArQnw5TLRkj4RNdrsQoH3jQXcDXeewvmP5gptr767NCtGvzmXn78Qb/11)/*))'),
            descsum_create('tr(03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,{pk(musig(KrpubTX7E33B4R29pwMZeiQ1J5oTVZJkV4dRxs763U3ySjQdVP1fiRUaepvhWiy9yjpSaFpZUtz3jcxHQVK9skE8oYYs8onZDamCDPMRnwq6BoHZ,KrprvXJ7sdXeAaebXkKYrAev99fJSdnQXmC1MWEBH3fPe3jf13UNhLcCrc1F3vMKwXmZp91s5qScmMDh2NccPt2UPx4mfS1UKWRz2BgnTqhfgXHN)/12/*),pk(musig(KrprvXJ7sdXeAaebXjupwAdJ7ipsW8NfBswZwSMcgrToSYYgf5vQdfVPDVff81ccahpy5ojveTRvvwKXrvgfuT2VHybX4B7M838J4NChS5UVMrPi,KrpubTX7E33B4R29px58EmQxMcfidNV4DVCgKz8EJ2jLfHWQJmgDNaySUpHzhLJLSdfHSHSnKpgQAVrgbRGerbty9p4FfY8GbWeRmp4P5wXzpFWq)/13/*)})'),
            descsum_create('tr(03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,{pk(musig(KrpubTX7E33B4R29pwMZeiQ1J5oTVZJkV4dRxs763U3ySjQdVP1fiRUaepvhWiy9yjpSaFpZUtz3jcxHQVK9skE8oYYs8onZDamCDPMRnwq6BoHZ,KrpubTX7E33B4R29pwAarCUeyeMrQ2sjPm2QxQrps9ShXmVPiTBW58vvuT9YBMNwFwzXnV9iwhxNXaeEpTCMTTVAUAuw2kB4xcvxvx9VvvNA46kT)/12/*),pk(musig(KrprvXJ7sdXeAaebXjupwAdJ7ipsW8NfBswZwSMcgrToSYYgf5vQdfVPDVff81ccahpy5ojveTRvvwKXrvgfuT2VHybX4B7M838J4NChS5UVMrPi,KrpubTX7E33B4R29px58EmQxMcfidNV4DVCgKz8EJ2jLfHWQJmgDNaySUpHzhLJLSdfHSHSnKpgQAVrgbRGerbty9p4FfY8GbWeRmp4P5wXzpFWq)/13/*)})')
        }

        descs_to_import = []
        for desc in expected_descs:
            descs_to_import.append({'desc': desc, 'timestamp': TIME_GENESIS_BLOCK})

        wallet.importdescriptors(descs_to_import)
        result = wallet.listdescriptors(True)
        actual_descs = [d['desc'] for d in result['descriptors']]

        assert_equal(len(actual_descs), len(expected_descs))
        for desc in actual_descs:
            if desc not in expected_descs:
                raise AssertionError(f"{desc} missing")



if __name__ == '__main__':
    ListDescriptorsTest(__file__).main()
