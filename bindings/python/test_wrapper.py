#!/usr/bin/env python3

import wrapper

SIGN_TEST_INPUT = [
    # format [sk, message, expected signature]
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/sign/small/sign_case_11b8c7cad5238946/data.yaml
    [
        bytes.fromhex(
            "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138"
        ),
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        bytes.fromhex(
            "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9"
        ),
    ],
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/sign/small/sign_case_142f678a8d05fcd1/data.yaml
    [
        bytes.fromhex(
            "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138"
        ),
        bytes.fromhex(
            "5656565656565656565656565656565656565656565656565656565656565656"
        ),
        bytes.fromhex(
            "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe"
        ),
    ],
]

SK_TO_PK_TEST_INPUT = [
    # format [sk, expected pk]
    # compare https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/sign/small/sign_case_d0e28d7e76eb6e9c/data.yaml
    # and https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/verify/small/verify_valid_case_2ea479adf8c40300/data.yaml
    [
        bytes.fromhex(
            "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3"
        ),
        bytes.fromhex(
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
        ),
    ]
]

VERIFY_TEST_INPUT = [
    # format [pk, message, signature, expected result]
    # valid case
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/verify/small/verify_valid_case_195246ee3bd3b6ec/data.yaml
    [
        bytes.fromhex(
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
        ),
        bytes.fromhex(
            "abababababababababababababababababababababababababababababababab"
        ),
        bytes.fromhex(
            "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9"
        ),
        True,
    ],
    # valid case
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/verify/small/verify_valid_case_2ea479adf8c40300/data.yaml
    [
        bytes.fromhex(
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
        ),
        bytes.fromhex(
            "5656565656565656565656565656565656565656565656565656565656565656"
        ),
        bytes.fromhex(
            "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"
        ),
        True,
    ],
    # tampered signature case
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/verify/small/verify_tampered_signature_case_195246ee3bd3b6ec/data.yaml
    [
        bytes.fromhex(
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
        ),
        bytes.fromhex(
            "abababababababababababababababababababababababababababababababab"
        ),
        bytes.fromhex(
            "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9ffffffff"
        ),
        False,
    ],
    # tampered message case
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/verify/small/verify_valid_case_195246ee3bd3b6ec/data.yaml
    # but modified message
    [
        bytes.fromhex(
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
        ),
        bytes.fromhex(
            "bbababababababababababababababababababababababababababababababab"
        ),
        bytes.fromhex(
            "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9"
        ),
        False,
    ],
    # wrong pubkey case: pubkey is valid with respect to KeyValidate (see
    # https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#section-2.5),
    # but not the right key for the provided signature
    # message and signature from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/verify/small/verify_valid_case_195246ee3bd3b6ec/data.yaml
    # pubkey from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/verify/small/verify_valid_case_2ea479adf8c40300/data.yaml
    [
        bytes.fromhex(
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
        ),
        bytes.fromhex(
            "abababababababababababababababababababababababababababababababab"
        ),
        bytes.fromhex(
            "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9"
        ),
        False,
    ],
]

POP_TEST_INPUT = [
    bytes.fromhex("47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138"),
    bytes.fromhex("263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3"),
]

POP_VERIFY_TEST_INPUT = [
    # format [pk, proof, expected result]
    # Invalid case: public key is identity point in G1
    [
        bytes.fromhex(
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ),
        bytes.fromhex(
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ),
        False,
    ],
    # Invalid case: pk does not represent a point on E1
    [
        bytes.fromhex(
            "a53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
        ),
        bytes.fromhex(
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ),
        False,
    ],
    # Invalid case: pk represents a point on E1 but is NOT an element of G1
    # from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-J.9.1:
    #   pubkey equals Q1.x of the first example, however the the most
    #   significant bit is set as described as described here:
    #       https://github.com/supranational/blst#serialization
    [
        bytes.fromhex(
            "960003aaf1632b13396dbad518effa00fff532f604de1a7fc2082ff4cb0afa2d63b2c32da1bef2bf6c5ca62dc6b72f9c"
        ),
        bytes.fromhex(
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ),
        False,
    ],
    # Invalid case: proof is not a point in E2 (tampered proof)
    [
        bytes.fromhex(
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
        ),
        bytes.fromhex(
            "b803eb0ed93ea10224a73b6b9c725796be9f5fefd215ef7a5b97234cc956cf6870db6127b7e4d824ec62276078e787db05584ce1adbf076bc0808ca0f15b73d59060254b25393d95dfc7abe3cda566842aaedf50bbb062aae1bbb6ef3b1fffff"
        ),
        False,
    ],
    # Invalid case: proof is a point in E2 but not the matching proof for pk
    [
        bytes.fromhex(
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
        ),
        bytes.fromhex(
            "88bb31b27eae23038e14f9d9d1b628a39f5881b5278c3c6f0249f81ba0deb1f68aa5f8847854d6554051aa810fdf1cdb02df4af7a5647b1aa4afb60ec6d446ee17af24a8a50876ffdaf9bf475038ec5f8ebeda1c1c6a3220293e23b13a9a5d26"
        ),
        False,
    ],
]

AGGREGATE_TEST_INPUT = [
    # format [[sig_1, ... , sig_n], expected result] where expected has format
    #   [True/False, expected agg_sig].
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/aggregate/small/aggregate_0x0000000000000000000000000000000000000000000000000000000000000000/data.yaml
    [
        [
            bytes.fromhex(
                "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55"
            ),
            bytes.fromhex(
                "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9"
            ),
            bytes.fromhex(
                "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115"
            ),
        ],
        [
            True,
            bytes.fromhex(
                "9683b3e6701f9a4b706709577963110043af78a5b41991b998475a3d3fd62abf35ce03b33908418efc95a058494a8ae504354b9f626231f6b3f3c849dfdeaf5017c4780e2aee1850ceaf4b4d9ce70971a3d2cfcd97b7e5ecf6759f8da5f76d31"
            ),
        ],
    ],
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/aggregate/small/aggregate_0x5656565656565656565656565656565656565656565656565656565656565656/data.yaml
    [
        [
            bytes.fromhex(
                "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"
            ),
            bytes.fromhex(
                "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe"
            ),
            bytes.fromhex(
                "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6"
            ),
        ],
        [
            True,
            bytes.fromhex(
                "ad38fc73846583b08d110d16ab1d026c6ea77ac2071e8ae832f56ac0cbcdeb9f5678ba5ce42bd8dce334cc47b5abcba40a58f7f1f80ab304193eb98836cc14d8183ec14cc77de0f80c4ffd49e168927a968b5cdaa4cf46b9805be84ad7efa77b"
            ),
        ],
    ],
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/aggregate/small/aggregate_0xabababababababababababababababababababababababababababababababab/data.yaml
    [
        [
            bytes.fromhex(
                "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121"
            ),
            bytes.fromhex(
                "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df"
            ),
            bytes.fromhex(
                "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9"
            ),
        ],
        [
            True,
            bytes.fromhex(
                "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930"
            ),
        ],
    ],
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/aggregate/small/aggregate_infinity_signature/data.yaml
    [
        [
            bytes.fromhex(
                "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        ],
        [
            True,
            bytes.fromhex(
                "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ),
        ],
    ],
    # Invalid case: no signatures
    [
        [],
        [
            False,
            bytes(),
        ],
    ],
    # Invalid case: one signature that does not represent a point on E2
    [
        [
            bytes.fromhex(
                "c10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        ],
        [
            False,
            bytes(),
        ],
    ],
    # Invalid case: 3rd signature does not represent a point on E2
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/aggregate/small/aggregate_0x0000000000000000000000000000000000000000000000000000000000000000/data.yaml
    # but 3rd signatures tampered
    [
        [
            bytes.fromhex(
                "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55"
            ),
            bytes.fromhex(
                "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9"
            ),
            bytes.fromhex(
                "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21bffff"
            ),
        ],
        [
            False,
            bytes(),
        ],
    ],
]

FAST_AGGREGATE_VERIFY_TEST_INPUT = [
    # format [[pk_1, ..., pk_n], msg, sig, expected result]
    # Valid case
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/fast_aggregate_verify/small/fast_aggregate_verify_valid_3d7576f3c0e3570a/data.yaml
    [
        [
            bytes.fromhex(
                "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
            ),
            bytes.fromhex(
                "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
            ),
            bytes.fromhex(
                "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
            ),
        ],
        bytes.fromhex(
            "abababababababababababababababababababababababababababababababab"
        ),
        bytes.fromhex(
            "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930"
        ),
        True,
    ],
    # Valid case
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/fast_aggregate_verify/small/fast_aggregate_verify_valid_5e745ad0c6199a6c/data.yaml
    [
        [
            bytes.fromhex(
                "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
            ),
        ],
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        bytes.fromhex(
            "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55"
        ),
        True,
    ],
    # Valid case
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/fast_aggregate_verify/small/fast_aggregate_verify_valid_3d7576f3c0e3570a/data.yaml
    [
        [
            bytes.fromhex(
                "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
            ),
            bytes.fromhex(
                "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
            ),
        ],
        bytes.fromhex(
            "5656565656565656565656565656565656565656565656565656565656565656"
        ),
        bytes.fromhex(
            "912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f779746d830d1"
        ),
        True,
    ],
    # Inalid case: extra public key
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/fast_aggregate_verify/small/fast_aggregate_verify_extra_pubkey_4f079f946446fabf/data.yaml
    [
        [
            bytes.fromhex(
                "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
            ),
            bytes.fromhex(
                "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
            ),
            bytes.fromhex(
                "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
            ),
        ],
        bytes.fromhex(
            "5656565656565656565656565656565656565656565656565656565656565656"
        ),
        bytes.fromhex(
            "912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f779746d830d1"
        ),
        False,
    ],
    # Inalid case: extra public key
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/fast_aggregate_verify/small/fast_aggregate_verify_extra_pubkey_5a38e6b4017fe4dd/data.yaml
    [
        [
            bytes.fromhex(
                "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
            ),
            bytes.fromhex(
                "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
            ),
            bytes.fromhex(
                "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
            ),
            bytes.fromhex(
                "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
            ),
        ],
        bytes.fromhex(
            "abababababababababababababababababababababababababababababababab"
        ),
        bytes.fromhex(
            "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930"
        ),
        False,
    ],
    # Inalid case: extra public key
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/fast_aggregate_verify/small/fast_aggregate_verify_extra_pubkey_a698ea45b109f303/data.yaml
    [
        [
            bytes.fromhex(
                "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
            ),
            bytes.fromhex(
                "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
            ),
        ],
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        bytes.fromhex(
            "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55"
        ),
        False,
    ],
    # Inalid case: no public keys and signature is identity point
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/fast_aggregate_verify/small/fast_aggregate_verify_na_pubkeys_and_infinity_signature/data.yaml
    [
        [],
        bytes.fromhex(
            "abababababababababababababababababababababababababababababababab"
        ),
        bytes.fromhex(
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ),
        False,
    ],
    # Inalid case: no public keys and signature is byte sequence with all bytes set to zero
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/fast_aggregate_verify/small/fast_aggregate_verify_na_pubkeys_and_infinity_signature/data.yaml
    [
        [],
        bytes.fromhex(
            "abababababababababababababababababababababababababababababababab"
        ),
        bytes.fromhex(
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ),
        False,
    ],
    # Inalid case: tampered signature
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/fast_aggregate_verify/small/fast_aggregate_verify_tampered_signature_3d7576f3c0e3570a/data.yaml
    [
        [
            bytes.fromhex(
                "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
            ),
            bytes.fromhex(
                "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
            ),
            bytes.fromhex(
                "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
            ),
        ],
        bytes.fromhex(
            "abababababababababababababababababababababababababababababababab"
        ),
        bytes.fromhex(
            "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfcffffffff"
        ),
        False,
    ],
    # Inalid case: tampered signature
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/fast_aggregate_verify/small/fast_aggregate_verify_tampered_signature_5e745ad0c6199a6c/data.yaml
    [
        [
            bytes.fromhex(
                "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
            ),
        ],
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        bytes.fromhex(
            "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380bffffffff"
        ),
        False,
    ],
    # Inalid case: tampered signature
    # from https://media.githubusercontent.com/media/ethereum/eth2.0-spec-tests/master/tests/general/phase0/bls/fast_aggregate_verify/small/fast_aggregate_verify_tampered_signature_652ce62f09290811/data.yaml
    [
        [
            bytes.fromhex(
                "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
            ),
            bytes.fromhex(
                "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
            ),
        ],
        bytes.fromhex(
            "5656565656565656565656565656565656565656565656565656565656565656"
        ),
        bytes.fromhex(
            "912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f7797ffffffff"
        ),
        False,
    ],
]


def test_sign():
    passed = True
    for input in SIGN_TEST_INPUT:
        [sk, msg, expected_sig] = input
        sig = wrapper.sign(sk, msg)
        if sig != expected_sig:
            passed = False
            print(
                "\nFAILED test for sign function:\nsk  =",
                sk.hex(),
                "\nmsg =",
                msg.hex(),
                "\nexpected sig =",
                expected_sig.hex(),
                "\nactual sig   =",
                sig.hex(),
                "\n",
            )
        else:
            print("Test for sign function PASSED")
    return passed


def test_SkToPk():
    passed = True
    for input in SK_TO_PK_TEST_INPUT:
        [sk, expected_pk] = input
        pk = wrapper.SkToPk(sk)
        if pk != expected_pk:
            passed = False
            print(
                "\nFAILED test for SkToPk:\nsk  =",
                sk.hex(),
                "\nexpected pk =",
                expected_pk.hex(),
                "\nactual pk   =",
                pk.hex(),
                "\n",
            )
        else:
            print("Test for SkToPk PASSED")
    return passed


def test_verify():
    passed = True
    for input in VERIFY_TEST_INPUT:
        [pk, msg, sig, expected_result] = input
        result = wrapper.verify(pk, msg, sig)
        if result != expected_result:
            passed = False
            print(
                "\nFAILED test for verify function:\npk  =",
                pk.hex(),
                "\nmsg =",
                msg.hex(),
                "\nsig =",
                sig.hex(),
                "\nexpected result  =",
                expected_result,
                "\nactual result  =",
                result,
                "\n",
            )
        else:
            print("Test for verify function PASSED")
    return passed


def test_pop():
    passed = True
    for sk in POP_TEST_INPUT:
        pk = wrapper.SkToPk(sk)
        proof = wrapper.PopProve(sk)
        if not wrapper.PopVerify(pk, proof):
            passed = False
            print(
                "\nFAILED test for proof of possession:\nsk  =",
                sk.hex(),
                "\npk =",
                pk.hex(),
                "\nproof =",
                proof.hex(),
                "\n",
            )
        else:
            print("Test for proof of possession PASSED")
    return passed


def test_pop_verify():
    passed = True
    for input in POP_VERIFY_TEST_INPUT:
        [pk, proof, expected_result] = input
        result = wrapper.PopVerify(pk, proof)
        if result != expected_result:
            passed = False
            print(
                "\nFAILED test for PopVerify function:\npk  =",
                pk.hex(),
                "\nproof =",
                proof.hex(),
                "\nexpected result  =",
                expected_result,
                "\nactual result  =",
                result,
                "\n",
            )
        else:
            print("Test for PopVerify function PASSED")
    return passed


def test_aggregate():
    passed = True
    for input in AGGREGATE_TEST_INPUT:
        [sigs, expected_result] = input
        result = wrapper.Aggregate(sigs)
        if result != expected_result:
            passed = False
            print(
                "\nFAILED test for Aggregate function:\nlen(sigs)  =",
                len(sigs),
                "\nsigs =",
                [sig.hex() for sig in sigs],
                "\nexpected result  =",
                expected_result[0],
                ", ",
                expected_result[1].hex(),
                "\nactual result    =",
                result[0],
                ",  ",
                result[1].hex(),
                "\n",
            )
        else:
            print("Test for Aggregate function PASSED")
    return passed


def test_fast_aggregate_verify():
    passed = True
    for input in FAST_AGGREGATE_VERIFY_TEST_INPUT:
        [pks, msg, sig, expected_result] = input
        result = wrapper.FastAggregateVerify(pks, msg, sig)
        if result != expected_result:
            passed = False
            print(
                "\nFAILED test for FastAggregateVerify function:\nlen(pks)  =",
                len(pks),
                "\npks =",
                [pk.hex() for pk in pks],
                "\nmsg =",
                msg.hex(),
                "\nsig =",
                sig.hex(),
                "\nexpected result  =",
                expected_result,
                "\nactual result  =",
                result,
                "\n",
            )
        else:
            print("Test for Aggregate function PASSED")
    return passed


if __name__ == "__main__":
    passed = test_sign()
    passed = passed and test_SkToPk()
    passed = passed and test_verify()
    passed = passed and test_pop()
    passed = passed and test_pop_verify()
    passed = passed and test_aggregate()
    passed = passed and test_fast_aggregate_verify()

    if passed:
        print("All tests PASSED")
    else:
        print("Some tests FAILED")
