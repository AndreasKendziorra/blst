#!/usr/bin/env python3

import lip0038_functions

TEST_INPUT_TAG_MESSAGE = [
    # format [tag, netId, msg, expected result]
    [
        b"LSK_TX_",
        bytes.fromhex(
            "9ee11e9df416b18bf69dbd1a920442e08c6ca319e69926bc843a561782ca17ee"
        ),
        bytes.fromhex("beaf"),
        bytes.fromhex(
            "4c534b5f54585f9ee11e9df416b18bf69dbd1a920442e08c6ca319e69926bc843a561782ca17eebeaf"
        ),
    ]
]

TEST_INPUT_SIGN_BLS = [
    # format [sk, tag, netId, msg, expected result]
    [
        bytes.fromhex(
            "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3"
        ),
        b"LSK_TX_",
        bytes.fromhex(
            "9ee11e9df416b18bf69dbd1a920442e08c6ca319e69926bc843a561782ca17ee"
        ),
        bytes.fromhex("beaf"),
        bytes.fromhex(
            "a6f889695b4ee393c6ede6af2215019cf9d7e004781b98ea12d6b227212126687ecde1c2a08e38e2d5c18eab2881879102e91ac5f0e9813126d6d68262af149ba6c25ffb88e6688fec49b5199cec863c0eb54110fdb6d92c6570f3ca9c1910b9"
        ),
    ]
]


TEST_INPUT_VERIFY_BLS = [
    # format [pk, tag, netId, msg, sig, expected result]
    [
        bytes.fromhex(
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
        ),
        b"LSK_TX_",
        bytes.fromhex(
            "9ee11e9df416b18bf69dbd1a920442e08c6ca319e69926bc843a561782ca17ee"
        ),
        bytes.fromhex("beaf"),
        bytes.fromhex(
            "a6f889695b4ee393c6ede6af2215019cf9d7e004781b98ea12d6b227212126687ecde1c2a08e38e2d5c18eab2881879102e91ac5f0e9813126d6d68262af149ba6c25ffb88e6688fec49b5199cec863c0eb54110fdb6d92c6570f3ca9c1910b9"
        ),
        True,
    ]
]

KEYS_LIST = [
    bytes.fromhex(
        "9998f02d85e3851a430333350ed6cc1c0afbd72ee52cf8ad2f23d394f3937bfdc92e056dce713b9d45dac7b106d82883"
    ),
    bytes.fromhex(
        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
    ),
    bytes.fromhex(
        "8f116ba0b305fb734405dd0968e255ad06a34d0cacfeece4c320502824da4a2ff90a978bfcffa1206ecae27f62bac645"
    ),
    bytes.fromhex(
        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
    ),
    bytes.fromhex(
        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
    ),
    bytes.fromhex(
        "a6b6a639f7fa0b64ad3a93be965e9cc34e1d9d0f0427c14c38fc80934a937c5fa745a3cb285f64d4d1c06d0825504488"
    ),
    bytes.fromhex(
        "b0b2b9b812972e5e629810f0b841391933822d166995530770b5e875a73d945969986e3041a93db90160ea8510439c3e"
    ),
    bytes.fromhex(
        "95324a8c4a890e8c1e83c96c6c639254937c9c9cee789556606744b07e98292e292c8c150efd9506b0b5547fea3fdf9f"
    ),
    bytes.fromhex(
        "884b52f84e801d2453edb023928c79125a5e4384c108dd8f17b7f2a20772c7dc4b9635602937df1b87d8b7284870c932"
    ),
]

TEST_INPUT_CREATE_AGG_SIG = [
    # format [keylist, pubKeySignaturePairs, expected bits, expected sig]
    [
        KEYS_LIST,
        [
            [
                bytes.fromhex(
                    "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
                ),
                bytes.fromhex(
                    "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121"
                ),
            ],
            [
                bytes.fromhex(
                    "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
                ),
                bytes.fromhex(
                    "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df"
                ),
            ],
            [
                bytes.fromhex(
                    "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
                ),
                bytes.fromhex(
                    "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9"
                ),
            ],
        ],
        bytes.fromhex("1a00"),
        bytes.fromhex(
            "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930"
        ),
    ],
    [
        KEYS_LIST,
        [
            [
                bytes.fromhex(
                    "b0b2b9b812972e5e629810f0b841391933822d166995530770b5e875a73d945969986e3041a93db90160ea8510439c3e"
                ),
                bytes.fromhex(
                    "996297e8b63de37e207ee092e769af55b38755472423260b2d4c1312957f38e8d9cce0c5ffe0142b7b4492334feaefc9142f250305aa6f352d8d2a0f85d9706a7a0cd5e5e4055aafe775b97705e46e815b1a21dc2682450e71dbd79ad89db5c0"
                ),
            ],
            [
                bytes.fromhex(
                    "884b52f84e801d2453edb023928c79125a5e4384c108dd8f17b7f2a20772c7dc4b9635602937df1b87d8b7284870c932"
                ),
                bytes.fromhex(
                    "b83429c1d6c890dbd8fa21c4c8489eb33c3004252a4c8524e4e7742a57d172d076a7def01eff1741af9971ce562f01e505dbe4c654572b5ccb4db213ceb941809fa5dd0732e8f06586ac9274b5f417808f6d58f3af5966a98117149e6bf54458"
                ),
            ],
        ],
        bytes.fromhex("4001"),
        bytes.fromhex(
            "89a3b2642b285b129ff9196fa310eea2fb77468b3919f6530ebef402a5c7d589b3d6cfa0bb884b38b365047a7a6a216614a72941479d2753438b3657a430318f43dbfd895632db1c23d988097115fe1d0c4aa5d2ef42da50b8027bd2e410d781"
        ),
    ],
]

TEST_INPUT_VERIFY_AGG_SIG = [
    # format [keysList, aggBits, sig, tag, netId, message, expected result]
    [
        KEYS_LIST,
        bytes.fromhex("4001"),
        bytes.fromhex(
            "89a3b2642b285b129ff9196fa310eea2fb77468b3919f6530ebef402a5c7d589b3d6cfa0bb884b38b365047a7a6a216614a72941479d2753438b3657a430318f43dbfd895632db1c23d988097115fe1d0c4aa5d2ef42da50b8027bd2e410d781"
        ),
        b"LSK_CE_",
        bytes.fromhex(
            "9ee11e9df416b18bf69dbd1a920442e08c6ca319e69926bc843a561782ca17ee"
        ),
        bytes.fromhex("beaf"),
        True,
    ]
]


def test_tag_message():
    passed = True
    for input in TEST_INPUT_TAG_MESSAGE:
        [tag, netId, msg, expected_result] = input
        result = lip0038_functions.tagMessage(tag, netId, msg)
        if result != expected_result:
            passed = False
            print(
                "\nFAILED test for signBLS function:\nsk  =",
                sk.hex(),
                "\ntag =",
                tag,
                "\nnetId =",
                netId.hex(),
                "\nmsg =",
                msg.hex(),
                "\nexpected result =",
                expected_result.hex(),
                "\nactual result   =",
                result.hex(),
                "\n",
            )
        else:
            print("Test for tagMessage PASSED")
    return passed


def test_sign_bls():
    passed = True
    for input in TEST_INPUT_SIGN_BLS:
        [sk, tag, netId, msg, expected_result] = input
        result = lip0038_functions.signBLS(sk, tag, netId, msg)
        if result != expected_result:
            passed = False
            print(
                "\nFAILED test for signBLS function:\ntag  =",
                tag,
                "\nnetId =",
                netId.hex(),
                "\nmsg =",
                msg.hex(),
                "\nexpected result =",
                expected_result.hex(),
                "\nactual result   =",
                result.hex(),
                "\n",
            )
        else:
            print("Test for signBLS PASSED")
    return passed


def test_verify_bls():
    passed = True
    for input in TEST_INPUT_VERIFY_BLS:
        [pk, tag, netId, msg, sig, expected_result] = input
        result = lip0038_functions.verifyBLS(pk, tag, netId, msg, sig)
        if result != expected_result:
            passed = False
            print(
                "\nFAILED test for verifyBLS function:\npk =",
                pk.hex(),
                "\ntag  =",
                tag.hex(),
                "\nnetId =",
                netId.hex(),
                "\nmsg =",
                msg.hex(),
                "\nsig =",
                sig.hex(),
                "\nexpected result =",
                expected_result,
                "\nactual result   =",
                result,
                "\n",
            )
        else:
            print("Test for verifyBLS PASSED")
    return passed


def test_create_agg_sig():
    passed = True
    for input in TEST_INPUT_CREATE_AGG_SIG:
        [keysList, pairs, expected_bits, expected_sig] = input
        result = lip0038_functions.createAggSig(keysList, pairs)
        if result != [expected_bits, expected_sig]:
            passed = False
            print(
                "\nFAILED test for createAggSig function:\nkeysList =",
                [key.hex() for key in keysList],
                "\nPairs  =",
                [
                    "(pk = " + p[0].hex() + ", sig = " + p[1].hex() + "), "
                    for p in pairs
                ],
                "\nexpected bits =",
                expected_bits.hex(),
                "\nactual bits   =",
                result[0].hex(),
                "\nexpected sig =",
                expected_sig.hex(),
                "\nactual sig   =",
                result[1].hex(),
                "\n",
            )
        else:
            print("Test for createAggSig PASSED")
    return passed


def test_verify_agg_sig():
    passed = True
    for input in TEST_INPUT_VERIFY_AGG_SIG:
        [keysList, bits, sig, tag, netId, msg, expected_result] = input
        result = lip0038_functions.verifyAggSig(keysList, bits, sig, tag, netId, msg)
        if result != expected_result:
            passed = False
            print(
                "\nFAILED test for verifyAggSig function:\nkeysList =",
                [key.hex() for key in keysList],
                "\naggBits =",
                bits.hex(),
                "\nsig =",
                sig.hex(),
                "\ntag =",
                str(tag, "UTF-8"),
                "\nnetId =",
                netId.hex(),
                "\nmsg =",
                msg.hex(),
                "\nexpected result =",
                expected_result,
                "\nactual result =",
                result,
                "\n",
            )
        else:
            print("Test for createAggSig PASSED")
    return passed


if __name__ == "__main__":
    result_tag_message = test_tag_message()
    result_sign_bls = test_sign_bls()
    result_verify_bls = test_verify_bls()
    result_create_agg_sig = test_create_agg_sig()
    result_verify_agg_sig = test_verify_agg_sig()

    passed = (
        result_tag_message
        and result_sign_bls
        and result_verify_bls
        and test_create_agg_sig
        and result_verify_agg_sig
    )

    if passed:
        print("All tests PASSED")
    else:
        print("Some tests FAILED")
