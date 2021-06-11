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


if __name__ == "__main__":
    passed = test_sign()
    passed = passed and test_SkToPk()
    passed = passed and test_verify()
    passed = passed and test_pop()
    passed = passed and test_pop_verify()

    if passed:
        print("All tests PASSED")
    else:
        print("Some tests FAILED")
