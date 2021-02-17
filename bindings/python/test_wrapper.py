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


if __name__ == "__main__":
    passed = test_sign()
    passed = passed and test_SkToPk()

    if passed:
        print("All tests PASSED")
    else:
        print("Some tests FAILED")
