import json
import pathlib
import unittest

import pytest

from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

VECTORS = (
    pathlib.Path(__file__).resolve().parents[1]
    / "assets"
    / "wycheproof"
    / "testvectors_v1"
)
ML_DSA_BY_PARAM = {44: ML_DSA_44, 65: ML_DSA_65, 87: ML_DSA_87}
# Keep normal CI fast with one result-independent sample from every fourth group.
DEFAULT_GROUP_STRIDE = 4


class TestML_DSA_Wycheproof(unittest.TestCase):
    """C2SP/wycheproof vectors at commit 65ca494727a52944c204441c860b039e6786b99b."""

    def load_vectors(self, filename):
        with (VECTORS / filename).open() as vector_file:
            return json.load(vector_file)

    def sign_case(self, mldsa, private_key, seeded, test):
        if seeded:
            _, sk = mldsa.key_derive(private_key)
        else:
            sk = private_key

        if "msg" in test:
            return mldsa.sign(
                sk,
                bytes.fromhex(test["msg"]),
                ctx=bytes.fromhex(test.get("ctx", "")),
                deterministic=True,
            )
        return mldsa.sign_external_mu(
            sk,
            bytes.fromhex(test["mu"]),
            deterministic=True,
        )

    def generic_sign_test(self, param, seeded, full=False):
        mode = "seed" if seeded else "noseed"
        filename = f"mldsa_{param}_sign_{mode}_test.json"
        mldsa = ML_DSA_BY_PARAM[param]

        for group_index, group in enumerate(self.load_vectors(filename)["testGroups"]):
            if not full and group_index % DEFAULT_GROUP_STRIDE:
                continue
            private_key = bytes.fromhex(
                group["privateSeed"] if seeded else group["privateKey"]
            )

            cases = group["tests"] if full else group["tests"][:1]
            for test in cases:
                with self.subTest(group=group_index, tcId=test["tcId"]):
                    if "rnd" in test:
                        self.skipTest(
                            "The public API cannot provide the vector's chosen signing randomness."
                        )
                    if "InvalidPrivateKey" in test.get("flags", []):
                        self.skipTest(
                            "FIPS 204 §7.3, Algorithm 25 treats skDecode inputs as trusted; "
                            "sign() does not validate coefficient ranges."
                        )

                    if test["result"] == "invalid":
                        with self.assertRaises(ValueError):
                            self.sign_case(mldsa, private_key, seeded, test)
                    else:
                        self.assertEqual(
                            self.sign_case(mldsa, private_key, seeded, test),
                            bytes.fromhex(test["sig"]),
                        )

    def generic_verify_test(self, param, full=False):
        filename = f"mldsa_{param}_verify_test.json"
        mldsa = ML_DSA_BY_PARAM[param]

        for group_index, group in enumerate(self.load_vectors(filename)["testGroups"]):
            if not full and group_index % DEFAULT_GROUP_STRIDE:
                continue
            pk = bytes.fromhex(group["publicKey"])
            cases = group["tests"] if full else group["tests"][:1]
            for test in cases:
                with self.subTest(group=group_index, tcId=test["tcId"]):
                    try:
                        actual = mldsa.verify(
                            pk,
                            bytes.fromhex(test["msg"]),
                            bytes.fromhex(test["sig"]),
                            ctx=bytes.fromhex(test.get("ctx", "")),
                        )
                    except ValueError:
                        actual = False
                    self.assertEqual(actual, test["result"] == "valid")

    def test_ML_DSA_44_sign_noseed(self):
        self.generic_sign_test(44, seeded=False)

    @pytest.mark.wycheproof_full
    def test_full_ML_DSA_44_sign_noseed(self):
        self.generic_sign_test(44, seeded=False, full=True)

    def test_ML_DSA_44_sign_seed(self):
        self.generic_sign_test(44, seeded=True)

    @pytest.mark.wycheproof_full
    def test_full_ML_DSA_44_sign_seed(self):
        self.generic_sign_test(44, seeded=True, full=True)

    def test_ML_DSA_44_verify(self):
        self.generic_verify_test(44)

    @pytest.mark.wycheproof_full
    def test_full_ML_DSA_44_verify(self):
        self.generic_verify_test(44, full=True)

    def test_ML_DSA_65_sign_noseed(self):
        self.generic_sign_test(65, seeded=False)

    @pytest.mark.wycheproof_full
    def test_full_ML_DSA_65_sign_noseed(self):
        self.generic_sign_test(65, seeded=False, full=True)

    def test_ML_DSA_65_sign_seed(self):
        self.generic_sign_test(65, seeded=True)

    @pytest.mark.wycheproof_full
    def test_full_ML_DSA_65_sign_seed(self):
        self.generic_sign_test(65, seeded=True, full=True)

    def test_ML_DSA_65_verify(self):
        self.generic_verify_test(65)

    @pytest.mark.wycheproof_full
    def test_full_ML_DSA_65_verify(self):
        self.generic_verify_test(65, full=True)

    def test_ML_DSA_87_sign_noseed(self):
        self.generic_sign_test(87, seeded=False)

    @pytest.mark.wycheproof_full
    def test_full_ML_DSA_87_sign_noseed(self):
        self.generic_sign_test(87, seeded=False, full=True)

    def test_ML_DSA_87_sign_seed(self):
        self.generic_sign_test(87, seeded=True)

    @pytest.mark.wycheproof_full
    def test_full_ML_DSA_87_sign_seed(self):
        self.generic_sign_test(87, seeded=True, full=True)

    def test_ML_DSA_87_verify(self):
        self.generic_verify_test(87)

    @pytest.mark.wycheproof_full
    def test_full_ML_DSA_87_verify(self):
        self.generic_verify_test(87, full=True)
