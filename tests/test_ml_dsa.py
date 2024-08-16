import unittest
import os
import json
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87


class TestMLDSA(unittest.TestCase):
    """
    Test ML DSA for internal consistency by generating signatures
    and verifying them!
    """

    def generic_test_ml_dsa(self, ML_DSA, count=5):
        for _ in range(count):
            msg = b"Signed by ML_DSA" + os.urandom(16)

            # Perform signature process
            pk, sk = ML_DSA.keygen()
            sig = ML_DSA.sign(sk, msg)
            check_verify = ML_DSA.verify(pk, msg, sig)

            # Generate some fail cases
            pk_bad, _ = ML_DSA.keygen()
            check_wrong_pk = ML_DSA.verify(pk_bad, msg, sig)
            check_wrong_msg = ML_DSA.verify(pk, b"", sig)

            # Check that signature works
            self.assertTrue(check_verify)

            # Check changing the key breaks verify
            self.assertFalse(check_wrong_pk)

            # Check changing the message breaks verify
            self.assertFalse(check_wrong_msg)

    def test_ml_dsa_44(self):
        self.generic_test_ml_dsa(ML_DSA_44)

    def test_ml_dsa_65(self):
        self.generic_test_ml_dsa(ML_DSA_65)

    def test_ml_dsa_87(self):
        self.generic_test_ml_dsa(ML_DSA_87)


class TestMLDSADeterministic(unittest.TestCase):
    """
    Test ML DSA for internal consistency by generating signatures
    and verifying them!
    """

    def generic_test_ml_dsa(self, ML_DSA, count=5):
        for _ in range(count):
            msg = b"Signed by ML_DSA" + os.urandom(16)

            # Perform signature process
            pk, sk = ML_DSA.keygen()
            sig = ML_DSA.sign(sk, msg, deterministic=True)
            check_verify = ML_DSA.verify(pk, msg, sig)

            # Generate some fail cases
            pk_bad, _ = ML_DSA.keygen()
            check_wrong_pk = ML_DSA.verify(pk_bad, msg, sig)
            check_wrong_msg = ML_DSA.verify(pk, b"", sig)

            # Check that signature works
            self.assertTrue(check_verify)

            # Check changing the key breaks verify
            self.assertFalse(check_wrong_pk)

            # Check changing the message breaks verify
            self.assertFalse(check_wrong_msg)

    def test_ml_dsa_44(self):
        self.generic_test_ml_dsa(ML_DSA_44)

    def test_ml_dsa_65(self):
        self.generic_test_ml_dsa(ML_DSA_65)

    def test_ml_dsa_87(self):
        self.generic_test_ml_dsa(ML_DSA_87)


class TestML_DSA_KAT(unittest.TestCase):
    """
    Test ML-DSA against test vectors collected from
    https://github.com/usnistgov/ACVP-Server/releases/tag/v1.1.0.35
    """

    def generic_keygen_kat(self, ML_DSA, index):
        with open("assets/ML-DSA-keyGen-FIPS204/internalProjection.json") as f:
            data = json.load(f)
        kat_data = data["testGroups"][index]["tests"]

        for test in kat_data:
            seed = bytes.fromhex(test["seed"])
            pk_kat = bytes.fromhex(test["pk"])
            sk_kat = bytes.fromhex(test["sk"])

            pk, sk = ML_DSA._keygen_internal(seed)
            self.assertEqual(pk, pk_kat)
            self.assertEqual(sk, sk_kat)

    def generic_sign_kat(self, ML_DSA, index, deterministic=False):
        with open("assets/ML-DSA-sigGen-FIPS204/internalProjection.json") as f:
            data = json.load(f)
        if deterministic:
            kat_data = data["testGroups"][2 * index]["tests"]
        else:
            kat_data = data["testGroups"][2 * index + 1]["tests"]

        for test in kat_data:
            sk_kat = bytes.fromhex(test["sk"])
            msg_kat = bytes.fromhex(test["message"])
            sig_kat = bytes.fromhex(test["signature"])

            if deterministic:
                rng_kat = bytes([0]) * 32
            else:
                rng_kat = bytes.fromhex(test["rng"])

            sig = ML_DSA._sign_internal(sk_kat, msg_kat, rng_kat)
            self.assertEqual(sig, sig_kat)

    def generic_verify_kat(self, ML_DSA, index):
        with open("assets/ML-DSA-sigVer-FIPS204/internalProjection.json") as f:
            data = json.load(f)
        pk_kat = bytes.fromhex(data["testGroups"][index]["pk"])
        kat_data = data["testGroups"][index]["tests"]

        for test in kat_data:
            check_kat = test["testPassed"]
            msg_kat = bytes.fromhex(test["message"])
            sig_kat = bytes.fromhex(test["signature"])

            check = ML_DSA._verify_internal(pk_kat, msg_kat, sig_kat)
            self.assertEqual(check, check_kat)

    def test_ML_DSA_44_keygen(self):
        self.generic_keygen_kat(ML_DSA_44, 0)

    def test_ML_DSA_65_keygen(self):
        self.generic_keygen_kat(ML_DSA_65, 1)

    def test_ML_DSA_87_keygen(self):
        self.generic_keygen_kat(ML_DSA_87, 2)

    def test_ML_DSA_44_sign(self):
        self.generic_sign_kat(ML_DSA_44, 0, deterministic=True)

    def test_ML_DSA_65_sign(self):
        self.generic_sign_kat(ML_DSA_65, 1, deterministic=True)

    def test_ML_DSA_87_sign(self):
        self.generic_sign_kat(ML_DSA_87, 2, deterministic=True)

    def test_ML_DSA_44_verify(self):
        self.generic_verify_kat(ML_DSA_44, 0)

    def test_ML_DSA_65_verify(self):
        self.generic_verify_kat(ML_DSA_65, 1)

    def test_ML_DSA_87_verify(self):
        self.generic_verify_kat(ML_DSA_87, 2)
