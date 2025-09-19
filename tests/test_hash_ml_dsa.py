import unittest
import os
from dilithium_py.ml_dsa import (
    HASH_ML_DSA_44_WITH_SHA512,
    HASH_ML_DSA_65_WITH_SHA512,
    HASH_ML_DSA_87_WITH_SHA512,
)


class TestHashMLDSA(unittest.TestCase):
    """
    Test ML DSA for internal consistency by generating signatures
    and verifying them!
    """

    def generic_test_hash_ml_dsa(self, HASH_ML_DSA, hash_name="SHA512", count=5):
        for _ in range(count):
            msg = b"Signed by HASH_ML_DSA" + os.urandom(16)
            ctx = os.urandom(128)

            # Perform signature process
            pk, sk = HASH_ML_DSA.keygen()
            sig = HASH_ML_DSA.sign(sk, msg, ctx=ctx)
            check_verify = HASH_ML_DSA.verify(pk, msg, sig, ctx=ctx)

            # Generate some fail cases
            pk_bad, _ = HASH_ML_DSA.keygen()
            check_wrong_pk = HASH_ML_DSA.verify(pk_bad, msg, sig, ctx=ctx)
            check_wrong_msg = HASH_ML_DSA.verify(pk, b"", sig, ctx=ctx)
            check_no_ctx = HASH_ML_DSA.verify(pk, msg, sig)

            # Check with user-supplied hashes
            hash_sig = HASH_ML_DSA._sign_with_pre_hash(sk, msg, hash_name, ctx=ctx)
            check_hash_verify = HASH_ML_DSA._verify_with_pre_hash(
                pk, msg, hash_sig, hash_name, ctx=ctx
            )

            # Check with the wrong hashes
            if hash_name == "SHA512":
                bad_hash = "SHA256"
            else:
                bad_hash = "SHA512"
            check_wrong_hash = HASH_ML_DSA._verify_with_pre_hash(
                pk, msg, hash_sig, bad_hash, ctx=ctx
            )

            # Check that signature works
            self.assertTrue(check_verify)

            # Check that signature works with custom hash
            self.assertTrue(check_hash_verify)

            # Ensure the hashes need to match
            self.assertFalse(check_wrong_hash)

            # Check changing the key breaks verify
            self.assertFalse(check_wrong_pk)

            # Check changing the message breaks verify
            self.assertFalse(check_wrong_msg)

            # Check removing the context breaks verify
            self.assertFalse(check_no_ctx)

    # Default hash is SHA512
    def test_hash_ml_dsa_44(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_44_WITH_SHA512)

    def test_hash_ml_dsa_65(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_65_WITH_SHA512)

    def test_hash_ml_dsa_87(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_87_WITH_SHA512)

    # Test with SHA256
    def test_hash_ml_dsa_44_sha256(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_44_WITH_SHA512, "SHA256")

    def test_hash_ml_dsa_65_sha256(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_65_WITH_SHA512, "SHA256")

    def test_hash_ml_dsa_87_sha256(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_87_WITH_SHA512, "SHA256")

    # Test with SHAKE128
    def test_hash_ml_dsa_44_shake128(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_44_WITH_SHA512, "SHAKE128")

    def test_hash_ml_dsa_65_shake128(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_65_WITH_SHA512, "SHAKE128")

    def test_hash_ml_dsa_87_shake128(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_87_WITH_SHA512, "SHAKE128")


class TestHashMLDSADeterministic(unittest.TestCase):
    """
    Test ML DSA for internal consistency by generating signatures
    and verifying them!
    """

    def generic_test_hash_ml_dsa(self, HASH_ML_DSA, count=5):
        for _ in range(count):
            msg = b"Signed by HASH_ML_DSA" + os.urandom(16)
            ctx = os.urandom(128)

            # Perform signature process
            pk, sk = HASH_ML_DSA.keygen()
            sig = HASH_ML_DSA.sign(sk, msg, ctx=ctx, deterministic=True)
            check_verify = HASH_ML_DSA.verify(pk, msg, sig, ctx=ctx)

            # Generate some fail cases
            pk_bad, _ = HASH_ML_DSA.keygen()
            check_wrong_pk = HASH_ML_DSA.verify(pk_bad, msg, sig, ctx=ctx)
            check_wrong_msg = HASH_ML_DSA.verify(pk, b"", sig, ctx=ctx)
            check_no_ctx = HASH_ML_DSA.verify(pk, msg, sig)

            # Check that signature works
            self.assertTrue(check_verify)

            # Check changing the key breaks verify
            self.assertFalse(check_wrong_pk)

            # Check changing the message breaks verify
            self.assertFalse(check_wrong_msg)

            # Check removing the context breaks verify
            self.assertFalse(check_no_ctx)

    def test_hash_ml_dsa_44(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_44_WITH_SHA512)

    def test_hash_ml_dsa_65(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_65_WITH_SHA512)

    def test_hash_ml_dsa_87(self):
        self.generic_test_hash_ml_dsa(HASH_ML_DSA_87_WITH_SHA512)
