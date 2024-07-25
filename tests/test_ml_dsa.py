import unittest
import os
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
from dilithium_py.drbg.aes256_ctr_drbg import AES256_CTR_DRBG


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


def read_kat_data(file_name, deterministic):
    if deterministic:
        params = 9
    else:
        params = 10
    data_blocks = []
    with open(file_name) as f:
        for _ in range(100):
            data_blocks.append("".join([next(f) for _ in range(params)]))
    return data_blocks


def parse_kat_data(data_blocks):
    parsed_data = {}
    for block in data_blocks:
        block_data = block.split("\n")[:-1]
        count, xi, rng, seed, pk, sk, msg, mlen, sm, smlen = [
            line.split(" = ")[-1] for line in block_data
        ]
        parsed_data[int(count)] = {
            "xi": bytes.fromhex(xi),
            "rng": bytes.fromhex(rng),
            "seed": bytes.fromhex(seed),
            "pk": bytes.fromhex(pk),
            "sk": bytes.fromhex(sk),
            "msg": bytes.fromhex(msg),
            "mlen": int(mlen),
            "sm": bytes.fromhex(sm),
            "smlen": int(smlen),
        }
    return parsed_data


def parse_kat_data_det(data_blocks):
    parsed_data = {}
    for block in data_blocks:
        block_data = block.split("\n")[:-1]
        count, xi, seed, pk, sk, msg, mlen, sm, smlen = [
            line.split(" = ")[-1] for line in block_data
        ]
        parsed_data[int(count)] = {
            "xi": bytes.fromhex(xi),
            "seed": bytes.fromhex(seed),
            "pk": bytes.fromhex(pk),
            "sk": bytes.fromhex(sk),
            "msg": bytes.fromhex(msg),
            "mlen": int(mlen),
            "sm": bytes.fromhex(sm),
            "smlen": int(smlen),
        }
    return parsed_data


class TestKnownTestValuesMLDSA(unittest.TestCase):
    def generic_test_ml_dsa(self, ML_DSA, file_name, deterministic=False):

        # https://github.com/post-quantum-cryptography/KAT/tree/main/MLDSA
        entropy_input = bytes.fromhex(
            "60496cd0a12512800a79161189b055ac3996ad24e578d3c5fc57c1"
            "e60fa2eb4e550d08e51e9db7b67f1a616681d9182d"
        )
        drbg = AES256_CTR_DRBG(entropy_input)

        # extract data from KAT
        kat_data_blocks = read_kat_data(file_name, deterministic)
        if deterministic:
            parsed_data = parse_kat_data_det(kat_data_blocks)
        else:
            parsed_data = parse_kat_data(kat_data_blocks)

        for count in range(100):
            data = parsed_data[count]

            seed = drbg.random_bytes(48)
            self.assertEqual(data["seed"], seed)

            msg_len = data["mlen"]

            # TODO: how is this message generated, it's not from
            # drbg.random_bytes(msg_len) apparently...
            # msg = drbg.random_bytes(msg_len)
            # self.assertEqual(data["msg"], msg)

            # Test generation of internal randomness
            ML_DSA.set_drbg_seed(seed)
            xi = ML_DSA.random_bytes(32)
            self.assertEqual(data["xi"], xi)
            if not deterministic:
                rng = ML_DSA.random_bytes(32)
                self.assertEqual(data["rng"], rng)

            # Test ML DSA, must reset seed from above
            ML_DSA.set_drbg_seed(seed)
            pk, sk = ML_DSA.keygen()

            # Check that the keygen matches
            self.assertEqual(data["pk"], pk)
            self.assertEqual(data["sk"], sk)

            # Check that the signature matches
            sm_KAT = data["sm"]
            sig_KAT = sm_KAT[:-msg_len]

            # sm_KAT has message as the last mlen bytes
            self.assertEqual(data["msg"], sm_KAT[-msg_len:])

            # Ensure that a generated signature matches
            # the one extracted from the KAT
            sig = ML_DSA.sign(sk, data["msg"], deterministic=deterministic)
            self.assertEqual(sig, sig_KAT)

            # Finally, make sure that the signature is
            # valid for the message
            verify_KAT = ML_DSA.verify(pk, data["msg"], sig)
            self.assertTrue(verify_KAT)

    def test_ml_dsa_44(self):
        self.generic_test_ml_dsa(ML_DSA_44, "assets/kat_MLDSA_44_hedged.rsp")

    def test_ml_dsa_65(self):
        self.generic_test_ml_dsa(ML_DSA_65, "assets/kat_MLDSA_65_hedged.rsp")

    def test_ml_dsa_87(self):
        self.generic_test_ml_dsa(ML_DSA_87, "assets/kat_MLDSA_87_hedged.rsp")

    def test_ml_dsa_44_det(self):
        self.generic_test_ml_dsa(
            ML_DSA_44, "assets/kat_MLDSA_44_det.rsp", deterministic=True
        )

    def test_ml_dsa_65_det(self):
        self.generic_test_ml_dsa(
            ML_DSA_65, "assets/kat_MLDSA_65_det.rsp", deterministic=True
        )

    def test_ml_dsa_87_det(self):
        self.generic_test_ml_dsa(
            ML_DSA_87, "assets/kat_MLDSA_87_det.rsp", deterministic=True
        )


if __name__ == "__main__":
    unittest.main()
