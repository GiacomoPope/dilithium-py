import unittest
import os
from dilithium import Dilithium2, Dilithium3, Dilithium5
from aes256_ctr_drbg import AES256_CTR_DRBG

def parse_kat_data(data):
    """
    Helper function to parse data from KAT
    file to bytes in a dictionary
    """
    parsed_data = {}
    count_blocks = data.split('\n\n')
    for block in count_blocks[1:-1]:
        block_data = block.split('\n')
        count, seed, mlen, msg, pk, sk, smlen, sm = [line.split(" = ")[-1] for line in block_data]
        parsed_data[count] = {
            "seed": bytes.fromhex(seed),
            "msg": bytes.fromhex(msg),
            "mlen": int(mlen),
            "pk": bytes.fromhex(pk),
            "sk": bytes.fromhex(sk),
            "sm": bytes.fromhex(sm),
        }
    return parsed_data

class TestDilithium(unittest.TestCase):
    """
    Test Dilithium for internal
    consistency by generating signatures
    and verifying them!
    """
    
    def generic_test_dilithium(self, Dilithium):
        msg = b"Signed by dilithium" + os.urandom(16)
        
        # Perform signature process
        pk, sk = Dilithium.keygen()
        sig = Dilithium.sign(sk, msg)
        check_verify = Dilithium.verify(pk, msg, sig)
        
        # Generate some fail cases
        pk_bad, _ = Dilithium.keygen()
        check_wrong_pk  = Dilithium.verify(pk_bad, msg, sig)
        check_wrong_msg = Dilithium.verify(pk, b"", sig)
        
        # Check that signature works
        self.assertTrue(check_verify)
        # Check changing the key breaks verify
        self.assertFalse(check_wrong_pk)
        # Check changing the message breaks verify
        self.assertFalse(check_wrong_msg)
        
    def test_dilithium2(self):
        for _ in range(5):
            self.generic_test_dilithium(Dilithium2)
    
    def test_dilithium3(self):
        for _ in range(5):
            self.generic_test_dilithium(Dilithium3)
            
    def test_dilithium5(self):
        for _ in range(5):
            self.generic_test_dilithium(Dilithium5)
            
class TestDilithiumDRBG(unittest.TestCase):
    """
    Ensure that deterministic DRBG is deterministic!
    
    Uses AES256 CTR DRBG for randomness.
    Note: requires pycryptodome for AES impl.
    """
    
    def generic_test_dilithium(self, Dilithium):
        """
        First we generate five pk,sk pairs
        from the same seed and make sure 
        they're all the same
        """
        seed = os.urandom(48)
        pk_output = []
        for _ in range(5):
            Dilithium.set_drbg_seed(seed)
            pk, sk = Dilithium.keygen()
            pk_output.append(pk + sk)
        self.assertEqual(len(pk_output), 5)
        self.assertEqual(len(set(pk_output)), 1)
            
        """
        Now given a fixed keypair make sure
        that all the signatures are the same
        and that they all verify correctly!
        """
        sig_output = []
        seed = os.urandom(48)
        msg  = b"Signed by Dilithium" + os.urandom(32)
        pk, sk = Dilithium.keygen()
        for _ in range(5):
            Dilithium.set_drbg_seed(seed)
            sig = Dilithium.sign(sk, msg)
            verify = Dilithium.verify(pk, msg, sig)
            # Check signature worked
            self.assertTrue(verify)
            sig_output.append(sig)
            
        # Make sure all five signatures are the same
        self.assertEqual(len(sig_output), 5)
        self.assertEqual(len(set(sig_output)), 1)
        
    def test_dilithium2(self):
        for _ in range(5):
            self.generic_test_dilithium(Dilithium2)
    
    def test_dilithium3(self):
        for _ in range(5):
            self.generic_test_dilithium(Dilithium3)
            
    def test_dilithium5(self):
        for _ in range(5):
            self.generic_test_dilithium(Dilithium5)

class TestKnownTestValuesDRBG(unittest.TestCase):
    """
    We know how the seeds and messages for the KAT are 
    generated, so let's check against our own implementation.
    
    We only need to test one file, as the seeds are the 
    same across the three files.
    """
    def test_known_answer_DRBG(self):
        # Set DRBG to generate seeds
        entropy_input = bytes([i for i in range(48)])
        rng = AES256_CTR_DRBG(entropy_input)
        
        with open("assets/PQCsignKAT_Dilithium2.rsp") as f:
            # extract data from KAT
            kat_data = f.read()
            parsed_data = parse_kat_data(kat_data)
        # Check all seeds match
        for data in parsed_data.values():
            seed = data["seed"]
            seed_check = rng.random_bytes(48)
            msg_len = data["mlen"]
            msg = data["msg"]
            msg_check = rng.random_bytes(msg_len)
            self.assertEqual(seed, seed_check)
            self.assertEqual(msg,  msg_check)

class TestKnownTestValuesDilithium(unittest.TestCase):
    def generic_test_dilithium(self, Dilithium, file_name):
        with open(f"assets/{file_name}") as f:
            # extract data from KAT
            kat_data = f.read()
            parsed_data = parse_kat_data(kat_data)

        failure = 0
        for data in parsed_data.values():
            seed_KAT = data["seed"]
            pk_KAT = data["pk"]
            sk_KAT = data["sk"]
            
            Dilithium.set_drbg_seed(seed_KAT)
            pk, sk = Dilithium.keygen()
            # Check that the keygen matches
            self.assertEqual(pk_KAT, pk)
            self.assertEqual(sk_KAT, sk)
            
            # Check that the signature matches
            msg = data["msg"]
            msg_len = data["mlen"]
            sm_KAT  = data["sm"]
            sig_KAT = sm_KAT[:-msg_len]
            
            # sm_KAT has message as the last mlen bytes
            self.assertEqual(msg, sm_KAT[-msg_len:])
            
            # Ensure that a generated signature matches
            # the one extracted from the KAT
            sig = Dilithium.sign(sk, msg)
            self.assertEqual(sig, sig_KAT)

            # Finally, make sure that the signature is
            # valid for the message
            verify_KAT = Dilithium.verify(pk, msg, sig)
            self.assertTrue(verify_KAT)
            
            

    def test_dilithium2(self):
        self.generic_test_dilithium(Dilithium2, "PQCsignKAT_Dilithium2.rsp")
        
    # def test_dilithium3(self):
    #     self.generic_test_dilithium(Dilithium3, "PQCsignKAT_Dilithium3.rsp")
        
    # def test_dilithium5(self):
    #     self.generic_test_dilithium(Dilithium5, "PQCsignKAT_Dilithium5.rsp")
    
if __name__ == '__main__':
    unittest.main()
    
