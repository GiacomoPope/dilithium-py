from .ml_dsa import ML_DSA
from hashlib import sha256, sha512, shake_128


class HashML_DSA(ML_DSA):
    def _hash_with_oid(self, m: bytes, hash_name: str) -> tuple[bytes, bytes]:
        hash_name = hash_name.upper()

        if hash_name == "SHA256":
            oid = bytes(
                [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
            )
            ph_m = sha256(m).digest()
        elif hash_name == "SHA512":
            oid = bytes(
                [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]
            )
            ph_m = sha512(m).digest()
        elif hash_name == "SHAKE128":
            oid = bytes(
                [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B]
            )
            ph_m = shake_128(m).digest(32)
        else:
            raise ValueError(f"unsupported hash algorithm: {hash_name}")

        return oid, ph_m

    def _sign_with_pre_hash(
        self,
        sk: bytes,
        m: bytes,
        hash_name: str,
        ctx: bytes = b"",
        deterministic: bool = False,
    ) -> bytes:
        """
        Generates a HashML-DSA signature following Algorithm 4 (FIPS 204)

        The hash name is a string which selects the pre-hash function and
        can currently be SHA256, SHA512 or SHAKE128.
        """
        if len(ctx) > 255:
            raise ValueError(
                f"ctx bytes must have length at most 255, ctx has length {len(ctx) = }"
            )

        if deterministic:
            rnd = bytes([0] * 32)
        else:
            rnd = self.random_bytes(32)

        # Prehash the message and return the OID of the used hash
        oid, ph_m = self._hash_with_oid(m, hash_name)

        # Format the message using the context
        m_prime = bytes([1]) + bytes([len(ctx)]) + ctx + oid + ph_m

        # Compute the signature of m_prime
        sig_bytes = self._sign_internal(sk, m_prime, rnd)
        return sig_bytes

    def _verify_with_pre_hash(
        self, pk: bytes, m: bytes, sig: bytes, hash_name: str, ctx: bytes = b""
    ) -> bool:
        """
        Verifies a signature sigma for a message M following algorithm 5 (FIPS 204)
        """
        if len(ctx) > 255:
            raise ValueError(
                f"ctx bytes must have length at most 255, ctx has length {len(ctx) = }"
            )

        # Prehash the message and return the OID of the used hash
        oid, ph_m = self._hash_with_oid(m, hash_name)

        # Format the message using the context
        m_prime = bytes([1]) + bytes([len(ctx)]) + ctx + oid + ph_m

        return self._verify_internal(pk, m_prime, sig)

    def sign(
        self,
        sk: bytes,
        m: bytes,
        ctx: bytes = b"",
        deterministic: bool = False,
    ) -> bytes:
        """
        Generates a HashML-DSA signature following Algorithm 4 (FIPS 204)
        with SHA512 as the chosen hash function.
        """
        return self._sign_with_pre_hash(sk, m, "SHA512", ctx, deterministic)

    def verify(self, pk: bytes, m: bytes, sig: bytes, ctx: bytes = b"") -> bool:
        """
        Verifies a signature sigma for a message M following algorithm 5 (FIPS 204)
        with SHA512 as the chosen hash function.
        """
        return self._verify_with_pre_hash(pk, m, sig, "SHA512", ctx)
