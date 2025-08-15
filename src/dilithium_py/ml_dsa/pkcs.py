"""
Import and export of keys to PKCS #8 and SPKI format.

This module allows for importing private keys (signing keys) from
PKCS #8 files, exporting them to PKCS #8 files, and both import and export
of the public keys (verification keys) from the Subject Public Key Info
format used in X.509 certificates and in bare public keys.
"""

try:
    from ecdsa import der
except ImportError:
    raise ImportError("PKCS functionality requires the ecdsa library")


from .default_parameters import ML_DSA_44, ML_DSA_65, ML_DSA_87


OIDS = {
    ML_DSA_44.oid: ML_DSA_44,
    ML_DSA_65.oid: ML_DSA_65,
    ML_DSA_87.oid: ML_DSA_87,
}


def pk_to_der(ml_dsa, pk):
    """
    Convert a verification key to a SPKI DER structure.

    :param ml_dsa: an ``ML_DSA`` object instance
    :param bytes pk: verification key matching the passed ML_DSA object
    :rtype: bytes
    """
    if not ml_dsa.oid:
        raise ValueError("Only ML_DSAs with specified OIDs can be encoded")

    if len(pk) != ml_dsa._pk_size():
        raise ValueError("Provided key size doesn't match the provided ML_DSA")

    enc = der.encode_sequence(
        der.encode_sequence(
            der.encode_oid(*ml_dsa.oid),
        ),
        der.encode_bitstring(pk, 0),
    )

    return enc


def pk_to_pem(ml_dsa, pk):
    """
    Convert a verification key to a SPKI PEM structure.

    :param ml_dsa: an ``ML_DSA`` object instance
    :param bytes pk: verification key matching the passed ML_DSA object
    :rtype: str
    """
    der_enc = pk_to_der(ml_dsa, pk)

    pem_enc = der.topem(der_enc, "PUBLIC KEY")

    return pem_enc


def pk_from_der(enc_key):
    """
    Extract a verification key from a SPKI DER encoding.

    :param bytes enc_key: SPKI DER encoding of a key
    :rtype: tuple(ML_DSA, bytes)
    """
    s1, empty = der.remove_sequence(enc_key)
    if empty:
        raise der.UnexpectedDER("Trailing junk after DER public key")

    alg_id, rem = der.remove_sequence(s1)

    alg_id, rest = der.remove_object(alg_id)
    if alg_id not in OIDS:
        raise der.UnexpectedDER(f"Not recognised algoritm OID: {alg_id}")
    if rest:
        raise der.UnexpectedDER("Parameters specified for an ML-DSA OID")

    ml_dsa = OIDS[alg_id]

    key, empty = der.remove_bitstring(rem, 0)
    if empty:
        raise der.UnexpectedDER("Trailing junk after public key bitstring")
    if len(key) != ml_dsa._pk_size():
        raise der.UnexpectedDER("Wrong key size for the OID in structure")

    return ml_dsa, key


def pk_from_pem(enc_key):
    """
    Extract a verification key from PEM encoding.

    :param str enc_key: SPKI PEM encoding of a key
    :rtype: tuple(ML_DSA, bytes)
    """
    der_key = der.unpem(enc_key)
    return pk_from_der(der_key)


def sk_to_der(ml_dsa, sk=None, seed=None, form=None):
    """
    Convert a signing key to a PKCS #8 DER structure.

    ``sk``, ``seed``, or both need to be specified.
    if ``form`` is not specified (is set to ``None``). The format that
    preserves maximum amount of information will be used.

    Proposed in draft-ietf-lamps-dilithium-certificates-12

    :param ml_dsa: an ``ML_DSA`` object instance
    :param bytes sk: signing key
    :param bytes seed: seed to generate the ML_DSA keys
    :param str form: What format to write the key in, options are:
        None - for automatic selection based on ``sk`` and ``seed``,
        ``seed`` for writing seed only, ``expanded`` for writing the expanded
        key only, and ``both`` for writing both seed and expanded key.
    :rtype: bytes
    """
    if not ml_dsa.oid:
        raise ValueError("Only ML_DSAs with specified OIDs can be encoded")

    if form not in ("seed", "expanded", "both", None):
        raise ValueError(
            f"Invalid form specified: {form}. "
            "Only 'seed', 'expanded', 'both', or None are allowed"
        )

    if not sk and not seed:
        raise ValueError("sk or seed must be specified")

    if sk and len(sk) != ml_dsa._sk_size():
        raise ValueError("Invalid signing key size for the provided ML_DSA")

    if seed and len(seed) != 32:
        raise ValueError("Invalid seed size")

    if form in ("both", "seed") and not seed:
        raise ValueError(f'Format "{form}" requires specifying seed')

    if form is None:
        if sk and seed:
            form = "both"
        elif sk:
            form = "expanded"
        else:
            assert seed
            form = "seed"

    if form in ("both", "expanded") and not sk:
        _, sk = ml_dsa.key_derive(seed)

    if form == "seed":
        enc_key = der.encode_implicit(0, seed)
    elif form == "expanded":
        enc_key = der.encode_octet_string(sk)
    else:
        assert form == "both"
        enc_key = der.encode_sequence(
            der.encode_octet_string(seed), der.encode_octet_string(sk)
        )

    encoded_pkcs8 = der.encode_sequence(
        der.encode_integer(0),
        der.encode_sequence(der.encode_oid(*ml_dsa.oid)),
        der.encode_octet_string(enc_key),
    )

    return encoded_pkcs8


def sk_to_pem(ml_dsa, sk=None, seed=None, form=None):
    """
    Convert a signing key to a PKCS #8 PEM structure.

    ``sk``, ``seed``, or both need to be specified.
    if ``form`` is not specified (is set to ``None``). The format that
    preserves maximum amount of information will be used.

    Proposed in draft-ietf-lamps-dilithium-certificates-12

    :param ml_dsa: an ``ML_DSA`` object instance
    :param bytes sk: signing key
    :param bytes seed: seed to generate the ML_DSA keys
    :param str form: What format to write the key in, options are:
        None - for automatic selection based on ``sk`` and ``seed``,
        ``seed`` for writing seed only, ``expanded`` for writing the expanded
        key only, and ``both`` for writing both seed and expanded key.
    :rtype: bytes
    """
    der_enc = sk_to_der(ml_dsa, sk, seed, form)

    pem_enc = der.topem(der_enc, "PRIVATE KEY")

    return pem_enc


def sk_from_der(enc_key):
    """
    Extract signing and verification key from from PKCS #8 DER encoding.

    :param bytes enc_key: PKCS #8 DER encoding of the key.
    :return: the first element is the ``ML_DSA`` object instance, the second
        is the signing key, third is the seed (if present), fourth is the
        verification key (if seed is present).
    :rtype: tuple(ML_DSA, bytes, bytes, bytes)
    """
    s1, empty = der.remove_sequence(enc_key)
    if empty:
        raise der.UnexpectedDER("Trailing junk after private key structure")

    ver, rest = der.remove_integer(s1)
    if ver != 0:
        raise der.UnexpectedDER(f"Unsupported version: {ver}")

    alg_id, rest = der.remove_sequence(rest)

    alg_id, empty = der.remove_object(alg_id)
    if empty:
        raise der.UnexpectedDER("Junk after algorithm OID")
    if alg_id not in OIDS:
        raise der.UnexpectedDER(f"Not recognised algorithm OID: {alg_id}")

    ml_dsa = OIDS[alg_id]

    priv_key, _ = der.remove_octet_string(rest)
    # rest can be either parameters or public key: we ignore those

    seed = None
    expanded = None
    pk = None

    if der.str_idx_as_int(priv_key, 0) == 0x04:
        # we have OCTET STRING, expanded only format
        expanded, empty = der.remove_octet_string(priv_key)
        if empty:
            raise der.UnexpectedDER("Trailing junk after expandedKey")
    elif der.is_sequence(priv_key):
        both, empty = der.remove_sequence(priv_key)
        if empty:
            raise der.UnexpectedDER("Trailing junk after both encoding")
        seed, key_val = der.remove_octet_string(both)
        expanded, empty = der.remove_octet_string(key_val)
        if empty:
            raise der.UnexpectedDER(
                "Trailing junk after 'expandedKey' in 'both' encoding"
            )
    else:
        tag, seed, empty = der.remove_implicit(priv_key)
        if tag != 0:
            raise der.UnexpectedDER(f"Unexpected tag in private key encoding: {tag}")
        if empty:
            raise der.UnexpectedDER("Junk after seed encoding")

    if expanded and len(expanded) != ml_dsa._sk_size():
        raise der.UnexpectedDER("Invalid expanded key size in encoding")

    if seed and len(seed) != 32:
        raise der.UnexpectedDER("Invalid length of seed in encoding")

    if not expanded:
        pk, expanded = ml_dsa.key_derive(seed)

    if not pk:
        # If we reach here, we need to compute the public key
        # directly from the secret key bytes
        pk = ml_dsa.pk_from_sk(expanded)

    return ml_dsa, expanded, seed, pk


def sk_from_pem(enc_key):
    """
    Extract signing and verification key from from PKCS #8 PEM encoding.

    :param bytes enc_key: PKCS #8 PEM encoding of the key.
    :return: the first element is the ``ML_DSA`` object instance, the second
        is the signing key, third is the seed (if present), fourth is the
        verification key (if seed is present).
    :rtype: tuple(ML_DSA, bytes, bytes, bytes)
    """
    der_key = der.unpem(enc_key)
    return sk_from_der(der_key)
