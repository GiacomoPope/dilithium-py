from .ml_dsa import ML_DSA
from .hash_ml_dsa import HashML_DSA


DEFAULT_PARAMETERS = {
    "ML_DSA_44": {
        "d": 13,  # number of bits dropped from t
        "tau": 39,  # number of ±1 in c
        "gamma_1": 131072,  # coefficient range of y: 2^17
        "gamma_2": 95232,  # low order rounding range: (q-1)/88
        "k": 4,  # Dimensions of A = (k, l)
        "l": 4,  # Dimensions of A = (k, l)
        "eta": 2,  # Private key range
        "omega": 80,  # Max number of ones in hint
        "c_tilde_bytes": 32,
        "oid": (2, 16, 840, 1, 101, 3, 4, 3, 17),
    },
    "ML_DSA_65": {
        "d": 13,  # number of bits dropped from t
        "tau": 49,  # number of ±1 in c
        "gamma_1": 524288,  # coefficient range of y: 2^19
        "gamma_2": 261888,  # low order rounding range: (q-1)/32
        "k": 6,  # Dimensions of A = (k, l)
        "l": 5,  # Dimensions of A = (k, l)
        "eta": 4,  # Private key range
        "omega": 55,  # Max number of ones in hint
        "c_tilde_bytes": 48,
        "oid": (2, 16, 840, 1, 101, 3, 4, 3, 18),
    },
    "ML_DSA_87": {
        "d": 13,  # number of bits dropped from t
        "tau": 60,  # number of ±1 in c
        "gamma_1": 524288,  # coefficient range of y: 2^19
        "gamma_2": 261888,  # low order rounding range: (q-1)/32
        "k": 8,  # Dimensions of A = (k, l)
        "l": 7,  # Dimensions of A = (k, l)
        "eta": 2,  # Private key range
        "omega": 75,  # Max number of ones in hint
        "c_tilde_bytes": 64,
        "oid": (2, 16, 840, 1, 101, 3, 4, 3, 19),
    },
    "HASH_ML_DSA_44_WITH_SHA512": {
        "d": 13,  # number of bits dropped from t
        "tau": 39,  # number of ±1 in c
        "gamma_1": 131072,  # coefficient range of y: 2^17
        "gamma_2": 95232,  # low order rounding range: (q-1)/88
        "k": 4,  # Dimensions of A = (k, l)
        "l": 4,  # Dimensions of A = (k, l)
        "eta": 2,  # Private key range
        "omega": 80,  # Max number of ones in hint
        "c_tilde_bytes": 32,
        "oid": (2, 16, 840, 1, 101, 3, 4, 3, 32),
    },
    "HASH_ML_DSA_65_WITH_SHA512": {
        "d": 13,  # number of bits dropped from t
        "tau": 49,  # number of ±1 in c
        "gamma_1": 524288,  # coefficient range of y: 2^19
        "gamma_2": 261888,  # low order rounding range: (q-1)/32
        "k": 6,  # Dimensions of A = (k, l)
        "l": 5,  # Dimensions of A = (k, l)
        "eta": 4,  # Private key range
        "omega": 55,  # Max number of ones in hint
        "c_tilde_bytes": 48,
        "oid": (2, 16, 840, 1, 101, 3, 4, 3, 33),
    },
    "HASH_ML_DSA_87_WITH_SHA512": {
        "d": 13,  # number of bits dropped from t
        "tau": 60,  # number of ±1 in c
        "gamma_1": 524288,  # coefficient range of y: 2^19
        "gamma_2": 261888,  # low order rounding range: (q-1)/32
        "k": 8,  # Dimensions of A = (k, l)
        "l": 7,  # Dimensions of A = (k, l)
        "eta": 2,  # Private key range
        "omega": 75,  # Max number of ones in hint
        "c_tilde_bytes": 64,
        "oid": (2, 16, 840, 1, 101, 3, 4, 3, 34),
    },
}

ML_DSA_44 = ML_DSA(DEFAULT_PARAMETERS["ML_DSA_44"])
ML_DSA_65 = ML_DSA(DEFAULT_PARAMETERS["ML_DSA_65"])
ML_DSA_87 = ML_DSA(DEFAULT_PARAMETERS["ML_DSA_87"])

HASH_ML_DSA_44_WITH_SHA512 = HashML_DSA(DEFAULT_PARAMETERS["ML_DSA_44"])
HASH_ML_DSA_65_WITH_SHA512 = HashML_DSA(DEFAULT_PARAMETERS["ML_DSA_65"])
HASH_ML_DSA_87_WITH_SHA512 = HashML_DSA(DEFAULT_PARAMETERS["ML_DSA_87"])
