from .dilithium import Dilithium

DEFAULT_PARAMETERS = {
    "dilithium2": {
        "n": 256,
        "q": 8380417,
        "d": 13,
        "k": 4,
        "l": 4,
        "eta": 2,
        "eta_bound": 15,
        "tau": 39,
        "omega": 80,
        "gamma_1": 131072,  # 2^17
        "gamma_2": 95232,  # (q-1)/88
    },
    "dilithium3": {
        "n": 256,
        "q": 8380417,
        "d": 13,
        "k": 6,
        "l": 5,
        "eta": 4,
        "eta_bound": 9,
        "tau": 49,
        "omega": 55,
        "gamma_1": 524288,  # 2^19
        "gamma_2": 261888,  # (q-1)/88
    },
    "dilithium5": {
        "n": 256,
        "q": 8380417,
        "d": 13,
        "k": 8,
        "l": 7,
        "eta": 2,
        "eta_bound": 15,
        "tau": 60,
        "omega": 75,
        "gamma_1": 524288,  # 2^19
        "gamma_2": 261888,  # (q-1)/88
    },
}

Dilithium2 = Dilithium(DEFAULT_PARAMETERS["dilithium2"])
Dilithium3 = Dilithium(DEFAULT_PARAMETERS["dilithium3"])
Dilithium5 = Dilithium(DEFAULT_PARAMETERS["dilithium5"])
