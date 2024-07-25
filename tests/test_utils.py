import unittest
from dilithium_py.utilities.utils import reduce_mod_pm
from random import randint


class TestUtils(unittest.TestCase):
    def test_reduce_mod_pm_even(self):
        for _ in range(100):
            modulus = 2 * randint(0, 100)
            for i in range(modulus):
                x = reduce_mod_pm(i, modulus)
                self.assertTrue(x <= modulus // 2)
                self.assertTrue(x > -modulus // 2)

    def test_reduce_mod_pm_odd(self):
        for _ in range(100):
            modulus = 2 * randint(0, 100) + 1
            for i in range(modulus):
                x = reduce_mod_pm(i, modulus)
                self.assertTrue(x <= (modulus - 1) // 2)
                self.assertTrue(x >= -(modulus - 1) // 2)
