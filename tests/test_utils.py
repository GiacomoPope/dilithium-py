import unittest
from dilithium_py.utilities.utils import reduce_mod_pm
from random import randint


class TestUtils(unittest.TestCase):
    def test_reduce_mod_pm_even(self):
        """
        For odd modulus the reduced value should be bounded by
        -(n-1)/2 <= x <= (n-1)/2
        """
        for _ in range(100):
            modulus = 2 * randint(0, 100)
            for i in range(modulus):
                x = reduce_mod_pm(i, modulus)
                self.assertTrue(x <= modulus // 2)
                self.assertTrue(-modulus // 2 < x)

    def test_reduce_mod_pm_odd(self):
        """
        For even modulus the reduced value should be bounded by
        -n/2 < x <= n/2
        """
        for _ in range(100):
            modulus = 2 * randint(0, 100) + 1
            for i in range(modulus):
                x = reduce_mod_pm(i, modulus)
                self.assertTrue(x <= (modulus - 1) // 2)
                self.assertTrue(-(modulus - 1) // 2 <= x)
