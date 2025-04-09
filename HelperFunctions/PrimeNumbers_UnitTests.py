import unittest
from PrimeNumbers import *

class PrimeNumber_UnitTests(unittest.TestCase):
    '''
    This class contains basic unit tests for the helper functions for prime numbers
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        
    def test_getPrimeNumbers_SieveOfEratosthenes_under10(self):
        '''
        This method tests finding the primes in a given range
        '''

        expect_primes = [2,3,5,7]
        primes = getPrimeNumbers_SieveOfEratosthenes(minimum_number=2,maximum_number=10)
        print(f"The primes calculated under 10 are {primes}")
        self.assertListEqual(primes,expect_primes)

    def test_getPrimeNumbers_SieveOfEratosthenes_40to50(self):
        '''
        This method tests finding the primes in a given range
        '''

        expect_primes = [41,43,47]
        primes = getPrimeNumbers_SieveOfEratosthenes(minimum_number=40,maximum_number=50)
        print(f"The primes calculated between 40 and 50 are {primes}")
        self.assertListEqual(primes,expect_primes)

    def test_getPrimeNumbers_SieveOfEratosthenes_190000to200000(self):
        '''
        This method tests finding the primes in a given range
        '''

        expect_primes = [199909, 199921, 199931, 199933, 199961, 199967, 199999]
        primes = getPrimeNumbers_SieveOfEratosthenes(minimum_number=199900,maximum_number=200000)
        print(f"The primes calculated between 199900 and 200000 are {primes}")
        self.assertListEqual(primes,expect_primes)

    def test_getPrimeNumbers_SieveOfEratosthenes_2to1000000(self):
        '''
        This method tests finding the primes in a given range
        '''

        expected_number_of_primes = 78498
        primes = getPrimeNumbers_SieveOfEratosthenes(minimum_number=2,maximum_number=1000000)
        print(f"The number of primes calculated between 2 and 1000000 is {len(primes)}")
        self.assertEqual(len(primes),expected_number_of_primes)

    def test_findPrimitiveRoots_7(self):
        '''
        This method tests finding the primitive roots of a prime number
        '''

        prime = 7
        expected_roots = [3, 5]
        roots = findPrimativeRoots(prime)
        print(f"The primitive roots of {prime} and {roots}")

        self.assertListEqual(roots,expected_roots)

    def test_findPrimitiveRoots_29(self):
        '''
        This method tests finding the primitive roots of a prime number
        '''

        prime = 29
        expected_roots = [2, 3, 8, 10, 11, 14, 15, 18, 19, 21, 26, 27]
        roots = findPrimativeRoots(prime)
        print(f"The primitive roots of {prime} and {roots}")

        self.assertListEqual(roots,expected_roots)

    def test_findPrimitiveRoots_199921(self):
        '''
        This method tests finding the primitive roots of a prime number
        '''

        prime = 509
        expected_number_of_roots = 252
        roots = findPrimativeRoots(prime)
        print(f"The number of primitive roots of {prime} is {len(roots)}")

        self.assertEqual(len(roots),expected_number_of_roots)

    def test_calculatePowerWithModulo(self):
        '''
        This method tests calculating power with modulo
        '''
        
        number = 2
        power = 2
        modulo = 8

        expected_result = 4
        result = calculatePowerWithModulo(number,power,modulo)
        
        print(f"The result of {number}**{power} % {modulo} is {result}")

        self.assertEqual(result, expected_result)

    def test_calculatePowerWithModulo_9to13mod15(self):
        '''
        This method tests calculating power with modulo
        '''

        number = 9
        power = 13
        modulo = 15

        expected_result = 9
        result = calculatePowerWithModulo(number,power,modulo)
        
        print(f"The result of {number}**{power} % {modulo} is {result}")

        self.assertEqual(result, expected_result)

    def test_findingModuloInvers(self):
        '''
        This method tests finding the modulo inverse of a number
        '''

        number = 9
        modulo = 17

        expected_result = 2
        result = calculateModuloInverse(number=number,modulo=modulo)

        print(f"The modulo {modulo} inverse of {number} is {result}")

        self.assertEqual(result,expected_result)

    def test_findingModuloInvers_87mod92(self):
        '''
        This method tests finding the modulo inverse of a number
        '''

        number = 87
        modulo = 92

        expected_result = 25
        result = calculateModuloInverse(number=number,modulo=modulo)

        print(f"The modulo {modulo} inverse of {number} is {result}")

        self.assertEqual(result,expected_result)

if __name__ == '__main__':
    unittest.main()