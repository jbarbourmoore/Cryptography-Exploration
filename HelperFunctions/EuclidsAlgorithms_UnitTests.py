import unittest
import EuclidsAlgorithms

class EuclidsAlgorithms_UnitTests(unittest.TestCase):
    '''
    This class contains basic unit tests for the helper functions
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_basic_euclids_algorithm(self):
        '''
        This method tests that the basic euclid's algorithm properly calculates the greatest common denominator
        '''

        largest_number = 125
        smaller_number = 25
        greatest_common_denominator = EuclidsAlgorithms.euclidsAlgorithm(largest_number, smaller_number, debug=True)
        self.assertEqual(greatest_common_denominator, smaller_number)

    def test_basic_euclids_algorithm_not_smaller_number(self):
        '''
        This method tests that the basic euclid's algorithm properly calculates the greatest common denominator
        '''

        largest_number = 40
        smaller_number = 64
        greatest_common_denominator = EuclidsAlgorithms.euclidsAlgorithm(largest_number, smaller_number, debug=True)
        self.assertEqual(greatest_common_denominator, 8)

    def test_basic_euclids_algorithm_primes(self):
        '''
        This method tests that the basic euclid's algorithm properly calculates the greatest common denominator
        '''

        largest_number = 17
        smaller_number = 97
        greatest_common_denominator = EuclidsAlgorithms.euclidsAlgorithm(largest_number, smaller_number, debug=True)
        self.assertEqual(greatest_common_denominator, 1)

    def test_extended_euclids_algorithm(self):
        '''
        This method tests that the extended euclid's algorithm properly calculates the greatest common denominator, s and t
        '''

        largest_number = 125
        smaller_number = 25
        greatest_common_denominator, s, t = EuclidsAlgorithms.extendedEuclidAlgorithm(larger_number=largest_number, smaller_number=smaller_number, debug=True)
        self.assertEqual(greatest_common_denominator, s*largest_number+t*smaller_number)
        self.assertEqual(greatest_common_denominator, smaller_number)

    def test_extended_euclids_algorithm_not_smaller_number(self):
        '''
        This method tests that the extended euclid's algorithm properly calculates the greatest common denominator
        '''

        largest_number = 40
        smaller_number = 64
        greatest_common_denominator, s, t = EuclidsAlgorithms.extendedEuclidAlgorithm(largest_number, smaller_number, debug=True)
        self.assertEqual(greatest_common_denominator, s*largest_number+t*smaller_number)
        self.assertEqual(greatest_common_denominator, 8)

    def test_extended_euclids_algorithm_primes(self):
        '''
        This method tests that the extended euclid's algorithm properly calculates the greatest common denominator
        '''

        largest_number = 17
        smaller_number = 97
        greatest_common_denominator, s, t = EuclidsAlgorithms.extendedEuclidAlgorithm(largest_number, smaller_number, debug=True)
        self.assertEqual(greatest_common_denominator, s*largest_number+t*smaller_number)
        self.assertEqual(greatest_common_denominator, 1)

if __name__ == '__main__':
    unittest.main()