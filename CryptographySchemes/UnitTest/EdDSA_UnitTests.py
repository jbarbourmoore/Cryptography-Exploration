import unittest
from CryptographySchemes.EdwardsCurveDigitalSignatureAlgorithm import *

class ECDSA_UnitTests(unittest.TestCase):
    '''
    This class contains basic unit tests for ecdsa
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        self.q = "B3EBFE9AD81341A6C0EEEA0B3F49115684D97F165535B2027CB5AFCE53FF944A"
        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=True,print_excess_error=False)
      
        self.message = "F495660A1FC6A591B0E2FB90574E3A28E485152ECF6C5745C137E2C53E619832D58A5F101B3EEAF88887DF1552AB16613E87AA4F38C91453A5824809BE2E198FF84E3C6EAF79AF8FD44EF7E4C0FDC70941A0F457F1908011F80E89CBCEBE47806C9F131AB5580132DE9BE0B9DB0D622F4D16C805AE852F0B68F1C6B1AB8E2BB4"
        self.message_bit_string = self.eddsa.hexStringToBitString(self.message)
        
        # expected values for signature generation
        self.signature = "F9593859640FD47FA3A67F6CF00184B9696A2928F0013A72411325D7356AF72460C26DDEB3B6A6C1BC89224179F72F75C8E3BE6D2F9EF6002F29BCE680C0B203"
    def test_bit_array_to_bit_string(self):
        '''
        This method tests the conversion of a bit array into a bit string
        '''
        expected_result = "01101111"
        bit_array = [0,1,1,0,1,1,1,1]
        result = self.eddsa.bitArrayToBitString(bit_array)
        print(f"bit array: {bit_array} ?= bit string: {result}")
        self.assertEqual(expected_result,result,f"bit array: {bit_array} != bit string: {result}")

    def test_bit_string_to_bit_array(self):
        '''
        This method tests the conversion of a bit array into a bit string
        '''
        bit_string = "01101111"
        expected_result = [0,1,1,0,1,1,1,1]
        result = self.eddsa.bitStringToBitArray(bit_string)
        print(f"bit string: {bit_string} ?= bit array: {result}")
        self.assertEqual(expected_result,result,f"bit string: {bit_string} != bit array: {result}")

    def test_bit_string_to_int(self):
        '''
        This method tests the conversion from bit string to int
        '''
        expected_results=[1,8,136,65]
        test_bit_strings = ["10000000","00010000","00010001","10000010"]
        for i in range(0, len(test_bit_strings)):
            actual_int = self.eddsa.bitStringToInt(test_bit_strings[i])
            self.assertEqual(actual_int,expected_results[i],f"{test_bit_strings[i]}->{actual_int} not expected:{expected_results[i]}")
    
    def test_int_to_bit_string(self):
        '''
        This method tests the conversion from int to bit string
        '''
        test_ints=[1,8,136,65]
        expected_results = ["10000000","00010000","00010001","10000010"]
        for i in range(0, len(test_ints)):
            actual_bit_str = self.eddsa.intToBitString(test_ints[i])
            self.assertEqual(actual_bit_str,expected_results[i],f"{test_ints[i]}->{actual_bit_str} not expected:{expected_results[i]}")
    

    # def test_signature_generation(self):

    #     signature = self.eddsa.createSignature(message_bit_string=self.message_bit_string)

    #     self.assertEqual(len(signature),128)

    # def test_signature_verification(self):
    #     signature = self.eddsa.createSignature(message_bit_string=self.message_bit_string)
    #     is_signature_valid = self.eddsa.verifySignature(self.message_bit_string,signature,self.eddsa.public_key)
    #     print(is_signature_valid)
    #     self.assertEqual(len(signature),128)

if __name__ == '__main__':
    print("Curve: Ed22519")

    unittest.main()