import unittest
from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm1 import *
from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm2 import *
from HelperFunctions.IntegerHandler import *

class SHA3_UnitTest(unittest.TestCase):
    '''
    This class contains example unit tests for SHA3
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")


    def test_sha1(self):
        '''
        This function tests the sha1 hash creation

        Test values taken from the SHA1 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
        input_string = "abc"
        result = sha1.hashAString(input_string)
        expected_value = "A9993E364706816ABA3E25717850C26C9CD0D89D"
        handler_expected = IntegerHandler.fromHexString(expected_value,False,32*5)
        print(f"Testing SHA1 With 3 Character Input \"{input_string}\"")
        print(f"Expected Hash : {handler_expected.getHexString()}")
        print(f"Actual Hash   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha224(self):
        '''
        This function tests the sha-224 hash creation

        Test values taken from the SHA2 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
        input_string = "abc"
        result = sha224.hashAString(input_string)
        expected_value = "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7"
        handler_expected = IntegerHandler.fromHexString(expected_value,False,224)
        print(f"Testing SHA-224 With 3 Character Input \"{input_string}\"")
        print(f"Expected Hash : {handler_expected.getHexString()}")
        print(f"Actual Hash   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha256(self):
        '''
        This function tests the sha-256 hash creation

        Test values taken from the SHA2 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        input_string = "abc"
        result = sha256.hashAString(input_string)
        expected_value = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        handler_expected = IntegerHandler.fromHexString(expected_value,False,256)
        print(f"Testing SHA-256 With 3 Character Input \"{input_string}\"")
        print(f"Expected Hash : {handler_expected.getHexString()}")
        print(f"Actual Hash   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha384(self):
        '''
        This function tests the sha-384 hash creation

        Test values taken from the SHA2 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''

        input_string = "abc"
        result = sha384.hashAString(input_string)
        expected_value = "CB00753F 45A35E8B B5A03D69 9AC65007 272C32AB 0EDED163 1A8B605A 43FF5BED 8086072B A1E7CC23 58BAECA1 34C825A7 ".replace(" ","")
        handler_expected = IntegerHandler.fromHexString(expected_value,False,384)
        print(f"Testing SHA-384 With 3 Character Input \"{input_string}\"")
        print(f"Expected Hash : {handler_expected.getHexString()}")
        print(f"Actual Hash   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha512(self):
        '''
        This function tests the sha-512 hash creation

        Test values taken from the SHA2 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        input_string = "abc"
        result = sha512.hashAString(input_string)
        expected_value = "DDAF35A1 93617ABA CC417349 AE204131 12E6FA4E 89A97EA2 0A9EEEE6 4B55D39A 2192992A 274FC1A8 36BA3C23 A3FEEBBD 454D4423 643CE80E 2A9AC94F A54CA49F".replace(" ","")
        handler_expected = IntegerHandler.fromHexString(expected_value,False,512)
        print(f"Testing SHA-512 With 3 Character Input \"{input_string}\"")
        print(f"Expected Hash : {handler_expected.getHexString()}")
        print(f"Actual Hash   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())
    
    def test_sha_512_224(self):
        '''
        This function tests the sha-512-224 hash creation

        Test values taken from the SHA2 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        input_string = "abc"
        result = sha512_224.hashAString(input_string)
        expected_value = "4634270F 707B6A54 DAAE7530 460842E2 0E37ED26 5CEEE9A4 3E8924AA".replace(" ","")
        handler_expected = IntegerHandler.fromHexString(expected_value,False,224)
        print(f"Testing SHA-512/224 With 3 Character Input \"{input_string}\"")
        print(f"Expected Hash : {handler_expected.getHexString()}")
        print(f"Actual Hash   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha_512_256(self):
        '''
        This function tests the sha-512-256 hash creation

        Test values taken from the SHA2 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        input_string = "abc"
        result = sha512_256.hashAString(input_string)
        expected_value = "53048E26 81941EF9 9B2E29B7 6B4C7DAB E4C2D0C6 34FC6D46 E0E2F131 07E7AF23".replace(" ","")
        handler_expected = IntegerHandler.fromHexString(expected_value,False,256)
        print(f"Testing SHA-512/256 With 3 Character Input \"{input_string}\"")
        print(f"Expected Hash : {handler_expected.getHexString()}")
        print(f"Actual Hash   : {result.getHexString()}")

if __name__ == '__main__':
    print("- - - - - - - - - - - -")
    print("Testing SHA1 and SHA2 Implementations Against Known Values")
    print("Expected Hashes are Sourced from NIST Cryptographic Standards and Guidelines: Examples With Intermediate Values")
    print("https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values")
    unittest.main()
