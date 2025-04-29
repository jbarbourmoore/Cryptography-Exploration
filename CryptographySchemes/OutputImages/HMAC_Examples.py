import unittest
from CryptographySchemes.MessageAuthenticationCodes.KeyedHashMessageAuthenticationCode import *

class HMAC_UnitTests(unittest.TestCase):
    '''
    This class contains example unit tests for HMAC
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_sha224(self):
        '''
        This function tests the hmac generation based an sha224 with a key length equal to the block length

        Test values taken from the hmac example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''

        hmac = HMAC_SHA224()
        message = "Sample message for keylen=blocklen"
        key = "00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F 20212223 24252627 28292A2B 2C2D2E2F 30313233 34353637 38393A3B 3C3D3E3F "

        result = hmac.HMAC(message=message, key=key, is_debug=False)

        expected_result = "C7405E3A E058E8CD 30B08B41 40248581 ED174CB3 4E1224BC C1EFC81B"
        expected_handler = IntegerHandler.fromHexString(expected_result)

        print(f"Testing HMAC Based On SHA-224 With Message: \"{message}\"")
        print(f"Expected HMAC : {expected_handler.getHexString(add_spacing=8)}")
        print(f"Actual HMAC   : {result.getHexString(add_spacing=8)}")
        
        self.assertEqual(result.getHexString(),expected_handler.getHexString())

    def test_sha256(self):
        '''
        This function tests the hmac generation based an sha256 with a key length equal to the block length

        Test values taken from the hmac example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''

        hmac = HMAC_SHA256()
        message = "Sample message for keylen=blocklen"
        key = "00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F 20212223 24252627 28292A2B 2C2D2E2F 30313233 34353637 38393A3B 3C3D3E3F "

        result = hmac.HMAC(message=message, key=key, is_debug=False)

        expected_result = "8BB9A1DB 9806F20D F7F77B82 138C7914 D174D59E 13DC4D01 69C9057B 133E1D62 "
        expected_handler = IntegerHandler.fromHexString(expected_result)

        print(f"Testing HMAC Based On SHA-256 With Message: \"{message}\"")
        print(f"Expected HMAC : {expected_handler.getHexString(add_spacing=8)}")
        print(f"Actual HMAC   : {result.getHexString(add_spacing=8)}")
        
        self.assertEqual(result.getHexString(),expected_handler.getHexString())

    def test_sha384(self):
        '''
        This function tests the hmac generation based an sha384 with a key length equal to the block length

        Test values taken from the hmac example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''

        hmac = HMAC_SHA384()
        message = "Sample message for keylen=blocklen"
        key = "00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F 20212223 24252627 28292A2B 2C2D2E2F 30313233 34353637 38393A3B 3C3D3E3F 40414243 44454647 48494A4B 4C4D4E4F 50515253 54555657 58595A5B 5C5D5E5F 60616263 64656667 68696A6B 6C6D6E6F 70717273 74757677 78797A7B 7C7D7E7F"

        result = hmac.HMAC(message=message, key=key, is_debug=False)

        expected_result = "63C5DAA5 E651847C A897C958 14AB830B EDEDC7D2 5E83EEF9 195CD458 57A37F44 8947858F 5AF50CC2 B1B730DD F29671A9 "
        expected_handler = IntegerHandler.fromHexString(expected_result)

        print(f"Testing HMAC Based On SHA-384 With Message: \"{message}\"")
        print(f"Expected HMAC : {expected_handler.getHexString(add_spacing=8)}")
        print(f"Actual HMAC   : {result.getHexString(add_spacing=8)}")
        
        self.assertEqual(result.getHexString(),expected_handler.getHexString())

    def test_sha512(self):
        '''
        This function tests the hmac generation based an sha512 with a key length equal to the block length

        Test values taken from the hmac example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''

        hmac = HMAC_SHA512()
        message = "Sample message for keylen=blocklen"
        key = "00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F 20212223 24252627 28292A2B 2C2D2E2F 30313233 34353637 38393A3B 3C3D3E3F 40414243 44454647 48494A4B 4C4D4E4F 50515253 54555657 58595A5B 5C5D5E5F 60616263 64656667 68696A6B 6C6D6E6F 70717273 74757677 78797A7B 7C7D7E7F"

        result = hmac.HMAC(message=message, key=key, is_debug=False)

        expected_result = "FC25E240 658CA785 B7A811A8 D3F7B4CA 48CFA26A 8A366BF2 CD1F836B 05FCB024 BD368530 81811D6C EA4216EB AD79DA1C FCB95EA4 586B8A0C E356596A 55FB1347"
        expected_handler = IntegerHandler.fromHexString(expected_result)

        print(f"Testing HMAC Based On SHA-512 With Message: \"{message}\"")
        print(f"Expected HMAC : {expected_handler.getHexString(add_spacing=8)}")
        print(f"Actual HMAC   : {result.getHexString(add_spacing=8)}")
        
        self.assertEqual(result.getHexString(),expected_handler.getHexString())

    def test_sha3_224(self):
        '''
        This function tests the hmac generation based an sha3_224 with a key length equal to the block length

        Test values taken from the hmac example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''

        hmac = HMAC_SHA3_224()
        message = "Sample message for keylen=blocklen"
        key = "00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f20212223 24252627 28292a2b 2c2d2e2f30313233 34353637 38393a3b 3c3d3e3f40414243 44454647 48494a4b 4c4d4e4f50515253 54555657 58595a5b 5c5d5e5f60616263 64656667 68696a6b 6c6d6e6f70717273 74757677 78797a7b 7c7d7e7f80818283 84858687 88898a8b 8c8d8e8f"
        result = hmac.HMAC(message=message, key=key, is_debug=False)

        expected_result = "d8b733bc f66c644a 12323d56 4e24dcf3fc75f231 f3b67968 359100c7 "
        expected_handler = IntegerHandler.fromHexString(expected_result)

        print(f"Testing HMAC Based On SHA3-224 With Message: \"{message}\"")
        print(f"Expected HMAC : {expected_handler.getHexString(add_spacing=8)}")
        print(f"Actual HMAC   : {result.getHexString(add_spacing=8)}")
        
        self.assertEqual(result.getHexString(),expected_handler.getHexString())

    def test_sha3_256(self):
        '''
        This function tests the hmac generation based an sha3_256 with a key length equal to the block length

        Test values taken from the hmac example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''

        hmac = HMAC_SHA3_256()
        message = "Sample message for keylen=blocklen"
        key = "00010203 04050607 08090a0b 0c0d0e0f10111213 14151617 18191a1b 1c1d1e1f20212223 24252627 28292a2b 2c2d2e2f30313233 34353637 38393a3b 3c3d3e3f40414243 44454647 48494a4b 4c4d4e4f50515253 54555657 58595a5b 5c5d5e5f60616263 64656667 68696a6b 6c6d6e6f70717273 74757677 78797a7b 7c7d7e7f80818283 84858687"
        result = hmac.HMAC(message=message, key=key, is_debug=False)

        expected_result = "68b94e2e 538a9be4 103bebb5 aa016d47 961d4d1a a9060613 13b557f8 af2c3faa"
        expected_handler = IntegerHandler.fromHexString(expected_result)

        print(f"Testing HMAC Based On SHA3-256 With Message: \"{message}\"")
        print(f"Expected HMAC : {expected_handler.getHexString(add_spacing=8)}")
        print(f"Actual HMAC   : {result.getHexString(add_spacing=8)}")
        
        self.assertEqual(result.getHexString(),expected_handler.getHexString())

    def test_sha3_384(self):
        '''
        This function tests the hmac generation based an sha3_384 with a key length equal to the block length

        Test values taken from the hmac example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''

        hmac = HMAC_SHA3_384()
        message = "Sample message for keylen=blocklen"
        key = "00010203 04050607 08090a0b 0c0d0e0f10111213 14151617 18191a1b 1c1d1e1f20212223 24252627 28292a2b 2c2d2e2f30313233 34353637 38393a3b 3c3d3e3f40414243 44454647 48494a4b 4c4d4e4f50515253 54555657 58595a5b 5c5d5e5f60616263 64656667 "
        result = hmac.HMAC(message=message, key=key, is_debug=False)

        expected_result = "a27d24b5 92e8c8cb f6d4ce6f c5bf62d8fc98bf2d 486640d9 eb8099e2 4047837f5f3bffbe 92dcce90 b4ed5b1e 7e44fa90"
        expected_handler = IntegerHandler.fromHexString(expected_result)

        print(f"Testing HMAC Based On SHA3-384 With Message: \"{message}\"")
        print(f"Expected HMAC : {expected_handler.getHexString(add_spacing=8)}")
        print(f"Actual HMAC   : {result.getHexString(add_spacing=8)}")
        
        self.assertEqual(result.getHexString(),expected_handler.getHexString())
    
    def test_sha3_512(self):
        '''
        This function tests the hmac generation based an sha3_512 with a key length equal to the block length

        Test values taken from the hmac example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''

        hmac = HMAC_SHA3_512()
        message = "Sample message for keylen=blocklen"
        key = "00010203 04050607 08090a0b 0c0d0e0f10111213 14151617 18191a1b 1c1d1e1f20212223 24252627 28292a2b 2c2d2e2f30313233 34353637 38393a3b 3c3d3e3f40414243 44454647"
        result = hmac.HMAC(message=message, key=key, is_debug=False)

        expected_result = "544e257e a2a3e5ea 19a590e6 a24b724ce6327757 723fe275 1b75bf00 7d80f6b360744bf1 b7a88ea5 85f9765b 47911976d3191cf8 3c039f5f fab0d29c c9d9b6da"
        expected_handler = IntegerHandler.fromHexString(expected_result)

        print(f"Testing HMAC Based On SHA3-512 With Message: \"{message}\"")
        print(f"Expected HMAC : {expected_handler.getHexString(add_spacing=8)}")
        print(f"Actual HMAC   : {result.getHexString(add_spacing=8)}")
        
        self.assertEqual(result.getHexString(),expected_handler.getHexString())
        
if __name__ == '__main__':
    print("- - - - - - - - - - - -")
    print("Testing HMAC Implementations Against Known Values")
    print("Expected Hashes are Sourced from NIST Cryptographic Standards and Guidelines: Examples With Intermediate Values")
    print("https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values")
    unittest.main()