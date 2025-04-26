import unittest
from CryptographySchemes.SymmetricEncryptionAlgorithms.TripleDataEncryptionStandard import*
from HelperFunctions.IntegerHandler import *

class TDES_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for aes modes
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_tdes_ecb_1encrypt(self):
        '''
        This method tests that the tdes encryption works properly in Electronic Codebook (ECB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_Core.pdf
        '''

        hex_to_encrypt   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        expected_results =  "06EDE3D8 2884090A FF322C19 F0518486 73057697 2A666E58 B6C88CF1 07340D3D".replace(" ","")
        
        key = "0123456789ABCDEF23456789ABCDEF010123456789ABCDEF"

        tdes = TDES_ECB(key=key, is_hex_key=True)
        result_hex = tdes.encryptHexString(hex_to_encrypt)
        self.assertEqual(expected_results, result_hex)
        print("Testing Encryption With Triple Data Encryption Standard In Electronic Cookbook (ECB) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_hex}")

    def test_tdes_ecb_2decrypt(self):
        '''
        This method tests that the tdes decryption works properly in Electronic Codebook (ECB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_Core.pdf
        '''

        expected_results = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        hex_to_decrypt   = "06EDE3D8 2884090A FF322C19 F0518486 73057697 2A666E58 B6C88CF1 07340D3D".replace(" ","")
        
        key = "0123456789ABCDEF23456789ABCDEF010123456789ABCDEF"

        tdes = TDES_ECB(key=key, is_hex_key=True)
        result_hex = tdes.decryptHexString(hex_to_decrypt)
        self.assertEqual(expected_results, result_hex)
        print("Testing Decryption With Triple Data Encryption Standard In Electronic Cookbook (ECB) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_hex}")

    def test_tdes_cbc_1encrypt(self):
        '''
        This method tests that the tdes encryption works properly in Cypher Block Chaining (CBC) mode 
        according to https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/ST/toolkit/documents/Examples/TDES_ModesA_All.txt
        '''

        hex_to_encrypt   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        expected_results =  "2079C3D5 3AA763E1 93B79E25 69AB5262 51657048 1F25B50F 73C0BDA8 5C8E0DA7".replace(" ","")
        
        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"

        tdes = TDES_CBC(key=key, is_hex_key=True)
        result_hex = tdes.encryptHexString(hex_to_encrypt,initialization_vector)
        self.assertEqual(expected_results, result_hex)
        print("Testing Encryption With Triple Data Encryption Standard In Cypher Block Chaining (CBC) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_hex}")

    def test_tdes_cbc_2decrypt(self):
        '''
        This method tests that the tdes decryption works properly in Cypher Block Chaining (CBC) mode 
        according to https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/ST/toolkit/documents/Examples/TDES_ModesA_All.txt
        '''

        expected_results = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        hex_to_decrypt   = "2079C3D5 3AA763E1 93B79E25 69AB5262 51657048 1F25B50F 73C0BDA8 5C8E0DA7".replace(" ","")
        
        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"

        tdes = TDES_CBC(key=key, is_hex_key=True)
        result_hex = tdes.decryptHexString(hex_to_decrypt, initialization_vector)
        self.assertEqual(expected_results, result_hex)
        print("Testing Decryption With Triple Data Encryption Standard In Cypher Block Chaining (CBC) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_hex}")

    def test_tdes_cfb_s64_1encrypt(self):
        '''
        This method tests that the tdes encryption works properly in Cypher Feedback (CFB) mode 
        according to https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/ST/toolkit/documents/Examples/TDES_ModesA_All.txt
        '''

        hex_to_encrypt   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        expected_results =  "078BB74E 59CE7ED6 7666DE9C F95EAF3F E9ED6BB4 60F45152 8A5F9FE4 ED710918".replace(" ","")
        
        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"
        s = 64

        tdes = TDES_CFB(key=key, s=s, is_hex_key=True)
        result_hex = tdes.encryptHexString(hex_to_encrypt,initialization_vector=initialization_vector)
        self.assertEqual(expected_results, result_hex)
        print("Testing Encryption With Triple Data Encryption Standard In Cypher Feedback (CFB) Mode With 64 Bits")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_hex}")

    def test_tdes_cfb_s64_2decrypt(self):
        '''
        This method tests that the tdes decryption works properly in Cypher Feedback (CFB) mode
        according to https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/ST/toolkit/documents/Examples/TDES_ModesA_All.txt
        '''

        expected_results = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        hex_to_decrypt   = "078BB74E 59CE7ED6 7666DE9C F95EAF3F E9ED6BB4 60F45152 8A5F9FE4 ED710918".replace(" ","")
        
        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"
        s = 64

        tdes = TDES_CFB(key=key, s=s, is_hex_key=True)
        result_hex = tdes.decryptHexString(hex_to_decrypt, initialization_vector)
        self.assertEqual(expected_results, result_hex)
        print("Testing Decryption With Triple Data Encryption Standard In Cypher Feedback (CFB) Mode With 64 Bits")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_hex}")

    def test_tdes_cfb_s1_1encrypt(self):
        '''
        This method tests that the tdes encryption works properly in Cypher Feedback (CFB) mode 
        according to https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/ST/toolkit/documents/Examples/TDES_ModesA_All.txt
        '''

        hex_to_encrypt   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        expected_results =  "5CB0126B 0CBD982E 68BCDEFD A8055647 85766DAC DF059F88 0E47F037 F69E9418".replace(" ","")
        
        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"
        s = 1

        tdes = TDES_CFB(key=key, s=s, is_hex_key=True)
        result_hex = tdes.encryptHexString(hex_to_encrypt,initialization_vector=initialization_vector)
        self.assertEqual(expected_results, result_hex)
        print("Testing Encryption With Triple Data Encryption Standard In Cypher Feedback (CFB) Mode With 1 Bit")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_hex}")

    def test_tdes_cfb_s1_2decrypt(self):
        '''
        This method tests that the tdes decryption works properly in Cypher Feedback (CFB) mode
        according to https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/ST/toolkit/documents/Examples/TDES_ModesA_All.txt
        '''

        expected_results = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        hex_to_decrypt   = "5CB0126B 0CBD982E 68BCDEFD A8055647 85766DAC DF059F88 0E47F037 F69E9418".replace(" ","")
        
        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"
        s = 1

        tdes = TDES_CFB(key=key, s=s, is_hex_key=True)
        result_hex = tdes.decryptHexString(hex_to_decrypt, initialization_vector)
        self.assertEqual(expected_results, result_hex)
        print("Testing Decryption With Triple Data Encryption Standard In Cypher Feedback (CFB) Mode With 1 Bit")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_hex}")

    def test_tdes_cfb_s8_1encrypt(self):
        '''
        This method tests that the tdes encryption works properly in Cypher Feedback (CFB) mode 
        according to https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/ST/toolkit/documents/Examples/TDES_ModesA_All.txt
        '''

        hex_to_encrypt   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        expected_results =  "07951B72 9DC23AB4 48FC82B4 0372623D C443A4B4 43B6B4A6 6C20D892 236028D5".replace(" ","")
        
        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"
        s = 8

        tdes = TDES_CFB(key=key, s=s, is_hex_key=True)
        result_hex = tdes.encryptHexString(hex_to_encrypt,initialization_vector=initialization_vector)
        self.assertEqual(expected_results, result_hex)
        print("Testing Encryption With Triple Data Encryption Standard In Cypher Feedback (CFB) Mode With 8 Bits")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_hex}")

    def test_tdes_cfb_s8_2decrypt(self):
        '''
        This method tests that the tdes decryption works properly in Cypher Feedback (CFB) mode
        according to https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/ST/toolkit/documents/Examples/TDES_ModesA_All.txt
        '''

        expected_results = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        hex_to_decrypt   = "07951B72 9DC23AB4 48FC82B4 0372623D C443A4B4 43B6B4A6 6C20D892 236028D5".replace(" ","")
        
        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"
        s = 8

        tdes = TDES_CFB(key=key, s=s, is_hex_key=True)
        result_hex = tdes.decryptHexString(hex_to_decrypt, initialization_vector)
        self.assertEqual(expected_results, result_hex)
        print("Testing Decryption With Triple Data Encryption Standard In Cypher Feedback (CFB) Mode With 8 Bits")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_hex}")


if __name__ == '__main__':
    print("Testing TDES With Block Cypher Modes Of Operation")
    print("https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf")
    unittest.main()