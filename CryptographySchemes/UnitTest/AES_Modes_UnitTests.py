import unittest
from CryptographySchemes.SymmetricEncryptionAlgorithms.AES_ModesOfOperation import*
from HelperFunctions.IntegerHandler import *

class AES_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for aes modes
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        example_aes_256_key = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4 "
        example_aes_256_key = example_aes_256_key.replace(" ","")
        self.aes_ecb_256 = AES_ECB_256(example_aes_256_key)
        key = ("2B7E151628AED2A6ABF7158809CF4F3C")
        example_aes_192_key = "8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b"
        example_aes_192_key = example_aes_192_key.replace(" ","")
        self.aes_ecb_192 = AES_ECB_192(example_aes_192_key)
        self.aes_ecb_128 = AES_ECB_128(key)

        self.aes_cbc_128 = AES_CBC_128(key)
        self.aes_cbc_192 = AES_CBC_192(example_aes_192_key)
        self.aes_cbc_256 = AES_CBC_256(example_aes_256_key)
        self.initialization_vector = "000102030405060708090a0b0c0d0e0f"

        self.aes_cfb8_128 = AES_CFB_128(key,8)
        self.aes_cfb8_192 = AES_CFB_192(example_aes_192_key,8)
        self.aes_cfb8_256 = AES_CFB_256(example_aes_256_key,8)

        self.aes_cfb1_128 = AES_CFB_128(key,1)
        self.aes_cfb128_128 = AES_CFB_128(key,128)

        self.aes_ofb_128 = AES_OFB_128(key)
        self.aes_ofb_192 = AES_OFB_192(example_aes_192_key)
        self.aes_ofb_256 = AES_OFB_256(example_aes_256_key)

        self.initialization_counter = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        self.aes_ctr_128 = AES_CTR_128(key)
        self.aes_ctr_192 = AES_CTR_192(example_aes_192_key)
        self.aes_ctr_256 = AES_CTR_256(example_aes_256_key)

    def test_aes_ecb_128_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 128 in  Electronic Codebook (ECB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
        '''

        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ["3AD77BB40D7A3660A89ECAF32466EF97",
                            "F5D3D58503B9699DE785895A96FDBAAF",
                            "43B1CD7F598ECE23881B00E3ED030688",
                            "7B0C785E27E8AD3F8223207104725DD4"]
        
        result_list = self.aes_ecb_128.encryptHexList(hex_to_encrypt)
        self.assertListEqual(expected_results, result_list)
        print("Testing Encryption With AES 128 In Electronic Cookbook (ECB) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_ecb_128_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 128 in  Electronic Codebook (ECB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
        '''

        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt   = ["3AD77BB40D7A3660A89ECAF32466EF97",
                            "F5D3D58503B9699DE785895A96FDBAAF",
                            "43B1CD7F598ECE23881B00E3ED030688",
                            "7B0C785E27E8AD3F8223207104725DD4"]
        
        result_list = self.aes_ecb_128.decryptHexList(hex_to_decrypt)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 128 In Electronic Cookbook (ECB) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_ecb_192_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 192 in  Electronic Codebook (ECB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core192.pdf
        '''

        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ["BD334F1D6E45F25FF712A214571FA5CC",
                            "974104846D0AD3AD7734ECB3ECEE4EEF",
                            "EF7AFD2270E2E60ADCE0BA2FACE6444E", 
                            "9A4B41BA738D6C72FB16691603C18E0E"]
        result_list = self.aes_ecb_192.encryptHexList(hex_to_encrypt)
        self.assertListEqual(expected_results, result_list)
        print("Testing Encryption With AES 192 In Electronic Cookbook (ECB) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_ecb_192_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 192 in  Electronic Codebook (ECB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core192.pdf
        '''

        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt   = ["BD334F1D6E45F25FF712A214571FA5CC",
                            "974104846D0AD3AD7734ECB3ECEE4EEF",
                            "EF7AFD2270E2E60ADCE0BA2FACE6444E", 
                            "9A4B41BA738D6C72FB16691603C18E0E"]
        result_list = self.aes_ecb_192.decryptHexList(hex_to_decrypt)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 192 In Electronic Cookbook (ECB) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_ecb_256_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 256 in Electronic Codebook (ECB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core256.pdf
        '''

        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ["F3EED1BDB5D2A03C064B5A7E3DB181F8", 
                            "591CCB10D410ED26DC5BA74A31362870",
                            "B6ED21B99CA6F4F9F153E7B1BEAFED1D",
                            "23304B7A39F9F3FF067D8D8F9E24ECC7"]
        result_list = self.aes_ecb_256.encryptHexList(hex_to_encrypt)
        self.assertListEqual(expected_results, result_list)
        print("Testing Encryption With AES 256 In Electronic Cookbook (ECB) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")


    def test_aes_ecb_256_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 192 in  Electronic Codebook (ECB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core256.pdf
        '''

        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt   = ["F3EED1BDB5D2A03C064B5A7E3DB181F8", 
                            "591CCB10D410ED26DC5BA74A31362870",
                            "B6ED21B99CA6F4F9F153E7B1BEAFED1D",
                            "23304B7A39F9F3FF067D8D8F9E24ECC7"]
        result_list = self.aes_ecb_256.decryptHexList(hex_to_decrypt)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 256 In Electronic Cookbook (ECB) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_cbc_128_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 128 in Cipher Block Chaining (CBC) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['7649ABAC8119B246CEE98E9B12E9197D', 
                            '5086CB9B507219EE95DB113A917678B2', 
                            '73BED6B8E3C1743B7116E69E22229516', 
                            '3FF1CAA1681FAC09120ECA307586E1A7']
        for i in range(0, 4):
            expected_results[i] = expected_results[i].upper()
        result_list = self.aes_cbc_128.encryptHexList(hex_to_encrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Encryption With AES 128 In Cipher Block Chaining (CBC) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_cbc_128_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 128 in Cipher Block Chaining (CBC) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''

        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt   = ['7649ABAC8119B246CEE98E9B12E9197D', 
                            '5086CB9B507219EE95DB113A917678B2', 
                            '73BED6B8E3C1743B7116E69E22229516', 
                            '3FF1CAA1681FAC09120ECA307586E1A7']
        result_list = self.aes_cbc_128.decryptHexList(hex_to_decrypt, self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 128 Cipher Block Chaining (CBC) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_cbc_192_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 192 in Cipher Block Chaining (CBC) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''

        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['4F021DB243BC633D7178183A9FA071E8',
                            'B4D9ADA9AD7DEDF4E5E738763F69145A',
                            '571B242012FB7AE07FA9BAAC3DF102E0',
                            '08B0E27988598881D920A9E64F5615CD']
        result_list = self.aes_cbc_192.encryptHexList(hex_to_encrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Encryption With AES 192 In Cipher Block Chaining (CBC) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_cbc_192_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 192 in Cipher Block Chaining (CBC) Mode 
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''

        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt   = ['4F021DB243BC633D7178183A9FA071E8',
                            'B4D9ADA9AD7DEDF4E5E738763F69145A',
                            '571B242012FB7AE07FA9BAAC3DF102E0',
                            '08B0E27988598881D920A9E64F5615CD']
        result_list = self.aes_cbc_192.decryptHexList(hex_to_decrypt, self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 192 Cipher Block Chaining (CBC) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_cbc_256_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 256 in Cipher Block Chaining (CBC) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['F58C4C04D6E5F1BA779EABFB5F7BFBD6',
                            '9CFC4E967EDB808D679F777BC6702C7D',
                            '39F23369A9D9BACFA530E26304231461',
                            'B2EB05E2C39BE9FCDA6C19078C6A9D1B']
        result_list = self.aes_cbc_256.encryptHexList(hex_to_encrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Encryption With AES 256 In Cipher Block Chaining (CBC) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_cbc_256_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 256 in Cipher Block Chaining (CBC) Mode
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
        '''

        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt   = ['F58C4C04D6E5F1BA779EABFB5F7BFBD6',
                            '9CFC4E967EDB808D679F777BC6702C7D',
                            '39F23369A9D9BACFA530E26304231461',
                            'B2EB05E2C39BE9FCDA6C19078C6A9D1B']
        result_list = self.aes_cbc_256.decryptHexList(hex_to_decrypt, self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 256 Cipher Block Chaining (CBC) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_cfb_128_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 128 in Cipher Feedback (CFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['3B79424C9C0DD436BACE9E0ED4586A4F',
                            '32B9DED50AE3BA69D472E88267FB5052',
                            '70CBAD1E257691F7C47C5038297EDDA3',
                            '2FF26D0ED19174096161ECC14086DD62']
        
        result_list = self.aes_cfb8_128.encryptHexList(hex_to_encrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Encryption With AES 128 In Cipher Feedback (CFB) Mode With 8 Bits")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_cfb_128_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 128 in Cipher Feedback (CFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt =   ['3B79424C9C0DD436BACE9E0ED4586A4F',
                            '32B9DED50AE3BA69D472E88267FB5052',
                            '70CBAD1E257691F7C47C5038297EDDA3',
                            '2FF26D0ED19174096161ECC14086DD62']
        
        result_list = self.aes_cfb8_128.decryptHexList(hex_to_decrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 128 In Cipher Feedback (CFB) Mode With 8 Bits")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_cfb_192_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 192 in Cipher Feedback (CFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['CDA2521EF0A905CA44CD057CBF0D47A0',
                            '678A7BCFB6AEAA3047B38936021F48BB',
                            'B63CEFDAC02B2E840904EFCE6F4326BE',
                            '228683739063DC30E937FFEDD63E3C94']
        
        result_list = self.aes_cfb8_192.encryptHexList(hex_to_encrypt, self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Encryption With AES 192 In Cipher Feedback (CFB) Mode With 8 Bits")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_cfb_192_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 192 in Cipher Feedback (CFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt =   ['CDA2521EF0A905CA44CD057CBF0D47A0',
                            '678A7BCFB6AEAA3047B38936021F48BB',
                            'B63CEFDAC02B2E840904EFCE6F4326BE',
                            '228683739063DC30E937FFEDD63E3C94']
        
        result_list = self.aes_cfb8_192.decryptHexList(hex_to_decrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 192 In Cipher Feedback (CFB) Mode With 8 Bits")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_cfb_256_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 256 in Cipher Feedback (CFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['DC1F1A8520A64DB55FCC8AC554844E88',
                            '9700ADC6E10C63CF2D8CD2D8CE668F3E',
                            'B9191719C47444FB43BFF9B9883C2CD0',
                            '51120402009F974998C89D195722A75B']
        
        result_list = self.aes_cfb8_256.encryptHexList(hex_to_encrypt, self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Encryption With AES 256 In Cipher Feedback (CFB) Mode With 8 Bits")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_cfb_256_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 256 in Cipher Feedback (CFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt =   ['DC1F1A8520A64DB55FCC8AC554844E88',
                            '9700ADC6E10C63CF2D8CD2D8CE668F3E',
                            'B9191719C47444FB43BFF9B9883C2CD0',
                            '51120402009F974998C89D195722A75B']
        
        result_list = self.aes_cfb8_256.decryptHexList(hex_to_decrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 256 In Cipher Feedback (CFB) Mode With 8 Bits")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_cfb1_128_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 128 in Cipher Feedback (CFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['68B3A264F838F5F8C3101070D1AB4C2E',
                            '22E7F950383A0B71ADE4FAD0095CB188',
                            'A57972C3C1882615F7511411FBEBF119',
                            '3997069704FC1D1F27028434C99E60F4']
        expected_bits =[0,1,1,0,1,0,0,0,1,0,1,1,0,0,1,1]
        expected_bits_handler = IntegerHandler.fromBitArray(expected_bits,False,16)

        result_list = self.aes_cfb1_128.encryptHexList(hex_to_encrypt,self.initialization_vector)
        result_bits_handler = IntegerHandler.fromHexString(result_list[0][:4],False,16)

        self.assertListEqual(expected_results, result_list)
        self.assertEqual(expected_bits_handler.getBitString(),result_bits_handler.getBitString())

        print("Testing Encryption With AES 128 In Cipher Feedback (CFB) Mode With 1 Bit")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_cfb1_128_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 128 in Cipher Feedback (CFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt =   ['68B3A264F838F5F8C3101070D1AB4C2E',
                            '22E7F950383A0B71ADE4FAD0095CB188',
                            'A57972C3C1882615F7511411FBEBF119',
                            '3997069704FC1D1F27028434C99E60F4']
        
        result_list = self.aes_cfb1_128.decryptHexList(hex_to_decrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 128 In Cipher Feedback (CFB) Mode With 1 Bit")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_cfb128_128_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 128 in Cipher Feedback (CFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['3B3FD92EB72DAD20333449F8E83CFB4A',
                            'C8A64537A0B3A93FCDE3CDAD9F1CE58B',
                            '26751F67A3CBB140B1808CF187A4F4DF',
                            'C04B05357C5D1C0EEAC4C66F9FF7F2E6']
        
        result_list = self.aes_cfb128_128.encryptHexList(hex_to_encrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)

        print("Testing Encryption With AES 128 In Cipher Feedback (CFB) Mode With 128 Bits")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_cfb128_128_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 128 in Cipher Feedback (CFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt =   ['3B3FD92EB72DAD20333449F8E83CFB4A',
                            'C8A64537A0B3A93FCDE3CDAD9F1CE58B',
                            '26751F67A3CBB140B1808CF187A4F4DF',
                            'C04B05357C5D1C0EEAC4C66F9FF7F2E6']
        
        result_list = self.aes_cfb128_128.decryptHexList(hex_to_decrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 128 In Cipher Feedback (CFB) Mode With 128 Bits")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_ofb_128_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 128 in Output Feedback (OFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['3B3FD92EB72DAD20333449F8E83CFB4A',
                            '7789508D16918F03F53C52DAC54ED825',
                            '9740051E9C5FECF64344F7A82260EDCC',
                            '304C6528F659C77866A510D9C1D6AE5E']
        
        result_list = self.aes_ofb_128.encryptHexList(hex_to_encrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)

        print("Testing Encryption With AES 128 In Output Feedback (OFB) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_ofb_128_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 128 in Output Feedback (OFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt =   ['3B3FD92EB72DAD20333449F8E83CFB4A',
                            '7789508D16918F03F53C52DAC54ED825',
                            '9740051E9C5FECF64344F7A82260EDCC',
                            '304C6528F659C77866A510D9C1D6AE5E']
        
        result_list = self.aes_ofb_128.decryptHexList(hex_to_decrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 128 In Output Feedback (OFB) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_ofb_192_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 192 in Output Feedback (OFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['CDC80D6FDDF18CAB34C25909C99A4174',
                            'FCC28B8D4C63837C09E81700C1100401',
                            '8D9A9AEAC0F6596F559C6D4DAF59A5F2',
                            '6D9F200857CA6C3E9CAC524BD9ACC92A']
        
        result_list = self.aes_ofb_192.encryptHexList(hex_to_encrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)

        print("Testing Encryption With AES 192 In Output Feedback (OFB) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_ofb_192_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 192 in Output Feedback (OFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt =   ['CDC80D6FDDF18CAB34C25909C99A4174',
                            'FCC28B8D4C63837C09E81700C1100401',
                            '8D9A9AEAC0F6596F559C6D4DAF59A5F2',
                            '6D9F200857CA6C3E9CAC524BD9ACC92A']
        
        result_list = self.aes_ofb_192.decryptHexList(hex_to_decrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 192 In Output Feedback (OFB) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_ofb_256_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 256 in Output Feedback (OFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['DC7E84BFDA79164B7ECD8486985D3860',
                            '4FEBDC6740D20B3AC88F6AD82A4FB08D',
                            '71AB47A086E86EEDF39D1C5BBA97C408',
                            '0126141D67F37BE8538F5A8BE740E484']
        
        result_list = self.aes_ofb_256.encryptHexList(hex_to_encrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)

        print("Testing Encryption With AES 256 In Output Feedback (OFB) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_ofb_256_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 256 in Output Feedback (OFB) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt =   ['DC7E84BFDA79164B7ECD8486985D3860',
                            '4FEBDC6740D20B3AC88F6AD82A4FB08D',
                            '71AB47A086E86EEDF39D1C5BBA97C408',
                            '0126141D67F37BE8538F5A8BE740E484']
        
        result_list = self.aes_ofb_256.decryptHexList(hex_to_decrypt,self.initialization_vector)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 256 In Output Feedback (OFB) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_ctr_128_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 128 in Counter (CTR) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['874D6191B620E3261BEF6864990DB6CE',
                            '9806F66B7970FDFF8617187BB9FFFDFF',
                            '5AE4DF3EDBD5D35E5B4F09020DB03EAB',
                            '1E031DDA2FBE03D1792170A0F3009CEE']
        
        result_list = self.aes_ctr_128.encryptHexList(hex_to_encrypt,self.initialization_counter)
        self.assertListEqual(expected_results, result_list)

        print("Testing Encryption With AES 128 In Counter (CTR) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_ctr_128_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 128 in Counter (CTR) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt =   ['874D6191B620E3261BEF6864990DB6CE',
                            '9806F66B7970FDFF8617187BB9FFFDFF',
                            '5AE4DF3EDBD5D35E5B4F09020DB03EAB',
                            '1E031DDA2FBE03D1792170A0F3009CEE']
        
        result_list = self.aes_ctr_128.decryptHexList(hex_to_decrypt,self.initialization_counter)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 128 In Counter (CTR) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_ctr_192_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 192 in Counter (CTR) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['1ABC932417521CA24F2B0459FE7E6E0B',
                            '090339EC0AA6FAEFD5CCC2C6F4CE8E94',
                            '1E36B26BD1EBC670D1BD1D665620ABF7',
                            '4F78A7F6D29809585A97DAEC58C6B050']
        
        result_list = self.aes_ctr_192.encryptHexList(hex_to_encrypt,self.initialization_counter)
        self.assertListEqual(expected_results, result_list)

        print("Testing Encryption With AES 192 In Counter (CTR) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_ctr_192_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 192 in Counter (CTR) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt =   ['1ABC932417521CA24F2B0459FE7E6E0B',
                            '090339EC0AA6FAEFD5CCC2C6F4CE8E94',
                            '1E36B26BD1EBC670D1BD1D665620ABF7',
                            '4F78A7F6D29809585A97DAEC58C6B050']
        
        result_list = self.aes_ctr_192.decryptHexList(hex_to_decrypt,self.initialization_counter)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 192 In Counter (CTR) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

    def test_aes_ctr_256_1encrypt(self):
        '''
        This method tests that the aes cypher for aes 256 in Counter (CTR) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        hex_to_encrypt   = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        expected_results = ['601EC313775789A5B7A7F504BBF3D228',
                            'F443E3CA4D62B59ACA84E990CACAF5C5',
                            '2B0930DAA23DE94CE87017BA2D84988D',
                            'DFC9C58DB67AADA613C2DD08457941A6']
        
        result_list = self.aes_ctr_256.encryptHexList(hex_to_encrypt,self.initialization_counter)
        self.assertListEqual(expected_results, result_list)

        print("Testing Encryption With AES 256 In Counter (CTR) Mode")
        print(f"Plain Text           : {hex_to_encrypt}")
        print(f"Expected Cypher Text : {expected_results}")
        print(f"Encrypted Text       : {result_list}")

    def test_aes_ctr_256_2decrypt(self):
        '''
        This method tests that the aes inverse cypher for aes 256 in Counter (CTR) Mode
        Uses test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        '''
        expected_results = ["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        hex_to_decrypt =   ['601EC313775789A5B7A7F504BBF3D228',
                            'F443E3CA4D62B59ACA84E990CACAF5C5',
                            '2B0930DAA23DE94CE87017BA2D84988D',
                            'DFC9C58DB67AADA613C2DD08457941A6']
        
        result_list = self.aes_ctr_256.decryptHexList(hex_to_decrypt,self.initialization_counter)
        self.assertListEqual(expected_results, result_list)
        print("Testing Decryption With AES 256 In Counter (CTR) Mode")
        print(f"Cypher Text          : {hex_to_decrypt}")
        print(f"Expected Plain Text  : {expected_results}")
        print(f"Decrypted Text       : {result_list}")

if __name__ == '__main__':
    print("Testing AES With Block Cypher Modes Of Operation")
    print("Electronic Cookbook (ECB) Mode, Cipher Block Chaining (CBC) Mode, Cipher Feedback (CFB) Mode, Output Feedback (OFB) Mode and Counter (CTR) Mode")
    print("From NIST SP 800-38A, \"Recommendation for Block Cipher Modes of Operation\"")
    print("https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf")
    unittest.main()