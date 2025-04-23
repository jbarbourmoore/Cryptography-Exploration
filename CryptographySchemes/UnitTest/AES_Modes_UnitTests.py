import unittest
from CryptographySchemes.SymmetricEncryptionAlgorithms.AES_ModesOfOperation import*

class AES_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for aes
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


if __name__ == '__main__':
    unittest.main()