import unittest
from CryptographySchemes.SymmetricEncryptionAlgorithms.AdvancedEncryptionStandard import *

class AES_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for aes
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        example_aes_256_key = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4 "
        example_aes_256_key = example_aes_256_key.replace(" ","")
        self.aes_256 = AES256(example_aes_256_key)
        key = ("2B7E151628AED2A6ABF7158809CF4F3C")
        example_aes_192_key = "8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b"
        example_aes_192_key = example_aes_192_key.replace(" ","")
        self.aes_192 = AES192(example_aes_192_key)
        self.aes_128 = AES128(key)

    def test_aes_128_cypher(self):
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
        for i in range(0,1):
            print(f"Encrypting With AES 128 => Plain Text: {hex_to_encrypt[i]} & Key: {self.aes_128.key.upper()}")
            decrypted = self.aes_128.cypher(hex_to_encrypt[i])
            print(f"Actual Cypher Text: {decrypted} == Expected Cypher Text: {expected_results[1]}")
            self.assertEqual(decrypted,expected_results[i])

    def test_aes_128_inverse_cypher(self):
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
        for i in range(0,1):
            print(f"Decrypting With AES 128 => Cypher Text: {hex_to_decrypt[i]} & Key: {self.aes_128.key.upper()}")
            decrypted = self.aes_128.inverseCypher(hex_to_decrypt[i])
            print(f"Actual Plain Text:  {decrypted} == Expected Plain Text:  {expected_results[1]}")
            self.assertEqual(decrypted,expected_results[i])

    def test_aes_192_cypher(self):
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
        for i in range(0,1):
            print(f"Encrypting With AES 192 => Plain Text: {hex_to_encrypt[i]} & Key: {self.aes_192.key.upper()}")
            decrypted = self.aes_192.cypher(hex_to_encrypt[i])
            print(f"Actual Cypher Text: {decrypted} == Expected Cypher Text: {expected_results[1]}")
            self.assertEqual(decrypted,expected_results[i])


    def test_aes_192_inverse_cypher(self):
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
        for i in range(0,1):
            print(f"Decrypting With AES 192 => Cypher Text: {hex_to_decrypt[i]} & Key: {self.aes_192.key.upper()}")
            decrypted = self.aes_192.inverseCypher(hex_to_decrypt[i])
            print(f"Actual Plain Text:  {decrypted} == Expected Plain Text:  {expected_results[1]}")
            self.assertEqual(decrypted,expected_results[i])

    def test_aes_256_cypher(self):
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
        for i in range(0,1):
            print(f"Encrypting With AES 256 => Plain Text: {hex_to_encrypt[i]} & Key: {self.aes_256.key.upper()}")
            decrypted = self.aes_256.cypher(hex_to_encrypt[i])
            print(f"Actual Cypher Text: {decrypted} == Expected Cypher Text: {expected_results[1]}")
            self.assertEqual(decrypted,expected_results[i])


    def test_aes_256_inverse_cypher(self):
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
        for i in range(0,1):
            print(f"Decrypting With AES 256 => Cypher Text: {hex_to_decrypt[i]} & Key: {self.aes_256.key.upper()}")
            decrypted = self.aes_256.inverseCypher(hex_to_decrypt[i])
            print(f"Actual Plain Text:  {decrypted} == Expected Plain Text:  {expected_results[1]}")
            self.assertEqual(decrypted,expected_results[i])

    
if __name__ == '__main__':
    unittest.main()