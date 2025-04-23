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
        for i in range(0,len(hex_to_encrypt)):
            print(f"Encrypting With AES 128 : {hex_to_encrypt[i]}")
            encrypted = self.aes_128.cypher(hex_to_encrypt[i])
            print(encrypted)
            self.assertEqual(encrypted,expected_results[i])

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
        for i in range(0,len(hex_to_decrypt)):
            print(f"Encrypting With AES 128 : {hex_to_decrypt[i]}")
            decrypted = self.aes_128.inverseCypher(hex_to_decrypt[i])
            print(decrypted)
            self.assertEqual(decrypted,expected_results[i])

    def test_aes_128_key_expansion(self):
        '''
        This method tests the expansion of an AES 128 bit key 
        Follows example from the Appendix of NIST FIPS 197 "A.1 Expansion of a 128-bit Key"
        '''
        expanded_key = self.aes_128.expanded_key
        self.assertEqual(self.aes_128.getWordAsHex(expanded_key[1]),"28aed2a6".upper())
        self.assertEqual(self.aes_128.getWordAsHex(expanded_key[4]),"a0fafe17".upper())
        self.assertEqual(self.aes_128.getWordAsHex(expanded_key[9]),"7a96b943".upper())
        self.assertEqual(self.aes_128.getWordAsHex(expanded_key[23]),"11f915bc".upper())
        self.assertEqual(self.aes_128.getWordAsHex(expanded_key[32]),"ead27321".upper())
        self.assertEqual(self.aes_128.getWordAsHex(expanded_key[43]),"b6630ca6".upper())

    def test_aes_192_key_expansion(self):
        '''
        This method tests the expansion of an AES 192 bit key 
        Follows example from the Appendix of NIST FIPS 197 "A.2 Expansion of a 192-bit Key"
        '''
        expanded_key = self.aes_192.expanded_key
        self.assertEqual(self.aes_192.getWordAsHex(expanded_key[1]),"da0e6452".upper())
        self.assertEqual(self.aes_192.getWordAsHex(expanded_key[6]),"fe0c91f7".upper())
        self.assertEqual(self.aes_192.getWordAsHex(expanded_key[9]),"6c827f6b".upper())
        self.assertEqual(self.aes_192.getWordAsHex(expanded_key[23]),"113b30e6".upper())
        self.assertEqual(self.aes_192.getWordAsHex(expanded_key[32]),"485f7032".upper())
        self.assertEqual(self.aes_192.getWordAsHex(expanded_key[43]),"ad07d753".upper())
        self.assertEqual(self.aes_192.getWordAsHex(expanded_key[48]),"e98ba06f".upper())
        self.assertEqual(self.aes_192.getWordAsHex(expanded_key[51]),"01002202".upper())

    def test_aes_256_key_expansion(self):
        '''
        This method tests the expansion of an AES 256 bit key 
        Follows example from the Appendix of NIST FIPS 197 "A.3 Expansion of a 256-bit Key"
        '''

        expanded_key = self.aes_256.expanded_key
        self.assertEqual(self.aes_256.getWordAsHex(expanded_key[1]),"15ca71be".upper())
        self.assertEqual(self.aes_256.getWordAsHex(expanded_key[8]),"9ba35411".upper())
        self.assertEqual(self.aes_256.getWordAsHex(expanded_key[9]),"8e6925af".upper())
        self.assertEqual(self.aes_256.getWordAsHex(expanded_key[12]),"a8b09c1a".upper())
        self.assertEqual(self.aes_192.getWordAsHex(expanded_key[23]),"2f6c79b3".upper())
        self.assertEqual(self.aes_256.getWordAsHex(expanded_key[32]),"68007bac".upper())
        self.assertEqual(self.aes_256.getWordAsHex(expanded_key[43]),"9674ee15".upper())
        self.assertEqual(self.aes_256.getWordAsHex(expanded_key[48]),"749c47ab".upper())
        self.assertEqual(self.aes_256.getWordAsHex(expanded_key[51]),"7401905a".upper())
        self.assertEqual(self.aes_256.getWordAsHex(expanded_key[52]),"cafaaae3".upper())
        self.assertEqual(self.aes_256.getWordAsHex(expanded_key[59]),"706c631e".upper())

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
        for i in range(0,len(hex_to_encrypt)):
            print(f"Encrypting With AES 192 : {hex_to_encrypt[i]}")
            encrypted = self.aes_192.cypher(hex_to_encrypt[i])
            print(encrypted)
            self.assertEqual(encrypted,expected_results[i])


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
        for i in range(0,len(hex_to_decrypt)):
            print(f"Encrypting With AES 192 : {hex_to_decrypt[i]}")
            decrypted = self.aes_192.inverseCypher(hex_to_decrypt[i])
            print(decrypted)
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
        for i in range(0,len(hex_to_encrypt)):
            print(f"Encrypting With AES 256 : {hex_to_encrypt[i]}")
            encrypted = self.aes_256.cypher(hex_to_encrypt[i])
            print(encrypted)
            self.assertEqual(encrypted,expected_results[i])


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
        for i in range(0,len(hex_to_decrypt)):
            print(f"Decrypting With AES 256 : {hex_to_decrypt[i]}")
            decrypted = self.aes_256.inverseCypher(hex_to_decrypt[i])
            print(decrypted)
            self.assertEqual(decrypted,expected_results[i])

    def test_xtimes(self):
        '''
        This method tests the xtimes function
        examples are pulled from Nist FIPS 197 "4.2 Multiplication in GF(2**8)"
        '''

        print(f"Working on xTimes :")
        print(f"{2}  : {hex(self.aes_128.xTimes(0x57,0x02))} should be 0xae")
        self.assertEqual(self.aes_128.xTimes(0x57,0x02), 0xae)
        print(f"{4}  : {hex(self.aes_128.xTimes(0x57,0x04))} should be 0x47")
        self.assertEqual(self.aes_128.xTimes(0x57,0x04), 0x47)
        print(f"{8}  : {hex(self.aes_128.xTimes(0x57,0x08))} should be 0x8e")
        self.assertEqual(self.aes_128.xTimes(0x57,0x08), 0x8e)
        print(f"{10} : {hex(self.aes_128.xTimes(0x57,0x10))}  should be  0x7")
        self.assertEqual(self.aes_128.xTimes(0x57,0x10), 0x7)
        print(f"{20} : {hex(self.aes_128.xTimes(0x57,0x20))}  should be  0xe")
        self.assertEqual(self.aes_128.xTimes(0x57,0x20), 0xe)
        print(f"{40} : {hex(self.aes_128.xTimes(0x57,0x40))} should be 0x1c")
        self.assertEqual(self.aes_128.xTimes(0x57,0x40), 0x1c)
        print(f"{80} : {hex(self.aes_128.xTimes(0x57,0x80))} should be 0x38")
        self.assertEqual(self.aes_128.xTimes(0x57,0x80), 0x38)
        print(f"{13} : {hex(self.aes_128.xTimes(0x57,0x13))} should be 0xfe")
        self.assertEqual(self.aes_128.xTimes(0x57,0x13), 0xfe)

    def test_mixed_columns(self):
        '''
        This method tests the mixed_columns function
        comparing mixed_columns and inverse_mixed_columns
        '''

        example_matrix = [[0xf2,0x01,0xc6,0xdb], [0x0a,0x01,0xc6,0x13],[0x22,0x01,0xc6,0x53], [0x5c,0x01,0xc6,0x45]]
        expected_result = "9FDC589D01010101C6C6C6C68E4DA1BC"
        print(self.aes_256.getMatrixAsHexString(example_matrix))
        mixed_columns = self.aes_256.mixColumns(example_matrix)
        print("Mixed Columns")
        mixed_columns = self.aes_256.getMatrixAsHexString(mixed_columns)
        print(mixed_columns)
        self.assertEqual(mixed_columns,expected_result)

    def test_inverse_mixed_columns(self):
        '''
        This method tests the invers mixed_columns function
        comparing mixed_columns and inverse_mixed_columns
        '''

        example_matrix = '9FDC589D01010101C6C6C6C68E4DA1BC'
        expected_result = 'F20A225C01010101C6C6C6C6DB135345'
        example_matrix = self.aes_256.hexStringToMatrix(example_matrix)
        example_matrix =self.aes_256.flipMatrix(example_matrix)
        print(self.aes_256.getMatrixAsHexString(example_matrix))
        mixed_columns = self.aes_256.inverseMixColumns(example_matrix)
        print("Inverse Mixed Columns")
        mixed_columns = self.aes_256.getMatrixAsHexString(mixed_columns)
        print(mixed_columns)
        self.assertEqual(mixed_columns,expected_result)

    
if __name__ == '__main__':
    unittest.main()