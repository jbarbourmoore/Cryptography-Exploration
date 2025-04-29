import unittest
from CryptographySchemes.SymmetricEncryptionAlgorithms.AES_ModesOfOperation import*
from HelperFunctions.IntegerHandler import *

class TDES_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for aes modes
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_aes256_1_ecb(self):
        '''
        This method tests that the aes256 implementation works properly in Electronic Codebook (ECB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_Core.pdf
        '''

        unencrypted_given =["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        encrypted_given  = ["F3EED1BDB5D2A03C064B5A7E3DB181F8", 
                            "591CCB10D410ED26DC5BA74A31362870",
                            "B6ED21B99CA6F4F9F153E7B1BEAFED1D",
                            "23304B7A39F9F3FF067D8D8F9E24ECC7"]
        key_given = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4".replace(" ","")

        aes = AES_ECB_256(key=key_given)

        self.outputResult(unencrypted_given, encrypted_given, key_given, aes, "Electronic Cookbook (ECB) Mode")

    def outputResult(self, unencrypted_given:str, encrypted_given:str, key_given:str, aes:AES_ECB_128, mode:str, initialization_vector:str=None):
        if initialization_vector == None:
            encrypted_result = aes.encryptHexList(unencrypted_given)
            unencrypted_result = aes.decryptHexList(encrypted_result)
        else:
            encrypted_result = aes.encryptHexList(unencrypted_given,initialization_vector)
            unencrypted_result = aes.decryptHexList(encrypted_result,initialization_vector)
        self.assertEqual(unencrypted_result, unencrypted_given)
        self.assertEqual(encrypted_result, encrypted_given)

        print(f"Advanced Encryption Standard (AES-256) In {mode} With Key: {self.presentHex(key_given)}{f" And IV: {self.presentHex(initialization_vector)}" if initialization_vector != None else ""}")
        print(f"Plain Text     : {self.presentHexList(unencrypted_given)}")
        print(f"Cypher Text    : {self.presentHexList(encrypted_result)}")
        print(f"Decrypted Text : {self.presentHexList(unencrypted_result)}")

    def presentHex(self, hex_string:str):
        hex_handler = IntegerHandler.fromHexString(hex_string, False, len(hex_string*4))
        return hex_handler.getHexString(add_spacing=16)
    
    def presentHexList(self, hex_list:list[str]):
        hex_string = ""
        for item in hex_list:
            hex_string += item
        return self.presentHex(hex_string)

    def test_aes_2_cbc(self):
        '''
        This method tests that the AES implementation works properly in Cypher Block Chaining (CBC) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf
        '''

        unencrypted_given =["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        encrypted_given = ['F58C4C04D6E5F1BA779EABFB5F7BFBD6',
                            '9CFC4E967EDB808D679F777BC6702C7D',
                            '39F23369A9D9BACFA530E26304231461',
                            'B2EB05E2C39BE9FCDA6C19078C6A9D1B']
        key_given = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4".replace(" ","")
        initialization_vector = "000102030405060708090a0b0c0d0e0f"

        aes = AES_CBC_256(key=key_given)

        self.outputResult(unencrypted_given, encrypted_given, key_given, aes, "Cypher Block Chaining (CBC) Mode", initialization_vector)

    def test_aes_5_cfb_s64(self):
        '''
        This method tests that the AES implementation works properly in Cypher Feedback (CFB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf
        '''

        unencrypted_given =["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        encrypted_given  = ['DC7E84BFDA79164B5354B1128A039EC7',
                            '506B65DA6782CDFA2EB7F5711565FC14',
                            '19345A7D5EED18808BE1D3864AE3E0DC',
                            'F435AE891B3032834EE359D40E86AF01']
        key_given = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4".replace(" ","")
        initialization_vector = "000102030405060708090a0b0c0d0e0f"
        s = 64

        aes = AES_CFB_256(key=key_given, s=s)
        self.outputResult(unencrypted_given, encrypted_given, key_given, aes, "Cypher Feedback (CFB) Mode With 64 Bits", initialization_vector)

    def test_aes_3_cfb_s1(self):
        '''
        This method tests that the AES implementation works properly in Cypher Feedback (CFB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf
        '''

        unencrypted_given =["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        encrypted_given  = ['9029C2BA5B7D440B562023DEEC3DE592',
                            '8E4FD76528E8CC3A548A0A49EDF001D0',
                            'D163541E6192479F27FE19A4F75D600D',
                            'E033103F1D2BC1794CE1CF1464C0603B']
        key_given = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4".replace(" ","")
        initialization_vector = "000102030405060708090a0b0c0d0e0f"
        s = 1

        aes = AES_CFB_256(key=key_given, s=s)
        self.outputResult(unencrypted_given, encrypted_given, key_given, aes, "Cypher Feedback (CFB) Mode With 1 Bit", initialization_vector)

    def test_aes_4_cfb_s8(self):
        '''
        This method tests that the AES implementation works properly in Cypher Feedback (CFB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ModesA_All.pdf
        '''

        unencrypted_given =["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]
        encrypted_given = ['DC1F1A8520A64DB55FCC8AC554844E88',
                            '9700ADC6E10C63CF2D8CD2D8CE668F3E',
                            'B9191719C47444FB43BFF9B9883C2CD0',
                            '51120402009F974998C89D195722A75B']
        key_given = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4".replace(" ","")
        initialization_vector = "000102030405060708090a0b0c0d0e0f"
        s = 8

        aes = AES_CFB_256(key=key_given, s=s)
        self.outputResult(unencrypted_given, encrypted_given, key_given, aes, "Cypher Feedback (CFB) Mode With 8 Bits", initialization_vector)


    def test_aes_6_ofb(self):
        '''
        This method tests that the AES implementation works properly in Output Feedback (OFB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ModesA_All.pdf
        '''

        unencrypted_given =["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]        
        encrypted_given =  ['DC7E84BFDA79164B7ECD8486985D3860',
                            '4FEBDC6740D20B3AC88F6AD82A4FB08D',
                            '71AB47A086E86EEDF39D1C5BBA97C408',
                            '0126141D67F37BE8538F5A8BE740E484']
        
        key_given = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4".replace(" ","")
        initialization_vector = "000102030405060708090a0b0c0d0e0f"

        aes = AES_OFB_256(key=key_given)
        self.outputResult(unencrypted_given, encrypted_given, key_given, aes, "Output Feedback (OFB) Mode", initialization_vector)

    def test_tdes_7_ctr(self):
        '''
        This method tests that the AES implementation works properly in Counter (CTR) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ModesA_All.pdf
        '''

        unencrypted_given =["6BC1BEE22E409F96E93D7E117393172A",
                            "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                            "30C81C46A35CE411E5FBC1191A0A52EF",
                            "F69F2445DF4F9B17AD2B417BE66C3710"]    
        encrypted_given =  ['601EC313775789A5B7A7F504BBF3D228',
                            'F443E3CA4D62B59ACA84E990CACAF5C5',
                            '2B0930DAA23DE94CE87017BA2D84988D',
                            'DFC9C58DB67AADA613C2DD08457941A6']
        key_given = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4".replace(" ","")
        initialization_vector = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".replace(" ","")

        aes = AES_CTR_256(key=key_given)
        self.outputResult(unencrypted_given, encrypted_given, key_given, aes, "Counter (CTR) Mode", initialization_vector)


if __name__ == '__main__':
    print("- - - - - - - - - - - -")
    print("Testing AES With Block Cypher Modes Of Operation (ECB, CBC, CFB, OFB and CTR)")
    print("Modes Outlined in NIST SP 800-38A : https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf")
    print("Test Vectors From Nist Cryptographic Standards And Guidelines : https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ModesA_All.pdf")
    unittest.main()