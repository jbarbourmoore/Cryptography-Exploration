import unittest
from CryptographySchemes.SymmetricEncryptionAlgorithms.TripleDataEncryptionStandard import*
from HelperFunctions.IntegerHandler import *

class TDES_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for aes modes
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_tdes_1_ecb(self):
        '''
        This method tests that the tdes works properly in Electronic Codebook (ECB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_Core.pdf
        '''

        unencrypted_given   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        encrypted_given =  "06EDE3D8 2884090A FF322C19 F0518486 73057697 2A666E58 B6C88CF1 07340D3D".replace(" ","")
        key_given = "0123456789ABCDEF23456789ABCDEF010123456789ABCDEF"

        tdes = TDES_ECB(key=key_given, is_hex_key=True)

        self.outputResult(unencrypted_given, encrypted_given, key_given, tdes, "Electronic Cookbook (ECB) Mode")

    def outputResult(self, unencrypted_given:str, encrypted_given:str, key_given:str, tdes:TDES_ECB, mode:str,initialization_vector:str=None):
        if initialization_vector == None:
            encrypted_result = tdes.encryptHexString(unencrypted_given)
            unencrypted_result = tdes.decryptHexString(encrypted_result)
        else:
            encrypted_result = tdes.encryptHexString(unencrypted_given,initialization_vector)
            unencrypted_result = tdes.decryptHexString(encrypted_result,initialization_vector)
        self.assertEqual(unencrypted_result, unencrypted_given)
        self.assertEqual(encrypted_result, encrypted_given)

        print(f"Triple Data Encryption Standard (TDES) In {mode} With Key: {self.presentHex(key_given)}{f" And IV: {self.presentHex(initialization_vector)}" if initialization_vector != None else ""}")
        print(f"Plain Text  : {self.presentHex(unencrypted_given)}  =>  Cypher Text : {self.presentHex(encrypted_result)}")
        print(f"Cypher Text : {self.presentHex(encrypted_result)}  =>  Plain Text  : {self.presentHex(unencrypted_result)}")

    def presentHex(self, hex_string:str):
        hex_handler = IntegerHandler.fromHexString(hex_string, False, len(hex_string*4))
        return hex_handler.getHexString(add_spacing=8)

    def test_tdes_2_cbc(self):
        '''
        This method tests that the tdes implementation works properly in Cypher Block Chaining (CBC) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf
        '''

        unencrypted_given   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        encrypted_given =  "2079C3D5 3AA763E1 93B79E25 69AB5262 51657048 1F25B50F 73C0BDA8 5C8E0DA7".replace(" ","")
        key_given = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"

        tdes = TDES_CBC(key=key_given, is_hex_key=True)

        self.outputResult(unencrypted_given, encrypted_given, key_given, tdes, "Cypher Block Chaining (CBC) Mode", initialization_vector)

    def test_tdes_5_cfb_s64(self):
        '''
        This method tests that the tdes encryption works properly in Cypher Feedback (CFB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf
        '''

        unencrypted_given   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        encrypted_given =  "078BB74E 59CE7ED6 7666DE9C F95EAF3F E9ED6BB4 60F45152 8A5F9FE4 ED710918".replace(" ","")
        key_given = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"
        s = 64

        tdes = TDES_CFB(key=key_given, s=s, is_hex_key=True)
        self.outputResult(unencrypted_given, encrypted_given, key_given, tdes, "Cypher Feedback (CFB) Mode With 64 Bits", initialization_vector)

    def test_tdes_3_cfb_s1(self):
        '''
        This method tests that the tdes encryption works properly in Cypher Feedback (CFB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf
        '''

        unencrypted_given   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        encrypted_given =  "5CB0126B 0CBD982E 68BCDEFD A8055647 85766DAC DF059F88 0E47F037 F69E9418".replace(" ","")
        key_given = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"
        s = 1

        tdes = TDES_CFB(key=key_given, s=s, is_hex_key=True)
        self.outputResult(unencrypted_given, encrypted_given, key_given, tdes, "Cypher Feedback (CFB) Mode With 1 Bit", initialization_vector)

    def test_tdes_4_cfb_s8(self):
        '''
        This method tests that the tdes encryption works properly in Cypher Feedback (CFB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf
        '''

        unencrypted_given   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        encrypted_given =  "07951B72 9DC23AB4 48FC82B4 0372623D C443A4B4 43B6B4A6 6C20D892 236028D5".replace(" ","")
        key_given = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"
        s = 8

        tdes = TDES_CFB(key=key_given, s=s, is_hex_key=True)
        self.outputResult(unencrypted_given, encrypted_given, key_given, tdes, "Cypher Feedback (CFB) Mode With 8 Bits", initialization_vector)


    def test_tdes_6_ofb(self):
        '''
        This method tests that the tdes encryption works properly in Output Feedback (OFB) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf
        '''

        unencrypted_given   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        encrypted_given =  "078BB74E 59CE7ED6 267E1206 92667DA1 A58662D7 E04CBC64 2144D55C 03DB5AEE".replace(" ","")
        
        key_given = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445DF4F9B17"

        tdes = TDES_OFB(key=key_given, is_hex_key=True)
        self.outputResult(unencrypted_given, encrypted_given, key_given, tdes, "Output Feedback (OFB) Mode", initialization_vector)

    def test_tdes_7_ctr(self):
        '''
        This method tests that the tdes implementation works properly in Counter (CTR) mode 
        according to https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf
        '''

        unencrypted_given   =  "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        encrypted_given =  "078BB74E 59CE7ED6 19AA11D2 5004FB65 A03CEDF1 BA0B09BA A3BC81B8 F69C1DA9".replace(" ","")
        key_given = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        initialization_vector = "F69F2445 DF4F9B17".replace(" ","")

        tdes = TDES_CTR(key=key_given, is_hex_key=True)
        self.outputResult(unencrypted_given, encrypted_given, key_given, tdes, "Counter (CTR) Mode", initialization_vector)


if __name__ == '__main__':
    print("- - - - - - - - - - - -")
    print("Testing TDES With Block Cypher Modes Of Operation (ECB, CBC, CFB, OFB and CTR)")
    print("Modes Outlined in NIST SP 800-38A : https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf")
    print("Test Vectors From Nist Cryptographic Standards And Guidelines : https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf")
    unittest.main()