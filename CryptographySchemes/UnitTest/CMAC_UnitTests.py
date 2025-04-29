import unittest
from CryptographySchemes.MessageAuthenticationCodes.CMAC import *
from HelperFunctions.IntegerHandler import *

class CMAS_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for CMAC
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_3des_no_message(self):
        '''
        This method tests CMAC with the 3DES block cypher and an empty message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
        '''

        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        plain_text = ""
        tag_length = 64

        expected_tag = "7DB0D37D F936C550".replace(" ","")
        expected_k2 = "3AE9CE72 662F2D9B".replace(" ","")

        cmac = CMAC_3DES(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k2.getHexString(), expected_k2)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With 3DES And An Empty Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (2)  : {k2.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")


    def test_3des_k1k3match_no_message(self):
        '''
        This method tests CMAC with the 3DES block cypher and an empty message with k1 and k3 matching

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
        '''

        key = "01234567 89ABCDEF 23456789 ABCDEF01 01234567 89ABCDEF".replace(" ","")
        plain_text = ""
        tag_length = 64

        expected_tag = "79CE52A7 F786A960".replace(" ","")
        expected_k2 = "1BA596F4 7B1111B2".replace(" ","")

        cmac = CMAC_3DES(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)

        self.assertEqual(k2.getHexString(), expected_k2)
        self.assertEqual(tag, expected_tag)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        print("Testing CMAC With 3DES And An Empty Message With K1 and K3 Matching")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (2)  : {k2.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")


    def test_3des_2block_message(self):
        '''
        This method tests CMAC with the 3DES block cypher and a 2 block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
        '''

        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A".replace(" ","")
        tag_length = 64

        expected_tag = "30239CF1 F52E6609".replace(" ","")
        expected_subkey = "9D74E739 331796C0".replace(" ","")

        cmac = CMAC_3DES(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k1.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With 3DES And An A Two Block Long Plain Text")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (1)  : {k1.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")


    def test_3des_k1k3match_2block_message(self):
        '''
        This method tests CMAC with the 3DES block cypher and a 2 block message with k1 and k3 matching

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
        '''

        key = "01234567 89ABCDEF 23456789 ABCDEF01 01234567 89ABCDEF".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A".replace(" ","")
        tag_length = 64

        expected_tag = "CC18A0B7 9AF2413B".replace(" ","")
        expected_subkey = "0DD2CB7A 3D8888D9".replace(" ","")

        cmac = CMAC_3DES(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k1.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With 3DES And An A Two Block Long Plain Text With K1 And K3 Matching")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (1)  : {k1.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

        
    def test_3des_2_and_half_block_message(self):
        '''
        This method tests CMAC with the 3DES block cypher and a 2.5 block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
        '''

        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57".replace(" ","")
        tag_length = 64

        expected_tag = "6C9F3EE4 923F6BE2".replace(" ","")
        expected_subkey = "3AE9CE72 662F2D9B".replace(" ","")

        cmac = CMAC_3DES(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k2.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With 3DES And An A Two And A Half Block Long Plain Text")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (2)  : {k2.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")


    def test_3des_k1k3match_2_and_half_block_message(self):
        '''
        This method tests CMAC with the 3DES block cypher and a 2.5 block message with k1 and k3 matching

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
        '''

        key = "01234567 89ABCDEF 23456789 ABCDEF01 01234567 89ABCDEF".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57".replace(" ","")
        tag_length = 64

        expected_tag = "C06D377E CD101969".replace(" ","")
        expected_subkey = "1BA596F4 7B1111B2".replace(" ","")

        cmac = CMAC_3DES(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k2.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With 3DES And An A Two And A Half Block Long Plain Text With K1 And K3 Matching")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (2)  : {k2.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")


    def test_3des_4_block_message(self):
        '''
        This method tests CMAC with the 3DES block cypher and a 2.5 block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
        '''

        key = "01234567 89ABCDEF 23456789 ABCDEF01 456789AB CDEF0123".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        tag_length = 64

        expected_tag = "99429BD0 BF7904E5".replace(" ","")
        expected_subkey = "9D74E739 331796C0".replace(" ","")

        cmac = CMAC_3DES(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k1.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With 3DES And A Four Block Long Plain Text")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (1)  : {k1.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    
    def test_3des_k1k3match_4_block_message(self):
        '''
        This method tests CMAC with the 3DES block cypher and a 4 block message with k1 and k3 matching

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
        '''

        key = "01234567 89ABCDEF 23456789 ABCDEF01 01234567 89ABCDEF".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51".replace(" ","")
        tag_length = 64

        expected_tag = "9CD33580 F9B64DFB".replace(" ","")
        expected_subkey = "0DD2CB7A 3D8888D9".replace(" ","")

        cmac = CMAC_3DES(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k1.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With 3DES And A Four Block Long Plain Text With K1 and K3 Matching")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (1)  : {k1.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes128_no_message(self):
        '''
        This method tests CMAC with the AES 128 block cypher and an empty message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "2B7E1516 28AED2A6 ABF71588 09CF4F3C".replace(" ","")
        plain_text = ""
        tag_length = 128

        expected_tag = "BB1D6929 E9593728 7FA37D12 9B756746".replace(" ","")
        expected_k2 = "F7DDAC30 6AE266CC F90BC11E E46D513B".replace(" ","")

        cmac = CMAC_AES128(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k2.getHexString(), expected_k2)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 128 And An Empty Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (2)  : {k2.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes128_1block_message(self):
        '''
        This method tests CMAC with the AES 128 block cypher and a single block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "2B7E1516 28AED2A6 ABF71588 09CF4F3C".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A".replace(" ","")
        tag_length = 128

        expected_tag = "070A16B4 6B4D4144 F79BDD9D D04A287C".replace(" ","")
        expected_subkey = "FBEED618 35713366 7C85E08F 7236A8DE".replace(" ","")

        cmac = CMAC_AES128(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k1.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 128 And A Single Block Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (1)  : {k1.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes128_1andquarter_block_message(self):
        '''
        This method tests CMAC with the AES 128 block cypher and a one and a quarter block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "2B7E1516 28AED2A6 ABF71588 09CF4F3C".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57".replace(" ","")
        tag_length = 128

        expected_tag = "7D85449E A6EA19C8 23A7BF78 837DFADE".replace(" ","")
        expected_subkey = "F7DDAC30 6AE266CC F90BC11E E46D513B".replace(" ","")

        cmac = CMAC_AES128(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k2.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 128 And A One And A Quarter Block Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (2)  : {k2.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes128_4_block_message(self):
        '''
        This method tests CMAC with the AES 128 block cypher and a four block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "2B7E1516 28AED2A6 ABF71588 09CF4F3C".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710".replace(" ","")
        tag_length = 128

        expected_tag = "51F0BEBF 7E3B9D92 FC497417 79363CFE".replace(" ","")
        expected_subkey = "FBEED618 35713366 7C85E08F 7236A8DE".replace(" ","")

        cmac = CMAC_AES128(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k1.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 128 And A Four Block Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (1)  : {k1.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes192_no_message(self):
        '''
        This method tests CMAC with the AES 192 block cypher and an empty message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B".replace(" ","")
        plain_text = ""
        tag_length = 128

        expected_tag = "D17DDF46 ADAACDE5 31CAC483 DE7A9367".replace(" ","")
        expected_k2 = "8914B639 26A2964E 7DCC873B A9B5452C".replace(" ","")

        cmac = CMAC_AES192(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k2.getHexString(), expected_k2)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 192 And An Empty Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (2)  : {k2.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes192_1block_message(self):
        '''
        This method tests CMAC with the AES 192 block cypher and a single block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A".replace(" ","")
        tag_length = 128

        expected_tag = "9E99A7BF 31E71090 0662F65E 617C5184".replace(" ","")
        expected_subkey = "448A5B1C 93514B27 3EE6439D D4DAA296".replace(" ","")

        cmac = CMAC_AES192(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k1.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 192 And A Single Block Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (1)  : {k1.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes192_1andquarter_block_message(self):
        '''
        This method tests CMAC with the AES 192 block cypher and a one and a quarter block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57".replace(" ","")
        tag_length = 128

        expected_tag = "3D75C194 ED960704 44A9FA7E C740ECF8".replace(" ","")
        expected_subkey = "8914B639 26A2964E 7DCC873B A9B5452C".replace(" ","")

        cmac = CMAC_AES192(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k2.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 192 And A One And A Quarter Block Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (2)  : {k2.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes192_4_block_message(self):
        '''
        This method tests CMAC with the AES 192 block cypher and a four block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710".replace(" ","")
        tag_length = 128

        expected_tag = "A1D5DF0E ED790F79 4D775896 59F39A11".replace(" ","")
        expected_subkey = "448A5B1C 93514B27 3EE6439D D4DAA296".replace(" ","")

        cmac = CMAC_AES192(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k1.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 192 And A Four Block Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (1)  : {k1.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes256_no_message(self):
        '''
        This method tests CMAC with the AES 256 block cypher and an empty message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4".replace(" ","")
        plain_text = ""
        tag_length = 128

        expected_tag = "028962F6 1B7BF89E FC6B551F 4667D983".replace(" ","")
        expected_k2 = "95A3DA06 533DDB58 5D353301 0C42A0D9".replace(" ","")

        cmac = CMAC_AES256(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k2.getHexString(), expected_k2)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 256 And An Empty Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (2)  : {k2.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes256_1block_message(self):
        '''
        This method tests CMAC with the 256 192 block cypher and a single block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A".replace(" ","")
        tag_length = 128

        expected_tag = "28A7023F 452E8F82 BD4BF28D 8C37C35C".replace(" ","")
        expected_subkey = "CAD1ED03 299EEDAC 2E9A9980 8621502F".replace(" ","")

        cmac = CMAC_AES256(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k1.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 256 And A Single Block Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (1)  : {k1.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes256_1andquarter_block_message(self):
        '''
        This method tests CMAC with the AES 256 block cypher and a one and a quarter block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57".replace(" ","")
        tag_length = 128

        expected_tag = "156727DC 0878944A 023C1FE0 3BAD6D93".replace(" ","")
        expected_subkey = "95A3DA06 533DDB58 5D353301 0C42A0D9".replace(" ","")

        cmac = CMAC_AES256(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k2.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 256 And A One And A Quarter Block Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (2)  : {k2.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

    def test_aes256_4_block_message(self):
        '''
        This method tests CMAC with the AES 256 block cypher and a four block message

        CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
        Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        '''

        key = "603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4".replace(" ","")
        plain_text = "6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710".replace(" ","")
        tag_length = 128

        expected_tag = "E1992190 549F6ED5 696A2C05 6C315410".replace(" ","")
        expected_subkey = "CAD1ED03 299EEDAC 2E9A9980 8621502F".replace(" ","")

        cmac = CMAC_AES256(key=key)
        k1, k2 = cmac.subkeyGeneration()
        tag = cmac.cmacGeneration(plain_text, tag_length)
        verified = cmac.cmacVerification(plain_text, tag_length, tag)

        self.assertTrue(verified)
        self.assertEqual(k1.getHexString(), expected_subkey)
        self.assertEqual(tag, expected_tag)

        print("Testing CMAC With AES 256 And A Four Block Message")
        print(f"Message     : \"{plain_text}\"")
        print(f"Subkey (1)  : {k1.getHexString()}")
        print(f"Tag         : {tag}")
        print(f"Verified    : {"The tag was successfully verified" if verified else "The tag failed verification"}")

if __name__ == '__main__':
    print("- - - - - - - - - - - -")
    print("Testing CMAC")
    print("CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf")
    print("Test Vectors From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf")
    unittest.main()