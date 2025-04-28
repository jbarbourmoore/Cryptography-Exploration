import unittest
from CryptographySchemes.SymmetricEncryptionAlgorithms.CMAC import *
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

if __name__ == '__main__':
    print("- - - - - - - - - - - -")
    print("Testing CMAC")
    print("CMAC is Laid Out In Nist SP 800-38b : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf")
    print("Test Vectors From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf")
    unittest.main()