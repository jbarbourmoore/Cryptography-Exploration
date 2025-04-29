import unittest
from CryptographySchemes.SymmetricEncryptionAlgorithms.AES_GaloisCounterMode import*
from HelperFunctions.IntegerHandler import *

class AES_GCM_Examples_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for aes gcm
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_015_multi_block_text(self):
        '''
        This method tests AES 256 GCM with a multiple blocks of 128 bits plain text

        Test Case 15 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''
        
        # load the test data
        key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308".upper()
        initialization_vector = "cafebabefacedbaddecaf888".upper()
        expected_tag = "b094dac5d93471bdec1a502270e3cc6c".upper()
        expected_cypher = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad".upper()
        plain_text = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255".upper()
        additional_data="".upper()

        # run the aes 256 gcm on the test data
        aes_256_gcm = AES_GCM_256(key)
        cypher_text, tag = aes_256_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,128)
        authenticated, unencrypted_text = aes_256_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()
    
        # output the test results
        self.print_test_results(15, "AES 256", "With Multi Block Length Plain Text", key, initialization_vector,additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def test_016_partial_block_text(self):
        '''
        This method tests AES 256 GCM with a partial block of 128 bits plain text

        Test Case 16 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''
        
        # load the test data
        key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308".upper()
        initialization_vector = "cafebabefacedbaddecaf888".upper()
        expected_tag = "76fc6ece0f4e1768cddf8853bb2d551b".upper()
        expected_cypher = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662".upper()
        plain_text = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39".upper()
        additional_data="feedfacedeadbeeffeedfacedeadbeefabaddad2".upper()

        # run the aes 256 gcm on the test data
        aes_256_gcm = AES_GCM_256(key)
        cypher_text, tag = aes_256_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,128)
        authenticated, unencrypted_text = aes_256_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()
    
        # output the test results
        self.print_test_results(16, "AES 256", "With Partial Block Length Plain Text", key, initialization_vector,additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def test_017_short_iv(self):
        '''
        This method tests AES 256 GCM with an initilization vector shorter than 92 bits

        Test Case 17 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''
        
        # load the test data
        key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308".upper()
        initialization_vector = "cafebabefacedbad".upper()
        expected_tag = "3a337dbf46a792c45e454913fe2ea8f2".upper()
        expected_cypher = "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f".upper()
        plain_text = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39".upper()
        additional_data="feedfacedeadbeeffeedfacedeadbeefabaddad2".upper()

        # run the aes 256 gcm on the test data
        aes_256_gcm = AES_GCM_256(key)
        cypher_text, tag = aes_256_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,128)
        authenticated, unencrypted_text = aes_256_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()
    
        # output the test results
        self.print_test_results(17, "AES 256", "With Short IV", key, initialization_vector,additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def test_018_long_iv(self):
        '''
        This method tests AES 256 GCM with an initilization vector longer than 128 bits

        Test Case 18 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''
        
        # load the test data
        key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308".upper()
        initialization_vector = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b".upper()
        expected_tag = "a44a8266ee1c8eb0c8b5d4cf5ae9f19a".upper()
        expected_cypher = "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f".upper()
        plain_text = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39".upper()
        additional_data="feedfacedeadbeeffeedfacedeadbeefabaddad2".upper()

        # run the aes 256 gcm on the test data
        aes_256_gcm = AES_GCM_256(key)
        cypher_text, tag = aes_256_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,128)
        authenticated, unencrypted_text = aes_256_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()
    
        # output the test results
        self.print_test_results(18, "AES 256", "With Long IV", key, initialization_vector,additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def verify_test_results(self, plain_text, expected_tag, expected_cypher, cypher_text:GCM_Block, tag:GCM_Block, authenticated, unencrypted_text):
        self.assertEqual(cypher_text.getHexString(), expected_cypher)
        self.assertEqual(tag.getHexString(), expected_tag)
        self.assertTrue(authenticated)
        self.assertEqual(unencrypted_text, plain_text)

    def presentHex(self, hex_string:str):
        hex_handler = IntegerHandler.fromHexString(hex_string, False, len(hex_string*4))
        return hex_handler.getHexString(add_spacing=8)
        
    def print_test_results(self, i, encryption_algorithm:str, test_description:str, key:str, initialization_vector:str, additional_data:str, plain_text:str, cypher_text:GCM_Block, tag:GCM_Block, authenticated:bool, unencrypted_text:str):
        print(f"Test {i}. Using {encryption_algorithm} Galois/Counter Mode {test_description} With Key: {self.presentHex(key)}")
        print(f"IV              : {self.presentHex(initialization_vector)}")
        print(f"Additional Data : {self.presentHex(additional_data)}")
        print(f"Plain Text      : {self.presentHex(plain_text)}")
        print(f"Tag             : {self.presentHex(tag.getHexString())}")
        print(f"Encrypted Text  : {self.presentHex(cypher_text.getHexString())}")
        print(f"Authenticate    : {"Tag successfully authenticated" if authenticated else "Tag failed authentication"}")
        print(f"Decrypted Text  : {self.presentHex(unencrypted_text)}")


if __name__ == '__main__':
    print("- - - - - - - - - - - -")
    print("Testing AES With Galois/Counter Mode")
    print("Test Vectors Are From https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf")
    unittest.main()