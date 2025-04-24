import unittest
from CryptographySchemes.SymmetricEncryptionAlgorithms.AES_GaloisCounterMode import*
from HelperFunctions.IntegerHandler import *

class AES_GCM_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for aes gcm
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_001_empty_text(self):
        '''
        This method tests AES GCM with an empty plain text

        Test Case 1 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''
        
        # load the test data
        key = "00000000000000000000000000000000"
        initialization_vector = "000000000000000000000000"
        expected_tag = "58e2fccefa7e3061367f1d57a4e7455a".upper()
        expected_cypher = ""
        plain_text = ""
        additional_data=""

        # run the aes 128 gcm on the test data
        aes_128_gcm = AES_GCM_128(key)
        cypher_text,tag = aes_128_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,128)
        authenticated, unencrypted_text = aes_128_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()
    
        # output the test results
        self.print_test_results(1, "AES 128","With Empty Plain Text", key, initialization_vector, additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def test_002_128bit_text(self):
        '''
        This method tests AES GCM with a 128 bit plain text length

        Test Case 2 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''
       
        # load the test data
        key = "00000000000000000000000000000000"
        initialization_vector = "000000000000000000000000"
        plain_text = "00000000000000000000000000000000"
        expected_tag = "ab6e47d42cec13bdf53a67b21257bddf".upper()
        expected_cypher = "0388dace60b6a392f328c2b971b2fe78".upper()
        tag_length = 128
        additional_data=[]

        # run the aes 128 gcm on the test data
        aes_128_gcm = AES_GCM_128(key)
        cypher_text,tag = aes_128_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,tag_length)
        authenticated, unencrypted_text = aes_128_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()

        # output the test results
        self.print_test_results(2, "AES 128", "With 128 Bit Plain Text", key, initialization_vector, additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def test_003_multiple_block_text(self):
        '''
        This method tests AES GCM with a plain text length that is 4 128 bit blocks

        Test Case 3 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''
        
        # load the test data
        key = "feffe9928665731c6d6a8f9467308308".upper()
        initialization_vector = "cafebabefacedbaddecaf888".upper()
        plain_text = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255".upper()
        expected_tag = "4d5c2af327cd64a62cf35abd2ba6fab4".upper()
        expected_cypher = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985".upper()
        tag_length = 128
        additional_data=[]

        # run the aes 128 gcm on the test data
        aes_128_gcm = AES_GCM_128(key)
        cypher_text,tag = aes_128_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,tag_length)
        authenticated, unencrypted_text = aes_128_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()

        # output the test results
        self.print_test_results(3, "AES 128", "With Multi Block Length Plain Text", key, initialization_vector, additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def test_004_incomplete_block_text(self):
        '''
        This method tests AES GCM with a plain text length which is not divisible by 128

        Test Case 4 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''

        # load test data
        key = "feffe9928665731c6d6a8f9467308308".upper()
        initialization_vector = "cafebabefacedbaddecaf888".upper()
        plain_text = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39".upper()
        expected_tag = "5bc94fbc3221a5db94fae95ae7121a47".upper()
        expected_cypher = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091".upper()
        additional_data="feedfacedeadbeeffeedfacedeadbeefabaddad2".upper()
        tag_length = 128

        # run the aes 128 gcm on the test data
        aes_128_gcm = AES_GCM_128(key,is_debug=False)
        cypher_text, tag = aes_128_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,tag_length)
        authenticated, unencrypted_text = aes_128_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()

        # output the test results
        self.print_test_results(4, "AES 128", "With Partial Block Length Plain Text", key, initialization_vector, additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def test_005_short_iv(self):
        '''
        This method tests AES GCM with an initialization vector that is less than 92 bits

        Test Case 5 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''

        # load test data
        key = "feffe9928665731c6d6a8f9467308308".upper()
        initialization_vector = "cafebabefacedbad".upper()
        plain_text = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39".upper()
        expected_tag = "3612d2e79e3b0785561be14aaca2fccb".upper()
        expected_cypher = "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598".upper()
        additional_data="feedfacedeadbeeffeedfacedeadbeefabaddad2".upper()
        tag_length = 128

        # run the aes 128 gcm on the test data
        aes_128_gcm = AES_GCM_128(key,is_debug=False)
        cypher_text, tag = aes_128_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,tag_length)
        authenticated, unencrypted_text = aes_128_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()

        # output the test results
        self.print_test_results(5, "AES 128", "With Short IV", key, initialization_vector, additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)


    def test_006_long_iv(self):
        '''
        This method tests AES GCM with an initialization vector that is longer than 128 bits

        Test Case 6 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''

        # load test data
        key = "feffe9928665731c6d6a8f9467308308".upper()
        initialization_vector = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b".upper()
        plain_text = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39".upper()
        expected_tag = "619cc5aefffe0bfa462af43c1699d050".upper()
        expected_cypher = "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5".upper()
        additional_data="feedfacedeadbeeffeedfacedeadbeefabaddad2".upper()
        tag_length = 128

        # run the aes 128 gcm on the test data
        aes_128_gcm = AES_GCM_128(key,is_debug=False)
        cypher_text, tag = aes_128_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,tag_length)
        authenticated, unencrypted_text = aes_128_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()

        # output the test results
        self.print_test_results(6, "AES 128", "With Long IV", key, initialization_vector, additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def test_007_empty_text(self):
        '''
        This method tests AES 192 GCM with an empty plain text

        Test Case 7 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''
        
        # load the test data
        key = "000000000000000000000000000000000000000000000000"
        initialization_vector = "000000000000000000000000"
        expected_tag = "cd33b28ac773f74ba00ed1f312572435".upper()
        expected_cypher = ""
        plain_text = ""
        additional_data=""

        # run the aes 192 gcm on the test data
        aes_192_gcm = AES_GCM_192(key)
        cypher_text, tag = aes_192_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,128)
        authenticated, unencrypted_text = aes_192_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()
    
        # output the test results
        self.print_test_results(7, "AES 192", "With Empty Plain Text", key, initialization_vector,additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def test_008_single_block_text(self):
        '''
        This method tests AES 192 GCM with a single block of 128 bits plain text

        Test Case 8 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''
        
        # load the test data
        key = "000000000000000000000000000000000000000000000000"
        initialization_vector = "000000000000000000000000"
        expected_tag = "2ff58d80033927ab8ef4d4587514f0fb".upper()
        expected_cypher = "98e7247c07f0fe411c267e4384b0f600".upper()
        plain_text = "00000000000000000000000000000000"
        additional_data=""

        # run the aes 192 gcm on the test data
        aes_192_gcm = AES_GCM_192(key)
        cypher_text, tag = aes_192_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,128)
        authenticated, unencrypted_text = aes_192_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()
    
        # output the test results
        self.print_test_results(8, "AES 192", "With 128 Bit Plain Text", key, initialization_vector,additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def test_013_empty_text(self):
        '''
        This method tests AES 256 GCM with an empty plain text

        Test Case 13 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''
        
        # load the test data
        key = "0000000000000000000000000000000000000000000000000000000000000000"
        initialization_vector = "000000000000000000000000"
        expected_tag = "530f8afbc74536b9a963b4f1c4cb738b".upper()
        expected_cypher = ""
        plain_text = ""
        additional_data=""

        # run the aes 256 gcm on the test data
        aes_256_gcm = AES_GCM_256(key)
        cypher_text, tag = aes_256_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,128)
        authenticated, unencrypted_text = aes_256_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()
    
        # output the test results
        self.print_test_results(13, "AES 256", "With Empty Plain Text", key, initialization_vector,additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def test_014_single_block_text(self):
        '''
        This method tests AES 256 GCM with a single block of 128 bits plain text

        Test Case 14 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
        https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        '''
        
        # load the test data
        key = "0000000000000000000000000000000000000000000000000000000000000000"
        initialization_vector = "000000000000000000000000"
        expected_tag = "d0d1c8a799996bf0265b98b5d48ab919".upper()
        expected_cypher = "cea7403d4d606b6e074ec5d3baf39d18".upper()
        plain_text = "00000000000000000000000000000000"
        additional_data=""

        # run the aes 256 gcm on the test data
        aes_256_gcm = AES_GCM_256(key)
        cypher_text, tag = aes_256_gcm.authenticatedEncryption(initialization_vector,plain_text,additional_data,128)
        authenticated, unencrypted_text = aes_256_gcm.authenticatedDecryption(initialization_vector,cypher_text,additional_data,tag)
        if authenticated:   
            unencrypted_text = unencrypted_text.getHexString()
    
        # output the test results
        self.print_test_results(14, "AES 256", "With 128 Bit Plain Text", key, initialization_vector,additional_data, plain_text, cypher_text, tag, authenticated, unencrypted_text)

        # verify that the test's results are as expected
        self.verify_test_results(plain_text, expected_tag, expected_cypher, cypher_text, tag, authenticated, unencrypted_text)

    def verify_test_results(self, plain_text, expected_tag, expected_cypher, cypher_text:GCM_Block, tag:GCM_Block, authenticated, unencrypted_text):
        self.assertEqual(cypher_text.getHexString(), expected_cypher)
        self.assertEqual(tag.getHexString(), expected_tag)
        self.assertTrue(authenticated)
        self.assertEqual(unencrypted_text, plain_text)

    def print_test_results(self, i, encryption_algorithm:str, test_description:str, key:str, initialization_vector:str, additional_data:str, plain_text:str, cypher_text:GCM_Block, tag:GCM_Block, authenticated:bool, unencrypted_text:str):
        print(f"Test {i}: Using {encryption_algorithm} Galois/Counter Mode {test_description}")
        print(f"Key            : {key}")
        print(f"IV             : {initialization_vector}")
        print(f"Additional Data: {additional_data}")
        print(f"Plain Text     : {plain_text}")
        print(f"Tag            : {tag.getHexString()}")
        print(f"Encrypted Text : {cypher_text.getHexString()}")
        print(f"Authenticate   : {"Tag successfully authenticated" if authenticated else "Tag failed authentication"}")
        print(f"Decrypted Text : {unencrypted_text}")


if __name__ == '__main__':
    print("Testing AES With Galois/Counter Mode")
    print("https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf")
    unittest.main()