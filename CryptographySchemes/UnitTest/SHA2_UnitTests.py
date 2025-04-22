import unittest
from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm2 import *

class TestCase():
    '''
    This class holds the information for a single test case for sha2
    '''

    def __init__(self, input:str, bytes: int, expected_result:str):
        '''
        This method initializes a sha 2 test case with an input, size in bytes and the expected hex digest

        Parameters :
            input : str
                The input for the sha function as a hex string
            bytes : int
                The length of the input as the number of bytes
            expected_result : str
                The hex string for the expected result of the hash function
        '''
        
        self.input = input.replace(" ","").upper()
        self.bytes = bytes
        self.expected_result = expected_result

    def runTest(self, test_case:unittest.TestCase, hash:SHA1, digest_length:int):
        '''
        This method runs the sha2 test for a certain test case, with a hash function and set digest length

        Parameters :
            test_case : unittest.TestCase
                The test case this test is being run for
            hash : SHA1
                The sha variant that this test is being run using
            digest_length : int
                The length in bits of the digest for this sha variant
        '''

        if len(self.input) > 50:
            display_input = self.input[0:20]+"..."+self.input[-21:]
        else :
            display_input = self.input
        print(f"Hashing \"{display_input}\", {self.bytes} bytes")
        hash = hash.hashAHexString(self.input,self.bytes)
        expected_handler = IntegerHandler.fromHexString(self.expected_result,False,digest_length)
        print(f"Expected hash : {expected_handler.getHexString(add_spacing=8)}")
        print(f"Actual hash   : {hash.getHexString(add_spacing=8)}")
        test_case.assertEqual(hash.getHexString(),expected_handler.getHexString())

class SHA3_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for SHA 2
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_sha224(self):
        '''
        This method tests the implementation of sha 224 against known hash values
        '''

        print("Testing SHA 224 Against Known Input \nFrom https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf")
        sha224_tests = []
        sha224_tests.append(TestCase("FF",1,"e33f9d75 e6ae1369 dbabf81b 96b4591a e46bba30 b591a6b6 c62542b5"))
        sha224_tests.append(TestCase("e5e09924",4,"fd19e746 90d29146 7ce59f07 7df31163 8f1c3a46 e510d0e4 9a67062d"))
        sha224_tests.append(TestCase("00"*56,56,"5c3e25b6 9d0ea26f 260cfae8 7e23759e 1eca9d1e cc9fbf3c 62266804"))
        sha224_tests.append(TestCase("99"*1005,1005,"cb00ecd0 3788bf6c 0908401e 0eb053ac 61f35e7e 20a2cfd7 bd96d640"))

        for test in sha224_tests:
            test.runTest(self, sha224, 224)
    
    def test_sha256(self):
        '''
        This method tests the implementation of sha 256 against known hash values
        '''

        print("Testing SHA 256 Against Known Input \nFrom https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf")
        sha256_tests = []
        sha256_tests.append(TestCase("BD",1,"68325720 aabd7c82 f30f554b 313d0570 c95accbb 7dc4b5aa e11204c0 8ffe732b"))
        sha256_tests.append(TestCase("c98c8e55",4,"7abc22c0 ae5af26c e93dbb94 433a0e0b 2e119d01 4f8e7f65 bd56c61c cccd9504"))
        sha256_tests.append(TestCase("00"*56,56,"d4817aa5 497628e7 c77e6b60 6107042b bba31308 88c5f47a 375e6179 be789fbb"))
        sha256_tests.append(TestCase("55"*1005,1005,"f4d62dde c0f3dd90 ea1380fa 16a5ff8d c4c54b21 740650f2 4afc4120 903552b0"))

        for test in sha256_tests:
            test.runTest(self, sha256, 256)

    def test_sha384(self):
        '''
        This method tests the implementation of sha 384 against known hash values
        '''

        print("Testing SHA 384 Against Known Input \nFrom https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf")
        sha384_tests = []
        sha384_tests.append(TestCase("",0," 38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da 274edebfe76f65fb d51ad2f14898b95b "))
        sha384_tests.append(TestCase("00"*111,111,"435770712c611be7 293a66dd0dc8d145 0dc7ff7337bfe115 bf058ef2eb9bed09 cee85c26963a5bcc 0905dc2df7cc6a76 "))
        sha384_tests.append(TestCase("00"*112,112,"3e0cbf3aee0e3aa7 0415beae1bd12dd7 db821efa446440f1 2132edffce76f635 e53526a111491e75 ee8e27b9700eec20 "))
        sha384_tests.append(TestCase("55"*1005,1005,"1bb8e256da4a0d1e 87453528254f223b 4cb7e49c4420dbfa 766bba4adba44eec a392ff6a9f565bc3 47158cc970ce44ec "))

        for test in sha384_tests:
            test.runTest(self, sha384, 384)

    def test_sha512(self):
        '''
        This method tests the implementation of sha 512 against known hash values
        '''

        print("Testing SHA 512 Against Known Input \nFrom https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf")
        sha512_tests = []
        sha512_tests.append(TestCase("",0,"cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e"))
        sha512_tests.append(TestCase("00"*111,111,"77ddd3a542e530fd 047b8977c657ba6c e72f1492e360b2b2 212cd264e75ec038 82e4ff0525517ab4 207d14c70c2259ba 88d4d335ee0e7e20 543d22102ab1788c"))
        sha512_tests.append(TestCase("00"*112,112,"2be2e788c8a8adea a9c89a7f78904cac ea6e39297d75e057 3a73c756234534d6 627ab4156b48a665 7b29ab8beb733340 40ad39ead81446bb 09c70704ec707952"))
        sha512_tests.append(TestCase("55"*1005,1005,"59f5e54fe299c6a8 764c6b199e44924a 37f59e2b56c3ebad 939b7289210dc8e4 c21b9720165b0f4d 4374c90f1bf4fb4a 5ace17a116179801 5052893a48c3d161"))

        for test in sha512_tests:
            test.runTest(self, sha512, 512)
   
if __name__ == '__main__':
    unittest.main()