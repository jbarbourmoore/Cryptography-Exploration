import unittest
from CryptographySchemes.SymmetricEncryptionAlgorithms.DataEncryptionStandard import *

class DES_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for des
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_des_cypher(self):
        '''
        This method tests the data encryption standard cypher 

        Test vectors are from page 28 of "Validating the correctness of hardware implementations of the NBS data encryption standard" by Jason Gait in 1977
        https://archive.org/details/validatingcorrec00gait/page/28/mode/2up
        '''

        hex_to_encrypt   = ["95F8A5E5DD31D900",
                            "DD7F121CA5015619",
                            "2E8653104F3834EA",
                            "4BD388FF6CD81D4F",
                            "20B9E767B2FB1456",
                            "55579380D77138EF",
                            "6CC5DEFAAF04512F",
                            "0D9F279BA5D87260"]
        expected_results = ["8000000000000000",
                            "4000000000000000",
                            "2000000000000000",
                            "1000000000000000",
                            "0800000000000000",
                            "0400000000000000",
                            "0200000000000000",
                            "0100000000000000"]
        
        hex_key ="0101010101010101"
        des = DataEncryptionStandard(hex_key, is_hex_key=True)
        for i in range(0,len(hex_to_encrypt)):
            encrypted = des.encryptHexMessage(hex_to_encrypt[i])[0]
            encrypted = IntegerHandler.fromBitString(encrypted,False,64).getHexString()
            self.assertEqual(encrypted,expected_results[i])
            print(f"Plain Text  : {hex_to_encrypt[i]}  ->  Cypher Text : {encrypted} (expected was {expected_results[i]})")


    def test_des_inverse_cypher(self):
        '''
        This method tests the data encryption standard inverse cypher 

        Test vectors are from page 28 of "Validating the correctness of hardware implementations of the NBS data encryption standard" by Jason Gait in 1977
        https://archive.org/details/validatingcorrec00gait/page/28/mode/2up
        '''

        expected_results = ["95F8A5E5DD31D900",
                            "DD7F121CA5015619",
                            "2E8653104F3834EA",
                            "4BD388FF6CD81D4F",
                            "20B9E767B2FB1456",
                            "55579380D77138EF",
                            "6CC5DEFAAF04512F",
                            "0D9F279BA5D87260"]
        hex_to_decrypt   = ["8000000000000000",
                            "4000000000000000",
                            "2000000000000000",
                            "1000000000000000",
                            "0800000000000000",
                            "0400000000000000",
                            "0200000000000000",
                            "0100000000000000"]
        hex_key ="0101010101010101"
        des = DataEncryptionStandard(hex_key, is_hex_key=True)
        for i in range(0,len(hex_to_decrypt)):
            decrypted = des.decryptHexMessage([IntegerHandler.fromHexString(hex_to_decrypt[i],False,64).getBitString()])
            self.assertEqual(decrypted,expected_results[i])
            print(f"Cypher Text : {hex_to_decrypt[i]}  ->  Plain Text : {decrypted} (expected was {expected_results[i]})")

if __name__ == '__main__':
    print("- - - - - - - - - - - -")
    print("Testing Data Encryption Standard (DES) Implementation")
    print("Test vectors are from page 28 of \"Validating the correctness of hardware implementations of the NBS data encryption standard\" by Jason Gait in 1977")
    unittest.main()