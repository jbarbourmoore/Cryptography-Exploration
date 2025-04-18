import unittest
from CryptographySchemes.EdwardsCurveDigitalSignatureAlgorithm import *
from HelperFunctions.IntegerHandler import *

class ECDSA_UnitTests(unittest.TestCase):
    '''
    This class contains basic unit tests for ecdsa
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        self.q = "B3EBFE9AD81341A6C0EEEA0B3F49115684D97F165535B2027CB5AFCE53FF944A"
        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=False,print_excess_error=False)
      
        self.message = "F495660A1FC6A591B0E2FB90574E3A28E485152ECF6C5745C137E2C53E619832D58A5F101B3EEAF88887DF1552AB16613E87AA4F38C91453A5824809BE2E198FF84E3C6EAF79AF8FD44EF7E4C0FDC70941A0F457F1908011F80E89CBCEBE47806C9F131AB5580132DE9BE0B9DB0D622F4D16C805AE852F0B68F1C6B1AB8E2BB4"
        
        message_handler = IntegerHandler.fromHexString(self.message, True)
        self.message_bit_string = message_handler.getBitString()
        
        # expected values for signature generation
        self.signature = "F9593859640FD47FA3A67F6CF00184B9696A2928F0013A72411325D7356AF72460C26DDEB3B6A6C1BC89224179F72F75C8E3BE6D2F9EF6002F29BCE680C0B203"
   
    def test_signature_generation(self):
        '''
        This method tests whether EdDSA successfully creates a 512 bit signature
        '''

        print("Testing Basic Key And Signature Generation")
        signature = self.eddsa.createSignature(message_bit_string=self.message_bit_string)
        print(f"Public key is {self.eddsa.public_key.getHexString()}")
        print(f"Public key point is {self.eddsa.public_key_point}")
        print(f"Private key is {self.eddsa.private_key}")
        self.assertEqual(signature.bit_length,512)

    def test_1_rfc8032_ed25519(self):
        '''
        This method tests whether EdDSA successfully creates and verifies the expected signature given a specific private key and message

        Tests the first test vector for ed25519 from rfc 8032
        https://www.rfc-editor.org/rfc/rfc8032.txt
        '''
        secret_key = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        expected_public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        message = []
        expected_signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        print("Testing Basic Key And Signature Generation With Set Private Key")
        print("Test 1 From RFC 8032 Section 7.1.  \"Test Vectors for Ed25519\"")
        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=False, private_key=secret_key,print_excess_error=False)
        signature = self.eddsa.createSignature(message_bit_string=message)
        print(f"Public key is {self.eddsa.public_key.getHexString(add_spacing = 8)}")
        self.assertEqual(self.eddsa.public_key.getHexString(),expected_public.upper())
        print(f"Signature is {signature.getHexString(add_spacing = 8)}")
        self.assertEqual(signature.getHexString(), expected_signature.upper())
        self.assertEqual(signature.bit_length,512)
        is_signature_valid = self.eddsa.verifySignature(message,signature,self.eddsa.public_key)
        print(f"The signature is valid : {is_signature_valid}")
        self.assertEqual(signature.bit_length,512)
        self.assertTrue(is_signature_valid)

    def test_2_rfc8032_ed25519(self):
        '''
        This method tests whether EdDSA successfully creates and verifies the expected signature given a specific private key and message

        Tests the second test vector for ed25519 from rfc 8032
        https://www.rfc-editor.org/rfc/rfc8032.txt
        '''

        secret_key = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        expected_public = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        message = IntegerHandler.fromHexString("72",True,8).getBitString()
        expected_signature = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        print("Testing Basic Key And Signature Generation With Set Private Key")
        print("Test 2 From RFC 8032 Section 7.1.  \"Test Vectors for Ed25519\"")
        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=False, private_key=secret_key,print_excess_error=False)
        signature = self.eddsa.createSignature(message_bit_string=message)
        print(f"Public key is {self.eddsa.public_key.getHexString(add_spacing = 8)}")
        self.assertEqual(self.eddsa.public_key.getHexString(),expected_public.upper())
        print(f"Signature is {signature.getHexString(add_spacing = 8)}")
        self.assertEqual(signature.getHexString(), expected_signature.upper())
        self.assertEqual(signature.bit_length,512)
        is_signature_valid = self.eddsa.verifySignature(message,signature,self.eddsa.public_key)
        print(f"The signature is valid : {is_signature_valid}")
        self.assertEqual(signature.bit_length,512)
        self.assertTrue(is_signature_valid)

    def test_3_rfc8032_ed25519(self):
        '''
        This method tests whether EdDSA successfully creates and verifies the expected signature given a specific private key and message

        Tests the third test vector for ed25519 from rfc 8032
        https://www.rfc-editor.org/rfc/rfc8032.txt
        '''

        secret_key = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
        expected_public = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        message = IntegerHandler.fromHexString("af82",True,16).getBitString()
        expected_signature = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        print("Testing Basic Key And Signature Generation With Set Private Key")
        print("Test 3 From RFC 8032 Section 7.1.  \"Test Vectors for Ed25519\"")
        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=False, private_key=secret_key,print_excess_error=False)
        signature = self.eddsa.createSignature(message_bit_string=message)
        print(f"Public key is {self.eddsa.public_key.getHexString(add_spacing = 8)}")
        self.assertEqual(self.eddsa.public_key.getHexString(),expected_public.upper())
        print(f"Signature is {signature.getHexString(add_spacing = 8)}")
        self.assertEqual(signature.getHexString(), expected_signature.upper())
        self.assertEqual(signature.bit_length,512)
        is_signature_valid = self.eddsa.verifySignature(message,signature,self.eddsa.public_key)
        print(f"The signature is valid : {is_signature_valid}")
        self.assertEqual(signature.bit_length,512)
        self.assertTrue(is_signature_valid)

    def test_5_rfc8032_ed25519(self):
        '''
        This method tests whether EdDSA successfully creates and verifies the expected signature given a specific private key and message

        Tests the fifth test vector for ed25519 from rfc 8032
        https://www.rfc-editor.org/rfc/rfc8032.txt
        '''

        secret_key = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
        expected_public = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
        message = IntegerHandler.fromHexString("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",True,512).getBitString()
        expected_signature = "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
        print("Testing Basic Key And Signature Generation With Set Private Key")
        print("Test 5 From RFC 8032 Section 7.1.  \"Test Vectors for Ed25519\"")
        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=False, private_key=secret_key,print_excess_error=False)
        signature = self.eddsa.createSignature(message_bit_string=message)
        print(f"Public key is {self.eddsa.public_key.getHexString(add_spacing = 8)}")
        self.assertEqual(self.eddsa.public_key.getHexString(),expected_public.upper())
        print(f"Signature is {signature.getHexString(add_spacing = 8)}")
        self.assertEqual(signature.getHexString(), expected_signature.upper())
        self.assertEqual(signature.bit_length,512)
        is_signature_valid = self.eddsa.verifySignature(message,signature,self.eddsa.public_key)
        print(f"The signature is valid : {is_signature_valid}")
        self.assertEqual(signature.bit_length,512)
        self.assertTrue(is_signature_valid)

    def test_signature_verification(self):
        '''
        This method tests whether EdDSA can successfully verify a 512 bit signature
        '''
        print("Testing Successful Signature Verification")
        signature = self.eddsa.createSignature(message_bit_string=self.message_bit_string)
        # print(f"Signature : {signature.getHexString(add_spacing = 8)}")
        is_signature_valid = self.eddsa.verifySignature(self.message_bit_string,signature,self.eddsa.public_key)
        print(f"The signature is valid : {is_signature_valid}")
        self.assertEqual(signature.bit_length,512)
        self.assertTrue(is_signature_valid)

    def test_ed448_signature_verification(self):
        '''
        This method tests whether EdDSA can successfully verify a 912 bit signature
        '''
        print("Ed448 : Testing Successful Signature Verification")
        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(useEdwards25519=False)
        signature = self.eddsa.createSignature(message_bit_string=self.message_bit_string)
        # print(f"Signature : {signature.getHexString(add_spacing = 8)}")
        is_signature_valid = self.eddsa.verifySignature(self.message_bit_string,signature,self.eddsa.public_key)
        print(f"The signature is valid : {is_signature_valid}")
        self.assertEqual(signature.bit_length,912)
        self.assertTrue(is_signature_valid)

    def test_signature_verification_wrong_public_key(self):
        '''
        This method tests whether EdDSA can successfully deny a 512 bit signature given the wrong public key
        '''
        print("Testing Signature Failing Verification Due To Wrong Public Key")
        signature = self.eddsa.createSignature(message_bit_string=self.message_bit_string)
        is_signature_valid = self.eddsa.verifySignature(self.message_bit_string,signature,"AF8C2D384530290299B86DA18FF79D2388873AC66C87B7EE9A6D6B3941FA29A5")
        print(f"The signature is valid : {is_signature_valid}")
        self.assertEqual(signature.bit_length,512)
        self.assertFalse(is_signature_valid)

    def test_signature_verification_wrong_signature(self):
        '''
        This method tests whether EdDSA can successfully deny a 512 bit signature given the wrong signature
        '''

        print("Testing Signature Failing Verification Due To Wrong Signature")
        signature = self.eddsa.createSignature(message_bit_string=self.message_bit_string)
        is_signature_valid = self.eddsa.verifySignature(self.message_bit_string,"4517EC65E21FBBD43957B80ED4A08EC15554ABEB0CBD31B22860F1E161EED1882909BAB48200F2D6780A8B4CB32D121C8ACBB3154AEBCFB789682FF76AE8E603",self.eddsa.public_key)
        print(f"The signature is valid : {is_signature_valid}")
        self.assertEqual(signature.bit_length,512)
        self.assertFalse(is_signature_valid)

    def test_signature_verification_one_less_byte_message(self):
        '''
        This method tests whether EdDSA can successfully deny a 512 bit signature given one less byte of the message
        '''

        print("Testing Signature Failing Verification Due To One Less Bit Of The Message")
        signature = self.eddsa.createSignature(message_bit_string=self.message_bit_string)
        is_signature_valid = self.eddsa.verifySignature(self.message_bit_string[1:],"4517EC65E21FBBD43957B80ED4A08EC15554ABEB0CBD31B22860F1E161EED1882909BAB48200F2D6780A8B4CB32D121C8ACBB3154AEBCFB789682FF76AE8E603",self.eddsa.public_key)
        print(f"The signature is valid : {is_signature_valid}")
        self.assertEqual(signature.bit_length,512)
        self.assertFalse(is_signature_valid)


if __name__ == '__main__':
    print("Curve: Ed22519")

    unittest.main()