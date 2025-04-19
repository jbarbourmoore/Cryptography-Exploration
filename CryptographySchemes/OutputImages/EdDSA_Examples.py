import unittest
from CryptographySchemes.EdwardsCurveDigitalSignatureAlgorithm import *
from HelperFunctions.IntegerHandler import *

class ECDSA_UnitTests(unittest.TestCase):
    '''
    This class contains basic unit tests for ecdsa
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=False,print_excess_error=False)
                 
    def test_1_rfc8032_ed25519(self):
        '''
        This method tests whether EdDSA successfully creates and verifies the expected signature given a specific private key and message

        Tests the first test vector for ed25519 from rfc 8032
        https://www.rfc-editor.org/rfc/rfc8032.txt
        '''
        secret_key = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        expected_public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        message = ""
        expected_signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        # print("Testing Basic Key And Signature Generation With Set Private Key")
        print("Test 1 From RFC 8032 Section 7.1.  \"Test Vectors for Ed25519\"")
        print(f"Message         : 0 bytes, \"{message}\"")
        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=False, private_key=secret_key,print_excess_error=False)
        signature = self.eddsa.createSignature(message_bit_string=message)
        print(f"Private key     : {self.eddsa.private.getHexString(add_spacing = 8)}")
        print(f"Public key      : {self.eddsa.public_key.getHexString(add_spacing = 8)}")
        self.assertEqual(self.eddsa.public_key.getHexString(),expected_public.upper())
        print(f"Signature       : {signature.getHexString(add_spacing = 8)}")
        self.assertEqual(signature.getHexString(), expected_signature.upper())
        self.assertEqual(signature.bit_length,512)
        is_signature_valid = self.eddsa.verifySignature(message,signature,self.eddsa.public_key)
        print(f"Signature valid : {is_signature_valid}")
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
        print(f"Message         : 0 bytes, \"{message}\"")
        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=False, private_key=secret_key,print_excess_error=False)
        signature = self.eddsa.createSignature(message_bit_string=message)
        print(f"Public key      : {self.eddsa.public_key.getHexString(add_spacing = 8)}")
        self.assertEqual(self.eddsa.public_key.getHexString(),expected_public.upper())
        print(f"Signature       : {signature.getHexString(add_spacing = 8)}")
        self.assertEqual(signature.getHexString(), expected_signature.upper())
        self.assertEqual(signature.bit_length,512)
        is_signature_valid = self.eddsa.verifySignature(message,signature,self.eddsa.public_key)
        print(f"Signature valid : {is_signature_valid}")
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
        print(f"Message         : 0 bytes, \"{message}\"")
        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=False, private_key=secret_key,print_excess_error=False)
        signature = self.eddsa.createSignature(message_bit_string=message)
        print(f"Public key      : {self.eddsa.public_key.getHexString(add_spacing = 8)}")
        self.assertEqual(self.eddsa.public_key.getHexString(),expected_public.upper())
        print(f"Signature       : {signature.getHexString(add_spacing = 8)}")
        self.assertEqual(signature.getHexString(), expected_signature.upper())
        self.assertEqual(signature.bit_length,512)
        is_signature_valid = self.eddsa.verifySignature(message,signature,self.eddsa.public_key)
        print(f"Signature valid : {is_signature_valid}")
        self.assertEqual(signature.bit_length,512)
        self.assertTrue(is_signature_valid)


    def test_ed448_verification_wrong_signature(self):
        '''
        This method tests whether EdDSA can successfully deny a 512 bit signature given the one less bit of the message
        '''
        print("Ed448 : Testing Signature Failing Verification Due To One Less Bit Of The Message")

        self.eddsa = EdwardsCurveDigitalSignatureAlgorithm(useEdwards25519=False)
        message = IntegerHandler.fromHexString("448",True,12).getBitString()
        signature = self.eddsa.createSignature(message_bit_string=message)
        print(f"Signature       : {signature.getHexString(add_spacing = 8)}")
        print(f"Validating The Signatue With The Entire Message : {message}")
        is_signature_valid = self.eddsa.verifySignature(message,signature,self.eddsa.public_key)
        print(f"Signature valid : {is_signature_valid}")
        self.assertTrue(is_signature_valid)
        print(f"Validating The Signatue With One Less Bit : {message[1:]}")
        is_signature_valid = self.eddsa.verifySignature(message[1:],signature,self.eddsa.public_key)
        print(f"Signature valid : {is_signature_valid}")
        self.assertEqual(signature.bit_length,912)
        self.assertFalse(is_signature_valid)

if __name__ == '__main__':
    print("Curve: Ed22519")

    unittest.main()