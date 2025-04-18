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

    def test_signature_verification(self):
        '''
        This method tests whether EdDSA can successfully verify a 512 bit signature
        '''
        print("Testing Successful Signature Verification")
        signature = self.eddsa.createSignature(message_bit_string=self.message_bit_string)
        # print(f"Signature : {signature.getHexString(add_spacing = 8)}")
        is_signature_valid = self.eddsa.verifySignature(self.message_bit_string,signature,self.eddsa.public_key)
        print(is_signature_valid)
        self.assertEqual(signature.bit_length,512)
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