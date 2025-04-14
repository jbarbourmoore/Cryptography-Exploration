import unittest
from CryptographySchemes.EllipticCurveDigitalSignatureAlgorithm import *
from HelperFunctions.EllipticCurveDetails import getCurveP521
class ECDSA_UnitTests(unittest.TestCase):
    '''
    This class contains basic unit tests for ecdsa
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        self.ecdsa = EllipticCurveDigitalSignatureAlgorithm([getCurveP521])

        self.message = "Example of ECDSA with P-521"
        self.sha = SHA3_512()
        # expected values for signature generation
        self.H = "EF88FB5AC01F35F5CB8A1B008E801146C13983CF8C2CCF1D88AFA8E9FEDE121C11FE829D41B402B32ADFDE20679C3F4D9101A3C4073A2E49039F5D38061CDBCC"
        self.E = "EF88FB5AC01F35F5CB8A1B008E801146C13983CF8C2CCF1D88AFA8E9FEDE121C11FE829D41B402B32ADFDE20679C3F4D9101A3C4073A2E49039F5D38061CDBCC"
        self.K = "C91E2349EF6CA22D2DE39DD51819B6AAD922D3AECDEAB452BA172F7D63E370CECD70575F597C09A174BA76BED05A48E562BE0625336D16B8703147A6A231D6BF"
        self.Kinv = "1EAB94335A7ED337BCE83C95DE95447925EDB0EE27F8E8378713E767D6DA570FCCFB4F13DCF57F898E77DDB540A9453E0C3D5C97AE8D2EC843590BCB1D349044C09"
        self.R_x = "140C8EDCA57108CE3F7E7A240DDD3AD74D81E2DE62451FC1D558FDC79269ADACD1C2526EEEEF32F8C0432A9D56E2B4A8A732891C37C9B96641A9254CCFE5DC3E2BA"
        self.R_y = "CD42A03AD1EB93C532FC8A54683998FF86FEC61F85F8E15B4ACD5B696498F211506D340091019900C918BD8088E0352E9742EA9E2B55983ECAA343E424B8113428"
        self.R = "140C8EDCA57108CE3F7E7A240DDD3AD74D81E2DE62451FC1D558FDC79269ADACD1C2526EEEEF32F8C0432A9D56E2B4A8A732891C37C9B96641A9254CCFE5DC3E2BA"
        self.D = "100085F47B8E1B8B11B7EB33028C0B2888E304BFC98501955B45BBA1478DC184EEEDF09B86A5F7C21994406072787205E69A63709FE35AA93BA333514B24F961722"
        self.S = "B25188492D58E808EDEBD7BF440ED20DB771CA7C618595D5398E1B1C0098E300D8C803EC69EC5F46C84FC61967A302D366C627FCFA56F87F241EF921B6E627ADBF"
    
    def test_hash_as_H(self):
        '''
        This method tests the sha3-512 hashing generates the expected hex value
        '''
        print("Testing SHA2-512 Hashing")
        actual_hash = self.sha.hashStringToHex(self.message)
        print(f"Actual Hash   : {actual_hash}")
        print(f"Expected Hash : {actual_hash}")
        self.assertEqual(self.H,actual_hash)

    def test_bit_to_int(self):
        '''
        This method tests the bit string to int method is working
        '''
        bit_string = "1011101110"
        expected_result = 750
        int_value = self.ecdsa.bitStringToInt(bit_string=bit_string)
        print("Test Bit String To Int")
        print(f"{bit_string} -> {int_value} ?= expected:{expected_result}")
        self.assertEqual(int_value, expected_result)

    def test_int_to_bit(self):
        '''
        This method tests the int to bit string method is working
        '''
        expected_result = "1011101110"
        int_value = 750
        bit_string = self.ecdsa.intToBitString(int_value)
        print("Test Int To Bit String")
        print(f"{int_value} -> {bit_string} ?= expected:{expected_result}")
        self.assertEqual(bit_string, expected_result)
    def test_E(self):
        #If len(n) ≥ hashlen, set E = H. Otherwise, set E equal to the leftmost log2(n) bits of H.
        pass

    def test_K_inv(self):
        pass

if __name__ == '__main__':
    print("Curve: P-521")
    print("Hash:  SHA3-524")
    print("https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf")

    unittest.main()