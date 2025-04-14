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

        self.k_int = self.ecdsa.bitStringToInt(self.ecdsa.format_hex_as_bit_string(self.K))
        self.d_int = self.ecdsa.bitStringToInt(self.ecdsa.format_hex_as_bit_string(self.D))
    
    def generate_signature_p521_sha3512(self):
        self.ecdsa.generateSignature(self.message,self.d_int,self.k_int,True)

    def test_hash_as_H(self):
        '''
        This method tests the sha3-512 hashing generates the expected hex value
        '''

        print("Testing SHA2-512 Hashing")
        actual_hash = self.sha.hashStringToHex(self.message)
        print(f"Actual Hash   : {actual_hash}")
        print(f"Expected Hash : {self.H}")
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
        '''
        This method tests that the E value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.generate_signature_p521_sha3512()
        print("Checking the Value for E When Generating Signature")
        print(f"Actual E      : {self.ecdsa.E}")
        print(f"Expected E    : {self.E}")
        self.assertEqual(self.ecdsa.E,self.E)

    def test_K(self):
        '''
        This method tests that the K value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''
        self.generate_signature_p521_sha3512()
        print("Checking the Value for K When Generating Signature")
        print(f"Actual K      : {self.ecdsa.K}")
        print(f"Expected K    : {self.K}")
        self.assertEqual(self.ecdsa.K,self.K)

    def test_K_inv(self):
        '''
        This method tests that the K_inv value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''
        self.generate_signature_p521_sha3512()
        print("Checking the Value for K Inverse When Generating Signature")
        print(f"Actual Kinv   : {self.ecdsa.k_inv}")
        print(f"Expected Kinv : {self.Kinv}")
        self.assertEqual(self.ecdsa.k_inv,self.Kinv)

    def test_R_x(self):
        '''
        This method tests that the R_x value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''
        self.generate_signature_p521_sha3512()
        print("Checking the Value for R_x When Generating Signature")
        print(f"Actual R_x    : {self.ecdsa.R_x}")
        print(f"Expected R_x  : {self.R_x}")
        self.assertEqual(self.ecdsa.R_x,self.R_x)

    def test_R_y(self):
        '''
        This method tests that the R_y value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''
        self.generate_signature_p521_sha3512()
        print("Checking the Value for R_y When Generating Signature")
        print(f"Actual R_y    : {self.ecdsa.R_y}")
        print(f"Expected R_y  : {self.R_y}")
        self.assertEqual(self.ecdsa.R_y,self.R_y)
    
    def test_r(self):
        '''
        This method tests that the r value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''
        self.generate_signature_p521_sha3512()
        print("Checking the Value for r When Generating Signature")
        print(f"Actual r      : {self.ecdsa.r}")
        print(f"Expected r    : {self.R}")
        self.assertEqual(self.ecdsa.r,self.R)

    def test_D(self):
        '''
        This method tests that the D value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''
        self.generate_signature_p521_sha3512()
        print("Checking the Value for D When Generating Signature")
        print(f"Actual D      : {self.ecdsa.d}")
        print(f"Expected D    : {self.D}")
        self.assertEqual(self.ecdsa.d,self.D)

    def test_s(self):
        '''
        This method tests that the s value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''
        self.generate_signature_p521_sha3512()
        print("Checking the Value for s When Generating Signature")
        print(f"Actual s      : {self.ecdsa.s}")
        print(f"Expected s    : {self.S}")
        self.assertEqual(self.ecdsa.s,self.S)

if __name__ == '__main__':
    print("Curve: P-521")
    print("Hash:  SHA3-524")
    print("https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf")

    unittest.main()