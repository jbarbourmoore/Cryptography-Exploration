import unittest
from CryptographySchemes.EllipticCurveDigitalSignatureAlgorithm import *
from HelperFunctions.EllipticCurveDetails import getCurveP224
from CryptographySchemes.SecureHashAlgorithm3 import SHA3_224

class ECDSA_UnitTests(unittest.TestCase):
    '''
    This class contains basic unit tests for ecdsa curve p224 with sha3-224 hashing algorithm
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        self.sha = SHA3_224()
        self.ecdsa = EllipticCurveDigitalSignatureAlgorithm([getCurveP224],self.sha)

        self.message = "Example of ECDSA with P-224"

        # expected values for signature generation
        self.H = "5FB11B966420EEEB0F540C356DD8C0FBDFBF417145E5E1F9E9B9AA43"
        self.E = "5FB11B966420EEEB0F540C356DD8C0FBDFBF417145E5E1F9E9B9AA43"
        self.K = "A548803B79DF17C40CDE3FF0E36D025143BCBBA146EC32908EB84937"
        self.Kinv = "B4D9D81FEFF7B325E09E770C40BACE8B008D6074371967326F39130C"
        self.R_x = "C3A3F5B82712532004C6F6D1DB672F55D931C3409EA1216D0BE77380"
        self.R_y = "9BF4978CA8C8A8DF855A74C6905A5A3947ACFF772FCE436D48341D46"
        self.R = "C3A3F5B82712532004C6F6D1DB672F55D931C3409EA1216D0BE77380"
        self.D = "3F0C488E987C80BE0FEE521F8D90BE6034EC69AE11CA72AA777481E8"
        self.S = "485732290B465E864A3345FF12673303FEAA4DB68AC29D784BF6DAE2"

        # expected values for signature verification
        self.Q_x = "E84FB0B8E7000CB657D7973CF6B42ED78B301674276DF744AF130B3E"
        self.Q_y = "4376675C6FC5612C21A0FF2D2A89D2987DF7A2BC52183B5982298555"
        self.Sinv = "19BBD45D10D5B00F3E0CE3A24B66696E5162CC49C1949A73297AE9AA"
        self.U = "A78399AD5562A130C6160A550E4A98983235CBDF6594807F59E86779"
        self.V = "81384A93C6620A0FB373F00EAC5F60E69E051788B7E0C769BEC38627"
        self.Rprime_X = "C3A3F5B82712532004C6F6D1DB672F55D931C3409EA1216D0BE77380"
        self.Rprime_Y = "9BF4978CA8C8A8DF855A74C6905A5A3947ACFF772FCE436D48341D46"
        self.Rprime = "C3A3F5B82712532004C6F6D1DB672F55D931C3409EA1216D0BE77380"

        # integer values for input to create signature without random selection
        self.k_int = self.ecdsa.bitStringToInt(self.ecdsa.hexStringToBitString(self.K))
        self.d_int = self.ecdsa.bitStringToInt(self.ecdsa.hexStringToBitString(self.D))
    
    def generate_signature_p224_sha3224(self):
        '''
        This method creates a signature using the provided private key and provided k value
        '''
        self.ecdsa.createSignature(self.message,self.d_int,self.k_int,True)
    
    def verify_signature_p224_sha3224(self):
        '''
        This method verifies a signature using the provided signature and public key
        '''
        self.ecdsa.verifySignature(self.message,(self.R,self.S),(self.Q_x,self.Q_y),is_debug=True)

    def test_verification_Q_x(self):
        '''
        This method tests that the Q_x value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p224_sha3224()
        print("Checking the Value for Q_x When Verifying Signature")
        print(f"Actual Q_x    : {self.ecdsa.Q_x}")
        print(f"Expected Q_x  : {self.Q_x}")
        self.assertEqual(self.ecdsa.Q_x,self.Q_x)

    def test_verification_Q_y(self):
        '''
        This method tests that the Q_y value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p224_sha3224()
        print("Checking the Value for Q_y When Verifying Signature")
        print(f"Actual Q_y    : {self.ecdsa.Q_y}")
        print(f"Expected Q_y  : {self.Q_y}")
        self.assertEqual(self.ecdsa.Q_y,self.Q_y)

    def test_verification_Sinv(self):
        '''
        This method tests that the S_inv value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p224_sha3224()
        print("Checking the Value for Sinv When Verifying Signature")
        print(f"Actual Sinv   : {self.ecdsa.sinv}")
        print(f"Expected Sinv : {self.Sinv}")
        self.assertEqual(self.ecdsa.sinv,self.Sinv)

    def test_verification_u(self):
        '''
        This method tests that the u value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p224_sha3224()
        print("Checking the Value for U When Verifying Signature")
        print(f"Actual u      : {self.ecdsa.u}")
        print(f"Expected u    : {self.U}")
        self.assertEqual(self.ecdsa.u,self.U)

    def test_verification_v(self):
        '''
        This method tests that the v value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p224_sha3224()
        print("Checking the Value for V When Verifying Signature")
        print(f"Actual v      : {self.ecdsa.v}")
        print(f"Expected v    : {self.V}")
        self.assertEqual(self.ecdsa.v,self.V)

    def test_verification_Sinv(self):
        '''
        This method tests that the S_inv value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p224_sha3224()
        print("Checking the Value for Sinv When Verifying Signature")
        print(f"Actual Sinv   : {self.ecdsa.sinv}")
        print(f"Expected Sinv : {self.Sinv}")
        self.assertEqual(self.ecdsa.sinv,self.Sinv)

    def test_verification_R1_x(self):
        '''
        This method tests that the Rprime_x value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p224_sha3224()
        print("Checking the Value for RPrime_x When Verifying Signature")
        print(f"Actual R1_x   : {self.ecdsa.R1_x}")
        print(f"Expected R1_x : {self.Rprime_X}")
        self.assertEqual(self.ecdsa.R1_x,self.Rprime_X)

    def test_verification_R1_y(self):
        '''
        This method tests that the Rprime_y value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p224_sha3224()
        print("Checking the Value for RPrime_y When Verifying Signature")
        print(f"Actual R1_y   : {self.ecdsa.R1_y}")
        print(f"Expected R1_y : {self.Rprime_Y}")
        self.assertEqual(self.ecdsa.R1_y,self.Rprime_Y)

    def test_verification_R1(self):
        '''
        This method tests that the Rprime value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p224_sha3224()
        print("Checking the Value for RPrime When Verifying Signature")
        print(f"Actual R1     : {self.ecdsa.r_1}")
        print(f"Expected R1   : {self.Rprime}")
        self.assertEqual(self.ecdsa.r_1,self.Rprime)

    def test_verification_result(self):
        '''
        This method tests that the result value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p224_sha3224()
        print("Checking the Result When Verifying Signature")
        print(f"Actual res    : {self.ecdsa.verified}")
        print(f"Expected res  : {True}")
        self.assertEqual(self.ecdsa.verified,True)

    def test_hash_as_H(self):
        '''
        This method tests the sha3-224 hashing generates the expected hex value
        '''

        print("Testing SHA2-224 Hashing")
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
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P224_SHA3-224.pdf        
        '''

        self.generate_signature_p224_sha3224()
        print("Checking the Value for E When Generating Signature")
        print(f"Actual E      : {self.ecdsa.E}")
        print(f"Expected E    : {self.E}")
        self.assertEqual(self.ecdsa.E,self.E)

    def test_E(self):
        '''
        This method tests that the E value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P224_SHA3-224.pdf        
        '''

        self.generate_signature_p224_sha3224()
        print("Checking the Value for H When Generating Signature")
        print(f"Actual H      : {self.ecdsa.H}")
        print(f"Expected H    : {self.H}")
        self.assertEqual(self.ecdsa.H,self.H)

    def test_K(self):
        '''
        This method tests that the K value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P224_SHA3-224.pdf        
        '''
        self.generate_signature_p224_sha3224()
        print("Checking the Value for K When Generating Signature")
        print(f"Actual K      : {self.ecdsa.K}")
        print(f"Expected K    : {self.K}")
        self.assertEqual(self.ecdsa.K,self.K)

    def test_K_inv(self):
        '''
        This method tests that the K_inv value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P224_SHA3-224.pdf        
        '''
        self.generate_signature_p224_sha3224()
        print("Checking the Value for K Inverse When Generating Signature")
        print(f"Actual Kinv   : {self.ecdsa.k_inv}")
        print(f"Expected Kinv : {self.Kinv}")
        self.assertEqual(self.ecdsa.k_inv,self.Kinv)

    def test_R_x(self):
        '''
        This method tests that the R_x value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P224_SHA3-224.pdf        
        '''
        self.generate_signature_p224_sha3224()
        print("Checking the Value for R_x When Generating Signature")
        print(f"Actual R_x    : {self.ecdsa.R_x}")
        print(f"Expected R_x  : {self.R_x}")
        self.assertEqual(self.ecdsa.R_x,self.R_x)

    def test_R_y(self):
        '''
        This method tests that the R_y value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P224_SHA3-224.pdf        
        '''
        self.generate_signature_p224_sha3224()
        print("Checking the Value for R_y When Generating Signature")
        print(f"Actual R_y    : {self.ecdsa.R_y}")
        print(f"Expected R_y  : {self.R_y}")
        self.assertEqual(self.ecdsa.R_y,self.R_y)
    
    def test_r(self):
        '''
        This method tests that the r value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P224_SHA3-224.pdf        
        '''
        self.generate_signature_p224_sha3224()
        print("Checking the Value for r When Generating Signature")
        print(f"Actual r      : {self.ecdsa.r}")
        print(f"Expected r    : {self.R}")
        self.assertEqual(self.ecdsa.r,self.R)

    def test_D(self):
        '''
        This method tests that the D value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P224_SHA3-224.pdf        
        '''
        self.generate_signature_p224_sha3224()
        print("Checking the Value for D When Generating Signature")
        print(f"Actual D      : {self.ecdsa.d}")
        print(f"Expected D    : {self.D}")
        self.assertEqual(self.ecdsa.d,self.D)

    def test_s(self):
        '''
        This method tests that the s value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P224_SHA3-224.pdf        '''
        self.generate_signature_p224_sha3224()
        print("Checking the Value for s When Generating Signature")
        print(f"Actual s      : {self.ecdsa.s}")
        print(f"Expected s    : {self.S}")
        self.assertEqual(self.ecdsa.s,self.S)

if __name__ == '__main__':
    print("Curve: P-224")
    print("Hash:  SHA3-224")
    print("https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P224_SHA3-224.pdf")

    unittest.main()