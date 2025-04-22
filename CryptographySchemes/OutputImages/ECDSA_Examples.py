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
        self.sha = sha3_512
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

        self.Q_x = "98E91EEF9A68452822309C52FAB453F5F117C1DA8ED796B255E9AB8F6410CCA16E59DF403A6BDC6CA467A37056B1E54B3005D8AC030DECFEB68DF18B171885D5C4"
        self.Q_y = "164350C321AECFC1CCA1BA4364C9B15656150B4B78D6A48D7D28E7F31985EF17BE8554376B72900712C4B83AD668327231526E313F5F092999A4632FD50D946BC2E"
        self.Sinv = "30EEEA9D35CB2754BA85E0226A15A5D911AC3033D6FB0F62FC32F7974337116095763C29C1CD293B64B72A83058EA7B8AA71B69C5C34FD35181A78512AEC9E063"
        self.U = "1FDE0A17B85CC2E14F03C192DBE87491BE3D539C2F151A3143401A9922C66F5021B1A51645FF9355687517D73993A7146AB8D934B4213708106CD65402D93634623"
        self.V = "12EFA2C213C577D5D002AF25AAEF6A147AD014AFE1342DB9E86E6F26638BD146F2842FEDA40D3F43DA16AF02CEDD8C85504ADB1426E33004205DAA5AAA32F7215B0"
        self.Rprime_X = "140C8EDCA57108CE3F7E7A240DDD3AD74D81E2DE62451FC1D558FDC79269ADACD1C2526EEEEF32F8C0432A9D56E2B4A8A732891C37C9B96641A9254CCFE5DC3E2BA"
        self.Rprime_Y = "CD42A03AD1EB93C532FC8A54683998FF86FEC61F85F8E15B4ACD5B696498F211506D340091019900C918BD8088E0352E9742EA9E2B55983ECAA343E424B8113428"
        self.Rprime = "140C8EDCA57108CE3F7E7A240DDD3AD74D81E2DE62451FC1D558FDC79269ADACD1C2526EEEEF32F8C0432A9D56E2B4A8A732891C37C9B96641A9254CCFE5DC3E2BA"

        self.k_int = self.ecdsa.bitStringToInt(self.ecdsa.hexStringToBitString(self.K))
        self.d_int = self.ecdsa.bitStringToInt(self.ecdsa.hexStringToBitString(self.D))
    
    def generate_signature_p521_sha3512(self):
        self.ecdsa.createSignature(self.message,self.d_int,self.k_int,True)
    
    def verify_signature_p521_sha2512(self):
        self.ecdsa.verifySignature(self.message,(self.R,self.S),(self.Q_x,self.Q_y),is_debug=True)

    def test_verification_R1(self):
        '''
        This method tests that the Rprime value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p521_sha2512()
        print("Checking the Value for RPrime When Verifying Signature")
        print(f"Actual R1       : {self.ecdsa.r_1}")
        print(f"Expected R1     : {self.Rprime}")
        self.assertEqual(self.ecdsa.r_1,self.Rprime)

    def test_verification_result(self):
        '''
        This method tests that the result value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''

        self.verify_signature_p521_sha2512()
        print("Checking the Result When Verifying Signature")
        print(f"Actual result     : {self.ecdsa.verified}")
        print(f"Expected result   : {True}")
        self.assertEqual(self.ecdsa.verified,True)

    def test_hash_as_H(self):
        '''
        This method tests the sha3-512 hashing generates the expected hex value
        '''

        print("Testing SHA3-512 Hashing")
        actual_hash = self.sha.hashString(self.message).getHexString()
        print(f"Actual Hash     : {actual_hash}")
        print(f"Expected Hash   : {self.H}")
        self.assertEqual(self.H,actual_hash)

    def test_r(self):
        '''
        This method tests that the r value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''
        self.generate_signature_p521_sha3512()
        print("Checking the Value for r When Generating Signature")
        print(f"Actual r        : {self.ecdsa.r}")
        print(f"Expected r      : {self.R}")
        self.assertEqual(self.ecdsa.r,self.R)

    def test_s(self):
        '''
        This method tests that the s value matches the known value from NIST
        https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf
        '''
        self.generate_signature_p521_sha3512()
        print("Checking the Value for s When Generating Signature")
        print(f"Actual s        : {self.ecdsa.s}")
        print(f"Expected s      : {self.S}")
        self.assertEqual(self.ecdsa.s,self.S)

if __name__ == '__main__':
    print("Curve: P-521")
    print("Hash:  SHA3-512")
    print("https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf")
    print(f"The message is {"Example of ECDSA with P-521"}")
    unittest.main()