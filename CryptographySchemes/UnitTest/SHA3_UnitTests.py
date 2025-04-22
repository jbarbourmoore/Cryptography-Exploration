import unittest
from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm3 import *

class SHA3_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for aes
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
    def test_sha3_theta(self):
        '''
        This function tests the the theta method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''

        print("Testing Theta")
        expected_before_theta ='D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
        expected_after_theta = 'D3 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00'
        handler_before = SHA3_ValueHandler.fromHexString(expected_before_theta)
        handler_expected = SHA3_ValueHandler.fromHexString(expected_after_theta)

        state = SHA3_StateArray.fromValueHandler(handler_before)
        state.theta()
        print(f"before   : {handler_before.getHexString()}")
        print(f"expected : {handler_expected.getHexString()}")
        handler_after = state.getValueHandler()
        print(f"after    : {handler_after.getHexString()}")

        self.assertEqual(handler_after, handler_expected)
   
    def test_sha3_theta_second(self):
        '''
        This function tests the the theta method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''

        print("Testing Theta")
        expected_before_theta = "D2 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00"
        expected_after_theta = '9A CF EA 26 00 E0 63 00 E6 DF C6 3B 0D 55 0C 01 EE E8 3B 6A 1A E0 63 00 0B CD 69 25 00 93 1A 01 9B F5 7E 4A 17 C6 16 00 48 CF EA 2E 00 E0 63 00 E6 DF B6 21 0D 35 1B 01 EE 68 52 6A 1A E0 63 00 D8 CD 79 2D 00 D3 00 01 9B 75 77 58 17 E6 1B 00 EC CE EA 27 00 E0 63 00 E6 79 D7 3B 0D 75 01 01 EE 68 52 6B 1A E0 63 00 7C 6A 78 25 00 93 1A 01 9B 75 17 4A 17 E6 1B 00 48 87 E9 16 0D E0 63 00 E6 DF D6 3B 0D 75 01 01 EE 20 51 6A 1A E0 E3 00 D8 8D 79 15 0D 93 1A 01 9B 75 17 4A 17 E6 9B 00 48 CF EA 26 00 33 63 00 E6 DF D6 3B 0D 75 41 01 A6 6B 52 6A 1A 33 63 00 D8 CD 79 25 00 93 1A 01 D3 76 17 4A 17 E6 5B 00'
        handler_before = SHA3_ValueHandler.fromHexString(expected_before_theta)
        handler_expected = SHA3_ValueHandler.fromHexString(expected_after_theta)

        state = SHA3_StateArray.fromValueHandler(handler_before)
        state.theta()
        print(f"before   : {handler_before.getHexString()}")
        print(f"expected : {handler_expected.getHexString()}")
        handler_after = state.getValueHandler()
        print(f"after    : {handler_after.getHexString()}")

        self.assertEqual(handler_after, handler_expected)

    
    def test_sha3_rho(self):
        '''
        This function tests the the rho method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''
        print("Testing Rho")

        expected_after_theta = 'D3 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00'
        expected_after_rho = "D3 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 40 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 69 00 00 00 00 00 "
        handler_before = SHA3_ValueHandler.fromHexString(expected_after_theta)
        handler_expected = SHA3_ValueHandler.fromHexString(expected_after_rho)

        state = SHA3_StateArray.fromValueHandler(handler_before)
        state.rho()
        print(f"before   : {handler_before.getHexString()}")
        print(f"expected : {handler_expected.getHexString()}")
        handler_after = state.getValueHandler()
        print(f"after    : {handler_after.getHexString()}")

        self.assertEqual(handler_after.getHexString(), handler_expected.getHexString())

    def test_sha3_pi(self):
        '''
        This function tests the the pi method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''
        
        print("Testing Pi")
        expected_after_rho = "D3 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 40 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 69 00 00 00 00 00 "
        expected_after_pi = "D3 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 80 69 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 "
        handler_before = SHA3_ValueHandler.fromHexString(expected_after_rho)
        handler_expected = SHA3_ValueHandler.fromHexString(expected_after_pi)

        state = SHA3_StateArray.fromValueHandler(handler_before)
        state.pi()
        print(f"before   : {handler_before.getHexString()}")
        print(f"expected : {handler_expected.getHexString()}")
        handler_after = state.getValueHandler()
        print(f"after    : {handler_after.getHexString()}")

    def test_sha3_chi(self):
        '''
        This function tests the the chi method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''
        print("Testing Chi")
        expected_after_pi = "D3 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 80 69 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 "
        expected_after_chi = "D3 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00 "
    
        handler_before = SHA3_ValueHandler.fromHexString(expected_after_pi)
        handler_expected = SHA3_ValueHandler.fromHexString(expected_after_chi)

        state = SHA3_StateArray.fromValueHandler(handler_before)
        state.chi()
        print(f"before   : {handler_before.getHexString()}")
        print(f"expected : {handler_expected.getHexString()}")
        handler_after = state.getValueHandler()
        print(f"after    : {handler_after.getHexString()}")


    def test_sha3_iota(self):
        '''
        This function tests the the iota method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''
        print("Testing Iota")
        expected_after_chi = "D3 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00 "
        expected_after_iota = "D2 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00"
        handler_before = SHA3_ValueHandler.fromHexString(expected_after_chi)
        handler_expected = SHA3_ValueHandler.fromHexString(expected_after_iota)

        state = SHA3_StateArray.fromValueHandler(handler_before)
        state.iota(0)
        print(f"before   : {handler_before.getHexString()}")
        print(f"expected : {handler_expected.getHexString()}")
        handler_after = state.getValueHandler()
        print(f"after    : {handler_after.getHexString()}")

    def test_sha3_iota_second(self):
        '''
        This function tests the the iota method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''
        print("Testing Iota")
        expected_after_chi = "6D 0D C2 68 29 1E 83 1E 3C 6E 06 9A BF 29 0E 45 9A 2E A6 39 96 FA F2 BE 10 92 76 B8 4D BD EC A2 25 54 8E F6 87 F2 44 EC A3 D8 5E B0 F0 69 9A 92 FE 0A D5 6E 38 AA 8E 5A 41 42 6F D0 29 69 1A E1 1D 1D 43 02 2B 85 B4 4A F9 83 C2 58 8A CC 47 4B 3A 9F E8 7A 32 12 14 63 5C 27 1D 7E 1E 29 85 88 E6 F8 DC FB 03 09 44 91 7D F8 98 06 A1 CF 3B 2E 8A D6 27 EA 32 2C 1C AA DA 05 2E 02 5D 61 D3 75 9B 8B E4 F0 6A 81 19 45 CD 4A C0 E9 40 32 8F A5 26 E9 36 DE 49 2D A4 E1 10 92 B2 F4 9F 1B 1D C7 A1 06 FA FF 5C B7 D1 51 16 67 15 F5 A6 97 54 59 2D 16 F3 0B 57 85 74 BE 45 D3 03 61 02 23 EB 54 B6 55 08 B3 E5 D9 CF 29 "
        expected_after_iota = "E7 8D C2 68 29 1E 83 9E 3C 6E 06 9A BF 29 0E 45 9A 2E A6 39 96 FA F2 BE 10 92 76 B8 4D BD EC A2 25 54 8E F6 87 F2 44 EC A3 D8 5E B0 F0 69 9A 92 FE 0A D5 6E 38 AA 8E 5A 41 42 6F D0 29 69 1A E1 1D 1D 43 02 2B 85 B4 4A F9 83 C2 58 8A CC 47 4B 3A 9F E8 7A 32 12 14 63 5C 27 1D 7E 1E 29 85 88 E6 F8 DC FB 03 09 44 91 7D F8 98 06 A1 CF 3B 2E 8A D6 27 EA 32 2C 1C AA DA 05 2E 02 5D 61 D3 75 9B 8B E4 F0 6A 81 19 45 CD 4A C0 E9 40 32 8F A5 26 E9 36 DE 49 2D A4 E1 10 92 B2 F4 9F 1B 1D C7 A1 06 FA FF 5C B7 D1 51 16 67 15 F5 A6 97 54 59 2D 16 F3 0B 57 85 74 BE 45 D3 03 61 02 23 EB 54 B6 55 08 B3 E5 D9 CF 29"
        handler_before = SHA3_ValueHandler.fromHexString(expected_after_chi)
        handler_expected = SHA3_ValueHandler.fromHexString(expected_after_iota)

        state = SHA3_StateArray.fromValueHandler(handler_before)
        state.iota(2)
        print(f"before   : {handler_before.getHexString()}")
        print(f"expected : {handler_expected.getHexString()}")
        handler_after = state.getValueHandler()
        print(f"after    : {handler_after.getHexString()}")
        
    def test_sha3_round(self):
        print("Testing Round")
        expected_before_theta ='D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
        expected_after_iota = "D2 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00"
        handler_before = SHA3_ValueHandler.fromHexString(expected_before_theta)
        handler_expected = SHA3_ValueHandler.fromHexString(expected_after_iota)

        state = SHA3_StateArray.fromValueHandler(handler_before)
        state.round(0)
        print(f"before   : {handler_before.getHexString()}")
        print(f"expected : {handler_expected.getHexString()}")
        handler_after = state.getValueHandler()
        print(f"after    : {handler_after.getHexString()}")

        self.assertEqual(handler_after, handler_expected)

    def test_sha224(self):
        '''
        This function tests the sha3-224 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
        sha3 = SHA3_224()
        bit_array_input = [1,1,0,0,1]
        result = sha3.hashBitArray(bit_array_input)
        expected_result = "FF BA D5 DA 96 BA D7 17 89 33 02 06 DC 67 68 EC AE B1 B3 2D CA 6B 33 01 48 96 74 AB"
        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print("Testing SHA3-224 With 5 Bit Input")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha224_30bit(self):
        '''
        This function tests the sha3-224 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
        sha3 = SHA3_224()
        bit_array_input = [1,1,0,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,0,0,1,1,0]
        result = sha3.hashBitArray(bit_array_input)
        expected_result = "D6 66 A5 14 CC 9D BA 25 AC 1B A6 9E D3 93 04 60 DE AA C9 85 1B 5F 0B AA B0 07 DF 3B"
        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print("Testing SHA3-224 With 30 Bit Input")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha256(self):
        '''
        This function tests the sha3-256 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        sha3 = SHA3_256()
        bit_array_input = [1,1,0,0,1]
        result = sha3.hashBitArray(bit_array_input)
        expected_result = "7B 00 47 CF 5A 45 68 82 36 3C BF 0F B0 53 22 CF 65 F4 B7 05 9A 46 36 5E 83 01 32 E3 B5 D9 57 AF"
        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print("Testing SHA3-256 With 5 Bit Input")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha256_30bit(self):
        '''
        This function tests the sha3-256 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        sha3 = SHA3_256()
        bit_array_input = [1,1,0,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,0,0,1,1,0]
        result = sha3.hashBitArray(bit_array_input)
        expected_result = "C8 24 2F EF 40 9E 5A E9 D1 F1 C8 57 AE 4D C6 24 B9 2B 19 80 9F 62 AA 8C 07 41 1C 54 A0 78 B1 D0"
        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print("Testing SHA3-256 With 30 Bit Input")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha384(self):
        '''
        This function tests the sha3-384 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''

        sha3 = SHA3_384()
        bit_array_input = [1,1,0,0,1]
        result = sha3.hashBitArray(bit_array_input)
        expected_result = "73 7C 9B 49 18 85 E9 BF 74 28 E7 92 74 1A 7B F8 DC A9 65 34 71 C3 E1 48 47 3F 2C 23 6B 6A 0A 64 55 EB 1D CE 9F 77 9B 4B 6B 23 7F EF 17 1B 1C 64"
        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print("Testing SHA3-384 With 5 Bit Input")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha384_30bit(self):
        '''
        This function tests the sha3-384 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''

        sha3 = SHA3_384()
        bit_array_input = [1,1,0,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,0,0,1,1,0]
        result = sha3.hashBitArray(bit_array_input)        
        expected_result = "95 5B 4D D1 BE 03 26 1B D7 6F 80 7A 7E FD 43 24 35 C4 17 36 28 11 B8 A5 0C 56 4E 7E E9 58 5E 1A C7 62 6D DE 2F DC 03 0F 87 61 96 EA 26 7F 08 C3"
        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print("Testing SHA3-384 With 30 Bit Input")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha512(self):
        '''
        This function tests the sha3-512 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        sha3 = SHA3_512()
        bit_array_input = [1,1,0,0,1]
        result = sha3.hashBitArray(bit_array_input)
        expected_result = "A1 3E 01 49 41 14 C0 98 00 62 2A 70 28 8C 43 21 21 CE 70 03 9D 75 3C AD D2 E0 06 E4 D9 61 CB 27 54 4C 14 81 E5 81 4B DC EB 53 BE 67 33 D5 E0 99 79 5E 5E 81 91 8A DD B0 58 E2 2A 9F 24 88 3F 37"
        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print("Testing SHA3-512 With 5 Bit Input")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_sha512_30bit(self):
        '''
        This function tests the sha3-512 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        sha3 = SHA3_512()
        bit_array_input = [1,1,0,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,0,0,1,1,0]
        result = sha3.hashBitArray(bit_array_input) 
        expected_result = "98 34 C0 5A 11 E1 C5 D3 DA 9C 74 0E 1C 10 6D 9E 59 0A 0E 53 0B 6F 6A AA 78 30 52 5D 07 5C A5 DB 1B D8 A6 AA 98 1A 28 61 3A C3 34 93 4A 01 82 3C D4 5F 45 E4 9B 6D 7E 69 17 F2 F1 67 78 06 7B AB"        
        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print("Testing SHA3-512 With 30 Bit Input")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString())

    def test_shake_128(self):
        '''
        This function tests the shake-128 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        shake = SHAKE_128()
        bit_array_input = [1,1,0,0,1]
        digest_length_hex = 56
        result = shake.hashBitArray(bit_array_input,digest_length_hex*4)
        expected_result = "2E 0A BF BA 83 E6 72 0B FB C2 25 FF 6B 7A B9 FF CE 58 BA 02 7E E3 D8 98 76 4F EF 28 7D DE CC CA 3E 6E 59 98 41 1E 7D DB 32 F6 75 38 F5 00 B1 8C 8C 97 C4 52 C3 70 EA 2C F0 AF CA 3E 05 DE 7E 4D E2 7F A4 41 A9 CB 34 FD 17 C9 78 B4 2D 5B 7E 7F 9A B1 8F FE FF C3 C5 AC 2F 3A 45 5E EB FD C7 6C EA EB 0A 2C CA 22 EE F6 E6 37 F4 CA BE 5C 51 DE D2 E3 FA D8 B9 52 70 A3 21 84 56 64 F1 07 D1 64 96 BB 7A BF BE 75 04 B6 ED E2 E8 9E 4B 99 6F B5 8E FD C4 18 1F 91 63 38 1C BE 7B C0 06 A7 A2 05 98 9C 52 6C D1 BD 68 98 36 93 B4 BD C5 37 28 B2 41 C1 CF F4 2B B6 11 50 2C 35 20 5C AB B2 88 75 56 55 D6 20 C6 79 94 F0 64 51 18 7F 6F D1 7E 04 66 82 BA 12 86 06 3F F8 8F E2 50 8D 1F CA F9 03 5A 12 31 AD 41 50 A9 C9 B2 4C 9B 2D 66 B2 AD 1B DE 0B D0 BB CB 8B E0 5B 83 52 29 EF 79 19 73 73 23 42 44 01 E1 D8 37 B6 6E B4 E6 30 FF 1D E7 0C B3 17 C2 BA CB 08 00 1D 34 77 B7 A7 0A 57 6D 20 86 90 33 58 9D 85 A0 1D DB 2B 66 46 C0 43 B5 9F C0 11 31 1D A6 66 FA 5A D1 D6 38 7F A9 BC 40 15 A3 8A 51 D1 DA 1E A6 1D 64 8D C8 E3 9A 88 B9 D6 22 BD E2 07 FD AB C6 F2 82 7A 88 0C 33 0B BF 6D F7 33 77 4B 65 3E 57 30 5D 78 DC E1 12 F1 0A 2C 71 F4 CD AD 92 ED 11 3E 1C EA 63 B9 19 25 ED 28 19 1E 6D BB B5 AA 5A 2A FD A5 1F C0 5A 3A F5 25 8B 87 66 52 43 55 0F 28 94 8A E2 B8 BE B6 BC 9C 77 0B 35 F0 67 EA A6 41 EF E6 5B 1A 44 90 9D 1B 14 9F 97 EE A6 01 39 1C 60 9E C8 1D 19 30 F5 7C 18 A4 E0 FA B4 91 D1 CA DF D5 04 83 44 9E DC 0F 07 FF B2 4D 2C 6F 9A 9A 3B FF 39 AE 3D 57 F5 60 65 4D 7D 75 C9 08 AB E6 25 64 75 3E AC 39 D7 50 3D A6 D3 7C 2E 32 E1 AF 3B 8A EC 8A E3 06 9C D9"
        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print(f"Testing Shake-128 With 5 Bit Input and {digest_length_hex*4} bit digest length")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()[:digest_length_hex]}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString()[:digest_length_hex])

        digest_length_hex = 128
        result = shake.hashBitArray(bit_array_input,digest_length_hex*4)
        print(f"Testing Shake-128 With 5 Bit Input and {digest_length_hex*4} bit digest length")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()[:digest_length_hex]}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString()[:digest_length_hex])

    def test_shake_256(self):
        '''
        This function tests the shake-256 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        shake = SHAKE_256()
        bit_array_input = [1,1,0,0,1]
        digest_length_hex = 56
        result = shake.hashBitArray(bit_array_input,digest_length_hex*4)
        expected_result = "48 A5 C1 1A BA EE FF 09 2F 36 46 EF 0D 6B 3D 3F F7 6C 2F 55 F9 C7 32 AC 64 70 C0 37 64 00 82 12 E2 1B 14 67 77 8B 18 19 89 F8 88 58 21 1B 45 DF 87 99 CF 96 1F 80 0D FA C9 9E 64 40 39 E2 97 9A 40 16 F5 45 6F F4 21 C5 B3 85 DA 2B 85 5D A7 E3 1C 8C 2E 8E 4B A4 1E B4 09 5C B9 99 D9 75 9C B4 03 58 DA 85 62 A2 E6 13 49 E0 5A 2E 13 F1 B7 4E C9 E6 9F 5B 42 6D C7 41 38 FF CD C5 71 C3 2B 39 B9 F5 55 63 E1 A9 9D C4 22 C3 06 02 6D 6A 0F 9D E8 51 62 B3 86 79 4C A0 68 8B 76 4B 3D 32 20 0C C4 59 74 97 32 A0 F3 A3 41 C0 EF C9 6A 22 C6 3B AD 7D 96 CC 9B A4 76 8C 6F CF A1 F2 00 10 7C F9 FA E5 C0 D7 54 95 8C 5A 75 6B 37 6A 3B E6 9F 88 07 4F 20 0E 9E 95 A8 CA 5B CF 96 99 98 DB 1D C3 7D 0D 3D 91 6F 6C AA B3 F0 37 82 C9 C4 4A 2E 14 E8 07 86 BE CE 45 87 B9 EF 82 CB F4 54 E0 E3 4B D1 75 AE 57 D3 6A F4 E7 26 B2 21 33 2C ED 36 C8 CE 2E 06 20 3C 65 6A E8 DA 03 7D 08 E7 16 0B 48 0C 1A 85 16 BF 06 DD 97 BF 4A A4 C0 24 93 10 DC 0B 06 5D C6 39 57 63 55 38 4D 16 5C 6A 50 9B 12 F7 BB D1 E1 5B 22 BC E0 2F A0 48 DD FA AC F7 41 5F 49 B6 32 4C 1D 06 7B 52 64 E1 12 5F 7F 75 42 7F 31 2B D9 34 6E B4 E4 00 B1 F7 CB 31 28 8C 9E 3F 73 5E CA 9C ED 0D B8 88 E2 E2 F4 02 24 3B D6 46 18 A2 3E 10 F9 C2 29 39 74 40 54 2D 0A B1 B2 E1 0D AC C5 C9 5E 59 7F 2C 7E A3 84 38 10 5F 97 80 3D BB 03 FC C0 FD 41 6B 09 05 A4 1D 18 4D EB 23 89 05 77 58 91 F9 35 01 FB 41 76 A3 BD 6C 46 44 61 D3 6E E8 B0 08 AA BD 9E 26 A3 40 55 E8 0C 8C 81 3E EB A0 7F 72 8A B3 2B 15 60 5A D1 61 A0 66 9F 6F CE 5C 55 09 FB B6 AF D2 4A EA CC 5F A4 A5 15 23 E6 B1 73 24 6E D4 BF A5 21 D7 4F C6 BB"

        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print(f"Testing Shake-256 With 5 Bit Input and {digest_length_hex*4} bit digest length")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()[:digest_length_hex]}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString()[:digest_length_hex])

        digest_length_hex = 128
        result = shake.hashBitArray(bit_array_input,digest_length_hex*4)
        print(f"Testing Shake-256 With 5 Bit Input and {digest_length_hex*4} bit digest length")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()[:digest_length_hex]}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString()[:digest_length_hex])

    def test_shake_128_30bit(self):
        '''
        This function tests the shake-128 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        shake = SHAKE_128()
        bit_array_input = [1,1,0,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,0,0,1,1,0]
        digest_length_hex = 32
        result = shake.hashBitArray(bit_array_input,digest_length_hex*4)
        expected_result = "6D 5D 39 C5 5F 3C CA 56 7F EA F4 22 DC 64 BA 17 40 1D 07 75 6D 78 B0 FA 3D 54 6D 66 AF C2 76 71 E0 01 06 85 FC 69 A7 EC 3C 53 67 B8 FA 5F DA 39 D5 7C E5 3F 15 3F A4 03 1D 27 72 06 77 0A EC 6B 2D DF 16 AE FA B6 69 11 0D 6E 4A 29 6A 14 FB 14 86 B0 84 6B 69 05 43 E4 05 7F 7F 42 AA 8C 0E 6A 5A 56 B6 0B 68 8D 55 A1 96 DF 6F 39 76 E3 06 88 CB B6 AF D4 85 25 D7 64 90 35 7F 3F D8 97 BA FC 87 36 D9 07 B9 BA C8 16 59 1F C2 4E 79 36 0B E3 A7 FF A6 29 82 C4 5A BB 0E 58 4C 07 EC 93 A1 95 30 50 9D 9F 81 62 15 D7 27 7B B9 99 43 7C 82 14 50 F0 75 92 81 CD 8E 16 A3 48 3E 3C C7 52 09 1B 7A AE 92 90 9D 2F 50 1E F7 DC E9 89 75 98 91 B3 37 7C EA B4 93 FF E4 96 01 0A 0C 7E 51 95 99 94 F5 6F 56 5E 63 3A F6 09 3A C6 E1 E0 F0 04 88 71 EC 47 78 F4 8E F8 BD 5B CB 80 EA 7D F9 FF 47 11 C8 1E 24 C0 22 1C 2A D9 74 4F BA 79 35 EA EC A1 14 22 4F D1 08 EF C5 AC 74 C6 62 52 08 92 75 B4 27 76 73 70 8C 4A F9 2F 88 13 B1 93 59 9F D6 4B D7 48 4F 2E 5E C3 69 E3 64 64 99 76 8E 58 1D D0 53 AA 48 14 D8 BF 1A CF F5 FD 77 45 19 A7 49 BE 66 75 47 41 EB C5 36 22 12 A9 FE A8 A8 14 E9 E0 10 BC 27 20 B3 B7 D9 4F AB 74 BC 7F 92 3E 10 72 B8 A5 DD DD A8 3B A0 15 7D 8C BA 55 C1 92 DF 69 65 CB 7D BA 46 A3 34 0D F8 C3 FA 89 C7 C4 DB 53 9D 38 DC 40 6F 1D 2C F5 4E 59 05 58 0B 44 04 BF D7 B3 71 95 61 C5 A5 9D 5D FD B1 BF 93 DF 13 82 52 25 ED CC E0 FA 7D 87 EF CD 23 9F EB 49 FC 9E 2D E9 D8 28 FE EB 1F 2C F5 79 B9 5D D0 50 AB 2C A4 71 05 A8 D3 0F 3F D2 A1 15 4C 15 F8 7F B3 7B 2C 71 56 BD 7F 3C F2 B7 45 C9 12 A4 0B C1 B5 59 B6 56 E3 E9 03 CC 57 33 E8 6B A1 5D FE F7 06 78"
        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print(f"Testing Shake-128 With 30 Bit Input and {digest_length_hex*4} bit digest length")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()[:digest_length_hex]}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString()[:digest_length_hex])

        digest_length_hex = 96
        result = shake.hashBitArray(bit_array_input,digest_length_hex*4)
        print(f"Testing Shake-128 With 30 Bit Input and {digest_length_hex*4} bit digest length")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()[:digest_length_hex]}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString()[:digest_length_hex])

    def test_shake_256_30bit(self):
        '''
        This function tests the shake-256 hash creation

        Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        '''
         
        shake = SHAKE_256()
        bit_array_input = [1,1,0,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,0,0,1,1,0]
        digest_length_hex = 32
        result = shake.hashBitArray(bit_array_input,digest_length_hex*4)
        expected_result = "46 5D 08 1D FF 87 5E 39 62 00 E4 48 1A 3E 9D CD 88 D0 79 AA 6D 66 22 6C B6 BA 45 41 07 CB 81 A7 84 1A B0 29 60 DE 27 9C CB E3 4B 42 C3 65 85 AD 86 96 4D B0 DB 52 B6 E7 B4 36 9E CE 8F 72 48 58 9B A7 8A B1 82 8F FC 33 5C B1 23 97 11 9B FD 2B 87 EB 78 98 AE B9 56 B6 F2 3D DF 0B D4 00 43 86 A8 E5 26 55 4E F4 E4 83 FA CE E3 0D D3 2E 20 4F FF 8C 36 BB D6 02 A5 76 D1 39 08 9C 75 A8 05 02 66 FC BF 72 1E 44 43 DE 46 45 83 29 22 EB 8A AE 39 D1 F5 72 84 53 64 81 7B 00 33 54 38 99 94 00 23 F2 E9 65 A6 0A 80 EB 22 1E B1 9D C5 7B 12 12 91 56 4C 6F 69 35 83 B3 AC 7C 6F 27 2F 4F 67 A1 9A 76 78 D4 23 4B 0B F4 A2 EB C0 8A A2 35 B9 78 8D B7 87 16 1F 66 17 02 28 65 C0 EF 9A A5 33 80 2D 13 6C DB C7 AE BA 53 2A CF 1B E1 83 B0 29 5A B0 E3 3A 2E F6 9B E3 56 DA AF 30 96 87 15 3E 2F 99 A1 24 36 09 D6 03 12 6A 8C 82 3E 88 43 E4 59 BF C7 2B 30 69 1C DC C3 DD B2 7C F0 28 AF D5 1E 44 37 EE 3B 71 C0 C1 EC 87 A9 34 36 F0 C2 47 B7 E8 C5 0C E9 68 25 C9 70 29 99 7A 74 C3 18 AF AC AA 18 A0 18 0B C7 F2 F0 F1 C5 E7 EF 1A 2D 18 3A C7 EE 7E 49 15 C3 B6 8C 30 97 8A B6 C4 28 19 34 41 DF 47 05 B7 22 CE 25 A0 8A 1F AD CA 0E EF 1F AF E8 3A DF 13 02 1D 52 0D E5 C8 27 FF 9A 97 B7 55 46 19 3A 9B 92 3F 05 90 38 5D C4 BF F7 C4 9D 49 15 B5 A3 65 DB 4C 84 DD CB 18 5D E8 F9 EE B3 34 96 5A 42 F1 38 1C 8B AD C2 2B A1 F8 EE 4C 0E 4D AA F7 A8 8E 7F 42 DD B8 14 8F 3B F8 D3 B8 D7 4F 09 81 55 A3 7C B4 CB 27 87 6B 85 DA 60 2E 5C 78 9C 10 E0 3B E7 34 07 BA B8 C4 92 13 F8 C7 4E 12 66 CE 9B 11 28 6E 67 4C A9 C1 0C 9C 99 55 04 9A 66 E9 05 1D 9A 2B 1F C9 AF E2 67 98 E9 CE C6"
        
        handler_expected = SHA3_ValueHandler.fromHexString(expected_result)
        print(f"Testing Shake-256 With 30 Bit Input and {digest_length_hex*4} bit digest length")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()[:digest_length_hex]}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString()[:digest_length_hex])

        digest_length_hex = 96
        result = shake.hashBitArray(bit_array_input,digest_length_hex*4)
        print(f"Testing Shake-256 With 30 Bit Input and {digest_length_hex*4} bit digest length")
        print(f"input    : {bit_array_input}")
        print(f"expected : {handler_expected.getHexString()[:digest_length_hex]}")
        print(f"digest   : {result.getHexString()}")
        
        self.assertEqual(result.getHexString(),handler_expected.getHexString()[:digest_length_hex])


if __name__ == '__main__':
    unittest.main()