import unittest
from CryptographySchemes.SecureHashAlgorithm3 import *
from math import log2

def format_hex_as_bit_string(hex_string:str):
    hex_string = hex_string.replace(" ","")
    hex_len = len(hex_string)
    value = int(hex_string,16)
    bit_string = '{0:0{1}b}'.format(value,hex_len*4)
    return bit_string

def format_bit_as_hex_string(bit_string:str):
    bit_string = bit_string.replace(" ","")
    bit_len = len(bit_string)
    value = int(bit_string,2)
    bin_string = '{0:0{1}x}'.format(value,bit_len//4).upper()
    return bin_string

class SHA3_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for aes
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        self.sha3_224 = SHA3_224()
        self.sha3_256 = SHA3_256()
        self.sha3_384 = SHA3_384()
        self.sha3_512 = SHA3_512()

        self.bit_string_input_5bit = "11001"
        self.maxDiff = None

    def test_sha224(self):
        '''
        This function tests the sha3-224 hash creation
        '''

        result = self.sha3_224.hashBinaryStringToHex(self.bit_string_input_5bit)
        expected_result = "FF BA D5 DA 96 BA D7 17 89 33 02 06 DC 67 68 EC AE B1 B3 2D CA 6B 33 01 48 96 74 AB"
        print(f"sha 224 hash of 11001 is {result}")
        self.assertEqual(len(result), 224//4)
        self.assertEqual(expected_result.replace(" ",""),result)
    def test_sha256(self):
        '''
        This function tests the sha3-256 hash creation
        '''
         
        result = self.sha3_256.hashBinaryStringToHex(self.bit_string_input_5bit)
        expected_result = "7B 00 47 CF 5A 45 68 82 36 3C BF 0F B0 53 22 CF 65 F4 B7 05 9A 46 36 5E 83 01 32 E3 B5 D9 57 AF"

        print(f"sha 256 hash of 11001 is {result}")
        self.assertEqual(len(result), 256//4)
        self.assertEqual(expected_result.replace(" ",""),result)

    def test_sha384(self):
        '''
        This function tests the sha3-384 hash creation
        '''

        result = self.sha3_384.hashBinaryStringToHex(self.bit_string_input_5bit)

        expected_result = "73 7C 9B 49 18 85 E9 BF 74 28 E7 92 74 1A 7B F8 DC A9 65 34 71 C3 E1 48 47 3F 2C 23 6B 6A 0A 64 55 EB 1D CE 9F 77 9B 4B 6B 23 7F EF 17 1B 1C 64"
        print(f"sha 384 hash of 11001 is {result}")
        self.assertEqual(len(result), 384//4)
        self.assertEqual(expected_result.replace(" ",""),result)

    def test_sha512(self):
        '''
        This function tests the sha3-512 hash creation
        '''
         
        result = self.sha3_512.hashBinaryStringToHex(self.bit_string_input_5bit)
        expected_result = "A1 3E 01 49 41 14 C0 98 00 62 2A 70 28 8C 43 21 21 CE 70 03 9D 75 3C AD D2 E0 06 E4 D9 61 CB 27 54 4C 14 81 E5 81 4B DC EB 53 BE 67 33 D5 E0 99 79 5E 5E 81 91 8A DD B0 58 E2 2A 9F 24 88 3F 37"
        
        print(f"sha 512 hash of 11001 is {result}")
        self.assertEqual(len(result), 512//4)
        self.assertEqual(expected_result.replace(" ",""),result)

    def test_state_array_to_bit_string_25bit(self):
        '''
        This method tests converting a bit string to a state array and back to ensure the bit placements are consistent
        With a 25 bit string
        '''

        bit_string = "0100000100010000010010111"
        state_array = bitStringToStateArray(bit_string)
        converted_back = stateArrayToBitString(state_array)
        self.assertEqual(bit_string,converted_back)
    
    def test_state_array_to_bit_string_1600bit(self):
        '''
        This method tests converting a bit string to a state array and back to ensure the bit placements are consistent
        With a 1600 bit string
        '''

        bit_string = "0100000100010000010010111010100010001000001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001111001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001111101000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001000001011111000100101110100000100011100010010111" \
        "0100000100010000010010111010100010001000001001011001000001000100000100101110100000100011100010010111" \
        "0100000100010000010000000010100010001000001001011001000001000100000100101110100000100011100010010111"
        state_array = bitStringToStateArray(bit_string)
        converted_back = stateArrayToBitString(state_array)
        self.assertEqual(bit_string,converted_back)

    def test_sha3_224_theta(self):
        '''
        This function tests the the theta method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''
        
        expected_before_theta ='D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
        expected_after_theta = 'D3 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00'
        binary_before_theta = h2b(expected_before_theta)
        self.assertEqual(expected_before_theta.replace(" ",""),b2h(binary_before_theta))
        self.assertEqual(binary_before_theta,stateArrayToBitString(bitStringToStateArray(binary_before_theta)))
        theta_result = theta(bitStringToStateArray(binary_before_theta))
        self.assertEqual(b2h(stateArrayToBitString(theta_result)),expected_after_theta.replace(" ",""))
   
    def test_sha3_224_theta_second(self):
        '''
        This function tests the the theta method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''

        expected_before_theta = "D2 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00"
        expected_after_theta = '9A CF EA 26 00 E0 63 00 E6 DF C6 3B 0D 55 0C 01 EE E8 3B 6A 1A E0 63 00 0B CD 69 25 00 93 1A 01 9B F5 7E 4A 17 C6 16 00 48 CF EA 2E 00 E0 63 00 E6 DF B6 21 0D 35 1B 01 EE 68 52 6A 1A E0 63 00 D8 CD 79 2D 00 D3 00 01 9B 75 77 58 17 E6 1B 00 EC CE EA 27 00 E0 63 00 E6 79 D7 3B 0D 75 01 01 EE 68 52 6B 1A E0 63 00 7C 6A 78 25 00 93 1A 01 9B 75 17 4A 17 E6 1B 00 48 87 E9 16 0D E0 63 00 E6 DF D6 3B 0D 75 01 01 EE 20 51 6A 1A E0 E3 00 D8 8D 79 15 0D 93 1A 01 9B 75 17 4A 17 E6 9B 00 48 CF EA 26 00 33 63 00 E6 DF D6 3B 0D 75 41 01 A6 6B 52 6A 1A 33 63 00 D8 CD 79 25 00 93 1A 01 D3 76 17 4A 17 E6 5B 00'
        binary_before_theta = h2b(expected_before_theta)
        self.assertEqual(expected_before_theta.replace(" ",""),b2h(binary_before_theta))
        self.assertEqual(binary_before_theta,stateArrayToBitString(bitStringToStateArray(binary_before_theta)))
        theta_result = theta(bitStringToStateArray(binary_before_theta))
        self.assertEqual(b2h(stateArrayToBitString(theta_result)),expected_after_theta.replace(" ",""))
   
    def test_sha3_224_rho(self):
        '''
        This function tests the the rho method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''

        expected_after_theta = 'D3 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00'
        expected_after_rho = "D3 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 40 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 69 00 00 00 00 00 "
        binary_after_theta = h2b(expected_after_theta)
        self.assertEqual(expected_after_theta.replace(" ",""),b2h(binary_after_theta))
        self.assertEqual(binary_after_theta,stateArrayToBitString(bitStringToStateArray(binary_after_theta)))
        rho_result = rho(bitStringToStateArray(binary_after_theta))
        self.assertEqual(b2h(stateArrayToBitString(rho_result)),expected_after_rho.replace(" ",""))
   
    def test_sha3_224_pi(self):
        '''
        This function tests the the pi method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''

        expected_after_rho = "D3 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 40 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 69 00 00 00 00 00 "
        expected_after_pi = "D3 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 80 69 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 "
        binary_after_rho = format_hex_as_bit_string(expected_after_rho)
        self.assertEqual(expected_after_rho.replace(" ",""),format_bit_as_hex_string(binary_after_rho))
        self.assertEqual(binary_after_rho,stateArrayToBitString(bitStringToStateArray(binary_after_rho)))
        pi_result = pi(bitStringToStateArray(binary_after_rho))
        self.assertEqual(format_bit_as_hex_string(stateArrayToBitString(pi_result)),expected_after_pi.replace(" ",""))
   
    def test_sha3_224_chi(self):
        '''
        This function tests the the chi method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''

        expected_after_pi = "D3 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 80 69 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 "
        expected_after_chi = "D3 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00 "
        binary_after_pi = format_hex_as_bit_string(expected_after_pi)
        self.assertEqual(expected_after_pi.replace(" ",""),format_bit_as_hex_string(binary_after_pi))
        self.assertEqual(binary_after_pi,stateArrayToBitString(bitStringToStateArray(binary_after_pi)))
        chi_result = chi(bitStringToStateArray(binary_after_pi))
        self.assertEqual(format_bit_as_hex_string(stateArrayToBitString(chi_result)),expected_after_chi.replace(" ",""))
   
    def test_sha3_224_iota(self):
        '''
        This function tests the the iota method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''

        expected_after_chi = "D3 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00 "
        expected_after_iota = "D2 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00"
        binary_after_chi = h2b(expected_after_chi)
        self.assertEqual(expected_after_chi.replace(" ",""),b2h(binary_after_chi))
        self.assertEqual(binary_after_chi,stateArrayToBitString(bitStringToStateArray(binary_after_chi)))
        iota_result = iota(bitStringToStateArray(binary_after_chi),12+21-33)
        self.assertEqual(b2h(stateArrayToBitString(iota_result)),expected_after_iota.replace(" ",""))
   
    def test_sha3_224_iota_second(self):
        '''
        This function tests the the iota method

        Expected output pulled from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
        '''

        expected_after_chi = "6D 0D C2 68 29 1E 83 1E 3C 6E 06 9A BF 29 0E 45 9A 2E A6 39 96 FA F2 BE 10 92 76 B8 4D BD EC A2 25 54 8E F6 87 F2 44 EC A3 D8 5E B0 F0 69 9A 92 FE 0A D5 6E 38 AA 8E 5A 41 42 6F D0 29 69 1A E1 1D 1D 43 02 2B 85 B4 4A F9 83 C2 58 8A CC 47 4B 3A 9F E8 7A 32 12 14 63 5C 27 1D 7E 1E 29 85 88 E6 F8 DC FB 03 09 44 91 7D F8 98 06 A1 CF 3B 2E 8A D6 27 EA 32 2C 1C AA DA 05 2E 02 5D 61 D3 75 9B 8B E4 F0 6A 81 19 45 CD 4A C0 E9 40 32 8F A5 26 E9 36 DE 49 2D A4 E1 10 92 B2 F4 9F 1B 1D C7 A1 06 FA FF 5C B7 D1 51 16 67 15 F5 A6 97 54 59 2D 16 F3 0B 57 85 74 BE 45 D3 03 61 02 23 EB 54 B6 55 08 B3 E5 D9 CF 29 "
        expected_after_iota = "E7 8D C2 68 29 1E 83 9E 3C 6E 06 9A BF 29 0E 45 9A 2E A6 39 96 FA F2 BE 10 92 76 B8 4D BD EC A2 25 54 8E F6 87 F2 44 EC A3 D8 5E B0 F0 69 9A 92 FE 0A D5 6E 38 AA 8E 5A 41 42 6F D0 29 69 1A E1 1D 1D 43 02 2B 85 B4 4A F9 83 C2 58 8A CC 47 4B 3A 9F E8 7A 32 12 14 63 5C 27 1D 7E 1E 29 85 88 E6 F8 DC FB 03 09 44 91 7D F8 98 06 A1 CF 3B 2E 8A D6 27 EA 32 2C 1C AA DA 05 2E 02 5D 61 D3 75 9B 8B E4 F0 6A 81 19 45 CD 4A C0 E9 40 32 8F A5 26 E9 36 DE 49 2D A4 E1 10 92 B2 F4 9F 1B 1D C7 A1 06 FA FF 5C B7 D1 51 16 67 15 F5 A6 97 54 59 2D 16 F3 0B 57 85 74 BE 45 D3 03 61 02 23 EB 54 B6 55 08 B3 E5 D9 CF 29"
        binary_after_chi = h2b(expected_after_chi)
        self.assertEqual(expected_after_chi.replace(" ",""),b2h(binary_after_chi))
        self.assertEqual(binary_after_chi,stateArrayToBitString(bitStringToStateArray(binary_after_chi)))
        iota_result = iota(bitStringToStateArray(binary_after_chi),2)
        self.assertEqual(b2h(stateArrayToBitString(iota_result)),expected_after_iota.replace(" ",""))
   
if __name__ == '__main__':
    unittest.main()