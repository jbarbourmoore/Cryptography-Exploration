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

    # def test_sha3_224_theta(self):
        
    #     expected_before_theta ='D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
    #     expected_after_theta = 'D3 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00'
    #     binary_before_theta = format_hex_as_bit_string(expected_before_theta)
    #     self.assertEqual(expected_before_theta.replace(" ",""),format_bit_as_hex_string(binary_before_theta))
    #     self.assertEqual(binary_before_theta,stateArrayToBitString(bitStringToStateArray(binary_before_theta)))
    #     theta_result = theta(bitStringToStateArray(binary_before_theta))
    #     self.assertEqual(format_bit_as_hex_string(stateArrayToBitString(theta_result)),expected_after_theta.replace(" ",""))
   
    # def test_sha3_224_theta_second(self):
        
    #     expected_before_theta = "D2 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00"
    #     expected_after_theta = '9A CF EA 26 00 E0 63 00 E6 DF C6 3B 0D 55 0C 01 EE E8 3B 6A 1A E0 63 00 0B CD 69 25 00 93 1A 01 9B F5 7E 4A 17 C6 16 00 48 CF EA 2E 00 E0 63 00 E6 DF B6 21 0D 35 1B 01 EE 68 52 6A 1A E0 63 00 D8 CD 79 2D 00 D3 00 01 9B 75 77 58 17 E6 1B 00 EC CE EA 27 00 E0 63 00 E6 79 D7 3B 0D 75 01 01 EE 68 52 6B 1A E0 63 00 7C 6A 78 25 00 93 1A 01 9B 75 17 4A 17 E6 1B 00 48 87 E9 16 0D E0 63 00 E6 DF D6 3B 0D 75 01 01 EE 20 51 6A 1A E0 E3 00 D8 8D 79 15 0D 93 1A 01 9B 75 17 4A 17 E6 9B 00 48 CF EA 26 00 33 63 00 E6 DF D6 3B 0D 75 41 01 A6 6B 52 6A 1A 33 63 00 D8 CD 79 25 00 93 1A 01 D3 76 17 4A 17 E6 5B 00'
    #     binary_before_theta = format_hex_as_bit_string(expected_before_theta)
    #     self.assertEqual(expected_before_theta.replace(" ",""),format_bit_as_hex_string(binary_before_theta))
    #     self.assertEqual(binary_before_theta,stateArrayToBitString(bitStringToStateArray(binary_before_theta)))
    #     theta_result = theta(bitStringToStateArray(binary_before_theta))
    #     self.assertEqual(format_bit_as_hex_string(stateArrayToBitString(theta_result)),expected_after_theta.replace(" ",""))
   
    def test_sha3_224_rho(self):
        expected_after_theta = 'D3 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00'
        expected_after_rho = "D3 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 40 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 69 00 00 00 00 00 "
        binary_after_theta = format_hex_as_bit_string(expected_after_theta)
        self.assertEqual(expected_after_theta.replace(" ",""),format_bit_as_hex_string(binary_after_theta))
        self.assertEqual(binary_after_theta,stateArrayToBitString(bitStringToStateArray(binary_after_theta)))
        rho_result = rho(bitStringToStateArray(binary_after_theta))
        self.assertEqual(format_bit_as_hex_string(stateArrayToBitString(rho_result)),expected_after_rho.replace(" ",""))
   
    def test_sha3_224_pi(self):
        expected_after_rho = "D3 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 40 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 69 00 00 00 00 00 "
        expected_after_pi = "D3 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 80 69 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 "
        binary_after_rho = format_hex_as_bit_string(expected_after_rho)
        self.assertEqual(expected_after_rho.replace(" ",""),format_bit_as_hex_string(binary_after_rho))
        self.assertEqual(binary_after_rho,stateArrayToBitString(bitStringToStateArray(binary_after_rho)))
        pi_result = pi(bitStringToStateArray(binary_after_rho))
        self.assertEqual(format_bit_as_hex_string(stateArrayToBitString(pi_result)),expected_after_pi.replace(" ",""))
   
    def test_sha3_224_chi(self):
        expected_after_pi = "D3 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 80 69 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 "
        expected_after_chi = "D3 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00 "
        binary_after_pi = format_hex_as_bit_string(expected_after_pi)
        self.assertEqual(expected_after_pi.replace(" ",""),format_bit_as_hex_string(binary_after_pi))
        self.assertEqual(binary_after_pi,stateArrayToBitString(bitStringToStateArray(binary_after_pi)))
        chi_result = chi(bitStringToStateArray(binary_after_pi))
        self.assertEqual(format_bit_as_hex_string(stateArrayToBitString(chi_result)),expected_after_chi.replace(" ",""))
   
    # def test_sha3_224_iota(self):
    #     expected_after_chi = "D3 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00 "
    #     expected_after_iota = "D2 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00"
    #     binary_after_chi = format_hex_as_bit_string(expected_after_chi)
    #     self.assertEqual(expected_after_chi.replace(" ",""),format_bit_as_hex_string(binary_after_chi))
    #     self.assertEqual(binary_after_chi,stateArrayToBitString(bitStringToStateArray(binary_after_chi)))
    #     w=64
    #     l=int(log2(w))
    #     nr = 12+2*l
    #     ir = 12+21 - nr
    #     iota_result = iota(bitStringToStateArray(binary_after_chi),ir=ir,w=w,l=l)
        
    #     self.assertEqual(format_bit_as_hex_string(stateArrayToBitString(iota_result)),expected_after_iota.replace(" ",""))
   
if __name__ == '__main__':
    unittest.main()