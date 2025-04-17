from HelperFunctions.IntegerHandler import *
import unittest

class IntegerHandler_UnitTests(unittest.TestCase):
    '''
    This class contains basic unit tests for the integer handler class
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        
    def test_from_binary_array_little(self):
        '''
        This method tests creating a integer handler from a binary array in little endian
        '''
        
        input = [1,0,1,1,1,0,0,0]
        expected_value = 29
        little_endian = True
        handled_value = IntegerHandler.fromBitArray(bit_array=input, little_endian=little_endian)
        print(f"Value : {handled_value.value} little_endian : {little_endian} from : {input}")
        self.assertEqual(handled_value.value, expected_value, f"actual:{handled_value.value} != expected:{expected_value}")
    
    def test_from_binary_array_big(self):
        '''
        This method tests creating a integer handler from a binary array in big endian
        '''
        
        input = [1,0,1,1,1,0,0,0]
        expected_value = 184
        little_endian = False
        handled_value = IntegerHandler.fromBitArray(bit_array=input, little_endian=little_endian)
        print(f"Value : {handled_value.value} little_endian : {little_endian} from : {input}")
        self.assertEqual(handled_value.value, expected_value,f"actual:{handled_value.value} != expected:{expected_value}")

    def test_from_hex_string_big(self):
        '''
        This method tests creating a integer handler from a hex string in big endian
        '''
        
        input = "106132DEE"
        expected_value = 4396887534
        little_endian = False
        handled_value = IntegerHandler.fromHexString(hex_string=input, little_endian=little_endian)
        print(f"Value : {handled_value.value} little_endian : {little_endian} from : {input}")
        self.assertEqual(handled_value.value, expected_value,f"actual:{handled_value.value} != expected:{expected_value}")

    def test_from_hex_string_little(self):
        '''
        This method tests creating a integer handler from a hex string in little endian
        '''

        input = "EE2D13061"
        expected_value = 4396887534
        little_endian = True
        handled_value = IntegerHandler.fromHexString(hex_string=input, little_endian=little_endian)
        print(f"Value : {handled_value.value} little_endian : {little_endian} from : {input}")
        self.assertEqual(handled_value.value, expected_value,f"actual:{handled_value.value} != expected:{expected_value}")

    def test_get_binary_array_little(self):
        '''
        This method tests getting the bit string as little endian
        '''
        input = [1,0,1,1,1,0,0,0]
        expected_value = 29
        expected_array = [1,0,1,1,1,0,0,0]
        expected_array_no_length = [1,0,1,1,1]
        bit_length = 8
        little_endian = True

        handled_value = IntegerHandler.fromBitArray(input,little_endian=little_endian, bit_length=bit_length)
        array = handled_value.getBitArray()
        print(f"Value : {handled_value.value} little_endian : {little_endian} from : {input}")
        self.assertEqual(handled_value.value, expected_value, f"actual:{handled_value.value} != expected:{expected_value}")
        self.assertEqual(array, expected_array, f"actual:{array} != expected:{expected_array}")
        print(f"Array: {array} With bit length: {handled_value.bit_length}")

        handled_value = IntegerHandler.fromBitArray(input,little_endian=little_endian)
        array_no_length = handled_value.getBitArray()
        self.assertEqual(handled_value.value, expected_value, f"actual:{handled_value.value} != expected:{expected_value}")
        self.assertEqual(array_no_length, expected_array_no_length, f"actual:{array_no_length} != expected:{expected_array_no_length}")
        print(f"Array: {array_no_length} With bit length: {handled_value.bit_length}")

    def test_get_binary_array_big(self):
        '''
        This method tests getting the bit string as big endian
        '''
        input = [1,0,1,1,1,0,0,0]
        expected_value = 184
        expected_array = [1,0,1,1,1,0,0,0]
        expected_array_no_length = [1,0,1,1,1,0,0,0]
        bit_length = 8
        little_endian = False

        handled_value = IntegerHandler.fromBitArray(input,little_endian=little_endian, bit_length=bit_length)
        array = handled_value.getBitArray()
        print(f"Value : {handled_value.value} little_endian : {little_endian} from : {input}")
        self.assertEqual(handled_value.value, expected_value, f"actual:{handled_value.value} != expected:{expected_value}")
        self.assertEqual(array, expected_array, f"actual:{array} != expected:{expected_array}")
        print(f"Array: {array} With bit length: {handled_value.bit_length}")

        handled_value = IntegerHandler.fromBitArray(input,little_endian=little_endian)
        array_no_length = handled_value.getBitArray()
        self.assertEqual(handled_value.value, expected_value, f"actual:{handled_value.value} != expected:{expected_value}")
        self.assertEqual(array_no_length, expected_array_no_length, f"actual:{array_no_length} != expected:{expected_array_no_length}")
        print(f"Array: {array_no_length} With bit length: {handled_value.bit_length}")

    def test_get_binary_array_big_extended(self):
        '''
        This method tests getting the bit string as big endian with a larger bit length
        '''
        input = [0,0,0,0,1,0,1,1,1,0,0,0]
        expected_value = 184
        expected_array = [0,0,0,0,1,0,1,1,1,0,0,0]
        expected_array_no_length = [1,0,1,1,1,0,0,0]
        bit_length = 12
        little_endian = False

        handled_value = IntegerHandler.fromBitArray(input,little_endian=little_endian, bit_length=bit_length)
        array = handled_value.getBitArray()
        print(f"Value : {handled_value.value} little_endian : {little_endian} from : {input}")
        self.assertEqual(handled_value.value, expected_value, f"actual:{handled_value.value} != expected:{expected_value}")
        self.assertEqual(array, expected_array, f"actual:{array} != expected:{expected_array}")
        print(f"Array: {array} With bit length: {handled_value.bit_length}")

        handled_value = IntegerHandler.fromBitArray(input,little_endian=little_endian)
        array_no_length = handled_value.getBitArray()
        self.assertEqual(handled_value.value, expected_value, f"actual:{handled_value.value} != expected:{expected_value}")
        self.assertEqual(array_no_length, expected_array_no_length, f"actual:{array_no_length} != expected:{expected_array_no_length}")
        print(f"Array: {array_no_length} With bit length: {handled_value.bit_length}")

    def test_get_hex_string_big(self):
        '''
        This method tests getting a hex string from an integer value in big endian
        '''
        input = "106132DEE"
        expected_value = 4396887534
        little_endian = False
        bit_length = 56
        expected_string_bits_spacing = "00 00 01 06 13 2D EE"
        expected_string = "0106132DEE"

        handled_value = IntegerHandler.fromHexString(hex_string=input, little_endian=little_endian, bit_length=bit_length)
        print(f"Value : {handled_value.value} little_endian : {little_endian} from : {input}")
        self.assertEqual(handled_value.value, expected_value,f"actual:{handled_value.value} != expected:{expected_value}")
        hexstring_bits_spacing = handled_value.getHexString(add_spacing=2)
        self.assertEqual(hexstring_bits_spacing, expected_string_bits_spacing, f"actual:{hexstring_bits_spacing} != expected:{expected_string_bits_spacing}")
        print(f"Hex String: '{hexstring_bits_spacing}' With bit length: {handled_value.bit_length} and spacing: 2")

        handled_value = IntegerHandler.fromHexString(hex_string=input, little_endian=little_endian)
        hexstring = handled_value.getHexString()
        self.assertEqual(hexstring, expected_string, f"actual:{hexstring} != expected:{expected_string} and spacing: None")
        print(f"Hex String: '{hexstring}' With bit length: {handled_value.bit_length}")

    def test_get_hex_string_little(self):
        '''
        This method tests getting a hex string from an integer value in little endian
        '''
        input = "EE2D13061"
        expected_value = 4396887534
        little_endian = True
        bit_length = 56
        expected_string_bits_spacing = "EE 2D 13 06 01 00 00"
        expected_string = "EE2D130601"

        handled_value = IntegerHandler.fromHexString(hex_string=input, little_endian=little_endian, bit_length=bit_length)
        print(f"Value : {handled_value.value} little_endian : {little_endian} from : {input}")
        self.assertEqual(handled_value.value, expected_value,f"actual:{handled_value.value} != expected:{expected_value}")
        hexstring_bits_spacing = handled_value.getHexString(add_spacing=2)
        self.assertEqual(hexstring_bits_spacing, expected_string_bits_spacing, f"actual:{hexstring_bits_spacing} != expected:{expected_string_bits_spacing}")
        print(f"Hex String: '{hexstring_bits_spacing}' With bit length: {handled_value.bit_length} and spacing: 2")

        handled_value = IntegerHandler.fromHexString(hex_string=input, little_endian=little_endian)
        hexstring = handled_value.getHexString()
        self.assertEqual(hexstring, expected_string, f"actual:{hexstring} != expected:{expected_string} and spacing: None")
        print(f"Hex String: '{hexstring}' With bit length: {handled_value.bit_length}")

    def test_concatenate_bits_no_length_big(self):
        '''
        This method tests concetenating bits with no length in big endian
        '''

        first_array = [0,1,1,0,1]
        second_array = [1,1,1,0,0]
        expected_concat = [1,1,0,1,1,1,1,0,0]
        list_handlers = [IntegerHandler.fromBitArray(first_array),IntegerHandler.fromBitArray(second_array)]

        concatenated = concatenate(list_handlers)
        print(f"{concatenated} : {first_array} || {second_array}")
        self.assertEqual(concatenated.getBitArray(),expected_concat)

    def test_concatenate_bits_no_length_little(self):
        '''
        This method tests concetenating bits with no length in little endian
        '''
        
        first_array = [0,1,1,0,1]
        second_array = [1,1,1,0,0]
        expected_concat = [0,1,1,0,1,1,1,1]
        list_handlers = [IntegerHandler.fromBitArray(first_array,True),IntegerHandler.fromBitArray(second_array,True)]

        concatenated = concatenate(list_handlers,True)
        print(f"{concatenated} : {first_array} || {second_array}")
        self.assertEqual(concatenated.getBitArray(),expected_concat)

    def test_concatenate_bits_length_big(self):
        '''
        This method tests concetenating bits with length in big endian
        '''

        first_array = [0,1,1,0,1]
        second_array = [1,1,1,0,0]
        expected_concat = [0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0]
        list_handlers = [IntegerHandler.fromBitArray(first_array,bit_length=8),IntegerHandler.fromBitArray(second_array,bit_length=8)]

        concatenated = concatenate(list_handlers)
        print(f"{concatenated} : {first_array} || {second_array}")
        self.assertEqual(concatenated.getBitArray(),expected_concat)

    def test_concatenate_bits_length_little(self):
        '''
        This method tests concetenating bits with length in little endian
        '''

        first_array = [0,1,1,0,1]
        second_array = [1,1,1,0,0]
        expected_concat = [0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0]
        list_handlers = [IntegerHandler.fromBitArray(first_array,True,8),IntegerHandler.fromBitArray(second_array,True,8)]

        concatenated = concatenate(list_handlers,True)
        print(f"{concatenated} : {first_array} || {second_array}")
        self.assertEqual(concatenated.getBitArray(),expected_concat)
if __name__ == '__main__':
    unittest.main()