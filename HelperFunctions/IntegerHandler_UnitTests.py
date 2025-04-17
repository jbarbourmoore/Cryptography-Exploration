from HelperFunctions.IntegerHandler import IntegerHandler
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
        self.assertEqual(handled_value.value, expected_value)

    def test_from_hex_string_big(self):
        '''
        This method tests creating a integer handler from a hex string in big endian
        '''
        
        input = "AB1C9"
        expected_value = 46761
        little_endian = False
        handled_value = IntegerHandler.fromHexString(hex_string=input, little_endian=little_endian)
        print(f"Value : {handled_value.value} little_endian : {little_endian} from : {input}")
        self.assertEqual(handled_value.value, expected_value)

    def test_from_hex_string_little(self):
        '''
        This method tests creating a integer handler from a hex string in little endian
        '''
        
        input = "AB1C9"
        expected_value = 39514
        little_endian = True
        handled_value = IntegerHandler.fromHexString(hex_string=input, little_endian=little_endian)
        print(f"Value : {handled_value.value} little_endian : {little_endian} from : {input}")
        self.assertEqual(handled_value.value, expected_value)

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
        
        handled_value = IntegerHandler.fromBitArray(input,little_endian=little_endian)
        array_no_length = handled_value.getBitArray()
        self.assertEqual(handled_value.value, expected_value, f"actual:{handled_value.value} != expected:{expected_value}")
        self.assertEqual(array_no_length, expected_array_no_length, f"actual:{array_no_length} != expected:{expected_array_no_length}")
    
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
        
        handled_value = IntegerHandler.fromBitArray(input,little_endian=little_endian)
        array_no_length = handled_value.getBitArray()
        self.assertEqual(handled_value.value, expected_value, f"actual:{handled_value.value} != expected:{expected_value}")
        self.assertEqual(array_no_length, expected_array_no_length, f"actual:{array_no_length} != expected:{expected_array_no_length}")
        
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
        
        handled_value = IntegerHandler.fromBitArray(input,little_endian=little_endian)
        array_no_length = handled_value.getBitArray()
        self.assertEqual(handled_value.value, expected_value, f"actual:{handled_value.value} != expected:{expected_value}")
        self.assertEqual(array_no_length, expected_array_no_length, f"actual:{array_no_length} != expected:{expected_array_no_length}")
        

if __name__ == '__main__':
    unittest.main()