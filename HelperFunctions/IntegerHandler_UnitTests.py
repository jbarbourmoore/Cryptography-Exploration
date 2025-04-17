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


if __name__ == '__main__':
    unittest.main()