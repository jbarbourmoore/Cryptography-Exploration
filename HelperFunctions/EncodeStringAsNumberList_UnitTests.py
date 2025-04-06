import unittest
from EncodeStringAsNumberList import EncodeStringAsNumbersList

class EncodeStringAsNumberList_UnitTests(unittest.TestCase):
    '''
    This class contains basic unit tests for the helper functions for encoding and decoding a string to a number list
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_encode_base214_block5(self):
        '''
        This method tests that the algorithm encodes and decodes properly using base 214 and blocks of 5 characters
        '''

        base = 214
        block_size = 5
        encoder = EncodeStringAsNumbersList(number_system_base=base,block_size=block_size)
        original_message = "This is a test string for encoding and decoding to a list of numbers"
        print(f"original message : {original_message}")
        encoded_list,status = encoder.convertStringMessageToNumberList(original_message)
        print(f"encoded list : {encoded_list}")
        self.assertEqual(status,"Success")
        decoded_message,status = encoder.convertNumberListToStringMessage(encoded_list)
        print(f"decoded message : {decoded_message}")
        self.assertEqual(status,"Success")
        self.assertNotEqual(original_message,encoded_list)
        self.assertEqual(original_message, decoded_message)

    def test_encode_base123_block1(self):
        '''
        This method tests that the algorithm encodes and decodes properly using base 123 and blocks of 1 character
        '''

        base = 123
        block_size = 1
        encoder = EncodeStringAsNumbersList(number_system_base=base,block_size=block_size)
        original_message = "This is a test string for encoding and decoding to a list of numbers"
        print(f"original message : {original_message}")
        encoded_list,status = encoder.convertStringMessageToNumberList(original_message)
        print(f"encoded list : {encoded_list}")
        self.assertEqual(status,"Success")
        decoded_message,status = encoder.convertNumberListToStringMessage(encoded_list)
        print(f"decoded message : {decoded_message}")
        self.assertEqual(status,"Success")
        self.assertNotEqual(original_message,encoded_list)
        self.assertEqual(original_message, decoded_message)

    def test_encode_base195_block2(self):
        '''
        This method tests that the algorithm encodes and decodes properly using base 195 and blocks of 2 characters
        '''

        base = 195
        block_size = 2
        encoder = EncodeStringAsNumbersList(number_system_base=base,block_size=block_size)
        original_message = "This is a test string for encoding and decoding to a list of numbers"
        print(f"original message : {original_message}")
        encoded_list,status = encoder.convertStringMessageToNumberList(original_message)
        print(f"encoded list : {encoded_list}")
        self.assertEqual(status,"Success")
        decoded_message,status = encoder.convertNumberListToStringMessage(encoded_list)
        print(f"decoded message : {decoded_message}")
        self.assertEqual(status,"Success")
        self.assertNotEqual(original_message,encoded_list)
        self.assertEqual(original_message, decoded_message)

    def test_encode_base214_block5_longer(self):
        '''
        This method tests that the algorithm encodes and decodes longer messages properly using base 214 and blocks of 5 characters
        '''

        base = 214
        block_size = 5
        encoder = EncodeStringAsNumbersList(number_system_base=base,block_size=block_size)
        original_message = "Let's try this with a longer and more complicated string just to see what might happen. It is very interesting to see all the quirks one might discover when developing test cases always. Ok this should be good to go!!"
        print(f"original message : {original_message}")
        encoded_list,status = encoder.convertStringMessageToNumberList(original_message)
        print(f"encoded list : {encoded_list}")
        self.assertEqual(status,"Success")
        decoded_message,status = encoder.convertNumberListToStringMessage(encoded_list)
        print(f"decoded message : {decoded_message}")
        self.assertEqual(status,"Success")
        self.assertNotEqual(original_message,encoded_list)
        self.assertEqual(original_message, decoded_message)
    
    def test_encode_base123_block1_longer(self):
        '''
        This method tests that the algorithm encodes and decodes properly longer messages properly using base 123 and blocks of 1 character
        '''

        base = 123
        block_size = 1
        encoder = EncodeStringAsNumbersList(number_system_base=base,block_size=block_size)
        original_message = "Let's try this with a longer and more complicated string just to see what might happen. It is very interesting to see all the quirks one might discover when developing test cases always. Ok this should be good to go!!"
        print(f"original message : {original_message}")
        encoded_list,status = encoder.convertStringMessageToNumberList(original_message)
        print(f"encoded list : {encoded_list}")
        self.assertEqual(status,"Success")
        decoded_message,status = encoder.convertNumberListToStringMessage(encoded_list)
        print(f"decoded message : {decoded_message}")
        self.assertEqual(status,"Success")
        self.assertNotEqual(original_message,encoded_list)
        self.assertEqual(original_message, decoded_message)

if __name__ == '__main__':
    unittest.main()