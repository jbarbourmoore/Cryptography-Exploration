
class EncodeStringAsNumbersList():
    '''
    This class allows one to convert a string to a list of numbers of a certain block size with a certain number system base and back again
    '''

    def __init__(self, number_system_base = 214, block_size = 5):
        '''
        This method initializes the EncodeStringAsNumbersList object

        Parameters :
            number_system_base : int, optional
                The number system base to use when converting the message to a list of numbers (default is 214)
            block_size : int, optional
                The number of characters in each block when encoded (default is five)
        '''

        self.number_system_base = number_system_base
        self.block_size = block_size
    
    def convertStringMessageToNumberList(self, string_message):
        '''
        This method converts the message into a list of numbers in a set base

        Parameters :
            message : str
                The message to be encrypted

        Returns :
            list_message_number : [int]
                The list of numbers that are the message
        '''

        string_list = [*string_message]
        number_of_characters = len(string_list)

        if number_of_characters == 0:
            return None, "String must have content"
        if not all( 32 <= ord(c) <= 126 for c in string_list):
            return None, "Alphanumeric and space characters only please"
       
        # Ensure the list is a multiple of 5 characters long by using an ascii null character (chr(31))
        r = 0 if number_of_characters % self.block_size == 0 else self.block_size - ( number_of_characters % 5 )
        string_list += [chr(31)] * r

        number_of_characters = len(string_list) 
        list_message_number = []

        # transform every block of 5 characters into a q-base number as a decimal
        for i in range(0, number_of_characters, self.block_size):
            five_char_block = string_list[i:i+self.block_size]
            list_char_base_q = [ ord(char) - 31 for char in five_char_block]
            block_as_decimal_number = 0

            for i in range(self.block_size-1, -1, -1):
                block_as_decimal_number = block_as_decimal_number * self.number_system_base + list_char_base_q[i]

            list_message_number.append(block_as_decimal_number)

        return list_message_number, "Success"

    def convertNumberListToStringMessage(self, list_message_number):
        '''
        This method converts the list of numbers back into a string

        Parameters :
            list_message_number : [int]
                The list of numbers that are the message

        Returns :
            message : str
                The message as a string
        '''

        number_of_character_blocks = len(list_message_number)
        if number_of_character_blocks == 0:
            return None, "List must have content to decode"
        
        codes = []
        for message_block_number in list_message_number:
            for _ in range(0, self.block_size):

                r = message_block_number % self.number_system_base
                if r >= 1:
                    codes.append(chr(r + 31))
                message_block_number = message_block_number // self.number_system_base

        return ''.join(codes), "Success"