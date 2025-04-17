from math import ceil
class IntegerHandler():
    '''
    This class should handle an integer value, allowing it to be accessed in various forms as specified in algorithm documentation
    '''

    def __init__(self, value: int = 0, little_endian:bool = False, bit_length:int = None):
        '''
        This method initializes an integer handler object with a specific value

        Parameters : 
            value : int, optional
                The value as an integer, default is 0
            little_endian : bool, optional
                Whether the integer will be interpretted as little endian, default is False
            bit_length : int
                How many bits the number is stored as, default is none or unlimited
        '''

        self.value = value
        self.is_little_endian = little_endian
        self.bit_length = bit_length

        if bit_length != None:
            self.value = value % (2**bit_length)


    def getBitArray(self) -> list[int]:
        '''
        This method returns the integer value as a bit array
        '''

        if not self.is_little_endian:
            value = self.value
            bit_array = []
            while value > 0:
                bit_array.insert(0,value % 2)
                value = value // 2
            if self.bit_length != None:
                if len(bit_array) < self.bit_length:
                    bit_array = [0]*(self.bit_length-len(bit_array)) + bit_array
                elif len(bit_array) > self.bit_length:
                    bit_array = bit_array[:len(bit_array)-self.bit_length]
        else:
            value = self.value
            bit_array = []
            while value > 0:
                bit_array.append(value % 2)
                value = value // 2
            if self.bit_length != None:
                if len(bit_array) < self.bit_length:
                    bit_array = bit_array+[0]*(self.bit_length-len(bit_array))
                elif len(bit_array) > self.bit_length:
                    bit_array = bit_array[len(bit_array)-self.bit_length:]

        return bit_array
    
    def getHexString(self, add_spacing:int = None) -> str:
        '''
        This method gets the integer value as a hex string, depending on whether it is little endian or not and bit length

        Returns:
            hex_string : str
                The value as a hex string
        '''
        
        if self.bit_length == None:
            int_value = self.value
        else:
            int_value = self.value % (2**self.bit_length)
        
        if not self.is_little_endian:
            hex_string = ""
            while int_value != 0:
                hex_string = self.singleByteIntToHex(int_value % 256) + hex_string
                int_value = int_value // 256
        else:
            hex_string = ""
            while int_value != 0:
                hex_string += self.singleByteIntToHex(int_value % 256)
                int_value = int_value // 256

        length_in_bits = len(hex_string) * 4

        if self.bit_length != None and length_in_bits < self.bit_length:
            desired_hex_length = ceil(self.bit_length/4)
            if desired_hex_length % 2 != 0: desired_hex_length += 1
            if self.is_little_endian:
                hex_string = hex_string + "0"*(desired_hex_length - len(hex_string))
            else:
                hex_string = "0"*(desired_hex_length - len(hex_string)) + hex_string

        if add_spacing !=None:
            hex_length = len(hex_string)
            for i in range(1, hex_length//add_spacing):
                position = i * add_spacing + i - 1
                hex_string = hex_string[:position]+" "+hex_string[position:]
        return hex_string
    
    def getBytes(self)-> bytes:
        '''
        This method returns a bytes object of the value

        Returns : 
            bytes_list : bytes
                The bytes corresponding to this value
        '''

        bytes_list = bytes.fromhex(self.getHexString())
        return bytes_list

    def __str__(self) -> str:
        '''
        This method outputs the integer a a _ and then the int value

        Return :
            value : str
                The value as a string of underscore and the in the value
        '''
        return f"_{self.value}"
    
    def getLeastSignificantBit(self) -> int:
        '''
        This method returns the least significant bit of the integer

        Returns:
            bit : int
                The least significant bit
        '''
        return self.value % 2
    
    @staticmethod
    def singleByteIntToHex(int_byte):
        '''
        This method transforms a single integer byte into 2 hex digits

        Parameters : 
            int_byte : int
                The value for one byte as an int

        returns : 
            hex_digits : str
                The 2 hex digits for that byte
        '''

        hex_byte = hex(int_byte)[2:]
        if len(hex_byte) == 1:
            hex_byte = "0"+hex_byte
        return hex_byte.upper()

    @staticmethod
    def fromBitArray(bit_array:list[int], little_endian:bool=False, bit_length:int=None):
        '''
        This method constructs an integer handler from a bit array

        Parameters :
            bit_array : [int]
                The value as a bit array
            little_endian : bool, optional
                Whether the integer will be interpretted as little endian, default is False
            bit_length : int
                How many bits the number is stored as, default is none or unlimited

        Return :
            integer_handler : IntegerHandler
                The value of the bit string as a handled integer
        '''

        int_value:int = 0
        if little_endian:
            for i in range(0,len(bit_array)):
                int_value += bit_array[i] * 2**i
        else:
            for i in range(0,len(bit_array)):
                int_value += bit_array[i] * 2**(len(bit_array) - 1 - i)
        return IntegerHandler(value=int_value, little_endian=little_endian, bit_length=bit_length)
        

    @staticmethod
    def fromHexString(hex_string:str, little_endian:bool=False, bit_length:int=None):
        '''
        This method creates a handled value from a hex string

        Parameters :
            hex_string : str
                The value as a hexadecimal string
            little_endian : bool, optional
                Whether the integer will be interpretted as little endian, default is False
            bit_length : int
                How many bits the number is stored as, default is none or unlimited

        Return :
            integer_handler : IntegerHandler
                The value of the bit string as a handled integer
        '''
        hex_string = hex_string.replace(" ","")
        if len(hex_string) % 2 != 0:
            if little_endian:
                hex_string = hex_string[:len(hex_string)-1] + "0" +hex_string[len(hex_string)-1]
            else:
                hex_string = "0" + hex_string
        int_value:int = 0
        hex_length = len(hex_string)
        if little_endian:
            for i in range(0, hex_length, 2):
                int_value += int(IntegerHandler.hexByteToInt(hex_string[i:i+2]) * pow(256,i//2))
        else:
            for i in range(0, hex_length, 2):
                int_value += int(IntegerHandler.hexByteToInt(hex_string[i:i+2]) * pow(256,hex_length//2-1-i//2))

        return IntegerHandler(value=int_value, little_endian=little_endian, bit_length=bit_length)
    
    @staticmethod
    def hexByteToInt(hex_byte:str) -> int:
        '''
        This method converts a single hex byte into an integer value

        Parameters :
            hex_byte : str
                A single hexadecimal byte as a string

        Returns :
            int_value : int
                The value of the byte as an integer
        '''
        return int(hex_byte,16)
    
def concatenate(list_of_handlers:list[IntegerHandler], little_endian: bool = False) -> IntegerHandler:
    '''
    This method creates a value holding the result of the concatenation of the bits from IntegerHandlers

    Parameters :
        list_of_handler : [IntegerHandler]
            The handlers that are being concatenated
        little_endian : bool, optional
            Whether the resulting IntegerHandler should be little endian, default is False

    Return : 
        concatenated_integer_handler : IntegerHandler
            The integer handler containing the result of the concatenation
    '''

    total_bit = []
    bit_length = 0
    for handler in list_of_handlers:
        total_bit += handler.getBitArray()
        if handler.bit_length != None:
            bit_length += handler.bit_length
        else:
            bit_length += len(handler.getBitArray())

    return IntegerHandler.fromBitArray(total_bit,little_endian=little_endian, bit_length=bit_length)
        
def bitwiseXor(list_of_handlers:list[IntegerHandler], little_endian: bool = False, bit_length = None) -> IntegerHandler:
    '''
    This method performs a bit wise xor of a list of integer handlers

    Parameters :
        list_of_handler : [IntegerHandler]
            The handlers that are being xored
        little_endian : bool, optional
            Whether the resulting IntegerHandler should be little endian, default is False
        bit_length : int, optional
            The bit length for the result, default is None
    Return : 
        xored_integer_handler : IntegerHandler
            The integer handler containing the result of the xor
    '''

    modified_handlers:list[IntegerHandler] = []
    if bit_length == None:
        bit_length_set = 0
        for handler in list_of_handlers:
            handler_length = 0
            if handler.bit_length != None:
                handler_length = bit_length_set
            else:
                handler_length = len(handler.getBitArray())
            if handler_length > bit_length_set:
                bit_length_set = handler_length
    else:
        bit_length_set=bit_length
    for handler in list_of_handlers:
        modified_handlers.append(IntegerHandler(handler.value, little_endian, bit_length_set))

    current_bits = modified_handlers[0].getBitArray()
    for j in range(1, len(modified_handlers)):
        comparison_bits = modified_handlers[j].getBitArray()
        new_bits = []
        for i in range(0, bit_length_set):
            new_bits.append(current_bits[i] ^ comparison_bits[i])
        current_bits = new_bits
    return IntegerHandler.fromBitArray(current_bits,little_endian,bit_length)

if __name__ == '__main__': 
    handled_value = IntegerHandler.fromHexString("106132DEE",False, bit_length=80) 
    print(handled_value)
    assert handled_value.value == 4396887534
    print(handled_value.getHexString(add_spacing=2))
    handled_value = IntegerHandler.fromHexString("EE2D13061",True, bit_length=80)
    print(handled_value)
    assert handled_value.value == 4396887534
    print(handled_value.getHexString())
    handled_value = IntegerHandler.fromBitArray([1,0,1,1,1,0,0,0],True)
    print(handled_value)
    handled_value = IntegerHandler.fromBitArray([1,0,1,1,1,0,0,0],False)
    print(handled_value)
    handled_value = IntegerHandler.fromBitArray([1,0,1,1,1,0,0,0],True, 12)
    print(handled_value.getBitArray())
    handled_value = IntegerHandler.fromBitArray(handled_value.getBitArray(),True)
    print(handled_value)
    handled_value = IntegerHandler.fromBitArray([1,0,1,1,1,0,0,0],False,12)
    print(handled_value.getBitArray())
    handled_value = IntegerHandler.fromBitArray(handled_value.getBitArray(),False)
    print(handled_value)