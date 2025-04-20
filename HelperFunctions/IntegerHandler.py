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

    def getValue(self)-> int:
        '''
        This method gets the value of the integer

        Returns :
            value : int
                The value being handled
        '''

        if self.bit_length != None:
            return self.value % (2**self.bit_length)
        return self.value
    
    def setValue(self,newValue:int):
        '''
        This method sets the value for the integer

        Parameters :
            new_value : int
                The new value for the integer
        '''
        if self.bit_length != None:
            newValue = newValue % (2**self.bit_length)
        self.value = newValue

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
        if bit_array == []:
            return [0]
        return bit_array
    
    def getBitString(self) -> str:
        bit_array = self.getBitArray()
        bit_string = ""
        for bit in bit_array:
            bit_string += str(bit)
        if bit_string == "":
            return "0"
        return bit_string
    
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
    
    def splitBits(self):
        '''
        This method returns two Integer Handlers, each holding half of the bits

        Returns :
            first_handler : IntegerHandler
                The IntegerHandler holding the first half of the bits
            second_handler : IntegerHandler
                The IntegerHandler holding the second half of the bits
        '''

        bit_array = self.getBitArray()
        length = len(bit_array)
        first_array = [bit_array[i] for i in range(0,length//2)]
        second_array = [bit_array[i] for i in range(length//2,length)]
        return IntegerHandler.fromBitArray(first_array,self.is_little_endian,length//2),IntegerHandler.fromBitArray(second_array,self.is_little_endian,length//2)
    
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
    
    def setMostSignificantBit(self, new_bit:int) -> int:
        '''
        This method sets the most significant bit and returns the previous value

        Parameters :
            new_bit : int
                The value that is being set for the most significant bit
        
        Returns :
            old_bit : int
                The value of the most significant bit before it was set
        '''

        if self.bit_length == None:
            bit_length = len(self.getBitArray())
        else:
            bit_length = self.bit_length
        new_value = self.value
        largest_bit_value = pow(2,bit_length-1)
        if self.value >= largest_bit_value:
            old_bit = 1
            if new_bit == 0:
                new_value = self.value - largest_bit_value
        else:
            old_bit = 0
            if new_bit == 1:
                new_value= self.value + largest_bit_value
        new_handler = IntegerHandler(new_value,self.is_little_endian,self.bit_length)
        return old_bit, new_handler


    def getBitLength(self) -> int:
        '''
        This method finds the minimum number of bits to store a number or the bit length if it is set

        Returns :
            counter : int
                The number of bits necessary to store a number
        '''

        if self.bit_length != None:
            return self.bit_length
        
        counter = 1
        while 2 ** counter <= self.value:
            counter +=1

        return counter
    

    def bitwiseNot(self):
        '''
        This method returns the bitwise not for a value

        Returns :
            not_result : IntegerHandler
                The result of the not operation
        '''

        max_value = 2**self.getBitLength() - 1
        not_result = max_value - self.value

        return IntegerHandler(not_result,little_endian=self.is_little_endian, bit_length=self.bit_length)
    
    def leftShift(self,shift_amount):
        '''
        This method returns the left shift

        Parameters :
            shift_amount : int
                The amount the value is being shifted to the left

        Returns :
            shift_result : IntegerHandler
                The result of the shift operation
        '''
        if self.is_little_endian:
            shift_result = self.value >> shift_amount
        else:
            shift_result = self.value << shift_amount

        return IntegerHandler(shift_result,little_endian=self.is_little_endian, bit_length=self.bit_length)
    
    def rightShift(self,shift_amount):
        '''
        This method returns the right shift

        Parameters :
            shift_amount : int
                The amount the value is being shifted to the right

        Returns :
            shift_result : IntegerHandler
                The result of the shift operation
        '''
        if self.is_little_endian:
            shift_result = self.value << shift_amount
        else:
            shift_result = self.value >> shift_amount

        return IntegerHandler(shift_result,little_endian=self.is_little_endian, bit_length=self.bit_length)
    
    def rotateLeft(self, rotation_amount):
        '''
        This method rotates the bits of this value a set number of places to the left

        Parameters :
            rotation_amount : int
                The amount the value is being rotated

        Returns : 
            rotate_result : IntegerHandler 
                The result of the rotation operation
        '''

        bit_length = self.getBitLength()
        rotation_amount = rotation_amount % bit_length
        modulus = 2**bit_length
        if self.is_little_endian:
            rotate_result = (self.value >> rotation_amount)|(self.value << (bit_length - (rotation_amount))) & (2**(self.getBitLength())-1)
        else:
            rotate_result = (self.value << rotation_amount)|(self.value >> (bit_length - rotation_amount))
        rotate_result %= modulus
        return IntegerHandler(rotate_result,little_endian=self.is_little_endian, bit_length=self.bit_length)

    def rotateRight(self, rotation_amount):
        '''
        This method rotates the bits of this value a set number of places to the right

        Parameters :
            rotation_amount : int
                The amount the value is being rotated

        Returns : 
            rotate_result : IntegerHandler 
                The result of the rotation operation
        '''
        
        bit_length = self.getBitLength()
        rotation_amount = rotation_amount % bit_length
        modulus = 2**bit_length
        if self.is_little_endian:
            rotate_result = (self.value << rotation_amount)|(self.value >> (bit_length - rotation_amount))

        else:
            rotate_result = (self.value >> rotation_amount)|(self.value << (bit_length - (rotation_amount))) & (2**(self.getBitLength())-1)
        rotate_result %= modulus
        return IntegerHandler(rotate_result,little_endian=self.is_little_endian, bit_length=self.bit_length)


    @staticmethod
    def fromOctetList(octet_list:list[int], little_endian:bool=False, bit_length:int=None):
        '''
        This method converts an octet list to an IntegerHandler

        Parameters : 
            octet_list : list[int]
                The list of octets to be converted
            little_endian : bool, optional
                Whether the integer will be interpretted as little endian, default is False
            bit_length : int
                How many bits the number is stored as, default is none or unlimited
        Returns :
            integer_value : Integer Handler
                The integer representing the converted octet list

        reversal of the algorithm from Nist 186-5 B.2.3 "Conversion of an Integer to an Octet String"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''

        integer_value = 0
        length = len(octet_list)
        for i in range(0, length):
            integer_value += octet_list[i]*(256**(i))
        return IntegerHandler(integer_value,little_endian,bit_length)

    @staticmethod
    def singleByteIntToHex(int_byte):
        '''
        This method transforms a single integer byte into 2 hex digits

        Parameters : 
            int_byte : int
                The value for one byte as an int

        returns : 
            hex_digits : str
                The 2 hex digits for the int byte
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
                The value of the bit array as a handled integer
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
    def fromBitString(bit_string:str, little_endian:bool=False, bit_length:int=None):
        '''
        This method constructs an integer handler from a bit string

        Parameters :
            bit_string : str
                The value as a bit string
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
            for i in range(0,len(bit_string)):
                int_value += int(bit_string[i],2) * 2**i
        else:
            for i in range(0,len(bit_string)):
                int_value += int(bit_string[i],2) * 2**(len(bit_string) - 1 - i)
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
        bit_length += handler.getBitLength()

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

    if bit_length == None:
        bit_length_set = 0
        for handler in list_of_handlers:
            handler_length = handler.getBitLength()
            if handler_length > bit_length_set:
                bit_length_set = handler_length
    else:
        bit_length_set=bit_length
    initial_value = 0
    for handler in list_of_handlers:
        initial_value = initial_value ^ handler.value

    return IntegerHandler(value=initial_value, little_endian=little_endian,bit_length=bit_length_set)

def bitwiseAnd(list_of_handlers:list[IntegerHandler], little_endian: bool = False, bit_length = None) -> IntegerHandler:
    '''
    This method performs a bit wise and of a list of integer handlers

    Parameters :
        list_of_handler : [IntegerHandler]
            The handlers that are being and-ed
        little_endian : bool, optional
            Whether the resulting IntegerHandler should be little endian, default is False
        bit_length : int, optional
            The bit length for the result, default is None
    Return : 
        xored_integer_handler : IntegerHandler
            The integer handler containing the result of the and
    '''

    if bit_length == None:
        bit_length_set = 0
        for handler in list_of_handlers:
            handler_length = handler.getBitLength()
            if handler_length > bit_length_set:
                bit_length_set = handler_length
    else:
        bit_length_set=bit_length
    initial_value = 2**bit_length_set-1
    for handler in list_of_handlers:
        initial_value = initial_value & handler.value
        print(initial_value)

    return IntegerHandler(value=initial_value, little_endian=little_endian,bit_length=bit_length_set)

def bitwiseOr(list_of_handlers:list[IntegerHandler], little_endian: bool = False, bit_length = None) -> IntegerHandler:
    '''
    This method performs a bit wise or of a list of integer handlers

    Parameters :
        list_of_handler : [IntegerHandler]
            The handlers that are being ored
        little_endian : bool, optional
            Whether the resulting IntegerHandler should be little endian, default is False
        bit_length : int, optional
            The bit length for the result, default is None
    Return : 
        xored_integer_handler : IntegerHandler
            The integer handler containing the result of the or
    '''

    if bit_length == None:
        bit_length_set = 0
        for handler in list_of_handlers:
            handler_length = handler.getBitLength()
            if handler_length > bit_length_set:
                bit_length_set = handler_length
    else:
        bit_length_set=bit_length
    initial_value = 0
    for handler in list_of_handlers:
        initial_value = initial_value | handler.value
        print(initial_value)

    return IntegerHandler(value=initial_value, little_endian=little_endian,bit_length=bit_length_set)

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

    handled_value = IntegerHandler(9,True,4)
    print(handled_value)
    print(handled_value.getLeastSignificantBit())
    print(handled_value.setMostSignificantBit(0))
    print(handled_value)

    handled_value = IntegerHandler.fromBitArray([1,1,1,0,0,0,1,0],True,8)
    print(handled_value)
    print(handled_value.getLeastSignificantBit())
    y,handled_value = handled_value.setMostSignificantBit(1)
    print(handled_value)

    handled_value = IntegerHandler.fromBitArray([1,1,1,0,0,0,1,0],True,256)
    print(handled_value)
    print(handled_value.getLeastSignificantBit())
    y,handled_value = handled_value.setMostSignificantBit(1)
    print(handled_value)
    print(y)

    handled_value = IntegerHandler.fromBitArray([0,0,0,0,0,0,1,0,0])
    print(handled_value.getBitLength())
    print(handled_value)