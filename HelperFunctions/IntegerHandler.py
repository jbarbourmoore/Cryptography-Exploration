
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

    def __str__(self) -> str:
        '''
        This method outputs the integer a a _ and then the int value

        Return :
            value : str
                The value as a string of underscore and the in the value
        '''
        return f"_{self.value}"

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

        int_value:int = 0
        if little_endian:
            for i in range(0, len(hex_string)):
                int_value += IntegerHandler.hexDigitToInt(hex_string[i],little_endian) * 8**i
        else:
            for i in range(0, len(hex_string)):
                int_value += IntegerHandler.hexDigitToInt(hex_string[i],little_endian) * 8**(len(hex_string) - i - 1)

        return IntegerHandler(value=int_value, little_endian=little_endian, bit_length=bit_length)
    
    @staticmethod
    def hexDigitToInt(hex_digit:str, little_endian:bool=False) -> int:
        '''
        This method converts a single hex digit into an integer value based on whether it is little endian or not

        Parameters :
            hex_digit : str
                A single hexadecimal digit as a string

        Returns :
            int_value : int
                The value of the digit as an integer
        '''

        if not little_endian:
            return int(hex_digit,16)
        
        int_val_big:int = int(hex_digit,16)

        bits:list[int] = []
        while int_val_big > 0:
            bits.insert(0, int_val_big % 2)
            int_val_big //= 2
        if len(bits)<4:
            bits =  bits + [0] * (4 - len(bits))
        int_value = 0
        for i in range(0,3):
            int_value += bits[i] * 2**(3-i)
        return int_value


        
if __name__ == '__main__': 
    handled_value = IntegerHandler.fromHexString("ABC",False) 
    print(handled_value)
    handled_value = IntegerHandler.fromHexString("ABC",True)
    print(handled_value)
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