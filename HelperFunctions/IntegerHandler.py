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

    def __str__(self) -> str:
        '''
        This method outputs the integer a a _ and then the int value

        Return :
            value : str
                The value as a string of underscore and the in the value
        '''
        return f"_{self.value}"
    
    @staticmethod
    def singleByteIntToHex(int_byte):


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