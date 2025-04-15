
def bitStringToHexString(bit_string:str) -> str :
        '''
        This method translates a bit string into a hex string 

        Parameters :
            bit_string : str
                The bit string to be translated

        Returns :
            hex_string : str
                The hex string equivalent to the bit sting
        '''

        bit_string = bit_string.replace(" ","")
        bit_len = len(bit_string)
        value = int(bit_string,2)
        hex_string = '{0:0{1}x}'.format(value,bit_len//4).upper()
        return hex_string

def  hexStringToBitString(hex_string:str) -> str:
        '''
        This method translates a hex string into a bit string 

        Parameters :
            hex_string : str
                The hex_string to be translated

        Returns :
            bit_string : str
                The bit string equivalent to the hex sting
        '''

        hex_string = hex_string.replace(" ","")
        hex_len = len(hex_string)
        value = int(hex_string,16)
        bit_string = '{0:0{1}b}'.format(value,hex_len*4)
        return bit_string

def intToHexString(integer_value:int) -> str:
        '''
        This method converts an integer value to a hex string

        Parameters : 
            integer_value : int
                The integer to be converted into a hex string
            
        Returns :
            hex_string : str
                The string of the hexdecimal equal to the original value
        '''

        return bitStringToHexString(intToBitString(integer_value))
    
def bitStringToInt(bit_string:str) -> int:
        '''
        This method converts a bit string to an integer value

        Parameters : 
            bit_string : str
                The string of the bits to be converted

        Returns :
            integer_value : int
                The integer representing the converted bit string

        follows the algorithm from Nist FIPS 186.5 B.2.1 "Conversion of a Bit String to an Integer"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''
        integer_value = 0
        length = len(bit_string)
        for i in range(0, length):
            integer_value += int(bit_string[i:i+1],2)*(2**(length-1-i))
        return integer_value
    
def intToBitString(int_value:int) -> str:
        '''
        This method converts an integer value to a bit string

        Parameters : 
            integer_value : int
                The integer to be converted into a bit string
            
        Returns :
            bit_string : str
                The string of the bits equal to the original value

        follows the algorithm from Nist FIPS 186.5 B.2.1 "Conversion of a Bit String to an Integer"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''
        current_int = int_value
        bit_string = ""
        while current_int > 0:
            next_bit = current_int % 2
            bit_string = str(next_bit)+bit_string
            current_int //= 2
        return bit_string
    