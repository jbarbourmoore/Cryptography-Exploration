from HelperFunctions.IntegerHandler import *

class SHA1():
    '''
    This class should hold the methods and values necessary in order to implement sha 1
    '''
    def __init__(self):
        self.word_bits = 32
        self.endian = False

    def ch(self, x:IntegerHandler, y:IntegerHandler, z:IntegerHandler) -> IntegerHandler:
        '''
        This method should perform the Ch function as required for sha1 
        Ch(x, y, z)=(x^y)xor(!x^z)
        Section 4.1.1 "SHA-1 Functions" of NIST FIPS 180-4
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x, y, z : IntegerHandler
                The values that the operation is being performed on as 32 bit big endian integer values

        Returns :
            ch_result : IntegerHandler
                The resulting value for the ch function as a 32 bit big endian integer value
        '''

        not_x = x.bitwiseNot()
        x_and_y = bitwiseAnd([x,y],self.endian,self.word_bits)
        not_x_and_z = bitwiseAnd([not_x,z],self.endian,self.word_bits)
        ch_result = bitwiseXor([x_and_y,not_x_and_z], self.endian, self.word_bits)
        return ch_result
    
    def parity(self, x:IntegerHandler, y:IntegerHandler, z:IntegerHandler) -> IntegerHandler:
        '''
        This method should perform the parity function as required for sha1 
        Parity(x, y, z)=x xor y xor z
        Section 4.1.1 "SHA-1 Functions" of NIST FIPS 180-4
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x, y, z : IntegerHandler
                The values that the operation is being performed on as 32 bit big endian integer values

        Returns :
            parity_result : IntegerHandler
                The resulting value for the parity function as a 32 bit big endian integer value
        '''

        parity_result = bitwiseXor([x,y,z], self.endian, self.word_bits)
        return parity_result

    def maj(self, x:IntegerHandler, y:IntegerHandler, z:IntegerHandler) -> IntegerHandler:
        '''
        This method should perform the maj function as required for sha1 
        Maj(x, y, z)=(x & y) xor (x & z) xor (y & z)
        Section 4.1.1 "SHA-1 Functions" of NIST FIPS 180-4
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x, y, z : IntegerHandler
                The values that the operation is being performed on as 32 bit big endian integer values

        Returns :
            maj_result : IntegerHandler
                The resulting value for the maj function as a 32 bit big endian integer value
        '''

        x_and_y = bitwiseAnd([x, y], self.endian, self.word_bits)
        x_and_z = bitwiseAnd([x, z], self.endian, self.word_bits)
        y_and_z = bitwiseAnd([y, z], self.endian, self.word_bits)
        maj_result = bitwiseXor([x_and_y,x_and_z,y_and_z], self.endian, self.word_bits)

    