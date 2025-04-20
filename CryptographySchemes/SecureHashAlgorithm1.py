from HelperFunctions.IntegerHandler import *
from CryptographySchemes.SecureHashAlgorithm1 import Sha1Int

class SHA1():
    '''
    This class should hold the methods and values necessary in order to implement sha 1
    '''
    def __init__(self):
        pass

    def ch(self, x:Sha1Int, y:Sha1Int, z:Sha1Int) -> Sha1Int:
        '''
        This method should perform the Ch function as required for sha1 
        Ch(x, y, z)=(x^y)xor(!x^z)
        Section 4.1.1 "SHA-1 Functions" of NIST FIPS 180-4
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x, y, z : Sha1Int
                The values that the operation is being performed on as 32 bit big endian integer values

        Returns :
            ch_result : Sha1Int
                The resulting value for the ch function as a 32 bit big endian integer value
        '''

        not_x = x.bitwiseNot()
        x_or_y = bitwiseOr([x,y],False,32)
        not_x_or_z = bitwiseOr([not_x,z],False,32)
        ch_result = bitwiseXor([x_or_y,not_x_or_z], False, 32)
        return ch_result


class Sha1Int(IntegerHandler):
    '''
    This class should control the values for SHA 1 
    based on the knowledge that it involves manipulating words that are 32 bits in big endian notation

    Section 4.1.1 "SHA-1 Functions" of NIST FIPS 180-4
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    '''
    def __init__(self, value = 0):
        super().__init__(value, False, 32)
        self.max_value = 2**32 - 1