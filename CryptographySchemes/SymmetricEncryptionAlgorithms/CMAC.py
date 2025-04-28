from CryptographySchemes.SymmetricEncryptionAlgorithms.TripleDataEncryptionStandard import TripleDataEncryptionStandard
from CryptographySchemes.SymmetricEncryptionAlgorithms.AES_ModesOfOperation import AES_ECB_128
from HelperFunctions.IntegerHandler import *
from math import ceil

class CMAC_3DES():
    '''
    A Cypher Based Message Authentication Code abbreviared as CMAC.
    
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
    '''

    def __init__(self, key:str):
        self.block_size = 64
        self.block_encryption = TripleDataEncryptionStandard(hex_key=key)
        self.R_b = IntegerHandler.fromBitString("0" * 59 + "11011", False, self.block_size)

    def cypher(self, hex_string:str) -> str :
        '''
        This method uses the symetric block encryption algorithm in order to encrypt a hexadecimal string
        
        Parameters :
            hex_string : str
                The hex string to be encrypted

        Returns :
            encrypted_hex : str
                The encrypted hex string
        '''
        encrypted_hex = self.block_encryption.encryptHex(hex_string)
        return encrypted_hex

    def subkeyGeneration(self):
        '''
        This method generates two subkeys

        Returns :
            K1, K2 : IntegerHandler
                The two subkeys for the CMAC
        '''

        byte_length = self.block_size // 4
        L = self.cypher("0" * byte_length)
        L = IntegerHandler.fromHexString(L,False,self.block_size)
        K1 = L.leftShift(1)
        if L.getMostSignificantBits(1).getBitArray()[0] == 1:
            K1 = bitwiseXor([K1,self.R_b], False, self.block_size)
        K2 = K1.leftShift(1)
        if K1.getMostSignificantBits(1).getBitArray()[0] == 1:
            K2 = bitwiseXor([K2,self.R_b], False, self.block_size)
        return K1, K2
    
    def cmacGeneration(self, message_hex:str, tag_length:int):
        '''
        This method generates the CMAC tag for a hexadecimal message

        Parameters : 
            message_hex : str
                The message as a hexadecimal string
            tag_length : int
                The length of the desired tag as an integer

        Returns :
            tag : str
                The tag as a hex string
        '''

        message_bits = IntegerHandler.fromHexString(message_hex, False, len(message_hex) * 4).getBitArray()
        K1, K2 = self.subkeyGeneration()
        message_length = len(message_bits)
        if message_length == 0:
            number_of_blocks = 1
        else:
            number_of_blocks = ceil(message_length / self.block_size)
        has_partial_block = message_length % self.block_size != 0
        message_handlers = []
        if has_partial_block or message_length == 0:
            message_bits = message_bits + [1] + [0] * (self.block_size * number_of_blocks - message_length - 1)
        for i in range(0, number_of_blocks):
            bit_segment = message_bits[i * self.block_size : i * self.block_size + self.block_size]
            message_handlers.append(IntegerHandler.fromBitArray(bit_segment, False, self.block_size))
        if has_partial_block or message_length == 0:
            message_handlers[number_of_blocks - 1] = bitwiseXor([K2, message_handlers[number_of_blocks - 1]])
        else:
            message_handlers[number_of_blocks - 1] = bitwiseXor([K1, message_handlers[number_of_blocks - 1]])
        C = IntegerHandler.fromBitString("0"*self.block_size, False, self.block_size)
        for i in range(0, number_of_blocks):
            xor_result = bitwiseXor([C, message_handlers[i]], False, self.block_size)
            C = IntegerHandler.fromHexString(self.cypher(xor_result.getHexString()), False, self.block_size)
        T = C.getMostSignificantBits(tag_length)
        return T.getHexString()
    
    def cmacVerification(self, message_hex:str, tag_length:int, tag:str) -> bool:
        '''
        This method verifies the CMAC tag for a hexadecimal message

        Parameters : 
            message_hex : str
                The message as a hexadecimal string
            tag_length : int
                The length of the desired tag as an integer
            tag : str
                The hexadecimal string of the tag to be verified

        Returns :
            verified : bool
                Whether or not the tag was successfully verified
        '''

        tag_prime = self.cmacGeneration(message_hex=message_hex, tag_length=tag_length)
        if tag == tag_prime:
            return True
        else:
            return False
        
class CMAC_AES128(CMAC_3DES):

    def __init__(self, key):
        self.block_encryption = AES_ECB_128(key=key)
        self.block_size = 128
        self.R_b = IntegerHandler.fromBitString("0" * 120 + "10000111", False, self.block_size)

    def cypher(self, hex_string):
        result_list = self.block_encryption.encryptHexList([hex_string])
        return result_list[0]