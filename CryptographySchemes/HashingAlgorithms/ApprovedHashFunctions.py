from HelperFunctions.IntegerHandler import *
from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm3 import *
from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm2 import *
from enum import Enum, IntEnum

class HashTypes(IntEnum):
    SHA1_Hash = 1
    SHA2_Hash = 2
    SHA3_Hash = 3
    SHAKE_Hash = 4
 
class ApprovedHashFunction():

    def __init__(self, hash_name:str, hash_object:SHA1|SHA3, hash_type:int, digest_length:int):
        self.hash_name = hash_name
        self.hash_object = hash_object
        self.hash_type = hash_type
        self.digest_length = digest_length

    def hashIntegerHandler(self, handler_to_hash: IntegerHandler) -> IntegerHandler:
        ''' 
        This method returns the result for the hash of a given IntegerHandler as an IntegerHandler

        Parameters : 
            handler_to_hash : IntegerHandler
                The IntegerHandler that is being hashed once it is converted to a hex string

        Returns :
            hash_handler : IntegerHandler
                The result of the hash as an IntegerHandler
        '''
        if self.hash_type == HashTypes.SHAKE_Hash:
            hash_hex = self.hash_object.hashHex(handler_to_hash.getHexString(), self.digest_length).getHexString()
            hash_handler = IntegerHandler.fromHexString(hash_hex, False, self.digest_length)
        elif self.hash_type == HashTypes.SHA3_Hash:
            hash_hex = self.hash_object.hashHex(handler_to_hash.getHexString()).getHexString()
            hash_handler = IntegerHandler.fromHexString(hash_hex, False, self.digest_length)
        else:
            hash_handler = self.hash_object.hashAHexString(handler_to_hash.getHexString(), handler_to_hash.getBitLength())
        return hash_handler

class ApprovedHashFunctions(Enum):
    SHA_224_Hash = ApprovedHashFunction("SHA-224",sha224,HashTypes.SHA2_Hash, 224)
    SHA_256_Hash = ApprovedHashFunction("SHA-256",sha256,HashTypes.SHA2_Hash, 256)
    SHA_384_Hash = ApprovedHashFunction("SHA-384",sha384,HashTypes.SHA2_Hash, 384)
    SHA_512_Hash = ApprovedHashFunction("SHA-512",sha512,HashTypes.SHA2_Hash, 512)
    SHA3_224_Hash = ApprovedHashFunction("SHA3-224",sha3_224,HashTypes.SHA3_Hash, 224)
    SHA3_256_Hash = ApprovedHashFunction("SHA3-256",sha3_256,HashTypes.SHA3_Hash, 256)
    SHA3_384_Hash = ApprovedHashFunction("SHA3-384",sha3_384,HashTypes.SHA3_Hash, 384)
    SHA3_512_Hash = ApprovedHashFunction("SHA3-512",sha3_512,HashTypes.SHA3_Hash, 512)
    SHAKE_128_Hash = ApprovedHashFunction("SHAKE-128",shake_128,HashTypes.SHAKE_Hash, 256)
    SHAKE_256_Hash = ApprovedHashFunction("SHAKE-256",shake_256,HashTypes.SHAKE_Hash, 512)