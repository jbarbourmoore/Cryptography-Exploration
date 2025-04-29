from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm3 import *
from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm2 import *
from HelperFunctions.IntegerHandler import *

class HMAC():
    '''
    Keyed Hash Message Authentication Code

    Based on :
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf (draft to replace nist fips 198)
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
    Example values: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA3-512.pdf
    '''
    def __init__(self, hashing_algorithm = SHA3_512(), b=576, l=512):
        '''
        This method initializes the HMAC object
        '''
        self.sha = hashing_algorithm
        self.b = b
        self.l = l

    def keyProcessing(self,secret_key:IntegerHandler)-> IntegerHandler:
        '''
        This message processes the key so it is the proper length

        Parameters : 
            secret_key : IntegerHandler
                The key as an IntegerHandler

        Return : 
            K_0 : IntegerHandler
                The procesed key as an IntegerHandler
        '''

        if secret_key.bit_length == self.b:
            K_0 = secret_key
        elif secret_key.bit_length > self.b:
            padding_length = self.b - self.l
            padding = IntegerHandler(value=0, little_endian=False, bit_length=padding_length)
            hash = self.hashIntegerHandler(secret_key)
            K_0 = concatenate([hash, padding], False)
        elif secret_key.bit_length < self.b:
            padding_length = self.b - secret_key.bit_length
            padding = IntegerHandler(value=0, little_endian=False, bit_length=padding_length)
            K_0 = concatenate([secret_key, padding], False)

        return K_0
    
    def HMAC(self, message:str, key:str, is_debug:bool = False) -> IntegerHandler|tuple[IntegerHandler,dict]:
        '''
        This method calculates the HMAC for a given message and key

        Parameters : 
            message : str
                The message as a string
            key : str
                The hex string for the key

        Returns :
            hmac : IntegerHandler
                The hmac as an IntegerHandler
        '''
        opad = "01011100" * (self.b // 8)
        ipad = "00110110" * (self.b // 8)
        opad_handler = IntegerHandler.fromBitString(bit_string=opad, little_endian=False, bit_length=self.b)
        ipad_handler = IntegerHandler.fromBitString(bit_string=ipad, little_endian=False, bit_length=self.b)

        key_handler = IntegerHandler.fromHexString(hex_string=key, little_endian=False, bit_length=len(key.replace(" ",""))*4)
        message_handler = IntegerHandler.fromString(message, little_endian=False,bit_length=len(message)*8)
        
        K_0 = self.keyProcessing(key_handler)

        K0_xor_opad = bitwiseXor([K_0, opad_handler], little_endian=False, bit_length=self.b)
        K0_xor_ipad = bitwiseXor([K_0, ipad_handler], little_endian=False, bit_length=self.b)

        K0_ipad_M = concatenate([K0_xor_ipad, message_handler], little_endian=False)
        hash_K0_ipad_M = self.hashIntegerHandler(K0_ipad_M)

        K0_opad_hash_K0_ipad_M = concatenate([K0_xor_opad, hash_K0_ipad_M],little_endian=False)
        final_hash = self.hashIntegerHandler(K0_opad_hash_K0_ipad_M)
        if is_debug:
            print(f"Text             : {message_handler.getHexString(add_spacing=8)}")
            print(f"Key              : {key_handler.getHexString(add_spacing=8)}")
            print(f"K_0              : {K_0.getHexString(add_spacing=8)}")
            print(f"K0_xor_opad      : {K0_xor_opad.getHexString(add_spacing=8)}")
            print(f"K0_xor_ipad      : {K0_xor_ipad.getHexString(add_spacing=8)}")
            print(f"hash_K0_ipad_M   : {hash_K0_ipad_M.getHexString(add_spacing=8)}")
            print(f"final_hash       : {final_hash.getHexString(add_spacing=8)}")
            intermediate_values={
                "Text": message_handler,
                "Key": key_handler,
                "K_0": K_0,
                "K0_xor_opad":K0_xor_opad,
                "K0_xor_ipad":K0_xor_ipad,
                "hash_K0_ipad_M":hash_K0_ipad_M,
            }
            return final_hash, intermediate_values

        return final_hash
    
    def hashIntegerHandler(self, handler: IntegerHandler) -> IntegerHandler:
        '''
        This method generates the hash value for the Integer Handler which has been passed to it

        Parameters :
            handler : IntegerHandler
                The IntegerHandler to be hashed

        Returns :
            hash_result : IntegerHandler
                The result of the hash as a IntegerHandler
        '''
        if issubclass(type(self.sha),SHA3):
            hash_result = self.sha.hashHex(hex_input=handler.getHexString())
        else:
            hash_result = self.sha.hashAHexString(handler.getHexString(), handler.bit_length//8)
        bit_length = hash_result.bit_length
        hash_result = hash_result.getHexString()
        return IntegerHandler.fromHexString(hash_result, little_endian=False, bit_length=bit_length)
    
class HMAC_SHA224(HMAC):
    def __init__(self):
        super().__init__(hashing_algorithm=sha224, b=512, l=224)
class HMAC_SHA256(HMAC):
    def __init__(self):
        super().__init__(hashing_algorithm=sha256, b=512, l=256)
class HMAC_SHA384(HMAC):
    def __init__(self):
        super().__init__(hashing_algorithm=sha384, b=1024, l=384)
class HMAC_SHA512(HMAC):
    def __init__(self):
        super().__init__(hashing_algorithm=sha512, b=1024, l=512)
class HMAC_SHA512_224(HMAC):
    def __init__(self):
        super().__init__(hashing_algorithm=sha512_224, b=1024, l=224)
class HMAC_SHA512_256(HMAC):
    def __init__(self):
        super().__init__(hashing_algorithm=sha512_256, b=1024, l=256)
class HMAC_SHA3_224(HMAC):
    def __init__(self):
        super().__init__(hashing_algorithm=sha3_224, b=1152, l=224)
class HMAC_SHA3_256(HMAC):
    def __init__(self):
        super().__init__(hashing_algorithm=sha3_256, b=1088, l=256)
class HMAC_SHA3_384(HMAC):
    def __init__(self):
        super().__init__(hashing_algorithm=sha3_384, b=832, l=384)
class HMAC_SHA3_512(HMAC):
    def __init__(self):
        super().__init__(hashing_algorithm=sha3_512, b=576, l=512)

if __name__ == '__main__':
    message = "Sample message for keylen<blocklen"
    text="53616d70 6c65206d 65737361 676520666f72206b 65796c65 6e3c626c 6f636b6c656e"
    text="53616D70 6C65206D 65737361 676520666F72206B 65796C65 6E3C626C 6F636B6C656E"
    assert message.encode().hex() == "53616d70 6c65206d 65737361 676520666f72206b 65796c65 6e3c626c 6f636b6c656e".replace(" ","")
    key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    expected_mac = "4efd629d 6c71bf86 162658f2 9943b1c308ce27cd fa6db0d9 c3ce8176 3f9cbce5f7ebe986 8031db1a 8f8eb7b6 b95e5c5e3f657a89 96c86a2f 6527e307 f0213196"
    expected_k0_xor_opad = "5c5d5e5f 58595a5b 54555657 505152534c4d4e4f 48494a4b 44454647 404142437c7d7e7f 78797a7b 74757677 707172736c6d6e6f 68696a6b 64656667 606162635c5c5c5c 5c5c5c5c"
    expected_second_hash = "7865df66 2f8577ba 01c208ff 369629c7f134ad57 4a0d1af3 bf31b444 3cc286a94afb9d6f d1c4141b d61599e5 95bec0a67f495e3e 6aa11f4d 89b16dab bf8e743b".replace(" ","").upper()
    expected_k0_xor_ipad = "36373435 32333031 3e3f3c3d 3a3b383926272425 22232021 2e2f2c2d 2a2b282916171415 12131011 1e1f1c1d 1a1b181906070405 02030001 0e0f0c0d 0a0b080936363636 36363636".replace(" ","")
    hmac_mine = HMAC()
    mac = hmac_mine.HMAC(message,key)
    print(mac.getHexString())
    assert mac.getHexString() == expected_mac.upper().replace(" ","")
    text = "5361 6D706C65 206D6573 73616765 20666F72 206B6579 6C656E3D 626C6F63 6B6C656E"
    key = "00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F 20212223 24252627 28292A2B 2C2D2E2F 30313233 34353637 38393A3B 3C3D3E3F "
    expected_mac = "C7405E3A E058E8CD 30B08B41 40248581 ED174CB3 4E1224BC C1EFC81B"
    expected_handler = IntegerHandler.fromHexString(expected_mac,little_endian=False,bit_length=len(expected_mac.replace(" ",""))*4)
    message = "Sample message for keylen=blocklen"
    hmac_sha224 = HMAC_SHA224()
    mac, intermediate_values = hmac_sha224.HMAC(message,key,True)
    print(mac.getHexString(add_spacing=8))
    assert mac.getHexString() == expected_handler.getHexString()
