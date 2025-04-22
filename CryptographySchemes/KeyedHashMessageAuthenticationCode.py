from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm3 import SHA3, SHA3_512
from HelperFunctions.IntegerHandler import *

class HMAC():
    '''
    Keyed Hash Message Authentication Code

    Based on :
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf (draft to replace nist fips 198)
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
    Example values: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA3-512.pdf
    '''
    def __init__(self):
        '''
        This method initializes the HMAC object
        '''
        self.sha3 = SHA3_512()
        self.b = 72*8
        self.l = 64*8

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
            hash_hex = self.hashHexToHex(secret_key.getHexString())
            hash = IntegerHandler.fromHexString(hash_hex, False, len(hash_hex) * 4)
            K_0 = concatenate([hash, padding], False)
        elif secret_key.bit_length < self.b:
            padding_length = self.b - secret_key.bit_length
            padding = IntegerHandler(value=0, little_endian=False, bit_length=padding_length)
            K_0 = concatenate([secret_key, padding], False)

        return K_0
    
    def HMAC(self, message:str, key:str) -> str:
        '''
        This method calculates the HMAC for a given message and key

        Parameters : 
            message : str
                The message as a string
            key : str
                The hex string for the key

        Returns :
            hmac : str
                The hmac as a hex string
        '''
        opad = "01011100" * (self.b // 8)
        ipad = "00110110" * (self.b // 8)
        opad_handler = IntegerHandler.fromBitString(bit_string=opad, little_endian=False, bit_length=self.b)
        ipad_handler = IntegerHandler.fromBitString(bit_string=ipad, little_endian=False, bit_length=self.b)
        key_handler = IntegerHandler.fromHexString(hex_string=key, little_endian=False, bit_length=len(key)*4)

        K_0 = self.keyProcessing(key_handler)

        K0_xor_opad = bitwiseXor([K_0, opad_handler], little_endian=False, bit_length=self.b)
        K0_xor_ipad = bitwiseXor([K_0, ipad_handler], little_endian=False, bit_length=self.b)

        message_handler = IntegerHandler.fromString(message, little_endian=False,bit_length=len(message)*8)
        
        K0_ipad_M = concatenate([K0_xor_ipad, message_handler], little_endian=False)
        hash_value = self.hashHexToHex(K0_ipad_M.getHexString())
        hash_K0_ipad_M = IntegerHandler.fromHexString(hex_string=hash_value, little_endian=False, bit_length=len(hash_value)*4)
        K0_opad_hash = concatenate([K0_xor_opad, hash_K0_ipad_M],little_endian=False)
        final_hash = self.hashHexToHex(K0_opad_hash.getHexString())
        return IntegerHandler.fromHexString(final_hash)
    
    def hashHexToHex(self, hex_value:str) -> str:
        '''
        This method generates the hex hash for the hex value which has been passed to it

        Parameters :
            hex_value : str
                The hex string to be hashed

        Returns :
            hash_result : str
                The result of the hash as a hex string
        '''
        hash_result = self.sha3.hashHex(hex_input=hex_value)
        hash_result = hash_result.getHexString()
        return hash_result.upper()
    

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
    print(hmac_mine.b)
    print(hmac_mine.l)