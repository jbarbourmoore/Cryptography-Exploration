from SecureHashAlgorithm3 import SHA3, SHA3_512
import hashlib

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

    def keyProcessing(self,secret_key:str)-> str:
        '''
        This message processes the key so it is the proper length

        Parameters : 
            secret_key : str
                The key as a bit string

        Return : 
            K_0 : str
                The procesed key as a bit string
        '''

        K = secret_key
        len_K = len(K)
        l = 64*8
        b = 72*8
        if len_K == b:
            K_0 = K
        elif len_K > b:
            K_0 = self.hexStringToBitString(self.hashHexToHex(K))+"0"*(b-l)
        elif len_K < b:
            K_0 = K + "0"*(b-len_K)

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
        binary_key = self.hexStringToBitString(key)
        K_0 = self.keyProcessing(binary_key)
        K0_xor_opad = self.bitwiseXor(K_0,opad)
        K0_xor_ipad = self.bitwiseXor(K_0,ipad)
        hex_messge = message.encode().hex().upper()
        hex_K0_xor_ipad = self.bitStringToHexString(K0_xor_ipad)
        hex_K0_xor_opad = self.bitStringToHexString(K0_xor_opad)
        assert hex_K0_xor_ipad == expected_k0_xor_ipad.upper()
        assert hex_K0_xor_opad == expected_k0_xor_opad.replace(" ","").upper()
        hex_concat = hex_K0_xor_ipad + hex_messge
        hash_K0_xor_ipad_M = self.hashHexToHex(hex_concat)
        K0_xor_opad_hex = self.bitStringToHexString(K0_xor_opad)
        final_hash = self.hashHexToHex(str(K0_xor_opad_hex) + str(hash_K0_xor_ipad_M))
        return final_hash
    
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
        byte_values = bytes.fromhex(hex_value)
        hash_result = hashlib.sha3_512(byte_values).hexdigest()
        # hash_result = self.sha3.h2b(self.sha3.hashHexToHex(self.sha3.b2h(self.hexStringToBitString(hex_value))))
        # hash_result = self.bitStringToHexString(hash_result)
        return hash_result.upper()

    def calculateHashOfItem(self, item_to_hash:str) -> str:
        '''
        This method calculate the sha3-512 hash digest of the message and returns it as a bit string

        Parameter :
            item_to_hash : str
                The item that is being hashed

        Returns :
            hash_value : str
                The hash value of the item as a bit string
        '''

        self.hash = self.sha3.hashStringToHex(item_to_hash)
        return self.bitStringToHexString(self.hexStringToBitString(self.hash))
    
    def bitwiseXor(self,string_1,string_2):
        '''
        This method performs a bitwise xor of two binary strings of the same length

        Parameters :
            string_1 : str
                The binary string for one of the values that is being xord
            string_2 str 
                The binary string for the other value being xord

        Returns :
            string_result : str
                The binary string of the result of the xor
        '''

        int_result = int(string_1,2) ^ int(string_2,2)
        string_result = '{0:0{1}b}'.format(int_result,len(string_1))
        return string_result
    
    def bitStringToHexString(self, bit_string:str) -> str :
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

    def  hexStringToBitString(self, hex_string:str) -> str:
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
    print(mac)
    assert mac == expected_mac.upper().replace(" ","")