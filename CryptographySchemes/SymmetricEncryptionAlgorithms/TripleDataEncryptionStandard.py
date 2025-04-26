from CryptographySchemes.SymmetricEncryptionAlgorithms.DataEncryptionStandard import DataEncryptionStandard
from HelperFunctions.IntegerHandler import *
class TripleDataEncryptionStandard():
    '''
	This class holds the necessary methods for a basic implementation of 3DES
    As laid out in NIST FIPS 46-3 which has since been withdrawn (Archived at https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf)
	'''


    def __init__(self, string_key=None, hex_key=None, is_debug=False):
        '''
        This method initializes the 3DES with a key which should be 24 characters long or 192 bits

        Parameters :
            key : str
                The string for the key for 3DES
        '''


        
        self.is_debug = is_debug
        if string_key != None:
            self.key = string_key
            self.des_1 = DataEncryptionStandard(string_key[:8])
            self.des_2 = DataEncryptionStandard(string_key[8:16])
            self.des_3 = DataEncryptionStandard(string_key[16:])
        else:
            self.key = hex_key
            self.des_1 = DataEncryptionStandard(hex_key[:16],is_hex_key=True)
            self.des_2 = DataEncryptionStandard(hex_key[16:32],is_hex_key=True)
            self.des_3 = DataEncryptionStandard(hex_key[32:],is_hex_key=True)

    def encrypt(self, message):
        '''
        This method encrypts a message using three rounds of des (encrypt, then decrypt, then encrypt) with different keys

        Parameters : 
            message : str
                The message to be encrypted
        
        Returns : 
            encrypted_decrypted_encrypted : [str]
                The encrypted message as a list of binarys
        '''
        message_hex = IntegerHandler.fromString(message).getHexString()
        hex_encrypted = self.encryptHex(message_hex)
        return hex_encrypted
    
    def encryptHex(self, message):
        '''
        This method encrypts a message using three rounds of des (encrypt, then decrypt, then encrypt) with different keys

        Parameters : 
            message : str
                The message to be encrypted
        
        Returns : 
            encrypted_decrypted_encrypted : [str]
                The encrypted message as a list of binarys
        '''

        encrypted = self.des_1.encryptHexMessage(message)
        encrypted_decrypted = self.des_2.decryptHexMessage(encrypted)
        encrypted_decrypted_encrypted = self.des_3.encryptHexMessage(encrypted_decrypted)

        return encrypted_decrypted_encrypted
    
    def decrypt(self,encrypted_decrypted_encrypted):
        '''
        This method decrypts a message using three rounds of des (decrypt, then encrypt, then decrypt) with different keys

        Parameters : 
            encrypted_decrypted_encrypted : [str]
                The encrypted message as a list of binarys
        
        Returns : 
            message : str
                The message to be encrypted
        '''

        decrypted_hex = self.decryptHex(encrypted_decrypted_encrypted)
        message = IntegerHandler.fromHexString(decrypted_hex,False).getString()
        return message
    
    def decryptHex(self,encrypted_hex):
        '''
        This method decrypts a message using three rounds of des (decrypt, then encrypt, then decrypt) with different keys

        Parameters : 
            encrypted_decrypted_encrypted : [str]
                The encrypted message as a list of binarys
        
        Returns : 
            message : str
                The message to be encrypted
        '''

        encrypted_decrypted = self.des_3.decryptHexMessage(encrypted_hex)
        encrypted = self.des_2.encryptHexMessage(encrypted_decrypted)
        message = self.des_1.decryptHexMessage(encrypted)

        return message
    
class TDES_ECB():
    '''
    This class should allow Triple Data Encryption Standard to be used in electronic cookbook (ECB) mode

    ECB is described in NIST SP 800-38a Section 6.1
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''
    def __init__(self, key:str, is_hex_key:bool=True):
        '''
        This method initializes TDES in ECB mode

        Parameters :
            key : str
                The key for the triple data encription as either a utf-8 string or hex string
            is_hex_key : bool
                Whether the key is a hexadecimal string
        '''
        if is_hex_key:
            self.tdes = TripleDataEncryptionStandard(hex_key=key)
        else:
            self.tdes = TripleDataEncryptionStandard(string_key=key)

        self.block_size = 64

    def encryptHexString(self, hex_message:str) -> str:
        '''
        This method encrypts a hexadecimal string

        Parameters :
            hex_message : str
                The hexadecimal string to be encrypted

        Returns :
            encrypted_hex : str
                The hexadecimal string as an encrypted hexadecimal string
        '''

        return self.tdes.encryptHex(hex_message)
        
    def decryptHexString(self, hex_encrypted:str) -> str:
        '''
        This method decrypts an encrypted hexadecimal string using TDES

        Parameters :
            hex_encrypted : stre
                The encrypted message as a hexadecimal string

        Returns :
            decrypted_hex : str
                The decrypted message as a hexadecimal string
        '''

        return self.tdes.decryptHex(hex_encrypted)
    
    def encryptString(self, string_message:str) -> str:
        '''
        This method encrypts a string message encoded using utf-8 and returns the encryption as a hexadecimal string

        Parameters :
            string_message : str
                The string to be encrypted

        Returns :
            encrypted_hex : str
                The string as an encrypted hexadecimal string
        '''

        hex_message = IntegerHandler.fromString(string_message,False,len(string_message)*8).getHexString()
        return self.encryptHexString(hex_message)
    
    def decryptString(self, encrypted_hex:str) -> str:
        '''
        This method decrypts an encrypted string using TDES

        Parameters :
            hex_encrypted : str
                The encrypted message as a hexadecimal string

        Returns :
            decrypted_string : str
                The decrypted message as a string decoded from utf-8
        '''

        decrypted_hex = self.decryptHexString(encrypted_hex)
        return IntegerHandler.fromHexString(decrypted_hex,False,len(decrypted_hex)*4).getString()

class TDES_CBC(TDES_ECB):
    '''
    This class implements the Cipher Block Chaining (CBC) Mode for Triple Data Encryption Standard (TDES)

    CBC is described in NIST SP 800-38a Section 6.2
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def encryptHexString(self, hex_message:str, initialization_vector:str) -> str:
        '''
        This method encrypts a hexadecimal string

        Parameters :
            hex_message : str
                The hexadecimal string to be encrypted
            initialization_vector : str
                The initialization vector to be used with the encryption mode

        Returns :
            encrypted_hex : str
                The hexadecimal string as an encrypted hexadecimal string
        '''

        if len(hex_message) % 16 != 0:
            hex_message = hex_message + "0" * (16 - (hex_message % 16))

        number_of_blocks = len(hex_message) // 16
        current_to_xor = initialization_vector
        encrypted_hex = ""
        for i in range(0, number_of_blocks):
            hex_segment = hex_message[i * 16 : i * 16 + 16]
            xor_result = self.xorHexString(current_to_xor, hex_segment)
            cipher_text = self.tdes.encryptHex(xor_result)
            encrypted_hex += cipher_text
            current_to_xor = cipher_text
            # print(f"hex:{hex_segment}, xord:{xor_result}, cipher:{cipher_text}")

        return encrypted_hex
    
    def xorHexString(self, hex_string_1:str, hex_string_2:str)-> str:
        '''
        This method performs an exclusive or operation on two hex strings

        Parameters:
            hex_string_1, hex_string_2 : str
                The two hex strings the xor operation is being performed on

        Returns : 
            xor_string : str
                The result of the xor operation as a hex string
        '''
        handler_1 = IntegerHandler.fromHexString(hex_string_1,False,len(hex_string_1)*4)
        handler_2 = IntegerHandler.fromHexString(hex_string_2,False,len(hex_string_2)*4)
        return bitwiseXor([handler_1,handler_2], False, handler_1.getBitLength()).getHexString()
    
    def decryptHexString(self, hex_encrypted:str, initialization_vector:str) -> str:
        '''
        This method decrypts an encrypted hexadecimal string using TDES

        Parameters :
            hex_encrypted : stre
                The encrypted message as a hexadecimal string
            initialization_vector : str
                The initialization vector to be used with the encryption mode

        Returns :
            decrypted_hex : str
                The decrypted message as a hexadecimal string
        '''

        number_of_blocks = len(hex_encrypted) // 16
        current_to_xor = initialization_vector
        unencrypted_hex = ""
        for i in range(0, number_of_blocks):
            hex_segment = hex_encrypted[i * 16 : i * 16 +16]
            post_cypher = self.tdes.decryptHex(hex_segment)
            post_xor =self.xorHexString(current_to_xor,post_cypher)
            current_to_xor = hex_segment
            unencrypted_hex += post_xor
        return unencrypted_hex
    
    def encryptString(self, string_message:str, initialization_vector:str) -> str:
        '''
        This method encrypts a string message encoded using utf-8 and returns the encryption as a hexadecimal string

        Parameters :
            string_message : str
                The string to be encrypted
            initialization_vector : str
                The initialization vector to be used with the encryption mode

        Returns :
            encrypted_hex : str
                The string as an encrypted hexadecimal string
        '''

        hex_message = IntegerHandler.fromString(string_message,False,len(string_message)*8).getHexString()
        return self.encryptHexString(hex_message, initialization_vector)
    
    def decryptString(self, encrypted_hex:str, initialization_vector:str) -> str:
        '''
        This method decrypts an encrypted string using TDES

        Parameters :
            hex_encrypted : str
                The encrypted message as a hexadecimal string
            initialization_vector : str
                The initialization vector to be used with the encryption mode

        Returns :
            decrypted_string : str
                The decrypted message as a string decoded from utf-8
        '''

        decrypted_hex = self.decryptHexString(encrypted_hex, initialization_vector)
        return IntegerHandler.fromHexString(decrypted_hex,False,len(decrypted_hex)*4).getString()
    
class TDES_CFB(TDES_CBC):
    '''
    This class implements the Cipher Feedback (CFB) Mode for TDES

    CFB is described in NIST SP 800-38a Section 6.3
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def __init__(self,  key:str, s:int, is_hex_key:bool=True):
        '''
        This method initializes TDES in CFB mode

        Parameters :
            key : str
                The key for the triple data encription as either a utf-8 string or hex string
            s : int
                The s value for the cypher feedback encryption mode
            is_hex_key : bool
                Whether the key is a hexadecimal string
        '''
        super().__init__(key)
        self.s = s

    def encryptHexString(self, hex_string:str, initialization_vector:str)->list[str]:
        '''
        This method encrypts a list of hex strings using TDES

        Follows Cipher Feedback (CFB) Mode Encryption as described in NIST SP 800-38a Section 6.3
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters : 
            hex_string : str
                The content to be encrypted as a hex string in the appropriate block size
            initialization_vector : str
                The initializtion vector as a hex string

        Returns :
            encrypted_hex : str
                The result of the encryption as a list of hex strings
        '''
        number_of_message_blocks = len(hex_string) // 16
        b = 64
        s = self.s
        rotations_per_segment = b // s        
        result_string = ""
        I = initialization_vector
        for i in range (0, number_of_message_blocks):
            message_chunk = IntegerHandler.fromHexString(hex_string[i*16:i*16+16],False,b)
            encrypted_message = IntegerHandler(0,False,0)
            for j in range (0, rotations_per_segment):
                O = self.tdes.encryptHex(I)
                # result_list.append(O)
                most_sig_O = IntegerHandler.fromHexString(O,False,b).getMostSignificantBits(s)
                P = IntegerHandler.fromBitArray(message_chunk.getBitArray()[j*s:j*s+s],False,s)
                C = bitwiseXor([P,most_sig_O],False,s)
                encrypted_message = concatenate([encrypted_message,C],False)
                lsb = IntegerHandler.fromHexString(I,False,64).getLeastSignificantBits(b-s)
                I = concatenate([lsb,C],False).getHexString()
            result_string += encrypted_message.getHexString()
        return result_string
    
    def decryptHexString(self, encrypted_hex:str, initialization_vector:str) -> list[str]:
        '''
        This method takes in a encrypted bex string and decrypts it using TDES

        Follows Cipher Feedback (CFB) Mode Decryption as described in NIST SP 800-38a Section 6.3
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters :
            encrypted_hex : hex
                The result of the encryption as a hexadecimal string
            initialization_vector : str
                The initializtion vector as a hex string
        
        Returns : 
            decrypted_hex : str
                The message that was encrypted using TDES
        '''

        b = 64
        s = self.s
        rotations_per_segment = b // s    
        number_of_message_blocks = len(encrypted_hex) // 16
        result_hex = ""
        I = initialization_vector
        for i in range (0, number_of_message_blocks):
            message_chunk = IntegerHandler(0, False, 0)
            encrypted_chunk = IntegerHandler.fromHexString(encrypted_hex[i * 16 : i * 16 + 16], False, b)
            for j in range (0, rotations_per_segment):
                O = self.tdes.encryptHex(I)
                most_sig_O = IntegerHandler.fromHexString(O,False,b).getMostSignificantBits(s)
                C = IntegerHandler.fromBitArray(encrypted_chunk.getBitArray()[j * s : j * s + s], False, s)
                P = bitwiseXor([C, most_sig_O], False, s)
                message_chunk = concatenate([message_chunk,P],False)
                lsb = IntegerHandler.fromHexString(I, False, 64).getLeastSignificantBits(b - s)
                I = concatenate([lsb, C], False).getHexString()
            result_hex += message_chunk.getHexString()
        return result_hex
    
class TDES_OFB(TDES_CBC):
    '''
    This class implements the Output Feedback (OFB) Mode for TDES
    
    OFB is described in NIST SP 800-38a Section 6.4
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def encryptHexString(self, hex_string:str, initialization_vector:str)->list[str]:
        '''
        This method encrypts a list of hex strings using TDES

        Follows Output Feedback (OFB) Mode Encryption as described in NIST SP 800-38a Section 6.3
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters : 
            hex_string : str
                The content to be encrypted as a hex string in the appropriate block size
            initialization_vector : str
                The initializtion vector as a hex string

        Returns :
            encrypted_hex : str
                The result of the encryption as a list of hex strings
        '''
        number_of_message_blocks = len(hex_string) // 16
        encrypted_hex = ""
        I = initialization_vector
        for i in range (0, number_of_message_blocks):
            hex_segment = hex_string[i * 16 : i * 16 + 16]
            O = self.tdes.encryptHex(I)
            C = self.xorHexString(hex_segment, O)
            encrypted_hex += C
            I = O
        return encrypted_hex
    
    def decryptHexString(self, encrypted_hex:str, initialization_vector:str) -> list[str]:
        '''
        This method takes in a encrypted bex string and decrypts it using TDES

        Follows Cipher Feedback (CFB) Mode Decryption as described in NIST SP 800-38a Section 6.3
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters :
            encrypted_hex : hex
                The result of the encryption as a hexadecimal string
            initialization_vector : str
                The initializtion vector as a hex string
        
        Returns : 
            decrypted_hex : str
                The message that was encrypted using TDES
            
        '''

        number_of_message_blocks = len(encrypted_hex) // 16
        decrypted_hex = ""
        I = initialization_vector
        for i in range (0, number_of_message_blocks):
            hex_segment = encrypted_hex[i * 16 : i * 16 + 16]
            O = self.tdes.encryptHex(I)
            P = self.xorHexString(hex_segment, O)
            decrypted_hex += P
            I = O
        return decrypted_hex
    
if __name__ == '__main__':

    key = "12345678asdfghjkqwertyui"
    triple_des = TripleDataEncryptionStandard(string_key=key, is_debug=True)
    message ="I want to encrypt this message hopefully!"
    print(message)
    entire_encrypted_message = triple_des.encrypt(message)
    decrypted_message = triple_des.decrypt(entire_encrypted_message)
    print(f"{message} : {decrypted_message}")
    assert message == decrypted_message
    other_3des = TripleDataEncryptionStandard(string_key="h28deqnct39hoqnxtak4bd8w")
    decrypted_message_wrong_key = other_3des.decrypt(entire_encrypted_message)
    print(decrypted_message_wrong_key)
    assert message != decrypted_message_wrong_key

    key ="0123456789ABCDEF"
    key2 = "23456789ABCDEF01"
    key3 = "456789ABCDEF0123"

    triple_des = TripleDataEncryptionStandard(hex_key=key+key2+key3,is_debug=True)
    from HelperFunctions.IntegerHandler import *
    plain_text_1 = "5468652071756663"
    plain_text_2 = "6B2062726F776E20"
    plain_text_3 = "666F78206A756D70"
    entire_encrypted_message = triple_des.encryptHex(plain_text_1+plain_text_2+plain_text_3)
    print(entire_encrypted_message)

    message = "The quick brown fox jump"
    entire_encrypted_message = triple_des.encryptHex(plain_text_1+plain_text_2+plain_text_3)
    print(entire_encrypted_message)