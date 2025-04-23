from CryptographySchemes.SymmetricEncryptionAlgorithms.AdvancedEncryptionStandard import *
from HelperFunctions.IntegerHandler import *
class AES_ECB_128(AES128):
    '''
    This class should allow AES 128 to be used in electronic cookbook (ECB) mode

    ECB is described in NIST SP 800-38a Section 6.1
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def encryptHexStringMessage(self, hex_message:str)->list[str]:
        '''
        This method encrypts a hex string using AES

        Parameters : 
            hex_message : str
                The content to be encrypted as a hex string

        Returns :
            encrypted_hex_list : [str]
                The result of the encryption as a list of hex strings
        '''

        hex_length = self.block_size // 4
        message_length = len(hex_message)
        if message_length % hex_length != 0:
            hex_message += "0"*(hex_length-message_length%hex_length)
            message_length = len(hex_message)
        hex_list = []
        for i in range (0, message_length//hex_length):
            hex_segment = hex_message[hex_length*i:hex_length*i+hex_length]
            hex_list.append(hex_segment)
        return self.encryptHexList(hex_list=hex_list)
    
    def encryptHexList(self, hex_list:list[str])->list[str]:
        '''
        This method encrypts a list of hex strings using AES

        Follows Eletronic Codebook (ECB) Mode Encryption as described in NIST SP 800-38a Section 6.1
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters : 
            hex_list : [str]
                The content to be encrypted as a list of hex strings in the appropriate block size

        Returns :
            encrypted_hex_list : [str]
                The result of the encryption as a list of hex strings
        '''
        number_of_message_blocks = len(hex_list)
        result_list = []
        for i in range (0, number_of_message_blocks):
            hex_segment = hex_list[i]
            result_list.append(self.cypher(hex_segment))
        return result_list

    def encryptStringMessage(self, string_message:str):
        '''
        This method takes in a string, uses utf-8 encoding to translate it to hex, and encrypts it in blocks using AES

        Parameters :
            string_message : str
                The message to be encrypted using AES
        
        Returns : 
            result_list : [str]
                The result of the encryption as a list of hexadecimal strings
        '''

        hex_list = self.stringToHexList(string_message)
        return self.encryptHexList(hex_list=hex_list)
    
    def decryptHexList(self, encrypted_list:list[str]) -> list[str]:
        '''
        This method takes in a list of encrypted hex strings and decypts them

        Follows Eletronic Codebook (ECB) Mode Decryption as described in NIST SP 800-38a Section 6.1
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters :
            encrypted_list : [str]
                The result of the encryption as a list of hexadecimal strings
        
        Returns : 
            unencrypted_hex_list : [str]
                The message that was encrypted using AES
            
        '''

        result_list = []
        for encoded_hex in encrypted_list:
            result_list.append(self.inverseCypher(encoded_hex))
        return result_list
    
    def decryptHexList_ToString(self, encrypted_list:list[str]) -> str:
        '''
        This method takes in a list of encrypted hex strings, decypts them and returns the message as a string

        Parameters :
            encrypted_list : [str]
                The result of the encryption as a list of hexadecimal strings
        
        Returns : 
            unencrypted_string : str
                The message that was encrypted using AES
            
        '''
        result_list = self.decryptHexList(encrypted_list=encrypted_list)
        unencrypted_string = self.hexListToString(result_list)
        return unencrypted_string
    
class AES_ECB_192(AES_ECB_128):
    '''
    This class is a subclass of AES_ECB_128 with a key length of 192 bits in Electronic Cookbook Mode

    ECB is described in NIST SP 800-38a Section 6.1
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''
    def __init__(self, key):
        '''
        This method should initialize aes_ecb_192 with a given key

        Parameters : 
            key : str
                The 192 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 192
        self.number_key_words = 6
        self.number_of_rounds = 12
        self.keyExpansion()

class AES_ECB_256(AES_ECB_128):
    '''
    This class is a subclass of AES_ECB_128 with a key length of 256 bits in Electronic Cookbook Mode

    ECB is described in NIST SP 800-38a Section 6.1
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def __init__(self, key):
        '''
        This method should initialize aes ecb 256 with a given key

        Parameters : 
            key : str
                The 256 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 256
        self.number_of_rounds = 14
        self.number_key_words = 8
        self.keyExpansion()

class AES_CBC_128(AES_ECB_128):
    '''
    This class implements the Cipher Block Chaining (CBC) Mode for AES 128

    CBC is described in NIST SP 800-38a Section 6.2
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def encryptHexList(self, hex_list:list[str], initialization_vector:str)->list[str]:
        '''
        This method encrypts a list of hex strings using AES

        Follows Cipher Block Chaining (CBC) Mode Encryption as described in NIST SP 800-38a Section 6.2
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters : 
            hex_list : [str]
                The content to be encrypted as a list of hex strings in the appropriate block size
            initialization_vector : str
                The initializtion vector as a hex string

        Returns :
            encrypted_hex_list : [str]
                The result of the encryption as a list of hex strings
        '''
        number_of_message_blocks = len(hex_list)
        result_list = []
        xor_vector = initialization_vector
        for i in range (0, number_of_message_blocks):
            hex_segment = hex_list[i]
            xor_result = self.xorHexString(xor_vector, hex_segment)
            cipher_text = self.cypher(xor_result)
            result_list.append(cipher_text)
            xor_vector = cipher_text
        return result_list
    
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
        value_1 = int(hex_string_1, 16)
        value_2 = int(hex_string_2, 16)
        xor_value = value_1 ^ value_2
        xor_string = str(hex(xor_value)[2:])
        if len(xor_string)< len(hex_string_1):
            xor_string = "0"*(len(hex_string_1)-len(xor_string))+xor_string
        return xor_string.upper()

    def decryptHexList(self, encrypted_list:list[str], initialization_vector:str) -> list[str]:
        '''
        This method takes in a list of encrypted hex strings and decypts them
        
        Follows Cipher Block Chaining (CBC) Mode Decryption as described in NIST SP 800-38a Section 6.2
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters :
            encrypted_list : [str]
                The result of the encryption as a list of hexadecimal strings
            initialization_vector : str
                The initializtion vector as a hex string
        
        Returns : 
            unencrypted_hex_list : [str]
                The message that was encrypted using AES
            
        '''

        result_list = []
        xor_vector = initialization_vector
        for encoded_hex in encrypted_list:
            post_cypher = self.inverseCypher(encoded_hex)
            post_xor =self.xorHexString(xor_vector,post_cypher)
            xor_vector = encoded_hex
            result_list.append(post_xor)
        return result_list
    
    def encryptHexStringMessage(self, hex_message:str, initialization_vector:str)->list[str]:
        '''
        This method encrypts a hex string using AES

        Parameters : 
            hex_message : str
                The content to be encrypted as a hex string
            initialization_vector : str
                The initializtion vector as a hex string

        Returns :
            encrypted_hex_list : [str]
                The result of the encryption as a list of hex strings
        '''

        hex_length = self.block_size // 4
        message_length = len(hex_message)
        if message_length % hex_length != 0:
            hex_message += "0"*(hex_length-message_length%hex_length)
            message_length = len(hex_message)
        hex_list = []
        for i in range (0, message_length//hex_length):
            hex_segment = hex_message[hex_length*i:hex_length*i+hex_length]
            hex_list.append(hex_segment)
        return self.encryptHexList(hex_list=hex_list, initialization_vector=initialization_vector)
    
    def encryptStringMessage(self, string_message:str, initializaion_vector:str):
        '''
        This method takes in a string, uses utf-8 encoding to translate it to hex, and encrypts it in blocks using AES

        Parameters :
            string_message : str
                The message to be encrypted using AES
            initialization_vector : str
                The initializtion vector as a hex string
        
        Returns : 
            result_list : [str]
                The result of the encryption as a list of hexadecimal strings
        '''

        hex_list = self.stringToHexList(string_message)
        return self.encryptHexList(hex_list=hex_list, initialization_vector=initializaion_vector)
    
    def decryptHexList_ToString(self, encrypted_list:list[str], initialization_vector:str) -> str:
        '''
        This method takes in a list of encrypted hex strings, decypts them and returns the message as a string

        Parameters :
            encrypted_list : [str]
                The result of the encryption as a list of hexadecimal strings
            initialization_vector : str
                The initializtion vector as a hex string
        
        Returns : 
            unencrypted_string : str
                The message that was encrypted using AES
            
        '''
        result_list = self.decryptHexList(encrypted_list=encrypted_list, initialization_vector=initialization_vector)
        unencrypted_string = self.hexListToString(result_list)
        return unencrypted_string
    
class AES_CBC_192(AES_CBC_128):
    '''
    This class is a subclass of AES_CBC_128 with a key length of 192 bits in Cipher Block Chaining (CBC) Mode

    CBC is described in NIST SP 800-38a Section 6.2
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''
    def __init__(self, key):
        '''
        This method should initialize aes_ecb_192 with a given key

        Parameters : 
            key : str
                The 192 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 192
        self.number_key_words = 6
        self.number_of_rounds = 12
        self.keyExpansion()

class AES_CBC_256(AES_CBC_128):
    '''
    This class is a subclass of AES_CBC_128 with a key length of 256 bits in Cipher Block Chaining (CBC) Mode

    CBC is described in NIST SP 800-38a Section 6.2
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def __init__(self, key):
        '''
        This method should initialize aes ecb 256 with a given key

        Parameters : 
            key : str
                The 256 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 256
        self.number_of_rounds = 14
        self.number_key_words = 8
        self.keyExpansion()

class AES_CFB_128(AES_CBC_128):
    '''
    This class implements the Cipher Feedback (CFB) Mode for AES 128

    CFB is described in NIST SP 800-38a Section 6.3
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def __init__(self, key, s:int):
        super().__init__(key)
        self.s = s

    def encryptHexList(self, hex_list:list[str], initialization_vector:str)->list[str]:
        '''
        This method encrypts a list of hex strings using AES

        Follows Cipher Feedback (CFB) Mode Encryption as described in NIST SP 800-38a Section 6.3
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters : 
            hex_list : [str]
                The content to be encrypted as a list of hex strings in the appropriate block size
            initialization_vector : str
                The initializtion vector as a hex string

        Returns :
            encrypted_hex_list : [str]
                The result of the encryption as a list of hex strings
        '''
        number_of_message_blocks = len(hex_list)
        b = self.block_size
        s = self.s
        rotations_per_segment = b // s        
        result_list = []
        I = initialization_vector
        for i in range (0, number_of_message_blocks):
            message_chunk = IntegerHandler.fromHexString(hex_list[i],False,b)
            encrypted_message = IntegerHandler(0,False,0)
            for j in range (0, rotations_per_segment):
                O = self.cypher(I)
                # result_list.append(O)
                most_sig_O = IntegerHandler.fromHexString(O,False,b).getMostSignificantBits(s)
                P = IntegerHandler.fromBitArray(message_chunk.getBitArray()[j*s:j*s+s],False,s)
                C = bitwiseXor([P,most_sig_O],False,s)
                encrypted_message = concatenate([encrypted_message,C],False)
                lsb = IntegerHandler.fromHexString(I,False,128).getLeastSignificantBits(b-s)
                I = concatenate([lsb,C],False).getHexString()
            result_list.append(encrypted_message.getHexString())
        return result_list

    def decryptHexList(self, encrypted_list:list[str], initialization_vector:str) -> list[str]:
        '''
        This method takes in a list of encrypted hex strings and decypts them

        Follows Cipher Feedback (CFB) Mode Decryption as described in NIST SP 800-38a Section 6.3
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters :
            encrypted_list : [str]
                The result of the encryption as a list of hexadecimal strings
            initialization_vector : str
                The initializtion vector as a hex string
        
        Returns : 
            unencrypted_hex_list : [str]
                The message that was encrypted using AES
            
        '''

        result_list = []
        b = self.block_size
        s = self.s
        rotations_per_segment = b // s    
        number_of_message_blocks = len(encrypted_list)
        result_list = []
        I = initialization_vector
        for i in range (0, number_of_message_blocks):
            message_chunk = IntegerHandler(0,False,0)
            encrypted_chunk = IntegerHandler.fromHexString(encrypted_list[i],False,b)
            for j in range (0, rotations_per_segment):
                O = self.cypher(I)
                most_sig_O = IntegerHandler.fromHexString(O,False,b).getMostSignificantBits(s)
                C = IntegerHandler.fromBitArray(encrypted_chunk.getBitArray()[j*s:j*s+s],False,s)
                P = bitwiseXor([C,most_sig_O],False,s)
                message_chunk = concatenate([message_chunk,P],False)
                lsb = IntegerHandler.fromHexString(I,False,128).getLeastSignificantBits(b-s)
                I = concatenate([lsb,C],False).getHexString()
            result_list.append(message_chunk.getHexString())
        return result_list

class AES_CFB_192(AES_CFB_128):
    '''
    This class is a subclass of AES_CFB_128 with a key length of 192 bits in Cipher Feedback (CFB) Mode

    CFB is described in NIST SP 800-38a Section 6.3
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''
    def __init__(self, key, s:int):
        '''
        This method should initialize aes_cfb_192 with a given key

        Parameters : 
            key : str
                The 192 bit key for the aes algorithm
        '''

        super().__init__(key, s)
        self.key_length = 192
        self.number_key_words = 6
        self.number_of_rounds = 12
        self.keyExpansion()

class AES_CFB_256(AES_CFB_128):
    '''
    This class is a subclass of AES_CFB_128 with a key length of 256 bits in Cipher Feedback (CFB) Mode

    CFB is described in NIST SP 800-38a Section 6.3
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def __init__(self, key, s:int):
        '''
        This method should initialize aes cfb 256 with a given key

        Parameters : 
            key : str
                The 256 bit key for the aes algorithm
        '''

        super().__init__(key, s)
        self.key_length = 256
        self.number_of_rounds = 14
        self.number_key_words = 8
        self.keyExpansion()

class AES_OFB_128(AES_CBC_128):
    '''
    This class implements the Output Feedback (OFB) Mode for AES 128
    
    OFB is described in NIST SP 800-38a Section 6.4
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def encryptHexList(self, hex_list:list[str], initialization_vector:str)->list[str]:
        '''
        This method encrypts a list of hex strings using AES

        Follows Output Feedback (OFB) Mode Encryption as described in NIST SP 800-38a Section 6.4
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters : 
            hex_list : [str]
                The content to be encrypted as a list of hex strings in the appropriate block size
            initialization_vector : str
                The initializtion vector as a hex string

        Returns :
            encrypted_hex_list : [str]
                The result of the encryption as a list of hex strings
        '''
        number_of_message_blocks = len(hex_list)
        result_list = []
        I = initialization_vector
        for i in range (0, number_of_message_blocks):
            hex_segment = hex_list[i]
            O = self.cypher(I)
            C = self.xorHexString(hex_segment,O)
            result_list.append(C)
            I = O
        return result_list
    
    def decryptHexList(self, encrypted_list:list[str], initialization_vector:str) -> list[str]:
        '''
        This method takes in a list of encrypted hex strings and decypts them

        Follows Output Feedback (OFB) Mode Decryption as described in NIST SP 800-38a Section 6.4
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters :
            encrypted_list : [str]
                The result of the encryption as a list of hexadecimal strings
            initialization_vector : str
                The initializtion vector as a hex string
        
        Returns : 
            unencrypted_hex_list : [str]
                The message that was encrypted using AES
            
        '''

        result_list = []
        I = initialization_vector
        for encoded_hex in encrypted_list:
            O = self.cypher(I)
            P = self.xorHexString(encoded_hex,O)
            result_list.append(P)
            I = O
        return result_list
    
class AES_OFB_192(AES_OFB_128):
    '''
    This class is a subclass of AES_OFB_128 with a key length of 192 bits in Output Feedback (OFB) Mode

    OFB is described in NIST SP 800-38a Section 6.4
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''
    def __init__(self, key):
        '''
        This method should initialize aes_ecb_192 with a given key

        Parameters : 
            key : str
                The 192 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 192
        self.number_key_words = 6
        self.number_of_rounds = 12
        self.keyExpansion()

class AES_OFB_256(AES_OFB_128):
    '''
    This class is a subclass of AES_OFB_128 with a key length of 256 bits in Output Feedback (OFB) Mode

    OFB is described in NIST SP 800-38a Section 6.4
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def __init__(self, key):
        '''
        This method should initialize aes ecb 256 with a given key

        Parameters : 
            key : str
                The 256 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 256
        self.number_of_rounds = 14
        self.number_key_words = 8
        self.keyExpansion()

class AES_CTR_128(AES_CBC_128):
    '''
    This class implements the Counter (CTR) Mode for AES 128

    CTR is described in NIST SP 800-38a Section 6.5
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def encryptHexList(self, hex_list:list[str], initialization_vector:str)->list[str]:
        '''
        This method encrypts a list of hex strings using AES

        Follows Counter (CTR) Mode Encryption as described in NIST SP 800-38a Section 6.5
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters : 
            hex_list : [str]
                The content to be encrypted as a list of hex strings in the appropriate block size
            initialization_vector : str
                The initializtion vector as a hex string

        Returns :
            encrypted_hex_list : [str]
                The result of the encryption as a list of hex strings
        '''
        number_of_message_blocks = len(hex_list)
        result_list = []
        T = IntegerHandler.fromHexString(initialization_vector,False,self.block_size)
        for i in range (0, number_of_message_blocks):
            hex_segment = hex_list[i]
            O = self.cypher(T.getHexString())
            C = self.xorHexString(hex_segment,O)
            result_list.append(C)
            T.setValue(T.getValue()+1)
        return result_list
    
    def decryptHexList(self, encrypted_list:list[str], initialization_vector:str) -> list[str]:
        '''
        This method takes in a list of encrypted hex strings and decypts them

        Follows Counter (CTR) Mode Decryption as described in NIST SP 800-38a Section 6.5
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        Parameters :
            encrypted_list : [str]
                The result of the encryption as a list of hexadecimal strings
            initialization_vector : str
                The initializtion vector as a hex string
        
        Returns : 
            unencrypted_hex_list : [str]
                The message that was encrypted using AES
            
        '''

        result_list = []
        T = IntegerHandler.fromHexString(initialization_vector,False,self.block_size)
        for encoded_hex in encrypted_list:
            O = self.cypher(T.getHexString())
            P = self.xorHexString(encoded_hex,O)
            result_list.append(P)
            T.setValue(T.getValue()+1)
        return result_list
    
class AES_CTR_192(AES_CTR_128):
    '''
    This class is a subclass of AES_CTR_128 with a key length of 192 bits in Counter (CTR) Mode

    CTR is described in NIST SP 800-38a Section 6.5
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''
    def __init__(self, key):
        '''
        This method should initialize aes_ctr_192 with a given key

        Parameters : 
            key : str
                The 192 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 192
        self.number_key_words = 6
        self.number_of_rounds = 12
        self.keyExpansion()

class AES_CTR_256(AES_CTR_128):
    '''
    This class is a subclass of AES_CTR_128 with a key length of 256 bits in Counter (CTR) Mode

    CTR is described in NIST SP 800-38a Section 6.5
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    '''

    def __init__(self, key):
        '''
        This method should initialize aes ctr 256 with a given key

        Parameters : 
            key : str
                The 256 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 256
        self.number_of_rounds = 14
        self.number_key_words = 8
        self.keyExpansion()