from CryptographySchemes.SymmetricEncryptionAlgorithms.AdvancedEncryptionStandard import *
class AES_ECB_128(AES128):
    '''
    This class should allow AES 128 to be used in electronic cookbook mode
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