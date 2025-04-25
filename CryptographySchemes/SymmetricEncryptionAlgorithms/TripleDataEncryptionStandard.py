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


        self.key = key
        self.is_debug = is_debug
        if string_key != None:
            self.des_1 = DataEncryptionStandard(string_key[:8])
            self.des_2 = DataEncryptionStandard(string_key[8:16])
            self.des_3 = DataEncryptionStandard(string_key[16:])
        else:
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