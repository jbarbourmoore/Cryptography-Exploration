from CryptographySchemes.DataEncryptionStandard import DataEncryptionStandard

class TripleDataEncryptionStandard():
    '''
	This class holds the necessary methods for a basic implementation of 3DES
    As laid out in NIST FIPS 46-3 which has since been withdrawn (Archived at https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf)
	'''


    def __init__(self, key, is_debug=False):
        '''
        This method initializes the 3DES with a key which should be 24 characters long or 192 bits

        Parameters :
            key : str
                The string for the key for 3DES
        '''


        self.key = key
        self.is_debug = is_debug

        self.des_1 = DataEncryptionStandard(key[:8])
        self.des_2 = DataEncryptionStandard(key[8:16])
        self.des_3 = DataEncryptionStandard(key[16:])

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

        encrypted = self.des_1.encryptMessage(message)
        encrypted_decrypted = self.des_2.decryptMessage(encrypted)
        encrypted_decrypted_encrypted = self.des_3.encryptMessage(encrypted_decrypted)

        if self.is_debug:
            print(self.des_3.binaryListToString(encrypted_decrypted_encrypted))
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

        encrypted_decrypted = self.des_3.decryptMessage(encrypted_decrypted_encrypted)
        encrypted = self.des_2.encryptMessage(encrypted_decrypted)
        message = self.des_1.decryptMessage(encrypted)

        return message
    
if __name__ == '__main__':

    key = "12345678asdfghjkqwertyui"
    triple_des = TripleDataEncryptionStandard(key, True)
    message ="I want to encrypt this message hopefully!"
    print(message)
    entire_encrypted_message = triple_des.encrypt(message)
    decrypted_message = triple_des.decrypt(entire_encrypted_message)
    print(f"{message} : {decrypted_message}")
    assert message == decrypted_message
    other_3des = TripleDataEncryptionStandard("h28deqnct39hoqnxtak4bd8w")
    decrypted_message_wrong_key = other_3des.decrypt(entire_encrypted_message)
    print(decrypted_message_wrong_key)
    assert message != decrypted_message_wrong_key