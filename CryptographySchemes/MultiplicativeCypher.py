from HelperFunctions.EuclidsAlgorithms import extendedEuclidAlgorithm

class MultiplicativeCypher():
    '''
    This class creates a multiplication cypher based around a given multiplication value
    '''

    def __init__(self, multiplication_value):
        '''
        This method initializes the multiplication cypher with a given multiplication value

        It also uses the extended form of euclid's algorithm to calculate the multiplicative inverse to be used in decryption
        
        gcd(26, mult_val) = s * 26 + t * mult_val
        inverse = t%26
        
        Parameters :
            multiplication_value : int
                The value to use for multiplication
        '''

        self.multiplication_value = multiplication_value
        _, _, self.inverse_value = extendedEuclidAlgorithm(26,self.multiplication_value)
        self.inverse_value = self.inverse_value % 26

    def encrypt(self, message, is_encrypting=True):
        '''
        This method encrypts the message according to the multilicative cypher's multiplication value

        Parameters :
            message : str
                The string message that is being encrypted 
            is_encrypting : Boolean
                whether the message is being encrypted or decrypted
                If it is false, the multiplicative inverse is used in the place of the multiplication value
        '''

        encrypted_message = ''
        for character in message:
            if character.isalpha():
                num = ord(character.lower()) - ord('a')
                encrypted_num = (num * (self.multiplication_value if is_encrypting else self.inverse_value)) % 26
                encrypted_message += chr(encrypted_num + ord('a'))
            else:
                encrypted_message += character
        return encrypted_message
       
    def decrypt(self, encrypted_message):
        '''
        This method decrypts an encrypted message

        Parameters :
            encrypted_message :
                The message which has already been encrypted using the multiplicative cypher
        '''

        return self.encrypt(encrypted_message,False)

if __name__ == '__main__':
    multiplicative_cypher = MultiplicativeCypher(7)
    message = "Multiplicative Cypher"
    encrypted_message = multiplicative_cypher.encrypt(message=message)
    decrypted_message = multiplicative_cypher.decrypt(encrypted_message=encrypted_message)
    print("Multiplicative Cypher is a simple example of encryption")
    print("- - - - - - - - - - - -")
    print(f"Original message: {message}")
    print(f"Encrypted message: {encrypted_message}")
    print(f"Decrypted message: {decrypted_message}")