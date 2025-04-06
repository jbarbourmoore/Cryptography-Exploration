class MultiplicativeCypher():
    '''
    This class creates a multiplication cypher based around a given multiplication value
    '''

    def __init__(self, multiplication_value):
        '''
        This method initializes the multiplication cypher with a given multiplication value

        It also uses the extended form of euclid's algorithm to calculation the multiplicative inverse to be used in decryption

        Parameters :
            multiplication_value : int
                The value to use for multiplication
        '''

        self.multiplication_value = multiplication_value
        self.inverse_value = self.extendedEuclidAlgorithm(26,7)
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

    def extendedEuclidAlgorithm(self, larger_number, smaller_number):
        '''
        This method implements the extended form of euclids algorithm

        Bezout Identity => s × a + t × b = gcd(a, b)

        Parameters :
            larger_number : int
                The larger number to be used
            smaller_number : int
                The smaller number to be used

        Returns : 
            t : int
                The number for t
        '''
        s = 1
        t = 0
        s_hat = 0
        t_hat = 1

        while smaller_number > 0:
            
            q = larger_number // smaller_number
            r = larger_number % smaller_number

            # m = q * n + r
            # or r = m - q * n = ( s - ( q * s_hat ) ) * m_0 + (t - ( q * t_hat ) ) * n_0  
            a = s - ( q * s_hat )
            b = t - ( q * t_hat )

            larger_number = smaller_number
            smaller_number = r
            s = s_hat
            t = t_hat
            s_hat = a
            t_hat = b

        return t

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