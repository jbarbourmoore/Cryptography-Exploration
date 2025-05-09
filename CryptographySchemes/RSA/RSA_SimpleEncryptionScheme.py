from HelperFunctions.EuclidsAlgorithms import extendedEuclidAlgorithm
from HelperFunctions.EncodeStringAsNumberList import EncodeStringAsNumbersList

class Simple_RSACryptographyScheme():
    '''
    This class contains an implementation along the lines of the RSA Cryptography Scheme

    Given two large prime numbers it generates 3 numbers => n, e and d
    
    The public key consists of n and e 
    While the private key consists of n and d

    Messages must first be converted into a list of numbers
    Then each number can be encrypted using the public key
    This can then be decrypted using the private key
    And converted back to a string

    encrypt => (M, (e, n)) = M**e % n
    decrypt => (M, (d, n)) = M**d % n
    '''

    def __init__(self, smaller_large_prime, larger_prime, number_system_base = 214, block_size = 5):
        '''
        This method initializes the RSACryptographyScheme

        Parameters :
            smaller_large_prime : int
                The smaller of the two large primes to generate the rsa keys
            larger_prime : int
                The larger of the two large primes to generate the rsa keys
            number_system_base : int, optional
                The number system base to use when converting the message to a list of numbers (default is 214)
            block_size : int, optional
                The number of characters in each block when encoded (default is five)
        '''

        self.smaller_large_prime = smaller_large_prime
        self.larger_prime = larger_prime
        self.string_to_numbers_encoder = EncodeStringAsNumbersList(number_system_base=number_system_base, block_size=block_size)
        self.number_system_base = number_system_base
        self.block_size = block_size

        self.generateRSAKeys()

    def generateRSAKeys(self):
        '''
        This method generates the RSA keys using the extended form of euclid's algorithm
        '''

        n = self.smaller_large_prime * self.larger_prime
        phi = ( self.smaller_large_prime - 1 ) * ( self.larger_prime - 1 )
        e = None
        d = None
        for e in range( self.smaller_large_prime//3, self.smaller_large_prime ):
            i, _, t = extendedEuclidAlgorithm(phi, e)
            if i == 1:
                if t < 0:
                    d = phi + t
                else:
                    d = t
                break
        self.n = n
        self.d = d
        self.e = e

    def getPublicKey(self):
        '''
        This method returns the public key components as a tuple
        '''

        return (self.e,self.n)
    
    def getPrivateKey(self):
        '''
        This method returns the private key components as a tuple
        '''
        
        return (self.d,self.n)

    def rsaEncoding(self, message):
        '''
        This method encodes the message using the public key

        Parameters :
            message : str
                The message to be encrypted

        Returns :
            list_message_rsa_encoded : [int]
                The list of numbers that are the encoded message
        '''

        list_message_numbers, status = self.string_to_numbers_encoder.convertStringMessageToNumberList(message)
        if status != "Success":
            return status
        list_message_rsa_encoded = [self.modular_exp(M, is_encoding=True) for M in list_message_numbers]
        return list_message_rsa_encoded
    
    def rsaDecoding(self, list_message_rsa_encoded):
        '''
        This method decodes the message using the private key

        Parameters :
            list_message_rsa_encoded : [int]
                The list of numbers that are the encoded message

        Returns :
            message : str
                The message that has been decrypted
        '''

        list_message_numbers = [self.modular_exp(M, is_encoding = False) for M in list_message_rsa_encoded]
        decoded_message, status = self.string_to_numbers_encoder.convertNumberListToStringMessage(list_message_numbers)
        if status != "Success":
            return status
        return decoded_message

    def modular_exp(self, message_number_block, is_encoding = True):
        '''
        This function uses the rsa keys with a modular expression to encrypt and decrypt a message block

        Parameters : 
            message_number_block : int
                A block of the message to be encrypted or decrypted
            is_encoding : Boolean, optional
                Whether the message is being encrypted of decrypted (Default is True, of Encrypting)
        '''

        if is_encoding:
            key_number = self.e
        else:
            key_number = self.d

        result = 1
        exp = message_number_block
        while key_number > 0:
            least_significant_bit = key_number % 2
            if least_significant_bit == 1:
                result = (result * exp) % self.n
            exp = (exp * exp) % self.n
            key_number = key_number // 2
        return result
if __name__ == '__main__':

    smaller_initial_prime = 1096341613
    larger_initial_prime = 4587343829
    rsa_crypto_scheme = Simple_RSACryptographyScheme(smaller_initial_prime, larger_initial_prime, block_size=5)

    print(f"Initial RSA Key Pair Generated With {smaller_initial_prime} and {larger_initial_prime} :")
    print(f'Public Key: {rsa_crypto_scheme.e, rsa_crypto_scheme.n}')
    print(f'Private Key: {rsa_crypto_scheme.d, rsa_crypto_scheme.n}')

    print("- - - - - - - - - - - -")

    original_message = 'This is a secret message'
    print(f'Original message : {original_message}')

    rsa_encrypted_message = rsa_crypto_scheme.rsaEncoding(original_message)
    print(f"Encrypted message with public key : {rsa_encrypted_message}")

    decoded_message = rsa_crypto_scheme.rsaDecoding(rsa_encrypted_message)
    print(f"Decrypted message with correct private key : {decoded_message}")
    assert original_message == decoded_message

    print("- - - - - - - - - - - -")

    smaller_second_prime = 2415707843
    larger_second_prime = 8300694107
    second_rsa_crypto_scheme = Simple_RSACryptographyScheme(smaller_second_prime, larger_second_prime)
    print(f"Second RSA Key Pair Generated With {smaller_second_prime} and {larger_second_prime} :")
    print(f'Public Key: {second_rsa_crypto_scheme.e, second_rsa_crypto_scheme.n}')
    print(f'Private Key: {second_rsa_crypto_scheme.d, second_rsa_crypto_scheme.n}')

    print("- - - - - - - - - - - -")

    decoded_message_wrong_key = second_rsa_crypto_scheme.rsaDecoding(rsa_encrypted_message)
    print(f"Decrypted message with wrong private key : {decoded_message_wrong_key}")
    assert original_message != decoded_message_wrong_key
    print("- - - - - - - - - - - -")

    second_message = 'And using the other key pairs around!'
    print(f'Second message : {second_message}')
    rsa_encrypted_second_message = second_rsa_crypto_scheme.rsaEncoding(second_message)
    print(f"Encrypted message with public key : {rsa_encrypted_second_message}")

    decoded_second_message = second_rsa_crypto_scheme.rsaDecoding(rsa_encrypted_second_message)
    print(f"Decrypted message with correct private key : {decoded_second_message}")
    assert second_message == decoded_second_message
    print("- - - - - - - - - - - -")

    decoded_second_message_wrong_key = rsa_crypto_scheme.rsaDecoding(rsa_encrypted_second_message)
    print(f"Decrypted message with wrong private key : {decoded_second_message_wrong_key}")
    assert second_message != decoded_second_message_wrong_key