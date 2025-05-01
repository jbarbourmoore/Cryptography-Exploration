from HelperFunctions.IntegerHandler import IntegerHandler

class RSA_PrimeData():
    def __init__(self, prime_factor:IntegerHandler, crt_exponent:IntegerHandler, crt_coefficient:IntegerHandler):
        '''
        This method initializes an additional prime data point

        Parameters :
            prime_factor : IntegerHandler
                The prime factor for the additional prime data
            crt_exponent : IntegerHandler
                The exponent for the additional prime data
            crt_coefficient : IntegerHandler
                The coefficient for the additional prime data
        '''
        self.r_i = prime_factor
        self.d_i = crt_exponent
        self.t_i = crt_coefficient

class RSA_PublicKey():
    def __init__(self, modulus:IntegerHandler, exponent:IntegerHandler):
        '''
        This method initializes an rsa public key

        As laid out in section 3.1 "RSA Public Key" of IETF RFC 8017 https://datatracker.ietf.org/doc/html/rfc8017

        Parameters :
            modulus : IntegerHandler
                The n value for the RSA public key as an IntegerHandler
            exponent : IntegerHandler
                The e value for the RSA public key as an IntegerHandler
        '''
        self.n = modulus
        self.e = exponent

class RSA_PrivateKey():
    def __init__(self, modulus:IntegerHandler, exponent:IntegerHandler):
        '''
        This method initializes an rsa private key

        As laid out in section 3.2 "RSA Private Key" of IETF RFC 8017 https://datatracker.ietf.org/doc/html/rfc8017

        Parameters :
            modulus : IntegerHandler
                The n value for the RSA private key as an IntegerHandler
            exponent : IntegerHandler
                The d value for the RSA private key as an IntegerHandler
        '''
        self.n = modulus
        self.d = exponent

class RSA_PrivateKey_QuintupleForm():
    def __init__(self, p:IntegerHandler, q:IntegerHandler, dP:IntegerHandler, dQ:IntegerHandler, qInv:IntegerHandler, additional_prime_data:list[RSA_PrimeData]):
        '''
        This method initializes an rsa private key in quintuple form

        As laid out in section 3.2 "RSA Private Key" of IETF RFC 8017 https://datatracker.ietf.org/doc/html/rfc8017

        Parameters :
            p : IntegerHandler
                The p value for the RSA private key as an IntegerHandler
            q : IntegerHandler
                The q value for the RSA private key as an IntegerHandler
            dP : IntegerHandler
                The dP value for the RSA private key as an IntegerHandler
            dQ : IntegerHandler
                The dQ value for the RSA private key as an IntegerHandler
            qInv : IntegerHandler
                The qInv value for the RSA private key as an IntegerHandler
            additional_prime_data : [RSA_Prime_Data]
                The additional_prime_data value for the RSA private key as a list of RSA_Prime_Data
        '''
        self.p = p
        self.q = q
        self.dP = dP
        self.dQ = dQ
        self.qInv = qInv
        self.u = 2 + len(additional_prime_data)
        self.additional_prime_data = additional_prime_data



class RSA():

    @staticmethod
    def modularExponent(base:IntegerHandler, exponent:IntegerHandler, modulus:IntegerHandler):
        '''
        This method provides modular exponent for the rsa implementation

        '''
        return pow(base.getValue(), exponent.getValue(), modulus.getValue())

    @staticmethod
    def RSA_EncryptionPrimitive(public_key:RSA_PublicKey, message_representative:IntegerHandler):
        '''
        This method implements the RSA Encription Primitive

        As laid out in section 5.1.1. "RSAEP" of IETF RFC 8017 https://datatracker.ietf.org/doc/html/rfc8017
        '''
        assert message_representative.value < public_key.n.value, "The message representative must be a smaller integer than the RSA modulus"
        return IntegerHandler(RSA.modularExponent(base=message_representative, exponent=public_key.e, modulus=public_key.n))
    
    @staticmethod
    def RSA_DecryptionPrimitive(private_key:RSA_PrivateKey | RSA_PrivateKey_QuintupleForm, cipher_text_representative:IntegerHandler):
        '''
        This method implements the RSA Encription Primitive

        As laid out in section 5.1.2. "RSADP" of IETF RFC 8017 https://datatracker.ietf.org/doc/html/rfc8017

        Parameters :
            private_key : RSA_PrivateKey or RSA_PrivateKey_QuintupleForm
                The private key for the decryption
            cipher_text_representative : IntegerHandler
                The cipher text representative as an IntegerHandler

        Returns :
            message_representative : IntegerHandler
                The message representative as an IntegerHandler
        '''
        if type(private_key) == RSA_PrivateKey:
            return RSA.modularExponent(base=cipher_text_representative, exponent=private_key.d, modulus=private_key.n)
        
        m_i:list[IntegerHandler] = []
        m_i.append(RSA.modularExponent( base=cipher_text_representative, exponent=private_key.dP, modulus=private_key.p))
        m_i.append(RSA.modularExponent( base=cipher_text_representative, exponent=private_key.dQ, modulus=private_key.q))
        for i in range(0, private_key.u - 1):
            m_i.append(RSA.modularExponent(base=cipher_text_representative, exponent=private_key.additional_prime_data[i].d_i, modulus=private_key.additional_prime_data[i].r_i))

        h = (m_i[0].getValue() - m_i[1].getValue()) * private_key.qInv.getValue() % private_key.p.getValue()
        m = m_i[1].getValue() + private_key.q.getValue() * h
        if private_key.u > 2:
            R = private_key.p.getValue() * private_key.q.getValue()
            h = ( m_i[2].getValue() - m ) * private_key.additional_prime_data[0].t_i.getValue() % private_key.additional_prime_data[0].r_i.getValue()
            m = m + R * h
            for i in range(2, private_key.u):
                R = R * private_key.additional_prime_data[i - 2].r_i.getValue()
                h = ( m_i[i] - m ) * private_key.additional_prime_data[i - 1].t_i.getValue() % private_key.additional_prime_data[i - 1].r_i.getValue()
                m = m + R * h
        return IntegerHandler(m, False, private_key.p.bit_length)



handler = IntegerHandler.fromHexString("01FF",True,16)
print(handler.getValue())

# from HelperFunctions.EuclidsAlgorithms import extendedEuclidAlgorithm
# from HelperFunctions.EncodeStringAsNumberList import EncodeStringAsNumbersList

# class RSACryptographyScheme():
#     '''
#     This class contains an implementation along the lines of the RSA Cryptography Scheme

#     Given two large prime numbers it generates 3 numbers => n, e and d
    
#     The public key consists of n and e 
#     While the private key consists of n and d

#     Messages must first be converted into a list of numbers
#     Then each number can be encrypted using the public key
#     This can then be decrypted using the private key
#     And converted back to a string

#     encrypt => (M, (e, n)) = M**e % n
#     decrypt => (M, (d, n)) = M**d % n
#     '''

#     def __init__(self, smaller_large_prime, larger_prime, number_system_base = 214, block_size = 5):
#         '''
#         This method initializes the RSACryptographyScheme

#         Parameters :
#             smaller_large_prime : int
#                 The smaller of the two large primes to generate the rsa keys
#             larger_prime : int
#                 The larger of the two large primes to generate the rsa keys
#             number_system_base : int, optional
#                 The number system base to use when converting the message to a list of numbers (default is 214)
#             block_size : int, optional
#                 The number of characters in each block when encoded (default is five)
#         '''

#         self.smaller_large_prime = smaller_large_prime
#         self.larger_prime = larger_prime
#         self.string_to_numbers_encoder = EncodeStringAsNumbersList(number_system_base=number_system_base, block_size=block_size)
#         self.number_system_base = number_system_base
#         self.block_size = block_size

#         self.generateRSAKeys()

#     def generateRSAKeys(self):
#         '''
#         This method generates the RSA keys using the extended form of euclid's algorithm
#         '''

#         n = self.smaller_large_prime * self.larger_prime
#         phi = ( self.smaller_large_prime - 1 ) * ( self.larger_prime - 1 )
#         e = None
#         d = None
#         for e in range( self.smaller_large_prime//3, self.smaller_large_prime ):
#             i, _, t = extendedEuclidAlgorithm(phi, e)
#             if i == 1:
#                 if t < 0:
#                     d = phi + t
#                 else:
#                     d = t
#                 break
#         self.n = n
#         self.d = d
#         self.e = e

#     def getPublicKey(self):
#         '''
#         This method returns the public key components as a tuple
#         '''

#         return (self.e,self.n)
    
#     def getPrivateKey(self):
#         '''
#         This method returns the private key components as a tuple
#         '''
        
#         return (self.d,self.n)

#     def rsaEncoding(self, message):
#         '''
#         This method encodes the message using the public key

#         Parameters :
#             message : str
#                 The message to be encrypted

#         Returns :
#             list_message_rsa_encoded : [int]
#                 The list of numbers that are the encoded message
#         '''

#         list_message_numbers, status = self.string_to_numbers_encoder.convertStringMessageToNumberList(message)
#         if status != "Success":
#             return status
#         list_message_rsa_encoded = [self.modular_exp(M, is_encoding=True) for M in list_message_numbers]
#         return list_message_rsa_encoded
    
#     def rsaDecoding(self, list_message_rsa_encoded):
#         '''
#         This method decodes the message using the private key

#         Parameters :
#             list_message_rsa_encoded : [int]
#                 The list of numbers that are the encoded message

#         Returns :
#             message : str
#                 The message that has been decrypted
#         '''

#         list_message_numbers = [self.modular_exp(M, is_encoding = False) for M in list_message_rsa_encoded]
#         decoded_message, status = self.string_to_numbers_encoder.convertNumberListToStringMessage(list_message_numbers)
#         if status != "Success":
#             return status
#         return decoded_message

#     def modular_exp(self, message_number_block, is_encoding = True):
#         '''
#         This function uses the rsa keys with a modular expression to encrypt and decrypt a message block

#         Parameters : 
#             message_number_block : int
#                 A block of the message to be encrypted or decrypted
#             is_encoding : Boolean, optional
#                 Whether the message is being encrypted of decrypted (Default is True, of Encrypting)
#         '''

#         if is_encoding:
#             key_number = self.e
#         else:
#             key_number = self.d

#         result = 1
#         exp = message_number_block
#         while key_number > 0:
#             least_significant_bit = key_number % 2
#             if least_significant_bit == 1:
#                 result = (result * exp) % self.n
#             exp = (exp * exp) % self.n
#             key_number = key_number // 2
#         return result
# if __name__ == '__main__':

#     smaller_initial_prime = 1096341613
#     larger_initial_prime = 4587343829
#     rsa_crypto_scheme = RSACryptographyScheme(smaller_initial_prime, larger_initial_prime, block_size=5)

#     print(f"Initial RSA Key Pair Generated With {smaller_initial_prime} and {larger_initial_prime} :")
#     print(f'Public Key: {rsa_crypto_scheme.e, rsa_crypto_scheme.n}')
#     print(f'Private Key: {rsa_crypto_scheme.d, rsa_crypto_scheme.n}')

#     print("- - - - - - - - - - - -")

#     original_message = 'This is a secret message'
#     print(f'Original message : {original_message}')

#     rsa_encrypted_message = rsa_crypto_scheme.rsaEncoding(original_message)
#     print(f"Encrypted message with public key : {rsa_encrypted_message}")

#     decoded_message = rsa_crypto_scheme.rsaDecoding(rsa_encrypted_message)
#     print(f"Decrypted message with correct private key : {decoded_message}")
#     assert original_message == decoded_message

#     print("- - - - - - - - - - - -")

#     smaller_second_prime = 2415707843
#     larger_second_prime = 8300694107
#     second_rsa_crypto_scheme = RSACryptographyScheme(smaller_second_prime, larger_second_prime)
#     print(f"Second RSA Key Pair Generated With {smaller_second_prime} and {larger_second_prime} :")
#     print(f'Public Key: {second_rsa_crypto_scheme.e, second_rsa_crypto_scheme.n}')
#     print(f'Private Key: {second_rsa_crypto_scheme.d, second_rsa_crypto_scheme.n}')

#     print("- - - - - - - - - - - -")

#     decoded_message_wrong_key = second_rsa_crypto_scheme.rsaDecoding(rsa_encrypted_message)
#     print(f"Decrypted message with wrong private key : {decoded_message_wrong_key}")
#     assert original_message != decoded_message_wrong_key
#     print("- - - - - - - - - - - -")

#     second_message = 'And using the other key pairs around!'
#     print(f'Second message : {second_message}')
#     rsa_encrypted_second_message = second_rsa_crypto_scheme.rsaEncoding(second_message)
#     print(f"Encrypted message with public key : {rsa_encrypted_second_message}")

#     decoded_second_message = second_rsa_crypto_scheme.rsaDecoding(rsa_encrypted_second_message)
#     print(f"Decrypted message with correct private key : {decoded_second_message}")
#     assert second_message == decoded_second_message
#     print("- - - - - - - - - - - -")

#     decoded_second_message_wrong_key = rsa_crypto_scheme.rsaDecoding(rsa_encrypted_second_message)
#     print(f"Decrypted message with wrong private key : {decoded_second_message_wrong_key}")
#     assert second_message != decoded_second_message_wrong_key