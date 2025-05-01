from HelperFunctions.IntegerHandler import IntegerHandler
little_endian = False
bit_length = 2048

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
        return IntegerHandler(pow(base.getValue(), exponent.getValue(), modulus.getValue()), little_endian, bit_length)

    @staticmethod
    def RSA_EncryptionPrimitive(public_key:RSA_PublicKey, message_representative:IntegerHandler):
        '''
        This method implements the RSA Encription Primitive

        As laid out in section 5.1.1. "RSAEP" of IETF RFC 8017 https://datatracker.ietf.org/doc/html/rfc8017

        Parameters :
            public_key : RSA_PublicKey
                The RSA public key being used to encrypt the data
            message_representative : Integer_Handler
                The portion of the message currently bring encrypted as an integer smaller than the RSA modulus
        '''
        assert message_representative.value < public_key.n.value, "The message representative must be a smaller integer than the RSA modulus"
        return RSA.modularExponent(base=message_representative, exponent=public_key.e, modulus=public_key.n)
    
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
        return IntegerHandler(m, little_endian, bit_length)



handler = IntegerHandler.fromHexString("01FF",little_endian,16)
print(handler.getValue())
ct = "5662E1AF1E949E5F17A917FD586F7F50F4490632358F4801AA75E5AC8D9CD37ED69806EC1988DEEA48002044089068A86C09E5817BE4195D4FFB38FD7FE66038EE208EC017EB59DACA82164EEC98FCE3726493EDD4C19E64581DD77262A86C5E4E0DDD0573DA0CFFF7BA431A48727A276D9AA5EC45AF46CB25029A24EA51940D9C5FC067BF6A7E1750D89D1A8CC466F341C2C3F7B509BE0F759C6FF2F25DD794D5CFDEAF65BCE931925BF503BEBB6794F48D81C2E569DD7A0E2623A99C107346DC5CD6F4585B80C384A9619383CC3598450C0265A4B4F0ABC4370AE67F6DDBF3EE79D0F454ADA1F7F22676D615A1B2190DA316770361BFAD502AA1FA5273E9FC"
pt = "5E74D2E3598F0286DDCD79AC41A82F8477D91FE56542EC16F00633306FA5D65DCBE3E6C4AF76D7CABA4661982F3DDEEFA642BBE58290DFA2C0B6AB8E3153B7EB203E7F3A5EFFC4D0C4B842C138FD80443EFEAD6B1536FBFE509FE09F9AA67476B2CED84D9797ADC1CEAA15B2F69667533A9111A9BEDD0B2FE81FB13A14EF6B0907AE91B9252A6E7D61BCECF156FB0388ECE7363BC18F5C0735D129B8D08218654B25FDD67C91287172513CA23F6C71A72C65433884C352204FC8158A8931E5554206AE3BD954EF68227D1A829074ADEDA63D51FF0B9C2A5DF293BC77FC5A238822A41BEC6464AF283D166E7797E9039FCC22BA2B70D45169BDCB3AB70B585B45"
dmp1 = ""
dmq1 = ""
iqmp = ""
p = "BA90B7396D2D1E28A2ACB086FD05BEB308469F74D47879512DDB4A68C085FFD933DDCD1340A83FBF2CB321EDE49F8BD0B93E42029B96C488A4F8E2ADEC4ADCC49A942589D577F14B493B0A98001D4A108936B39D499A6E5966A38B32F489FB374C220B2EB015076CDB8C9C0AEF2A2B2F2BD636E78128E6A6C3D69EDDE4CDD7E7"
q =  "FB6E6185BF10B5981F76D2403190BB653049B86661B58774D2EAD2356FB843A8FBBC9729C2D1172C2B9803297CFF3853C2520B7BF725BA92982357D73CE03023A04E4069E37EB83BC4AF8B1B481F9729C10F16A0DBE3F73B267AA87B0DDCDCB7B44C491429F962D9F2E65FEE61E10D409F64B41898E56FE96269634557AB2225"
d = "153430AAC32B36E85584B0AFE9BDA8108043318A179D720E98042B245E9835B0F799D85D45EA46E9D179DA9F3DFB05D162B0DDF1F1CC75B388C7FAEED5A318B0BDFB583349FDEF88DB3B548DDF56C83AEBAACE65AA55119F0646BE765177BE148434A797C61F87570F9E9242248C5A1460D4F25FB6D83736DB0D695CCFB4AAD360CE844852468CEFC2E2952ABC86F879765B1E55034BF7861D8E75F6623B4DFEFF0ED1BB10BAC318D0FBEB51ED40A519BF49241391556392B7F14626318FB7CD18E9E8F65B9FE7839CD94B2FA933D4AFE115CE226334762A1544510386AACD4EFF9AA22BC53297C3907E9FDD93EA03BAEA8280EFB06DDC42810753DE6D35C7A5"
n = "B73C54E656923F3F184546C1FB00BC7E2C9DF9A95E4EDE9DA559F2BE1773C8B52159BD54A25B8142839FAF6D0E2F70130B9961C875D1EB2D99F36A1DFB72E05F46C9B83456BCEFA33A0A14DCD6CB34F32666B516F148858498CD52BE9804F5E7D5D3714629AB27F4102B7DC419A9A1BAA9B2A0990C15A368C028EC678FFF266D9F19FC61DFEBFE500AC3C5701B1291DDA1BE47F330BB11C1DD14BE6EE2C098EB934DB695A097449AE269D3878554026245325A872DE759F6ECAE043E80479E1A7EE6FF52F77FF5441BB7C09B03E01C62F1AD2530FC5D0AA02B9222080BF6242987D23267B7F7A486CBA254648D5B3DBF5D475BFE83FA2D1397D0BE9720B9E263"
e = "02DE387DD9"
expected_cipher = IntegerHandler.fromHexString(ct, little_endian, bit_length)
expected_plain = IntegerHandler.fromHexString(pt, little_endian, bit_length)
given_p = IntegerHandler.fromHexString(p, little_endian, bit_length)
given_q = IntegerHandler.fromHexString(q, little_endian, bit_length)
given_n = IntegerHandler.fromHexString(n, little_endian, bit_length)
given_e = IntegerHandler.fromHexString(e, little_endian, bit_length)
given_d = IntegerHandler.fromHexString(d, little_endian, bit_length)

public_key = RSA_PublicKey(given_n, given_e)
private_key = RSA_PrivateKey(given_n, given_d)
calculated_cipher = RSA.RSA_EncryptionPrimitive(public_key, expected_plain)
print(f"Expected Cipher : {expected_cipher.getHexString()}")
print()
print(f"Calculated Cipher : {calculated_cipher.getHexString()}")

assert expected_cipher.getHexString() == calculated_cipher.getHexString()

calculated_plain = RSA.RSA_DecryptionPrimitive(private_key, calculated_cipher)
print()
print(f"Expected Plain : {expected_plain.getHexString()}")
print()
print(f"Calculated Cipher : {calculated_plain.getHexString()}")

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