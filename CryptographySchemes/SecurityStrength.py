from enum import Enum

class SecurityStrengthDetails():
    def __init__(self, security_strength:int, integer_factorization_cryptography:int, symmetric_key_algorithm:str, finite_field_cryptography:tuple[int,int], elliptic_curve_cryptography:int):
        '''
        Parameters :
            security_strength : int
                The desired security strength
            integer_factorization_cryptography : int
                The value k for use with RSA cryptography and other integer factoriration based cryptography
            symmetric_key_algorithm : str
                The name of the symmetric key algorithm that provides the desired security strength
            finite_field_cryptography : (int, int)
                The values for finite field cryptography such as DH, DSA, MQV as a tuple(L,N)
            elliptic_curve_cryptography : int
                The minimum curve strength required
        '''
        
        self.security_strength = security_strength
        self.integer_factorization_cryptography = integer_factorization_cryptography
        self.symmetric_key_algotithm = symmetric_key_algorithm
        self.finite_field_cryptography = finite_field_cryptography
        self.elliptic_curve_cryptography = elliptic_curve_cryptography

class SecurityStrength(Enum):
    '''
    The security strengths for various cryptography types

    According to Table 2: "Comparable security strengths of symmetric block cipher and asymmetric-key algorithms" from NIST SP 800-56pt1r5
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
    '''
    s80 = SecurityStrengthDetails(80, 1024, "2 key tdes", (1024,160), 160)
    s112 = SecurityStrengthDetails(112, 2048, "3 key tdes", (2048,224), 224)
    s128 = SecurityStrengthDetails(128, 3072, "aes-128", (3072,256), 256)
    s192 = SecurityStrengthDetails(192, 7680, "aes-192", (7680,386), 386)
    s256 = SecurityStrengthDetails(256, 15360, "aes-256", (15360, 512), 512)