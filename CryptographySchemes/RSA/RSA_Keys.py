from HelperFunctions.IntegerHandler import IntegerHandler, bitwiseXor
little_endian = False
from secrets import randbits, randbelow
from math import ceil, floor, sqrt
from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm3 import *
from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm2 import *
from CryptographySchemes.HashingAlgorithms.ApprovedHashFunctions import *
from HelperFunctions.EuclidsAlgorithms import euclidsAlgorithm
from HelperFunctions.PrimeNumbers import *
from CryptographySchemes.SecurityStrength import SecurityStrength
from decimal import Decimal
from enum import IntEnum

'''
    Security Strength - RSA k
    <80 - 1024
    112 - 2048
    128 - 3072
    192 - 7680
    256 - 15360
'''
class RSA_PrivateKey_Type(IntEnum):
    Standard = 0
    Quint = 1

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
        self.type = RSA_PrivateKey_Type.Standard
        self.p, self.q, self.dP, self.dQ, self.qInv, self.u, self.additional_prime_data = None, None, None, None, None, None, None

class RSA_PrivateKey_QuintupleForm(RSA_PrivateKey):
    def __init__(self, modulus:IntegerHandler, exponent:IntegerHandler, p:IntegerHandler, q:IntegerHandler, dP:IntegerHandler, dQ:IntegerHandler, qInv:IntegerHandler, additional_prime_data:list[RSA_PrimeData]):
        '''
        This method initializes an rsa private key in quintuple form

        As laid out in section 3.2 "RSA Private Key" of IETF RFC 8017 https://datatracker.ietf.org/doc/html/rfc8017

        Parameters :
            modulus : IntegerHandler
                The n value for the RSA private key as an IntegerHandler
            exponent : IntegerHandler
                The d value for the RSA private key as an IntegerHandler
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
        super().__init__(modulus, exponent)
        self.p = p
        self.q = q
        self.dP = dP
        self.dQ = dQ
        self.qInv = qInv
        self.u = 2 + len(additional_prime_data)
        self.additional_prime_data = additional_prime_data
        self.type = RSA_PrivateKey_Type.Quint

class RSA_KeyGeneration():

    @staticmethod
    def generateRSAKeyPair_ProbablePrimes(security_strength: int = SecurityStrength.s112.value.security_strength, private_key_type:int = RSA_PrivateKey_Type.Standard.value, is_debug:bool = False)-> tuple[RSA_PublicKey, RSA_PrivateKey]:
        '''
        This method generates an RSA key pair of the requented security strength

        Parameters : 
            security_strength : int, optional
                The requested security strength for the RSA Key Pair, default is security strength 112
            private_key_type : int, optional
                The private key type to return, default is Standard
            is_debug : bool, optional
                Whether the method is being debugged and should output extra information, default is false

        Returns :
            public_key : RSA_PublicKey
                The public key in the key pair
            private_key : RSA_PrivateKey
                The private key in the key pair
        '''
        
        nlen = RSA_KeyGeneration._getNLength(security_strength)
        if nlen == None:
            print("Desired security strength must be 112, 128, 192 or 256")
            return None, None
        
        gcd_e_phi_1 = False
        while not gcd_e_phi_1:
            e = RSA_KeyGeneration._generateRandomPublicKeyExponent()
            success, p, q = RSA_KeyGeneration._generatePairOfPrimes_Probable(nlen, e)                   
            if success: 
                    n, public_key, gcd_e_phi_1 = RSA_KeyGeneration._calculatePublicKey(e, p, q, gcd_e_phi_1)

        d = RSA_KeyGeneration._calculatePrivateKeyExponent(e, p, q)

        if private_key_type == RSA_PrivateKey_Type.Standard:
            private_key = RSA_PrivateKey(n, d)
        else:
            private_key = RSA_KeyGeneration.generatePrivateKey_QuintForm(n, d, p, q)

        if is_debug: 
            print("RSA Key Pair Using Probable Primes Has Been Generated")
            RSA_KeyGeneration._outputKeyDetails(private_key_type, p, q, public_key, private_key)

        return public_key, private_key
    
    @staticmethod
    def generateRSAKeyPair_ProbablePrimes_AuxillaryProvablePrimes(bitlens:list[int] = None, security_strength: int = SecurityStrength.s112.value.security_strength, private_key_type:int = RSA_PrivateKey_Type.Standard.value, hash_function:ApprovedHashFunction = ApprovedHashFunctions.SHA_512_Hash.value, a:int = None, b:int = None, is_debug:bool = False)-> tuple[RSA_PublicKey, RSA_PrivateKey]:
        '''
        This method generates an RSA key pair of the requented security strength

        Parameters : 
            security_strength : int, optional
                The requested security strength for the RSA Key Pair, default is security strength 112
            private_key_type : int, optional
                The private key type to return, default is Standard
            is_debug : bool, optional
                Whether the method is being debugged and should output extra information, default is false

        Returns :
            public_key : RSA_PublicKey
                The public key in the key pair
            private_key : RSA_PrivateKey
                The private key in the key pair
        '''
        
        nlen = RSA_KeyGeneration._getNLength(security_strength)
        if nlen == None:
            print("Desired security strength must be 112, 128, 192 or 256")
            return None, None
        
        if nlen <= 3071:
            min_bitlens = 140
            max_bitlens = 1007
        elif nlen <= 4095:
            min_bitlens = 170
            max_bitlens = 1518
        else:
            min_bitlens = 200
            max_bitlens = 2030
        
        if bitlens == None:
            bitlen = (max_bitlens // 2 - min_bitlens) // 2 + min_bitlens
            bitlens = [bitlen, bitlen, bitlen, bitlen]
        else:
            for bitlen in bitlens:
                if bitlen < min_bitlens:
                    print(f"Bitlen {bitlen} is below minimum bitlen {min_bitlens}")
                    return None, None
            if bitlens[0] + bitlens[1] > max_bitlens or bitlens[2] + bitlens[3] > max_bitlens:
                print("At least one bitlens pair is above max bitlens")
                return None, None
        
        gcd_e_phi_1 = False
        while not gcd_e_phi_1:
            e = RSA_KeyGeneration._generateRandomPublicKeyExponent()
            success, seed = RSA_KeyGeneration._generateSeed(nlen)
            if success: 
                success, p, q = RSA_KeyGeneration._generatePairOfPrimes_Probable_AuxillaryProvablePrimes(nlen, e, seed, bitlens, a, b, hash_function)                   
                if success: 
                        n, public_key, gcd_e_phi_1 = RSA_KeyGeneration._calculatePublicKey(e, p, q, gcd_e_phi_1)

        d = RSA_KeyGeneration._calculatePrivateKeyExponent(e, p, q)

        if private_key_type == RSA_PrivateKey_Type.Standard:
            private_key = RSA_PrivateKey(n, d)
        else:
            private_key = RSA_KeyGeneration.generatePrivateKey_QuintForm(n, d, p, q)

        if is_debug: 
            print("RSA Key Pair Using Probable Primes With Provable Auxillary Primes Has Been Generated")
            RSA_KeyGeneration._outputKeyDetails(private_key_type, p, q, public_key, private_key)

        return public_key, private_key
    
    @staticmethod
    def generateRSAKeyPair_ProbablePrimes_AuxillaryProbablePrimes(bitlens:list[int] = None, security_strength: int = SecurityStrength.s112.value.security_strength, private_key_type:int = RSA_PrivateKey_Type.Standard.value, hash_function:ApprovedHashFunction = ApprovedHashFunctions.SHA_512_Hash.value, a:int = None, b:int = None, is_debug:bool = False)-> tuple[RSA_PublicKey, RSA_PrivateKey]:
        '''
        This method generates an RSA key pair of the requented security strength

        Parameters : 
            security_strength : int, optional
                The requested security strength for the RSA Key Pair, default is security strength 112
            private_key_type : int, optional
                The private key type to return, default is Standard
            is_debug : bool, optional
                Whether the method is being debugged and should output extra information, default is false

        Returns :
            public_key : RSA_PublicKey
                The public key in the key pair
            private_key : RSA_PrivateKey
                The private key in the key pair
        '''
        
        nlen = RSA_KeyGeneration._getNLength(security_strength)
        if nlen == None:
            print("Desired security strength must be 112, 128, 192 or 256")
            return None, None
        
        if nlen <= 3071:
            min_bitlens = 140
            max_bitlens = 1007
        elif nlen <= 4095:
            min_bitlens = 170
            max_bitlens = 1518
        else:
            min_bitlens = 200
            max_bitlens = 2030
        
        if bitlens == None:
            bitlen = (max_bitlens // 2 - min_bitlens) // 2 + min_bitlens
            bitlens = [bitlen, bitlen, bitlen, bitlen]
        else:
            for bitlen in bitlens:
                if bitlen < min_bitlens:
                    print(f"Bitlen {bitlen} is below minimum bitlen {min_bitlens}")
                    return None, None
            if bitlens[0] + bitlens[1] > max_bitlens or bitlens[2] + bitlens[3] > max_bitlens:
                print("At least one bitlens pair is above max bitlens")
                return None, None
        
        gcd_e_phi_1 = False
        while not gcd_e_phi_1:
            e = RSA_KeyGeneration._generateRandomPublicKeyExponent()
        
            success, p, q = RSA_KeyGeneration._generatePairOfPrimes_Probable_AuxillaryProbablePrimes(nlen, e, bitlens, a, b)                   
            if success: 
                    n, public_key, gcd_e_phi_1 = RSA_KeyGeneration._calculatePublicKey(e, p, q, gcd_e_phi_1)

        d = RSA_KeyGeneration._calculatePrivateKeyExponent(e, p, q)

        if private_key_type == RSA_PrivateKey_Type.Standard:
            private_key = RSA_PrivateKey(n, d)
        else:
            private_key = RSA_KeyGeneration.generatePrivateKey_QuintForm(n, d, p, q)

        if is_debug: 
            print("RSA Key Pair Using Probable Primes With Probable Auxillary Primes Has Been Generated")
            RSA_KeyGeneration._outputKeyDetails(private_key_type, p, q, public_key, private_key)

        return public_key, private_key

    @staticmethod
    def generateRSAKeyPair_ProvablePrimes(security_strength: int = SecurityStrength.s112.value.security_strength, hash_function:ApprovedHashFunction = ApprovedHashFunctions.SHA_512_Hash.value, private_key_type:int = RSA_PrivateKey_Type.Standard.value, is_debug:bool = False)-> tuple[RSA_PublicKey, RSA_PrivateKey]:
        '''
        This method generates an RSA key pair of the requented security strength

        Parameters : 
            security_strength : int, optional
                The requested security strength for the RSA Key Pair, default is 112
            hash_function : ApprovedHashFunction, optional
                The approved hashfunction to be used while generating the key pair, default is SHA 512
            private_key_type : int, optional
                The private key type to return, default is Standard
            is_debug : bool, optional
                Whether the method is being debugged and should output extra information, default is false

        Returns :
            public_key : RSA_PublicKey
                The public key in the key pair
            private_key : RSA_PrivateKey
                The private key in the key pair
        '''

        nlen = RSA_KeyGeneration._getNLength(security_strength)
        if nlen == None:
            print("Desired security strength must be 112, 128, 192 or 256")
            return None, None
        
        gcd_e_phi_1 = False
        while not gcd_e_phi_1:
            e = RSA_KeyGeneration._generateRandomPublicKeyExponent()
            success, seed = RSA_KeyGeneration._generateSeed(nlen)
            if success: 
                success, p, q = RSA_KeyGeneration._generatePairOfPrimes_Provable(nlen, e, seed,hash_function)
                if success:
                    n, public_key, gcd_e_phi_1 = RSA_KeyGeneration._calculatePublicKey(e, p, q, gcd_e_phi_1)

        d = RSA_KeyGeneration._calculatePrivateKeyExponent(e, p, q)

        if private_key_type == RSA_PrivateKey_Type.Standard:
            private_key = RSA_PrivateKey(n, d)
        else:
            private_key = RSA_KeyGeneration.generatePrivateKey_QuintForm(n, d, p, q)

        if is_debug: 
            print("RSA Key Pair Using Provable Primes Has Been Generated")
            RSA_KeyGeneration._outputKeyDetails(private_key_type, p, q, public_key, private_key)
        return public_key, private_key
    
    @staticmethod
    def generateRSAKeyPair_ProvablePrimes_AuxillaryPrimes(bitlens:list[int] = None, security_strength: int = SecurityStrength.s112.value.security_strength, hash_function:ApprovedHashFunction = ApprovedHashFunctions.SHA_512_Hash.value, private_key_type:int = RSA_PrivateKey_Type.Standard.value, is_debug:bool = False)-> tuple[RSA_PublicKey, RSA_PrivateKey]:
        '''
        This method generates an RSA key pair of the requented security strength

        Parameters : 
            security_strength : int, optional
                The requested security strength for the RSA Key Pair, default is 112
            hash_function : ApprovedHashFunction, optional
                The approved hashfunction to be used while generating the key pair, default is SHA 512
            private_key_type : int, optional
                The private key type to return, default is Standard
            is_debug : bool, optional
                Whether the method is being debugged and should output extra information, default is false

        Returns :
            public_key : RSA_PublicKey
                The public key in the key pair
            private_key : RSA_PrivateKey
                The private key in the key pair
        '''

        nlen = RSA_KeyGeneration._getNLength(security_strength)
        if nlen == None:
            print("Desired security strength must be 112, 128, 192 or 256")
            return None, None
        
        if nlen <= 3071:
            min_bitlens = 140
            max_bitlens = 494
        elif nlen <= 4095:
            min_bitlens = 170
            max_bitlens = 750
        else:
            min_bitlens = 200
            max_bitlens = 1005
        
        if bitlens == None:
            bitlen = (max_bitlens // 2 - min_bitlens) // 2 + min_bitlens
            bitlens = [bitlen, bitlen, bitlen, bitlen]
        else:
            for bitlen in bitlens:
                if bitlen < min_bitlens:
                    print(f"Bitlen {bitlen} is below minimum bitlen {min_bitlens}")
                    return None, None
            if bitlens[0] + bitlens[1] > max_bitlens or bitlens[2] + bitlens[3] > max_bitlens:
                print("At least one bitlens pair is above max bitlens")
                return None, None
        
        gcd_e_phi_1 = False
        while not gcd_e_phi_1:
            e = RSA_KeyGeneration._generateRandomPublicKeyExponent()
            success, seed = RSA_KeyGeneration._generateSeed(nlen)
            if success: 
                success, p, q = RSA_KeyGeneration._generatePairOfPrimes_Probable_AuxillaryProvablePrimes(nlen, e, seed, bitlens, hash_function)
                if success:
                    n, public_key, gcd_e_phi_1 = RSA_KeyGeneration._calculatePublicKey(e, p, q, gcd_e_phi_1)

        d = RSA_KeyGeneration._calculatePrivateKeyExponent(e, p, q)

        if private_key_type == RSA_PrivateKey_Type.Standard:
            private_key = RSA_PrivateKey(n, d)
        else:
            private_key = RSA_KeyGeneration.generatePrivateKey_QuintForm(n, d, p, q)

        if is_debug: 
            print("RSA Key Pair Using Provable Primes With Auxillary Primes Has Been Generated")
            RSA_KeyGeneration._outputKeyDetails(private_key_type, p, q, public_key, private_key)
        return public_key, private_key
    
    @staticmethod
    def _outputKeyDetails(private_key_type:int, p:IntegerHandler, q:IntegerHandler, public_key:RSA_PublicKey, private_key:RSA_PrivateKey):
        '''
        This method outputs the details of the generated key

        Parameters : 
            private_key_type : int
                The n value for the private key
            p : IntegerHandler
                The first prime being used in the RSA key pair
            q : IntegerHandler
                The second prime being used in the RSA key pair
            public_key : RSA_PublicKey
                The public key that was generated
            private_key : RSA_PrivateKey
                The private key that was generated
        '''
        
        print(f"n : {public_key.n.getHexString()}")
        print(f"e : {public_key.e.getHexString()}")
        print(f"d : {private_key.d.getHexString()}")
        print(f"p : {p.getHexString()}")
        print(f"q : {q.getHexString()}")
        if private_key_type == RSA_PrivateKey_Type.Quint:
            print(f"dP   : {private_key.dP.getHexString() if private_key.dP != None else "None"}")
            print(f"dQ   : {private_key.dQ.getHexString() if private_key.dQ != None else "None"}")
            print(f"qInv : {private_key.qInv.getHexString() if private_key.qInv != None else "None"}")
    
    @staticmethod
    def generatePrivateKey_QuintForm(n:IntegerHandler, d:IntegerHandler, p:IntegerHandler, q:IntegerHandler) -> RSA_PrivateKey_QuintupleForm:
        '''
        This method generates the qunituple form of the private key

        (Used with chinese remainder theorem in order to increase efficiency when decrypting)

        Parameters : 
            n : IntegerHandler
                The n value for the private key
            d : IntegerHandler 
                The d value for the private key
            p : IntegerHandler
                The first prime being used in the RSA key pair
            q : IntegerHandler
                The second prime being used in the RSA key pai

        Returns :
            private_key : RSA_PrivateKey_QuintupleForm
                The RSA private key in quintuple form
        '''
        dP = d.getValue() % (p.getValue() - 1)
        dQ = d.getValue() % (q.getValue() - 1)
        qInv = calculateModuloInverse(q.getValue(), p.getValue())
        dP = IntegerHandler(dP, little_endian)
        dQ = IntegerHandler(dQ, little_endian)
        qInv = IntegerHandler(qInv, little_endian)

        return RSA_PrivateKey_QuintupleForm(n,d,p,q,dP,dQ,qInv,[])
    
    @staticmethod
    def _generateSeed(nlen:int):
        '''
        This method returns a random seed with twice the number of bits as the security strength indicated by nlen

        From NIST FIPS 186-5 Section A.1.2.1 "Get the Seed" 
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

        Parameters :
            nlen : int
                The desired length of the n modulus
        
        Returns :
            success_or_failure : bool
                True, if successful creating the seed value
            seed : IntegerHandler 
                The seed value as an IntegerHandler with 2 * the security strength bits
        '''

        security_strength = RSA_KeyGeneration._getSecurityStrength(nlen)
        if security_strength == None:
            return False, IntegerHandler(0, little_endian, 0)
        
        seed = randbits(security_strength * 2)
        return True, IntegerHandler(seed, little_endian, security_strength * 2)

    @staticmethod
    def _getSecurityStrength(nlen):
        '''
        This method gets the security strength that corresponds to a given nlen

        Parameters :
            nlen : int
                The nlen for the RSA implementation
        
        Returns : 
            security_strength : int or None
                The security strength that corresponds to the given nlen as an int
        '''
        security_strength = None
        for strength in SecurityStrength:
            if strength.value.integer_factorization_cryptography == nlen:
                security_strength = strength.value.security_strength
        return security_strength

    @staticmethod
    def _generatePairOfPrimes_Probable(nlen:int, e:IntegerHandler, a:int = None, b:int = None) -> tuple[bool, IntegerHandler, IntegerHandler]:
        '''
        This method generates 2 probable primes for use in an RSA scheme based
        
        From NIST FIPS 186-5 Section A.1.3 "Generation of Random Primes that are Probably Prime"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

        Parameters :
            nlen : int
                The desired bit length for the n value in the implementation (at least 2048)
            e : IntegerHandler
                The e public exponent for the rsa key pair as an IntegerHandler
            a : int, optional
                The desired mod 8 value for p, default is none
            b : int, optional
                The desired mod 8 value for q, default is none

        Returns : 
            is_success : bool
                Whether the prime generation was successful
            p, q : IntegerHandlers
                The generated primes as IntegerHandlers
        '''
        
        if nlen < 2048:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        elif e.getValue() <= pow(2, 16) or e.getValue() >= pow(2, 256) or (e.getValue() % 2) == 0:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)

        # generate p
        p, p_probably_prime = 0, False
        i = 0
        p_q_test_iterations = 4
        sq2 = Decimal.from_float(sqrt(2))
        sq2_2toL = floor(sq2 * (pow(2, (nlen // 2) - 1)))
        while not p_probably_prime:
            while p < sq2_2toL:
                p = randbits(nlen // 2)
                if a != None:
                    p = p + (a - p) % 8
                elif p % 2 == 0:
                    p = p + 1

            if euclidsAlgorithm(p-1, e.getValue()) == 1:
                p_probably_prime = runMillerRabinPrimalityTest(p, p_q_test_iterations) and runLucasPrimalityTest(p)
                if p_probably_prime:
                    print(p)
                    break
            i = i + i
            p = 0
            if i > 5 * nlen:
                return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        
        # generate q
        q, q_probably_prime = 0, False
        i = 0
        sq2 = Decimal.from_float(sqrt(2))
        sq2_2toL = floor(sq2 * (pow(2, (nlen // 2) - 1)))
        while not q_probably_prime:
            while q < sq2_2toL:
                q = randbits(nlen // 2)
                if b != None:
                    q = q + (b - q) % 8
                elif q % 2 == 0:
                    q = q + 1

            if euclidsAlgorithm(q-1, e.getValue()) == 1:
                q_probably_prime = runMillerRabinPrimalityTest(q, p_q_test_iterations) and runLucasPrimalityTest(q)
                if q_probably_prime and p_probably_prime:
                    print(q)
                    return True, IntegerHandler(p, little_endian, nlen // 2), IntegerHandler(q, little_endian, nlen // 2)
            i = i + i
            q = 0
            if i > 5 * nlen:
                return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
    
    @staticmethod
    def _generatePairOfPrimes_Probable_AuxillaryProvablePrimes(nlen:int, e:IntegerHandler, seed: IntegerHandler, bitlens:list[int], a:int = None, b:int = None, hash_function = ApprovedHashFunctions.SHA_512_Hash.value) -> tuple[bool, IntegerHandler, IntegerHandler]:
        '''
        This method generates 2 probable primes for use in an RSA scheme based
        
        From NIST FIPS 186-5 Section A.1.5 "Generation of Probable Primes with Conditions Based on Auxiliary Provable Primes"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

        Parameters :
            nlen : int
                The desired bit length for the n value in the implementation (at least 2048)
            e : IntegerHandler
                The e public exponent for the rsa key pair as an IntegerHandler
            seed : IntegerHandler
                The seed to be used in calculating the auxillary provable primes
            bitlens : [int]
                The list of 4 bit lengths for p_1, p_2, q_1 and q_2
            a : int, optional
                The desired mod 8 value for p, default is none
            b : int, optional
                The desired mod 8 value for q, default is none

        Returns : 
            is_success : bool
                Whether the prime generation was successful
            p, q : IntegerHandlers
                The generated primes as IntegerHandlers
        '''
        
        if nlen < 2048:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        elif e.getValue() <= pow(2, 16) or e.getValue() >= pow(2, 256) or (e.getValue() % 2) == 0:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        security_strength = RSA_KeyGeneration._getSecurityStrength(nlen)
        if security_strength == None:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        if seed.getBitLength() < 2 * security_strength:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        
        # generate p
        success, p_1, prime_seed, counter = RSA_KeyGeneration._generatePrime_ShaweTaylor(bitlens[0], seed, hash_function)
        if not success: return False, IntegerHandler(0), IntegerHandler(0)
        success, p_2, prime_seed, counter = RSA_KeyGeneration._generatePrime_ShaweTaylor(bitlens[1], prime_seed, hash_function)
        if not success: return False, IntegerHandler(0), IntegerHandler(0)
        success, p, X_p = RSA_KeyGeneration._generatePrime_Probable_AuxillaryPrimes(p_1, p_2, nlen, e, a)
        if not success: return False, IntegerHandler(0), IntegerHandler(0)

        minimum_difference = pow(2, nlen // 2 - 100)
        pq_diff, x_pq_diff = 0, 0
        # generate q
        while pq_diff < minimum_difference or x_pq_diff < minimum_difference:
            success, q_1, prime_seed, counter = RSA_KeyGeneration._generatePrime_ShaweTaylor(bitlens[2], prime_seed, hash_function)
            if not success: return False, IntegerHandler(0), IntegerHandler(0)
            success, q_2, prime_seed, counter = RSA_KeyGeneration._generatePrime_ShaweTaylor(bitlens[3], prime_seed, hash_function)
            if not success: return False, IntegerHandler(0), IntegerHandler(0)
            success, q, X_q = RSA_KeyGeneration._generatePrime_Probable_AuxillaryPrimes(q_1, q_2, nlen, e, b)
            if not success: return False, IntegerHandler(0), IntegerHandler(0)
            pq_diff = abs(p - q)
            x_pq_diff = abs(X_p - X_q)
        # print(f"p_1:{p_1}, p_2:{p_2}, q_1:{q_1}, q_2:{q_2}")
        X_p, X_q, prime_seed, p_1, p_2, q_1, q_2 = 0, 0, 0, 0, 0, 0, 0
        return True, IntegerHandler(p, False, nlen // 2), IntegerHandler(q, False, nlen // 2)
    
    @staticmethod
    def _generatePairOfPrimes_Probable_AuxillaryProbablePrimes(nlen:int, e:IntegerHandler, bitlens:list[int], a:int = None, b:int = None) -> tuple[bool, IntegerHandler, IntegerHandler]:
        '''
        This method generates 2 probable primes for use in an RSA scheme based
        
        From NIST FIPS 186-5 Section A.1.6 "Generation of Probable Primes with Conditions Based on Auxiliary Probable Primes"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

        Parameters :
            nlen : int
                The desired bit length for the n value in the implementation (at least 2048)
            e : IntegerHandler
                The e public exponent for the rsa key pair as an IntegerHandler
            bitlens : [int]
                The list of 4 bit lengths for p_1, p_2, q_1 and q_2
            a : int, optional
                The desired mod 8 value for p, default is none
            b : int, optional
                The desired mod 8 value for q, default is none

        Returns : 
            is_success : bool
                Whether the prime generation was successful
            p, q : IntegerHandlers
                The generated primes as IntegerHandlers
        '''
        
        if nlen < 2048:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        elif e.getValue() <= pow(2, 16) or e.getValue() >= pow(2, 256) or (e.getValue() % 2) == 0:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        
        # generate p
        p_1 = RSA_KeyGeneration._generateRandomPrime_Probable(bitlens[0], e)
        p_2 = RSA_KeyGeneration._generateRandomPrime_Probable(bitlens[1], e)
        success, p, X_p = RSA_KeyGeneration._generatePrime_Probable_AuxillaryPrimes(p_1, p_2, nlen, e, a)
        if not success: return False, IntegerHandler(0), IntegerHandler(0)

        minimum_difference = pow(2, nlen // 2 - 100)
        pq_diff, x_pq_diff = 0, 0
        # generate q
        while pq_diff < minimum_difference or x_pq_diff < minimum_difference:
            
            q_1 = RSA_KeyGeneration._generateRandomPrime_Probable(bitlens[2], e)
            q_2 = RSA_KeyGeneration._generateRandomPrime_Probable(bitlens[3], e)
            success, q, X_q = RSA_KeyGeneration._generatePrime_Probable_AuxillaryPrimes(q_1, q_2, nlen, e, b)
            if not success: return False, IntegerHandler(0), IntegerHandler(0)
            pq_diff = abs(p - q)
            x_pq_diff = abs(X_p - X_q)
        
        X_p, X_q, p_1, p_2, q_1, q_2 = 0, 0, 0, 0, 0, 0
        return True, IntegerHandler(p, False, nlen // 2), IntegerHandler(q, False, nlen // 2)
    
    @staticmethod
    def _generateRandomPrime_Probable(bitlen, e: IntegerHandler):
        '''
        This method generates a random probably prime with a given bit length and public exponent

        Parameters :
            bitlen : int
                The desired bitlength for the prime
            e : IntegerHandler
                The public exponent

        Returns : 
            probable_prime : int
                A probable prime following successful miller rabin tests
        '''
        potential_prime = 0
        while True:
            while potential_prime % 2 == 0:
                potential_prime = randbits(bitlen)

            while potential_prime < pow(2, bitlen):
                if euclidsAlgorithm(potential_prime + 1, e.getValue()) == 1:
                    if runMillerRabinPrimalityTest(potential_prime):
                        return potential_prime
                potential_prime += 2

    @staticmethod
    def _generatePrime_Probable_AuxillaryPrimes(r_1:int, r_2:int, nlen:int, e:IntegerHandler, c:int = None) -> tuple[bool, int, int]:
        '''
        This method constructs a probable prime for use in an RSA scheme based on two auxillary primes
        
        From NIST FIPS 186-5 Section B.9 "Compute a Probable Prime Factor Based on Auxiliary Primes"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

        Parameters :
            r_1 : int
                The first auxillary prime value
            r_2 : int
                The second auxillary prime value
            nlen : int
                The desired bit length for the n value in the implementation (at least 2048)
            e : IntegerHandler
                The e public exponent for the rsa key pair as an IntegerHandler
            c : int, optional
                The desired mod 8 value, default is none

        Returns : 
            is_success : bool
                Whether the prime generation was successful
            probable_prime_factor : int
                The generated prime
            X : int
                The random value used in generating the prime
        '''
        if nlen < 2048:
            return False, 0, 0
        elif e.getValue() <= pow(2, 16) or e.getValue() >= pow(2, 256) or (e.getValue() % 2) == 0:
            return False, 0, 0
        elif euclidsAlgorithm(2*r_1, r_2) != 1:
            return False, 0, 0
        
        inv_r2_mod2r1 = calculateInverseMod_GCD1_ExtendedEuclidsBased(r_2, 2 * r_1)
        inv_2r1_modr2 = calculateInverseMod_GCD1_ExtendedEuclidsBased(r_1 * 2, r_2)
        R = inv_r2_mod2r1 * r_2 - (inv_2r1_modr2 * 2 * r_1)
        max_value = pow(2, nlen // 2) - 1
        Y = -1
        i = 0 
        while i < 10 * nlen:
            while Y == -1 or Y >= max_value:
                min_X = Decimal.from_float(sqrt(2)) * Decimal.from_float(pow(2, (nlen - 1) // 2))
                X = 0
                while X < min_X or X > max_value:
                    X = randbits(nlen // 2)
                Y = X + ((R - X) % (2 * r_1 * r_2))
                if c != None:
                    if Y % 8 == c:
                        pass
                    elif (Y + 2 * r_1 * r_2) % 8 == c:
                        Y = Y + 2 * r_1 * r_2
                    elif (Y + 4 * r_1 * r_2) % 8 == c:
                        Y = Y + 4 * r_1 * r_2
                    elif (Y + 6 * r_1 * r_2) % 8 == c:
                        Y = Y + 6 * r_1 * r_2
            while Y < max_value:
                if euclidsAlgorithm(Y+1,e.getValue()) == 1:
                    probably_prime = runMillerRabinPrimalityTest(Y, 44) and runLucasPrimalityTest(Y)
                    if probably_prime:
                        private_prime_factor = Y
                        return True, private_prime_factor, X
                i = i + 1
                if i >= 10 * nlen:
                    return False, 0, 0
                if c != None:
                    Y = Y * (8 * r_1 * r_2)
                else:
                    Y = Y * (2 * r_1 * r_2)

    
    @staticmethod
    def _generatePairOfPrimes_Provable(nlen:int, e:IntegerHandler, seed:IntegerHandler, hash_function:ApprovedHashFunction = ApprovedHashFunctions.SHA_512_Hash.value, bitlens:list[int]=None) -> tuple[bool, IntegerHandler, IntegerHandler]:
        '''
        This method constructs two provable primes, p and q, for use in an RSA scheme
        
        From NIST FIPS 186-5 Section A.1.2.2 "Construction of the Provable Primes p and q"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

        Parameters :
            nlen : int
                The desired bit length for the n value in the implementation (at least 2048)
            e : IntegerHandler
                The e public exponent for the rsa key pair as an IntegerHandler
            seed : IntegerHandler
                The initial seed value for the prime generation as an IntegerHandler

        Returns : 
            is_success : bool
                Whether the prime generation was successful
            p, q : IntegerHandlers
                The generated primes as IntegerHandlers
        '''
        if e.getValue() <= pow(2, 16) or e.getValue() >= pow(2, 256) or (e.getValue() % 2) == 0:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        security_strength = RSA_KeyGeneration._getSecurityStrength(nlen)
        if security_strength == None:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        if seed.getBitLength() < 2 * security_strength:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        
        working_seed = seed
        L = nlen // 2
        if bitlens == None:
            p_N_1, p_N_2, q_N_1, q_N_2 = 1, 1, 1, 1
        else:
            p_N_1, p_N_2, q_N_1, q_N_2 = bitlens


        success, p, p_1, p_2, pseed = RSA_KeyGeneration._generatePrime_Provable_AuxillaryPrimeLengths(L,p_N_1,p_N_2,working_seed,e,hash_function)
        print(f"p has been determined as {p}")
        if not success:
            print("p failed")
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        working_seed = pseed
        q_not_determined = True
        while q_not_determined:
            success, q, q_1, q_2, qseed= RSA_KeyGeneration._generatePrime_Provable_AuxillaryPrimeLengths(L,q_N_1,q_N_2,working_seed,e,hash_function)
            if not success:
                print("q failed")
                return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
            if abs(p - q) > pow(2, ( nlen // 2 - 100 )):
                q_not_determined = False
        print(f"q has been determined as {q}")
        pseed,qseed,working_seed =0,0,0
        return True, IntegerHandler(p, little_endian, L), IntegerHandler(q, little_endian, L)

    @staticmethod
    def _generatePrime_Provable_AuxillaryPrimeLengths(L:int, N_1:int, N_2:int, first_seed:IntegerHandler, e: IntegerHandler, hash_function:ApprovedHashFunction = ApprovedHashFunctions.SHA_512_Hash.value) -> tuple[bool, int, int, int, IntegerHandler]:
        '''
        This method constructs a provable primes, potentially with conditions
        
        From NIST FIPS 186-5 Section B.10 "Construct a Provable Prime (Possibly with Conditions) Based on Contemporaneously Constructed Auxiliary Provable Primes"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

        Parameters :
            L : int
                The desired bit length for the prime being constructed
            N_1 : int
                The requested bit length for p_1
            N_2 : int
                The requested bit length for p_2
            first_seed : IntegerHandler
                The initial seed value for the prime generation as an IntegerHandler
            e : IntegerHandler
                The public key exponent as an integer value

        Returns : 
            is_success : bool
                Whether the prime generation was successful
            p : int
                The generated prime as an int
            p_1, p_2 : int
                The additional factors
            prime_seed : IntegerHandler
                The incremented seed value to be used in subsequent generations
        '''
        hash_length = hash_function.digest_length
        if N_1 == 1: #2
            p_1 = 1
            p_2seed = first_seed
        else: #3
            success, p_1, p_2seed, p_counter = RSA_KeyGeneration._generatePrime_ShaweTaylor(N_1, first_seed)
            if success == False:
                print("p1 failed")
                return False, 0, 0, 0, IntegerHandler(0,little_endian,0)
            else:
                print(f"small prime_1 is {p_1}")
        if N_2 == 1: #4
            p_2 = 1
            p_0seed = p_2seed
        else: #5
            success, p_2, p_0seed, p_counter = RSA_KeyGeneration._generatePrime_ShaweTaylor(N_2, p_2seed)
            if success == False:
                print("p2 failed")
                return False, 0, 0, 0, IntegerHandler(0,little_endian,0)
            else:
                print(f"small prime_2 is {p_1}")
        length = ceil(L / 2) + 1
        success, p_0, prime_seed, prime_gen_counter = RSA_KeyGeneration._generatePrime_ShaweTaylor(length, p_0seed) #6
        if success == False:
                print("p0 failed")
                return False, 0, 0, 0, IntegerHandler(0,little_endian,0)
        else:
            print(f"p_0 is {p_0}")
        if euclidsAlgorithm(p_0*p_1, p_2) != 1:
            return False, 0, 0, 0, IntegerHandler(0,little_endian,0)
        iterations = ceil(L / hash_length) - 1
        # print(f"iterations : {iterations} L = {L}")
        pgen_counter = 0
        x = 0
        for i in range(0, iterations + 1):
            pseed_i_handler = IntegerHandler(prime_seed.getValue() + i, little_endian, prime_seed.bit_length)
            hash_value = RSA_KeyGeneration._getHashValue(pseed_i_handler,hash_function)
            x = x + hash_value * pow(2, (i * hash_length))
        prime_seed = IntegerHandler(prime_seed.getValue() + iterations + 1, little_endian, prime_seed.bit_length)
        from decimal import Decimal
        sq2 = Decimal.from_float(sqrt(2))

        sq2_2toL = floor(sq2 * (pow(2, L - 1)))
        # print(sq2)
        # print(sq2_2toL)
        assert sq2_2toL > pow(2, L - 1)
        assert sq2_2toL < pow(2, L)

        x = sq2_2toL + (x % (pow(2, L) - sq2_2toL))
        # print(f"x: {x} in range {sq2_2toL} to {pow(2,L)-1}")
        assert x >= sq2_2toL
        assert x <= pow(2, L)-1
        # print(f"p_0:{p_0}, p_1:{p_1}, p_2:{p_2}, p_0*p_1%p_2={p_0*p_1%p_2}")
        p0p1 = p_0 * p_1
        # print(f"p0p1 = {p0p1} p2 = {p_2}")
        y = calculateInverseMod_GCD1_ExtendedEuclidsBased(p0p1, p_2)
        # print(f"p0p1 = {p0p1} y = {y} p0p1y - 1 = {(p0p1 * y -1) % p_2}")
        # assert (p0p1 * y) % p_2 == 1
        denominator = Decimal.from_float(2 * p_0 * p_1 * p_2)
        numerator = Decimal.from_float(2 * y * p_0 * p_1 + x)
        #t = ceil(( 2 * y * p_0 * p_1 + x)/(2 * p_0 * p_1 * p_2))
        t = ceil(numerator / denominator)
        # print(f"t: {t}")
        # while True:
        while pgen_counter <= 5 * L:
            if  (2 * (t * p_2 - y) * p_0 * p_1 + 1) > pow(2,L):
                denominator = Decimal.from_float(2 * p_0 * p_1 * p_2)
                numerator = Decimal.from_float(2 * y * p_0 * p_1 + sq2_2toL)
                t = ceil(numerator / denominator)
            # print(f"t: {t}")
            p = 2 * (t * p_2 - y) * p_0 * p_1 + 1
            #print(f"p : {p} = ( p-1) % (2p0 p1) {(p-1)%(2*p_0*p_1)} = ( p+1) mod p2. {(p+1)%p_2}")
            #print(f"Miller Rabin : {RSA.isMillerRabinPassed(p)}")
            pgen_counter += 1
            if euclidsAlgorithm((p - 1), e.getValue()) == 1:
                a = 0
                for i in range(0, iterations+1):
                    pseed_i_handler = IntegerHandler(prime_seed.getValue() + i, little_endian, prime_seed.bit_length)
                    hash_value = RSA_KeyGeneration._getHashValue(pseed_i_handler, hash_function)
                    a = a + hash_value * 2 ** (i * hash_length)
                prime_seed = IntegerHandler(prime_seed.getValue() + iterations + 1, little_endian, prime_seed.bit_length)
                a = 2 + a % (p - 3)
                # print(f"a : {a} in range 2 to p-2 {p-2}")
                assert a <= p - 2
                exp = 2 * (t * p_2 - y) * p_1
                z = pow(a, exp, p)
                # print(f"z ** p_0 % p = {pow(z,p_0,p)}")
                if 1 == euclidsAlgorithm(z - 1, p) and 1 == pow(z, p_0, p):
                    return True, p, p_1, p_2, prime_seed
            t = t + 1
        print(f"provable prime construction failed, pgen_counter:{pgen_counter}")
        return False, 0, 0, 0, IntegerHandler(0,little_endian,0)

    @staticmethod
    def _getHashValue(handler_to_hash: IntegerHandler, hash_function:ApprovedHashFunction = ApprovedHashFunctions.SHA_512_Hash.value) -> int:
        ''' 
        This method returns the value for the hash of a given IntegerHandler

        Parameters : 
            handler_to_hash : IntegerHandler
                The IntegerHandler that is being hashed once it is converted to a hex string

        Returns :
            hash_value : int
                The value of the hash as an int
        '''
        hash_handler = RSA_KeyGeneration._getHashHandler(handler_to_hash, hash_function)
        return hash_handler.getValue()
    
    @staticmethod
    def _getHashHandler(handler_to_hash: IntegerHandler, hash_function:ApprovedHashFunction = ApprovedHashFunctions.SHA_512_Hash.value) -> IntegerHandler:
        ''' 
        This method returns the result for the hash of a given IntegerHandler as an IntegerHandler

        Parameters : 
            handler_to_hash : IntegerHandler
                The IntegerHandler that is being hashed once it is converted to a hex string

        Returns :
            hash_handler : IntegerHandler
                The result of the hash as an IntegerHandler
        '''
        hash_handler = hash_function.hashIntegerHandler(handler_to_hash)
        return hash_handler

    @staticmethod
    def  _generatePrime_ShaweTaylor(length:int, input_seed:IntegerHandler, hash_function:ApprovedHashFunction = ApprovedHashFunctions.SHA_512_Hash.value)-> tuple[bool, int, IntegerHandler, int]:
        '''
        This method generates a pseudo random prime of a given length using a given seed

        Based on NIST FIPS 186-5 Section B.6 "Shawe-Taylor Random_Prime Routine"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

        Parameters :
            length : int 
                The bit length of the prime to be generated
            input_seed : IntegerHandler
                The input seed for the prime generator as an IntegerHandler

        Returns : 
            is_success : bool
                Whether the prime generation was successful
            prime : int
                The generated prime as an int
            prime_seed : IntegerHandler
                The next prime seed
            prime_gen_counter : int
                The counter for the prime generation
        '''
        if length < 2:
            return False, 0, IntegerHandler(0), 0
        hash_length = hash_function.digest_length
        prime_gen_counter = 0
        prime_seed = input_seed
        while length < 33 and prime_gen_counter <= 4 * length:
            prime_seed_inc = IntegerHandler(prime_seed.getValue()+1, False, prime_seed.bit_length)
            c = bitwiseXor([RSA_KeyGeneration._getHashHandler(prime_seed,hash_function), RSA_KeyGeneration._getHashHandler(prime_seed_inc,hash_function)],little_endian,hash_length)
            c = pow(2, (length - 1)) + (c.getValue() % pow(2, (length - 1)))
            c = (2 * floor(c / 2)) + 1
            prime_gen_counter = prime_gen_counter + 1
            prime_seed = IntegerHandler(prime_seed.getValue() + 2, little_endian, prime_seed.bit_length)
            if testSmallPrime(c):
                return True, c, prime_seed, prime_gen_counter
            elif prime_gen_counter > 4 * length:
                return False, 0, IntegerHandler(0), 0
        status, c_0, prime_seed, prime_gen_counter = RSA_KeyGeneration._generatePrime_ShaweTaylor(ceil(length / 2) + 1,prime_seed)
        if status == False:
            return False, 0, IntegerHandler(0), 0
        iterations = ceil(length / hash_length) - 1
        # print(f"iterations : {iterations}")
        old_counter = prime_gen_counter
        x = 0
        for i in range(0, iterations):
            pseed_i_handler = IntegerHandler(prime_seed.getValue() + i, little_endian, prime_seed.bit_length)
            hash_value = RSA_KeyGeneration._getHashValue(pseed_i_handler,hash_function)
            x = x + hash_value * pow(2, (i * hash_length)) 
        prime_seed = IntegerHandler(prime_seed.getValue()+iterations+1,little_endian,prime_seed.bit_length)
        x = pow(2, (length - 1)) + x % pow( 2, (length - 1))
        numerator = Decimal.from_float(x)
        denominator = Decimal.from_float(2 * c_0)
        t = ceil(numerator / denominator) #22
        # print(f"t : {t}")
        while (prime_gen_counter <= (4 * length) + old_counter):
            if 2 * t * c_0 + 1 > pow(2, length): #23
                numerator = Decimal.from_float(pow(2, length-1))
                denominator = Decimal.from_float(2 * c_0)
                t = ceil(numerator / denominator)
            c = 2 * t * c_0 + 1
            prime_gen_counter = prime_gen_counter + 1 #25
            # print(c)
            # print(RSA.isMillerRabinPassed(c))
            a = 0
            for i in range (0, iterations):
                prime_seed_inc = IntegerHandler(prime_seed.getValue() + i, False, prime_seed.bit_length)
                a = a + RSA_KeyGeneration._getHashValue(prime_seed_inc,hash_function) * pow(2, (i * hash_length)) #27
                # print(f"a : {a}")
            prime_seed = IntegerHandler(prime_seed.getValue() + iterations + 1, little_endian, prime_seed.bit_length)
            a = 2 + (a % (c - 3))
            z = pow(a, 2 * t, c)
            # print(f"gcd = {euclidsAlgorithm(z-1, c)} pow = {pow(z, c_0, c)}")
            # if 1 == euclidsAlgorithm(z-1, c) :
            if 1 == euclidsAlgorithm(z-1, c) and 1 == pow(z, c_0, c):
                # print(f"prime is {c}: {RSA.isMillerRabinPassed(c)}")
                prime = c
                return True, prime, prime_seed, prime_gen_counter
            elif  (prime_gen_counter >= ((4 * length) + old_counter)):
                return False, 0, IntegerHandler(0), 0
            t = t + 1
            # print(prime_gen_counter)
    
    

    @staticmethod
    def _calculatePublicKey(e:IntegerHandler, p:IntegerHandler, q:IntegerHandler, gcd_e_phi_1:bool) -> tuple[IntegerHandler, RSA_PublicKey, bool]:
        '''
        This method calculates the RSA public key given e, p and q

        Parameters :
            e : IntegerHandler
                The public key exponent
            p : IntegerHandler
                The first prime being used
            q : IntegerHandler 
                The second prime being used

        Returns
            n : IntegerHandler
                The n value for the RSA
            public_key : RSA_PublicKey
                The public key for the RSA
            gcd_e_phi_1 : int
                Whether the greatest common denominator of e and phi is 1
        '''
        
        n = IntegerHandler((p.getValue()) * (q.getValue()),little_endian)
        p_1 = p.getValue() - 1
        q_1 = q.getValue() - 1
        gcd_p1_q1 = euclidsAlgorithm(p_1, q_1)
        phi = p_1 * q_1 // gcd_p1_q1
        public_key = RSA_PublicKey(n, e)

        if euclidsAlgorithm(phi,e.getValue()) == 1:
            gcd_e_phi_1 = True
        return n, public_key, gcd_e_phi_1

    

    @staticmethod
    def _generateRandomPublicKeyExponent(min_e: int = None, max_e: int = None):
        '''
        This method generates a random IntegerHandler between 2 ** 16 and 2 ** 256 to use as the public exponent

        Parameters : 
            min_e : int, optional
                The minimum value for e, default is 2 ** 16
            max_e : int, optional
                The maximum value for e, default is 2**256
        Return :
            e : IntegerHandler
                The random value for the public exponent
        '''
        e = 0
        if min_e == None:
            min_e = pow(2, 16)
        if max_e == None:
            max_e = pow(2, 256)
        while e % 2 == 0 or e < min_e or e > max_e:
            e = randbelow(max_e)
        e = IntegerHandler(e, little_endian)
        return e

    @staticmethod
    def _getNLength(security_strength):
        '''
        This method determines the appropriate nlen based on a requested security strength

        Parameters : 
            security_strength : int
                The requested security strength as an int

        Returns :
            nlen : int
                The bit length for n that corresponds to the requested security strength
        '''

        nlen = None
        for strength in SecurityStrength:
            if security_strength == strength.value.security_strength:
                nlen = strength.value.integer_factorization_cryptography
                break
        
        return nlen
    
    @staticmethod
    def _calculatePrivateKeyExponent(e:IntegerHandler, p:IntegerHandler, q:IntegerHandler) -> IntegerHandler:
        '''
        This method calculates the value for d given e, p and q

        Parameters :
            e : IntegerHandler
                The public exponent
            p, q : IntegerHandler
                The primes that make up the RSA
        
        Returns :
            d : IntegerHandler
                The private exponent value 
        '''
        phi = (p.getValue() - 1) * (q.getValue() - 1)
        p_1 = p.getValue() - 1
        q_1 = q.getValue() - 1
        gcd_p1_q1 = euclidsAlgorithm(p_1, q_1)
        phi = p_1 * q_1 // gcd_p1_q1
        d = calculateInverseMod_GCD1_ExtendedEuclidsBased(e.getValue(), phi)
        return IntegerHandler(d, little_endian=little_endian)
    
   
    
    
   
if __name__ == '__main__':
    for i in range(1,10000):
        rabin = runMillerRabinPrimalityTest(i)
        lucas = runLucasPrimalityTest(i)
        print(f"{i} : rabin:{rabin} lucas:{lucas}")
        from sympy import isprime
        assert rabin == isprime(i), f"{i} should be classified as {isprime(i)}, not {rabin}"
        assert lucas == isprime(i), f" {i} should be classified as {isprime(i)}, not {lucas}"

    success, seed = RSA_KeyGeneration._generateSeed(2048)

    strength = SecurityStrength.s112.value
    rsa_bit_length_for_strength = strength.integer_factorization_cryptography
    public_key_gen, private_key_gen = RSA_KeyGeneration.generateRSAKeyPair_ProvablePrimes_AuxillaryPrimes([100,100,100,100], strength.security_strength, RSA_PrivateKey_Type.Quint, is_debug=True)
    public_key_gen, private_key_gen = RSA_KeyGeneration.generateRSAKeyPair_ProbablePrimes_AuxillaryProvablePrimes(None, strength.security_strength, RSA_PrivateKey_Type.Quint, is_debug=True)
    public_key_gen, private_key_gen = RSA_KeyGeneration.generateRSAKeyPair_ProbablePrimes_AuxillaryProbablePrimes(None, strength.security_strength, RSA_PrivateKey_Type.Quint, is_debug=True)

    assert public_key_gen.n.getValue() == private_key_gen.n.getValue()

    pt = "0D3E74F20C249E1058D4787C22F95819066FA8927A95AB004A240073FE20CBCB149545694B0EE318557759FCC4D2CA0E3D55307D1D3A4CD1F3B031CE0DF356A5DEDCC25729C4302FABA4CB885C9FA3C2F57A4D1308451C300D2378E90F4F83DCEDCDCF5217BC3840A796FCDAF73483A3D199C389BDB50CFE95D9C02E5F4FC1917FA4606CF6AB7559253202698D7EABE7561137271CE1A524E5956D25C379AF4F121877355F2495DC154A0EB33CF2F3B6990F60FCC0CCE199EF1E76E11585895EE1C619FB6D140266006AB41D56CE3E6C68571902568CD4520F1F9E5E284B4B9DFCC3782D05CDF826895450E314FBC654032A775F47088F18D3B4000AC23BD107"
    plain = IntegerHandler.fromHexString(pt, little_endian)
    '''
        Security Strength - RSA k
        <80 - 1024
        112 - 2048
        128 - 3072
        192 - 7680
        256 - 15360
    '''
    perfect_square = [4,16,49,81,144,10000]
    for square in perfect_square:
        is_square = checkForAPerfectSquare(square)
        assert is_square == True
    not_perfect_square = [5,19,52,88,150,10001]
    for not_square in not_perfect_square:
        is_square = checkForAPerfectSquare(not_square)
        assert is_square == False

    jacobiSymbol(5, 3439601197, True)

    success, r_1, r_2_seed, counter = RSA_KeyGeneration._generatePrime_ShaweTaylor(140,seed)
    print(f"r_1 is {r_1}")
    success, r_2, r_3_seed, counter = RSA_KeyGeneration._generatePrime_ShaweTaylor(140,r_2_seed)
    print(f"r_2 is {r_2}")
    success, prime_candidate, random_num = RSA_KeyGeneration._generatePrime_Probable_AuxillaryPrimes(r_1,r_2,2048,public_key_gen.e)
    print(prime_candidate)

    success, p, q = RSA_KeyGeneration._generatePairOfPrimes_Probable_AuxillaryProvablePrimes(strength.integer_factorization_cryptography, public_key_gen.e,seed,bitlens=[141,141,141,141])
    print(p.getHexString())
    print(q.getHexString())
    success, p, q = RSA_KeyGeneration._generatePairOfPrimes_Probable_AuxillaryProbablePrimes(strength.integer_factorization_cryptography, public_key_gen.e,bitlens=[141,141,141,141],a=3,b=5)
    print(p.getHexString())
    print(q.getHexString())
