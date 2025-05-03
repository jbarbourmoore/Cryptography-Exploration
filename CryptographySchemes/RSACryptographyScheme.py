from HelperFunctions.IntegerHandler import IntegerHandler, bitwiseXor
little_endian = False
bit_length = 2048
from secrets import randbits
from math import ceil, floor
from HashingAlgorithms.SecureHashAlgorithm3 import shake_256
from HelperFunctions.EuclidsAlgorithms import euclidsAlgorithm
from HelperFunctions.PrimeNumbers import getPrimeNumbers_SieveOfEratosthenes

'''
    Security Strength - RSA k
    <80 - 1024
    112 - 2048
    128 - 3072
    192 - 7680
    256 - 15360
'''

hash_alg = shake_256
hash_length = 512
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
        for i in range(0, private_key.u - 2):
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
    
    @staticmethod
    def RSA_SeedGeneration(nlen:int):
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
        if nlen == 2048:
            security_strength = 112
        elif nlen == 3072:
            security_strength = 128
        elif nlen == 7680:
            security_strength = 192
        elif nlen == 15360:
            security_strength = 256
        else:
            return False, IntegerHandler(0, little_endian, 0)
        
        seed = randbits(security_strength * 2)
        return True, IntegerHandler(seed, little_endian, security_strength * 2)
    
    @staticmethod
    def constructionOfProvablePrimes(nlen:int, e:IntegerHandler, seed:IntegerHandler) -> tuple[bool, IntegerHandler, IntegerHandler]:
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
        if e.getValue() <= 2**16 or e.getValue() >= 2**256 or (e.getValue() % 2) == 0:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        if nlen == 2048:
            security_strength = 112
        elif nlen == 3072:
            security_strength = 128
        elif nlen == 7680:
            security_strength = 192
        elif nlen == 15360:
            security_strength = 256
        else:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        if seed.getBitLength() < 2 * security_strength:
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        
        working_seed = seed
        L = nlen // 2
        N_1 = 1
        N_2 = 1

        success, p, p_1, p_2, pseed = RSA.provablePrimeConstruction(L,N_1,N_2,working_seed,e)
        if not success:
            print("p failed")
            return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
        working_seed = pseed
        q_not_determined = True
        while q_not_determined:
            success, q, q_1, q_2, qseed= RSA.provablePrimeConstruction(L,N_1,N_2,working_seed,e)
            if not success:
                print("q failed")
                return False, IntegerHandler(0, little_endian, 0), IntegerHandler(0, little_endian, 0)
            if abs(p - q) > 2 **( nlen//2 -100):
                q_not_determined = False
        pseed,qseed,working_seed =0,0,0
        return True, IntegerHandler(p, little_endian, L), IntegerHandler(q, little_endian, L)

    @staticmethod
    def provablePrimeConstruction(L:int, N_1:int, N_2:int, first_seed:IntegerHandler, e: IntegerHandler) -> tuple[bool, int, int, int, IntegerHandler]:
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
        if N_1 == 1: #2
            p_1 = 1
            p_2seed = first_seed
        else: #3
            p_1, p_2seed = RSA.randomPrimeGeneration_ShaweTaylor()
            if p_1 == False:
                print("p1 failed")
                return False, 0, 0, 0, IntegerHandler(0,little_endian,0)
        if N_2 == 1: #4
            p_2 = 1
            p_0seed = p_2seed
        else: #5
            p_2, p_0seed = RSA.randomPrimeGeneration_ShaweTaylor()
            if p_2 == False:
                print("p2 failed")
                return False, 0, 0, 0, IntegerHandler(0,little_endian,0)
        length = ceil(L / 2) + 1
        success, p_0, prime_seed, prime_gen_counter = RSA.randomPrimeGeneration_ShaweTaylor(length, p_0seed) #6
        if success == False:
                print("p0 failed")
                return False, 0, 0, 0, IntegerHandler(0,little_endian,0)
        if euclidsAlgorithm(p_0*p_1, p_2) != 1:
            return False, 0, 0, 0, IntegerHandler(0,little_endian,0)
        iterations = ceil(L/hash_length) - 1
        pgen_counter = 0
        x = 0
        for i in range(0, iterations):
            pseed_i_handler = IntegerHandler(prime_seed.getValue() + i, little_endian, prime_seed.bit_length)
            hash_value = RSA.getHashValue(pseed_i_handler)
            x = x + hash_value * 2 ** (i * hash_length)
        prime_seed = IntegerHandler(prime_seed.getValue()+iterations+1,little_endian,prime_seed.bit_length)
        sq2_2toL = floor(2**(.5) * (2**(L - 1)))
        x = sq2_2toL + x % (2**L - sq2_2toL)
        # print(f"p_0:{p_0}, p_1:{p_1}, p_2:{p_2}, p_0*p_1%p_2={p_0*p_1%p_2}")
        y = RSA.calculateInverseModA(p_0 * p_1, p_2)
        t = ceil((2*y*p_0*p_1+x)/(2*p_0*p_1*p_2))
        while pgen_counter <= 5:
            if  (2 * (t * p_2 - y) * p_0 * p_1 + 1) > 2**L:
                t = ceil((2*y*p_0*p_1+sq2_2toL)/(2*p_0*p_1*p_2))

            p = 2 * (t * p_2 - y) * p_0 * p_1 + 1
            pgen_counter += 1
            if euclidsAlgorithm((p-1),e.getValue()) == 1:
                a = 0
                for i in range(0, iterations):
                    pseed_i_handler = IntegerHandler(prime_seed.getValue() + i, little_endian, prime_seed.bit_length)
                    hash_value = RSA.getHashValue(pseed_i_handler)
                    x = x + hash_value * 2 ** (i * hash_length)
                prime_seed = IntegerHandler(prime_seed.getValue()+iterations+1,little_endian,prime_seed.bit_length)
                a = 2 + a % (p-3)
                exp = 2*(t*p_2-y)*p_1
                z = pow(a,exp,p)
                if 1 == euclidsAlgorithm(z-1,p):
                    return True, p, p_1, p_2, prime_seed
            t = t + 1
        print(f"provable prime construction failed, pgen_counter:{pgen_counter}")
        return False, 0, 0, 0, IntegerHandler(0,little_endian,0)
    
    @staticmethod
    def calculateInverseModA(z:int, a:int) -> int:
        '''
        This method calculates the inverse of a value within a modulus a

        From NIST FIPS 186-5 Section B.1 "Computation of the Inverse Value"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

        Parameters :
            z : int
                The value for which one is calculating the inverse
            a : int
                The modulus within which one is calculating the inverse

        Returns :
            z_inverse : int
                The inverse of z within the modulus a 
        '''
        if z >= a:
            z = z % a
        i = a
        j = z
        y_1 = 1
        y_2 = 0
        while j > 0:
            quotient = floor(i/j)
            remainder = i - (j * quotient)
            y = y_2 - (y_1 * quotient)
            i = j
            j = remainder
            y_2 = y_1
            y_2 = y
        assert i == 1
        return y_2 % a

    @staticmethod
    def getHashValue(handler_to_hash: IntegerHandler) -> int:
        ''' 
        This method returns the value for the hash of a given IntegerHandler

        Parameters : 
            handler_to_hash : IntegerHandler
                The IntegerHandler that is being hashed once it is converted to a hex string

        Returns :
            hash_value : int
                The value of the hash as an int
        '''
        hash_hex = hash_alg.hashHex(handler_to_hash.getHexString(), hash_length).getHexString()
        hash_handler = IntegerHandler.fromHexString(hash_hex, False, hash_length)
        return hash_handler.getValue()
    
    @staticmethod
    def getHashHandler(handler_to_hash: IntegerHandler) -> IntegerHandler:
        ''' 
        This method returns the result for the hash of a given IntegerHandler as an IntegerHandler

        Parameters : 
            handler_to_hash : IntegerHandler
                The IntegerHandler that is being hashed once it is converted to a hex string

        Returns :
            hash_handler : IntegerHandler
                The result of the hash as an IntegerHandler
        '''

        hash_hex = hash_alg.hashHex(handler_to_hash.getHexString(), hash_length).getHexString()
        hash_handler = IntegerHandler.fromHexString(hash_hex, False, hash_length)
        return hash_handler

    @staticmethod
    def  randomPrimeGeneration_ShaweTaylor(length:int, input_seed:IntegerHandler)-> tuple[bool, int, IntegerHandler, int]:
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
        prime_gen_counter = 0
        prime_seed = input_seed
        while length < 33 and prime_gen_counter <= 4 * length:
            prime_seed_inc = IntegerHandler(prime_seed.getValue()+1, False, prime_seed.bit_length)
            c = bitwiseXor([RSA.getHashHandler(prime_seed), RSA.getHashHandler(prime_seed_inc)],little_endian,hash_length)
            c = 2 ** (length - 1) + (c.getValue() % (2 ** (length - 1)))
            c = (2 * floor(c / 2)) + 1
            prime_gen_counter = prime_gen_counter + 1
            prime_seed = IntegerHandler(prime_seed.getValue() + 2, little_endian, prime_seed.bit_length)
            if RSA.testPrime(c):
                return True, c, prime_seed, prime_gen_counter
            elif prime_gen_counter > 4 * length:
                return False, 0, IntegerHandler(0), 0
        status, c_0, prime_seed, prime_gen_counter = RSA.randomPrimeGeneration_ShaweTaylor(ceil(length / 2) + 1,prime_seed)
        if status == False:
            return False, 0, IntegerHandler(0), 0
        iterations = ceil(length / hash_length) - 1
        old_counter = prime_gen_counter
        x = 0
        for i in range(0, iterations):
            pseedihex = IntegerHandler(prime_seed.getValue() + i, little_endian, prime_seed.bit_length).getHexString()
            hash_hex = hash_alg.hashHex(pseedihex, hash_length).getHexString()
            hash_value = IntegerHandler.fromHexString(hash_hex,False, hash_length).getValue()
            x = x + hash_value * 2 ** (i * hash_length)  
        prime_seed = IntegerHandler(prime_seed.getValue()+iterations+1,little_endian,prime_seed.bit_length)
        x = 2**(length - 1) + x % ( 2**(length - 1))
        t = ceil(x / (2 * c_0)) #22
        while True:
            if 2 * t * c_0 + 1 > 2 **length: #23
                t = ceil(2**(length - 1) / (2 * c_0)) 
            c = 2 * t * c_0 + 1
            prime_gen_counter = prime_gen_counter + 1 #25
            # print(c)
            # print(RSA.testPrime(c))
            a = 0
            for i in range (0, iterations):
                prime_seed_inc = IntegerHandler(prime_seed.getValue()+i, False, prime_seed.bit_length)
                a = a + RSA.getHashValue(prime_seed_inc) * 2 ** (i * hash_length) #27
            prime_seed = IntegerHandler(prime_seed.getValue()+iterations+1,little_endian,prime_seed.bit_length)
            a = 2 + (a % (c - 3))
            z = pow(a, 2*t, c)
            # print(f"gcd = {euclidsAlgorithm(z-1, c)} pow = {pow(z, c_0, c)}")
            # if 1 == euclidsAlgorithm(z-1, c) :
            if 1 == euclidsAlgorithm(z-1, c) and 1 == pow(z, c_0, c):
                return True, c, prime_seed, prime_gen_counter
            elif  (prime_gen_counter >= ((4 * length) + old_counter)):
                return False, 0, IntegerHandler(0), 0
            t = t + 1
            # print(prime_gen_counter)

    @staticmethod
    def testPrime(potential_prime:int) -> bool:
        '''
        This method tests whether an integer is a prime number

        Based on NIST FIPS 186-5 Section B.7 "Trial Division"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
    
        Parameters : 
            potential_prime : int 
                The potentical prime int value to be tested

        Returns : 
            is_prime : bool
                Whether the integer value is a prime or not
        '''
        sqrt_c = potential_prime ** .5
        primes_under_c = getPrimeNumbers_SieveOfEratosthenes(2,int(sqrt_c))
        for prime in primes_under_c:
            if potential_prime % prime == 0:
                return False
        return True

        
if __name__ == '__main__':
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
    from HelperFunctions.PrimeNumbers import calculateModuloInverse
    dP = given_d.getValue() % (given_p.getValue() - 1)
    dQ = given_d.getValue() % (given_q.getValue() - 1)
    qInv = calculateModuloInverse(given_q.getValue(), given_p.getValue())
    calc_dP = IntegerHandler(dP,little_endian,bit_length)
    calc_dQ = IntegerHandler(dQ,little_endian,bit_length)
    calc_qInv = IntegerHandler(qInv,little_endian,bit_length)

    public_key = RSA_PublicKey(given_n, given_e)
    private_key = RSA_PrivateKey(given_n, given_d)
    private_key_quint = RSA_PrivateKey_QuintupleForm(given_p,given_q,calc_dP,calc_dQ,calc_qInv,[])

    calculated_cipher = RSA.RSA_EncryptionPrimitive(public_key, expected_plain)
    print(f"Expected Cipher : {expected_cipher.getHexString()}")
    print()
    print(f"Calculated Cipher : {calculated_cipher.getHexString()}")

    assert expected_cipher.getHexString() == calculated_cipher.getHexString()

    calculated_plain = RSA.RSA_DecryptionPrimitive(private_key, calculated_cipher)
    print()
    print(f"Expected Plain : {expected_plain.getHexString()}")
    print()
    print(f"Calculated Plain : {calculated_plain.getHexString()}")

    calculated_plain_quint = RSA.RSA_DecryptionPrimitive(private_key_quint, calculated_cipher)
    print()
    print(f"Calculated Plain Quint : {calculated_plain_quint.getHexString()}")
    print()


    assert expected_plain.getHexString() == calculated_plain.getHexString()
    assert expected_plain.getHexString() == calculated_plain_quint.getHexString()


    ct = "742D529EE4A41CE7BAD178E358F51DCF872FCC12A304EBFABB12030AE6AB06A738010B59BA0C339C8C48435B16164DF7521D29CCC206027F860DAA1840A930FD2D8EFAA6ED70ECB0FB8F18A5847207662A44B416A9333632A7F8C9A7BD2F2BA5EEC7CE1E7C783B0633D2FFF938AA7850B468476C4F1EC5FBAC761E28772083FB88514FFCC3BBCE72B003356F2FE3A8C62140C7412AB4F63DC491D94BEAEC0A68422FDCE07099917BA97120465B8A8D86C109148189C52A6432C096543777E4D14A91F9BC6969D036C25106551929FD5AE511C2CFBD54F93BEC464A41CF53CDB0C63A6F59E5739884D8D2D6830117AB7D0165A70428AB0BB9EADE2F02EEA9089A"
    pt = "0D3E74F20C249E1058D4787C22F95819066FA8927A95AB004A240073FE20CBCB149545694B0EE318557759FCC4D2CA0E3D55307D1D3A4CD1F3B031CE0DF356A5DEDCC25729C4302FABA4CB885C9FA3C2F57A4D1308451C300D2378E90F4F83DCEDCDCF5217BC3840A796FCDAF73483A3D199C389BDB50CFE95D9C02E5F4FC1917FA4606CF6AB7559253202698D7EABE7561137271CE1A524E5956D25C379AF4F121877355F2495DC154A0EB33CF2F3B6990F60FCC0CCE199EF1E76E11585895EE1C619FB6D140266006AB41D56CE3E6C68571902568CD4520F1F9E5E284B4B9DFCC3782D05CDF826895450E314FBC654032A775F47088F18D3B4000AC23BD107"
    dmp1 = ""
    dmq1 = ""
    iqmp = ""
    p = "EB48E387997710CB6D83CC6A2CCFD327B3064638ABEEE8708F7F25EE89AC8975BB062EC227129E923586F190F1A5C2E2E8DA988286E09F190A0B99380A45525E14BD10EEB2BB024B88CD184A08F27B29B72F33DB0A9D33CCF5E07D2A5D27604ED0F9836CCF7A121CB6A220BAAC94FA8835F75F6A942257972ADF69C4D8B8EEA9"
    q =  "BA09FCB64170DEDFBE8E7A37A088EAB99BD73A8CA78B83B63E666449A83A43B6B631CF7BAE9255305EBFA5B3831EC70C89ADB34DE0F5D48A85AB4897A13D9E6441FE55679574664E241A827C15086187FE0686479F84B40C9964EF14E07A4BE03BBBBCE4A5C6120FF452D295026EEE74BF2912ED1DDA20FEE3FB2DA7835AA1F7"
    d = "42B7EAE4BFC8E11D33536136EF3C2B26A516C5D480FA7D55E31CF6CA68E070D9B1E8C18351354B01294CAB22F0D3676821F0462A410989160D060F3A11331103E09D68D8B9FB1E922E538B4AB23C2D0CD033868BE59B746A42BBE638F379154E729B04739C7504ECA3585C65AB57FC31F5D871C195A30E04D27A5FCAA3C45CFB2D3BB0D5D694EE648C1DA6584B75DA110482C24159576E729D7E3DAA0096DB623AD9F6DE63181B4C539BCA9B502C4E33AB455728AC2E358503E90D258FE1BED937CFC355A8C3B54C3F8B3031D5612F7E63C307F899DB3F391F1A83E248580CC145887E25614D59B32892834BBDC75D55FE39CFD797CAB80E2506C5A8E684426F"
    n = "AAFC2323C735635B862201C4920D397EA283F11A1E76C56BA8C5573314D7D1DBE70C1DF2ACE3C7E71D549F7ED8D1E82DF3F8148B81A479C7BED674DB4A8B9F8F95F07ED1F3DF1809E0AD53AFE8F589AD8431F24F8CFBF7F0BAFCF77C9487B037AD16C8564A9EED11C1E8BAD2063307627CD6971E99F88FC7524F05D89F1A609FA328EFEEB3DBF511C9EFFA7CD2734F3BF1C2A5FC2FC3548EEFB8B6EE1E4D8C0859E1A993BDCF8ED744E9BB32444C7FEF86FDD96D596CC99B701B0201D95D6DAC931FBE3A6E38DBF589E43330DE8425A474E1D28003D7C9D70BA14F9D9EA633B4BF921F54DBDEEB130A05DE2CEC30F15F1B1B793FB00BF89D8679119CCAF08E0F"
    e = "8792D8C9AF"
    expected_cipher = IntegerHandler.fromHexString(ct, little_endian, bit_length)
    expected_plain = IntegerHandler.fromHexString(pt, little_endian, bit_length)
    given_p = IntegerHandler.fromHexString(p, little_endian, bit_length)
    given_q = IntegerHandler.fromHexString(q, little_endian, bit_length)
    given_n = IntegerHandler.fromHexString(n, little_endian, bit_length)
    given_e = IntegerHandler.fromHexString(e, little_endian, bit_length)
    given_d = IntegerHandler.fromHexString(d, little_endian, bit_length)
    dP = given_d.getValue() % (given_p.getValue() - 1)
    dQ = given_d.getValue() % (given_q.getValue() - 1)
    qInv = calculateModuloInverse(given_q.getValue(), given_p.getValue())
    calc_dP = IntegerHandler(dP,little_endian,bit_length)
    calc_dQ = IntegerHandler(dQ,little_endian,bit_length)
    calc_qInv = IntegerHandler(qInv,little_endian,bit_length)

    public_key = RSA_PublicKey(given_n, given_e)
    private_key = RSA_PrivateKey(given_n, given_d)
    private_key_quint = RSA_PrivateKey_QuintupleForm(given_p,given_q,calc_dP,calc_dQ,calc_qInv,[])
    calculated_cipher = RSA.RSA_EncryptionPrimitive(public_key, expected_plain)
    print(f"Expected Cipher : {expected_cipher.getHexString()}")
    print()
    print(f"Calculated Cipher : {calculated_cipher.getHexString()}")

    assert expected_cipher.getHexString() == calculated_cipher.getHexString()

    calculated_plain = RSA.RSA_DecryptionPrimitive(private_key, calculated_cipher)
    print()
    print(f"Expected Plain : {expected_plain.getHexString()}")
    print()
    print(f"Calculated Plain : {calculated_plain.getHexString()}")

    calculated_plain_quint = RSA.RSA_DecryptionPrimitive(private_key_quint, calculated_cipher)
    print()
    print(f"Calculated Plain Quint : {calculated_plain_quint.getHexString()}")
    print()


    assert expected_plain.getHexString() == calculated_plain.getHexString()
    assert expected_plain.getHexString() == calculated_plain_quint.getHexString()
    success, seed = RSA.RSA_SeedGeneration(2048)
    print(success)
    success, p, q = RSA.constructionOfProvablePrimes(2048,given_e,seed)
    print(seed.getHexString())
    print(p.getHexString())
    print(q.getHexString())
    print(success)


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