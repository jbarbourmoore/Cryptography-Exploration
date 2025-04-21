from HelperFunctions.IntegerHandler import *
from CryptographySchemes.SecureHashAlgorithm1 import SHA1

class SHA2(SHA1):
    '''
    This class should hold the methods and values necessary in order to implement sha 2
    '''

    K_hex =   ["428a2f98", "71374491", "b5c0fbcf", "e9b5dba5", "3956c25b", "59f111f1", "923f82a4", "ab1c5ed5",
               "d807aa98", "12835b01", "243185be", "550c7dc3", "72be5d74", "80deb1fe", "9bdc06a7", "c19bf174",
               "e49b69c1", "efbe4786", "0fc19dc6", "240ca1cc", "2de92c6f", "4a7484aa", "5cb0a9dc", "76f988da",
               "983e5152", "a831c66d", "b00327c8", "bf597fc7", "c6e00bf3", "d5a79147", "06ca6351", "14292967",
               "27b70a85", "2e1b2138", "4d2c6dfc", "53380d13", "650a7354", "766a0abb", "81c2c92e", "92722c85",
               "a2bfe8a1", "a81a664b", "c24b8b70", "c76c51a3", "d192e819", "d6990624", "f40e3585", "106aa070",
               "19a4c116", "1e376c08", "2748774c", "34b0bcb5", "391c0cb3", "4ed8aa4a", "5b9cca4f", "682e6ff3",
               "748f82ee", "78a5636f", "84c87814", "8cc70208", "90befffa", "a4506ceb", "bef9a3f7", "c67178f2"]

    def sigmaCapitalFromZero(self, x:IntegerHandler):
        '''
        This method implements Sigma from 0 as defined by section 4.1.2 "SHA-224 and SHA-256 Functions" of Nist Fips 180-4

        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x : IntegerHandler
                The value being operated on

        Returns :
            sigma_result : IntegerHandler
                The value after the sigma operation
        '''

        rotr_2 = x.rotateRight(2)
        rotr_13 = x.rotateRight(13)
        rotr_22 = x.rotateRight(22)
        sigma_result = bitwiseXor([rotr_2,rotr_13,rotr_22], self.endian, self.word_bits)
        return sigma_result
    
    def sigmaCapitalFromOne(self, x:IntegerHandler):
        '''
        This method implements Sigma from 1 as defined by section 4.1.2 "SHA-224 and SHA-256 Functions" of Nist Fips 180-4

        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x : IntegerHandler
                The value being operated on

        Returns :
            sigma_result : IntegerHandler
                The value after the sigma operation
        '''
        
        rotr_6 = x.rotateRight(6)
        rotr_11 = x.rotateRight(11)
        rotr_25 = x.rotateRight(25)
        sigma_result = bitwiseXor([rotr_6,rotr_11,rotr_25], self.endian, self.word_bits)
        return sigma_result
    
    def sigmaLittleFromZero(self, x:IntegerHandler):
        '''
        This method implements sigma from 0 as defined by section 4.1.2 "SHA-224 and SHA-256 Functions" of Nist Fips 180-4

        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x : IntegerHandler
                The value being operated on

        Returns :
            sigma_result : IntegerHandler
                The value after the sigma operation
        '''
        
        rotr_7 = x.rotateRight(7)
        rotr_18 = x.rotateRight(18)
        shr_3 = x.rightShift(3)
        sigma_result = bitwiseXor([rotr_7,rotr_18,shr_3], self.endian, self.word_bits)
        return sigma_result
    
    def sigmaLittleFromOne(self, x:IntegerHandler):
        '''
        This method implements sigma from 1 as defined by section 4.1.2 "SHA-224 and SHA-256 Functions" of Nist Fips 180-4

        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x : IntegerHandler
                The value being operated on

        Returns :
            sigma_result : IntegerHandler
                The value after the sigma operation
        '''
        
        rotr_17 = x.rotateRight(17)
        rotr_19 = x.rotateRight(19)
        shr_10 = x.rightShift(10)
        sigma_result = bitwiseXor([rotr_17,rotr_19,shr_10], self.endian, self.word_bits)
        return sigma_result



class SHA256(SHA2):
    H_0_hex = ["6a09e667", "bb67ae85", "3c6ef372", "a54ff53a", "510e527f", "9b05688c", "1f83d9ab", "5be0cd19"]
    def __init__(self):
        super().__init__()
        self.word_bits = 32
        self.digest_length = 256

    def processMessageBlock(self, message_block:list[IntegerHandler],previousHash:list[IntegerHandler]):
        '''
        This message hashes a single message block

        Parameters :
            message_block : [IntegerHandler]
                The message block of 512 bits as a list of 32 bit IntegerHandlers
            previous_hash : [IntegerHandler]
                The previous hash value as a list of 8 32 bit IntegerHandlers

        Returns
            hash : [IntegerHandler]
                The hash value after this message block as a list of 8 32 bit IntegerHandlers
        '''

        message_schedule = []
        for t in range(0,16):
            message_schedule.append(message_block[t])

        for t in range(16,64):
            sigma_one_2 = self.sigmaLittleFromOne(message_schedule[t-2])
            sigma_zero_15 = self.sigmaLittleFromZero(message_schedule[t-15])
            W_7 = message_schedule[t-7]
            W_16 = message_schedule[t-16]
            add_result = self.wordAddition([sigma_one_2,W_7,sigma_zero_15,W_16])
            message_schedule.append(add_result)

        a,b,c,d,e,f,g,h = previousHash[0],previousHash[1],previousHash[2],previousHash[3],previousHash[4],previousHash[5],previousHash[6],previousHash[7]

        for t in range(0,64):
            sigma_big_one_e = self.sigmaCapitalFromOne(e)
            ch_efg = self.ch(e,f,g)
            K_t = self.K[t]
            W_t = message_schedule[t]
            T_1 = self.wordAddition([h, sigma_big_one_e, ch_efg, K_t, W_t])

            sigma_big_zero_a = self.sigmaCapitalFromZero(a)
            maj_abc = self.maj(a,b,c)
            T_2 = self.wordAddition([sigma_big_zero_a, maj_abc])

            h = g
            g = f
            f = e
            e = self.wordAddition([d, T_1])
            d = c
            c = b
            b = a
            a = self.wordAddition([T_1, T_2])
            # self.printHash([a,b,c,d,e,f,g,h],t)

            
        current_hash = []
        current_hash.append(self.wordAddition([previousHash[0], a]))
        current_hash.append(self.wordAddition([previousHash[1], b]))
        current_hash.append(self.wordAddition([previousHash[2], c]))
        current_hash.append(self.wordAddition([previousHash[3], d]))
        current_hash.append(self.wordAddition([previousHash[4], e]))
        current_hash.append(self.wordAddition([previousHash[5], f]))
        current_hash.append(self.wordAddition([previousHash[6], g]))
        current_hash.append(self.wordAddition([previousHash[7], h]))
        return current_hash
    
    def printHash(self, hash:list[IntegerHandler],numbering=None):
        '''
        This method returns the prints a hash value to the console

        Parameters :
            hash : [IntegerHandlers]
                The hash that is being printed
            numbering : int, optional
                The index for the hash to be printed, default is none
        '''

        if numbering != None:
            number_str = f"{numbering}: "
        else:
            number_str = ""
        print(f"{number_str}{hash[0].getHexString()} {hash[1].getHexString()} {hash[2].getHexString()} {hash[3].getHexString()} {hash[4].getHexString()} {hash[5].getHexString()} {hash[6].getHexString()} {hash[7].getHexString()}")

class SHA224(SHA256):
    H_0_hex = ["c1059ed8", "367cd507", "3070dd17", "f70e5939", "ffc00b31", "68581511", "64f98fa7", "befa4fa4"]
    def __init__(self):
        super().__init__()
        self.word_bits = 32
        self.digest_length = 224

    def hashAString(self,message:str) -> IntegerHandler:
        '''
        This method hashes a string using SHA224

        Parameters :
            message : str
                The string to be hashed

        Returns :
            hash : IntegerHandler
                The hash for the string as an IntegerHandler
        '''

        message_chunks = self.preprocessing_FromString(message=message)
        hash_value = self.H_0
        for i in range(0,len(message_chunks)):
            hash_value = self.processMessageBlock(message_chunks[i],hash_value)
            # self.printHash(hash_value)
        hash = concatenate(hash_value[0:7],self.endian)
        return hash
    
sha256 = SHA256()
sha224 = SHA224()

if __name__ =="__main__":
    hash = sha224.hashAString("hash this string please and thank you hopefully it comes out ok")
    print(hash.getHexString(add_spacing=8))
    # hash = sha1.hashAString("This is my second string to hash with sha 1. I am hoping to make it a bit longer than the previous string but probably not too long.")
    # print(hash.getHexString())

    print("- - - - - - - - - - - -")
    print("Testing SHA-256 Against Known Values")
    print("Expected Hashes are Sourced from Nist Cryptographic Standards and Guidelines: Examples With Intermediate Values")
    print("https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf")
    print("- - - - - - - - - - - -")

    hash = sha256.hashAString("abc")
    expected_value = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    expected_handler = IntegerHandler.fromHexString(expected_value,False,256)
    print("Hashing \"abc\"")
    print(f"Expected hash : {expected_handler.getHexString(add_spacing=8)}")
    print(f"Actual hash   : {hash.getHexString(add_spacing=8)}")
    assert expected_handler.value == hash.value, "The first SHA256 example is not matching the expected value"
    print("- - - - - - - - - - - -")

    hash = sha256.hashAString("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    expected_value = "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
    expected_handler = IntegerHandler.fromHexString(expected_value,False,256)
    print("Hashing \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"")
    print(f"Expected hash : {expected_handler.getHexString(add_spacing=8)}")
    print(f"Actual hash   : {hash.getHexString(add_spacing=8)}")

    assert expected_handler.value == hash.value, "The second SHA256 example is not matching the expected value"

    print("- - - - - - - - - - - -")
    print("Testing SHA-224 Against Known Values")
    print("Expected Hashes are Sourced from Nist Cryptographic Standards and Guidelines: Examples With Intermediate Values")
    print("https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA224.pdf")
    print("- - - - - - - - - - - -")

    hash = sha224.hashAString("abc")
    expected_value = "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7"
    expected_handler = IntegerHandler.fromHexString(expected_value,False,224)
    print("Hashing \"abc\"")
    print(f"Expected hash : {expected_handler.getHexString(add_spacing=8)}")
    print(f"Actual hash   : {hash.getHexString(add_spacing=8)}")
    assert expected_handler.value == hash.value, "The first SHA224 example is not matching the expected value"
    print("- - - - - - - - - - - -")

    hash = sha224.hashAString("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    expected_value = "75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525"
    expected_handler = IntegerHandler.fromHexString(expected_value,False,224)
    print("Hashing \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"")
    print(f"Expected hash : {expected_handler.getHexString(add_spacing=8)}")
    print(f"Actual hash   : {hash.getHexString(add_spacing=8)}")

    assert expected_handler.value == hash.value, "The second SHA224 example is not matching the expected value"

    print("- - - - - - - - - - - -")

