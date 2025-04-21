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
    def __init__(self, word_bits = 32):
        super().__init__(word_bits)
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
    
class SHA2_64BitWords(SHA256):
    K_hex =    ["428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc",
                "3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
                "d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
                "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
                "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65",
                "2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
                "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4",
                "c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
                "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
                "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
                "a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30",
                "d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
                "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8",
                "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
                "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
                "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
                "ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178",
                "06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
                "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c",
                "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817"]
    
    def __init__(self):
        super().__init__(word_bits=64)

    def sigmaCapitalFromZero(self, x:IntegerHandler):
        '''
        This method implements Sigma from 0 as defined by section 4.1.3 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions" of Nist Fips 180-4

        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x : IntegerHandler
                The value being operated on

        Returns :
            sigma_result : IntegerHandler
                The value after the sigma operation
        '''

        rotr_28 = x.rotateRight(28)
        rotr_34 = x.rotateRight(34)
        rotr_39 = x.rotateRight(39)
        sigma_result = bitwiseXor([rotr_28,rotr_34,rotr_39], self.endian, self.word_bits)
        return sigma_result
    
    def sigmaCapitalFromOne(self, x:IntegerHandler):
        '''
        This method implements Sigma from 1 as defined by section 4.1.3 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions" of Nist Fips 180-4

        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x : IntegerHandler
                The value being operated on

        Returns :
            sigma_result : IntegerHandler
                The value after the sigma operation
        '''
        
        rotr_14 = x.rotateRight(14)
        rotr_18 = x.rotateRight(18)
        rotr_41 = x.rotateRight(41)
        sigma_result = bitwiseXor([rotr_14,rotr_18,rotr_41], self.endian, self.word_bits)
        return sigma_result
    
    def sigmaLittleFromZero(self, x:IntegerHandler):
        '''
        This method implements sigma from 0 as defined by section 4.1.3 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions" of Nist Fips 180-4

        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x : IntegerHandler
                The value being operated on

        Returns :
            sigma_result : IntegerHandler
                The value after the sigma operation
        '''
        
        rotr_1 = x.rotateRight(1)
        rotr_8 = x.rotateRight(8)
        shr_7 = x.rightShift(7)
        sigma_result = bitwiseXor([rotr_1,rotr_8,shr_7], self.endian, self.word_bits)
        return sigma_result
    
    def sigmaLittleFromOne(self, x:IntegerHandler):
        '''
        This method implements sigma from 1 as defined by section 4.1.3 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions" of Nist Fips 180-4

        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x : IntegerHandler
                The value being operated on

        Returns :
            sigma_result : IntegerHandler
                The value after the sigma operation
        '''
        
        rotr_19 = x.rotateRight(19)
        rotr_61 = x.rotateRight(61)
        shr_6 = x.rightShift(6)
        sigma_result = bitwiseXor([rotr_19,rotr_61,shr_6], self.endian, self.word_bits)
        return sigma_result
    
    def preprocessing_FromString(self, message:str) -> list[list[IntegerHandler]]:
        '''
        This method should preprocess a string message, both adding padding and breaking it into chunks

        5.1.2 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256" of NIST FIPS 180-4
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            message : str
                The message to be hashed as a string (utf-8)

        Returns :
            message_chunks : [[IntegerHandler]]
                The message in chunks of bits for processing
        '''

        chunk_size = 1024
        message_handler = IntegerHandler.fromString(message, little_endian = self.endian)
        length = 8 * len(message)
        k = (-length - 1 + 896) % chunk_size
        padding = [1]+[0]*k
        padded_handler = concatenate([message_handler,IntegerHandler.fromBitArray(padding,bit_length= 1+k),IntegerHandler(length,self.endian,128)])
        bits = padded_handler.getBitArray()
        segment_count = len(bits) // chunk_size
        message_chunks = []
        for i in range(0, segment_count):
            chunk = []
            for j in range(0,16):
                chunk.append(IntegerHandler.fromBitArray(bits[ i * chunk_size + j * self.word_bits: i * chunk_size + j * self.word_bits + self.word_bits], self.endian, bit_length = self.word_bits))
            message_chunks.append(chunk)
        return message_chunks



class SHA512(SHA2_64BitWords):
    H_0_hex = ["6a09e667f3bcc908", "bb67ae8584caa73b", "3c6ef372fe94f82b", "a54ff53a5f1d36f1",
               "510e527fade682d1", "9b05688c2b3e6c1f", "1f83d9abfb41bd6b", "5be0cd19137e2179"]
    
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

        for t in range(16,80):
            sigma_one_2 = self.sigmaLittleFromOne(message_schedule[t-2])
            sigma_zero_15 = self.sigmaLittleFromZero(message_schedule[t-15])
            W_7 = message_schedule[t-7]
            W_16 = message_schedule[t-16]
            add_result = self.wordAddition([sigma_one_2,W_7,sigma_zero_15,W_16])
            message_schedule.append(add_result)

        a,b,c,d,e,f,g,h = previousHash[0],previousHash[1],previousHash[2],previousHash[3],previousHash[4],previousHash[5],previousHash[6],previousHash[7]

        for t in range(0,80):
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
    
    

class SHA386(SHA2_64BitWords):
    H_0_hex = ["cbbb9d5dc1059ed8", "629a292a367cd507", "9159015a3070dd17", "152fecd8f70e5939",
               "67332667ffc00b31", "8eb44a8768581511", "db0c2e0d64f98fa7", "47b5481dbefa4fa4"]
    
sha256 = SHA256()
sha224 = SHA224()
sha512 = SHA512()

if __name__ =="__main__":
    hash = sha512.hashAString("hash this string please and thank you hopefully it comes out ok")
    print(hash.getHexString(add_spacing=16))
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
    print("Testing SHA-512 Against Known Values")
    print("Expected Hashes are Sourced from Nist Cryptographic Standards and Guidelines: Examples With Intermediate Values")
    print("https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf")
    print("- - - - - - - - - - - -")

    hash = sha512.hashAString("abc")
    expected_value = "DDAF35A1 93617ABA CC417349 AE204131 12E6FA4E 89A97EA2 0A9EEEE6 4B55D39A 2192992A 274FC1A8 36BA3C23 A3FEEBBD 454D4423 643CE80E 2A9AC94F A54CA49F".replace(" ","")
    expected_handler = IntegerHandler.fromHexString(expected_value,False,512)
    print("Hashing \"abc\"")
    print(f"Expected hash : {expected_handler.getHexString(add_spacing=8)}")
    print(f"Actual hash   : {hash.getHexString(add_spacing=8)}")
    assert expected_handler.value == hash.value, "The first SHA512 example is not matching the expected value"
    print("- - - - - - - - - - - -")

    hash = sha512.hashAString("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
    expected_value = "8E959B75 DAE313DA 8CF4F728 14FC143F 8F7779C6 EB9F7FA1 7299AEAD B6889018 501D289E 4900F7E4 331B99DE C4B5433A C7D329EE B6DD2654 5E96E55B 874BE909".replace(" ","")
    expected_handler = IntegerHandler.fromHexString(expected_value,False,512)
    print("Hashing \"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu\"")
    print(f"Expected hash : {expected_handler.getHexString(add_spacing=8)}")
    print(f"Actual hash   : {hash.getHexString(add_spacing=8)}")

    assert expected_handler.value == hash.value, "The second SHA512 example is not matching the expected value"

    print("- - - - - - - - - - - -")
