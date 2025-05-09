from HelperFunctions.IntegerHandler import *

class SHA1():
    '''
    This class should hold the methods and values necessary in order to implement sha 1
    '''
    K_hex = ["5a827999","6ed9eba1","8f1bbcdc","ca62c1d6"]
    H_0_hex = ["67452301","efcdab89","98badcfe","10325476","c3d2e1f0"]

    def __init__(self, word_bits = 32, truncate_bit_length = None):
        self.word_bits:int = word_bits
        self.endian:bool = False
        self.truncate_bit_length = truncate_bit_length
        self.H_0 = []
        self.K = []
        for i in range(0,len(self.H_0_hex)):
            self.H_0.append(IntegerHandler.fromHexString(self.H_0_hex[i],self.endian,self.word_bits))
        for i in range(0,len(self.K_hex)):
            self.K.append(IntegerHandler.fromHexString(self.K_hex[i],self.endian,self.word_bits))
        self.chunk_size = 512
        self.chunk_capacity = 448
        self.length_bits = 64
    
    def hashAString(self,message:str) -> IntegerHandler:
        '''
        This method hashes a string using SHA1

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
        hash = concatenate(hash_value,self.endian)
        if self.truncate_bit_length != None:
            hash = hash.truncateLeft(bit_length=self.truncate_bit_length)
        return hash
    
    def hashAHexString(self,message:str,bytes:int) -> IntegerHandler:
        '''
        This method hashes a string using SHA1

        Parameters :
            message : str
                The hex string to be hashed
            bytes : int
                The number of bytes in the hex string being hashed

        Returns :
            hash : IntegerHandler
                The hash for the string as an IntegerHandler
        '''

        message_chunks = self.preprocessing_FromString(message=message,is_hex=True,bytes=bytes)
        hash_value = self.H_0
        for i in range(0,len(message_chunks)):
            hash_value = self.processMessageBlock(message_chunks[i],hash_value)
            # self.printHash(hash_value)
        hash = concatenate(hash_value,self.endian)
        if self.truncate_bit_length != None:
            hash = hash.truncateLeft(bit_length=self.truncate_bit_length)
        return hash

    def processMessageBlock(self, message_block:list[IntegerHandler],previousHash:list[IntegerHandler]):
        '''
        This message hashes a single message block

        Parameters :
            message_block : [IntegerHandler]
                The message block of 512 bits as a list of 32 bit IntegerHandlers
            previous_hash : [IntegerHandler]
                The previous hash value as a list of 5 32 bit IntegerHandlers

        Returns
            hash : [IntegerHandler]
                The hash value after this message block as a list of 5 32 bit IntegerHandlers
        '''

        message_schedule = []
        for t in range(0,16):
            message_schedule.append(message_block[t])
        for t in range(16,80):
            xor_result = bitwiseXor([message_schedule[t-3],message_schedule[t-8],message_schedule[t-14],message_schedule[t-16]],little_endian=self.endian,bit_length=self.word_bits)
            message_schedule.append(xor_result.rotateLeft(1))

        a,b,c,d,e = previousHash[0],previousHash[1],previousHash[2],previousHash[3],previousHash[4]

        for t in range(0,80):
            a_rotl = a.rotateLeft(5)
            if t <= 19:  
                f_x = self.ch(b,c,d)
                k = self.K[0]
            elif t <= 39:
                f_x = self.parity(b,c,d)
                k = self.K[1]
            elif t <= 59:
                f_x = self.maj(b,c,d)
                k = self.K[2]
            else:
                f_x = self.parity(b,c,d)
                k = self.K[3]
            T = self.wordAddition([a_rotl,f_x,e,k,message_schedule[t]])
            e = d
            d = c
            c = b.rotateLeft(30)
            b = a
            a = T
            # self.printHash([a,b,c,d,e],t)
        current_hash = []
        current_hash.append(self.wordAddition([previousHash[0], a]))
        current_hash.append(self.wordAddition([previousHash[1], b]))
        current_hash.append(self.wordAddition([previousHash[2], c]))
        current_hash.append(self.wordAddition([previousHash[3], d]))
        current_hash.append(self.wordAddition([previousHash[4], e]))
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
        print(f"{number_str}{hash[0].getHexString()} {hash[1].getHexString()} {hash[2].getHexString()} {hash[3].getHexString()} {hash[4].getHexString()}")

    def wordAddition(self, values:list[IntegerHandler]) -> IntegerHandler:
        '''
        This method handles addition of words

        Parameters :
            values : [IntegerHandler]
                The values being added together as an integer handler

        Returns :
            sum : IntegerHandler
                The result of the addition mod 2**32
        '''
        current_value = values[0].getValue()
        for i in range(1,len(values)):
            current_value = current_value + values[i].getValue()
            current_value %= (2**self.word_bits)
        return IntegerHandler(current_value,self.endian,self.word_bits)

    def preprocessing_FromString(self, message:str, is_hex:bool = False, bytes:int = 0) -> list[list[IntegerHandler]]:
        '''
        This method should preprocess a string message, both adding padding and breaking it into chunks

        5.1.1 "SHA-1, SHA-224 and SHA-256" of NIST FIPS 180-4
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            message : str
                The message to be hashed as a string (utf-8) or a hex string
            is_hex : bool
                Whether the input is a hex string 
            bytes : int
                The number of bytes in the hex string

        Returns :
            message_chunks : [[IntegerHandler]]
                The message in chunks of bits for processing
        '''
        if not is_hex:
            message_handler = IntegerHandler.fromString(message, little_endian = self.endian)
            length = 8 * len(message)
        else: 
            message_handler = IntegerHandler.fromHexString(message, little_endian = self.endian, bit_length=bytes*8)
            length = 8 * bytes
        k = (-length - 1 + self.chunk_capacity) % self.chunk_size
        padding = [1]+[0]*k
        padded_handler = concatenate([message_handler,IntegerHandler.fromBitArray(padding,bit_length= 1+k),IntegerHandler(length,self.endian,self.length_bits)])
        bits = padded_handler.getBitArray()
        segment_count = len(bits) // self.chunk_size
        message_chunks = []
        for i in range(0, segment_count):
            chunk = []
            for j in range(0,16):
                chunk.append(IntegerHandler.fromBitArray(bits[ i * self.chunk_size + j * self.word_bits: i * self.chunk_size + j * self.word_bits + self.word_bits], self.endian, bit_length = self.word_bits))
            message_chunks.append(chunk)
        return message_chunks


    def ch(self, x:IntegerHandler, y:IntegerHandler, z:IntegerHandler) -> IntegerHandler:
        '''
        This method should perform the Ch function as required for sha1 
        Ch(x, y, z)=(x^y)xor(!x^z)
        Section 4.1.1 "SHA-1 Functions" of NIST FIPS 180-4
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x, y, z : IntegerHandler
                The values that the operation is being performed on as 32 bit big endian integer values

        Returns :
            ch_result : IntegerHandler
                The resulting value for the ch function as a 32 bit big endian integer value
        '''

        not_x = x.bitwiseNot()
        x_and_y = bitwiseAnd([x,y],self.endian,self.word_bits)
        not_x_and_z = bitwiseAnd([not_x,z],self.endian,self.word_bits)
        ch_result = bitwiseXor([x_and_y,not_x_and_z], self.endian, self.word_bits)
        return ch_result
    
    def parity(self, x:IntegerHandler, y:IntegerHandler, z:IntegerHandler) -> IntegerHandler:
        '''
        This method should perform the parity function as required for sha1 
        Parity(x, y, z)=x xor y xor z
        Section 4.1.1 "SHA-1 Functions" of NIST FIPS 180-4
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x, y, z : IntegerHandler
                The values that the operation is being performed on as 32 bit big endian integer values

        Returns :
            parity_result : IntegerHandler
                The resulting value for the parity function as a 32 bit big endian integer value
        '''

        parity_result = bitwiseXor([x,y,z], self.endian, self.word_bits)
        return parity_result

    def maj(self, x:IntegerHandler, y:IntegerHandler, z:IntegerHandler) -> IntegerHandler:
        '''
        This method should perform the maj function as required for sha1 
        Maj(x, y, z)=(x & y) xor (x & z) xor (y & z)
        Section 4.1.1 "SHA-1 Functions" of NIST FIPS 180-4
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

        Parameters :
            x, y, z : IntegerHandler
                The values that the operation is being performed on as 32 bit big endian integer values

        Returns :
            maj_result : IntegerHandler
                The resulting value for the maj function as a 32 bit big endian integer value
        '''

        x_and_y = bitwiseAnd([x, y], self.endian, self.word_bits)
        x_and_z = bitwiseAnd([x, z], self.endian, self.word_bits)
        y_and_z = bitwiseAnd([y, z], self.endian, self.word_bits)
        maj_result = bitwiseXor([x_and_y,x_and_z,y_and_z], self.endian, self.word_bits)
        return maj_result
sha1 = SHA1()

if __name__ =="__main__":
    # hash = sha1.hashAString("hash this string please and thank you hopefully it comes out ok")
    # print(hash.getHexString())
    # hash = sha1.hashAString("This is my second string to hash with sha 1. I am hoping to make it a bit longer than the previous string but probably not too long.")
    # print(hash.getHexString())

    print("- - - - - - - - - - - -")
    print("Testing SHA-1 Against Known Values")
    print("Expected Hashes are Sourced from Nist Cryptographic Standards and Guidelines: Examples With Intermediate Values")
    print("https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf")
    print("- - - - - - - - - - - -")

    hash = sha1.hashAString("abc")
    expected_value = "A9993E364706816ABA3E25717850C26C9CD0D89D"
    expected_handler = IntegerHandler.fromHexString(expected_value,False,32*5)
    print("Hashing \"abc\"")
    print(f"Expected hash : {expected_handler.getHexString(add_spacing=8)}")
    print(f"Actual hash   : {hash.getHexString(add_spacing=8)}")
    assert expected_handler.value == hash.value, "The first SHA1 example is not matching the expected value"
    print("- - - - - - - - - - - -")

    hash = sha1.hashAString("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    expected_value = "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"
    expected_handler = IntegerHandler.fromHexString(expected_value,False,32*5)
    print("Hashing \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"")
    print(f"Expected hash : {expected_handler.getHexString(add_spacing=8)}")
    print(f"Actual hash   : {hash.getHexString(add_spacing=8)}")

    assert expected_handler.value == hash.value, "The second SHA1 example is not matching the expected value"

    print("- - - - - - - - - - - -")

