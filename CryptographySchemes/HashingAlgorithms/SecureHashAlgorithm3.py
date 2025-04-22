from HelperFunctions.IntegerHandler import *

class SHA3_ValueHandler():
    '''
    This class handles the values within SHA 3 (expecially b2h and h2b)
    Internally, the value is stored as a bit array
    '''

    def __init__(self, bit_array=None):
        '''
        This method initializes the value handler

        Parameters :
            bit_array : [int]
                The bit array that is being handled
        '''
        if bit_array == None:
            bit_array = [0,0,0,0,0,0,0,0]
        self.bit_array = bit_array
        self.bit_length = len(bit_array)
    
    def getBit(self, index:int) -> int:
        '''
        This method gets a bit at a certain index

        Parameters :
            index : int
                The index of the bit being retrieved
        '''

        return self.bit_array[index]
    
    def setBit(self, index:int, bit:int):
        '''
        This method sets a bit at a certain index

        Parameters :
            index : int
                The index of the bit being set
            bit : int
                The value being set for the bit 
        '''

        self.bit_array[index] = bit

    def bitwiseXor(self, handler):
        '''
        This method performs a bit wise Xor on two SHA3_ValueHandlers

        Parameters :
            handler : SHA3_ValueHandler
                The other handler being xored

        Returns :
            xor_result : SHA3_ValueHandler
                The result of the XOR
        '''

        assert self.bit_length == handler.bit_length, "Bit wise xor can only be calculated with two handlers with the same bit length"
        result_bits = [0 for _ in range(0,self.bit_length)]
        for bit in range(0, self.bit_length):
            if self.getBit(bit) ^ handler.getBit(bit):
                result_bits[bit] = 1
        return SHA3_ValueHandler(bit_array=result_bits)
    
    def concatenate(self, handler):
        '''
        This method concatenates two handlers

        Parameters :
            handler : SHA3_ValueHandler
                The other handler being concatenated

        Returns :
            concat_result : SHA3_ValueHandler
                The result of the concatenation
        '''
        concat = self.bit_array + handler.bit_array
        return SHA3_ValueHandler(bit_array=concat)
    
    def splitSegments(self, segment_length:int):
        '''
        This method splits the value into a list of handlers of a certain bit length

        Parameters : 
            segment_length : int
                The length of each segment

        Returns :
            list_of_segments : [SHA3_ValueHandler]
                The list of value handlers for each segment
        '''
        number_of_segments = self.bit_length // segment_length
        assert self.bit_length == number_of_segments * segment_length,"The content must be evenly divisible by the segment length"

        segment_list = []
        for i in range(0, number_of_segments):
            segment_list.append(SHA3_ValueHandler(self.bit_array[i * segment_length: i * segment_length + segment_length]))

        return segment_list


    @staticmethod
    def fromHexString(hex_string:str, bit_length=None):
        '''
        This method converts a hexadecimal string to a binary array as according to the appendix of nist fips 202
\
        Parameters : 
            hex_string : str
                The hexadecimal string being converted
            bit_length : int
                The maximum length of the binary string

        Returns 
            binary_result : SHA3_ValueHandler
                The sha3 value handler resulting from the conversion
        '''

        hex_string = hex_string.replace(" ","")
        if len(hex_string) % 2 == 1:
            hex_string = "0"+hex_string
        bits_per_octet = 8
        octet_length = len(hex_string)//2
        binary_result = [0] * 4 * len(hex_string)
        if bit_length == None:
            bit_length = bits_per_octet * octet_length
        for i in range(0, len(hex_string)//2):
            integer_value = int(hex_string[2*i:2*i+2],16)
            for j in range(bits_per_octet - 1, -1, -1):
                if integer_value >= 2 ** j:
                    binary_result[i * bits_per_octet + j] = 1
                    integer_value -= 2 ** j
        return SHA3_ValueHandler(binary_result[:bit_length])
    
    @staticmethod
    def fromString(string:str):
        '''
        This method constructs an integer handler from a string

        Parameters :
            bit_string : str
                The value as a string

        Return :
            value_handler : SHA3_ValueHandler
                The value of the string as a handled integer
        '''

        string_hex = string.encode("utf-8").hex()
        return SHA3_ValueHandler.fromHexString(string_hex)
      
    def getHexString(self) -> str:
        '''
        This method converts the sha3 value handler to a hexadecimal string as according to the appendix of nist fips 202

        Returns 
            hex_string : str
                The hexadecimal string resulting from the conversion
        '''
        bits_per_octet = 8
        hex_length= ceil(self.bit_length / bits_per_octet)
        bit_array = self.bit_array + [0] * (-self.bit_length % bits_per_octet)
        hex_string = ''
        for octet_count in range(0,hex_length):
            octet_value = 0
            for bit_count in range(0, bits_per_octet):
                octet_value += bit_array[octet_count * bits_per_octet + bit_count] * (2 ** bit_count)
            octet_string = hex(octet_value)[2:].upper()
            if len(octet_string) % 2 == 1:
                octet_string = "0"+octet_string
            elif len(octet_string) == 0:
                octet_string = "00"
            hex_string += octet_string
        return hex_string
    
    def __eq__(self, value):
        '''
        This method compared two ValueHandlers based on their bit_array and bit_length
        '''
        if type(value) == SHA3_ValueHandler and value.bit_array == self.bit_array and value.bit_length == self.bit_length:
            return True
        else:
            return False
    
class SHA3_StateArray():
    '''
    This class should hold the state array for the sha3 calculation
    '''

    def __init__(self, state_array = None, w = 64):
        '''
        This method initialized the state array

        Parameters :
            state_array : [[[int]]]
                An existing state array, defualt is all 0s
            w : int
                The width of the state array, default is 64
        '''
        self.w = w
        if state_array == None:
            self.array = [[[0 for z in range(0,w)] for y in range(0, 5)] for x in range(0,5)]
        else: self.array = state_array

    def getValueHandler(self) -> SHA3_ValueHandler:
        ''''
        This method gets the value handler corresponding to the current state

        Returns : 
            value_handler : SHA3_ValueHandler
                The value handler corresponding to the current state
        '''
        bit_length = 5 * 5 * self.w
        bit_array = [0] * bit_length
        for x in range(0, 5):
            for y in range(0, 5):
                for z in range(0, self.w):
                    bit_array[self.w * (5 * y + x) + z] = self.array[x][y][z]
        return SHA3_ValueHandler(bit_array=bit_array)

    @staticmethod
    def fromValueHandler(value_handler : SHA3_ValueHandler):
        '''
        This method creates a state array from a given valuehandler

        Parameters :
            value_handler : SHA3_ValueHandler
                The value handler for the bit array being converted into the state array

        Returns :
            state_array : SHA3_StateArray
                The state array created from the value handler
        '''

        bit_length = value_handler.bit_length
        w = bit_length // 25
        array = [[[0 for z in range(0,w)] for y in range(0, 5)] for x in range(0,5)]
        for x in range(0, 5):
            for y in range(0, 5):
                for z in range(0, w):
                    array[x][y][z] = value_handler.bit_array[w * (5 * y + x) + z]
        return SHA3_StateArray(state_array = array, w = w)
    
    def getRow_x(self, y:int, z:int) -> SHA3_ValueHandler:
        '''
        This method gets a row (x) at a given y and z as a value handler

        Parameters : 
            y, z : int
                The location for the row

        Returns : 
            row : SHA3_ValueHandler
                All the bits for the row as a value handler
        '''
        row = [0, 0, 0, 0, 0]
        for x in range(0, 5):
            row[x] = self.array[x][y][z]
        return SHA3_ValueHandler(bit_array=row)
    
    def setRow_x(self, y:int, z:int, handler:SHA3_ValueHandler):
        '''
        This method sets a row (x) at a given y and z from a value handler

        Parameters : 
            y, z : int
                The location for the row
            handler : SHA3_ValueHandler
                All the bits for the row as a value handler
        '''
        for x in range(0, 5):
            self.array[x][y][z] = handler.getBit(x)
    
    def getColumn_y(self, x:int, z:int) -> SHA3_ValueHandler:
        '''
        This method gets a column (y) at a given x and z as a value handler

        Parameters : 
            x, z : int
                The location for the column

        Returns : 
            column : SHA3_ValueHandler
                All the bits for the column as a value handler
        '''
        column = [0, 0, 0, 0, 0]
        for y in range(0, 5):
            column[y] = self.array[x][y][z]
        return SHA3_ValueHandler(bit_array=column)
    
    def setColumn_y(self, x:int, z:int, handler:SHA3_ValueHandler):
        '''
        This method sets a column (y) at a given x and z from a value handler

        Parameters : 
            x, z : int
                The location for the column
            handler : SHA3_ValueHandler
                All the bits for the column as a value handler
        '''
        for y in range(0, 5):
            self.array[x][y][z] = handler.getBit(y)

    def getLane_z(self, x:int, y:int) -> SHA3_ValueHandler:
        '''
        This method gets a lane (z) at a given x and y as a value handler

        Parameters : 
            x, y : int
                The location for the lane

        Returns : 
            lane : SHA3_ValueHandler
                All the bits for the lane as a value handler
        '''
        lane = [0 for _ in range(0, self.w)]
        for z in range(0, self.w):
            lane[z] = self.array[x][y][z]
        return SHA3_ValueHandler(bit_array=lane)
    
    def setLane_z(self, x:int, y:int, handler:SHA3_ValueHandler):
        '''
        This method sets a lane (z) at a given x and y from a value handler

        Parameters : 
            x, y : int
                The location for the lane

        Returns : 
            lane : SHA3_ValueHandler
                All the bits for the lane as a value handler
        '''
        for z in range(0, self.w):
            self.array[x][y][z] = handler.getBit(z)

    def __eq__(self, value):
        '''
        This method compares two state arrays based on their internal array
        '''

        if type(value) == SHA3_StateArray and value.array == self.array:
            return True
        else:
            return False
    
    def getBit(self, x:int, y:int, z: int) -> int:
        '''
        This method gets a bit at a given x and y and z
        '''
        # if self.array[x][y][z] == 1:
        #     print(f"get {1} at x={x} y={y} z={z}")
        return self.array[x][y][z]
    
    def setBit(self, bit:int, x:int, y:int, z:int):
        '''
        This method sets a bit at a given x and y and z
        '''

        # if bit == 1:
        #     print(f"set {bit} at x={x} y={y} z={z}")
        self.array[x][y][z] = bit

    def theta(self):
        '''
        This method should implement theta as according to Algorithm 1 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        '''
        # 1. For all pairs (x,z) such that 0≤x<5 and 0≤z<w, let 
        # C[x,z]=A[x, 0,z] ⊕ A[x, 1,z] ⊕ A[x, 2,z] ⊕ A[x, 3,z] ⊕ A[x, 4,z].
        C = [[0 for z in range(0, self.w)]  for x in range(0,5)]
        for x in range(0, 5):
            for z in range(0, self.w):
                new_bit = self.getBit(x=x,y=0,z=z) ^ self.getBit(x=x,y=1,z=z) ^ self.getBit(x=x,y=2,z=z) ^ self.getBit(x=x,y=3,z=z) ^ self.getBit(x=x,y=4,z=z)
                C[x][z] = new_bit
        # 2. For all pairs (x, z) such that 0≤x<5 and 0≤z<w let 
        # D[x,z]=C[(x-1) mod 5, z] ⊕ C[(x+1) mod 5, (z –1) mod w].
        D = [[0 for z in range(0, self.w)]  for x in range(0,5)]
        for x in range(0, 5):
            for z in range(0, self.w):
                new_bit = C[(x - 1) % 5][z] ^ C[(x + 1) % 5][(z - 1) % self.w]
                D[x][z] = new_bit
        # 3. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
        # A′[x, y,z] = A[x, y,z] ⊕ D[x,z]."
        for x in range (0, 5):
            for y in range(0, 5):
                for z in range(0, self.w):
                    bit = self.getBit(x=x,y=y,z=z) ^ D[x][z]
                    self.setBit(x=x, y=y, z=z, bit=bit)

    def rho(self):
        '''
        This method should implement rho as according to Algorithm 2 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        '''

        rho_matrix=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
        A_prime = [[[0 for z in range(0, self.w)] for y in range(0, 5)] for x in range(0, 5)]
        for x in range(0, 5):
            for y in range(0, 5):
                for z in range(0, self.w):
                    select = rho_matrix[x][y]
                    A_prime[x][y][z] = self.getBit(x, y, (z - select) % self.w)
        self.array = A_prime

    def pi(self):
        '''
        This method should implement pi as according to Algorithm 3 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        '''

        # 1. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
        # A′[x, y, z]=A[(x + 3y) mod 5, x, z].
        A_prime = [[[0 for z in range(0, self.w)] for y in range(0, 5)] for x in range(0, 5)]
        for x in range(0, 5):
            for y in range(0, 5):
                for z in range(0, self.w):
                    x_old_loc =( x + 3 * y) % 5
                    y_old_loc = x
                    A_prime[x][y][z] = self.getBit(x_old_loc, y_old_loc, z)
        self.array = A_prime

    def chi(self):
        '''
        This method should implement chi as according to Algorithm 4 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        '''
        
        A_prime = [[[0 for z in range(0, self.w)] for y in range(0, 5)] for x in range(0, 5)]
        for x in range(0, 5):
            for y in range(0, 5):
                for z in range(0, self.w):
                    xor = self.getBit(x=(x + 1) % 5, y=y, z=z) ^ 1
                    mul = xor * self.getBit(x=(x + 2) % 5, y=y, z=z)
                    A_prime[x][y][z] = self.getBit(x,y,z) ^ mul
        self.array = A_prime

    def iota(self, ir):
        '''
        This method should implement iota as according to Algorithm 6 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        
        Parameters :
            ir : int
                Which round we are on
        '''
        iota_round_constants = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

        iota_round_constant = iota_round_constants[ir]

        # 4. For all z such that 0≤z<w, let A′[0, 0,z]=A′[0, 0,z] ⊕ RC[z].
        for z in range(self.w):
            new_bit = self.getBit(0, 0, z) ^ ((iota_round_constant >> z) & 1)
            self.setBit(new_bit, 0, 0, z)

    def round(self, ir):
        '''
        This method should implement round as according to Algorithm 7 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters :
            ir : int
                Which round we are on

        Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir)
        '''
        # print(f"Before Theta : {self.getValueHandler().getHexString()}")
        self.theta() # θ
        # print(f"After Theta : {self.getValueHandler().getHexString()}")
        self.rho() # ρ
        # print(f"After Rho : {self.getValueHandler().getHexString()}")
        self.pi() # π
        self.chi() # χ
        self.iota(ir) # ι

        
class Keccak():
    '''
    This class holds the functions necessary for Keccak
    '''
    @staticmethod
    def keccak_p(message_chunk:SHA3_ValueHandler, number_rounds:int) -> SHA3_ValueHandler:
        '''
        This method should implement keccakp as according to Algorithm 7 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters :
            message_chunk : SHA3_ValueHandler
                The message chunk being processed
            number_rounds : int
                The number of rounds to run

        Returns :
            changed_chunk : SHA3_ValueHandler
                The message chunk after it has been processed
        '''

        # 1. Convert S into a state array, A, as described in Sec. 3.1.2. 
        state = SHA3_StateArray.fromValueHandler(message_chunk)

        # 2. For ir from 0 to nr, let A=Rnd(A, ir)
        for x in range(0,number_rounds):
            state.round(x)
            
        changed_chunk = state.getValueHandler()

        return changed_chunk
    
    @staticmethod
    def keccak_f(message_chunk:SHA3_ValueHandler)-> SHA3_ValueHandler:
        '''
        The method should implement keccak f as according to https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        It calls keccak_p a set number of times (24)

        Parameters :
            message_chunk : SHA3_ValueHandler
                The message chunk being processed

        Returns :
            changed_chunk : SHA3_ValueHandler
                The message chunk after it has been processed

        '''

        return Keccak.keccak_p(message_chunk, 24)
    
class SHA3():

    def __init__(self, f, digest_length, is_debug = False):
        '''
        This method initializes the SHA 3 object

        Parameters: 
            f : str
                the function name
            digest_length: int
                The size of the SHA3 digest in bits
        '''

        self.function_name = f
        self.digest_length = digest_length
        self.capacity = digest_length * 2
        self.b = 1600
        self.is_debug = is_debug

    def hashBitArray(self, bit_array:list[int]) -> SHA3_ValueHandler:
        '''
        This method takes in a bit array and creates the SHA3 hash for it

        Parameters :
            bit_array : [int]
                The array of bit that are to be hashed

        Returns :
            hash_digest : SHA3_ValueHandler
                The hash digest as a SHA3_ValueHandler
        '''
        input_handler = SHA3_ValueHandler(bit_array=bit_array)
        input_handler = input_handler.concatenate(SHA3_ValueHandler([0,1]))
        return self.sponge(input_handler)
    
    def hashString(self, string_input:str) -> SHA3_ValueHandler:
        '''
        This method takes in a bit array and creates the SHA3 hash for it

        Parameters :
            string_input : str
                The string that is to be hashed

        Returns :
            hash_digest : SHA3_ValueHandler
                The hash digest as a SHA3_ValueHandler
        '''
        input_handler = SHA3_ValueHandler.fromString(string=string_input)
        input_handler = input_handler.concatenate(SHA3_ValueHandler([0,1]))
        return self.sponge(input_handler)

    def sponge(self, input_handler:SHA3_ValueHandler) -> SHA3_ValueHandler:
        '''
        This method should implement sponge as according to Algorithm 8 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters:
            input_handler : SHA3_ValueHandler
                The input currently being processessed as a SHA3_ValueHandler
        
        Returns :
            digest : SHA3_ValueHandler
                The hash digest as a binary string
        '''
        r = self.b - self.capacity
        padded_input = input_handler.concatenate(self.addPadding(r, input_handler.bit_length))
        input_chunks:list[SHA3_ValueHandler] = padded_input.splitSegments(r)
        segment_count = len(input_chunks)
        S = SHA3_ValueHandler([0] * self.b)
        for x in range(0,segment_count):
            value_to_xor = input_chunks[x].concatenate(SHA3_ValueHandler([0]*self.capacity))
            S = S.bitwiseXor(value_to_xor)
            S = Keccak.keccak_f(S)
       
        Z = SHA3_ValueHandler(S.bit_array[:r])
        while self.digest_length > Z.bit_length:
            S = Keccak.keccak_f(S)
            Z = Z.concatenate(SHA3_ValueHandler(S.bit_array[:r]))
        return SHA3_ValueHandler(Z.bit_array[:self.digest_length])
    
    def addPadding(self, segment_length:int, message_length:int) -> SHA3_ValueHandler:
        '''
        This method should implement pad10*1 as according to Algorithm 9 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters :
            segment_length : int
                The lenth of each message segment
            message_length : int
                The length of the message

        Returns : 
            padding : SHA3_ValueHandler
                The handler for the padding to be added to the input        
        '''

        y = (-message_length - 2) % segment_length
        pad_array = [1] + [0] * y + [1]
        padding_handler = SHA3_ValueHandler(pad_array)
        return padding_handler
    
class SHA3_224(SHA3):
    '''
    This class instantiates a sha 3 object with a 224 bit digest length
    '''

    def __init__(self):
        '''
        method class instantiates a sha 3 object with a 224 bit digest length
        '''

        super().__init__(f="SHA3-224", digest_length=224)

class SHA3_256(SHA3):
    '''
    This class instantiates a sha 3 object with a 256 bit digest length
    '''

    def __init__(self):
        '''
        This method instantiates a sha 3 object with a 256 bit digest length
        '''

        super().__init__(f="SHA3-256", digest_length=256)
        
class SHA3_384(SHA3):
    '''
    This class instantiates a sha 3 object with a 384 bit digest length
    '''

    def __init__(self):
        '''
        This method instantiates a sha 3 object with a 384 bit digest length
        '''

        super().__init__(f="SHA3-384", digest_length=384)

class SHA3_512(SHA3):
    '''
    This class instantiates a sha 3 object with a 512 bit digest length
    '''
    def __init__(self):
        '''
        This method instantiates a sha 3 object with a 512 bit digest length
        '''
        
        super().__init__(f="SHA3-512", digest_length=512)

sha3_224 = SHA3_224()
sha3_256 = SHA3_256()
sha3_384 = SHA3_384()
sha3_512 = SHA3_512()
    
if __name__ == '__main__':

    handler1 = SHA3_ValueHandler([1,1,0,0,0,1,0,1])
    print(handler1.getHexString())
    handler2 = SHA3_ValueHandler([1,1,0,0,0,1,0,1,0,1,1,1,0,1,0,0])
    print(handler2.getHexString())
    handler = SHA3_ValueHandler([0,1,0,0,0,0,0,0])
    print(handler.getHexString())
    handler = SHA3_ValueHandler.fromHexString("02")
    handler_xor = handler1.bitwiseXor(handler=handler)
    print(handler_xor.bit_array)

    print(handler.bit_array)
    handler = SHA3_ValueHandler.fromHexString("A3")
    print(handler.bit_array)
    handler = SHA3_ValueHandler.fromHexString("A32E")
    print(handler.bit_array)

    handler = SHA3_ValueHandler.fromHexString("BB"*25)
    print(handler.bit_array)
    print(handler.bit_length)
    state = SHA3_StateArray.fromValueHandler(handler)
    print(state.array)
    new_handler = state.getValueHandler()
    print(new_handler.bit_array)
    print(new_handler.bit_length)
    assert handler == new_handler
