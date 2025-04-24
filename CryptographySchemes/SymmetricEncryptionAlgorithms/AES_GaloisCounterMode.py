from HelperFunctions.IntegerHandler import *
from CryptographySchemes.SymmetricEncryptionAlgorithms.AdvancedEncryptionStandard import *
from math import ceil

class GCM_Block(IntegerHandler):
    '''
    This is a subclass of Integer Handler specific to keeping track of the 128 bit blocks used in Galois/Counter Mode 
    '''


    def __init__(self, value = 0):
        '''
        Initializes the GCM block, setting bit length to 128 and endianess to big endian

        Parameters :
            value : int
                The value of the GCM block as an int
        '''
        super().__init__(value, False, 128)

    @staticmethod
    def fromBitArray(bit_array:list[int]):
        '''
        This method constructs a gcm block from a bit array

        Parameters :
            bit_array : [int]
                The value as a bit array

        Return :
            gcm_block : GCM_Block
                The value of the bit array as a gcm block
        '''

        int_value:int = 0
        for i in range(0,len(bit_array)):
            int_value += bit_array[i] * 2**(len(bit_array) - 1 - i)
        return GCM_Block(value=int_value)
    
    @staticmethod
    def fromHexString(hex_string:str):
        '''
        This method creates a gcm block from a hex string

        Parameters :
            hex_string : str
                The value as a hexadecimal string

        Return :
            gcm_block : GCM_Block
                The value of the bit string as a gcm_block
        '''
        hex_string = hex_string.replace(" ","")
        if len(hex_string) % 2 != 0:
            hex_string = "0" + hex_string
        int_value:int = 0
        hex_length = len(hex_string)
        for i in range(0, hex_length, 2):
            int_value += int(IntegerHandler.hexByteToInt(hex_string[i:i+2]) * pow(256,hex_length//2-1-i//2))

        return GCM_Block(value=int_value)
    
    def inc(self, variable_bit_count):
        '''
        This method increments the GCM_block value by a given amount

        Parameters :
            variable_bits : int
                The number of bits which may vary during the increment

        Returns :
            gcm_block : GCM_Block
                The new GCM Block with the incremented value
        '''
        stationary_bit_count = 128 - variable_bit_count
        stationary_bits = self.getBitArray()[:stationary_bit_count]
        variable_bits =  IntegerHandler.fromBitArray(self.getBitArray()[stationary_bit_count:], False, variable_bit_count)
        variable_bits.setValue(variable_bits.getValue()+1)

        updated_bits = stationary_bits + variable_bits.getBitArray()
        return GCM_Block.fromBitArray(updated_bits)

    def rightShift(self,shift_amount):
        '''
        This method returns the right shift

        Parameters :
            shift_amount : int
                The amount the value is being shifted to the right

        Returns :
            shift_result : IntegerHandler
                The result of the shift operation
        '''
        shift_result = self.value >> shift_amount

        return GCM_Block(shift_result)

    def blockMultiplication(self, other):
        '''
        This method performs the block multiplication for Galois Counter Mode

        Approximation of Algorithm 1 from NIST SP 800-38D Section 6.3 Multiplication Operation on Blocks
        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

        Parameters :
            other : GCM_Block
                The other GCM Block that is being multiplied with this one

        Returns :
        '''

        x = self.getValue()
        y = other.getValue()
        result = 0
        for i in range(127, -1, -1):
            result ^= x * ((y >> i) & 1)
            x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
        return GCM_Block(result)
    
class AES_GCM_128(AES128):
    '''
    This class is a subclass of AES 128 and implements the Galois / Counter Mode

    As detailed in NIST SP 800-38 D "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    '''

    def __init__(self, key:str, is_debug:bool = False):
        '''
        This method initializes the AES GCM with a given key

        Parameters :
            key : str
                The key as a hexadecimal string
            is_debug : bool, optional
                Whether the AES GCM instance is being debugged and should output intermediary values
        '''

        super().__init__(key)
        self.is_debug = is_debug
    
    def GHASH(self, hash_block:GCM_Block, input_bits:list[int]) -> GCM_Block:
        '''
        This method performs the GHASH algorithm as laid out in NIST SP-800 38D section 6.4 GHASH Function

        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

        Parameters :
            hash_block : GCM_Block
                The hash subkey for the GHASH iteration
            input_bits : [int]
                The data the GHASH is being performed on as a bit array

        Returns :
            result_block : GCM_Block
                The result of the GHASH operation on X as a GCM_Block
        '''
        # GHASH is only to be used on full blocks and the initial resulting block is 0
        number_of_blocks = len(input_bits) // 128
        result_block = GCM_Block(0)
        if self.is_debug:
            print(f"Starting GHASH blocks:{number_of_blocks} H:{hash_block.getHexString()} Y:{result_block.getHexString()}")
        
        # Go through each 128 bit block and XOR it with the previous result before multiplying with the hash subkey
        for i in range(0, number_of_blocks):
            current_input_block = GCM_Block.fromBitArray(input_bits[i*128:i*128+128])
            xor_result = bitwiseXorGCM([result_block, current_input_block])
            result_block = xor_result.blockMultiplication(hash_block)
            if self.is_debug:
                print(f"GHASH {i} -> X_i:{current_input_block.getHexString()} xor:{xor_result.getHexString()} Y:{result_block.getHexString()}")
        if self.is_debug:
            print(f"Finish GHASH -> Y:{result_block.getHexString()}")
        return result_block
    
    def GCTR(self, initial_counter_block:GCM_Block | list[int], input_bits:list[int]) -> list[int]:
        '''
        This method performs the GCTR algorithm as laid out in NIST SP-800 38D section 6.5 GCTR Function

        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

        Parameters :
            initial_counter_block : GCM_Block | [int]
                The hash subkey for the GHASH iteration as a GCM block or bit array
            input_bits : [int]
                The data the GCTR is being performed on as a bit array

        Returns :
            result_bits : [int]
                The result of the GHASH operation on X as a GCM_Block
        '''

        if input_bits == []:
            return []
        
        # determine how many 128 bit blocks of data there are and if any are incomplete
        number_full_blocks = len(input_bits) // 128
        contains_incomplete_block = len(input_bits) % 128 != 0
        if self.is_debug :
            print(f"Starting GCTR with {number_full_blocks} full blocks{" and 1 partial block" if contains_incomplete_block else ""}")

        # Ensure the counter block is formated as a GCM_Block
        if type(initial_counter_block) == list:
            counter_block = GCM_Block.fromBitArray(initial_counter_block)
        else:
            counter_block = initial_counter_block

        result_bits = []
        # Perform the GCTR Operation on all full blocks in the data and add the resulting 128 bit blocks to the output while incrementing the counter
        for i in range(0,number_full_blocks):
            current_block = GCM_Block.fromBitArray(input_bits[i*128:i*128+128])
            cypher_result_block = GCM_Block.fromHexString(self.cypher(counter_block.getHexString()))
            current_result_block = bitwiseXorGCM([cypher_result_block, current_block])
            result_bits += current_result_block.getBitArray()
            if self.is_debug:
                print(f"{i}: X:{current_block.getHexString()} Cypher:{cypher_result_block.getHexString()} Y_i:{current_result_block.getHexString()}")
            counter_block = counter_block.inc(32)

        # Perform the GCTR Operation on any partial block from the data and add the resulting less that 128 bits to the output
        # Use IntegerHandler instead of GCM Block in order to handle data under 128 bits
        if contains_incomplete_block:
            partial_handler = IntegerHandler.fromBitArray(input_bits[i*number_full_blocks:],False, len(input_bits[i*128+128:]))
            cypher_result_block = IntegerHandler.fromHexString(self.cypher(counter_block.getHexString()), False, 128)
            most_sig_bits_of_cypher = cypher_result_block.getMostSignificantBits(partial_handler.bit_length)
            current_result_handler = bitwiseXor([most_sig_bits_of_cypher, partial_handler],False, most_sig_bits_of_cypher.bit_length)
            result_bits += current_result_handler.getBitArray()
            if self.is_debug:
                print(f"Partial Block: {partial_handler.getHexString()} Cypher:{cypher_result_block.getHexString()} Y_n:{current_result_handler.getHexString()} msb:{most_sig_bits_of_cypher.getHexString()}")
        
        if self.is_debug:
            print("Finishing GCTR")
        return result_bits
    
    def authenticatedEncryption(self, initialization_vector:IntegerHandler | str | int | list[int], plain_text:IntegerHandler | str | int | list[int], additional_data:IntegerHandler | str | int | list[int], tag_length:int) -> tuple[IntegerHandler, IntegerHandler]:
        '''
        This method performs an authenticated encryption using AES Galois Counter Mode

        As laid out in NIST SP-800 38D Section 7.1 "Algorithm for the Authenticated Encryption Function"

        https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

        Parameters : 
            initialization_vector : [int] | IntegerHandler | str | int
                The initialization vector as a bit array, IntegerHandler, hex string or int
            plain_text : [int] | IntegerHandler | str | int
                The plain text to be encrypted as a bit array, IntegerHandler, hex string or int
            additional_data : [int] | IntegerHandler | str | int
                The additional data as a bit array, IntegerHandler, hex string or int
            tag_length : int
                The tag length as an int
        
        Returns :
            cypher_text : IntegerHandler
                The cypher text that was generated as an Integer_Handler object
            tag : IntegerHandler
                The tag that was generated as an Integer Handler object
        '''
        # convert all input data except for tag length into bit arrays
        initialization_vector = self.makeBitArray(initialization_vector)
        plain_text = self.makeBitArray(plain_text)
        additional_data = self.makeBitArray(additional_data)

        # initialize the hash subkey block to zero
        hash_block = GCM_Block.fromHexString(self.cypher("0"*32))
        if self.is_debug:
            print(f"Staring Authenricated Encryption with H:{hash_block.getHexString()}")

        # initialize the pre counter block as 128 bits
        if len(initialization_vector) == 96:
            j = initialization_vector + ([0] * 31) + [1]
            pre_counter_block = GCM_Block.fromBitArray(j)
        else:
            s = ceil(len(initialization_vector) / 128) * 128 - len(initialization_vector)
            to_be_ghashed = initialization_vector + ([0] * (s + 64)) + IntegerHandler(len(initialization_vector),False,64).getBitArray()
            pre_counter_block = self.GHASH(hash_block,to_be_ghashed)
        if self.is_debug:
            print(f"J_0 is {pre_counter_block.getHexString()}")

        # use GCTR in order to create the cypher text 
        counter_block = pre_counter_block.inc(32)
        cypher_text = self.GCTR(counter_block ,plain_text)

        # create and pad the bit array of the data to be GHASHed in order to create cypher blcok generate the tag
        u = ceil(len(cypher_text) / 128) * 128 - len(cypher_text)
        v = ceil(len(additional_data) / 128) * 128 - len(additional_data)
        if self.is_debug:
            print(f"lenC:{len(cypher_text)} lenA:{len(additional_data)} u_C={u} v_A={v}")
        lenalenc = GCM_Block.fromBitArray(IntegerHandler(len(additional_data),False,64).getBitArray() + IntegerHandler(len(cypher_text),False,64).getBitArray())
        padded_A = additional_data + ([0] * v)
        padded_C = cypher_text + ([0] * u)
        to_be_ghashed = padded_A + padded_C + lenalenc.getBitArray()

        # use GHASH and then GCTR in order to generate the tag for the data
        ghash_result = self.GHASH(hash_block, to_be_ghashed)
        if self.is_debug:
            print(f"S is {ghash_result.getHexString()}")
        gctr_result = self.GCTR(pre_counter_block,ghash_result.getBitArray())
        tag = gctr_result[:tag_length]
        return IntegerHandler.fromBitArray(cypher_text, False, len(cypher_text)), IntegerHandler.fromBitArray(tag, False, len(tag))
    
    def authenticatedDecryption(self, initialization_vector:IntegerHandler | str | int | list[int], cypher_text:IntegerHandler | str | int | list[int], additional_data:IntegerHandler | str | int | list[int], tag:IntegerHandler | str | int | list[int]):
        '''
        This method performs an authenticated decryption using AES Galois Counter Mode

        Parameters : 
            IV : [int] | IntegerHandler | str | int
                The initialization vector as a bit array, IntegerHandler, hex string or int
            C : [int] | IntegerHandler | str | int
                The cypher text as a bit array, IntegerHandler, hex string or int
            A : [int] | IntegerHandler | str | int
                The additional data as a bit array, IntegerHandler, hex string or int
            T : [int] | IntegerHandler | str | int
                The tag as a bit array, IntegerHandler, hex string or int
        
        Returns :
            is_authenticated : bool
                Whether the tag was able to be successfully authenticated
            unencrypted_text : IntegerHandler | None
                The unencrypted data as an IntegerHandler or None is the tag was not authenticated
        '''

        # convert all of the input into arrays of bits
        cypher_text = self.makeBitArray(cypher_text)
        initialization_vector = self.makeBitArray(initialization_vector)
        additional_data = self.makeBitArray(additional_data)
        tag = self.makeBitArray(tag)

        # initialize the hash subkey block to zero
        hash_block = GCM_Block.fromHexString(self.cypher("0"*32))
        if self.is_debug:
            print(f"Staring Authenricated Encryption with H:{hash_block.getHexString()}")

        # initialize the pre counter block as 128 bits
        if len(initialization_vector) == 96:
            j = initialization_vector + ([0] * 31) + [1]
            pre_counter_block = GCM_Block.fromBitArray(j)
        else:
            s = ceil(len(initialization_vector) / 128) * 128 - len(initialization_vector)
            to_be_ghashed = initialization_vector + ([0] * (s + 64)) + IntegerHandler(len(initialization_vector),False,64).getBitArray()
            pre_counter_block = self.GHASH(hash_block,to_be_ghashed)
        if self.is_debug:
            print(f"J_0 is {pre_counter_block.getHexString()}")

        # use GCTR in order to create the plain text 
        counter_block = pre_counter_block.inc(32)
        plain_text = self.GCTR(counter_block , cypher_text)

        # create and pad the bit array of the data to be GHASHed in order to create cypher blcok generate the tag
        u = (ceil(len(cypher_text)/128)*128 - len(cypher_text))
        v = (ceil(len(additional_data)/128)*128 - len(additional_data) )
        if self.is_debug:
            print(f"lenC:{len(cypher_text)} lenA:{len(additional_data)} u_C={u} v_A={v}")
        lenalenc = GCM_Block.fromBitArray(IntegerHandler(len(additional_data),False,64).getBitArray() + IntegerHandler(len(cypher_text),False,64).getBitArray())
        padded_A = additional_data + ([0] * v)
        padded_C = cypher_text + ([0] * u)
        to_be_ghashed = padded_A + padded_C + lenalenc.getBitArray()

        # use GHASH and then GCTR in order to generate the appropriate tag for the data
        ghash_result = self.GHASH(hash_block, to_be_ghashed)
        if self.is_debug:
            print(f"S:{ghash_result.getHexString()}")
        gctr_result = self.GCTR(pre_counter_block, ghash_result.getBitArray())
        tag_prime = gctr_result[:len(tag)]

        # comapare the tag you generated with the one provided in order to verify authenticity
        if tag_prime == tag:
            return True, IntegerHandler.fromBitArray(plain_text, False, len(plain_text))
        return False, None

    def makeBitArray(self, value) -> list[int]:
        '''
        This method ensures a value is formatted as a bit array

        Parameters : 
            value : [int] | IntegerHandler | str | int
                The value being processed as a bit array, IntegerHandler, hex string or int
        
        Returns :
            value : [int]
                The value being processed as a binary array
        '''
        if type(value) == IntegerHandler:
            value = value.getBitArray()
        elif type(value) == str:
            value = IntegerHandler.fromHexString(value, False, len(value)*4).getBitArray()
        elif type(value) == int:
            value = IntegerHandler(value, False).getBitArray()
        return value

def bitwiseXorGCM(list_of_blocks:list[GCM_Block]) -> GCM_Block:
    '''
    This method performs a bit wise xor of a list of GCM Blocks

    Parameters :
        list_of_handler : [GCM_Block]
            The blocks that are being xored
        
    Return : 
        xored_block : GCM_Block
            The GCM Block containing the result of the xor
    '''

    initial_value = 0
    for block in list_of_blocks:
        initial_value = initial_value ^ block.value

    return GCM_Block(value=initial_value)

class AES_GCM_192(AES_GCM_128):
    '''
    This class is a subclass of AES_GCM_128 with a key length of 192 bits in Galois/Counter Mode (GCM)

    GCM is detailed in NIST SP 800-38 D "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    '''
    def __init__(self, key):
        '''
        This method should initialize aes_ecb_192 with a given key

        Parameters : 
            key : str
                The 192 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 192
        self.number_key_words = 6
        self.number_of_rounds = 12
        self.keyExpansion()

class AES_GCM_256(AES_GCM_128):
    '''
    This class is a subclass of AES_GCM_128 with a key length of 256 bits in Galois/Counter Mode (GCM)

    GCM is detailed in NIST SP 800-38 D "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    '''

    def __init__(self, key):
        '''
        This method should initialize aes ecb 256 with a given key

        Parameters : 
            key : str
                The 256 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 256
        self.number_of_rounds = 14
        self.number_key_words = 8
        self.keyExpansion()
