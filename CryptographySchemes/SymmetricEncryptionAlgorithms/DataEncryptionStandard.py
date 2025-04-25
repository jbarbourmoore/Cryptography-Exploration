from HelperFunctions.IntegerHandler import *

class DataEncryptionStandard():
    '''
	This class holds the necessary methods for a basic implementation of DES
    As laid out in NIST FIPS 46-3 which has since been withdrawn (Archived at https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf)
	'''

    initial_permutation_matrix = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7]
    inverse_initial_permutation_matrix = [
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25]
    expansion_matrix = [
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1]
    substitution_matrices = [
        [[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
         [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
         [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
         [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]],
        [[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
         [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
         [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
         [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]],
        [[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
         [13,  7,  0,  9,  3 , 4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
         [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
         [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]],
        [[ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
         [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
         [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
         [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]],
        [[ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
         [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
         [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
         [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]],
        [[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
         [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
         [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
         [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]],
        [[ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
         [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
         [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
         [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]],
        [[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
         [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
         [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
         [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]]]
    permutation_matrix = [
        16,  7, 20, 21,
        29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14, 
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25]
    key_first_permutation_matrix = [
        57, 49, 41, 33, 25, 17,  9,  1,
        58, 50, 42, 34, 26, 18, 10,  2,
        59, 51, 43, 35, 27, 19, 11,  3,
        60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15,  7, 62, 54, 46, 38,
        30, 22, 14,  6, 61, 53, 45, 37,
        29, 21, 13,  5, 28, 20, 12,  4]
    key_second_permutation_matrix = [
        14, 17, 11, 24,  1,  5,  3, 28,
        15,  6, 21, 10, 23, 19, 12,  4,
        26,  8, 16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]
    left_shift_schedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    def __init__(self, key, is_hex_key = False):
        '''
        This method initializes a DataEncryptionStandard with a given key

        Parameters :
            key : str
                the key for this DES
        '''

        self.key = key
        self.is_hex_key = is_hex_key

    def stringToBinaryList(self, string_message:str):
        '''
        This method converts a string message into a list of binary strings with a 64 bit length

        Parameters :
            string_message : str
                The message to be encrypted as a string

        Returns : 
            binary_list : [str]
                The message as a list of 64 bit binary strings
        '''

        length = len(string_message)
        list_of_blocks = []
        for x in range(0,length,8):
            list_of_blocks.append(string_message[x:x+8])
        
        for j in range(0,len(list_of_blocks)):
            list_of_blocks[j]=self.stringToBinary(list_of_blocks[j])
        return list_of_blocks
    
    def hexToBinaryList(self, string_message:str):
        '''
        This method converts a string message into a list of binary strings with a 64 bit length

        Parameters :
            string_message : str
                The message to be encrypted as a string

        Returns : 
            binary_list : [str]
                The message as a list of 64 bit binary strings
        '''

        length = len(string_message)
        list_of_blocks = []
        for x in range(0,length,16):
            list_of_blocks.append(IntegerHandler.fromHexString(string_message[x:x+16],0,64).getBitString())
        return list_of_blocks

    def stringToBinary(self, string:str):
        '''
        This method converts a string message a 64 bit binary string

        Parameters :
            string : str
                The message to be encrypted as a string

        Returns : 
            binary : str
                The message as a 64 bit binary string
        '''

        bit_string =  IntegerHandler.fromString(string,False,bit_length=len(string)*8).getBitString()
        if(len(bit_string) < 64):
            bit_string += '0' * (64 - len(bit_string))
        return bit_string

    def binaryToString(self,binary_str):
        '''
        This method converts a binary string back to a readable string

        Parameters :
            binary_str : str
                The binary string

        Returns :
            message_string : str
                The binary string converted into a readable string
        '''
        return IntegerHandler.fromBitString(binary_str, False,bit_length=64).getString() 
        
    
    def binaryListToString(self, binary_list):
        '''
        This method converts a binary string list back to a readable string

        Parameters :
            binary_list : str
                The binary string

        Returns :
            string : str
                The binary string list converted into a readable string
        '''

        string=""
        for i in range(0,len(binary_list)):
            string+=self.binaryToString(binary_list[i])
        return str(string)
    
    def performInitialPermutation(self, binary_string):
        '''
        This method handles the initial permutation of the message binary

        Parameters :
            binary_string : str
                The binary that is being permutated

        Returns :
            permutated_string : str
                The result of the permutation
        '''
    
        initial_permutation = [None] * 64
        
        for i in range(64):
            initial_permutation[i] = binary_string[self.initial_permutation_matrix[i] - 1]
        
        return ''.join(initial_permutation)
    
    def getBinaryKey(self):
        '''
        This method gets the DigitalEncryptionStandard key as a binary string

        Returns : 
            binary_key : str
                The key as a binary sting
        '''
        if not self.is_hex_key:
            return self.stringToBinary(self.key)
        else:
            
            return IntegerHandler.fromHexString(hex_string=self.key, little_endian=False,bit_length=len(self.key)*4).getBitString()
    
    def generateKeysForEachRound(self):
        '''
        This method generates the keys for each round using the permutation matrices and the left shift schedule

        Returns :
            keys_for_each_round : [string]
                The list of 16 keys for each round of the encryption
        '''
        
        key_binary = self.getBinaryKey()
        key_permutated = ''.join(key_binary[bit - 1] for bit in self.key_first_permutation_matrix)

        key_first_half = key_permutated[:28]
        key_second_half = key_permutated[28:]
        keys_for_each_round = []

        for i in range(0, 16):
            key_first_half = key_first_half[self.left_shift_schedule[i]:] + key_first_half[:self.left_shift_schedule[i]]
            key_second_half = key_second_half[self.left_shift_schedule[i]:] + key_second_half[:self.left_shift_schedule[i]]
            key_reformed = key_first_half + key_second_half
            key_for_round_i = ''.join(key_reformed[bit - 1] for bit in self.key_second_permutation_matrix)
            keys_for_each_round.append(key_for_round_i)
        
        return keys_for_each_round
    
    def singleRoundOfEncryption(self, left_half_current, right_half_current, key_for_round):
        '''
        This method completes the necessary steps for a single round of encryption

        Parameters :
            left_half_current : str
                The current left half of the message bits
            right_half_current : str
                The current right half of the message bits
            key_for_round : str
                The key for this round of encryption

        Returns :
            left_half_current : str
                The updated left half of the message bits after this round
            right_half_current : str
                The updated current right half of the message bits after this round
        '''

        expanded_right = ''.join([right_half_current[i - 1] for i in self.expansion_matrix])
        xor_expanded_right_and_key = ''
        for i in range(48):
            xor_expanded_right_and_key += str(int(expanded_right[i]) ^ int(key_for_round[i]))

        blocks_right = [xor_expanded_right_and_key[i:i+6] for i in range(0, 48, 6)]

        substituted_right = ''

        for i in range(8):
            row_i_right = int(blocks_right[i][0] + blocks_right[i][-1], 2)
            column_i_right = int(blocks_right[i][1:-1], 2)
            substitution_value_i_right = self.substitution_matrices[i][row_i_right][column_i_right]
            substituted_right += format(substitution_value_i_right, '04b')

        permutated_right = [substituted_right[i - 1] for i in self.permutation_matrix]

        left_half_list = list(left_half_current)

        new_right_half = ''.join([str(int(left_half_list[i]) ^ int(permutated_right[i])) for i in range(32)])

        left_half_current = right_half_current
        right_half_current = new_right_half
        return left_half_current,right_half_current
    
    def encryptSingleBlock(self, binary_message):
        '''
        This method encrypts a single 8 character block of a message

        Parameters :
            binary_message : str
                The 8 character block of the message as a binary string

        Returns : 
            binary_encrypted_message : str
                The 8 character block of the message an an encrypted binary string
        '''

        keys_for_each_round = self.generateKeysForEachRound()

        initial_permuted = self.performInitialPermutation(binary_message)
        left_half_current = initial_permuted[:32]
        right_half_current = initial_permuted[32:]

        for i in range(0, 16):

            key_for_round = keys_for_each_round[i]

            left_half_current, right_half_current = self.singleRoundOfEncryption(left_half_current, right_half_current, key_for_round)


        final_result = right_half_current + left_half_current

        encrypted_binary = ''.join([final_result[self.inverse_initial_permutation_matrix[i] - 1] for i in range(64)])
        
        return encrypted_binary
    
    def encryptMessage(self, message):
        '''
        This method encrypts a message

        Parameters :
            message : str
                The message to be encrypted

        Returns : 
            binary_encrypted_list : [str]
                A list of the encrypted binary strings in 8 character blocks
        '''

        binary_list = self.stringToBinaryList(message)
        encrypted_list = []
        for binary_string in binary_list:
            encrypted_list.append(self.encryptSingleBlock(binary_string))

        return encrypted_list
    
    def encryptHexMessage(self, message:str)->list[str]:
        '''
        This method encrypts a message

        Parameters :
            message : str
                The message to be encrypted

        Returns : 
            binary_encrypted_list : [str]
                A list of the encrypted binary strings in 8 character blocks
        '''

        binary_list = self.hexToBinaryList(message)
        result_string = ""
        for binary_string in binary_list:
            #encrypted_list.append(self.encryptSingleBlock(binary_string))
            result_string += IntegerHandler.fromBitString(self.encryptSingleBlock(binary_string),False,64).getHexString()
        return result_string
        
    def decryptSingleBlock(self, encrypted_binary):
        '''
        This method decrypts a single 8 character block of a message

        Parameters :
            encrypted_binary : str
                The 8 character block of the encrypted message as a binary string

        Returns : 
            binary_message : str
                The decrypted 8 character block of the message an an binary string
        '''
    
        keys_for_each_round = self.generateKeysForEachRound()
        
        initial_permuated = self.performInitialPermutation(encrypted_binary)
        
        left_half_current = initial_permuated[:32]
        right_half_current = initial_permuated[32:]

        for i in range(0, 16):       

            key_for_round = keys_for_each_round[15-i] 
            
            left_half_current, right_half_current = self.singleRoundOfEncryption(left_half_current, right_half_current, key_for_round)
        
        final_result = right_half_current + left_half_current

        encrypted_binary = ''.join([final_result[self.inverse_initial_permutation_matrix[i] - 1] for i in range(64)])

        return encrypted_binary
    
    def decryptMessage(self, encrypted_binary_list):
        '''
        This method decrypts an encrypted message

        Parameters :
            encrypted_binary_list : [str]
                A list of the encrypted binary strings in 8 character blocks

        Returns : 
            decrypted_message : str
                The message that has been decrypted
        '''

        decrypted_list = []
        for encrypted_binary in encrypted_binary_list:
            decrypted_list.append(self.decryptSingleBlock(encrypted_binary))
        decrypted_message = self.binaryListToString(decrypted_list)
        return decrypted_message
    
    def decryptHexMessage(self, encrypted_hex):
        '''
        This method decrypts an encrypted message

        Parameters :
            encrypted_binary_list : [str]
                A list of the encrypted binary strings in 8 character blocks

        Returns : 
            decrypted_message : str
                The message that has been decrypted
        '''
        length = len(encrypted_hex) * 4
        block_count = length // 64
        decrypted_hex = ""
        for i in range (0, block_count):
            encrypted_bits = IntegerHandler.fromHexString(encrypted_hex[i*16:i*16+16],False,64).getBitString()
            decrypted_bits = self.decryptSingleBlock(encrypted_bits)
            decrypted_hex = decrypted_hex + IntegerHandler.fromBitString(decrypted_bits,False,64).getHexString()
        # decrypted_list = []
        # for encrypted_binary in encrypted_hex:
        #     decrypted_list.append(self.decryptSingleBlock(encrypted_binary))
        # result_string = ""
        # for message in decrypted_list:
        #     result_string = result_string + IntegerHandler.fromBitString(message,False,64).getHexString()
        return decrypted_hex
    
if __name__ == '__main__':

    key = "key"
    des = DataEncryptionStandard(key)
    message ="I want to encrypt this message hopefully!"
    binary_message_list = des.stringToBinaryList(message)
    print(des.binaryListToString(binary_message_list))

    encrypted = des.encryptSingleBlock(binary_message_list[0])
    decrypted = des.decryptSingleBlock(encrypted)
    print(f"First block encrypted: {encrypted}    --->   decrypted: {decrypted}")

    entire_encrypted_message = des.encryptMessage(message=message)
    print(entire_encrypted_message)
    decrypted_message = des.decryptMessage(entire_encrypted_message)
    print(decrypted_message)
    print(f"{message} : {decrypted_message}")
    assert message == decrypted_message
    other_des = DataEncryptionStandard("wrong")
    decrypted_message_wrong_key = other_des.decryptMessage(entire_encrypted_message)
    print(decrypted_message_wrong_key)
    assert message != decrypted_message_wrong_key

    des = DataEncryptionStandard(key="0101010101010101", is_hex_key=True)
    data = "95F8A5E5DD31D900"
    encrypt_data = des.encryptHexMessage(data)
    print(encrypt_data)
    decrypt_data = des.decryptHexMessage(encrypt_data)
    print(decrypt_data)
