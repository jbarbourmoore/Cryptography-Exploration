
class AES():
    '''
    This class should include the cypher and most of the necessary components for Advanced Encryption Standard

    As laid out in nist fips 197
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    '''

    # From NIST FIPS 197 : Table 4. "SBOX(): substitution values for the byte xy (in hexadecimal format)"
    substitution_matrix = [
        [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
        [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
        [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
        [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
        [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
        [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
        [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
        [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
        [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
        [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
        [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
        [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
        [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
        [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
        [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
        [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]
    # From NIST FIPS 197 : Table 6. "INVSBOX(): substitution values for the byte xy (in hexadecimal format)""
    inverse_substitution_matrix = [
        [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
        [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
        [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
        [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
        [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
        [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
        [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
        [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
        [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
        [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
        [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
        [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
        [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
        [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
        [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]]
    # From NIST FIPS 197 Table 5. "Round constants"
    round_constants = [
        [0x01,0x00,0x00,0x00],
        [0x02,0x00,0x00,0x00],
        [0x04,0x00,0x00,0x00],
        [0x08,0x00,0x00,0x00],
        [0x10,0x00,0x00,0x00],
        [0x20,0x00,0x00,0x00],
        [0x40,0x00,0x00,0x00],
        [0x80,0x00,0x00,0x00],
        [0x1b,0x00,0x00,0x00],
        [0x36,0x00,0x00,0x00]]
    # From NIST FIPS 197 Section 5.1.3 "MixColumns()"
    mix_columns_matrix = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]]
    # From NIST FIPS 197 Section 5.3.3 "InvMixColumns()"
    inverse_mix_columns_matrix = [
        [0x0e, 0x0b, 0x0d, 0x09],
        [0x09, 0x0e, 0x0b, 0x0d],
        [0x0d, 0x09, 0x0e, 0x0b],
        [0x0b, 0x0d, 0x09, 0x0e]]
    
    def __init__(self, key):
        '''
        This method should initialize aes with a given key

        Parameters : 
            key : str
                The key for the aes algorithm
        '''
        self.block_size = 128
        self.key = key
        self.number_key_words = 0
        self.number_of_rounds = 0

    def substituteBytes(self, s):
        '''
        This method substitutes bytes according to the substitution matrix
        According to Figure 2 from NIST FIPS 197  "Illustration of SUBBYTES()"

        Parameters : 
            s : [[int]]
                The 4x4 matrix which is being substituted
                
        Returns : 
            substituted_matrix : [[int]]
                The substituted matrix
        '''

        substituted_matrix = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
        for r in range(0, 4):
            for c in range(0, 4):
                s_rc_r = s[r][c]//16
                s_rc_c = s[r][c]%16
                substituted_matrix[r][c] = self.substitution_matrix[s_rc_r][s_rc_c]
        return substituted_matrix
    
    def inverseSubstituteBytes(self, s):
        '''
        This method applies the inverse substitutes bytes according to the inverse_substitution matrix
        According to NIST FIPS Section 5.3.2 "INVSUBBYTES()"

        Parameters : 
            s : [[int]]
                The 4x4 matrix which is being substituted

        Returns : 
            substituted_matrix : [[int]]
                The substituted matrix
        '''

        substituted_matrix = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
        for r in range(0, 4):
            for c in range(0, 4):
                s_rc_r = s[r][c]//16
                s_rc_c = s[r][c]%16
                substituted_matrix[r][c] = self.inverse_substitution_matrix[s_rc_r][s_rc_c]
        return substituted_matrix

    def shiftRows(self, s):
        '''
        This method shifts rows within a 4x4 matrix s[r][c]
        According to Figure 3 "Illustration pf ShiftRows()" of Nist Fips 197

        Parameters :
            s : [[int]]
                The 4x4 matrix which is having its rows shifted
        
        Returns :
            shifted_rows : [[int]]
                The 4x4 matrix with it's rows shift
        '''
        shifted_rows = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
        shifted_rows[0][0], shifted_rows[0][1], shifted_rows[0][2], shifted_rows[0][3] = s[0][0], s[0][1], s[0][2], s[0][3]
        shifted_rows[1][0], shifted_rows[1][1], shifted_rows[1][2], shifted_rows[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
        shifted_rows[2][0], shifted_rows[2][1], shifted_rows[2][2], shifted_rows[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
        shifted_rows[3][0], shifted_rows[3][1], shifted_rows[3][2], shifted_rows[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]
        return shifted_rows
    
    def inverseShiftRows(self, s):
        '''
        This method shifts rows within a 4x4 matrix s[r][c]
        According to Figure 9. "Illustration of INVSHIFTROWS()" of Nist Fips 197

        Parameters :
            s : [[int]]
                The 4x4 matrix which is having its rows shifted
        
        Returns :
            shifted_rows : [[int]]
                The 4x4 matrix with it's rows shift
        '''
        shifted_rows = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
        shifted_rows[0][0], shifted_rows[0][1], shifted_rows[0][2], shifted_rows[0][3] = s[0][0], s[0][1], s[0][2], s[0][3]
        shifted_rows[1][0], shifted_rows[1][1], shifted_rows[1][2], shifted_rows[1][3] = s[1][3], s[1][0], s[1][1], s[1][2]
        shifted_rows[2][0], shifted_rows[2][1], shifted_rows[2][2], shifted_rows[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
        shifted_rows[3][0], shifted_rows[3][1], shifted_rows[3][2], shifted_rows[3][3] = s[3][1], s[3][2], s[3][3], s[3][0]
        return shifted_rows

    def mixColumns(self, s):
        '''
        This method mixes columns for a 4 x 4 matrix
        According to Figure 4 "Illustration of MIXCOLUMNS()" of Nist Fips 197

        Parameters :
            s : [[int]]
                The 4x4 matrix which is having its rows shifted
        '''

        mixed_columns = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
        for r in range(0,4):
            for c in range(0,4):
                first_mult = self.xTimes(s[0][c],self.mix_columns_matrix[r][0])
                second_mult = self.xTimes(s[1][c],self.mix_columns_matrix[r][1])
                third_mult = self.xTimes(s[2][c],self.mix_columns_matrix[r][2])
                fourth_mult = self.xTimes(s[3][c],self.mix_columns_matrix[r][3])
                mixed_columns[r][c] = first_mult ^ second_mult ^ third_mult ^ fourth_mult
        return mixed_columns

    def inverseMixColumns(self, s):
        '''
        This method mixes columns for a 4 x 4 matrix
        According to Figure 4 "Illustration of MIXCOLUMNS()" of Nist Fips 197

        Parameters :
            s : [[int]]
                The 4x4 matrix which is having its rows shifted
        '''

        mixed_columns = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
        for r in range(0,4):
            for c in range(0,4):
                first_mult = self.xTimes(s[0][c],self.inverse_mix_columns_matrix[r][0])
                second_mult = self.xTimes(s[1][c],self.inverse_mix_columns_matrix[r][1])
                third_mult = self.xTimes(s[2][c],self.inverse_mix_columns_matrix[r][2])
                fourth_mult = self.xTimes(s[3][c],self.inverse_mix_columns_matrix[r][3])
                mixed_columns[r][c] = first_mult ^ second_mult ^ third_mult ^ fourth_mult
        return mixed_columns

    def xTimes(self, first_byte, multiplication_factor):
        '''
        This method multiplies two hexadecimal numbers as a polynomial, ensuring the end result is still a byte
        From Nist Fips 197 Section 4.2 "Multiplication in GF(2**8)"

        Parameters :
            first_byte : int
                The first byte to be multiplied
            multiplication_factor : int 
                The factor the byte is being multiplied by
        Returns
            byte: int
                The result of the multiplication as a single byte
        '''

        if multiplication_factor == 1:
            return first_byte
        elif multiplication_factor == 2:
            temp = (first_byte << 1) & 0xff
            return temp if first_byte < 128 else temp ^ 0x1b
        else:
            if multiplication_factor%2 == 0:
                xtime = self.xTimes(first_byte, multiplication_factor//2)
                temp = (xtime << 1) & 0xff
                return temp if xtime < 128 else temp ^ 0x1b
            else:
                xtime = self.xTimes(first_byte, multiplication_factor-1)
                return xtime ^ first_byte
        
    def rotateWord(self, word):
        '''
        This method rotates a word
        As described by section 5.10 of NIST FIPS 197

        Parameters :
            word : [int,int,int,int]
                a four number word to be rotated
        '''
        new_word = [0,0,0,0]
        new_word[0],new_word[1],new_word[2],new_word[3] = word[1],word[2],word[3],word[0]
        return new_word

    def substituteWord(self, word):
        '''
        This method substitutes a word
        As described by section 5.11 of NIST FIPS 197

        Parameters :
            word : [int,int,int,int]
                a four number word to be substituted
        '''
        new_word = [0,0,0,0]
        for c in range(0, 4):
                word_c_r = word[c] // 16
                word_c_c = word[c] % 16
                new_word[c] = self.substitution_matrix[word_c_r][word_c_c]
        return new_word

    def hexStringToMatrix(self, hex_string):
        '''
        This method transforms a hex sting into a matrix of words
        '''
        matrix=[]
        for i in range(0, len(hex_string), 8):
            new_word = []
            for j in range(0,8,2):
                new_word.append(int(hex_string[i+j:i+2+j],16))
            matrix.append(new_word)
        return matrix
    
    def addRoundKey(self, s, key, is_debug=False):
        key = self.flipMatrix(key)
        s = self.flipMatrix(s)
        if is_debug:
            print("Round Key :")
            self.printMatrixAsHex(key)
            print("- - - - - - - - - - - -")
        round_key_state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
        for c in range(0, 4):
            word_to_xor = [s[0][c],s[1][c],s[2][c],s[3][c]]
            if is_debug:
                print("Column as word :")
                self.printWordAsHex(word_to_xor)
                print("Key as word :")
                self.printWordAsHex(key[c])
            xor_result_word = self.xorWords(word_to_xor,key[c])
            if is_debug:
                print("Xor result :")
                self.printWordAsHex(xor_result_word)
                print("- - - - - - - - - - - -")
            for r in range(0,4):
                round_key_state[r][c] = xor_result_word[r]
        return self.flipMatrix(round_key_state)
    
    def flipMatrix(self,matrix):
        flipped = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
        for c in range(0,4):
            for r in range(0,4):
                flipped[c][r] = matrix[r][c]
        return flipped
    
    def xorWords(self, word_1,word_2):
        '''
        This method performs a xor on two words presented as a list
        '''

        value_1 = self.wordListToWordHex(word_1)
        value_2 = self.wordListToWordHex(word_2)
        xor_value = value_1 ^ value_2
        result_word = self.valueToWordList(xor_value)
        return result_word

    def valueToWordList(self, value):
        '''
        This method transforms a value into a four byte list
        '''
        word_list = []
        hex_string = str(hex(value))[2:]
        if len(hex_string) < 8:
            hex_string = '0'*(8-len(hex_string))+hex_string
        elif len(hex_string) >8:
            hex_string = hex_string[-8:]
        for i in range(0,4):
            word_list.append(int(hex_string[i*2:i*2+2],16))
        return word_list

    def wordListToWordHex(self, word):
        '''
        This method transforms a word list into a word hex
        '''
        word_string = ''
        for value in word:
            char_string=str(hex(value))[2:]
            if len(char_string)<2:
                char_string='0'+char_string
            word_string+=char_string
        return int(word_string,16)

    def printValueAsHex(self, hex_value):
        '''
        This method prints out a single hex value followed by a comma and space
        '''

        print('{:02x}'.format(hex_value), end=', ')
    
    def printMatrixAsHex(self,matrix, number_rows = False):
        '''
        This method print out a 4x4 matrix as a formatted hex

        Parameters : 
            matrix
                The 4x4 matrix to be printed to the console
        '''

        for r in range(0,len(matrix)):
            if number_rows:
                print(f"{r}:",end=" ")
            for c in range(0, len(matrix[r])):
                self.printValueAsHex(matrix[r][c])
            print()
    def printMatrixAsHexString(self,matrix, number_rows = False):
        '''
        This method print out a 4x4 matrix as a formatted hex

        Parameters : 
            matrix
                The 4x4 matrix to be printed to the console
        '''

        for r in range(0,len(matrix)):
            for c in range(0, len(matrix[r])):
                print('{:02x}'.format(matrix[c][r]).upper(), end='')
            print("",end=" ")
        print()

    def getMatrixAsHexString(self,matrix):
        '''
        This method print out a 4x4 matrix as a formatted hex

        Parameters : 
            matrix
                The 4x4 matrix to be printed to the console
        '''
        string_hex = ""
        for r in range(0,len(matrix)):
            for c in range(0, len(matrix[r])):
                string_hex+='{:02x}'.format(matrix[c][r]).upper()
        
        return string_hex

    def printWordAsHex(self,word):
        '''
        This method print out a wor as a formatted hex

        Parameters : 
            matrix
                The word to be printed to the console
        '''

        for c in range(0, 4):
            self.printValueAsHex(word[c])
        print()
    def getWordAsHex(self,word):
        '''
        This method print out a wor as a formatted hex

        Parameters : 
            matrix
                The word to be printed to the console
        '''
        word_string = ""
        for c in range(0, 4):
            word_string+='{:02x}'.format(word[c]).upper()
        return word_string
    
    def keyExpansion(self, is_debug = False):
        '''
        This method implements the key expansion as defined by Algorithm 2 "Pseudocode for KEYEXPANSION()" in NIST FIPS 197
        '''
        expanded_key = self.hexStringToMatrix(self.key)
        if is_debug:
            self.printMatrixAsHex(expanded_key)
        for i in range(self.number_key_words,(4*self.number_of_rounds+ 4)):
            temp = expanded_key[i-1].copy()
            if is_debug:
                print("Temp: ",end="")
                self.printWordAsHex(temp)
            if i % self.number_key_words == 0:
                rotated = self.rotateWord(temp)
                if is_debug:
                    print("Rotated: ",end="")
                    self.printWordAsHex(rotated)
                substituted = self.substituteWord(rotated)
                if is_debug:
                    print("Substituted: ",end="")
                    self.printWordAsHex(substituted)
                round_constant = self.round_constants[i//self.number_key_words - 1].copy()
                if is_debug:
                    print("Round Constant: ",end="")
                    self.printWordAsHex(round_constant)
                temp = self.xorWords(substituted, round_constant)
                if is_debug:
                    print("After Xor: ",end="")
                    self.printWordAsHex(temp)
            elif self.number_key_words > 6 and i % self.number_key_words == 4:
                temp = self.substituteWord(temp)
            word_number_of_keys_ago = expanded_key[i-self.number_key_words].copy()
            new_word= self.xorWords(temp, word_number_of_keys_ago)
            if is_debug:
                self.printWordAsHex(temp)
            expanded_key.append(new_word)
        self.expanded_key = expanded_key

    def cypher(self, input, is_debug = False):
        '''
        This method applies the aes cypher to a 128 block as laid out in NIST FIPS 197 section 5.1 "Cipher()"

        Parameters :
            input : str
                a string of 128bit hex to encypher

        Returns :
            state : [[int]]
                The encyphered hex as a 4x4 matrix
        '''

        state = self.hexStringToMatrix(input)
        state = self.flipMatrix(state)

        if is_debug:
            print("Input:")
            self.printMatrixAsHexString(state)
            print("- - - - - - - - - - - -")
        state = self.addRoundKey(state, self.expanded_key[0:4])
        if is_debug:
            print("State With Round Key:")
            self.printMatrixAsHexString(state)
            print("- - - - - - - - - - - -")
        for i in range(1,self.number_of_rounds):
            if is_debug:
                print(f"Start Of Round:{i}")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
            state = self.substituteBytes(state)
            if is_debug:
                print("Substituted Bytes:")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
            state = self.shiftRows(state)
            if is_debug:
                print("Shifted Rows:")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
            state = self.mixColumns(state)
            if is_debug:
                print("Mixed Columns:")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
            state = self.addRoundKey(state, self.expanded_key[4*i:4*(i+1)])
            # if is_debug:
            #     print("Added Round Key:")
            #     self.printMatrixAsHex(state)
            #     print("- - - - - - - - - - - -")
        if is_debug:
                print("Start Of Round:")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
        state = self.substituteBytes(state)
        state = self.shiftRows(state)
        state = self.addRoundKey(state, self.expanded_key[4*self.number_of_rounds:4*(self.number_of_rounds+1)])
        return(self.getMatrixAsHexString(state))
    
    def inverseCypher(self, input, is_debug=False):
        '''
        This method applies the aes inverseCypher to a 128 block as laid out in NIST FIPS 197 section 5.3 "InvCipher()"

        Parameters :
            input : [[int]]
                The encyphered hex as a 4x4 matrix

        Returns :
            state : [[int]]
                The decyphered hex as a 4x4 matrix
        '''

        state = self.hexStringToMatrix(input)
        state = self.flipMatrix(state)
        if is_debug:
            print("Input:")
            self.printMatrixAsHexString(state)
            print("- - - - - - - - - - - -")
        
        state = self.addRoundKey(state, self.expanded_key[4*self.number_of_rounds:4*(self.number_of_rounds+1)])
        if is_debug:
            print("State With Round Key:")
            self.printMatrixAsHexString(state)
            print("- - - - - - - - - - - -")
        state = self.inverseSubstituteBytes(state)
        if is_debug:
                print("Substituted Bytes:")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
        state = self.inverseShiftRows(state)
        if is_debug:
                print("Shifted Rows:")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
        
        for i in range(self.number_of_rounds-1,0,-1):
            if is_debug:
                print(f"Start Of Round: {i}")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
            state = self.addRoundKey(state, self.expanded_key[4*i:4*(i+1)])
            if is_debug:
                print("Added Round Key:")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
            state = self.inverseMixColumns(state)
            if is_debug:
                print("Mixed Columns:")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
            state = self.inverseSubstituteBytes(state)
            if is_debug:
                print("Substituted Bytes:")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
            state = self.inverseShiftRows(state)
            if is_debug:
                print("Shifted Rows:")
                self.printMatrixAsHexString(state)
                print("- - - - - - - - - - - -")
        state = self.addRoundKey(state,self.expanded_key[0:4])
        return(self.getMatrixAsHexString(state))

class AES128(AES):
    '''
    This class is a subclass of AES with a key length of 128 bits
    '''

    def __init__(self, key):
        '''
        This method should initialize aes 128 with a given key

        Parameters : 
            key : str
                The 128 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 128
        self.number_of_rounds = 10
        self.number_key_words = 4
        self.keyExpansion(False)


class AES192(AES):
    '''
    This class is a subclass of AES with a key length of 192 bits
    '''

    def __init__(self, key):
        '''
        This method should initialize aes192 with a given key

        Parameters : 
            key : str
                The 192 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 192
        self.number_key_words = 6
        self.number_of_rounds = 12
        self.keyExpansion()
    
class AES256(AES):
    '''
    This class is a subclass of AES with a key length of 256 bits
    '''

    def __init__(self, key):
        '''
        This method should initialize aes 256 with a given key

        Parameters : 
            key : str
                The 256 bit key for the aes algorithm
        '''

        super().__init__(key)
        self.key_length = 256
        self.number_of_rounds = 14
        self.number_key_words = 8
        self.keyExpansion()

if __name__ == '__main__':

    example_aes_256_key = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4 "
    example_aes_256_key = example_aes_256_key.replace(" ","")
    aes_256 = AES256(example_aes_256_key)
    print(aes_256.key)
    print("- - - - - - - - - - - -")
    print("Mix Columns Example Matrix:")
    example_matrix = [[0xf2,0x01,0xc6,0xdb], [0x0a,0x01,0xc6,0x13],[0x22,0x01,0xc6,0x53], [0x5c,0x01,0xc6,0x45]]
    aes_256.printMatrixAsHex(example_matrix)
    mixed_columns = aes_256.mixColumns(example_matrix)
    print("Mixed Columns")
    aes_256.printMatrixAsHex(mixed_columns)
    print("- - - - - - - - - - - -")
    print("Substitute Example Matrix:")
    example_matrix = [[0x53,0x01,0xc6,0xdb], [0x0a,0x01,0xc6,0x13],[0x22,0x01,0xc6,0x53], [0x5c,0x01,0xc6,0x45]]
    aes_256.printMatrixAsHex(example_matrix)
    substitution_matrix = aes_256.substituteBytes(example_matrix)
    print("Substituted:")
    aes_256.printMatrixAsHex(substitution_matrix)
    print("- - - - - - - - - - - -")
    print("Substitute Example Word: ")
    example_word = [0x53, 0xf2, 0x12, 0x32]
    aes_256.printWordAsHex(example_word)
    substituted = aes_256.substituteWord(example_word)
    print("Substituted:")
    aes_256.printWordAsHex(substituted)
    print("- - - - - - - - - - - -")
    print("Rotate Example Word: ")
    example_word = [0x53, 0xf2, 0x12, 0x32]
    aes_256.printWordAsHex(example_word)
    rotated = aes_256.rotateWord(example_word)
    print("Rotated:")
    aes_256.printWordAsHex(rotated)
    print("- - - - - - - - - - - -")
    print("Key Expansion for AES 128")
    aes_128 = AES128("2b7e151628aed2a6abf7158809cf4f3c")
    aes_128.printMatrixAsHex(aes_128.expanded_key,True)
    print("- - - - - - - - - - - -")
    print("Key Expansion for AES 192")
    example_aes_192_key = "8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b"
    example_aes_192_key = example_aes_192_key.replace(" ","")
    aes_192 = AES192(example_aes_192_key)
    aes_192.printMatrixAsHex(aes_192.expanded_key,True)
    print("- - - - - - - - - - - -")
    print("Key Expansion for AES 256")
    aes_256.printMatrixAsHex(aes_256.expanded_key,True)
    hextoencrypt = "2b7e151628aed2a6abf7158809cf4f3c"

    print("- - - - - - - - - - - -")
    print(f"Working on xTimes :")
    print(f"{2}  : {hex(aes_128.xTimes(0x57,0x02))} should be 0xae")
    print(f"{4}  : {hex(aes_128.xTimes(0x57,0x04))} should be 0x47")
    print(f"{8}  : {hex(aes_128.xTimes(0x57,0x08))} should be 0x8e")
    print(f"{10} : {hex(aes_128.xTimes(0x57,0x10))}  should be  0x7")
    print(f"{20} : {hex(aes_128.xTimes(0x57,0x20))}  should be  0xe")
    print(f"{40} : {hex(aes_128.xTimes(0x57,0x40))} should be 0x1c")
    print(f"{80} : {hex(aes_128.xTimes(0x57,0x80))} should be 0x38")
    print(f"{13} : {hex(aes_128.xTimes(0x57,0x13))} should be 0xfe")
    print("- - - - - - - - - - - -")
    print("Expanded Key for AES 128")
    aes_128.printMatrixAsHex(aes_128.expanded_key,True)
    print("- - - - - - - - - - - -")
    hextoencrypt ="3243f6a8885a308d313198a2e0370734"
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    aes_128 = AES128(key=key)
    print(f"Encrypting With AES 128 : {hextoencrypt}")
    encrypted = aes_128.cypher(hextoencrypt)
    print("- - - - - - - - - - - -")
    aes_128.printMatrixAsHex(encrypted)
    print("- - - - - - - - - - - -")
    hextoencrypt = "6BC1BEE22E409F96E93D7E117393172"
    print(f"Encrypting With AES 128 : {hextoencrypt}")
    encrypted = aes_128.cypher(hextoencrypt)
    aes_128.printMatrixAsHex(encrypted)
    print("- - - - - - - - - - - -")
    cypher_text = "3AD77BB40D7A3660A89ECAF32466EF97"
    key = ("2B7E151628AED2A6ABF7158809CF4F3C")
    aes_128 = AES128(key)
    print(f"Decrypting With AES 128 : {cypher_text}")
    decrypted = aes_128.inverseCypher(cypher_text)
    aes_128.printMatrixAsHexString(decrypted)
    cypher_text = "F5D3D58503B9699DE785895A96FDBAAF"
    print(f"Decrypting With AES 128 : {cypher_text}")
    decrypted = aes_128.inverseCypher(cypher_text)
    aes_128.printMatrixAsHexString(decrypted)
    cypher_text = "43B1CD7F598ECE23881B00E3ED030688"
    print(f"Decrypting With AES 128 : {cypher_text}")
    decrypted = aes_128.inverseCypher(cypher_text)
    aes_128.printMatrixAsHexString(decrypted)
    cypher_text = "7B0C785E27E8AD3F8223207104725DD4"
    print(f"Decrypting With AES 128 : {cypher_text}")
    decrypted = aes_128.inverseCypher(cypher_text)
    aes_128.printMatrixAsHexString(decrypted)
    print("- - - - - - - - - - - -")
    hextoencrypt = "6BC1BEE22E409F96E93D7E117393172"
    print(f"Encrypting With AES 128 : {hextoencrypt}")
    encrypted = aes_128.cypher(hextoencrypt)
    aes_128.printMatrixAsHexString(encrypted)
    print("- - - - - - - - - - - -")
    hextoencrypt = "3243f6a8885a308d313198a2e0370734"
    print(f"Encrypting With AES 128 : {hextoencrypt}")
    encrypted = aes_128.cypher(hextoencrypt)
    aes_128.printMatrixAsHexString(encrypted)
    print("- - - - - - - - - - - -")
    cypher_text = "3925841D02DC09FBDC118597196A0B32"
    print(f"Decrypting With AES 128 : {cypher_text}")
    decrypted = aes_128.inverseCypher(cypher_text)
    aes_128.printMatrixAsHexString(decrypted)
    print("- - - - - - - - - - - -")
    hextoencrypt = "6BC1BEE22E409F96E93D7E117393172A"
    print(f"Encrypting With AES 128 : {hextoencrypt}")
    encrypted = aes_128.cypher(hextoencrypt)
    aes_128.printMatrixAsHexString(encrypted)
    hextoencrypt = "AE2D8A571E03AC9C9EB76FAC45AF8E51"
    print(f"Encrypting With AES 128 : {hextoencrypt}")
    encrypted = aes_128.cypher(hextoencrypt)
    aes_128.printMatrixAsHexString(encrypted)
    hextoencrypt = "30C81C46A35CE411E5FBC1191A0A52EF"
    print(f"Encrypting With AES 128 : {hextoencrypt}")
    encrypted = aes_128.cypher(hextoencrypt)
    aes_128.printMatrixAsHexString(encrypted)
    hextoencrypt = "F69F2445DF4F9B17AD2B417BE66C3710"
    print(f"Encrypting With AES 128 : {hextoencrypt}")
    encrypted = aes_128.cypher(hextoencrypt)
    aes_128.printMatrixAsHexString(encrypted)
    print("- - - - - - - - - - - -")
    print(f"Encrypting With AES 256 : {hextoencrypt}")
    encrypted = aes_256.cypher(hextoencrypt)
    aes_256.printMatrixAsHexString(encrypted)
    cypher_text = "23304B7A39F9F3FF067D8D8F9E24ECC7"
    print(f"Decrypting With AES 256 : {cypher_text}")
    decrypted = aes_256.inverseCypher(cypher_text)
    aes_256.printMatrixAsHexString(decrypted)
    print("- - - - - - - - - - - -")