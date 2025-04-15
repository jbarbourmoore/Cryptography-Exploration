import secrets
from HelperFunctions import EllipticCurveDetails
from HelperFunctions.EllipticCurveCalculations import EllipticCurveCalculations
from CryptographySchemes.SecureHashAlgorithm3 import SHA3_512, SHA3
from HelperFunctions.PrimeNumbers import calculateModuloInverse

class EllipticCurveDigitalSignatureAlgorithm():
    '''
    This class stores the public information for the elliptic curve digital signature algorithm
    '''

    def __init__(self, get_curve_functions:list[EllipticCurveDetails.EllipticCurveWeierstrassFormDetails], sha3:SHA3 = None, is_debug:bool=False):
        '''
        This method initializes the elliptic curve digital signature with a randomly selected curve and generator point

        Parameters :
            get_curve_functions : [function]
                The list of potential curve functions to choose from
            sha3 : SHA3, optional
                The sha3 object to use, defaults to sha3-521
            is_debug = Bool, optional
                Whether the EllipticCurveDigitalSignatureAlgorithm is being debugged and should output more detailed information (default is False)
        '''

        self.public_key_list = []
        number_of_functions = len(get_curve_functions)
        if number_of_functions == 1:
            get_curve_function = get_curve_functions[0]
        else:
            random_index = secrets.randbelow(number_of_functions)
            get_curve_function = get_curve_functions[random_index]
        
        if sha3 == None:
            self.sha3 = SHA3_512()
        else:
            self.sha3 = sha3

        self.curve_details = get_curve_function()
        self.curve = EllipticCurveCalculations(self.curve_details.a,self.curve_details.b,finite_field=self.curve_details.prime_modulus)
        self.n =self.curve_details.order
        self.length_n = len(self.intToBitString(self.n))
        self.is_debug = is_debug
        if is_debug:
            print("A elliptic curve digital signature algorithm has been initiated")
            print(f"The elliptic curve is {self.curve_details.name} and the generator point is {self.curve_details.generator_point}")

        self.generatePrivateKey()
        self.calculatePublicKey()

        if is_debug:
            print(F"Private Key: {self.private_key}")
            print(F"Public Key: {self.public_key}")

    
    def calculatePublicKey(self):
        '''
        This method calculates the public key based on the selected elliptic curve and the private key
        '''

        self.public_key = self.multiplesOfG(self.private_key)
        if self.is_debug:
            self.public_x = self.intToHexString(self.public_key[0])
            self.public_y = self.intToHexString(self.public_key[1])

    def generatePrivateKey(self):
        '''
        This method randomly generate a private key below the prime modulus of the selected curve
        '''

        self.private_key = secrets.randbelow(self.curve_details.prime_modulus)
        if self.is_debug:
            self.private = self.intToHexString(self.private_key)

    def calculateHashOfItem(self, item_to_hash:str) -> str:
        '''
        This method calculate the sha3-512 hash digest of the message and returns it as a bit string

        Parameter :
            item_to_hash : str
                The item that is being hashed

        Returns :
            hash_value : str
                The hash value of the item as a bit string
        '''

        self.hash = self.sha3.hashStringToHex(item_to_hash)
        if self.is_debug:
            print(self.hash)
        return self.hexStringToBitString(self.hash)
    
    def bitStringToHexString(self, bit_string:str) -> str :
        '''
        This method translates a bit string into a hex string 

        Parameters :
            bit_string : str
                The bit string to be translated

        Returns :
            hex_string : str
                The hex string equivalent to the bit sting
        '''

        bit_string = bit_string.replace(" ","")
        bit_len = len(bit_string)
        value = int(bit_string,2)
        hex_string = '{0:0{1}x}'.format(value,bit_len//4).upper()
        return hex_string

    def  hexStringToBitString(self, hex_string:str) -> str:
        '''
        This method translates a hex string into a bit string 

        Parameters :
            hex_string : str
                The hex_string to be translated

        Returns :
            bit_string : str
                The bit string equivalent to the hex sting
        '''

        hex_string = hex_string.replace(" ","")
        hex_len = len(hex_string)
        value = int(hex_string,16)
        bit_string = '{0:0{1}b}'.format(value,hex_len*4)
        return bit_string
    
    def getCompressedPublicKey(self) -> str:
        return self.curve.compressPointOnEllipticCurve(self.public_key)
    
    def generateSecretK(self) -> int:
        '''
        This method generates a 1 time secret value for creating a signature that is less than n
        '''
        return secrets.randbelow(self.n)
    
    def multiplesOfG(self, multiplier:int) -> tuple[int,int]:
        '''
        This method multiplies the generator point by a constant

        Parameters :
            multiplier : int
                The constant by which to multiply

        Returns : 
            result : (int, int)
                The multiplied point
        '''
        return self.curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(self.curve_details.generator_point,multiplier)
    
    def createSignature(self, message_string:str , d:int = None, k:int = None, is_debug:bool = False) -> tuple[str,str]:
        '''
        This method creates the signature (r,s) for a message

        Parameters : 
            message : str
                The message as a string
            d : int
                The private key to be used, default is your own
            k : int 
                The one time variable to be used, defaults to random generation
            is_debug : Boolean
                Whether the method is being debugged and should save intermediate values

        Returns :
            r : str
                The x coordinate of a point which is half of the signature as a hexadecimal string
            s : str
                An integer which is half of the signature as a hexadecimal string

        implemented based on Nist Fips 168-5 Section 6.4.1 "ECDSA Signature Generation Algorithm"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''
        
        bit_hash = self.calculateHashOfItem(message_string)
        hash_length = len(bit_hash)
        if hash_length > self.length_n:
            E = bit_hash[:self.length_n]
        else:
            E = bit_hash
        if d == None:
            d = self.private_key
        e = self.bitStringToInt(E)
        r = 0
        s = 0
        while r == 0 or s == 0:
            if k == None:
                k = self.generateSecretK()
            k_inv = calculateModuloInverse(k,self.n)
            R = self.multiplesOfG(k)
            R_x, R_y = R
            r_1 = self.curve.convertFieldElementToInt(R_x)
            r = r_1 % self.n
            s = k_inv * ((e + (r * d))  % self.n)  % self.n
            if r == 0 or s == 0:
                k = self.generateSecretK()
        if is_debug or self.is_debug:
            self.H = self.bitStringToHexString(bit_hash)
            self.E = self.bitStringToHexString(E)
            self.K = self.intToHexString(k)
            self.k_inv = self.intToHexString(k_inv)
            self.R_x = self.intToHexString(R_x)
            self.R_y = self.intToHexString(R_y)
            self.r = self.intToHexString(r)
            self.d = self.intToHexString(d)
            self.s = self.intToHexString(s)
            # print("Signature Has Been Succesfully Generated")
            # print(f"r: {self.r}")
            # print(f"s: {self.s}")
        return (self.intToHexString(r), self.intToHexString(s))
    
    def intToHexString(self, integer_value:int)-> str:
        return self.bitStringToHexString(self.intToBitString(integer_value))
    
    def bitStringToInt(self, bit_string:str) -> int:
        '''
        This method converts a bit string to an integer value

        Parameters : 
            bit_string : str
                The string of the bits to be converted

        Returns :
            integer_value : int
                The integer representing the converted bit string

        follows the algorithm from Nist FIPS 186.5 B.2.1 "Conversion of a Bit String to an Integer"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''
        integer_value = 0
        length = len(bit_string)
        for i in range(0, length):
            integer_value += int(bit_string[i:i+1],2)*(2**(length-1-i))
        return integer_value
    
    def intToBitString(self, int_value:int) -> str:
        '''
        This method converts an integer value to a bit string

        Parameters : 
            integer_value : int
                The integer representing the converted bit string
            
        Returns :
            bit_string : str
                The string of the bits equal to the original value

        follows the algorithm from Nist FIPS 186.5 B.2.1 "Conversion of a Bit String to an Integer"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''
        current_int = int_value
        bit_string = ""
        while current_int > 0:
            next_bit = current_int % 2
            bit_string = str(next_bit)+bit_string
            current_int //= 2
        return bit_string
    
    def intToOctetList(self, int_value:int)->list[int]:
        '''
        This method converts an integer value to an octet list
        Parameters : 
            integer_value : int
                The integer representing the converted bit string
            
        Returns :
            octet_list : str
                The octet list equal to the original value

        follows the algorithm from Nist FIPS 186-5 B.2.3 "Conversion of an Integer to an Octet String"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''

        current_int = int_value
        octet_list = []
        while current_int > 0:
            next_octet = current_int % 256
            octet_list.insert(0, next_octet)
            current_int //= 256
        return octet_list
    
    def octetListToInt(self, octet_list:list[int]) -> int:
        '''
        This method converts an octet list to an integer value

        Parameters : 
            octet_list : list[int]
                The list of octets to be converted

        Returns :
            integer_value : int
                The integer representing the converted octet list

        reversal of the algorithm from Nist 186-5 B.2.3 "Conversion of an Integer to an Octet String"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''

        integer_value = 0
        length = len(octet_list)
        for i in range(0, length):
            integer_value += octet_list[i]*(256**(length-1-i))
        return integer_value
    
    def bitStringToOctetList(self, bit_string:str, modulo:int)->list[int]:
        '''
        This method converts a bit string to an octet list

        Parameters : 
            bit_string : str
                The bit string to be converted
            modulo : int
                The modulus value for the int

        Returns :
            octet_list : [int]
                The octet list representing the bit string

        uses the algorithm from Nist 186-5 B.2.4 "Conversion of a Bit String to an Octet String"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''

        length = len(bit_string)
        length_modulo = len(self.intToBitString(modulo))
        if length < length_modulo:
            bit_string = (length_modulo - length)*"0" + bit_string
        elif length > length_modulo:
            bit_string = bit_string[:length_modulo]

        integer_value = self.bitStringToInt(bit_string)
        if integer_value > modulo:
            integer_value = integer_value % modulo
        X = self.intToOctetList(integer_value)
        return X
    
    def hexStringToInt(self, hex_string:str)-> int:
        '''
        This method converts a hex string to an int

        Parameters : 
            hex_string : str
                The hex string to be converted

        Returns :
            int_value : int
                The hex strings value as an integer
        '''

        return self.bitStringToInt(self.hexStringToBitString(hex_string))

    def verifySignature(self, message_string, signature, public_key = None, compressed=False, is_debug = False):
        '''
        This method verifies the signature using the public key, message and signature

        Parameters :
            message_string : int
                The message as that was sent with the signature
            signature : (str, str)
                The message signature sent as two strings
            public_key : int, optional
                The public key for the signature, default uses your own public key
            is_debug : Bool, optional
                Whether the method is being debuggued and should store intermediate values

        Returns : 
            is_verified : boolean
                Whether the signature was successfully verified

        implemented based on nist fips 186-5 section 6.4.2 "ECDSA Signature Verification Algorithm"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''

        if public_key == None:
            Q = self.public_key
        else:
            if compressed:
                Q = self.curve.decompressPointOnEllipticCurve(public_key,prime_modulus=2**224-2**96+1)
            else:
                Q = public_key
        # print(f"public key is {Q}")
        r, s = signature
        try:
            if type(r) != int:
                r = self.hexStringToInt(r)
            if type(s) != int:
                s = self.hexStringToInt(s)
            if type(Q[0]) != int:
                Q = (self.hexStringToInt(Q[0]), Q[1])
            if type(Q[1]) != int:
                Q = (Q[0], self.hexStringToInt(Q[1]))
        except:
            return False
        
        
        # print(f"Q is ({self.intToHexString(Q[0])}, {self.intToHexString(Q[1])})")
        bit_hash = self.calculateHashOfItem(message_string)
        hash_length = len(bit_hash)
        if hash_length > self.length_n:
            E = bit_hash[:self.length_n]
        else:
            E = bit_hash
        e = self.bitStringToInt(E)
        s_inv = calculateModuloInverse(s,self.n)
        u = e * s_inv % self.n
        v = r * s_inv % self.n

        uG = self.multiplesOfG(u)
        vQ = self.curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(Q, v)
        R_1 = self.curve.calculatePointAddition(uG, vQ)
        if R_1 == (0,0): return False
        R1_x, R1_y = R_1
        r_1 = self.curve.convertFieldElementToInt(R1_x)

        if is_debug or self.is_debug:
            self.H = self.bitStringToHexString(bit_hash)
            self.E = self.bitStringToHexString(E)
            self.Q_x = self.intToHexString(Q[0])
            self.Q_y = self.intToHexString(Q[1])
            self.sinv = self.intToHexString(s_inv)
            self.u = self.intToHexString(u)
            self.v = self.intToHexString(v)
            self.R1_x = self.intToHexString(R1_x)
            self.R1_y = self.intToHexString(R1_y)
            self.r_1 = self.intToHexString(r_1)
            self.r = self.intToHexString(r)
            self.s = self.intToHexString(s)
            self.verified = (r == r_1 % self.n)
            # if self.verified:
            #     print("The Signature Has Successfully Been Verified")
            # else:
            #     print("The Signature Failed Validation")
        if r == r_1 % self.n: return True
        else: return False
       
if __name__ == '__main__':    
    print("The example runs the elliptic curve digital signature algorithm for a given message and verifies the signature")
    print("The Elliptic Curve math is based on Weirstrass form elliptic curves and implemented in HelperFunctions.EllipticCurveCalculations")
    
    print("- - - - - - - - - - - -")

    elliptic_curve_digital_signature_algorithm = EllipticCurveDigitalSignatureAlgorithm([EllipticCurveDetails.getCurveP192,EllipticCurveDetails.getCurveP224,EllipticCurveDetails.getCurveP521,EllipticCurveDetails.getSecp256r1],is_debug=True)
 
    print("- - - - - - - - - - - -")
    
    message = "This is the message which is being signed"
    signature = elliptic_curve_digital_signature_algorithm.createSignature(message)
    
    print("- - - - - - - - - - - -")
    is_signature_valid = elliptic_curve_digital_signature_algorithm.verifySignature(message,signature)
    
    assert is_signature_valid