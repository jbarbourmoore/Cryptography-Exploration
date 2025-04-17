import secrets
from HelperFunctions import EllipticCurveDetails
from HelperFunctions.EllipticCurveCalculations import EdwardsCurveCalculation
from CryptographySchemes.SecureHashAlgorithm3 import SHA3_512, SHA3
from HelperFunctions.PrimeNumbers import calculateModuloInverse
from HelperFunctions.IntegerHandler import *
import hashlib

class EdwardsCurveDigitalSignatureAlgorithm():
    '''
    This class stores the public information for the edwards curve digital signature algorithm
    '''

    def __init__(self, private_key = None, useEdwards25519 = True, is_debug:bool=False, print_excess_error:bool=False):
        '''
        This method initializes the elliptic curve digital signature with a randomly selected curve and generator point

        Parameters :
            curve : EdwardsCurveCalculation
                The edwards curve being used for EdDSA
            is_debug = Bool, optional
                Whether the EllipticCurveDigitalSignatureAlgorithm is being debugged and should output more detailed information (default is False)
        '''

        self.public_key_list = []
        if useEdwards25519:
            self.curve = EllipticCurveDetails.getEdwards25519()
            self.b = 256
            self.number_of_octets = self.b//8
            self.requested_security_strength = 128
            self.H = hashlib.sha512 
            self.is_25519 = True
            self.is_448 = False
        else:
            self.curve = EllipticCurveDetails.getEdwards448
            self.b = 456
            self.number_of_octets = self.b//8
            self.requested_security_strength = 224
            self.H = hashlib.shake_256
            self.is_25519 = False
            self.is_448 = True

        self.n = self.curve.n
        #self.length_n = len(self.intToBitString(self.n))
        self.is_debug = is_debug
        self.print_excess_output = print_excess_error
        if is_debug:
            print("A elliptic curve digital signature algorithm has been initiated")
            self.curve.printEllipticCurveEquation()
        if private_key == None:
            succcessfully_generated = False
            #for i in range(0,3):
            while not succcessfully_generated:
                self.keyPairGeneration()
                decoded_point = self.decodePoint(self.Q)
                if decoded_point == self.public_key_point:
                    succcessfully_generated = True
                else:
                    if print_excess_error:
                        print("Retrying Key Generation")
        else:
            self.private_key = private_key
            self.calculatePublicKey()
        if is_debug:
            print(F"Private Key: {self.private_key}")
            print(F"Public Key: {self.public_key.getHexString()}")

    def keyPairGeneration(self):
        '''
        This method generates a random private key and then calculates the matching public key
        '''

        self.private_key = None
        self.Q = None
        self.generatePrivateKey()
        self.calculatePublicKey()
        while self.private_key == None or self.Q == None:
            try:
                self.generatePrivateKey()
                self.calculatePublicKey()
            except:
                pass
            
    
    def calculatePublicKey(self):
        '''
        This method calculates the public key based on the selected edwards curve, hash and the private key
        '''

        self.H_d = IntegerHandler.fromHexString(self.H(self.private.getBytes()).hexdigest(),little_endian=True,bit_length=self.b*2)
        if self.is_25519:
            self.hdigest1 = [self.H_d.getBitArray()[i] for i in range(0,self.b)]
            self.hdigest1[0] = 0
            self.hdigest1[1] = 0
            self.hdigest1[2] = 0
            self.hdigest1[self.b - 2] = 1
            self.hdigest1[self.b - 1] = 0
            
        elif self.is_448:
            self.hdigest1 = [self.H_d.getBitArray()[i] for i in range(0,self.b)]
            self.hdigest1[0] = 0
            self.hdigest1[1] = 0
            self.hdigest1[self.b - 9] = 1
        self.hdigest1 = IntegerHandler.fromBitArray(self.hdigest1,little_endian=True,bit_length= self.b)
        self.s = self.hdigest1.value
        self.public_key_point = self.multiplesOfG(self.s)
        self.Q = self.encodePoint(self.public_key_point)
        self.public_key = self.Q

    def encodePoint(self, point:tuple[int,int]) -> list[int]:
        '''
        This method encodes a point (x, y) as a list of octets as ints

        Parameters :
            point : (int,int)
                The point to encode

        Returns :
            encoded_point : [int]
                The encoded point as a list of octets as ints
        '''

        x_handler = IntegerHandler(point[0] % self.curve.p,little_endian=True,bit_length=self.b)
        print(x_handler.getBitArray()[0])
        # get the least significant bit of x
        x_0 = x_handler.getLeastSignificantBit()

        y_handler = IntegerHandler(point[1] % self.curve.p,little_endian=True,bit_length=self.b)
        print(f"Y before bit set = {y_handler.value} x_0 = {x_0}")
        # set the most significant bit of y to the bit from x
        
        y_max = y_handler.setMostSignificantBit(x_0)
        print(f"Y after bit set = {y_handler.value}  y_max = {y_max}")

        return y_handler
    
    def singleBitStringToOctetInt(self, bit_string: str) -> int:
        '''
        This method returns the value of a single octet from a bit string

        Parameters :
            bit_string : str
                The octet as a bit string (b[0] is the least significant bit)

        Returns : 
            int_value : int
                The integer value for the octet from the bit string
        '''

        int_value = 0
        for i in range(0, len(bit_string)):
            int_value += 2**i * int(bit_string[i], 2)
        return int_value
    
    # def getMostSignificantBitInOctetAndResetIt(self, octet: int) -> tuple[int,int]:
    #     '''
    #     This method gets the most significant bit in an octet and resets it to 0

    #     Parameters :
    #         octet : int
    #             The octet's value as an integer
           
    #     Returns :
    #         most_sig_bit : str
    #             The most significant bit of the octet as a string
    #         octet_value : int
    #             The octet's value with the new zeroed most significant bit
    #     '''

    #     bit_string = self.singleOctetToBitString(octet)
    #     most_sig_bit = bit_string[-1]
    #     bit_string = bit_string[0:len(bit_string)-1]+"0"
    #     octet_value = self.singleBitStringToOctetInt(bit_string)
    #     return most_sig_bit, octet_value

    def singleOctetToBitString(self, int_value:int) -> str:
        '''
        This method translate the integer value of an octet into the corresponding 8 bit string

        Parameters :
            int_value : int
                The integer value of the octet

        Returns :   
            bit_string : str
                The corresponding 8 bit string for the octet
                (b[0] is the least significant bit)
        '''

        bit_string = ""
        for i in range(0,8):
            bit_string = bit_string+str(int_value % 2)
            int_value //= 2
        return bit_string

    # def bitArrayToOctetArray(self, bit_array:list[int]) -> list[int]:
    #     '''
    #     This method translates a bit array into an octet array of integer values

    #     a[0] is the least significant bit / octet
    #     length of octet array is 1//8 the length of the bit array

    #     Parameters :
    #         bit_array : [int]
    #             a bit array of 0s and 1s

    #     Returns :
    #         octet_array :
    #             an array of octets with values between 0 and 255
    #     '''

    #     length = len(bit_array) // 8
    #     octet_array = [0 for _ in range(0,length)]
    #     for i in range(0,length):
    #         integer_value = 0
    #         for j in range(0,8):
    #             integer_value += bit_array[i*8+j]*2**j
    #         octet_array[i]=integer_value
    #     return octet_array

    # def hexStringToBitArray(self, hex_string: str) -> list[int]:
    #     '''
    #     This method translates a hex string into a bit array

    #     bit array is 4 times the length of hexstring and h[0] and b[0] are the least significant

    #     Parameters :
    #         hex_string : str
    #             The value as as a hex string

    #     Returns :
    #         bit_array : [int]
    #             The value as an array of bits
    #     '''

    #     length = len(hex_string) * 4
    #     bit_array = [0 for _ in range(0, length)]
    #     for i in range(0, len(hex_string)):
    #         int_value = int(hex_string[i],16)
    #         for j in range(0,4):
    #             bit_array[i*4+j] = int_value % 2
    #             int_value //= 2
    #     return bit_array
    
    # def bitArrayToHexString(self, bit_array:list[int]) -> str:
    #     '''
    #     This method translates a bit array into a hex string

    #     Parameters :
    #         bit_array : [int]
    #             The value as an array of ints

    #     Returns :
    #         hex_string :
    #             The value as a hexadecimal string
    #     '''
    #     if len(bit_array) % 4 !=0:
    #         bit_array = bit_array + [0]*(4 - len(bit_array) % 4 )
    #     length = len(bit_array) // 4
    #     hex_string = ""
    #     for i in range(0, length):
    #         int_value = 0
    #         for j in range(0,4):
    #             int_value+=bit_array[i*4+j] * 2**j
    #         hex_string += hex(int_value)
    #     return hex_string

    def generatePrivateKey(self):
        '''
        This method randomly generate a private key below the prime modulus of the selected curve
        '''

        self.private = IntegerHandler(secrets.randbelow(self.curve.p), True, self.b)

        if self.is_debug:
            self.private_key = self.private.getHexString()

    def calculateHashOfIntegerHandler(self, item_to_hash:IntegerHandler) -> IntegerHandler:
        '''
        This method calculate the sha3-512 hash digest of the message and returns it as a bit string

        Parameter :
            item_to_hash : IntegerHandler
                The IntegerHandler that is being hashed

        Returns :
            hash_value : IntegerHandler
                The hash value of the item as an intger handler
        '''
        self.hash = IntegerHandler.fromHexString(self.H(item_to_hash.getBytes()).hexdigest(),little_endian=True, bit_length=512)
        if self.is_debug:
            print(f"The hash is {self.hash.getHexString()} and message length was {item_to_hash.bit_length}")
        return self.hash
    
    # def bitStringToHexString(self, bit_string:str) -> str :
    #     '''
    #     This method translates a bit string into a hex string 

    #     Parameters :
    #         bit_string : str
    #             The bit string to be translated

    #     Returns :
    #         hex_string : str
    #             The hex string equivalent to the bit sting
    #     '''
    #     bit_string = bit_string.replace(" ","")
    #     if len(bit_string) % 4 != 0:
    #         bit_string = bit_string+"0"*(4-len(bit_string)%4)
    #     hex_length = len(bit_string) // 4
    #     hex_string = ""
    #     for i in range(0, hex_length):
    #         int_value = 0
    #         for j in range(0, 4):
    #             int_value += int(bit_string[i*4+j]) * 2**j
    #         hex_string += hex(int_value)[2:].upper()
    #     return hex_string

    # def hexStringToBitString(self, hex_string:str) -> str:
    #     '''
    #     This method translates a hex string into a bit string 

    #     Parameters :
    #         hex_string : str
    #             The hex_string to be translated

    #     Returns :
    #         bit_string : str
    #             The bit string equivalent to the hex sting
    #     '''
    #     hex_string = hex_string.replace(" ","")

    #     bit_string = ""
    #     for i in range(0, len(hex_string)):
    #         int_value = int(hex_string[i],16)
    #         bit_string_chunk = ""
    #         for _ in range(0, 4):
    #             bit_string_chunk =str(int_value % 2)+bit_string_chunk
    #             int_value = int_value // 2
    #         bit_string+=bit_string_chunk
    #     return bit_string
    
    def decodePoint(self, coded_point: IntegerHandler | str | list[int]) -> tuple[int]:
        '''
        this method decodes a point 

        Parameters :
            coded_point : IntegerHandler or str or [int]
                The coded point as an integer handler, a hexadecimal string or as an octet list

        Returns :
            point : (int, int)
                The decoded point as a tuple with two ints

        From section 7.3 "Decoding" of Nist Fips 186.5
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''

        d,a,p = self.curve.d,self.curve.a,self.curve.p

        # translate the coded point into an octet list if it is an hex string
        if type(coded_point) == str:
            coded_point = IntegerHandler.fromHexString(coded_point, True, self.b)
        if type(coded_point) == list:
            coded_point = IntegerHandler.fromOctetList(coded_point, True, self.b)
        

        x_0 = coded_point.setMostSignificantBit(0)
        if self.print_excess_output:
            print(f"The y is now {coded_point.value} and x_0 is now {x_0}")

        y = coded_point.value
        if y > self.curve.p:
            if self.print_excess_output:
                print("Error decoding y")
            return None
        u = (y**2 % p - 1) % p
        v = ((d * y**2 % p) - a) % p

        # find the square roots
        if p % 4 == 3:
            #this should be for ed448
            exp = ((p - 3) % p // 4) % p
            cand_root = (u**5 % p) * (v**3 % p) % p
            cand_root = pow(cand_root,exp,p)
            cand_root = cand_root * ((u**3 % p) * v % p)
            cand_root = cand_root % p
            if (cand_root**2 % p) * v % p == u:
                root =  cand_root
            else:
                if self.print_excess_output:
                    print("No square root")
                return None
        elif p % 8 == 5:
            # this should be for ed22519
            exp = ((p - 5) % p // 8) % p
            cand_root = (u % p) * (v**7 % p) % p
            cand_root = pow(cand_root, exp, p)
            cand_root = cand_root * ((v**3 % p) * u % p)
            cand_root = cand_root % p
            if (cand_root**2 % p) * v % p == u % p:
                root =  cand_root
            elif (cand_root**2 % p) * v % p == -u % p:
                exp = (p - 1) // 4 % p
                root = cand_root * (pow(2,exp,p)) % p
            else:
                if self.print_excess_output:
                    print("No square root")
                return None
        
        if x_0 == 0 and root == 0:
            if self.print_excess_output:
                print("Decoding Failed, x_0 and root are both zero")
            return None
        else :
            if root % 2 == x_0:
                print(f"root is {root}")
                return (root, y)
            else:
                print(f"root is {p - root}")
                return ((p - root) % p, y)
   
    # def generateSecretK(self) -> int:
    #     '''
    #     This method generates a 1 time secret value for creating a signature that is less than n

    #     Returns :
    #         secret_number : int
    #             a secret integer value less than n
    #     '''
    #     return secrets.randbelow(self.n)
    
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
        point =  self.curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(self.curve.getGeneratorPoint(),multiplier)
        return point
    
    def createSignature(self, message_bit_string:str , d:int = None, is_debug:bool = False) -> tuple[str,str]:
        '''
        This method creates the signature (r,s) for a message

        Parameters : 
            message_bit_string : str
                The message as a bit string
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
        
        message_handler =  IntegerHandler.fromBitString(message_bit_string, little_endian=True, bit_length=len(message_bit_string))       
        
        if d == None:
            d = self.private
            H_d = self.H_d
        else:
            d = IntegerHandler(d, True, self.b)
            H_d = self.calculateHashOfIntegerHandler(d)

        self.hdigest2 = IntegerHandler.fromBitArray([H_d.getBitArray()[i] for i in range(self.b,self.b*2)], little_endian=True, bit_length=self.b)
        hashable_handler = concatenate([self.hdigest2,message_handler], little_endian=True)
        message_hash = self.calculateHashOfIntegerHandler(hashable_handler)
        r = message_hash.value
        self.hdigest1 = IntegerHandler.fromBitArray([H_d.getBitArray()[i] for i in range(0,self.b)], little_endian=True, bit_length=self.b)
        s = self.hdigest1.value
        point_rG = self.multiplesOfG(r)
        R = self.encodePoint(point_rG)
        Q =  self.Q

        RQM_handler = concatenate([R,Q,message_handler], True)
        H_RQM = self.calculateHashOfIntegerHandler(RQM_handler)
        digest = H_RQM.value
        S = (r + digest * s) % self.n
        S = IntegerHandler(S,True,self.b)
        signature = concatenate([R,S],True)

        print(f"R is {R.getHexString(add_spacing=8)} length is {R.bit_length}")
        print(f"S is {S.getHexString(add_spacing=8)} length is {S.bit_length}")
        return signature
    
    # def bitArrayToBitString(self, bit_array:list[int]) -> str:
    #     '''
    #     This method translates a bit array into a bit string
    #     '''
    #     bit_string = ""
    #     for bit in bit_array:
    #         bit_string += str(bit)
    #     return bit_string

    # def bitStringToBitArray(self, bit_string:str) -> list[int]:
    #     '''
    #     This method translates a bit string into a bit array
    #     '''
    #     bit_array = []
    #     for bit in bit_string:
    #         bit_array.append(int(bit,2))
    #     return bit_array
    
    # def intToHexString(self, integer_value:int)-> str:
    #     return self.bitStringToHexString(self.intToBitString(integer_value))
    
    # def bitStringToInt(self, bit_string:str) -> int:
    #     '''
    #     This method converts a bit string to an integer value

    #     Parameters : 
    #         bit_string : str
    #             The string of the bits to be converted

    #     Returns :
    #         integer_value : int
    #             The integer representing the converted bit string

    #     follows the algorithm from Nist FIPS 186.5 B.2.1 "Conversion of a Bit String to an Integer"
    #     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
    #     '''
    #     integer_value = 0
    #     length = len(bit_string)
    #     for i in range(0, length):
    #         integer_value += int(bit_string[i],2)*(2**(i))
    #     return integer_value
    
    # def intToBitString(self, int_value:int,length:int = None) -> str:
    #     '''
    #     This method converts an integer value to a bit string

    #     Parameters : 
    #         integer_value : int
    #             The integer representing the converted bit string
            
    #     Returns :
    #         bit_string : str
    #             The string of the bits equal to the original value

    #     follows the algorithm from Nist FIPS 186.5 B.2.1 "Conversion of a Bit String to an Integer"
    #     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
    #     '''
    #     current_int = int_value
    #     bit_string = ""
    #     while current_int > 0:
    #         next_bit = current_int % 2
    #         bit_string = bit_string+str(next_bit)
    #         current_int //= 2

    #     if length != None and length > len(bit_string):
    #         bit_string = bit_string + "0"*(length - len(bit_string))
    #     if length == None and len(bit_string) % 8 != 0:
    #         bit_string = bit_string + "0"*(8 - len(bit_string)%8)
    #     return bit_string
    
    # def intToOctetList(self, int_value:int)->list[int]:
    #     '''
    #     This method converts an integer value to an octet list
    #     Parameters : 
    #         integer_value : int
    #             The integer representing the converted bit string
            
    #     Returns :
    #         octet_list : str
    #             The octet list equal to the original value

    #     follows the algorithm from Nist FIPS 186-5 B.2.3 "Conversion of an Integer to an Octet String"
    #     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
    #     '''

    #     current_int = int_value
    #     octet_list = []
    #     while current_int > 0:
    #         next_octet = current_int % 256
    #         current_int //= 256
    #         octet_list.append(next_octet)
    #     if len(octet_list)< self.number_of_octets:
    #         for i in range(0,self.number_of_octets-len(octet_list)):
    #             octet_list.insert(0,0)
    #     return octet_list
    
    # def octetListToInt(self, octet_list:list[int]) -> int:
    #     '''
    #     This method converts an octet list to an integer value

    #     Parameters : 
    #         octet_list : list[int]
    #             The list of octets to be converted

    #     Returns :
    #         integer_value : int
    #             The integer representing the converted octet list

    #     reversal of the algorithm from Nist 186-5 B.2.3 "Conversion of an Integer to an Octet String"
    #     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
    #     '''

    #     integer_value = 0
    #     length = len(octet_list)
    #     for i in range(0, length):
    #         integer_value += octet_list[i]*(256**(i))
    #     return integer_value
    
    # def octetListToBitString(self,octet_list:list[int]) -> str:
    #     '''
    #     This method translates an octet list into a bit string
    #     '''

    #     bit_string = ""
    #     for octet in octet_list:
    #         octet_bit = self.singleOctetToBitString(octet)
    #         bit_string+=octet_bit
    #     return bit_string
    
    # def bitStringToOctetList(self, bit_string:str, modulo:int=None)->list[int]:
    #     '''
    #     This method converts a bit string to an octet list

    #     Parameters : 
    #         bit_string : str
    #             The bit string to be converted
    #         modulo : int
    #             The modulus value for the int

    #     Returns :
    #         octet_list : [int]
    #             The octet list representing the bit string

    #     uses the algorithm from Nist 186-5 B.2.4 "Conversion of a Bit String to an Octet String"
    #     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
    #     '''
    #     if modulo == None:
    #         length_modulo = len(bit_string)
    #         is_modulo = False
    #     else:
    #         length_modulo = len(self.intToBitString(modulo))

    #     length = len(bit_string)
    #     if length < length_modulo:
    #         bit_string = (length_modulo - length)*"0" + bit_string
    #     elif length > length_modulo:
    #         bit_string = bit_string[:length_modulo]

    #     integer_value = self.bitStringToInt(bit_string)
    #     if is_modulo and integer_value > modulo:
    #         integer_value = integer_value % modulo
    #     X = self.intToOctetList(integer_value)
    #     return X
    
    # def hexStringToInt(self, hex_string:str)-> int:
    #     '''
    #     This method converts a hex string to an int

    #     Parameters : 
    #         hex_string : str
    #             The hex string to be converted

    #     Returns :
    #         int_value : int
    #             The hex strings value as an integer
    #     '''

    #     return self.bitStringToInt(self.hexStringToBitString(hex_string))

    def verifySignature(self, message_bit_string:str, signature:str, Q:str, is_debug = False):
        '''
        This method verifies the signature using the message bit string, signature and purported Q

        Parameters :
            message_bit_string : str
                The message as that was sent with the signature as a bit string
            signature : str
                The message signature as a hex string R || S
            Q : str
                Purported signature key Q as a hex string 
            is_debug : Bool, optional
                Whether the method is being debuggued and should store intermediate values

        Returns : 
            is_verified : boolean
                Whether the signature was successfully verified

        implemented based on nist fips 186-5 section 6.4.2 "ECDSA Signature Verification Algorithm"
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
        '''
        message_handler =  IntegerHandler.fromBitString(message_bit_string, little_endian=True, bit_length=len(message_bit_string))       

        if type(signature) == IntegerHandler:
            signature_handler = signature
        else:
            signature_handler = IntegerHandler.fromHexString(signature,little_endian=True,bit_length=2*self.b)
        R, S = signature_handler.splitBits()
        print(R.bit_length)
        if type(Q) == str:
            Q = IntegerHandler.fromHexString(Q,True,self.b)

        print(Q.bit_length)
        t = S.value

        R_point = self.decodePoint(R.getHexString())
        Q_point = self.decodePoint(Q.getHexString())

        if R_point == None or Q_point == None:
            return False
        
        rqm = concatenate([R,Q,message_handler],True)
        digest = self.calculateHashOfIntegerHandler(rqm)
        u = digest.value

        t_G = self.multiplesOfG(t)
        u_Q = self.curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(Q_point,u)
        R_u_Q = self.curve.calculatePointAddition(u_Q,R_point)
        print(t_G)
        print(R_u_Q)
        
        if t_G == R_u_Q:
            return True
        else :
            return False

if __name__ == '__main__':    
    print("The example runs the elliptic curve digital signature algorithm for a given message and verifies the signature")
    print("The Elliptic Curve math is based on Weirstrass form elliptic curves and implemented in HelperFunctions.EllipticCurveCalculations")
    
    print("- - - - - - - - - - - -")

    eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=True,print_excess_error=True)
    octet = 64
    # print(f"starting octet value = {octet}")
    # octet_bit_set = eddsa.setMostSignificantBitInOctet(octet,"1")
    # print(f"octet with its most significant bit set = {octet_bit_set}")
    # bit, octet_restored = eddsa.getMostSignificantBitInOctetAndResetIt(octet_bit_set)
    # print(f"bit was {bit} and restored octet value is {octet_restored}")
    # as_bit = eddsa.intToBitString(64)
    # print(f"64 as bit sting = {as_bit}")
    # result_str = eddsa.bitStringToInt(as_bit)
    # print(f"64 as bit sting as int = {result_str}")

    # num = eddsa.intToOctetList(26483764)
    # print(num)
    # int_value = eddsa.octetListToInt(num)
    # print(int_value)
    print("- - - - - - - - - - - -")
    
    message = "010101010111"
    signature = eddsa.createSignature(message)
    print(f"signature is {signature}")
    print("- - - - - - - - - - - -")
    is_signature_valid = eddsa.verifySignature(message_bit_string=message,signature=signature,Q=eddsa.public_key)
    print(is_signature_valid)
    
    # assert is_signature_valid