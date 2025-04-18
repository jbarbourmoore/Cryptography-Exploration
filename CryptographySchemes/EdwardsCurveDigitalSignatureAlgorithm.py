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
            self.private = IntegerHandler.fromHexString(self.private_key, True, self.b)
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
        # get the least significant bit of x
        x_0 = x_handler.getLeastSignificantBit()

        y_handler = IntegerHandler(point[1] % self.curve.p,little_endian=True,bit_length=self.b)
        if self.is_debug:
            print(f"Y before bit set = {y_handler.getHexString(add_spacing=8)} x_0 = {x_0}")
        # set the most significant bit of y to the bit from x
        
        y_max, new_y = y_handler.setMostSignificantBit(x_0)
        if self.is_debug:
            print(f"Y after bit set = {new_y.getHexString(add_spacing=8)}  y_max = {y_max}")

        return new_y
    
    def generatePrivateKey(self):
        '''
        This method randomly generate a private key below the prime modulus of the selected curve
        '''

        self.private = IntegerHandler(secrets.randbelow(self.curve.p), True, self.b)

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
        

        x_0, y_decoded = coded_point.setMostSignificantBit(0)
        if self.print_excess_output:
            print(f"The y is now {y_decoded.value} and x_0 is now {x_0}")

        y = y_decoded.value
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
                # print(f"root is {root}")
                return (root, y)
            else:
                # print(f"root is {p - root}")
                return ((p - root) % p, y)
   
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
        r = message_hash.value % self.n
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
        s = self.hdigest1.value % self.n
        point_rG = self.multiplesOfG(r)
        R = self.encodePoint(point_rG)
        Q =  self.Q

        RQM_handler = concatenate([R,Q,message_handler], True)
        H_RQM = self.calculateHashOfIntegerHandler(RQM_handler)
        digest = H_RQM.value % self.n
        S = (r + digest * s) % self.n
        S = IntegerHandler(S,True,self.b)
        signature = concatenate([R,S],True)

        print(f"R is {R.getHexString(add_spacing=8)} length is {R.bit_length}")
        print(f"S is {S.getHexString(add_spacing=8)} length is {S.bit_length}")
        return signature
    
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
        if type(Q) == str:
            Q = IntegerHandler.fromHexString(Q,True,self.b)

        t = S.value

        R_point = self.decodePoint(R.getHexString())
        Q_point = self.decodePoint(Q.getHexString())

        if R_point == None or Q_point == None:
            return False
        
        rqm = concatenate([R,Q,message_handler],True)
        digest = self.calculateHashOfIntegerHandler(rqm)
        u = digest.value % self.n

        t_G = self.multiplesOfG(t % self.n)
        u_Q = self.curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(Q_point,u % self.n)
        R_u_Q = self.curve.calculatePointAddition(u_Q, R_point)
 
        if t_G == R_u_Q:
            return True
        else :
            return False

if __name__ == '__main__':    
    print("The example runs the elliptic curve digital signature algorithm for a given message and verifies the signature")
    print("The Elliptic Curve math is based on Weirstrass form elliptic curves and implemented in HelperFunctions.EllipticCurveCalculations")
    
    print("- - - - - - - - - - - -")

    eddsa = EdwardsCurveDigitalSignatureAlgorithm(is_debug=True,print_excess_error=True)
    print("- - - - - - - - - - - -")
    
    message = "010101010111"
    signature = eddsa.createSignature(message)
    print(f"signature is {signature.getHexString(add_spacing=8)}")
    print("- - - - - - - - - - - -")
    is_signature_valid = eddsa.verifySignature(message_bit_string=message,signature=signature,Q=eddsa.public_key)
    print(is_signature_valid)
    
    # assert is_signature_valid
