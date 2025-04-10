import secrets
from HelperFunctions import EllipticCurveDetails
from HelperFunctions.EllipticCurveCalculations import EllipticCurveCalculations
from random import randint
import hashlib

class EllipticCurveDigitalSignatureAlgorithm():
    '''
    This class stores the public information for the elliptic curve digital signature algorithm
    '''

    def __init__(self, get_curve_functions , is_debug=False):
        '''
        This method initializes the elliptic curve digital signature with a randomly selected curve and generator point

        Parameters :
            get_curve_functions : [function]
                The list of potential curve functions to choose from
            is_debug = Bool, optional
                Whether the EllipticCurveDigitalSignatureAlgorithm is being debugged and should output more detailed information (default is False)
        '''

        self.public_key_list = []
        number_of_functions = len(get_curve_functions)
        if number_of_functions == 1:
            get_curve_function = get_curve_functions[0]
        else:
            random_index = randint(0,number_of_functions - 1)
            get_curve_function = get_curve_functions[random_index]

        self.curve_details = get_curve_function()
        self.curve = EllipticCurveCalculations(self.curve_details.a,self.curve_details.b,finite_field=self.curve_details.prime_modulus)
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

        self.public_key = self.curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(self.curve_details.generator_point,self.private_key)

    def generatePrivateKey(self):
        '''
        This method randomly generate a private key below the prime modulus of the selected curve
        '''

        self.private_key = secrets.randbelow(self.curve_details.prime_modulus)

    def calculateHashOfItem(self, item_to_hash):
        '''
        This method calculate the sha512 hash digest of the message and returns it as an int
        '''

        return int(hashlib.sha512(str(item_to_hash).encode("utf-8")).hexdigest(), 16)
    
    def createSignature(self, message):
        '''
        This method creates the signature (R,s) for a message

        Parameters : 
            message : str
                The message as an integer

        Returns :
            R : (int, int)
                A point which is half of the signature
            s : int
                An integer which is half of the signature
        '''

        message_as_int = self.convertMessageToInt(message=message)

        r = self.calculateHashOfItem(self.calculateHashOfItem(message_as_int) + message_as_int) % self.curve.finite_field
        R = self.curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(self.curve_details.generator_point,r)
        h = self.calculateHashOfItem(R[0] + self.public_key[0] + message_as_int) % self.curve.finite_field
        s = (r + h * self.private_key) 

        if self.is_debug:
            print("The signature has been generated")
            print(f"R: {R}")
            print(f"s: {s}")
        return (R,s)
    
    def verifySignature(self, message, signature):
        '''
        This method verifies the signature using the public key, message and signature

        Parameters :
            message : int
                The message as that was sent with the signature
            signature : ((int, int), int)
                The message signature sent as a point and an integer
        '''

        R,s = signature

        message_as_int = self.convertMessageToInt(message=message)

        hash = self.calculateHashOfItem(R[0] + self.public_key[0] + message_as_int) % self.curve.finite_field
        signature_verification_point = self.curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(self.curve_details.generator_point,s) 
        point_with_hash = self.curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(self.public_key, hash)
        signature_verification_point_two = self.curve.calculatePointAddition(R, point_with_hash)
        if signature_verification_point[0] == signature_verification_point_two[0] and signature_verification_point[1] == signature_verification_point_two[1]:
            if self.is_debug:
                print("The signature has been successfully verified")
            return True
        else:
            if self.is_debug:
                print("The signature has failed verification")
                print(f"Signature Verification Point 1 : {signature_verification_point}")
                print(f"Signature Verification Point 2 : {signature_verification_point_two}")

            return False
        
    def convertMessageToInt(self, message):
        '''
        This method translates a message into an integer value
        '''

        message_utf8 = message.encode('utf-8')
        message_in_hex = message_utf8.hex()
        message_as_int = int(message_in_hex, 16)
        return message_as_int

if __name__ == '__main__':
    
    print("The example runs the elliptic curve digital signature algorithm for a given message and verifies the signature")
    print("The Elliptic Curve math is based on Weirstrass form elliptic curves and implemented in HelperFunctions.EllipticCurveCalculations")
    print("It relies upon the sha-512 hashing function from hashlib and uses the secrets library to generate a private key")
    
    print("- - - - - - - - - - - -")

    elliptic_curve_digital_signature_algorithm = EllipticCurveDigitalSignatureAlgorithm([EllipticCurveDetails.getCurveP192,EllipticCurveDetails.getSecp256r1,EllipticCurveDetails.getCurveP521],is_debug=True)
 
    print("- - - - - - - - - - - -")
    
    message = "This is the message which is being signed"
    signature = elliptic_curve_digital_signature_algorithm.createSignature(message=message)
    
    print("- - - - - - - - - - - -")
    is_signature_valid = elliptic_curve_digital_signature_algorithm.verifySignature(message,signature)

    assert is_signature_valid
    