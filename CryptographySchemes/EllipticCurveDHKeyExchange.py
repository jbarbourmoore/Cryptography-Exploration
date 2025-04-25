import secrets
from HelperFunctions import EllipticCurveDetails
from HelperFunctions.EllipticCurveCalculations import WeirrstrassCurveCalculations
from random import randint

class EllipticCurveDHKeyPair():
    '''
    This class handles the information for a single user in the elliptic curve diffie hellman key exchange
    '''

    def __init__(self, elliptic_curve_dh_key_exchange_data=None, is_debug = False):
        '''
        This method initializes a single user in the elliptic curve diffie hellman key exchange

        Parameters :
            elliptic_curve_dh_key_exchange_data : EllipticCurveDHKeyExchange
                the elliptic curve diffie hellman key exchange the user is participating in
                This keeps track of the agreed upon curve, as well as the agreed upon generator point and the public keys
            is_debug = Bool, optional
                Whether the EllipDiffieHellmanKeyPair is being debugged and should output more detailed information (default is False)
        '''

        self.elliptic_curve_dh_key_exchange_data = elliptic_curve_dh_key_exchange_data
        self.is_debug = is_debug
        self.generatePrivateAndPublicKeys()
    
    def generatePrivateAndPublicKeys(self):
        '''
        This method generates the public and private keys

        The private key is a random integer value and the public key is calculated based off of it
        It features a loop that checks whether the public key value is already stored in the elliptic curve diffie hellman object to prevent duplicate keys
        '''

        not_added_public_key = True
        while not_added_public_key:
            self.generatePrivateKey()
            self.calculatePublicKey()
            if self.getCompressedPublicKey() not in self.elliptic_curve_dh_key_exchange_data.public_key_list:
                self.elliptic_curve_dh_key_exchange_data.addPublicKey(self.getCompressedPublicKey())
                not_added_public_key = False
                if self.is_debug:
                    print(f"A diffie hellman key pair for {self.elliptic_curve_dh_key_exchange_data.curve_details.name} with a public key of {self.public_key} has been created")
        
    def calculatePublicKey(self):
        '''
        This method calculates the public key based on the selected elliptic curve and the private key
        '''

        self.public_key = self.elliptic_curve_dh_key_exchange_data.curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(self.elliptic_curve_dh_key_exchange_data.curve_details.generator_point,self.private_key)

    def getCompressedPublicKey(self) -> str:
        '''
        This method gets the compressed form of the public key

        Returns :
            compressed_public_key : hex
                The compressed public key as a hexadecimal
        '''

        return self.elliptic_curve_dh_key_exchange_data.curve.compressPointOnEllipticCurve(self.public_key)

    def generatePrivateKey(self):
        '''
        This method randomly generate a private key below the prime modulus of the selected curve
        '''

        self.private_key = secrets.randbelow(self.elliptic_curve_dh_key_exchange_data.curve_details.prime_modulus)

    def calculateSharedSecret(self):
        '''
        This method calculates the shared secret based on its own private key, the other public key in the diffie hellman key exchange, and the selected curve
        '''

        for key in self.elliptic_curve_dh_key_exchange_data.public_key_list:
            if key != self.getCompressedPublicKey():
                other_public_key = key
        
        decompressed_key = self.elliptic_curve_dh_key_exchange_data.curve.decompressPointOnEllipticCurve(other_public_key)

        self.shared_secret = self.elliptic_curve_dh_key_exchange_data.curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(decompressed_key,self.private_key)
        
        if self.is_debug:
            print(f"A elliptic curve diffie hellman key pair for {self.elliptic_curve_dh_key_exchange_data.curve_details.name} with a public key of {self.public_key} has calculated the shared secret of {self.shared_secret}")

class EllipticCurveDHKeyExchange():
    '''
    This class stores the public information for the elliptic curve diffie hellman key exchange
    '''

    def __init__(self, get_curve_functions , is_debug):
        '''
        This method initializes the elliptic curve diffie hellman key exchange with a randomly selected curve and generator point

        Parameters :
            get_curve_functions : [function]
                The list of potential curve functions to choose from
            is_debug = Bool, optional
                Whether the DiffieHellmanKeyExchange is being debugged and should output more detailed information (default is False)
        '''

        self.public_key_list = []
        number_of_functions = len(get_curve_functions)
        if number_of_functions == 1:
            get_curve_function = get_curve_functions[0]
        else:
            random_index = randint(0,number_of_functions - 1)
            get_curve_function = get_curve_functions[random_index]

        self.curve_details:EllipticCurveDetails.EllipticCurveWeierstrassFormDetails = get_curve_function()
        self.curve:WeirrstrassCurveCalculations = WeirrstrassCurveCalculations(self.curve_details.a,self.curve_details.b,finite_field=self.curve_details.prime_modulus)
        
        if is_debug:
            print("A elliptic curve diffie hellman exchange has been initiated")
            print(f"The agreed upon curve is {self.curve_details.name} and the agreed upon generator is {self.curve_details.generator_point}")

    def addPublicKey(self, key):
        '''
        This function adds a public key to the exchange's list of public keys
        '''

        self.public_key_list.append(key)


if __name__ == '__main__':
    elliptic_curve_dh_key_exchange = EllipticCurveDHKeyExchange([EllipticCurveDetails.getCurveP192,EllipticCurveDetails.getSecp256r1,EllipticCurveDetails.getCurveP521],is_debug=True)

    first_elliptic_curve_dh_key_pair = EllipticCurveDHKeyPair(elliptic_curve_dh_key_exchange, is_debug=True)
    second_elliptic_curve_dh_key_pair = EllipticCurveDHKeyPair(elliptic_curve_dh_key_exchange, is_debug=True)
    first_elliptic_curve_dh_key_pair.calculateSharedSecret()
    second_elliptic_curve_dh_key_pair.calculateSharedSecret()

    assert first_elliptic_curve_dh_key_pair.shared_secret == second_elliptic_curve_dh_key_pair.shared_secret
