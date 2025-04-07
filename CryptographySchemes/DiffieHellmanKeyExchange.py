from HelperFunctions.PrimeNumbers import getPrimeNumbers_SieveOfEratosthenes, findPrimativeRoots, calculatePowerWithModulo
from random import randint

class DiffieHellmanKeyPair():
    '''
    This class handles the information for a single user in the diffie hellman key exchange
    '''

    def __init__(self, diffie_hellman_key_exchange, is_debug = False):
        '''
        This method initializes a single user in the diffie hellman key exchange

        Parameters :
            diffie_hellman_key_exchange : DiffieHellmanKeyExchange
                the diffie hellman key exchange the user is participating in
                This keeps track of the agreed upon prime_number, as well as the agreed upon generator and the public keys
            is_debug = Bool, optional
                Whether the DiffieHellmanKeyPair is being debugged and should output more detailed information (default is False)
        '''

        self.diffie_hellman_key_exchange = diffie_hellman_key_exchange
        self.is_debug = is_debug
        self.generatePrivateAndPublicKeys()
    
    def generatePrivateAndPublicKeys(self):
        '''
        This method generates the public and private keys

        The private key is a random integer value and the public key is calculated based off of it
        It features a loop that checks whether the public key value is already stored in the diffie hellman object to prevent duplicate keys
        '''

        not_added_public_key = True
        while not_added_public_key:
            self.generatePrivateKey()
            self.public_key = calculatePowerWithModulo(self.diffie_hellman_key_exchange.generator,self.private_key,self.diffie_hellman_key_exchange.selected_prime)
            if self.public_key not in diffie_hellman_key_exchange.public_keys:
                diffie_hellman_key_exchange.public_keys.append(self.public_key)
                not_added_public_key = False
                if self.is_debug:
                    print(f"A diffie hellman key pair with a public key of {self.public_key} has been created")
        
    def generatePrivateKey(self):
        '''
        This method randomly generate a private key between 10 and 500
        '''

        self.private_key = randint(10,500)

    def calculateSharedSecret(self):
        '''
        This method calculates the shared secret based on its own private key, the other public key in the diffie hellman key exchange, and the selected prime number
        '''

        for key in self.diffie_hellman_key_exchange.public_keys:
            if key != self.public_key:
                other_public_key = key
        
        self.shared_secret = calculatePowerWithModulo(other_public_key,self.private_key,self.diffie_hellman_key_exchange.selected_prime)
        if self.is_debug:
            print(f"A diffie hellman key pair with a public key of {self.public_key} has calculated the shared secret of {self.shared_secret}")

class DiffieHellmanKeyExchange():
    '''
    This class stores the public information for the diffie hellman key exchange
    '''

    def __init__(self, prime_lower_bounds = 500, prime_upper_bounds = 1000, is_debug = False):
        '''
        This method initializes the diffie hellman key exchange with a random prime and a random selected value from its primitive root

        Parameters :
            prime_lower_bounds : int, optional
                The smallest number that could be selected as prime value (default is 500)
            prime_upper_bounds : int, optional
                The largest number that could be selected as prime value (default is 1000)
            is_debug = Bool, optional
                Whether the DiffieHellmanKeyExchange is being debugged and should output more detailed information (default is False)
        '''

        list_of_prime_numbers = getPrimeNumbers_SieveOfEratosthenes(prime_lower_bounds,prime_upper_bounds)
        selected_prime_index = randint(0,len(list_of_prime_numbers)-1)
        self.selected_prime = list_of_prime_numbers[selected_prime_index]
        list_of_primitive_roots = findPrimativeRoots(self.selected_prime)
        selected_primitive_root_index = randint(0,len(list_of_primitive_roots)-1)
        self.generator = list_of_primitive_roots[selected_primitive_root_index]
        if is_debug:
            print("A diffie hellman exchange has been initiated")
            print(f"The agreed upon prime is {self.selected_prime} and the agreed upon generator is {self.generator}")
        self.public_keys = []


if __name__ == '__main__':
    diffie_hellman_key_exchange = DiffieHellmanKeyExchange(is_debug=True)

    first_diffie_hellman_key_pair = DiffieHellmanKeyPair(diffie_hellman_key_exchange, is_debug=True)
    second_diffie_hellman_key_pair = DiffieHellmanKeyPair(diffie_hellman_key_exchange, is_debug=True)
    first_diffie_hellman_key_pair.calculateSharedSecret()
    second_diffie_hellman_key_pair.calculateSharedSecret()

    assert first_diffie_hellman_key_pair.shared_secret == second_diffie_hellman_key_pair.shared_secret



