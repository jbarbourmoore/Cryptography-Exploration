from HelperFunctions.PrimeNumbers import getPrimeNumbers_SieveOfEratosthenes, findPrimativeRoots, calculatePowerWithModulo
from random import randint

class DiffieHellmanKeyPair():
    '''
    This class handles the information for a single user in the diffie hellman key exchange
    '''

    def __init__(self, diffie_hellman_key_exchange_data=None, is_debug = False):
        '''
        This method initializes a single user in the diffie hellman key exchange

        Parameters :
            diffie_hellman_key_exchange : DiffieHellmanKeyExchange
                the diffie hellman key exchange the user is participating in
                This keeps track of the agreed upon prime_number, as well as the agreed upon generator and the public keys
            is_debug = Bool, optional
                Whether the DiffieHellmanKeyPair is being debugged and should output more detailed information (default is False)
        '''

        self.diffie_hellman_key_exchange = diffie_hellman_key_exchange_data
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
            if self.public_key not in self.diffie_hellman_key_exchange.public_key_list:
                self.diffie_hellman_key_exchange.addPublicKey(self.public_key)
                not_added_public_key = False
                if self.is_debug:
                    print(f"A diffie hellman key pair for {self.diffie_hellman_key_exchange.selected_prime} with a public key of {self.public_key} has been created")
        
    def generatePrivateKey(self):
        '''
        This method randomly generate a private key between 10 and 500
        '''

        self.private_key = randint(10,500)

    def calculateSharedSecret(self):
        '''
        This method calculates the shared secret based on its own private key, the other public key in the diffie hellman key exchange, and the selected prime number
        '''

        for key in self.diffie_hellman_key_exchange.public_key_list:
            if key != self.public_key:
                other_public_key = key
        
        self.shared_secret = calculatePowerWithModulo(other_public_key,self.private_key,self.diffie_hellman_key_exchange.selected_prime)
        if self.is_debug:
            print(f"A diffie hellman key pair for {self.diffie_hellman_key_exchange.selected_prime} with a public key of {self.public_key} has calculated the shared secret of {self.shared_secret}")

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

        self.public_key_list = []
        list_of_prime_numbers = getPrimeNumbers_SieveOfEratosthenes(prime_lower_bounds,prime_upper_bounds)
        selected_prime_index = randint(0,len(list_of_prime_numbers)-1)
        self.selected_prime = list_of_prime_numbers[selected_prime_index]
        list_of_primitive_roots = findPrimativeRoots(self.selected_prime)
        selected_primitive_root_index = randint(0,len(list_of_primitive_roots)-1)
        self.generator = list_of_primitive_roots[selected_primitive_root_index]
        if is_debug:
            print("A diffie hellman exchange has been initiated")
            print(f"The agreed upon prime is {self.selected_prime} and the agreed upon generator is {self.generator}")

    def addPublicKey(self, key):
        self.public_key_list.append(key)


def createCommunicationNetwork(DiffieHellmanKeyPair, DiffieHellmanKeyExchange, number_of_people):
    '''
    This function generates the keys necessary for every person to communicate with every other person
    '''
    number_of_key_pairs = 0
    diffie_hellman_key_exchanges_matrix = []
    for person in range(0,number_of_people):
        diffie_hellman_key_exchanges_list = []
        for person_to_communicate in range(0,number_of_people):
            if person == person_to_communicate:
                diffie_hellman_key_exchanges_list.append(None)
            elif person > person_to_communicate:
                diffie_hellman_key_exchanges_list.append(diffie_hellman_key_exchanges_matrix[person_to_communicate][person])
            else:
                diffie_hellman_key_exchanges_list.append(DiffieHellmanKeyExchange(is_debug=True))
        diffie_hellman_key_exchanges_matrix.append(diffie_hellman_key_exchanges_list)
    people = {}
    for person in range(0,number_of_people):
        people_to_communicate_with = {}
        for person_to_communicate in range(0,number_of_people):
            if diffie_hellman_key_exchanges_matrix[person][person_to_communicate] != None:
                number_of_key_pairs += 1
                people_to_communicate_with[person_to_communicate] = DiffieHellmanKeyPair(diffie_hellman_key_exchange_data=diffie_hellman_key_exchanges_matrix[person][person_to_communicate], is_debug=True)
        people[person] = people_to_communicate_with

    for person in people.values():
        shared_secrets_list = []
        for person_to_communicate_with in person.values():
            person_to_communicate_with.calculateSharedSecret()

    for person in range(0,number_of_people):
        for person_to_communicate in range(0,number_of_people):
            if person == person_to_communicate:
                shared_secrets_list.append(None)
            else:
                assert people[person][person_to_communicate].shared_secret == people[person_to_communicate][person].shared_secret
    
    return number_of_key_pairs

if __name__ == '__main__':
    diffie_hellman_key_exchange = DiffieHellmanKeyExchange(is_debug=True)

    first_diffie_hellman_key_pair = DiffieHellmanKeyPair(diffie_hellman_key_exchange, is_debug=True)
    second_diffie_hellman_key_pair = DiffieHellmanKeyPair(diffie_hellman_key_exchange, is_debug=True)
    first_diffie_hellman_key_pair.calculateSharedSecret()
    second_diffie_hellman_key_pair.calculateSharedSecret()

    assert first_diffie_hellman_key_pair.shared_secret == second_diffie_hellman_key_pair.shared_secret

    number_of_people = 3
    number_of_key_pairs_3_people = createCommunicationNetwork(DiffieHellmanKeyPair, DiffieHellmanKeyExchange, number_of_people)

    number_of_people = 6
    number_of_key_pairs_6_people = createCommunicationNetwork(DiffieHellmanKeyPair, DiffieHellmanKeyExchange, number_of_people)

    print(f"3 people need {number_of_key_pairs_3_people} keys")
    print(f"6 people need {number_of_key_pairs_6_people} keys")