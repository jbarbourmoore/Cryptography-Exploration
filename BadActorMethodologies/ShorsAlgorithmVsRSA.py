from CryptographySchemes.RSACryptographyScheme import RSACryptographyScheme

from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister, transpile
from qiskit.circuit.library import UnitaryGate
from qiskit.circuit.library import QFT
from qiskit_aer import AerSimulator
import math
import numpy as np
from math import gcd, floor, log
from fractions import Fraction
import random

class badActor_RSA():
    '''
    This class acts as a bad actor, using Shor's algorithm to gain access to encrypted messages not meant for them
    '''

    def __init__(self, target_public_key, own_rsa_keys = None):
        '''
        This method initializes the bad actor with access to a target's public key

        The bad actor then uses Shor's algorithm to find the prime factors of the public key's n and duplicate the target's private key

        (it is limited by the input qubits available in the quantum simulator and can currently only factor values up to 7 qubits or 127)

        Parameters :
            target_public_key : (int, int)
                Two integers for the target's public key, e and n
            own_rsa_keys : RSACryptographyScheme, optional
                The attackers own rsa keys, defaults to using 11 and 13 as the prime numbers to create keys
        '''

        print("- - - - - - - - - - - -")

        print(f"A bad actor is targeting someone with the public key {target_public_key}")
        self.target_rsa_e, self.target_rsa_n = target_public_key
        if own_rsa_keys == None:
            self.own_rsa_keys = RSACryptographyScheme(11, 13, block_size=1)
        else:
            self.own_rsa_keys = own_rsa_keys
        print(f"The attacker has their own rsa keys with a public key {self.own_rsa_keys.getPublicKey()}")
        target_n_factors = findTwoPrimeFactors_QuantumShorsAlgorithm_Qiskit(self.target_rsa_n)
        # from HelperFunctions import PrimeNumbers
        # target_n_factors = PrimeNumbers.calculatePrimeFactors_classical(self.target_rsa_n)
        self.target_prime_factors = target_n_factors
        target_n_factors.sort()
        print(f"Shor's Algorithm was used to find two factors of N from the target's public key: {target_n_factors}")

        self.duplicate_target_crypto_scheme = RSACryptographyScheme(target_n_factors[0], target_n_factors[1], block_size=1)
        print(f"The bad actor now has access to the target's private key {self.duplicate_target_crypto_scheme.getPrivateKey()}")
        print("- - - - - - - - - - - -")
    
    def decryptMessageForTarget(self, rsa_encrypted_message):
        '''
        This method decrypt's a message meant for the bad actor's target

        Parameters :
            rsa_encrypted_message : [int]
                A message meant for the target as an encrypted list of numbers

        Returns :
            decrypted_message_for_target : str
                The string of the decrypted message meant for the target
        '''

        decrypted_message_for_target = self.duplicate_target_crypto_scheme.rsaDecoding(rsa_encrypted_message)
        return decrypted_message_for_target
    
    def decryptMessageForSelf(self, rsa_encrypted_message):
        '''
        This method decrypt's a message meant for the bad actor

        Parameters :
            rsa_encrypted_message : [int]
                A message meant for the bad actor as an encrypted list of numbers

        Returns :
            decrypted_message_for_self : str
                The string of the decrypted message meant for the bad actor
        '''

        decrypted_message_for_self = self.own_rsa_keys.rsaDecoding(rsa_encrypted_message)
        return decrypted_message_for_self

def runBadActorAgainstRSAScheme():
    '''
    This function runs a very simple example of utilizing the Shor's Algorithm for prime factorisation to duplicate RSA private keys based on the public key
    
    Note: The example is constrained by the number of qubit available for input in the quantum simulator
    (in this case 7, so the largest number it can factor is 127)
    '''

    print("- - - - - - - - - - - -")
    print("Please note the values chosen for this example are limited by the number of qubits available in the quantum simulator.")
    print("- - - - - - - - - - - -")

    smaller_initial_prime = 7
    larger_initial_prime = 13
    rsa_crypto_scheme = RSACryptographyScheme(smaller_initial_prime, larger_initial_prime, block_size=1)

    print(f"Initial RSA Key Pair Generated With {smaller_initial_prime} and {larger_initial_prime} :")
    print(f'Public Key: {rsa_crypto_scheme.e, rsa_crypto_scheme.n}')
    print(f'Private Key: {rsa_crypto_scheme.d, rsa_crypto_scheme.n}')

    print("- - - - - - - - - - - -")

    original_message = 'This is a secret message'
    print(f'Original message : {original_message}')

    rsa_encrypted_message = rsa_crypto_scheme.rsaEncoding(original_message)
    print(f"Encrypted message with public key : {rsa_encrypted_message}")

    decoded_message = rsa_crypto_scheme.rsaDecoding(rsa_encrypted_message)
    print(f"Decrypted message with correct private key : {decoded_message}")
    assert original_message == decoded_message

    bad_actor = badActor_RSA(rsa_crypto_scheme.getPublicKey())
    decoded_message_bad_actor_key = bad_actor.decryptMessageForSelf(rsa_encrypted_message)

    print(f"Decrypted message with the bad actor's own rsa keys : {decoded_message_bad_actor_key}")
    assert original_message != decoded_message_bad_actor_key
    print("The bad actor's own keys did not allow them to access the message's content")

    decoded_message_stolen_key = bad_actor.decryptMessageForTarget(rsa_encrypted_message)
    print(f"Decrypted message with duplicated rsa keys for the target : {decoded_message_stolen_key}")
    assert original_message == decoded_message_stolen_key
    print("The private key the bad actor managed to duplicate using Shor's algorithm allowed them to access the message's content")
    print("- - - - - - - - - - - -")


def createMultipleOfModulusGate(a, n):
    '''
    This function generates a custom unitary gate for f(x) = ax%n

    This is a unitary function provided that the greatest common denominator of a and n is 1
    It is a permutation matrix and both deterministic and invertable
    
    Parameters :
        a : int
            The multiple of the modulo calculation
        n : int
            The number that is the modulo value

    Returns :
        unitary_gate : UnitaryGate
            The custom unitary gate which satisfies the function f(x) = ax%n
    '''

    assert gcd(a, n) == 1, f"This is not a unitary operation if the greatest common denomitor of {a} and {n} does not equal 1"

    number_of_bits = floor(log(n-1, 2)) + 1

    # create a unitary matrix of 0s and 1s for every value in Zn such that f(x) = ax%n = 1
    unitary_matrix = np.full((2 ** number_of_bits, 2 ** number_of_bits), 0)
    for x in range(n): unitary_matrix[a*x % n][x] = 1
    for x in range(n, 2 ** number_of_bits): unitary_matrix[x][x] = 1

    unitary_gate = UnitaryGate(unitary_matrix)
    unitary_gate.name = f"Mod_{a}"

    return unitary_gate
    
def createCircuitToFindOrder(a, n):
    '''
    This function creates a quantum circuit in order to find the order of ax%n
    
    Parameters :
        a : int
            The multiple of the modulo calculation
        n : int
            The number that is the modulo value

    Returns :
        quantum_circuit : QuantumCircuit
            The quantum circuit to find the order of ax%n
    '''
 
    number_of_bits = floor(log(n - 1, 2)) + 1
    double_bits = 2 * number_of_bits

    # create input qubits and classical bits that are twice the size of n
    # create output qubits that are the size of n
    inputs = QuantumRegister(double_bits, name = "X")
    outputs = QuantumRegister(number_of_bits, name = "Y")
    classical_bits = ClassicalRegister(double_bits, name = "Z")

    quantum_circuit = QuantumCircuit(inputs, outputs, classical_bits)
    quantum_circuit.x(double_bits)

    # generate circuits for calculating ax%n for every qubit in the input
    for i, input in enumerate(inputs):
        quantum_circuit.h(i)
        b = pow(a, 2**i, n)
        quantum_circuit.compose( createMultipleOfModulusGate(b, n).control(), qubits = [input] + list(outputs), inplace=True)

    # take the inverse fourier transform of the inputs
    quantum_circuit.compose( QFT(double_bits, inverse=True), qubits=inputs, inplace=True)

    quantum_circuit.measure(inputs, classical_bits)
    
    return quantum_circuit
    
def calculateOrder(a, n):
    '''
    This function finds the order of the funtion f(x)=ax%n

    Assuming that the greatest common denominator of n and a is 1
    The order is the smallest integer r such that a**r = 1 % n

    Parameters :
        a : int
            The multiple of the modulo calculation
        n : int
            The number that is the modulo value

    Returns :
        order : int 
            The order of ax%n
    '''

    assert gcd(a, n) == 1, f"The order cannot be calculated if the greatest common denomitor of {a} and {n} does not equal 1"

    number_of_bits = floor(log(n-1, 2)) + 1
    double_bits = 2 * number_of_bits
    quantum_circuit = createCircuitToFindOrder(a, n)
    transpiled_circuit = transpile(quantum_circuit,AerSimulator())

    # due to the nature of quantum computing and randomness, the circuit to calculate the result should be repeated until the answer given is verified
    running_aer_simulator = True
    while running_aer_simulator:
        result = AerSimulator().run(
            transpiled_circuit,
            shots=1,
            memory=True).result()

        y = int(result.get_memory()[0], 2)
        order = Fraction(y / 2 ** double_bits ).limit_denominator(n).denominator

        # verify result from the simulator
        if pow(a, order, n) == 1:
            running_aer_simulator = False

    return order
    
def findTwoPrimeFactors_QuantumShorsAlgorithm_Qiskit(public_key_n):
    '''
    This function finds the two distinct prime factors of the rsa public key n value

    Parameters :
        public_key_n : int
            The RSA public key n that is to be factored

    Returns : 
        factors_found : [int, int]
            The two distinct factors found for the public key n value
    '''

    factors_found = []

    # loop continues until two factors are identified
    # no factor will be identified on an iteration where:
    # a. order of a%n is odd
    # b. order of a%n is even and the greatest common denominator of a**r/2 and n is 1
    # as the key n should be factor_1 * factor_2 the second factor should be calculated from the first
    while len(factors_found) < 2:

        # A random number is selected and its greatest common denominator with n is found 
        random_guess = random.randint(2, public_key_n - 1)
        potential_prime_factor = gcd(random_guess, public_key_n)

        # if the greatest common denominator is larger than 1, the random guess itself is a factor of n
        if potential_prime_factor > 1:
            factors_found.append(potential_prime_factor)
            second_potential_factor = public_key_n // potential_prime_factor
            if second_potential_factor not in factors_found and second_potential_factor > 1:
                factors_found.append(second_potential_factor)

        # otherwise, the order of the random guess and n is calculated as the greatest common denominator is 1
        else:
            order = calculateOrder(random_guess, public_key_n)

            # order needs to be even in order to calculate a ** (r/2) % n
            if order % 2 == 0:
                x = pow(random_guess, order // 2, public_key_n) - 1
                potential_prime_factor = gcd(x, public_key_n)
                
                # if the greatest common denominator is larger than 1 it is a factor
                if potential_prime_factor > 1 : 
                    factors_found.append(potential_prime_factor)
                    second_potential_factor = public_key_n // potential_prime_factor
                    if second_potential_factor not in factors_found and second_potential_factor > 1:
                        factors_found.append(second_potential_factor)
    return factors_found

if __name__ == '__main__':

    runBadActorAgainstRSAScheme()