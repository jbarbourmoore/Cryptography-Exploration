from HelperFunctions.EuclidsAlgorithms import euclidsAlgorithm
import math

def getPrimeNumbers_SieveOfEratosthenes(minimum_number=2, maximum_number=10000):
    '''
    This function finds all prime numbers between minimum and maximum numbers using the algorithm sieve of eratosthenes

    Parameters :
        minimum_number : int, optional
            The lower bounds for the range in which we are finding prime numbers (default is 2)
        maximum_number : int, optional
            The upper bounds for the range in which we are finding prime numbers (default is 10000)
    '''
      
    is_prime_list = [True for _ in range(0, maximum_number+1)]
     
    potential_prime_number = 2
    while(potential_prime_number * potential_prime_number <= maximum_number):
        # If the value in the array is still true it is not divisible by any number smaller than it
        # so it must be a prime
        if (is_prime_list[potential_prime_number] == True):
            # find all multiples in the range as they cannot be primes
            for i in range(potential_prime_number * potential_prime_number, maximum_number + 1, potential_prime_number):
                is_prime_list[i] = False
        potential_prime_number += 1
 
    # create list of all prime numbers
    list_of_primes = []
    for potential_prime_number in range(minimum_number, maximum_number):
        if is_prime_list[potential_prime_number]:
            list_of_primes.append(potential_prime_number)
    return list_of_primes
 
def findPrimativeRoots(prime_number):
    '''
    This function finds the primative roots for a given prime number

    Parameters :
        prime_number : int
            The number to which one is finding the primitive roots
    '''

    primative_roots = []
    required_set = set(i for i in range (1, prime_number) if euclidsAlgorithm(i, prime_number) == 1)

    for j in range(1, prime_number):
        actual_set = set(calculatePowerWithModulo(j,i,prime_number) for i in range (1, prime_number))
        if required_set == actual_set:
            primative_roots.append(j)           
    return primative_roots

def calculatePowerWithModulo(a_number, a_power, a_modulo):
    '''
    This function raises a given number to a given power and finds the given modulo for it

    Parameters :
        a_number : int
            The number to be raised to a power
        a_power : int
            The power to which to raise the number
        a_modulo : int
            The modulo value to take once the number has been raised to a power
    '''

    return (a_number**a_power) % a_modulo

def calculateModuloInverse(number, modulo):
    '''
    This function calculates the modulo inverse of a number

    Parameters : 
        number : int
            The number for which we are finding the modulo inverse
        modulo : int
            The value of the modulus

    Returns : 
        modulo_inverse : int
            The modulo inverse of the number
    '''
    if number % modulo == 0:
            return None
    
    # not efficient enough when dealing with large numbers
    # return calculatePowerWithModulo(number, modulo-2, modulo)

    return pow(number,modulo-2,modulo)

def calculatePrimeFactors_classical(number):
        '''
        This method calculates the prime factors of a number

        (classical methodology, not shor's quantum algorithm)

        Parameters :
            number : int
                The number for which we are finding the prime factors

        Returns :
            prime_factors : [int]
                A list of the prime factors for the number
        '''

        prime_factors = []

        while number % 2 == 0:
            prime_factors.append(2)
            number = number // 2
            
        for i in range(3, int(math.sqrt(number))+1, 2):
            
            while number % i == 0:
                prime_factors.append(i)
                number = number // i

        if number > 2:
            prime_factors.append(number)

        return(prime_factors)

def findOrder_classical(number, modulo): 
    '''
    This function finds the order such that
    number ** order % modulo == 1 

    Parameters : 
        number : int
            The number that we are finding the order for
        modulo : int
            The modulo value for which we are finding the order

    returns
        potential_order : int
            The order of number and modulo
    '''
 
    if euclidsAlgorithm(modulo, number) != 1:
        return None
 
    
    potential_order = 3
    while True: 
        if (pow(number, potential_order, modulo) == 1): 
            return potential_order
        
        potential_order += 1

def calculateModuloSquareRoot(number, modulo):
    ''''
    This function calculates the modulo square root of a number 

    Parameters : 
        number : int
            The number that we are finding the square root of
        modulo : int
            The modulo value for which we are finding the square root of number

    returns
        square_root : int | None
            The square root of number
    '''
 
    number = number % modulo
    for i in range (2, modulo):
        if ((i * i) % modulo == number) :
            return i
    return None