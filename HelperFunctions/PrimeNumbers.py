from HelperFunctions.EuclidsAlgorithms import euclidsAlgorithm, extendedEuclidAlgorithm
import math
from secrets import randbits, randbelow
from decimal import Decimal
from HelperFunctions.IntegerHandler import *

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
    #return calculatePowerWithModulo(number, modulo-2, modulo)

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

def runMillerRabinPrimalityTest(w:int, iterations:int=44) -> bool: 
    '''
    This method performs the miller rabin primality test on a given potential prime number

    iteration counts should be taken from Nist FIPS 186-5 Table B.1. "Minimum number of rounds of M-R testing when generating primes for use in RSA Digital Signatures (see Appendix C)"

    As laid out in NIST FIPS 186-5 Section 
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

    Parameters:
        w : int
            The candidate prime number being tested
        iterations : int, optional
            The number of iterations being performed of the miller rabin test, default is 44

    Returns :
        is_likely_prime : bool
            Whether the candidate is likely prime or not
    '''
    basic_primes = (2,3,5,7)
    basic_not_primes = (0,1,4,6,8,9)
    if w in basic_primes: return True
    if w in basic_not_primes: return False
    a = 0
    m = w-1

    while m % 2 == 0: 
        m //= 2
        a += 1

    assert m == ((w-1)//(pow(2,a)))
    if a == 0:
        return False
    
    def trial_composite(b):
        z = pow(b, m, w)
        if z == 1:
            return False
        for i in range(0, a):
            z = pow(b, pow(2, i) * m, w)
            if z == w-1:
                return False
        return True  

    for i in range(0, iterations): 
        b = 0
        while b <= 1 or b > w - 1:
            b = randbelow(w) 

        if trial_composite(b):
            return False
        
    return True

def runLucasPrimalityTest(candidate_prime: int, is_debug:bool = False) -> bool:
    '''
    This method checks whether a value is probably prime

    As according to NIST FIPS 186-5 Section B.3.3 "(General) Lucas Probabilistic Primality Test"

    Parameters :
        candidate_prime : int
            The value being checked to see if it is probably prime
        is_debug : bool
            Whether the method is being debugged

    Returns : 
        probably_prime : bool
            Whether the value is probably prime
    '''
    basic_primes = (2,3,5,7,11,13,17)
    basic_not_primes = (0,1,4,6,8,9)
    if candidate_prime in basic_primes: return True
    if candidate_prime in basic_not_primes: return False

    if candidate_prime % 2 == 0:
        return False

    if checkForAPerfectSquare(candidate_prime):
        return False
    
    D, jacobi_dc, gcd_dc = -3, 0, 0
    while jacobi_dc != 1 or gcd_dc != 1:
        if D < 0:
            D = -D + 2
        else:
            D = -D - 2
        jacobi_dc = jacobiSymbol(D, candidate_prime)
        gcd_dc = euclidsAlgorithm(candidate_prime, (1-D) // 4)
        if is_debug: print(f"D : {D}, Jacobi: {jacobi_dc}, GCD = {gcd_dc}")
        if jacobi_dc == 0:
            return False
    
    K = IntegerHandler(candidate_prime+1,False).getBitArray()
    if is_debug: print(f"Bit Array for K is {K}")
    inv_2 = calculateInverseMod_GCD1_ExtendedEuclidsBased(2,candidate_prime)
    U, V = 1, 1
    for i in range(1,len(K)):
        if is_debug: print(f"{i}: U:{U}, V:{V}, K_i:{K[i]} r:{len(K)-i}")
        U_temp = U * V % candidate_prime
        V_temp = ((V * V) + (D * U * U)) % candidate_prime
        V_temp *= inv_2
        V_temp %= candidate_prime
        
        if K[i] == 1:
            U = (U_temp + V_temp) % candidate_prime * inv_2 % candidate_prime
            V = (V_temp + D * U_temp) % candidate_prime * inv_2 % candidate_prime
        else :
            U = U_temp
            V = V_temp
        if is_debug: print(f"k[i]:{K[i]} = U:{U}, V:{V}")
    if U == 1: return True
    else: return False


def jacobiSymbol(a:int, n:int, is_debug = False):
    '''
    This method computes the jacobi symbol a/n

    As according to NIST FIPS 186-5 Section B.5 "Jacobi Symbol Algorithm"

    Parameters :
        a : int
            The value above the line in the jacobi symbol
        b : int
            The value below the line in the jacobi symbol
        is_debug : bool, optional
            Whether the method is being debugged, default is false

    Returns : 
        result : int
            The calculated jacobi symbol value
    '''
    
    a = a % n
    if is_debug:
        print(f"starting jacobi with a:{a}, n:{n}")
    if a == 1 or n == 1 :
        if is_debug:
            print(f"Result jacobi(a/n) a:{a}, n:{n} = {1}")
        return 1
    if a == 0:
        if is_debug:
            print(f"Result jacobi(a/n) a:{a}, n:{n} = {0}")
        return 0
    
    e = 0
    a_1 = a
    while a_1 % 2 == 0:
        a_1 //= 2
        e += 1
    #print(f"e : {e}")
    if e % 2 == 0:
        s = 1
    elif n % 8 == 1 or n % 8 == 7:
        s = 1
    elif n % 8 == 3 or n % 8 == 5:
        s = -1
    #print(f"Initial s : {s}")
    if n % 4 == 3 and a_1 % 4 == 3:
        s = -s
    #print(f"Final s : {s}")
    n_1 = n % a_1
    #print(f"a_1 = {a_1}, n_1 = {n_1}")
    result = s * jacobiSymbol(n_1, a_1, is_debug)
    if is_debug:
        print(f"Result jacobi(a/n) a:{a}, n:{n}, s:{s} = {result}")
    return result
    

@staticmethod
def checkForAPerfectSquare(C:int) -> bool:
    '''
    This method checks whether a value is a perfect square

    As according to NIST FIPS 186-5 Section B.4 "Checking for a Perfect Square"

    Parameters :
        C : int
            The value being checked to see if it is a perfect square

    Returns : 
        is_perfect_square : bool
            Whether the value is a perfect square
    '''
    # print(f"C = {C}")
    n = 0
    while pow(2, n) <= C:
        n += 1
    m = ceil(Decimal.from_float(n)/Decimal.from_float(2))
    i = 0
    X = pow(2, m)
    max_limit = pow(2, m) + C
    while X * X >= max_limit:
        i = i + 1
        X = (X * X + C) // (2 * X)
        # print(f"{i} : X:{X} C:{C} X^2:{X*X} max_limit:{max_limit}")
        
    if C == math.floor(X * X):
        # print(True)
        return True
    # print(f"False and C = {C} flor(x^2) = {floor(X * X)}")
    return False

def calculateInverseMod_GCD1_ExtendedEuclidsBased(value:int, modulus:int) -> int:
    '''
    This method uses the extended form of euclids algorithm to find the inverse modulo assuming the gcd = 1

    Parameters :
        value : int
            The value for which you are finding the modular inverse
        modulus : int
            The modulus in which you are calculating the modular inverse

    Returns :
        inverse : int
            The modular inverse of the value
    '''
    gcd, _, t = extendedEuclidAlgorithm(modulus,value)
    assert gcd == 1, f"The GCD of modulus {modulus} and value {value} needs to be one for this implementation to find modular inverse"
    if t < 0:
        inverse = modulus + t
    else:
        inverse = t
    return inverse

def calculateInverseModA_NISTFIPS1865(z:int, a:int) -> int:
    '''
    This method calculates the inverse of a value within a modulus a

    From NIST FIPS 186-5 Section B.1 "Computation of the Inverse Value"
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

    Parameters :
        z : int
            The value for which one is calculating the inverse
        a : int
            The modulus within which one is calculating the inverse

    Returns :
        z_inverse : int
            The inverse of z within the modulus a 
    '''
    if z >= a:
        z = z % a
    print(f"z is {z} a is {a}")
    i = a
    j = z
    y_1 = 1
    y_2 = 0
    while j > 0:
        quotient = i // j
        remainder = i - (j * quotient)
        y = y_2 - (y_1 * quotient)
        i = j
        j = remainder
        y_2 = y_1
        y_2 = y
    assert i == 1
    return y_2 % a

@staticmethod
def testSmallPrime(potential_prime:int) -> bool:
    '''
    This method tests whether an integer is a prime number

    Based on NIST FIPS 186-5 Section B.7 "Trial Division"
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

    Parameters : 
        potential_prime : int 
            The potentical prime int value to be tested

    Returns : 
        is_prime : bool
            Whether the integer value is a prime or not
    '''
    sqrt_c = math.sqrt(potential_prime)
    primes_under_c = getPrimeNumbers_SieveOfEratosthenes(2, int(sqrt_c))
    for prime in primes_under_c:
        if potential_prime % prime == 0:
            return False
    return True