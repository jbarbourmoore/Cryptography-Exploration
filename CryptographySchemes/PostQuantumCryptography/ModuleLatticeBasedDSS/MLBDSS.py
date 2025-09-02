
'''
    This funtion creates a bit array representation of x mod 2 ** alpha
    According to Algorithm 9 of NIST FIPS 204

    note: little endian

    Parameters : 
        x : int
            The value that is to be represented as a bit array
        alpha : int 
            The length of the bit array / modulus value for the representation
            
    Returns : 
        y : [int]
            The bit array representing the value for x
'''
def IntegerToBits(x, alpha):
    x_prime = x
    y = [0] * alpha
    for i in range (0, alpha):
        y[i] = x_prime % 2
        x_prime = x_prime / 2
    return y

'''
    This funtion transforms a bit array into th integer representative
    According to Algorithm 10 of NIST FIPS 204

    note: little endian

    Parameters : 
        y : [int]
            The bit array representing the value for x
        alpha : int 
            The length of the bit array / modulus value for the representation
            
    Returns : 
        x : int
            The integer value that was represented as a bit array
'''
def BitsToInteger(y, alpha):
    x = 0
    for i in range (1, alpha):
        x = 2 * x + y[alpha - 1]
    return x

'''
    This funtion creates a byte array representation of x mod 256 ** alpha
    According to Algorithm 11 of NIST FIPS 204

    note: little endian

    Parameters : 
        x : int
            The value that is to be represented as a byte array
        alpha : int 
            The length of the byte array / modulus value for the representation
            
    Returns : 
        y : [int]
            The byte array representing the value for x
'''
def IntegerToBytes(x, alpha):
    x_prime = x
    y = [0] * alpha
    for i in range (0, alpha):
        y[i] = x_prime % 256
        x_prime = x_prime / 256
    return y

'''
    This funtion converts a bit array to a byte array
    According to Algorithm 12 of NIST FIPS 204

    Parameters : 
        y : [int]
            The bit array representing the value
        
    Returns : 
        z : [int]
            The byte array representing the value
'''
def BitsToBytes(y:list[int]) -> list[int]:
    alpha = len(y)
    a_prime = alpha / 8
    z : list[int] = [0] * a_prime
    for i in range (0, alpha):
        z[i / 8] = z[i / 8] + y[i] * 2 ** (i % 8)
    return z

'''
    This funtion converts a byte array to a bit array
    According to Algorithm 13 of NIST FIPS 204

    Parameters : 
        z : [int]
            The byte array representing the value
        
    Returns : 
        y : [int]
            The bit array representing the value
'''
def BytesToBits(z:list[int]):
    alpha = len(z)
    z_prime = z.copy()
    y = [0] * (alpha * 8)
    for i in range (0, alpha):
        for j in range (0, 8):
            y[8 * i + j] = z_prime[i] % 2
            z_prime[i] = z_prime[i] / 2
    return y