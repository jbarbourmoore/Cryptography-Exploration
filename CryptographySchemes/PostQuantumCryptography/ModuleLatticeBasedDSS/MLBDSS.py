
'''
    This funtion creates a bit array representation of x mod 2 ** alpha
    According to Algorithm 9 of NIST FIPS 204

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