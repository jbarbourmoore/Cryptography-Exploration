
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