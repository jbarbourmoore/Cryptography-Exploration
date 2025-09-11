
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

'''
    This funtion converts three bytes to a coefficinent modulo q of a polynomial
    According to Algorithm 14 of NIST FIPS 204

    Parameters : 
        b_0 : int
            The byte in the lowest position
        b_1 : int
            The byte in the middle position
        b_2 : int 
            The byte in the highest position
        q : int
            The modulo value
        
    Returns : 
        z : int 
            The integer value for the coefficient, -1 if it fails
        success : bool
            Whether the coefficient was successfully calculated
'''
def CoeffFromThreeBytes(b_0:int, b_1:int, b_2:int, q:int) -> set[bool, int]:
    b_2_prime = b_2
    if b_2_prime > 127:
        b_2_prime -= 128
    
    z = (2 ** 16) * b_2_prime + (2 ** 8) * b_1 + b_0
    if z < q:
        return True, q
    else :
        return False, -1
    
'''
    This funtion calculates the coefficient of a polynomial based on half a byte
    According to Algorithm 15 of NIST FIPS 204

    Parameters : 
        eta : int
            The bounds for the coefficient from - n to + n
        b : int
            The half byte to be calculated from
        
    Returns : 
        success : bool
            Whether the coefficient was successfully calculated
        z : int 
            The integer value for the coefficient, -1 if it fails
'''
def CoeffFromHalfByte(eta:int, b:int) -> set[bool, int]:
    success = False
    z = -1
    if eta == 2 and b < 16:
        success = True
        z = 2 - (b % 5)
    elif eta == 4 and b < 9:
        success = True
        z = 4 - b
    
    return success, z

'''
    This function converts a polynomial into a bit string consisting of bit values of equal lengths
    All coefficients are less than b but greater than 0
    As laid out in algorithm 16 of NIST FIPS 204

    Parameters:
        w : list[int]
            The coefficients for the polynomial
        b : int 
            The modulo value for the coefficients such that all coefficients are less than b but greater than 0
    
    Returns:
        z : list[int]
            The bit array consisting of the coefficients as equal length bit strings
'''
def SimpleBitPack(w:list[int], b:int)->list[int]:
    z = []
    bitlen = b.bit_length()

    for i in range(0, 256):
        z = z + IntegerToBits(w[i], bitlen)
    
    return z

'''
    This function converts a polynomial into a bit string consisting of bit values of equal lengths
    All coefficients are less than b but greater than a
    As laid out in algorithm 17 of NIST FIPS 204

    Parameters:
        w : list[int]
            The coefficients for the polynomial
        a : int
            The lower bounds for the coefficients
        b : int 
            The upper bounds for the coefficients
    
    Returns:
        z : list[int]
            The bit array consisting of the coefficients as equal length bit strings
'''
def BitPack(w:list[int], a:int, b:int)->list[int]:
    z = []
    c = b - a
    bitlen = c.bit_length()

    for i in range(0, 256):
        z = z + IntegerToBits(b - w[i], bitlen)
    
    return z

'''
    This function reverses the procedure for simple bit unpack
    According to Algorithm 18 of NIST FIPS 204

    Parameters :
        v : list[int]
            The bit array to be unpacked
        b : int 
            The modulous value that every coefficient falls below

    Returns :
        w : list[int]
            The byte array of coefficients
'''
def SimpleBitUnpack(v:list[int], b:int)->list[int]:
    c = b.bit_length()

    z = v.copy()
    w = []

    for i in range(0, 256):
        w = w + BitsToInteger(z[i * c : (i + 1) * c], c)

    return w

'''
    This function reverses the procedure for bit pack
    According to Algorithm 19 of NIST FIPS 204

    Parameters :
        v : list[int]
            The bit array to be unpacked
        a : int 
            The minimum value for every coefficient
        b : int 
            The modulous value that every coefficient falls below

    Returns :
        w : list[int]
            The byte array of coefficients
'''
def BitUnpack(v:list[int], a:int, b:int):
    c = b - a
    c = c.bit_length()

    z = v.copy()
    w = []

    for i in range(0, 256):
        w = w + BitsToInteger(z[i * c : (i + 1) * c], c)

    return w

'''
    This function reverses the procedure for hint bit pack
    According to Algorithm 20 of NIST FIPS 204

    Parameters :
        h : list[int]
            The byte array of coefficients to be packed
        w : int
        k : int

    Returns :
        w : list[int]
            The byte array resulting from the packing
'''
def HintBitPack(h:list[int], w:int, k:int):
    y = [0] * (w + k)
    index = 0
    for i in range(0, k):
        for j in range(0, 256):
            if h[i] != 0:
                y[index] = j
                index += 1
        y[w+i] = index
    return y

'''
    This function reverses the procedure for hint bit pack
    According to Algorithm 21 of NIST FIPS 204

    Parameters :
        y : list[int]
            The byte array to be unpacked
        w : int 
        k : int 

    Returns :
        success : bool
            Whether the hint unpacking was successful or not
        h : list[int]
            The byte array of coefficients
        
'''
def HintBitUnpack(y:list[int], w:int, k:int):
    h = [0] * k
    index = 0

    for i in range(0, k):
        if y[w + i] < index or y[w + i] > w:
            return False, []
        first = index
        while index < y[w + i]:
            if index > first and y[index - 1] >= y[index]:
                return False, []
            h[i] = 1
            index += 1
    
    return True, h

'''
    This function encodes a public key into a byte string
    According to Algorithm 22 of NIST FIPS 204

    Parameters :
        p : list[int]
            The primary key to encode
        k : int 
            Length of the key

    Returns :
        pk : list[int]
            The encoded primary key

'''
def pkEncode(p:list[int], t:list[int], k:int, q:int, d:int) -> list[int]:
    pk = p
    bits = q - 1
    bits = bits.bit_length()
    bits = bits - d
    mod = 2 ** bits - 1


    for i in range (0, k):
        pk = pk + SimpleBitPack(IntegerToBits(t[i]), mod)
    
    return pk

'''
    This function decodes a public key from a byte string
    According to Algorithm 23 of NIST FIPS 204

    Parameters :
        pk: list[int]
            The encoded public key

    Returns :
        p : list[int]
        t : list[int]
'''
def pkDecode(pk:list[int], k:int, q:int, d:int) -> list[list[int], list[int]]:
    p = pk[0:k]
    z = pk[k:]
    t = [0]*k

    bits = q - 1
    bits = bits.bit_length()
    bits = bits - d
    mod = 2 ** bits - 1

    for i in range(0, k):
        t[i] = SimpleBitUnpack(IntegerToBits(z[i]), mod)

    return p, t