'''
Starting to put together pieces. Will likely create classes and such before I'm done

https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
Notes from NIST FIPS 202

b = number of bits
w = b /25
l = log2(b/25)

For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y< 5, and 0 ≤ z < w, 
given bit string S
A[x, y, z] = S [w(5y + x) + z].

 
For each pair of integers (i, j) such that 0 ≤ i < 5 and 0 ≤ j < 5, define the string Lane (i, j) by  
Lane (i, j) = A[i, j, 0] || A[i, j, 1] || A[i, j, 2] || … || A[i, j, w-2] || A[i, j, w-1].


For each integer j such that 0 ≤ j < 5, define the string Plane (j) by 
Plane (j) = Lane (0, j) || Lane (1, j) || Lane (2, j) || Lane (3, j) || Lane (4, j). 

Then S = Plane (0) || Plane (1) || Plane (2) || Plane (3) || Plane (4). 
'''

from math import log2
import numpy as np

expected_values = {
    "b":[25,50,100,200,400,800,1600],
    "w":[1,2,4,8,16,32,64],
    "l":[0,1,2,3,4,5,6]
}

def theta(A):
    '''
    This method should implement theta as according to Algorithm 1 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    
    "Algorithm 1: θ(A)
    Input:
    state array A.
    Output:
    state array A′

    Steps:
    1. For all pairs (x,z) such that 0≤x<5 and 0≤z<w, let 
    C[x,z]=A[x, 0,z] ⊕ A[x, 1,z] ⊕ A[x, 2,z] ⊕ A[x, 3,z] ⊕ A[x, 4,z].
    2. For all pairs (x, z) such that 0≤x<5 and 0≤z<w let 
    D[x,z]=C[(x1) mod 5, z] ⊕ C[(x+1) mod 5, (z –1) mod w].
    3. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
    A′[x, y,z] = A[x, y,z] ⊕ D[x,z]."
    '''
    w= len(A[0][0])
    # 1. For all pairs (x,z) such that 0≤x<5 and 0≤z<w, let 
    # C[x,z]=A[x, 0,z] ⊕ A[x, 1,z] ⊕ A[x, 2,z] ⊕ A[x, 3,z] ⊕ A[x, 4,z].
    C = [[0 for z in range(0, w)]  for x in range(0,5)]
    for x in range(0, len(A)):
        for z in range(0, w):
            C[x][z] = A[x][0][z] ^ A[x][1][z] ^ A[x][2][z] ^ A[x][3][z] ^ A[x][4][z]

    # 2. For all pairs (x, z) such that 0≤x<5 and 0≤z<w let 
    # D[x,z]=C[(x-1) mod 5, z] ⊕ C[(x+1) mod 5, (z –1) mod w].
    D = [[0 for z in range(0, w)]  for x in range(0,5)]
    for x in range(0, 5):
        for z in range(0, w):
            D[x][z] = C[(x - 1) % 5][z] ^ C[(x + 1) % 5][(z - 1) % w]
    
    # 3. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
    # A′[x, y,z] = A[x, y,z] ⊕ D[x,z]."
    A_prime = [[[0 for z in range(0,w)] for y in range(0,5)] for x in range(0,5)]
    for x in range (0, 5):
        for y in range(0, 5):
            for z in range(0, w):
                A_prime[x][y][z] = A[x][y][z] ^ D[x][z]
    return A_prime

def rho(A):
    '''
    This method should implement rho as according to Algorithm 2 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    "Algorithm 2: ρ(A)
    Input:
    state array A.
    Output:
    state array A′.
    Steps:
    1. For all z such that 0≤z<w, let A′ [0, 0,z] = A[0, 0,z].
    2. Let (x, y) = (1, 0).
    3. For t from 0 to 23:
    a. for all z such that 0≤z<w, let A′[x, y,z] = A[x, y, (z–(t+1)(t+2)/2) mod w];
    b. let (x, y) = (y, (2x+3y) mod 5).
    4. Return A′"
    '''
    w = len(A[0][0])
    A_prime = [[[0 for z in range(0, w)] for y in range(0, 5)] for x in range(0, 5)]

    # 1. For all z such that 0≤z<w, let A′ [0, 0,z] = A[0, 0, z].
    for z in range(0, w):
          A_prime[0][0][z] = A[0][0][z]     

    # 3. For t from 0 to 23:
    # a. for all z such that 0≤z<w, let A′[x, y,z] = A[x, y, (z–(t+1)(t+2)/2) mod w];
    # b. let (x, y) = (y, (2x+3y) mod 5).
    x = 0
    y = 1
    for t in range(0, 24):
        for z in range(0, w):
            z_prime_locationPre_modulo = (z - (((t + 1) * (t + 2)) // 2))
            z_prime_location = z_prime_locationPre_modulo  % w
            # print(f"z:{z} t:{t} z-prime-loc = {z_prime_locationPre_modulo} z-prime-location = {z_prime_location}")
            A_prime[x][y][z] = A[x][y][ z_prime_location ]
            x_new = y
            y = (2 * x + 3 * y) % 5
            x = x_new

    return A_prime

def pi(A):
    '''
    This method should implement pi as according to Algorithm 3 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    Algorithm 3: π(A)
    Input:
    state array A.
    Output:
    state array A′.
    Steps:
    1. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
    A′[x, y, z]=A[(x + 3y) mod 5, x, z].
    2. Return A
    '''

    # 1. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
    # A′[x, y, z]=A[(x + 3y) mod 5, x, z].
    A_prime = []
    for x in range(0, len(A)):
        A_x_prime = []
        for y in range(0, len(A[x])):
            A_x_y_prime = []
            for z in range(0, len(A[x][y])):
               x_old_loc =( x + 3 * y) % 5
               y_old_loc = x
               A_x_y_prime.append(A[x_old_loc][y_old_loc][z])
            A_x_prime.append(A_x_y_prime)
        A_prime.append(A_x_prime)

    return A_prime

def chi(A):

    '''
    This method should implement chi as according to Algorithm 4 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    "Algorithm 4: χ(A)
    Input:
    state array A.
    Output:
    state array A′.
    Steps:
    1. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
    A′[x, y,z] = A[x, y,z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
    2. Return A′."
    '''

    A_prime = [[[0 for z in range(0,len(A[0][0]))] for y in range(0,len(A[0]))] for x in range(0,len(A))]
    for x in range(0, len(A)):
        for y in range(0, len(A[x])):
            for z in range(0, len(A[x][y])):
                xor = np.bitwise_xor(A[(x+1)%5][y][z], 1)
                mul = xor * (A[(x+2)%5][y][z])
                A_prime[x][y][z] = np.bitwise_xor(A[x][y][z], mul)
           

    return A_prime

def rc(t):
    '''
    This method should implement rc as according to Algorithm 5 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    "Algorithm 5: rc(t)
    Input:
    integer t.
    Output:
    bit rc(t).
    Steps:
    1. If t mod 255 = 0, return 1.
    2. Let R = 10000000.
    3. For i from 1 to t mod 255, let: 
    a. R = 0 || R;
    b. R[0] = R[0] ⊕ R[8];
    c. R[4] = R[4] ⊕ R[8];
    d. R[5] = R[5] ⊕ R[8];
    e. R[6] = R[6] ⊕ R[8];
    f. R =Trunc8[R].
    4. Return R[0]."
    '''

    # 1. If t mod 255 = 0, return 1.
    if t % 255 == 0:
        return 1
    
    # 2. Let R = 10000000.
    R = [1,0,0,0,0,0,0,0]

    # 3. For i from 1 to t mod 255, let: 
    for x in range(1, t % 255 + 1):
        # a. R = 0 || R
        R = [0] + R
        # b. R[0] = R[0] ⊕ R[8]
        R[0] = R[0] ^ R[8]
        # c. R[4] = R[4] ⊕ R[8]
        R[4] = R[4] ^ R[8]
        # d. R[5] = R[5] ⊕ R[8]
        R[5] = R[5] ^ R[8]
        # e. R[6] = R[6] ⊕ R[8]
        R[6] = R[6] ^ R[8]
        # f. R =Trunc8[R]
        R = R[0:8]
    # 4. Return R[0]
    return R[0]

def iota(A, ir, w, l):
    '''
    This method should implement iota as according to Algorithm 6 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    "Algorithm 6: ι(A, ir)
    Input:
    state array A;
    round index ir.
    Output:
    state array A′.
    Steps:
    1. For all triples (x, y,z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let A′[x, y,z] = A[x, y,z].
    2. Let RC=0w
    .
    3. For j from 0 to l, let RC[2**j –1]=rc(j+7ir).
    4. For all z such that 0≤z<w, let A′[0, 0,z]=A′[0, 0,z] ⊕ RC[z].
    5. Return A′."
    '''

    # 1. For all triples (x, y,z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let A′[x, y,z] = A[x, y,z].
    A_prime = [[[A[x][y][z] for z in range(0,len(A[0][0]))] for y in range(0,len(A[0]))] for x in range(0,len(A))]
    
    # 2. Let RC=0w
    RC = [0]*w

    # 3. For j from 0 to l, let RC[2**j –1]=rc(j+7ir).
    for j in range(0, int(l)):
        RC[2**j - 1]=rc(j + 7 * ir)

    #4. For all z such that 0≤z<w, let A′[0, 0,z]=A′[0, 0,z] ⊕ RC[z].
    for z in range(0,w):
        A_prime[0][0][z] = A_prime[0][0][z] ^ RC[z]

    return A_prime

def round(A, ir, w, l, is_debug):
    '''
    This method should implement round as according to Algorithm 7 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir)
    '''
    
    A_theta = theta(A) # θ
    A_rho = rho(A_theta) # ρ
    A_pi = pi(A_rho) # π
    A_chi = chi(A_pi) # χ
    A_iota = iota(A_chi, ir,w,l) # ι
    if is_debug:
        print(f"Initial State: {stateArrayToBitString(A,w)}")
        print(f"After Theta: {stateArrayToBitString(A_theta,w)}")
        print(f"After Rho: {stateArrayToBitString(A_rho,w)}")
        print(f"After Pi: {stateArrayToBitString(A_pi,w)}")
        print(f"After Chi: {stateArrayToBitString(A_chi,w)}")
        print(f"After Iota: {stateArrayToBitString(A_iota,w)}")

    return A_iota

def keccak_p(S, nr):
    '''
    This method should implement keccakp as according to Algorithm 7 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    "Algorithm 7: KECCAK-p[b, nr](S) 
    Input:
    string S of length b;
    number of rounds nr.
    Output:
    string S′ of length b.
    Steps:
    1. Convert S into a state array, A, as described in Sec. 3.1.2. 
    2. For ir from 12+2l –nr to 12+2l –1, let A=Rnd(A, ir).
    3. Convert A into a string S′ of length b, as described in Sec. 3.1.3.
    4. Return S′ "
    '''

    b = len(S)
    w = b // 25
    l = log2(w)
    # 1. Convert S into a state array, A, as described in Sec. 3.1.2. 
    A = bitStringToStateArray(S)

    # 2. For ir from 12+2l –nr to 12+2l –1, let A=Rnd(A, ir)
    for x in range(12+21 - nr,12+21):
        A = round(A, x, w, l, is_debug=False)
    
    S_prime = stateArrayToBitString(A)

    return S_prime


def bitStringToStateArray(S):
    '''
    This method should convert a string to a state array as according to Section 3.1.2 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    b = number of bits
    w = b /25
    l = log2(b/25)

    "For all triples (x, y,z) such that 0≤x<5, 0≤y<5, and 0≤z<w, 
    A[x, y,z]=S[w(5y+x)+z]"
    '''
    b = len(S)
    w = b // 25
    A = [[[0 for z in range(0,w)] for y in range(0,5)] for x in range(0,5)]
    for x in range(0,5):
        for y in range(0,5):
            for z in range (0,w):
                index = w * (5 * y + x) + z
                A[x][y][z] = (int(S[index],2))
    return A

def stateArrayToBitString(A):
    '''
    This method should convert a state array to a bit string as according to Section 3.1.4 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    b = number of bits
    w = b /25
    l = log2(b/25)

    "For each pair of integers (i, j) such that 0 ≤ i < 5 and 0 ≤ j < 5, define the string Lane (i, j) by  
    Lane (i, j) = A[i, j, 0] || A[i, j, 1] || A[i, j, 2] || … || A[i, j, w-2] || A[i, j, w-1].


    For each integer j such that 0 ≤ j < 5, define the string Plane (j) by 
    Plane (j) = Lane (0, j) || Lane (1, j) || Lane (2, j) || Lane (3, j) || Lane (4, j). 

    Then S = Plane (0) || Plane (1) || Plane (2) || Plane (3) || Plane (4)"
    '''

    #print(len(A[0][0]))
    S = ""
    for y in range(0, 5):
        for x in range(0, 5):
            for z in range (0, len(A[0][0])):
                S+=str(A[x][y][z])   
    return S

def pad101(x, m):
    '''
    This method should implement pad10*1 as according to Algorithm 9 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    Algorithm 9: pad10*1(x, m)
    Input:
    positive integer x;
    non-negative integer m.
    Output:
    string P such that m + len(P) is a positive multiple of x.
    Steps:
    1. Let j = (– m – 2) mod x.
    2. Return P = 1 || 0 * j || 1
    '''

    y = (-m - 2) % x
    pad = "1" + "0" * y + "1"
    print("pad"+pad)
    return pad

class SHA3():

    def __init__(self, f, digest_length, is_debug = True):
        self.function_name = f
        self.digest_length = digest_length
        self.capacity = digest_length * 2
        self.b = 1600
        self.is_debug = is_debug

    def sponge(self, N):
        '''
        This method should implement sponge as according to Algorithm 8 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        d --> self.digest_length

        "Algorithm 8: SPONGE[f, pad, r](N, d)
        Input:
        string N,
        nonnegative integer d.
        19
        Output:
        string Z such that len(Z)=d.
        Steps:
        1. Let P=N || pad(r, len(N)).
        2. Let n=len(P)/r.
        3. Let c=br.
        4. Let P0, … , Pn-1 be the unique sequence of strings of length r such that P = P0 || … || Pn1.
        5. Let S=0b.
        6. For i from 0 to n1, let S=f (S ⊕ (Pi|| 0c)).
        7. Let Z be the empty string.
        8. Let Z=Z || Truncr(S).
        9. If d≤|Z|, then return Trunc d (Z); else continue.
        10. Let S=f(S), and continue with Step 8."
        '''
        r = self.b - self.capacity
        w = self.b // 25
        l = int(log2(w))
        nr = 12+2*l
        P_string = N + pad101(r, len(N))
        print(self.binaryToHex(P_string))
        n = len(P_string) // r
        P = []
        for x in range(0,n):
            P.append(P_string[x:x+r])
        S = '0'*self.b
        for x in range(0,n):
            if self.is_debug:
                print("Data to be absorbed: "+self.binaryToHex(P[x]))
            S = self.bitwiseXor(S, P[x]+"0"*self.capacity)
            if self.is_debug:
                print("Xord: "+self.binaryToHex(S))
            S = keccak_p(S,nr=nr)
       
        Z = ''
        Z = Z + S[:r]
        while self.digest_length > len(Z):
            S = keccak_p(S,nr=nr)
            Z = Z + S[:r]
        return Z[:self.digest_length]
    

    def binaryToHex(self, binary):
        #print(binary)
        return '{0:0{1}x}'.format(int(binary,2),len(binary)//4)

    def hashStringToHex(self, message_string):
        bytes_data = message_string.encode('utf-8')
        binary_string = bin(int(bytes_data.hex(),16))[2:]
        print(binary_string)
        return hex(int(self.sponge(binary_string+"01"),2))[2:]
    
    def hashBinaryStringToHex(self, binary_message):
        return hex(int(self.sponge(binary_message+"01"),2))[2:]

    def bitwiseXor(self,string_1,string_2):
        int_result = int(string_1,2) ^ int(string_2,2)
        string_result = '{0:0{1}b}'.format(int_result,len(string_1))
        return string_result

class SHA3_224(SHA3):

    def __init__(self):
        super().__init__(f="SHA3-224", digest_length=224)

class SHA3_256(SHA3):

    def __init__(self):
        super().__init__(f="SHA3-256", digest_length=256)
        
class SHA3_384(SHA3):

    def __init__(self):
        super().__init__(f="SHA3-384", digest_length=384)

class SHA3_512(SHA3):

    def __init__(self):
        super().__init__(f="SHA3-512", digest_length=512)
if __name__ =="__main__":
    test_string_1 = '1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010'
    test_string_1 = test_string_1.replace(" ","")
    response_string = keccak_p(test_string_1,18)
    print(response_string)
    print(len(response_string))
    test_string_1 = '1010101010 1111111111 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010 1010101010'
    test_string_1 = test_string_1.replace(" ","")
    response_string = keccak_p(test_string_1,1)
    print(response_string)
    print(len(response_string))
    test_string_1 = '1010101010 1111110111 01011'
    test_string_1 = test_string_1.replace(" ","")
    response_string = keccak_p(test_string_1,2)
    print(response_string)
    print(len(response_string))
    sha512 = SHA3_512()
    # hash_hello = sha512.hashStringToHex("whst am I doing")
    # print(hash_hello)

    # import hashlib
    # print(hashlib.sha3_512("whst am I doing".encode("utf-8")).hexdigest())

    input_string = "11001"
    expected_hash = "A1 3E 01 49 41 14 C0 98 00 62 2A 70 28 8C 43 21 21 CE 70 03 9D 75 3C AD D2 E0 06 E4 D9 61 CB 27 54 4C 14 81 E5 81 4B DC EB 53 BE 67 33 D5 E0 99 79 5E 5E 81 91 8A DD B0 58 E2 2A 9F 24 88 3F 37"
    sha512 = SHA3_512()
    print(sha512.binaryToHex(input_string))
    print(sha512.binaryToHex(input_string+"01"))
    hash = sha512.hashBinaryStringToHex(input_string)
    print(hash)

    xord_state_expected = "D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    xord_state_expected = xord_state_expected.replace(" ","")
    xord_state_binary = '{0:0{1}b}'.format(int(xord_state_expected,16),len(xord_state_expected*4))
    print(len(xord_state_binary))
    xord_state = bitStringToStateArray(xord_state_binary)
    theta = theta(xord_state)
    print(len(theta[0][0]))
    print("state arry to string",len(stateArrayToBitString(theta)))
    print("state arry to hex",len(sha512.binaryToHex(stateArrayToBitString(theta))))

    theta_state_expected = "D3 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A6 01 00 00 00 00 00 80 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 80 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A6 01 00 00 00 00 00 80 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A6 01 00 00 00 00 00 80 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A6 01 00 00 00 00 00 80"
    theta_state_expected = theta_state_expected.replace(" ","")
    print(sha512.binaryToHex(stateArrayToBitString(theta)).upper())
    print(theta_state_expected.upper())