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
expected_values = {
    "b":[25,50,100,200,400,800,1600],
    "w":[1,2,4,8,16,32,64],
    "l":[0,1,2,3,4,5,6]
}

def theta(A, w):
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

    # 1. For all pairs (x,z) such that 0≤x<5 and 0≤z<w, let 
    # C[x,z]=A[x, 0,z] ⊕ A[x, 1,z] ⊕ A[x, 2,z] ⊕ A[x, 3,z] ⊕ A[x, 4,z].
    C = []
    for x in range(0, len(A)):
        C_x = []
        for z in range(0, len(A[x][0])):
            C_x_z = A[x][0][z]
            for y in range(1, len(A[x])):
                C_x_z = C_x_z ^ A[x][y][z]
            C_x.append(C_x_z)
        C.append(C_x)
        
    # 2. For all pairs (x, z) such that 0≤x<5 and 0≤z<w let 
    # D[x,z]=C[(x1) mod 5, z] ⊕ C[(x+1) mod 5, (z –1) mod w].
    D = []
    for x in range(0, len(A)):
        D_x = []
        for z in range(0, len(A[x][0])):
            D_x_z = C[(x - 1) % 5][z] ^ C[(x + 1) % 5][(z - 1) % w]
            D_x.append(D_x_z)
        D.append(D_x)

    # 3. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
    # A′[x, y,z] = A[x, y,z] ⊕ D[x,z]."
    A_prime = []
    for x in range (0, len(A)):
        A_prime_x = []
        for y in range(0, len(A[x])):
            A_prime_x_y = []
            for z in range(0, len(A[x][y])):
                A_prime_x_y_z = A[x][y][z] ^ D[x][z]
                A_prime_x_y.append(A_prime_x_y_z)
            A_prime_x.append(A_prime_x_y)
        A_prime.append(A_prime_x)
    
    return A_prime

def rho(A, w):
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
    # 1. For all z such that 0≤z<w, let A′ [0, 0,z] = A[0, 0,z].
    A_prime = []
    for x in range(0, len(A)):
        A_x_prime = []
        for y in range(0, len(A[x])):
            A_x_y_prime = []
            for z in range(0, len(A[x][y])):
                if x == 0 and y == 0:
                    A_x_y_prime.append(A[x][y][z])
                else : A_x_y_prime.append(0)
            A_x_prime.append(A_x_y_prime)
        A_prime.append(A_x_prime)

    # 3. For t from 0 to 23:
    # a. for all z such that 0≤z<w, let A′[x, y,z] = A[x, y, (z–(t+1)(t+2)/2) mod w];
    # b. let (x, y) = (y, (2x+3y) mod 5).
    x = 0
    y = 1
    for t in range(0, 23):
        for z in range(0, w):
            z_prime_location = (z - (t + 1) * (t + 2) // 2) % w
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

    A_prime = []
    for x in range(0, len(A)):
        A_x_prime = []
        for y in range(0, len(A[x])):
            A_x_y_prime = []
            for z in range(0, len(A[x][y])):
               A_x_1 = A[(x + 1) % 5][y][z] ^ 1
               A_x_2 = A[(x + 1) % 5][y][z]
               A_x_1x2 = A_x_1 * A_x_2
               A_x_y_prime.append(A[x][y][z] ^ A_x_1x2)
            A_x_prime.append(A_x_y_prime)
        A_prime.append(A_x_prime)

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
    for i in range(1, t % 255 + 1):
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
    3. For j from 0 to l, let RC[2j –1]=rc(j+7ir).
    4. For all z such that 0≤z<w, let A′[0, 0,z]=A′[0, 0,z] ⊕ RC[z].
    5. Return A′."
    '''
    # 1. For all triples (x, y,z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let A′[x, y,z] = A[x, y,z].
    A_prime = []
    for x in range(0, len(A)):
        A_x_prime = []
        for y in range(0,len(A[x])):
            A_x_y_prime = []
            for z in range(0,len(A[x][y])):
                A_x_y_prime.append(z)
            A_x_prime.append(A_x_y_prime)
        A_prime.append(A_x_prime)

    # 2. Let RC=0w
    RC = [0]*w

    # 3. For j from 0 to l, let RC[2j –1]=rc(j+7ir).
    for j in range(0, int(l)):
        RC[2 * j - 1]=rc(j + 7 * ir)

    #4. For all z such that 0≤z<w, let A′[0, 0,z]=A′[0, 0,z] ⊕ RC[z].
    for z in range(0,w):
        A_prime[0][0][z] = A_prime[0][0][z] ^ RC[z]

    return A_prime

def round(A, i, w, l, is_debug):
    '''
    This method should implement round as according to Algorithm 7 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir)
    '''
    
    A_theta = theta(A,w) # θ
    A_rho = rho(A_theta,w) # ρ
    A_pi = pi(A_rho) # π
    A_chi = chi(A_pi) # χ
    A_iota = iota(A_chi, i,w,l) # ι
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
    for i in range(12+21 - nr,12+21):
        A = round(A, i, w, l, is_debug=True)
    
    S_prime = stateArrayToBitString(A,w)

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
    A = []
    for x in range(0,5):
        A_x = []
        for y in range(0,5):
            A_x_y = []
            for z in range (0,w):
                index = w * (5 * y + x) + z
                A_x_y.append(int(S[index]))
            A_x.append(A_x_y)
        A.append(A_x)
    
    return A

def stateArrayToBitString(A, w):
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

    
    S = ""
    for x in range(0, 5):
        for y in range(0, 5):
            for z in range (0, w):
                S+=str(A[x][y][z])
    return S

test_string_1 = '1010101010 1010101010 1010101010 1010101010 1010101010'
test_string_1 = test_string_1.replace(" ","")
response_string = keccak_p(test_string_1,18)
print(response_string)
print(len(response_string))
test_string_1 = '1010101010 1111111111 1010101010 1010101010 1010101010'
test_string_1 = test_string_1.replace(" ","")
response_string = keccak_p(test_string_1,1)
print(response_string)
print(len(response_string))
test_string_1 = '1010101010 1111110111 01011'
test_string_1 = test_string_1.replace(" ","")
response_string = keccak_p(test_string_1,2)
print(response_string)
print(len(response_string))