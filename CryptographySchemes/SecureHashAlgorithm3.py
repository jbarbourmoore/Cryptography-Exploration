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
            C_x_z = A[x][0]
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
    This method should implement theta as according to Algorithm 1 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

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
    w = 1600 // 25

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
            z_prime_location = (z - (t + 1)(t + 2) // 2) % w
            A_prime[x][y][z] = A[x][y][ z_prime_location ]
            x_new = y
            y = (2 * x + 3 * y) % 5
            x = x_new

    return A_prime