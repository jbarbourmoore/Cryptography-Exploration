'''
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

from math import log2, ceil
import numpy as np

expected_values = {
    "b":[25,50,100,200,400,800,1600],
    "w":[1,2,4,8,16,32,64],
    "l":[0,1,2,3,4,5,6]
}



class SHA3():

    def __init__(self, f, digest_length, is_debug = False):
        '''
        This method initializes the SHA 3 object

        Parameters: 
            f : str
                the function name
            digest_length: int
                The size of the SHA3 digest in bits
        '''

        self.function_name = f
        self.digest_length = digest_length
        self.capacity = digest_length * 2
        self.b = 1600
        self.is_debug = is_debug

    def sponge(self, N):
        '''
        This method should implement sponge as according to Algorithm 8 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters:
            N : str
                The binary string currently being processessed
        
        Returns :
            digest : str
                The hash digest as a binary string

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
        P_string = N + self.pad101(r, len(N))
        n = len(P_string) // r
        P = []
        for x in range(0,n):
            P.append(P_string[x:x+r])
        S = '0'*self.b
        for x in range(0,n):
            if self.is_debug:
                print("Data to be absorbed: "+ self.b2h(P[x]))
            S = self.bitwiseXor(S, P[x]+"0"*self.capacity)
            if self.is_debug:
                print("Xord: "+self.b2h(S))
            S = self.keccak_f(S)
       
        Z = ''
        Z = Z + S[:r]
        while self.digest_length > len(Z):
            S = self.keccak_f(S)
            Z = Z + S[:r]
        return Z[:self.digest_length]

    def hashBinaryStringToHex(self, binary_message):
        '''
        This method takes in a binary string and returns the SHA 3 hash for it as a hexadecimal string

        Parameters :
            binary_message : str
                The message to be hashed as a binary string

            hex_string : str
                The sha3 hash value for the message as a hexadecimal string
        '''

        binary_message += "01"
        binary_result = self.sponge(binary_message)
        hex_string = self.b2h(binary_result)
        return hex_string

    def bitwiseXor(self,string_1,string_2):
        '''
        This method performs a bitwise xor of two binary strings of the same length

        Parameters :
            string_1 : str
                The binary string for one of the values that is being xord
            string_2 str 
                The binary string for the other value being xord

        Returns :
            string_result : str
                The binary string of the result of the xor
        '''

        int_result = int(string_1,2) ^ int(string_2,2)
        string_result = '{0:0{1}b}'.format(int_result,len(string_1))
        return string_result
    
    def theta(self, A):
        '''
        This method should implement theta as according to Algorithm 1 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        
        Parameters :
            A : [[[int]]]
                The current state array for the hashing process

        Returns : 
            A_prime : [[[int]]]
                The state array for the hashing process at the conclusion of this method

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

    def rho(self, A):
        '''
        This method should implement rho as according to Algorithm 2 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters :
            A : [[[int]]]
                The current state array for the hashing process

        Returns : 
            A_prime : [[[int]]]
                The state array for the hashing process at the conclusion of this method
                
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
        rho_matrix=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
        A_prime = [[[0 for z in range(0, w)] for y in range(0, 5)] for x in range(0, 5)]
        for i in range(0,5):
            for j in range(0,5):
                for k in range(w):
                    select = rho_matrix[i][j] # Use lookup table to "calculate" (t + 1)(t + 2)/2
                    A_prime[i][j][k] = A[i][j][(k - select)%w]
        return A_prime

    def pi(self, A):
        '''
        This method should implement pi as according to Algorithm 3 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters :
            A : [[[int]]]
                The current state array for the hashing process

        Returns : 
            A_prime : [[[int]]]
                The state array for the hashing process at the conclusion of this method

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

    def chi(self, A):

        '''
        This method should implement chi as according to Algorithm 4 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        
        Parameters :
            A : [[[int]]]
                The current state array for the hashing process

        Returns : 
            A_prime : [[[int]]]
                The state array for the hashing process at the conclusion of this method

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

    def rc(self, t):
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

    def iota(self, A, ir):
        '''
        This method should implement iota as according to Algorithm 6 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        
        Parameters :
            A : [[[int]]]
                The current state array for the hashing process

        Returns : 
            A_prime : [[[int]]]
                The state array for the hashing process at the conclusion of this method

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
        w = len(A[0][0])

        iota_round_constants = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
        
        # 1. For all triples (x, y,z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let A′[x, y,z] = A[x, y,z].
        A_prime = [[[A[x][y][z] for z in range(0,w)] for y in range(0,5)] for x in range(0,5)]

        iota_round_constant = iota_round_constants[ir]

        # 4. For all z such that 0≤z<w, let A′[0, 0,z]=A′[0, 0,z] ⊕ RC[z].
        for z in range(w):
            A_prime[0][0][z] ^= (iota_round_constant >> z) & 1

        return A_prime
        
    def round(self, A, ir):
        '''
        This method should implement round as according to Algorithm 7 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters :
            A : [[[int]]]
                The current state array for the hashing process
            ir : int
                Which round we are on

        Returns : 
            A_iota : [[[int]]]
                The state array for the hashing process at the conclusion of this method

        Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir)
        '''
        A_theta = self.theta(A) # θ
        A_rho = self.rho(A_theta) # ρ
        A_pi = self.pi(A_rho) # π
        A_chi = self.chi(A_pi) # χ
        A_iota = self.iota(A_chi, ir) # ι
        if self.is_debug:
            print(f"Initial State: {self.b2h(self.stateArrayToBitString(A))}")
            print(f"After Theta: {self.b2h(self.stateArrayToBitString(A_theta))}")
            print(f"After Rho: {self.b2h(self.stateArrayToBitString(A_rho))}")
            print(f"After Pi: {self.b2h(self.stateArrayToBitString(A_pi))}")
            print(f"After Chi: {self.b2h(self.stateArrayToBitString(A_chi))}")
            print(f"IR: {ir} After Iota: {self.b2h(self.stateArrayToBitString(A_iota))}")

        return A_iota

    def keccak_p(self, S, nr):
        '''
        This method should implement keccakp as according to Algorithm 7 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters :
            S : str
                The message string being processed
            nr : int
                The number of rounds to run

        Returns :
            S_prime : str
                The message string after it has been processed

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

        # 1. Convert S into a state array, A, as described in Sec. 3.1.2. 
        A = self.bitStringToStateArray(S)

        # 2. For ir from 0 to nr, let A=Rnd(A, ir)
        for x in range(0,nr):
            A = self.round(A, x)
            
        S_prime = self.stateArrayToBitString(A)

        return S_prime

    def keccak_f(self, S):
        '''
        The method should implement keccak f as according to https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        It calls keccak_p a set number of times (24)

        Parameters :
            S : str
                The message string being processed

        Returns :
            S_prime : str
                The message string after it has been processed

        '''

        return self.keccak_p( S, 24)

    def bitStringToStateArray(self, S):
        '''
        This method should convert a string to a state array as according to Section 3.1.2 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters :
            S : str
                The bit string being converted

        Returns :
            A : [[[int]]]
                The equivalent state array to the bit string

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

    def stateArrayToBitString(self, A):
        '''
        This method should convert a state array to a bit string as according to Section 3.1.4 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters :
            A : [[[int]]]
                The state array being converted

        Returns :
            S : str
                The equivalent binary string to the state array

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
        for y in range(0, 5):
            for x in range(0, 5):
                for z in range (0, len(A[0][0])):
                    S+=str(A[x][y][z])   
        return S

    def pad101(self, x, m):
        '''
        This method should implement pad10*1 as according to Algorithm 9 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

        Parameters :
            x : int
                The lenth of each message segment
            m : int
                The length of the message

        Returns : str
            The bit string of the padding
        
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
        return pad

    def h2b(self, H:str,n=None):
        '''
        This method converts a hexadecimal string to a binary string as according to th appendix of nist fips 202
        ! not the normal way to interpret a hexadecimal string !

        Parameters : 
            H : str
                The hexadecimal string being converted
            n : int
                The maximum length of the binary string

        Returns 
            binary_result : str
                The binary string resulting from the conversion

        Algorithm 10: h2b(H, n).
        Input:
        hexadecimal string H consisting of 2m digits for some positive integer m;
        positive integer n such that n ≤ 8m.
        Output:
        bit string S, such that len(S)=n.
        Steps:
        1. For each integer i such that 0 ≤ i < 2m-1, let Hi be the ith hexadecimal digit in H: 
        H=H0 H1 H2 H3 … H2m-2 H2m-1.
        2. For each integer i such that 0 ≤ i < m:
        a. Let hi =16⋅ H2i +H2i+1. 
        b. Let bi0 bi1 bi2 bi3 bi4 bi5 bi6 bi7 be the unique sequence of bits such that 
        hi =bi7⋅ 27+ bi6⋅ 26+ bi5⋅ 25+ bi4⋅ 24+ bi3⋅ 23+ bi2⋅ 22+ bi1⋅ 21 + bi0⋅ 20
        .
        3. For each pair of integers (i, j) such that 0 ≤ i < m and 0 ≤ j < 8, let T[8i + j]=bij.
        4. Return S=Truncn(T).
    '''
        
        H = H.replace(" ","")
        m = len(H)//2
        H_i = []
        if n == None:
            n=8*m
        for i in range(0,2*m):
            H_i.append(int(H[i],16))
        
        binary_result = ""
        for i in range(0,m):
            h_i = 16*H_i[2*i]+H_i[2*i+1]
            binary = '{0:0{1}b}'.format(h_i,8)
            for i in range(0,8):
                binary_result+=(binary[7-i])
        return binary_result[:n]


    def b2h(self, S):
        '''
        This method converts a binary string to a hexadecimal string as according to th appendix of nist fips 202
        ! not the normal way to interpret a hexadecimal string !

        Parameters : 
            S : str
                The binary string being converted

        Returns 
            hex_string : str
                The hexadecimal string resulting from the conversion
        Algorithm 11: b2h(S).
        Input:
        bit string S consisting of n bits for a positive integer n.
        Output:
        hexadecimal string H consisting of 2n/8 digits. 
        Steps:
        1. Let n=len(S).
        2. Let T=S || 0-n mod 8 and m=n/8.
        3. For each pair of integers (i, j) such that 0 ≤ i < m and 0 ≤ j < 8, let bij=T[8i + j].
        4. For each integer i such that 0 ≤ i < m:
        a. Let hi = bi7⋅ 27+ bi6⋅ 26+ bi5⋅ 25+ bi4⋅ 24+ bi3⋅ 23+ bi2⋅ 22+ bi1⋅ 21+ bi0⋅ 20.
        b. Let H2i and H2i +1 be the hexadecimal digits such that hi=16⋅ H2i + H2i+1. 
        5. Return H = H0 H1 H2 H3 … H2m-2 H2m-1.
        '''
        n = len(S)
        m= ceil(n/8)
        T = S+"0"*(-n%8)
        b=[]
        hex_string = ''
        for i in range(0,m):
            b_i = []
            for j in range(0,8):
                b_i.append(T[8*i+j])
            b.append(b_i)
            h = b[i][7]+b[i][6]+b[i][5]+b[i][4]+b[i][3]+b[i][2]+b[i][1]+b[i][0]
            H='{0:0{1}x}'.format(int(h,2),2).upper()
            hex_string+=H
        return hex_string

class SHA3_224(SHA3):
    '''
    This class instantiates a sha 3 object with a 224 bit digest length
    '''

    def __init__(self):
        '''
        method class instantiates a sha 3 object with a 224 bit digest length
        '''

        super().__init__(f="SHA3-224", digest_length=224)

class SHA3_256(SHA3):
    '''
    This class instantiates a sha 3 object with a 256 bit digest length
    '''

    def __init__(self):
        '''
        This method instantiates a sha 3 object with a 256 bit digest length
        '''

        super().__init__(f="SHA3-256", digest_length=256)
        
class SHA3_384(SHA3):
    '''
    This class instantiates a sha 3 object with a 384 bit digest length
    '''

    def __init__(self):
        '''
        This method instantiates a sha 3 object with a 384 bit digest length
        '''

        super().__init__(f="SHA3-384", digest_length=384)

class SHA3_512(SHA3):
    '''
    This class instantiates a sha 3 object with a 512 bit digest length
    '''
    def __init__(self):
        '''
        This method instantiates a sha 3 object with a 512 bit digest length
        '''
        
        super().__init__(f="SHA3-512", digest_length=512)


if __name__ =="__main__":
    # Test values taken from the SHA3 example files at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
    
    sha3_224 = SHA3_224()
    sha3_256 = SHA3_256()
    sha3_384 = SHA3_384()
    sha3_512 = SHA3_512()
    bit_string_input_5bit = "11001"

    result = sha3_224.hashBinaryStringToHex(bit_string_input_5bit)
    expected_result = "FF BA D5 DA 96 BA D7 17 89 33 02 06 DC 67 68 EC AE B1 B3 2D CA 6B 33 01 48 96 74 AB"
    print(f"sha 224 hash of 11001 is {result}")
    assert result == expected_result.replace(" ","")
    
    result = sha3_256.hashBinaryStringToHex(bit_string_input_5bit)
    expected_result = "7B 00 47 CF 5A 45 68 82 36 3C BF 0F B0 53 22 CF 65 F4 B7 05 9A 46 36 5E 83 01 32 E3 B5 D9 57 AF"
    print(f"sha 256 hash of 11001 is {result}")
    assert result == expected_result.replace(" ","")

    result = sha3_384.hashBinaryStringToHex(bit_string_input_5bit)
    expected_result = "73 7C 9B 49 18 85 E9 BF 74 28 E7 92 74 1A 7B F8 DC A9 65 34 71 C3 E1 48 47 3F 2C 23 6B 6A 0A 64 55 EB 1D CE 9F 77 9B 4B 6B 23 7F EF 17 1B 1C 64"
    print(f"sha 384 hash of 11001 is {result}")
    assert result == expected_result.replace(" ","")

    result = sha3_512.hashBinaryStringToHex(bit_string_input_5bit)
    expected_result = "A1 3E 01 49 41 14 C0 98 00 62 2A 70 28 8C 43 21 21 CE 70 03 9D 75 3C AD D2 E0 06 E4 D9 61 CB 27 54 4C 14 81 E5 81 4B DC EB 53 BE 67 33 D5 E0 99 79 5E 5E 81 91 8A DD B0 58 E2 2A 9F 24 88 3F 37"
    print(f"sha 512 hash of 11001 is {result}")
    assert result == expected_result.replace(" ","")