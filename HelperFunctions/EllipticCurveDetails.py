class EllipticCurveWeierstrassFormDetails():
    def __init__(self, name, a, b, prime_modulus, generator_x, generator_y, order=None, sha_seed=None, sha_output=None):
        self.name = name
        self.a = a
        self.b = b
        self.prime_modulus = prime_modulus
        self.generator_point = (generator_x, generator_y)
        self.order = order
        self.sha_seed = sha_seed
        self.sha_output = sha_output

def getCurveP192() -> EllipticCurveWeierstrassFormDetails:
    '''
    from NIST FIPS 186-4
    Weirstrass Form ==> y**2 = x**3 + ax + b
    E :  y**2 ≡  x**3 – 3 x + b (mod p)
    '''

    a = -3
    b = int('0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1',16)
    p = 6277101735386680763835789423207666416083908700390324961279
    generator_x = int('0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012',16)
    generator_y = int('0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811',16)
    order = 6277101735386680763835789423176059013767194773182842284081
    sha_seed = int('0x3045ae6fc8422f64ed579528d38120eae12196d5',16)
    sha_output = int('0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65',16)

    return EllipticCurveWeierstrassFormDetails("Curve P-192",a,b,p,generator_x,generator_y,order,sha_seed,sha_output)

def getSecp256r1() -> EllipticCurveWeierstrassFormDetails:
    '''
    from http://www.secg.org/sec2-v2.pdf
    Weirstrass Form ==> y**2 = x**3 + ax + b
    E :  y**2 ≡  x**3 + 7 (mod p)
    '''

    a = 0
    b = 7
    p = int('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',16)
    generator_x = int('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',16)
    generator_y = int('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',16)
    order = int('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',16)

    return EllipticCurveWeierstrassFormDetails("secp256r1",a,b,p,generator_x,generator_y,order)


getCurveP192()
getSecp256r1()