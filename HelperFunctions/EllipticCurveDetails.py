from HelperFunctions.EllipticCurveCalculations import EdwardsCurveCalculation, Edwards448Calculation

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

def getCurveP224() -> EllipticCurveWeierstrassFormDetails:
    '''
    from NIST FIPS 186-4
    Weirstrass Form ==> y**2 = x**3 + ax + b
    E :  y**2 ≡  x**3 – 3 x + b (mod p)
    '''

    a = -3
    b = int('0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4',16)
    p = 26959946667150639794667015087019630673557916260026308143510066298881 
    generator_x = int('0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21',16)
    generator_y = int('0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34',16)
    order = 26959946667150639794667015087019625940457807714424391721682722368061
    sha_seed = int('0xbd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5',16)
    sha_output = int('0x5b056c7e11dd68f40469ee7f3c7a7d74f7d121116506d031218291fb',16)

    return EllipticCurveWeierstrassFormDetails("Curve P-224",a,b,p,generator_x,generator_y,order,sha_seed,sha_output)

def getCurveP521():
    '''
    from NIST FIPS 186-4
    Weirstrass Form ==> y**2 = x**3 + ax + b
    E :  y**2 ≡  x**3 – 3 x + b (mod p)
    '''

    a = -3
    b = int('0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00',16)
    p = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151    
    generator_x = int('0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66',16)
    generator_y = int('0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650',16)
    order = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449  
    sha_seed = int('0xd09e8800291cb85396cc6717393284aaa0da64ba',16)
    sha_output = int('0x0b48bfa5f420a34949539d2bdfc264eeeeb077688e44fbf0ad8f6d0edb37bd6b533281000518e19f1b9ffbe0fe9ed8a3c2200b8f875e523868c70c1e5bf55bad637',16)

    return EllipticCurveWeierstrassFormDetails("Curve P-521",a,b,p,generator_x,generator_y,order,sha_seed,sha_output)

def getEdwards25519(is_debug:bool=False) -> EdwardsCurveCalculation:
    '''
    This method returns an EdwardsCurveCalculation object for the curve Edwards 25519

    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf p17

    Parameters :
        is_debug : bool, optional
            Whether the curve will be used for debugging purposes and should output more information, default is false

    Returns : 
        EdwardsCurveCalculation 
            The calculations class for Edwards25519
    '''
    name = "Edwards25519"
    a = -1
    d = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
    p = 2**255 - 19
    b = 256
    Gx = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
    Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
    Gy = 0x6666666666666666666666666666666666666666666666666666666666666658
    Gy = 46316835694926478169428394003475163141307993866256225615783033603165251855960
    h = 8
    n = 2**252 + 0x14def9dea2f79cd65812631a5cf5d3ed
    tr = -0xa6f7cef517bce6b2c09318d2e7ae9f7a

    return EdwardsCurveCalculation(a=a,d=d,p=p,Gx=Gx,Gy=Gy,h=h,n=n,tr=tr,curve_name=name,is_debug=is_debug)

def getEdwards448(is_debug:bool=False) -> Edwards448Calculation:
    '''
    This method returns an EdwardsCurveCalculation object for the curve Edwards 448

    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf p18

    Parameters :
        is_debug : bool, optional
            Whether the curve will be used for debugging purposes and should output more information, default is false

    Returns : 
        EdwardsCurveCalculation 
            The calculations class for Edwards448
    '''
    name = "Edwards448"
    a = 1
    d = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756
    p = 2**448 - 2**224 - 1
    Gx =0x4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e
    Gy =0x693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14
    h = 4
    n = 2**446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
    tr = 0x10cd77058eec492d944a725bf7a4cf635c8e9c2ab721cf5b5529eec34

    return Edwards448Calculation(a=a,d=d,p=p,Gx=Gx,Gy=Gy,h=h,n=n,tr=tr,curve_name=name,is_debug=is_debug)

getCurveP521()
getCurveP224()
getCurveP192()
getSecp256r1()
getEdwards25519()
getEdwards448()