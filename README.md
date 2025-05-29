# Cryptography Exploration
A repository created in order to explore cryptography related algorithms, implementations and concepts. The algorithms so far have been implemented in Python and/or C++. The GUI applicaton was created using QT and C++. The sequence diagrams shown below are created using plantuml code I generated using Python based on the results of the implemented algorithms. The graphs are created using data exported to CSV and plotted using Python with Pandas, Matplotlib and Seaborn. For any sections where the code consists of more than one file the link simply takes you to one of the main relevant files.   

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/b64503c1bfa82b46574c159d853ab17ae7a76e9a/CryptographySchemes/OutputImages/C%2B%2BGuiApplication.jpg" 
    alt="This is screenshots from the C++ GUI application. It shows the use of C++ to generate RSA Keys and use them to both encrypt and decrypt simple hexadecimal strings. The other image shows the use of SHA1 and SHA2 to create hash digests of the string input. The last image shows the use of AES to encrypt data.">
</img>  

## Table of Contents
1. Cryptography Schemes - [README Section](#cryptography-schemes)
    1. Symmetric Encryption Algorithms - [README Section](#symmetric-encryption-algorithms)
        1. Advanced Encryption Standard (AES) - [README Section](#advanced-encryption-standard-aes) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/SymmetricEncryptionAlgorithms/AdvancedEncryptionStandard.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/UnitTest/AES_UnitTests.py) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/b64503c1bfa82b46574c159d853ab17ae7a76e9a/C%2B%2B_Implementations/AES/src/AES.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/b64503c1bfa82b46574c159d853ab17ae7a76e9a/C%2B%2B_Implementations/Tests/AESTests/src/AESCypherTests.cpp)
            * Galois / Counter Mode (GCM) - [README Section](#galois--counter-mode-gcm) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/SymmetricEncryptionAlgorithms/AES_GaloisCounterMode.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/UnitTest/AES_GCM_UnitTests.py)
            * Basic Modes of Operation - [README Section](#basic-modes-of-operation) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/SymmetricEncryptionAlgorithms/AES_ModesOfOperation.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/UnitTest/AES_Modes_UnitTests.py) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/b64503c1bfa82b46574c159d853ab17ae7a76e9a/C%2B%2B_Implementations/AES/src/Modes/AES_CFB.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/b64503c1bfa82b46574c159d853ab17ae7a76e9a/C%2B%2B_Implementations/Tests/AESTests/src/ModesTests/AES_CFBTests.cpp)
        2. Triple Data Encryption Standard (TDES) - [README Section](#triple-data-encryption-standard-tdes) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/SymmetricEncryptionAlgorithms/TripleDataEncryptionStandard.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/UnitTest/TDES_UnitTests.py)
            * Basic Modes of Operation - [README Section](#basic-modes-of-operation-1) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/SymmetricEncryptionAlgorithms/TripleDataEncryptionStandard.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/UnitTest/TDES_UnitTests.py)
    2. Elliptic Curve Digital Signature Algorithm (ECDSA) - [README Section](#elliptic-curve-digital-signature-algorithm-ecdsa) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/EllipticCurveDigitalSignatureAlgorithm.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/UnitTest/ECDSA_UnitTests.py)
    3. Edwards-Curve Digital Signature Algotithm (EdDSA) - [README Section](#edwards-curve-digital-signature-algotithm-eddsa) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/EdwardsCurveDigitalSignatureAlgorithm.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/UnitTest/EdDSA_UnitTests.py)
    4. RSA Cryptography Scheme - [README Section](#rsa-cryptography-scheme) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/RSA/RSA_Primitives.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/UnitTest/RSA_UnitTests.py) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/tree/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/RSA/src) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/Tests/RSATests/src/EncryptionPrimitiveTests.cpp)
        1. RSA Key Generation - [README Section](#rsa-key-generation) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/RSA/RSA_Keys.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/UnitTest/RSA_KeyGeneration_UnitTests.py) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/RSA/src/RSAKeyGeneration.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/Tests/RSATests/src/KeyGenTests_ProbablyPrime.cpp)
        2. RSA Private Key Forms - [README Section](#rsa-private-key-forms) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/RSA/RSA_Keys.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/CryptographySchemes/UnitTest/RSA_KeyGeneration_UnitTests.py) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/RSA/src/RSAPrivateKey.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/Tests/RSATests/src/KeyGenTests_ProbablyPrime.cpp)
    5. Diffie Hellman Key Exchange - [README Section](#diffie-hellman-key-exchange) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/0a5b12a1dcd05a0785b3af13584fc09e29bb1590/CryptographySchemes/DiffieHellmanKeyExchange.py)
    6. Elliptic Curve Diffie Hellman Key Exchange - [README Section](#diffie-hellman-key-exchange) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/0a5b12a1dcd05a0785b3af13584fc09e29bb1590/CryptographySchemes/EllipticCurveDHKeyExchange.py)
    7. Hashing Algorithms - [README Section](#hashing-algorithms)
        1. Secure Hash Algoithm 1 (SHA1) - [README Section](#secure-hash-algoithm-1-sha1) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/0a5b12a1dcd05a0785b3af13584fc09e29bb1590/CryptographySchemes/HashingAlgorithms/SecureHashAlgorithm1.py) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/HashingAlgorithms/src/SHA1.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/Tests/HashingTests/src/SHA1_tests.cpp)
        2. Secure Hash Algorithm 2 (SHA2) - [README Section](#secure-hash-algorithm-2-sha2) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/0a5b12a1dcd05a0785b3af13584fc09e29bb1590/CryptographySchemes/HashingAlgorithms/SecureHashAlgorithm2.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/0a5b12a1dcd05a0785b3af13584fc09e29bb1590/CryptographySchemes/UnitTest/SHA2_UnitTests.py) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/HashingAlgorithms/src/SHA256.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/0a5b12a1dcd05a0785b3af13584fc09e29bb1590/CryptographySchemes/UnitTest/SHA2_UnitTests.py)
        3. Secure Hash Algorithm 3 (SHA3) - [README Section](#secure-hash-algorithm-3-sha3) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/0a5b12a1dcd05a0785b3af13584fc09e29bb1590/CryptographySchemes/HashingAlgorithms/SecureHashAlgorithm3.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/0a5b12a1dcd05a0785b3af13584fc09e29bb1590/CryptographySchemes/UnitTest/SHA3_UnitTests.py)
    8. Message Authentication Codes - [README Section](#message-authentication-codes)
        1. Keyed-Hash Message Authentication Code (HMAC) - [README Section](#keyed-hash-message-authentication-code-hmac) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/754b9c731626a64aa6448544444dfd5b0d2f5ab7/CryptographySchemes/MessageAuthenticationCodes/KeyedHashMessageAuthenticationCode.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/754b9c731626a64aa6448544444dfd5b0d2f5ab7/CryptographySchemes/UnitTest/HMAC_UnitTests.py)
        2. CMAC Mode For Authentication - [README Section](#cmac-mode-for-authentication) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/754b9c731626a64aa6448544444dfd5b0d2f5ab7/CryptographySchemes/MessageAuthenticationCodes/KeyedHashMessageAuthenticationCode.py) - [Python Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/754b9c731626a64aa6448544444dfd5b0d2f5ab7/CryptographySchemes/UnitTest/CMAC_UnitTests.py)
    9. Historical Cyphers - [README Section](#historical-cyphers)
        1. Caesar Cypher - [README Section](#caesar-cypher) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/754b9c731626a64aa6448544444dfd5b0d2f5ab7/CryptographySchemes/HistoricalCyphers/CaesarCypher.py)
        2. Multiplicative Cypher - [README Section](#multiplicative-cypher) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/754b9c731626a64aa6448544444dfd5b0d2f5ab7/CryptographySchemes/HistoricalCyphers/MultiplicativeCypher.py)
2. Bad Actor Methodologies - [README Section](#bad-actor-methodologies)
    1. Shor's Algorithm Vs RSA - [README Section](#shors-algorithm-vs-rsa) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/754b9c731626a64aa6448544444dfd5b0d2f5ab7/BadActorMethodologies/ShorsAlgorithmVsRSA.py)
    2. Brute Force Vs Caesar Cypher - [README Section](#brute-force-vs-caesar-cypher) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/754b9c731626a64aa6448544444dfd5b0d2f5ab7/BadActorMethodologies/BruteForceVsCaesarCypher.py)
    3. Brute Force Vs Multiplicative Cypher - [README Section](#brute-force-vs-multiplicative-cypher) - [Python Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/754b9c731626a64aa6448544444dfd5b0d2f5ab7/BadActorMethodologies/BruteForceVsMultiplicativeCypher.py)

## Cryptography Schemes  

### Symmetric Encryption Algorithms

#### Advanced Encryption Standard (AES)

I implemented a version of the Advanced Encryption Standard as laid out in [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf). It operates on blocks of 128 bits of the input at a time. AES has several variants based on the length of the key and I implemented AES-128, AES-192 and AES-256. . As the Advanced Encryption Standard is a symetric encryption algorithm, so it is necessary to have the same key to encrypt the message as you use to decrypt the message. For the example sequence shown below, I relied on the use of Elliptic Curve Diffie Hellman key exchange in order to use the shared secret to generate the same key as both the originator and the receiver. Symmetric Block Ciphers such as AES also operate in various modes in order to increase security or provide various supplemental functionality such as verifying authenticity. The example sequence diagram portrays the use of AES 256 in Galois/Counter Mode (GCM).

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/9b2f53435d36261373e30b008615e10c703e2e98/GeneratingDiagrams/Diagrams/AES_GCM_With_ECDHKeyExchange.png" 
    alt="This is a sequence diagram for a message exchange using AES, with ECDH key exchange used to generate the key">
</img>  

##### Galois / Counter Mode (GCM)    

Galois / Counter Mode is laid out in NIST SP 800-38D ["Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/21d2d0c8f185f773bf07ad21e2de559f8f14cbb2/CryptographySchemes/OutputImages/AES_GCM_Examples.png). GCM relies on the use of an initialization vector, which is a separate block of input from the key that does not need to be secret, but should be unpredictable and different each time. The IV is incremented for processing each subsequent block of input. Operations on blocks are performed within the Galois Field, 2**128. The Galois / Counter Mode produces a unique tag based on all of the input which allows for the authenticity to be verified, as well as the encrypted cypher text. I was able to create unit tests based on the example data from Appendix B "AES Test Vectors" of ["The Galois/Counter Mode of Operation (GCM)"](https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf). This allowed me to verify both encryption and decryption, as well as the creation of the appropriate tags, against several known hex strings, in order to be sure my implementations were operating appropriately. Below is a sample of the output from this testing. 

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/21d2d0c8f185f773bf07ad21e2de559f8f14cbb2/CryptographySchemes/OutputImages/AES_GCM_Examples.png" 
    alt="Sample output of AES GCM unit tests ran against NIST sample data.">
</img>  

##### Basic Modes of Operation   
###### Electronic Cookbook (ECB), Cipher Block Chaining (CBC), Cipher Feedback (CFB), Output Feedback (OFB) and Counter (CTR)

There are several modes of operation outlined in NIST SP 800-38A ["Recommendation for Block Cipher Modes of Operation"](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf). Electronic Cookbook (ECB) Mode simply applies the same AES cypher to each block of the input. The other modes rely on the use of an initialization vector, which is a separate block of input from the key that does not need to be secret, but should be unpredictable and different each time. Cipher Block Chaining (CBC) Mode uses xor with the initialization vector and the first block of input before running that through the AES Cipher. Each following block is xored with the result of the previous cypher in the place of the initialization block. Cipher Feedback Mode (CFB) does not apply the AES cipher directly to the input, but to the initialization vector and then xors that with the input. Each successive block uses the result of the xor operation from the previous block in the place of the initialization vector. It also allows the user to select an 's', which is the number of bits of the input to use in each block. The other bits are the least significant bits from the initialization vector concatenated with the previous cipher values. Output Feedback Mode (OFB) also does not apply the AES cipher directly to the input. The initialization vector for each subsequent block is the result of the cipher operation in the previous block. Counter Mode (CTR) also does not apply the apply the cipher directly to the input, but to the initialization vector which it xors with the input. The initialization vector is incremented for each successive block.     

For these basic modes of operation for AES, I was able to create unit tests based on the example data provided by NIST in their [Cryptographic Standards and Guidelines](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ModesA_All.pdf). Below is a sample of the output from this testing.    

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/9b2f53435d36261373e30b008615e10c703e2e98/CryptographySchemes/OutputImages/AES_Modes_Examples.png" 
    alt="Sample output of AES unit tests ran against NIST sample data.">
</img>  

#### Triple Data Encryption Standard (TDES)

I implemented a version of the Triple Data Encryption Standard as laid out in NIST SP 800-67 [Recommendation for the Triple 
Data Encryption Algorithm (TDEA) Block Cipher](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-67r1.pdf). It is a symmetric block cipher much like AES, though it operates on 64 bit blocks of input at a time instead of 128 bit blocks. It is built upon Data Encryption Standard (DES) from [NIST FIPS 46-3](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf). TDES uses three keys with DES and encrypts with the first key, decrypts with the second and then encrypts with the third.

##### Basic Modes of Operation   
###### Electronic Cookbook (ECB), Cipher Block Chaining (CBC), Cipher Feedback (CFB), Output Feedback (OFB) and Counter (CTR)

Triple Data Encryption Standard also uses the same basic modes of operation from NIST SP 800-38A ["Recommendation for Block Cipher Modes of Operation"](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) as seen with AES. For these basic modes of operation for TDES, I was able to create unit tests based on the example data provided by NIST in their [Cryptographic Standards and Guidelines](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf). Below is a sample of the output from this testing.    

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/9b2f53435d36261373e30b008615e10c703e2e98/CryptographySchemes/OutputImages/TDES_Modes_Examples.png" 
    alt="Sample output of TDES unit tests ran against NIST sample data.">
</img>  

### Elliptic Curve Digital Signature Algorithm (ECDSA)   

I implemented a version of Elliptic Curve Digital Signature Algorithm as laid out in [NIST FIPS 186-6](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf), [NIST FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) and [NIST SP 800-186](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf). As ECDSA does require the use of a hashing algorithm I was able to use my implementation of SHA3, after verifying the hash output matched the NIST examples in the Digital Signatures section of ["Cryptographic Standards and Guidelines"](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values). The elliptic curves that I have implemented at this time follow the Weirstrass Form of y**2 = x**3 +ax +b. Both of the curves shown in the examples below are from [NIST FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) Section D.1.2 "Curves over Prime Fields". The sequence diagram shows the ECDSA both generating a digital signature based on the message hash, curve attributes and the private key, as well as verifying the signature using the message hash, curve attributes, and the public key.    

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8424d8c1e943f47aad1e9525794120a217840b80/GeneratingDiagrams/Diagrams/EllipticCurveDigitalSignatureAlgorithmWithSha3.png" 
    alt="This is a sequence diagram for a generating and verifying a signature using ECDSA">
</img>  

I was able to get NIST  examples for a couple of the curves and hashing algorithms including [Curve P-521 with SHA3-512](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf) in order to verify that my Elliptic Curve Digital Signature Algorithms function as expected, including the intermediate values. Below is an example of the output from a couple of the unit tests I created.   

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/3777c4a98aa1df785faa190a3a28292e70a5a232/CryptographySchemes/OutputImages/ECDSA_Examples.png" 
    alt="Sample output of ECDSA unit tests ran against NIST sample data.">
</img>  

### Edwards-Curve Digital Signature Algotithm (EdDSA)   

Building on top of my ECDSA implementation, I was able to also implement EdDSA. Edwards-curve digital signature algorithm is closely related to ECDSA, except the curves used and the hashing algorithms are slighly different. In particular I used the curve Ed25519 with SHA-512 and Ed448 with Shake-256 as laid out in [NIST FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) and [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032). Ed448 is designed to provide higher security than Ed25519 while both are designed to run faster than the standard ECDSA. I was able to create unit tests using known data provided in RFC 8032 in order to verify the implementation is generating the signatures expected and some example output is shown below.   

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/3e9b1aaa1cad4a2c966b3a1f09ef028855db453f/CryptographySchemes/OutputImages/EdDSA_Examples.png" 
    alt="Sample output of EdDSA unit tests ran against sample data from RFC 8032.">
</img>  

### RSA Cryptography Scheme  

I have implemented versions of the RSA Cryptography scheme in both C++ and Python. RSA was named after R.L. Rivest, A. Shamir, and L. Adleman who laid out the system in their paper ["A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"](https://people.csail.mit.edu/rivest/Rsapaper.pdf) from 1977. It relies on the difficulty in factoring large primes in order to prevnt people from breaking the security, and it is no longer particularly secure today, due to advancements in computing. When using RSA to encrypt messages each participant generates a private a public key. The message is sent using the recipient's public key and can then be decrypted using their private key. RSA keys are generated by first generating two large prime numbers, p and q. These prime numbers are mulitplied together in order to calculate n which is part of the public key. d and e are calculated with the help of the extended form of euclids algorithm such that when encrypting with the public key e and n, the public key d and n may be used to decrypt.    

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/1198ce3dad1ca992daadf42effca7986062f38a2/GeneratingDiagrams/Diagrams/BasicRSACryptographySchemeSequence.png" 
    alt="This is a sequence diagram for a simple message and reply using the RSA Cryptography scheme">
</img>

#### RSA Key Generation

RSA Cryptography relies on pairs of public and private keys that are created using two large prime numbers. NIST FIPS 186-5 ["Digital Signature Standard (DSS)"](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) lays out multiple methods by which these prime numbers may be generated. The include Appendix A.1.2 "Generation of Random Primes that are Provably Prime", Appendix A.1.3 "Generation of Random Primes that are Probably Prime", Appendix A.1.4 "Generation of Provable Primes with Conditions Based on Auxiliary Provable Primes", A.1.5 "Generation of Probable Primes with Conditions Based on Auxiliary Provable Primes" and Appendix A.1.6 "Generation of Probable Primes with Conditions Based on Auxiliary Probable Primes". The bit lengths for the keys are also specified in NIST SP 800-57 Part 1 ["Recommendation for Key Management: Part 1 – General"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) Table 2: "Comparable security strengths of symmetric block cipher and asymmetric-key algorithms". RSA or other integer factorization algorithms are listed by "k", the bit length of the "n" value, or the two primes multiplied together. For a security strength of 112 (equivalent to TDES), "k" must be 2048, for a security strength of 128 (equivalent to AES 128) "k" must be 3072, for a security strength of 192 (equivalent to AES 192) "k" must be 7680, and for a security strength of 256 (equivalent to AES 256) "k" must be 15360. Generating these extremely large primes does cause my computer to take a long time, though I admit freely that none of my implementations are designed for efficiency. I still think it is interesting to view the comparisons of the running times for each prime generation method depending on programming language and key length.

##### Python Durations

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/f72678c06aeacaf69ca0f76224ee13000f4598b2/CryptographySchemes/OutputImages/RSA_KeyGeneration_DurationGraphs.png" 
    alt="This shows the key generation duration for each prime generation methodology over the various key lengths.">
</img>

##### C++ Durations

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8ab2c9fa1fa2a755bc7ffb7005982704b671f248/CryptographySchemes/OutputImages/RSA_KeyGeneration_DurationGraphs_Cpp.png" 
    alt="This shows the key generation duration for each prime generation methodology over the various key lengths.">
</img>

#### RSA Private Key Forms

As mentioned in NIST FIPS 186-5 ["Digital Signature Standard (DSS)"](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) and IETF 8017 "PKCS #1: RSA Cryptography Specifications Version 2.2", there are actually two ways to store the private key. The first way is simply the "n" value or the multiple of the two large prime numbers, and the private exponent, "d". The second way uses a quintuple form and can increase the efficiency when decrypting data. The quintuple consists of both large prime numbers ("p" and "q"), the private exponent mod "p" and "q" ("dP" and "dQ"), as well as "qInv", or the inverse of "q" mod "p". The following graphs show the difference in time for both the standard and quintuple forms for decryption, though it does really not effect encrytion or key generation times.

##### Python Durations

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/f72678c06aeacaf69ca0f76224ee13000f4598b2/CryptographySchemes/OutputImages/RSA_KeyGeneration_DurationGraphs_Simple.png" 
    alt="This shows the comparison between standard and quintuple private key forms during generation, encryption and decryption.">
</img>

##### C++ Durations

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8ab2c9fa1fa2a755bc7ffb7005982704b671f248/CryptographySchemes/OutputImages/RSA_KeyGeneration_DurationGraphs_Simple_Cpp.png" 
    alt="This shows the comparison between standard and quintuple private key forms during generation, encryption and decryption.">
</img>

##### Python Durations Vs. C++ Durations

The most pronouned difference, however, is visible when directly comparing the amount of time it takes to generate keys in Python vs. C++ with a shared y-axis.

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8ab2c9fa1fa2a755bc7ffb7005982704b671f248/CryptographySchemes/OutputImages/RSA_KeyGeneration_DurationGraphs_Cpp_Vs_Python.png" 
    alt="This shows the comparison between generating standard and quintuple private key forms in Python or C++.">
</img>

### Diffie Hellman Key Exchange   

I implemented a version of the Diffie Helman key exchange. The Diffie Hellman key exchange is a method by which two parties can establish a shared secret, without needing to transmit it directly. The scheme was originally published by Whitfield Diffie and Martin E. Hellman in their paper ["New Directions in Cryptography"](https://ee.stanford.edu/%7Ehellman/publications/24.pdf) from 1976. To begin the Diffie Hellman key exchange both parties must agree on both a prime number and a generator value. The generator value should be a prime root for the prime number that was agreed upon. Then both participants select their private keys. These private keys are then used with the agreed upon prime and generator in order to calculate the public keys. These public keys are then exchanged and each participant can use their own private key and the other participant's public key in order to calculate a shared secret value. As anyone intercepting messages would not have access to either participant's private keys, it would be computationally difficult to generate the same shared secret. 

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%; max-height:100%"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/1198ce3dad1ca992daadf42effca7986062f38a2/GeneratingDiagrams/Diagrams/DiffieHellmanKeyExchangeSequence.png" 
    alt="This is a sequence diagram for a diffie hellman key exchange">
</img>

### Elliptic Curve Diffie Hellman Key Exchange    

I implemented a form of the Elliptic Curve Diffie Hellman Key Exchange based on Weirstrass Form elliptic curves. Weirstrass Form elliptic curves take the form y**2 = x**3 + ax + b and multiple have been laid out as appropropriate for use in cryptography. For example I have included the parameters for Curve P-194 from page 90 of [NIST FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) and Secp256r1 from page 9 of ["SEC 2: Recommended Elliptic Curve Domain Parameters"](https://www.secg.org/sec2-v2.pdf). Most of the implementations for the actual calculations are not in the EllipticCurveDHKeyExchange class, but rather under Helper Functions in the EllipticCurveCalculations class as there are other cryptography schemes that rely on elliptic curve cryptography which I hope to implement going forward. In this form of the elliptic curve diffie hellman key exchange, the public keys are exchanged in a compressed hexadecimal form before being decompressed in order to calculate the shared secret.   

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%; max-height:100%"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/56c29b0f81b7e892a86127e93d93269bb62d746d/GeneratingDiagrams/Diagrams/EllipticCurveDHKeyExchangeSequence.png" 
    alt="This is a sequence diagram for an elliptic curve diffie hellman key exchange">
</img>   

### Hashing Algorithms

#### Secure Hash Algoithm 1 (SHA1)  

I implemented a version of the SHA1 hashing algorithm as laid out in NIST FIPS 180-4, ["Secure Hash Standard (SHS)"](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). SHA1 was developed by the United States National Security Agency(NSA) and was originally published in 1995. It is no longer considered secure. The SHA1 algorithm consists of a few functions that are run on 32 bit words, particularly ch, parity and maj, as well as bitwise operations including xor, and, shift and rotate. It produces a 160 bit hashdigest and can be quite prone to hash collisions compared to the other SHA algorithms.

#### Secure Hash Algorithm 2 (SHA2)    

##### (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256)    

I implemented versions of the SHA2 hashing algorithms as laid out in NIST FIPS 180-4, ["Secure Hash Standard (SHS)"](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). Much like SHA1, SHA2 was initial developed by the NSA and was published in 2001. SHA2 is really a collection of algorithms with varying hash digest lengths that are built upon some of the characteristics of SHA1. Particularly, SHA-256 also rely upon the use of the ch and maj functions on 32 bit words, though they do not use the parity function and also add sigma functions. SHA-512 builds on the foundations of the SHA-256 functions, however it uses them on 64-bit words. The other algorithms within the SHA2 family all are strongly connected with either SHA-256 or SHA-512. SHA-224 has different starting hash values than SHA-256 and truncates the ouput to 224 bit, but otherwise is the same internally. SHA-384, SHA-512/224 and SHA-512/256 share a similar relationship with SHA-512. Below you can see sample output from unit tests showing that the SHA1 and SHA2 implementations accurately produce the results provided by NIST in their [Cryptographic Standards and Guidelines: Example Values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values).

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%; max-height:100%"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/c64dd77d1af011e085e4f557b75676b456d3a54d/CryptographySchemes/OutputImages/SHA1_SHA2_Examples.png" 
    alt="This shows example from unit tests for the SHA1 and SHA2 implementations using known values from NIST">
</img>   

#### Secure Hash Algorithm 3 (SHA3)    

##### (SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 and SHAKE256)

I implemented versions of the SHA3 hashing algorithms as laid out in NIST FIPS 202, ["SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions)"](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf). SHA3 is an entirely separate algorithm compared to SHA1 and SHA2. It is based on Keccak which was described in ["Keccek implementation overview"](https://keccak.team/files/Keccak-implementation-3.2.pdf) by Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer from 2012. The internal state of the SHA3 algorithm is stored in a 3 dimensional bit array where x is between 0 and 4, y is between 0 and 4 and z is between 0 and 63. It is based on a sponge construction and each iteration it performs a series of function on the state array, theta, rho, pi, chi and iota. SHA3-224, SHA3-256, SHA3-384 and SHA3-512 each produce hashes of a set length and the largest difference between each of them is how much capacity there is in each iteration. SHAKE128 and SHAKE256 both allow the user to specify the length of the digest to be produced but still vary based on the internal capcity. SHA3 does have its own algorithms for translating bit strings into hex strings and back as specified in the appendix of NIST FIPS 202. Below you can see sample output from unit tests showing that the SHA3 implementations accurately produce the results provided by NIST in their [Cryptographic Standards and Guidelines: Example Values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values).

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%; max-height:100%"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8874f359a5e7d13f335a13659e313719045e1f86/CryptographySchemes/OutputImages/SHA3_Examples.png" 
    alt="This shows example from unit tests for the SHA3 implementation using known values from NIST">
</img>   

### Message Authentication Codes 

#### Keyed-Hash Message Authentication Code (HMAC)

I implemented a version of HMAC as defined in NIST SP 800-224 [Keyed-Hash Message Authentication Code (HMAC)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf). It creates a unique code for a given message based on a secret key which allows for the message to be authenticated. HMAC relies on hashing algorithms in order to generate the unique code. This is implemented on top of my secure hashing implementations for both SHA2 and SHA3. Below is sample output from unit tests based on test vectors from NIST's [Cryptographic Standards and Guidelines: Example Values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values).

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%; max-height:100%"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/120d2786aaa72224296367cad6b1191e4523be37/CryptographySchemes/OutputImages/HMAC_Examples.png" 
    alt="This shows example from unit tests for the hmac message authentication">
</img>   

#### CMAC Mode For Authentication    

I implemented a version of CMAC as defined in NIST SP 800-38B [The CMAC Mode for Authentication](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf). Unlike HMAC's reliance on hashing algorithms in order to generate the unique code, CMAC relies on Block Cyphers. This is built on top of my implementations for both AES and TDES. Below is sample output from unit tests based on test vectors from NIST's [Cryptographic Standards and Guidelines: Example Values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values).

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%; max-height:100%"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/120d2786aaa72224296367cad6b1191e4523be37/CryptographySchemes/OutputImages/CMAC_Examples.png" 
    alt="This shows example from unit tests for the cmac message authentication">
</img>   

### Historical Cyphers

#### Caesar Cypher  

I implemented a version of the caesar cypher in Python. The caesar cypher is a very simple example of a cypher which relies on shifting every character in a message the same number of places in the alphabet. For example if you were to encrypt "def" with a multiplcation value of four the result would be "hij". The idea is that, without the knowing the shift value, it is harder to find the original message. However, since the cypher is limited by the number of letters in the alphabet, it is trivial to brute force.

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/1198ce3dad1ca992daadf42effca7986062f38a2/GeneratingDiagrams/Diagrams/BasicCaesarCypherSequence.png" 
    alt="This is a sequence diagram for a simple message and reply using caesar cypher">
</img>

#### Multiplicative Cypher  

I implemented a version of the multiplicative cypher in Python.The multiplicative cypher is also a very simple example of a cypher. It relies on multiplying every character in a message by the same value before calculating the modulus. For example if you were to encrypt "def" with a shift value of four the result would be "mqu". The idea is that, without the knowing the multiplication value, it is harder to find the original message. While it relies on more calculation than the caesar cypher, the multiplicative cypher is still limited and is trivial to brute force.

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/1198ce3dad1ca992daadf42effca7986062f38a2/GeneratingDiagrams/Diagrams/BasicMultiplicativeCypherSequence.png" 
    alt="This is a sequence diagram for a simple message and reply using a multiplicative cypher">
</img>

## Bad Actor Methodologies   

### Shor's Algorithm Vs RSA   

I implemented a version of Shor's Algorithm in Python using IBM's Qiskit package. Shor's Algorithm is a quantum algorithm for factoring large number that was first laid out by Peter Shor in his paper ["Algorithms for quantum computation: Discrete logarithms and factoring"](https://ieeexplore.ieee.org/document/365700) in 1997. Given a quantum computer with enough qubits, Shor's Algorithm should be capable of factoring large numbers in polynomial time, greatly affecting the computational time required to break cryptographic algorithms such as RSA. Shor's Algorithm to factor a large number, n, takes a random guess then uses a quantum circuit to find the order such that f(x) = ax%n. If the order is even, it can be used to calculate a factor. The second factor of n can be calculated simply using n divided by the first factor.  

By reducing the computational time for factoring large numbers to polynomial time, it greatly speeds up the ability to break RSA encryption. As RSA relies on calculations involving two large prime numbers where their product is part of the public key, factoring the value from the public key can allow the bad actor to generate the value for the private key and decrypt the information. So far, quantum computers are still rare and expensive, especially with larger numbers of qubits so the actual uses of Shor's algorithm are not not very common. Using the simulator I was limited to 7 qubits for the input so the example sequence pictured below uses trivially small prime numbers.  

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/1198ce3dad1ca992daadf42effca7986062f38a2/GeneratingDiagrams/Diagrams/ShorsAlgorithmVsRSASequence.png" 
    alt="This is a sequence diagram for a bad actor using Shor's Algorithm against RSA encrypted messaging">
</img>

### Brute Force Vs Caesar Cypher   

I implemented an algorithm for brute forcing a caesar cypher by a bad actor who is intercepting communication between two individuals who know the shift value. Each time the bad actor intercepts a message they run the encrypted with each possible shift values. These attempted decrypted strings are then compared to a dictionary of common English words. As some wrong decryptions will by chance include actual words the bad actor has set a minimum number of English words in a particular shift value that they believe to be significant enough to select a likely successful decryption using that shift value. The bad actor is then able to use that particular shift value to easily decrypt any future messages.   

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/1198ce3dad1ca992daadf42effca7986062f38a2/GeneratingDiagrams/Diagrams/BruteForceVsCaesarCypherSequence.png" 
    alt="This is a sequence diagram for a bad actor using a brute force attack against a caesar cypher">
</img>

### Brute Force Vs Multiplicative Cypher   

I implemented an algorithm for brute forcing a multiplicative cypher by a bad actor who is intercepting communication between two individuals who know the multiplication value. Each time the bad actor intercepts a message they run the encrypted message with each possible multiplication value. These attempted decrypted strings are then compared to a dictionary of common English words. As some wrong decryptions will by chance include actual words, the bad actor has set a minimum number of English words in a particular multiplication value that they believe to be significant enough to select a likely successful decryption using that multiplication value. The bad actor is then able to use that particular multiplication value to easily decrypt any future messages.   

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%; "
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/1198ce3dad1ca992daadf42effca7986062f38a2/GeneratingDiagrams/Diagrams/BruteForceVsMultiplicativeCypherSequence.png" 
    alt="This is a sequence diagram for a bad actor using a brute force attack against a multiplicative cypher">
</img>

