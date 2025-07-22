# Cryptography Exploration With C++ Graphical User Interface
This folder contains the information for my C++ implementations while exploring cryptography. The GUI applicaton was created using QT. The RSA implementation relies upon OPENSSL for big number handling and random number generation only. Unit tests were created using the GTest framework.

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8326a330db482b89a248ea3926b94f454bce63b1/CryptographySchemes/OutputImages/C%2B%2BGuiApplication.jpg" 
    alt="This is screenshots from the C++ GUI application. The top left screenshot shows the use of C++ to generate RSA Keys and use them to both encrypt and decrypt simple hexadecimal strings. The top right screenshot shows the use of SHA1, SHA2 and SHA3 to create hash digests of the string input. The bottom left screenshot shows the use of AES to encrypt data. The bottom right screenshot shows the use of ECDSA to generate and verify a signature.">
</img>  

## Table of Contents
1. RSA Cryptography Scheme - [README Section](#rsa-cryptography-scheme) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/tree/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/RSA/src) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/Tests/RSATests/src/EncryptionPrimitiveTests.cpp)
    1. RSA Key Generation - [README Section](#rsa-key-generation) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/RSA/src/RSAKeyGeneration.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/Tests/RSATests/src/KeyGenTests_ProbablyPrime.cpp)
    2. RSA Private Key Forms - [README Section](#rsa-private-key-forms) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/RSA/src/RSAPrivateKey.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8b6984fe2783e544e4cbff22bdc1420a83d6e633/C%2B%2B_Implementations/Tests/RSATests/src/KeyGenTests_ProbablyPrime.cpp)
2. Hashing Algorithms - [README Section](#hashing-algorithms)
     1. Secure Hash Algoithm 1 (SHA1) - [README Section](#secure-hash-algoithm-1-sha1) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/HashingAlgorithms/src/SHA1.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/Tests/HashingTests/src/SHA1_tests.cpp)
    2. Secure Hash Algorithm 2 (SHA2) - [README Section](#secure-hash-algorithm-2-sha2) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/HashingAlgorithms/src/SHA256.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/0a5b12a1dcd05a0785b3af13584fc09e29bb1590/CryptographySchemes/UnitTest/SHA2_UnitTests.py)
    3. Secure Hash Algorithm 3 (SHA3) 
3. Advanced Encryption Standard (AES) - [README Section](#advanced-encryption-standard-aes) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/b64503c1bfa82b46574c159d853ab17ae7a76e9a/C%2B%2B_Implementations/AES/src/AES.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/b64503c1bfa82b46574c159d853ab17ae7a76e9a/C%2B%2B_Implementations/Tests/AESTests/src/AESCypherTests.cpp)
    1.  Basic Modes of Operation - [README Section](#basic-modes-of-operation) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/b64503c1bfa82b46574c159d853ab17ae7a76e9a/C%2B%2B_Implementations/AES/src/Modes/AES_CFB.cpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/b64503c1bfa82b46574c159d853ab17ae7a76e9a/C%2B%2B_Implementations/Tests/AESTests/src/ModesTests/AES_CFBTests.cpp)
    2.  Galois / Counter Mode (GCM) - [README Section](#galois--counter-mode-gcm) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/AES/include/Modes/AES_GCM.hpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/Tests/AESTests/src/ModesTests/AES_GCMTests.cpp)
4. Elliptic Curve Digital Signature Algorithm (ECDSA) - [README Section](#elliptic-curve-digital-signature-algorithm-ecdsa) - [C++ Code](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/EllipticCurveCryptography/include/ECDSA.hpp) - [C++ Tests](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/Tests/ECCTests/src/ECDSATests.cpp)

## RSA Cryptography Scheme  

I have implemented a version of the RSA Cryptography scheme in C++. RSA was named after R.L. Rivest, A. Shamir, and L. Adleman who laid out the system in their paper ["A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"](https://people.csail.mit.edu/rivest/Rsapaper.pdf) from 1977. It relies on the difficulty in factoring large primes in order to prevnt people from breaking the security, and it is no longer particularly secure today, due to advancements in computing. When using RSA to encrypt messages each participant generates a private a public key. The message is sent using the recipient's public key and can then be decrypted using their private key. RSA keys are generated by first generating two large prime numbers, 'p' and 'q'. These prime numbers are mulitplied together in order to calculate 'n' which is part of the public key. d and e are calculated with the help of the extended form of euclids algorithm such that when encrypting with the public key 'e' and 'n', the public key 'd' and 'n' may be used to decrypt.   

The GUI application allows the user to generate RSA keys based on their selections in three dropdowns. The user can select the key length in bits (nlen), the prime generation method to be used and the form of the private key. There are tabs to allow the user to view the generated values for 'n', 'd' and 'e', as well as 'p', 'q', 'dP', 'dQ' and 'qInv' if the quintuple form was chosen for the private key. The user may then enter a hexadecimal string into the input field and press the "Encrypt" button to encrypt it using the generated public key.   

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/QT_GUI_Cryptography/Screenshots/RSAEncrypt.png" 
    alt="This shows the key generation and encryption of Hex String in the GUI Application using RSA.">
</img>   

In order to decrypt the value that they had entered, the user may use the "Move Output To Input" button to move the result of the encryption into the input field. Then the user can use the "Decrypt" button in order to decrypt the value using the generated private key.

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/QT_GUI_Cryptography/Screenshots/RSADecrypt.png" 
    alt="This shows the decryption of Hex String in the GUI Application using RSA.">
</img>   

### RSA Key Generation

RSA Cryptography relies on pairs of public and private keys that are created using two large prime numbers. NIST FIPS 186-5 ["Digital Signature Standard (DSS)"](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) lays out multiple methods by which these prime numbers may be generated. The include Appendix A.1.2 "Generation of Random Primes that are Provably Prime", Appendix A.1.3 "Generation of Random Primes that are Probably Prime", Appendix A.1.4 "Generation of Provable Primes with Conditions Based on Auxiliary Provable Primes", A.1.5 "Generation of Probable Primes with Conditions Based on Auxiliary Provable Primes" and Appendix A.1.6 "Generation of Probable Primes with Conditions Based on Auxiliary Probable Primes". The bit lengths for the keys are also specified in NIST SP 800-57 Part 1 ["Recommendation for Key Management: Part 1 – General"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) Table 2: "Comparable security strengths of symmetric block cipher and asymmetric-key algorithms". RSA or other integer factorization algorithms are listed by "k", the bit length of the "n" value, or the two primes multiplied together. For a security strength of 112 (equivalent to TDES), "k" must be 2048, for a security strength of 128 (equivalent to AES 128) "k" must be 3072, for a security strength of 192 (equivalent to AES 192) "k" must be 7680, and for a security strength of 256 (equivalent to AES 256) "k" must be 15360. Generating these extremely large primes does cause my computer to take a long time, though I admit freely that none of my implementations are designed for efficiency. I still think it is interesting to view the comparisons of the running times for each prime generation method depending on programming language and key length.

#### C++ Durations

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8ab2c9fa1fa2a755bc7ffb7005982704b671f248/CryptographySchemes/OutputImages/RSA_KeyGeneration_DurationGraphs_Cpp.png" 
    alt="This shows the key generation duration for each prime generation methodology over the various key lengths.">
</img>

### RSA Private Key Forms

As mentioned in NIST FIPS 186-5 ["Digital Signature Standard (DSS)"](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) and IETF 8017 "PKCS #1: RSA Cryptography Specifications Version 2.2", there are actually two ways to store the private key. The first way is simply the "n" value or the multiple of the two large prime numbers, and the private exponent, "d". The second way uses a quintuple form and can increase the efficiency when decrypting data. The quintuple consists of both large prime numbers ("p" and "q"), the private exponent mod "p" and "q" ("dP" and "dQ"), as well as "qInv", or the inverse of "q" mod "p". The following graphs show the difference in time for both the standard and quintuple forms for decryption, though it does really not effect encrytion or key generation times.

#### C++ Durations

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/8ab2c9fa1fa2a755bc7ffb7005982704b671f248/CryptographySchemes/OutputImages/RSA_KeyGeneration_DurationGraphs_Simple_Cpp.png" 
    alt="This shows the comparison between standard and quintuple private key forms during generation, encryption and decryption.">
</img>

## Hashing Algorithms    

I have implemented both SHA1 and SHA in C++ and they can be used to hash string values in the GUI Application. Once the user has opened the "SHA" tab they can simply enter the string that they wish to hash into the input textarea, and then press the hash button. The application shall then generate the hash digests for SHA1, SHA224, SHA256, SHA382, SHA512, SHA512/224 and SHA512/256 and display them in the appropriate text areas.

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/QT_GUI_Cryptography/Screenshots/SHA.png" 
    alt="This shows the generation of SHA digests in the GUI Application.">
</img>   

### Secure Hash Algoithm 1 (SHA1)  

I implemented a version of the SHA1 hashing algorithm as laid out in NIST FIPS 180-4, ["Secure Hash Standard (SHS)"](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). SHA1 was developed by the United States National Security Agency(NSA) and was originally published in 1995. It is no longer considered secure. The SHA1 algorithm consists of a few functions that are run on 32 bit words, particularly ch, parity and maj, as well as bitwise operations including xor, and, shift and rotate. It produces a 160 bit hashdigest and can be quite prone to hash collisions compared to the other SHA algorithms.

### Secure Hash Algorithm 2 (SHA2)    

#### (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256)    

I implemented versions of the SHA2 hashing algorithms as laid out in NIST FIPS 180-4, ["Secure Hash Standard (SHS)"](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). Much like SHA1, SHA2 was initial developed by the NSA and was published in 2001. SHA2 is really a collection of algorithms with varying hash digest lengths that are built upon some of the characteristics of SHA1. Particularly, SHA-256 also rely upon the use of the ch and maj functions on 32 bit words, though they do not use the parity function and also add sigma functions. SHA-512 builds on the foundations of the SHA-256 functions, however it uses them on 64-bit words. The other algorithms within the SHA2 family all are strongly connected with either SHA-256 or SHA-512. SHA-224 has different starting hash values than SHA-256 and truncates the ouput to 224 bit, but otherwise is the same internally. SHA-384, SHA-512/224 and SHA-512/256 share a similar relationship with SHA-512. I used the GTest framework to create unit tests showing that the SHA1 and SHA2 implementations accurately produce the results provided by NIST in their [Cryptographic Standards and Guidelines: Example Values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values).

### Secure Hash Algorithm 3 (SHA3)

#### (SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 and SHAKE256)

I implemented versions of the SHA3 hashing algorithms as laid out in NIST FIPS 202, ["SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions)"](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf). SHA3 is an entirely separate algorithm compared to SHA1 and SHA2. It is based on Keccak which was described in "Keccek implementation overview" by Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer from 2012. The internal state of the SHA3 algorithm is stored in a 3 dimensional bit array where x is between 0 and 4, y is between 0 and 4 and z is between 0 and 63. It is based on a sponge construction and each iteration it performs a series of function on the state array, theta, rho, pi, chi and iota. SHA3-224, SHA3-256, SHA3-384 and SHA3-512 each produce hashes of a set length and the largest difference between each of them is how much capacity there is in each iteration. SHAKE128 and SHAKE256 both allow the user to specify the length of the digest to be produced but still vary based on the internal capcity. SHA3 does have its own algorithms for translating bit strings into hex strings and back as specified in the appendix of NIST FIPS 202. I used the GTest framework to create unit tests showing that the SHA1 and SHA2 implementations accurately produce the results provided by NIST in their [Cryptographic Standards and Guidelines: Example Values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values).

### Advanced Encryption Standard (AES)

Using C++, I implemented a version of the Advanced Encryption Standard as laid out in [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf). It operates on blocks of 128 bits of the input at a time. AES has several variants based on the length of the key and I implemented AES-128, AES-192 and AES-256. . As the Advanced Encryption Standard is a symetric encryption algorithm, so it is necessary to have the same key to encrypt the message as you use to decrypt the message. For the example sequence shown below, I relied on the use of Elliptic Curve Diffie Hellman key exchange in order to use the shared secret to generate the same key as both the originator and the receiver. Symmetric Block Ciphers such as AES also operate in various modes in order to increase security or provide various supplemental functionality such as verifying authenticity.     

In the GUI application the user selects the key length and mode they would like to use. They may either generate a key and potential initialization vector they would like to use for the encryption or enter their own. The user may then enter a hexadecimal string into the input field and press the "Encrypt" button to encrypt it using the key.   

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/QT_GUI_Cryptography/Screenshots/AESEncrypt.png" 
    alt="This shows the AES version of key generation and encryption of Hex String in the GUI Application.">
</img>   

In order to decrypt the value that they had entered, the user may use the "Move Output To Input" button to move the result of the encryption into the input field. Then the user can use the "Decrypt" button in order to decrypt the value using the same key as it is a symmetric cypher.

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/QT_GUI_Cryptography/Screenshots/AESDecrypt.png" 
    alt="This shows the AES version of decryption of a Hex String in the GUI Application.">

#### Basic Modes of Operation   
##### Electronic Cookbook (ECB), Cipher Block Chaining (CBC), Cipher Feedback (CFB), Output Feedback (OFB) and Counter (CTR)

There are several modes of operation outlined in NIST SP 800-38A ["Recommendation for Block Cipher Modes of Operation"](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf). Electronic Cookbook (ECB) Mode simply applies the same AES cypher to each block of the input. The other modes rely on the use of an initialization vector, which is a separate block of input from the key that does not need to be secret, but should be unpredictable and different each time. Cipher Block Chaining (CBC) Mode uses xor with the initialization vector and the first block of input before running that through the AES Cipher. Each following block is xored with the result of the previous cypher in the place of the initialization block. Cipher Feedback Mode (CFB) does not apply the AES cipher directly to the input, but to the initialization vector and then xors that with the input. Each successive block uses the result of the xor operation from the previous block in the place of the initialization vector. It also allows the user to select an 's', which is the number of bits of the input to use in each block. The other bits are the least significant bits from the initialization vector concatenated with the previous cipher values. Output Feedback Mode (OFB) also does not apply the AES cipher directly to the input. The initialization vector for each subsequent block is the result of the cipher operation in the previous block. Counter Mode (CTR) also does not apply the apply the cipher directly to the input, but to the initialization vector which it xors with the input. The initialization vector is incremented for each successive block. Each of these modes can be selected using the drop down in the GUI applications. For the cipher feedback mode, the user may select from three of the most common 's' values, 1 bit, 8 bit and 128 bit.     

#### Galois / Counter Mode (GCM)    

Galois / Counter Mode generates tag value to allow for authenticating the messages. If the tag does not authenticate the message shall not be decrypted. 

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/QT_GUI_Cryptography/Screenshots/AESDecrypt_WrongGCMTag.png" 
    alt="This shows the AES version of decryption of a Hex String in the GUI Application where the GCM tag does not authenticate.">

Galois / Counter Mode is laid out in NIST SP 800-38D ["Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"](https://github.com/jbarbourmoore/Cryptography-Exploration/blob/21d2d0c8f185f773bf07ad21e2de559f8f14cbb2/CryptographySchemes/OutputImages/AES_GCM_Examples.png). GCM relies on the use of an initialization vector, which is a separate block of input from the key that does not need to be secret, but should be unpredictable and different each time. The IV is incremented for processing each subsequent block of input. Operations on blocks are performed within the Galois Field, 2**128. The Galois / Counter Mode produces a unique tag based on all of the input which allows for the authenticity to be verified, as well as the encrypted cypher text. I was able to use the Google Test framework to implement tests based on the example data from Appendix B "AES Test Vectors" of ["The Galois/Counter Mode of Operation (GCM)"](https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf). This allowed me to verify both encryption and decryption, as well as the creation of the appropriate tags, against several known hex strings, in order to be sure my implementations were operating appropriately

### Elliptic Curve Digital Signature Algorithm (ECDSA)   

I implemented version of Elliptic Curve Digital Signature Algorithm as laid out in [NIST FIPS 186-6](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf), [NIST FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) and [NIST SP 800-186](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf). As ECDSA does require the use of a hashing algorithm I was able to use my implementation of SHA3, after verifying the hash output matched the NIST examples in the Digital Signatures section of ["Cryptographic Standards and Guidelines"](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values). The elliptic curves that I have implemented at this time follow the Weirstrass Form of y**2 = x**3 +ax +b. The curves shown in the application below are from [NIST FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) Section D.1.2 "Curves over Prime Fields".

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/QT_GUI_Cryptography/Screenshots/ECDSA_Generate.png" 
    alt="This shows the screen for generating a ECDSA Private Key and creating a signature">
</img>  

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/main/C%2B%2B_Implementations/QT_GUI_Cryptography/Screenshots/ECDSA_Verify.png" 
    alt="This is a sequence diagram for a calculating the ECDSA Public Key and verifying a signature matches the public key">
</img>  

I was able to get NIST  examples for a couple of the curves and hashing algorithms including [Curve P-521 with SHA3-512](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA3-512.pdf) in order to verify that my Elliptic Curve Digital Signature Algorithms function as expected, including the intermediate values. I used these values to create unit tests using the Google Test suite.

