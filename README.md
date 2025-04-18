# Cryptography Exploration
A repository created in order to explore cryptography related algorithms, implementations and concepts. The sequence diagrams shown below are created using plantuml code I generated using Python based on the results of the implemented algorithms.

## Cryptography Schemes  

### Advanced Encryption Standard (AES)   

I implemented a version of the Advanced Encryption Standard as laid out in [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf). AES has several variants based on the length of the key and I implemented AES-128, AES-192 and AES 256. The Advanced Encryption Standard is a symetric encryption algorithm, so it is necessary to have the same key to encrypt the message as you use to decrypt the message. For the example sequence shown below, I relied on the use of Elliptic Curve Diffie Hellman key exchange in order to use the shared secret to generate the same key as both the originator and the receiver.    

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/7749310c7971a234fdea77e301452805eec7d0c1/GeneratingDiagrams/Diagrams/AES_With_ECDHKeyExchange.png" 
    alt="This is a sequence diagram for a message exchange using AES, with ECDH key exchange used to generate the key">
</img>  

For AES, I was also able to create unit tests based on the example data provided by NIST in their [Cryptographic Standards and Guidelines](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core_All.pdf). This allowed me to verify both encryption and decryption against several known hex strings, in order to be sure they were being properly encrypted. Below is a sample of the output from this testing.

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/7749310c7971a234fdea77e301452805eec7d0c1/CryptographySchemes/OutputImages/AES_Examples.png" 
    alt="Sample output of AES unit tests ran against NIST sample data.">
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

I implemented a version of the RSA Cryptography scheme. RSA was named after R.L. Rivest, A. Shamir, and L. Adleman who laid out the system in their paper ["A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"](https://people.csail.mit.edu/rivest/Rsapaper.pdf) from 1977. It relies on the difficulty in factoring large primes in order to prevnt people from breaking the security, and it is no longer particularly secure today, due to advancements in computing. When using RSA to encrypt messages each participant generates a private a public key. The message is sent using the recipient's public key and can then be decrypted using their private key. RSA keys are generated by first generating two large prime numbers, p and q. These prime numbers are mulitplied together in order to calculate n which is part of the public key. d and e are calculated with the help of the extended form of euclids algorithm such that when encrypting with the public key e and n, the public key d and n may be used to decrypt.    

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/1198ce3dad1ca992daadf42effca7986062f38a2/GeneratingDiagrams/Diagrams/BasicRSACryptographySchemeSequence.png" 
    alt="This is a sequence diagram for a simple message and reply using the RSA Cryptography scheme">
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

### SHA-3   

I implemented a version of SHA3, including SHA3-224, SHA3-256, SHA3-384 and SHA3-512. SHA3 is currently one of the recommended algorithms for creating secure hashes. The algorithm guidelines for SHA3 are laid out in NIST FIPS 202, ["SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf). SHA-3 is based on Keccak which was described in ["Keccek implementation overview"](https://keccak.team/files/Keccak-implementation-3.2.pdf) by Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer from 2012. Much like with AES, NIST provides a list of some example inputs and output at ["Cryptographic Standards and Guidelines"](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values) to allow a developer to verify their program is functioning as expected. I was able to use this information to develop unit tests for my implementation and an example of the output is shown below. I do think it is worth mentioning that the example data is not read to binary strings exactly as one would expect, but by the use of custom algorithms as laid out in the appendix of [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) (Algorithm 10 "h2b" and Algorithm 11 "b2h").

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%; max-height:100%"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/7749310c7971a234fdea77e301452805eec7d0c1/CryptographySchemes/OutputImages/SHA3_Examples.png" 
    alt="This shows example from unit tests for the SHA3 implementation using known values from NIST">
</img>   

### Caesar Cypher  

I implemented a version of the caesar cypher in Python. The caesar cypher is a very simple example of a cypher which relies on shifting every character in a message the same number of places in the alphabet. For example if you were to encrypt "def" with a multiplcation value of four the result would be "hij". The idea is that, without the knowing the shift value, it is harder to find the original message. However, since the cypher is limited by the number of letters in the alphabet, it is trivial to brute force.

<img 
    style="display: block; margin-left: auto; margin-right: auto; width: 100%;"
    src="https://github.com/jbarbourmoore/Cryptography-Exploration/blob/1198ce3dad1ca992daadf42effca7986062f38a2/GeneratingDiagrams/Diagrams/BasicCaesarCypherSequence.png" 
    alt="This is a sequence diagram for a simple message and reply using caesar cypher">
</img>

### Multiplicative Cypher  

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

