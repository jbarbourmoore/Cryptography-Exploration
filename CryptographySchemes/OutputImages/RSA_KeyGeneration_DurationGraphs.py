import unittest
from HelperFunctions.IntegerHandler import IntegerHandler
from CryptographySchemes.SecurityStrength import SecurityStrength, SecurityStrengthDetails
from CryptographySchemes.RSA.RSA_Keys import RSA_KeyGeneration, RSA_PublicKey, RSA_PrivateKey, RSA_PrivateKey_QuintupleForm, RSA_PrivateKey_Type
from CryptographySchemes.RSA.RSA_Primitives import RSA
from CryptographySchemes.HashingAlgorithms.ApprovedHashFunctions import ApprovedHashFunction, ApprovedHashFunctions
import time
import pandas as pd
from matplotlib import pyplot as plt
import seaborn as sns


prime_durations={
    "Security Strength":[],
    "Key Generation Duration": [],
    "Generation Method":[],
    "Encryption":[],
    "Decryption":[],
    "Private Key Type":[]
}

class RSA_KeyGeneration_UnitTests(unittest.TestCase):
    def test_provably_prime(self):
        '''
        This method tests the generation of primes which are provably prime as RSA keys
        '''
        for i in range(0, len(strengths)):
            for j in range(0, number_of_iterations):
                test_case_number = i * number_of_iterations + j + 1
                with self.subTest(f"Provably Prime Key Generation : Test Case {test_case_number} With Security Strength {strengths[i].security_strength}"):
                    print("- - - - - - - - - - - -")
                    print(f"Provably Prime Key Generation : Test Case {test_case_number} With Security Strength {strengths[i].security_strength}")
                    
                    rsa_bit_length_for_strength = strengths[i].integer_factorization_cryptography
                    if j % 2 == 0: private_key_type = RSA_PrivateKey_Type.Standard
                    else : private_key_type = RSA_PrivateKey_Type.Quint
                    start_time = time.time()
                    public_key, private_key = RSA_KeyGeneration.generateRSAKeyPair_ProvablePrimes(security_strength=strengths[i].security_strength, hash_function=ApprovedHashFunctions.SHA_512_Hash.value, private_key_type=private_key_type, is_debug=False)
                    generation_duration = time.time() - start_time
                    successful_generation = self.verifyKeyGeneration(strengths, i, public_key, private_key, generation_duration)

                    encryption_duration, decryption_duration, successful_encryption, successful_decryption = self.verifyEncryptionDecryption(little_endian, strengths, i, rsa_bit_length_for_strength, public_key, private_key)

                    if successful_generation and successful_encryption and successful_decryption:
                        generation_method = "Provably Prime"
                        self.saveIterationData(i, private_key_type, generation_duration, encryption_duration, decryption_duration, generation_method)

    def saveIterationData(self, i, private_key_type, generation_duration, encryption_duration, decryption_duration, generation_method):
        prime_durations["Encryption"].append(encryption_duration)
        prime_durations["Decryption"].append(decryption_duration)
        prime_durations["Private Key Type"].append("Standard" if private_key_type==0 else "Quintuple")
        prime_durations["Generation Method"].append(generation_method)
        prime_durations["Key Generation Duration"].append(generation_duration)
        prime_durations["Security Strength"].append(strengths[i].security_strength)

    def test_provably_prime_with_auxillary_primes(self):
        '''
        This method tests the generation of primes which are provably prime with auxillary primes as RSA keys
        '''

        for i in range(0, len(strengths)):
            rsa_bit_length_for_strength = strengths[i].integer_factorization_cryptography                    
            hash_function = ApprovedHashFunctions.SHA_512_Hash.value
            
            for j in range(0, number_of_iterations):
                test_case_number = i * number_of_iterations + j + 1
                with self.subTest(f"Provably Prime With Auxillary Primes Key Generation : Test Case {test_case_number} With Security Strength {strengths[i].security_strength}"):
                    print("- - - - - - - - - - - -")
                    print(f"Provably Prime Key Generation With Auxillary Primes : Test Case {test_case_number} With Security Strength {strengths[i].security_strength}")
                    bitlens = None
                    if j % 2 == 0: private_key_type = RSA_PrivateKey_Type.Standard
                    else : private_key_type = RSA_PrivateKey_Type.Quint
                    start_time = time.time()
                    public_key, private_key = RSA_KeyGeneration.generateRSAKeyPair_ProvablePrimes_AuxillaryPrimes(bitlens=bitlens,security_strength=strengths[i].security_strength, hash_function=hash_function, private_key_type=private_key_type, is_debug=False)
                    generation_duration = time.time() - start_time
                    successful_generation = self.verifyKeyGeneration(strengths, i, public_key, private_key, generation_duration)
                    encryption_duration, decryption_duration, successful_encryption, successful_decryption = self.verifyEncryptionDecryption(little_endian, strengths, i, rsa_bit_length_for_strength, public_key, private_key)

                    if successful_generation and successful_encryption and successful_decryption:
                        generation_method = "Provably Prime, Aux Primes"
                        self.saveIterationData(i, private_key_type, generation_duration, encryption_duration, decryption_duration, generation_method)

    def test_probably_prime(self):
        '''
        This method tests the generation of primes which are probably prime as RSA keys
        '''

        for i in range(0, len(strengths)):
            rsa_bit_length_for_strength = strengths[i].integer_factorization_cryptography
            for j in range(0, number_of_iterations):
                test_case_number = i * number_of_iterations + j + 1
                with self.subTest(f"Probably Prime Key Generation : Test Case {test_case_number} With Security Strength {strengths[i].security_strength}"):
                    print("- - - - - - - - - - - -")
                    print(f"Probably Prime Key Generation : Test Case {test_case_number} With Security Strength {strengths[i].security_strength}")
                    if j % 2 == 0: private_key_type = RSA_PrivateKey_Type.Standard
                    else : private_key_type = RSA_PrivateKey_Type.Quint
                    start_time = time.time()
                    public_key, private_key = RSA_KeyGeneration.generateRSAKeyPair_ProbablePrimes(security_strength=strengths[i].security_strength, private_key_type=private_key_type, is_debug=False)
                    generation_duration = time.time() - start_time
                    successful_generation = self.verifyKeyGeneration(strengths, i, public_key, private_key, generation_duration)

                    encryption_duration, decryption_duration, successful_encryption, successful_decryption = self.verifyEncryptionDecryption(little_endian, strengths, i, rsa_bit_length_for_strength, public_key, private_key)

                    if successful_generation and successful_encryption and successful_decryption:
                        generation_method = "Probably Prime"
                        self.saveIterationData(i, private_key_type, generation_duration, encryption_duration, decryption_duration, generation_method)

    def test_probably_prime_with_prob_aux(self):
        '''
        This method tests the generation of primes which are probably prime as RSA keys
        '''

        for i in range(0, len(strengths)):
            rsa_bit_length_for_strength = strengths[i].integer_factorization_cryptography
            for j in range(0, number_of_iterations):
                test_case_number = i * number_of_iterations + j + 1
                with self.subTest(f"Probably Prime With Probably Prime Auxillary Primes Key Generation : Test Case {test_case_number} With Security Strength {strengths[i].security_strength}"):
                    print("- - - - - - - - - - - -")
                    print(f"Probably Prime With Probably Prime Auxillary Primes Key Generation : Test Case {test_case_number} With Security Strength {strengths[i].security_strength}")
                    if j % 2 == 0: private_key_type = RSA_PrivateKey_Type.Standard
                    else : private_key_type = RSA_PrivateKey_Type.Quint
                    bitlens = None
                    start_time = time.time()
                    public_key, private_key = RSA_KeyGeneration.generateRSAKeyPair_ProbablePrimes_AuxillaryProbablePrimes(bitlens=bitlens, security_strength=strengths[i].security_strength, private_key_type=private_key_type, is_debug=False)
                    generation_duration = time.time() - start_time
                    successful_generation = self.verifyKeyGeneration(strengths, i, public_key, private_key, generation_duration)

                    encryption_duration, decryption_duration, successful_encryption, successful_decryption = self.verifyEncryptionDecryption(little_endian, strengths, i, rsa_bit_length_for_strength, public_key, private_key)

                    if successful_generation and successful_encryption and successful_decryption:
                        generation_method = "Probably Prime, Probable Aux Primes"
                        self.saveIterationData(i, private_key_type, generation_duration, encryption_duration, decryption_duration, generation_method)

    
    def test_probably_prime_with_prov_aux(self):
        '''
        This method tests the generation of primes which are probably prime as RSA keys
        '''

        for i in range(0, len(strengths)):
            rsa_bit_length_for_strength = strengths[i].integer_factorization_cryptography
            for j in range(0, number_of_iterations):
                test_case_number = i * number_of_iterations + j + 1
                with self.subTest(f"Probably Prime With Provably Prime Auxillary Primes Key Generation : Test Case {test_case_number} With Security Strength {strengths[i].security_strength}"):
                    print("- - - - - - - - - - - -")
                    print(f"Probably Prime With Provably Prime Auxillary Primes Key Generation : Test Case {test_case_number} With Security Strength {strengths[i].security_strength}")
                    if j % 2 == 0: private_key_type = RSA_PrivateKey_Type.Standard
                    else : private_key_type = RSA_PrivateKey_Type.Quint
                    bitlens = None
                    start_time = time.time()
                    public_key, private_key = RSA_KeyGeneration.generateRSAKeyPair_ProbablePrimes_AuxillaryProvablePrimes(bitlens=bitlens, security_strength=strengths[i].security_strength, private_key_type=private_key_type, is_debug=False)
                    generation_duration = time.time() - start_time
                    successful_generation = self.verifyKeyGeneration(strengths, i, public_key, private_key, generation_duration)

                    encryption_duration, decryption_duration, successful_encryption, successful_decryption = self.verifyEncryptionDecryption(little_endian, strengths, i, rsa_bit_length_for_strength, public_key, private_key)

                    if successful_generation and successful_encryption and successful_decryption:
                        generation_method = "Probably Prime, Provable Aux Primes"
                        self.saveIterationData(i, private_key_type, generation_duration, encryption_duration, decryption_duration, generation_method)

    def verifyEncryptionDecryption(self, little_endian:bool, strengths:list[SecurityStrengthDetails], i:int, rsa_bit_length_for_strength:int, public_key:RSA_PublicKey, private_key:RSA_PrivateKey):
        '''
        This method verifies the encryption and decryption operations can be successfully completed with the generated key pair
        '''
        
        if strengths[i] == SecurityStrength.s112.value:
            pt = "0D3E74F20C249E1058D4787C22F95819066FA8927A95AB004A240073FE20CBCB149545694B0EE318557759FCC4D2CA0E3D55307D1D3A4CD1F3B031CE0DF356A5DEDCC25729C4302FABA4CB885C9FA3C2F57A4D1308451C300D2378E90F4F83DCEDCDCF5217BC3840A796FCDAF73483A3D199C389BDB50CFE95D9C02E5F4FC1917FA4606CF6AB7559253202698D7EABE7561137271CE1A524E5956D25C379AF4F121877355F2495DC154A0EB33CF2F3B6990F60FCC0CCE199EF1E76E11585895EE1C619FB6D140266006AB41D56CE3E6C68571902568CD4520F1F9E5E284B4B9DFCC3782D05CDF826895450E314FBC654032A775F47088F18D3B4000AC23BD107"
        elif strengths[i] == SecurityStrength.s128.value:
            pt = "2F56A87647F57039FD097C231DE7F1BBA45EB79DE69049E91851DADD2B7B592FAE0846EF40A94E1F2DBDCDD7134713D52527D550401C82793034C1E884410805BD90DBBE100D14E3048369D88C5821D8CB30FED48AD00E1DF41681C0B6E91DDF515449C06164E9854227DB51D8034A6D3C8F52207C585776A1BA4A32EA166B2000DE3420FA94C88245E76B8B7001C0E05DAFD1FB5799465420B794374C3F2AE74C6C2477C61F1FBA9B65D4D62DB4EBB06B83FACC4131DD040AD0E639C5CAF778FC3CF66C08A53002343167B49F6B3F98A144510F874D27FDF58164D9FFCC9F746D4473C56D5B197F3E5F80D786B3775FA21E9C09C97989FFE9A97420443A8CCC0EBA13018D5456AC25596D7C9144D0785B01A22DB98AFB605D14A1C4AD140B289B54B2DBC80924EDA11D24B78B0FAAA7C299410FADD9EBFEE6FDCC38EB3AAF8D867C6FABB83EDD453F9A388AA533A6211C9897550562C9A5C5CB312DCE8E8F6CEBA1872C4E22D746FB8CBBEFA503849C6A95639055E72185182053DDB994D301"
        elif strengths[i] == SecurityStrength.s192.value:
            pt = "63BB1B3301164D4F7B2E33A1005A21ECB150394D3AB6BB2FFF96EAA726F1877A30C212C623BEA81FD0A58742552760C12CDD8936F675D710B92645166C55EB2578C79E521C8F9A50CD4D7785448C8D813F0DB014A27793260A49C9D59310B34A5A7778E22300C96C3B5389CD54D149C9AB402B2C60081B869BC61114AA8D21A63FAEFA3D91150D1E97E14C6167E0FFFDDD9AE6017ADF229A54B98B5CFBE69921E366C980F667EF2282F20FAAB53448B9B73519B472421C2B3E2A0AB88D2BA9C85CCA7F6DD954D0444F20AEB58AAE68FB3806A7DD30AB109A2B71451A888BACD18918677458E3D2A09622FE0CC12C6D8A7BB2868D20814EA89BAA1D1BCD5C66CF469BEF0B8C6162D7A1940E9E64085A12EEFAFA0687E2B7BCA580D07726F1BAC9F344545B47CAA6EBFB083B2B3C35DB18E918C7611DFB788B64D68C5891D607C286E8E291805543E81973800A62873503759A32EA7C6CC908CBBDCD68469B4C085BC8D1A84F7AB5319FAE5C0C74E7368223DA55BE3709EB226CC1500E1B6F3A795226DCB42869BC6E755CD864DF8803767B5AF36298EF18658C79497CA9D9260C6DE58B4EBE1280580C9EBF2929094CBC7FB9CFEC36CFF87528ADE16316AB736E6FAE1373BA7C95F1DD0C7D7BD4C9067FBE054E41FB88E840AE623BEB81189475B590A449253D38B9121D2929112923ED9F409529A712DEC56EA394D69D7A0B6A"
        elif strengths[i] == SecurityStrength.s256.value:
            pt = "63BB1B3301164D4F7B2E33A1005A21ECB150394D3AB6BB2FFF96EAA726F1877A30C212C623BEA81FD0A58742552760C12CDD8936F675D710B92645166C55EB2578C79E521C8F9A50CD4D7785448C8D813F0DB014A27793260A49C9D59310B34A5A7778E22300C96C3B5389CD54D149C9AB402B2C60081B869BC61114AA8D21A63FAEFA3D91150D1E97E14C6167E0FFFDDD9AE6017ADF229A54B98B5CFBE69921E366C980F667EF2282F20FAAB53448B9B73519B472421C2B3E2A0AB88D2BA9C85CCA7F6DD954D0444F20AEB58AAE68FB3806A7DD30AB109A2B71451A888BACD18918677458E3D2A09622FE0CC12C6D8A7BB2868D20814EA89BAA1D1BCD5C66CF469BEF0B8C6162D7A1940E9E64085A12EEFAFA0687E2B7BCA580D07726F1BAC9F344545B47CAA6EBFB083B2B3C35DB18E918C7611DFB788B64D68C5891D607C286E8E291805543E81973800A62873503759A32EA7C6CC908CBBDCD68469B4C085BC8D1A84F7AB5319FAE5C0C74E7368223DA55BE3709EB226CC1500E1B6F3A795226DCB42869BC6E755CD864DF8803767B5AF36298EF18658C79497CA9D9260C6DE58B4EBE1280580C9EBF2929094CBC7FB9CFEC36CFF87528ADE16316AB736E6FAE1373BA7C95F1DD0C7D7BD4C9067FBE054E41FB88E840AE623BEB81189475B590A449253D38B9121D2929112923ED9F409529A712DEC56EA394D69D7A0B6A"
                    
        plain = IntegerHandler.fromHexString(pt, little_endian)
        start_time = time.time()
        encrypted = RSA.RSA_EncryptionPrimitive(public_key, plain, bit_length=rsa_bit_length_for_strength)
        encryption_duration = time.time() - start_time
        start_time = time.time()
        decrypted = RSA.RSA_DecryptionPrimitive(private_key, encrypted, bit_length=rsa_bit_length_for_strength)
        decryption_duration = time.time() - start_time
        successful_encryption = plain.getValue() != encrypted.getValue()
        successful_decryption = plain.getValue() == decrypted.getValue()
        if successful_encryption:
            print(f"The encryption was successful in {encryption_duration:.4f} seconds")
        if successful_decryption:
            print(f"The decryption was successful in {decryption_duration:.4f} seconds")
        self.assertTrue(successful_decryption)
        self.assertTrue(successful_encryption)
        return encryption_duration,decryption_duration,successful_encryption,successful_decryption

    def verifyKeyGeneration(self, strengths:list[SecurityStrengthDetails], i:int, public_key:RSA_PublicKey, private_key:RSA_PrivateKey, generation_duration:float):
        '''
        This method verifies the successful generation of the public and private RSA keys
        '''
        
        self.assertIsNotNone(public_key)
        self.assertIsNotNone(private_key)
        successful_generation = public_key.n == private_key.n
        if successful_generation:
            print(f"The RSA Keys for security strength {strengths[i].security_strength} were generated in {generation_duration:.4f} seconds")
        self.assertEqual( public_key.n.getValue(), private_key.n.getValue())
        return successful_generation

if __name__ == '__main__':
    
    number_of_iterations = 2
    strengths_lists = [[SecurityStrength.s112.value],[SecurityStrength.s128.value],[SecurityStrength.s192.value],[SecurityStrength.s256.value]]
    for j in range (0, 3):
        for i in range(0, 4):
        # strengths = [SecurityStrength.s112.value, SecurityStrength.s128.value]
        # strengths = [SecurityStrength.s112.value, SecurityStrength.s128.value, SecurityStrength.s192.value]
            prime_durations={
                "Security Strength":[],
                "Key Generation Duration": [],
                "Generation Method":[],
                "Encryption":[],
                "Decryption":[],
                "Private Key Type":[]
            }
            strengths = strengths_lists[i]
            little_endian = False
            unittest.main(exit=False)
            prime_df = pd.DataFrame.from_dict(prime_durations)
            print(prime_df)
            
            # fig, axes = plt.subplots(nrows=1, ncols=1, sharey=False)
            # fig.set_figwidth(8)
            # fig.set_figheight(8)

            # bright_palette = sns.hls_palette(h=.5)
            # sns.set_context("paper")
            # sns.set_theme(style="whitegrid", palette=bright_palette, font_scale=1)

            # sns.scatterplot(data=prime_df, x="Security Strength", y="Key Generation Duration", ax=axes, hue="Generation Method", palette=bright_palette)
            # sns.regplot(data=prime_df[prime_df["Generation Method"] == "Provably Prime"], x="Security Strength", y="Key Generation Duration", ax=axes, color=bright_palette[3])
            # sns.regplot(data=prime_df[prime_df["Generation Method"] == "Provably Prime, Aux Primes"], x="Security Strength", y="Key Generation Duration", ax=axes, color=bright_palette[4])
            # sns.regplot(data=prime_df[prime_df["Generation Method"] == "Probably Prime"], x="Security Strength", y="Key Generation Duration", ax=axes, color=bright_palette[0])
            # sns.regplot(data=prime_df[prime_df["Generation Method"] == "Probably Prime, Probable Aux Primes"], x="Security Strength", y="Key Generation Duration", ax=axes, color=bright_palette[1])
            # sns.regplot(data=prime_df[prime_df["Generation Method"] == "Probably Prime, Provable Aux Primes"], x="Security Strength", y="Key Generation Duration", ax=axes, color=bright_palette[2])
            if i+j == 0:
                add_header = True
            else:
                add_header = False
            prime_df.to_csv('RSA_KeyGeneration_DurationsData.csv', mode='a', index=False, header=add_header)
  
    # plt.tight_layout()
    # plt.show()


