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
import numpy as np
from enum import StrEnum

class GenerationMethods(StrEnum):
    '''
    This enum keeps track of the generation methods for RSA keys
    '''
    probably_prime = "Probably Prime"
    probably_prime_probable_aux = "Probably Prime, Probable Aux Primes"
    probably_prime_provable_aux = "Probably Prime, Provable Aux Primes"
    provably_prime = "Provably Prime"
    provably_prime_aux = "Provably Prime, Aux Primes"

def get_empty_dictionary():
    '''
    This method returns an empty dictionary with the categories that are to be saved to the csv 
    '''
    return {"Security Strength":[],
            "Key Generation Duration": [],
            "Generation Method":[],
            "Encryption":[],
            "Decryption":[],
            "Private Key Type":[]}

def time_key_generation(strength:SecurityStrengthDetails, private_key_type:int, generation_method:str):
    '''
    This method tests the generation of RSA keys and tracks the time it takes to generate them

    Parameters :
        strength : SecurityStrengthDetails
            The security strength that is being tested
        private_key_type : int
            The type of private key to be used 
        generation_method : str
            How the keys primes are to be generated
    '''


    # set basic parameters
    nlen = strength.integer_factorization_cryptography
    hash_function = ApprovedHashFunctions.SHA_512_Hash.value
    bitlens = None
    security_strength = strength.security_strength
    private_key_string = "Standard" if private_key_type==0 else "Quintuple"

    # output the basic parameters to the command line
    print("- - - - - - - - - - - -")
    print(f"{generation_method} Key Generation With Security Strength {security_strength} And {private_key_string} Private Key")
    
    # generate the keys and time the duration
    start_time = time.time()
    if generation_method == GenerationMethods.provably_prime.value:
        public_key, private_key = RSA_KeyGeneration.generateRSAKeyPair_ProvablePrimes(security_strength=security_strength, hash_function=hash_function, private_key_type=private_key_type, is_debug=False)
    elif generation_method == GenerationMethods.provably_prime_aux.value:
        public_key, private_key = RSA_KeyGeneration.generateRSAKeyPair_ProvablePrimes_AuxillaryPrimes(bitlens=bitlens,security_strength=security_strength, hash_function=hash_function, private_key_type=private_key_type, is_debug=False)
    elif generation_method == GenerationMethods.probably_prime.value:
        public_key, private_key = RSA_KeyGeneration.generateRSAKeyPair_ProbablePrimes(security_strength=security_strength, private_key_type=private_key_type, is_debug=False)
    elif generation_method == GenerationMethods.probably_prime_probable_aux:
        public_key, private_key = RSA_KeyGeneration.generateRSAKeyPair_ProbablePrimes_AuxillaryProbablePrimes(bitlens=bitlens, security_strength=security_strength, private_key_type=private_key_type, is_debug=False)
    elif generation_method == GenerationMethods.probably_prime_provable_aux:
        public_key, private_key = RSA_KeyGeneration.generateRSAKeyPair_ProbablePrimes_AuxillaryProvablePrimes(bitlens=bitlens, security_strength=security_strength, private_key_type=private_key_type, is_debug=False)
    generation_duration = time.time() - start_time

    # verify key generation and ability to both encrypt and decrypt
    successful_generation = verifyKeyGeneration(security_strength, public_key, private_key, generation_duration)
    encryption_duration, decryption_duration, successful_encryption, successful_decryption = verifyEncryptionDecryption(little_endian, security_strength, nlen, public_key, private_key)

    # export the generated data to the csv for later analysis
    if successful_generation and successful_encryption and successful_decryption:
        saveIterationData(security_strength, private_key_string, generation_duration, encryption_duration, decryption_duration, generation_method)
    else:
        print("Something Went Wrong")

def saveIterationData(security_strength:int, private_key_string:str, generation_duration:float, encryption_duration:float, decryption_duration:float, generation_method:str):
    '''
    This method saves the data of the iteration to the CSV file for further analysis

    Parameters :
        security_strength : int
            The requested security strength of the iteration (112,128,192,256)
        private_key_string : str
            The private key type as a string
        generation_duration : float
            How long it took to generate the keys in seconds
        encryption_duration : float
            How long it took to use the generated keys to encrypt the data
        decryption_duration : float
            How long it took to use the generated keys to decrypt the data
        generation_method : str
            What generation method was used to generate the RSA keys
    '''
    
    prime_durations = get_empty_dictionary()
    prime_durations["Encryption"].append(encryption_duration)
    prime_durations["Decryption"].append(decryption_duration)
    prime_durations["Private Key Type"].append(private_key_string)
    prime_durations["Generation Method"].append(generation_method)
    prime_durations["Key Generation Duration"].append(generation_duration)
    prime_durations["Security Strength"].append(security_strength)

    prime_df = pd.DataFrame.from_dict(prime_durations)
    prime_df.to_csv('RSA_KeyGeneration_DurationsDataLocal.csv', mode='a', index=False, header=False)


def verifyEncryptionDecryption(little_endian:bool, security_strength:int, nlen:int, public_key:RSA_PublicKey, private_key:RSA_PrivateKey):
        '''
        This method verifies the encryption and decryption operations can be successfully completed with the generated key pair
        
        Parameters : 
            little_endian : bool
                Whether the data is being stored in little endian format
            security_strength : int
                The requested security strength
            nlen : int
                The corresponding bit length for the key
            public_key : RSA_PublicKey
                The public key to be used in encryption
            private_key : RSA_PrivateKey
                The private key to be used in decryption
        '''
        #select the plain text to encrypt
        if security_strength == SecurityStrength.s112.value.security_strength:
            pt = "0D3E74F20C249E1058D4787C22F95819066FA8927A95AB004A240073FE20CBCB149545694B0EE318557759FCC4D2CA0E3D55307D1D3A4CD1F3B031CE0DF356A5DEDCC25729C4302FABA4CB885C9FA3C2F57A4D1308451C300D2378E90F4F83DCEDCDCF5217BC3840A796FCDAF73483A3D199C389BDB50CFE95D9C02E5F4FC1917FA4606CF6AB7559253202698D7EABE7561137271CE1A524E5956D25C379AF4F121877355F2495DC154A0EB33CF2F3B6990F60FCC0CCE199EF1E76E11585895EE1C619FB6D140266006AB41D56CE3E6C68571902568CD4520F1F9E5E284B4B9DFCC3782D05CDF826895450E314FBC654032A775F47088F18D3B4000AC23BD107"
        elif security_strength == SecurityStrength.s128.value.security_strength:
            pt = "2F56A87647F57039FD097C231DE7F1BBA45EB79DE69049E91851DADD2B7B592FAE0846EF40A94E1F2DBDCDD7134713D52527D550401C82793034C1E884410805BD90DBBE100D14E3048369D88C5821D8CB30FED48AD00E1DF41681C0B6E91DDF515449C06164E9854227DB51D8034A6D3C8F52207C585776A1BA4A32EA166B2000DE3420FA94C88245E76B8B7001C0E05DAFD1FB5799465420B794374C3F2AE74C6C2477C61F1FBA9B65D4D62DB4EBB06B83FACC4131DD040AD0E639C5CAF778FC3CF66C08A53002343167B49F6B3F98A144510F874D27FDF58164D9FFCC9F746D4473C56D5B197F3E5F80D786B3775FA21E9C09C97989FFE9A97420443A8CCC0EBA13018D5456AC25596D7C9144D0785B01A22DB98AFB605D14A1C4AD140B289B54B2DBC80924EDA11D24B78B0FAAA7C299410FADD9EBFEE6FDCC38EB3AAF8D867C6FABB83EDD453F9A388AA533A6211C9897550562C9A5C5CB312DCE8E8F6CEBA1872C4E22D746FB8CBBEFA503849C6A95639055E72185182053DDB994D301"
        elif security_strength == SecurityStrength.s192.value.security_strength:
            pt = "63BB1B3301164D4F7B2E33A1005A21ECB150394D3AB6BB2FFF96EAA726F1877A30C212C623BEA81FD0A58742552760C12CDD8936F675D710B92645166C55EB2578C79E521C8F9A50CD4D7785448C8D813F0DB014A27793260A49C9D59310B34A5A7778E22300C96C3B5389CD54D149C9AB402B2C60081B869BC61114AA8D21A63FAEFA3D91150D1E97E14C6167E0FFFDDD9AE6017ADF229A54B98B5CFBE69921E366C980F667EF2282F20FAAB53448B9B73519B472421C2B3E2A0AB88D2BA9C85CCA7F6DD954D0444F20AEB58AAE68FB3806A7DD30AB109A2B71451A888BACD18918677458E3D2A09622FE0CC12C6D8A7BB2868D20814EA89BAA1D1BCD5C66CF469BEF0B8C6162D7A1940E9E64085A12EEFAFA0687E2B7BCA580D07726F1BAC9F344545B47CAA6EBFB083B2B3C35DB18E918C7611DFB788B64D68C5891D607C286E8E291805543E81973800A62873503759A32EA7C6CC908CBBDCD68469B4C085BC8D1A84F7AB5319FAE5C0C74E7368223DA55BE3709EB226CC1500E1B6F3A795226DCB42869BC6E755CD864DF8803767B5AF36298EF18658C79497CA9D9260C6DE58B4EBE1280580C9EBF2929094CBC7FB9CFEC36CFF87528ADE16316AB736E6FAE1373BA7C95F1DD0C7D7BD4C9067FBE054E41FB88E840AE623BEB81189475B590A449253D38B9121D2929112923ED9F409529A712DEC56EA394D69D7A0B6A"
        elif security_strength == SecurityStrength.s256.value.security_strength:
            pt = "63BB1B3301164D4F7B2E33A1005A21ECB150394D3AB6BB2FFF96EAA726F1877A30C212C623BEA81FD0A58742552760C12CDD8936F675D710B92645166C55EB2578C79E521C8F9A50CD4D7785448C8D813F0DB014A27793260A49C9D59310B34A5A7778E22300C96C3B5389CD54D149C9AB402B2C60081B869BC61114AA8D21A63FAEFA3D91150D1E97E14C6167E0FFFDDD9AE6017ADF229A54B98B5CFBE69921E366C980F667EF2282F20FAAB53448B9B73519B472421C2B3E2A0AB88D2BA9C85CCA7F6DD954D0444F20AEB58AAE68FB3806A7DD30AB109A2B71451A888BACD18918677458E3D2A09622FE0CC12C6D8A7BB2868D20814EA89BAA1D1BCD5C66CF469BEF0B8C6162D7A1940E9E64085A12EEFAFA0687E2B7BCA580D07726F1BAC9F344545B47CAA6EBFB083B2B3C35DB18E918C7611DFB788B64D68C5891D607C286E8E291805543E81973800A62873503759A32EA7C6CC908CBBDCD68469B4C085BC8D1A84F7AB5319FAE5C0C74E7368223DA55BE3709EB226CC1500E1B6F3A795226DCB42869BC6E755CD864DF8803767B5AF36298EF18658C79497CA9D9260C6DE58B4EBE1280580C9EBF2929094CBC7FB9CFEC36CFF87528ADE16316AB736E6FAE1373BA7C95F1DD0C7D7BD4C9067FBE054E41FB88E840AE623BEB81189475B590A449253D38B9121D2929112923ED9F409529A712DEC56EA394D69D7A0B6A"
        plain = IntegerHandler.fromHexString(pt, little_endian)

        # Run and time the encryption process
        start_time = time.time()
        encrypted = RSA.RSA_EncryptionPrimitive(public_key, plain, bit_length=nlen)
        encryption_duration = time.time() - start_time

        # run and time the decryption process
        start_time = time.time()
        decrypted = RSA.RSA_DecryptionPrimitive(private_key, encrypted, bit_length=nlen)
        decryption_duration = time.time() - start_time

        # evaluate whether encryption and decryption were successful
        successful_encryption = plain.getValue() != encrypted.getValue()
        successful_decryption = plain.getValue() == decrypted.getValue()
        if successful_encryption:
            print(f"The encryption was successful in {encryption_duration:.4f} seconds")
        if successful_decryption:
            print(f"The decryption was successful in {decryption_duration:.4f} seconds")

        return encryption_duration,decryption_duration,successful_encryption,successful_decryption

def verifyKeyGeneration(security_strength:int, public_key:RSA_PublicKey, private_key:RSA_PrivateKey, generation_duration:float):
        '''
        This method verifies the successful generation of the public and private RSA keys
        
        Parameters :
            security_strength : int
                The requested security strength
            public_key : RSA_PublicKey
                The public key to be used in encryption
            private_key : RSA_PrivateKey
                The private key to be used in decryption
            generation_duration : float
                The amount of time in seconds that it took to generate the keys
        '''
        
        successful_generation = public_key != None and private_key != None and public_key.n == private_key.n
        if successful_generation:
            print(f"The RSA Keys for security strength {security_strength} were generated in {generation_duration:.4f} seconds")
        return successful_generation
    
def add_key_length(row):
    '''
    This method gets the key length for a row of the duration data so it can be added as an additional column

    Parameters :
        row : Array
            The current row being processed from the dataframe
    '''
    security_strength = row["Security Strength"]
    for strength in SecurityStrength:
        if security_strength == strength.value.security_strength:
            nlen = strength.value.integer_factorization_cryptography
    nlens.append(nlen)

def prepare_dataframe_from_csv():
    '''
    This method loads the dataframe from the CSV and adjusts the data for presentation purposes

    Returns :
        prime_df : int
            The key generation data as a dataframe ready to be turned into graphs
    '''
    prime_df = pd.read_csv("RSA_KeyGeneration_DurationsData.csv")
    prime_df = prime_df.reset_index()
    prime_df.apply(add_key_length, axis=1)
    prime_df["Key Lengths"] = nlens
    prime_df = prime_df.rename(columns={'Encryption': 'Encryption Duration', 'Decryption': 'Decryption Duration', 'Generation Method':'Method'})
    return prime_df

if __name__ == '__main__':
    
    number_of_iterations = 1
    # strengths_lists = [[SecurityStrength.s112.value],[SecurityStrength.s128.value],[SecurityStrength.s192.value],[SecurityStrength.s256.value]]
    strengths_lists = [[SecurityStrength.s112.value]]
    little_endian = False
    beginning_execution = time.time()
    for j in range (0, number_of_iterations):
        for i in range(0, len(strengths_lists)):
            for generation_method in GenerationMethods:
                strengths = strengths_lists[i]
                for strength in strengths:
                    for private_key_type in RSA_PrivateKey_Type:
                        time_key_generation(strength=strength,private_key_type=private_key_type.value,generation_method=generation_method)
                        print(f"Total Time Elapsed During This Run : {time.time() - beginning_execution:.4f}")
            
    nlens = []
    prime_df = prepare_dataframe_from_csv()

    standard_priv_df = prime_df[prime_df["Private Key Type"] == "Standard"]
    quintuple_priv_df = prime_df[prime_df["Private Key Type"] != "Standard"]
    fig, axes = plt.subplots(nrows=1, ncols=3, sharey=False)
    fig.set_figwidth(14)
    fig.set_figheight(5)

    bright_palette = sns.hls_palette(h=.5)
    sns.set_context("paper")
    sns.set_theme(style="whitegrid", palette=bright_palette, font_scale=.7)

    axes[0].set_title('Key Length Vs. Key Generation Duration')
    sns.regplot(data=prime_df, x="Key Lengths", y="Key Generation Duration", x_estimator=np.mean, ax=axes[0], order=2, color=bright_palette[2])

    axes[1].set_title('Key Length Vs. Encryption Duration')
    sns.scatterplot(data=prime_df, x="Key Lengths", y="Encryption Duration", hue="Private Key Type", style="Private Key Type", ax=axes[1], palette=bright_palette, markers=["o", "s"], alpha = .5)
    sns.regplot(data=standard_priv_df, x="Key Lengths", y="Encryption Duration", scatter=False, ax=axes[1], order=2, color=bright_palette[0])
    sns.regplot(data=quintuple_priv_df, x="Key Lengths", y="Encryption Duration", scatter=False, ax=axes[1], order=2, color=bright_palette[1])

    axes[2].set_title('Key Length Vs. Decryption Duration')
    sns.scatterplot(data=prime_df, x="Key Lengths", y="Decryption Duration", hue="Private Key Type", style="Private Key Type", ax=axes[2], palette=bright_palette, markers=["o", "s"], alpha = .5)
    sns.regplot(data=standard_priv_df, x="Key Lengths", y="Decryption Duration", scatter=False, ax=axes[2], order=2, color=bright_palette[0])
    sns.regplot(data=quintuple_priv_df, x="Key Lengths", y="Decryption Duration", scatter=False, ax=axes[2], order=2, color=bright_palette[1])
    
    sns.lmplot(x="Key Lengths", y="Key Generation Duration", hue="Method", col="Method", data=prime_df,order=2, height=4, x_estimator=np.mean, legend_out=True, legend=False)
    plt.tight_layout()
    plt.show()