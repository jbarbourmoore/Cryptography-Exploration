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
from multiprocessing import Manager, Pool, Lock

class GenerationMethods(StrEnum):
    '''
    This enum keeps track of the generation methods for RSA keys
    '''
    probably_prime = "Probably Prime"
    probably_prime_probable_aux = "Probably Prime, Probable Aux Primes"
    probably_prime_provable_aux = "Probably Prime, Provable Aux Primes"
    provably_prime = "Provably Prime"
    provably_prime_aux = "Provably Prime, Aux Primes"

class RSA_KeyGeneration_IterationDetails():

    def __init__(self, file_lock, strength:SecurityStrengthDetails, private_key_type:int, generation_method:str, hash_function:ApprovedHashFunction = ApprovedHashFunctions.SHA_512_Hash.value, bitlens:list[int]=None):
        self.file_lock = file_lock
        self.strength = strength
        self.private_key_type = private_key_type
        self.generation_method = generation_method
        self.hash_function = hash_function
        self.bitlens = bitlens
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

def time_key_generation(details:RSA_KeyGeneration_IterationDetails):
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
    file_lock = details.file_lock
    nlen = details.strength.integer_factorization_cryptography
    hash_function = details.hash_function
    bitlens = details.bitlens
    security_strength = details.strength.security_strength
    generation_method = details.generation_method
    private_key_type = details.private_key_type
    private_key_string = "Standard" if details.private_key_type==0 else "Quintuple"
    little_endian = False

    # output the basic parameters to the command line
    # print("- - - - - - - - - - - -")
    # print(f"{generation_method} Key Generation With Security Strength {security_strength} And {private_key_string} Private Key")
    
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
        prime_durations = saveIterationData(file_lock, security_strength, private_key_string, generation_duration, encryption_duration, decryption_duration, generation_method)
    else:
        print("Something Went Wrong")
        prime_durations={"error":"Something Went Wrong"}
    return prime_durations

def saveIterationData(file_lock,security_strength:int, private_key_string:str, generation_duration:float, encryption_duration:float, decryption_duration:float, generation_method:str):
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

    file_lock.acquire()
    try:
        prime_df.to_csv('RSA_KeyGeneration_DurationsDataLocal.csv', mode='a', index=False, header=False)
    finally:
        file_lock.release()
    return prime_durations


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
            pt = "00000000009FF6DB1AE0F46E99A340A0390CF1F7E04791E0A1548E73AF2FBA1FFA43FCFDFE0279B4DE87EA8F98656EBC90F2C0B3EB4E75390627D78C2167D1A1E03B00C9396EE62292AC1E21045F836C139FDC1CB8D1FFE1F0A695F16EFF8114E492521D051AA2AB2A3855E94567691CDBB5BA797B749EC353E9DDCE68F7DC5AC47A6E42E6D809006374D517259307C9CE1F016030808D4432AA3DD0BA1FDFDEA84535637C2545E5CD3F55FAD8386C46369979004697231DA50BCD533FAEC7B1EF45142345BAA1B2AF65438DAADCC0FD5DA0B6640CB324BA86C1A5453F99A066FC1CE820197542D976EC134969E7C5FA8DC6E84399830B768D6818A2F491B494C6C5C26F027F04CE4CCD289A6E7BDF4974F151EB96DD382F79776D1EAE1C24E136D77B89EE02EB84B13F28D1D428B8D841AE3CF996E27332776DBD369932EC06497E7E601F3428432845F591333EC99A3B9AF73E1A3F9EFBCEDCAF5BF5B242050426EFC01A8F6ECCD59C5474568E31C5624874BA9F5474A1163C0C9435257D0D2163164CBEAF076801DA0F406A6D70CEE6C029EC3885BB52981F7BB358B1DF050267B414BBBDD584A876DBB941D2E526DDC26F83CC5FD4696A52C090C6392D7FFC9A66127585D145B1552BF35F6C9F789FB15685D3110CC0581760D78B56D6EE03254157DE80D8C14C648A31F27DC3279522D33942CA69305837AC84BF1FB7DA9F12457083058F9B6B03B5CB43A61B1B893EEB469968DCBB16E669C4D84ADF80E44CE195A34C53CD6716E8BE2ABE590CDA680CE3FE098885524475B77CCC382235422A837948A2086934617CEBEE6905BF7BB3F8E0094C6A572231A1FFC7F56A836371BC441C6CB59A305E96E76BF44238EE428D1016CB3D78B08D5E9BF0291ADAC3A1EE0434A880047B920D80AC05D58F0711B153E64D5930429383591029713655BF40D16AB27265172BB3544497FA81027EBC1CDAB013EE799742DEAD373AC6016333BCE7B6017D21F795FCE2C5C44A8F883C65A3B339536471F707BA6F5DAC4D4701C5D5F4507449BB817AB959667CDD45AEFEF5B105D1571F201DB9D296EB4A48150C4D8C5BD0E9923859760A258ABC30F88717E58FCB8E476F4359F0F9AF14F007BC100AC4EAD99D4BBADC4918F00E7DDCC067FB92CA97A5E7DCE6F6694477EF950D0E3C8BC656FAEAAFA2BC2324C7E04094D5393C9F601A42E772906D3E8CFC79C334DEF9C03C0F67FF4FFBBA85A8AB158381A2CADB6C093C56B14F7A52435C6EB7E99D9758451C832D96699F4D6CA8B3B7207E15416C4854B6442D82E9B87497DD4EDD897B25D33568DAC04AC358DD620FBA56AA7902B042690C4E14"
        elif security_strength == SecurityStrength.s256.value.security_strength:
            pt = "0000000000AB4D4CDF38FB0712519E1A76477EA6798225321B42BA5580E87F7804AFBD09F4240E782992C2E1C36465F3027FF505DAC4AF842D1BD4D895A4BB2A6A8E85F18F669A3C13057BC69E500F0BACA52734A696939D2BDB607026F4FA5F65C8F414D890654D88F33D9DB1B1463BE1C945E3A4AB5FBFAD98EE2FE7F260DC6CCA928D19C824C0E17DB6815C041D87C84939D73F145A49622925D3238E8552B6133EAB4AFFCBAB0A73CBBD86EC3B316B983FED2DD7E66E66CB6D0DB851FB9AC48CF1912E6B30C5AE9FE7A28BE8CA5ED643E4B073D7D15B479566CA8B0162D8A945957FE7D41E21A1108468DADD0EBB88B9EF0460332AAF362E544230EF7EC15F077831B4CB8D241CC1EBA6D1615DE9FD86CB97DCF2BDFC80FCB53EDEBF2E2EDC69B86D172CBCE46B8D0C59A339D6487A05F858F39882EEE0C54A3925D8A8C514587C8D7D368DF8209C683B57EFB693C7021AC19676D32ADBDBC342E99064DF249F3F3A8E3B3DDBB5B0A2926C4B20996A486430B34E3095D35138B13BA5957AF59AD1221CDE299ADE2587BF78A79FD334CC2767B066FCBE15B074FEBFE2EF56F8FE5AED30FFBC606317552B91CC856157B9D2916616624FAE524D233F54930CB8F2758958E80485B744B7113387574CB7CF5C434705CA42A6690A0B89DD1B6949A6E10F0CC22FE6FD2541AA7DAA48D40AAEE98F05F0FA1863031F15E376B0CB9E573E2B0D7E870F5923D10779C32D7516BF7EB73F945BCD161D84F8B47F37157F8947D123B2F13F50D22A52B8A69AE1706F8B8F69DAC7758327F2ABCC492AC5C3042F62F3FA046CC97B4C6DDD9C374BF56244BD05E866039243024BFE455D60738731E7BE057AC482CAC97DEB41CBA87E403657FA46B2AAA41E826E754A221C56A9DA066DF385A748EBC03A6EDB18EE63483CA3FACB0705F585AAD41EC6BDBF33006177EB0C3ADD6E12C3B0084442FBC5AB274E2F7F85DF8D3B10345442D98D0A781763DBF8A1427963A13E9B73C22150A2121B4685A998F2EF34EBAE8695D26EE689275DD31629725D57DABE0E654B11F5693A235B14CCE7019C884FB59365138E7A5A7D6F986E5D3626C31E37B6816D677AB547192DB12D583070652AD95D9815CF1FD9217E791517C6A1F57E352AD7F886165E1674233B933CCD50D9298FFA3530BD5264D6ED71072768D6DADC67766C65642F344834142EA8FDAFA4E3BD20742A5FA22B118523548344D17224F8FA973655376AD47CEEB68ED040B81305FD71585191B6923B197DD03765C2D8D3DAE94C54FC937DCC787BFBAA2D1A8C7C960BFDC07A8EE0481B2821379D297FE92FCEA27D0B6578DC0F4B9B130AB8F5B20E9A891B9C008AADB4303FB5B57311AEA080512FFCB5E9113C654CF1B6C029DA31CE0A4CE2414D4EC24B11AB6525A6F1D1EDE06228A7DA38414BCD7A130BF65E793B3F4601F96C62ABA794DA79C62C93F4A745E1754806357CF8199727316DA83058B7BE1AFBAB3F74F27BD86FAF590F02E35EA996717869091142A8F396C42B0F38220D2E98E2188E5B642FA6043C6EDB2EAF25421EDE6A9366BD66169351D2502B1FF24FFB8D81704FDC9B6C752BA31578B3CA40CDF5F72C853550DB73AA28F1BD0E4FC3727BC7BD2C4E2BBA3C129B9A1BE5006826BCE3788104A73C1B0530A28B749BD80CDFC2EBDF8C464148F481245D7B9912C68451B32AD473A989F4CAE1AA4628E81B4BDFE1DA9D4B8D1694FA931F50219498CC7E6FE6182F83FE1E23B4F074ED3BABDA2A1491A0F1BB7ADED53F2966E1ECE79CDDC88AEF5410B17D32E5FC3BA8729E1A56003E76AD871F239113DE9FEF4C6886009CDB4B90863D83C01004DBB1B5D788042C07D2675D88439CD91D930DB1E5C6F5B5EAA52C2C589CCA43F3DDC6271DB667B3AC4EF16DCD09F23BBB79B77B0EDD72E3048DE9B1AF91C26D55A9E55BE49C0B746E9B1EFB3A6A4FE8155D5807D2F848A90B9F61581D9F68036EBA4A6988B4EE937E4F577B82F54B24D01E0463ECEA266E150542D360F0F6543AEEA2DFC4E257D5C244F055EE1B0E8F72503F3346D48258288EEBE324B8DFDE5B1F2822F2C3A83B2D5593188010F866157B9E6CFD844D6348EC7480B9EE0E7055430F2376ECE906A7FB1CCDB09FD620D9C2CCA74E4511F055D55769005EACC68E12631CEAF21707E8788780DBC67CDC974C1E5E42E5150F7F98BC1294E91173880F4FEFEC715ADFFCEE6F04C84D4983B9C5A71C672214F145401CE22E1F7BB8C690F6ACBDE4485490B69CB3BD0030F377A68E141396A255FE415F36046323C1B03E011376A6CE7419875EE32C519171480CFEA504350F5BDB38A6EC552ECB1B8F1954E7D798F4AEFF8AC95EFFB3F4FDA5D5D1891EDD1F46A26ED825D340D691C01FFA0F7AFA2CC70E63536FEC7AB5F9BF1A767D16CC67559CF7D03B2006B4113726362F4CF39C3811D3EAA2673D884149D4E9D797BDE427715C2E0061B883835E526C67B8E95DB5C38D2D520CBE5D06998FCF664B12C95003517552D7FAFB103D60C32CB40CE6834B9FFF9BB5B5EDD8736A5B6630E3BF01A244B293E747EC6BDDC895D08965E9B976B4944BDF3421838BE3B9E2ED161B21E62155A580854DFD1A25422E77F0DBB86EC3AD314619B703B2B75483C37A8A0B49879CB32392BA0E3A558AB7D54B5076CDB5309151B858E411233D886C6230E0D1D69BF7291984"
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
            print(f"The encryption for {security_strength} was successful in {encryption_duration:.4f} seconds")
        if successful_decryption:
            print(f"The decryption for {security_strength} was successful in {decryption_duration:.4f} seconds")

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

    decryption_duration = row["Decryption"]
    encryption_duration = row["Encryption"]
    byte_length = 8
    security_strength = row["Security Strength"]
    for strength in SecurityStrength:
        if security_strength == strength.value.security_strength:
            nlen = strength.value.integer_factorization_cryptography
    encryption_bytes = nlen // byte_length
    encryption_duration_per_byte = encryption_duration / encryption_bytes
    decryption_duration_per_byte = decryption_duration / encryption_bytes
    
    encryption_per_byte.append(encryption_duration_per_byte)
    decryption_per_byte.append(decryption_duration_per_byte)
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
    print(encryption_per_byte)
    prime_df['Encryption Duration Per Byte Of Data'] = encryption_per_byte
    prime_df['Decryption Duration Per Byte Of Data'] = decryption_per_byte
    prime_df = prime_df.rename(columns={'Encryption': 'Encryption Duration', 'Decryption': 'Decryption Duration', 'Generation Method':'Method'})
    
    return prime_df

def prepare_dataframe_from_csv_cpp_comp():
    '''
    This method loads the dataframe from the CSV and adjusts the data for presentation purposes

    Returns :
        prime_df : int
            The key generation data as a dataframe ready to be turned into graphs
    '''
    prime_df = pd.read_csv("RSA_KeyGeneration_DurationsData.csv")
    prime_df["Programming Language"] = pd.Series(["Python" for x in range(len(prime_df.index))]) 
    cpp_prime_df = pd.read_csv("RSA_KeyGeneration_DurationsData_c++.csv")
    cpp_prime_df["Programming Language"] = pd.Series(["C++" for x in range(len(cpp_prime_df.index))]) 
    prime_df = pd.concat([prime_df,cpp_prime_df])
    print(prime_df.info())
    prime_df = prime_df.reset_index()
    prime_df.apply(add_key_length, axis=1)
    prime_df["Key Lengths"] = nlens
    print(encryption_per_byte)
    prime_df['Encryption Duration Per Byte Of Data'] = encryption_per_byte
    prime_df['Decryption Duration Per Byte Of Data'] = decryption_per_byte
    prime_df = prime_df.rename(columns={'Encryption': 'Encryption Duration', 'Decryption': 'Decryption Duration', 'Generation Method':'Method'})
    
    return prime_df

if __name__ == '__main__':
    
    # e_min = pow(2, 16)
    # hex_e_min = IntegerHandler(e_min).getHexString()
    # e_max = pow(2, 256)
    # hex_e_max = IntegerHandler(e_max).getHexString()

    # print(f"e_min : {hex_e_min} {e_min}")
    # print(f"e_max : {hex_e_max} {e_max}")

    # def calcMinPQDif(nlen:int):
    #     min_pq_diff =  pow(2, nlen//2 - 100)
    #     return IntegerHandler(min_pq_diff).getHexString()
    
    # print("min diff p q ")
    # print(f"2048  : {calcMinPQDif(2048)}")
    # print(f"3072  : {calcMinPQDif(3072)}")
    # print(f"7680  : {calcMinPQDif(7680)}")
    # print(f"15360 : {calcMinPQDif(15360)}")

    # from decimal import Decimal
    # from math import sqrt
    # def calc_prime_min(nlen:int):
    #     sqrt2 = Decimal.from_float(sqrt(2))
    #     nlen2_1 =  Decimal.from_float(pow(2, nlen//2 - 1))
    #     result = int(sqrt2 * nlen2_1)
    #     return IntegerHandler(result).getHexString()


    # print("prime min")
    # print(f"2048  : {calc_prime_min(2048)}")
    # print(f"3072  : {calc_prime_min(3072)}")
    # print(f"7680  : {calc_prime_min(7680)}")
    # print(f"15360 : {calc_prime_min(15360)}")

    # from sympy import isprime
    # print(f"is prime : {isprime(int("DCE02F59C1D1ECAF57A545B223024F03BA8D4EAFF8A022434AD9949E44529E80A71D6603DF6693A7931291AE1593A2E8874ABC2DE7858372F305476E2C11ADF594226141F58D21206425D6FC3A61CE4DE8BDD6BDA464956C63A413FF8F785DBA252E7BECBC7E7361CEE870EEA4FAC61701FAB862720417682C9C3F8753DAE549",16))}")
    # print(f"is prime : {isprime(int("F51F6FC17F642E3F14A39D6CAB5F347E8FECE78A8D569ED66BE1F037D4313E1F75A4A9E25F2A825C5247995AA3CD93A45682F805F6967472B1C45E1206A1EB7CCE5E1F836EDA592702162FFB882419ABFFA2FB67CEEE33E527001EF130003554DC16F40112AB8194D420671C00128CC7CDD2746411C33245539D3124D130B69D",16))}")

    # p = "FC0EF6F02038053B7672BEC5B09D2B218FFC75ED4F001F096E26F44546F8FD5A5B8D9B4544818A0FFAD6F5C25F5F0B3CC8217447F975D45D4C35BAF4D4180FC80FAFA506DD1F08CE576BD28A31B1D15307728A98C54AB2E17D7F83BD3A96C256999882BF2CDB5DE138FCD7366BA0B0755BE3E6BDDA3D07598B51F1A2093FC8E3"
    # p0 = "A2C79F48926B634B837EE70C556B2E365023ADA6D0DB4127466CF6BBE2C4981AD0943CFCA434E97D883EC7DA5521924DD254C93409B7A9A76EDCADEE7C437CF3"
    # z = "D0CCE65FA1A1E3CB57E73B541679D969F44086F7A16552E26CF340163B76009C776096B734005C74D5243739F7AA67150D1A1D86A4EC73E563043B8B46209939EA7FD069411C8017A61D37BF2112EEDAF5E598626701C1921733DA76534B72A38AFF8D3DC728B848047F1985D1544FFF54C1AFB1BB7B99C3ECCDE015D1306280"
    # print(pow(int(z,16),int(p0,16), int(p,16)))
    # print(f"is prime : {isprime(int(p,16))}")
    # file_lock = Lock()
    # number_of_iterations = 1
    # strengths_lists = [[SecurityStrength.s112.value],[SecurityStrength.s128.value],[SecurityStrength.s192.value],[SecurityStrength.s256.value]]
    # # strengths_lists = [[SecurityStrength.s192.value],[SecurityStrength.s256.value]]
    # little_endian = False
    # beginning_execution = time.time()
    # m = Manager()
    # file_lock = m.Lock()
    # generation_methods_abbreviated = [GenerationMethods.probably_prime, GenerationMethods.provably_prime]

    # iterations_details:list[RSA_KeyGeneration_IterationDetails] = []
    # for j in range (0, number_of_iterations):
    #     for i in range(0, len(strengths_lists)):
    #         # for generation_method in generation_methods_abbreviated:
    #         for generation_method in GenerationMethods:
    #             strengths = strengths_lists[i]
    #             for strength in strengths:
    #                 for private_key_type in RSA_PrivateKey_Type:
    #                     iterations_details.append(RSA_KeyGeneration_IterationDetails(file_lock=file_lock, strength=strength,private_key_type=private_key_type.value,generation_method=generation_method))

    # with Pool(processes=4) as pool:
    #     pool.map(time_key_generation,iterations_details)
    # print(iterations_details)
    # # time_key_generation(strength=strength,private_key_type=private_key_type.value,generation_method=generation_method)
    # print(f"Total Time Elapsed During This Run : {time.time() - beginning_execution:.4f}")
    
    nlens, encryption_per_byte, decryption_per_byte = [],[],[]
    prime_df = prepare_dataframe_from_csv_cpp_comp()
    print(prime_df.info())

    standard_priv_df = prime_df[prime_df["Private Key Type"] == "Standard"]
    quintuple_priv_df = prime_df[prime_df["Private Key Type"] != "Standard"]

    bright_palette = sns.hls_palette(h=.5)
    sns.set_context("paper")
    sns.set_theme(style="ticks", palette=bright_palette, font_scale=.7)
    

    abreviated_df = prime_df[prime_df["Method"] == GenerationMethods.provably_prime]
    sns.lmplot(x="Key Lengths", y="Key Generation Duration", hue="Private Key Type", col="Programming Language", data=abreviated_df, order=3, height=4, x_estimator=np.mean, legend_out=True, legend=True)
    # plt.legend(loc="upper left",shadow=True,title = "Prime Generation Method",bbox_to_anchor=(1.05, 1)) 
    # plt.tight_layout()
    # plt.show()

    cpp_df = prime_df[prime_df["Programming Language"] == "C++"]
    fig, axes = plt.subplots(nrows=1, ncols=3, sharey=False)
    fig.set_figwidth(13)
    fig.set_figheight(5)

    standard_priv_df = cpp_df[cpp_df["Private Key Type"] == "Standard"]
    quintuple_priv_df = cpp_df[cpp_df["Private Key Type"] != "Standard"]

    axes[0].set_title('Key Length Vs. Key Generation Duration')
    # sns.regplot(data=prime_df, x="Key Lengths", y="Key Generation Duration", x_estimator=np.mean, ax=axes[0], order=2, color=bright_palette[2])
    sns.regplot(data=standard_priv_df, x="Key Lengths", y="Key Generation Duration", x_estimator=np.mean, ax=axes[0], order=3, color=bright_palette[0], label = "Standard")
    sns.regplot(data=quintuple_priv_df, x="Key Lengths", y="Key Generation Duration", x_estimator=np.mean, ax=axes[0], order=3, color=bright_palette[1], label = "Quintuple")
    # plt.legend(loc="upper left",shadow=True,title = "Private Key Type")

    axes[1].set_title('Key Length Vs. Encryption Duration')
    # sns.scatterplot(data=prime_df, x="Key Lengths", y="Encryption Duration", hue="Private Key Type", style="Private Key Type", ax=axes[1], palette=bright_palette, markers=["o", "s"], alpha = .5)
    sns.regplot(data=standard_priv_df, x="Key Lengths", y="Encryption Duration Per Byte Of Data", x_estimator=np.mean, ax=axes[1], order=2, color=bright_palette[0], label = "Standard")
    sns.regplot(data=quintuple_priv_df, x="Key Lengths", y="Encryption Duration Per Byte Of Data", x_estimator=np.mean, ax=axes[1], order=2, color=bright_palette[1], label = "Quintuple")
    # plt.legend(loc="upper left",shadow=True,title = "Private Key Type")

    axes[2].set_title('Key Length Vs. Decryption Duration')
    # sns.scatterplot(data=prime_df, x="Key Lengths", y="Decryption Duration", hue="Private Key Type", style="Private Key Type", ax=axes[2], palette=bright_palette, markers=["o", "s"], alpha = .5)
    sns.regplot(data=standard_priv_df, x="Key Lengths", y="Decryption Duration Per Byte Of Data", x_estimator=np.mean, ax=axes[2], order=2, color=bright_palette[0], label = "Standard")
    sns.regplot(data=quintuple_priv_df, x="Key Lengths", y="Decryption Duration Per Byte Of Data", x_estimator=np.mean, ax=axes[2], order=2, color=bright_palette[1], label = "Quintuple")
    plt.legend(loc="upper left",shadow=True,title = "Private Key Type",bbox_to_anchor=(1.05, 1))
    plt.tight_layout()
    plt.show()

    # fig, axes = plt.subplots(nrows=1, ncols=3, sharey=False)
    # fig.set_figwidth(13)
    # fig.set_figheight(5)


    # axes[0].set_title('Key Length Vs. Key Generation Duration')
    # # sns.regplot(data=prime_df, x="Key Lengths", y="Key Generation Duration", x_estimator=np.mean, ax=axes[0], order=2, color=bright_palette[2])
    # sns.regplot(data=standard_priv_df, x="Key Lengths", y="Key Generation Duration", x_estimator=np.mean, ax=axes[0], order=3, color=bright_palette[0], label = "Standard")
    # sns.regplot(data=quintuple_priv_df, x="Key Lengths", y="Key Generation Duration", x_estimator=np.mean, ax=axes[0], order=3, color=bright_palette[1], label = "Quintuple")
    # # plt.legend(loc="upper left",shadow=True,title = "Private Key Type")

    # axes[1].set_title('Key Length Vs. Encryption Duration')
    # # sns.scatterplot(data=prime_df, x="Key Lengths", y="Encryption Duration", hue="Private Key Type", style="Private Key Type", ax=axes[1], palette=bright_palette, markers=["o", "s"], alpha = .5)
    # sns.regplot(data=standard_priv_df, x="Key Lengths", y="Encryption Duration Per Byte Of Data", x_estimator=np.mean, ax=axes[1], order=3, color=bright_palette[0], label = "Standard")
    # sns.regplot(data=quintuple_priv_df, x="Key Lengths", y="Encryption Duration Per Byte Of Data", x_estimator=np.mean, ax=axes[1], order=3, color=bright_palette[1], label = "Quintuple")
    # # plt.legend(loc="upper left",shadow=True,title = "Private Key Type")

    # axes[2].set_title('Key Length Vs. Decryption Duration')
    # # sns.scatterplot(data=prime_df, x="Key Lengths", y="Decryption Duration", hue="Private Key Type", style="Private Key Type", ax=axes[2], palette=bright_palette, markers=["o", "s"], alpha = .5)
    # sns.regplot(data=standard_priv_df, x="Key Lengths", y="Decryption Duration Per Byte Of Data", x_estimator=np.mean, ax=axes[2], order=3, color=bright_palette[0], label = "Standard")
    # sns.regplot(data=quintuple_priv_df, x="Key Lengths", y="Decryption Duration Per Byte Of Data", x_estimator=np.mean, ax=axes[2], order=3, color=bright_palette[1], label = "Quintuple")
    # plt.legend(loc="upper left",shadow=True,title = "Private Key Type",bbox_to_anchor=(1.05, 1))
    # plt.tight_layout()
    # plt.show()

    # abreviated_df = prime_df[prime_df["Key Lengths"] != SecurityStrength.s256.value.integer_factorization_cryptography]
    # sns.lmplot(x="Key Lengths", y="Key Generation Duration", hue="Method", col="Method", data=prime_df,order=3, height=4, x_estimator=np.mean, legend_out=True, legend=True)
    # # plt.legend(loc="upper left",shadow=True,title = "Prime Generation Method",bbox_to_anchor=(1.05, 1)) 
    # plt.tight_layout()
    # plt.show()