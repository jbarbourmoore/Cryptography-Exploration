from CryptographySchemes.SymmetricEncryptionAlgorithms.AdvancedEncryptionStandard import AES256
from CryptographySchemes.SymmetricEncryptionAlgorithms.AES_GaloisCounterMode import AES_GCM_256
from HelperFunctions import EllipticCurveDetails
from CryptographySchemes.EllipticCurveDHKeyExchange import EllipticCurveDHKeyExchange, EllipticCurveDHKeyPair
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup
from CryptographySchemes.HashingAlgorithms.SecureHashAlgorithm3 import *
from HelperFunctions.IntegerHandler import*
from math import ceil
import secrets

def runEllipticCurveDHKeyExchangeExampleScenario():
    '''
    This function runs a simple example scenario for the Elliptic Curve Diffie Hellman Key Exchange
    '''
    elliptic_curve_dh_key_exchange = EllipticCurveDHKeyExchange([EllipticCurveDetails.getCurveP521],is_debug=True)

    originator_ecdhkeypair = EllipticCurveDHKeyPair(elliptic_curve_dh_key_exchange, is_debug=True)
    receiver_ecdhkeypair = EllipticCurveDHKeyPair(elliptic_curve_dh_key_exchange, is_debug=True)
    originator_ecdhkeypair.calculateSharedSecret()
    receiver_ecdhkeypair.calculateSharedSecret()

    assert originator_ecdhkeypair.shared_secret == receiver_ecdhkeypair.shared_secret
    return elliptic_curve_dh_key_exchange,originator_ecdhkeypair,receiver_ecdhkeypair

def constructECDHKeyExchangeSequence(elliptic_curve_dh_key_exchange:EllipticCurveDHKeyExchange, originator_ecdhkeypair:EllipticCurveDHKeyPair, receiver_ecdhkeypair:EllipticCurveDHKeyPair, ecdhkeyexchange_sequence:BasicSequenceDiagramSetup):
    '''
    This function constructs the sequence for the simple diffie hellman key exchange scenario
    '''
    
    ecdhkeyexchange_sequence.initializeParticipants(2)

    # First both participants agree on a shard prime and matching generator value
    ecdhkeyexchange_sequence.addDivider("Agreeing On Shared Values")
    ecdhkeyexchange_sequence.activateParticipant(0)
    ecdhkeyexchange_sequence.activateParticipant(1)
    ecdhkeyexchange_sequence.addMutualAgreement("Selecting An Elliptic Curve", f"The curve is {elliptic_curve_dh_key_exchange.curve_details.name}")
    gen_x, gen_y = elliptic_curve_dh_key_exchange.curve_details.generator_point
    gen_x = IntegerHandler(gen_x,False).getHexString()
    gen_y = IntegerHandler(gen_y,False).getHexString()
    ecdhkeyexchange_sequence.addMutualAgreement("Selecting A Generator Point", f"The generator is ({gen_x}, {gen_y})")
    ecdhkeyexchange_sequence.deactivateParticipant(1)

    # each participant selects their private key and then calculates their public key
    ecdhkeyexchange_sequence.addDivider("Generating Public and Private Keys")
    orig_priv = IntegerHandler(originator_ecdhkeypair.private_key,False).getHexString()
    orig_pub_x, orig_pub_y = originator_ecdhkeypair.public_key
    orig_pub_x = IntegerHandler(orig_pub_x,False).getHexString()
    orig_pub_y = IntegerHandler(orig_pub_y,False).getHexString()
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"New private key is {orig_priv}","Generating Private Key For Originator")
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"New public key is ({orig_pub_x}, {orig_pub_y})","Calculating Public Key For Originator")
    ecdhkeyexchange_sequence.deactivateParticipant(0)
    ecdhkeyexchange_sequence.activateParticipant(1)
    rec_priv = IntegerHandler(receiver_ecdhkeypair.private_key,False).getHexString()
    rec_pub_x, rec_pub_y = receiver_ecdhkeypair.public_key
    rec_pub_x = IntegerHandler(rec_pub_x,False).getHexString()
    rec_pub_y = IntegerHandler(rec_pub_y,False).getHexString()
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"New private key is {rec_priv}","Generating Private Key For Receiver")
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"New public key is ({rec_pub_x}, {rec_pub_y})","Calculating Public Key For Receiver")
    ecdhkeyexchange_sequence.deactivateParticipant(1)

    # now the participants can use the other's public key along with their pre existing knowledge to calculate the shared value
    ecdhkeyexchange_sequence.addDivider("Calculating Shared Secret")
    ecdhkeyexchange_sequence.addALabeledRetrieval(1,0,f"Receiver's compressed public key is {receiver_ecdhkeypair.getCompressedPublicKey()[2:].upper()}","Retrieving Receiver's Compressed Public Key")
    ecdhkeyexchange_sequence.activateParticipant(0)
    orig_share_x, orig_share_y = originator_ecdhkeypair.shared_secret
    orig_share_x = IntegerHandler(orig_share_x,False).getHexString()
    orig_share_y = IntegerHandler(orig_share_y,False).getHexString()
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"Shared secret is ({orig_share_x}, {orig_share_y})","Calculating Shared Secret Using Originator's Private\\nKey And Receiver's Public Key")
    ecdhkeyexchange_sequence.deactivateParticipant(0)
    ecdhkeyexchange_sequence.addALabeledRetrieval(0,1,f"Originator's compressed public key is {originator_ecdhkeypair.getCompressedPublicKey()[2:].upper()}","Retrieving Originator's Compressed Public Key")
    ecdhkeyexchange_sequence.activateParticipant(1)
    rec_share_x, rec_share_y = receiver_ecdhkeypair.shared_secret
    rec_share_x = IntegerHandler(rec_share_x,False).getHexString()
    rec_share_y = IntegerHandler(rec_share_y,False).getHexString()
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"Shared secret is ({rec_share_x}, {rec_share_y})","Calculating Shared Secret Using Receiver's Private\\nKey And Originator's Public Key")
    ecdhkeyexchange_sequence.deactivateParticipant(1)

def generateIVandA():
    '''
    This method generates random values for the initialization vector and additional data

    Returns :
        initialization_value : str
            A 96 bit hex string for use with AES GCM
        additional_data : str
            A 128 bit hex string for use with AES GCM
    '''

    iv = secrets.randbits(96)
    iv = IntegerHandler(iv,False,96).getHexString()

    a = secrets.randbits(128)
    a = IntegerHandler(a,False,128).getHexString()

    return iv, a

def getAES256KeyFromSharedSecret(curve, shared_secret):
    '''
    This function gets a 64 byte hexadecimal key from the shared secret

    Uses the one step key derivation process outlined in section 4 of NIST SP 800 56
    In this case H(x) has been chosen as the SHA3-512 hashing function
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf

    Returns :
        key : str
            A 256 bit key for aes 256 as a hexadecimal key
        initialization_value : str
            A 96 bbit for use with AES GCM
        additional_data : str
            A 128 bit hex string for use with AES GCM
    '''
    L = 256
    sha3 = sha3_512
    H = sha3.hashBitArray
    Z = SHA3_ValueHandler.fromHexString(curve.compressPointOnEllipticCurve(shared_secret)[2:])
    fixed_info = SHA3_ValueHandler.fromString("This is fixed information to be used in the generation of a key")

    if L > 0:
        reps = ceil(L/sha3.digest_length)

    result = SHA3_ValueHandler([0])
    for i in range(0,reps):
        hash_contents = SHA3_ValueHandler.fromHexString(str(i))
        hash_contents = hash_contents.concatenate(Z)
        hash_contents = hash_contents.concatenate(fixed_info)
        k = H(hash_contents.bit_array)
        result = result.concatenate(k)
    derived_key_material = SHA3_ValueHandler(result.bit_array[:L])
    return derived_key_material.getHexString()[:L//4]

def sendMessageWithAES(originator_ecdhkeypair, receiver_ecdhkeypair):
    '''
    This function uses the shared secret in order to encrypt and decrypt a message using AES-256
    '''

    originator_aes_key = getAES256KeyFromSharedSecret(originator_ecdhkeypair.elliptic_curve_dh_key_exchange_data.curve, originator_ecdhkeypair.shared_secret)
    originator_iv, originator_ad = generateIVandA()
    receiver_aes_key= getAES256KeyFromSharedSecret(receiver_ecdhkeypair.elliptic_curve_dh_key_exchange_data.curve, receiver_ecdhkeypair.shared_secret)
    originator_aes_256_gcm = AES_GCM_256(originator_aes_key)
    message = "The password for our email server is TheSUp3RS3CurePW!"
    encrypted_message, tag = originator_aes_256_gcm.authenticatedEncryption_StringMessage(originator_iv,message,originator_ad,128)    
    receiver_aes_256 = AES_GCM_256(receiver_aes_key)
    authenticated, decrypted_message = receiver_aes_256.authenticatedDecryption_StringMessage(originator_iv,encrypted_message,originator_ad,tag)
    return originator_aes_key,receiver_aes_key,message,encrypted_message.getHexString(),decrypted_message, tag.getHexString(), authenticated, originator_iv, originator_ad

def sendReplyWithAES(originator_ecdhkeypair, receiver_ecdhkeypair):
    '''
    This function uses the shared secret in order to encrypt and decrypt a reply using AES-256
    '''

    originator_aes_key = getAES256KeyFromSharedSecret(originator_ecdhkeypair.elliptic_curve_dh_key_exchange_data.curve, originator_ecdhkeypair.shared_secret)
    receiver_aes_key  = getAES256KeyFromSharedSecret(receiver_ecdhkeypair.elliptic_curve_dh_key_exchange_data.curve, receiver_ecdhkeypair.shared_secret)
    receiver_iv, receiver_ad = generateIVandA()
    originator_aes_256 = AES_GCM_256(originator_aes_key)
    receiver_aes_256 = AES_GCM_256(receiver_aes_key)
    reply = "Ok! I will be updating the system in a week."
    encrypted_reply, reply_tag = receiver_aes_256.authenticatedEncryption_StringMessage(receiver_iv,reply,receiver_ad,128)
    reply_authenticated, decrypted_reply = originator_aes_256.authenticatedDecryption_StringMessage(receiver_iv,encrypted_reply,receiver_ad,reply_tag)
    return reply,encrypted_reply.getHexString(),decrypted_reply, reply_tag.getHexString(), reply_authenticated, receiver_iv, receiver_ad

def addSendingAESMessageToDiagram(elliptic_curve_dhkeyexchange_sequence:BasicSequenceDiagramSetup, originator_aes_key:str, receiver_aes_key:str, message:str, encrypted_message:str, decrypted_message:str, tag:str, authenticated:bool, initialization_vector:str):
    '''
    This function adds sending a message to the sequence diagram
    '''

    elliptic_curve_dhkeyexchange_sequence.addDivider("Sending A Message With AES-256")
    elliptic_curve_dhkeyexchange_sequence.activateParticipant(0)
    elliptic_curve_dhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"Originator's AES key is {originator_aes_key}","Calculating AES-256 Key With Shared Secret")
    elliptic_curve_dhkeyexchange_sequence.activateParticipant(1)
    elliptic_curve_dhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"Receiver's AES key is  {receiver_aes_key}","Calculating AES-256 Key With Shared Secret")
    elliptic_curve_dhkeyexchange_sequence.deactivateParticipant(1)
    elliptic_curve_dhkeyexchange_sequence.encryptSendAndDecryptMessageWithTagAuthAndIV(0,1,message,encrypted_message,tag,authenticated,initialization_vector,decrypted_message,deactivate_end = False)

if __name__ == '__main__':
    elliptic_curve_dh_key_exchange, originator_ecdhkeypair, receiver_ecdhkeypair = runEllipticCurveDHKeyExchangeExampleScenario()
    elliptic_curve_dhkeyexchange_sequence = BasicSequenceDiagramSetup("AES-256-GCM With ECDH Key Exchange Example")
    elliptic_curve_dhkeyexchange_sequence.addBannerNote("This sequence shows the use of Elliptic Curve Diffie Hellman Key Exchange with Curve P-512 to securely establish the use of AES-256 Symmetric Block Encryption in Galois/Counter Mode (GCM)")
    constructECDHKeyExchangeSequence(elliptic_curve_dh_key_exchange, originator_ecdhkeypair, receiver_ecdhkeypair, elliptic_curve_dhkeyexchange_sequence)
    originator_aes_key, receiver_aes_key, message, encrypted_message, decrypted_message, tag, authenticated, orig_iv, orig_ad = sendMessageWithAES(originator_ecdhkeypair, receiver_ecdhkeypair)
    addSendingAESMessageToDiagram(elliptic_curve_dhkeyexchange_sequence, originator_aes_key, receiver_aes_key, message, encrypted_message, decrypted_message,tag,authenticated,orig_iv)
    reply, encrypted_reply, decrypted_reply, reply_tag, reply_authenticated, rec_iv, rec_ad = sendReplyWithAES(originator_ecdhkeypair, receiver_ecdhkeypair)
    elliptic_curve_dhkeyexchange_sequence.addDivider("Sending A Reply With AES-256")
    elliptic_curve_dhkeyexchange_sequence.encryptSendAndDecryptMessageWithTagAuthAndIV(1,0,reply,encrypted_reply,reply_tag,reply_authenticated,rec_iv,decrypted_reply, "Reply",activate_start=False)
    
    
    elliptic_curve_dhkeyexchange_sequence.printAllDiagrams()