from CryptographySchemes.AdvancedEncryptionStandard import AES256
from HelperFunctions import EllipticCurveDetails
from CryptographySchemes.EllipticCurveDHKeyExchange import EllipticCurveDHKeyExchange, EllipticCurveDHKeyPair
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup
from CryptographySchemes.SecureHashAlgorithm3 import SHA3_512
from math import ceil

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
    ecdhkeyexchange_sequence.addMutualAgreement("Selecting A Generator Point", f"The generator is {elliptic_curve_dh_key_exchange.curve_details.generator_point}")
    ecdhkeyexchange_sequence.deactivateParticipant(1)

    # each participant selects their private key and then calculates their public key
    ecdhkeyexchange_sequence.addDivider("Generating Public and Private Keys")
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"New private key is {originator_ecdhkeypair.private_key}","Generating Private Key For Originator")
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"New public key is {originator_ecdhkeypair.public_key}","Calculating Public Key For Originator")
    ecdhkeyexchange_sequence.deactivateParticipant(0)
    ecdhkeyexchange_sequence.activateParticipant(1)
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"New private key is {receiver_ecdhkeypair.private_key}","Generating Private Key For Receiver")
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"New public key is {receiver_ecdhkeypair.public_key}","Calculating Public Key For Receiver")
    ecdhkeyexchange_sequence.deactivateParticipant(1)

    # now the participants can use the other's public key along with their pre existing knowledge to calculate the shared value
    ecdhkeyexchange_sequence.addDivider("Calculating Shared Secret")
    ecdhkeyexchange_sequence.addALabeledRetrieval(1,0,f"Receiver's compressed public key is {receiver_ecdhkeypair.getCompressedPublicKey()}","Retrieving Receiver's Compressed Public Key")
    ecdhkeyexchange_sequence.activateParticipant(0)
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"Shared secret is {originator_ecdhkeypair.shared_secret}","Calculating Shared Secret Using Originator's Private\\nKey And Receiver's Public Key")
    ecdhkeyexchange_sequence.deactivateParticipant(0)
    ecdhkeyexchange_sequence.addALabeledRetrieval(0,1,f"Originator's compressed public key is {originator_ecdhkeypair.getCompressedPublicKey()}","Retrieving Originator's Compressed Public Key")
    ecdhkeyexchange_sequence.activateParticipant(1)
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"Shared secret is {receiver_ecdhkeypair.shared_secret}","Calculating Shared Secret Using Receiver's Private\\nKey And Originator's Public Key")
    ecdhkeyexchange_sequence.deactivateParticipant(1)

def getAES256KeyFromSharedSecret(curve, shared_secret):
    '''
    This function gets a 64 byte hexadecimal key from the shared secret

    Uses the one step key derivation process outlined in section 4 of NIST SP 800 56
    In this case H(x) has been chosen as the SHA3-512 hashing function
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf
    '''
    L = 256
    sha3 = SHA3_512()
    H = sha3.hashStringToHex
    Z = sha3.h2b(curve.compressPointOnEllipticCurve(shared_secret)[2:])
    fixed_info = "This is fixed information to be used in the generation of a key"

    if L > 0:
        reps = ceil(L/sha3.digest_length)

    result = ""
    for i in range(0,reps):
        k = sha3.h2b(H(str(i)+Z+fixed_info))
        result = result+k
    derived_key_material = result[:L]
    return sha3.b2h(derived_key_material)

def sendMessageWithAES(originator_ecdhkeypair, receiver_ecdhkeypair):
    '''
    This function uses the shared secret in order to encrypt and decrypt a message using AES-256
    '''

    originator_aes_key = getAES256KeyFromSharedSecret(originator_ecdhkeypair.elliptic_curve_dh_key_exchange_data.curve, originator_ecdhkeypair.shared_secret)
    receiver_aes_key = getAES256KeyFromSharedSecret(receiver_ecdhkeypair.elliptic_curve_dh_key_exchange_data.curve, receiver_ecdhkeypair.shared_secret)
    originator_aes_256 = AES256(originator_aes_key)
    message = "The password for our email server is TheSUp3RS3CurePW!"
    encrypted_message = originator_aes_256.encryptStringMessage_ECB(message)
    receiver_aes_256 = AES256(receiver_aes_key)
    decrypted_message = receiver_aes_256.decryptHexList_ECB(encrypted_message)
    return originator_aes_key,receiver_aes_key,message,encrypted_message,decrypted_message

def sendReplyWithAES(originator_ecdhkeypair, receiver_ecdhkeypair):
    '''
    This function uses the shared secret in order to encrypt and decrypt a reply using AES-256
    '''

    originator_aes_key = getAES256KeyFromSharedSecret(originator_ecdhkeypair.elliptic_curve_dh_key_exchange_data.curve, originator_ecdhkeypair.shared_secret)
    receiver_aes_key = getAES256KeyFromSharedSecret(receiver_ecdhkeypair.elliptic_curve_dh_key_exchange_data.curve, receiver_ecdhkeypair.shared_secret)
    originator_aes_256 = AES256(originator_aes_key)
    receiver_aes_256 = AES256(receiver_aes_key)
    reply = "Ok! I will be updating the system in a week."
    encrypted_reply = receiver_aes_256.encryptStringMessage_ECB(reply)
    decrypted_reply = originator_aes_256.decryptHexList_ECB(encrypted_reply)
    return reply,encrypted_reply,decrypted_reply

def addSendingAESMessageToDiagram(elliptic_curve_dhkeyexchange_sequence, originator_aes_key, receiver_aes_key, message, encrypted_message, decrypted_message):
    '''
    This function adds sending a message to the sequence diagram
    '''

    elliptic_curve_dhkeyexchange_sequence.addDivider("Sending A Message With AES-256")
    elliptic_curve_dhkeyexchange_sequence.activateParticipant(0)
    elliptic_curve_dhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"Originator's AES key is {originator_aes_key}","Calculating AES-256 Key With Shared Secret")
    elliptic_curve_dhkeyexchange_sequence.activateParticipant(1)
    elliptic_curve_dhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"Receiver's AES key is  {receiver_aes_key}","Calculating AES-256 Key With Shared Secret")
    elliptic_curve_dhkeyexchange_sequence.deactivateParticipant(1)
    elliptic_curve_dhkeyexchange_sequence.encryptSendAndDecryptMessage(0,1,message,encrypted_message,decrypted_message,deactivate_end = False)

if __name__ == '__main__':
    elliptic_curve_dh_key_exchange, originator_ecdhkeypair, receiver_ecdhkeypair = runEllipticCurveDHKeyExchangeExampleScenario()
    elliptic_curve_dhkeyexchange_sequence = BasicSequenceDiagramSetup("AES-256 With ECDH Key Exchange Example")
    elliptic_curve_dhkeyexchange_sequence.addBannerNote("This sequence shows the use of Elliptic Curve Diffie Hellman Key Exchange with Curve P-512 to securely establish the use of AES-256 symmetric encryption")
    constructECDHKeyExchangeSequence(elliptic_curve_dh_key_exchange, originator_ecdhkeypair, receiver_ecdhkeypair, elliptic_curve_dhkeyexchange_sequence)
    originator_aes_key, receiver_aes_key, message, encrypted_message, decrypted_message = sendMessageWithAES(originator_ecdhkeypair, receiver_ecdhkeypair)
    addSendingAESMessageToDiagram(elliptic_curve_dhkeyexchange_sequence, originator_aes_key, receiver_aes_key, message, encrypted_message, decrypted_message)
    reply, encrypted_reply, decrypted_reply = sendReplyWithAES(originator_ecdhkeypair, receiver_ecdhkeypair)
    elliptic_curve_dhkeyexchange_sequence.addDivider("Sending A Reply With AES-256")
    elliptic_curve_dhkeyexchange_sequence.encryptSendAndDecryptMessage(1,0,reply,encrypted_reply,decrypted_reply, "Reply",activate_start=False)
    
    
    elliptic_curve_dhkeyexchange_sequence.printAllDiagrams()