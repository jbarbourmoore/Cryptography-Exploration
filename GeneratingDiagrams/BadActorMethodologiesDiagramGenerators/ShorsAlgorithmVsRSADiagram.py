from CryptographySchemes.RSACryptographyScheme import RSACryptographyScheme
from BadActorMethodologies.ShorsAlgorithmVsRSA import badActor_RSA
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup


def runBadActorAgainstRSASchemeAndGenerateDiagrams():
    '''
    This function runs a very simple example of utilizing the Shor's Algorithm for prime factorisation to duplicate RSA private keys based on the public key
    
    Note: The example is constrained by the number of qubit available for input in the quantum simulator
    (in this case 7, so the largest number it can factor is 127)
    '''

    originator_rsa, recipient_rsa, message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply, bad_actor, prime_factors, decoded_message_stolen_key, bad_actor_originator, decoded_reply_stolen_key = runScenario()
    
    rsa_sequence = BasicSequenceDiagramSetup("Shor's Algorithm Vs. RSA Example")
    constructSequence(originator_rsa, recipient_rsa, message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply, bad_actor, prime_factors, decoded_message_stolen_key, bad_actor_originator, decoded_reply_stolen_key, rsa_sequence)
    
    rsa_sequence.printAllDiagrams()

def constructSequence(originator_rsa:RSACryptographyScheme, recipient_rsa:RSACryptographyScheme, message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply, bad_actor, prime_factors, decoded_message_stolen_key, bad_actor_originator, decoded_reply_stolen_key, rsa_sequence:BasicSequenceDiagramSetup):
    '''
    This function constructs the sequence for the Shor's algorithm vs. RSA scenario
    '''
    
    rsa_sequence.initializeParticipants(3)
    rsa_sequence.addBannerNote("Due to constraints in the quantum simulator I am using, I cannot factor numbers larger \\nthan 7 qubits so the RSA keys in this example are using very small prime numbers")
    rsa_sequence.addDivider("Generating RSA Keys")
    rsa_sequence.activateParticipant(0)
    rsa_sequence.sendSelfMessage_particpantNumber(0,f"New public keys are {originator_rsa.getPublicKey()}","Generating Both Public and Private Keys For Originator")
    rsa_sequence.deactivateParticipant(0)
    rsa_sequence.activateParticipant(2)
    rsa_sequence.sendSelfMessage_particpantNumber(2,f"New public keys are {recipient_rsa.getPublicKey()}","Generating Both Public and Private Keys For Receiver")
    rsa_sequence.deactivateParticipant(2)
    rsa_sequence.addDivider("Attacking RSA Keys")
    rsa_sequence.activateParticipant(rsa_sequence.participants[1])
    rsa_sequence.addALabeledRetrieval(rsa_sequence.participants[0],rsa_sequence.participants[1],message=f"Receiver's public keys are {recipient_rsa.getPublicKey()}",note="Getting Receiver's Public Key")
    rsa_sequence.sendSelfMessage_particpantNumber(1,f"The prime factors are {prime_factors} and private key is {bad_actor.duplicate_target_crypto_scheme.getPrivateKey()}","Use Shor's Algorithm To Find Prime\\nFactors of receiver's Public Key's n component\\nand calculate the private key")
    rsa_sequence.addALabeledRetrieval(rsa_sequence.participants[2],rsa_sequence.participants[1],message=f"Originator's public keys are {originator_rsa.getPublicKey()}",note="Getting Originator's Public Key")
    rsa_sequence.sendSelfMessage_particpantNumber(1,f"The prime factors are {prime_factors} and private key is {bad_actor_originator.duplicate_target_crypto_scheme.getPrivateKey()}","Use Shor's Algorithm To Find Prime\\nFactors of receiver's Public Key's n component\\nand calculate the private key")
    rsa_sequence.deactivateParticipant(rsa_sequence.participants[1])
    rsa_sequence.addDivider("Sending A Message")
    rsa_sequence.addALabeledRetrieval(2,0,message=f"Receiver's public keys are {recipient_rsa.getPublicKey()}",note="Getting Receiver's Public Key")
    rsa_sequence.encryptSendAndDecryptMessageIntercepted(0,2,message=message,encrypted_message=encrypted_message,intercepting_participent_number=1,intercepted_message=decoded_message_stolen_key,decrypted_message=decrypted_message)
    rsa_sequence.addDivider("Sending A Reply")
    rsa_sequence.addALabeledRetrieval(0,2,message=f"Originator's public keys are {originator_rsa.getPublicKey()}",note="Getting Originator's Public Key")
    rsa_sequence.encryptSendAndDecryptMessageIntercepted(2,0,message=reply,encrypted_message=encrypted_reply,intercepting_participent_number=1,intercepted_message=decoded_reply_stolen_key,decrypted_message=decrypted_reply,message_label="Reply",intercepted_note="Attempting to Decrypt Reply")

def runScenario():
    '''
    This function runs a very simple example of utilizing the Shor's Algorithm for prime factorisation to duplicate RSA private keys based on the public key
    
    Note: The example is constrained by the number of qubit available for input in the quantum simulator
    (in this case 7, so the largest number it can factor is 127)
    '''

    smaller_initial_prime = 7
    larger_initial_prime = 17
    originator_rsa = RSACryptographyScheme(smaller_initial_prime, larger_initial_prime, block_size=1)

    smaller_second_prime = 7
    larger_second_prime = 13
    recipient_rsa = RSACryptographyScheme(smaller_second_prime, larger_second_prime, block_size=1)

    message = "What is the password for root on the web server?"
    encrypted_message = recipient_rsa.rsaEncoding(message=message)
    decrypted_message = recipient_rsa.rsaDecoding(encrypted_message)
    reply = "The password is T0pS3cr3TWebsErVeR!"
    encrypted_reply = originator_rsa.rsaEncoding(message=reply)
    decrypted_reply = originator_rsa.rsaDecoding(encrypted_reply)
    bad_actor = badActor_RSA(recipient_rsa.getPublicKey())
    prime_factors = bad_actor.target_prime_factors
    decoded_message_stolen_key = bad_actor.decryptMessageForTarget(encrypted_message)
    bad_actor_originator = badActor_RSA(originator_rsa.getPublicKey())
    decoded_reply_stolen_key = bad_actor_originator.decryptMessageForTarget(encrypted_reply)
    return originator_rsa,recipient_rsa,message,encrypted_message,decrypted_message,reply,encrypted_reply,decrypted_reply,bad_actor,prime_factors,decoded_message_stolen_key,bad_actor_originator,decoded_reply_stolen_key

if __name__ == '__main__':

    runBadActorAgainstRSASchemeAndGenerateDiagrams()