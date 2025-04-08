from CryptographySchemes.RSACryptographyScheme import RSACryptographyScheme
from BadActorMethodologies.ShorsAlgorithmVsRSA import badActor_RSA
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup


def runBadActorAgainstRSAScheme():
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
    
    rsa_sequence = BasicSequenceDiagramSetup("Shor's Algorithm Vs. RSA Example")
    rsa_sequence.initializeParticipants(3)
    rsa_sequence.addBannerNote("Due to constraints in the quantum simulator I am using, I cannot factor numbers larger \\nthan 7 qubits so the RSA keys in this example are using very small prime numbers")
    rsa_sequence.addDivider("Generating RSA Keys")
    rsa_sequence.sendSelfMessage_particpantNumber(0,f"New public keys are {originator_rsa.getPublicKey()}","Generate both public and private keys for originator")
    rsa_sequence.sendSelfMessage_particpantNumber(2,f"New public keys are {recipient_rsa.getPublicKey()}","Generate both public and private keys for receiver")
    rsa_sequence.addDivider("Attacking RSA Keys")
    rsa_sequence.activateParticipant(rsa_sequence.participants[1])
    rsa_sequence.sendALabeledMessage(rsa_sequence.participants[0],rsa_sequence.participants[1],message=f"Receiver's public keys are {recipient_rsa.getPublicKey()}",note="Getting receiver's Public Key")
    rsa_sequence.sendSelfMessage_particpantNumber(1,f"The prime factors are {prime_factors} and private key is {bad_actor.duplicate_target_crypto_scheme.getPrivateKey()}","Use Shor's Algorithm To Find Prime\\nFactors of receiver's Public Key's n component\\nand calculate the private key")
    rsa_sequence.sendALabeledMessage(rsa_sequence.participants[2],rsa_sequence.participants[1],message=f"Originator's public keys are {originator_rsa.getPublicKey()}",note="Getting receiver's Public Key")
    rsa_sequence.sendSelfMessage_particpantNumber(1,f"The prime factors are {prime_factors} and private key is {bad_actor_originator.duplicate_target_crypto_scheme.getPrivateKey()}","Use Shor's Algorithm To Find Prime\\nFactors of receiver's Public Key's n component\\nand calculate the private key")
    rsa_sequence.deactivateParticipant(rsa_sequence.participants[1])
    rsa_sequence.addDivider("Sending A Message")
    rsa_sequence.encryptSendAndDecryptMessageIntercepted(0,2,message=message,encrypted_message=encrypted_message,intercepting_participent_number=1,intercepted_message=decoded_message_stolen_key,decrypted_message=decrypted_message)
    rsa_sequence.addDivider("Sending A Reply")
    rsa_sequence.encryptSendAndDecryptMessageIntercepted(2,0,message=reply,encrypted_message=encrypted_reply,intercepting_participent_number=1,intercepted_message=decoded_reply_stolen_key,decrypted_message=decrypted_reply,message_label="Reply",intercepted_note="Attempting to Decrypt Reply")
    
    rsa_sequence.printAllDiagrams()

if __name__ == '__main__':

    runBadActorAgainstRSAScheme()