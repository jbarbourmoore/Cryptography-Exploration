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

    participants = ["Originator","Bad Actor","Receiver"]
    messages = [("Note","Due to constraints in the quantum simulator I am using, I cannot factor numbers larger \\nthan 7 qubits so the RSA keys in this example are using very small prime numbers","across",None),
                ("Divider","Generating RSA Keys"),
                ("Note","Generate both public and private keys for originator","left of",0),("Message",0,0,f"New public keys are {originator_rsa.getPublicKey()}"),
                ("Note","Generate both public and private keys for receiver","right of",2),("Message",2,2,f"New public keys are {recipient_rsa.getPublicKey()}"),
                ("Divider","Attacking the RSA Keys"),
                ("Note","Getting receiver's Public Key","right of",1), ("Lifeline",1,"Activate"),("Message",2,1,f"Receiver's public keys are {recipient_rsa.getPublicKey()}"),
                ("Note","Use Shor's Algorithm To Find Prime\\nFactors of receiver's Public Key's n component\\nand calculate the private key","right of",1),("Message",1,1,f"The prime factors are {prime_factors} and private key is {bad_actor.duplicate_target_crypto_scheme.getPrivateKey()}"),
                ("Note","Getting originator's Public Key","left of",1),("Message",0,1,f"Originator's public keys are {originator_rsa.getPublicKey()}"),
                ("Note","Use Shor's Algorithm To Find Prime\\nFactors of originator's Public Key's n component\\nand calculate the private key","right of",1),("Message",1,1,f"The prime factors are {bad_actor_originator.target_prime_factors} and private key is {bad_actor_originator.duplicate_target_crypto_scheme.getPrivateKey()}"),
                ("Lifeline",1,"Deactivate"),("Divider","Sending Message"), ("Lifeline",0,"Activate"),
                ("Note","Getting Recipient's Public Key","right of",0),("Message",2,0,f"Receiver's public keys are {recipient_rsa.getPublicKey()}"),
                ("Note","Encrypting Message With Receiver's Public Keys","left of",0),("Message",0,0,message),
                ("Note","Transmitting Message","right of",0),("Message",0,2,encrypted_message),
                ("Lifeline",0,"Deactivate"), ("Lifeline",2,"Activate"),("Lifeline",1,"Activate"),
                ("Note","Decrypting Message With Receiver's Private Keys","right of",2),("Note","Intercepted Message","right of",1,True),("Message",2,2,decrypted_message),
                ("Lifeline",2,"Deactivate"),("Note","Decrypting Message With calculated version \\nof receiver's Private Keys","right of",1),("Message",1,1,decoded_message_stolen_key),
                ("Lifeline",2,"Activate"),("Lifeline",1,"Deactivate"),("Divider","Replying"),
                ("Note","Getting Originator's Public Key","left of",2),("Message",0,2,f"Originator's public keys are {originator_rsa.getPublicKey()}"),
                ("Note","Encrypting Reply With Originator's Public Keys","right of",2),("Message",2,2,reply),
                ("Note","Transmitting Message","left of",2),("Message",2,0,encrypted_reply),
                ("Lifeline",2,"Deactivate"), ("Lifeline",0,"Activate"),("Lifeline",1,"Activate"),
                ("Note","Decrypting Message With Originator's Private Keys","left of",0),("Note","Intercepted Message","right of",1,True),("Message",0,0,decrypted_reply),
                ("Lifeline",0,"Deactivate"),("Note","Decrypting Message With calculated version \\nof originator's Private Keys","right of",1),("Message",1,1,decoded_reply_stolen_key),("Lifeline",1,"Deactivate"),
                ]
    
    rsa_sequence = BasicSequenceDiagramSetup("Shor's Algorithm Vs. RSA Example",participants_list=participants,messages_list=messages)
    rsa_sequence.printAllDiagrams()
if __name__ == '__main__':

    runBadActorAgainstRSAScheme()