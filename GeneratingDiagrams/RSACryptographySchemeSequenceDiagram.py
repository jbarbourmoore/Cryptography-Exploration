from CryptographySchemes.RSACryptographyScheme import RSACryptographyScheme
from BasicSequenceDiagramSetup import BasicSequenceDiagramSetup

if __name__ == '__main__':

    smaller_initial_prime = 1096341613
    larger_initial_prime = 4587343829
    originator_rsa = RSACryptographyScheme(smaller_initial_prime, larger_initial_prime, block_size=5)

    smaller_second_prime = 2415707843
    larger_second_prime = 8300694107
    recipient_rsa = RSACryptographyScheme(smaller_second_prime, larger_second_prime)
    
    message = "Hello. How are you?"
    encrypted_message = recipient_rsa.rsaEncoding(message=message)
    decrypted_message = recipient_rsa.rsaDecoding(encrypted_message)
    reply = "Hi! I am doing well, thanks."
    encrypted_reply = originator_rsa.rsaEncoding(message=reply)
    decrypted_reply = originator_rsa.rsaDecoding(encrypted_reply)

    reply = "Hi! I am doing well, thanks."
    participants = ["Originator","Receiver"]
    messages = [("Divider","Generating RSA Keys"),
                ("Note","Generate both public and private keys for originator","left of",0),("Message",0,0,f"New public keys are {originator_rsa.getPublicKey()}"),
                ("Note","Generate both public and private keys for receiver","right of",1),("Message",1,1,f"New public keys are {recipient_rsa.getPublicKey()}"),
                ("Divider","Sending Message"), ("Lifeline",0,"Activate"),
                ("Note","Getting Recipient's Public Key","right of",0),("Message",1,0,f"Receiver's public keys are {recipient_rsa.getPublicKey()}"),
                ("Note","Encrypting Message With Receiver's Public Keys","left of",0),("Message",0,0,message),
                ("Note","Transmitting Message","right of",0),("Message",0,1,encrypted_message),
                ("Lifeline",0,"Deactivate"), ("Lifeline",1,"Activate"),
                ("Note","Decrypting Message With Receiver's Private Keys","right of",1),("Message",1,1,decrypted_message),
                ("Divider","Replying"),
                ("Note","Getting Originator's Public Key","left of",1),("Message",0,1,f"Originator's public keys are {originator_rsa.getPublicKey()}"),
                ("Note","Encrypting Reply With Originator's Public Keys","right of",1),("Message",1,1,reply),
                ("Note","Transmitting Message","left of",1),("Message",1,0,encrypted_reply),
                ("Lifeline",1,"Deactivate"), ("Lifeline",0,"Activate"),
                ("Note","Decrypting Message With Originator's Private Keys","left of",0),("Message",0,0,decrypted_reply),
                ]
    
    rsa_sequence = BasicSequenceDiagramSetup("RSA Cryptography Scheme Example",participants_list=participants,messages_list=messages)
    rsa_sequence.printAllDiagrams()