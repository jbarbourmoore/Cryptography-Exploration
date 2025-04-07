from CryptographySchemes.DiffieHellmanKeyExchange import DiffieHellmanKeyExchange,DiffieHellmanKeyPair
from BasicSequenceDiagramSetup import BasicSequenceDiagramSetup

if __name__ == '__main__':
    diffie_hellman_key_exchange = DiffieHellmanKeyExchange(is_debug=True)

    first_diffie_hellman_key_pair = DiffieHellmanKeyPair(diffie_hellman_key_exchange, is_debug=True)
    second_diffie_hellman_key_pair = DiffieHellmanKeyPair(diffie_hellman_key_exchange, is_debug=True)
    first_diffie_hellman_key_pair.calculateSharedSecret()
    second_diffie_hellman_key_pair.calculateSharedSecret()

    assert first_diffie_hellman_key_pair.shared_secret == second_diffie_hellman_key_pair.shared_secret

    reply = "Hi! I am doing well, thanks."
    participants = ["Originator","Receiver"]
    messages = [("Divider","Agreeing On Shared Values"),
                ("Note","Generate a prime","across",None),("Message",0,1,f"New prime is {diffie_hellman_key_exchange.selected_prime}",2),
                ("Note","Select a generator value","across",None),("Message",0,1,f"New generator is {diffie_hellman_key_exchange.generator}",2),
                ("Divider","Generating Public and Private Keys"),
                ("Note","Generate private key for originator","left of",0),("Message",0,0,f"New private key is {first_diffie_hellman_key_pair.private_key}"),
                ("Note","Calculate public key for originator","left of",0),("Message",0,0,f"New public key is {first_diffie_hellman_key_pair.public_key}"),
                ("Note","Generate private key for receiver","right of",1),("Message",1,1,f"New private key is {second_diffie_hellman_key_pair.private_key}"),
                ("Note","Calculate public key for receiver","right of",1),("Message",1,1,f"New public key is {second_diffie_hellman_key_pair.public_key}"),
                ("Divider","Calculating Shared Secret"),
                ("Note","Calculating shared secret using originator's private\\n key and receiver's public key","left of",0),("Message",0,0,f"Shared secret is {first_diffie_hellman_key_pair.shared_secret}"),
                ("Note","Calculating shared secret using receiver's private\\n key and originator's public key","right of",1),("Message",1,1,f"Shared secret is {second_diffie_hellman_key_pair.shared_secret}"),
                ]
                # ("Note","Generate both public and private keys for originator","left of",0),("Message",0,0,f"New public keys are {originator_rsa.getPublicKey()}"),
                # ("Note","Generate both public and private keys for receiver","right of",1),("Message",1,1,f"New public keys are {recipient_rsa.getPublicKey()}"),
                # ("Divider","Sending Message"), ("Lifeline",0,"Activate"),
                # ("Note","Getting Recipient's Public Key","right of",0),("Message",1,0,f"Receiver's public keys are {recipient_rsa.getPublicKey()}"),
                # ("Note","Encrypting Message With Receiver's Public Keys","left of",0),("Message",0,0,message),
                # ("Note","Transmitting Message","right of",0),("Message",0,1,encrypted_message),
                # ("Lifeline",0,"Deactivate"), ("Lifeline",1,"Activate"),
                # ("Note","Decrypting Message With Receiver's Private Keys","right of",1),("Message",1,1,decrypted_message),
                # ("Divider","Replying"),
                # ("Note","Getting Originator's Public Key","left of",1),("Message",0,1,f"Originator's public keys are {originator_rsa.getPublicKey()}"),
                # ("Note","Encrypting Reply With Originator's Public Keys","right of",1),("Message",1,1,reply),
                # ("Note","Transmitting Message","left of",1),("Message",1,0,encrypted_reply),
                # ("Lifeline",1,"Deactivate"), ("Lifeline",0,"Activate"),
                # ("Note","Decrypting Message With Originator's Private Keys","left of",0),("Message",0,0,decrypted_reply),
                # ]
    
    dhkeyexchange_sequence = BasicSequenceDiagramSetup("Diffie Hellman Key Exchange Example",participants_list=participants,messages_list=messages)
    dhkeyexchange_sequence.printAllDiagrams()