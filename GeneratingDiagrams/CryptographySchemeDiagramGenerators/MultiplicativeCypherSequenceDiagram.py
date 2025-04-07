from CryptographySchemes.MultiplicativeCypher import MultiplicativeCypher
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup

if __name__ == '__main__':
    message = "Hello. How are you?"
    multiplication_value = 4
    multiplicative_cyper = MultiplicativeCypher(multiplication_value=multiplication_value)
    encrypted_message = multiplicative_cyper.encrypt(message=message)
    decrypted_message = multiplicative_cyper.decrypt(encrypted_message=encrypted_message)
    reply = "Hi! I am doing well, thanks."
    encrypted_reply = multiplicative_cyper.encrypt(message=reply)
    decrypted_reply = multiplicative_cyper.decrypt(encrypted_message=encrypted_reply)

    participants = ["Originator","Receiver"]
    messages = [("Note","Both participants are aware of the multiplication value, 4","across",None),
                ("Divider","Sending Message"), ("Lifeline",0,"Activate"),
                ("Note","Encrypting Message","left of",0),("Message",0,0,message),
                ("Note","Transmitting Message","right of",0),("Message",0,1,encrypted_message),
                ("Lifeline",0,"Deactivate"), ("Lifeline",1,"Activate"),
                ("Note","Decrypting Message","right of",1),("Message",1,1,decrypted_message),
                ("Divider","Replying"),
                ("Note","Encrypting Reply","right of",1),("Message",1,1,reply),
                ("Note","Transmitting Reply","left of",1),("Message",1,0,encrypted_reply),
                ("Lifeline",1,"Deactivate"), ("Lifeline",0,"Activate"),
                ("Note","Decrypting Reply","left of",0),("Message",0,0,decrypted_reply)]
    caesar_sequence = BasicSequenceDiagramSetup("Basic Multiplicative Cypher Example",participants_list=participants,messages_list=messages)
    caesar_sequence.printAllDiagrams()