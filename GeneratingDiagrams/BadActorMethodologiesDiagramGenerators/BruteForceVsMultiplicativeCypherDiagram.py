from CryptographySchemes.MultiplicativeCypher import MultiplicativeCypher
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup
from BadActorMethodologies.BruteForceVsMultiplicativeCypher import BruteForceVsMultiplicativeCypher, interpret_decryption_attempt

if __name__ == '__main__':
    multiplicative_cypher = MultiplicativeCypher(5)
    first_message = "this is a super secret multiplicative cypher that is being used to transit information"
    first_message_encrypted = multiplicative_cypher.encrypt(first_message)
    second_message = "as such, it is totally fine to share our password in this chat"
    second_message_encrypted = multiplicative_cypher.encrypt(second_message)
    third_message = "the password for admin on the web server is Sup3RSeCR3tPW!"
    third_message_encrypted = multiplicative_cypher.encrypt(third_message)
    minimum_meaningful_total_count = 10
    brute_force_attempt = BruteForceVsMultiplicativeCypher(minimum_meaningful_total_count=minimum_meaningful_total_count)

    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(first_message_encrypted)
    first_result = interpret_decryption_attempt(brute_force_attempt, decryption_attempt, first_message_encrypted, 2, minimum_meaningful_total_count)
    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(second_message_encrypted)
    second_result = interpret_decryption_attempt(brute_force_attempt, decryption_attempt, second_message_encrypted, 3, minimum_meaningful_total_count)
    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(third_message_encrypted)
    third_result = interpret_decryption_attempt(brute_force_attempt, decryption_attempt, third_message_encrypted, 4, minimum_meaningful_total_count)
    
    participants = ["Originator", "Bad Actor", "Receiver"]
    messages = [("Note","Both the originator and the receiver are aware that the multiplicative cypher multiplication value is 5 but the bad actor is not","across",None),
                ("Divider","Sending First Message"), ("Lifeline",0,"Activate"),
                ("Note","Encrypting Message","left of",0),("Message",0,0,first_message),
                ("Note","Transmitting Message","right of",0),("Message",0,2,first_message_encrypted),
                ("Lifeline",0,"Deactivate"), ("Lifeline",2,"Activate"),("Lifeline",1,"Activate"),
                ("Note","Decrypting Message","right of",2),("Note","Intercepted Message","right of",1,True),("Message",2,2,first_message),
                ("Lifeline",2,"Deactivate"),("Note","Attempting Decryption","right of",1),("Message",1,1,first_result),
                ("Lifeline",1,"Deactivate"),("Divider","Sending Second Message"), ("Lifeline",0,"Activate"),
                ("Note","Encrypting Message","left of",0),("Message",0,0,second_message),
                ("Note","Transmitting Message","right of",0),("Message",0,2,second_message_encrypted),
                ("Lifeline",0,"Deactivate"), ("Lifeline",2,"Activate"),("Lifeline",1,"Activate"),
                ("Note","Decrypting Message","right of",2),("Note","Intercepted Message","right of",1,True),("Message",2,2,second_message),
                ("Lifeline",2,"Deactivate"),("Note","Attempting Decryption","right of",1),("Message",1,1,second_result),
                ("Lifeline",1,"Deactivate"),("Divider","Sending Third Message"), ("Lifeline",0,"Activate"),
                ("Note","Encrypting Message","left of",0),("Message",0,0,third_message),
                ("Note","Transmitting Message","right of",0),("Message",0,2,third_message_encrypted),
                ("Lifeline",0,"Deactivate"), ("Lifeline",2,"Activate"),("Lifeline",1,"Activate"),
                ("Note","Decrypting Message","right of",2),("Note","Intercepted Message","right of",1,True),("Message",2,2,third_message),
                ("Lifeline",2,"Deactivate"),("Note","Attempting Decryption","right of",1),("Message",1,1,third_result),
                ("Lifeline",1,"Deactivate")
                ]
    
    caesar_sequence = BasicSequenceDiagramSetup("Brute Force Vs Multiplicative Cypher Example Diagram",participants_list=participants,messages_list=messages)
    caesar_sequence.printAllDiagrams()

    