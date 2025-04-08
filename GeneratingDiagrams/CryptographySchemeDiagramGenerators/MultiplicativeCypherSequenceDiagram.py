from CryptographySchemes.MultiplicativeCypher import MultiplicativeCypher
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup

def runBasicMultiplicativeCypherScenario():
    '''
    This function runs a basic multiplicative cypher scenario
    '''

    message = "The mission is scheduled for tomorrow morning"
    multiplication_value = 5
    multiplicative_cyper = MultiplicativeCypher(multiplication_value=multiplication_value)
    encrypted_message = multiplicative_cyper.encrypt(message=message)
    decrypted_message = multiplicative_cyper.decrypt(encrypted_message=encrypted_message)
    reply = "Ok we will meet you at the airfield"
    encrypted_reply = multiplicative_cyper.encrypt(message=reply)
    decrypted_reply = multiplicative_cyper.decrypt(encrypted_message=encrypted_reply)
    return message,encrypted_message,decrypted_message,reply,encrypted_reply,decrypted_reply

def setupMultiplicativeCypherSequence(message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply, multiplicative_sequence:BasicSequenceDiagramSetup):
    '''
    This function constructs the sequence for the basic multiplicative cypher scenario
    '''
    
    multiplicative_sequence.initializeParticipants(2)
    multiplicative_sequence.addBannerNote("Both participants are aware of the multiplication value which is 5")
    multiplicative_sequence.addDivider("Sending A Message")
    multiplicative_sequence.encryptSendAndDecryptMessage(0,1,message=message,encrypted_message=encrypted_message,decrypted_message=decrypted_message,deactivate_end=False)
    multiplicative_sequence.addDivider("Sending A Reply")
    multiplicative_sequence.encryptSendAndDecryptMessage(1,0,message=reply,encrypted_message=encrypted_reply,decrypted_message=decrypted_reply,message_label="Reply",activate_start=False)

if __name__ == '__main__':
    message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply = runBasicMultiplicativeCypherScenario()
    multiplicative_sequence = BasicSequenceDiagramSetup("Basic Multiplicative Cypher Example")
    setupMultiplicativeCypherSequence(message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply, multiplicative_sequence)
    multiplicative_sequence.printAllDiagrams()