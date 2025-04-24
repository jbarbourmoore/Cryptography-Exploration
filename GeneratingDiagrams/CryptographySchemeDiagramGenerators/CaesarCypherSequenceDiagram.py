from CryptographySchemes.HistoricalCyphers.CaesarCypher import CaesarCipher
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup

def runBasicCaesarCypherScenario():
    '''
    This function runs a basic caesar cypher scenario example
    '''

    message = "Did you change the password for admin?"
    shift_value = 5
    caesar_cyper = CaesarCipher(shift_value=shift_value)
    encrypted_message = caesar_cyper.encrypt(message=message)
    decrypted_message = caesar_cyper.decrypt(encrypted_message=encrypted_message)
    reply = "Yes it is now AsupErSEcRetPassWoRD"
    encrypted_reply = caesar_cyper.encrypt(message=reply)
    decrypted_reply = caesar_cyper.decrypt(encrypted_message=encrypted_reply)
    return message,encrypted_message,decrypted_message,reply,encrypted_reply,decrypted_reply

def constructCaesarSypherSequence(message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply, caesar_sequence:BasicSequenceDiagramSetup):
    '''
    This function constructs the sequence for the basic caesar cypher scenario
    '''
    
    caesar_sequence.initializeParticipants(2)
    caesar_sequence.addBannerNote("Both participants are aware of the caesar shift value which is 5")
    caesar_sequence.addDivider("Sending A Message")
    caesar_sequence.encryptSendAndDecryptMessage(0,1,message=message,encrypted_message=encrypted_message,decrypted_message=decrypted_message,deactivate_end=False)
    caesar_sequence.addDivider("Sending A Reply")
    caesar_sequence.encryptSendAndDecryptMessage(1,0,message=reply,encrypted_message=encrypted_reply,decrypted_message=decrypted_reply,message_label="Reply",activate_start=False)

if __name__ == '__main__':
    message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply = runBasicCaesarCypherScenario()
    caesar_sequence = BasicSequenceDiagramSetup("Basic Caesar Cypher Example")
    constructCaesarSypherSequence(message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply, caesar_sequence)
    caesar_sequence.printAllDiagrams()