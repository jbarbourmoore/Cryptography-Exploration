from CryptographySchemes.RSACryptographyScheme import RSACryptographyScheme
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup


def runBasicRSAScenario():
    '''
    This function runs a basic scenario using the RSA cryptography scheme
    '''
    smaller_initial_prime = 1096341613
    larger_initial_prime = 4587343829
    originator_rsa = RSACryptographyScheme(smaller_initial_prime, larger_initial_prime, block_size=5)

    smaller_second_prime = 2415707843
    larger_second_prime = 8300694107
    recipient_rsa = RSACryptographyScheme(smaller_second_prime, larger_second_prime)
    
    message = "What is the password for root on the web server?"
    encrypted_message = recipient_rsa.rsaEncoding(message=message)
    decrypted_message = recipient_rsa.rsaDecoding(encrypted_message)
    reply = "The password is T0pS3cr3TWebsErVeR!"
    encrypted_reply = originator_rsa.rsaEncoding(message=reply)
    decrypted_reply = originator_rsa.rsaDecoding(encrypted_reply)
    return originator_rsa,recipient_rsa,message,encrypted_message,decrypted_message,reply,encrypted_reply,decrypted_reply

def setupSequenceDiagram(originator_rsa:RSACryptographyScheme, recipient_rsa:RSACryptographyScheme, message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply, rsa_sequence:BasicSequenceDiagramSetup):
    '''
    This function sets up the sequence diagram for the basic scenario using RSA
    '''
    
    rsa_sequence.initializeParticipants()
    rsa_sequence.addDivider("Generating RSA Keys")
    rsa_sequence.activateParticipant(rsa_sequence.participants[0])
    rsa_sequence.sendSelfMessage_particpantNumber(0,f"New public keys are {originator_rsa.getPublicKey()}","Generating Both Public and Private Keys For Originator")
    rsa_sequence.deactivateParticipant(rsa_sequence.participants[0])
    rsa_sequence.activateParticipant(rsa_sequence.participants[1])
    rsa_sequence.sendSelfMessage_particpantNumber(1,f"New public keys are {recipient_rsa.getPublicKey()}","Generating Both Public and Private Keys For Receiver")
    rsa_sequence.deactivateParticipant(rsa_sequence.participants[1])
    rsa_sequence.addDivider("Sending A Message")
    rsa_sequence.addALabeledRetrieval(1,0,message=f"Receiver's public keys are {recipient_rsa.getPublicKey()}",note="Getting Receiver's Public Key")
    rsa_sequence.encryptSendAndDecryptMessage(0,1,message=message,encrypted_message=encrypted_message,decrypted_message=decrypted_message, deactivate_end=False)
    rsa_sequence.addDivider("Sending A Reply")
    rsa_sequence.addALabeledRetrieval(0,1,message=f"Originator's public keys are {originator_rsa.getPublicKey()}",note="Getting Originator's Public Key")
    rsa_sequence.encryptSendAndDecryptMessage(1,0,message=reply,encrypted_message=encrypted_reply,decrypted_message=decrypted_reply,message_label="Reply",activate_start=False)

if __name__ == '__main__':

    originator_rsa, recipient_rsa, message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply = runBasicRSAScenario()

    rsa_sequence = BasicSequenceDiagramSetup("RSA Cryptography Scheme Example")
    setupSequenceDiagram(originator_rsa, recipient_rsa, message, encrypted_message, decrypted_message, reply, encrypted_reply, decrypted_reply, rsa_sequence)
    
    rsa_sequence.printAllDiagrams()