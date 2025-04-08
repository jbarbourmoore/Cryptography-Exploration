from BadActorMethodologies.BruteForceVsCaesarCypher import BruteForceVsCaesarCypher, interpret_decryption_attempt
from CryptographySchemes.CaesarCypher import CaesarCipher
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup


def setupBruteForceVsCaesarCypherSequence(first_message, first_message_encrypted, first_message_decrypted, second_message, second_message_encrypted, second_message_decrypted, third_message, third_message_encrypted, third_message_decrypted, first_result, second_result, third_result, caesar_sequence:BasicSequenceDiagramSetup):
    '''
    This function sets up the sequence diagram for the brute force vs caesar cypher example scenario
    '''
    
    caesar_sequence.initializeParticipants(3)
    caesar_sequence.addBannerNote("Both the originator and the receiver are aware that the caesar cypher shift value is 5 but the bad actor is not")
    caesar_sequence.addDivider("Sending First Message")
    caesar_sequence.encryptSendAndDecryptMessageIntercepted(0,2,message=first_message,encrypted_message=first_message_encrypted,decrypted_message=first_message_decrypted,intercepting_participent_number=1,intercepted_message=first_result)
    caesar_sequence.addDivider("Sending Second Message")
    caesar_sequence.encryptSendAndDecryptMessageIntercepted(0,2,message=second_message,encrypted_message=second_message_encrypted,decrypted_message=second_message_decrypted,intercepting_participent_number=1,intercepted_message=second_result)
    caesar_sequence.addDivider("Sending Third Message")
    caesar_sequence.encryptSendAndDecryptMessageIntercepted(0,2,message=third_message,encrypted_message=third_message_encrypted,decrypted_message=third_message_decrypted,intercepting_participent_number=1,intercepted_message=third_result)

def runExampleBruteForceVsCaesarCypherScenario():
    '''
    This function runs a basic example scenario for brute force vs caesar cypher
    '''

    caesar_cipher = CaesarCipher(5)
    first_message = "this is a super secret caesar cypher that is being used to transit information"
    first_message_encrypted = caesar_cipher.encrypt(first_message)
    first_message_decrypted = caesar_cipher.decrypt(first_message_encrypted)
    second_message = "as such, it is totally fine to share our password in this chat"
    second_message_encrypted = caesar_cipher.encrypt(second_message)
    second_message_decrypted = caesar_cipher.decrypt(second_message_encrypted)
    third_message = "the password for admin on the web server is Sup3RSeCR3tPW!"
    third_message_encrypted = caesar_cipher.encrypt(third_message)
    third_message_decrypted = caesar_cipher.decrypt(third_message_encrypted)
    minimum_meaningful_total_count = 10
    brute_force_attempt = BruteForceVsCaesarCypher(minimum_meaningful_total_count=minimum_meaningful_total_count)

    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(first_message_encrypted)
    first_result = interpret_decryption_attempt(brute_force_attempt, decryption_attempt, first_message_encrypted, 2, minimum_meaningful_total_count)
    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(second_message_encrypted)
    second_result = interpret_decryption_attempt(brute_force_attempt, decryption_attempt, second_message_encrypted, 3, minimum_meaningful_total_count)
    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(third_message_encrypted)
    third_result = interpret_decryption_attempt(brute_force_attempt, decryption_attempt, third_message_encrypted, 4, minimum_meaningful_total_count)
    return first_message,first_message_encrypted,first_message_decrypted,second_message,second_message_encrypted,second_message_decrypted,third_message,third_message_encrypted,third_message_decrypted,first_result,second_result,third_result

if __name__ == '__main__':
    first_message, first_message_encrypted, first_message_decrypted, second_message, second_message_encrypted, second_message_decrypted, third_message, third_message_encrypted, third_message_decrypted, first_result, second_result, third_result = runExampleBruteForceVsCaesarCypherScenario()
    caesar_sequence = BasicSequenceDiagramSetup("Brute Force Vs Caesar Cypher Example Diagram")
    setupBruteForceVsCaesarCypherSequence(first_message, first_message_encrypted, first_message_decrypted, second_message, second_message_encrypted, second_message_decrypted, third_message, third_message_encrypted, third_message_decrypted, first_result, second_result, third_result, caesar_sequence)
    caesar_sequence.printAllDiagrams()

    