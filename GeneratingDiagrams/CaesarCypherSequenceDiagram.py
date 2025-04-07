from CryptographySchemes.CaesarCypher import CaesarCipher
from BasicSequenceDiagramSetup import BasicSequenceDiagramSetup

if __name__ == '__main__':
    message = "This message is being encrypted using caesar's cypher with a shift of five"
    shift_value = 5
    caesar_cyper = CaesarCipher(shift_value=shift_value)
    encrypted_message = caesar_cyper.encrypt(message=message)
    decrypted_message = caesar_cyper.decrypt(encrypted_message=encrypted_message)
    print("Caesar Cypher is a very simple example of encryption")
    print("Each letter is simply replaced by those a certain number of space over in the alphabet")
    print("For example 'abc' with a shift of 3 would be 'def'")
    print("- - - - - - - - - - - -")
    print(f"Original message: {message}")
    print(f"Encrypted message: {encrypted_message}")
    print(f"Decrypted message: {decrypted_message}")

    participants = ["Originator","Receiver"]
    messages = [(0,0,message),(0,1,encrypted_message),(1,1,decrypted_message)]
    caesar_sequence = BasicSequenceDiagramSetup("Basic Caesar Cypher Example",participants_list=participants,messages_list=messages)
    caesar_sequence.printAllDiagrams()