
class CaesarCipher():
    '''
    This class creates the caesar cypher object for a specified shift value
    '''

    def __init__(self, shift_value):
        '''
        This method initializes a caesar cypher object with a specified shift value

        Parameters :
            shift_value : int
                The value of the shift for this caesar cypher
        '''

        self.shift_value = shift_value
        
    def encrypt(self, message, is_encrypting=True):
        '''
        This method encrypts the message according to the caesar cypher's shift value

        Parameters :
            message : str
                The string message that is being encrypted 
            is_encrypting : Boolean
                whether the message is being encrypted or decrypted
                If it is false, the letters are shifted negatively
        '''

        encrypted_message = ''
        for char in message:

            # shift any capital letter 
            if 'A' <= char <= 'Z':
                encrypted_message += chr((ord(char) - 65 + (self.shift_value if is_encrypting else -self.shift_value)) % 26 + 65)
            
            # shift any lowercase letter
            elif 'a' <= char <= 'z':
                encrypted_message += chr((ord(char) - 97 + (self.shift_value if is_encrypting else -self.shift_value)) % 26 + 97)
            
            # if the character is not a letter, leave it alone
            else:
                encrypted_message += char

        return encrypted_message
            
    def decrypt(self, encrypted_message):
        '''
        This method decrypts an encryppted message

        Parameters :
            encrypted_message :
                The message which has already been encrypted using the caesar cypher
        '''

        return self.encrypt(encrypted_message, is_encrypting=False)
    
class ROT13Cypher(CaesarCipher):
    def __init__(self):
        self.shift_value = 13

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
    assert message == decrypted_message
    second_message = "This is using a different caesar cypher with a shift of nine"
    second_shift_value = 9
    second_caesar_cyper = CaesarCipher(shift_value=second_shift_value)
    second_encrypted_message = second_caesar_cyper.encrypt(message=second_message)
    second_decrypted_message = second_caesar_cyper.decrypt(encrypted_message=second_encrypted_message)
    print("- - - - - - - - - - - -")
    print(f"Second message: {second_message}")
    print(f"Encrypted second message: {second_encrypted_message}")
    print(f"Decrypted second message: {second_decrypted_message}")
    assert second_message == second_decrypted_message
    print("- - - - - - - - - - - -")
    incorrectly_decrypted_message = second_caesar_cyper.decrypt(encrypted_message=encrypted_message)
    second_incorrectly_decrypted_message = caesar_cyper.decrypt(encrypted_message=second_encrypted_message)
    assert message != incorrectly_decrypted_message
    assert second_message != second_incorrectly_decrypted_message
    print(f"Original message decrypted with second caesar cypher: {incorrectly_decrypted_message}")
    print(f"Second message decrypted with original caesar cypher: {second_incorrectly_decrypted_message}")
    print("- - - - - - - - - - - -")
    print("Without the correct shift value decryption will still leave the message unreadable")
    print("However shift options are limited bt the size of the alphabet so it is very easy to brute force")
    print("- - - - - - - - - - - -")
    rot13_cypher = ROT13Cypher()
    rot13_message = "ROT13 is a special form of Caesar Cypher. It rotates 13 so halfway through the alphabet and can be decrypted by running the encryption again"
    rot13_encrypted_message = rot13_cypher.encrypt(message=rot13_message)
    rot13_decrypted_message = rot13_cypher.encrypt(message=rot13_encrypted_message)
    print(f"ROT13 message: {rot13_message}")
    print(f"Encrypted ROT13 message: {rot13_encrypted_message}")
    print(f"Double Encrypted / Decrypted ROT13 message: {rot13_decrypted_message}")
    assert rot13_message == rot13_decrypted_message
