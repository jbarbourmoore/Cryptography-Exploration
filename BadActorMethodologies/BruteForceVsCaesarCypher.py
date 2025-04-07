from CryptographySchemes.CaesarCypher import CaesarCipher

class BruteForceVsCaesarCypher():
    '''
    This class is used to simulate a bad actor attempting to brute force a caesar cypher
    '''

    def __init__(self, minimum_meaningful_total_count = 10, is_debug = False):
        '''
        This method initializes the bad actor's brute force attempt

        Parameters :
            minimum_meaningful_total_count : int, optional
                The minimum count of common words for a single shift value that the bad actor believes will be statistically significant to decide that it is the most likely shift value (default is 10)
            is_debug = Bool, optional
                Whether the brute force attempt is being debugged and should output more detailed information (default is False)
        '''

        self.encrypted_messages = []
        self.createSetCommonWords()
        self.decryption_attempts = {i : CaesarCypherDecryptionAttemptData(i) for i in range(0,26)}
        self.maximum_common_word_count = 0
        self.minimum_meaningful_total_count = minimum_meaningful_total_count
        self.most_likely_shift = None
        self.is_debug = is_debug

    def attemptEncryptedMessage(self, encrypted_message):
        '''
        This method takes in a new encrypted message and attempts to decrypt it

        Parameters :
            encrypted_message : str
                the new encrypted message to attempt to decode

        Returns : 
            decrypted_message | (most_likely_shift, decrypted_messages_so_far) | None : str | (int,[str]) | None
                the decrypted message if the brute force attempt has already decided on the most likely shift value
                the most likely shift value and the decrypted messages so far if the algorithm decides on the most likely shift value when decrypting this message
                None if the algorithm still has not decided on the most likely shift value after this message has been run
        '''

        self.encrypted_messages.append(encrypted_message)

        # calls a method to brute force all potential shift values on the new message if the minimum total count of common words in a single shift decryption has yet to be reached
        # returns None if the minimum count has yet to be reached after this iteration
        # returns a tuple with the most probable shift value and the list of decrypted message so far if it does reach the minimum count
        if self.maximum_common_word_count < self.minimum_meaningful_total_count:
            return self.iterateShiftValues(encrypted_message)
        
        # if the algorithm has settled on a specific shift value because the minimum total count of common words in a single shift decryption
        else : 
            # decrypts the new message and counts the common english words that appear and returns the decrypted messages
            potential_message = self.caesar_cipher.decrypt(encrypted_message)
            common_word_count = 0
            for common_word in self.common_words:
                if common_word in potential_message.lower():
                    common_word_count += 1
            self.decryption_attempts[self.most_likely_shift].addNewData(common_word_count=common_word_count,potential_message=potential_message)
            if self.is_debug:
                print(f"Using shift value {self.most_likely_shift}: {potential_message}")
            return potential_message

    def iterateShiftValues(self,encrypted_message):
        '''
        This method takes in a new encrypted message and runs it against all of the possible shift values while counting any occurances of common english words for each shift value

        Parameters :
            encrypted_message : str
                the new encrypted message to attempt to decode

        Returns : 
            (most_likely_shift, decrypted_messages_so_far) | None : (int,[str]) | None
                the most likely shift value and the decrypted messages so far if the algorithm decides on the most likely shift value when decrypting this message
                None if the algorithm still has not decided on the most likely shift value after this message has been run
        '''
        for i in range(0,26):
            caesar_cypher = CaesarCipher(i)
            potential_message = caesar_cypher.decrypt(encrypted_message)
            common_word_count = 0
            for common_word in self.common_words:
                if common_word in potential_message.lower():
                    common_word_count += 1
            self.decryption_attempts[i].addNewData(common_word_count=common_word_count,potential_message=potential_message)
            if self.maximum_common_word_count < self.decryption_attempts[i].common_word_count:
                self.maximum_common_word_count = self.decryption_attempts[i].common_word_count
                self.most_likely_shift = i

        if self.maximum_common_word_count >= self.minimum_meaningful_total_count:
            self.caesar_cipher = CaesarCipher(self.most_likely_shift)
            if self.is_debug:
                print(f"The common word count for a shift of {self.most_likely_shift} is {self.maximum_common_word_count} which is >= the minimum meaningful count for this brute force attempt {self.minimum_meaningful_total_count}")
                print("The most likely message translations so far are :")
                for message in self.decryption_attempts[self.most_likely_shift].potential_messages:
                    print(message)
            return self.most_likely_shift, self.decryption_attempts[self.most_likely_shift].potential_messages

        else:
            return None
    
    def outputPossibleShiftValues(self, minimum_meaningful_count = 1):
        '''
        This method prints out the possible shift values that currently have a count of common words that meat the minimum value passed

        Parameters :
            minimum_meaningful_count : int
                The minimum common_word_count for each possible shift value to print out
        '''

        for i in range(0,26):
            if self.decryption_attempts[i].common_word_count >= minimum_meaningful_count:
                print(f"Shift value {i}: common word count is {self.decryption_attempts[i].common_word_count}")
                print(self.decryption_attempts[i].potential_messages)

    def createSetCommonWords(self):
        '''
        This method creates a list of common English words to compare to the cypher translations

        As it is a demo it is very short and people would likely use a more extensive list. They may also customise the list with names and such depending on their knowledge of the target
        '''

        self.common_words = set(["the","password","user","hello","what","why","be","to","of","in","that","have","not","with","he", "as","to","this"])

class CaesarCypherDecryptionAttemptData():
    '''
    This class keeps track of all of the relevent data for each shift value such as the common_word_count and the potential_messages
    '''

    def __init__(self, shift, common_word_count = 0, potential_message = None):
        '''
        This method initializes the CaesarCypherDecryptionAttemptData object for a specific shift value

        Parameters :
            shift : int
                The shift value for this data object
            common_word_count : int, optional
                The count of common words so far, default is 0
            potential_message : str | None, optional
                The first potential message, default is None
        '''

        self.shift = shift
        self.common_word_count = common_word_count
        if potential_message != None:
            self.potential_messages = [potential_message]
        else:
            self.potential_messages = []

    def addNewData(self, common_word_count, potential_message):
        '''
        This method adds new data to the data object for this shift value

        Parameters :
            common_word_count : int
                The count of common words so far
            potential_message : str
                The potential message
        '''

        self.potential_messages.append(potential_message)
        self.common_word_count += common_word_count


def interpret_decryption_attempt(brute_force_attempt, decryption_attempt, encrypted_message, minimum_meaningful_count = 2, total_meaningful_count = 10):
    '''
    This method interprets the result of the decryption attempt and outputs the results to the console

    Parameters :
        brute_force_attempt : BruteForceVsCaesarCypher
            The current brute force object
        decryption_attempt : str | (int,[str]) | None
            The results of the decryption attempt
        encrypted_message : str
            The encrypted message
        minimum_meaningful_count : int, optional
            The minimum_meaningful count for outputting potential shift values (default is 2)
        total_meaningful_count : int, optional
            The minimum meaningful count for the algorithm to decide on a potential shift value
    '''
    
    result = ""
    print(f"The bad actor has intercepted a new encrypted message : {encrypted_message}")
    if type(decryption_attempt) == str:
        print("Decryption Results:")
        print(f"The most likely decrypted message is: {decryption_attempt}")
        result = f"The most likely decrypted message is: {decryption_attempt}"
    else:
        print("Outputting More Likely Shift Values:")
        brute_force_attempt.outputPossibleShiftValues(minimum_meaningful_count)
        print("- - - - - - - - - - - -")
        print("Decryption Results:")
        if type(decryption_attempt) == tuple:
            most_likely_shift, potential_messages = decryption_attempt
            print(f"The most likely shift value for the cipher has been determined to be {most_likely_shift}")
            print(f"Most likely messages so far: {potential_messages}")
            result = f"The most likely shift value is {most_likely_shift} and decrypted messages so far are: {potential_messages}"
        elif decryption_attempt == None:
            result = f"The most likely message has yet to be determined as the total common word count of none of the shift values has passed the threshold of {total_meaningful_count}"
            print(f"The most likely message has yet to be determined as the total common word count of none of the shift values has passed the threshold of {total_meaningful_count}")
    print("- - - - - - - - - - - -")
    return result

if __name__ == '__main__':
    caesar_cipher = CaesarCipher(5)
    first_message = "this is a super secret caesar cypher that is being used to transit information"
    first_message_encrypted = caesar_cipher.encrypt(first_message)
    second_message = "as such, it is totally fine to share our password in this chat"
    second_message_encrypted = caesar_cipher.encrypt(second_message)
    third_message = "the password for admin on the web server is Sup3RSeCR3tPW!"
    third_message_encrypted = caesar_cipher.encrypt(third_message)
    fourth_message = "please be careful to continue to keep this information secret"
    fourth_message_encrypted = caesar_cipher.encrypt(fourth_message)
    minimum_meaningful_total_count = 10
    brute_force_attempt = BruteForceVsCaesarCypher(minimum_meaningful_total_count=minimum_meaningful_total_count)
    print("This is a simple demo scenario of a brute force attack on a caesar cypher. This scenario assumes that there is a bad actor who is intercepting messages that are encrypted using a caesar cypher with an unknown shift value.", end=" ")
    print("In this case the bad actors decisions are automated but in the real world a human may be involved.", end=" ")
    print("The bad actor iterates through each of the possible shift values and decrypts the messages.", end=" ")
    print("The bad actor compares the potential messages to a list of common English words.", end=" ")
    print("As there are some times a not decrypted message will appear to show a common english word, the bad actor has set a minimum count of common words they assume to be statistically significant.", end=" ")
    print("Once one of the cypher shift values has reached that number of common English words, the bad actor is pretty sure they have found the right cypher to continue decrypting messages they intercept.")
    print("- - - - - - - - - - - -")

    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(first_message_encrypted)
    interpret_decryption_attempt(brute_force_attempt, decryption_attempt, first_message_encrypted, 2, minimum_meaningful_total_count)
    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(second_message_encrypted)
    interpret_decryption_attempt(brute_force_attempt, decryption_attempt, second_message_encrypted, 3, minimum_meaningful_total_count)
    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(third_message_encrypted)
    interpret_decryption_attempt(brute_force_attempt, decryption_attempt, third_message_encrypted, 4, minimum_meaningful_total_count)
    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(fourth_message_encrypted)
    interpret_decryption_attempt(brute_force_attempt, decryption_attempt, third_message_encrypted, 4, minimum_meaningful_total_count)
