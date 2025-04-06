from CryptographySchemes.MultiplicativeCypher import MultiplicativeCypher


class BruteForceVsMultiplicativeCypher():
    '''
    This class is used to simulate a bad actor attempting to brute force a multiplicative cypher
    '''

    def __init__(self, minimum_meaningful_total_count = 10, is_debug = False):
        '''
        This method initializes the bad actor's brute force attempt

        Parameters :
            minimum_meaningful_total_count : int, optional
                The minimum count of common words for a single multiplication value that the bad actor believes will be statistically significant to decide that it is the most likely multiplication value (default is 10)
            is_debug = Bool, optional
                Whether the brute force attempt is being debugged and should output more detailed information (default is False)
        '''

        self.encrypted_messages = []
        self.createSetCommonWords()
        self.decryption_attempts = {i : MultiplicativeCypherDecryptionAttemptData(i) for i in range(1,26)}
        self.maximum_common_word_count = 0
        self.minimum_meaningful_total_count = minimum_meaningful_total_count
        self.most_likely_multiplication_value = None
        self.is_debug = is_debug

    def attemptEncryptedMessage(self, encrypted_message):
        '''
        This method takes in a new encrypted message and attempts to decrypt it

        Parameters :
            encrypted_message : str
                the new encrypted message to attempt to decode

        Returns : 
            decrypted_message | (most_likely_multiplication_value, decrypted_messages_so_far) | None : str | (int,[str]) | None
                the decrypted message if the brute force attempt has already decided on the most likely multiplication value
                the most likely multiplication value and the decrypted messages so far if the algorithm decides on the most likely multiplication value when decrypting this message
                None if the algorithm still has not decided on the most likely multiplication value after this message has been run
        '''

        self.encrypted_messages.append(encrypted_message)

        # calls a method to brute force all potential multiplication values on the new message if the minimum total count of common words in a single multiplication decryption has yet to be reached
        # returns None if the minimum count has yet to be reached after this iteration
        # returns a tuple with the most probable multiplication value and the list of decrypted message so far if it does reach the minimum count
        if self.maximum_common_word_count < self.minimum_meaningful_total_count:
            return self.iterateAllPotentialMultiplicationValues(encrypted_message)
        
        # if the algorithm has settled on a specific multiplication value because the minimum total count of common words in a single multiplication decryption
        else : 
            # decrypts the new message and counts the common english words that appear and returns the decrypted messages
            potential_message = self.multiplicative_cypher.decrypt(encrypted_message)
            common_word_count = 0
            for common_word in self.common_words:
                if common_word in potential_message.lower():
                    common_word_count += 1
            self.decryption_attempts[self.most_likely_multiplication_value].addNewData(common_word_count=common_word_count,potential_message=potential_message)
            if self.is_debug:
                print(f"Using multiplication value {self.most_likely_multiplication_value}: {potential_message}")
            return potential_message

    def iterateAllPotentialMultiplicationValues(self,encrypted_message):
        '''
        This method takes in a new encrypted message and runs it against all of the possible multiplication values while counting any occurances of common english words for each multiplication value

        Parameters :
            encrypted_message : str
                the new encrypted message to attempt to decode

        Returns : 
            (most_likely_multiplication_value, decrypted_messages_so_far) | None : (int,[str]) | None
                the most likely multiplication value and the decrypted messages so far if the algorithm decides on the most likely multiplication value when decrypting this message
                None if the algorithm still has not decided on the most likely multiplication value after this message has been run
        '''
        for i in range(1,26):
            multiplicative_cypher = MultiplicativeCypher(i)
            potential_message = multiplicative_cypher.decrypt(encrypted_message)
            common_word_count = 0
            for common_word in self.common_words:
                if common_word in potential_message.lower():
                    common_word_count += 1
            self.decryption_attempts[i].addNewData(common_word_count=common_word_count,potential_message=potential_message)
            if self.maximum_common_word_count < self.decryption_attempts[i].common_word_count:
                self.maximum_common_word_count = self.decryption_attempts[i].common_word_count
                self.most_likely_multiplication_value = i

        if self.maximum_common_word_count >= self.minimum_meaningful_total_count:
            self.multiplicative_cypher = MultiplicativeCypher(self.most_likely_multiplication_value)
            if self.is_debug:
                print(f"The common word count for a multiplication value of {self.most_likely_multiplication_value} is {self.maximum_common_word_count} which is >= the minimum meaningful count for this brute force attempt {self.minimum_meaningful_total_count}")
                print("The most likely message translations so far are :")
                for message in self.decryption_attempts[self.most_likely_multiplication_value].potential_messages:
                    print(message)
            return self.most_likely_multiplication_value, self.decryption_attempts[self.most_likely_multiplication_value].potential_messages

        else:
            return None
    
    def outputPossibleMultiplicationValues(self, minimum_meaningful_count = 1):
        '''
        This method prints out the possible multiplication values that currently have a count of common words that meat the minimum value passed

        Parameters :
            minimum_meaningful_count : int
                The minimum common_word_count for each possible multiplication value to print out
        '''

        for i in range(1,26):
            if self.decryption_attempts[i].common_word_count >= minimum_meaningful_count:
                print(f"Multiplication value {i}: common word count is {self.decryption_attempts[i].common_word_count}")
                print(self.decryption_attempts[i].potential_messages)

    def createSetCommonWords(self):
        '''
        This method creates a list of common English words to compare to the multiplicative translations

        As it is a demo it is very short and people would likely use a more extensive list. They may also customise the list with names and such depending on their knowledge of the target
        '''

        self.common_words = set(["the","password","user","hello","what","why","be","to","of","in","that","have","not","with","he", "as","to","this"])

class MultiplicativeCypherDecryptionAttemptData():
    '''
    This class keeps track of all of the relevent data for each multiplication value such as the common_word_count and the potential_messages
    '''

    def __init__(self, multiplication_value, common_word_count = 0, potential_message = None):
        '''
        This method initializes the MultiplicativeCypherDecryptionAttemptData object for a specific multiplication value

        Parameters :
            multiplication_value : int
                The multiplication value for this data object
            common_word_count : int, optional
                The count of common words so far, default is 0
            potential_message : str | None, optional
                The first potential message, default is None
        '''

        self.multiplication_value = multiplication_value
        self.common_word_count = common_word_count
        if potential_message != None:
            self.potential_messages = [potential_message]
        else:
            self.potential_messages = []

    def addNewData(self, common_word_count, potential_message):
        '''
        This method adds new data to the data object for this multiplication value

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
        brute_force_attempt : BruteForceVsMultiplicativeCypher
            The current brute force object
        decryption_attempt : str | (int,[str]) | None
            The results of the decryption attempt
        encrypted_message : str
            The encrypted message
        minimum_meaningful_count : int, optional
            The minimum_meaningful count for outputting potential multiplication values (default is 2)
        total_meaningful_count : int, optional
            The minimum meaningful count for the algorithm to decide on a potential multiplication value
    '''
    
    print(f"The bad actor has intercepted a new encrypted message : {encrypted_message}")
    if type(decryption_attempt) == str:
        print("Decryption Results:")
        print(f"The most likely decrypted message is: {decryption_attempt}")
    else:
        print("Outputting More Likely Multiplication Values:")
        brute_force_attempt.outputPossibleMultiplicationValues(minimum_meaningful_count)
        print("- - - - - - - - - - - -")
        print("Decryption Results:")
        if type(decryption_attempt) == tuple:
            most_likely_multiplication_value, potential_messages = decryption_attempt
            print(f"The most likely multiplication value for the cipher has been determined to be {most_likely_multiplication_value}")
            print(f"Most likely messages so far: {potential_messages}")
        elif decryption_attempt == None:
            print(f"The most likely message has yet to be determined as the total common word count of none of the multiplication values has passed the threshold of {total_meaningful_count}")
    print("- - - - - - - - - - - -")

if __name__ == '__main__':
    multiplicative_cypher = MultiplicativeCypher(5)
    first_message = "this is a super secret multiplicatice cypher that is being used to transit information"
    first_message_encrypted = multiplicative_cypher.encrypt(first_message)
    second_message = "as such, it is totally fine to share our password in this chat"
    second_message_encrypted = multiplicative_cypher.encrypt(second_message)
    third_message = "the password for admin on the web server is Sup3RSeCR3tPW!"
    third_message_encrypted = multiplicative_cypher.encrypt(third_message)
    fourth_message = "please be careful to continue to keep this information secret"
    fourth_message_encrypted = multiplicative_cypher.encrypt(fourth_message)
    minimum_meaningful_total_count = 10
    brute_force_attempt = BruteForceVsMultiplicativeCypher(minimum_meaningful_total_count=minimum_meaningful_total_count)
    print("This is a simple demo scenario of a brute force attack on a multiplicative cypher. This scenario assumes that there is a bad actor who is intercepting messages that are encrypted using a multiplicative cypher with an unknown multiplication value.", end=" ")
    print("In this case the bad actors decisions are automated but in the real world a human may be involved.", end=" ")
    print("The bad actor iterates through each of the possible multiplication values and decrypts the messages.", end=" ")
    print("The bad actor compares the potential messages to a list of common English words.", end=" ")
    print("As there are some times a not decrypted message will appear to show a common english word, the bad actor has set a minimum count of common words they assume to be statistically significant.", end=" ")
    print("Once one of the cypher multiplication values has reached that number of common English words, the bad actor is pretty sure they have found the right cypher to continue decrypting messages they intercept.")
    print("- - - - - - - - - - - -")

    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(first_message_encrypted)
    interpret_decryption_attempt(brute_force_attempt, decryption_attempt, first_message_encrypted, 2, minimum_meaningful_total_count)
    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(second_message_encrypted)
    interpret_decryption_attempt(brute_force_attempt, decryption_attempt, second_message_encrypted, 3, minimum_meaningful_total_count)
    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(third_message_encrypted)
    interpret_decryption_attempt(brute_force_attempt, decryption_attempt, third_message_encrypted, 4, minimum_meaningful_total_count)
    decryption_attempt = brute_force_attempt.attemptEncryptedMessage(fourth_message_encrypted)
    interpret_decryption_attempt(brute_force_attempt, decryption_attempt, third_message_encrypted, 4, minimum_meaningful_total_count)
