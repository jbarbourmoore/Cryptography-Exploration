

class DataEncryptionStandard():
    '''
	This class holds the necessary methods for a basic implementation of DES
	'''
	
    def __init__(self, key):
        '''
        This method initializes a DataEncryptionStandard with a given key

        Parameters :
            key : str
                the key for this DES
        '''

        self.key = key

    def stringToBinaryList(self, string_message:str):
        '''
        This method converts a string message into a list of binary strings with a 64 bit length

        Parameters :
            string_message : str
                The message to be encrypted as a string

        Returns : 
            binary_list : [str]
                The message as a list of 64 bit binary strings
        '''

        length = len(string_message)
        list_of_blocks = []
        for x in range(0,length,8):
            list_of_blocks.append(string_message[x:x+8])
        for j in range(0,len(list_of_blocks)):
            list_of_blocks[j]=self.stringToBinary(list_of_blocks[j])
        return list_of_blocks

    def stringToBinary(self, string):
        '''
        This method converts a string message a 64 bit binary string

        Parameters :
            string : str
                The message to be encrypted as a string

        Returns : 
            binary : str
                The message as a 64 bit binary string
        '''

        string = ''.join(format(ord(i), '08b') for i in string)
        if(len(string) < 64):
            string += '0'*(64-len(string))
        return string

    def binaryToString(self,binary_str):
        '''
        This method converts a binary string back to a readable string

        Parameters :
            binary_str : str
                The binary string

        Returns :
            message_string : str
                The binary string converted into a readable string
        '''

        message_string = ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])
        return message_string
    
    def binaryListToString(self, binary_list):
        '''
        This method converts a binary string list back to a readable string

        Parameters :
            binary_list : str
                The binary string

        Returns :
            string : str
                The binary string list converted into a readable string
        '''

        string=""
        for i in range(0,len(binary_list)):
            string+=self.binaryToString(binary_list[i])
        return string

key = "key"
des = DataEncryptionStandard(key)
message ="I want to encrypt this message hopefully!"
binary_message_list = des.stringToBinaryList(message)
print(des.binaryListToString(binary_message_list))