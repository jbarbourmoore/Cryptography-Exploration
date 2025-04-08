class BasicSequenceDiagramSetup():
    '''
    This class allows the generation of sequence diagrams in mermaid, zenuml and plantuml
    '''

    def __init__(self, title, participants_list=None, messages_list=None):
        '''
        This method initializes the basic sequence diagram object

        Parameters :
            title : str
                The title for the diagram
            participants_list : [str], optional
                The participants in the sequence diagram
            messages_list : [(int,int,str)]
                The messages in the sequence diagram as a tuple with the start participant, end participant, and message string
        '''

        self.title = title
        self.participants = {}
        self.events = {}
        self.number_of_participants = 0
        self.number_of_events = 0

        if participants_list == None:
            if messages_list != None:
                print("You cannot add messages without participants")
        else:
            participants_length = len(participants_list)
            for i in range(0, participants_length):
                self.addParticipant(participant_name=participants_list[i], index=i)
            if messages_list != None:
                communications_length = len(messages_list)
                for i in range(0, communications_length):
                    self.addEventsFromTuple(event_tuple=messages_list[i], index=i)
            else:
                self.number_of_events = 0
                self.events = {}

    def addParticipant(self, participant_name, index = None):
        '''
        This method adds a participant to the sequence diagram

        Parameters :
            participant_name : str
                The name of the participant
            index : int, optional
                The index for the participant, default is None (self.number_of_participants)
        '''

        self.participants[self.number_of_participants if index == None else index] = BasicParticipant(participant_name, self.number_of_participants if index == None else index)
        self.number_of_participants += 1

    def addEventsFromTuple(self, event_tuple, index = None):
        '''
        This method adds a message to the sequence diagram from a tuple

        Parameters :
            communication_tuple : (str,int,int,str)
                he message as a tuple with the start participant, end participant, and message string
            index : int, optional
                The index for the participant, default is None (self.number_of_communications)
        '''

        if event_tuple[0] == "Message":
            if len(event_tuple) == 4:
                _,start_participant_number, end_participant_number, message = event_tuple
                self.events[self.number_of_events if index == None else index] = BasicCommunication(message=message, start_participant=self.participants[start_participant_number], end_participant=self.participants[end_participant_number])
            elif len(event_tuple) == 5:
                _,start_participant_number, end_participant_number, message, direction = event_tuple
                self.events[self.number_of_events if index == None else index] = BasicCommunication(message=message, start_participant=self.participants[start_participant_number], end_participant=self.participants[end_participant_number], direction=direction)
        elif event_tuple[0] == "Note":
            if len(event_tuple) == 4:
                _,note_content, position, participant_number = event_tuple
                self.events[self.number_of_events if index == None else index] = BasicNote(note_content=note_content,position=position,participant=(self.participants[participant_number] if participant_number!=None else None))
            elif len(event_tuple) == 5:
                _,note_content, position, participant_number,same_time = event_tuple
                self.events[self.number_of_events if index == None else index] = BasicNote(note_content=note_content,position=position,participant=(self.participants[participant_number] if participant_number!=None else None),same_time=same_time)
        elif event_tuple[0] == "Divider":
            _, divider_name = event_tuple
            self.events[self.number_of_events if index == None else index] = BasicDivider(divider_name=divider_name)
        elif event_tuple[0] == "Lifeline":
            _, participant_number, action = event_tuple
            self.events[self.number_of_events if index == None else index] = BasicLifeline(participant=self.participants[participant_number], action=action)
        
        self.number_of_events += 1

    def incrementEvents(self):
        '''
        This method increments the number of events in this sequence
        '''

        self.number_of_events += 1

    def incrementParticipants(self):
        '''
        This method increments the number of participants in the sequence
        '''

        self.number_of_participants += 1

    def addEvent(self, event):
        '''
        This method adds an event to the sequence
        
        Parameters :
            event : BasicEvent
                The event to be added to the sequence
        '''

        self.events[self.number_of_events] = event
        self.incrementEvents()

    def activateParticipant(self, participant_input):
        '''
        This method activates a participant's lifeline

        Parameters :
            participant_input : BasicParticipant | int
                The participant whose lifeline is being activated
        '''
        if type(participant_input) == int:
            participant = self.participants[participant_input]
        else:
            participant = participant_input
        
        self.addEvent(BasicLifeline(participant,"Activate"))

    def deactivateParticipant(self, participant_input):
        '''
        This method deactivates a participant's lifeline

        Parameters :
            participant_input : BasicParticipant | int
                The participant whose lifeline is being deactivated
        '''

        if type(participant_input) == int:
            participant = self.participants[participant_input]
        else:
            participant = participant_input
        
        self.addEvent(BasicLifeline(participant,"Deactivate"))

    def sendALabeledMessage(self,start_participant_input, end_participant_input, message, note, direction = 1):
        '''
        This method sends a labeled message with a note

        Parameters :
            start_participant : BasicParticipant
                The index of the person sending the message
            end_participant : BasicParticipant
                The index of the intended recipient for the message
            message : str
                The message content to be sent
            note : str
                The label for the message being sent
            direction : int, optional
                Whether the message is being sent in both directions or just 1, default is one
        '''
        if type(start_participant_input) == int:
            start_participant = self.participants[start_participant_input]
        else:
            start_participant = start_participant_input
        if type(end_participant_input) == int:
            end_participant = self.participants[end_participant_input]
        else:
            end_participant = end_participant_input 

        if start_participant.id < end_participant.id:
            note_position = "right of"
        else:
            note_position = "left of"
        self.addEvent(BasicNote(note_content=note, position=note_position,participant=start_participant))
        self.addEvent(BasicCommunication(message=message,start_participant=start_participant,end_participant=end_participant,direction=direction))

    def addALabeledRetrieval(self, start_participant_input, end_participant_input, message, note, direction = 1):
        '''
        This method shows a retrieval of some information initiated by the retrievor

        Parameters :
            start_participant : BasicParticipant
                The index of the person sending the message
            end_participant : BasicParticipant
                The index of the intended recipient for the message
            message : str
                The message content to be sent
            note : str
                The label for the message being sent
            direction : int, optional
                Whether the message is being sent in both directions or just 1, default is one
        '''

        if type(start_participant_input) == int:
            start_participant = self.participants[start_participant_input]
        else:
            start_participant = start_participant_input
        if type(end_participant_input) == int:
            end_participant = self.participants[end_participant_input]
        else:
            end_participant = end_participant_input 

        if start_participant.id > end_participant.id:
            note_position = "right of"
        else:
            note_position = "left of"
        
        self.addEvent(BasicNote(note_content=note, position=note_position, participant=end_participant))
        self.addEvent(BasicCommunication(message=message,start_participant=start_participant,end_participant=end_participant,direction=direction))

    def sendSelfMessage(self, participant, message, note, simultaneous_note = None, simultaneous_participant = None):
        '''
        This method adds sending a labeled message to the same participent

        Parameters:
            participant : BasicParticipant
                The person sending and receiving the message
            message : str
                The message content being sent to oneself
            note : str
                The label for the message being sent
            simultaneous_note : str
                A note for another participant to be displayed simultaneously, defaults to None
            simultaneous_participant : BasicParticipant
                The participant for the simultaneous note, defaults to None
        '''
        
        if participant.id == 0:
            note_position = "left of"
        else: note_position = "right of"
        self.addEvent(BasicNote(note_content=note, position=note_position,participant=participant))
        if simultaneous_note != None and simultaneous_participant != None:
            self.addEvent(BasicNote(note_content=note, position=note_position,participant=participant, same_time=True))
        self.addEvent(BasicCommunication(message=message,start_participant=participant,end_participant=participant,direction=1))

    def sendSelfMessage_particpantNumber(self, participant_number, message, note, simultaneous_note = None, simultaneous_participant = None):
        '''
        This method adds sending a labeled message to the same participent

        Parameters:
            participant_number : BasicParticipant
                The person sending and receiving the message
            message : str
                The message content being sent to oneself
            note : str
                The label for the message being sent
            simultaneous_note : str
                A note for another participant to be displayed simultaneously, defaults to None
            simultaneous_participant : BasicParticipant
                The participant for the simultaneous note, defaults to None
        '''

        participant = self.participants[participant_number]
        
        if participant_number == 0:
            note_position = "left of"
        else: note_position = "right of"
        self.addEvent(BasicNote(note_content=note, position=note_position,participant=participant))
        if simultaneous_note != None and simultaneous_participant != None:
            self.addEvent(BasicNote(note_content=note, position=note_position,participant=participant, same_time=True))
        self.addEvent(BasicCommunication(message=message,start_participant=participant,end_participant=participant,direction=1))


    def encryptSendAndDecryptMessage(self, start_participant_number, end_participant_number, message, encrypted_message, decrypted_message=None, message_label = "Message", deactivate_end = True, activate_start = True):
        '''
        This method setups up sending and receiving an encrypted message 

        Parameters :
            start_participant_number : int
                The index of the person sending the message
            end_participant_number : int
                The index of the intended recipient for the message
            message : str
                The message content to be sent
            encrypted_message : any
                The encrypted form of the message being sent
            decrypted_message : str, optional
                The message content decrypted by the intended recipient, defaults to message
            message_label : str, optional
                The label for the message, defaults to "Message"
            activate_start : Boolean, optional
                whether to activate the starting participant before begining, default is True
            deactivate_end : Boolean, optional
                whether to deactivate the ending participant at completion, default is True
        '''
        
        start_participant = self.participants[start_participant_number]
        end_participant = self.participants[end_participant_number]
        if activate_start: self.activateParticipant(participant_input=start_participant)
        self.sendSelfMessage(participant=start_participant,message=message,note=f"Encrypting {message_label}")
        self.sendALabeledMessage(start_participant_input=start_participant,end_participant_input=end_participant,message=encrypted_message, note=f"Sending Encrypted {message_label}")
        self.deactivateParticipant(participant_input=start_participant)
        self.activateParticipant(participant_input=end_participant)
        self.sendSelfMessage(participant=end_participant,message=(decrypted_message if decrypted_message != None else message),note="Decrypting Message")
        if deactivate_end: self.deactivateParticipant(participant_input=end_participant)

    def encryptSendAndDecryptMessageIntercepted(self, start_participant_number, end_participant_number, message, encrypted_message, intercepting_participent_number, intercepted_message=None, intercepted_note="Attempting to Decrypt Message", decrypted_message=None, message_label = "Message", deactivate_end = True, activate_start = True):
        '''
        This method setups up sending an encrypted message which is intercepted

        Parameters :
            start_participant_number : int
                The index of the person sending the message
            end_participant_number : int
                The index of the intended recipient for the message
            message : str
                The message content to be sent
            encrypted_message : any
                The encrypted form of the message being sent
            intercepting_participant_number : int
                The index of the person intercepting the message
            intercepted_message : str, optional
                The message content decrypted by the person who intercepted it, defaults to message
            intercepted_note : str, optional
                The note to display when processing intercepted message, defaults to "Attempting to Decrypt Message"
            decrypted_message : str, optional
                The message content decrypted by the intended recipient, defaults to message
            message_label : str, optional
                The label for the message, defaults to "Message"
            activate_start : Boolean, optional
                whether to activate the starting participant before begining, default is True
            deactivate_end : Boolean, optional
                whether to deactivate the ending participant at completion, default is True
        '''
        
        start_participant = self.participants[start_participant_number]
        end_participant = self.participants[end_participant_number]
        intercepting_participant = self.participants[intercepting_participent_number]
        if activate_start: self.activateParticipant(participant_input=start_participant)
        self.sendSelfMessage(participant=start_participant,message=message,note=f"Encrypting {message_label}")
        self.sendALabeledMessage(start_participant_input=start_participant,end_participant_input=end_participant,message=encrypted_message, note=f"Sending Encrypted {message_label}")
        self.deactivateParticipant(participant_input=start_participant)
        self.activateParticipant(participant_input=end_participant)
        self.activateParticipant(participant_input=intercepting_participant)
        self.sendSelfMessage(participant=end_participant,message=(decrypted_message if decrypted_message != None else message),note=f"Decrypting {message_label}",simultaneous_note=f"Intercepted {message_label}",simultaneous_participant=intercepting_participant)
        self.deactivateParticipant(participant_input=end_participant)
        self.sendSelfMessage(participant=intercepting_participant,message=(intercepted_message if intercepted_message != None else message),note=intercepted_note)
        if deactivate_end: self.deactivateParticipant(participant_input=intercepting_participant)

    def initializeParticipants(self,number_of_participants=2,list_of_names=None):
        '''
        This method initializes participants for the sequence

        if no list of name is provided 
            and you want one participant
                They default to "Participant"
            and you want two participants
                They default to 0. "Originator" 1. "Receiver"
            and you want three participants
                They default to 0. "Originator" 1. "Bad Actor" 3."Receiver"
            and you want more participants, number n
                They default to 0. "Participant_0" 1. "Participant_1" ... n. "Participant_n"

        Parameters:
            number_of_participants : int, optional
                The number of participants to be added if a list of names is not provided, default is 2
            list_of_names : [str], optional
                The list of names for the participants to be added, default is None
        '''

        if list_of_names == None:
            if number_of_participants == 2:
                self.addParticipant("Originator")
                self.addParticipant("Receiver")
            elif number_of_participants == 3:
                self.addParticipant("Originator")
                self.addParticipant("Bad Actor")
                self.addParticipant("Receiver")
            elif number_of_participants == 1:
                self.addParticipant("Participant")
            else:
                for i in number_of_participants:
                    self.addParticipant(f"Participant_{i}")
        else:
            for name in list_of_names:
                self.addParticipant(name)

    def addMutualAgreement(self, note_content, message_content):
        '''
        This method setups up a mutual agreement between all parties

        Parameters :
            note_content : str
                The content for the banner note
            message_content : str
                The content for the message agreement
        '''

        self.addBannerNote(note_content=note_content)
        self.addCommunication(message=message_content,start_participant_number=0,end_participant_number=self.number_of_participants-1,direction=2)
   
    def addBannerNote(self, note_content):
        '''
        This method adds a simple note over the entire sequence

        Parameters :
            note_content : str
                The content of the note to be displayed on the diagram
        '''

        self.addEvent(BasicNote(note_content,position="across",participant=None,same_time=False))

    def addDivider(self, divider_name):
        '''
        This method adds a simple divider over the sequence

        Parameters :
            divider_name : str
                The name of the divider to be displayed on the diagram
        '''

        self.addEvent(BasicDivider(divider_name))

    def addCommunication(self, message, start_participant_number, end_participant_number, direction = 1):
        '''
        This method adds a message to the sequence diagram

        Parameters :
            start_participant_number : int
                The participant index with which the message originates
            end_participant_number : int
                The participant index with the message destination
            message : str
                The content of the message
        '''

        self.events[self.number_of_events] = BasicCommunication(message=message, start_participant=self.participants[start_participant_number], end_participant=self.participants[end_participant_number],direction=direction)
        self.number_of_events += 1

    def printMermaidSequenceDiagram(self):
        '''
        This method prints the sequence diagram to the command line in the form of a mermaid diagram
        '''
        print("---")
        print("config:")
        print("  theme: forest")
        print("---")
        print("sequenceDiagram")
        print("\tautonumber")
        print(f"\tTitle {self.title}")
        for i in range(0, self.number_of_participants):
            if self.participants[i].name == "Bad Actor":
                print("\tbox pink")
                print(f"\tParticipant {self.participants[i].name}")
                print("\tend")
            else:
                print(f"\tParticipant {self.participants[i].name}")
        for i in range(0,self.number_of_events):
            if self.events[i].type == "Message":
                if self.events[i].direction == 2:
                    print(f"\t{self.events[i].start_participant.name} <<->> {self.events[i].end_participant.name}: {self.events[i].message}")
                else:
                    print(f"\t{self.events[i].start_participant.name} ->> {self.events[i].end_participant.name}: {self.events[i].message}")
            elif self.events[i].type =="Lifeline":
                print(f"\t{self.events[i].action} {self.events[i].participant.name}")
            elif self.events[i].type =="Divider":
                command = f"over {self.participants[0].name},{self.participants[self.number_of_participants-1].name}"
                print("\trect rgb(191, 223, 255)")
                print(f"\tNote {command} : {self.events[i].divider_name}")
                print("\tend")
            elif self.events[i].type == "Note":
                content  = self.events[i].note_content.replace('\\n','<br/>')
                if self.events[i].participant != None:
                    print(f"\tNote {self.events[i].position} {self.events[i].participant.name if self.events[i].participant != None else ""}: {content}")
                else:
                    command = f"over {self.participants[0].name},{self.participants[self.number_of_participants-1].name}"
                    print(f"\tNote {command} : {content}")


    def printZenUMLDiagram(self):
        '''
        This method prints the sequence diagram to the command line in the form of a ZenUMl diagram
        '''

        print(f"title {self.title}")
        for i in range(0, self.number_of_participants):
            print(f"@Actor \"{self.participants[i].name}\"")
        for i in range(0,self.number_of_events):
            if self.events[i].type == "Message":
                print(f"\"{self.events[i].start_participant.name}\"->\"{self.events[i].end_participant.name}\": {self.events[i].message}")

    def printPlantUMLDiagram(self):
        '''
        This method prints the sequence diagram to the command line in the form of a PlantUML diagram
        '''
        bad_actor_color = "#DarkRed"
        bad_actor_note_color = "#LightCoral"
        banner_color = "#Lavender"
        print("@startuml")
        print("!theme reddress-lightblue")
        print("hide footbox")
        print(f"title \"{self.title}\"")
        print("autonumber")
        print("skinparam maxMessageSize 300")
        print("skinparam NoteBackgroundColor LightSteelBlue")
        print("skinparam NoteBorderColor Black")
        print("skinparam ParticipantBackgroundColor Navy")
        print("skinparam ParticipantFontColor White")
        print("skinparam ParticipantFontSize 16")
        print("skinparam TitleFontSize 18")
        print("skinparam SequenceLifeLineBorderColor Black")
        print("skinparam SequenceLifeLineBackgroundColor LightSteelBlue")
        print("skinparam SequenceDividerBorderThickness 2")
        print("skinparam SequenceDividerBorderColor Indigo")
        print("skinparam SequenceDividerBackgroundColor Lavender")
        print("skinparam SequenceDividerFontSize 14")
        print("skinparam SequenceDividerFontStyle Italic")
        for i in range(0, self.number_of_participants):
            print(f"Participant \"{self.participants[i].name}\" {bad_actor_color if self.participants[i].name == "Bad Actor" else ""}")
        for i in range(0,self.number_of_events):
            if self.events[i].type == "Message":
                if self.events[i].start_participant.id == 0 and self.events[i].end_participant.id == 0:
                    print(f"\"{self.events[i].start_participant.name}\"<-\"{self.events[i].end_participant.name}\": {self.events[i].message}")
                else:
                    if self.events[i].direction == 2:
                        print(f"\"{self.events[i].start_participant.name}\"<->\"{self.events[i].end_participant.name}\": {self.events[i].message}")
                    else:
                        print(f"\"{self.events[i].start_participant.name}\"->\"{self.events[i].end_participant.name}\": {self.events[i].message}")
            elif self.events[i].type == "Note":
                if self.events[i].same_time == False:
                    print(f"hnote {self.events[i].position} {f"\"{self.events[i].participant.name}\"" if self.events[i].participant != None else ""} {banner_color if self.events[i].position == "across" else ""}{bad_actor_note_color if self.events[i].participant != None and self.events[i].participant.name == "Bad Actor" else ""}: {self.events[i].note_content}")
                else:
                    print(f"/ hnote {self.events[i].position} {f"\"{self.events[i].participant.name}\"" if self.events[i].participant != None else ""} {bad_actor_note_color if self.events[i].participant != None and self.events[i].participant.name == "Bad Actor" else ""}: {self.events[i].note_content}")
            elif self.events[i].type =="Divider":
                print(f"=={self.events[i].divider_name}==")
            elif self.events[i].type =="Lifeline":
                print(f"{self.events[i].action} \"{self.events[i].participant.name}\" {bad_actor_note_color if self.events[i].action == "Activate" and self.events[i].participant.name == "Bad Actor" else ""}")
        print("@enduml")

    def printAllDiagrams(self):
        '''
        This method prints all of the uml diagram types for this sequence diagram
        '''

        print("- - - - - - - - - - - -")
        self.printMermaidSequenceDiagram()
        print("- - - - - - - - - - - -")
        self.printZenUMLDiagram()
        print("- - - - - - - - - - - -")
        self.printPlantUMLDiagram()
        print("- - - - - - - - - - - -")

class BasicEvent():
    '''
    This class is a basic event for a sequence diagram. It is inheritted by all other event types.
    '''

    def __init__(self, type = "Event"):
        '''
        This method initializes the basic event

        Parameters:
            type : str, optional
                The type of the event
        '''

        self.type = type

class BasicNote(BasicEvent):
    '''
    This class holds the information for a basic note for the sequence
    '''

    def __init__(self, note_content, position, participant = None, same_time = False):
        '''
        This method initializes the basic note event with a type of "Note"

        Parameters:
            note_content : str
                The content of the note
            position : str
                The position of the note
            participant : BasicParticipant
                The participant the note is connected to
        '''

        self.type = "Note"
        self.note_content = note_content
        self.position = position
        self.participant = participant
        self.same_time = same_time

class BasicDivider(BasicEvent):
    '''
    This class holds the information for a basic divider for the sequence
    '''

    def __init__(self, divider_name):
        '''
        This method initializes the basic divider event with a type of "Divider"

        Parameters:
            divider_name : str
                The name of the divider
        '''

        self.type = "Divider"
        self.divider_name = divider_name

class BasicLifeline(BasicEvent):
    '''
    This class holds the information for a basic lifeline state for the sequence
    '''

    def __init__(self, participant, action):
        '''
        This method initializes the basic lifeline event with a type of "Lifeline"

        Parameters:
            participant : BasicParticipant
                The participant who's lifeline is being affected
            action : str
                The action which is being performed on the lifeline
        '''

        self.type = "Lifeline"
        self.participant = participant
        self.action = action
        
class BasicCommunication(BasicEvent):
    '''
    This class holds the information for a basic message in a sequence diagram
    '''

    def __init__(self, message, start_participant, end_participant, direction=1):
        '''
        This method initializes the communication with a message, start_participant and end_participant

        Parameters :
            message : str
                The message content for the communication
            start_participant : BasicParticipant
                The message originator
            end_participant
                The message destination
            direction : int, optional
                Whether the message is going in one direction or two(default is 1)
        '''

        self.type = "Message"
        self.message = message
        self.start_participant = start_participant
        self.end_participant = end_participant
        self.direction = direction

class BasicParticipant():
    '''
    This class holds the information for a basic participant in a sequence diagram
    '''

    def __init__(self, name, id = 0):
        '''
        This method initializes the participant with a given name

        Parameters :
            name : str
                The name of the participant
        '''
        self.name = name
        self.id = id

if __name__ == '__main__':
    sequence_diagram = BasicSequenceDiagramSetup("Basic Sequence")
    sequence_diagram.initializeParticipants(number_of_participants=3)
    sequence_diagram.addBannerNote("This is a simple example of a layout that can be generated more easily")
    sequence_diagram.addDivider("Sending a Message")
    sequence_diagram.encryptSendAndDecryptMessageIntercepted(0,2,"message content","encrypted message content",1)
    sequence_diagram.addDivider("Sending a Reply")
    sequence_diagram.encryptSendAndDecryptMessageIntercepted(2,0,"reply content","encrypted reply content",1,intercepted_note="Attempting to Decrypt Reply",message_label="Reply")
    sequence_diagram.printAllDiagrams()