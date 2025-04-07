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
            _,note_content, position, participant_number = event_tuple
            self.events[self.number_of_events if index == None else index] = BasicNote(note_content=note_content,position=position,participant=(self.participants[participant_number] if participant_number!=None else None))
        elif event_tuple[0] == "Divider":
            _, divider_name = event_tuple
            self.events[self.number_of_events if index == None else index] = BasicDivider(divider_name=divider_name)
        elif event_tuple[0] == "Lifeline":
            _, participant_number, action = event_tuple
            self.events[self.number_of_events if index == None else index] = BasicLifeline(participant=self.participants[participant_number], action=action)
        
        self.number_of_events += 1

    def addCommunication(self, message, start_participant_number, end_participant_number):
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

        self.events[self.number_of_events] = BasicCommunication(message=message, start_participant=self.participants[start_participant_number], end_participant=self.participants[end_participant_number])
        self.number_of_events += 1

    def printMermaidSequenceDiagram(self):
        '''
        This method prints the sequence diagram to the command line in the form of a mermaid diagram
        '''

        print("sequenceDiagram")
        print("\tautonumber")
        print(f"\tTitle {self.title}")
        for i in range(0, self.number_of_participants):
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
                command = "over "
                for j in range(0, self.number_of_participants):
                        command += self.participants[j].name
                        if j < self.number_of_participants -1:
                            command += ","
                print(f"\tNote {command} : {self.events[i].divider_name}")
            elif self.events[i].type == "Note":
                content  = self.events[i].note_content.replace('\\n','<br/>')
                if self.events[i].participant != None:
                    print(f"\tNote {self.events[i].position} {self.events[i].participant.name if self.events[i].participant != None else ""}: {content}")
                else:
                    command = "over "
                    for j in range(0, self.number_of_participants):
                        command += self.participants[j].name
                        if j < self.number_of_participants -1:
                            command += ","
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

        print("@startuml")
        print("!theme reddress-lightblue")
        print("hide footbox")
        print(f"title \"{self.title}\"")
        print("autonumber")
        print("skinparam maxMessageSize 300")
        print("skinparam NoteBackgroundColor LightSteelBlue")
        print("skinparam NoteBorderColor Navy")
        print("skinparam ParticipantBackgroundColor Navy")
        print("skinparam ParticipantFontColor White")
        print("skinparam ParticipantFontSize 13")
        print("skinparam TitleFontColor Navy")
        print("skinparam SequenceLifeLineBorderColor Navy")
        print("skinparam SequenceLifeLineBackgroundColor LightSteelBlue")
        print("skinparam SequenceDividerBorderThickness 1")
        print("skinparam SequenceDividerBorderColor Navy")
        print("skinparam SequenceDividerBackgroundColor LightSteelBlue")
        print("skinparam SequenceDividerFontSize 12")
        print("skinparam SequenceDividerFontStyle Italic")
        for i in range(0, self.number_of_participants):
            print(f"Participant \"{self.participants[i].name}\"")
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
                print(f"hnote {self.events[i].position} {self.events[i].participant.name if self.events[i].participant != None else ""}: {self.events[i].note_content}")
            elif self.events[i].type =="Divider":
                print(f"=={self.events[i].divider_name}==")
            elif self.events[i].type =="Lifeline":
                print(f"{self.events[i].action} {self.events[i].participant.name}")
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

    def __init__(self, note_content, position, participant = None):
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
    participant_list = ["Originator","Bad Actor","Recipient"]
    communication_list = [("Message",0,2,"Hello"),("Message",2,0,"Hi"),("Message",1,1,"Thinking"),("Note","A long\\nnote","across",None)]
    sequence_diagram = BasicSequenceDiagramSetup("Basic Sequence",participants_list=participant_list,messages_list=communication_list)
    sequence_diagram.printAllDiagrams()