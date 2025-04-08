from CryptographySchemes.DiffieHellmanKeyExchange import DiffieHellmanKeyExchange,DiffieHellmanKeyPair
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup

def runDiffieHellmanKeyExchangeExampleScenario():
    '''
    This function runs a simple example scenario for the Diffie Hellman Key Exchange
    '''
    diffie_hellman_key_exchange = DiffieHellmanKeyExchange(is_debug=True)

    originator_dhkeypair = DiffieHellmanKeyPair(diffie_hellman_key_exchange, is_debug=True)
    receiver_dhkeypair = DiffieHellmanKeyPair(diffie_hellman_key_exchange, is_debug=True)
    originator_dhkeypair.calculateSharedSecret()
    receiver_dhkeypair.calculateSharedSecret()

    assert originator_dhkeypair.shared_secret == receiver_dhkeypair.shared_secret
    return diffie_hellman_key_exchange,originator_dhkeypair,receiver_dhkeypair

def constructDHKeyExchangeSequence(diffie_hellman_key_exchange:DiffieHellmanKeyExchange, originator_dhkeypair:DiffieHellmanKeyPair, receiver_dhkeypair:DiffieHellmanKeyPair, dhkeyexchange_sequence:BasicSequenceDiagramSetup):
    '''
    This function constructs the sequence for the simple diffie hellman key exchange scenario
    '''
    
    dhkeyexchange_sequence.initializeParticipants(2)

    # First both participants agree on a shard prime and matching generator value
    dhkeyexchange_sequence.addDivider("Agreeing On Shared Values")
    dhkeyexchange_sequence.activateParticipant(0)
    dhkeyexchange_sequence.activateParticipant(1)
    dhkeyexchange_sequence.addMutualAgreement("Generating A Prime", f"New prime is {diffie_hellman_key_exchange.selected_prime}")
    dhkeyexchange_sequence.addMutualAgreement("Selecting A Generator Value", f"New generator is {diffie_hellman_key_exchange.generator}")
    dhkeyexchange_sequence.deactivateParticipant(1)

    # each participant selects their private key and then calculates their public key
    dhkeyexchange_sequence.addDivider("Generating Public and Private Keys")
    dhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"New private key is {originator_dhkeypair.private_key}","Generating Private Key For Originator")
    dhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"New public key is {originator_dhkeypair.public_key}","Calculating Public Key For Originator")
    dhkeyexchange_sequence.deactivateParticipant(0)
    dhkeyexchange_sequence.activateParticipant(1)
    dhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"New private key is {receiver_dhkeypair.private_key}","Generating Private Key For Receiver")
    dhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"New public key is {receiver_dhkeypair.public_key}","Calculating Public Key For Receiver")
    dhkeyexchange_sequence.deactivateParticipant(1)

    # now the participants can use the other's public key along with their pre existing knowledge to calculate the shared value
    dhkeyexchange_sequence.addDivider("Calculating Shared Secret")
    dhkeyexchange_sequence.addALabeledRetrieval(1,0,f"Receiver's public key is {receiver_dhkeypair.public_key}","Retrieving Receiver's Public Key")
    dhkeyexchange_sequence.activateParticipant(0)
    dhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"Shared secret is {originator_dhkeypair.shared_secret}","Calculating Shared Secret Using Originator's Private\\nKey And Receiver's Public Key")
    dhkeyexchange_sequence.deactivateParticipant(0)
    dhkeyexchange_sequence.addALabeledRetrieval(0,1,f"Originator's public key is {originator_dhkeypair.public_key}","Retrieving Originator's Public Key")
    dhkeyexchange_sequence.activateParticipant(1)
    dhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"Shared secret is {receiver_dhkeypair.shared_secret}","Calculating Shared Secret Using Receiver's Private\\nKey And Originator's Public Key")
    dhkeyexchange_sequence.deactivateParticipant(1)

if __name__ == '__main__':
    diffie_hellman_key_exchange, originator_dhkeypair, receiver_dhkeypair = runDiffieHellmanKeyExchangeExampleScenario()
    dhkeyexchange_sequence = BasicSequenceDiagramSetup("Diffie Hellman Key Exchange Example")
    constructDHKeyExchangeSequence(diffie_hellman_key_exchange, originator_dhkeypair, receiver_dhkeypair, dhkeyexchange_sequence)
    dhkeyexchange_sequence.printAllDiagrams()