from HelperFunctions import EllipticCurveDetails
from CryptographySchemes.EllipticCurveDHKeyExchange import EllipticCurveDHKeyExchange, EllipticCurveDHKeyPair
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup

def runEllipticCurveDHKeyExchangeExampleScenario():
    '''
    This function runs a simple example scenario for the Elliptic Curve Diffie Hellman Key Exchange
    '''
    elliptic_curve_dh_key_exchange = EllipticCurveDHKeyExchange([EllipticCurveDetails.getCurveP192,EllipticCurveDetails.getSecp256r1],is_debug=True)

    originator_ecdhkeypair = EllipticCurveDHKeyPair(elliptic_curve_dh_key_exchange, is_debug=True)
    receiver_ecdhkeypair = EllipticCurveDHKeyPair(elliptic_curve_dh_key_exchange, is_debug=True)
    originator_ecdhkeypair.calculateSharedSecret()
    receiver_ecdhkeypair.calculateSharedSecret()

    assert originator_ecdhkeypair.shared_secret == receiver_ecdhkeypair.shared_secret
    return elliptic_curve_dh_key_exchange,originator_ecdhkeypair,receiver_ecdhkeypair

def constructECDHKeyExchangeSequence(elliptic_curve_dh_key_exchange:EllipticCurveDHKeyExchange, originator_ecdhkeypair:EllipticCurveDHKeyPair, receiver_ecdhkeypair:EllipticCurveDHKeyPair, ecdhkeyexchange_sequence:BasicSequenceDiagramSetup):
    '''
    This function constructs the sequence for the simple diffie hellman key exchange scenario
    '''
    
    ecdhkeyexchange_sequence.initializeParticipants(2)

    # First both participants agree on a shard prime and matching generator value
    ecdhkeyexchange_sequence.addDivider("Agreeing On Shared Values")
    ecdhkeyexchange_sequence.activateParticipant(0)
    ecdhkeyexchange_sequence.activateParticipant(1)
    ecdhkeyexchange_sequence.addMutualAgreement("Selecting An Elliptic Curve", f"The curve is {elliptic_curve_dh_key_exchange.curve_details.name}")
    ecdhkeyexchange_sequence.addMutualAgreement("Selecting A Generator Point", f"The generator is {elliptic_curve_dh_key_exchange.curve_details.generator_point}")
    ecdhkeyexchange_sequence.deactivateParticipant(1)

    # each participant selects their private key and then calculates their public key
    ecdhkeyexchange_sequence.addDivider("Generating Public and Private Keys")
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"New private key is {originator_ecdhkeypair.private_key}","Generating Private Key For Originator")
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"New public key is {originator_ecdhkeypair.public_key}","Calculating Public Key For Originator")
    ecdhkeyexchange_sequence.deactivateParticipant(0)
    ecdhkeyexchange_sequence.activateParticipant(1)
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"New private key is {receiver_ecdhkeypair.private_key}","Generating Private Key For Receiver")
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"New public key is {receiver_ecdhkeypair.public_key}","Calculating Public Key For Receiver")
    ecdhkeyexchange_sequence.deactivateParticipant(1)

    # now the participants can use the other's public key along with their pre existing knowledge to calculate the shared value
    ecdhkeyexchange_sequence.addDivider("Calculating Shared Secret")
    ecdhkeyexchange_sequence.addALabeledRetrieval(1,0,f"Receiver's compressed public key is {receiver_ecdhkeypair.getCompressedPublicKey()}","Retrieving Receiver's Compressed Public Key")
    ecdhkeyexchange_sequence.activateParticipant(0)
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(0,f"Shared secret is {originator_ecdhkeypair.shared_secret}","Calculating Shared Secret Using Originator's Private\\nKey And Receiver's Public Key")
    ecdhkeyexchange_sequence.deactivateParticipant(0)
    ecdhkeyexchange_sequence.addALabeledRetrieval(0,1,f"Originator's compressed public key is {originator_ecdhkeypair.getCompressedPublicKey()}","Retrieving Originator's Compressed Public Key")
    ecdhkeyexchange_sequence.activateParticipant(1)
    ecdhkeyexchange_sequence.sendSelfMessage_particpantNumber(1,f"Shared secret is {receiver_ecdhkeypair.shared_secret}","Calculating Shared Secret Using Receiver's Private\\nKey And Originator's Public Key")
    ecdhkeyexchange_sequence.deactivateParticipant(1)

if __name__ == '__main__':
    elliptic_curve_dh_key_exchange, originator_ecdhkeypair, receiver_ecdhkeypair = runEllipticCurveDHKeyExchangeExampleScenario()
    elliptic_curve_dhkeyexchange_sequence = BasicSequenceDiagramSetup("Elliptic Curve Diffie Hellman Key Exchange Example")
    constructECDHKeyExchangeSequence(elliptic_curve_dh_key_exchange, originator_ecdhkeypair, receiver_ecdhkeypair, elliptic_curve_dhkeyexchange_sequence)
    elliptic_curve_dhkeyexchange_sequence.printAllDiagrams()