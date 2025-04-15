from CryptographySchemes.EllipticCurveDigitalSignatureAlgorithm import EllipticCurveDigitalSignatureAlgorithm
from GeneratingDiagrams.BasicSequenceDiagramSetup import BasicSequenceDiagramSetup
from HelperFunctions import EllipticCurveDetails

def generateSignature():
    '''
    This method generates the signature and prepares the data for the diagram
    '''
    ecdsa_sign = EllipticCurveDigitalSignatureAlgorithm([EllipticCurveDetails.getCurveP224],is_debug=True)
    message = "Please visit my website at jbarbourmoore.com"


    signature = ecdsa_sign.createSignature(message, is_debug=True)
    hash_calc = f"H = hash(message)  = {ecdsa_sign.H}\\n"
    r_calcs = ""
    r_calcs += f"K = randum integer = {ecdsa_sign.K}\\n"
    r_calcs += f"Kinv = k**-1 % n   = {ecdsa_sign.K}\\n"
    r_calcs += f"R = k * generator  = ({ecdsa_sign.R_x},\\n"
    r_calcs += f"                   = {ecdsa_sign.R_y})\\n"
    r_calcs += f"r = R_x % n        = {ecdsa_sign.r}\\n"
    s_calcs = ""
    s_calcs += f"s = Kinv * (H + r * private_key) % n"
    s_calcs += f"s = {ecdsa_sign.s}"
    signature_message = f"r = {signature[0]}\\ns = {signature[1]}"
    public_key_message = f"({ecdsa_sign.public_x}, \\n{ecdsa_sign.public_y})"
    return ecdsa_sign,message,signature,hash_calc,r_calcs,s_calcs,signature_message,public_key_message


def verifySignature(ecdsa_sign, message, signature):
    '''
    This method performs the signature verification and prepares the data for the diagram
    '''
    ecdsa_ver = EllipticCurveDigitalSignatureAlgorithm([EllipticCurveDetails.getCurveP224],is_debug=True)
    verification = ecdsa_ver.verifySignature(message,signature, ecdsa_sign.public_key,compressed=False,is_debug=True)
    
    hash_calc_ver = f"H = hash(message)  = {ecdsa_ver.H}\\n"
    ver_calcs = ""
    ver_calcs += f"s_inv = s**-1 % n   = {ecdsa_ver.sinv}\\n"
    ver_calcs += f"u = H * s_inv % n   = {ecdsa_ver.sinv}\\n"
    ver_calcs += f"v = r * s_inv % n   = {ecdsa_ver.sinv}\\n"
    ver_calcs += "Rprime = u * generator_point + v * public_key\\n"
    ver_calcs += f"({ecdsa_ver.R1_x}, {ecdsa_ver.R1_y})"

    if verification:
        verification_banner = f"The Signature Was Successfully Verified"
        verification_message = "Rprime_x == r\\n"
        verification_message += f"Rprime_x: {ecdsa_ver.R1_x}\\n"
        verification_message += f"r:        {ecdsa_ver.r}"

    else:
        verification_banner = f"The Signature Failed Verification"
        verification_message = "Rprime_x != r\\n"
        verification_message += f"Rprime_x: {ecdsa_ver.R1_x}\\n"
        verification_message += f"r:        {ecdsa_ver.r}"
    return hash_calc_ver,ver_calcs,verification_banner,verification_message

def constructECDSASequence(ecdsa_sign, message, hash_calc, r_calcs, s_calcs, signature_message, public_key_message, hash_calc_ver, ver_calcs, verification_banner, verification_message, ecdsa_sequence):
    '''
    This method constructs the sequence of events involved in the ECDSA process
    '''
    
    ecdsa_sequence.addDivider("Agreeing On Shared Values")
    ecdsa_sequence.activateParticipant(0)
    ecdsa_sequence.activateParticipant(1)
    ecdsa_sequence.addMutualAgreement("Selecting An Elliptic Curve", f"The curve is {ecdsa_sign.curve_details.name}")
    ecdsa_sequence.addMutualAgreement("Selecting A Generator Point", f"The generator is ({hex(ecdsa_sign.curve_details.generator_point[0])[2:]},\\n{hex(ecdsa_sign.curve_details.generator_point[1])[2:]})")
    ecdsa_sequence.addMutualAgreement("Selecting A Hashing Algorithm", f"The hashing algorithm is {ecdsa_sign.sha3.function_name.upper()}")
    ecdsa_sequence.deactivateParticipant(1)
    ecdsa_sequence.addDivider("Generating Keys")
    ecdsa_sequence.sendSelfMessage_particpantNumber(0,f"Private Key is {ecdsa_sign.private}","Generating Private Key")
    ecdsa_sequence.sendSelfMessage_particpantNumber(0,f"Public Key is {public_key_message}","Calculating Public Key")
    ecdsa_sequence.addDivider("Creating Signature")
    ecdsa_sequence.sendSelfMessage_particpantNumber(0,hash_calc,"Generating SHA3 Hash")
    ecdsa_sequence.sendSelfMessage_particpantNumber(0,r_calcs,"Calculating Message Signature : r")
    ecdsa_sequence.sendSelfMessage_particpantNumber(0,s_calcs,"Calculating Message Signature : s")
    ecdsa_sequence.addDivider("Sending Message")
    ecdsa_sequence.activateParticipant(1)
    ecdsa_sequence.sendALabeledMessage(0,1,message,"Sending The Message")
    ecdsa_sequence.sendALabeledMessage(0,1,signature_message,"Sending The Signature")
    ecdsa_sequence.sendALabeledMessage(0,1,public_key_message,"Sending The Public Key")
    ecdsa_sequence.deactivateParticipant(0)
    ecdsa_sequence.addDivider("Verifying Signature")
    ecdsa_sequence.sendSelfMessage_particpantNumber(1,hash_calc_ver,"Generating SHA3 Hash")
    ecdsa_sequence.sendSelfMessage_particpantNumber(1,ver_calcs,"Calculating Rprime")
    ecdsa_sequence.sendSelfMessage_particpantNumber(1,verification_message,verification_banner)

if __name__ == '__main__':

    ecdsa_sign, message, signature, hash_calc, r_calcs, s_calcs, signature_message, public_key_message = generateSignature()
    hash_calc_ver, ver_calcs, verification_banner, verification_message = verifySignature(ecdsa_sign, message, signature)

    ecdsa_sequence = BasicSequenceDiagramSetup("Elliptic Curve Digital Signature Algorithm With SHA3")
    ecdsa_sequence.initializeParticipants(2)
    ecdsa_sequence.addBannerNote("This sequence uses one of the smaller bit curves, P-224 and a smaller SHA-3 hash length, SHA3-224, ir order to improve legibility")
    constructECDSASequence(ecdsa_sign, message, hash_calc, r_calcs, s_calcs, signature_message, public_key_message, hash_calc_ver, ver_calcs, verification_banner, verification_message, ecdsa_sequence)

    ecdsa_sequence.printAllDiagrams()

