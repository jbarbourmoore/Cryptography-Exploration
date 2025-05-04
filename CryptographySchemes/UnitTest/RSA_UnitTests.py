
import unittest
from CryptographySchemes.RSACryptographyScheme import *
from HelperFunctions.PrimeNumbers import calculateModuloInverse

class RSA_TestCase_Details():

    def __init__(self,ct:str,pt:str,p:str,q:str,d:str,n:str,e:str):
        self.ct = IntegerHandler.fromHexString(ct, little_endian, bit_length)
        self.pt = IntegerHandler.fromHexString(pt, little_endian, bit_length)
        self.p = IntegerHandler.fromHexString(p, little_endian, bit_length)
        self.q = IntegerHandler.fromHexString(q, little_endian, bit_length)
        self.d = IntegerHandler.fromHexString(d, little_endian, bit_length)
        self.n = IntegerHandler.fromHexString(n, little_endian, bit_length)
        self.e = IntegerHandler.fromHexString(e, little_endian, bit_length)

    def get_private_quint_form(self):
        dP = self.d.getValue() % (self.p.getValue() - 1)
        dQ = self.d.getValue() % (self.q.getValue() - 1)
        qInv = calculateModuloInverse(self.q.getValue(), self.p.getValue())
        calc_dP = IntegerHandler(dP,little_endian,bit_length)
        calc_dQ = IntegerHandler(dQ,little_endian,bit_length)
        calc_qInv = IntegerHandler(qInv,little_endian,bit_length)
        private_key_quint = RSA_PrivateKey_QuintupleForm(self.p,self.q,calc_dP,calc_dQ,calc_qInv,[])
        return private_key_quint
    
    def get_private(self):
        return RSA_PrivateKey(self.n,self.d)
    
    def get_public(self):
        return RSA_PublicKey(self.n, self.e)

encryption_primitive_test_cases:list[RSA_TestCase_Details] = []

class RSA_UnitTest(unittest.TestCase):
    '''
    This class contains basic unit tests for rsa
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")

    def test_encryption_primitive_calculate_d(self):
        '''
        This method tests calculating 'd' as laid out in NIST FIPS 186-5

        Test vectors from RSA encryption primitive test data provided by NIST
        '''
        print("Test Calculating 'd'")
        for i in range(0, len(encryption_primitive_test_cases)):
            print("- - - - - - - - - - - -")
            print(f"Test Case {i+1}")
            test_details = encryption_primitive_test_cases[i]
            calc_d = RSA.calculateD(test_details.e, test_details.p, test_details.q)
            print(f"Expected 'd'   : {test_details.d.getValue()}")
            print(f"Calculated 'd' : {calc_d}")
            self.assertEqual(test_details.d.getValue(), calc_d, f"The value calculated for 'd' (in test {i+1}) : ({calc_d}) is not the expected value : ({test_details.d.getValue()})")

    def test_encryption_primitive_calculate_n(self):
        '''
        This method tests calculating 'n' as laid out in NIST FIPS 186-5

        Test vectors from RSA encryption primitive test data provided by NIST
        '''
        print("Test Calculating 'n'")
        for i in range(0, len(encryption_primitive_test_cases)):
            print("- - - - - - - - - - - -")
            print(f"Test Case {i+1}")   
            test_details = encryption_primitive_test_cases[i]  
            calc_n = test_details.p.getValue() * test_details.q.getValue()
            print(f"Expected 'n'   : {test_details.n.getValue()}")
            print(f"Calculated 'n' : {calc_n}")
            self.assertEqual(test_details.n.getValue(), calc_n, f"The value calculated for n ({calc_n}) is not the expected value ({test_details.n.getValue()})")
    
    def test_encryption_primitive_prime_p(self):
        '''
        This method tests primality of 'p' with Miller Rabin as laid out in NIST FIPS 186-5

        Test vectors from RSA encryption primitive test data provided by NIST
        '''
        print("Test 'p' Primality With Miller Rabin")
        for i in range(0, len(encryption_primitive_test_cases)):
            print("- - - - - - - - - - - -")
            print(f"Test Case {i+1}")   
            test_details = encryption_primitive_test_cases[i]  
            miller_rabin_result_p = RSA.isMillerRabinPassed(test_details.p.getValue())
            print(f"Value of 'p'   : {test_details.p.getValue()}")
            print(f"Probably Prime : {miller_rabin_result_p}")
            self.assertTrue(miller_rabin_result_p)

    def test_encryption_primitive_prime_q(self):
        '''
        This method tests primality of 'q' with Miller Rabin as laid out in NIST FIPS 186-5

        Test vectors from RSA encryption primitive test data provided by NIST
        '''
        print("Test 'q' Primality With Miller Rabin")
        for i in range(0, len(encryption_primitive_test_cases)):
            print("- - - - - - - - - - - -")
            print(f"Test Case {i+1}")   
            test_details = encryption_primitive_test_cases[i]  
            miller_rabin_result_q = RSA.isMillerRabinPassed(test_details.q.getValue())
            print(f"Value of 'p'   : {test_details.q.getValue()}")
            print(f"Probably Prime : {miller_rabin_result_q}")
            self.assertTrue(miller_rabin_result_q)

    def test_encryption_primitive_decryption_quintform(self):
        '''
        This method tests the decryption primitive with the pribate key in quintuple form as laid out in NIST FIPS 186-5

        Test vectors from RSA encryption primitive test data provided by NIST
        '''
        print("Test Decyption Primitive With Private Key in Quintuple Form")
        for i in range(0, len(encryption_primitive_test_cases)):
            print("- - - - - - - - - - - -")
            print(f"Test Case {i+1}")   
            test_details = encryption_primitive_test_cases[i]  

            private_key_quint = test_details.get_private_quint_form()
            print(f"Expected Plain Text   : {test_details.pt.getHexString()}")
            calculated_plain_quint = RSA.RSA_DecryptionPrimitive(private_key_quint, test_details.ct)
            print(f"Calculated Plain Text : {calculated_plain_quint.getHexString()}")

            self.assertEqual(test_details.pt.getHexString(), calculated_plain_quint.getHexString())

    def test_encryption_primitive_encryption(self):
        '''
        This method tests the encryption primitive with the public key as laid out in NIST FIPS 186-5

        Test vectors from RSA encryption primitive test data provided by NIST
        '''
        print("Test Encryption Primitive With Public Key")
        for i in range(0, len(encryption_primitive_test_cases)):
            print("- - - - - - - - - - - -")
            print(f"Test Case {i+1}")   
            test_details = encryption_primitive_test_cases[i]  
            public_key = test_details.get_public()
        
            calculated_cipher = RSA.RSA_EncryptionPrimitive(public_key, test_details.pt)
            print(f"Expected Cipher   : {test_details.ct.getHexString()}")
            print(f"Calculated Cipher : {calculated_cipher.getHexString()}")

            self.assertEqual(test_details.ct.getHexString(), calculated_cipher.getHexString())

    def test_encryption_primitive_decryption(self):
        '''
        This method tests the decryption primitive with the private key as laid out in NIST FIPS 186-5

        Test vectors from RSA encryption primitive test data provided by NIST
        '''
        print("Test Decryption Primitive With Private Key")
        for i in range(0, len(encryption_primitive_test_cases)):
            print("- - - - - - - - - - - -")
            print(f"Test Case {i+1}")   
            test_details = encryption_primitive_test_cases[i]  
            private_key = test_details.get_private()
            
            calculated_plain = RSA.RSA_DecryptionPrimitive(private_key, test_details.ct)
            print(f"Expected Plain Text   : {test_details.pt.getHexString()}")
            print(f"Calculated Plain Text : {calculated_plain.getHexString()}")

            self.assertEqual(test_details.pt.getHexString(), calculated_plain.getHexString())

def setup_encryption_primitives():
        '''
        This method creates the test data for the RSA Encryotion and Decryption primitives
        '''
        ct = "5662E1AF1E949E5F17A917FD586F7F50F4490632358F4801AA75E5AC8D9CD37ED69806EC1988DEEA48002044089068A86C09E5817BE4195D4FFB38FD7FE66038EE208EC017EB59DACA82164EEC98FCE3726493EDD4C19E64581DD77262A86C5E4E0DDD0573DA0CFFF7BA431A48727A276D9AA5EC45AF46CB25029A24EA51940D9C5FC067BF6A7E1750D89D1A8CC466F341C2C3F7B509BE0F759C6FF2F25DD794D5CFDEAF65BCE931925BF503BEBB6794F48D81C2E569DD7A0E2623A99C107346DC5CD6F4585B80C384A9619383CC3598450C0265A4B4F0ABC4370AE67F6DDBF3EE79D0F454ADA1F7F22676D615A1B2190DA316770361BFAD502AA1FA5273E9FC"
        pt = "5E74D2E3598F0286DDCD79AC41A82F8477D91FE56542EC16F00633306FA5D65DCBE3E6C4AF76D7CABA4661982F3DDEEFA642BBE58290DFA2C0B6AB8E3153B7EB203E7F3A5EFFC4D0C4B842C138FD80443EFEAD6B1536FBFE509FE09F9AA67476B2CED84D9797ADC1CEAA15B2F69667533A9111A9BEDD0B2FE81FB13A14EF6B0907AE91B9252A6E7D61BCECF156FB0388ECE7363BC18F5C0735D129B8D08218654B25FDD67C91287172513CA23F6C71A72C65433884C352204FC8158A8931E5554206AE3BD954EF68227D1A829074ADEDA63D51FF0B9C2A5DF293BC77FC5A238822A41BEC6464AF283D166E7797E9039FCC22BA2B70D45169BDCB3AB70B585B45"
        p = "BA90B7396D2D1E28A2ACB086FD05BEB308469F74D47879512DDB4A68C085FFD933DDCD1340A83FBF2CB321EDE49F8BD0B93E42029B96C488A4F8E2ADEC4ADCC49A942589D577F14B493B0A98001D4A108936B39D499A6E5966A38B32F489FB374C220B2EB015076CDB8C9C0AEF2A2B2F2BD636E78128E6A6C3D69EDDE4CDD7E7"
        q =  "FB6E6185BF10B5981F76D2403190BB653049B86661B58774D2EAD2356FB843A8FBBC9729C2D1172C2B9803297CFF3853C2520B7BF725BA92982357D73CE03023A04E4069E37EB83BC4AF8B1B481F9729C10F16A0DBE3F73B267AA87B0DDCDCB7B44C491429F962D9F2E65FEE61E10D409F64B41898E56FE96269634557AB2225"
        d = "153430AAC32B36E85584B0AFE9BDA8108043318A179D720E98042B245E9835B0F799D85D45EA46E9D179DA9F3DFB05D162B0DDF1F1CC75B388C7FAEED5A318B0BDFB583349FDEF88DB3B548DDF56C83AEBAACE65AA55119F0646BE765177BE148434A797C61F87570F9E9242248C5A1460D4F25FB6D83736DB0D695CCFB4AAD360CE844852468CEFC2E2952ABC86F879765B1E55034BF7861D8E75F6623B4DFEFF0ED1BB10BAC318D0FBEB51ED40A519BF49241391556392B7F14626318FB7CD18E9E8F65B9FE7839CD94B2FA933D4AFE115CE226334762A1544510386AACD4EFF9AA22BC53297C3907E9FDD93EA03BAEA8280EFB06DDC42810753DE6D35C7A5"
        n = "B73C54E656923F3F184546C1FB00BC7E2C9DF9A95E4EDE9DA559F2BE1773C8B52159BD54A25B8142839FAF6D0E2F70130B9961C875D1EB2D99F36A1DFB72E05F46C9B83456BCEFA33A0A14DCD6CB34F32666B516F148858498CD52BE9804F5E7D5D3714629AB27F4102B7DC419A9A1BAA9B2A0990C15A368C028EC678FFF266D9F19FC61DFEBFE500AC3C5701B1291DDA1BE47F330BB11C1DD14BE6EE2C098EB934DB695A097449AE269D3878554026245325A872DE759F6ECAE043E80479E1A7EE6FF52F77FF5441BB7C09B03E01C62F1AD2530FC5D0AA02B9222080BF6242987D23267B7F7A486CBA254648D5B3DBF5D475BFE83FA2D1397D0BE9720B9E263"
        e = "02DE387DD9"

        test_case_details = RSA_TestCase_Details(ct,pt,p,q,d,n,e)
        encryption_primitive_test_cases.append(test_case_details)

        ct = "742D529EE4A41CE7BAD178E358F51DCF872FCC12A304EBFABB12030AE6AB06A738010B59BA0C339C8C48435B16164DF7521D29CCC206027F860DAA1840A930FD2D8EFAA6ED70ECB0FB8F18A5847207662A44B416A9333632A7F8C9A7BD2F2BA5EEC7CE1E7C783B0633D2FFF938AA7850B468476C4F1EC5FBAC761E28772083FB88514FFCC3BBCE72B003356F2FE3A8C62140C7412AB4F63DC491D94BEAEC0A68422FDCE07099917BA97120465B8A8D86C109148189C52A6432C096543777E4D14A91F9BC6969D036C25106551929FD5AE511C2CFBD54F93BEC464A41CF53CDB0C63A6F59E5739884D8D2D6830117AB7D0165A70428AB0BB9EADE2F02EEA9089A"
        pt = "0D3E74F20C249E1058D4787C22F95819066FA8927A95AB004A240073FE20CBCB149545694B0EE318557759FCC4D2CA0E3D55307D1D3A4CD1F3B031CE0DF356A5DEDCC25729C4302FABA4CB885C9FA3C2F57A4D1308451C300D2378E90F4F83DCEDCDCF5217BC3840A796FCDAF73483A3D199C389BDB50CFE95D9C02E5F4FC1917FA4606CF6AB7559253202698D7EABE7561137271CE1A524E5956D25C379AF4F121877355F2495DC154A0EB33CF2F3B6990F60FCC0CCE199EF1E76E11585895EE1C619FB6D140266006AB41D56CE3E6C68571902568CD4520F1F9E5E284B4B9DFCC3782D05CDF826895450E314FBC654032A775F47088F18D3B4000AC23BD107"
        p = "EB48E387997710CB6D83CC6A2CCFD327B3064638ABEEE8708F7F25EE89AC8975BB062EC227129E923586F190F1A5C2E2E8DA988286E09F190A0B99380A45525E14BD10EEB2BB024B88CD184A08F27B29B72F33DB0A9D33CCF5E07D2A5D27604ED0F9836CCF7A121CB6A220BAAC94FA8835F75F6A942257972ADF69C4D8B8EEA9"
        q =  "BA09FCB64170DEDFBE8E7A37A088EAB99BD73A8CA78B83B63E666449A83A43B6B631CF7BAE9255305EBFA5B3831EC70C89ADB34DE0F5D48A85AB4897A13D9E6441FE55679574664E241A827C15086187FE0686479F84B40C9964EF14E07A4BE03BBBBCE4A5C6120FF452D295026EEE74BF2912ED1DDA20FEE3FB2DA7835AA1F7"
        d = "42B7EAE4BFC8E11D33536136EF3C2B26A516C5D480FA7D55E31CF6CA68E070D9B1E8C18351354B01294CAB22F0D3676821F0462A410989160D060F3A11331103E09D68D8B9FB1E922E538B4AB23C2D0CD033868BE59B746A42BBE638F379154E729B04739C7504ECA3585C65AB57FC31F5D871C195A30E04D27A5FCAA3C45CFB2D3BB0D5D694EE648C1DA6584B75DA110482C24159576E729D7E3DAA0096DB623AD9F6DE63181B4C539BCA9B502C4E33AB455728AC2E358503E90D258FE1BED937CFC355A8C3B54C3F8B3031D5612F7E63C307F899DB3F391F1A83E248580CC145887E25614D59B32892834BBDC75D55FE39CFD797CAB80E2506C5A8E684426F"
        n = "AAFC2323C735635B862201C4920D397EA283F11A1E76C56BA8C5573314D7D1DBE70C1DF2ACE3C7E71D549F7ED8D1E82DF3F8148B81A479C7BED674DB4A8B9F8F95F07ED1F3DF1809E0AD53AFE8F589AD8431F24F8CFBF7F0BAFCF77C9487B037AD16C8564A9EED11C1E8BAD2063307627CD6971E99F88FC7524F05D89F1A609FA328EFEEB3DBF511C9EFFA7CD2734F3BF1C2A5FC2FC3548EEFB8B6EE1E4D8C0859E1A993BDCF8ED744E9BB32444C7FEF86FDD96D596CC99B701B0201D95D6DAC931FBE3A6E38DBF589E43330DE8425A474E1D28003D7C9D70BA14F9D9EA633B4BF921F54DBDEEB130A05DE2CEC30F15F1B1B793FB00BF89D8679119CCAF08E0F"
        e = "8792D8C9AF"

        test_case_details = RSA_TestCase_Details(ct,pt,p,q,d,n,e)
        encryption_primitive_test_cases.append(test_case_details)

if __name__ == '__main__':
    setup_encryption_primitives()
    unittest.main()