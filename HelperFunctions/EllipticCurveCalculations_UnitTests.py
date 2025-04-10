import unittest
from EllipticCurveCalculations import EllipticCurveCalculations
import time

class EllipticCurveCalculations_UnitTests(unittest.TestCase):
    '''
    This class contains basic unit tests for the helper functions for elliptic curve calculations
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        self.simple_elliptic_curve = EllipticCurveCalculations(a=0, b=7, finite_field=17)
        self.secp192r1 = EllipticCurveCalculations(a=6277101735386680763835789423207666416083908700390324961276,
                                                   b=2455155546008943817740293915197451784769108058161191238065,
                                                    finite_field=6277101735386680763835789423207666416083908700390324961279 )

    def test_origin_on_curve(self):
        '''
        This method tests that the origin is on the curve
        '''

        point = (0,0)
        result = self.simple_elliptic_curve.validatePointOnCurve(point=point)
        self.simple_elliptic_curve.printEllipticCurveEquation()
        print(f"Is {point} on curve? {result}")
        self.assertTrue(result)

    def test_true_point_on_curve(self):
        '''
        This method tests that the point is on the curve
        '''

        point = (15,13)
        result = self.simple_elliptic_curve.validatePointOnCurve(point=point)
        self.simple_elliptic_curve.printEllipticCurveEquation()
        print(f"Is {point} on curve? {result}")
        self.assertTrue(result)

    def test_false_point_on_curve(self):
        '''
        This method tests that the point is not on the curve
        '''

        point = (1,2)
        result = self.simple_elliptic_curve.validatePointOnCurve(point=point)
        self.simple_elliptic_curve.printEllipticCurveEquation()
        print(f"Is {point} on curve? {result}")
        self.assertFalse(result)

    def test_adding_two_same_points(self):
        '''
        This method tests adding two points which are the same
        '''

        point = (15, 13)
        expected_result = (2, 10)
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=point))
        result = self.simple_elliptic_curve.calculatePointAddition(point_p=point,point_q=point)
        self.simple_elliptic_curve.printEllipticCurveEquation()
        print(f"{point} + {point} = {result}")
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=result))
        self.assertEqual(result, expected_result)

    def test_multiplying_by_two(self):
        '''
        This method tests multiplying a point by 2
        '''

        point = (15, 13)
        constant = 2
        expected_result = (2, 10)
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=point))
        start_continual_adding = time.time()
        result_continual_adding = self.simple_elliptic_curve.calculatedPointMultiplicationByConstant_continualAddition(point=point,constant=constant)
        duration_continual_adding = time.time() - start_continual_adding
        start_double_and_add = time.time()
        result_double_and_add = self.simple_elliptic_curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(point=point,constant=constant)
        duration_double_and_add = time.time() - start_double_and_add
        self.simple_elliptic_curve.printEllipticCurveEquation()
        print(f"{point} * {constant} = Continual Adding : {result_continual_adding} Double and Add : {result_double_and_add}")
        print(f"Durations --> Continual Adding : {duration_continual_adding:.3f} Double and Add : {duration_double_and_add:.3f}")
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=result_continual_adding))
        self.assertEqual(result_continual_adding, expected_result)
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=result_double_and_add))
        self.assertEqual(result_double_and_add, expected_result)

    def test_multiplying_by_nineteen(self):
        '''
        This method tests multiplying a point by 19 (finite_field + 2)
        '''

        point = (15, 13)
        constant = 19
        expected_result = (15, 13)
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=point))
        result_continual_adding = self.simple_elliptic_curve.calculatedPointMultiplicationByConstant_continualAddition(point=point,constant=constant)
        result_double_and_add = self.simple_elliptic_curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(point=point,constant=constant)
        self.simple_elliptic_curve.printEllipticCurveEquation()
        print(f"{point} * {constant} = Continual Adding : {result_continual_adding} Double and Add : {result_double_and_add}")
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=result_continual_adding))
        self.assertEqual(result_continual_adding, expected_result)
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=result_double_and_add))
        self.assertEqual(result_double_and_add, expected_result)

    def test_adding_two_different_points(self):
        '''
        This method tests adding two different points on the elliptic curve in the finite field
        '''

        point_p = (15, 13)
        point_q = (2, 10)
        expected_result = (8, 3)
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=point_p))
        result = self.simple_elliptic_curve.calculatePointAddition(point_p=point_p,point_q=point_q)
        self.simple_elliptic_curve.printEllipticCurveEquation()
        print(f"{point_p} + {point_q} = {result}")
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=result))
        self.assertEqual(result, expected_result)

    def test_calculating_point_inverse(self):
        '''
        This method tests finding the inverse of a point
        '''

        point = (15, 13)
        expected_result = (15, 4)
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=point))
        result = self.simple_elliptic_curve.calculatePointInverse(point=point)
        self.simple_elliptic_curve.printEllipticCurveEquation()
        print(f"The inverse of {point} is {result}")
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=result))
        self.assertEqual(result, expected_result)

    def test_adding_point_inverse(self):
        '''
        This method tests adding a point to its inverse point to get the origin point
        '''

        point = (15, 13)
        inverse_point = (15, 4)
        origin_point = (0, 0)
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=point))
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=inverse_point))
        result = self.simple_elliptic_curve.calculatePointAddition(point_p=point,point_q=inverse_point)
        self.simple_elliptic_curve.printEllipticCurveEquation()
        print(f"Adding {point} to its inverse {inverse_point} is {result}")
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=result))
        self.assertEqual(result, origin_point)

    def test_compressingAPoint(self):
        '''
        This method tests compressing a point
        '''

        point = (15, 13)
        expected_compressed_point = "0xf1"
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(point=point))
        result = self.simple_elliptic_curve.compressPointOnEllipticCurve(point)
        print(f"The compressed form of {point} is {result}")
        self.assertEqual(result,expected_compressed_point)

    def test_decompressingAPoint(self):
        '''
        This method tests decompressing a point
        '''

        compressed_point = "0xf1"
        expected_point = (15, 13)
        result = self.simple_elliptic_curve.decompressPointOnEllipticCurve(compressed_point)
        print(f"The decompressed point for {compressed_point} is {result}")
        self.assertTrue(self.simple_elliptic_curve.validatePointOnCurve(result))
        self.assertEqual(result, expected_point)

    def test_origin_on_secp192r1(self):
        '''
        This method tests that the origin is on the curve for secp192r1
        '''

        point = (0,0)
        result = self.secp192r1.validatePointOnCurve(point=point)
        self.secp192r1.printEllipticCurveEquation()
        print(f"Is {point} on curve? {result}")
        self.assertTrue(result)

    def test_point_on_secp192r1(self):
        '''
        This method tests that the point is on the curve for secp192r1
        '''

        point = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
        result = self.secp192r1.validatePointOnCurve(point=point)
        self.secp192r1.printEllipticCurveEquation()
        print(f"Is {point} on curve? {result}")
        self.assertTrue(result)

    def test_adding_two_same_points_secp192r1(self):
        '''
        This method tests adding two points which are the same on secp192r1
        '''

        point = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
        expected_result = (5369744403678710563432458361254544170966096384586764429448, 5429234379789071039750654906915254128254326554272718558123)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=point))
        result = self.secp192r1.calculatePointAddition(point_p=point,point_q=point)
        self.secp192r1.printEllipticCurveEquation()
        print(f"{point} + {point} = {result}")
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result))
        self.assertEqual(result, expected_result)

    def test_multiplying_by_two_secp192r1(self):
        '''
        This method tests multiplying a point by 2
        '''

        point = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
        constant = 2
        expected_result = (5369744403678710563432458361254544170966096384586764429448, 5429234379789071039750654906915254128254326554272718558123)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=point))
        start_continual_adding = time.time()
        result_continual_adding = self.secp192r1.calculatedPointMultiplicationByConstant_continualAddition(point=point,constant=constant)
        duration_continual_adding = time.time() - start_continual_adding
        start_double_and_add = time.time()
        result_double_and_add = self.secp192r1.calculatedPointMultiplicationByConstant_doubleAndAddMethod(point=point,constant=constant)
        duration_double_and_add = time.time() - start_double_and_add
        self.secp192r1.printEllipticCurveEquation()
        print(f"{point} * {constant} = Continual Adding : {result_continual_adding} Double and Add : {result_double_and_add}")
        print(f"Durations --> Continual Adding : {duration_continual_adding:.3f} Double and Add : {duration_double_and_add:.3f}")        
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result_continual_adding))
        self.assertEqual(result_continual_adding, expected_result)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result_double_and_add))
        self.assertEqual(result_double_and_add, expected_result)

    def test_multiplying_by_104_secp192r1(self):
        '''
        This method tests multiplying a point by 104
        '''

        point = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
        constant = 104
        expected_result = (5124267969112884640430558489079512598372932209181558738984, 5241168070499360885696850377502882660536951875217754938315)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=point))
        start_continual_adding = time.time()
        result_continual_adding = self.secp192r1.calculatedPointMultiplicationByConstant_continualAddition(point=point,constant=constant)
        duration_continual_adding = time.time() - start_continual_adding
        start_double_and_add = time.time()
        result_double_and_add = self.secp192r1.calculatedPointMultiplicationByConstant_doubleAndAddMethod(point=point,constant=constant)
        duration_double_and_add = time.time() - start_double_and_add
        self.secp192r1.printEllipticCurveEquation()
        print(f"{point} * {constant} = Continual Adding : {result_continual_adding} Double and Add : {result_double_and_add}")
        print(f"Durations --> Continual Adding : {duration_continual_adding:.3f} Double and Add : {duration_double_and_add:.3f}")        
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result_continual_adding))
        self.assertEqual(result_continual_adding, expected_result)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result_double_and_add))
        self.assertEqual(result_double_and_add, expected_result)

    def test_multiplying_by_19364_secp192r1(self):
        '''
        This method tests multiplying a point by 19364
        '''

        point = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
        constant = 19364
        expected_result = (426633705220448967421986414450829068867705697807080443935, 3216648681216470491428170926157712464969850933119010868622)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=point))
        start_continual_adding = time.time()
        result_continual_adding = self.secp192r1.calculatedPointMultiplicationByConstant_continualAddition(point=point,constant=constant)
        duration_continual_adding = time.time() - start_continual_adding
        start_double_and_add = time.time()
        result_double_and_add = self.secp192r1.calculatedPointMultiplicationByConstant_doubleAndAddMethod(point=point,constant=constant)
        duration_double_and_add = time.time() - start_double_and_add
        self.secp192r1.printEllipticCurveEquation()
        print(f"{point} * {constant} = Continual Adding : {result_continual_adding} Double and Add : {result_double_and_add}")
        print(f"Durations --> Continual Adding : {duration_continual_adding:.3f} Double and Add : {duration_double_and_add:.3f}")        
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result_continual_adding))
        self.assertEqual(result_continual_adding, expected_result)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result_double_and_add))
        self.assertEqual(result_double_and_add, expected_result)

    def test_multiplying_by_237568_secp192r1(self):
        '''
        This method tests multiplying a point by 237568
        '''

        point = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
        constant = 237568
        expected_result = (871023611157170972703611374923345710780774914879018003341, 1903816589192018542033229449349641804651012623594677678608)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=point))
        start_continual_adding = time.time()
        result_continual_adding = self.secp192r1.calculatedPointMultiplicationByConstant_continualAddition(point=point,constant=constant)
        duration_continual_adding = time.time() - start_continual_adding
        start_double_and_add = time.time()
        result_double_and_add = self.secp192r1.calculatedPointMultiplicationByConstant_doubleAndAddMethod(point=point,constant=constant)
        duration_double_and_add = time.time() - start_double_and_add
        self.secp192r1.printEllipticCurveEquation()
        print(f"{point} * {constant} = Continual Adding : {result_continual_adding} Double and Add : {result_double_and_add}")
        print(f"Durations --> Continual Adding : {duration_continual_adding:.3f} Double and Add : {duration_double_and_add:.3f}")        
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result_continual_adding))
        self.assertEqual(result_continual_adding, expected_result)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result_double_and_add))
        self.assertEqual(result_double_and_add, expected_result)

    def test_adding_two_different_points_secp192r1(self):
        '''
        This method tests adding two different points  on secp192r1
        '''

        point_p = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
        point_q = (5369744403678710563432458361254544170966096384586764429448, 5429234379789071039750654906915254128254326554272718558123)
        expected_result = (2915109630280678890720206779706963455590627465886103135194,2946626711558792003980654088990112021985937607003425539581)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=point_p))
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=point_q))
        result = self.secp192r1.calculatePointAddition(point_p=point_p,point_q=point_q)
        self.secp192r1.printEllipticCurveEquation()
        print(f"{point_p} + {point_q} = {result}")
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result))
        self.assertEqual(result, expected_result)

    def test_calculating_point_inverse_secp192r1(self):
        '''
        This method tests finding the inverse of a point
        '''

        point = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
        expected_result = (602046282375688656758213480587526111916698976636884684818, 6103051403093058732430931870927447005719885211462938310638)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=point))
        result = self.secp192r1.calculatePointInverse(point=point)
        self.secp192r1.printEllipticCurveEquation()
        print(f"The inverse of {point} is {result}")
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result))
        self.assertEqual(result, expected_result)

    def test_adding_point_inverse_secp192r1(self):
        '''
        This method tests adding a point to its inverse point to get the origin point
        '''

        point = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
        inverse_point = (602046282375688656758213480587526111916698976636884684818, 6103051403093058732430931870927447005719885211462938310638)
        origin_point = (0, 0)
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=point))
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=inverse_point))
        result = self.secp192r1.calculatePointAddition(point_p=point,point_q=inverse_point)
        self.secp192r1.printEllipticCurveEquation()
        print(f"Adding {point} to its inverse {inverse_point} is {result}")
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=result))
        self.assertEqual(result, origin_point)

    def test_compressingAPoint_secp192r1(self):
        '''
        This method tests compressing a point on secp192r1
        '''

        point = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
        expected_compressed_point = "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff10121"
        self.assertTrue(self.secp192r1.validatePointOnCurve(point=point))
        result = self.secp192r1.compressPointOnEllipticCurve(point)
        print(f"The compressed form of {point} is {result}")
        self.assertEqual(result,expected_compressed_point)

    def test_decompressingAPoint_secp192r1(self):
        '''
        This method tests decompressing a point on secp192r1
        '''

        compressed_point = "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff10121"
        expected_point = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
        result = self.secp192r1.decompressPointOnEllipticCurve(compressed_point)
        print(f"The decompressed point for {compressed_point} is {result}")
        self.assertTrue(self.secp192r1.validatePointOnCurve(result))
        self.assertEqual(result, expected_point)

if __name__ == '__main__':
    unittest.main()