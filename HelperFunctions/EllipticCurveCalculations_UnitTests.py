import unittest
from EllipticCurveCalculations import EllipticCurveCalculations

class EncodeStringAsNumberList_UnitTests(unittest.TestCase):
    '''
    This class contains basic unit tests for the helper functions for encoding and decoding a string to a number list
    '''

    def setUp(self):
        print("- - - - - - - - - - - -")
        self.simple_elliptic_curve = EllipticCurveCalculations(a=0, b=7, finite_field=17)

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
        self.assertEqual(result, expected_result)

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
        self.assertEqual(result, expected_result)

if __name__ == '__main__':
    unittest.main()