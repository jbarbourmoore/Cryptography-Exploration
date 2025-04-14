from HelperFunctions.PrimeNumbers import calculateModuloInverse
from decimal import Decimal

class EllipticCurveCalculations():
    '''
    This class should hopefully help with the elliptic curve calculations given that the curve is in the Weierstrass form
    such that y**2 = x**3 + a * x + b
    and the curve is in a defined finite field
    '''

    origin_point = (0,0)

    def __init__(self, a, b, finite_field, is_debug = False):
        '''
        This function defines the elliptic curve that is being used for the calculation in the form y**2 = x**3 + a * x + b
        as well as the size of the finite field

        Parameters : 
            a : int
                The coefficient for x in y**2 = x**3 + a * x + b
            b : int 
                The constant in y**2 = x**3 + a * x + b
            finite_field : int
                The size of the finite field for the elliptic curve calculation
                (Generally used as the modulus value)
        '''

        self.a = a
        self.b = b
        self.finite_field = finite_field
        self.is_debug = is_debug
    
    def validatePointOnCurve(self, point):
        '''
        This method checks to see whether a point is indeed on the elliptic curve y**2 = x**3 + a * x + b

        Parameters :
            point : (int, int)

        Returns :
            is_valid : Boolean
                Whether the point is on the elliptic curve in the finite field
        '''

        if point == self.origin_point:
            return True
        else:
            x,y = point

            x_in_finite_field = x < self.finite_field and x >= 0
            y_in_finite_field = y < self.finite_field and y >= 0
            point_on_curve = (y**2 - (x**3 + self.a*x + self.b)) % self.finite_field == 0

            if x_in_finite_field and y_in_finite_field and point_on_curve:
                return True
            else:
                return False
            
    def calculatePointInverse(self, point):
        '''
        This method calculate the inverse of a point on the elliptic curve assuming the curve is y**2 = x**3 + a * x + b
        
        Parameters :
            point : (int, int)
                A point on the elliptic curve over the finite field

        Returns : 
            point_r (int, int)
                The point on the elliptic curve which is the inverse of the original point
        '''

        if point == self.origin_point:
            return point
        
        x, y = point
        point_r =  (x, (-y) % self.finite_field)

        return point_r
    
    def convertFieldElementToInt(self, field_element):
        if self.finite_field % 2 == 1:
            return field_element
        else:
            raise NotImplementedError
    
    def calculatePointAddition(self,point_p, point_q):
        '''
        This method calculated the addition of point_p and point_q on the elliptic curve assuming the curve is y**2 = x**3 + a * x + b
        
        Parameters :
            point_p : (int, int)
                one of the points on the elliptic curve that are being added together
            point_q : (int, int)
                the other point on the elliptic curve that is being added

        Returns :
            point_r : (int, int) or None
                The result of the point addition
        '''

        # can only add valid points
        if not (self.validatePointOnCurve(point_p) and self.validatePointOnCurve(point_q)):
            return None
        
        #if one point is (0,0), the addition is just the other point
        if point_q == self.origin_point:
            return point_p
        elif point_p == self.origin_point:
            return point_q
        
        # if the two points are inverses, by definition the addition is (0,0)
        elif point_q == self.calculatePointInverse(point_p):
            return self.origin_point
        
        else:
            x_p,y_p = point_p
            x_q,y_q = point_q

            if point_p == point_q:
                dydx = (3 * x_p**2 + self.a) * calculateModuloInverse(2 * y_p, self.finite_field)
            else:
                dydx = (y_q - y_p) * calculateModuloInverse(x_q - x_p, self.finite_field)
            
            x_r = (dydx**2 - x_p - x_q) % self.finite_field
            y_r = (dydx * (x_p - x_r) - y_p) % self.finite_field

            point_r = (x_r, y_r)

        # The result of the addition of two points on an elliptic curve over a finite field
        # should always also be a point on the elliptic curve over a finite field
        if self.validatePointOnCurve(point_r):
            return point_r
        else: 
            return None
        
    def calculatedPointMultiplicationByConstant_continualAddition(self, point, constant):
        '''
        This method calculates the multiplication of a point on the elliptic curve by a constant

        It uses the continual addition of the same point method so it is not particularly efficient

        Parameters : 
            point : (int,int)
                The point that is being multiplied by a constant
            constant : int
                The constant value that the point is being multiplied by

        Returns : 
            point_r : (int, int)
                The resulting point of the multiplication
        '''

        # rapidly solve base cases
        if constant == 0 or point==(0,0):
            return (0,0)
        elif constant == 1:
            return point
        
        # add the point for the constant number of times
        point_r = point
        for _ in range(1, constant):
            point_r = self.calculatePointAddition(point,point_r)

        # the result of the multiplication must also be on the elliptic curve
        assert self.validatePointOnCurve(point=point_r)

        return point_r
    
    def calculatedPointMultiplicationByConstant_doubleAndAddMethod(self, point, constant):
        '''
        This method calculates the multiplication of a point on the elliptic curve by a constant

        It uses the "Double and Add Method" so it should be more efficient than the constant addition (roughly O=log_2(constant) time)

        Parameters : 
            point : (int,int)
                The point that is being multiplied by a constant
            constant : int
                The constant value that the point is being multiplied by

        Returns : 
            point_r : (int, int)
                The resulting point of the multiplication
        '''
     
        # get rapidly solve base cases
        if constant == 0 or point==(0,0):
            return (0,0)
        elif constant == 1:
            return point

        point_r = point
        
        # a string of the constant as binary 0s and 1s
        binary_of_constant = bin(constant) 
        binary_of_constant = binary_of_constant[2:len(binary_of_constant)] 
        
        # going from most significant bit to least significant bit
        # always doubling the current result point
        # and then adding the initial point if the bit is 1, not 0
        for i in range(1, len(binary_of_constant)):
            bit = binary_of_constant[i: i+1]
            point_r = self.calculatePointAddition(point_r, point_r)
            
            if bit == '1':
                point_r = self.calculatePointAddition(point_r, point)
        
        # the rest of the multiplication must also be on the elliptic curve
        assert self.validatePointOnCurve(point=point_r)

        return point_r
    
    def compressPointOnEllipticCurve(self, point):
        '''
        This method gets the compressed form of the point on the elliptic curve

        Parameters :
            point : (int, int)
                The point on the elliptic curve to be compressed

        Returns :
            compressed_point : str
                The compressed point as a hexadecimal as a str
        '''

        x, y = point
        return hex(x) + hex(y % 2)[2:]
    
    def decompressPointOnEllipticCurve(self, compressed_point):
        '''
        This function decompresses the point on the elliptic curve

        Parameters : 
            compressed_point : str
                The compressed point on the elliptic curve as a hexadecimal string

        Returns
            point : (int, int)
                The decompressed point on the elliptic curve
        '''

        x=int(compressed_point[:len(compressed_point)-1],16)
        y_bit = compressed_point[len(compressed_point)-1:]
        y_squared = (pow(x, 3) + self.a*x + self.b) % self.finite_field
        if self.is_debug:
            print(f"x:{x} a={self.a} b={self.b} x**3={pow(x,3)} y**2 = {pow(x, 3) + self.a*x + self.b}")
        power = (self.finite_field+1)/4
        if type(power ) == int :
            y = pow(y_squared, power, self.finite_field )
        else:
            try:
                y = int(y_squared**power % self.finite_field)
            except:
                y = pow(y_squared, (self.finite_field+1)//4, self.finite_field )
        if y % 2 != int(y_bit):
            y = self.finite_field - y
        
        return (x,y)
                    
    def printEllipticCurveEquation(self):
        '''
        This method outputs the values for this elliptic curve to the command line
        '''

        print(f"The values for this elliptic curve are: a={self.a} b={self.b} finite field={self.finite_field}")
        print(f"y**2 = x**3 + ax + b ==> y**2 = x**3 + {self.a}x + {self.b}")

if __name__ == '__main__':
    elliptic_curve = EllipticCurveCalculations(0,7,17)
    point = (15,13)
    print(elliptic_curve.validatePointOnCurve(point=point))
    print(point)

    sum = point
    for i in range(0,20):
        sum = elliptic_curve.calculatePointAddition(point,sum)
        print(sum)

    print(elliptic_curve.calculatedPointMultiplicationByConstant_continualAddition(point,7))
    print(elliptic_curve.calculatedPointMultiplicationByConstant_doubleAndAddMethod(point,7))
    compressed_point = elliptic_curve.compressPointOnEllipticCurve(point=point)
    print(compressed_point)
    print(elliptic_curve.decompressPointOnEllipticCurve(compressed_point=compressed_point))
    