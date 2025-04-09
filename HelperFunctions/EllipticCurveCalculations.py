from PrimeNumbers import calculateModuloInverse

class EllipticCurveCalculations():
    '''
    This class should hopefully help with the elliptic curve calculations given that the curve is in the Weierstrass form
    such that y**2 = x**3 + a * x + b
    and the curve is in a defined finite field
    '''

    origin_point = (0,0)

    def __init__(self, a, b, finite_field):
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
                
elliptic_curve = EllipticCurveCalculations(0,7,17)
point = (15,13)
print(elliptic_curve.validatePointOnCurve(point=point))
print(point)

sum = point
for i in range(0,20):
    sum = elliptic_curve.calculatePointAddition(point,sum)
    print(sum)
