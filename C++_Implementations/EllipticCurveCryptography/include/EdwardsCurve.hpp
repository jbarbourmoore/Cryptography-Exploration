#include "EllipticCurve.hpp"

class EdwardsCurve : public EllipticCurve{
    private:

        /// @brief The coefficient (a) for x^2 in the equation ax^2 + y^2 = 1 + dx^2y^2
        BIGNUM* a_;

        /// @brief The coefficient (d) for x^2y^2 in the equation ax^2 + y^2 = 1 + dx^2y^2
        BIGNUM* d_;

        /// @brief The finite field (p) within which all points are (modulus)
        BIGNUM* finite_field_;

        /// @brief The origin point (0,0)
        Point origin_;

        /// @brief The generator point for the curve
        Point g_;

        /// @brief The order of the curve
        BIGNUM* n_;

    public:

        /// @brief The default constructor for an Edwards Curve in the form ax^2 + y^2 = 1 + dx^2y^2
        EdwardsCurve();

        /// @brief The constructor for an Edwards Curve in the form ax^2 + y^2 = 1 + dx^2y^2
        /// @param a The coefficient (a) for x^2 in the equation ax^2 + y^2 = 1 + dx^2y^2
        /// @param d The coefficient (d) for x^2y^2 in the equation ax^2 + y^2 = 1 + dx^2y^2
        /// @param finite_field The finite field (p) within which all points are (modulus)
        /// @param gx The x coordinate of the generator point for the curve
        /// @param gy The y coordinate of the generator point for the curve
        EdwardsCurve(const BIGNUM* a, const BIGNUM* d, const BIGNUM* finite_field, const BIGNUM* gx, const BIGNUM* gy);

        /// @brief The constructor for an Edwards Curve in the form ax^2 + y^2 = 1 + dx^2y^2
        /// @param a_hex The coefficient (a) for x^2 in the equation ax^2 + y^2 = 1 + dx^2y^2
        /// @param d_hex The coefficient (d) for x^2y^2 in the equation ax^2 + y^2 = 1 + dx^2y^2
        /// @param finite_field_hex The finite field (p) within which all points are (modulus)
        /// @param gx_hex The x coordinate of the generator point for the curve
        /// @param gy_hex The y coordinate of the generator point for the curve
        /// @param n_hex The order of the curve
        EdwardsCurve(std::string a_hex, std::string d_hex, std::string finite_field_hex, std::string gx_hex, std::string gy_hex, std::string n_hex);

        /// @brief This method cleans up the EdwardsCurve and takes care of the BIGNUMs
        void deleteCurve() override;

        /// @brief This method returns a string containing the the equation for the Edwards curve
        /// @return The equation as a string value (integers are represented in hexadecimal form)
        std::string getEquation() override;

        /// @brief This method prints the details of the curve to the console
        void printCurveDetails() override;

        /// @brief This method validates whether a point exists on the Edwards Curve
        /// @param p The point that is being checked against the curve
        /// @return True if the point is on the curve
        bool validatePointOnCurve(Point p) override;

        /// @brief This method returns the hex string value for the finite field associated with this curve
        /// @return 
        std::string getFiniteFieldAsHex();

        /// @brief This method returns the hex string value for the x coefficient associated with this curve
        /// @return 
        std::string getAAsHex();

        /// @brief This method returns the hex string value for the constant associated with this curve
        /// @return 
        std::string getBAsHex();

        BIGNUM* getN();

        Point getG();

        /// @brief This method multiplies a given point by a constant value
        /// @param p The point that is to be multiplied by a given constant
        /// @param k The constant that the point shall be multiplied by
        /// @return The point resulting from the multiplication
        Point calculatePointMultiplicationByConstant(Point p, BIGNUM* k) override;

        /// @brief This method calculates the inverse of a given point on the curve
        /// @param p The point for which we are calculating the inverse
        /// @return The inverse to the given point
        Point calculatePointInverse(Point p) override;

        /// @brief This method adds two point together on a given curve
        /// @param p One of the points to be added together
        /// @param q One of the points to be added together
        /// @return The point resulting from the addition
        Point calculatePointAddition(Point p, Point q) override;
};

class edwards25519 : public EdwardsCurve{
    public  : 
        edwards25519() : EdwardsCurve(
            "-1",   // a (x coefficient)
            "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",   // d (y coefficient)
            "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",   // p (finite field)
            "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",   // g_x (The x coordinate of the generator point)
            "6666666666666666666666666666666666666666666666666666666666666658",   // g_y (The y coordinate of the generator point)
            "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"   // n (The order of the curve)
        ){};
};