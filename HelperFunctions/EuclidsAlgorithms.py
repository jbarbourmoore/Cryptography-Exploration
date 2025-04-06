def extendedEuclidAlgorithm(larger_number, smaller_number, debug=False):
        '''
        This method implements the extended form of euclids algorithm

        Bezout Identity => s * larger_number + t * smaller_number = gcd(larger_number, smaller_number)

        Parameters :
            larger_number : int
                The larger number to be used
            smaller_number : int
                The smaller number to be used
            debug : Boolean, optional
                Whether the function is being debugged and should generate more detailed output, default is False

        Returns : 
            greatest_common_denominator : int
                The greatest common denominator for larger_number and smaller_number
            s : int
                The multiplication factor for larger_number in the bezout identity
            t : int
                The multiplication factor for smaller_number in the bezout identity
        '''
        
        s = 1
        t = 0
        s_hat = 0
        t_hat = 1

        remainder = 1
        greatest_commmon_denominator = larger_number
        r = smaller_number

        while remainder > 0:
            
            quotient = greatest_commmon_denominator // r
            remainder = greatest_commmon_denominator % r

            # m = q * n + r
            # or r = m - q * n = ( s - ( q * s_hat ) ) * m_0 + (t - ( q * t_hat ) ) * n_0  
            a = s - ( quotient * s_hat )
            b = t - ( quotient * t_hat )

            greatest_commmon_denominator = r
            r = remainder
            s = s_hat
            t = t_hat
            s_hat = a
            t_hat = b

        if debug :
            print(f"Running the extended form of Euclid's Algorithm for {larger_number} and {smaller_number}")
            print(f"s * {larger_number} + t * {smaller_number} = gcd(a, b)")
            print(f"Greatest common denominator: {greatest_commmon_denominator}, s: {s}, t: {t}")
            print(f"({s} * {larger_number}) + ({t} * {smaller_number}) = {greatest_commmon_denominator}")

        assert greatest_commmon_denominator == s * larger_number + t * smaller_number, f"({s} * {larger_number}) + ({t} * {smaller_number}) != {greatest_commmon_denominator}. Algorithm failed."
        
        return greatest_commmon_denominator, s, t

def euclidsAlgorithm(larger_number, smaller_number, debug=False):
    '''
    Uses the basic form of Euclid's Algorithm to find the greatest common denominator of larger_number and smaller_number

    Parameters:
        larger_number : int
            One of the numbers for which one is finding the greatest common denominator
        smaller_number : int
            One of the numbers for which one is finding the greatest common denominator
        debug : Boolean, optional
                Whether the function is being debugged and should generate more detailed output (default is False)

    Returns : 
        greatest_common_denominator 
            The greatest common denominator for larger_number and smaller_number
    '''

    greatest_common_denominator = larger_number
    r = smaller_number

    while r != 0:
        remainder = greatest_common_denominator % r
        greatest_common_denominator = r
        r = remainder

    if debug :
            print(f"Running the basic form of Euclid's Algorithm for {larger_number} and {smaller_number}")
            print(f"The greatest common denominator is {greatest_common_denominator}")

    return greatest_common_denominator