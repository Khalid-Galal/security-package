using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {

        public int Encrypt(int p, int q, int M, int e)
        {
            int modulus = p * q;
            int result = 1;
            for (int i = 0; i < e; i++)
            {
                result = (result * M) % modulus;
            }
            result = result % modulus;
            return result;
        }

        public int Inv(int a, int modulus)
        {
            int quotient = modulus, remainder = 0, factor1 = 1, factor2 = 0;
            while (a > 0)
            {
                int quotientTemp = quotient / a, remainderTemp = a;
                a = quotient % remainderTemp;
                quotient = remainderTemp;
                remainderTemp = factor2;
                factor2 = factor1 - quotientTemp * factor2;
                factor1 = remainderTemp;
            }
            factor1 %= modulus;
            if (factor1 < 0) factor1 = (factor1 + modulus) % modulus;
            return factor1;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            // Calculate n and F
            int n, F, d, m = -1;
            n = p * q;
            F = (p - 1) * (q - 1);
            // Calculate the private key exponent d
            for (d = 0; d < n; d++)
            {
                if (d * e % F == 1)
                    break;
            }
            // Decrypt the cipher text using the private key
            for (int i = 0; i < d; i++)
            {
                if (i == 0)
                {
                    m = C % n;
                }
                else
                {
                    m = (m * C) % n;
                }
            }
            return m;
        }



    }


}
