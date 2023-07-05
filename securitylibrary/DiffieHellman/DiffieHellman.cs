using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            // to store the resulting keys
            List<int> keys = new List<int>();

            // Calculate public keys of parties A and B
            int ya = ModularExponentiation(alpha, xa, q);
            int yb = ModularExponentiation(alpha, xb, q);

            // Calculate shared secret keys
            int sharedKeyA = ModularExponentiation(yb, xa, q);
            int sharedKeyB = ModularExponentiation(ya, xb, q);

            // Add the shared secret keys to the list of keys
            keys.Add(sharedKeyA);
            keys.Add(sharedKeyB);

            return keys;
        }

        // Calculates the modular exponentiation of the base raised to the power modulo the modulus.
        private int ModularExponentiation(int baseValue, int power, int modValue)
        {
            int result = 1;
            baseValue = baseValue % modValue;

            while (power > 0)
            {
                if (power % 2 == 1)
                {
                    result = (result * baseValue) % modValue;
                }
                baseValue = (baseValue * baseValue) % modValue;
                power = power / 2;
            }

            return result;
        }
    }
}