using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{



    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        /// 



        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int a1 = 1, a2 = 0, a3 = baseN, b1 = 0, b2 = 1, b3 = number, Q, B1, B2, B3;
            while (true)
            {

                if (b3 == 0)
                {
                    return -1;//no result
                }
                else if (b3 == 1)
                {
                    if (b2 < 0)
                    {
                        b2 += 26;
                    }
                    return b2;
                }
                Q = a3 / b3;
                B1 = a1 - Q * b1;
                B2 = a2 - Q * b2;
                B3 = a3 - Q * b3;
                a1 = b1;
                a2 = b2;
                a3 = b3;
                b1 = B1;
                b2 = B2;
                b3 = B3;

            }



            //throw new NotImplementedException();
        }
    }
}