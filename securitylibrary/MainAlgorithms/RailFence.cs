using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {


            string newCT = cipherText.ToLower();
            string PT = plainText;
            int newKey = 2;
            for (int i = 0; i < PT.Length / 2; i++)
            {
                if (PT[i] != newCT[i])
                {
                    PT = PT.Remove(i, 1);
                    newKey++;
                }
                if (PT[i] == newCT[i])
                {
                    PT = PT.Remove(i + 1, 1);
                }
                if (PT[0] == newCT[0] && PT[1] == newCT[1])
                    break;
            }
            return newKey;


        }

        public string Decrypt(string cipherText, int key1)
        {
            string PT = cipherText;
            int key = key1;

            char[] chararr = PT.ToCharArray();
            int result = PT.Length / key;
            int count = 1;
            string dec = "";
            if (PT.Length % result != 0)
            {
                result++;
            }
            char[] matrices = new char[PT.Length];
            int k = 0;
            for (int i = 0; i < PT.Length; i++)

            {

                if (k >= PT.Length)
                {
                    k = count;
                    count++;

                    if (count > result)
                    {
                        break;
                    }

                }
                matrices[i] = chararr[k];
                k += result;
                Console.Write(matrices[i]);
                dec += matrices[i];

            }


            return dec;
        }

        public string Encrypt(string plainText, int key1)
        {
            string PT = plainText;
            int key = key1;
            char[] chararr = PT.ToCharArray();
            int result = PT.Length / key;
            int count = 1;
            if (PT.Length % result != 0)
            {
                result++;
            }
            char[] matrices = new char[PT.Length];
            int k = 0;
            string enc = "";
            for (int i = 0; i < PT.Length; i++)
            {

                if (k >= PT.Length)
                {
                    k = count;
                    count++;

                    if (count > key)
                    {
                        break;
                    }

                }
                matrices[i] = chararr[k];
                k += key;
                enc += matrices[i];
                Console.Write(matrices[i]);


            }
            return enc;
            
        }
    }
}
