using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            for (int i = 0; i < plainText.Length; i++)
            {
                int p = plainText[i] - 97;
                int c = cipherText[i] - 97;
                if (cipherText[i] - plainText[i] < 0)
                {
                    key += Convert.ToChar((((c - p) + 26) % 26) + 97);
                }
                else
                {
                    key += Convert.ToChar(((c - p) % 26) + 97);

                }
            }

            // remove repeated part
            int keyEnd = -1;
            string firstPart;
            string secondPart;
            for (int j = 0; j < key.Length; j++)
            {
                if (j * 2 + 2 < key.Length)
                {
                    firstPart = key.ToString().Substring(0, j + 1);
                    secondPart = key.ToString().Substring(j + 1, j + 1);
                    if (firstPart.Equals(secondPart))
                    {
                        keyEnd = j;
                    }
                }
                else break;
            }
            string newKey = "";
            if (keyEnd < 0)
            {
                newKey = key.ToString();
            }
            else
            {
                newKey = key.ToString().Substring(0, keyEnd + 1);
            }

            //string newKey = "";
            //int add = 0, k;
            //for (k = 0; k < key.Length; k++)
            //{
            //    if (key[k] == key[add] && key[k + 1] == key[add + 1])
            //    {
            //        break;
            //    }
            //}
            //for (int j = 0; j < k; j++)
            //{
            //    newKey += key[j];
            //}


            return newKey;


            // return keyee;
            // throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string plantext = "";
            int j = 0;
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                int p = cipherText[i] - 97;
                int k = key[j] - 97;

                if (cipherText[i] - key[j] < 0)
                {
                    plantext += Convert.ToChar((((p - k) + 26) % 26) + 97);
                }
                else
                {
                    plantext += Convert.ToChar(((p - k) % 26) + 97);

                }
                // plantext += Convert.ToChar(((p - k) % 26) + 97);
                j = (j + 1) % key.Length;

            }

            return plantext;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            string chiperText = "";
            int j = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                int p = plainText[i] - 97;
                int k = key[j] - 97;
                chiperText += Convert.ToChar(((p + k) % 26) + 97);
                j = (j + 1) % key.Length;

            }
            // throw new NotImplementedException();
            return chiperText;

        }
    }
}