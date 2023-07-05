using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string chars = "abcdefghijklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();
            string newkey = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                newkey += chars[((chars.IndexOf(cipherText[i]) - chars.IndexOf(plainText[i])) + 26) % 26];
            }
            string temp = "";
            temp = temp + newkey[0];
            for (int j = 1; j < newkey.Length; j++)
            {
                if (cipherText.Equals(Encrypt(plainText, temp)))
                {
                    return temp;
                }
                temp += newkey[j];
            }
            return newkey;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string newkey = "";
            string chars = "abcdefghijklmnopqrstuvwxyz";
            newkey = key;
            int x = 0;
            while (newkey.Length != cipherText.Length)
            {
                newkey += chars[((cipherText[x] - newkey[x]) + 26) % 26];
                x++;
            }
            string plain = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                plain += chars[((chars.IndexOf(cipherText[i]) - chars.IndexOf(newkey[i])) + 26) % 26];
            }
            return plain;
        }

        public string Encrypt(string plainText, string key)
        {

            string newkey = "";
            string chars = "abcdefghijklmnopqrstuvwxyz";
            newkey = key;
            int x = 0;
            while (newkey.Length != plainText.Length)
            {
                newkey += plainText[x];
                x++;
            }
            string ciphertext = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                ciphertext += chars[((chars.IndexOf(plainText[i]) + chars.IndexOf(newkey[i]))) % 26];
            }
            return ciphertext;
        }
    }
}
