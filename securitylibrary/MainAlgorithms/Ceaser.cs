using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            Dictionary<char, int> plan = new Dictionary<char, int>();
            Dictionary<int, char> revplan = new Dictionary<int, char>();
            string cipherText = "";
            int i = 0;
            for (char ind = 'a'; ind <= 'z'; ind++)
            {

                plan.Add(ind, i);
                revplan.Add(i, ind);
                i++;
            }
            foreach (char p in plainText.ToLower())
            {
                cipherText += revplan[((plan[p] + key) % 26)];

            }
            //throw new NotImplementedException();

            return cipherText.ToUpper();

        }

        public string Decrypt(string cipherText, int key)
        {
            Dictionary<char, int> plan = new Dictionary<char, int>();
            Dictionary<int, char> revplan = new Dictionary<int, char>();
            string planText = "";
            int i = 0;
            for (char ind = 'a'; ind <= 'z'; ind++)
            {
                plan.Add(ind, i);
                revplan.Add(i, ind);
                i++;
            }
            foreach (char p in cipherText.ToLower())
            {
                //planText += revplan[((plan[p] - key) % 26)];
                int ciind = (plan[p] - key) % 26;
                if (ciind < 0)
                {
                    ciind += 26;
                }
                planText += revplan[ciind];
            }

            return planText.ToUpper();
            // throw new NotImplementedException();
        }

        public int Analyse(string plainText, string cipherText)
        {
            Dictionary<char, int> P = new Dictionary<char, int>();
            Dictionary<int, char> d = new Dictionary<int, char>();
            int cnt = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                P[c] = cnt;
                d[cnt] = c;
                cnt++;
            }
            int key = 0;
            for (int k = 0; k < 26; k++)
            {
                string Hack = "";
                for (int i = 0; i < plainText.Length; i++)
                {
                    if (P[cipherText.ToLower()[i]] == ((P[plainText[i]] + k) % 26))
                    {
                        Hack += d[((P[plainText[i]] + k) % 26)];
                    }
                }
                if (Hack == cipherText.ToLower())
                {
                    key = k;
                    break;
                }
            }
            return key;
        }
        //throw new NotImplementedException();
    }
}

