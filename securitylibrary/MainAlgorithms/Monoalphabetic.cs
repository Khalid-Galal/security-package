using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            SortedDictionary<char, char> corospoding = new SortedDictionary<char, char>();
            Dictionary<char, bool> checkChar = new Dictionary<char, bool>();
            List<char> chaar = new List<char> { 'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z'};
            string keyy = "";
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            for (int c = 0; c < plainText.Length; c++)
            {
                if (!corospoding.ContainsKey(plainText[c]))
                {
                    corospoding.Add(plainText[c], cipherText[c]);
                    checkChar.Add(cipherText[c], true);
                }
            }
            if (corospoding.Count != 26)
            {
                int i, j;
                for (i = 0; i < 26; i++)
                {
                    if (!corospoding.ContainsKey(chaar[i]))
                    {
                        for (j = 0; j < 26; j++)
                        {
                            if (!checkChar.ContainsKey(chaar[j]))
                            {
                                checkChar.Add(chaar[j], true);
                                corospoding.Add(chaar[i], chaar[j]);
                                break;
                            }
                        }
                    }
                }
            }
            foreach (var item in corospoding)
            {
                keyy = keyy + item.Value;
            }

            return keyy;
        }

        public string Decrypt(string cipherText, string key)
        {
            IDictionary<char, char> corospoding = new Dictionary<char, char>();
            List<char> chaar = new List<char> { 'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z'};
            cipherText = cipherText.ToLower();
            for (int c = 0; c < 26; c++)
            {
                corospoding.Add(key[c], chaar[c]);
            }
            string pt = "";
            for (int x = 0; x < cipherText.Length; x++)
            {
                pt = pt + corospoding[cipherText[x]];
            }
            return pt;
        }

        public string Encrypt(string plainText, string key)
        {
            IDictionary<char, char> corospoding = new Dictionary<char, char>();
            List<char> chaar = new List<char> { 'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z'};
            for (int c = 0; c < 26; c++)
            {
                corospoding.Add(chaar[c], key[c]);
            }
            string ct = "";
            for (int x = 0; x < plainText.Length; x++)
            {
                ct = ct + corospoding[plainText[x]];
            }
            return ct;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            SortedDictionary<char, char> corresponding = new SortedDictionary<char, char>();
            Dictionary<char, int> alphabetFrequency = new Dictionary<char, int>();

            cipher = cipher.ToLower();
            string letters = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();

            for (int j = 0; j < cipher.Length; j++)
            {
                if (!alphabetFrequency.ContainsKey(cipher[j]))
                    alphabetFrequency.Add(cipher[j], 0);
                else
                    alphabetFrequency[cipher[j]]++;
            }
            alphabetFrequency = alphabetFrequency.OrderBy(x => x.Value).Reverse().ToDictionary(x => x.Key, x => x.Value);
            int n = 0;
            foreach (var x in alphabetFrequency)
            {
                corresponding.Add(x.Key, letters[n]);
                n++;
            }
            string plaintext = "";
            for (int i = 0; i < cipher.Length; i++)
            {
                plaintext = plaintext + corresponding[cipher[i]];
            }
            return plaintext;
        }
    }
}