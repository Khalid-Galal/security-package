using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToUpper();
            int pt_len = plainText.Length;
            cipherText = cipherText.ToUpper();
            int ct_len = cipherText.Length;
            int columm = 1;
            for (int i = 0; i < pt_len; i++)
            {
                for (int j = 0; j < ct_len; j++)
                {
                    int ct = cipherText[i];
                    int pt = plainText[j];

                    if (ct == pt)
                    {
                        for (int k = j + 1; k < ct_len; k++)
                        {

                            int new_i = i + 1;
                            int p = plainText[k];
                            if (p == cipherText[new_i])
                            {
                                break;
                            }
                            else
                            {

                                columm += 1;
                            }

                        }
                    }
                    if (columm <= 1) continue;
                    else break;
                }
                if (columm <= 1) continue;
                else break;
            }
            //////////////////
            int dif = -1;
            int row = ct_len / columm;
            if (ct_len % columm != 0)
            {
                int ct_temp = ct_len;
                row++;
                do
                {
                    if (ct_temp % columm != 0)
                    {
                        dif++;
                        ct_temp++;
                    }


                } while (ct_temp % columm != 0);
            }

            ///////////////////////////////
            List<int> indx = new List<int>();
            int idx = 1;
            for (int i = 0; i < ct_len; i += row)
            {
                bool flag = false;
                for (int j = 0; j < columm; j++)
                {

                    int ct = cipherText[i];
                    int pt = plainText[j];
                    if (pt == ct && i < ct_len - 1)
                    {
                        if (plainText[j + columm] == cipherText[i + 1] && !indx.Contains(j))
                        {
                            flag = true;
                            indx.Add(j);
                            idx++;
                            break;
                        }
                    }
                    else if (plainText[j + columm] == ct && !indx.Contains(j))
                    {
                        if (i > 0 && pt == cipherText[i - 1])
                        {
                            flag = true;
                            indx.Add(j);
                            idx++;
                            break;
                        }
                    }
                }

                if (!flag)
                {
                    for (int j = 0; j < columm; j++)
                    {
                        int p = plainText[j];
                        if (cipherText[i - dif] == p && !indx.Contains(j))
                        {
                            if (plainText[j + columm] == cipherText[i - dif + 1])
                            {
                                indx.Add(j);
                                idx++;
                                if (flag == true) break;
                                else continue;
                            }
                        }
                    }
                }
            }


            List<int> keys = new List<int>();

            for (int i = 0; i < columm; i++)
            {
                for (int j = 0; j < columm; j++)
                {
                    if (indx[j] != i)
                    {

                        continue;
                    }
                    else
                    {
                        keys.Add(j + 1);
                        break;
                    }

                }
            }
            return keys;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int n = key.Count;
            int m = (int)Math.Ceiling((double)cipherText.Length / n);

            // Fill the matrix with space character
            char[,] matrix = new char[m, n];
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    matrix[i, j] = ' ';
                }
            }

            // Fill the matrix with cipherText characters
            int k = 0;
            for (int j = 0; j < n; j++)
            {
                int index = key.IndexOf(j + 1);
                for (int i = 0; i < m; i++)
                {
                    if (k < cipherText.Length)
                    {
                        matrix[i, index] = cipherText[k];
                        k++;
                    }
                }
            }

            // Extract the plainText from the matrix
            string plainText = "";
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    if (matrix[i, j] != ' ')
                    {
                        plainText += matrix[i, j];
                    }
                }
            }

            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string ct = "";
            int col = key.Count;
            int pt_len = plainText.Length;
            int rows = plainText.Length / col;
            List<List<char>> mtrx = new List<List<char>>();

            // add x in free spaces 
            if (pt_len != rows * col)
            {
                rows = rows + 1;
                int x = (rows * col) - plainText.Length;
                string add_x = new string('x', x);
                plainText += add_x;
            }

            // add plain text to matrix 
            int c = 0;
            for (int i = 0; i < rows; i++)
            {
                mtrx.Add(new List<char>());
                for (int j = 0; j < col; j++)
                {
                    mtrx[i].Add(plainText[c]);
                    c++;
                }
            }

            // characters in column for each key
            Dictionary<int, string> cip = new Dictionary<int, string>();
            for (int i = 0; i < col; i++)
            {
                string temp = "";
                for (int j = 0; j < rows; j++)
                {
                    temp += mtrx[j][i];
                }
                cip[key[i]] = temp;
            }

            // combine cipher text
            for (int i = 1; i <= cip.Count; i++)
            {
                ct += cip[i];
            }

            return ct;
        }
    }
}
