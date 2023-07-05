using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            // Divide the length of the plaintext by 2 to get the length of each segment
            int x = plainText.Count / 2;

            // Initialize arrays to store values
            int[,] pt = new int[2, 1]; // plaintext
            int[,] rowKey = new int[1, 2]; // row key
            int[,] key = new int[2, 2]; // key
            int cnt = 0, ind = 0; // counters

            // Loop through all possible pairs of letters in the English alphabet
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    // Initialize ciphertext array with length x
                    int[,] ct = new int[1, x];
                    int count;

                    // Set the row key to the current pair of letters
                    rowKey[0, 0] = i; rowKey[0, 1] = j;

                    // Get the ciphertext for the current row key and plaintext
                    ct = GetCT2(rowKey, plainText, x);

                    // Count the number of matches between the ciphertext and the even-indexed characters of the cipherText array
                    count = 0;
                    for (int a = 0, b = ind; a < x; a++, b += 2)
                    {
                        if (ct[0, a] == cipherText[b])
                            count++;
                    }

                    // If all even-indexed characters match, store the row key in the key array
                    if (count == x)
                    {
                        key[cnt, 0] = rowKey[0, 0];
                        key[cnt, 1] = rowKey[0, 1];
                        cnt++;
                        ind++;
                        break;
                    }

                    // Set the row key to the current pair of letters reversed
                    rowKey[0, 0] = j; rowKey[0, 1] = i;

                    // Get the ciphertext for the reversed row key and plaintext
                    ct = GetCT2(rowKey, plainText, x);

                    // Count the number of matches between the ciphertext and the even-indexed characters of the cipherText array
                    count = 0;
                    for (int a = 0, b = ind; a < x; a++, b += 2)
                    {
                        if (ct[0, a] == cipherText[b])
                            count++;
                    }

                    // If all even-indexed characters match, store the reversed row key in the key array
                    if (count == x)
                    {
                        key[cnt, 0] = rowKey[0, 0];
                        key[cnt, 1] = rowKey[0, 1];
                        cnt++;
                        ind++;
                        break;
                    }
                }

                // If we have found two matching row keys, break out of the loop
                if (cnt == 2)
                    break;
            }

            // If we have not found two matching row keys, throw an exception
            if (cnt != 2)
            {
                throw new InvalidAnlysisException();
            }

            // Combine the row keys into a single list and return it
            List<int> finalList = new List<int>();
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    finalList.Add(key[i, j]);
                }
            }
            return finalList;
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            // Initialize variables and arrays
            List<int> plainText = new List<int>();
            int m = 0;

            // Determine matrix size based on length of key
            if (key.Count == 4)
            {
                m = 2;
            }
            else
            {
                m = 3;
            }

            int[,] k = new int[m, m]; // key matrix
            int[,] invK = new int[m, m]; // inverse key matrix
            int[,] ct = new int[m, 1]; // ciphertext matrix
            int cnt = 0; // counter

            // Fill key matrix with values from key list
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    k[i, j] = key[cnt++];
                }
            }

            // Find inverse key matrix using FindInvKey function
            int[,] invKey = FindInvKey(k);

            // If the inverse key matrix has length 1, throw an exception
            if (invKey.Length == 1)
            {
                throw new Exception();
            }

            // Loop through ciphertext in blocks of size m
            for (int i = 0; i < cipherText.Count; i += m)
            {
                // Fill ciphertext matrix with values from ciphertext list
                for (int j = i, x = 0; j < i + m; j++, x++)
                {
                    ct[x, 0] = cipherText[j];
                }

                // Multiply inverse key matrix by ciphertext matrix to get plaintext matrix
                int[,] pt = MatrixMutliplication(invKey, ct, m, m, 1);

                // Add plaintext values to plaintext list
                for (int a = 0; a < m; a++)
                {
                    plainText.Add(pt[a, 0]);
                }
            }

            // Return plaintext list
            return plainText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            // Initialize variables and arrays
            List<int> cipherText = new List<int>();
            int m = 0;

            // Determine matrix size based on length of key
            if (key.Count == 4)
            {
                m = 2;
            }
            else
            {
                m = 3;
            }

            int[,] k = new int[m, m]; // key matrix
            int[,] pt = new int[m, 1]; // plaintext matrix
            int cnt = 0; // counter

            // Fill key matrix with values from key list
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    k[i, j] = key[cnt++];
                }
            }

            // Loop through plaintext in blocks of size m
            for (int i = 0; i < plainText.Count; i += m)
            {
                // Fill plaintext matrix with values from plaintext list
                for (int j = i, x = 0; j < i + m; j++, x++)
                {
                    pt[x, 0] = plainText[j];
                }

                // Multiply key matrix by plaintext matrix to get ciphertext matrix
                int[,] ct = MatrixMutliplication(k, pt, m, m, 1);

                // Add ciphertext values to ciphertext list
                for (int a = 0; a < m; a++)
                {
                    cipherText.Add(ct[a, 0]);
                }
            }

            // Return ciphertext list
            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            // Determine the number of blocks of size 3 in the plaintext
            int x = plainText.Count / 3;

            // Initialize variables and arrays
            int[,] pt = new int[3, 1]; // plaintext matrix
            int[,] rowKey = new int[1, 3]; // row key matrix
            int[,] key = new int[3, 3]; // final key matrix
            int cnt = 0, ind = 0; // counters

            // Loop through all possible combinations of row keys
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        // Try each row key combination and check if it produces the correct ciphertext
                        int[,] ct = new int[1, x];
                        rowKey[0, 0] = i; rowKey[0, 1] = j; rowKey[0, 2] = k;
                        ct = GetCT(rowKey, plainText, x);
                        int count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {
                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {
                            // If the row key produces the correct ciphertext, add it to the final key matrix
                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }

                        // Try other permutations of the row key and check if they produce the correct ciphertext
                        rowKey[0, 0] = i; rowKey[0, 1] = k; rowKey[0, 2] = j;
                        ct = GetCT(rowKey, plainText, x);
                        count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {
                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {
                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }
                        rowKey[0, 0] = j; rowKey[0, 1] = i; rowKey[0, 2] = k;
                        ct = GetCT(rowKey, plainText, x);
                        count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {
                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {
                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }
                        rowKey[0, 0] = j; rowKey[0, 1] = k; rowKey[0, 2] = i;
                        ct = GetCT(rowKey, plainText, x);
                        count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {
                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {
                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }
                        rowKey[0, 0] = k; rowKey[0, 1] = i; rowKey[0, 2] = j;
                        ct = GetCT(rowKey, plainText, x);
                        count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {
                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {
                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }
                        rowKey[0, 0] = k; rowKey[0, 1] = j; rowKey[0, 2] = i;
                        ct = GetCT(rowKey, plainText, x);
                        count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {
                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {
                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }

                        // If three valid row keys have been found, exit the loop
                        if (cnt == 3)
                            break;
                    }
                    if (cnt == 3)
                        break;
                }
                if (cnt == 3)
                    break;
            }

            // If three valid row keys were not found, throw an exception
            if (cnt != 3)
            {
                throw new InvalidAnlysisException();
            }

            // Convert the key matrix to a list and return it
            List<int> finalList = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    finalList.Add(key[i, j]);
                }
            }
            return finalList;
        }

        //Helper functions
        public int[,] MatrixMutliplication(int[,] a, int[,] b, int row1, int col1, int col2)
        {
            int[,] result = new int[row1, col2];

            for (int i = 0; i < row1; i++)
            {
                for (int j = 0; j < col2; j++)
                {
                    for (int x = 0; x < col1; x++)
                    {
                        result[i, j] += (a[i, x] * b[x, j]);
                    }
                    result[i, j] %= 26;
                }
            }
            return result;
        }


        public int[,] GetCT(int[,] rowKey, List<int> plainText, int x)
        {
            int[,] ct = new int[1, x];
            int[,] pt = new int[3, 1];
            for (int z = 0, t = 0; z < plainText.Count; z += 3, t++)
            {
                pt[0, 0] = plainText[z];
                pt[1, 0] = plainText[z + 1];
                pt[2, 0] = plainText[z + 2];
                int[,] res = MatrixMutliplication(rowKey, pt, 1, 3, 1);
                ct[0, t] = res[0, 0];
            }
            return ct;
        }


        public int[,] GetCT2(int[,] rowKey, List<int> plainText, int x)
        {
            int[,] ct = new int[1, x];
            int[,] pt = new int[2, 1];
            for (int z = 0, t = 0; z < plainText.Count; z += 2, t++)
            {
                pt[0, 0] = plainText[z];
                pt[1, 0] = plainText[z + 1];

                int[,] res = MatrixMutliplication(rowKey, pt, 1, 2, 1);
                ct[0, t] = res[0, 0];
            }
            return ct;
        }

        public int[,] FindInvKey(int[,] key)
        {
            int[,] errorMatrix = new int[1, 1];
            int det = FindDet(key);
            if (det > 0)
                det %= 26;
            else
                det = (det % 26) + 26;

            // Check that det and 26 are coprime
            if (GCD(det, 26) != 1)
                return errorMatrix;

            // Get the Modular multiplicative inverse of det(k)
            int b = ModularMultiplicativeInverse(det, 26);
            if (b == -1)
                return errorMatrix;

            // Get the inverse key if the matrix is 2*2
            if (key.Length == 4)
            {
                int x = 1 / (key[0, 0] * key[1, 1] - key[0, 1] * key[1, 0]);
                int[,] inv = new int[2, 2];
                inv[0, 0] = (key[1, 1] * x) % 26;
                inv[1, 1] = (key[0, 0] * x) % 26;
                inv[0, 1] = (-1 * key[0, 1] * x) % 26;
                inv[1, 0] = (-1 * key[1, 0] * x) % 26;
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        if (inv[i, j] < 0)
                        {
                            inv[i, j] += 26;
                        }
                    }
                }
                return inv;
            }

            // Get the inverse key if the matrix is 3*3
            int[,] invKey = new int[3, 3];

            invKey[0, 0] = (b * (int)Math.Pow((int)-1, (int)0) * ((key[1, 1] * key[2, 2] - key[1, 2] * key[2, 1]) % 26)) % 26;
            invKey[0, 1] = (b * (int)Math.Pow((int)-1, (int)1) * ((key[1, 0] * key[2, 2] - key[1, 2] * key[2, 0]) % 26)) % 26;
            invKey[0, 2] = (b * (int)Math.Pow((int)-1, (int)2) * ((key[1, 0] * key[2, 1] - key[1, 1] * key[2, 0]) % 26)) % 26;

            invKey[1, 0] = (b * (int)Math.Pow((int)-1, (int)1) * ((key[0, 1] * key[2, 2] - key[0, 2] * key[2, 1]) % 26)) % 26;
            invKey[1, 1] = (b * (int)Math.Pow((int)-1, (int)2) * ((key[0, 0] * key[2, 2] - key[0, 2] * key[2, 0]) % 26)) % 26;
            invKey[1, 2] = (b * (int)Math.Pow((int)-1, (int)3) * ((key[0, 0] * key[2, 1] - key[0, 1] * key[2, 0]) % 26)) % 26;

            invKey[2, 0] = (b * (int)Math.Pow((int)-1, (int)2) * ((key[0, 1] * key[1, 2] - key[0, 2] * key[1, 1]) % 26)) % 26;
            invKey[2, 1] = (b * (int)Math.Pow((int)-1, (int)3) * ((key[0, 0] * key[1, 2] - key[0, 2] * key[1, 0]) % 26)) % 26;
            invKey[2, 2] = (b * (int)Math.Pow((int)-1, (int)4) * ((key[0, 0] * key[1, 1] - key[0, 1] * key[1, 0]) % 26)) % 26;

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (invKey[i, j] < 0)
                        invKey[i, j] += 26;
                }
            }

            int[,] finalInvKey = new int[3, 3];
            for (int j = 0; j < 3; j++)
            {
                for (int i = 0; i < 3; i++)
                {
                    finalInvKey[j, i] = invKey[i, j];
                }
            }


            return finalInvKey;
        }


        public int FindDet(int[,] matrix)
        {
            int det = 0;
            if (matrix.Length == 4)
            {
                det = (matrix[0, 0] * matrix[1, 1]) - (matrix[0, 1] * matrix[1, 0]);
            }
            else
            {
                det = matrix[0, 0] * (matrix[1, 1] * matrix[2, 2] - matrix[1, 2] * matrix[2, 1]) - matrix[0, 1] * (matrix[1, 0] * matrix[2, 2] - matrix[1, 2] * matrix[2, 0]) + matrix[0, 2] * (matrix[1, 0] * matrix[2, 1] - matrix[1, 1] * matrix[2, 0]);
            }
            return det;
        }

        public int GCD(int a, int b)
        {
            if (b == 0)
                return a;

            int rem = a % b;
            return GCD(b, rem);
        }


        public int ModularMultiplicativeInverse(int a, int m)
        {
            int b = -1;
            for (int i = 0; i < m; i++)
            {
                if ((i * a) % 26 == 1)
                {
                    return i;
                }
            }
            return b;
        }

    }
}