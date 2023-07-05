using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        static string searchIn(int x1, int x2, int y1, int y2, char[,] matrix, char a, char b)
        {
            string s = "";
            //in the same row 
            if (x1 == x2)
            {
                //Console.WriteLine("the first one is " + matrix[x1, (y1 + 1) % 5]);
                //Console.WriteLine("the first one is " + matrix[x1, (y2 + 1) % 5]);
                s += matrix[x1, (y1 + 1) % 5];
                s += matrix[x1, (y2 + 1) % 5];
            }
            //in the same foken colmun
            if (y1 == y2)
            {
                //Console.WriteLine("the first one is " + matrix[(x1 + 1) % 5, y1]);
                //Console.WriteLine("the first one is " + matrix[(x2 + 1) % 5, y2]);
                s += matrix[(x1 + 1) % 5, y1];
                s += matrix[(x2 + 1) % 5, y2];
            }
            //msh 3arfen ba3d
            if (x1 != x2 && y1 != y2)
            {
                //Console.WriteLine("the first one is " + matrix[x1, y2]);
                //Console.WriteLine("the first one is " + matrix[x2, y1]);
                s += matrix[x1, y2];
                s += matrix[x2, y1];
            }

            return s;

        }
        static String removeDuplicate(char[] str, int n)
        {
            // Used as index in the modified string
            int index = 0;

            // Traverse through all characters
            for (int i = 0; i < n; i++)
            {

                // Check if str[i] is present before it
                int j;
                for (j = 0; j < i; j++)
                {
                    if (str[i] == str[j])
                    {
                        break;
                    }
                }

                if (j == i)
                {
                    str[index++] = str[i];
                }
            }
            char[] ans = new char[index];
            Array.Copy(str, ans, index);
            return String.Join("", ans);
        }
        static void print(char[,] matrix)
        {
            ////display array

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    Console.Write(matrix[i, j] + " ");
                }
                Console.WriteLine();
            }
        }
        static string handlingPT(string PT)
        {

            for (int i = 0; i < PT.Length - 1; i += 2)
            {
                if (i == PT.Length - 1)
                {
                    PT = PT + 'x';
                }
                else if (PT[i] == PT[i + 1])
                {
                    PT = PT.Substring(0, i + 1) + 'x' + PT.Substring(i + 1);
                }

            }
            if (PT.Length % 2 != 0)
                PT += 'x';
         
            return PT;
        }
        //create the matrix
        static char[,] create(string st)
        {
            
            int x = st.Length;
            int k = 0;
            char[,] matrix = new char[5, 5];
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (x > k)
                    {
                        matrix[i, j] = st[k];
                        k++;
                    }
                }
            }
            return matrix;
        }
        static int[] search(char a, char b, char[,] matrix)
        {
            int x1 = 0;
            int x2 = 0;
            int y1 = 0;
            int y2 = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[i, j] == a)
                    {
                        x1 = i;
                        y1 = j;

                    }
                    if (matrix[i, j] == b)
                    {
                        x2 = i;
                        y2 = j;
                    }
                }
            }
            int[] arr = { x1, x2, y1, y2 };
            return arr;
        }
        static string Dyc(int x1, int x2, int y1, int y2, char[,] matrix, char a, char b)
        {
            string s = "";
            //in the same row 
            if (x1 == x2)
            {
                s += matrix[x1, (y1 - 1 + 5) % 5];
                s += matrix[x1, (y2 - 1 + 5) % 5];


            }
            //in the same 
            if (y1 == y2)
            {
                s += matrix[(x1 - 1 + 5) % 5, y1];
                s += matrix[(x2 - 1 + 5) % 5, y2];


            }
            //msh 3arfen ba3d
            if (x1 != x2 && y1 != y2)
            {
                s += matrix[x1, y2];
                s += matrix[x2, y1];

            }

            return s;

        }
        static string decripton(String CT, String key)
        {
            String PT = "";
            String alp = "abcdefghiklmnopqrstuvwxyz";
            
            CT = CT.ToLower();
            key = key.ToLower() + alp ;
            char[]newkey=key.ToCharArray();
            key=removeDuplicate(newkey, key.Length);
            int[] arr;
            char[,] matrix1 = new char[5, 5];
            matrix1 = create(key);
            print(matrix1);
            for (int i = 0; i < CT.Length; i += 2)
            {

                char a = CT[i];
                char b = CT[i + 1];
                arr = search(a, b, matrix1);
                PT += Dyc(arr[0], arr[1], arr[2], arr[3], matrix1, a, b);

            }
            if (PT[PT.Length - 1] == 'x')
            {
                PT = PT.Substring(0, PT.Length - 1);
            }
            for (int i = 0; i < PT.Length - 1; i += 2)
            {
                if (PT[i + 1] == 'x' && PT[i] == PT[i + 2])
                {
                    PT = PT.Substring(0, i + 1) + PT.Substring(i + 2);
                    i--;
                }
            }

            // Console.WriteLine("the CT text is: " + CT);
            //Console.WriteLine("the plain text is: " + PT);
            return PT;
        }

        public string Decrypt(string cipherText, string key)
        {
            String plain;
            plain= decripton(cipherText, key);
            return plain;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {

            String alp = "abcdefghiklmnopqrstuvwxyz";
            String PT = plainText;
            char[,] matrix = new char[5, 5];
            String str = key;
            str += alp;
            char[] allname = str.ToCharArray();
            int n = allname.Length;
            string st = removeDuplicate(allname, n);
            string s = handlingPT(PT);
            Console.WriteLine(s);
            matrix = create(st);
            int[] arr;
            string hamedoo = "";
            for (int i = 0; i < s.Length; i +=2)
            {
                char a = s[i];
                char b = s[i + 1];
                arr = search(a, b, matrix);
                hamedoo += searchIn(arr[0], arr[1], arr[2], arr[3], matrix, a, b);
            }
            Console.WriteLine(hamedoo);
            //string ct = "";
            return hamedoo.ToUpper();
        }
    }
}