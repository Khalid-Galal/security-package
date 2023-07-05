using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        private static Dictionary<char, string> HToB_Dictionery = new Dictionary<char, string> { { '0', "0000" }, { '1', "0001" }, { '2', "0010" }, { '3', "0011" }, { '4', "0100" }, { '5', "0101" }, { '6', "0110" }, { '7', "0111" }, { '8', "1000" }, { '9', "1001" }, { 'a', "1010" }, { 'b', "1011" }, { 'c', "1100" }, { 'd', "1101" }, { 'e', "1110" }, { 'f', "1111" } };
        private static Dictionary<string, char> BToH_Dictionery = new Dictionary<string, char> { { "0000", '0' }, { "0001", '1' }, { "0010", '2' }, { "0011", '3' }, { "0100", '4' }, { "0101", '5' }, { "0110", '6' }, { "0111", '7' }, { "1000", '8' }, { "1001", '9' }, { "1010", 'a' }, { "1011", 'b' }, { "1100", 'c' }, { "1101", 'd' }, { "1110", 'e' }, { "1111", 'f' } };


        string[,] myS_box = new string[,] { { " ", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" }, { "0", "63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76" }, { "1", "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0" }, { "2", "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15" }, { "3", "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75" }, { "4", "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84" }, { "5", "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf" }, { "6", "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8" }, { "7", "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2" }, { "8", "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73" }, { "9", "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db" }, { "a", "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79" }, { "b", "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08" }, { "c", "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a" }, { "d", "70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e" }, { "e", "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df" }, { "f", "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16" } };
        static string[,] Inv_S_box = new string[,] { { " ", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" }, { "0", "52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb" }, { "1", "7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb" }, { "2", "54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e" }, { "3", "08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25" }, { "4", "72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92" }, { "5", "6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84" }, { "6", "90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06" }, { "7", "d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b" }, { "8", "3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73" }, { "9", "96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e" }, { "a", "47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b" }, { "b", "fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4" }, { "c", "1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f" }, { "d", "60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef" }, { "e", "a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61" }, { "f", "17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d" } };
        string[,] T_14 = new string[,] { { " ", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" }, { "0", "00", "0e", "1c", "12", "38", "36", "24", "2a", "70", "7e", "6c", "62", "48", "46", "54", "5a" }, { "1", "e0", "ee", "fc", "f2", "d8", "d6", "c4", "ca", "90", "9e", "8c", "82", "a8", "a6", "b4", "ba" }, { "2", "db", "d5", "c7", "c9", "e3", "ed", "ff", "f1", "ab", "a5", "b7", "b9", "93", "9d", "8f", "81" }, { "3", "3b", "35", "27", "29", "03", "0d", "1f", "11", "4b", "45", "57", "59", "73", "7d", "6f", "61" }, { "4", "ad", "a3", "b1", "bf", "95", "9b", "89", "87", "dd", "d3", "c1", "cf", "e5", "eb", "f9", "f7" }, { "5", "4d", "43", "51", "5f", "75", "7b", "69", "67", "3d", "33", "21", "2f", "05", "0b", "19", "17" }, { "6", "76", "78", "6a", "64", "4e", "40", "52", "5c", "06", "08", "1a", "14", "3e", "30", "22", "2c" }, { "7", "96", "98", "8a", "84", "ae", "a0", "b2", "bc", "e6", "e8", "fa", "f4", "de", "d0", "c2", "cc" }, { "8", "41", "4f", "5d", "53", "79", "77", "65", "6b", "31", "3f", "2d", "23", "09", "07", "15", "1b" }, { "9", "a1", "af", "bd", "b3", "99", "97", "85", "8b", "d1", "df", "cd", "c3", "e9", "e7", "f5", "fb" }, { "a", "9a", "94", "86", "88", "a2", "ac", "be", "b0", "ea", "e4", "f6", "f8", "d2", "dc", "ce", "c0" }, { "b", "7a", "74", "66", "68", "42", "4c", "5e", "50", "0a", "04", "16", "18", "32", "3c", "2e", "20" }, { "c", "ec", "e2", "f0", "fe", "d4", "da", "c8", "c6", "9c", "92", "80", "8e", "a4", "aa", "b8", "b6" }, { "d", "0c", "02", "10", "1e", "34", "3a", "28", "26", "7c", "72", "60", "6e", "44", "4a", "58", "56" }, { "e", "37", "39", "2b", "25", "0f", "01", "13", "1d", "47", "49", "5b", "55", "7f", "71", "63", "6d" }, { "f", "d7", "d9", "cb", "c5", "ef", "e1", "f3", "fd", "a7", "a9", "bb", "b5", "9f", "91", "83", "8d" } };
        string[,] T_9 = new string[,] { { " ", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" }, { "0", "00", "09", "12", "1b", "24", "2d", "36", "3f", "48", "41", "5a", "53", "6c", "65", "7e", "77" }, { "1", "90", "99", "82", "8b", "b4", "bd", "a6", "af", "d8", "d1", "ca", "c3", "fc", "f5", "ee", "e7" }, { "2", "3b", "32", "29", "20", "1f", "16", "0d", "04", "73", "7a", "61", "68", "57", "5e", "45", "4c" }, { "3", "ab", "a2", "b9", "b0", "8f", "86", "9d", "94", "e3", "ea", "f1", "f8", "c7", "ce", "d5", "dc" }, { "4", "76", "7f", "64", "6d", "52", "5b", "40", "49", "3e", "37", "2c", "25", "1a", "13", "08", "01" }, { "5", "e6", "ef", "f4", "fd", "c2", "cb", "d0", "d9", "ae", "a7", "bc", "b5", "8a", "83", "98", "91" }, { "6", "4d", "44", "5f", "56", "69", "60", "7b", "72", "05", "0c", "17", "1e", "21", "28", "33", "3a" }, { "7", "dd", "d4", "cf", "c6", "f9", "f0", "eb", "e2", "95", "9c", "87", "8e", "b1", "b8", "a3", "aa" }, { "8", "ec", "e5", "fe", "f7", "c8", "c1", "da", "d3", "a4", "ad", "b6", "bf", "80", "89", "92", "9b" }, { "9", "7c", "75", "6e", "67", "58", "51", "4a", "43", "34", "3d", "26", "2f", "10", "19", "02", "0b" }, { "a", "d7", "de", "c5", "cc", "f3", "fa", "e1", "e8", "9f", "96", "8d", "84", "bb", "b2", "a9", "a0" }, { "b", "47", "4e", "55", "5c", "63", "6a", "71", "78", "0f", "06", "1d", "14", "2b", "22", "39", "30" }, { "c", "9a", "93", "88", "81", "be", "b7", "ac", "a5", "d2", "db", "c0", "c9", "f6", "ff", "e4", "ed" }, { "d", "0a", "03", "18", "11", "2e", "27", "3c", "35", "42", "4b", "50", "59", "66", "6f", "74", "7d" }, { "e", "a1", "a8", "b3", "ba", "85", "8c", "97", "9e", "e9", "e0", "fb", "f2", "cd", "c4", "df", "d6" }, { "f", "31", "38", "23", "2a", "15", "1c", "07", "0e", "79", "70", "6b", "62", "5d", "54", "4f", "46" } };
        string[,] T_11 = new string[,] { { " ", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" }, { "0", "00", "0b", "16", "1d", "2c", "27", "3a", "31", "58", "53", "4e", "45", "74", "7f", "62", "69" }, { "1", "b0", "bb", "a6", "ad", "9c", "97", "8a", "81", "e8", "e3", "fe", "f5", "c4", "cf", "d2", "d9" }, { "2", "7b", "70", "6d", "66", "57", "5c", "41", "4a", "23", "28", "35", "3e", "0f", "04", "19", "12" }, { "3", "cb", "c0", "dd", "d6", "e7", "ec", "f1", "fa", "93", "98", "85", "8e", "bf", "b4", "a9", "a2" }, { "4", "f6", "fd", "e0", "eb", "da", "d1", "cc", "c7", "ae", "a5", "b8", "b3", "82", "89", "94", "9f" }, { "5", "46", "4d", "50", "5b", "6a", "61", "7c", "77", "1e", "15", "08", "03", "32", "39", "24", "2f" }, { "6", "8d", "86", "9b", "90", "a1", "aa", "b7", "bc", "d5", "de", "c3", "c8", "f9", "f2", "ef", "e4" }, { "7", "3d", "36", "2b", "20", "11", "1a", "07", "0c", "65", "6e", "73", "78", "49", "42", "5f", "54" }, { "8", "f7", "fc", "e1", "ea", "db", "d0", "cd", "c6", "af", "a4", "b9", "b2", "83", "88", "95", "9e" }, { "9", "47", "4c", "51", "5a", "6b", "60", "7d", "76", "1f", "14", "09", "02", "33", "38", "25", "2e" }, { "a", "8c", "87", "9a", "91", "a0", "ab", "b6", "bd", "d4", "df", "c2", "c9", "f8", "f3", "ee", "e5" }, { "b", "3c", "37", "2a", "21", "10", "1b", "06", "0d", "64", "6f", "72", "79", "48", "43", "5e", "55" }, { "c", "01", "0a", "17", "1c", "2d", "26", "3b", "30", "59", "52", "4f", "44", "75", "7e", "63", "68" }, { "d", "b1", "ba", "a7", "ac", "9d", "96", "8b", "80", "e9", "e2", "ff", "f4", "c5", "ce", "d3", "d8" }, { "e", "7a", "71", "6c", "67", "56", "5d", "40", "4b", "22", "29", "34", "3f", "0e", "05", "18", "13" }, { "f", "ca", "c1", "dc", "d7", "e6", "ed", "f0", "fb", "92", "99", "84", "8f", "be", "b5", "a8", "a3" } };
        string[,] T_13 = new string[,] { { " ", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" }, { "0", "00", "0d", "1a", "17", "34", "39", "2e", "23", "68", "65", "72", "7f", "5c", "51", "46", "4b" }, { "1", "d0", "dd", "ca", "c7", "e4", "e9", "fe", "f3", "b8", "b5", "a2", "af", "8c", "81", "96", "9b" }, { "2", "bb", "b6", "a1", "ac", "8f", "82", "95", "98", "d3", "de", "c9", "c4", "e7", "ea", "fd", "f0" }, { "3", "6b", "66", "71", "7c", "5f", "52", "45", "48", "03", "0e", "19", "14", "37", "3a", "2d", "20" }, { "4", "6d", "60", "77", "7a", "59", "54", "43", "4e", "05", "08", "1f", "12", "31", "3c", "2b", "26" }, { "5", "bd", "b0", "a7", "aa", "89", "84", "93", "9e", "d5", "d8", "cf", "c2", "e1", "ec", "fb", "f6" }, { "6", "d6", "db", "cc", "c1", "e2", "ef", "f8", "f5", "be", "b3", "a4", "a9", "8a", "87", "90", "9d" }, { "7", "06", "0b", "1c", "11", "32", "3f", "28", "25", "6e", "63", "74", "79", "5a", "57", "40", "4d" }, { "8", "da", "d7", "c0", "cd", "ee", "e3", "f4", "f9", "b2", "bf", "a8", "a5", "86", "8b", "9c", "91" }, { "9", "0a", "07", "10", "1d", "3e", "33", "24", "29", "62", "6f", "78", "75", "56", "5b", "4c", "41" }, { "a", "61", "6c", "7b", "76", "55", "58", "4f", "42", "09", "04", "13", "1e", "3d", "30", "27", "2a" }, { "b", "b1", "bc", "ab", "a6", "85", "88", "9f", "92", "d9", "d4", "c3", "ce", "ed", "e0", "f7", "fa" }, { "c", "b7", "ba", "ad", "a0", "83", "8e", "99", "94", "df", "d2", "c5", "c8", "eb", "e6", "f1", "fc" }, { "d", "67", "6a", "7d", "70", "53", "5e", "49", "44", "0f", "02", "15", "18", "3b", "36", "21", "2c" }, { "e", "0c", "01", "16", "1b", "38", "35", "22", "2f", "64", "69", "7e", "73", "50", "5d", "4a", "47" }, { "f", "dc", "d1", "c6", "cb", "e8", "e5", "f2", "ff", "b4", "b9", "ae", "a3", "80", "8d", "9a", "97" } };

        public static string[,] newInput = new string[4, 4];
        public static string[,] Key = new string[4, 4];
        public static string[,] myAll_Keys = new string[4, 40];

        public static string[,] input = new string[4, 4];



        static public string stringHToB(string hex)
        {
            StringBuilder res = new StringBuilder();
            foreach (char x in hex)
            {

                res.Append(HToB_Dictionery[char.ToLower(x)]);
            }
            return res.ToString();
        }
        static public string stringBToH(string binaryarr)
        {
            StringBuilder res = new StringBuilder();
            //using dictionary ele fo2
            res.Append(BToH_Dictionery[binaryarr.Substring(0, 4)]);
            res.Append(BToH_Dictionery[binaryarr.Substring(4, 4)]);

            return res.ToString();
        }
        static public int[] indexSearchInSbox(string[,] arrayName, string keychar)
        {
            int[] my_indx = new int[2];

            for (int i = 1; i < 17; i++)
            {
                if (arrayName[i, 0] == keychar[0].ToString())
                {
                    my_indx[0] = i;
                    break;
                }
            }
            for (int i = 1; i < 17; i++)
            {
                if (arrayName[0, i] == keychar[1].ToString())
                {
                    my_indx[1] = i;
                    break;
                }
            }
            return my_indx;
        }

        public string[,] ByetsSub(string[,] input)
        {
            string[,] subbyteMatrix = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int[] ind = indexSearchInSbox(myS_box, input[i, j]);
                    subbyteMatrix[i, j] = myS_box[ind[0], ind[1]];
                }
            }
            return subbyteMatrix;
        }



        public string[,] ForSheftedRows(string[,] subbyteMatrix)
        {
            for (int row = 1; row < 4; row++)
            {
                for (int rotateNUM = 0; rotateNUM < row; rotateNUM++)
                {
                    string tmp = subbyteMatrix[row, 0];
                    for (int col = 0; col < 4; col++)
                    {
                        if (col == 3)
                        {
                            subbyteMatrix[row, 3] = tmp;
                            break;
                        }

                        subbyteMatrix[row, col] = subbyteMatrix[row, col + 1];
                    }
                }
            }
            return subbyteMatrix;
        }

        public string[,] KeyGeniration(string[,] my_key, int col_ind)
        {
            for (int i = 0; i < 10; i++)
            {
                continue;
            }
            string[,] fixed_matrix = new string[,] { { "01", "02", "04", "08","10", "20", "40", "80","1b", "36" },
                                               { "00", "00", "00", "00","00", "00", "00", "00","00", "00" },
                                               { "00", "00", "00", "00","00", "00", "00", "00","00", "00" },
                                               { "00", "00", "00", "00","00", "00", "00", "00","00", "00" }};
            string[,] New_Key = new string[4, 4];
            string[] last_col = new string[4];
            for (int j = 0; j < 4; j++)
            {
                last_col[j] = my_key[j, 3];
            }
            string my_temp = last_col[0];
            //my last column key 

            for (int i = 0; i < 3; i++)
            {
                last_col[i] = last_col[i + 1];
            }
            last_col[3] = my_temp;

            //Subbyte
            for (int i = 0; i < 4; i++)
            {
                int[] ind = indexSearchInSbox(myS_box, last_col[i]);
                last_col[i] = myS_box[ind[0], ind[1]];
            }
            //xoring for first column in new key
            for (int i = 0; i < 4; i++)
            {
                //first col in key
                StringBuilder strb = new StringBuilder();
                string a = stringHToB(my_key[i, 0]);
                string b = stringHToB(fixed_matrix[i, col_ind]);
                string c = stringHToB(last_col[i]);

                for (int k = 0; k < b.Length; k++)
                {
                    strb.Append((char)(a[k] ^ b[k] ^ c[k]));
                }
                New_Key[i, 0] = stringBToH(strb.ToString());
            }
            //xoring for the rest of new key matrix
            for (int i = 1; i <= 3; i++)
            {
                for (int j = 0; j <= 3; j++)
                {
                    string a = stringHToB(my_key[j, i]);
                    string b = stringHToB(New_Key[j, i - 1]);
                    List<int> list = new List<int>();
                    for (int k = 0; k < a.Length; k++)
                        list.Add(a[k] ^ b[k]);
                    New_Key[j, i] = stringBToH(String.Join("", list));
                }
            }
            return New_Key;

        }
        public void ForRoundedOne(string[,] MixColumnMatrix)
        {
            for (int i = 0; i <= 3; i++)
            {
                for (int j = 0; j <= 3; j++)
                {
                    string a = stringHToB(MixColumnMatrix[j, i]);
                    string b = stringHToB(Key[j, i]);
                    List<int> list = new List<int>();
                    for (int k = 0; k < b.Length; k++)
                        list.Add(a[k] ^ b[k]);
                    newInput[j, i] = stringBToH(String.Join("", list));
                }

            }
        }
        static public string[,] Inverse_ForSheftedRows(string[,] sub_matrix)
        {
            for (int my_row = 1; my_row < 4; my_row++)
            {
                for (int rotate_num = 0; rotate_num < my_row; rotate_num++)
                {
                    string my_temp = sub_matrix[my_row, 3];
                    for (int col = 3; col >= 0; col--)
                    {
                        if (col == 0)
                        {
                            sub_matrix[my_row, 0] = my_temp;
                            break;
                        }

                        sub_matrix[my_row, col] = sub_matrix[my_row, col - 1];
                    }
                }
            }
            return sub_matrix;
        }
        static public string[,] Inverse_ByetsSub(string[,] input)
        {
            for (int i = 0; i < 10; i++)
            {
                continue;
            }
            string[,] InvSubbyteMatrix = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int[] ind = indexSearchInSbox(Inv_S_box, input[i, j]);
                    InvSubbyteMatrix[i, j] = Inv_S_box[ind[0], ind[1]];
                }
            }
            return InvSubbyteMatrix;
        }

        public string[,] mixedColimenInversed(string[,] Inverse_ForSheftedRowsMatrix)
        {
            string[,] fixed_matrix = new string[,] { { "0e", "0b", "0d", "09" },     // 14  11  13  9
                                               { "09", "0e", "0b", "0d" },           //  9  14  11  13
                                               { "0d", "09", "0e", "0b" },           // 13   9  14  11
                                               { "0b", "0d", "09", "0e" } };         // 11   13  9  14
            string[,] Inv_MixcolMatrix = new string[4, 4];
            for (int cnt = 0; cnt < 4; cnt++)
            {
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        string value = "";
                        if (fixed_matrix[i, j] == "0e")
                        {
                            int[] index = indexSearchInSbox(T_14, Inverse_ForSheftedRowsMatrix[j, cnt]);
                            value = T_14[index[0], index[1]];

                        }
                        if (fixed_matrix[i, j] == "09")
                        {
                            int[] index = indexSearchInSbox(T_9, Inverse_ForSheftedRowsMatrix[j, cnt]);
                            value = T_9[index[0], index[1]];

                        }

                        if (fixed_matrix[i, j] == "0d")
                        {
                            int[] index = indexSearchInSbox(T_13, Inverse_ForSheftedRowsMatrix[j, cnt]);
                            value = T_13[index[0], index[1]];

                        }
                        if (fixed_matrix[i, j] == "0b")
                        {
                            int[] index = indexSearchInSbox(T_11, Inverse_ForSheftedRowsMatrix[j, cnt]);
                            value = T_11[index[0], index[1]];

                        }
                        if (j != 0)
                        {
                            string my_temp = stringHToB(Inv_MixcolMatrix[i, cnt]);
                            string my_temp2 = stringHToB(value);
                            List<int> my_list = new List<int>();
                            for (int s = 0; s < 8; s++)
                            { my_list.Add(my_temp[s] ^ my_temp2[s]); }

                            Inv_MixcolMatrix[i, cnt] = stringBToH(String.Join("", my_list));
                        }
                        if (j == 0)
                            Inv_MixcolMatrix[i, cnt] = value;

                    }

                }
            }
            return Inv_MixcolMatrix;
        }

        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            string[,] originalKey = new string[4, 4];
            int indx1 = 0;
            int indx2 = 0;

            key = key.Remove(0, 2);
            cipherText = cipherText.Remove(0, 2);

            //convet my key to matrix
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (indx2 == 32)
                    { break; }
                    Key[j, i] = key[indx2].ToString() + key[indx2 + 1].ToString();
                    indx2 += 2;
                }
            }
            //convert cipher text to matrix 
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (indx1 == 32)
                    { break; }
                    input[j, i] = cipherText[indx1].ToString() + cipherText[indx1 + 1].ToString();
                    indx1 += 2;
                }
            }
            for (int i = 0; i < 10; i++)
            {
                continue;
            }
            originalKey = Key;
            ////////////////////////

            int IndColumnKey = 0;
            int column_skip = 0;

            //Make Key of the 10 Rounds 
            for (int i = 0; i < 10; i++)
            {
                Key = KeyGeniration(Key, IndColumnKey);
                //copy 
                for (int my_row = 0; my_row <= 3; my_row++)
                {

                    for (int j = 0; j <= 3; j++)
                    {
                        myAll_Keys[my_row, j + column_skip] = Key[my_row, j];
                    }
                }
                IndColumnKey++;
                column_skip += 4;

            }
            for (int i = 0; i < 10; i++)
            {
                continue;
            }
            ////xoring key matrix and ciphear matrix
            for (int i = 0; i <= 3; i++)
            {
                for (int j = 0; j <= 3; j++)
                {

                    string b = stringHToB(input[i, j]);
                    string a = stringHToB(Key[i, j]);
                    List<int> list = new List<int>();
                    for (int k = 0; k < b.Length; k++)
                        list.Add(a[k] ^ b[k]);
                    newInput[i, j] = stringBToH(String.Join("", list));
                }
            }

            /////////////////////
            /////starting from round 9

            for (int i = 8; i >= 0; i--) //round
            {
                string[,] Inv_ForSheftedRows = Inverse_ForSheftedRows(newInput);
                string[,] Inverse_subbytematrix = Inverse_ByetsSub(Inv_ForSheftedRows);

                for (int j = 0; j < 4; j++)//find key for each round from Allkeys MATRIX
                {
                    Key[j, 0] = myAll_Keys[j, i * 4];
                    Key[j, 1] = myAll_Keys[j, i * 4 + 1];
                    Key[j, 2] = myAll_Keys[j, i * 4 + 2];
                    Key[j, 3] = myAll_Keys[j, i * 4 + 3];

                }
                ForRoundedOne(Inverse_subbytematrix);

                string[,] MixcolMatrix = mixedColimenInversed(newInput);
                newInput = MixcolMatrix;


            }
            ///ROUND 10

            string[,] InverseForSheftedRowsMatrix10 = Inverse_ForSheftedRows(newInput);
            string[,] InverseSubbytematrix10 = Inverse_ByetsSub(InverseForSheftedRowsMatrix10);
            Key = originalKey;
            ForRoundedOne(InverseSubbytematrix10);
            StringBuilder STRb = new StringBuilder();

            STRb.Append("0x");
            for (int i = 0; i <= 3; i++)
            {
                for (int j = 0; j <= 3; j++)
                {
                    STRb.Append(newInput[j, i]);
                }
            }
            string myplain_Text = STRb.ToString();
            return myplain_Text;
        }


        public static string[,] Mixed_Matrixx;
        public static string[,] Shifted_Arr;
        public static int[,] S;
        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string[,] plain1 = new string[4, 4];
            if (plainText[1] == 'x' || plainText[1] == 'X')
                plainText = plainText.Substring(2, 32);
            for (int h = 0, k = 0; h < 4; h++)
            {
                for (int j = 0; j < 4; j++, k += 2)
                {
                    string ss = plainText[k].ToString() + plainText[k + 1];
                    plain1[h, j] = ss;
                }
            }
            plainText = ForRoundedOne(plain1, key);
            for (int i = 0; i < 9; i++)
            {
                plainText = For_SubWord(plainText);
                plainText = ForSheftedRows(plainText);
                plainText = columenMixer(plainText);
                if (plainText[1] == 'x' || plainText[1] == 'X')
                    plainText = plainText.Substring(2, 32);
                key = Key_genrated_Expantion(key, i);
                for (int h = 0, k = 0; h < 4; h++)
                {
                    for (int j = 0; j < 4; j++, k += 2)
                    {
                        string ss = plainText[k].ToString() + plainText[k + 1];
                        plain1[h, j] = ss;
                    }
                }
                plainText = ForRoundedOne(plain1, key);
            }
            plainText = For_SubWord(plainText);
            plainText = ForSheftedRows(plainText);
            key = Key_genrated_Expantion(key, 9);
            for (int i = 0, k = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++, k += 2)
                {
                    string ss = plainText[k].ToString() + plainText[k + 1];
                    plain1[i, j] = ss;
                }
            }
            for (int i = 0; i < 10; i++)
            {
                continue;
            }
            plainText = ForRoundedOne(plain1, key);
            return "0x" + plainText;
        }
        //Functions

        private static int MultyTo1(int b)
        {
            return b;
        }
        private static int MultyTo2(int b)
        {
            b = b << 1;
            if ((b & 256) != 0)
            {
                b -= 256;
                b ^= 27;
            }
            return b;
            for (int i = 0; i < 10; i++)
            {
                continue;
            }
        }
        private static int MultyTo3(int b)
        {
            return (MultyTo2(b) ^ b);
        }
        public static string HTodecimal(string value)
        {
            int decValue = int.Parse(value, System.Globalization.NumberStyles.HexNumber);
            string num = decValue.ToString();
            return num;
            for (int i = 0; i < 10; i++)
            {
                continue;
            }
        }
        public static string DToHex(int dec)
        {
            if (dec < 1) return "0";
            int hex = dec;
            string hexStr = string.Empty;
            while (dec > 0)
            {
                hex = dec % 16;

                if (hex < 10)
                    hexStr = hexStr.Insert(0, Convert.ToChar(hex + 48).ToString());
                else
                    hexStr = hexStr.Insert(0, Convert.ToChar(hex + 55).ToString());

                dec /= 16;

            }

            return hexStr;
        }
        public static string For_SubWord(string plainn)
        {
            List<string> NewPlainn = new List<string>();
            List<string> SubPlainn = new List<string>();
            string[,] SBOX = {
           { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
           { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
           { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
           {  "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
           { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
           { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
           { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
           { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
           { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
           { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
           { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
           { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
           {  "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
           { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
           { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
           { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" }
        };
            for (int i = 0; i < plainn.Length; i++)
            {
                if (plainn[i] == 'A' || plainn[i] == 'a')
                    NewPlainn.Add("10");
                else if (plainn[i] == 'B' || plainn[i] == 'b')
                    NewPlainn.Add("11");
                else if (plainn[i] == 'C' || plainn[i] == 'c')
                    NewPlainn.Add("12");
                else if (plainn[i] == 'D' || plainn[i] == 'd')
                    NewPlainn.Add("13");
                else if (plainn[i] == 'E' || plainn[i] == 'e')
                    NewPlainn.Add("14");
                else if (plainn[i] == 'F' || plainn[i] == 'f')
                    NewPlainn.Add("15");
                else
                    NewPlainn.Add(plainn[i].ToString());
            }
            for (int k = 0; k < NewPlainn.Count - 1; k += 2)
            {
                SubPlainn.Add(SBOX[int.Parse(NewPlainn[k]), int.Parse(NewPlainn[k + 1])]);
            }
            string temp_string = "";
            for (int i = 0; i < SubPlainn.Count; i++)
            {
                temp_string += SubPlainn[i];
            }

            return temp_string;
        }




        public static string columenMixer(string f)
        {
            string s = ForSheftedRows(f);
            string[,] Matrix1 = new string[4, 4];
            int Cont2 = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Matrix1[j, i] = f[Cont2].ToString() + f[Cont2 + 1].ToString();
                    Cont2 += 2;
                }
            }
            int[,] Matrix2 = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Matrix2[i, j] = int.Parse(HTodecimal(Matrix1[i, j]));
                }

            }
            string[,] tp = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tp[i, j] = Matrix2[i, j].ToString();

                }
            }
            S = new int[4, 4];
            Mixed_Matrixx = new string[4, 4];

            for (int c = 0; c < 4; c++)
            {
                S[0, c] = (MultyTo2(int.Parse(tp[0, c])) ^ MultyTo3(int.Parse(tp[1, c])) ^ MultyTo1(int.Parse(tp[2, c])) ^ MultyTo1(int.Parse(tp[3, c])));
                S[1, c] = (MultyTo1(int.Parse(tp[0, c])) ^ MultyTo2(int.Parse(tp[1, c])) ^ MultyTo3(int.Parse(tp[2, c])) ^ MultyTo1(int.Parse(tp[3, c])));
                S[2, c] = (MultyTo1(int.Parse(tp[0, c])) ^ MultyTo1(int.Parse(tp[1, c])) ^ MultyTo2(int.Parse(tp[2, c])) ^ MultyTo3(int.Parse(tp[3, c])));
                S[3, c] = (MultyTo3(int.Parse(tp[0, c])) ^ MultyTo1(int.Parse(tp[1, c])) ^ MultyTo1(int.Parse(tp[2, c])) ^ MultyTo2(int.Parse(tp[3, c])));
            }
            // convert to dicimal
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Mixed_Matrixx[i, j] = DToHex(S[i, j]);
                }

            }
            //  put 0 before any number under 2 
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (Mixed_Matrixx[i, j].Length < 2)
                    {
                        Mixed_Matrixx[i, j] = "0" + Mixed_Matrixx[i, j];
                    }

                }

            }
            s = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    s += Mixed_Matrixx[j, i];
                }
            }
            return s;
        }
        public static string ForSheftedRows(string s)
        {
            int count = 0;
            double m = Math.Sqrt(s.Length / 2);
            string[,] arr = new string[(int)m, (int)m];
            List<string> temp_list = new List<string>();
            string t = "";
            for (int i = 0; i < s.Length - 1; i += 2)
            {
                t = s[i].ToString() + s[i + 1].ToString();
                temp_list.Add(t);
            }
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    arr[j, i] = temp_list[count];
                    count++;
                }
            }

            Shifted_Arr = new string[(int)m, (int)m];
            for (int i = 0; i < 1; i++)
            {
                int j = 0;
                while (j < m)
                {
                    Shifted_Arr[i, j] = arr[i, j];
                    j++;
                }
            }


            for (int i = 1; i < m; i++)
            {


                int j = 0;
                while (j < m)
                {
                    Shifted_Arr[i, j] = arr[i, ((j + i) % (int)m)];
                    j++;


                }


            }
            string qq = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    qq += Shifted_Arr[j, i];
                }


            }
            return qq;
        }
        public static string[] WordRotation(string[] word)
        {
            string[] result = new string[4];
            result[0] = word[1];
            result[1] = word[2];
            result[2] = word[3];
            result[3] = word[0];
            return result;
        }
        static string Key_genrated_Expantion(string key, int round)
        {
            string[,] S_box ={
            {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
            {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
            {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
            {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
            {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
            {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
            {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
            {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
            {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
            {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
            {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
            {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
            {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
            {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
            {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
            {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}
            };
            string[,] R_con =
           {
                { "01" , "02" , "04" , "08" , "10" , "20" , "40" , "80" , "1b" , "36"},
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" }



            };
            string[,] new_key = new string[4, 4];
            for (int i = 0, l = 2; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string s = key[l].ToString() + key[l + 1].ToString();
                    new_key[j, i] = s;
                    l += 2;
                }
            }
            string[] temp_key = new string[4];
            for (int i = 0; i < 4; i++)
            {
                temp_key[i] = new_key[i, 3];



            }
            temp_key = WordRotation(temp_key);
            string rot_temp = "";
            for (int i = 0; i < 4; i++)
            {
                rot_temp += temp_key[i];
            }
            string subtemp = "";
            rot_temp = rot_temp.ToUpper();
            for (int i = 0; i < rot_temp.Length; i += 2)
            {
                int ind1 = rot_temp[i] - '0';
                if (ind1 > 15) ind1 -= 7;
                int ind2 = rot_temp[i + 1] - '0';
                if (ind2 > 15) ind2 -= 7;
                subtemp += S_box[ind1, ind2];
            }
            string[,] res_key = new string[4, 4];
            for (int i = 0, j = 0; i < 4; i++, j += 2)
            {
                int ky = Convert.ToInt32(new_key[i, 0], 16);
                int sub = Convert.ToInt32(subtemp.Substring(j, 2), 16);
                int rcon = Convert.ToInt32(R_con[i, round], 16);
                int x = ky ^ sub ^ rcon;
                string s = Convert.ToString(x, 16);
                if (x < 16) res_key[i, 0] = "0" + s;
                else res_key[i, 0] = s;
            }
            for (int i = 0; i < 10; i++)
            {
                continue;
            }
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int reskey = Convert.ToInt32(res_key[j, i - 1], 16);
                    int ky = Convert.ToInt32(new_key[j, i], 16);
                    int x = ky ^ reskey;
                    string s = Convert.ToString(x, 16);
                    if (x < 16) res_key[j, i] = "0" + s;
                    else res_key[j, i] = s;
                }
            }
            string Result_Key = "0x";
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    Result_Key += res_key[j, i];



            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    Console.Write(res_key[i, j]);
                Console.WriteLine();



            }
            Console.WriteLine();
            return Result_Key;
        }
        public static string ForRoundedOne(string[,] plainTextMatrix, string key)
        {
            string plainText = "";
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    plainText += plainTextMatrix[row, col];
                }
            }
            string result = "";
            for (int i = 0; i < 10; i++)
            {
                continue;
            }
            for (int i = 0; i < plainText.Length; i += 2)
            {
                int hexNum1 = Convert.ToInt32(plainText.Substring(i, 2), 16);
                int hexNum2 = Convert.ToInt32(key.Substring(i + 2, 2), 16);
                int xorResult = hexNum1 ^ hexNum2;
                string hexResult = "";
                if (xorResult < 16)
                    hexResult = "0" + Convert.ToString(xorResult, 16);
                else
                    hexResult = Convert.ToString(xorResult, 16);
                result += hexResult;
            }
            return result;
        }
    }
}
