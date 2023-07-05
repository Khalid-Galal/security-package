using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public int[] pc1 =
        {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };
        private int[] noOfshifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        public int[] pc2 =
        {   14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };
        public static int[] ip =
{
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };
        public int[] bitsSelect =
            {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11,12, 13,
            12, 13, 14, 15, 16,17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };

        public int[] permutation_in_last_mangular =
        {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        };

        public byte[,] S =
        {
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            },
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            },
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            },
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            },
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            },
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            },
            {
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            }
        };
        //the last permu
        public static int[] ipInverse =
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };
        int[][][] sbox =
       {
                new int[][]
                {
                    new int[] {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    new int[] {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    new int[] {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    new int[] {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
                },
                new int[][]
                {
                    new int[] {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    new int[] {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    new int[] {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    new int[] {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
                },
                new int[][]
                {
                    new int[] {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    new int[] {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    new int[] {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    new int[] {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
                },
                new int[][]
                {
                    new int[] {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    new int[] {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    new int[] {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    new int[] {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
                },
                new int[][]
                {
                    new int[] {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    new int[] {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    new int[] {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    new int[] {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
                },
                new int[][]
                {
                    new int[] {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    new int[] {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    new int[] {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    new int[] {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
                },
                new int[][]
                {
                    new int[] {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    new int[] {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    new int[] {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    new int[] {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
                },
                new int[][]
                {
                    new int[] {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    new int[] {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                    new int[] {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    new int[] {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
                }
        };
        public string permute(string k, int[] arr)
        {
            string per = "";
            for (int i = 0; i < arr.Length; i++)
            {
                per += k[arr[i] - 1];
            }
            return per;
        }
        // XOR
        public string xor(string a, string b)
        {
            string ans = "";
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] == b[i])
                {
                    ans += "0";
                }
                else
                {
                    ans += "1";
                }
            }
            return ans;
        }

        // shifting left
        public string shift_left(string k, int shifts)
        {
            string s = "";
            for (int i = 0; i < shifts; i++)
            {
                for (int j = 1; j < 28; j++)
                {
                    s += k[j];
                }
                s += k[0];
                k = s;
                s = "";
            }
            return k;
        }

        public override string Decrypt(string cipherText, string key)
        {
            //Hexadecimal to binary
            key = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');



            key = permute(key, pc1);

            //int[] shift_table = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            // Split
            string C = key.Substring(0, 28);
            string D = key.Substring(28);

            List<string> rkb = new List<string>();

            for (int i = 0; i < 16; i++)
            {
                C = shift_left(C, noOfshifts[i]);
                D = shift_left(D, noOfshifts[i]);
                string combine = C + D;
                string RoundKey = permute(combine, pc2);
                rkb.Add(RoundKey);

            }
            rkb.Reverse();

            //handling cipherText
            string Text = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            Text = permute(Text, ip);

            // Spliting cipherText
            string left = Text.Substring(0, 32);
            string right = Text.Substring(32);


            for (int i = 0; i < 16; i++)
            {
                string right_expanded = permute(right, bitsSelect);
                string x = xor(rkb[i], right_expanded);
                string op = "";
                for (int j = 0; j < 8; j++)
                {
                    int row = Convert.ToInt32(x[j * 6].ToString() + x[j * 6 + 5].ToString(), 2);
                    int col = Convert.ToInt32(x[j * 6 + 1].ToString() + x[j * 6 + 2].ToString() + x[j * 6 + 3].ToString() + x[j * 6 + 4].ToString(), 2);
                    int val = sbox[j][row][col];
                    op = op + Convert.ToString(val, 2).PadLeft(4, '0');

                }

                // XORING left with rigth
                op = permute(op, permutation_in_last_mangular);
                left = xor(op, left);

                // Exchange left with right
                string tmp = left;
                left = right;
                right = tmp;

            }
            string combinedkey = right + left;


            string txt = "0x" + Convert.ToInt64(permute(combinedkey, ipInverse), 2).ToString("x").PadLeft(16, '0');
            return txt;



            //throw new NotImplementedException();
        }
        public override string Encrypt(string plainText, string key)
        {
            BitArray keys, PT_N, NewPT, ArrPermution, Arr_Shifted;
            keys = ConversionFromHex(key);
            PT_N = ConversionFromHex(plainText);
            NewPT = initialPermu(PT_N);
            Arr_Shifted = firstPermu(keys);
            for (int i = 0; i <= 15; ++i)
            {
                Arr_Shifted = shiftleft(Arr_Shifted, i);
                ArrPermution = secondPermu(Arr_Shifted);
                NewPT = generate_Rn_Ln(NewPT, ArrPermution);
            }
            NewPT = swabb(NewPT);
            NewPT = permuInverse(NewPT);
            return CoversionFromBits(NewPT);
            //throw new NotImplementedException();
        }
        public static BitArray ConversionFromHex(string s)
        {
            int L = s.Length;
            string hexString = s.Substring(2, L - 2);
            int L2 = hexString.Length;
            BitArray bits = new BitArray(L2 * 4);
            for (int i = 0; i < hexString.Length; i++)
            {
                byte b = byte.Parse(hexString[i].ToString(), NumberStyles.HexNumber);
                for (int j = 0; j < 4; j++)
                    bits.Set(i * 4 + j, (b & (1 << (3 - j))) != 0);
            }
            return bits;
        }
        private BitArray initialPermu(BitArray newpt)
        {
            BitArray bitarr;
            bitarr = new BitArray(64);
            for (int i = 0; i < 64; ++i)
                bitarr[i] = newpt[ip[i] - 1];
            return bitarr;
        }
        private BitArray firstPermu(BitArray the_keyy)
        {
            BitArray carry_key_N = new BitArray(56);
            for (int i = 0; i < 56; ++i)
                carry_key_N[i] = the_keyy[pc1[i] - 1];
            return carry_key_N;
        }
        private BitArray shiftleft(BitArray bits, int A)
        {
            int size = 28;
            BitArray right = new BitArray(size);
            BitArray left = new BitArray(size);
            int numbersToshift = noOfshifts[A];
            int i, j;
            for (i = 0; i < size; ++i)
            {
                right[i] = bits[i + size];
                left[i] = bits[i];
            }
            //Find all C's and D's for right & left
            int c = left.Length, d = right.Length;
            BitArray allC = new BitArray(c);
            BitArray allD = new BitArray(d);
            int L3 = left.Length;
            for (j = 0; j < L3; j++)
            {
                if (c > j + numbersToshift)
                {
                    allC[j] = left[j + numbersToshift];
                    allD[j] = right[j + numbersToshift];
                }
                else
                {
                    allC[j] = left[(j + numbersToshift) - c];
                    allD[j] = right[(j + numbersToshift) - d];
                }
            }
            BitArray cAndD = new BitArray(56);
            for (i = 0; i < size; ++i)
                cAndD[i] = allC[i];
            for (j = 0; j < size; ++j)
                cAndD[j + size] = allD[j];
            return cAndD;
        }

        private BitArray secondPermu(BitArray key)
        {
            BitArray keys2 = new BitArray(48);
            for (int i = 0; i < 48; ++i)
                keys2[i] = key[pc2[i] - 1];
            return keys2;
        }
        private BitArray generate_Rn_Ln(BitArray round1pt, BitArray round2key)
        {
            BitArray rn, left, ln, right;
            rn = new BitArray(32);
            left = new BitArray(32);
            ln = new BitArray(32);
            right = new BitArray(32);
            for (int i = 0; i < 32; ++i)
            {
                right[i] = round1pt[i + 32];
                left[i] = round1pt[i];
            }
            ln = right;
            BitArray bitArr2 = new BitArray(48);
            bitArr2 = F(right);
            bitArr2.Xor(round2key);
            rn = applyS(bitArr2);
            rn = applyPermuF(rn);
            rn.Xor(left);
            BitArray PT = new BitArray(64);
            for (int i = 0; i < 32; ++i)
                PT[i] = ln[i];
            for (int j = 0; j < 32; ++j)
                PT[j + 32] = rn[j];
            return PT;
        }
        private BitArray F(BitArray R)
        {
            BitArray arr = new BitArray(48);
            for (int i = 0; i < 48; ++i)
                arr[i] = R[bitsSelect[i] - 1];
            return arr;
        }

        private BitArray applyS(BitArray bitarr)
        {
            BitArray row = new BitArray(2);
            BitArray column = new BitArray(4);
            BitArray nwR = new BitArray(32);
            int cont = 0;
            for (int i = 0; i < 48; i += 6)
            {
                row[0] = bitarr[i + 5];
                row[1] = bitarr[i];
                int[] INt = new int[1];
                row.CopyTo(INt, 0);
                column[0] = bitarr[i + 4];
                column[1] = bitarr[i + 3];
                column[2] = bitarr[i + 2];
                column[3] = bitarr[i + 1];
                int[] INT2 = new int[1];
                column.CopyTo(INT2, 0);
                byte u = S[i / 6, INt[0] * 16 + INT2[0]];
                BitArray Byttes = new BitArray(BitConverter.GetBytes(u).ToArray());
                for (int j = 0; j < 4; ++j)
                {
                    nwR[cont] = Byttes[3 - j];
                    cont++;
                }
            }
            return nwR;
        }
        private BitArray applyPermuF(BitArray R)
        {
            BitArray arr = new BitArray(32);
            for (int i = 0; i < 32; ++i)
                arr[i] = R[permutation_in_last_mangular[i] - 1];
            return arr;
        }

        private BitArray swabb(BitArray nwPT)
        {
            BitArray left;
            BitArray Right;
            left = new BitArray(32);
            Right = new BitArray(32);
            for (int i = 0; i < 32; ++i)
            {
                left[i] = nwPT[i];
                Right[i] = nwPT[i + 32];
            }
            for (int i = 0; i < 32; ++i)
            {
                nwPT[i] = Right[i];
                nwPT[i + 32] = left[i];
            }
            return nwPT;
        }

        private BitArray permuInverse(BitArray NewPT)
        {
            BitArray bitarr;
            bitarr = new BitArray(64);
            for (int i = 0; i < 64; ++i)
                bitarr[i] = NewPT[ipInverse[i] - 1];
            return bitarr;
        }
        private string CoversionFromBits(BitArray Arr_bits)
        {
            StringBuilder nwStrings;
            int size1 = Arr_bits.Length / 4;
            int size2 = Arr_bits.Length;
            nwStrings = new StringBuilder(size1);
            for (int i = 0; i < size2; i += 4)
            {
                int Value = (Arr_bits[i] ? 8 : 0) | (Arr_bits[i + 1] ? 4 : 0) | (Arr_bits[i + 2] ? 2 : 0) | (Arr_bits[i + 3] ? 1 : 0);

                nwStrings.Append(Value.ToString("x1"));
            }
            return "0x" + nwStrings.ToString();
        }
    }
}