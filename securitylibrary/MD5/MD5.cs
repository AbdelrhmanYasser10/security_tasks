using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.MD5
{
    public class MD5
    {
        // Zie Wikipedia
        protected readonly static uint[] T = new uint[64]
            {
                0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
                0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
                0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
                0x6b901122,0xfd987193,0xa679438e,0x49b40821,
                0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
                0xd62f105d,0x2441453,0xd8a1e681,0xe7d3fbc8,
                0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
                0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
                0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
                0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
                0x289b7ec6,0xeaa127fa,0xd4ef3085,0x4881d05,
                0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
                0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
                0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
                0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
                0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
            };

        // Zie Wikipedia
        protected readonly static int[] s = new int[64]
        {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        };


        // Standaard waarden
        uint A = 0x67452301;
        uint B = 0xEFCDAB89;
        uint C = 0x98BADCFE;
        uint D = 0X10325476;

        protected uint[] X = new uint[16];
        protected byte[] MByte;

        public void mdFunction(string s_val)
        {
            int length = s_val.Length;
            MByte = Encoding.ASCII.GetBytes(s_val);
            //or another solution
            //for (int i = 0; i < length; i++) {
            //    MByte[i] = (byte)s_val[i];
            //}
        }

        public string createMD5Algorithm()
        {
            byte[] Bmsg_arr;uint LengthValue;
            Bmsg_arr = pdBuffer();

            LengthValue = (uint)(Bmsg_arr.Length * 8) / 32;
            LengthValue /= 16;
            for (uint i = 0; i < LengthValue; i++)
            {
                mkBlock(Bmsg_arr, i);
                calculateTransform();
            }

            string s = reverseTheByte(A).ToString("X8") +
                        reverseTheByte(B).ToString("X8") +
                        reverseTheByte(C).ToString("X8") +
                        reverseTheByte(D).ToString("X8");
            return s;
        }

        private static uint reverseTheByte(uint uiNumber)
        {
            uint f_value = (uiNumber & 0x000000ff) << 24;
            uint s_value = (uiNumber >> 24);
            uint t_value = (uiNumber & 0x00ff0000) >> 8;
            uint forth_value = (uiNumber & 0x0000ff00) << 8;
            uint final_result = (f_value | s_value | t_value | forth_value);
            return final_result;
        }

        private void swap_functions(ref uint tempA, ref uint tempB) { 
            uint tempVal = tempA;
            tempA = tempB;
            tempB = tempVal;
        }

        protected void calculateTransform()
        {
            uint CurrentA = A, CurrentB = B, CurrentC = C, CurrentD = D;
            uint F = 0;
            int g = 0;

            for (int i = 0; i < 64; i++)
            {
                if (i >= 0 && i <= 15)
                {
                    F = ((CurrentB & CurrentC) | (~(CurrentB) & CurrentD));
                    g = i;
                }
                else if (i >= 16 && i <= 31)
                {
                    F = ((CurrentB & CurrentD) | (CurrentC & ~CurrentD));
                    g = (5 * i + 1) % 16;
                }
                else if (i >= 32 && i <= 47)
                {
                    F = (CurrentB ^ CurrentC ^ CurrentD);
                    g = (3 * i + 5) % 16;
                }
                else if (i >= 48 && i <= 63)
                {
                    F = (CurrentC ^ (CurrentB | ~CurrentD));
                    g = (7 * i) % 16;
                }
                //Swapping
                uint dtemp = CurrentD;
                CurrentD = CurrentC;
                CurrentC = CurrentB;

                uint dtempt = CurrentA + F + T[i] + X[g];
                dtempt = (dtempt << s[i]) | (dtempt >> (32 - s[i]));
                CurrentB = CurrentB + dtempt;
                CurrentA = dtemp;
            }

            //Add the values to update
            A += CurrentA;
            B += CurrentB;
            C += CurrentC;
            D += CurrentD;
        }
        private byte getByteVal(ulong sizeMsg,int index) {
            return (byte)(sizeMsg >> ((8 - index) * 8) & 0x00000000000000ff);
        }
        protected void mkBlock(byte[] bMsg, uint blk)
        {
            blk = blk << 6;
            for (uint i = 0; i < 61; i += 4)
            {
                uint f_value = (uint)((bMsg[blk + (i + 3)]) << 24);
                uint s_value = (uint)((bMsg[blk + (i + 2)]) << 16);
                uint th_value = (uint)((bMsg[blk + (i + 1)]) << 8);
                uint fo_value = (uint)(bMsg[blk + (i)]);
                uint index_no = i >> 2;
                X[index_no] = (f_value | s_value | th_value | fo_value);
            }
        }
        protected byte[] pdBuffer()
        {
            uint pad;
            byte[] bMsg;
            ulong sizeMsg;
            uint sizeMsgBuff;

            uint padChecking_Val = ((uint)(((448 - ((MByte.Length * 8) % 512)) + 512) % 512));

            pad = padChecking_Val == 0 ?
                512:
                padChecking_Val;

            sizeMsgBuff = (uint)((MByte.Length) + (pad / 8) + 8);
            sizeMsg = (ulong)MByte.Length * 8;
            bMsg = new byte[sizeMsgBuff];
            Array.Copy(MByte, 0, bMsg, 0, MByte.Length);
            for (int i = 0; i < MByte.Length; i++)
            {
                bMsg[i] = MByte[i];
            }

            bMsg[MByte.Length] |= 0x80;

            for (int i = 8; i > 0; i--)
            {
                bMsg[sizeMsgBuff - i] = getByteVal(sizeMsg,i);
            }

            return bMsg;

        }
        public string GetHash(string text)
        {
            Console.WriteLine("meeeeee");
            mdFunction(text);
            return createMD5Algorithm();
        }

    }
}