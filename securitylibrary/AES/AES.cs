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

        public enum Key_Size{ Bits128, Bits192, Bits256 };
        int keySize = 0;

        byte[,] rconMat = new byte[4, 11]
            {
                {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36},
                {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
                {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
                {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
            };

        byte[] subsBox = new byte[] 
                     {
                        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
                     };
        byte[] inverseSubsBox = new byte[] {
     0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
      0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
      0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
     0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
     0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
     0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
     0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
     0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
      0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
      0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
      0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
      0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
     0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
      0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

        byte[,] keyExpansionMat;
        string[,] resultMatrix = new string[4, 4];

        string[,] sbox = {
        { "0x63", "0x7c", "0x77", "0x7b", "0xf2", "0x6b", "0x6f", "0xc5", "0x30", "0x01", "0x67", "0x2b", "0xfe", "0xd7", "0xab", "0x76" },
        { "0xca", "0x82", "0xc9", "0x7d", "0xfa", "0x59", "0x47", "0xf0", "0xad", "0xd4", "0xa2", "0xaf", "0x9c", "0xa4", "0x72", "0xc0" },
        { "0xb7", "0xfd", "0x93", "0x26", "0x36", "0x3f", "0xf7", "0xcc", "0x34", "0xa5", "0xe5", "0xf1", "0x71", "0xd8", "0x31", "0x15" },
        { "0x04", "0xc7", "0x23", "0xc3", "0x18", "0x96", "0x05", "0x9a", "0x07", "0x12", "0x80", "0xe2", "0xeb", "0x27", "0xb2", "0x75" },
        { "0x09", "0x83", "0x2c", "0x1a", "0x1b", "0x6e", "0x5a", "0xa0", "0x52", "0x3b", "0xd6", "0xb3", "0x29", "0xe3", "0x2f", "0x84" },
        { "0x53", "0xd1", "0x00", "0xed", "0x20", "0xfc", "0xb1", "0x5b", "0x6a", "0xcb", "0xbe", "0x39", "0x4a", "0x4c", "0x58", "0xcf" },
        { "0xd0", "0xef", "0xaa", "0xfb", "0x43", "0x4d", "0x33", "0x85", "0x45", "0xf9", "0x02", "0x7f", "0x50", "0x3c", "0x9f", "0xa8" },
        { "0x51", "0xa3", "0x40", "0x8f", "0x92", "0x9d", "0x38", "0xf5", "0xbc", "0xb6", "0xda", "0x21", "0x10", "0xff", "0xf3", "0xd2" },
        { "0xcd", "0x0c", "0x13", "0xec", "0x5f", "0x97", "0x44", "0x17", "0xc4", "0xa7", "0x7e", "0x3d", "0x64", "0x5d", "0x19", "0x73" },
        { "0x60", "0x81", "0x4f", "0xdc", "0x22", "0x2a", "0x90", "0x88", "0x46", "0xee", "0xb8", "0x14", "0xde", "0x5e", "0x0b", "0xdb" },
        { "0xe0", "0x32", "0x3a", "0x0a", "0x49", "0x06", "0x24", "0x5c", "0xc2", "0xd3", "0xac", "0x62", "0x91", "0x95", "0xe4", "0x79" },
        { "0xe7", "0xc8", "0x37", "0x6d", "0x8d", "0xd5", "0x4e", "0xa9", "0x6c", "0x56", "0xf4", "0xea", "0x65", "0x7a", "0xae", "0x08" },
        { "0xba", "0x78", "0x25", "0x2e", "0x1c", "0xa6", "0xb4", "0xc6", "0xe8", "0xdd", "0x74", "0x1f", "0x4b", "0xbd", "0x8b", "0x8a" },
        { "0x70", "0x3e", "0xb5", "0x66", "0x48", "0x03", "0xf6", "0x0e", "0x61", "0x35", "0x57", "0xb9", "0x86", "0xc1", "0x1d", "0x9e" },
        { "0xe1", "0xf8", "0x98", "0x11", "0x69", "0xd9", "0x8e", "0x94", "0x9b", "0x1e", "0x87", "0xe9", "0xce", "0x55", "0x28", "0xdf" },
        { "0x8c", "0xa1", "0x89", "0x0d", "0xbf", "0xe6", "0x42", "0x68", "0x41", "0x99", "0x2d", "0x0f", "0xb0", "0x54", "0xbb", "0x16" }
        };
        string[,] MixedColsMatrix =
        {
            {"02", "03", "01", "01"},
            {"01", "02", "03", "01"},
            {"01", "01", "02", "03"},
            {"03", "01", "01", "02"}
        };
        string[,] Rcon = new string[4, 11] {  {  "00","01","02","04","08","10","20","40","80","1b","36" },
                                              {  "00","00","00","00","00","00","00","00","00" ,"00","00" },
                                              {  "00","00","00","00","00","00","00","00","00" ,"00","00"  },
                                              {  "00","00","00","00","00","00","00","00","00" ,"00","00" }
            };
        private byte[,] shiftValues(byte[,] matrix)
        {
            byte[,] finalVal = new byte[4, 1];
            finalVal[0, 0] = matrix[1, 0];
            finalVal[1, 0] = matrix[2, 0];
            finalVal[2, 0] = matrix[3, 0];
            finalVal[3, 0] = matrix[0, 0];

            return finalVal;
        }
        private void addRoundKeyFun(int round , ref byte[,]mat)
        {
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    mat[row, col] = (byte)(mat[row, col] ^ keyExpansionMat[row, (round * 4) + col]);
                }
            }
        }
        private void createKeyExpansionMatrix(int numberOfRounds,int blockSize , int keySize , ref byte[,] keyMatrix)
        {
            int colSize = (numberOfRounds + 1) * blockSize;
            keyExpansionMat = new byte[4, colSize];

            for (int i = 0; i < keySize; i++)
            {
                keyExpansionMat[i, 0] = keyMatrix[i, 0];
                keyExpansionMat[i, 1] = keyMatrix[i, 1];
                keyExpansionMat[i, 2] = keyMatrix[i, 2];
                keyExpansionMat[i, 3] = keyMatrix[i, 3];
            }

            byte[,] currCol = new byte[4, 1]; 

            for (int col = keySize; col < colSize; col++)
            {
                currCol[0, 0] = keyExpansionMat[0, col - 1];
                currCol[1, 0] = keyExpansionMat[1, col - 1];
                currCol[2, 0] = keyExpansionMat[2, col - 1];
                currCol[3, 0] = keyExpansionMat[3, col - 1];

                if (col % keySize == 0)
                {
                    currCol = shiftValues(currCol);

                    currCol[0, 0] = subsBox[currCol[0, 0]];
                    currCol[1, 0] = subsBox[currCol[1, 0]];
                    currCol[2, 0] = subsBox[currCol[2, 0]];
                    currCol[3, 0] = subsBox[currCol[3, 0]];

                    
                    currCol[0, 0] = (byte)(currCol[0, 0] ^ rconMat[0, col / keySize]);
                    currCol[1, 0] = (byte)(currCol[1, 0] ^ rconMat[1, col / keySize]);
                    currCol[2, 0] = (byte)(currCol[2, 0] ^ rconMat[2, col / keySize]);
                    currCol[3, 0] = (byte)(currCol[3, 0] ^ rconMat[3, col / keySize]);

                }
                
                keyExpansionMat[0, col] = (byte)(keyExpansionMat[0, col - keySize] ^ currCol[0, 0]);
                keyExpansionMat[1, col] = (byte)(keyExpansionMat[1, col - keySize] ^ currCol[1, 0]);
                keyExpansionMat[2, col] = (byte)(keyExpansionMat[2, col - keySize] ^ currCol[2, 0]);
                keyExpansionMat[3, col] = (byte)(keyExpansionMat[3, col - keySize] ^ currCol[3, 0]);
            }


        }
        private int numberOfRounds(Key_Size key_size) {

            if (key_size == Key_Size.Bits128)
            {
                keySize = 4;
                return 10;
            }
            else if (key_size == Key_Size.Bits192)
            {
                keySize = 6;
                return 12;
            }
            else if (key_size == Key_Size.Bits256)
            {
                keySize = 8;
                return 14;
            }
            return 0;
        }
        private void inverseShiftedRows(ref byte[,] mat, int blockSize)
        {

            byte[,] tMat = new byte[4, 4];

            for (int row = 0; row < 4; row++)  
            {
                for (int col = 0; col < 4;col++)
                {
                    tMat[row, col] = mat[row, col];
                }
            }

            for (int row = 1; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    mat[row, (row + col) % blockSize] = tMat[row, col]; 
                }
            }

        }

        private void getInverseSubBytes(ref byte[,] mat)
        {
            for (int rowNumber = 0; rowNumber < 4; ++rowNumber)
            {
                for (int colNumber = 0; colNumber < 4; ++colNumber)
                {
                    mat[rowNumber, colNumber] = inverseSubsBox[mat[rowNumber, colNumber]];
                }
            }
        }

        private void inverseMixedColumns(int blockSize , ref byte[,] mat)
        {
            byte[,] cMatrixFromMain = new byte[blockSize, blockSize];

            for (int row = 0; row < 4; row++)  
            {
                for (int col = 0; col < 4; col++)
                {
                    cMatrixFromMain[row, col] = mat[row, col];
                }
            }

            for (int col = 0; col < 4; col++)
            {
                mat[0, col] = (byte)((int)mixColMby0e(cMatrixFromMain[0, col]) ^ (int)mixColMby0b(cMatrixFromMain[1, col]) ^ (int)mixColMby0d(cMatrixFromMain[2, col]) ^ (int)mixColMby09(cMatrixFromMain[3, col]));
                mat[1, col] = (byte)((int)mixColMby09(cMatrixFromMain[0, col]) ^ (int)mixColMby0e(cMatrixFromMain[1, col]) ^ (int)mixColMby0b(cMatrixFromMain[2, col]) ^ (int)mixColMby0d(cMatrixFromMain[3, col]));
                mat[2, col] = (byte)((int)mixColMby0d(cMatrixFromMain[0, col]) ^ (int)mixColMby09(cMatrixFromMain[1, col]) ^ (int)mixColMby0e(cMatrixFromMain[2, col]) ^ (int)mixColMby0b(cMatrixFromMain[3, col]));
                mat[3, col] = (byte)((int)mixColMby0b(cMatrixFromMain[0, col]) ^ (int)mixColMby0d(cMatrixFromMain[1, col]) ^ (int)mixColMby09(cMatrixFromMain[2, col]) ^ (int)mixColMby0e(cMatrixFromMain[3, col]));
            }
        }
        private void MixedColumns(int blockSize, ref byte[,] mat)
        {
            byte[,] cMatrixFromMain = new byte[blockSize, blockSize];

            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    cMatrixFromMain[row, col] = mat[row, col];
                }
            }

            for (int col = 0; col < 4; col++)
            {
                mat[0, col] = (byte)((int)mixColMby02(cMatrixFromMain[0, col]) ^ (int)mixColMby03(cMatrixFromMain[1, col]) ^ (int)mixColMby01(cMatrixFromMain[2, col]) ^ (int)mixColMby01(cMatrixFromMain[3, col]));
                mat[1, col] = (byte)((int)mixColMby01(cMatrixFromMain[0, col]) ^ (int)mixColMby02(cMatrixFromMain[1, col]) ^ (int)mixColMby03(cMatrixFromMain[2, col]) ^ (int)mixColMby01(cMatrixFromMain[3, col]));
                mat[2, col] = (byte)((int)mixColMby01(cMatrixFromMain[0, col]) ^ (int)mixColMby01(cMatrixFromMain[1, col]) ^ (int)mixColMby02(cMatrixFromMain[2, col]) ^ (int)mixColMby03(cMatrixFromMain[3, col]));
                mat[3, col] = (byte)((int)mixColMby03(cMatrixFromMain[0, col]) ^ (int)mixColMby01(cMatrixFromMain[1, col]) ^ (int)mixColMby01(cMatrixFromMain[2, col]) ^ (int)mixColMby02(cMatrixFromMain[3, col]));
            }
        }
        string[] SubBytes(string[] cipherMatrix)
        {

            string[] resultMatrix2 = new string[cipherMatrix.Length];
            int ind1, ind2;
            for (int i = 0; i < cipherMatrix.Length; i++)
            {
                ind1 = int.Parse((cipherMatrix[i][0]).ToString(), System.Globalization.NumberStyles.HexNumber);
                ind2 = int.Parse((cipherMatrix[i][1]).ToString(), System.Globalization.NumberStyles.HexNumber);
                string newCipherElement = sbox[ind1, ind2];
                resultMatrix2[i] = String.Concat(newCipherElement[2], newCipherElement[3]);


            }

            return resultMatrix2;
        }
        string[,] ExpandKey(string[,] previousKey, int currentKeyindex)
        {

            string[,] key2 = new string[4, 4];
            string[] w3shifted = new string[4];
            //shiftby1
            for (int i = 1; i < 4; i++)
            {
                //Talet col??
                w3shifted[i - 1] = previousKey[i, 3];
            }
            w3shifted[3] = previousKey[0, 3];
            w3shifted = SubBytes(w3shifted);
            //Na2es Nehot Subbyte Henaaaa b3d l shift
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    if (j == 0)
                    {
                        int K1W0 = Convert.ToInt32(previousKey[i, j], 16);
                        int updatedW3 = Convert.ToInt32(w3shifted[i], 16);
                        //El -1 ab2a ashofha
                        int rcon = Convert.ToInt32(Rcon[i, currentKeyindex], 16);
                        key2[i, j] = (K1W0 ^ updatedW3 ^ rcon).ToString("X");
                    }
                    else
                    {
                        int K1SameCol = Convert.ToInt32(previousKey[i, j], 16);
                        int K2PrevCol = Convert.ToInt32(key2[i, j - 1], 16);
                        key2[i, j] = (K1SameCol ^ K2PrevCol).ToString("X");
                    }
                    if (key2[i, j].Length == 1)
                    {
                        key2[i, j] = "0" + key2[i, j];
                    }

                }
            }
            return key2;

        }
        void byteprintMatrix(byte[,] matrix)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    Console.Write(matrix[i, j] + " ");
                }
                Console.WriteLine();
            }
            Console.WriteLine("----------------------");
        }
        void printMatrix(string[,] matrix)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    Console.Write(matrix[i, j] + " ");
                }
                Console.WriteLine();
            }
            Console.WriteLine("----------------------");
        }
        string[,] Swap(string[,] cipherMatrix, int i)
        {
            int col = i;
            for (int q = 0; q < i; q++)
            {
                resultMatrix[i, 4 - i + q] = cipherMatrix[i, q];
            }
            for (int j = 0; j < 4 - i; j++)
            {
                resultMatrix[i, col - i] = cipherMatrix[i, col];
                col++;
            }
            return resultMatrix;
        }
        string[,] ShiftRows(string[,] cipherMatrix)
        {
            for (int w = 0; w < 4; w++)
                resultMatrix[0, w] = cipherMatrix[0, w];
            for (int i = 1; i < 4; i++)
            {
                resultMatrix = Swap(cipherMatrix, i);
            }
            return resultMatrix;
        }
        string[,] DoSubBytes(string[,] cipherMatrix)
        {
            int rows = cipherMatrix.GetLength(0);
            int col = cipherMatrix.GetLength(1);
            string[,] resultMatrix2 = new string[rows, col];
            int ind1, ind2;
            for (int y = 0; y < rows; y++)
            {
                for (int r = 0; r < col; r++)
                {
                    ind1 = int.Parse((cipherMatrix[y, r][0]).ToString(), System.Globalization.NumberStyles.HexNumber);
                    ind2 = int.Parse((cipherMatrix[y, r][1]).ToString(), System.Globalization.NumberStyles.HexNumber);
                    string newCipherElement = sbox[ind1, ind2];
                    resultMatrix2[y, r] = String.Concat(newCipherElement[2], newCipherElement[3]);
                }
            }
            return resultMatrix2;
        }
        string[,] AddRoundKey(string[,] cipherMatrix, string[,] keyMatrix)
        {
            string[,] result = new string[4, 4];
            int ind1, ind2, keyed1, keyed2;
            string xored1, xored2;
            for (int d = 0; d < 4; d++)
            {
                for (int r = 0; r < 4; r++)
                {
                    ind1 = int.Parse((cipherMatrix[d, r][0]).ToString(), System.Globalization.NumberStyles.HexNumber);
                    keyed1 = int.Parse((keyMatrix[d, r][0]).ToString(), System.Globalization.NumberStyles.HexNumber);
                    xored1 = (ind1 ^ keyed1).ToString("x");
                    ind2 = int.Parse((cipherMatrix[d, r][1]).ToString(), System.Globalization.NumberStyles.HexNumber);
                    keyed2 = int.Parse((keyMatrix[d, r][1]).ToString(), System.Globalization.NumberStyles.HexNumber);
                    xored2 = (ind2 ^ keyed2).ToString("x");
                    result[d, r] = string.Concat(xored1, xored2);
                }
            }
            return result;
        }
        string[,] DoMixColumns(string[,] cipherMatrix)
        {
            string[,] result = new string[4, 4];
            for (int w = 0; w < 4; w++)
            {
                for (int e = 0; e < 4; e++)
                {

                }
            }
            return result;
        }
        private byte[,] generateByteMatrix(int blockSize, string text) {
            byte[,] mat = new byte[blockSize, blockSize];
            for (int i = 0; i < blockSize * blockSize; i++) {
                string tempText = text[2 * i + 2] + "" + text[2 * i + 3];
                int rowIdx = i % blockSize;
                int colIdx = i / blockSize;
                //Convert to hexadecimal
                mat[rowIdx, colIdx] = Convert.ToByte(tempText, 16);
            }
            return mat;
        }
        public override string Decrypt(string cipherText, string key)
        {
            byte[,] keyMatrix = generateByteMatrix(4,key);
            byte[,] cipherMatrix = generateByteMatrix(4,cipherText);

            int no_Rounds = numberOfRounds(Key_Size.Bits128);
            createKeyExpansionMatrix(no_Rounds, 4 , keySize, ref keyMatrix);
            addRoundKeyFun(no_Rounds , ref cipherMatrix);
            for (int round = no_Rounds - 1; round > 0; round--)
            {
                inverseShiftedRows(ref cipherMatrix, 4);
                getInverseSubBytes(ref cipherMatrix);
                addRoundKeyFun(round,ref cipherMatrix);
                inverseMixedColumns(4,ref cipherMatrix);
            }
            inverseShiftedRows(ref cipherMatrix, 4);
            getInverseSubBytes(ref cipherMatrix);
            addRoundKeyFun(0, ref cipherMatrix);
            string plainText = "0x";
            for (int i = 0; i < 4 * 4; i++)
            {
                int rowIdx = i % 4;
                int colIdx = i / 4;
                plainText += cipherMatrix[rowIdx, colIdx].ToString("X2");
            }
            return plainText;

        }

        public override string Encrypt(string plainText, string key)
        {
            string[,] matrix = new string[4, 4];
            string[,] keyMatrix = new string[4, 4];
            string[,] cipherMatrix = new string[4, 4];
            string[,] result = new string[4, 4];
            string finalResult = "";
            int k = 2;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    matrix[i, j] = string.Concat(plainText[k], plainText[k + 1]);
                    keyMatrix[i, j] = string.Concat(key[k], key[k + 1]);
                    k += 2;
                }
            }
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    int d1 = Convert.ToInt32(matrix[i, j], 16);
                    int d2 = Convert.ToInt32(keyMatrix[i, j], 16);
                    cipherMatrix[i, j] = (d1 ^ d2).ToString("x");
                    if (cipherMatrix[i, j].Length == 1)
                        cipherMatrix[i, j] = "0" + cipherMatrix[i, j];
                }
            }
            //ExpandKey
            List<string[,]> KeysList = new List<string[,]>();
            string[,] tempMatrix = keyMatrix;
            for (int i = 1; i <= 10; i++)
            {
                string[,] newkey = ExpandKey(tempMatrix, i);


                KeysList.Add(newkey);
                tempMatrix = newkey;
            }
            Console.WriteLine(KeysList.Count);
            printMatrix(matrix);
            string[,] input = new string[4, 4];
            //First Round
            printMatrix(keyMatrix);
            input = AddRoundKey(matrix, keyMatrix);
            //ROUND
            for (int q = 0; q < 9; q++)
            {
                printMatrix(input);
                input = DoSubBytes(input);
                printMatrix(input);
                input = ShiftRows(input);
                printMatrix(input);
                byte[,] byteResult = new byte[4, 4];
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        byteResult[i, j] = Convert.ToByte(input[i, j], 16);
                    }
                }
                MixedColumns(4, ref byteResult);
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        input[i, j] = Convert.ToString(byteResult[i, j], 16);
                        if (input[i, j].Length == 1)
                        {
                            input[i, j] = "0" + input[i, j];
                        }
                    }
                }
                //printMatrix(KeysList[q]);
                input = AddRoundKey(input, KeysList[q]);

            }
            input = DoSubBytes(input);
            printMatrix(input);
            input = ShiftRows(input);
            printMatrix(input);
            input = AddRoundKey(input, KeysList[9]);
            string ciphertext = "0x";
            for (int i = 0; i < 4 * 4; i++)
            {
                int rowIdx = i % 4;
                int colIdx = i / 4;
                ciphertext += input[rowIdx, colIdx].ToString().ToUpper();
            }
            Console.WriteLine(ciphertext);


            return ciphertext;

        }

        #region GaliosFieldMat
      

        private static byte mixColMby02(byte b)
        {
            if (b < 0x80) 
                return (byte)(b << 1);
            else
                return (byte)((b << 1) ^ (0x1b));
        }
        private static byte mixColMby01(byte b)
        {
            return b;
        }
        private static byte mixColMby0b(byte b)
        {
            return (byte)(mixColMby02(mixColMby02(mixColMby02(b))) ^
                           mixColMby02(b) ^
                           b);
        }

        private static byte mixColMby09(byte b)
        {
            return (byte)(mixColMby02(mixColMby02(mixColMby02(b))) ^ b);  //it's like 2*2*2*1 -or- 2 xor 2 xor 2 xor 1
        }
        private static byte mixColMby03(byte b)
        {
            return (byte)(mixColMby02(b) ^ b);
        }

        private static byte mixColMby0e(byte b)
        {
            return (byte)(mixColMby02(mixColMby02(mixColMby02(b))) ^
                           mixColMby02(mixColMby02(b)) ^
                           mixColMby02(b));
        }

        private static byte mixColMby0d(byte b)
        {
            return (byte)(mixColMby02(mixColMby02(mixColMby02(b))) ^
                           mixColMby02(mixColMby02(b)) ^
                           (b));
        }

        

        #endregion GaliosFieldMat
    }
}
