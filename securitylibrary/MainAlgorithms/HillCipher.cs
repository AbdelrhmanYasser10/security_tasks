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
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            for (int firstVal = 0; firstVal < 26; firstVal++)
            {
                for (int secondVal = 0; secondVal < 26; secondVal++)
                {
                    for (int thirdVal = 0; thirdVal < 26; thirdVal++)
                    {
                        for (int forthVal = 0; forthVal < 26; forthVal++)
                        {
                            List<int> tst_key = new List<int>(new[] { firstVal, secondVal, thirdVal, forthVal });
                            List<int> enc_val = Encrypt(plainText, tst_key);
                            bool check = true;
                            int i = 0;
                            foreach (int val in enc_val) {
                                if (val != cipherText[i]) {
                                    check = false;
                                }
                                i++;
                            }
                            if (check)
                            {
                                return tst_key;
                            }

                        }
                    }
                }
            }

            throw new InvalidAnlysisException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plainText = new List<int>();
            
            // That's mean the key matrix is 2 by 2
            if (key.Count == 4)
            {
                List<double> keyD = key.ConvertAll(x => (double)x);
                double factor = 1 / (keyD[0] * keyD[3] - keyD[1] * keyD[2]);
                int[,] keyMat = new int[2, 2];
                double[,] first_mat = new double[2, 2];

                first_mat[0, 0] = key[3] * factor;
                first_mat[0, 1] = key[1] * -1 * factor;
                first_mat[1, 0] = key[2] * -1 * factor;
                first_mat[1, 1] = key[0] * factor;
                Console.WriteLine(Math.Abs((double)first_mat[0, 0]).ToString());
                if (Math.Abs((int)first_mat[0, 0]).ToString() != Math.Abs((double)first_mat[0, 0]).ToString())
                {
                    throw new SystemException();
                }
                else {
                    keyMat[0, 0] =(int) (key[3] * factor);
                    keyMat[0, 1] = (int)(key[1] * -1 * factor);
                    keyMat[1, 0] = (int)(key[2] * -1 * factor);
                    keyMat[1, 1] = (int)(key[0] * factor);
                }
                int colSize = (int)Math.Ceiling((decimal)(cipherText.Count / 2));
                int[,] cipherTextMatrix = new int[2, colSize];
                int cipherCounter = 0;
                for (int i = 0; i < colSize; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        cipherTextMatrix[j, i] = cipherText[cipherCounter];
                        cipherCounter++;
                    }
                }
                for (int i = 0; i < cipherTextMatrix.GetLength(1); i++)
                {
                    int[,] vec = new int[2, 1];
                    for (int j = 0; j < 2; j++)
                    {
                        vec[j, 0] = cipherTextMatrix[j, i];
                    }
                    int[,] result = MultiplyMatrix(keyMat, vec);

                    for (int c = 0; c < result.GetLength(0); c++)
                    {
                        for (int o = 0; o < result.GetLength(1); o++)
                        {
                            if (result[c, o] > 0)
                            {
                                plainText.Add(result[c, o] % 26);
                            }
                            else
                            {
                                plainText.Add((result[c, o]%26 + 26) % 26);
                            }
                        }
                    }
                }
            }
            // That's mean the key matrix is 3 by 3 or more
            else {
                int det = 0;
                int[,] keyMat = new int[3, 3];
                int keyCounter = 0;
                for (int i = 0; i < 3; i++) {
                    for (int j = 0; j < 3; j++) {
                        keyMat[i, j] = key[keyCounter];
                        keyCounter++;
                    }
                }
                for (int i = 0; i < 3; i++)
                    det = det + (keyMat[0, i] * (keyMat[1, (i + 1) % 3] * keyMat[2, (i + 2) % 3] - keyMat[1, (i + 2) % 3] * keyMat[2, (i + 1) % 3]));
                if (det < 0) {
                    det = (det % 26 + 26) % 26;
                }
                int b;
                int c;
                for (int i = 1; ; i++) {
                    if ((det * (26 - i)) % 26 == 1) {
                        c = i;
                        break;
                    }
                }
                b = 26 - c;
                //Calc new matrix
                int[,] newKeyMat = new int[3, 3];
                for (int i = 0; i < 3; i++) {
                    for (int j = 0; j < 3; j++) {
                        List<int> detVal = new List<int>();
                        for (int v = 0; v < 3; v++) {
                            for (int k = 0; k < 3; k++) {
                                if (v == i || k == j) {
                                    continue;
                                }
                                detVal.Add(keyMat[v, k]);
                            }
                        }
                        int temp = 0;
                        temp = detVal[0] * detVal[3] - detVal[1] * detVal[2];
                        int value = (int)(b * Math.Pow(-1, (i + j)) * temp) % 26;
                        if (value < 0) {
                            value = (value + 26) % 26;
                        }
                        newKeyMat[i, j] = value;
                    }
                }
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {

                        keyMat[j, i] = newKeyMat[i, j];
                    }
                }
                int cipherCounter = 0;
                int matSize = (int)Math.Ceiling(Math.Sqrt(key.Count));
                int colSize = (int)Math.Ceiling((decimal)(cipherText.Count / matSize));
                int[,] cipherMatrix = new int[matSize, colSize];
                for (int i = 0; i < colSize; i++)
                {
                    for (int j = 0; j < matSize; j++)
                    {
                        cipherMatrix[j, i] = cipherText[cipherCounter];
                        cipherCounter++;
                    }
                }
                for (int i = 0; i < cipherMatrix.GetLength(1); i++)
                {
                    int[,] vec = new int[3, 1];
                    for (int j = 0; j < 3; j++)
                    {
                        vec[j, 0] = cipherMatrix[j, i];
                    }
                    int[,] result = MultiplyMatrix(keyMat, vec);
                    for (int k = 0; k < result.GetLength(0); k++)
                    {
                        for (int o = 0; o < result.GetLength(1); o++)
                        {
                            if (result[k, o] > 0)
                            {
                                plainText.Add(result[k, o] % 26);
                            }
                            else
                            {
                                plainText.Add((result[k, o] % 26 + 26) % 26);
                            }
                            
                        }
                    }
                }
            }

            return plainText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherValues = new List<int>();
            //*First Solution (static)
            /*
            int key_length = key.Count;
            //mat 2x2
            if (key_length == 4)
            {
                for (int i = 0; i < plainText.Count; i+= 2) {
                    int first_val = (key[0] * plainText[i] + key[1] * plainText[i + 1]) % 26;
                    int second_val = (key[2] * plainText[i] + key[3] * plainText[i + 1]) %26;
                    cipherValues.Add(first_val);cipherValues.Add(second_val);
                }
            }
            //mat 3x3
            else {
                for (int i = 0; i < plainText.Count; i+=3)
                {
                    int first_val = (key[0] * plainText[i] + key[1] * plainText[i + 1] + key[2] * plainText[i + 2]) % 26;
                    int second_val = (key[3] * plainText[i] + key[4] * plainText[i + 1] + key[5] * plainText[i + 2]) % 26;
                    int third_val = (key[6] * plainText[i] + key[7] * plainText[i + 1] + key[8] * plainText[i + 2]) % 26;
                    cipherValues.Add(first_val); cipherValues.Add(second_val);cipherValues.Add(third_val);
                }
            }
            */

            //*Second Solution Dynamic
            int matSize = (int)Math.Ceiling(Math.Sqrt(key.Count));
            int colSize = (int)Math.Ceiling((decimal)(plainText.Count / matSize));
            int[,] keyMatrix = new int[matSize, matSize];
            int[,] plainTextMatrix = new int[matSize, colSize];
            int keyCounter = 0;
            for (int i = 0; i < matSize; i++) {
                for (int j = 0; j < matSize; j++) {
                    keyMatrix[i , j] = key[keyCounter];
                    keyCounter++;
                }
            }
            int plainTextCounter = 0;
            for (int i = 0; i < colSize; i++) {
                for (int j = 0; j < matSize; j++) {
                    plainTextMatrix[j, i] = plainText[plainTextCounter];
                    plainTextCounter++;
                }
            }

            for (int i = 0; i < plainTextMatrix.GetLength(1); i++) {
                int[,] vec = new int[matSize, 1];
                for (int j = 0; j < matSize ; j++) {
                    vec[j, 0] = plainTextMatrix[j, i];
                }
                int[,] result = MultiplyMatrix(keyMatrix, vec);
        
                for (int c = 0; c < result.GetLength(0); c++) {
                    for (int o = 0; o < result.GetLength(1); o++) {
                        cipherValues.Add(result[c, o] % 26);
                    }
                }
            }
            return cipherValues;
        }
        private int[,] MultiplyMatrix(int[,] matA, int[,] matB)
        {
            int rowACount = matA.GetLength(0);
            int colACount = matA.GetLength(1);
            int rowBCount = matB.GetLength(0);
            int colBCount = matB.GetLength(1);

            if (colACount != rowBCount)
            {
                return null;
            }
            else
            {
                int temp = 0;
                int[,] res = new int[rowACount, colBCount];

                for (int i = 0; i < rowACount; i++)
                {
                    for (int j = 0; j < colBCount; j++)
                    {
                        temp = 0;
                        for (int k = 0; k < colACount; k++)
                        {
                            temp += matA[i, k] * matB[k, j];
                        }
                        res[i, j] = temp;
                    }
                }

                return res;
            }
        }

        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();
            int[,] keyMatrix = new int[3,3];
            int m = (int)Math.Sqrt(cipherText.Count);
            int colSizeCipher = (int)cipherText.Count / m;
            int colSizePlain = (int)plainText.Count / m;
            int[,] plainTextMat = new int[3,m];
            int[,] cipherTextMat = new int[3,m];

            int plainTextCounter = 0;
            int cipherCounter = 0;
            for (int i = 0; i < colSizePlain; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    plainTextMat[j, i] = plainText[plainTextCounter];
                    plainTextCounter++;
                }
            }

            for (int i = 0; i < colSizeCipher; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    cipherTextMat[j, i] = cipherText[cipherCounter];
                    cipherCounter++;
                }
            }
            int[,] newPlainTextMat = new int[3, 3];
            int c = plainTextMat[0, 0] * (plainTextMat[1, 1] * plainTextMat[2, 2] - plainTextMat[1, 2] * plainTextMat[2, 1]) -
                       plainTextMat[0, 1] * (plainTextMat[1, 0] * plainTextMat[2, 2] - plainTextMat[1, 2] * plainTextMat[2, 0]) +
                       plainTextMat[0, 2] * (plainTextMat[1, 0] * plainTextMat[2, 1] - plainTextMat[1, 1] * plainTextMat[2, 0]);
            c = (int)c % 26 >= 0 ? (int)c % 26 : (int)c % 26 + 26;
            int b = 0;
            for (int i = 0; i < 26; i++)
            {
                if (c * i % 26 == 1)
                {
                    b = i;
                }
            }

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    List<int> detVal = new List<int>();
                    for (int v = 0; v < 3; v++)
                    {
                        for (int k = 0; k < 3; k++)
                        {
                            if (v == i || k == j)
                            {
                                continue;
                            }
                            detVal.Add(plainTextMat[v, k]);
                        }
                    }
                    int temp = 0;
                    temp = detVal[0] * detVal[3] - detVal[1] * detVal[2];
                    int value = (int)(b * Math.Pow(-1, (i + j)) * temp) % 26;
                    if (value < 0)
                    {
                        value = (value + 26) % 26;
                    }
                    newPlainTextMat[i, j] = value;
                }
            }
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {

                    plainTextMat[j, i] = newPlainTextMat[i, j];
                }
            }
            keyMatrix = MultiplyMatrix(cipherTextMat, plainTextMat);
           
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {

                   key.Add(keyMatrix[i, j] % 26);
                }
            }
            return key;
        }

    }
}
