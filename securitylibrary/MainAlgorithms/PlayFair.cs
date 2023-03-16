using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public static string removeDuplicates(string str)
        {
            string resultString = string.Empty;
            for (int i = 0; i < str.Length; i++)
            {
                if (!resultString.Contains(str[i]))
                {
                    resultString += str[i];
                }
            }
            return resultString;
        }
        public string Decrypt(string cipherText, string key)
        {

            //reference for letters in english
            string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            key = key.ToUpper();
            cipherText = cipherText.ToUpper();


            key = key.Replace('J', 'I');
            alphabet = alphabet.Replace('J', 'I');


            //merge key and the alphabet
            key += alphabet;

            //remove duplicates
            string letters = removeDuplicates(key);


            //matrix form
            char[,] matrix = new char[5, 5];
            int rows = 0, cols = 0;
            for (int i = 0; i < letters.Length; i++)
            {
                matrix[rows, cols] = letters[i];
                //Console.WriteLine(matrix[rows, cols]);  
                cols++;
                if (cols == 5)
                {
                    cols = 0;
                    rows++;
                }
            }

            int rowIndex1st = 0, rowIndex2nd = 0, colIndex1st = 0, colIndex2nd = 0;

            string outputString = string.Empty;
            for (int letter = 0; letter < cipherText.Length; letter += 2)
            {
                // find the place of the 2 characters
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (matrix[i, j] == cipherText[letter])
                        {
                            rowIndex1st = i;
                            colIndex1st = j;
                        }
                        if (matrix[i, j] == cipherText[letter + 1])
                        {
                            colIndex2nd = j;
                            rowIndex2nd = i;
                        }
                    }
                }
                // 1st special case
                if (rowIndex1st == rowIndex2nd)
                {
                    if ((colIndex1st - 1) != -1)
                    {
                        colIndex1st = colIndex1st - 1;
                    }
                    else
                    {
                        colIndex1st = (colIndex1st - 1) + 5;
                        //Console.WriteLine(colIndex1st);
                    }
                    if ((colIndex2nd - 1) != -1)
                    {
                        colIndex2nd = colIndex2nd - 1;
                    }
                    else
                    {
                        colIndex2nd = (colIndex2nd - 1) + 5;
                    }
                    outputString += matrix[rowIndex1st, colIndex1st];
                    outputString += matrix[rowIndex2nd, colIndex2nd];

                }
                // 2nd special case
                else if (colIndex2nd == colIndex1st)
                {
                    if ((rowIndex1st - 1) != -1)
                    {
                        rowIndex1st = rowIndex1st - 1;
                    }
                    else
                    {
                        rowIndex1st = (rowIndex1st - 1) + 5;
                    }
                    if ((rowIndex2nd - 1) != -1)
                    {
                        rowIndex2nd = rowIndex2nd - 1;
                    }
                    else
                    {
                        rowIndex2nd = (rowIndex2nd - 1) + 5;
                    }
                    outputString += matrix[rowIndex1st, colIndex1st];
                    outputString += matrix[rowIndex2nd, colIndex1st];
                }
                // normal case
                else
                {
                    outputString += matrix[rowIndex1st, colIndex2nd];
                    outputString += matrix[rowIndex2nd, colIndex1st];
                }

            }

            if (!outputString.Contains("X"))
            {
                return outputString;
            }


            if (outputString[outputString.Length - 1] == 'X')
            {
                outputString = outputString.Remove((outputString.Length) - 1);
            }
            for (int i = 1; i < outputString.Length - 1; i += 2)
            {
                if (outputString[i] == 'X' && outputString[i - 1] == outputString[i + 1])
                {
                    outputString = outputString.Remove(i, 1);
                    //LAZMMM N INSERTT HAGA 3SHANN ELTEST CASE MTHZANSHHHH
                    outputString = outputString.Insert(i, ".");
                }
            }
            if (outputString.Contains("."))
            {
                outputString = outputString.Replace(".", "");
            }

            return outputString;
        }

        public string Encrypt(string plainText, string key)
        {
            key = key.ToUpper();
            plainText = plainText.ToUpper();
            string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";


            key = key.Replace('J', 'I');
            alphabet = alphabet.Replace('J', 'I');


            //merge key and the alphabet
            key += alphabet;

            //remove duplicates
            string letters = removeDuplicates(key);

            string plainTextWithX = string.Empty;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (i == (plainText.Length - 1))
                {
                    plainTextWithX += plainText[i];
                    plainTextWithX += 'X';
                    break;
                }

                plainTextWithX += plainText[i];
                if (plainText[i].CompareTo(plainText[i + 1]) == 0)
                {
                    plainTextWithX += 'X';
                }
                else
                {
                    plainTextWithX += plainText[i + 1];
                    i++;
                }
            }

            //Console.WriteLine(plainTextWithX.ToString());   
            // matrix form
            char[,] matrix = new char[5, 5];
            int rows = 0, cols = 0;
            for (int i = 0; i < letters.Length; i++)
            {
                matrix[rows, cols] = letters[i];
                cols++;
                if (cols == 5)
                {
                    cols = 0;
                    rows++;
                }

            }

            int rowIndex1st = 0, rowIndex2nd = 0, colIndex1st = 0, colIndex2nd = 0;
            string outputString = string.Empty;

            for (int letter = 0; letter < plainTextWithX.Length; letter += 2)
            {
                // find the place of the 2 characters
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (matrix[i, j] == plainTextWithX[letter])
                        {
                            rowIndex1st = i;
                            colIndex1st = j;
                        }
                        if (matrix[i, j] == plainTextWithX[letter + 1])
                        {
                            colIndex2nd = j;
                            rowIndex2nd = i;
                        }

                    }
                }
                // 1st special case
                if (rowIndex1st == rowIndex2nd)
                {

                    outputString += matrix[rowIndex1st, (colIndex1st + 1) % 5];
                    outputString += matrix[rowIndex1st, (colIndex2nd + 1) % 5];

                }
                // 2nd special case
                else if (colIndex1st == colIndex2nd)
                {
                    outputString += matrix[(rowIndex1st + 1) % 5, colIndex1st];
                    outputString += matrix[(rowIndex2nd + 1) % 5, colIndex1st];
                }
                // normal case
                else
                {
                    outputString += matrix[rowIndex1st, colIndex2nd];
                    outputString += matrix[rowIndex2nd, colIndex1st];
                }
            }

            return outputString;
        }
    }
}