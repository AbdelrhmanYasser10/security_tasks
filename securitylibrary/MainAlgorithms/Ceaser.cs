using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class Ceaser : ICryptographicTechnique<string, int>
    {
        string Letters = "abcdefghijklmnopqrstuvwxyz";
        public string Encrypt(string plainText, int key)
        {
            int Result = 0;
            string CipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < Letters.Length; j++)
                {
                    if (plainText[i].Equals(Letters[j]))
                    {
                        Result = (j + key) % 26;
                        CipherText += Letters[Result];

                    }
                }
            }
            return CipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int Result = 0;
            string PlainText = "";

            for (int i = 0; i < cipherText.Length; i++)
            {

                for (int j = 0; j < Letters.Length; j++)
                {
                    if (cipherText[i].Equals(Letters[j]))
                    {
                        Result = (j - key) % 26;
                        if (Result < 0)
                        {
                            PlainText += Letters[Result + 26];
                        }
                        // special case
                        else
                        {
                            PlainText += Letters[Result];
                        }
                    }
                }
            }
            return Encrypt(cipherText, 26 - key);
        }

        public int Analyse(string plainText, string cipherText)
        {

            int cipherTextIndex = 0, plainTextIndex = 0, key = 0;

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            // n3raf elindex beascii a=97
            cipherTextIndex = cipherText[0] - 97;
            plainTextIndex = plainText[0] - 97;


            if (cipherTextIndex < plainTextIndex)
            {
                key = (cipherTextIndex - plainTextIndex) + 26;
            }
            else
            {
                key = (cipherTextIndex - plainTextIndex);
            }

            return key;
        }
    }
}
