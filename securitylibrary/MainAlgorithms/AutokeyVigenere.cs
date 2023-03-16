using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            string output = "";
            for (int k = 0; k < plainText.Length; k++)
            {
                output += getTheChar(cipherText[k], plainText[k], false);
            }
            string keyTrial = "";
            keyTrial += output[0];

            for (int i = 1; i < output.Length; i++)
            {
                if (cipherText == Encrypt(plainText, keyTrial))
                {
                    return keyTrial;
                }
                keyTrial += output[i];
            }

            return output;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();

            string plainText = "";
            for (int k = 0; k < cipherText.Length; k++)
            {
                plainText += getTheChar(cipherText[k], key[k], false);
                key += plainText[k];
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            if (plainText.Length > key.Length)
            {
                string newKey = key;
                int counter = 0;
                while (newKey.Length < plainText.Length)
                {
                    newKey += plainText[counter % plainText.Length];
                    counter++;
                }
                key = newKey;
            }
            string cipherText = "";

            for (int k = 0; k < plainText.Length; k++)
            {
                cipherText += getTheChar(plainText[k], key[k] , true);
            }
            return cipherText;
        }
        private char getTheChar(char firstChar, char SecondChar, bool encrypt)
        {
            int idx;
            string allChars = "abcdefghijklmnopqrstuvwxyz";
            if (encrypt)
            {
                idx = (allChars.IndexOf(firstChar) + allChars.IndexOf(SecondChar)) % 26;
                return allChars[idx];
            }
            else
            {
                idx = allChars.IndexOf(firstChar) - allChars.IndexOf(SecondChar) + 26;
                idx = idx % 26;
                return allChars[idx];
            }

        }

    }
}
