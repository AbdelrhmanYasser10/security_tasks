using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);
        }

        public override  string Encrypt(string plainText, string key)
        {
            bool hexadecimalval = false;
            if (plainText[0] == '0' && plainText[1] == 'x')
                hexadecimalval = true;

            if (hexadecimalval)
            {
                plainText = hex2str(plainText);
                key = hex2str(key);
            }
            int[] s = new int[256];
            int j = 0;
            //init
            for (int i = 0; i < 256; i++) {
                s[i] = i;
            }
            //Swap
            for (int i = 0; i < 256; i++) {
                j = (j + s[i] + key[i % key.Length]) % 256;
                int temp = s[i];
                s[i] = s[j];
                s[j] = temp;
            }
            j = 0;
            int l = 0;
            string ciphertxt = "";
            for (int i = 0; i < plainText.Length; i++) {
                l = (l + 1) % 256;
                j = (j + s[l]) % 256;
                //Swap
                int temp = s[l];
                s[l] = s[j];
                s[j] = temp;

                //init 
                int t = (s[l] + s[j]) % 256;
                int k = s[t];

                // XOR
                char cipher = (char)(plainText[i] ^ k);
                ciphertxt += cipher;
            }
            if (hexadecimalval)
            {
                string cipherVaL = "0x";

                for (int i = 0; i < ciphertxt.Length; i++)
                {
                    int value = ciphertxt[i] / 16;
                    int moduleVal = ciphertxt[i] % 16;

                    if (value >= 0 && value <= 9)
                        value += '0';
                    if (value >= 10 && value <= 15)
                        value = 'a' + (value - 10);
                    if (moduleVal >= 0 && moduleVal <= 9)
                        moduleVal += '0';
                    if (moduleVal >= 10 && moduleVal <= 15)
                        moduleVal = 'a' + (moduleVal - 10);


                    cipherVaL += (char)(value);
                    cipherVaL += (char)(moduleVal);
                }
                //Console.WriteLine(cipherVaL);
                return cipherVaL;

            }
            //Console.WriteLine(ciphertxt);
            return ciphertxt;
        }
        #region hex2str
        private string hex2str(string ptxt)
        {
            string tem2str = "", preval = "";
            ptxt += '1';

            for (int i = 2; i < ptxt.Length; i++)
            {
                if (i % 2 == 0 && tem2str.Length == 2)
                {
                    int a = 0, b = 0;
                    int firstChar = tem2str[0];
                    int secondChar = tem2str[1];
                    if (firstChar >= '0' && firstChar <= '9')
                        a = firstChar - '0';

                    else if (firstChar >= 'a' && firstChar <= 'f')
                        a = firstChar  - 'a' + 10;

                    if (secondChar >= '0' && secondChar <= '9')
                        b = secondChar - '0';

                    else if (secondChar >= 'a' && secondChar <= 'f')
                        b = secondChar - 'a' + 10;


                    preval += (char)((16 * a) + b);
                    tem2str = "";
                }
                tem2str += ptxt[i];
            }
            return preval;
        }
        #endregion
    }
}
