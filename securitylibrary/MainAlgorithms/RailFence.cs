using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            List<int> keyValues = new List<int>();
            cipherText = cipherText.ToLower();
            char charVal = cipherText.ElementAt(1);
            int i = 0;
            foreach (char val in plainText)
            {
                if (val == charVal)
                    keyValues.Add(i);
                i++;
            }

            foreach (var value in keyValues)
            {
                string s = Encrypt(plainText, value);
                bool check = cipherText.Equals(s);
                if (check)
                {
                    return value;
                }
            }

            return -1;
        }

        public string Decrypt(string cipherText, int key)
        {
            string ans = "";
            int ptLength = (int)Math.Ceiling((decimal)cipherText.Length / (decimal)key);
            int[,] mat = new int[key,ptLength];
            for (int i = 0; i < key; i++) {
                for (int j = 0; j < ptLength; j++) {
                    mat[i, j] = -1;
                }
            }
            int index_of_char = 0;
            for (int i = 0; i < key; i++) {
                for (int j = 0; j < ptLength; j++) {
                    if (index_of_char < cipherText.Length)
                    {
                        mat[i, j] = index_of_char;
                        index_of_char++;
                    }
                }
            }
            for (int i = 0; i < ptLength; i++) {
                for (int j = 0; j < key; j++) {
                    if (mat[j, i] <= index_of_char && mat[j,i] != -1)
                    {
                        ans += cipherText[mat[j, i]];
                    }
                }
            }
            return ans;
        }

        public string Encrypt(string plainText, int key)
        {
            string trimmed = String.Concat(plainText.Where(c => !Char.IsWhiteSpace(c)));
            string ans = "";
            for (int j = 0; j < key; j++)
            {
                for (int i = j; i < trimmed.Length; i += key) {
                    ans += trimmed[i];
                }
            }
            Console.WriteLine(ans);
            return ans;
        }
    }
}
