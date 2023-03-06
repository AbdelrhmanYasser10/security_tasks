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
            throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherValues = new List<int>();
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
            return cipherValues;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

    }
}
