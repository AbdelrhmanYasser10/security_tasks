using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string CipherText = cipherText.ToLower();
            string PlainText = plainText.ToLower();
            char[] alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToLower().ToCharArray();
            char[] Key = new char[26];
            Dictionary<char, int> map = new Dictionary<char, int>();
            string aa = new string(alpha.ToArray());
            List<char> Notfound = new List<char>();
            if (PlainText.Equals(aa) || PlainText.Equals(aa, StringComparison.InvariantCultureIgnoreCase) == true || aa == PlainText)
            {
                return CipherText;
            }
            for (int i = 0; i < alpha.Length; i++)
            {
                map.Add(alpha[i], i);
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = map[plainText[i]];
                Key[index] = CipherText[i];
            }
            for (int i = 0; i < alpha.Length; i++)
            {
                if (!Key.Contains(alpha[i]))
                {
                    Notfound.Add(alpha[i]);
                }
            }
            for (int i = 0; i < Key.Length; i++)
            {
                if (Key[i] == '\0' || Key[i] == null)
                {
                    int lastelement = Notfound.Count - 1;
                    Key[i] = Notfound[lastelement];
                    Notfound.RemoveAt(lastelement);
                }
            }
            var s = Key.Distinct();
            Console.WriteLine(Key.Length);
            var res = new string(s.ToArray());
            return res;
        }

        public string Decrypt(string cipherText, string key)
        {
            string CipherText = cipherText.ToLower();
            List<char> result = new List<char>();
            char[] alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            Dictionary<char, char> map = new Dictionary<char, char>();
            for (int i = 0; i < key.Length; i++)
            {
                map.Add(key[i], alpha[i]);
            }
            foreach (var es in map)
            {
                Console.WriteLine("Employee with key {0}: ID = {1}", es.Key, es.Value);
            }

            for (int i = 0; i < CipherText.Length; i++)
            {
                Console.WriteLine(CipherText[i]);
                result.Add(map[CipherText[i]]);
                Console.WriteLine(result[i]);
            }
            var res = new string(result.ToArray());

            return res.ToUpper();
        }

        public string Encrypt(string plainText, string key)
        {
            string PlainText = plainText.ToUpper();
            List<char> result = new List<char>();
            char[] alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            Dictionary<char, char> map = new Dictionary<char, char>();
            for (int i = 0; i < key.Length; i++)
            {
                map.Add(alpha[i], key[i]);
            }
            foreach (var es in map)
            {
                Console.WriteLine("Employee with key {0}: ID = {1}", es.Key, es.Value);
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                Console.WriteLine(PlainText[i]);
                result.Add(map[PlainText[i]]);
                Console.WriteLine(result[i]);
            }
            var res = new string(result.ToArray());

            return res.ToUpper();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49            etaoinsrhldcumfpgwybvkxjqz
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>

        public string AnalyseUsingCharFrequency(string cipher)
        {
            List<char> result = new List<char>();
            string frequency = "etaoinsrhldcumfpgwybvkxjqz".ToUpper();
            Dictionary<char, int> map = new Dictionary<char, int>();
            char[] alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            int counter;
            for (int i = 0; i < alpha.Length; i++)
            {
                counter = 0;

                Console.WriteLine(alpha[i]);
                Console.WriteLine("---------------------------------------------------");
                for (int j = 0; j < cipher.Length; j++)
                {

                    if (alpha[i].Equals(cipher[j]))
                    {
                        Console.WriteLine(cipher[j]);
                        counter++;
                    }
                }
                //Console.WriteLine(alpha[i]);
                //Console.WriteLine(counter);
                map.Add(alpha[i], counter);
            }

            var sortedmap = map.OrderByDescending(x => x.Value).ToList();
            Dictionary<char, char> cipherFreq = new Dictionary<char, char>();
            Console.WriteLine(sortedmap.Count);
            for (int i = 0; i < frequency.Length; i++)
            {
                Console.WriteLine($"{sortedmap[i].Key} is {sortedmap[i].Value} years old");
                //Console.WriteLine(sortedmap[i].Key);
                //Console.WriteLine(sortedmap[i].Value);
                cipherFreq.Add(sortedmap[i].Key, frequency[i]);
                Console.WriteLine($"{sortedmap[i].Key} is {frequency[i]} haaaa??");
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                Console.Write(cipherFreq[cipher[i]]);
                result.Add(cipherFreq[cipher[i]]);
            }
            var res = new string(result.ToArray());
            return res.ToLower();


        }
    }
}