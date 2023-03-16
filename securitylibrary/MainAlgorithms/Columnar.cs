using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        //"ttna aptm tsuo aodw coi knl pet"
        //"ctip scoe emrn uce"
        //cusn pre mei eot cc
        List<List<int>> Permutation(int[] arrayOfKeys, int begin, int end, List<List<int>> resultantKeys)
        {
            if (begin == end)
            {
                //kda weslna l list of desired keys
                resultantKeys.Add(new List<int>(arrayOfKeys));
            }
            else
            {
                for (var i = begin; i <= end; i++)
                {
                    Swap(ref arrayOfKeys[begin], ref arrayOfKeys[i]);
                    /*var temp = arrayOfKeys[begin];
                    arrayOfKeys[begin] = arrayOfKeys[i];
                    arrayOfKeys[i] = temp;*/
                    Permutation(arrayOfKeys, begin + 1, end, resultantKeys);
                    Swap(ref arrayOfKeys[begin], ref arrayOfKeys[i]);
                    /*temp = arrayOfKeys[begin];
                    arrayOfKeys[begin] = arrayOfKeys[i];
                    arrayOfKeys[i] = temp;*/
                }
            }

            return resultantKeys;
        }

        void Swap(ref int a, ref int b)
        {
            var temp = a;
            a = b;
            b = temp;
        }

        //Console.WriteLine("ARRAY OF KEYS");
        //for(int K=0; K<a.Length; K++)    
        //  Console.WriteLine(a[K]);

        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            List<List<int>> possibleKey = new List<List<int>>();
            for (int i = 3; i < 10; i++)
            {
                var list = new List<List<int>>();
                int[] a = Enumerable.Range(1, i).ToArray<int>();
                //Console.WriteLine("before");
                possibleKey = Permutation(a, 0, a.Length - 1, list);
                //Console.WriteLine("after");
                /*foreach (var sublist in possibleKey)
                {
                    foreach (var obj in sublist)
                    {
                        Console.Write(obj);
                    }
                    Console.WriteLine();
                }*/
                for (int j = 0; j < possibleKey.Count; j++)
                {
                    //Console.WriteLine("before 2");
                    string result = (Encrypt(plainText, possibleKey[j])).ToLower();
                    //Console.WriteLine("after 2");
                    if (result.Equals(cipherText))
                    {
                        //Console.WriteLine(possibleKey[j]);
                        Console.WriteLine("Khalasna");
                        return possibleKey[j];
                    }
                }
            }
            Console.WriteLine("Not found");
            return possibleKey[0];
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            double x = (cipherText.Length) / (key.Count);
            List<string> rows = new List<string>();
            //Console.WriteLine(cipherText.Length);
            //Console.WriteLine(key.Count);
            int depth = (int)Math.Floor(x);
            //Console.WriteLine(x);
            if ((cipherText.Length) % (key.Count) != 0)
            {
                depth += 1;
                for (int i = 0; i < (cipherText.Length) % (key.Count); i++)
                    cipherText += 'x';
            }
            //Console.WriteLine(depth);
            char[,] array = new char[depth, key.Count];
            int cipherCounter = 0;
            for (int j = 0; j < key.Count; j++)
            {
                string kdaho = "";
                for (int i = 0; i < depth; i++)
                {
                    kdaho += cipherText[cipherCounter];
                    cipherCounter++;

                }
                rows.Add(kdaho);
                //Console.WriteLine(cipherCounter);
                if (cipherCounter == cipherText.Length - 1)
                    break;
            }
            //for (int oo = 0; oo < rows.Count; oo++)
            Console.WriteLine("----------------------------");
            List<char> result = new List<char>();
            string t = "";
            for (int i = 0; i < key.Count; i++)
            {
                Console.WriteLine(rows[i]);
                //Console.WriteLine(i);
                Console.WriteLine(key.IndexOf(i + 1));
                for (int j = 0; j < depth; j++)
                {
                    array[j, key.IndexOf(i + 1)] = rows[i][j];
                    result.Add(rows[i][j]);
                    //Console.WriteLine(array[j, key.IndexOf(i + 1)]);
                }
                Console.WriteLine("----------------------------");

            }
            for (int i = 0; i < depth; i++)
            {
                for (int y = 0; y < key.Count; y++)
                    t += (array[i, y]);
            }
            Console.WriteLine(t);
            return t.ToUpper();

            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            double x = (plainText.Length) / (key.Count);
            int depth = (int)Math.Floor(x);
            if ((plainText.Length) % (key.Count) != 0) depth += 1;
            char[,] array = new char[depth, key.Count];
            int plaincounter = 0;
            for (int i = 0; i < depth; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {

                    if (plaincounter + 1 > plainText.Length)
                    {
                        array[i, j] = 'x';
                    }
                    else
                    {
                        array[i, j] = plainText[plaincounter];
                    }
                    plaincounter++;
                }
            }
            List<char> result = new List<char>();
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < depth; j++)
                {
                    result.Add(array[j, key.IndexOf(i + 1)]);
                }
            }
            string res = new string(result.ToArray());
            //Console.WriteLine(res);
            return res.ToUpper();

        }
    }
}