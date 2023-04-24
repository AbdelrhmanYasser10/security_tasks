using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int Pow(int a, int b, int q)
        {
            int result = 1;
            for (int i = 0; i < b; i++)
            {
                result %= q;
                result *= a;

            }
            return result % q;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> output = new List<int>();
            int ya = Pow(alpha, xa, q);
            int yb = Pow(alpha, xb, q);
            int K = Pow(yb, xa, q);
            //I will add k of user A twice cause user A and B have the same key
            output.Add(K);
            output.Add(K);

            return output;
        }
    }
}
