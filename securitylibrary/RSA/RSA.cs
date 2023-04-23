using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public static int CalcuOfPower(int x, int y)
        {
            if (y == 0)
                return 1;
            else
                return x * CalcuOfPower(x, y - 1);
        }

        public int ModMultInverse(int e, int eulerValue)
        {
            double inverse = 1;

            for (int i = 1; i <= e; i++)
            {
                inverse = i * eulerValue;
                inverse++;
                inverse = inverse / e;
                if (inverse % 1 == 0)
                    break;
            }

            return (int)inverse;
        }

        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int result;
            int result1 = 1;
            for (int i = 1; i <= e; i++)
            {
                result = (CalcuOfPower(M, 1));
                result1 = (result % n) * (result1 % n);
            }
            result1 = result1 % n;
            return (int)result1;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int eluer = (p - 1) * (q - 1);
            int final_res = 1;
            int n = p * q;
            int d = ModMultInverse(e, eluer);
            for (int i = 0; i < d; i++)
            {
                final_res = final_res * C;
                final_res = final_res % n;
            }
            //final_res = final_res % n;
            return (int)final_res;
        }
    }
}
