using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public static int CalcuOfPower(int x, int y)
        {
            if (y == 0)
                return 1;
            else
                return x * CalcuOfPower(x, y - 1);
        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> result = new List<long>();
            double K = (Math.Pow(y, k)) % q;
            int tempRes;
            int result1 = 1;
            int result11 = 1;
            for (int i = 0; i < k; i++)
            {
                tempRes = (CalcuOfPower(y, 1));
                result1 = (tempRes % q) * (result1 % q);
            }
            result1 = result1 % q;
            for (int i = 0; i < k; i++)
            {
                tempRes = (CalcuOfPower(alpha, 1));
                result11 = (tempRes % q) * (result11 % q);
            }
            result11 = result11 % q;
            long C1 = (long)(result11 % q);
            long C2 = (long)result1 * m % q;
            result.Add(C1);
            result.Add(C2);
            return result;
            //throw new NotImplementedException();

        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            int res_K = 1;
            int pow_val = c1;
            for (int b = x; b > 0; b /= 2) {
                if (b % 2 == 1)
                {
                    res_K = (res_K * pow_val) % q;
                }
                pow_val = (pow_val * pow_val) % q;
            }
            res_K = res_K % q;
            int inverseK = (int)extendedGCD(res_K, q);
            int M = (c2 * inverseK) % q;
            return M % q;

        }
        #region[Extended GCD]
        public static long extendedGCD(long a, long b)
        {
            long s_result = b;
            //Swap values
            if (a < b)
            {
                long tmp = a;
                a = b;
                b = tmp;
            }
            long R = b,
                Q = 0,
                X0 = 1,
                Y0 = 0,
                X1 = 0,
                Y1 = 1,
                X = 0,
                Y = 0;
            while (R > 1)
            {
                R = a % b;
                Q = a / b;
                X = (X0 - Q * X1);
                Y = (Y0 - Q * Y1);
                X0 = X1;
                Y0 = Y1;
                X1 = X;
                Y1 = Y;
                a = b;
                b = R;
            }
            while (Y < 0)
                Y += s_result;
            return Y;
        }
        #endregion
    }
}
