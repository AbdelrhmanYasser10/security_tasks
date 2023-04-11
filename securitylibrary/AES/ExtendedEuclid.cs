using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>

        public int GreatestCommonDivisor(int number1, int number2)
        {
            if (number2 == 0) return number1;
            else return GreatestCommonDivisor(number2, number1 % number2);

        }

        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();

            int A = 0, B = 0, T1 = 0, T2 = 1, Q, R = -1, T;
            A = baseN;
            B = number;

            if (GreatestCommonDivisor(A, B) != 1)
                return -1;
            while (true)
            {
                if (R == 0)
                {
                    if (T1 < 0)
                        return T1 + 26;
                    else
                        return T1;
                }

                Q = A / B;
                R = A % B;
                T = T1 - T2 * Q;
                A = B;
                B = R;
                T1 = T2;
                T2 = T;

            }
        }
    }
}
