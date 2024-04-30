using System.Security.Cryptography;
/*
Copyright (C) 2004, OATH.  All rights reserved.

License to copy and use this software is granted provided that it
is identified as the "OATH HOTP Algorithm" in all material
mentioning or referencing this software or this function.

License is also granted to make and use derivative works provided
that such works are identified as
 "derived from OATH HOTP algorithm"
in all material mentioning or referencing the derived work.

OATH (Open AuTHentication) and its members make no
representations concerning either the merchantability of this
software or the suitability of this software for any particular
purpose.

It is provided "as is" without express or implied warranty
of any kind and OATH AND ITS MEMBERS EXPRESSaLY DISCLAIMS
ANY WARRANTY OR LIABILITY OF ANY KIND relating to this software.

These notices must be retained in any copies of any part of this
documentation and/or software.
*/

/// <summary>
/// This class contains static methods that are used to calculate the
/// One-Time Password (OTP) using
/// JCE to provide the HMAC-SHA-1.
///  
/// @author Loren Hart
/// @version 1.0
/// </summary>
public class HOTP
{
    private static int[] DIGITS_POWER
         //  0  1   2    3     4      5       6        7         8
         = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
    // These are used to calculate the check-sum digits.
    private static int[] doubleDigits =
                        { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };

    public static void Test()
    {
        var key = StringToByteArray("3132333435363738393031323334353637383930");
        System.Console.WriteLine($"Count\tHOTP");
        for (ulong i = 0UL; i < 10; i++)
        {
            System.Console.WriteLine($"{i}\t{generateOTP(key, i, 6, false)}");
        }
    }

    public static string ByteArrayToString(byte[] ba)
    {
        return BitConverter.ToString(ba).Replace("-", "");
    }
    public static byte[] StringToByteArray(string hex)
    {
        int NumberChars = hex.Length;
        byte[] bytes = new byte[NumberChars / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }
    /// <summary>
    /// Calculates the checksum using the credit card algorithm.
    /// This algorithm has the advantage that it detects any single
    /// mistyped digit and any single transposition of
    /// adjacent digits.
    /// </summary>
    /// <param name="num">the number to calculate the checksum for</param>
    /// <param name="digits">number of significant places in the number</param>
    /// <returns>the checksum of num</returns>
    public static int calcChecksum(long num, int digits)
    {
        bool doubleDigit = true;
        int total = 0;
        while (0 < digits--)
        {
            int digit = (int)(num % 10);
            num /= 10;
            if (doubleDigit)
            {
                digit = doubleDigits[digit];
            }
            total += digit;
            doubleDigit = !doubleDigit;
        }
        int result = total % 10;
        if (result > 0)
        {
            result = 10 - result;
        }
        return result;
    }
    /// <summary>
    /// This method generates an OTP value for the given
    /// set of parameters.
    /// </summary>
    /// <param name="secret">the shared secret</param>
    /// <param name="movingFactor">the counter, time, or other value that changes on a per use basis.</param>
    /// <param name="codeDigits">the number of digits in the OTP, not including the checksum, if any.</param>
    /// <param name="addChecksum">a flag that indicates if a checksum digit should be appended to the OTP.</param>
    /// <returns>A numeric String in base 10 that includes <see cref="codeDigits"/> digits plus the optional checksum digit if requested.</returns>
    public static string generateOTP(byte[] secret, ulong movingFactor, int codeDigits, bool addChecksum)
    {
        // put movingFactor value into text byte array
        int digits = addChecksum ? (codeDigits + 1) : codeDigits;
        byte[] text = BitConverter.GetBytes(movingFactor).Reverse().ToArray();
        // compute hmac hash
        byte[] hash = HMACSHA1.HashData(secret, text);
        var truncationOffset = (int)hash.Last();
        // return ByteArrayToString(hash);
        // System.Console.WriteLine($"hash:{ByteArrayToString(hash)}");
        // put selected bytes into result int
        int offset = hash[hash.Length - 1] & 0xf;
        if ((0 <= truncationOffset) &&
               (truncationOffset < (hash.Length - 4)))
        {
            offset = truncationOffset;
        }
        int binary =
            ((hash[offset] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];
        if (addChecksum)
        {
            otp = (otp * 10) + calcChecksum(otp, codeDigits);
        }
        return otp.ToString().PadLeft(digits, '0');
    }

}