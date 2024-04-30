using System.Security.Cryptography;

/// <summary>
/// This is an example implementation of the OATH
/// TOTP algorithm.
/// Visit www.openauthentication.org for more information.
/// 
/// @author Johan Rydell, PortWise, Inc.
/// </summary>
public class TOTP
{
    /// <summary>
    /// This method uses the JCE to provide the crypto algorithm.
    /// HMAC computes a Hashed Message Authentication Code with the
    /// crypto hash algorithm as a parameter.
    /// </summary>
    /// <param name="crypto">the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)</param>
    /// <param name="keyBytes">the bytes to use for the HMAC key</param>
    /// <param name="text">the message or text to be authenticated</param>
    private static byte[] hmac_sha(string crypto, byte[] keyBytes,
            byte[] text)
    {
        try
        {
            HMAC? hmac = CryptoConfig.CreateFromName(crypto) as HMAC;
            if (hmac == null)
                throw new Exception($"algorithm not found:{crypto}");
            hmac.Key = keyBytes;
            return hmac.ComputeHash(text);
        }
        catch
        {
            throw;
        }
    }

    /// <summary>
    /// This method converts a HEX string to Byte[]
    /// </summary>
    /// <param name="hex">the HEX string</param>
    /// <returns>a byte array</returns>
    private static byte[] hexStr2Bytes(string hex)
    {
        int NumberChars = hex.Length;
        byte[] bytes = new byte[NumberChars / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    private static int[] DIGITS_POWER
    //  0   1    2     3      4       5        6         7          8
    = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

    /// <summary>
    /// This method generates a TOTP value for the given
    /// set of parameters.
    /// </summary>
    /// <param name="key">the shared secret, HEX encoded</param>
    /// <param name="time">a value that reflects a time</param>
    /// <param name="returnDigits">number of digits to return</param>
    /// <returns>a numeric string in base 10 that includes <see cref="truncationDigits"/> digits</returns>
    public static string generateTOTP(string key,
            ulong time,
            int returnDigits)
    {
        return generateTOTP(key, time, returnDigits, "HmacSHA1");
    }

    /// <summary>
    /// This method generates a TOTP value for the given
    /// set of parameters.
    /// </summary>
    /// <param name="key">the shared secret, HEX encoded</param>
    /// <param name="time">a value that reflects a time</param>
    /// <param name="returnDigits">number of digits to return</param>
    /// <returns>a numeric string in base 10 that includes <see cref="truncationDigits"/> digits</returns>
    public static string generateTOTP256(string key,
            ulong time,
            int returnDigits)
    {
        return generateTOTP(key, time, returnDigits, "HmacSHA256");
    }


    /// <summary>
    /// This method generates a TOTP value for the given
    /// set of parameters.
    /// </summary>
    /// <param name="key">the shared secret, HEX encoded</param>
    /// <param name="time">a value that reflects a time</param>
    /// <param name="returnDigits">number of digits to return</param>
    /// <returns>a numeric string in base 10 that includes <see cref="truncationDigits"/> digits</returns>
    public static string generateTOTP512(string key,
            ulong time,
            int returnDigits)
    {
        return generateTOTP(key, time, returnDigits, "HmacSHA512");
    }

    /// <summary>
    /// This method generates a TOTP value for the given
    /// set of parameters.
    /// </summary>
    /// <param name="key">the shared secret, HEX encoded</param>
    /// <param name="time">a value that reflects a time</param>
    /// <param name="returnDigits">number of digits to return</param>
    /// <param name="crypto">the crypto function to use</param>
    /// <returns>a numeric string in base 10 that includes {@link truncationDigits} digits</returns>
    public static string generateTOTP(string key,
            ulong time,
            int returnDigits,
            string crypto)
    {
        int codeDigits = returnDigits;
        string result;

        // Using the counter
        // First 8 bytes are for the movingFactor
        // Compliant with base RFC 4226 (HOTP)
        var timeBytes = BitConverter.GetBytes(time).Reverse().ToArray();
        // Get the HEX in a Byte[]
        byte[] k = hexStr2Bytes(key);

        byte[] hash = hmac_sha(crypto, k, timeBytes);

        // put selected bytes into result int
        int offset = hash[hash.Length - 1] & 0xf;

        int binary =
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = otp.ToString().PadLeft(codeDigits, '0');
        return result;
    }

    public static void Test()
    {
        // Seed for HMAC-SHA1 - 20 bytes
        string seed = "3132333435363738393031323334353637383930";
        // Seed for HMAC-SHA256 - 32 bytes
        string seed32 = "3132333435363738393031323334353637383930" +
        "313233343536373839303132";
        // Seed for HMAC-SHA512 - 64 bytes
        string seed64 = "3132333435363738393031323334353637383930" +
        "3132333435363738393031323334353637383930" +
        "3132333435363738393031323334353637383930" +
        "31323334";
        ulong T0 = 0;
        ulong X = 30;
        ulong[] testTime = {59UL, 1111111109UL, 1111111111UL,
                 1234567890UL, 2000000000UL, 20000000000UL};

        System.Console.WriteLine(
                "+---------------+-----------------------+" +
        "------------------+--------+--------+");
        System.Console.WriteLine(
                "|  Time(sec)    |   Time (UTC format)   " +
        "| Value of T(Hex)  |  TOTP  | Mode   |");
        System.Console.WriteLine(
                "+---------------+-----------------------+" +
        "------------------+--------+--------+");

        for (int i = 0; i < testTime.Length; i++)
        {
            ulong T = (testTime[i] - T0) / X;
            ulong steps = T;
            string fmtTime = testTime[i].ToString().PadLeft(11, ' ');

            string utcTime = DateTimeOffset.FromUnixTimeSeconds((long)testTime[i]).ToString("yyyy-MM-dd HH:mm:ss");
            System.Console.WriteLine($"|  {fmtTime}  |  {utcTime}  | {steps:X16} |{generateTOTP(seed, steps, 8, "HmacSHA1")}| SHA1   |");
            System.Console.WriteLine($"|  {fmtTime}  |  {utcTime}  | {steps:X16} |{generateTOTP(seed32, steps, 8, "HmacSHA256")}| SHA256 |");
            System.Console.WriteLine($"|  {fmtTime}  |  {utcTime}  | {steps:X16} |{generateTOTP(seed64, steps, 8, "HmacSHA512")}| SHA512 |");
            System.Console.WriteLine(
                    "+---------------+-----------------------+" +
            "------------------+--------+--------+");
        }
        {
            var nowTime = DateTimeOffset.Now;
            ulong testNowTime = (ulong)nowTime.ToUnixTimeSeconds();
            ulong T = (testNowTime - T0) / X;
            ulong steps = T;
            string fmtTime = testNowTime.ToString().PadLeft(11, ' ');
            string utcTime = nowTime.ToString("yyyy-MM-dd HH:mm:ss");
            System.Console.WriteLine($"|  {fmtTime}  |  {utcTime}  | {steps:X16} |{generateTOTP(seed, steps, 8, "HmacSHA1")}| SHA1   |");
            System.Console.WriteLine($"|  {fmtTime}  |  {utcTime}  | {steps:X16} |{generateTOTP(seed32, steps, 8, "HmacSHA256")}| SHA256 |");
            System.Console.WriteLine($"|  {fmtTime}  |  {utcTime}  | {steps:X16} |{generateTOTP(seed64, steps, 8, "HmacSHA512")}| SHA512 |");
            System.Console.WriteLine(
                    "+---------------+-----------------------+" +
            "------------------+--------+--------+");
        }
    }
}



