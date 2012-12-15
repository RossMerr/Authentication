using System;
using System.Text;
using System.Security.Cryptography;

namespace Authentication.Encryption
{
    public class Hash
    {
        public static string ComputeHash(string plainText, HashAlgorithm hashAlgorithm, string salt)
        {
            System.Security.Cryptography.HashAlgorithm hash;

            switch (hashAlgorithm)
            {   
                case HashAlgorithm.SHA1:
                    hash = new SHA1Managed();
                    break;

                case HashAlgorithm.SHA256:
                    hash = new SHA256Managed();
                    break;

                case HashAlgorithm.SHA384:
                    hash = new SHA384Managed();
                    break;

                case HashAlgorithm.SHA512:
                    hash = new SHA512Managed();
                    break;

                default:
                    hash = new MD5CryptoServiceProvider();
                    break;
            }

            var plainTextWithSalt = Encoding.UTF8.GetBytes(plainText + salt);
            var hashBytes = hash.ComputeHash(plainTextWithSalt);
            var hashValue = Convert.ToBase64String(hashBytes);

            return hashValue;
        }

        public static string Salt()
        {
            // Define min and max salt sizes.
            const int minSaltSize = 4;
            const int maxSaltSize = 8;

            // Generate a random number for the size of the salt.
            var random = new Random();
            var saltSize = random.Next(minSaltSize, maxSaltSize);

            // Allocate a byte array, which will hold the salt.
            var saltBytes = new byte[saltSize];

            // Initialize a random number generator.
            var rng = new RNGCryptoServiceProvider();

            // Fill the salt with cryptographically strong byte values.
            rng.GetNonZeroBytes(saltBytes);
            return Convert.ToBase64String(saltBytes);
        }
    }
}