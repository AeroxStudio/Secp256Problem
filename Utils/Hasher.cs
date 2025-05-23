using SHA3.Net;
using System.Security.Cryptography;

namespace AeroxChain.Utils
{
    abstract class Hasher
    {
        public static byte[] Keccak256(byte[] input)
        {
            return Sha3.Sha3256().ComputeHash(input);
        }
    }
}
