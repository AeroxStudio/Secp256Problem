using System.Numerics;
using System.Text;

namespace AeroxChain.Utils
{
    public abstract class Base58Check
    {
        public enum Network { Mainnet, Testnet, Developnet}
        private readonly static string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        public const int ADDRESS_SIZE = 32;

        /// <summary>
        /// Generates a byte[] address from a public key using SHA3-256.
        /// </summary>
        /// <param name="publicKey">The uncompressed public key.</param>
        /// <param name="network">Network version byte prefix.</param>
        public static byte[] GenerateNewAddress(byte[] publicKey, Network network)
        {
            if (publicKey == null || publicKey.Length == 0)
                throw new ArgumentException("Public key cannot be null or empty");

            // 1. Хешируем публичный ключ (SHA3-256)
            byte[] sha3Hash = Hasher.Keccak256(publicKey);

            byte networkByte = network switch
            {
                Network.Mainnet => 1,
                Network.Testnet => 2,
                Network.Developnet => 3,
                _ => throw new ArgumentException("Invalid network")
            };

            byte[] address = new byte[ADDRESS_SIZE];
            address[0] = networkByte;
            Buffer.BlockCopy(sha3Hash, 0, address, 1, ADDRESS_SIZE - 1);

            return address;

        }
        /// <summary>
        /// Encode a byte[] to Base58Check format address.
        /// </summary>
        /// <param name="address">The byte[] address.</param>
        public static string ToBase58Address(byte[] address)
        {
            char prefixChar = address[0] switch
            {
                1 => '1',
                2 => '2',
                3 => '3',
                _ => throw new Exception("Invalid prefix")
            };
            byte[] hashPart = new byte[31];
            Buffer.BlockCopy(address, 1, hashPart, 0, 31);
            string suffix = EncodeBase58CheckWithoutPrefix(hashPart);

            return prefixChar + suffix;
        }
        /// <summary>
        /// Decode a Base58Check to byte[] format address.
        /// </summary>
        /// <param name="address">The Base58Check address.</param>
        public static byte[] DecodeAddress(string base58Address)
        {
            if (string.IsNullOrEmpty(base58Address))
                throw new ArgumentException("Address cannot be empty");

            char prefixChar = base58Address[0];
            byte networkByte = prefixChar switch
            {
                '1' => 1, // Mainnet
                '2' => 2, // Testnet
                '3' => 3, // Developnet
                _ => throw new FormatException("Invalid address prefix")
            };

            byte[] decoded = DecodeBase58Check(base58Address[1..]); // Decode without prefix

            byte[] address = new byte[ADDRESS_SIZE];
            address[0] = networkByte;
            Buffer.BlockCopy(decoded, 0, address, 1, Math.Min(decoded.Length, ADDRESS_SIZE - 1));

            return address;
        }
        private static string EncodeBase58CheckWithoutPrefix(byte[] data)
        {
            byte[] checksum = Hasher.Keccak256(Hasher.Keccak256(data));
            byte[] dataWithChecksum = new byte[data.Length + 4];
            Buffer.BlockCopy(data, 0, dataWithChecksum, 0, data.Length);
            Buffer.BlockCopy(checksum, 0, dataWithChecksum, data.Length, 4);

            BigInteger number = new(dataWithChecksum, isUnsigned: true, isBigEndian: true);
            var result = new StringBuilder();
            BigInteger alphabetLength = new(Base58Alphabet.Length);

            while (number > 0)
            {
                int remainder = (int)(number % alphabetLength);
                number /= alphabetLength;
                result.Insert(0, Base58Alphabet[remainder]);
            }
            for (int i = 1; i < data.Length && data[i] == 0; i++)
            {
                result.Insert(0, '1');
            }
            return result.ToString();
        }
        private static byte[] DecodeBase58Check(string input)
        {
            BigInteger number = 0;
            foreach (char c in input)
            {
                int digit = Base58Alphabet.IndexOf(c);
                if (digit < 0)
                    throw new FormatException($"Invalid Base58 character: '{c}'");
                number = number * Base58Alphabet.Length + digit;
            }

            byte[] decoded = number.ToByteArray(isUnsigned: true, isBigEndian: true);

            // Проверяем контрольную сумму (последние 4 байта)
            if (decoded.Length < 4)
                throw new FormatException("Invalid checksum");

            byte[] data = decoded[..^4];
            byte[] checksum = decoded[^4..];
            byte[] expectedChecksum = Hasher.Keccak256(Hasher.Keccak256(data))[..4];

            if (!checksum.SequenceEqual(expectedChecksum))
                throw new FormatException("Checksum mismatch");

            return data;
        }
    }
}
