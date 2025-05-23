using AeroxChain.Utils;
using Secp256k1Net;
using System.Security.Cryptography;
using System.Text;

namespace AeroxChain.Wallet
{
    public abstract class Biper
    {
        private static readonly string[] BIP39Wordlist = File.ReadAllLines(Path.Combine("Resources/phrase", "english.txt"));
        private static byte[] GenerateEntropy(int strength = 128)
        {
            if (strength % 32 != 0 || strength < 128 || strength > 256)
                throw new ArgumentException("Strength must be 128, 160, 192, 224, or 256");

            byte[] entropy = new byte[strength / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(entropy);
            }
            return entropy;
        }
        static Biper()
        {
            BIP39Wordlist = File.ReadAllLines(Path.Combine("Resources/phrase", "english.txt"));
            if (BIP39Wordlist.Length != 2048)
                throw new InvalidDataException("BIP39 wordlist must contain exactly 2048 words");
        }
        private static byte[] AddChecksum(byte[] entropy)
        {
            byte[] hash = Hasher.Keccak256(entropy);
            int checksumLength = entropy.Length * 8 / 32; // 4 bits for 128-bit entropy

            // Получаем только нужные биты checksum
            byte checksumBits = (byte)(hash[0] >> (8 - checksumLength));

            // Возвращаем оригинальный entropy без добавления нового байта
            // (checksum будет добавлен в последние биты последнего байта)
            return entropy;
        }

        private static string[] EntropyToMnemonic(byte[] entropyWithChecksum)
        {
            int entropyBits = entropyWithChecksum.Length * 8;
            int checksumBits = entropyBits / 32;
            int totalBits = entropyBits + checksumBits;
            int wordCount = totalBits / 11;

            // Вычисляем SHA256 хеш для получения checksum
            byte[] hash = SHA256.HashData(entropyWithChecksum);
            byte checksumByte = (byte)(hash[0] >> (8 - checksumBits));

            // Создаем BitArray и добавляем checksum биты
            var bits = new System.Collections.BitArray(entropyWithChecksum);
            var allBits = new System.Collections.BitArray(entropyBits + checksumBits);

            // Копируем биты энтропии
            for (int i = 0; i < entropyBits; i++)
            {
                allBits[i] = bits[i];
            }

            // Добавляем checksum биты
            for (int i = 0; i < checksumBits; i++)
            {
                allBits[entropyBits + i] = (checksumByte & (1 << (checksumBits - 1 - i))) != 0;
            }

            // Генерируем мнемоническую фразу
            var mnemonic = new string[wordCount];
            for (int wordIndex = 0; wordIndex < wordCount; wordIndex++)
            {
                int value = 0;
                for (int bit = 0; bit < 11; bit++)
                {
                    int bitPosition = wordIndex * 11 + bit;
                    if (allBits[bitPosition])
                    {
                        value |= 1 << (10 - bit);
                    }
                }
                mnemonic[wordIndex] = BIP39Wordlist[value];
            }

            return mnemonic;
        }
        public static string[] GenerateMnemonic()
        {
            byte[] entropy = GenerateEntropy(128); // 128 bits → 12 words
            byte[] entropyWithChecksum = AddChecksum(entropy);
            string[] mnemonicWords = EntropyToMnemonic(entropyWithChecksum);

            return mnemonicWords;
        }
        public static byte[] GenerateSeedFromMnemonic(string[] mnemonicWords, string passphrase = "")
        {
            string mnemonic = string.Join(" ", mnemonicWords);
            using var derive = new Rfc2898DeriveBytes(
                mnemonic,
                Encoding.UTF8.GetBytes("mnemonic" + passphrase),
                2048,
                HashAlgorithmName.SHA256
            );
            return derive.GetBytes(64);
        }
    }
}
