using Secp256k1Net;
using SHA3.Net;

namespace AeroxChain
{
    class Program
    {
        public static string FromAddress = "3JYeY6SsvdmqxubL43eQtR9inYsvfsDE5ot4sw7Wag4EUuw5g";
        public static byte[] PublicKey = HexStringToByteArray("64-D8-C3-D6-A6-00-74-91-60-6A-92-A0-42-B1-C2-20-45-3D-B1-22-2C-C6-05-E1-7C-90-14-98-9F-A9-6C-8C-89-31-47-3A-65-83-3F-61-93-82-C0-B8-4E-CB-CD-88-59-63-48-8C-FD-A6-05-94-0A-2E-6D-B3-2C-95-8F-33");
        public static byte[] PrivateKey = HexStringToByteArray("18-1C-60-A4-E3-5C-8B-BA-68-93-17-29-CB-6E-A8-8F-D3-D5-49-7D-F6-54-14-AC-37-C6-46-EC-72-55-F0-D9");
        
        static void Main(string[] args)
        {
            Tx tx = new(PrivateKey, PublicKey, FromAddress);
            Console.WriteLine($"PublicKey: {BitConverter.ToString(PublicKey)}");
            Console.WriteLine($"Hash: {BitConverter.ToString(tx.Hash).Replace("-", "").ToLower()}");
            Console.WriteLine($"Signature: {Convert.ToBase64String(tx.Signature)}");
            Console.WriteLine($"RecoveredPublicKey: {BitConverter.ToString(tx.RecoverKey())}");
        }
        public static byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace("-", "").Replace(" ", "");

            if (hex.Length % 2 != 0)
                throw new ArgumentException("Incorrect string");

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                string byteStr = hex.Substring(i * 2, 2);
                bytes[i] = Convert.ToByte(byteStr, 16);
            }
            return bytes;
        }
    }
    class Tx
    {
        private byte[] PrivateKey;
        public byte[] PublicKey { get; private set; }
        public string FromAddress { get; private set; }
        public byte[] Hash { get; private set; }
        public byte[] Signature { get; private set; }

        public Tx(byte[] privateKey, byte[] publicKey, string fromAddress)
        {
            this.PrivateKey = privateKey;
            this.PublicKey = publicKey;
            this.FromAddress = fromAddress;
            this.Hash = Sha3.Sha3256().ComputeHash(publicKey);
            this.Signature = Sign(PrivateKey);
        }

        public byte[] Sign(byte[] privateKey)
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            if (!secp256k1.Sign(signature, Hash, privateKey))
                throw new Exception("SIGN ISN'T SUCCESSFUL");
            return signature;
        }
        public byte[] RecoverKey()
        {
            using var secp256k1 = new Secp256k1();
            byte[] recoveredKey = new byte[Secp256k1.PUBKEY_LENGTH];
            if (!secp256k1.Recover(recoveredKey, Signature, Hash)) throw new Exception("Failed Recover");
            if (recoveredKey.SequenceEqual(PublicKey)) Console.WriteLine("The keys matched");
            return recoveredKey;
        }
    }
}
