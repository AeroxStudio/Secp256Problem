using AeroxChain.Utils;
using Secp256k1Net;

namespace AeroxChain.Contract
{
    public enum Status { Confirmed, Pending, Failed, Cancelled }
    class Transaction
    {
        //----- Core -----
        public byte[] FromAddress { get; } 
        public byte[]? ToAddress { get; }
        public decimal Amount { get; }
        public byte[] PublicKey { get; } //Soon delete
        public DateTime Timestamp { get; } = DateTime.Now;
        public byte[]? Data { get; }

        //----- AI Proof-Of-Validation ------
        public float Weight { get; set; } = 1.0f;

        //----- DAG Tangle -----
        public byte[][]? ParentHashes { get; }

        //----- Cryptography -----
        public byte[] Signature { get; set; }
        public byte[] Hash { get; private set; }
        //public Coin Coin { get; set; } (In Data)

        public Transaction(byte[] fromAddress, byte[] toAddress, byte[] publicKey, decimal amount, byte[]? data)
        {
            FromAddress = fromAddress;
            ToAddress = toAddress;
            PublicKey = publicKey;
            Amount = amount;
            Data = data;
            Hash = GetHash();
        }
        public byte[] GetHash()
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);

            writer.Write(FromAddress);
            writer.Write(ToAddress);
            writer.Write(Amount);
            if (Data != null) writer.Write(Data);

            return Hasher.Keccak256(stream.ToArray()); // SHA3_256 (Sha3.Net Library)
        }
        public void Sign(byte[] privateKey)
        {
            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            if (!Keyer.SignData(signature, Hash, privateKey)) throw new Exception("SIGN ISN'T SUCCESSFUL");
            Signature = signature;
        }
        public byte[] GetRecoveryPublicKey()
        {
            return Keyer.RecoveryData(Signature, Hash);
        }
        public bool IsValid()
        {
            bool validationChecks = (FromAddress, ToAddress, Signature, Amount, Timestamp) switch
            {
                (_, _, _, _, var date) when date > DateTime.Now => false,
                (var from, var to, _, _, _) when from == to => false,
                (null, _, _, _, _) => false,
                (_, _, null, _, _) => false,
                (_, _, _, <= 0, _) => false,
                _ => true
            };
            if (!validationChecks) return false;
            return Keyer.VerifyData(Signature, Hash, PublicKey);
        }
        public int Calc() => new Func<int>[]
        {
            () => ParentHashes?.Any() == true ? ParentHashes.Length : 0,
            () => FromAddress.Length,
            () => PublicKey.Length,
            () => ToAddress.Length,
            () => sizeof(long),  // Timestamp
            () => sizeof(decimal), // Amount
            () => Data.Length,
            () => Hash.Length,
            () => sizeof(float), // Weight
            () => Signature.Length
        }.Sum(f => f());
        public Task DebugOutput => Task.Run(() =>
        {
            Console.WriteLine("\n[Transaction Debug]");
            Console.WriteLine($"Hash: {BitConverter.ToString(GetHash()).Replace("-", "").ToLower()}");
            Console.WriteLine($"ParentHashes: {(ParentHashes == null || ParentHashes.Length == 0 ? "Genesis Transaction" : "")}");
            Console.WriteLine($"Timestamp: {Timestamp}");
            Console.WriteLine($"From: {Base58Check.ToBase58Address(FromAddress)}");
            Console.WriteLine($"To: {Base58Check.ToBase58Address(ToAddress)}");
            Console.WriteLine($"Amount: {Amount}");
            Console.WriteLine($"Coin: undefined");
            Console.WriteLine($"PublicKey: {BitConverter.ToString(PublicKey)}");
            Console.WriteLine($"Signature: {Convert.ToBase64String(Signature)}");
            Console.WriteLine($"Valid Tx: {IsValid()} ");
            Console.WriteLine($"Recovery Key: {BitConverter.ToString(Keyer.RecoveryData(Signature, Hash))}");

            if (PublicKey.SequenceEqual(Keyer.RecoveryData(Signature, Hash))) Console.WriteLine("The keys matched");
        });
    }
}