using AeroxChain.Contract;
using AeroxChain.Utils;
using AeroxChain.Wallet;
using System.Text;

namespace AeroxChain
{
    class Program
    {
        public static void Main(string[] args)
        {
            var mnemonic = Biper.GenerateMnemonic(); // BIP39 Phrases
            var (uncompressedPublicKey, compressedPublicKey, privateKey) = Keyer.GenerateSecp256k1Keys(Biper.GenerateSeedFromMnemonic(mnemonic));
            var Address = Base58Check.GenerateNewAddress(uncompressedPublicKey, Base58Check.Network.Developnet);

            Console.WriteLine($"Phrases: {string.Join(" ", mnemonic)}");
            Console.WriteLine($"Address: {Base58Check.ToBase58Address(Address)}");

            Transaction tx = new(Address, Base58Check.DecodeAddress("3SGm1U3kQXtzwhChecLVGNCXBLhzDk2Ug9Hc37ffGaCG9wKPM"), uncompressedPublicKey, 0.05m, Encoding.UTF8.GetBytes("ARX"));
            tx.Sign(privateKey);
            tx.DebugOutput.Wait();
            //Console.WriteLine("Signature: " + Convert.ToBase64String(tx.Signature));
            //Console.WriteLine($"Valid Tx: {tx.IsValid()}");
            //Console.WriteLine($"Tx size: {tx.Calc()} bytes");
        }
    }

}