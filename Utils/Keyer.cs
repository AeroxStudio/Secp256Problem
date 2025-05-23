using Secp256k1Net;
using System.Security.Cryptography;

namespace AeroxChain.Utils
{
    abstract class Keyer
    {
        public static (byte[] uncompressedPublicKey, byte[] compressedPublicKey, byte[] privateKey) GenerateSecp256k1Keys(byte[] seed)
        {
            byte[] privateKey = new byte[32];

            if (seed == null || seed.Length < 32)
            {
                RandomNumberGenerator.Fill(privateKey);
            }
            else
            {
                Array.Copy(seed, privateKey, Math.Min(seed.Length, 32));
            }
            using var secp256k1 = new Secp256k1();
            while (!secp256k1.SecretKeyVerify(privateKey))
            {
                privateKey = SHA256.HashData(privateKey);
            }
            byte[] publicKey = new byte[64];
            if (!secp256k1.PublicKeyCreate(publicKey, privateKey))
            {
                throw new CryptographicException("Failed to generate public key");
            }
            byte[] compressedPubKey = new byte[33];
            if (!secp256k1.PublicKeySerialize(compressedPubKey, publicKey, Flags.SECP256K1_EC_COMPRESSED))
            {
                throw new CryptographicException("Failed to compress public key");
            }
            byte[] parsedFromCompressed = new byte[64];
            if (!secp256k1.PublicKeyParse(parsedFromCompressed, compressedPubKey))
            {
                throw new CryptographicException("Compressed key is invalid");
            }
            if (!publicKey.AsSpan().SequenceEqual(parsedFromCompressed))
            {
                throw new CryptographicException("Uncompressed and compressed keys mismatch");
            }

            return (publicKey, compressedPubKey, privateKey);
        }
        public static bool SignData(Span<byte> signatureOutput, Span<byte> txHash, Span<byte> privateKey)
        {
            using var secp256k1 = new Secp256k1();
            return secp256k1.Sign(signatureOutput, txHash, privateKey);
        }
        public static bool VerifyData(Span<byte> signatureOutput, Span<byte> txHash, Span<byte> publicKey)
        {
            using var secp256k1 = new Secp256k1();
            return secp256k1.Verify(signatureOutput, txHash, publicKey);
        }
        public static byte[] DecompressPublicKey(byte[] compressedKey)
        {
            if (compressedKey == null || compressedKey.Length != 33)
                throw new ArgumentException("Invalid compressed public key format");
            using (var secp256k1 = new Secp256k1())
            {
                var pubkey = new byte[64];
                if (!secp256k1.PublicKeyParse(pubkey, compressedKey))
                    throw new InvalidOperationException("Failed to parse public key");

                byte[] uncompressed = new byte[65];
                if (!secp256k1.PublicKeySerialize(uncompressed, pubkey, Flags.SECP256K1_EC_UNCOMPRESSED))
                    throw new InvalidOperationException("Failed to serialize public key");

                return uncompressed[1..];
            }
        }
        public static byte[] RecoveryData(byte[] signature, byte[] hash)
        {
            if (signature.Length != 65) throw new ArgumentException("Signature must be 65 bytes");
            using var secp256k1 = new Secp256k1();
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            if (!secp256k1.Recover(publicKey, signature, hash)) throw new Exception("Recovery Failed");
            return publicKey;
        }
    }
}
