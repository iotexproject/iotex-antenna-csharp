using Crypto;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Signer;
using Nethereum.Util;

namespace IoTeX.antenna.Account
{
    public class Account
    {
        public Account(string privateKey)
        {
            Initialise(new EthECKey(privateKey));
        }

        private void Initialise(EthECKey key)
        {
            PrivateKey = key.GetPrivateKey();
            PublicKey = key.GetPubKey().ToHex();
            var sha3 = new Sha3Keccack();
            Address = Bech32.Encode("io", sha3.CalculateHash(key.GetPubKey().Slice(1)).Slice(12));
        }

        public string Address { get; private set; }
        public string PrivateKey { get; private set; }
        public string PublicKey { get; private set; }
    }
}