using Nethereum.Util;

namespace Crypto
{
    public class Hash
    {
        public static byte[] Hash160B(byte[] data)
        {
            return Hash256B(data).Slice(12);
        }

        public static byte[] Hash256B(byte[] data)
        {
            var sha3 = new Sha3Keccack();
            return sha3.CalculateHash(data);
        }
    }
}