namespace IoTeX.antenna.Accounts
{
    public interface IAccount
    {
        string Address { get; }
        string PrivateKey { get; }
        string PublicKey { get; }
        
        byte[] Sign(byte[] data);

        string Recover(string message, byte[] signature, bool preFixed);

        byte[] HashMessage(byte[] data);
    }
}