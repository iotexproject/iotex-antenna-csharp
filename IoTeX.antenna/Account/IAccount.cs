namespace IoTeX.antenna.Account
{
    public interface IAccount
    {
        string Address { get; }
        string PrivateKey { get; }
        string PublicKey { get; }
    }
}