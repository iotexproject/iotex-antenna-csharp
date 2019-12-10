namespace IoTeX.antenna.Accounts
{
    public interface IAccount
    {
        string Address { get; }
        string PrivateKey { get; }
        string PublicKey { get; }
    }
}