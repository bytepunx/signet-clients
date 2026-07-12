using Signet;
using Xunit;

namespace SignetClient.Tests;

/// <summary>Ports every case from go/client_test.go's admin-dial coverage.</summary>
public class AdminConnectionTests
{
    [Theory]
    [InlineData("localhost", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("10.0.0.5", false)]
    [InlineData("signet.internal", false)]
    public void IsLoopbackHost_MatchesGoReference(string host, bool want)
    {
        Assert.Equal(want, AdminTransport.IsLoopbackHost(host));
    }

    [Theory]
    [InlineData("localhost:8444", "localhost")]
    [InlineData("signet.internal:8444", "signet.internal")]
    [InlineData("[::1]:8444", "::1")]
    [InlineData("localhost", "localhost")]
    public void ExtractHost_HandlesPortsAndBracketedIPv6(string addr, string wantHost)
    {
        Assert.Equal(wantHost, AdminTransport.ExtractHost(addr));
    }

    [Fact]
    public void Resolve_LoopbackDefaultsToPlaintext()
    {
        var resolved = AdminTransport.Resolve("localhost:8444", null, forceTls: false);
        Assert.False(resolved.UseTls, "expected plaintext for loopback address without forceTls");
    }

    [Fact]
    public void Resolve_NonLoopbackRequiresTls()
    {
        var resolved = AdminTransport.Resolve("signet.internal:8444", null, forceTls: false);
        Assert.True(resolved.UseTls, "expected TLS to be required for a non-loopback address");
    }

    [Fact]
    public void Resolve_ForceTlsOnLoopback()
    {
        var resolved = AdminTransport.Resolve("localhost:8444", null, forceTls: true);
        Assert.True(resolved.UseTls, "expected TLS to be required when forceTls is set");
    }

    [Fact]
    public void Resolve_CaPemProvidedForcesTlsEvenOnLoopback()
    {
        // Matches Go: len(caPEM) > 0 alone is enough to require TLS, independent of loopback-ness.
        var pem = GenerateSelfSignedCaPem();
        var resolved = AdminTransport.Resolve("localhost:8444", pem, forceTls: false);
        Assert.True(resolved.UseTls, "a non-empty CA bundle should require TLS even for a loopback address");
        Assert.NotNull(resolved.Handler);
    }

    private static byte[] GenerateSelfSignedCaPem()
    {
        using var ec = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=signet-test-ca", ec, System.Security.Cryptography.HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        var pem = cert.ExportCertificatePem();
        return System.Text.Encoding.ASCII.GetBytes(pem);
    }

    [Fact]
    public void ParseCaBundle_InvalidPem_ThrowsClearArgumentException()
    {
        var bad = System.Text.Encoding.ASCII.GetBytes("not a cert");
        var ex = Assert.Throws<ArgumentException>(() => AdminTransport.ParseCaBundle(bad));
        Assert.Contains("no PEM certificates found", ex.Message);
    }

    [Fact]
    public void Resolve_InvalidCaPem_ThrowsClearArgumentException()
    {
        var bad = System.Text.Encoding.ASCII.GetBytes("not a cert");
        var ex = Assert.Throws<ArgumentException>(() => AdminTransport.Resolve("signet.internal:8444", bad, forceTls: false));
        Assert.Contains("no PEM certificates found", ex.Message);
    }

    [Fact]
    public void DialAdmin_RejectsEmptyToken()
    {
        var ex = Assert.Throws<ArgumentException>(() => SignetConnect.DialAdmin("localhost:8444", "  "));
        Assert.Contains("token must not be empty", ex.Message);
    }

    [Fact]
    public void DialAdmin_RejectsWhitespaceOnlyToken()
    {
        Assert.Throws<ArgumentException>(() => SignetConnect.DialAdmin("localhost:8444", "   \t  "));
    }

    [Fact]
    public void DialAdmin_LoopbackWithoutTls_ConstructsChannelWithoutThrowing()
    {
        // GrpcChannel.ForAddress is lazy — no socket is actually opened — so this exercises the
        // full plaintext-scheme wiring without a live network connection.
        using var conn = SignetConnect.DialAdmin("localhost:8444", "test-token");
        Assert.NotNull(conn.AdminClient);
        Assert.NotNull(conn.GitOpsClient);
    }

    [Fact]
    public void DialAdmin_NonLoopback_ConstructsHttpsChannelWithoutThrowing()
    {
        using var conn = SignetConnect.DialAdmin("signet.internal:8444", "test-token");
        Assert.NotNull(conn.AdminClient);
    }

    [Fact]
    public void DialAdmin_InvalidCaPem_ThrowsBeforeTouchingNetwork()
    {
        var bad = System.Text.Encoding.ASCII.GetBytes("definitely not pem");
        var ex = Assert.Throws<ArgumentException>(
            () => SignetConnect.DialAdmin("signet.internal:8444", "test-token", bad));
        Assert.Contains("no PEM certificates found", ex.Message);
    }
}
