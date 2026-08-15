using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Signet;
using Xunit;
using YamlDotNet.Serialization;

namespace SignetClient.Tests;

/// <summary>
/// Ports every case from go/sops_encrypt_test.go's coverage of EncryptForSecret. The core
/// correctness bar (<see cref="EncryptForSecret_RealSopsCanDecrypt"/>) is the real sops binary,
/// not just self-consistency with this assembly's own code — if the AES-GCM nonce size, AAD, or
/// MAC computation is even slightly wrong, that test fails with a real decrypt error from the
/// actual sops tool.
/// </summary>
public class SopsEncryptTests
{
    private const string SecretValue = "hello-world";

    [Fact]
    public void EncryptForSecret_RealSopsCanDecrypt()
    {
        var sopsPath = FindSops();
        if (sopsPath is null)
        {
            return; // sops binary not found on PATH; skip, matching the Go test's precedent.
        }

        var (identity, recipient) = GenerateX25519Identity();
        var encrypted = SopsEncryption.EncryptForSecret(recipient, Encoding.UTF8.GetBytes(SecretValue));

        var secretPath = Path.Combine(Path.GetTempPath(), $"sops-test-{Guid.NewGuid()}.yaml");
        File.WriteAllBytes(secretPath, encrypted);
        try
        {
            var (exitCode, stdout, stderr) = RunSops(sopsPath, secretPath, identity);
            Assert.True(exitCode == 0, $"sops decrypt failed: {stderr}");

            var deserializer = new DeserializerBuilder().Build();
            var doc = deserializer.Deserialize<Dictionary<string, object>>(stdout);
            Assert.Equal(SecretValue, doc["value"]);
        }
        finally
        {
            File.Delete(secretPath);
        }
    }

    [Fact]
    public void EncryptForSecret_WrongIdentityFails()
    {
        var sopsPath = FindSops();
        if (sopsPath is null)
        {
            return;
        }

        var (_, encryptedToRecipient) = GenerateX25519Identity();
        var (wrongIdentity, _) = GenerateX25519Identity();

        var encrypted = SopsEncryption.EncryptForSecret(encryptedToRecipient, Encoding.UTF8.GetBytes(SecretValue));

        var secretPath = Path.Combine(Path.GetTempPath(), $"sops-test-{Guid.NewGuid()}.yaml");
        File.WriteAllBytes(secretPath, encrypted);
        try
        {
            var (exitCode, _, stderr) = RunSops(sopsPath, secretPath, wrongIdentity);
            Assert.True(exitCode != 0, $"expected sops decrypt with the wrong identity to fail, but it succeeded: {stderr}");
        }
        finally
        {
            File.Delete(secretPath);
        }
    }

    [Fact]
    public void EncryptForSecret_EmptyPublicKey_Throws()
    {
        var ex = Assert.Throws<SopsEncryptionException>(
            () => SopsEncryption.EncryptForSecret(string.Empty, Encoding.UTF8.GetBytes(SecretValue)));
        Assert.Contains("public key must not be empty", ex.Message);
    }

    [Fact]
    public void EncryptForSecret_InvalidPublicKey_Throws()
    {
        Assert.Throws<SopsEncryptionException>(
            () => SopsEncryption.EncryptForSecret("not-a-real-age-key", Encoding.UTF8.GetBytes(SecretValue)));
    }

    private static string? FindSops()
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var dir in pathVar.Split(Path.PathSeparator))
        {
            var candidate = Path.Combine(dir, "sops");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static (int ExitCode, string Stdout, string Stderr) RunSops(string sopsPath, string secretPath, string ageIdentity)
    {
        var psi = new ProcessStartInfo(sopsPath, $"--decrypt \"{secretPath}\"")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            psi.Environment[(string)entry.Key] = (string?)entry.Value;
        }
        psi.Environment["SOPS_AGE_KEY"] = ageIdentity;

        using var proc = Process.Start(psi)!;
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        return (proc.ExitCode, stdout, stderr);
    }

    /// <summary>
    /// Generates a fresh X25519 identity/recipient pair the same way filippo.io/age's
    /// GenerateX25519Identity/String/Recipient does, using the internal Bech32 codec this
    /// assembly already ships for parsing recipients in <see cref="SopsEncryption.EncryptForSecret"/>.
    /// </summary>
    private static (string Identity, string Recipient) GenerateX25519Identity()
    {
        var secretKey = RandomNumberGenerator.GetBytes(32);
        var publicKey = new byte[32];
        Org.BouncyCastle.Math.EC.Rfc7748.X25519.ScalarMultBase(secretKey, 0, publicKey, 0);

        var identity = Bech32.Encode("AGE-SECRET-KEY-", secretKey).ToUpperInvariant();
        var recipient = Bech32.Encode("age", publicKey);
        return (identity, recipient);
    }
}
