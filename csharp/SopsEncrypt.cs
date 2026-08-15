using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using AesEngine = Org.BouncyCastle.Crypto.Engines.AesEngine;
using BcChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;
using GcmBlockCipher = Org.BouncyCastle.Crypto.Modes.GcmBlockCipher;
using X25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace Signet;

/// <summary>
/// Produces real SOPS-compatible encrypted secret values, for use with signetd's
/// <c>SyncBundle</c>/<c>TriggerSync</c> RPCs (via <c>AdminConnection.GitOpsClient</c>) and the
/// <c>signet secret set</c> CLI. signetd never encrypts secrets on the caller's behalf —
/// <c>SyncBundle</c> stores file content as-is, and a plaintext value submitted through it fails
/// to decrypt server-side and is silently never stored (signet's documented trust model is "only
/// SOPS ciphertext leaves the operator's machine"). <see cref="EncryptForSecret"/> is the
/// correct way to produce a value <c>SyncBundle</c> will actually persist. See
/// bytepunx/signet-clients#49.
/// </summary>
public static class SopsEncryption
{
    // SopsFileVersion is recorded in the file's sops.version metadata field. The real sops CLI
    // only requires this to be non-empty to decrypt — it doesn't gate decryption on matching its
    // own build version.
    private const string SopsFileVersion = "3.13.1";

    /// <summary>
    /// Encrypts <paramref name="value"/> into a SOPS-compatible encrypted YAML document with a
    /// single top-level <c>value</c> key, encrypted to the single age (X25519) recipient
    /// <paramref name="publicKey"/> (e.g. as returned by GitOpsService's
    /// <c>GetSOPSPublicKey</c> RPC). The result is byte-for-byte equivalent to what
    /// <c>sops --encrypt</c> produces for a file containing exactly <c>value: "&lt;secret&gt;"</c>.
    ///
    /// Implementation note: this hand-implements the narrow slice of the SOPS file format needed
    /// for a single-leaf, single-age-recipient document — AES-256-GCM value/MAC encryption with
    /// SOPS's own non-standard 32-byte GCM nonce, a SHA-512 MAC, and the age-encryption.org/v1
    /// file format for wrapping the data key — directly on BouncyCastle.Cryptography, rather than
    /// importing a full SOPS or age library. No trustworthy in-process .NET library exists for
    /// either: everything under "sops" on nuget.org shells out to the real sops/age binaries
    /// (disqualified — signetd's trust model and this library's own API contract require
    /// in-process encryption, no external binary at runtime), and the one candidate age library,
    /// AgeSharp (github.com/pscheid92/AgeSharp), targets net10.0 only and does not build against
    /// this project's net8.0 target framework (confirmed via a spike: NuGet reports NU1202,
    /// incompatible with net8.0, across every published version). Every other
    /// bytepunx/signet-clients language has to hand-roll this same logic (no other ecosystem has
    /// a trustworthy SOPS-format library either), so this keeps one consistent approach across all
    /// of them instead of C# being the odd one out. The algorithm below is verified line-for-line
    /// against github.com/getsops/sops/v3's own sops.go (Tree.Encrypt), aes/cipher.go
    /// (Cipher.Encrypt), and filippo.io/age's age.go/x25519.go/primitives.go and
    /// internal/format+internal/stream packages (the reference age implementation, read directly
    /// from the Go module cache to get every byte-level detail — HKDF info strings, nonce
    /// construction, header MAC scope — exactly right), and this assembly's tests confirm the
    /// real sops binary can decrypt the result.
    /// </summary>
    /// <param name="publicKey">A Bech32-encoded age X25519 recipient string (<c>age1...</c>).</param>
    /// <param name="value">The raw UTF-8 bytes of the secret value to encrypt.</param>
    /// <returns>The encrypted SOPS document, as UTF-8 YAML bytes.</returns>
    /// <exception cref="SopsEncryptionException">
    /// <paramref name="publicKey"/> is empty or not a valid age X25519 recipient.
    /// </exception>
    public static byte[] EncryptForSecret(string publicKey, byte[] value)
    {
        if (string.IsNullOrEmpty(publicKey))
        {
            throw new SopsEncryptionException("signet: public key must not be empty");
        }

        byte[] recipientPublicKey;
        try
        {
            var (hrp, data) = Bech32.Decode(publicKey);
            if (hrp != "age" || data.Length != 32)
            {
                throw new SopsEncryptionException($"signet: parse age recipient: malformed recipient {publicKey}");
            }
            recipientPublicKey = data;
        }
        catch (SopsEncryptionException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SopsEncryptionException($"signet: parse age recipient: {ex.Message}", ex);
        }

        var dataKey = RandomNumberGenerator.GetBytes(32);

        // MAC: SHA-512 over the plaintext bytes of every leaf value, in tree order
        // (github.com/getsops/sops/v3's Tree.Encrypt + ToBytes). For our fixed {value: ...}
        // shape that's the single "value" leaf, and a plain string's ToBytes is just its raw
        // UTF-8 bytes.
        var macHex = Convert.ToHexString(SHA512.HashData(value)); // already uppercase

        var encValue = SopsAeadLeaf.Encrypt(dataKey, value, "value:");

        var lastModified = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var encMac = SopsAeadLeaf.Encrypt(dataKey, Encoding.UTF8.GetBytes(macHex), lastModified);

        var encDataKey = AgeFile.EncryptArmored(dataKey, recipientPublicKey);

        var document = new SopsDocument
        {
            Value = encValue,
            Sops = new SopsMetadata
            {
                Age = new List<SopsAgeKeyEntry>
                {
                    new() { Recipient = publicKey, Enc = encDataKey },
                },
                LastModified = lastModified,
                Mac = encMac,
                Version = SopsFileVersion,
            },
        };

        var serializer = new SerializerBuilder().Build();
        return Encoding.UTF8.GetBytes(serializer.Serialize(document));
    }

    private sealed class SopsAgeKeyEntry
    {
        [YamlMember(Alias = "recipient")]
        public string Recipient { get; set; } = string.Empty;

        [YamlMember(Alias = "enc")]
        public string Enc { get; set; } = string.Empty;
    }

    private sealed class SopsMetadata
    {
        [YamlMember(Alias = "age")]
        public List<SopsAgeKeyEntry> Age { get; set; } = new();

        // Explicit double-quoting matters here, not just cosmetics: an unquoted RFC3339
        // timestamp is auto-detected as a YAML 1.1 !!timestamp by go-yaml (which sops uses),
        // and sops's own struct field expects a plain string — see stores/stores.go's
        // `LastModified string`. An unquoted value fails to decode with "expected type
        // 'string', got unconvertible type 'time.Time'" (confirmed against the real sops binary).
        [YamlMember(Alias = "lastmodified", ScalarStyle = ScalarStyle.DoubleQuoted)]
        public string LastModified { get; set; } = string.Empty;

        [YamlMember(Alias = "mac")]
        public string Mac { get; set; } = string.Empty;

        [YamlMember(Alias = "version", ScalarStyle = ScalarStyle.DoubleQuoted)]
        public string Version { get; set; } = string.Empty;
    }

    private sealed class SopsDocument
    {
        [YamlMember(Alias = "value")]
        public string Value { get; set; } = string.Empty;

        [YamlMember(Alias = "sops")]
        public SopsMetadata Sops { get; set; } = new();
    }
}

/// <summary>
/// Encrypts a single SOPS tree leaf (the <c>value</c> or <c>mac</c> field) and renders it in
/// SOPS's own wire format, matching github.com/getsops/sops/v3/aes.Cipher.Encrypt: a 32-byte
/// random nonce (not the usual 12 bytes AES-GCM normally uses — confirmed .NET's built-in
/// <see cref="AesGcm"/> rejects anything but a 12-byte nonce on net8.0, so this uses
/// BouncyCastle's <see cref="GcmBlockCipher"/>, which accepts arbitrary nonce sizes),
/// <paramref name="additionalData"/> as the GCM AAD, and the sealed output split into "data"
/// (everything but the last 16 bytes) and "tag" (the last 16 bytes) — BouncyCastle, like Go's
/// cipher.AEAD.Seal, appends the tag to the ciphertext; SOPS stores them as separate base64
/// fields.
/// </summary>
internal static class SopsAeadLeaf
{
    private const int GcmNonceSize = 32;
    private const int GcmTagSizeBytes = 16;
    private const int GcmTagSizeBits = GcmTagSizeBytes * 8;

    internal static string Encrypt(byte[] dataKey, byte[] plaintext, string additionalData)
    {
        var nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);

        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(
            forEncryption: true,
            new Org.BouncyCastle.Crypto.Parameters.AeadParameters(
                new KeyParameter(dataKey), GcmTagSizeBits, nonce, Encoding.UTF8.GetBytes(additionalData)));

        var sealedOutput = new byte[cipher.GetOutputSize(plaintext.Length)];
        var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, sealedOutput, 0);
        len += cipher.DoFinal(sealedOutput, len);

        var data = sealedOutput[..(len - GcmTagSizeBytes)];
        var tag = sealedOutput[(len - GcmTagSizeBytes)..len];

        return "ENC[AES256_GCM,data:" + Convert.ToBase64String(data) +
               ",iv:" + Convert.ToBase64String(nonce) +
               ",tag:" + Convert.ToBase64String(tag) +
               ",type:str]";
    }
}

/// <summary>
/// Hand-implements the age-encryption.org/v1 file format for wrapping a data key to a single
/// X25519 recipient — the exact form SOPS embeds in the "enc" field of a <c>sops.age[]</c>
/// entry (mirrors github.com/getsops/sops/v3/age.MasterKey.Encrypt, which does the same thing
/// via filippo.io/age). Every constant and construction below (HKDF info strings, the X25519
/// recipient stanza's shared-secret salt, the header MAC's key derivation and scope, and the
/// single-chunk STREAM payload nonce) was read directly from filippo.io/age's own source
/// (age.go, x25519.go, primitives.go, internal/format, internal/stream) rather than
/// reconstructed from the prose spec, and this assembly's tests confirm the real age-compatible
/// sops binary can decrypt the result.
/// </summary>
internal static class AgeFile
{
    private const string X25519Label = "age-encryption.org/v1/X25519";
    private const string Intro = "age-encryption.org/v1\n";
    private const int FileKeySize = 16; // age's own internal file key, distinct from SOPS's 32-byte data key
    private const int StreamNonceSize = 16;
    private const int ChaChaNonceSize = 12;
    private const int Sha256Size = 32;

    /// <summary>
    /// Encrypts <paramref name="dataKey"/> (SOPS's 32-byte AES data key) to
    /// <paramref name="recipientPublicKey"/> (a raw 32-byte X25519 point) as a complete,
    /// ASCII-armored age file. <paramref name="dataKey"/> is always far smaller than age's 64KiB
    /// STREAM chunk size, so the payload is always exactly one, final chunk.
    /// </summary>
    internal static string EncryptArmored(byte[] dataKey, byte[] recipientPublicKey)
    {
        var fileKey = RandomNumberGenerator.GetBytes(FileKeySize);

        // --- X25519 recipient stanza: wrap fileKey to recipientPublicKey ---
        var ephemeralPrivate = RandomNumberGenerator.GetBytes(32);
        var ephemeralPublic = new byte[32];
        X25519.ScalarMultBase(ephemeralPrivate, 0, ephemeralPublic, 0);
        var sharedSecret = new byte[32];
        X25519.ScalarMult(ephemeralPrivate, 0, recipientPublicKey, 0, sharedSecret, 0);

        var salt = new byte[64];
        Buffer.BlockCopy(ephemeralPublic, 0, salt, 0, 32);
        Buffer.BlockCopy(recipientPublicKey, 0, salt, 32, 32);
        var wrappingKey = Hkdf(sharedSecret, salt, X25519Label, 32);
        // Fixed all-zero nonce is safe here: wrappingKey is derived from fresh ephemeral
        // randomness and used exactly once (mirrors age's own aeadEncrypt helper).
        var wrappedFileKey = ChaCha20Poly1305Seal(wrappingKey, new byte[ChaChaNonceSize], fileKey);

        // --- header: intro line, one recipient stanza, MAC line ---
        var header = new StringBuilder();
        header.Append(Intro);
        header.Append("-> X25519 ").Append(Base64RawStd(ephemeralPublic)).Append('\n');
        header.Append(WrapBase64(Base64RawStd(wrappedFileKey)).Wrapped);
        header.Append('\n'); // unconditional trailing newline, matching age's Stanza.Marshal
        header.Append("---");

        var headerWithoutMac = Encoding.ASCII.GetBytes(header.ToString());
        var hmacKey = Hkdf(fileKey, new byte[Sha256Size], "header", 32);
        var mac = HmacSha256(hmacKey, headerWithoutMac);
        var fullHeader = header + " " + Base64RawStd(mac) + "\n";

        // --- payload: single-chunk STREAM encryption of dataKey ---
        var streamNonce = RandomNumberGenerator.GetBytes(StreamNonceSize);
        var streamKey = Hkdf(fileKey, streamNonce, "payload", 32);
        var chunkNonce = new byte[ChaChaNonceSize];
        chunkNonce[^1] = 0x01; // lastChunkFlag — the only (and therefore final) chunk
        var ciphertext = ChaCha20Poly1305Seal(streamKey, chunkNonce, dataKey);

        var ageFile = new byte[Encoding.ASCII.GetByteCount(fullHeader) + streamNonce.Length + ciphertext.Length];
        var offset = Encoding.ASCII.GetBytes(fullHeader, 0, fullHeader.Length, ageFile, 0);
        Buffer.BlockCopy(streamNonce, 0, ageFile, offset, streamNonce.Length);
        Buffer.BlockCopy(ciphertext, 0, ageFile, offset + streamNonce.Length, ciphertext.Length);

        // --- ASCII armor: PEM-style wrapping with standard (padded) base64 ---
        var (armorBody, armorLastLineEmpty) = WrapBase64(Convert.ToBase64String(ageFile));
        var armor = new StringBuilder();
        armor.Append("-----BEGIN AGE ENCRYPTED FILE-----\n");
        armor.Append(armorBody);
        if (!armorLastLineEmpty)
        {
            armor.Append('\n');
        }
        armor.Append("-----END AGE ENCRYPTED FILE-----\n");
        return armor.ToString();
    }

    private static byte[] Hkdf(byte[] ikm, byte[] salt, string info, int length)
    {
        var generator = new HkdfBytesGenerator(new Sha256Digest());
        generator.Init(new HkdfParameters(ikm, salt, Encoding.ASCII.GetBytes(info)));
        var output = new byte[length];
        generator.GenerateBytes(output, 0, length);
        return output;
    }

    private static byte[] HmacSha256(byte[] key, byte[] data)
    {
        var hmac = new HMac(new Sha256Digest());
        hmac.Init(new KeyParameter(key));
        hmac.BlockUpdate(data, 0, data.Length);
        var output = new byte[hmac.GetMacSize()];
        hmac.DoFinal(output, 0);
        return output;
    }

    /// <summary>ChaCha20-Poly1305 seal with the standard 12-byte nonce and no AAD (age never uses AAD).</summary>
    private static byte[] ChaCha20Poly1305Seal(byte[] key, byte[] nonce, byte[] plaintext)
    {
        var cipher = new BcChaCha20Poly1305();
        cipher.Init(forEncryption: true, new Org.BouncyCastle.Crypto.Parameters.AeadParameters(new KeyParameter(key), 128, nonce));
        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        len += cipher.DoFinal(output, len);
        return output;
    }

    private static string Base64RawStd(byte[] data) => Convert.ToBase64String(data).TrimEnd('=');

    /// <summary>
    /// Reproduces age's own WrappedBase64Encoder byte-for-byte: splits <paramref name="base64"/>
    /// into 64-character lines, each terminated by a single LF, with no line inserted for zero
    /// input. <c>LastLineEmpty</c> is true exactly when the total length is a multiple of 64 (the
    /// only case where the final line was already LF-terminated inline, rather than needing one
    /// appended by the caller) — see age's internal/format.WrappedBase64Encoder and the callers
    /// in age.go/armor.go this mirrors.
    /// </summary>
    private static (string Wrapped, bool LastLineEmpty) WrapBase64(string base64)
    {
        var sb = new StringBuilder();
        var written = 0;
        var i = 0;
        while (i < base64.Length)
        {
            var take = Math.Min(64 - (written % 64), base64.Length - i);
            sb.Append(base64, i, take);
            i += take;
            written += take;
            if (written % 64 == 0)
            {
                sb.Append('\n');
            }
        }

        return (sb.ToString(), written % 64 == 0);
    }
}

/// <summary>
/// A minimal Bech32 (BIP-173) decoder for age's <c>age1...</c> recipient and
/// <c>AGE-SECRET-KEY-1...</c> identity encodings — ported from filippo.io/age's
/// internal/bech32 package (itself a modified version of the BIP-173 reference
/// implementation), since age recipients are the only public input this library needs to parse.
/// </summary>
internal static class Bech32
{
    private const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static readonly uint[] Generator = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };

    /// <summary>
    /// Encodes <paramref name="data"/> as Bech32 with human-readable part <paramref name="hrp"/>.
    /// Not used by <see cref="SopsEncryption.EncryptForSecret"/> itself (which only ever parses a
    /// recipient string), but exposed internally so this assembly's tests can generate age
    /// identities/recipients the same way filippo.io/age's GenerateX25519Identity does, without a
    /// second, separate Bech32 implementation.
    /// </summary>
    internal static string Encode(string hrp, byte[] data)
    {
        var values = ConvertBits(data, 8, 5, pad: true);
        var sb = new StringBuilder();
        sb.Append(hrp.ToLowerInvariant());
        sb.Append('1');
        foreach (var p in values)
        {
            sb.Append(Charset[p]);
        }

        foreach (var p in CreateChecksum(hrp.ToLowerInvariant(), values))
        {
            sb.Append(Charset[p]);
        }

        return sb.ToString();
    }

    private static byte[] CreateChecksum(string hrp, byte[] data)
    {
        var values = new List<byte>(HrpExpand(hrp));
        values.AddRange(data);
        values.AddRange(new byte[] { 0, 0, 0, 0, 0, 0 });
        var mod = Polymod(values.ToArray()) ^ 1;
        var ret = new byte[6];
        for (var p = 0; p < 6; p++)
        {
            ret[p] = (byte)((mod >> (5 * (5 - p))) & 31);
        }

        return ret;
    }

    internal static (string Hrp, byte[] Data) Decode(string s)
    {
        if (s.ToLowerInvariant() != s && s.ToUpperInvariant() != s)
        {
            throw new FormatException("mixed case");
        }

        var pos = s.LastIndexOf('1');
        if (pos < 1 || pos + 7 > s.Length)
        {
            throw new FormatException("separator '1' at invalid position");
        }

        var hrp = s[..pos];
        s = s.ToLowerInvariant();

        var data = new byte[s.Length - pos - 1];
        for (var i = 0; i < data.Length; i++)
        {
            var d = Charset.IndexOf(s[pos + 1 + i]);
            if (d == -1)
            {
                throw new FormatException("invalid character in data part");
            }

            data[i] = (byte)d;
        }

        if (Polymod(Concat(HrpExpand(hrp), data)) != 1)
        {
            throw new FormatException("invalid checksum");
        }

        var raw = ConvertBits(data[..^6], 5, 8, pad: false);
        return (hrp, raw);
    }

    private static uint Polymod(byte[] values)
    {
        var chk = 1u;
        foreach (var v in values)
        {
            var top = chk >> 25;
            chk = (chk & 0x1ffffff) << 5;
            chk ^= v;
            for (var i = 0; i < 5; i++)
            {
                if (((top >> i) & 1) == 1)
                {
                    chk ^= Generator[i];
                }
            }
        }

        return chk;
    }

    private static byte[] HrpExpand(string hrp)
    {
        var h = hrp.ToLowerInvariant();
        var ret = new byte[h.Length * 2 + 1];
        for (var i = 0; i < h.Length; i++)
        {
            ret[i] = (byte)(h[i] >> 5);
        }

        ret[h.Length] = 0;
        for (var i = 0; i < h.Length; i++)
        {
            ret[h.Length + 1 + i] = (byte)(h[i] & 31);
        }

        return ret;
    }

    private static byte[] ConvertBits(byte[] data, int frombits, int tobits, bool pad)
    {
        var ret = new List<byte>();
        uint acc = 0;
        var bits = 0;
        var maxv = (1 << tobits) - 1;
        foreach (var value in data)
        {
            if ((value >> frombits) != 0)
            {
                throw new FormatException("invalid data range");
            }

            acc = (acc << frombits) | value;
            bits += frombits;
            while (bits >= tobits)
            {
                bits -= tobits;
                ret.Add((byte)((acc >> bits) & maxv));
            }
        }

        if (pad)
        {
            if (bits > 0)
            {
                ret.Add((byte)((acc << (tobits - bits)) & maxv));
            }
        }
        else if (bits >= frombits || ((acc << (tobits - bits)) & maxv) != 0)
        {
            throw new FormatException("illegal zero padding / non-zero padding");
        }

        return ret.ToArray();
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }
}
