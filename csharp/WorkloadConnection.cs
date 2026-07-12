using System.Net.Http;
using Grpc.Net.Client;
using Spiffe.Grpc;
using Spiffe.Id;
using Spiffe.Ssl;
using Spiffe.WorkloadApi;

namespace Signet;

/// <summary>
/// A workload connection to signet's SecretsService, authenticated via SPIFFE mTLS.
/// Disposing releases the gRPC channel, the SPIFFE X.509 source, and the Workload API
/// channel used to fetch it — the SPIFFE analogue of Go's <c>DialWorkload</c> returning a
/// <c>closer func() error</c> alongside the connection.
/// </summary>
public sealed class WorkloadConnection : IAsyncDisposable
{
    private readonly GrpcChannel _channel;
    private readonly X509Source _x509Source;
    private readonly GrpcChannel _workloadApiChannel;
    private int _disposed;

    internal WorkloadConnection(GrpcChannel channel, X509Source x509Source, GrpcChannel workloadApiChannel)
    {
        _channel = channel;
        _x509Source = x509Source;
        _workloadApiChannel = workloadApiChannel;
    }

    /// <summary>The underlying gRPC channel, for constructing additional service clients if needed.</summary>
    public GrpcChannel Channel => _channel;

    /// <summary>A SecretsService client bound to this connection.</summary>
    public Signet.V1.SecretsService.SecretsServiceClient SecretsClient => new(_channel);

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return ValueTask.CompletedTask;
        }

        _channel.Dispose();
        _x509Source.Dispose();
        _workloadApiChannel.Dispose();
        return ValueTask.CompletedTask;
    }
}

public static partial class SignetConnect
{
    /// <summary>
    /// Opens a gRPC connection to signet's workload listener, authenticating via SPIFFE mTLS.
    /// <paramref name="socketPath"/> is the SPIFFE Workload API socket (e.g.
    /// <c>unix:///run/spire/sockets/agent.sock</c>); <paramref name="trustDomain"/> must match
    /// the trust domain of the target signet instance — the server's presented SPIFFE ID is
    /// rejected unless it is a member of this trust domain (mirrors Go's
    /// <c>tlsconfig.AuthorizeMemberOf</c>).
    /// </summary>
    /// <remarks>
    /// Backed by the third-party <c>Spiffe</c> NuGet package (github.com/vurhanau/csharp-spiffe),
    /// not an official spiffe.io project — see README.md for the full maturity writeup. Its API
    /// (X509Source, Workload API client, AuthorizeMemberOf) maps directly onto go-spiffe's,
    /// which is what Go's <c>DialWorkload</c> uses.
    /// </remarks>
    /// <exception cref="SignetConnectionException">
    /// The Workload API could not be reached, or the gRPC channel could not be constructed.
    /// </exception>
    /// <exception cref="ArgumentException"><paramref name="trustDomain"/> is not a valid SPIFFE trust domain.</exception>
    public static async Task<WorkloadConnection> DialWorkloadAsync(
        string addr, string socketPath, string trustDomain, CancellationToken cancellationToken = default)
    {
        var workloadApiChannel = GrpcChannelFactory.CreateChannel(socketPath);

        X509Source source;
        try
        {
            var workloadApiClient = WorkloadApiClient.Create(workloadApiChannel);
            source = await X509Source.CreateAsync(workloadApiClient, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            workloadApiChannel.Dispose();
            throw new SignetConnectionException(
                $"connect to SPIFFE workload API at {socketPath}: {ex.Message}", ex);
        }

        TrustDomain trustDomainId;
        try
        {
            trustDomainId = TrustDomain.FromString(trustDomain);
        }
        catch (Exception ex)
        {
            source.Dispose();
            workloadApiChannel.Dispose();
            throw new ArgumentException($"invalid trust domain '{trustDomain}': {ex.Message}", nameof(trustDomain), ex);
        }

        var sslOptions = SpiffeSslConfig.GetMtlsClientOptions(source, Authorizers.AuthorizeMemberOf(trustDomainId));
        var handler = new SocketsHttpHandler { SslOptions = sslOptions };

        GrpcChannel channel;
        try
        {
            channel = GrpcChannel.ForAddress($"https://{addr}", new GrpcChannelOptions { HttpHandler = handler });
        }
        catch (Exception ex)
        {
            source.Dispose();
            workloadApiChannel.Dispose();
            throw new SignetConnectionException($"dial {addr}: {ex.Message}", ex);
        }

        return new WorkloadConnection(channel, source, workloadApiChannel);
    }
}
