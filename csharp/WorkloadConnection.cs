using System.Net.Http;
using Grpc.Core;
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

/// <summary>
/// Pure retry-loop logic behind <c>DialWorkloadAsync</c>'s SPIRE identity-readiness probe,
/// factored out so it's unit-testable without a live Workload API. Mirrors the Go client's
/// <c>retryUntilIdentityIssued</c>/<c>isNoIdentityIssuedErr</c> (see <c>go/client.go</c>) and the
/// race it exists to close — see bytepunx/signet-clients#33.
/// </summary>
internal static class WorkloadDialRetry
{
    /// <summary>
    /// Backoff between identity-readiness probe attempts: 1s, 2s, 4s, 8s — doubling each time,
    /// capped at 8s. This is the exact schedule verified working in a real downstream consumer
    /// that hit this race (bytepunx/kluster's RabbitMQ credential-provisioning Job), so
    /// <c>Backoff.Length</c> retries are made beyond the initial attempt — <see cref="MaxAttempts"/>
    /// total — with a worst case of roughly 15s of waiting before giving up.
    /// </summary>
    internal static readonly TimeSpan[] Backoff =
    {
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(4),
        TimeSpan.FromSeconds(8),
    };

    /// <summary>
    /// Total identity-readiness probes made: the initial attempt plus <see cref="Backoff"/>'s
    /// four retries.
    /// </summary>
    internal static readonly int MaxAttempts = Backoff.Length + 1;

    /// <summary>
    /// Reports whether <paramref name="ex"/> is the SPIFFE Workload API's "no identity issued"
    /// failure: a <see cref="StatusCode.PermissionDenied"/> <see cref="RpcException"/> returned
    /// when the calling workload has no SPIFFE identity registered yet — the exact condition this
    /// retry exists for. Matching is deliberately on status code alone, not error text, since the
    /// code is the stable part of this contract across SPIRE versions.
    /// </summary>
    internal static bool IsNoIdentityIssuedError(Exception ex) =>
        ex is RpcException rpc && rpc.StatusCode == StatusCode.PermissionDenied;

    /// <summary>
    /// Calls <paramref name="probe"/>, retrying per <see cref="Backoff"/> (via
    /// <paramref name="delay"/>, so tests can substitute a non-blocking fake) as long as it keeps
    /// failing with <see cref="IsNoIdentityIssuedError"/>. Returns as soon as <paramref
    /// name="probe"/> succeeds. Any other failure propagates immediately, unretried, so this never
    /// masks a real misconfiguration (bad <c>socketPath</c>, a canceled <paramref
    /// name="cancellationToken"/>, a malformed trust domain, a genuine authorization problem once
    /// identity issuance is actually broken rather than merely delayed, ...) as a transient blip.
    /// Throws once <see cref="MaxAttempts"/> is exhausted, naming the last "no identity issued"
    /// failure as the inner exception.
    /// </summary>
    internal static async Task RunAsync(
        Func<CancellationToken, Task> probe,
        Func<TimeSpan, CancellationToken, Task> delay,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            try
            {
                await probe(cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (IsNoIdentityIssuedError(ex))
            {
                lastError = ex;
            }

            if (attempt == Backoff.Length)
            {
                break;
            }

            await delay(Backoff[attempt], cancellationToken).ConfigureAwait(false);
        }

        throw new SignetConnectionException($"no identity issued after {MaxAttempts} attempts", lastError!);
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
    /// <para>
    /// Backed by the third-party <c>Spiffe</c> NuGet package (github.com/vurhanau/csharp-spiffe),
    /// not an official spiffe.io project — see README.md for the full maturity writeup. Its API
    /// (X509Source, Workload API client, AuthorizeMemberOf) maps directly onto go-spiffe's,
    /// which is what Go's <c>DialWorkload</c> uses.
    /// </para>
    /// <para>
    /// Retries automatically — no opt-in required — if the Workload API reports "no identity
    /// issued" before it can hand back a connection. This is a real, verified-in-production race,
    /// not speculative hardening: SPIRE's controller-manager reconciles a brand-new pod's SPIFFE
    /// identity registration reactively, off the pod's own creation event, and that registration
    /// takes a few seconds to propagate from there to the node-local SPIRE agent this dials over
    /// <paramref name="socketPath"/>. A freshly-created pod's very first
    /// <c>DialWorkloadAsync</c> call — a Job's is the sharpest case, since a Job has no prior pod
    /// that might have already won this race for the same ServiceAccount — can lose it outright
    /// and see "no identity issued" even though the identity shows up moments later. See
    /// bytepunx/signet-clients#33 for the full writeup, including where this was first hit
    /// (bytepunx/kluster's RabbitMQ credential-provisioning Job).
    /// </para>
    /// <para>
    /// The retry makes up to <see cref="WorkloadDialRetry.MaxAttempts"/> (5) attempts total — the
    /// initial attempt plus up to 4 retries — backing off per <see cref="WorkloadDialRetry.Backoff"/>
    /// (1s, 2s, 4s, 8s) between them. Only the "no identity issued" failure is retried: every
    /// other error is returned to the caller immediately, unretried, so this never masks a real
    /// misconfiguration as a transient blip. The probe itself is a single-shot, non-watching
    /// fetch (<c>IWorkloadApiClient.FetchX509ContextAsync</c>) rather than the long-lived watching
    /// source (<c>X509Source</c>, which <c>WatchX509ContextAsync</c> backs internally) — that
    /// watch already retries "no identity issued" forever with its own uncontrollable, unbounded
    /// backoff, silently absorbing the very error this method needs to see and pace itself by, so
    /// it can't be used to classify or bound retries directly. Once the probe confirms identity is
    /// issued, the real long-lived <c>X509Source</c> is established as usual; its own internal
    /// retry remains as a safety net for any further transient hiccup, but the race this method
    /// exists to close has already been won by then.
    /// </para>
    /// </remarks>
    /// <exception cref="SignetConnectionException">
    /// The Workload API could not be reached (including exhausting the identity-readiness retry
    /// above), or the gRPC channel could not be constructed.
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

            // Probe first — see the doc comment above for why this must be a single-shot fetch
            // rather than going straight to the long-lived watching X509Source.
            await WorkloadDialRetry.RunAsync(
                probe: async ct => await workloadApiClient.FetchX509ContextAsync(ct).ConfigureAwait(false),
                delay: Task.Delay,
                cancellationToken).ConfigureAwait(false);

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
