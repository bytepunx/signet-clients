using System.Threading.Channels;

namespace Signet;

/// <summary>
/// Coordinated-restart primitives: <see cref="WatchBundleAsync"/>, <see cref="AcquireLockAsync"/>,
/// and <see cref="WaitForRestartAsync"/> let a service pull its own configuration directly and
/// in-memory, and safely coordinate a fleet-wide serialized restart when it changes.
///
/// This library deliberately does NOT: spawn or supervise a child process, write the bundle to
/// environment variables/files/anywhere outside memory, refetch the bundle after the lock is
/// acquired (there's no replacement process to hand it to — the next process instance fetches it
/// fresh during its own normal startup), or call <see cref="Environment.Exit(int)"/> itself. See
/// README.md's "Coordinated restarts" section for the full rationale.
/// </summary>
public static partial class Restart
{
    /// <summary>
    /// Blocks until this replica acquires signet's restart lock for
    /// <paramref name="namespace"/>/<paramref name="service"/>, queueing behind any current
    /// holder. <paramref name="ttl"/> must be greater than zero and must cover the full time
    /// between acquiring the lock and calling <see cref="Lock.ReleaseAsync"/> — signet has no
    /// server-side default. Heartbeats are sent automatically at <c>ttl / 4</c> (signet's
    /// documented convention: 4 consecutive missed heartbeats exhaust the TTL) until the lock is
    /// released, <paramref name="cancellationToken"/> is canceled, or the lock is lost (see
    /// <see cref="Lock.Lost"/>).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="ttl"/> is zero or negative. Thrown synchronously, before any stream is opened.
    /// </exception>
    /// <exception cref="LockAcquisitionException">
    /// The stream could not be opened, or it errored/closed before the lock was acquired.
    /// </exception>
    public static Task<Lock> AcquireLockAsync(
        Signet.V1.SecretsService.SecretsServiceClient client,
        string @namespace,
        string service,
        TimeSpan ttl,
        CancellationToken cancellationToken = default)
    {
        if (ttl <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ttl), ttl,
                "signet: ttl must be > 0 — signet has no server-side default TTL for the restart lock");
        }

        return AcquireLockCoreAsync(client, @namespace, service, ttl, cancellationToken);
    }

    private static async Task<Lock> AcquireLockCoreAsync(
        Signet.V1.SecretsService.SecretsServiceClient client,
        string @namespace,
        string service,
        TimeSpan ttl,
        CancellationToken cancellationToken)
    {
        Grpc.Core.AsyncDuplexStreamingCall<Signet.V1.AcquireRestartLockRequest, Signet.V1.AcquireRestartLockResponse> call;
        try
        {
            call = client.AcquireRestartLock(cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            throw new LockAcquisitionException($"signet: open AcquireRestartLock stream: {ex.Message}", ex);
        }

        return await Lock.AcquireAsync(new GrpcLockStream(call), @namespace, service, ToTtlSeconds(ttl), cancellationToken)
            .ConfigureAwait(false);
    }

    internal static int ToTtlSeconds(TimeSpan ttl)
    {
        var seconds = (int)ttl.TotalSeconds;
        return seconds > 0 ? seconds : 1;
    }

    /// <summary>
    /// Convenience combining <see cref="WatchBundleAsync"/> and <see cref="AcquireLockAsync"/>:
    /// waits for the next bundle change (debounced by <paramref name="debounce"/> — zero means
    /// act on the first event immediately), then acquires the restart lock, returning once held.
    /// Does not fetch the updated bundle — since this call doesn't spawn a replacement process,
    /// the next process instance fetches it fresh during its own normal startup.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="ttl"/> is zero or negative.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled first.</exception>
    public static Task<Lock> WaitForRestartAsync(
        Signet.V1.SecretsService.SecretsServiceClient client,
        string @namespace,
        string service,
        TimeSpan ttl,
        TimeSpan debounce,
        CancellationToken cancellationToken = default)
    {
        if (ttl <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ttl), ttl,
                "signet: ttl must be > 0 — signet has no server-side default TTL for the restart lock");
        }

        return WaitForRestartCoreAsync(client, @namespace, service, ttl, debounce, cancellationToken);
    }

    private static async Task<Lock> WaitForRestartCoreAsync(
        Signet.V1.SecretsService.SecretsServiceClient client,
        string @namespace,
        string service,
        TimeSpan ttl,
        TimeSpan debounce,
        CancellationToken cancellationToken)
    {
        var changes = WatchBundleAsync(client, @namespace, service, cancellationToken);

        if (!await WaitAndDrainAsync(changes, cancellationToken).ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new SignetException("signet: bundle watch stream ended before any change was observed");
        }

        if (debounce > TimeSpan.Zero)
        {
            while (true)
            {
                using var raceCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                var debounceElapsed = Task.Delay(debounce, raceCts.Token);
                var nextChange = changes.WaitToReadAsync(raceCts.Token).AsTask();

                var winner = await Task.WhenAny(debounceElapsed, nextChange).ConfigureAwait(false);
                raceCts.Cancel();

                if (winner == debounceElapsed)
                {
                    // Swallow the expected cancellation of the losing wait; anything else propagates.
                    try
                    {
                        await nextChange.ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                    }

                    break;
                }

                try
                {
                    await debounceElapsed.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }

                if (!await nextChange.ConfigureAwait(false))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new SignetException("signet: bundle watch stream ended during debounce");
                }

                await changes.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        return await AcquireLockAsync(client, @namespace, service, ttl, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> WaitAndDrainAsync(ChannelReader<bool> reader, CancellationToken cancellationToken)
    {
        if (!await reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }
}
