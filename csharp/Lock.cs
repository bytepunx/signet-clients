using Grpc.Core;

namespace Signet;

/// <summary>
/// The subset of <c>SecretsServiceClient.AcquireRestartLock</c>'s bidirectional stream that
/// the lock state machine depends on, so tests can substitute a hand-written fake instead of
/// a real gRPC stream — mirrors the Go client's <c>lockStream</c> interface.
/// </summary>
internal interface ILockStream
{
    Task SendAsync(Signet.V1.AcquireRestartLockRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the next message, or throws if the stream errored or ended (graceful close is
    /// surfaced as <see cref="StreamClosedException"/>) — mirrors Go's <c>Recv() (msg, err)</c>,
    /// where both cases are simply "err != nil".
    /// </summary>
    Task<Signet.V1.AcquireRestartLockResponse> ReceiveAsync(CancellationToken cancellationToken = default);

    Task CloseSendAsync();
}

/// <summary>Adapts the generated gRPC duplex stream to <see cref="ILockStream"/>.</summary>
internal sealed class GrpcLockStream : ILockStream
{
    private readonly AsyncDuplexStreamingCall<Signet.V1.AcquireRestartLockRequest, Signet.V1.AcquireRestartLockResponse> _call;

    internal GrpcLockStream(
        AsyncDuplexStreamingCall<Signet.V1.AcquireRestartLockRequest, Signet.V1.AcquireRestartLockResponse> call)
    {
        _call = call;
    }

    public Task SendAsync(Signet.V1.AcquireRestartLockRequest request, CancellationToken cancellationToken = default)
        => _call.RequestStream.WriteAsync(request, cancellationToken);

    public async Task<Signet.V1.AcquireRestartLockResponse> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        if (!await _call.ResponseStream.MoveNext(cancellationToken).ConfigureAwait(false))
        {
            throw new StreamClosedException("AcquireRestartLock stream closed by the server");
        }

        return _call.ResponseStream.Current;
    }

    public async Task CloseSendAsync() => await _call.RequestStream.CompleteAsync().ConfigureAwait(false);
}

/// <summary>
/// Represents a held signet restart lock. Call <see cref="ReleaseAsync"/> (or dispose) once
/// your own graceful shutdown — draining in-flight work, closing resources — is complete,
/// immediately before the process exits. This library never calls
/// <see cref="Environment.Exit(int)"/> itself; that decision belongs entirely to the caller.
/// </summary>
public sealed class Lock : IAsyncDisposable
{
    private readonly ILockStream _stream;
    private readonly object _gate = new();
    private string _token = string.Empty;
    private DateTimeOffset _expiresAt;
    private bool _released;

    private readonly TaskCompletionSource<Exception> _lostTcs =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private CancellationTokenSource? _heartbeatCts;
    private Task? _heartbeatTask;
    private Task _recvTask = Task.CompletedTask;

    private Lock(ILockStream stream) => _stream = stream;

    /// <summary>Identifies this lock acquisition, for audit/logging purposes.</summary>
    public string Token
    {
        get { lock (_gate) return _token; }
    }

    /// <summary>The lock's current expiry, updated as heartbeats are acknowledged.</summary>
    public DateTimeOffset ExpiresAt
    {
        get { lock (_gate) return _expiresAt; }
    }

    /// <summary>
    /// Completes, at most once, with the error that caused the lock to be lost unexpectedly
    /// (a stream error, or the server closing the stream) before <see cref="ReleaseAsync"/> was
    /// called. Deliberately never completes for an intentional release — awaiting this task is
    /// how a caller distinguishes "another replica may now acquire and restart concurrently"
    /// (this completes) from a clean, intentional release (this never completes). There is
    /// nothing to undo on loss, only to log.
    /// </summary>
    public Task<Exception> Lost => _lostTcs.Task;

    internal static async Task<Lock> AcquireAsync(
        ILockStream stream,
        string @namespace,
        string service,
        int ttlSeconds,
        CancellationToken cancellationToken)
    {
        var l = new Lock(stream);

        try
        {
            await stream.SendAsync(
                new Signet.V1.AcquireRestartLockRequest
                {
                    Namespace = @namespace,
                    Service = service,
                    TtlSeconds = ttlSeconds,
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new LockAcquisitionException($"signet: send initial AcquireRestartLock request: {ex.Message}", ex);
        }

        var acquired = new TaskCompletionSource<Exception?>(TaskCreationOptions.RunContinuationsAsynchronously);
        l._recvTask = l.RecvLoopAsync(acquired);

        Exception? failure;
        await using (cancellationToken.Register(
                         static state => ((TaskCompletionSource<Exception?>)state!).TrySetResult(
                             new OperationCanceledException("signet: AcquireLock canceled while waiting to acquire")),
                         acquired).ConfigureAwait(false))
        {
            failure = await acquired.Task.ConfigureAwait(false);
        }

        if (failure != null)
        {
            // Nothing was ever running against the stream but the recv loop itself — make sure
            // it's allowed to unwind (it already returned after reporting failure) and surface a
            // clear, specific exception rather than a bare stream/transport error.
            if (failure is OperationCanceledException oce)
            {
                throw oce;
            }

            throw new LockAcquisitionException($"signet: acquire restart lock: {failure.Message}", failure);
        }

        l._heartbeatCts = new CancellationTokenSource();
        l._heartbeatTask = l.HeartbeatLoopAsync(ttlSeconds, l._heartbeatCts.Token);
        return l;
    }

    /// <summary>
    /// Owns <c>ReceiveAsync</c> for the stream's entire lifetime: delivers the first ACQUIRED
    /// (or a fatal error before it) via <paramref name="acquired"/>, then keeps reading
    /// TTL_EXTENDED acks (updating <see cref="ExpiresAt"/>) until the stream errors or closes,
    /// at which point it reports loss via <see cref="Lost"/> (unless <see cref="ReleaseAsync"/>
    /// already initiated the close). This is the single task that must run continuously for the
    /// lock's entire hold duration — it is not fire-and-forget heartbeating.
    /// </summary>
    private async Task RecvLoopAsync(TaskCompletionSource<Exception?> acquired)
    {
        var gotAcquired = false;
        while (true)
        {
            Signet.V1.AcquireRestartLockResponse resp;
            try
            {
                resp = await _stream.ReceiveAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (!gotAcquired)
                {
                    acquired.TrySetResult(ex);
                }
                else
                {
                    ReportLost(ex);
                }

                return;
            }

            switch (resp.MessageType)
            {
                case Signet.V1.AcquireRestartLockResponse.Types.MessageType.Acquired:
                    lock (_gate)
                    {
                        _token = resp.Token;
                        if (resp.ExpiresAt is not null)
                        {
                            _expiresAt = resp.ExpiresAt.ToDateTimeOffset();
                        }
                    }

                    if (!gotAcquired)
                    {
                        gotAcquired = true;
                        acquired.TrySetResult(null);
                    }

                    break;

                case Signet.V1.AcquireRestartLockResponse.Types.MessageType.TtlExtended:
                    lock (_gate)
                    {
                        if (resp.ExpiresAt is not null)
                        {
                            _expiresAt = resp.ExpiresAt.ToDateTimeOffset();
                        }
                    }

                    break;

                case Signet.V1.AcquireRestartLockResponse.Types.MessageType.QueuePosition:
                default:
                    // No state to track; callers who want position visibility can watch the
                    // stream themselves before calling AcquireLockAsync if that becomes a real need.
                    break;
            }
        }
    }

    /// <summary>
    /// Sends a heartbeat every <c>ttlSeconds / 4</c> — signet's documented convention: 4
    /// consecutive missed heartbeats exhaust the TTL (see docs/restart-lock.md). Deliberately
    /// ttl/4, not ttl/2 — a too-infrequent heartbeat was a real bug found in kickr, signet's
    /// existing process-host client.
    /// </summary>
    private async Task HeartbeatLoopAsync(int ttlSeconds, CancellationToken cancellationToken)
    {
        var intervalSeconds = ttlSeconds / 4.0;
        var interval = TimeSpan.FromSeconds(intervalSeconds > 0 ? intervalSeconds : 1);
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    await _stream.SendAsync(
                        new Signet.V1.AcquireRestartLockRequest { Heartbeat = true },
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    ReportLost(ex);
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on ReleaseAsync/cancellation.
        }
    }

    private void ReportLost(Exception ex)
    {
        lock (_gate)
        {
            if (_released)
            {
                return;
            }
        }

        _lostTcs.TrySetResult(ex);
    }

    /// <summary>
    /// Closes the lock stream, releasing the lock for the next waiting replica. Idempotent —
    /// safe to call more than once; subsequent calls are a no-op.
    /// </summary>
    public async Task ReleaseAsync()
    {
        lock (_gate)
        {
            if (_released)
            {
                return;
            }

            _released = true;
        }

        _heartbeatCts?.Cancel();
        if (_heartbeatTask is not null)
        {
            try
            {
                await _heartbeatTask.ConfigureAwait(false);
            }
            catch
            {
                // The heartbeat loop already reports failures via ReportLost; nothing more to do.
            }
        }

        try
        {
            await _stream.CloseSendAsync().ConfigureAwait(false);
        }
        finally
        {
            try
            {
                await _recvTask.ConfigureAwait(false);
            }
            catch
            {
                // RecvLoopAsync never throws out — this is defensive only.
            }
        }
    }

    public async ValueTask DisposeAsync() => await ReleaseAsync().ConfigureAwait(false);
}
