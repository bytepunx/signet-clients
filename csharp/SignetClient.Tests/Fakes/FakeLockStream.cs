using System.Threading.Channels;
using Signet;

namespace SignetClient.Tests.Fakes;

/// <summary>
/// Hand-written fake satisfying <see cref="ILockStream"/>, driven by a scripted sequence of
/// responses (or errors) fed to <see cref="ReceiveAsync"/>, and recording every
/// <see cref="SendAsync"/> for assertions. Mirrors go/restart_test.go's <c>fakeLockStream</c>.
/// </summary>
internal sealed class FakeLockStream : ILockStream
{
    private readonly Channel<(Signet.V1.AcquireRestartLockResponse? Resp, Exception? Err)> _responses;
    private readonly List<Signet.V1.AcquireRestartLockRequest> _sent = new();
    private readonly object _gate = new();
    private bool _closed;
    private Exception? _failNextSend;

    internal FakeLockStream(int capacity = 16)
    {
        _responses = Channel.CreateBounded<(Signet.V1.AcquireRestartLockResponse?, Exception?)>(capacity);
    }

    internal void PushResponse(Signet.V1.AcquireRestartLockResponse response) =>
        _responses.Writer.TryWrite((response, null));

    internal void PushError(Exception error) => _responses.Writer.TryWrite((null, error));

    /// <summary>Makes the next call to <see cref="SendAsync"/> fail with <paramref name="error"/>.</summary>
    internal void FailNextSend(Exception error)
    {
        lock (_gate)
        {
            _failNextSend = error;
        }
    }

    public Task SendAsync(Signet.V1.AcquireRestartLockRequest request, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (_failNextSend is { } err)
            {
                _failNextSend = null;
                return Task.FromException(err);
            }

            if (_closed)
            {
                return Task.FromException(new InvalidOperationException("send on closed stream"));
            }

            _sent.Add(request);
        }

        return Task.CompletedTask;
    }

    public async Task<Signet.V1.AcquireRestartLockResponse> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        (Signet.V1.AcquireRestartLockResponse? Resp, Exception? Err) item;
        try
        {
            item = await _responses.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            throw new StreamClosedException("stream closed");
        }

        if (item.Err is not null)
        {
            throw item.Err;
        }

        return item.Resp!;
    }

    public Task CloseSendAsync()
    {
        lock (_gate)
        {
            if (_closed)
            {
                return Task.CompletedTask;
            }

            _closed = true;
        }

        _responses.Writer.TryComplete();
        return Task.CompletedTask;
    }

    internal int SentCount
    {
        get
        {
            lock (_gate)
            {
                return _sent.Count;
            }
        }
    }

    internal IReadOnlyList<Signet.V1.AcquireRestartLockRequest> Sent
    {
        get
        {
            lock (_gate)
            {
                return _sent.ToArray();
            }
        }
    }
}
