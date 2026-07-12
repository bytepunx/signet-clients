using System.Threading.Channels;
using Signet;

namespace SignetClient.Tests.Fakes;

/// <summary>
/// Hand-written fake satisfying <see cref="IWatchStream"/>. Mirrors go/restart_test.go's
/// <c>fakeWatchStream</c>, including exposing a receive-call counter so tests can deterministically
/// wait for a scripted batch of responses to be fully drained before asserting on coalescing.
/// </summary>
internal sealed class FakeWatchStream : IWatchStream
{
    private readonly Channel<(Signet.V1.WatchServiceBundleResponse? Resp, Exception? Err)> _responses;
    private int _receiveCalls;

    internal FakeWatchStream(int capacity = 16)
    {
        _responses = Channel.CreateBounded<(Signet.V1.WatchServiceBundleResponse?, Exception?)>(capacity);
    }

    internal void PushChanged() => _responses.Writer.TryWrite(
        (new Signet.V1.WatchServiceBundleResponse
        {
            EventType = Signet.V1.WatchServiceBundleResponse.Types.EventType.Changed,
        }, null));

    internal void PushError(Exception error) => _responses.Writer.TryWrite((null, error));

    internal int ReceiveCalls => Volatile.Read(ref _receiveCalls);

    public async Task<Signet.V1.WatchServiceBundleResponse> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _receiveCalls);

        (Signet.V1.WatchServiceBundleResponse? Resp, Exception? Err) item;
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
}
