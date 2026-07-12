using System.Threading.Channels;
using Signet;
using SignetClient.Tests.Fakes;
using Xunit;

namespace SignetClient.Tests;

/// <summary>Ports every case from go/restart_test.go's watch-loop coverage.</summary>
public class WatchTests
{
    [Fact]
    public async Task WatchLoop_CoalescesRapidChanges()
    {
        // 3 changes are pushed but the response channel is never closed, so after they're
        // drained the 4th Receive call just blocks — no error, no reconnect, so open() is only
        // ever called once.
        var stream = new FakeWatchStream();
        stream.PushChanged();
        stream.PushChanged();
        stream.PushChanged();

        var channel = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
        });

        using var cts = new CancellationTokenSource();
        _ = Restart.WatchLoopAsync(channel.Writer, _ => Task.FromResult<IWatchStream>(stream), cts.Token);

        // Wait until the loop has actually drained all 3 pushed events (the 4th Receive call is
        // the one that blocks) before checking coalescing — otherwise this is racy: consuming
        // the first signal before all 3 are processed just frees the buffer for a legitimately
        // new one.
        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (stream.ReceiveCalls < 4 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(5);
        }

        Assert.True(stream.ReceiveCalls >= 4, $"only issued {stream.ReceiveCalls} Receive calls, want >= 4");
        Assert.True(channel.Reader.TryPeek(out _), "expected exactly 1 coalesced pending signal");

        Assert.True(channel.Reader.TryRead(out _));
        Assert.False(channel.Reader.TryRead(out _), "expected no further pending signal after draining the coalesced one");

        cts.Cancel();
    }

    [Fact]
    public async Task WatchLoop_ReconnectsAfterStreamError()
    {
        var first = new FakeWatchStream();
        first.PushError(new InvalidOperationException("boom"));

        var second = new FakeWatchStream();
        second.PushChanged();

        var attempt = 0;
        var gate = new object();

        var channel = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        _ = Restart.WatchLoopAsync(
            channel.Writer,
            _ =>
            {
                IWatchStream chosen;
                lock (gate)
                {
                    attempt++;
                    chosen = attempt == 1 ? first : second;
                }

                return Task.FromResult(chosen);
            },
            cts.Token);

        var read = await channel.Reader.WaitToReadAsync(cts.Token);
        Assert.True(read, "expected the watch loop to reconnect and eventually deliver a change");
    }
}
