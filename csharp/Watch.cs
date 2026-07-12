using System.Threading.Channels;
using Grpc.Core;

namespace Signet;

/// <summary>
/// The subset of <c>SecretsServiceClient.WatchServiceBundle</c>'s server-streaming call that
/// the watch loop depends on — mirrors the Go client's <c>watchStream</c> interface.
/// </summary>
internal interface IWatchStream
{
    /// <summary>Mirrors Go's <c>Recv() (msg, err)</c> — a graceful end of stream throws too.</summary>
    Task<Signet.V1.WatchServiceBundleResponse> ReceiveAsync(CancellationToken cancellationToken = default);
}

/// <summary>Adapts the generated gRPC server-streaming call to <see cref="IWatchStream"/>.</summary>
internal sealed class GrpcWatchStream : IWatchStream
{
    private readonly AsyncServerStreamingCall<Signet.V1.WatchServiceBundleResponse> _call;

    internal GrpcWatchStream(AsyncServerStreamingCall<Signet.V1.WatchServiceBundleResponse> call) => _call = call;

    public async Task<Signet.V1.WatchServiceBundleResponse> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        if (!await _call.ResponseStream.MoveNext(cancellationToken).ConfigureAwait(false))
        {
            throw new StreamClosedException("WatchServiceBundle stream closed by the server");
        }

        return _call.ResponseStream.Current;
    }
}

public static partial class Restart
{
    private static readonly TimeSpan WatchBackoffMin = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan WatchBackoffMax = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Watches for signet bundle-change notifications for <paramref name="namespace"/>/<paramref name="service"/>,
    /// reconnecting with exponential backoff (1s, doubling, capped at 30s, reset to 1s on any
    /// successful receive) if the stream breaks. Rapid successive changes are coalesced: the
    /// returned reader only ever has at most one pending "at least one change happened since you
    /// last read" signal — never a backlog/count. The channel completes when
    /// <paramref name="cancellationToken"/> is canceled.
    /// </summary>
    public static ChannelReader<bool> WatchBundleAsync(
        Signet.V1.SecretsService.SecretsServiceClient client,
        string @namespace,
        string service,
        CancellationToken cancellationToken = default)
    {
        var channel = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true,
            SingleWriter = true,
        });

        _ = WatchLoopAsync(
            channel.Writer,
            ct =>
            {
                var call = client.WatchServiceBundle(
                    new Signet.V1.WatchServiceBundleRequest { Namespace = @namespace, Service = service },
                    cancellationToken: ct);
                return Task.FromResult<IWatchStream>(new GrpcWatchStream(call));
            },
            cancellationToken);

        return channel.Reader;
    }

    /// <summary>Internal seam so tests can drive the reconnect/coalesce state machine against a fake stream.</summary>
    internal static async Task WatchLoopAsync(
        ChannelWriter<bool> writer,
        Func<CancellationToken, Task<IWatchStream>> open,
        CancellationToken cancellationToken)
    {
        try
        {
            var backoff = WatchBackoffMin;
            while (!cancellationToken.IsCancellationRequested)
            {
                IWatchStream stream;
                try
                {
                    stream = await open(cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    if (!await DelayOrDoneAsync(backoff, cancellationToken).ConfigureAwait(false))
                    {
                        return;
                    }

                    backoff = NextBackoff(backoff);
                    continue;
                }

                while (true)
                {
                    Signet.V1.WatchServiceBundleResponse resp;
                    try
                    {
                        resp = await stream.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch
                    {
                        break;
                    }

                    backoff = WatchBackoffMin;
                    if (resp.EventType == Signet.V1.WatchServiceBundleResponse.Types.EventType.Changed)
                    {
                        // Bounded(1) + DropWrite: if a signal is already pending and unread, this
                        // silently drops the new one instead of queuing a backlog — coalescing.
                        writer.TryWrite(true);
                    }
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    return;
                }

                if (!await DelayOrDoneAsync(backoff, cancellationToken).ConfigureAwait(false))
                {
                    return;
                }

                backoff = NextBackoff(backoff);
            }
        }
        finally
        {
            writer.TryComplete();
        }
    }

    private static async Task<bool> DelayOrDoneAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private static TimeSpan NextBackoff(TimeSpan current)
    {
        var next = current + current;
        return next > WatchBackoffMax ? WatchBackoffMax : next;
    }
}
