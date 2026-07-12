using Signet;
using SignetClient.Tests.Fakes;
using Xunit;
using static SignetClient.Tests.ResponseBuilders;

namespace SignetClient.Tests;

/// <summary>
/// Ports every case from go/restart_test.go's lock coverage, driving <see cref="Lock"/>'s
/// internal state machine against <see cref="FakeLockStream"/> rather than a live signet
/// instance — exactly mirroring the Go client's fake-stream testing pattern.
/// </summary>
public class LockTests
{
    // xUnit2014 assumes any Assert.Throws() wrapping a Task-returning call means you forgot to
    // await it and meant ThrowsAsync. That doesn't apply here: AcquireLockAsync validates ttl
    // and throws *synchronously*, before it ever creates a Task — that's precisely the behavior
    // under test (reject ttl <= 0 before any stream is opened), so the plain, synchronous
    // Assert.Throws is intentional.
#pragma warning disable xUnit2014

    [Fact]
    public void AcquireLockAsync_RejectsZeroTtl_BeforeOpeningStream()
    {
        // Block body (not an expression lambda) so this binds to the synchronous
        // Assert.Throws<T>(Action) overload rather than the obsolete Func<Task> one.
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            Restart.AcquireLockAsync(null!, "ns", "svc", TimeSpan.Zero);
        });
        Assert.Contains("ttl must be > 0", ex.Message);
    }

    [Fact]
    public void AcquireLockAsync_RejectsNegativeTtl_BeforeOpeningStream()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            Restart.AcquireLockAsync(null!, "ns", "svc", TimeSpan.FromSeconds(-1));
        });
        Assert.Contains("ttl must be > 0", ex.Message);
    }

#pragma warning restore xUnit2014

    [Fact]
    public async Task AcquireAsync_QueuePositionThenAcquired_ReturnsLockWithToken()
    {
        var stream = new FakeLockStream();
        stream.PushResponse(QueuePosition(2));
        stream.PushResponse(QueuePosition(1));
        stream.PushResponse(Acquired("tok-1", DateTimeOffset.UtcNow.AddSeconds(30)));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var @lock = await Lock.AcquireAsync(stream, "ns", "svc", 4, cts.Token);
        try
        {
            Assert.Equal("tok-1", @lock.Token);
            Assert.Equal(1, stream.SentCount); // exactly the initial send, before any heartbeat fires
        }
        finally
        {
            await @lock.ReleaseAsync();
        }
    }

    [Fact]
    public async Task AcquireAsync_StreamErrorBeforeAcquired_ThrowsLockAcquisitionException()
    {
        var stream = new FakeLockStream();
        stream.PushError(new InvalidOperationException("boom"));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var ex = await Assert.ThrowsAsync<LockAcquisitionException>(
            () => Lock.AcquireAsync(stream, "ns", "svc", 4, cts.Token));
        Assert.Contains("boom", ex.Message);
        Assert.NotNull(ex.InnerException);
    }

    [Fact]
    public async Task HeartbeatInterval_IsTtlOverFour()
    {
        var stream = new FakeLockStream();
        stream.PushResponse(Acquired("tok-1", DateTimeOffset.UtcNow.AddSeconds(4)));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        // ttl=4s => heartbeat interval = 1s. Wait ~2.5s and expect >= 2 heartbeats sent, in
        // addition to the 1 initial request.
        var @lock = await Lock.AcquireAsync(stream, "ns", "svc", 4, cts.Token);
        try
        {
            await Task.Delay(2500);
            Assert.True(
                stream.SentCount >= 3,
                $"SentCount = {stream.SentCount}, want >= 3 (1 initial + >= 2 heartbeats at ~1s interval)");
        }
        finally
        {
            await @lock.ReleaseAsync();
        }
    }

    [Fact]
    public async Task TtlExtended_UpdatesExpiresAt()
    {
        var stream = new FakeLockStream();
        var first = DateTimeOffset.UtcNow.AddSeconds(4);
        stream.PushResponse(Acquired("tok-1", first));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var @lock = await Lock.AcquireAsync(stream, "ns", "svc", 4, cts.Token);
        try
        {
            var extended = DateTimeOffset.UtcNow.AddSeconds(60);
            stream.PushResponse(TtlExtended(extended));

            var deadline = DateTime.UtcNow.AddSeconds(2);
            while (@lock.ExpiresAt != extended && DateTime.UtcNow < deadline)
            {
                await Task.Delay(10);
            }

            Assert.Equal(extended, @lock.ExpiresAt);
        }
        finally
        {
            await @lock.ReleaseAsync();
        }
    }

    [Fact]
    public async Task ReleaseAsync_IsIdempotent()
    {
        var stream = new FakeLockStream();
        stream.PushResponse(Acquired("tok-1", DateTimeOffset.UtcNow.AddSeconds(30)));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var @lock = await Lock.AcquireAsync(stream, "ns", "svc", 4, cts.Token);

        await @lock.ReleaseAsync();
        await @lock.ReleaseAsync(); // must be a silent no-op, not throw
    }

    [Fact]
    public async Task Lost_ReportedOnUnexpectedStreamErrorWhileHeld()
    {
        var stream = new FakeLockStream();
        stream.PushResponse(Acquired("tok-1", DateTimeOffset.UtcNow.AddSeconds(4)));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var @lock = await Lock.AcquireAsync(stream, "ns", "svc", 4, cts.Token);
        try
        {
            stream.PushError(new InvalidOperationException("lock lost"));

            var completed = await Task.WhenAny(@lock.Lost, Task.Delay(TimeSpan.FromSeconds(2)));
            Assert.Same(@lock.Lost, completed);
            var err = await @lock.Lost;
            Assert.NotNull(err);
        }
        finally
        {
            await @lock.ReleaseAsync();
        }
    }

    [Fact]
    public async Task HeartbeatSendFailure_ReportsLost()
    {
        // Distinct code path from a Recv() failure: the heartbeat loop's own Send() can fail
        // (e.g. the write side of the stream breaks) independently of the recv loop.
        var stream = new FakeLockStream();
        stream.PushResponse(Acquired("tok-1", DateTimeOffset.UtcNow.AddSeconds(4)));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var @lock = await Lock.AcquireAsync(stream, "ns", "svc", 4, cts.Token);
        try
        {
            stream.FailNextSend(new InvalidOperationException("send boom"));

            var completed = await Task.WhenAny(@lock.Lost, Task.Delay(TimeSpan.FromSeconds(3)));
            Assert.Same(@lock.Lost, completed);
            var err = await @lock.Lost;
            Assert.Contains("send boom", err.Message);
        }
        finally
        {
            await @lock.ReleaseAsync();
        }
    }

    [Fact]
    public async Task ReleaseAsync_DoesNotSignalLost()
    {
        var stream = new FakeLockStream();
        stream.PushResponse(Acquired("tok-1", DateTimeOffset.UtcNow.AddSeconds(30)));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var @lock = await Lock.AcquireAsync(stream, "ns", "svc", 4, cts.Token);

        await @lock.ReleaseAsync();

        var completed = await Task.WhenAny(@lock.Lost, Task.Delay(TimeSpan.FromMilliseconds(200)));
        Assert.NotSame(@lock.Lost, completed); // Lost never fired for a clean, intentional release
    }
}
