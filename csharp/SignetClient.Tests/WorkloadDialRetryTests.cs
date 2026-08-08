using Grpc.Core;
using Signet;
using Xunit;

namespace SignetClient.Tests;

/// <summary>
/// Ports the retry-schedule/attempt-count/classification coverage for
/// <c>retryUntilIdentityIssued</c>/<c>isNoIdentityIssuedErr</c> from go/client_test.go to
/// <see cref="WorkloadDialRetry"/> — see bytepunx/signet-clients#33.
/// </summary>
public class WorkloadDialRetryTests
{
    [Fact]
    public void IsNoIdentityIssuedError_PermissionDenied_ReturnsTrue()
    {
        var ex = new RpcException(new Status(StatusCode.PermissionDenied, "no identity issued"));
        Assert.True(WorkloadDialRetry.IsNoIdentityIssuedError(ex));
    }

    [Theory]
    [InlineData(StatusCode.Unavailable)]
    [InlineData(StatusCode.DeadlineExceeded)]
    [InlineData(StatusCode.Unauthenticated)]
    [InlineData(StatusCode.InvalidArgument)]
    public void IsNoIdentityIssuedError_OtherStatusCodes_ReturnsFalse(StatusCode code)
    {
        var ex = new RpcException(new Status(code, "boom"));
        Assert.False(WorkloadDialRetry.IsNoIdentityIssuedError(ex));
    }

    [Fact]
    public void IsNoIdentityIssuedError_NonRpcException_ReturnsFalse()
    {
        Assert.False(WorkloadDialRetry.IsNoIdentityIssuedError(new InvalidOperationException("boom")));
    }

    [Fact]
    public void Backoff_MatchesVerifiedSchedule()
    {
        Assert.Equal(
            new[]
            {
                TimeSpan.FromSeconds(1),
                TimeSpan.FromSeconds(2),
                TimeSpan.FromSeconds(4),
                TimeSpan.FromSeconds(8),
            },
            WorkloadDialRetry.Backoff);
        Assert.Equal(5, WorkloadDialRetry.MaxAttempts);
    }

    [Fact]
    public async Task RunAsync_SucceedsFirstTry_NoDelaysNoRetries()
    {
        var attempts = 0;
        var delays = new List<TimeSpan>();

        await WorkloadDialRetry.RunAsync(
            probe: _ => { attempts++; return Task.CompletedTask; },
            delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; },
            CancellationToken.None);

        Assert.Equal(1, attempts);
        Assert.Empty(delays);
    }

    [Fact]
    public async Task RunAsync_SucceedsOnThirdAttempt_RetriesAndBacksOffCorrectly()
    {
        var attempts = 0;
        var delays = new List<TimeSpan>();
        var permissionDenied = new RpcException(new Status(StatusCode.PermissionDenied, "no identity issued"));

        await WorkloadDialRetry.RunAsync(
            probe: _ =>
            {
                attempts++;
                if (attempts < 3)
                {
                    throw permissionDenied;
                }

                return Task.CompletedTask;
            },
            delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; },
            CancellationToken.None);

        Assert.Equal(3, attempts);
        Assert.Equal(new[] { TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2) }, delays);
    }

    [Fact]
    public async Task RunAsync_AllAttemptsFail_ThrowsAfterExactlyFiveAttemptsAndFourDelays()
    {
        var attempts = 0;
        var delays = new List<TimeSpan>();
        var permissionDenied = new RpcException(new Status(StatusCode.PermissionDenied, "no identity issued"));

        var ex = await Assert.ThrowsAsync<SignetConnectionException>(() =>
            WorkloadDialRetry.RunAsync(
                probe: _ => { attempts++; throw permissionDenied; },
                delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; },
                CancellationToken.None));

        Assert.Equal(5, attempts);
        Assert.Equal(
            new[]
            {
                TimeSpan.FromSeconds(1),
                TimeSpan.FromSeconds(2),
                TimeSpan.FromSeconds(4),
                TimeSpan.FromSeconds(8),
            },
            delays);
        Assert.Contains("no identity issued after 5 attempts", ex.Message);
        Assert.Same(permissionDenied, ex.InnerException);
    }

    [Fact]
    public async Task RunAsync_NonRetryableError_PropagatesImmediatelyWithoutRetryOrDelay()
    {
        var attempts = 0;
        var delays = new List<TimeSpan>();
        var unavailable = new RpcException(new Status(StatusCode.Unavailable, "socket not found"));

        var thrown = await Assert.ThrowsAsync<RpcException>(() =>
            WorkloadDialRetry.RunAsync(
                probe: _ => { attempts++; throw unavailable; },
                delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; },
                CancellationToken.None));

        Assert.Same(unavailable, thrown);
        Assert.Equal(1, attempts);
        Assert.Empty(delays);
    }

    [Fact]
    public async Task RunAsync_NonRpcException_PropagatesImmediatelyWithoutRetry()
    {
        var attempts = 0;
        var boom = new InvalidOperationException("boom");

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            WorkloadDialRetry.RunAsync(
                probe: _ => { attempts++; throw boom; },
                delay: (_, _) => Task.CompletedTask,
                CancellationToken.None));

        Assert.Same(boom, thrown);
        Assert.Equal(1, attempts);
    }

    [Fact]
    public async Task RunAsync_RetryableFailureAfterSomeSuccesses_StopsRetryingAfterFirstNonRetryable()
    {
        // A non-retryable failure encountered mid-loop (e.g. on the 2nd attempt) must still stop
        // immediately, not be swallowed into the "no identity issued" exhaustion path.
        var attempts = 0;
        var permissionDenied = new RpcException(new Status(StatusCode.PermissionDenied, "no identity issued"));
        var invalidArgument = new RpcException(new Status(StatusCode.InvalidArgument, "bad trust domain"));

        var thrown = await Assert.ThrowsAsync<RpcException>(() =>
            WorkloadDialRetry.RunAsync(
                probe: _ =>
                {
                    attempts++;
                    throw attempts == 1 ? permissionDenied : invalidArgument;
                },
                delay: (_, _) => Task.CompletedTask,
                CancellationToken.None));

        Assert.Same(invalidArgument, thrown);
        Assert.Equal(2, attempts);
    }
}
