using Google.Protobuf.WellKnownTypes;

namespace SignetClient.Tests;

/// <summary>Small builders for the streamed response messages used across the lock/watch tests.</summary>
internal static class ResponseBuilders
{
    internal static Signet.V1.AcquireRestartLockResponse Acquired(string token, DateTimeOffset expiresAt) =>
        new()
        {
            MessageType = Signet.V1.AcquireRestartLockResponse.Types.MessageType.Acquired,
            Token = token,
            ExpiresAt = Timestamp.FromDateTimeOffset(expiresAt),
        };

    internal static Signet.V1.AcquireRestartLockResponse QueuePosition(int position) =>
        new()
        {
            MessageType = Signet.V1.AcquireRestartLockResponse.Types.MessageType.QueuePosition,
            Position = position,
        };

    internal static Signet.V1.AcquireRestartLockResponse TtlExtended(DateTimeOffset expiresAt) =>
        new()
        {
            MessageType = Signet.V1.AcquireRestartLockResponse.Types.MessageType.TtlExtended,
            ExpiresAt = Timestamp.FromDateTimeOffset(expiresAt),
        };
}
