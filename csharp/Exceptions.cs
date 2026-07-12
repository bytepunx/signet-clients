namespace Signet;

/// <summary>
/// Base type for exceptions raised by the Signet client library. Catch this to handle any
/// signet-specific failure without needing to enumerate every subtype.
/// </summary>
public class SignetException : Exception
{
    public SignetException(string message) : base(message)
    {
    }

    public SignetException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// Raised when <see cref="SignetConnect.DialWorkloadAsync"/> or <see cref="SignetConnect.DialAdmin"/>
/// fail to establish a connection (SPIFFE Workload API unreachable, invalid trust domain,
/// channel construction failure, etc).
/// </summary>
public class SignetConnectionException : SignetException
{
    public SignetConnectionException(string message) : base(message)
    {
    }

    public SignetConnectionException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// Raised when <see cref="Restart.AcquireLockAsync"/> fails before the lock is acquired —
/// either the stream could not be opened, or it errored/closed while still queued.
/// </summary>
public class LockAcquisitionException : SignetException
{
    public LockAcquisitionException(string message) : base(message)
    {
    }

    public LockAcquisitionException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// Thrown by the internal stream abstractions when a stream ends gracefully (the server
/// completed the response stream) rather than via an explicit RPC error. Treated identically
/// to an RPC error by the lock/watch state machines — either way, there is no more data.
/// </summary>
public class StreamClosedException : SignetException
{
    public StreamClosedException(string message) : base(message)
    {
    }
}
