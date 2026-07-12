using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Grpc.Net.Client;

namespace Signet;

/// <summary>
/// An operator connection to signet's AdminService/GitOpsService, authenticated with a
/// bearer token. Mirrors the Go client's <c>DialAdmin</c> — plaintext for loopback
/// addresses (the documented <c>kubectl port-forward</c> workflow), TLS for everything
/// else, using the system trust store unless a CA bundle is supplied.
/// </summary>
public sealed class AdminConnection : IDisposable
{
    private readonly GrpcChannel _channel;
    private readonly CallInvoker _invoker;

    internal AdminConnection(GrpcChannel channel, string token)
    {
        _channel = channel;
        _invoker = channel.Intercept(new BearerTokenInterceptor(token));
    }

    /// <summary>The underlying gRPC channel, for constructing additional service clients if needed.</summary>
    public GrpcChannel Channel => _channel;

    /// <summary>An AdminService client bound to this connection, with the bearer token injected on every call.</summary>
    public Admin.V1.AdminService.AdminServiceClient AdminClient => new(_invoker);

    /// <summary>A GitOpsService client bound to this connection, with the bearer token injected on every call.</summary>
    public Admin.V1.GitOpsService.GitOpsServiceClient GitOpsClient => new(_invoker);

    public void Dispose() => _channel.Dispose();
}

/// <summary>
/// Injects <c>Authorization: Bearer &lt;token&gt;</c> into every outgoing call. Implemented as
/// an interceptor (rather than <see cref="CallCredentials"/>) so it works uniformly whether
/// the underlying channel is plaintext (loopback dev/port-forward) or TLS — Grpc.Net.Client's
/// <see cref="CallCredentials"/> refuses to attach to an insecure channel.
/// </summary>
internal sealed class BearerTokenInterceptor : Interceptor
{
    private readonly string _authorizationHeader;

    internal BearerTokenInterceptor(string token)
    {
        _authorizationHeader = "Bearer " + token;
    }

    public override TResponse BlockingUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        BlockingUnaryCallContinuation<TRequest, TResponse> continuation)
        => continuation(request, WithAuth(context));

    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
        => continuation(request, WithAuth(context));

    public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncServerStreamingCallContinuation<TRequest, TResponse> continuation)
        => continuation(request, WithAuth(context));

    public override AsyncClientStreamingCall<TRequest, TResponse> AsyncClientStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncClientStreamingCallContinuation<TRequest, TResponse> continuation)
        => continuation(WithAuth(context));

    public override AsyncDuplexStreamingCall<TRequest, TResponse> AsyncDuplexStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncDuplexStreamingCallContinuation<TRequest, TResponse> continuation)
        => continuation(WithAuth(context));

    private ClientInterceptorContext<TRequest, TResponse> WithAuth<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context)
        where TRequest : class
        where TResponse : class
    {
        var headers = context.Options.Headers ?? new Metadata();
        headers.Add("authorization", _authorizationHeader);
        var options = context.Options.WithHeaders(headers);
        return new ClientInterceptorContext<TRequest, TResponse>(context.Method, context.Host, options);
    }
}

/// <summary>
/// Pure helper logic behind <c>DialAdmin</c>, factored out so it's unit-testable without a
/// live network connection — mirrors the Go client's <c>adminTransportCreds</c> and its
/// dedicated test coverage in <c>client_test.go</c>.
/// </summary>
internal static class AdminTransport
{
    internal readonly record struct Options(bool UseTls, System.Net.Http.SocketsHttpHandler? Handler);

    internal static Options Resolve(string addr, byte[]? caPem, bool forceTls)
    {
        var host = ExtractHost(addr);
        var useTls = forceTls || (caPem is { Length: > 0 }) || !IsLoopbackHost(host);
        if (!useTls)
        {
            return new Options(false, null);
        }

        if (caPem is not { Length: > 0 })
        {
            return new Options(true, null);
        }

        var caCerts = ParseCaBundle(caPem);
        var handler = new System.Net.Http.SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, cert, _, _) =>
                {
                    if (cert is null)
                    {
                        return false;
                    }

                    using var verifyChain = new X509Chain();
                    verifyChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    verifyChain.ChainPolicy.CustomTrustStore.Clear();
                    verifyChain.ChainPolicy.CustomTrustStore.AddRange(caCerts);
                    verifyChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    using var leaf = new X509Certificate2(cert);
                    return verifyChain.Build(leaf);
                },
            },
        };
        return new Options(true, handler);
    }

    /// <summary>
    /// Parses a PEM-encoded CA bundle, throwing a clear, specific <see cref="ArgumentException"/>
    /// (not a raw <see cref="System.Security.Cryptography.CryptographicException"/>) if it
    /// contains no usable certificates.
    /// </summary>
    internal static X509Certificate2Collection ParseCaBundle(byte[] pem)
    {
        var collection = new X509Certificate2Collection();
        try
        {
            collection.ImportFromPem(Encoding.ASCII.GetString(pem));
        }
        catch (Exception ex)
        {
            throw new ArgumentException(
                $"no PEM certificates found in provided CA bundle: {ex.Message}", nameof(pem), ex);
        }

        if (collection.Count == 0)
        {
            throw new ArgumentException("no PEM certificates found in provided CA bundle", nameof(pem));
        }

        return collection;
    }

    /// <summary>Mirrors Go's <c>net.SplitHostPort</c>-based host extraction, including bracketed IPv6 literals.</summary>
    internal static string ExtractHost(string addr)
    {
        if (string.IsNullOrEmpty(addr))
        {
            return addr;
        }

        if (addr[0] == '[')
        {
            var close = addr.IndexOf(']');
            if (close > 0)
            {
                return addr[1..close];
            }

            return addr;
        }

        var idx = addr.LastIndexOf(':');
        return idx >= 0 ? addr[..idx] : addr;
    }

    /// <summary>Mirrors Go's <c>isLoopbackHost</c> exactly, including its case-sensitive "localhost" check.</summary>
    internal static bool IsLoopbackHost(string host)
    {
        if (host == "localhost")
        {
            return true;
        }

        return IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip);
    }
}

public static partial class SignetConnect
{
    /// <summary>
    /// Opens a gRPC connection to signet's admin listener, injecting <paramref name="token"/>
    /// into every RPC as a bearer credential. Loopback addresses (the documented
    /// <c>kubectl port-forward</c> workflow) use plaintext by default; every other address is
    /// upgraded to TLS automatically using the system trust store, or the CA in
    /// <paramref name="caPem"/> if provided. <paramref name="forceTls"/> requests TLS even for
    /// a loopback address.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// <paramref name="token"/> is empty/whitespace, or <paramref name="caPem"/> contains no
    /// parseable PEM certificates.
    /// </exception>
    /// <exception cref="SignetConnectionException">The gRPC channel could not be constructed.</exception>
    public static AdminConnection DialAdmin(string addr, string token, byte[]? caPem = null, bool forceTls = false)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("token must not be empty", nameof(token));
        }

        var resolved = AdminTransport.Resolve(addr, caPem, forceTls);
        var scheme = resolved.UseTls ? "https" : "http";

        var options = new GrpcChannelOptions();
        if (resolved.Handler is not null)
        {
            options.HttpHandler = resolved.Handler;
        }

        GrpcChannel channel;
        try
        {
            channel = GrpcChannel.ForAddress($"{scheme}://{addr}", options);
        }
        catch (Exception ex)
        {
            throw new SignetConnectionException($"dial {addr}: {ex.Message}", ex);
        }

        return new AdminConnection(channel, token.Trim());
    }
}
