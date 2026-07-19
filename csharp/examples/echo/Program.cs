// TEST-ONLY BUILD — DO NOT RUN IN PRODUCTION. This program prints retrieved secrets to
// stdout, unredacted, so a smoke-test verification script can grep container logs for them.
// It exists solely for the signet-smoke-test Docker/Kubernetes harness
// (bytepunx/signet-smoke-test), which deploys one of these per client language into a real
// cluster running signet + SPIRE to prove the client actually works end-to-end.
//
// Sequence (mirrors ../../README.md's "Coordinated restarts" section):
//  1. Log the banner below, unconditionally, first.
//  2. Dial signet's workload listener over SPIFFE mTLS.
//  3. Fetch this namespace/service's bundle and print it (secrets base64-decoded) as a single
//     ECHO_BUNDLE: line.
//  4. Block on WaitForRestartAsync — this is expected to hang indefinitely in steady state.
//  5. Once it returns, log an ECHO_RESTART: line describing the acquired lock, release it,
//     and exit 0. Kubernetes restarts the pod; the new instance repeats from step 1 against
//     whatever changed — that's the behavior this whole harness exists to prove.
//
// Everything is configured via environment variables (no CLI flags) since this runs as a
// container in Kubernetes; see RequireEnv/OptionalPositiveIntEnv below for the full list.

using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using Google.Protobuf.WellKnownTypes;
using Signet;
using Signet.V1;

Console.WriteLine(
    "TEST-ONLY BUILD — DO NOT RUN IN PRODUCTION. This program prints retrieved secrets to stdout.");

using var cts = new CancellationTokenSource();

void RequestShutdown(string reason)
{
    Console.WriteLine($"shutting down: {reason}");
    try
    {
        cts.Cancel();
    }
    catch (ObjectDisposedException)
    {
        // Already past the point where cancellation matters.
    }
}

void HandlePosixShutdownSignal(PosixSignalContext context)
{
    // Prevent the runtime's default "terminate immediately" behavior — we want the blocking
    // await in RunAsync to observe cancellation and exit 0 on its own instead.
    context.Cancel = true;
    RequestShutdown($"received {context.Signal}");
}

using var sigTermRegistration = PosixSignalRegistration.Create(PosixSignal.SIGTERM, HandlePosixShutdownSignal);
using var sigIntRegistration = PosixSignalRegistration.Create(PosixSignal.SIGINT, HandlePosixShutdownSignal);

// Silent backstop for any other exit path (e.g. the console host tearing down) that doesn't
// go through the POSIX signal handlers above — just unblocks a hanging await, without adding
// a log line to every ordinary Environment.Exit call already logging its own reason.
AppDomain.CurrentDomain.ProcessExit += (_, _) =>
{
    try
    {
        cts.Cancel();
    }
    catch (ObjectDisposedException)
    {
    }
};

try
{
    await RunAsync(cts.Token).ConfigureAwait(false);
}
catch (OperationCanceledException)
{
    Console.WriteLine("shutting down: cancellation requested");
    Environment.Exit(0);
}

return;

async Task RunAsync(CancellationToken cancellationToken)
{
    var addr = RequireEnv("SIGNET_ADDR");
    var trustDomain = RequireEnv("SIGNET_TRUST_DOMAIN");
    var socket = RequireEnv("SPIFFE_WORKLOAD_SOCKET");
    var ns = RequireEnv("SIGNET_NAMESPACE");
    var service = RequireEnv("SIGNET_SERVICE");
    var sharedNamespace = Environment.GetEnvironmentVariable("SIGNET_SHARED_NAMESPACE");
    var sharedService = Environment.GetEnvironmentVariable("SIGNET_SHARED_SERVICE");
    var lockTtl = TimeSpan.FromSeconds(OptionalPositiveIntEnv("RESTART_LOCK_TTL_SECONDS", 30));
    var debounce = TimeSpan.FromSeconds(OptionalPositiveIntEnv("RESTART_DEBOUNCE_SECONDS", 5));

    await using var conn = await SignetConnect.DialWorkloadAsync(addr, socket, trustDomain, cancellationToken)
        .ConfigureAwait(false);

    var client = conn.SecretsClient;

    var bundle = await client.GetServiceBundleAsync(
        new GetServiceBundleRequest { Namespace = ns, Service = service },
        cancellationToken: cancellationToken).ConfigureAwait(false);

    Console.WriteLine("ECHO_BUNDLE: " + FormatBundle(bundle));

    // Optional second fetch proving cross-namespace access via an admin-granted policy
    // actually works, not just the namespace/service convention — most workloads never need
    // this (see signet's docs/policies.md), but the smoke-test harness sets these two env
    // vars specifically to exercise that path end to end.
    if (!string.IsNullOrEmpty(sharedNamespace) && !string.IsNullOrEmpty(sharedService))
    {
        var sharedBundle = await client.GetServiceBundleAsync(
            new GetServiceBundleRequest { Namespace = sharedNamespace, Service = sharedService },
            cancellationToken: cancellationToken).ConfigureAwait(false);

        Console.WriteLine("ECHO_SHARED_BUNDLE: " + FormatBundle(sharedBundle));
    }

    // Blocks, potentially indefinitely — that's expected steady-state while nothing has
    // changed in this namespace/service's bundle.
    var restartLock = await Restart.WaitForRestartAsync(client, ns, service, lockTtl, debounce, cancellationToken)
        .ConfigureAwait(false);

    Console.WriteLine($"ECHO_RESTART: token={restartLock.Token} expires_at={restartLock.ExpiresAt:O}");

    await restartLock.ReleaseAsync().ConfigureAwait(false);

    Environment.Exit(0);
}

// Fails fast with a specific, unambiguous message naming the missing variable — this
// container's only observable output is its logs, so error clarity matters a lot here.
string RequireEnv(string name)
{
    var value = Environment.GetEnvironmentVariable(name);
    if (!string.IsNullOrEmpty(value))
    {
        return value;
    }

    Console.Error.WriteLine($"FATAL: required environment variable {name} is not set");
    Environment.Exit(1);
    throw new InvalidOperationException("unreachable: Environment.Exit terminates the process");
}

int OptionalPositiveIntEnv(string name, int defaultValue)
{
    var raw = Environment.GetEnvironmentVariable(name);
    if (string.IsNullOrEmpty(raw))
    {
        return defaultValue;
    }

    return int.TryParse(raw, out var parsed) && parsed > 0 ? parsed : defaultValue;
}

// Renders a GetServiceBundleResponse as a single line of JSON: config fields at the top
// level (as signet itself returns them) plus config_version, with the reserved "secrets"
// field's values base64-decoded rather than left as the base64 strings signet returns them
// as. Google.Protobuf's JsonFormatter can't do the decoding step, so this walks the Struct
// by hand.
string FormatBundle(GetServiceBundleResponse response)
{
    var root = new JsonObject { ["config_version"] = response.ConfigVersion };
    var secrets = new JsonObject();

    if (response.Bundle is not null)
    {
        foreach (var (key, value) in response.Bundle.Fields)
        {
            if (key == "secrets" && value.KindCase == Value.KindOneofCase.StructValue)
            {
                foreach (var (secretName, secretValue) in value.StructValue.Fields)
                {
                    secrets[secretName] = DecodeSecretValue(secretValue);
                }

                continue;
            }

            root[key] = ToJsonNode(value);
        }
    }

    root["secrets"] = secrets;
    return root.ToJsonString();
}

// Secrets are returned as base64-encoded plaintext strings; decode to the plaintext (UTF-8)
// value so the printed line carries the real secret, not its base64 encoding. Falls back to
// the raw value if it somehow isn't valid base64 rather than dropping it silently.
JsonNode? DecodeSecretValue(Value value)
{
    if (value.KindCase != Value.KindOneofCase.StringValue)
    {
        return ToJsonNode(value);
    }

    try
    {
        return JsonValue.Create(Encoding.UTF8.GetString(Convert.FromBase64String(value.StringValue)));
    }
    catch (FormatException)
    {
        return JsonValue.Create(value.StringValue);
    }
}

// Recursively converts a protobuf Struct/Value tree (as used by google.protobuf.Struct) into
// System.Text.Json's JsonNode tree.
JsonNode? ToJsonNode(Value value) => value.KindCase switch
{
    Value.KindOneofCase.NullValue => null,
    Value.KindOneofCase.NumberValue => JsonValue.Create(value.NumberValue),
    Value.KindOneofCase.StringValue => JsonValue.Create(value.StringValue),
    Value.KindOneofCase.BoolValue => JsonValue.Create(value.BoolValue),
    Value.KindOneofCase.StructValue => ToJsonObject(value.StructValue),
    Value.KindOneofCase.ListValue => ToJsonArray(value.ListValue),
    _ => null,
};

JsonObject ToJsonObject(Struct s)
{
    var obj = new JsonObject();
    foreach (var (key, value) in s.Fields)
    {
        obj[key] = ToJsonNode(value);
    }

    return obj;
}

JsonArray ToJsonArray(ListValue list)
{
    var arr = new JsonArray();
    foreach (var value in list.Values)
    {
        arr.Add(ToJsonNode(value));
    }

    return arr;
}
