# SSH Read-only Docker Tools Spec

## Goal

Add a small set of Docker inspection tools to SSH Read-only Mode while preserving the extension's core safety model: fixed read-only remote command templates, shell-quoted user inputs, bounded output, and no arbitrary remote command execution.

## Tools

Add these tools to the SSH Read-only Tool Gate and active tool list:

- `sshro_docker_ps`
- `sshro_docker_inspect`
- `sshro_docker_stats`

Do not add a generic `sshro_docker` action multiplexer in v1. Separate tools keep schemas small, prompts clear, and policy differences explicit.

## Startup behavior

Docker is not a startup requirement.

- Do not add `docker` to `REQUIRED_REMOTE_COMMANDS`.
- Each Docker tool checks `command -v docker` at execution time.
- If Docker is missing, unavailable, or permission-denied, return a normal tool error result.
- SSH Read-only Mode must not fail startup merely because Docker is unavailable.

## Shared implementation rules

All Docker tools must:

- use the existing `sshExec` / `sshChecked` SSH execution path
- run through fixed remote command templates
- shell-quote all user-controlled strings with `shellQuote`
- reject control characters/newlines via `validatePathLike` or equivalent
- apply output line/byte truncation with existing `truncateText`
- use finite commands only; no streaming commands
- return text content, preferably pretty JSON where JSON parsing succeeds
- include visible stderr when useful for diagnosis
- mark `isError: true` for missing Docker, permission failures, and command failures with no useful output

Docker object identifiers/names are not filesystem paths, so do not apply `remotePath` or filesystem credential path policy to them. Still reject control characters and `~` using existing path-like validation unless a new name validator is introduced.

Recommended helper:

```ts
function validateDockerRef(value: string, label: string): void {
  validatePathLike(value, label);
}
```

## JSON preference

Prefer JSON for Docker tools where Docker supports it natively.

- Use native `--format json` where available.
- Parse NDJSON/JSON locally in the extension when possible.
- Return pretty-printed JSON arrays/objects to the agent.
- Reject row limits below 1 with a clear `limit must be >= 1` error.
- Append an explicit `[ssh-ro output truncated ...]` note when Docker row output is limited.
- Avoid requiring remote `jq`.
- Do not add table/text fallback for `sshro_docker_ps`; if expected JSON output is unavailable, return a clear error message.

## `sshro_docker_ps`

### Purpose

List Docker containers, including exited/restarting containers, with stable structured fields for triage.

### Parameters

```ts
Type.Object({
  all: Type.Optional(Type.Boolean({ description: "Include stopped containers, default true" })),
  name: Type.Optional(Type.String({ description: "Optional Docker name filter substring/pattern" })),
  limit: Type.Optional(Type.Number({ description: "Maximum containers/output lines, default 100, max 2000" })),
})
```

### Default behavior

Equivalent intent:

```sh
docker ps --all --no-trunc --format json
```

The oldest supported target is known to support `docker ps --format json`, so this is the primary implementation rather than a best-effort fallback.

If `all === false`, omit `--all`.

If `name` is provided, prefer Docker's filter:

```sh
--filter name=<quoted-name>
```

### Output

Output: JSON array parsed from Docker's NDJSON rows, normalized to lower-case/camel-ish keys. Preserve Docker command strings, include Docker's mount summary, and redact label values whose keys look sensitive (`token`, `secret`, `password`, `key`, `credential`, etc.).

If `--format json` unexpectedly fails or output cannot be parsed as NDJSON, return a clear tool error explaining that Docker JSON output was unavailable/unparseable. Do not fall back to table output for `sshro_docker_ps`.

If `limit` is smaller than the number of returned rows, append a note such as:

```text
[ssh-ro output truncated to 10 containers]
```

### Timeout

20 seconds.

## `sshro_docker_inspect`

### Purpose

Inspect a container/image/network/volume by name or ID while avoiding secret-heavy raw inspect output.

### Parameters

```ts
Type.Object({
  target: Type.String({ description: "Docker object name or ID to inspect" }),
  kind: Type.Optional(Type.Union([
    Type.Literal("container"),
    Type.Literal("image"),
    Type.Literal("network"),
    Type.Literal("volume"),
  ])),
})
```

### Default behavior

Run a fixed command:

```sh
docker inspect [--type <kind>] <target>
```

Parse the returned JSON locally.

### Output policy

Always return curated JSON.

For container-like objects, include:

```json
{
  "id": "...",
  "name": "...",
  "image": "...",
  "created": "...",
  "state": {
    "status": "...",
    "running": true,
    "paused": false,
    "restarting": false,
    "oomKilled": false,
    "dead": false,
    "pid": 123,
    "exitCode": 0,
    "error": "...",
    "startedAt": "...",
    "finishedAt": "..."
  },
  "restartCount": 0,
  "restartPolicy": {},
  "config": {
    "hostname": "...",
    "user": "...",
    "workingDir": "...",
    "entrypoint": [],
    "cmd": [],
    "image": "...",
    "labels": {},
    "env": "[redacted]"
  },
  "hostConfig": {
    "networkMode": "...",
    "privileged": false,
    "readonlyRootfs": false,
    "restartPolicy": {},
    "binds": []
  },
  "mounts": [],
  "ports": {},
  "networks": {}
}
```

Always redact `Config.Env` from curated output. Show an explicit marker such as `"env": "[redacted]"` when environment variables are present, or `"env": []` / `"env": null` when Docker reports none. There is intentionally no `includeEnv` parameter in v1; if env values are needed, the agent should ask the human operator to inspect them manually.

Redact Docker label values whose keys look sensitive (`token`, `secret`, `password`, `key`, `credential`, etc.). Omit image `GraphDriver.Data` because it exposes Docker storage internals such as `/var/lib/docker/overlay2/...` paths.

Container inspect output is normalized to lower-case/camel-ish keys. Image, network, and volume inspect output may preserve Docker's native shape after redaction/omission. This should be documented clearly so the agent understands which outputs are normalized versus Docker-shaped.

### Secret considerations

`docker inspect` can expose secrets in environment variables, labels, command arguments, mount paths, topology, and image metadata. Curated output always redacts environment variable values and visibly marks that redaction, redacts sensitive-looking label values, and omits image storage internals, but this reduces rather than eliminates secret-exposure risk. Volume inspect may expose mountpoints. Network inspect may expose internal IP/MAC/container mappings.

### Timeout

20 seconds.

## `sshro_docker_stats`

### Purpose

Show a one-shot resource snapshot for containers.

### Parameters

```ts
Type.Object({
  container: Type.Optional(Type.String({ description: "Optional container name or ID" })),
  limit: Type.Optional(Type.Number({ description: "Maximum rows/output lines, default 100, max 2000" })),
})
```

### Default behavior

Use non-streaming stats only:

```sh
docker stats --no-stream --format '{{json .}}' [container]
```

Never run streaming `docker stats`.

### Output

Output: JSON array parsed from Docker's NDJSON rows.

If `limit` is smaller than the number of returned rows, append a note such as:

```text
[ssh-ro output truncated to 10 stat rows]
```

If stats JSON output is unavailable or unparseable, return a clear tool error.

### Timeout

20 seconds.

## Prompt/system note updates

Update the SSH Read-only Mode note to mention Docker tools as fixed read-only Docker inspections when present.

Suggested wording:

> Docker tools, when available on the remote host and permitted for the SSH user, provide fixed read-only inspections of containers, inspect metadata, and one-shot stats. Docker inspect output is curated because full inspect data may expose environment variables or other sensitive metadata.

## README updates

Add the tools to the README tool list and document:

- Docker is optional and checked at tool runtime.
- Docker permission errors are returned as tool errors.
- `sshro_docker_ps` normalizes Docker rows, preserves command strings, includes Docker's mount summary, redacts sensitive labels, and appends truncation notes when row-limited.
- `sshro_docker_inspect` returns curated JSON by default and visibly redacts environment variables.
- `sshro_docker_stats` uses `--no-stream` only.

## CONTEXT.md updates

Add domain statements:

- Docker tools are optional runtime diagnostics and are not part of startup health checks.
- Docker tools use native Docker JSON where available and parse/pretty-print locally.
- `sshro_docker_inspect` curates output by default and visibly redacts environment variable values; v1 has no parameter to reveal env values in curated output.
- Docker label values with sensitive-looking keys are redacted, image `GraphDriver.Data` is omitted, and volume/network inspect output may reveal mountpoints/topology.
- Docker stats are one-shot only.

## Acceptance criteria

- `TOOL_NAMES` includes the three Docker tools.
- `--ssh-ro` active sessions expose the three Docker tools and still block all other tools.
- Startup succeeds on hosts without Docker if the original required commands are present.
- Each Docker tool returns a clear error if Docker is absent or permission-denied.
- `sshro_docker_ps` returns normalized JSON array output when Docker JSON templates work, rejects `limit < 1`, and appends row-truncation notes.
- `sshro_docker_inspect` returns curated pretty JSON and visibly marks `Config.Env` values as redacted; there is no option to reveal env values.
- Invalid `sshro_docker_inspect.kind` values return `kind must be one of: container, image, network, volume`.
- `sshro_docker_stats` uses `--no-stream`, returns JSON array output when Docker JSON templates work, rejects `limit < 1`, and appends row-truncation notes.
- No Docker tool accepts arbitrary Docker subcommands or shell fragments.
- `node --check index.ts` passes.
- `git diff --check` passes.
