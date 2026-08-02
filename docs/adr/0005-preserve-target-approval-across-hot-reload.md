# Preserve target approval across hot reload, not session replacement

Target Approval and Inspection Tool Suite activation survive Pi's `/reload` because reload refreshes extension code without changing the human's conversation or security intent. The extension records the latest approval/activation snapshot as a versioned, non-context custom session entry and restores it only when `session_start.reason` is `reload`. Identical snapshots are not appended repeatedly.

Startup, `/new`, `/resume`, and `/fork` deliberately ignore inherited snapshots and append a cleared state. This prevents approval from surviving a process restart or crossing into a replacement session while avoiding unnecessary reapproval during development hot reloads. The `--ssh-ro` startup flag is applied only for the initial `startup` event, so `/sshro logout` is not silently undone by a later reload and replacement sessions are still cleared. Remote command-path and sudo capability caches are always cleared because they describe server state rather than human intent.

Clearing approvals increments an approval generation. A confirmation started in an older generation cannot add approval after logout or shutdown, even if its UI promise resolves later.
