# Spike: NFS subPath Scoped Mount for x509 Proxy Minting

**Phase 0 Spike #2** — must pass before the credential provider for x509/VOMS is implemented.

## What this validates

The ephemeral proxy-mint Job needs read-only access to:
- `/home/<username>/.globus/usercert.pem`
- `/home/<username>/.globus/userkey.pem`

Those files live on the AF NFS home filesystem. The Job must mount **only**
the user's own subdirectory — not the entire NFS export and not any other
user's home.

This spike answers two questions:

1. Can a Job running as UID/GID `<uid>/<gid>` read `usercert.pem` via a
   subPath-scoped NFS volume mount?
2. Does the same Job fail to read a **different** user's certificate?

## Prerequisites

- `kubectl` access to the target cluster with a namespace you can create Jobs in.
- The NFS server must be reachable from cluster nodes.
- Values to substitute before applying:
  - `<UID>` / `<GID>` — the numeric uid/gid of the user under test
  - `<USERNAME>` — the username string (used as the NFS subPath)
  - `<NFS_SERVER>` — IP or hostname of the NFS server
  - `<NFS_PATH>` — the exported path (e.g., `/export/home`)
  - `<OTHER_USERNAME>` — a different user's username for the isolation test

## How to run

```bash
# Edit the manifests to fill in real values, then:
kubectl apply -f spikes/nfs-subpath/mint-job-test.yaml
kubectl wait --for=condition=complete job/nfs-subpath-positive --timeout=60s
kubectl logs job/nfs-subpath-positive

kubectl apply -f spikes/nfs-subpath/mint-job-test.yaml  # second Job inside the file
kubectl wait --for=condition=complete job/nfs-subpath-isolation --timeout=60s
kubectl logs job/nfs-subpath-isolation
```

## Pass / fail criteria

| Job | Expected output | Pass | Fail |
|---|---|---|---|
| `nfs-subpath-positive` | `PASS` printed, exit 0 | cert files visible under subPath mount | Job exits non-zero or `FAIL` printed |
| `nfs-subpath-isolation` | `ls` returns empty or permission error, exit non-zero or `ISOLATION_PASS` | other user's files not visible | Other user's `usercert.pem` is readable |

## Why this matters

If the positive test fails, the proxy-mint Job design cannot work at all —
revisit the NFS export options or the subPath approach.

If the isolation test fails, we have a security gap: any UID could read any
user's private key. **Do not proceed to Phase 1 credential implementation
until both tests pass.**
