<!-- Toolchain | SPDX-License-Identifier: MPL-2.0 -->
# sync

`tlc sync` converges a project in one operation:

1. parse and validate `toolchain.yaml`;
2. resolve compatible dependency versions when the lock is missing or stale;
3. write `Toolchain.lock.json` atomically;
4. restore its exact OS/architecture digests;
5. enforce registry, package, and signature policy during the pull.

```powershell
tlc sync
tlc sync -Frozen
tlc sync -Update
tlc sync -Update -Activate
```

An unchanged manifest reuses its coherent lock without querying the package
catalog. `-Update` deliberately resolves the newest allowed versions. `-Frozen`
fails when the lock is missing, malformed, for another platform, or no longer
matches the manifest. `-NoRestore` updates only the lock. `-Path` selects another
lock path, and `-PassThru` returns structured status.
