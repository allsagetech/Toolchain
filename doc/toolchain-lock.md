<!-- Toolchain | SPDX-License-Identifier: MPL-2.0 -->
# lock and restore

`tlc lock` resolves the packages from the nearest `Toolchain.ps1` to exact OCI
platform-manifest digests and writes `Toolchain.lock.json`. The editable project
file expresses intent; the lock file makes developer and CI restores repeatable.

```powershell
tlc lock
tlc lock -Update node
tlc restore
```

Use `-Packages` to lock an explicit package list and `-Path` to select another
lock-file location. `tlc restore` validates every package name and SHA-256 digest
before pulling. A lock created for one OS/architecture records that platform and
should not silently substitute another platform.
