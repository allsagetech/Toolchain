<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# help

Shows the command overview or detailed help for a specific command. Detailed
help includes the command's purpose, usage forms, options, examples, and notes.

## Usage

    tlc help
    tlc COMMAND help
    tlc COMMAND SUBCOMMAND help
    tlc help COMMAND [SUBCOMMAND]

The suffix tokens `help`, `h`, `-h`, `--help`, `?`, and `/?` are accepted.

## Examples

```powershell
# Complete command overview
tlc help

# Top-level command help
tlc update help
tlc prune --help

# Command-group and nested-command help
tlc remote help
tlc remote models help
tlc cluster create help

# Prefix-style equivalent
tlc help cluster create
```

Help requests are handled before the command runs. For example, `tlc update
help` displays help without updating packages, and `tlc cluster create dev
help` displays `cluster create` help without creating a cluster.
