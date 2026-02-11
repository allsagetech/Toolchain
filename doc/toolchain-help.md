<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# help

Outputs usage for this command.

## Usage

    toolchain help

## Example

```
PS C:\example> toolchain help

Usage: toolchain COMMAND

Commands:
  version        Outputs the version of the module
  list           Outputs a list of installed packages
  remote list    Outputs an object of remote packages and versions
  pull           Downloads packages
  load           Loads packages into the PowerShell session
  exec           Runs a user-defined scriptblock in a managed PowerShell session
  run            Runs a user-defined scriptblock provided in a project file
  update         Updates all tagged packages
  prune          Deletes unreferenced packages
  remove         Untags and deletes packages
  save           Downloads packages for use in an offline installation
  init           Writes a starter Toolchain.ps1 in the current directory
  doctor         Prints diagnostics for your Toolchain setup
  help           Outputs usage for this command

For detailed documentation and examples, visit https://github.com/allsagetech/toolchain.

```
