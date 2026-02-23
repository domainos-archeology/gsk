# gsk -- Ghidra Swiss-army Knife

A command-line interface for [Ghidra](https://ghidra-sre.org/) that exposes its reverse engineering capabilities over HTTP. Pair it with an AI coding assistant or use it from your terminal -- either way it turns Ghidra into a scriptable, composable tool.

The project ships two pieces:

1. **Ghidra plugin** (Java) -- an HTTP server that runs inside Ghidra and exposes its analysis engine.
2. **`gsk` CLI** (Go) -- a fast, ergonomic client for that server.

## Quick start

```bash
# Clone and build everything (downloads Ghidra automatically)
git clone https://github.com/domainos-archeology/ghidra-skill.git
cd ghidra-skill
make build          # downloads Ghidra, verifies checksum, builds plugin
go install ./cmd/gsk/

# Install the plugin into Ghidra:
#   File -> Install Extensions -> + -> pick the zip from ghidra-plugin/dist/
#   Restart Ghidra. The HTTP server starts automatically on port 8080.

# Open a binary in Ghidra, then:
gsk info                         # program metadata at a glance
gsk memorymap                    # memory layout
gsk function list                # all functions
gsk analyze 0x401000             # decompile + disassemble + xrefs
gsk rename 0x401000 main         # rename a function
```

## Building

**Prerequisites:** Go 1.25+, Java 21+. Ghidra itself is downloaded automatically.

| Command | What it does |
|---------|-------------|
| `make build` | Download Ghidra + build the plugin (first time) |
| `make plugin` | Rebuild just the plugin |
| `go build ./cmd/gsk/` | Build just the CLI |
| `make test` | Run Go and Java tests |
| `make clean` | Remove build artifacts |

## Configuration

`gsk` looks for a `.gsk.yaml` in the current directory:

```yaml
server: localhost:8080
```

You can also pass `--server <host:port>` on any command, or set the `GHIDRA_SERVER` environment variable.

## Command reference

### Orientation

```bash
gsk info                              # program name, format, language, image base, MD5, ...
gsk context                           # current cursor address + function in Ghidra
gsk memorymap                         # memory blocks with permissions (rwx) and types
```

### Functions

```bash
gsk function list                     # list all functions
gsk function get <address>            # info for one function
gsk function current                  # whichever function is selected in Ghidra
gsk search <query>                    # search functions by name
gsk analyze <address>                 # decompile + disassemble + xrefs in one shot
gsk decompile <address>               # C pseudocode
gsk disassemble <address>             # assembly listing
```

### Annotations

```bash
gsk rename <address> <new_name>
gsk prototype <address> "int foo(char *buf, int len)"
gsk vartype <func_addr> <var> <type>
gsk comment decompiler <address> "note about this block"
gsk comment disassembly <address> "note on this instruction"
```

### Labels

```bash
gsk label list [--address ADDR]
gsk label add <address> <name> [--local]
gsk label delete <address> <name>
```

### Bookmarks

```bash
gsk bookmark list [--type Note] [--limit N]
gsk bookmark add <address> "check this" [--type Note] [--category Review]
gsk bookmark delete <address> [--type Note] [--category Review]
```

### Cross-references

```bash
gsk xrefs to <address> [--limit N]
gsk xrefs from <address> [--limit N]
```

### Data types

```bash
gsk type list [--category CAT]        # list types
gsk type get <name>                   # detailed type info (fields, enum values, ...)
gsk type search <query>               # search by name
gsk type create <name> --kind struct --definition "int x; int y"
gsk type update <name> --definition "int x; int y; int z"
```

### Data at addresses

```bash
gsk data get <address>                # what type is applied here?
gsk data set <address> dword          # apply a type
gsk data set <address> MyStruct       # custom struct
gsk data clear <address> [length]     # clear defined data
```

### Memory

```bash
gsk read <address> [length]           # hex dump
```

### Equates (named constants)

```bash
gsk equate list
gsk equate get --name FOO
gsk equate set FOO 0x42
gsk equate delete FOO
```

### Symbol tree

```bash
gsk namespace list
gsk class list
gsk import list [--filter libc]
gsk export list [--filter main]
```

### Strings

```bash
gsk strings [--filter hello] [--limit N]
```

### Change tracking

```bash
gsk changes                           # changes since last check
gsk changes --watch                   # live stream of changes
gsk changes --since 1700000000000     # changes after a timestamp
```

## Using with AI assistants

`gsk` was designed to be used by AI coding assistants (Claude Code, Cursor, etc.) as a tool for reverse engineering. The repo includes an `AGENTS.md` with prompts and workflows that teach an assistant how to drive Ghidra effectively. Point your assistant at a binary, and it can iteratively decompile, rename, retype, and annotate -- building up understanding function by function.

## How it works

The Ghidra plugin starts a lightweight HTTP server (default port 8080) inside Ghidra's JVM. The server exposes ~40 endpoints that map to Ghidra's program model: functions, types, symbols, memory, the decompiler, and so on. The `gsk` CLI is a thin Go client that calls those endpoints and prints the results. Responses are plain text (tab-separated where appropriate), so they're easy to pipe, grep, and script against.

## Status

This is an early release. The core commands work and have been used daily for real reverse engineering work, but there are rough edges. If something doesn't work the way you expect, or you have ideas for commands that would be useful, please let us know.

## Contributing

We'd love your help. Here are some ways to get involved:

- **Try it out** -- install the plugin, point `gsk` at a binary, and see how it feels. First impressions are valuable.
- **File issues** -- if something breaks, is confusing, or is missing, [open an issue](https://github.com/domainos-archeology/ghidra-skill/issues). Bug reports with the Ghidra version and the command you ran are especially helpful.
- **Suggest features** -- what commands would make your RE workflow faster? What information does Ghidra expose that `gsk` doesn't?
- **Send patches** -- PRs are welcome. The codebase is straightforward: add a handler class in `GhidraHTTPServer.java`, a client method in `client.go`, and a cobra command in `cmd/gsk/cli/`.
