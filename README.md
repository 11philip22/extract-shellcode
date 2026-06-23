<div align="center">
  <h1>extract-shellcode</h1>
  <p><strong>Extract <code>.text</code> shellcode from Windows PE files with linker map precision.</strong></p>

  <p>
    <a href="https://crates.io/crates/extract-shellcode"><img src="https://img.shields.io/crates/v/extract-shellcode?style=for-the-badge&logo=rust&logoColor=white" alt="Crates.io version"></a>
    <a href="https://github.com/11philip22/extract-shellcode"><img src="https://img.shields.io/badge/Rust-2024-f74c00?style=for-the-badge&logo=rust&logoColor=white" alt="Rust 2024"></a>
    <a href="https://www.microsoft.com/windows"><img src="https://img.shields.io/badge/Windows-PE%20tooling-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows PE tooling"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge" alt="MIT license"></a>
  </p>

  <p>
    <a href="#overview">Overview</a> &middot;
    <a href="#requirements">Requirements</a> &middot;
    <a href="#install">Install</a> &middot;
    <a href="#usage">Usage</a> &middot;
    <a href="#map-files">Map files</a> &middot;
    <a href="#development">Development</a> &middot;
    <a href="#safety">Safety</a>
  </p>
</div>

## Overview

`extract-shellcode` is a small Rust toolkit for turning a Windows PE executable into a raw shellcode blob, then optionally testing that blob in memory on Windows.

| Binary | Purpose |
| --- | --- |
| `extract_shellcode` | Parses a PE file, finds the first section named `.text`, reads the shellcode length from a linker `.map` file, and writes the trimmed bytes to disk. |
| `test_shellcode` | Loads a shellcode blob, prints basic diagnostics, allocates executable memory with `VirtualAlloc`, and calls into the buffer. |

The extractor uses [`goblin`](https://crates.io/crates/goblin) for PE parsing and [`clap`](https://crates.io/crates/clap) for the command-line interface.

## Requirements

- Rust toolchain with edition 2024 support.
- A Windows PE executable and its matching linker map file.
- Windows if you plan to run `test_shellcode`; extraction can parse files on other platforms.

## Install

Install the published crate:

```sh
cargo install extract-shellcode
```

Or build from source:

```sh
git clone https://github.com/11philip22/extract-shellcode.git
cd extract-shellcode
cargo build --release
```

## Usage

Extract shellcode from a PE and linker map:

```sh
extract_shellcode --exe path\to\program.exe --map path\to\program.map --out shellcode.bin
```

The same command through Cargo while developing locally:

```sh
cargo run --bin extract_shellcode -- --exe path\to\program.exe --map path\to\program.map --out shellcode.bin
```

Inspect and execute the extracted blob on Windows:

```sh
test_shellcode --input shellcode.bin
```

Or run it from source:

```sh
cargo run --bin test_shellcode -- --input shellcode.bin
```

Short flags are also available:

```sh
extract_shellcode -e program.exe -m program.map -o shellcode.bin
test_shellcode -i shellcode.bin
```

## Map files

The extractor looks for the first map line that contains both `.text` and `CODE`, then parses the second whitespace-delimited column as a hexadecimal length ending in `H`:

```text
0001:00000000 00000XXXH .text CODE
```

That length controls how many bytes are kept from the PE section's raw `.text` data. If the map length is larger than the section data, extraction fails instead of writing a truncated or malformed blob.

## Development

Useful local checks:

```sh
cargo fmt
cargo clippy --all-targets --all-features
cargo test
cargo build --release
```

## Safety

> [!CAUTION]
> `test_shellcode` allocates read-write-execute memory and transfers control to the bytes you provide. Run only known-safe shellcode in an isolated Windows environment.

Common failure cases:

- `No .text section found in PE file`: the extractor requires a section named exactly `.text`.
- `Could not find .text CODE entry in map file`: the map file does not include the expected `.text CODE` line.
- `Shellcode execution only supported on Windows`: `test_shellcode` was run on a non-Windows platform.
