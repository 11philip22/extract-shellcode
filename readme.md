# extract-shellcode

Small Rust toolkit for pulling shellcode out of a Windows PE and (optionally) executing it in-memory for quick validation.

## components
- `extract-shellcode`: reads a PE, finds the `.text` section, and uses a linker map file to decide how many bytes to keep.
- `test-shellcode`: loads a binary blob, allocates executable memory with `VirtualAlloc` on Windows, and jumps to it.

## prerequisites
- Rust toolchain (edition 2024).
- Windows for `test-shellcode` execution (other platforms bail out).
- A PE executable and its corresponding `.map` file; the map line for `.text` should look like `0001:00000000 00000XXXH .text CODE`.

## building
```bash
cargo build
```

## usage
Extract shellcode from a PE using its map file:
```bash
cargo run --bin extract-shellcode -- -e path\\to\\program.exe -m path\\to\\program.map -o shellcode.bin
```

Inspect and execute a shellcode blob (Windows only):
```bash
cargo run --bin test-shellcode -- -i shellcode.bin
```
The runner prints the byte count and first few bytes before executing. Execution uses RWX pages; use only in a controlled environment.

## notes and limitations
- The extractor looks for the first `.text` section named exactly `.text` and trusts the map file length; malformed inputs will error out.
- The tester does not apply mitigations (no DEP/CFG bypass), so only run known-safe shellcode.
- CI/tests are not provided; use `cargo clippy` and `cargo fmt` locally if desired.


## License
This project is licensed under the MIT License - see the [license](license) file for details.
