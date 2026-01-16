use anyhow::{Context, Result, bail};
use clap::Parser;
use goblin::pe::PE;
use std::fs;
use std::path::PathBuf;

/// Extract shellcode from a PE executable's .text section using a linker map file.
#[derive(Parser)]
#[command(name = "extract-shellcode")]
#[command(about = "Extract shellcode from PE .text section using MAP file for length")]
struct Args {
    /// Input PE executable
    #[arg(long, short = 'e')]
    exe: PathBuf,

    /// Input linker map file
    #[arg(long, short = 'm')]
    map: PathBuf,

    /// Output shellcode binary
    #[arg(long, short = 'o')]
    out: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Read and parse the PE file
    let exe_data = fs::read(&args.exe)
        .with_context(|| format!("Failed to read PE file: {:?}", args.exe))?;

    let pe = PE::parse(&exe_data)
        .with_context(|| "Failed to parse PE file")?;

    // Find the .text section
    let text_section = pe
        .sections
        .iter()
        .find(|s| {
            let name = String::from_utf8_lossy(&s.name);
            name.trim_end_matches('\0') == ".text"
        })
        .context("No .text section found in PE file")?;

    // Read the map file and parse the .text section length
    let map_contents = fs::read_to_string(&args.map)
        .with_context(|| format!("Failed to read map file: {:?}", args.map))?;

    let shellcode_length = parse_map_file(&map_contents)?;

    // Extract the .text section raw data
    let text_start = text_section.pointer_to_raw_data as usize;
    let text_size = text_section.size_of_raw_data as usize;

    if text_start + text_size > exe_data.len() {
        bail!("Invalid .text section bounds in PE file");
    }

    let text_data = &exe_data[text_start..text_start + text_size];

    if shellcode_length > text_data.len() {
        bail!(
            "Map file indicates length 0x{:X} but .text section only has 0x{:X} bytes",
            shellcode_length,
            text_data.len()
        );
    }

    // Write the shellcode to output file
    let shellcode = &text_data[..shellcode_length];
    fs::write(&args.out, shellcode)
        .with_context(|| format!("Failed to write output file: {:?}", args.out))?;

    println!("Shellcode length: 0x{:04X}", shellcode_length);

    Ok(())
}

/// Parse the map file to find the .text section length.
/// Expected format: `0001:00000000 00000XXXH .text CODE`
fn parse_map_file(contents: &str) -> Result<usize> {
    for line in contents.lines() {
        // Look for lines containing ".text" and "CODE"
        if line.contains(".text") && line.contains("CODE") {
            // Split by whitespace and find the length field (ends with 'H')
            let parts: Vec<&str> = line.split_whitespace().collect();

            // Find the hex length field (second column, ends with 'H')
            if parts.len() >= 2 {
                let length_field = parts[1];
                if length_field.ends_with('H') || length_field.ends_with('h') {
                    let hex_str = length_field.trim_end_matches(['H', 'h']);
                    let length = usize::from_str_radix(hex_str, 16)
                        .with_context(|| format!("Failed to parse hex length: {}", hex_str))?;
                    return Ok(length);
                }
            }
        }
    }

    bail!("Could not find .text CODE entry in map file")
}
