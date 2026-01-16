use std::fs;
use std::path::PathBuf;
use clap::Parser;
use anyhow::{Context, Result};

/// Test extracted shellcode by executing it in memory.
#[derive(Parser)]
#[command(name = "test-shellcode")]
#[command(about = "Load and execute shellcode from a binary file")]
struct Args {
    /// Shellcode binary file to test
    #[arg(long, short = 'i')]
    input: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let shellcode = fs::read(&args.input)
        .with_context(|| format!("Failed to read shellcode file: {:?}", args.input))?;

    println!("Loaded {} bytes of shellcode", shellcode.len());
    println!("First 16 bytes: {:02X?}", &shellcode[..shellcode.len().min(16)]);

    // Allocate executable memory and run the shellcode
    unsafe {
        execute_shellcode(&shellcode)?;
    }

    println!("Shellcode executed successfully!");
    Ok(())
}

#[cfg(windows)]
unsafe fn execute_shellcode(shellcode: &[u8]) -> Result<()> {
    use std::ptr;

    // Windows API bindings
    unsafe extern "system" {
        fn VirtualAlloc(
            lpAddress: *mut u8,
            dwSize: usize,
            flAllocationType: u32,
            flProtect: u32,
        ) -> *mut u8;
        fn VirtualFree(lpAddress: *mut u8, dwSize: usize, dwFreeType: u32) -> i32;
    }

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    // Allocate executable memory
    let exec_mem = unsafe {
        VirtualAlloc(
            ptr::null_mut(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if exec_mem.is_null() {
        anyhow::bail!("VirtualAlloc failed");
    }

    // Copy shellcode to executable memory
    unsafe {
        ptr::copy_nonoverlapping(shellcode.as_ptr(), exec_mem, shellcode.len());
    }

    println!("Executing shellcode at {:p}...", exec_mem);

    // Cast to function pointer and call
    let func: extern "C" fn() = unsafe { std::mem::transmute(exec_mem) };
    func();

    // Free memory
    unsafe {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
    }

    Ok(())
}

#[cfg(not(windows))]
unsafe fn execute_shellcode(_shellcode: &[u8]) -> Result<()> {
    anyhow::bail!("Shellcode execution only supported on Windows")
}
