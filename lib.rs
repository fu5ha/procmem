//! Helpers for accessing other processes' memory in Windows.
#![cfg(windows)]

use core::mem::MaybeUninit;
use core::ffi::c_void;

use enumflags2::{bitflags, BitFlags};
use windows::{
    core::Error as WinError,
    Win32,
    Win32::Foundation::{CHAR, HANDLE},
};


#[bitflags]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AccessRights {
    Read = Win32::System::Threading::PROCESS_VM_READ.0,
    Write = Win32::System::Threading::PROCESS_VM_WRITE.0,
}

impl From<AccessRights> for Win32::System::Threading::PROCESS_ACCESS_RIGHTS {
    fn from(caps: AccessRights) -> Win32::System::Threading::PROCESS_ACCESS_RIGHTS {
        Win32::System::Threading::PROCESS_ACCESS_RIGHTS(caps as u32)
    }
}

pub struct ProcessHandle {
    handle: HANDLE,
    rights: BitFlags<AccessRights>,
}

pub enum OpenProcessNamedError {
    NotFound,
    WinErr(WinError),
}

impl From<WinError> for OpenProcessNamedError {
    fn from(err: WinError) -> OpenProcessNamedError {
        OpenProcessNamedError::WinErr(err)
    }
}

impl ProcessHandle {
    pub fn open_process_named(process_name: &str, accesses: BitFlags<AccessRights>) -> Result<ProcessHandle, OpenProcessNamedError> {
        let mut entry = Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32 {
            dwSize: core::mem::size_of::<Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32>() as u32,
            szExeFile: [CHAR(0); 260],
            ..Default::default()
        };

        unsafe {
            let snapshot = Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
                0,
            ).ok()?;

            let mut str = String::with_capacity(260);
            let mut copied = Win32::System::Diagnostics::ToolHelp::Process32First(snapshot, &mut entry as *mut _).as_bool();
            loop {
                if !copied {
                    return Err(OpenProcessNamedError::NotFound)
                }

                let matched_name = std::ffi::CStr::from_bytes_with_nul(unsafe {
                    core::slice::from_raw_parts(entry.szExeFile.as_ptr().cast(), entry.szExeFile.len())
                })
                    .ok()
                    .and_then(|cstr| cstr.to_str().ok())
                    .map(|str| str == process_name)
                    .unwrap_or(false) ;

                if matched_name {
                    return Self::open_process(entry.th32ProcessID, accesses).map_err(From::from)
                }

                copied = Win32::System::Diagnostics::ToolHelp::Process32Next(snapshot, &mut entry as *mut _).as_bool();
            }
        }
    }

    pub fn open_process(pid: u32, accesses: BitFlags<AccessRights>) -> Result<Self, WinError> {
        let raw_handle = unsafe {
            use windows::Win32::System::Threading::*;
            let desired_access = PROCESS_VM_OPERATION | PROCESS_ACCESS_RIGHTS(accesses.bits());
            
            OpenProcess(desired_access, false, pid).ok()?
        };

        Ok(Self {
            handle: raw_handle,
            rights: accesses,
        })
    }

    pub fn main_module_base_ptr(&self) -> *mut u8 {

    }

    /// - ptr is an absolute pointer, not an offset from the process's base memory address.
    pub fn read_from_process_raw(
        process: ProcessHandle,
        ptr: *const c_void,
        out: &mut [MaybeUninit<u8>]
    ) -> Result<(), WinError> {
        if out.is_empty() {
            return Ok(())
        }

        unsafe {
            Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process.handle,
                ptr,
                out.as_ptr() as *mut _,
                out.len(),
                core::ptr::null_mut(),
            ).ok()
        }    
    }
}

