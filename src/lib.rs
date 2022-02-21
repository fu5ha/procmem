//! Helpers for accessing other processes' memory in Windows.
#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;
use std::os::windows::prelude::OsStringExt;

use windows::{
    core::Error as WinError,
    Win32,
    Win32::Foundation::HANDLE,
};

bitflags::bitflags! {
    pub struct AccessRightsBits: u32 {
        const READ = Win32::System::Threading::PROCESS_VM_READ.0;
        const WRITE = Win32::System::Threading::PROCESS_VM_WRITE.0;
    }
}

pub mod protect {
    pub use windows::Win32::System::Memory::{
        PAGE_PROTECTION_FLAGS, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_NOACCESS, PAGE_TARGETS_INVALID,
        PAGE_TARGETS_NO_UPDATE, PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE,
    };
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

pub enum ProcessAccessError {
    InvalidRights,
    UnalignedPointer,
    WinErr(WinError),
}

impl From<WinError> for ProcessAccessError {
    fn from(err: WinError) -> ProcessAccessError {
        ProcessAccessError::WinErr(err)
    }
}

pub struct ModuleInfo {
    pub name: String,
    pub base_ptr: *mut u8,
    pub size: usize,
}

pub struct Process {
    pid: u32,
    handle: HANDLE,
    name: String,
    rights: AccessRightsBits,
    modules: Vec<ModuleInfo>,
}

impl Process {
    /// Opens the first process with a name that contains the given `process_name` string. If there may be more than one process with the name
    /// you are intereted in, use [`pids_for_name`] to get a list and then open the ones you are interested in with [`Process::open_process`].
    pub fn open_process_named(process_name: &str, accesses: AccessRightsBits) -> Result<Process, OpenProcessNamedError> {
        let mut entry = Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W {
            dwSize: core::mem::size_of::<Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        unsafe {
            let snapshot = Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
                0,
            ).ok()?;

            let mut copied = Win32::System::Diagnostics::ToolHelp::Process32FirstW(snapshot, &mut entry as *mut _).as_bool();
            loop {
                if !copied {
                    break;
                }

                let matched_name = std::ffi::OsString::from_wide(&entry.szExeFile)
                    .to_str()
                    .map(|str| str.contains(process_name))
                    .unwrap_or(false);

                if matched_name {
                    Win32::Foundation::CloseHandle(snapshot).ok()?;
                    return Self::open_process(entry.th32ProcessID, accesses).map_err(From::from)
                }

                copied = Win32::System::Diagnostics::ToolHelp::Process32NextW(snapshot, &mut entry as *mut _).as_bool();
            }

            Win32::Foundation::CloseHandle(snapshot).ok()?;
            return Err(OpenProcessNamedError::NotFound)
        }
    }

    /// Opens the process with the specified process id.
    pub fn open_process(pid: u32, accesses: AccessRightsBits) -> Result<Self, WinError> {
        let raw_handle = unsafe {
            use windows::Win32::System::Threading::*;
            let desired_access = PROCESS_VM_OPERATION | PROCESS_ACCESS_RIGHTS(accesses.bits());
            
            OpenProcess(desired_access, false, pid).ok()?
        };

        let snapshot = unsafe { Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
            Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE
                | Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE32
                | Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
            pid,
        ).ok()? };

        let mut proc_entry = Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W {
            dwSize: core::mem::size_of::<Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        unsafe {
            Win32::System::Diagnostics::ToolHelp::Process32FirstW(snapshot, &mut proc_entry as *mut _).ok()?;
        }

        assert!(proc_entry.th32ProcessID == pid);

        let process_name = std::ffi::OsString::from_wide(&proc_entry.szExeFile).to_string_lossy().to_string();

        let mut modules = Vec::new();

        unsafe {
            let mut mod_entry = Win32::System::Diagnostics::ToolHelp::MODULEENTRY32W {
                dwSize: core::mem::size_of::<Win32::System::Diagnostics::ToolHelp::MODULEENTRY32W>() as u32,
                ..Default::default()
            };

            let mut copied = Win32::System::Diagnostics::ToolHelp::Module32FirstW(snapshot, &mut mod_entry as *mut _).as_bool();
            loop {
                if !copied {
                    break;
                }

                modules.push(ModuleInfo {
                    name: std::ffi::OsString::from_wide(&mod_entry.szModule).to_string_lossy().to_string(),
                    base_ptr: mod_entry.modBaseAddr,
                    size: mod_entry.modBaseSize as usize,
                });

                copied = Win32::System::Diagnostics::ToolHelp::Module32NextW(snapshot, &mut mod_entry as *mut _).as_bool();
            }

            Win32::Foundation::CloseHandle(snapshot).ok()?;
        }

        let main_module_index = modules.iter().position(|m| &m.name == &process_name).expect("Process does not have a main module");

        modules.swap(0, main_module_index);

        Ok(Self {
            pid,
            name: process_name,
            handle: raw_handle,
            rights: accesses,
            modules,
        })
    }

    pub fn refresh_modules(&mut self) -> Result<(), WinError> {
        self.modules.clear();

        unsafe {
            let snapshot = Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE
                    | Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE32,
                self.pid,
            ).ok()?;

            let mut mod_entry = Win32::System::Diagnostics::ToolHelp::MODULEENTRY32W {
                dwSize: core::mem::size_of::<Win32::System::Diagnostics::ToolHelp::MODULEENTRY32W>() as u32,
                ..Default::default()
            };

            let mut copied = Win32::System::Diagnostics::ToolHelp::Module32FirstW(snapshot, &mut mod_entry as *mut _).as_bool();
            loop {
                if !copied {
                    break;
                }

                self.modules.push(ModuleInfo {
                    name: std::ffi::OsString::from_wide(&mod_entry.szModule).to_string_lossy().to_string(),
                    base_ptr: mod_entry.modBaseAddr,
                    size: mod_entry.modBaseSize as usize,
                });

                copied = Win32::System::Diagnostics::ToolHelp::Module32NextW(snapshot, &mut mod_entry as *mut _).as_bool();
            }

            Win32::Foundation::CloseHandle(snapshot).ok()?;
        }

        let main_module_index = self.modules.iter().position(|m| &m.name == &self.name).expect("Process does not have a main module");

        self.modules.swap(0, main_module_index);

        Ok(())
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn main_module(&self) -> &ModuleInfo {
        &self.modules[0]
    }

    pub fn modules(&self) -> &[ModuleInfo] {
        &self.modules
    }

    /// - `base_ptr` is an absolute pointer, not an offset from the process's base memory address.
    /// 
    /// # Safety
    /// 
    /// This function is incredibly unsafe. If it returns without error, then you know the requested copy succeeded at least,
    /// but it's very possible to do very bad things by copying data that doesn't make sense for some `T` into it through this
    /// function.
    pub unsafe fn read_memory<T: ?Sized>(
        &self,
        base_ptr: *const c_void,
        out: &mut T,
    ) -> Result<(), ProcessAccessError> {
        if !self.rights.contains(AccessRightsBits::READ) {
            return Err(ProcessAccessError::InvalidRights)
        }

        let layout = core::alloc::Layout::for_value(out);

        if layout.size() == 0 {
            return Ok(())
        }

        if !is_aligned(base_ptr as usize, layout.align()) {
            return Err(ProcessAccessError::UnalignedPointer)
        }

        unsafe {
            Win32::System::Diagnostics::Debug::ReadProcessMemory(
                self.handle,
                base_ptr,
                out as *mut T as *mut _,
                layout.size(),
                core::ptr::null_mut(),
            )
                .ok()
                .map_err(From::from)
        }    
    }

    /// - `base_ptr` is an absolute pointer, not an offset from the process's base memory address.
    /// 
    /// # Safety
    /// 
    /// This is kinda mostly safe for the calling process but you could do some bad sh*t to the process you're writing
    /// to if you do it wrong. Checks a couple common footguns, but, be careful.
    pub unsafe fn write_memory<T: ?Sized>(
        &self,
        base_ptr: *mut c_void,
        data: &T,
    ) -> Result<(), ProcessAccessError> {
        if !self.rights.contains(AccessRightsBits::WRITE) {
            return Err(ProcessAccessError::InvalidRights)
        }

        let layout = core::alloc::Layout::for_value(data);

        if layout.size() == 0 {
            return Ok(())
        }

        if !is_aligned(base_ptr as usize, layout.align()) {
            return Err(ProcessAccessError::UnalignedPointer)
        }

        unsafe {
            Win32::System::Diagnostics::Debug::WriteProcessMemory(
                self.handle,
                base_ptr,
                data as *const T as *const c_void,
                layout.size(),
                core::ptr::null_mut(),
            )
                .ok()
                .map_err(From::from)
        }
    }

    /// Changes the virtual protection flags for a region starting at `start_addr` and extending `size` bytes.
    /// 
    /// - `base_ptr` is an absolute pointer, not an offset from the process's base memory address.
    /// 
    /// # Safety
    /// 
    /// I don't know exactly how unsafe this is but you can probably brake shit with it so I'm leaving it unsafe, fight me.
    pub unsafe fn virtual_protect(
        &self,
        start_addr: *const c_void,
        size: usize,
        new_protect_flags: protect::PAGE_PROTECTION_FLAGS
    ) -> Result<protect::PAGE_PROTECTION_FLAGS, WinError> {
        let mut old_protection = protect::PAGE_PROTECTION_FLAGS(0);

        unsafe {
            Win32::System::Memory::VirtualProtectEx(
                self.handle,
                start_addr,
                size,
                new_protect_flags,
                &mut old_protection as *mut _,
            ).ok()?
        }

        Ok(old_protection)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            Win32::Foundation::CloseHandle(self.handle).expect("Failed to close process handle on drop")
        }
    }
}

pub fn pids_for_name(process_name: &str) -> Result<Vec<u32>, WinError> {
    let mut entry = Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W {
        dwSize: core::mem::size_of::<Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut pids = Vec::new();

    unsafe {
        let snapshot = Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
            Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
            0,
        ).ok()?;

        let mut copied = Win32::System::Diagnostics::ToolHelp::Process32FirstW(snapshot, &mut entry as *mut _).as_bool();
        loop {
            if !copied {
                break;
            }

            let matched_name = std::ffi::OsString::from_wide(&entry.szExeFile)
                .to_str()
                .map(|str| str.contains(process_name))
                .unwrap_or(false);

            if matched_name {
                pids.push(entry.th32ProcessID);
            }

            copied = Win32::System::Diagnostics::ToolHelp::Process32NextW(snapshot, &mut entry as *mut _).as_bool();
        }

        Win32::Foundation::CloseHandle(snapshot).ok()?;
    }
    Ok(pids)
}

fn is_aligned(ptr: usize, align: usize) -> bool {
    ptr % align == 0
}