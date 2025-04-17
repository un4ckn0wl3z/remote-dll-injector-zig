const std = @import("std");
const win = std.os.windows;

extern "kernel32" fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: bool, dwProcessId: u32) callconv(win.WINAPI) ?win.HANDLE;
extern "kernel32" fn VirtualAllocEx(hProcess: ?win.HANDLE, lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(win.WINAPI) ?*anyopaque;
extern "kernel32" fn WriteProcessMemory(hProcess: ?win.HANDLE, lpBaseAddress: ?*anyopaque, lpBuffer: [*]const u8, nSize: usize, lpNumberOfBytesWritten: ?*usize) callconv(win.WINAPI) bool;
extern "kernel32" fn GetModuleHandleA(lpModuleName: ?[*:0]const u8) callconv(win.WINAPI) ?win.HMODULE;
extern "kernel32" fn GetProcAddress(hModule: ?win.HMODULE, lpProcName: [*:0]const u8) callconv(win.WINAPI) ?*anyopaque;
extern "kernel32" fn CreateRemoteThread(hProcess: ?win.HANDLE, lpThreadAttributes: ?*anyopaque, dwStackSize: usize, lpStartAddress: ?*anyopaque, lpParameter: ?*anyopaque, dwCreationFlags: u32, lpThreadId: ?*u32) callconv(win.WINAPI) ?win.HANDLE;
extern "kernel32" fn CloseHandle(hObject: ?win.HANDLE) callconv(win.WINAPI) bool;

// Windows constants
const PROCESS_ALL_ACCESS = 0x1F0FFF;
const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const PAGE_READWRITE = 0x04;

pub fn main() !void {
    // Command-line arguments for PID and DLL path
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    if (args.len != 3) {
        std.debug.print("Usage: injector.exe <PID> <DLL_PATH>\n", .{});
        return;
    }

    // Parse PID
    const pid = try std.fmt.parseInt(u32, args[1], 10);
    const dll_path = args[2];

    // Open target process
    const h_process = OpenProcess(PROCESS_ALL_ACCESS, false, pid) orelse {
        std.debug.print("Failed to open process: {}\n", .{win.GetLastError()});
        return;
    };
    defer _ = CloseHandle(h_process);

    // Allocate memory in target process
    const dll_path_len = dll_path.len + 1; // Include null terminator
    const alloc_addr = VirtualAllocEx(h_process, null, dll_path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) orelse {
        std.debug.print("Failed to allocate memory: {}\n", .{win.GetLastError()});
        return;
    };

    // Write DLL path to allocated memory
    var bytes_written: usize = 0;
    if (!WriteProcessMemory(h_process, alloc_addr, dll_path.ptr, dll_path_len, &bytes_written)) {
        std.debug.print("Failed to write process memory: {}\n", .{win.GetLastError()});
        return;
    }

    // Get LoadLibraryA address
    const kernel32 = GetModuleHandleA("kernel32.dll") orelse {
        std.debug.print("Failed to get kernel32 handle: {}\n", .{win.GetLastError()});
        return;
    };
    const load_library = GetProcAddress(kernel32, "LoadLibraryA") orelse {
        std.debug.print("Failed to get LoadLibraryA address: {}\n", .{win.GetLastError()});
        return;
    };

    // Create remote thread to call LoadLibraryA
    const h_thread = CreateRemoteThread(h_process, null, 0, load_library, alloc_addr, 0, null) orelse {
        std.debug.print("Failed to create remote thread: {}\n", .{win.GetLastError()});
        return;
    };
    defer _ = CloseHandle(h_thread);

    std.debug.print("DLL injected successfully into PID {}\n", .{pid});
}
