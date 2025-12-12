//! 微信多开助手：关闭微信实例互斥锁以允许多开
//!
//! 架构：父子进程模式
//! - 父进程：监控微信进程，发现新进程时启动子进程
//! - 子进程：关闭互斥锁后立即退出，避免句柄占用

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("错误：此工具仅支持 Windows 系统");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    windows_impl::run()
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use anyhow::{anyhow, Context, Result};
    use std::collections::HashSet;
    use std::ffi::c_void;
    use std::io::{self, Write};
    use std::mem::size_of;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;
    use widestring::U16CStr;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Console::{FreeConsole, GetConsoleWindow};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
        KEY_SET_VALUE, REG_SZ,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE};
    use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
    use windows::core::PCWSTR;

    /// 目标 Mutex 名称关键字（只需匹配这部分）
    const TARGET_MUTEX_KEYWORDS: &[&str] = &[
        "_WxMutex_App_Instance_Identity_Mutex_Name",
        "XWeChat_App_Instance_Identity_Mutex_Name",
        "_WeChat_App_Instance_Identity_Mutex_Name",
    ];

    /// 注册表自启动路径
    const AUTOSTART_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const AUTOSTART_VALUE_NAME: &str = "WeChatMultiHelper";

    /// 监控间隔（毫秒）
    const MONITOR_INTERVAL_MS: u64 = 2000;

    /// NT 状态码
    type NTSTATUS = i32;
    const STATUS_SUCCESS: NTSTATUS = 0;
    const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004_u32 as i32;

    const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
    const OBJECT_NAME_INFORMATION: u32 = 1;
    const DUPLICATE_CLOSE_SOURCE: u32 = 0x00000001;

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct SystemHandleTableEntryInfoEx {
        object: *mut c_void,
        unique_process_id: usize,
        handle_value: usize,
        granted_access: u32,
        creator_back_trace_index: u16,
        object_type_index: u16,
        handle_attributes: u32,
        reserved: u32,
    }

    #[repr(C)]
    struct SystemHandleInformationEx {
        number_of_handles: usize,
        reserved: usize,
    }

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct ObjectNameInformation {
        name: UnicodeString,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            system_information_class: u32,
            system_information: *mut c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> NTSTATUS;

        fn NtQueryObject(
            handle: *mut c_void,
            object_information_class: u32,
            object_information: *mut c_void,
            object_information_length: u32,
            return_length: *mut u32,
        ) -> NTSTATUS;

        fn NtDuplicateObject(
            source_process_handle: *mut c_void,
            source_handle: *mut c_void,
            target_process_handle: *mut c_void,
            target_handle: *mut *mut c_void,
            desired_access: u32,
            handle_attributes: u32,
            options: u32,
        ) -> NTSTATUS;
    }

    pub fn run() -> Result<()> {
        let args: Vec<String> = std::env::args().collect();

        // 子进程模式：关闭指定 PID 的互斥锁
        if args.len() >= 3 && args[1] == "--kill-mutex" {
            let pid: u32 = args[2].parse().unwrap_or(0);
            if pid > 0 {
                let _ = close_weixin_mutex(pid);
            }
            return Ok(());
        }

        // 静默模式：关闭所有微信的互斥锁然后退出（给 VBS 调用）
        if args.len() > 1 && args[1] == "--kill-mutex-all" {
            // 等待一下确保微信完全启动
            thread::sleep(Duration::from_millis(500));

            if let Ok(pids) = find_weixin_processes() {
                for pid in &pids {
                    let _ = close_weixin_mutex(*pid);
                }
            }
            return Ok(());
        }

        // 后台守护进程模式
        if args.len() > 1 && args[1] == "--daemon" {
            return run_daemon_mode();
        }

        // 交互式菜单
        println!("=== 微信多开助手 ===\n");
        println!("请选择运行模式：");
        println!("  1. 单次执行 - 立即关闭当前所有微信的互斥锁");
        println!("  2. 开启后台监控 - 持续监控并自动处理新微信");
        println!("  3. 设置开机自启");
        println!("  4. 关闭开机自启");
        println!("  5. 退出");
        print!("\n请输入选项 [1-5]: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => run_once_mode(),
            "2" => {
                println!("\n正在启动后台监控...");
                println!("程序将在后台运行，监控新的微信进程。");
                println!("可以关闭此窗口，程序会继续在后台运行。\n");
                thread::sleep(Duration::from_secs(2));
                run_daemon_mode()
            }
            "3" => enable_autostart(),
            "4" => disable_autostart(),
            "5" | "" => {
                println!("已退出");
                Ok(())
            }
            _ => {
                println!("无效选项");
                wait_for_enter();
                Ok(())
            }
        }
    }

    /// 单次执行模式（直接在主进程中操作）
    fn run_once_mode() -> Result<()> {
        println!("\n--- 单次执行模式 ---\n");

        let pids = find_weixin_processes()?;
        if pids.is_empty() {
            println!("未找到运行中的微信进程 (Weixin.exe)");
            println!("提示：请先启动微信，然后运行本工具");
            wait_for_enter();
            return Ok(());
        }

        println!("找到 {} 个微信进程: {:?}\n", pids.len(), pids);

        // 直接在主进程中关闭互斥锁
        let mut total_closed = 0;
        for pid in &pids {
            match close_weixin_mutex(*pid) {
                Ok(count) => {
                    if count > 0 {
                        println!("[PID {}] 成功关闭 {} 个 Mutex 句柄", pid, count);
                        total_closed += count;
                    } else {
                        println!("[PID {}] 未找到目标 Mutex（可能已被关闭）", pid);
                    }
                }
                Err(e) => {
                    eprintln!("[PID {}] 处理失败: {}", pid, e);
                }
            }
        }

        println!("\n=== 处理完成 ===");
        if total_closed > 0 {
            println!("已关闭 {} 个 Mutex 句柄，现在可以启动新的微信实例了", total_closed);
        } else {
            println!("未找到需要关闭的 Mutex");
        }

        wait_for_enter();
        Ok(())
    }

    /// 守护进程模式：监控微信进程
    fn run_daemon_mode() -> Result<()> {
        // 隐藏控制台窗口
        hide_console_window();

        let mut known_pids: HashSet<u32> = HashSet::new();

        // 初始化：记录并处理当前已存在的进程
        if let Ok(pids) = find_weixin_processes() {
            for pid in &pids {
                // 启动子进程处理
                spawn_kill_mutex_process(*pid);
                known_pids.insert(*pid);
            }
        }

        // 监控循环
        loop {
            thread::sleep(Duration::from_millis(MONITOR_INTERVAL_MS));

            let current_pids = match find_weixin_processes() {
                Ok(pids) => pids,
                Err(_) => continue,
            };

            let current_set: HashSet<u32> = current_pids.iter().cloned().collect();

            // 处理新进程
            for pid in &current_set {
                if !known_pids.contains(pid) {
                    // 等待进程初始化
                    thread::sleep(Duration::from_millis(1000));
                    // 启动子进程处理
                    spawn_kill_mutex_process(*pid);
                }
            }

            // 更新已知进程列表
            known_pids = current_set;
        }
    }

    /// 启动子进程来关闭指定 PID 的互斥锁
    fn spawn_kill_mutex_process(pid: u32) -> bool {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let exe_path = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return false,
        };

        // 启动子进程，不创建新窗口
        match Command::new(&exe_path)
            .args(["--kill-mutex", &pid.to_string()])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
        {
            Ok(mut child) => {
                // 等待子进程完成
                match child.wait() {
                    Ok(status) => status.success(),
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }

    /// 设置开机自启
    fn enable_autostart() -> Result<()> {
        println!("\n--- 设置开机自启 ---\n");

        let exe_path = std::env::current_exe().context("无法获取程序路径")?;
        let startup_cmd = format!("\"{}\" --daemon", exe_path.to_string_lossy());

        set_autostart(&startup_cmd)?;

        println!("已设置开机自启动！");
        println!("启动命令: {}", startup_cmd);
        println!("\n开机后程序将自动在后台运行，监控新的微信进程。");

        wait_for_enter();
        Ok(())
    }

    /// 关闭开机自启
    fn disable_autostart() -> Result<()> {
        println!("\n--- 关闭开机自启 ---\n");

        remove_autostart()?;

        println!("已移除开机自启动！");
        println!("提示：如需停止后台进程，请在任务管理器中结束 wechatmult.exe");

        wait_for_enter();
        Ok(())
    }

    fn hide_console_window() {
        unsafe {
            let hwnd = GetConsoleWindow();
            if hwnd.0 != 0 {
                let _ = ShowWindow(hwnd, SW_HIDE);
            }
            let _ = FreeConsole();
        }
    }

    fn set_autostart(command: &str) -> Result<()> {
        unsafe {
            let key_path: Vec<u16> = AUTOSTART_KEY.encode_utf16().chain(std::iter::once(0)).collect();
            let value_name: Vec<u16> = AUTOSTART_VALUE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
            let value_data: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();

            let mut hkey = HKEY::default();

            let result = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(key_path.as_ptr()),
                0,
                KEY_SET_VALUE,
                &mut hkey,
            );

            if result.is_err() {
                return Err(anyhow!("无法打开注册表键: {:?}", result));
            }

            let result = RegSetValueExW(
                hkey,
                PCWSTR(value_name.as_ptr()),
                0,
                REG_SZ,
                Some(&std::slice::from_raw_parts(
                    value_data.as_ptr() as *const u8,
                    value_data.len() * 2,
                )),
            );

            let _ = RegCloseKey(hkey);

            if result.is_err() {
                return Err(anyhow!("无法写入注册表值: {:?}", result));
            }

            Ok(())
        }
    }

    fn remove_autostart() -> Result<()> {
        unsafe {
            let key_path: Vec<u16> = AUTOSTART_KEY.encode_utf16().chain(std::iter::once(0)).collect();
            let value_name: Vec<u16> = AUTOSTART_VALUE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

            let mut hkey = HKEY::default();

            let result = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(key_path.as_ptr()),
                0,
                KEY_SET_VALUE,
                &mut hkey,
            );

            if result.is_err() {
                return Err(anyhow!("无法打开注册表键: {:?}", result));
            }

            let _ = RegDeleteValueW(hkey, PCWSTR(value_name.as_ptr()));
            let _ = RegCloseKey(hkey);

            Ok(())
        }
    }

    fn wait_for_enter() {
        println!("\n按回车键退出...");
        let _ = io::stdin().read_line(&mut String::new());
    }

    fn find_weixin_processes() -> Result<Vec<u32>> {
        let mut pids = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).context("创建进程快照失败")?;

            let mut entry = PROCESSENTRY32W {
                dwSize: size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let exe_name = U16CStr::from_ptr_str(entry.szExeFile.as_ptr());
                    let exe_str = exe_name.to_string_lossy();

                    if exe_str.eq_ignore_ascii_case("Weixin.exe") {
                        pids.push(entry.th32ProcessID);
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        Ok(pids)
    }

    /// 关闭指定进程中的微信 Mutex（仅子进程调用）
    fn close_weixin_mutex(pid: u32) -> Result<u32> {
        unsafe {
            let process_handle = OpenProcess(PROCESS_DUP_HANDLE, false, pid)
                .with_context(|| format!("无法打开进程 {}", pid))?;

            let result = close_mutex_in_process(process_handle, pid);

            let _ = CloseHandle(process_handle);

            result
        }
    }

    fn close_mutex_in_process(process_handle: HANDLE, target_pid: u32) -> Result<u32> {
        let handles = enumerate_process_handles(target_pid)?;
        let mut closed_count = 0;
        let current_process = unsafe { GetCurrentProcess() };

        for handle_entry in handles {
            if let Some(name) = get_handle_name(process_handle, handle_entry.handle_value, current_process) {
                // 检查是否匹配任何一个关键字
                let is_target = TARGET_MUTEX_KEYWORDS.iter().any(|keyword| name.contains(keyword));
                if is_target {
                    if close_remote_handle(process_handle, handle_entry.handle_value) {
                        closed_count += 1;
                    }
                }
            }
        }

        Ok(closed_count)
    }

    fn enumerate_process_handles(pid: u32) -> Result<Vec<SystemHandleTableEntryInfoEx>> {
        unsafe {
            let mut buffer_size: u32 = 0x100000;

            loop {
                let mut buffer = vec![0u8; buffer_size as usize];
                let mut return_length: u32 = 0;

                let status = NtQuerySystemInformation(
                    SYSTEM_EXTENDED_HANDLE_INFORMATION,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer_size,
                    &mut return_length,
                );

                if status == STATUS_INFO_LENGTH_MISMATCH {
                    buffer_size = return_length.saturating_add(0x10000);
                    continue;
                }

                if status != STATUS_SUCCESS {
                    return Err(anyhow!("NtQuerySystemInformation 失败: 0x{:08X}", status as u32));
                }

                let info_ptr = buffer.as_ptr() as *const SystemHandleInformationEx;
                let info = std::ptr::read_unaligned(info_ptr);
                let handle_count = info.number_of_handles;

                let handles_ptr = buffer.as_ptr().add(size_of::<SystemHandleInformationEx>())
                    as *const SystemHandleTableEntryInfoEx;

                let handles_bytes = buffer.len().saturating_sub(size_of::<SystemHandleInformationEx>());
                let max_entries = handles_bytes / size_of::<SystemHandleTableEntryInfoEx>();
                let count = usize::min(handle_count, max_entries);

                let mut result = Vec::new();
                for i in 0..count {
                    let entry = std::ptr::read_unaligned(handles_ptr.add(i));
                    if entry.unique_process_id as u32 == pid {
                        result.push(entry);
                    }
                }

                return Ok(result);
            }
        }
    }

    fn get_handle_name(process_handle: HANDLE, handle_value: usize, current_process: HANDLE) -> Option<String> {
        unsafe {
            let mut duplicated_handle: *mut c_void = std::ptr::null_mut();

            let status = NtDuplicateObject(
                process_handle.0 as *mut c_void,
                handle_value as *mut c_void,
                current_process.0 as *mut c_void,
                &mut duplicated_handle,
                0,
                0,
                0,
            );

            if status != STATUS_SUCCESS {
                return None;
            }

            let name = query_object_name(duplicated_handle);
            let _ = CloseHandle(HANDLE(duplicated_handle as isize));

            name
        }
    }

    fn query_object_name(handle: *mut c_void) -> Option<String> {
        unsafe {
            let mut buffer_size: u32 = 0x1000;

            loop {
                let mut buffer = vec![0u8; buffer_size as usize];
                let mut return_length: u32 = 0;

                let status = NtQueryObject(
                    handle,
                    OBJECT_NAME_INFORMATION,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer_size,
                    &mut return_length,
                );

                if status == STATUS_INFO_LENGTH_MISMATCH {
                    buffer_size = return_length.saturating_add(0x100);
                    continue;
                }

                if status != STATUS_SUCCESS {
                    return None;
                }

                let info = std::ptr::read_unaligned(buffer.as_ptr() as *const ObjectNameInformation);

                if info.name.length == 0 || info.name.buffer.is_null() {
                    return None;
                }

                let slice = std::slice::from_raw_parts(info.name.buffer, (info.name.length / 2) as usize);

                return Some(String::from_utf16_lossy(slice));
            }
        }
    }

    fn close_remote_handle(process_handle: HANDLE, handle_value: usize) -> bool {
        unsafe {
            let current_process = GetCurrentProcess();
            let status = NtDuplicateObject(
                process_handle.0 as *mut c_void,
                handle_value as *mut c_void,
                current_process.0 as *mut c_void,
                std::ptr::null_mut(),
                0,
                0,
                DUPLICATE_CLOSE_SOURCE,
            );

            status == STATUS_SUCCESS
        }
    }
}
