<# : WhoLocksIt.cmd - batch/PowerShell hybrid. The batch part only launches PowerShell.
@echo off
setlocal
set "WL_SELF=%~f0"
set "WL_ARG=%~1"
set "WL_OPT=%~2"
title WhoLocksIt
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression ([System.IO.File]::ReadAllText($env:WL_SELF))"
set "WL_EXIT=%ERRORLEVEL%"
endlocal & exit /b %WL_EXIT%
#>

# ---------------------------------------------------------------------------
#  WhoLocksIt - find out which process is holding a file, an app or a folder,
#  and optionally kill it.
#
#  Everything below this line is PowerShell (Windows PowerShell 5.1+).
#  https://github.com/<your-user>/WhoLocksIt  -  MIT License
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Continue'
$Script:Version        = '1.1.0'
$Script:SelfPath       = $env:WL_SELF
$Script:SelfDir        = Split-Path -Parent $env:WL_SELF
$Script:MaxFolderFiles = 20000     # cap for files checked inside a folder
$Script:RmChunkSize    = 500       # files registered per Restart Manager session

# Processes that must never be killed (killing them crashes / logs off Windows).
$Script:Critical = @('system', 'idle', 'registry', 'smss', 'csrss', 'wininit', 'winlogon',
                     'services', 'lsass', 'lsaiso', 'memory compression', 'secure system',
                     'fontdrvhost', 'dwm')
# Processes that can be killed, but deserve an extra warning.
$Script:Risky = @{
    'explorer' = 'This is Windows Explorer (taskbar, desktop, file windows). It will be restarted.'
    'svchost'  = 'This is a Windows service host. Killing it can stop several Windows services.'
    'msmpeng'  = 'This is Microsoft Defender. Windows will usually refuse or restart it.'
}
# File types that are loaded into processes as code (checked against loaded modules).
$Script:ModuleExts = @('.dll', '.exe', '.ocx', '.sys', '.drv', '.cpl', '.node', '.pyd', '.mui', '.winmd')

if (-not ('WhoLocksIt.RestartManager' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace WhoLocksIt {
    public class RmProc {
        public int Pid;
        public string AppName;
        public string ServiceName;
        public int AppType;
    }

    public static class RestartManager {
        [StructLayout(LayoutKind.Sequential)]
        struct RM_UNIQUE_PROCESS {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct RM_PROCESS_INFO {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]  public string strServiceShortName;
            public int ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, StringBuilder strSessionKey);

        [DllImport("rstrtmgr.dll")]
        static extern int RmEndSession(uint pSessionHandle);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
            uint nApplications, RM_UNIQUE_PROCESS[] rgApplications, uint nServices, string[] rgsServiceNames);

        [DllImport("rstrtmgr.dll")]
        static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
            [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);

        const int ERROR_MORE_DATA = 234;

        // Returns every process that Windows reports as using any of the given files.
        public static RmProc[] GetHolders(string[] files) {
            uint session;
            int rc = RmStartSession(out session, 0, new StringBuilder(64));
            if (rc != 0) throw new Win32Exception(rc);

            var result = new List<RmProc>();
            try {
                rc = RmRegisterResources(session, (uint)files.Length, files, 0, null, 0, null);
                if (rc != 0) throw new Win32Exception(rc);

                uint needed = 0, count = 0, reasons = 0;
                RM_PROCESS_INFO[] info = null;
                for (int attempt = 0; attempt < 5; attempt++) {
                    rc = RmGetList(session, out needed, ref count, info, ref reasons);
                    if (rc != ERROR_MORE_DATA) break;
                    count = needed + 8;
                    info = new RM_PROCESS_INFO[count];
                }
                if (rc != 0) throw new Win32Exception(rc);

                if (info != null) {
                    for (int i = 0; i < count; i++) {
                        result.Add(new RmProc {
                            Pid = info[i].Process.dwProcessId,
                            AppName = info[i].strAppName,
                            ServiceName = info[i].strServiceShortName,
                            AppType = info[i].ApplicationType
                        });
                    }
                }
            } finally {
                RmEndSession(session);
            }
            return result.ToArray();
        }
    }

    public class HandleHit {
        public int Pid;
        public string Path;
    }

    public class HandleScanResult {
        public HandleHit[] Hits;
        public int SkippedProcesses;   // processes we were not allowed to inspect
        public int TimedOutHandles;    // handles whose name query hung and was abandoned
        public string CanonicalTarget;
        public string Error;
    }

    // Enumerates every open file/folder handle in the system (like Sysinternals handle.exe)
    // and returns the ones that point at the target or anything below it.
    public static class HandleScanner {
        [DllImport("ntdll.dll")]
        static extern uint NtQuerySystemInformation(int infoClass, IntPtr info, int size, out int returnLength);
        [DllImport("ntdll.dll")]
        static extern uint RtlAdjustPrivilege(int privilege, bool enable, bool currentThread, out bool wasEnabled);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcHandle, IntPtr dstProc, out IntPtr dstHandle,
            uint access, bool inherit, uint options);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")]
        static extern uint GetFileType(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandle(IntPtr h, StringBuilder buf, uint size, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

        const int SystemExtendedHandleInformation = 64;
        const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        const uint PROCESS_DUP_HANDLE = 0x40;
        const uint DUPLICATE_SAME_ACCESS = 2;
        const uint FILE_TYPE_DISK = 1;
        const uint FILE_SHARE_ALL = 7;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        class Scan {
            public long[] Pids;
            public IntPtr[] Handles;
            public Dictionary<long, IntPtr> Procs;
            public string[] Targets;
            public bool IsFolder;
            public List<HandleHit> Hits = new List<HandleHit>();
            public readonly object Lock = new object();
            public int Next, Gen, BusyIndex = -1, BusySince;
            public bool Done;
        }

        static string Normalize(string p) {
            if (p == null) return null;
            if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + p.Substring(8);
            if (p.StartsWith(@"\\?\")) return p.Substring(4);
            return p;
        }

        static string FinalPath(IntPtr h, StringBuilder sb) {
            sb.Length = 0;
            uint len = GetFinalPathNameByHandle(h, sb, (uint)sb.Capacity, 0);
            if (len == 0) return null;
            if (len >= sb.Capacity) {
                sb.EnsureCapacity((int)len + 1);
                len = GetFinalPathNameByHandle(h, sb, (uint)sb.Capacity, 0);
                if (len == 0 || len >= sb.Capacity) return null;
            }
            return Normalize(sb.ToString());
        }

        static bool Matches(string path, string[] targets, bool isFolder) {
            foreach (string t in targets) {
                if (path.Equals(t, StringComparison.OrdinalIgnoreCase)) return true;
                if (isFolder && path.StartsWith(t.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        static void Worker(Scan s, int gen) {
            var sb = new StringBuilder(1024);
            IntPtr self = GetCurrentProcess();
            while (true) {
                int i;
                lock (s.Lock) {
                    if (s.Gen != gen) return;
                    if (s.Next >= s.Pids.Length) { s.Done = true; return; }
                    i = s.Next++;
                    s.BusyIndex = i;
                    s.BusySince = Environment.TickCount;
                }
                string path = null;
                IntPtr dup;
                if (DuplicateHandle(s.Procs[s.Pids[i]], s.Handles[i], self, out dup, 0, false, DUPLICATE_SAME_ACCESS)) {
                    try {
                        // Only real disk files/folders; pipes etc. can block name queries forever.
                        if (GetFileType(dup) == FILE_TYPE_DISK) path = FinalPath(dup, sb);
                    } finally { CloseHandle(dup); }
                }
                lock (s.Lock) {
                    if (s.Gen != gen) return;
                    s.BusyIndex = -1;
                    if (path != null && Matches(path, s.Targets, s.IsFolder))
                        s.Hits.Add(new HandleHit { Pid = (int)s.Pids[i], Path = path });
                }
            }
        }

        public static HandleScanResult Find(string target, bool isFolder) {
            var res = new HandleScanResult { Hits = new HandleHit[0] };
            bool was;
            RtlAdjustPrivilege(20, true, false, out was);   // SeDebugPrivilege, only succeeds when elevated

            // Canonical form of the target (resolves junctions, subst drives, 8.3 names).
            var targets = new List<string> { target.TrimEnd('\\').Length < 3 ? target : target.TrimEnd('\\') };
            var sb = new StringBuilder(1024);
            IntPtr th = CreateFile(target, 0, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (th != INVALID_HANDLE_VALUE) {
                string c = FinalPath(th, sb);
                CloseHandle(th);
                if (c != null) {
                    if (c.Length > 3) c = c.TrimEnd('\\');
                    res.CanonicalTarget = c;
                    if (!targets.Contains(c)) targets.Add(c);
                }
            }

            // Open a directory ourselves so we can learn the object type index used for "File".
            IntPtr probe = CreateFile(Environment.SystemDirectory, 0, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (probe == INVALID_HANDLE_VALUE) { res.Error = "could not open probe handle"; return res; }

            IntPtr buf = IntPtr.Zero;
            try {
                int size = 4 * 1024 * 1024, needed;
                while (true) {
                    buf = Marshal.AllocHGlobal(size);
                    uint st = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, size, out needed);
                    if (st == 0) break;
                    Marshal.FreeHGlobal(buf);
                    buf = IntPtr.Zero;
                    if (st != STATUS_INFO_LENGTH_MISMATCH || size > 1024 * 1024 * 1024) {
                        res.Error = "NtQuerySystemInformation failed: 0x" + st.ToString("X8");
                        return res;
                    }
                    size = Math.Max(size * 2, needed + 1024 * 1024);
                }

                int ptr = IntPtr.Size;
                int entrySize = 3 * ptr + 16;
                long count = Marshal.ReadIntPtr(buf).ToInt64();
                long selfPid = System.Diagnostics.Process.GetCurrentProcess().Id;
                IntPtr basePtr = new IntPtr(buf.ToInt64() + 2 * ptr);

                int fileType = -1;
                for (long i = 0; i < count; i++) {
                    IntPtr e = new IntPtr(basePtr.ToInt64() + i * entrySize);
                    if (Marshal.ReadIntPtr(e, ptr).ToInt64() == selfPid && Marshal.ReadIntPtr(e, 2 * ptr) == probe) {
                        fileType = (ushort)Marshal.ReadInt16(e, 3 * ptr + 6);
                        break;
                    }
                }
                if (fileType < 0) { res.Error = "could not determine the File object type"; return res; }

                var pids = new List<long>();
                var handles = new List<IntPtr>();
                var procs = new Dictionary<long, IntPtr>();
                for (long i = 0; i < count; i++) {
                    IntPtr e = new IntPtr(basePtr.ToInt64() + i * entrySize);
                    if ((ushort)Marshal.ReadInt16(e, 3 * ptr + 6) != fileType) continue;
                    long pid = Marshal.ReadIntPtr(e, ptr).ToInt64();
                    if (pid <= 4 || pid == selfPid) continue;
                    IntPtr ph;
                    if (!procs.TryGetValue(pid, out ph)) {
                        ph = OpenProcess(PROCESS_DUP_HANDLE, false, (int)pid);
                        procs[pid] = ph;
                        if (ph == IntPtr.Zero) res.SkippedProcesses++;
                    }
                    if (ph == IntPtr.Zero) continue;
                    pids.Add(pid);
                    handles.Add(Marshal.ReadIntPtr(e, 2 * ptr));
                }

                var s = new Scan { Pids = pids.ToArray(), Handles = handles.ToArray(), Procs = procs,
                                   Targets = targets.ToArray(), IsFolder = isFolder };
                StartWorker(s, 0);
                var sw = System.Diagnostics.Stopwatch.StartNew();
                while (sw.Elapsed.TotalSeconds < 90) {
                    System.Threading.Thread.Sleep(20);
                    lock (s.Lock) {
                        if (s.Done) break;
                        // A query that hangs is abandoned; a fresh worker continues with the next handle.
                        if (s.BusyIndex >= 0 && Environment.TickCount - s.BusySince > 300) {
                            s.Gen++;
                            s.BusyIndex = -1;
                            res.TimedOutHandles++;
                            StartWorker(s, s.Gen);
                        }
                    }
                }
                lock (s.Lock) {
                    s.Gen++;   // stop any worker still running
                    res.Hits = s.Hits.ToArray();
                }
                // Process handles are intentionally left open: an abandoned worker may still use them.
            } finally {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                CloseHandle(probe);
            }
            return res;
        }

        static void StartWorker(Scan s, int gen) {
            var t = new System.Threading.Thread(() => Worker(s, gen));
            t.IsBackground = true;
            t.Start();
        }
    }
}
'@
}

# --------------------------------------------------------------------------- helpers

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-HandleExe {
    $names = if ([Environment]::Is64BitOperatingSystem) { @('handle64.exe', 'handle.exe') } else { @('handle.exe') }
    foreach ($dir in @($Script:SelfDir, (Join-Path $Script:SelfDir 'tools'))) {
        foreach ($n in $names) {
            $p = Join-Path $dir $n
            if (Test-Path -LiteralPath $p) { return $p }
        }
    }
    foreach ($n in $names) {
        $cmd = Get-Command $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Write-Header {
    Clear-Host
    Write-Host ''
    Write-Host '  ==========================================================' -ForegroundColor DarkCyan
    Write-Host "   WhoLocksIt v$Script:Version  -  who is holding my file / folder?" -ForegroundColor Cyan
    Write-Host '  ==========================================================' -ForegroundColor DarkCyan
    if (Test-IsAdmin) {
        Write-Host '   Mode       : Administrator (full results)' -ForegroundColor Green
    } else {
        Write-Host '   Mode       : Standard user (run as admin for full results)' -ForegroundColor Yellow
    }
    $h = Find-HandleExe
    if ($h) {
        Write-Host "   handle.exe : found ($h)" -ForegroundColor Green
    } else {
        Write-Host '   handle.exe : not found (optional - built-in handle scan is used)' -ForegroundColor DarkGray
    }
    Write-Host ''
}

function Show-Usage {
    Write-Host ''
    Write-Host '  WhoLocksIt - find which process is holding a file, an app or a folder.'
    Write-Host ''
    Write-Host '  Usage:'
    Write-Host '    WhoLocksIt.cmd                     interactive mode (menu + file/folder picker)'
    Write-Host '    WhoLocksIt.cmd "C:\path\to\item"   check this file or folder right away'
    Write-Host '    WhoLocksIt.cmd "C:\path" /list     print holders and exit (no menu)'
    Write-Host ''
    Write-Host '  Exit codes in /list mode: 0 = nothing holds it, 1 = holders found, 2 = error'
    Write-Host '  You can also drag and drop a file or folder onto WhoLocksIt.cmd.'
    Write-Host ''
}

function Resolve-Target([string]$raw, [switch]$Quiet) {
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $p = $raw.Trim().Trim('"').Trim("'").Trim()
    $p = [Environment]::ExpandEnvironmentVariables($p)

    if (-not (Test-Path -LiteralPath $p)) {
        Write-Host "  Path not found: $p" -ForegroundColor Red
        return $null
    }
    $item = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSProvider.Name -ne 'FileSystem') {
        Write-Host "  Not a file or folder on disk: $p" -ForegroundColor Red
        return $null
    }

    # A shortcut (.lnk) is rarely what is locked - offer to inspect what it points to.
    if (-not $item.PSIsContainer -and $item.Extension -ieq '.lnk' -and -not $Quiet) {
        try {
            $lnkTarget = (New-Object -ComObject WScript.Shell).CreateShortcut($item.FullName).TargetPath
        } catch { $lnkTarget = $null }
        if ($lnkTarget -and (Test-Path -LiteralPath $lnkTarget)) {
            Write-Host "  This is a shortcut pointing to: $lnkTarget" -ForegroundColor Yellow
            $a = Read-Host '  Inspect the shortcut target instead? [Y/n]'
            if ($a -notmatch '^(n|no)$') {
                $item = Get-Item -LiteralPath $lnkTarget -Force
            }
        }
    }

    $full = $item.FullName
    if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
    [pscustomobject]@{ Path = $full; IsFolder = [bool]$item.PSIsContainer }
}

function Show-Picker([string]$kind) {
    Add-Type -AssemblyName System.Windows.Forms
    $owner = New-Object System.Windows.Forms.Form
    $owner.TopMost = $true
    try {
        if ($kind -eq 'Folder') {
            $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
            $dlg.Description = 'WhoLocksIt - choose the folder to inspect'
            $dlg.ShowNewFolderButton = $false
            if ($dlg.ShowDialog($owner) -eq 'OK') { return $dlg.SelectedPath }
        } else {
            $dlg = New-Object System.Windows.Forms.OpenFileDialog
            $dlg.Title = 'WhoLocksIt - choose the file or app to inspect'
            $dlg.Filter = 'All files (*.*)|*.*|Programs (*.exe)|*.exe'
            $dlg.DereferenceLinks = $false
            $dlg.CheckFileExists = $true
            if ($dlg.ShowDialog($owner) -eq 'OK') { return $dlg.FileName }
        }
    } finally {
        $owner.Dispose()
    }
    return $null
}

function Read-Target {
    while ($true) {
        Write-Host '  What do you want to inspect?' -ForegroundColor White
        Write-Host '    [1] A file or an app (.exe, .dll, document, video, ...)'
        Write-Host '    [2] A folder (every file inside it is checked too)'
        Write-Host '    [Q] Quit'
        $c = (Read-Host '  Choose').Trim()
        if ($c -match '^(q|quit)$') { return $null }
        if ($c -eq '1') { $kind = 'File' }
        elseif ($c -eq '2') { $kind = 'Folder' }
        else { Write-Host '  Please type 1, 2 or Q.' -ForegroundColor Yellow; Write-Host ''; continue }

        Write-Host ''
        Write-Host "  Paste or type the full path to the $($kind.ToLower())," -ForegroundColor White
        Write-Host '  or just press Enter to open a browse window.' -ForegroundColor White
        $raw = Read-Host '  Path'
        if ([string]::IsNullOrWhiteSpace($raw)) {
            $raw = Show-Picker $kind
            if (-not $raw) { Write-Host '  Cancelled.' -ForegroundColor Yellow; Write-Host ''; continue }
            Write-Host "  Selected: $raw" -ForegroundColor DarkGray
        }

        $t = Resolve-Target $raw
        if (-not $t) { Write-Host ''; continue }
        if ($kind -eq 'File' -and $t.IsFolder) {
            Write-Host '  That path is a folder - it will be inspected as a folder.' -ForegroundColor Yellow
        } elseif ($kind -eq 'Folder' -and -not $t.IsFolder) {
            Write-Host '  That path is a file - it will be inspected as a file.' -ForegroundColor Yellow
        }
        return $t
    }
}

function Test-UnderTarget([string]$path, $target) {
    if ([string]::IsNullOrEmpty($path)) { return $false }
    if ($path.StartsWith('\\?\')) { $path = $path.Substring(4) }
    if ($target.IsFolder) {
        $prefix = $target.Path.TrimEnd('\') + '\'
        return ($path.Equals($target.Path, [StringComparison]::OrdinalIgnoreCase) -or
                $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase))
    }
    return $path.Equals($target.Path, [StringComparison]::OrdinalIgnoreCase)
}

function Get-FolderFiles([string]$root, [int]$max) {
    $files = New-Object System.Collections.Generic.List[string]
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($root)
    $truncated = $false
    while ($stack.Count -gt 0 -and -not $truncated) {
        $dir = $stack.Pop()
        try {
            foreach ($f in [IO.Directory]::GetFiles($dir)) {
                if ($files.Count -ge $max) { $truncated = $true; break }
                $files.Add($f)
            }
        } catch { }
        try {
            foreach ($d in [IO.Directory]::GetDirectories($dir)) {
                # Do not follow junctions / symlinks (avoids loops and leaving the folder).
                try {
                    if (([IO.File]::GetAttributes($d) -band [IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push($d) }
                } catch { }
            }
        } catch { }
    }
    @{ Files = $files.ToArray(); Truncated = $truncated }
}

function Add-Holder($map, [int]$procId, [string]$reason, [switch]$Hint) {
    if ($procId -le 0 -or $Script:ExcludePids -contains $procId) { return }
    if (-not $map.ContainsKey($procId)) {
        $map[$procId] = [pscustomobject]@{
            PID      = $procId
            Name     = $null
            Path     = $null
            Reasons  = New-Object System.Collections.Generic.List[string]
            HintOnly = $true
        }
    }
    $h = $map[$procId]
    if (-not $Hint) { $h.HintOnly = $false }
    if (-not $h.Reasons.Contains($reason)) { $h.Reasons.Add($reason) }
}

# --------------------------------------------------------------------------- detection

function Find-Holders($target) {
    $map   = @{}
    $notes = New-Object System.Collections.Generic.List[string]
    $isAdmin = Test-IsAdmin
    $what = if ($target.IsFolder) { 'folder' } else { 'file' }

    # 1. Process list (also used to fill in names/paths later).
    Write-Host '  [1/4] Reading the process list...' -ForegroundColor DarkGray
    $procs = @{}
    try {
        Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
    } catch {
        $notes.Add("Could not read the process list via WMI: $($_.Exception.Message)")
    }
    # Never report ourselves. The cmd.exe window that launched us has the target on its
    # command line, so it is skipped for command-line hints (but not for real handles).
    $Script:ExcludePids = @([int]$PID)
    $parentPid = -1
    if ($procs.ContainsKey([int]$PID)) { $parentPid = [int]$procs[[int]$PID].ParentProcessId }

    # 2. Restart Manager - the same API installers use to find apps holding files.
    Write-Host '  [2/4] Asking Windows which processes use the file(s)...' -ForegroundColor DarkGray
    if ($target.IsFolder) {
        $scan = Get-FolderFiles $target.Path $Script:MaxFolderFiles
        $files = $scan.Files
        if ($scan.Truncated) {
            $notes.Add("The folder has more than $Script:MaxFolderFiles files - only the first $Script:MaxFolderFiles were checked by Restart Manager.")
        }
    } else {
        $files = @($target.Path)
    }
    $appTypes = @{ 1 = 'app window'; 2 = 'app'; 3 = 'service'; 4 = 'Windows Explorer'; 5 = 'console app'; 1000 = 'critical system process' }
    for ($i = 0; $i -lt $files.Count; $i += $Script:RmChunkSize) {
        $last  = [Math]::Min($i + $Script:RmChunkSize, $files.Count) - 1
        $chunk = [string[]]@($files[$i..$last])
        try {
            foreach ($r in [WhoLocksIt.RestartManager]::GetHolders($chunk)) {
                $reason = if ($target.IsFolder) { 'Has a file inside the folder open' } else { 'Has the file open' }
                if ($r.ServiceName) { $reason += " (service: $($r.ServiceName))" }
                elseif ($appTypes.ContainsKey($r.AppType)) { $reason += " ($($appTypes[$r.AppType]))" }
                Add-Holder $map $r.Pid $reason
            }
        } catch {
            $notes.Add("Restart Manager check failed for some files: $($_.Exception.Message)")
        }
    }

    # 3. Running programs: the target is the app itself, a DLL it loaded, or mentioned on its command line.
    Write-Host '  [3/4] Checking running programs and loaded DLLs...' -ForegroundColor DarkGray
    $rx = '(?i)' + [regex]::Escape($target.Path.TrimEnd('\')) + '(?=$|[\\"''\s,;])'
    foreach ($p in $procs.Values) {
        $procId = [int]$p.ProcessId
        if (Test-UnderTarget $p.ExecutablePath $target) {
            $reason = if ($target.IsFolder) { 'Is a program running from inside the folder' } else { 'Is this program, currently running' }
            Add-Holder $map $procId $reason
        }
        if ($procId -ne $parentPid -and $p.CommandLine -and $p.CommandLine -match $rx) {
            Add-Holder $map $procId 'Its command line mentions the target (hint - may not hold a lock)' -Hint
        }
    }
    $ext = if ($target.IsFolder) { '' } else { [IO.Path]::GetExtension($target.Path).ToLower() }
    if ($target.IsFolder -or $Script:ModuleExts -contains $ext) {
        foreach ($gp in Get-Process) {
            if ($Script:ExcludePids -contains $gp.Id) { continue }
            try { $mods = $gp.Modules } catch { continue }
            if (-not $mods) { continue }
            $exePath = $null
            if ($procs.ContainsKey([int]$gp.Id)) { $exePath = $procs[[int]$gp.Id].ExecutablePath }
            $hits = @($mods | Where-Object { $_.FileName -ne $exePath -and (Test-UnderTarget $_.FileName $target) } |
                      ForEach-Object { $_.ModuleName } | Select-Object -Unique)
            if ($hits.Count -gt 0) {
                $list = ($hits | Select-Object -First 3) -join ', '
                if ($hits.Count -gt 3) { $list += " (+$($hits.Count - 3) more)" }
                Add-Holder $map $gp.Id "Has loaded: $list"
            }
        }
        if (-not $isAdmin) { $notes.Add('Loaded DLLs of elevated / other users'' processes could not be inspected (not admin).') }
    }

    # 4. Open handles - every open file AND folder handle in the system (terminal working
    #    directories, file watchers, apps browsing the folder, ...).
    Write-Host '  [4/4] Scanning all open file and folder handles...' -ForegroundColor DarkGray
    $byPid = @{}
    $scanRes = $null
    try {
        $scanRes = [WhoLocksIt.HandleScanner]::Find($target.Path, $target.IsFolder)
        if ($scanRes.Error) { $notes.Add("Handle scan problem: $($scanRes.Error)") }
        if ($scanRes.CanonicalTarget -and -not $scanRes.CanonicalTarget.Equals($target.Path, [StringComparison]::OrdinalIgnoreCase)) {
            $notes.Add("The target is a link/junction to $($scanRes.CanonicalTarget) - that real location was checked too.")
        }
        foreach ($hit in $scanRes.Hits) {
            $k = [int]$hit.Pid
            if (-not $byPid.ContainsKey($k)) { $byPid[$k] = New-Object System.Collections.Generic.List[string] }
            $byPid[$k].Add($hit.Path)
        }
        if ($scanRes.SkippedProcesses -gt 0 -and -not $isAdmin) {
            $notes.Add("$($scanRes.SkippedProcesses) admin/SYSTEM processes were not scanned for open handles. If nothing above explains the lock, press [E] to re-run as admin.")
        }
    } catch {
        $notes.Add("Handle scan failed: $($_.Exception.Message)")
    }

    # Sysinternals handle.exe (optional extra, admin only) - merged with the scan above.
    $handleExe = Find-HandleExe
    if ($handleExe -and $isAdmin) {
        $out = & $handleExe -accepteula -nobanner $target.Path 2>$null
        foreach ($line in $out) {
            $s = "$line"
            if ($s -match '^(?<name>\S.*?)\s+pid:\s*(?<pid>\d+)\s+type:\s*(?<type>\S+)\s+(?<h>[0-9A-Fa-f]+):\s*(?<path>.+?)\s*$') {
                if (Test-UnderTarget $Matches['path'] $target) {
                    $k = [int]$Matches['pid']
                    if (-not $byPid.ContainsKey($k)) { $byPid[$k] = New-Object System.Collections.Generic.List[string] }
                    $byPid[$k].Add($Matches['path'])
                }
            }
        }
    }

    $roots = @($target.Path.TrimEnd('\'))
    if ($scanRes -and $scanRes.CanonicalTarget) { $roots += $scanRes.CanonicalTarget.TrimEnd('\') }
    foreach ($k in $byPid.Keys) {
        $paths = @($byPid[$k] | Select-Object -Unique)
        $self  = @($paths | Where-Object { $roots -contains $_.TrimEnd('\') })
        $other = @($paths | Where-Object { $roots -notcontains $_.TrimEnd('\') })
        if ($self.Count -gt 0 -and $target.IsFolder) {
            Add-Holder $map $k 'Has the folder itself open (e.g. its working directory or a folder watcher)'
        } elseif ($self.Count -gt 0) {
            Add-Holder $map $k 'Has an open handle to the file'
        }
        if ($other.Count -gt 0) {
            $shown = ($other | Select-Object -First 2) -join '; '
            if ($other.Count -gt 2) { $shown += " (+$($other.Count - 2) more)" }
            Add-Holder $map $k "Open handle: $shown"
        }
    }

    # Fill in names and paths.
    foreach ($h in $map.Values) {
        if ($procs.ContainsKey($h.PID)) {
            $h.Name = $procs[$h.PID].Name
            $h.Path = $procs[$h.PID].ExecutablePath
        } else {
            $gp = Get-Process -Id $h.PID -ErrorAction SilentlyContinue
            if ($gp) { $h.Name = $gp.ProcessName + '.exe'; try { $h.Path = $gp.Path } catch { } }
        }
        if (-not $h.Name) { $h.Name = '<exited or unknown>' }
    }

    $holders = @($map.Values | Sort-Object @{ Expression = 'HintOnly' }, @{ Expression = 'Name' })
    @{ Holders = $holders; Notes = $notes; What = $what }
}

# --------------------------------------------------------------------------- output / actions

function Show-Results($target, $res) {
    $h = $res.Holders
    Write-Host ''
    Write-Host "  Target: $($target.Path)" -ForegroundColor White
    Write-Host ''
    if ($h.Count -eq 0) {
        Write-Host "  Nothing seems to be holding this $($res.What)." -ForegroundColor Green
    } else {
        $real = @($h | Where-Object { -not $_.HintOnly }).Count
        Write-Host "  Found $($h.Count) process(es) ($real confirmed, $($h.Count - $real) hint):" -ForegroundColor Yellow
        Write-Host ''
        for ($i = 0; $i -lt $h.Count; $i++) {
            $x = $h[$i]
            $color = if ($x.HintOnly) { 'Gray' } else { 'White' }
            Write-Host ('  [{0}] {1}   PID {2}' -f ($i + 1), $x.Name, $x.PID) -ForegroundColor $color
            if ($x.Path) { Write-Host "      $($x.Path)" -ForegroundColor DarkGray }
            foreach ($r in $x.Reasons) { Write-Host "      - $r" -ForegroundColor $(if ($x.HintOnly) { 'DarkGray' } else { 'Cyan' }) }
        }
    }
    if ($res.Notes.Count -gt 0) {
        Write-Host ''
        foreach ($n in $res.Notes) { Write-Host "  note: $n" -ForegroundColor DarkYellow }
    }
    Write-Host ''
}

function Stop-Holder($h, [switch]$NoConfirm) {
    $base = [IO.Path]::GetFileNameWithoutExtension([string]$h.Name).ToLower()
    if ($h.PID -le 4 -or $Script:Critical -contains $base) {
        Write-Host "  Refusing to kill $($h.Name) (PID $($h.PID)) - it is a critical Windows process." -ForegroundColor Red
        return $false
    }
    if ($Script:Risky.ContainsKey($base)) { Write-Host "  Warning: $($Script:Risky[$base])" -ForegroundColor Yellow }
    if (-not $NoConfirm) {
        $a = Read-Host "  Kill $($h.Name) (PID $($h.PID))? Unsaved work in it will be lost. [y/N]"
        if ($a -notmatch '^(y|yes)$') { Write-Host '  Skipped.' -ForegroundColor DarkGray; return $false }
    }

    $err = $null
    try { Stop-Process -Id $h.PID -Force -ErrorAction Stop } catch { $err = $_.Exception.Message }
    if ($err) { & taskkill.exe /PID $h.PID /F > $null 2> $null }

    $alive = $true
    for ($t = 0; $t -lt 15; $t++) {
        if (-not (Get-Process -Id $h.PID -ErrorAction SilentlyContinue)) { $alive = $false; break }
        Start-Sleep -Milliseconds 200
    }
    if ($alive) {
        Write-Host "  Could not kill $($h.Name) (PID $($h.PID)). $err" -ForegroundColor Red
        if (-not (Test-IsAdmin)) { Write-Host '  Tip: press [E] to re-run as Administrator and try again.' -ForegroundColor Yellow }
        return $false
    }
    Write-Host "  Killed $($h.Name) (PID $($h.PID))." -ForegroundColor Green

    if ($base -eq 'explorer') {
        Start-Sleep -Seconds 2
        if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
            Write-Host '  Restarting Windows Explorer...' -ForegroundColor DarkGray
            Start-Process explorer.exe
        }
    }
    return $true
}

function Restart-Elevated($target) {
    try {
        if ($target) {
            $p = $target.Path
            if ($p.EndsWith('\')) { $p += '.' }   # "C:\" would escape the closing quote
            Start-Process -FilePath $Script:SelfPath -ArgumentList ('"' + $p + '"') -Verb RunAs -ErrorAction Stop
        } else {
            Start-Process -FilePath $Script:SelfPath -Verb RunAs -ErrorAction Stop
        }
        exit 0
    } catch {
        Write-Host '  Elevation was cancelled or failed.' -ForegroundColor Yellow
    }
}

function Read-Action($hasHolders) {
    $isAdmin = Test-IsAdmin
    $parts = @()
    if ($hasHolders) { $parts += '[K] Kill one', '[A] Kill all' }
    $parts += '[R] Rescan', '[N] New target'
    if (-not $isAdmin) { $parts += '[E] Run as admin' }
    $parts += '[Q] Quit'
    Write-Host ('  ' + ($parts -join '   ')) -ForegroundColor White
    return (Read-Host '  Choose').Trim().ToUpper()
}

# --------------------------------------------------------------------------- main

function Invoke-Main {
    $Host.UI.RawUI.WindowTitle = 'WhoLocksIt'

    if ($env:WL_ARG -match '^(/\?|-h|--help|/help|-\?)$') { Show-Usage; return 0 }

    $target = $null
    if ($env:WL_ARG) {
        $target = Resolve-Target $env:WL_ARG -Quiet:($env:WL_OPT -match '^[/-]list$')
        if (-not $target -and $env:WL_OPT -match '^[/-]list$') { return 2 }
    }

    # Non-interactive mode: WhoLocksIt.cmd "path" /list
    if ($env:WL_OPT -match '^[/-]list$') {
        if (-not $target) { Show-Usage; return 2 }
        $res = Find-Holders $target
        Show-Results $target $res
        if ($res.Holders.Count -gt 0) { return 1 } else { return 0 }
    }

    while ($true) {
        if (-not $target) {
            Write-Header
            $target = Read-Target
            if (-not $target) { return 0 }
        }

        Write-Header
        Write-Host "  Scanning $($target.Path) ..." -ForegroundColor White
        $res = Find-Holders $target
        Write-Header
        Show-Results $target $res
        $holders = $res.Holders

        $next = $null
        while (-not $next) {
            $choice = Read-Action ($holders.Count -gt 0)
            switch ($choice) {
                'K' {
                    if ($holders.Count -eq 0) { break }
                    $sel = Read-Host '  Number(s) to kill, e.g. 1 or 1,3 (Enter = cancel)'
                    $nums = @($sel -split '[,;\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
                    $killed = $false
                    foreach ($n in $nums) {
                        if ($n -lt 1 -or $n -gt $holders.Count) { Write-Host "  No entry [$n]." -ForegroundColor Yellow; continue }
                        if (Stop-Holder $holders[$n - 1]) { $killed = $true }
                    }
                    if ($killed) { Read-Host '  Press Enter to rescan' | Out-Null; $next = 'rescan' }
                }
                'A' {
                    if ($holders.Count -eq 0) { break }
                    Write-Host '  This will kill:' -ForegroundColor Yellow
                    foreach ($x in $holders) { Write-Host "    - $($x.Name) (PID $($x.PID))" -ForegroundColor Yellow }
                    $a = Read-Host '  Kill ALL of them? Unsaved work will be lost. [y/N]'
                    if ($a -match '^(y|yes)$') {
                        foreach ($x in $holders) { Stop-Holder $x -NoConfirm | Out-Null }
                        Read-Host '  Press Enter to rescan' | Out-Null
                        $next = 'rescan'
                    }
                }
                'R' { $next = 'rescan' }
                'N' { $target = $null; $next = 'new' }
                'E' { Restart-Elevated $target }
                'Q' { return 0 }
                default { Write-Host '  Unknown choice.' -ForegroundColor Yellow }
            }
            Write-Host ''
        }
    }
}

try {
    $code = Invoke-Main
    exit ([int]($code | Select-Object -Last 1))
} catch {
    Write-Host ''
    Write-Host "  Unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  at line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -ForegroundColor DarkGray
    Read-Host '  Press Enter to close' | Out-Null
    exit 2
}
