# WhoLocksIt

> Find out **which process is holding a file, an app or a folder** on Windows, and kill it if you want.

Ever seen one of these?

- *"The action can't be completed because the file is open in another program"*
- *"The process cannot access the file because it is being used by another process"*
- *"Folder In Use"* when you try to delete, rename or move something

WhoLocksIt is a single `.cmd` file. Run it, pick the file or folder, and it shows every process that is using it, with an option to kill them.

You don't need to install anything. It works on a clean Windows 10 / 11 with the built-in Windows PowerShell 5.1.

---

## Features

- **File or folder.** For a folder, every file inside it (including subfolders) is checked.
- **Type a path, paste it, or browse.** Press Enter at the path prompt to open a normal Windows file or folder picker.
- **Drag and drop.** Drop a file or folder onto `WhoLocksIt.cmd`.
- **Explains why.** Each process is listed with its PID, its full path and the reason it was found (file open, program running, DLL loaded, open handle).
- **Kill one, several or all.** Every kill asks for confirmation first. Critical Windows processes (`csrss`, `lsass`, `winlogon`, ...) are never killed. If you kill Explorer, it is restarted automatically.
- **Run as admin.** One key re-launches the script elevated, with the same target, so it can see and kill processes that belong to other users or are elevated.
- **Script mode.** `WhoLocksIt.cmd "C:\path" /list` prints the result and exits with a meaningful exit code.
- **Finds folder locks too.** A built-in handle scan (no extra download) catches programs that hold the *folder itself*, for example a terminal or background server whose working directory is that folder (`adb.exe`, `node.exe`, `python.exe`, ...), file watchers, and Explorer windows.
- **Optional Sysinternals `handle.exe` support.** If `handle.exe` is present and you run as admin, its results are merged in as an extra cross-check.

---

## Quick start

1. Download or clone this repository:
   ```bat
   git clone https://github.com/<your-user>/WhoLocksIt.git
   ```
   You can also download just `WhoLocksIt.cmd`. It is self-contained.
2. Double-click **`WhoLocksIt.cmd`**.
3. Choose what to inspect:
   ```
     What do you want to inspect?
       [1] A file or an app (.exe, .dll, document, video, ...)
       [2] A folder (every file inside it is checked too)
       [Q] Quit
   ```
4. Paste the full path, for example `C:\Users\me\Videos\clip.mp4` (quotes are fine). Or just press **Enter** to browse for it.
5. Read the result:
   ```
     Target: C:\Users\me\Videos\clip.mp4

     Found 2 process(es) (2 confirmed, 0 hint):

     [1] vlc.exe   PID 9120
         C:\Program Files\VideoLAN\VLC\vlc.exe
         - Has the file open (app window)
     [2] explorer.exe   PID 6644
         C:\Windows\explorer.exe
         - Has the file open (Windows Explorer)

     [K] Kill one   [A] Kill all   [R] Rescan   [N] New target   [E] Run as admin   [Q] Quit
   ```
6. Press **K** and type the number(s) to kill (`1` or `1,2`). Or press **A** to kill all of them. You are asked to confirm before anything is killed.

> **Tip:** For the most complete results, press **E** (or right-click the file and choose **Run as administrator**). Without admin rights, Windows hides some details about elevated processes and processes that belong to other users.

---

## Usage reference

| Command | What it does |
|---|---|
| `WhoLocksIt.cmd` | Interactive mode: menu, then a path or the picker |
| `WhoLocksIt.cmd "C:\some\file.txt"` | Checks that file right away, then shows the menu |
| `WhoLocksIt.cmd "D:\Projects\MyApp"` | Checks that folder (and everything in it) right away |
| `WhoLocksIt.cmd "C:\some\file.txt" /list` | Prints the holders and exits (no menu, nothing is killed) |
| `WhoLocksIt.cmd /?` | Shows help |
| Drag & drop onto `WhoLocksIt.cmd` | Same as passing the path |

**Exit codes in `/list` mode:** `0` = nothing holds the target, `1` = at least one holder was found, `2` = bad path or error.

```bat
call WhoLocksIt.cmd "C:\build\output.dll" /list >nul
if errorlevel 1 echo Something is still using output.dll
```

### Menu keys (after a scan)

| Key | Action |
|---|---|
| `K` | Kill one or more listed processes (by number, e.g. `2` or `1,3`) |
| `A` | Kill all listed processes (one confirmation for all) |
| `R` | Rescan the same target |
| `N` | Choose a new target |
| `E` | Re-launch as Administrator with the same target (shown only when not admin) |
| `Q` | Quit |

### Optional: add a "Who is locking this?" right-click entry

To add a right-click menu entry for all files and folders, save the text below as `add-context-menu.reg`. Change the path to wherever you keep `WhoLocksIt.cmd`, then double-click the `.reg` file:

```reg
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\*\shell\WhoLocksIt]
@="Who is locking this?"

[HKEY_CURRENT_USER\Software\Classes\*\shell\WhoLocksIt\command]
@="\"C:\\Tools\\WhoLocksIt\\WhoLocksIt.cmd\" \"%1\""

[HKEY_CURRENT_USER\Software\Classes\Directory\shell\WhoLocksIt]
@="Who is locking this?"

[HKEY_CURRENT_USER\Software\Classes\Directory\shell\WhoLocksIt\command]
@="\"C:\\Tools\\WhoLocksIt\\WhoLocksIt.cmd\" \"%1\""
```

On Windows 11 the entry appears under **Show more options**. To remove it, delete the two `WhoLocksIt` keys in `regedit`.

---

## How it works

`WhoLocksIt.cmd` is a batch/PowerShell hybrid. The first few lines are batch, and all they do is start Windows PowerShell and pass it the rest of the file. The detection runs in four steps:

| # | Method | Finds | Needs admin? |
|---|---|---|---|
| 1 | **Process list** (`Win32_Process`) | Names, paths and command lines of running processes | No (more detail with admin) |
| 2 | **Windows Restart Manager API** (`rstrtmgr.dll`) | Processes and services that have the **file** open. This is the same API Windows installers use for "close these apps to continue". | No |
| 3 | **Running programs and loaded modules** | The target **is** a running `.exe`, or a running program was started from inside the target folder, or a process has loaded a DLL from the target | Partly |
| 4 | **Built-in handle scan** (`NtQuerySystemInformation` + `GetFinalPathNameByHandle`) | Every open file **and folder** handle, including a process's working directory and folder watchers. Name queries that hang are abandoned after 300 ms, so the scan can't freeze. | No for your own processes, **yes** for admin/SYSTEM ones |
| + | **Sysinternals `handle.exe`** (optional) | Same as #4, as a cross-check | Yes |

A process whose command line merely mentions the target is shown in gray as a **hint**. It may have opened the file earlier and already closed it.

### Limitations

- **Without admin rights**, handles held by elevated / SYSTEM processes (services, apps you started "as administrator") are not visible. The script tells you how many processes it skipped. Press **E** if nothing it lists explains the lock.
- **Very large folders.** Only the first 20,000 files are checked through Restart Manager. You can change `$Script:MaxFolderFiles` near the top of the script.
- **Without admin rights**, processes owned by other users, services and elevated apps may be missing details, or may not be killable.
- **Protected processes** (antivirus, some system services) cannot be killed even as admin. That is by design in Windows.
- **Network shares.** Locks held by *another computer* on a shared folder are not visible locally. Use `openfiles /query` or *Computer Management → Shared Folders → Open Files* on the server.

### Adding `handle.exe` (optional)

1. Download **Handle** from Microsoft Sysinternals: <https://learn.microsoft.com/sysinternals/downloads/handle>
2. Extract `handle64.exe` (or `handle.exe`) and put it in **one** of these places:
   - next to `WhoLocksIt.cmd`
   - in a `tools\` folder next to it
   - in any folder on your `PATH`
3. Run WhoLocksIt as Administrator. The header shows `handle.exe : found`.

You don't need it for normal use. The built-in handle scan already finds folder locks.

`handle.exe` is **not** included in this repository because Sysinternals tools have their own license. The `.gitignore` keeps it from being committed by accident.

---

## Requirements

- Windows 10 or Windows 11 (Windows 8.1 / Server 2012 R2+ should work too)
- Windows PowerShell 5.1 (built into Windows)
- Optional: Sysinternals Handle for folder-handle detection

---

## Safety

Killing a process is the same as ending it in Task Manager. **Unsaved work in that program is lost.** WhoLocksIt always asks before killing anything, and it refuses to touch processes whose termination would crash or log off Windows. When possible, close the program normally instead.

The script does not download anything, connect to the network or change any system settings. It only reads process information and, if you ask it to, ends processes.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| The window flashes and closes | Run it from a `cmd` window to see the message: `WhoLocksIt.cmd /?` |
| "Running scripts is disabled on this system" | Should not happen, because the script starts PowerShell with `-ExecutionPolicy Bypass` for this run only. If your organisation enforces a policy through Group Policy, ask your admin. |
| Nothing is found but Windows still says the file is in use | Press **E** to run as admin, then **R** to rescan. The lock is probably held by an elevated app or a service. |
| "Folder In Use" and the culprit is `adb.exe`, `node.exe`, `java.exe`, ... | A background server was started from inside that folder and keeps it as its working directory. Kill it (or stop it properly, e.g. `adb kill-server`), and it will start from a neutral folder next time. |
| "Could not kill ..." | Run as admin. If it still fails, the process is protected by Windows. |
| The browse window opened behind the console | Check the taskbar. It is a normal Windows dialog. |
| SmartScreen warns on first run | The file is plain text, so you can open it in Notepad to review it. Then choose *More info → Run anyway*. |

---

## Project layout

```
WhoLocksIt/
├── WhoLocksIt.cmd     # the tool (batch launcher + PowerShell, single file)
├── README.md          # this file
├── LICENSE            # MIT
├── CHANGELOG.md
├── .gitattributes     # keeps CRLF line endings for .cmd (required by cmd.exe)
└── .gitignore         # ignores handle*.exe, logs, editor junk
```

## Contributing

Issues and pull requests are welcome. Please keep the tool a **single, dependency-free file** that runs on stock Windows PowerShell 5.1, which means no PowerShell 7-only syntax (`??`, `?:`, `&&`).

## License

[MIT](LICENSE)
