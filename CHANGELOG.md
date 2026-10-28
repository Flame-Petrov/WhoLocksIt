# Changelog

## 1.1.0 - 2026-10-28

- **Fix:** folders reported as "Folder In Use" by Windows showed "nothing is holding" when
  the lock was a handle to the folder itself (e.g. a process's working directory).
- New built-in handle scan (no `handle.exe` needed) that finds every open file and folder
  handle; hung name queries are abandoned so the scan cannot freeze.
- Junction / subst / 8.3 targets are resolved to their real path and both are checked.
- The launching cmd.exe is no longer hidden from real handle results (only from command-line hints).

## 1.0.0 - 2026-10-28

- First release.
- Interactive menu: choose file or folder, type/paste a path or browse with a picker.
- Drag & drop and command-line path support, `/list` script mode with exit codes.
- Detection via Restart Manager, running executables, loaded modules, command-line hints
  and optional Sysinternals `handle.exe`.
- Kill one / several / all holders with confirmation; critical processes are protected;
  Explorer is restarted automatically.
- Re-launch as Administrator with the same target.
