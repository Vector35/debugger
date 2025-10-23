# Arch Linux libxml2 Issue - Complete Resolution Guide

## Issue Summary

**Issue #735**: Debugger cannot load properly on Arch Linux due to libxml2.

The Binary Ninja debugger fails to load on Arch Linux because LLDB is dynamically linked against `libxml2.so.2`, which has been replaced by `libxml2.so.16` in recent Arch Linux releases.

## For Users: Immediate Workarounds

If you're experiencing this issue right now, see:
- **[arch-linux-libxml2-workaround.md](arch-linux-libxml2-workaround.md)** - Multiple workaround options with step-by-step instructions

The quickest workaround is:
```bash
sudo ln -s /usr/lib/libxml2.so /usr/lib/libxml2.so.2
```

## For Developers: Understanding the Problem

### Root Cause
- LLDB binaries distributed in lldb-artifacts are dynamically linked against system libraries
- `libxml2.so.2` (old ABI) → `libxml2.so.16` (new ABI) on Arch Linux
- Dynamic linker fails before plugin code executes
- No code-based workaround is possible in the debugger repository

### Why This Can't Be Fixed in the Debugger Repository
1. The issue occurs at the dynamic linker level when loading `libdebuggercore.so`
2. LLDB (not the debugger plugin) is what links against libxml2
3. If library loading fails, no plugin code ever executes
4. The fix must be in the LLDB build process itself

## For Maintainers: Implementing the Permanent Fix

The permanent solution requires building LLDB with statically linked dependencies:

### Quick Start
1. **Read the plan**: [lldb-build-fix-plan.md](lldb-build-fix-plan.md)
2. **Follow the guide**: [lldb-static-linking-guide.md](lldb-static-linking-guide.md)
3. Create an `llvm-build` repository (similar to `qt-build`)
4. Implement the build scripts
5. Publish updated artifacts to `lldb-artifacts`

### Key Requirements
- Build libxml2 from source with static output
- Build editline/libedit from source with static output
- Configure LLDB to link these statically
- Verify no runtime dependencies remain
- Test on multiple Linux distributions

### Expected Outcome
After implementation:
- `ldd liblldb.so | grep libxml2` → no output
- `ldd liblldb.so | grep editline` → no output
- Works on Arch, Ubuntu, Fedora, and other distros without modification
- No user workarounds needed

## Repository Structure

```
docs/
├── arch-linux-libxml2-workaround.md    # User-facing workarounds
├── lldb-build-fix-plan.md               # High-level implementation plan
├── lldb-static-linking-guide.md         # Detailed technical guide
└── README-libxml2-issue.md              # This file
```

## Testing Checklist

When implementing the fix, verify:
- [ ] LLDB binary has no runtime dependency on libxml2
- [ ] LLDB binary has no runtime dependency on editline
- [ ] Debugger loads successfully on Arch Linux
- [ ] Debugger loads successfully on Ubuntu 22.04
- [ ] Debugger loads successfully on Fedora 39
- [ ] Can launch and debug local processes
- [ ] Can attach to running processes
- [ ] Remote debugging works
- [ ] LLDB commands work (including those requiring XML parsing)
- [ ] Command-line editing works (including history)

## Additional Context

### Related Issues
- #147: Missing libncurses and libpanel on Arch Linux (similar packaging issue)
- #238: Feature request: Publish LLDB development builds (resolved)

### Similar Solutions
The `qt-build` repository demonstrates the pattern:
- https://github.com/Vector35/qt-build
- Shows how Vector35 builds and packages dependencies
- Can be used as a template for `llvm-build`

### Upstream References
- LLVM CMake: https://llvm.org/docs/CMake.html
- libxml2: http://www.xmlsoft.org/
- editline: https://github.com/troglobit/editline

## Timeline

1. **Immediate** (Now): Users can apply workarounds
2. **Short-term** (1-2 weeks): Create llvm-build repository and scripts
3. **Medium-term** (2-4 weeks): Test and refine the build process
4. **Long-term** (4+ weeks): Deploy to production, update lldb-artifacts

## Contact

For questions or assistance:
- Open an issue on the debugger repository
- Tag @xusheng6 (issue assignee)
- Reference issue #735

## License

This documentation follows the Apache License 2.0 like the rest of the debugger project.
