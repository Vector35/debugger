# Workaround for Arch Linux libxml2 Issue

## Problem

On Arch Linux, LLDB cannot load because it's looking for `libxml2.so.2`, but Arch has moved to `libxml2.so.16`.

Error message:
```
Plugin module 'libdebuggercore.so' failed to load
dlerror() reports: libxml2.so.2: cannot open shared object file: No such file or directory
```

## Temporary Workarounds

### Option 1: Create a Symlink (Recommended)

Create a symbolic link from the new library to the old name:

```bash
sudo ln -s /usr/lib/libxml2.so /usr/lib/libxml2.so.2
```

This works because libxml2.so.16 is backward compatible with the .2 ABI in most cases.

### Option 2: Install Compatibility Package

Install the `libxml2-2.9` AUR package which provides the old version:

```bash
yay -S libxml2-2.9  # or your preferred AUR helper
```

### Option 3: Use LD_PRELOAD

Preload the newer library:

```bash
export LD_PRELOAD=/usr/lib/libxml2.so.16
binaryninja
```

Add this to your `~/.bashrc` or shell startup script to make it permanent.

### Option 4: Build Debugger Locally (Advanced)

If you're comfortable building from source, you can build the debugger locally and link against your system's libxml2:

1. Follow the instructions in `build.md`
2. The build will automatically link against your system's libxml2

## Verifying the Fix

After applying any workaround, verify that the debugger loads correctly:

1. Launch Binary Ninja
2. Open any binary file
3. Click Debugger menu
4. You should not see any error messages about libxml2

## Known Limitations

- The symlink workaround may break if libxml2.so.16 introduces breaking changes (unlikely for a minor version bump)
- Using LD_PRELOAD might affect other applications if set globally

## Permanent Solution

The Vector35 team is working on a permanent fix that will bundle libxml2 and editline with LLDB distributions, eliminating system library dependencies. Track progress in issue #735.

## See Also

- Issue #735: Debugger cannot load properly on arch linux due to libxml2
- Issue #147: Missing libncurses and libpanel on Archlinux (similar issue)
