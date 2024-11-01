# Debugger

Binary Ninja Debugger is a plugin that can debug executables on Windows, Linux, and macOS, and more!

The debugger plugin is shipped with Binary Ninja. It is [open-source](https://github.com/Vector35/debugger) under an Apache License 2.0. Bug reports and pull requests are welcome!


## UI

[<img src="../../img/debugger/ui.png" width="100%" align="center"/>](../../img/debugger/ui.png)

The debugger UI mainly consists of six parts:

- debugger sidebar
- debugger menu
- global area panels
- debugger status widget
- debugger context menu
- stack variable annotations


### Debugger Sidebar

Clicking the debugger sidebar button (along the left edge of the main window, the one that looks like a bug) will activate the debugger sidebar.

The debugger sidebar contains three widgets: the control buttons, the register widget, and the breakpoint widget.


#### Control Buttons

![](../../img/debugger/controlbuttons.png)

There is a row of buttons at the top of the debugger sidebar. They control the execution of the target. The behavior of each button is hopefully intuitive from its icon. You can also hover over the button to see the name of the icon.

Buttons that do not work for the current target status are disabled. For example: before launching the target, the `Step Into` button is disabled.

A common scenario is to click the left-most button to launch the target and then use the buttons on the right to resume the target, step into/over/return. The `Pause` button can be used to break into the target while it is running.

For `Step Into` and `Step Over`, if the current view is viewing an IL function, then the operation appears to be performed on that IL, offering a source-code debugging-like experience. However, the underlying operation is still performed at the disassembly level because that is the only thing the backend understands. The high-level operations are simulated, i.e., the debugger may decide to step the target multiple times before finally yielding the control. These are transparent to the users.

When the `Attach To Process...` button is clicked, a dialog pops up and shows all the running processes on the system. Selecting one of them and clicking `Attach` will attach to the process.

![](../../img/debugger/attachtopid.png)

#### Register Widget

![](../../img/debugger/registerwidget.png)

Register widget lists registers and their values. A hint column presents anything interesting pointed to by the register. Currently, only strings and pointers to strings are considered. In the future, we would also annotate variables.

Double-clicking a value enters editing mode, and the user can type in new values for the register. The new value is parsed as hex.

The register widget tracks the last seen value of registers and provides visual feedback. Unchanged values are colored white, changed values are colored blue. User-edited values are colored orange.

An experimental feature is added to shorten the list: registers with a value of zero are not shown in the list. To disable it temporarily, right-click and unselect "Hide Unused Registers". 


#### Breakpoint Widget

![](../../img/debugger/breakpointwidget.png)

The breakpoint widget lists breakpoints in the target. There are two columns in it, the left one shows the address in the format of `module + offset`, and the right column shows the absolute address.

The context menu of the widget offers to delete a breakpoint or to jump to the address of a breakpoint.


### Debugger Menu

There is a `Debugger` menu in the main window menu bar.

![](../../img/debugger/debuggermenu.png)

It contains duplicates of the debugger control operations available via icons and also shows the hotkeys bound to those actions.

The `Debug Adapter Settings...` menu item will trigger a `Debug Adapter Settings` dialog:

![](../../img/debugger/adaptersettings.png)

Within this dialog, you can select which DebugAdapter to use, as well as configure debugger settings such as command-line arguments or the working directory.

The `Executable Path` specifies the path of the executable to run, and `Input File` specifies the input file used to create the database. 
These two should be the same if you wish to debug the code in an executable. 
However, if you wish to debug a shared library or DLL, they should be different -- the `Input File` will be the library or DLL you opened in Binary Ninja, while `Executable Path` will be the executable that loads the library or DLL.  

For example, if you wish to debug a `sample.dll` on Windows, then you should open the `sample.dll` in Binary Ninja, and configure the adapter as follows: 

```
Input File: path of sample.dll
Executable Path: C:\Windows\System32\rundll32.exe (or the .exe that loads the DLL)
```

`Run in Seperate Terminal` will cause the target to run in its own terminal, and the debugger will not be able to monitor its `stdout/stderr`, or send input `stdin`.
This is suitable when the target sends complex output, and the debugger's console emulator (which is quite basic now) cannot handle it.

There are several useful actions in the debugger menu that are worth explaining:

1. `Create Stack View` splits the active view and navigates to the stack pointer value in the new pane. Very useful for viewing stack variables.
2. `Jump to IP` navigates to the value of the instruction pointer. This is especially helpful when one explores the binary and wishes to get back to the current instruction.
3. `Override IP` allows changing the instruction pointer value. This is useful when we wish to revert a branch -- simply set the new IP at the other target of the branch. 
The new IP defaults to the currently selected address. A dialog will pop up after clicking this action, which allows confirming and editing the new IP.

![](../../img/debugger/overrideip.png)

### Global Area Panels

The debugger adds four new global area widgets: Target Console (terminal), Debugger Console, Stack Trace, and the Modules List.

#### Target Console

![](../../img/debugger/targetterminal.png)

The `Target Console` panel simulates a terminal for the target. If the process writes to stdout, the content will be printed here. There is an input box at the bottom, and anything entered into it will be sent to the target's stdin.

Due to a backend limitation, this feature only works on macOS and Linux.  On Windows, the target always runs in its own external terminal and all input/output happens there.

On macOS and Linux, the default setting redirects the stdin/stdout here. However, if the user configures the target to run in its terminal (by calling `dbg.request_terminal_emulator = True`), then the stdin/stdout will not be redirected, and need to be accessed in the target's terminal.

#### Debugger Console

![](../../img/debugger/debuggerconsole.png)

The debugger console allows the user to execute backend commands and get the result.

On Linux and macOS, the backend is based on LLDB and the console accepts LLDB commands.

On Windows, the backend is based on Windows Debugger Engine, and it supports WinDbg command syntax. All WinDbg extension command, e.g., `!peb` are also supported.

The console supports resuming the target, e.g., stepping.

Like the Python console, all addresses in the debugger console is clickable -- clicking it navigates to the address.

#### Stack Trace

![](../../img/debugger/stacktracewidget.png)

The stack trace widget lists all the threads along with the stack frames. 

When the target stops, the active thread is expanded and its stack frames are displayed. Stack traces for other threads are collapsed by default and can be expanded from the UI. 

Double-clicking the addresses in the PC (program counter), SP (stack pointer), and FP (frame pointer) column navigates to the address. 

The active thread is marked with `(*)`. Double-clicking another thread will set that as the active thread. As a result, the register widget will show the registers from the new active thread.

![](../../img/debugger/threadwidgetcontextmenu.png)

The context menu offers to suspend and resume each thread individually. A convenience method is offered to make a thread "solo", which suspends all other threads and resumes the thread. Note, resuming the thread does NOT cause the thread to start executing immediately. It only makes the thread execute the next time the target is resumed, e.g., by pressing the `Go` or `Step Over` button. There are some known issues when suspending/resuming individual threads with LLDB adapter.

#### Module Widget

![](../../img/debugger/modulewidget.png)

The module widget shows the start/end address, size, name, and path information of the target's modules.

Double-clicking the addresses navigates to the address.

Note: on macOS 13, the size of system dylib are calculated wrong. The bizarrely huge size is caused by dyld_shared_cache on macOS, which will be addressed in the future.
The size of the main executable is still calculated correctly.


### Debugger Status Widget

![](../../img/debugger/statuswidget.png)

A debugger status widget is added to the main window's status bar. It indicates the current status of the target.

For example, when the target stops, it will include the reason for the stop. When the target exits, the exit code is reported. When an error occurs during certain operations, an error message will also be displayed here.

The widget shows the status of the debugger for the current binary view if a debugging session is active.


### Context menu

![](../../img/debugger/contextmenu.png)

The debugger registers a series of useful actions along with keyboard shortcuts. These shortcuts can be customized using Binary Ninja's keybindings support.

Among these actions, target control actions, e.g., `Run`/`Step Into` have the same effect as the control buttons in the sidebar.

`Toggle Breakpoint` adds a breakpoint at the current location if there is no breakpoint; otherwise, the existing breakpoint is removed.

`Run To Here` lets the target execute until the current line is hit.

[//]: # (`Make Code` is an experimental feature that displays the selected region as code. If the region is indeed code, the user can use `P` to create a function there. Note that we recommend in _most_ situations that `p` be used, or if some code is incorrectly associated with another function, the fix is resolving the reason for that mistake. For example, adding a `No Return` property to a function.

### Stack Variable Annotation

![](../../img/debugger/stackvariable.png)

When the target breaks and a stack trace is available, the debugger annotates the stack variables in the linear view as data variables.

The above image shows the annotated stack with two stack frames. The start and end of each stack frame are marked, and stack variables are defined according to the stack variables in the functions.

To quickly create a split view that views code and stack side-by-side, in the main window menu, click `Debugger`->`Create Stack View`.

Only the stack frames and variables of the current (active) thread are annotated to avoid confusion. If you wish to view stack variables from a different thread, first switch to that thread in the `Stack Trace` global area panel.

The annotation is done only when there are at least two frames in the stack trace. This is a known limitation, and we will address it later.

If the stack variable annotation does not work in certain cases or even causes problems, it can be disabled by setting `debugger.stackVariableAnnotations` to false.


### Other UI Elements

On every line that has a breakpoint, there are two visual indicators:

- the line is highlighted in red
- a red breakpoint tag is added to the left

On the line where the program counter is at, there are two visual indicators:

- the line is highlighted in blue
- a program counter tag (=>) is added to the left


## Design

### Debug Adapters

The goal of the Binary Ninja debugger is to provide a unified way of debugging programs on different platforms (e.g., Windows, Linux, macOS, etc). However, this is not an easy task, because each platform has its own way of supporting debugging and it varies considerably.

To deal with this, we abstract the core functionalities of a debugger into a class `DebugAdapter`. Each debug adapter is a subclass of the `DebugAdapter` with the platform-dependent implementation of each method.

The debugger then **drives** the various adapters, creating a unified debugging experience, both in GUI and API.

Right now, the debugger comes with two debug adapters. The `LLDBAdapter` uses [LLDB](https://lldb.llvm.org/) as its backend and debugs programs on macOS and Linux. The `DbgEngAdapter` uses [Windows debugger engine](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/introduction), and debugs programs on Windows.

New debug adapters can be created by subclassing `DebugAdapter` to support other targets.


### The Debugger Memory Region

Starting from 4.1.5542-dev (0ad6b08b), the debugger no longer involves two binary views during debugging. Instead,
it always uses the incoming binary view (e.g., PE view) that is used to create the controller. Memory regions 
that are not present in the original binary view are represented using the new Memory Map/Region API.

These regions get added automatically when the target is launched, and gets removed after debugging. Analysis is no longer lost after debugging.

During debugging, the binary view reads and writes its memory from the connected `DebugAdapter` backend.
Writing to it will also cause the target's memory to change.

The binary view can be accessed by the ``data`` property of the controller.

## API

The debugger exposes its functionality in both the Python and C++ APIs. The Python documentation can be accessed online, for [stable](https://api.binary.ninja/binaryninja.debugger.debuggercontroller-module.html)
and [dev](https://dev-api.binary.ninja/binaryninja.debugger.debuggercontroller-module.html) version.

The API is centered around the [`DebuggerController`](https://dev-api.binary.ninja/binaryninja.debugger.debuggercontroller-module.html#binaryninja.debugger.debuggercontroller.DebuggerController) class, which provides all functionalities of the debugger. There is no need to directly access the `DebugAdapter` classes.

When the debugger is used within the UI, the `dbg` magic variable is injected into the Python interpreter. It always represents the debugger for the currently active Binary View. You can think of it as being created by

```Python
dbg = DebuggerController(bv)
```

where `bv` is another magic variable that always represents the current BinaryView.

You can simply run `dbg.launch()` in the Python console to launch the target.


## How-to Guide

Here is an incomplete guide on how to get started with the debugger, covering most of the basics on operations in the debugger.


### Launch and Control the Target

There are several ways to launch the target:

- Use the control buttons at the top of the debugger sidebar
- Use the debugger main window menu
- Use the debugger context menu or its keybindings (`F7`, `F8`, etc)
- Run LLDB/WinDbg commands in the debugger console
- Run `dbg.go()`, `dbg.step_into()`, etc. in the Python console.

### Configure Launch Parameters

- Click "Debugger" -> "Launch/Connect Settings..." in the main window menu, and edit parameters in the dialog
- Directly set the value of `dbg.cmd_line`, `dbg.working_directory`, `dbg.working_dir`, etc


### Add/Remove Breakpoints

- Select the line, use the `Toggle Breakpoint` context menu or the debugger main window menu
- Select the line, press `F2` hot key
- Right-click a line in the Breakpoint widget in the sidebar, and select `Remove Breakpoint`
- Run `dbg.add_breakpoint(address)` or `dbg.delete_breakpoint(address)` in the Python console.


### Modify Register Values

- Right-click a value item in the Register widget, type in the new value, and hit enter
- Run `dbg.regs[reg_name] = value` in the Python console
- Run `dbg.set_reg_value(reg_name, value)` in the Python console.


### View/Edit Memory

- Switch to Linear or hex view of the Debugger BinaryView, and view/edit in the normal way
- Get the BinaryView by `dbg.data`, and read/write it in the normal way


### Navigating the binary

- Double-clicking a value in the register widget, modules widget, and thread frames widget navigates to the address. 
Note the 0th (first) frame in the stack frame widget usually contains the program counter and the stack pointer, which is used quite often.
- Clicking an address in the debugger console navigates to the address
- Use the `Jump to IP` action to instantly jump back to the current IP
- Use the `Create Stack View` action to split the view and navigate to the stack pointer in the new pane
- Use register values in the expression parser. We can use `$reg` to refer to the value of a register in the expression parser. 
For example, `$rax` evaluates to the value of the `rax` register. 
We can use `$eip`/`$rip`/`pc` to navigate to the current program counter, or `$esp`/`$rsp`/`sp` to navigate to the current stack pointer.
Thanks to the power of the expression parse, these register values can be combined with other arithmetic operations.
This is especially helpful to quickly navigate to the stack variables since they typically have an address like `$rsp+0x20` or `$rbp-0x8`, which the expression parser can calculate properly:

![](../../img/debugger/expressionparser.png)

### Remote Debugging

See [Remote Debugging Guide](remote-debugging.md)

### Time-travel Debugging

See [Time Travel Debugging Guide](dbgeng-ttd.md)

### Windows Kernel Debugging

See [Windows Kernel Debugging Guide](windows-kd.md)


### Loading Windows Dump Files

- (optional) Open the executable file used to generate the dump
- Open `Debug Adapter Settings` dialog
- Select `WINDOWS_DUMP_FILE` adapter
- Change the executable path to the path of the dump file
- <img src="../../img/debugger/windows_dump_file.png" width="600px">
- Click OK and then launch the target
- These information should be available if they have been recorded in the dump file:
    - Register values
    - Threads and stack traces
    - Memory bytes
- Buttons to resume the target would have no effects


### Debugging without Opening a File

Normally one would first open a file and then start debugging. However, the debugger can also be used without first opening a file.
For example, if you debug a virtual machine or the Windows kernel and do not have a specific module to look at, then there is no motivation to open a file first.
Or, if the file is huge and rebasing it takes too long during the launch, then using the debugger directly can save a lot of time.

Below are the steps to use the debugger without opening a file:

- Create an empty mapped file
    - In menu, click `File`->`New Mapped Data`
    - In the popup dialog, select the architecture and platform of your target
    - Click `Accept`
    - This step is necessary and it would not work on a `Raw` view
- Configure the debugger
    - Open the debugger sidebar
    - Open the debug adapter settings dialog by clicking the right-most button in the control buttons area
    - Select the appropriate debug adapter
    - Set the Executable Path
    - Set other fields as needed
- Start debugging as usual

Please be advised when using the debugger in this way, the debugger would not be able to add the initial breakpoint at
the entry point (because the debugger does not have analysis information about the target). The target will execute on
its own freely. One can set the `debugger.stopAtSystemEntryPoint` setting to true and which will stop the target at a
proper time. 

Note, this does not work if you first create a raw view and then create a mapped view from it -- you must directly create
a mapped view in the above way.


## Running Debug Adapter Backend Commands

Although the debugger already provides UI interfaces for most its functionalities, there are still plenty of features
that do not have a readily available UI. luckily, since we the debugger is using WinDbg/LLDB as backends, we can do
plenty of them by running a backend command directly.

To do so, first find the [`Debugger`](#debugger-console) console in the global area widget, type a command into the
input box, and then press enter.

### Hardware Breakpoints

Hardware breakpoint is very useful and we plan to add better support for it soon. It is tracked by this
[issue](https://github.com/Vector35/debugger/issues/53). For now, we can run a backend command directly to set
hardware breakpoints.

#### WinDbg/DbgEng

For WinDbg/EbgEng, hardware breakpoints can be added using the
[`ba` (break-on-access)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/ba--break-on-access-)
command. It is followed by one of r/w/e to specify the access type, followed by an integer that specifies the size of
the access. For example:

- `ba e1 0x12345678`: add a hardware execution breakpoint at 0x12345678
- `ba r4 0x12345678`: add a four-byte hardware read/write breakpoint at 0x12345678
- `ba w2 0x12345678`: add a two-byte hardware write breakpoint at 0x12345678

#### LLDB

- `breakpoint set --address 0x12345678 -H`: add a hardware execution breakpoint at 0x12345678
- `watchpoint set expression -w read -s 1 -- 0x100003f9f`: add an one-byte hardware read watchpoint at 0x100003f9f
- `watchpoint set expression -w write -s 4 -- 0x100003f9f`: add a four-byte hardware write watchpoint at 0x100003f9f
- The parameter after the `-w` can be `read | write | read_write`
- The parameter after the `-s` can be `1 | 2 | 4 | 8`
- Run `help watchpoint set expression` for more information on setting watchpoints


### Managing Breakpoints

Breakpoints added outside the debugger (i.e., directly with a backend command) are not shown in the breakpoint
widget. We can manage them using backend commands directly.

#### WinDbg/DbgEng

- `bl`: show all the breakpoints
- `bc n`: delete the nth breakpoint
- `bd n`: disable the nth breakpoint
- `be n`: enable the nth breakpoint

#### LLDB

- `breakpoint list`: list all the breakpoints
- `breakpoint delete n`: delete the nth breakpoint
- `breakpoint disable n`: disable the nth breakpoint
- `breakpoint enable n`: enable the nth breakpoint


### View Registers Wider than 8 Bytes

Right now the debugger uses an `uint64_t` to represent a register value, and value wider than that is truncated. Until
we have a proper fix for it, one can run a backend command to view the register value directly.

#### WinDbg/DbgEng

- `r`: show all registers and their values
- `r <register-name>`: read the value of a specific register

#### LLDB

- `reg read -a`: show all registers and their values
- `reg read <register-name>`: read the value of a specific register


### Handle Fork

When a `fork` or `vfork` happens, LLDB folows the parent process by default. To change the behavior, one can run:

- `settings set target.process.follow-fork-mode child`: make LLDB follow the child process during `fork` or `vfork`
- `settings set target.process.follow-fork-mode parent`: make LLDB follow the parent process during `fork` or `vfork`




## Known Issues and Workarounds

There are some known issues and limitations with the current debugger. Here is a list including potential workarounds.

### Administrative Access

Cannot debug binaries that require Administrator (Windows) or root (Linux/macOS). There are two ways to get around it:

- On Windows, run Binary Ninja with Administrator privilege (not recommended).
- Launch the process with necessary privilege, and connect to it using Binary Ninja debugger. See [Remote Debugging Guide](remote-debugging.md) for more details.
    - Must be an admin or in the \_developer group on macOS to debug.
- This is tracked by https://github.com/Vector35/debugger/issues/563

### macOS

- For fat binaries on macOS, the currently viewed architecture will be debugged. For example, if a fat binary contains both x86 and arm code, and the current binary view is x86, then the debugger will debug x86 code in it.
- Cannot debug certain protected applications due to SIP (System Integrity Protection) on macOS. This includes applications in `/Applications`. While this can be circumvented by disabling the SIP, it will pose serious threat to the safety of you device. So we do not recommend it and you will need to proceed with it at your own risk.

### Self-modifying code

If the target contains self-modifying code (SMC), when the target stops, the code in the linear/graph view may not always be up-to-date. To force a memory cache update and re-analysis of the function, right click and select "Reanalyze Current Function" in the context menu.

To avoid the need to manually force an update frequently, set `debugger.aggressiveAnalysisUpdate` to true. Then the debugger will explicitly refresh the memory cache and re-analyze all functions every time the target stops. This is very helpful for obfuscated code with lots of SMC. However, it could cause lag in response if the target is large and has a lot of functions.


### Network Adapter on Windows

On Windows, the debugging sometimes does not work if the machine does not have a network adapter. The reason for this
is yet unknown; the debugger itself does not require a network connection to work. This is probably a bug in WinDbg
itself, or a bug in the way that we use the DbgEng API.

To fix this, just create a network adapter in the VM but do not connect it to any actual network. The presence of a
network adapter is enough for the debugger to work. We will also try to fix the issue in a proper way.


### Slow launching Speed on Windows on Slow Networks

When the DbgEng adapter launches the target, the DbgEng automatically downloads symbols for the loaded DLLs from
the Microsoft symbol server. As a result, if you are on a slow network, the launch can be slow. If you on a network
that has access to the Internet, but not to the Microsoft symbol server in particular, the launch could also hang.
To fix this, disconnect from the network before launching. We will also create a proper fix for it as tracked in
https://github.com/Vector35/debugger/issues/519


### Single-stepping using the API with LLDB Adapter

If you are debugging with the LLDB adapter and using the API to repeatedly single-step the target at a fast pace, you
may run into a case that when you resume the target, instead of resuming the target, LLDB unexpectedly reports the
target is still running and cannot be resumed. Failure to account for this can cause the debugger's internal state to
de-synchronize and later lead to a crash.

We are still working to understand the nature of this unexpected behavior. We highly suspect that this is a timing
related issue in LLDB. Until we have a proper fix for it, please add a tiny wait before you resume the target, e.g., 
add a `time.sleep(0.1)` before `dbg.step_into_and_wait()`, like we do in our debugger unit test
[script](https://github.com/Vector35/debugger/blob/2012056e9c1ece686735ec165d9a1d4f0192ff5d/test/debugger_test.py#L52-L54). 


## Troubleshooting

While we have tested the debugger in many scenarios, it may still malfunction in certain cases. Here are some basic steps to troubleshoot the situation.
If you encounter a bug, please file [an issue](https://github.com/Vector35/debugger/issues) with reproduction steps, and if possible, attach the binary involved.

1. If it crashes Binary Ninja, then it is always considered a bug.
2. If the debugger cannot launch the file properly, first check to make sure the file can be executed directly without a debugger.
3. Try to relaunch Binary Ninja and retry. There could be unintended side effects from previous debugging sessions. Whether it fixes the problem or not, please [file an issue](https://github.com/vector35/debugger/issues).
4. Try to use the LLDB/WinDbg binding that comes with Binary Ninja to debug the file directly. If LLDB/WinDbg can debug it properly, then it is a Binary Ninja issue. Otherwise, it is a bug in the LLDB/WinDbg itself. In both cases, please file an issue and let us know which case it is.
    The LLDB/WinDbg path can be found in the following path:
    - Windows, user installation: %APPDATA%\Binary Ninja\dbgeng\Windows Kits\10\Debuggers\x64\windbg.exe
    - Windows, system installation: %PROGRAMDATA%\Binary Ninja\dbgeng\Windows Kits\10\Debuggers\x64\windbg.exe
    - If the program you are debugging is x86, replace `x64` with `x86` in the above path.
    - Linux: [Binary Ninja Installation folder]/plugins/lldb/bin/lldb
    - macOS: /Applications/Binary Ninja.app/Contents/MacOS/plugins/lldb/bin/lldb


## Open-Source

Vector 35 is grateful for the following open source packages that are used in Binary Ninja debugger:

- [fmt](https://github.com/fmtlib/fmt) ([fmt license](https://github.com/fmtlib/fmt/blob/master/LICENSE) - MIT)
- [pugixml](https://pugixml.org/) ([pugixml license](https://pugixml.org/license.html) - MIT)
- [gdb](https://www.gnu.org/software/gdb) ([GPLv3](https://www.gnu.org/licenses/gpl-3.0.html))
- [lldb](https://lldb.llvm.org/) ([Apache 2.0 License with LLVM exceptions](https://llvm.org/docs/DeveloperPolicy.html#new-llvm-project-license-framework))
