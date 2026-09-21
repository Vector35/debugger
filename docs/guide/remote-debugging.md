# Remote Debugging

## Support Status

Windows user-mode remote debugging is supported from Linux, macOS, and Windows using the **Windows Remote** adapter.
Linux/macOS remote debugging is also supported from all three platforms. The older **DbgEng** remote adapter requires
a Windows client; it is a separate option, not a requirement for Windows Remote.

We also support gdbserver/lldb-server/debugserver remote debugging from all platforms. Targets that expose a GDB stub
that speaks the GDB RSP protocal, e.g., QEMU, VMWare, Qiling, Corellium, are also support from all platforms.


## Debug Server v.s. Remote Process

There are two types of remote debugging: via a `debug server` or a `remote process`.

A remote process is straightforward -- it is a process that runs on the remote host. The debugger connects to it and then debugs it. If you have used `gdbserver` or `debugserver` previously, you probably already know about it.

A debug server is a server that runs on the remote host. The debugger connects to it and can instruct the debug server to launch a process as needed. Then the debugger can connect to the running process and debug it.
One advantage of using a debug server is that the user does not need to access the remote host to launch the target repeatedly—this can be done within the debugger.
Moreover, a debug server often offers more functionalities than launching a remote process. For example, the `lldb-server` supports reading and writing the remote file system, as well as executing shell commands on the remote host.

We recommend using a debug server whenever possible and only use the remote process as a backup.

The `DbgEng` adapter supports debug server mode. `LLDB` and `Windows Remote` support both debug server and remote process modes.

## Windows Remote Debugging

Use **Windows Remote** to debug a Windows user-mode process from Binary Ninja on Linux, macOS, or Windows.
The Windows host runs `windows-debug-server.exe`; Binary Ninja runs on your local machine.

### Preparing the Windows Host and Local Binary

1. Update local Binary Ninja to the latest development build, then download
   [windows-debug-server.zip](https://github.com/Vector35/debugger/releases/latest/download/windows-debug-server.zip)
   and extract it on your Windows VM or remote Windows machine. The standalone server is signed by Vector 35
   and does not require the Microsoft Visual C++ Redistributable. Binary Ninja does not need to be installed on
   the Windows host. Alternatively, copy the signed
   `windows-debug-server.exe` from a matching Binary Ninja Windows package's `plugins` directory.
   These downloads are for the remote server only; update Binary Ninja itself to update your local debugger.
   For building the server yourself, see the repository's
   [build instructions](https://github.com/Vector35/debugger/blob/dev/build.md#windows-remote-debug-server).
2. Put the target executable and its dependencies on the Windows host. Windows Remote does **not** upload them for you.
3. Open a copy of the same executable in local Binary Ninja. Keep the same filename on both machines (for example,
   `hello.exe` on both); the directories may differ. Module matching uses filenames, so renaming only the local copy
   can prevent rebasing and module-relative breakpoints from working.

The server runs on x64 Windows and supports x64 and x86/WOW64 user-mode targets. The initial release has a known
x86/WOW64 **Step Return** unwinding limitation; the Windows Remote integration suite uses x64 targets.
This adapter does not provide Windows kernel debugging, TTD, or reverse execution.

### Starting the Server and Securing the Connection

The connection has no built-in authentication or encryption and gives the client control over debugged processes.
Only use the direct connection below on a trusted network. Do not expose the server to the Internet or an untrusted
network, and restrict inbound access to your debugging machine. As an alternative, you can bind to `127.0.0.1` and
forward the port over SSH for an authenticated, encrypted connection.

On Windows, in PowerShell:

```powershell
.\windows-debug-server.exe server --ip 0.0.0.0 --port 31338
```

`0.0.0.0` listens on all IPv4 interfaces; it is not the address to enter in Binary Ninja. These are also the default
bind address and port. Leave this console running and find the Windows host's IPv4 address (for example, using
`ipconfig`). Allow inbound TCP port 31338 through the Windows firewall **only from your debugging machine**.
Run the server elevated only when the target's privileges require it.

### Connecting and Launching

1. Open **Debugger → Debug Adapter Settings…** and select **Windows Remote**.
2. In the **connect** settings group, set **IP Address** to the Windows host's IPv4 address (not `0.0.0.0`) and **Port**
   to `31338`. The adapter currently expects an IPv4 address, not a hostname. These settings are used
   for Windows Remote's debug server connection, not the `debugServer` settings used by DbgEng/LLDB.
3. In the **launch** group, set **Executable Path** and **Working Directory** to paths on the **Windows host**, such as
   `C:\targets\hello.exe` and `C:\targets`. Set **Command Line Arguments** if needed. Keep the input file pointing to
   the local binary you opened; do not replace it with a remote path.
4. Accept the settings, then choose **Debugger → Connect to Debug Server**. If the settings dialog appears again,
   confirm the adapter and the **connect** values.
5. Launch the target using the debugger's **Launch** action. You can now use breakpoints, stepping, registers, memory,
   threads, and stack views.

The server stays available after a target exits, so you can launch another session without restarting the server.
To attach instead, connect to the debug server first, then choose **Debugger → Attach To Process…** and select a
process on the Windows host. If access is denied, check the server's privileges.

Use **Debugger → Disconnect from Debug Server** to close the connection. This also quits an active target; detach
first if you want to leave it running. Stop the server console with Ctrl+C when finished. Selecting Windows Remote
does not cause a subsequent launch to fall back to local debugging.

### Connecting to a Prelaunched Target (Optional)

For a single target session, start the server in `target` mode instead:

```powershell
.\windows-debug-server.exe target C:\targets\hello.exe --ip 0.0.0.0 --port 31338
```

Use the same trusted-network setup described above. In Binary Ninja select **Windows Remote**, set the
**connect** address to the Windows host's IPv4 address and port to `31338`, then choose
**Debugger → Connect to Remote Process**, not **Connect to Debug Server**.
Restart the server command for each new target-mode session. Use `server` mode when you need launch arguments or
repeated launches from Binary Ninja.

### Troubleshooting

- **Connection fails:** check the server console, IPv4 address, port, and firewall. Use matching client/server
  builds; this protocol is not compatible with `dbgsrv.exe`, `gdbserver`, or `lldb-server`.
- **Launch fails:** verify that the executable, dependencies, and working directory exist on Windows, not just locally.
- **Breakpoints or rebasing fail:** verify that the local and remote files are the same build and have the same basename.
- **Attach fails:** check process permissions and whether another debugger is already attached.

## Windows Remote Debugging with DbgEng (Windows Clients Only)

The following is an alternative for a Windows Binary Ninja client using **DbgEng** and `dbgsrv.exe`.
For a Linux or macOS client, use **Windows Remote** as described above.

### Preparing the Remote Host

- Download or copy the `debugger-win32.zip` from the [release page](https://github.com/Vector35/debugger/releases/latest)
  to the remote host
- Extract it

### Launching the Debug Server

To start a remote debugging session, launch the `dbgsrv.exe` on the remote machine as described below:

- Determine whether the target program is x64 or x86
    - If the target is x64, then use the `dbgsrv.exe` in `debugger-win32\plugins\dbgeng\amd64`
    - If the target is x86, then use the `dbgsrv.exe` in `debugger-win32\plugins\dbgeng\x86`
    - If the version of `dbgsrv.exe` does not match the program, the debugger will behave unexpectedly
- Launch the dbgsrv by running `dbgsrv.exe -t tcp:port=<PORT>,server=<IP_ADDRESS>`
    - `IP_ADDRESS:PORT` is the IP and port the Binary Ninja will later connect to
    - For example, `dbgsrv.exe -t tcp:port=12345,server=192.168.72.25`
    - Note, the `server=` part cannot be omitted.
- If this is done for the first time, the Windows firewall will pop up a confirmation dialog. Allow the operation.
- If the operation succeeds, the `dbgsrv.exe` will keep running in the background. If any error occurs, it will show a
  message box.
- If the target program requires Administrative privilege to run, run `dbgsrv.exe` from a command prompt with
  Administrative privilege


### Connecting to the Debug Server

Now, connect to a debug server in Binary Ninja using DbgEng adapter.

- Open the binary you wish to debug
- Click "Debugger" -> "Connect to Debug Server" in the main window menu bar. The `Debug adapter settings` dialog will
  popup

![](../../img/debugger/debugserver-dbgeng.png)

- Make sure the "DbgEng" adapter is selected
- Navigate to the "debugServer" settings group (if it is not selected by default)
- Type in the `IP Address` and `Port` to connect to
- Click `Accept`. A message box will show up if the connection is successful

Now you can launch or connect to a process on the remote host. It works similarly as if you launch or attach to
a process locally.

### Launching a Process on the Remote Host

- Click "Debugger" -> "Debug Adapter Settings..." in the main window menu bar

<img src="../../img/debugger/remoteadaptersettings.png" width="600px">

- Make sure the "DbgEng" adapter is selected
- Navigate to the "launch" settings group
- Specify the executable path and working directory on the remote machine. This is likely different from the local path
  which is shown by default
- Launch the target

### Attaching to a Process on the Remote Host

- Click "Debugger" -> "Attach To Process..." in the menu bar
- Select the process to attach to
- If the process is not listed, you might need to run `dbgsrv.exe` with Administrator privilege
- Click "Attach" to attach to the process and start debugging

When connected to the debug server, the debugger can launch or connect to a process multiple times using the same
connection. There is no need to relaunch and reconnect to the debug server after the target exits.

To disconnect from the debug server, click "Debugger" -> "Disconnect from Debug Server". After that, if we launch the
target, it will execute on the local machine. Be careful!


## Linux Remote Debugging (Using Debug Server)

This section explains how to remotely debug a process running on Linux. This can be done from all platforms, i.e.,
Windows, Linux, and macOS.

There are two ways to do Linux remote debugging, i.e., using a debug server or a remote process. Debug server is the
recommended way. However, if it does not work for you, you can try using the remote process approach or using
`gdbserver`, which are documented later.

### Preparing the Remote Host

- Download or copy `debugger-linux.zip` from the [release page](https://github.com/Vector35/debugger/releases/latest) 
  to the remote host
- Extract it
- One can also use the `lldb-server` that can be installed via a package manager. However, it may have compatibility
  issues.

### Launching the Debug Server

- `cd debugger-linux/plugins/lldb`
- `./lldb-server p --server --listen 0.0.0.0:31337`

Specifying `0.0.0.0` instructs lldb-server to listen on all interfaces. You can also specify a particular IP address of
an interface that the Binary Ninja debugger will later connect to.


### Connecting to the Debug Server

- Open the binary you wish to debug
- Click "Debugger" -> "Connect to Debug Server" in the main window menu bar. The `Debug adapter settings` dialog will
popup

![](../../img/debugger/debugserver-lldb.png)

- Navigate to the "debugServer" settings group (if it is not selected by default)
- Type in the `IP Address` and `Port` to connect to
- Select `remote-linux` in the `Platform` dropdown menu
- Click `Accept`. A message box will show up if the connection is successful

### Launching a Process on the Remote Host

- Click "Launch", and the `Debug Adapter Settings` dialog will popup
- Navigate to the "launch" settings group (if it is not selected by default)
- Set the `Working Directory` to the *remote* directory that you wish to launch the process in. Do not leave the path
  unchanged since it will then be a local path, and there will be an error during launch.
- Do NOT change the `Executable Path` to a remote path. Set it to the local path where the executable is in. During
  launch, LLDB will copy the executable to the remote host, put it in the working directory we supplied above, and
  launch it. Setting a remote path here will cause errors. LLDB is smart enough to check the hash of the file so that it
  will only copy the file once.
- Configure other parameters as needed
- Launch the target

### Attaching to a Process on the Remote Host

- Click "Debugger" -> "Attach To Process..." in the menu bar
- Select the process to attach to
- If the process is not listed, you might need to run `lldb-server` with sudo
- Click "Attach" to attach to the process

When connected to the debug server, the debugger can launch the executable multiple times using the same connection. There is no need to relaunch and reconnect to the debug server after the target exits.

To disconnect from the debug server, click "Debugger" -> "Disconnect from Debug Server". After that, if we launch the target, it will execute on the local machine. Be careful!



## Linux Remote Debugging (using Remote Process)

If the debug server does not work, you can try Linux remote debugging via the remote process approach. This uses
`lldb-server` in GDB mode and might be simpler to configure.

### Preparing the Remote Host

- Download or copy `debugger-linux.zip` from the [release page](https://github.com/Vector35/debugger/releases/latest)
  to the remote host
- Extract it
- One can also use the `lldb-server` that can be installed via a package manager. However, it may have compatibility
  issues.

### Launching or Attaching to a Remote Process

- `cd debugger-linux/plugins/lldb`
- To launch a new process, run `./lldb-server g 0.0.0.0:31337 -- /path/to/helloworld foo bar`
    - `/path/to/helloworld` is the path of the executable
    - `foo bar` are two arguments
- To attach to a running process by PID, run `./lldb-server g 0.0.0.0:31337 --attach 1234`
    - `1234` is the PID of the target process

Specifying `0.0.0.0` instructs lldb-server to listen on all interfaces. You can also specify a particular IP address of
an interface that the Binary Ninja debugger will later connect to.


### Connecting to the Remote Process

- Open the binary you wish to debug
- Click "Debugger" -> "Connect to Remote Process" in the main window menu bar. The `Debug adapter settings` dialog will
  popup

![](../../img/debugger/remoteprocess-lldb.png)

- Navigate to the "connect" settings group (if it is not selected by default)
- Type in the `IP Address` and `Port` to connect to
- select `gdb-remote` For the `Process Plugin`
- Click `Accept`
- The debugger will now connect to the process launched or attached to in the previous step and start debugging

When using the remote process mode, when the debugging stops (the target exits or gets killed), the connection is
automatically closed. There is no extra steps needed to close the connection.

If you wish to debug the target again, you will need to repeat the steps above to launch or attach to a remote process.





## MacOS Remote Debugging (Using Debug Server)

This section explains how to remotely debug a process running on MacOS. This can be done from all platforms, i.e.,
Windows, Linux, and macOS.

You must use a debug server on macOS. Remote process does not work on macOS.

### Preparing the Remote Host

- Download or copy `debugger-darwin.zip` from the [release page](https://github.com/Vector35/debugger/releases/latest)
  to the remote host
- Extract it


### Launching the Debug Server

- `cd debugger-darwin/plugins/lldb`
- `./lldb-server p --server --listen 0.0.0.0:31337`

Specifying `0.0.0.0` instructs lldb-server to listen on all interfaces. You can also specify a particular IP address of
an interface that Binary Ninja debugger will later connect to.


### Connecting to the Debug Server

- Open the binary you wish to debug
- Click "Debugger" -> "Connect to Debug Server" in the main window menu bar. The `Debug adapter settings` dialog will
  popup

![](../../img/debugger/debugserver-lldb.png)

- Navigate to the "debugServer" settings group (if it is not selected by default)
- Type in the `IP Address` and `Port` to connect to
- Select `remote-macosx` in the `Platform` dropdown menu
- Click `Accept`. A message box will show up if the connection is successful

### Launching a Process on the Remote Host

- Open the `Debug Adapter Settings` dialog
- Set the `Working Directory` to the *remote* directory that you wish to launch the process in. Do not leave the path
  unchanged since it will then be a local path, and there will be an error during launch.
- Do NOT change the `Executable Path` to a remote path. Set it to the local path where the executable is in. During
  launch, LLDB will copy the executable to the remote host, put it in the working directory we supplied above, and
  launch it. Setting a remote path here will cause errors. LLDB is smart enough to check the hash of the file so that it
  will only copy the file once.
- Launch the target

### Attaching to a Process on the Remote Host

- Click "Debugger" -> "Attach To Process..." in the menu bar
- Select the process to attach to
- If the process is not listed, you might need to run `lldb-server` with sudo
- Click "Attach" to attach to the process

When connected to the debug server, the debugger can launch the executable multiple times using the same connection. There is no need to relaunch and reconnect to the debug server after the target exits.

To disconnect from the debug server, click "Debugger" -> "Disconnect from Debug Server". After that, if we launch the target, it will execute on the local machine. Be careful!


## GDB Server Remote Debugging

GDB server is a widely used mechanism for remote debugging. On Linux systems, there is a `gdbserver` executable that can
be installed and executed. Many other projects, e.g., QEMU, also include a gdb stub that speaks the same protocol.

Please note that although the "GDB server" has a "server" in its name, normally it operates as a remote process. In other
words, the debugging is one-shot, that when the target exits, the connection gets closed. If you wish to debug it
again, you need to start the GDB server again.

You can connect to a gdbserver/GDB Stub using either the LLDB adapter or the GDB RSP adatepr.

### Launching GDB Server

- On Linux, to launch a new process, run `gdbserver 0.0.0.0:31337 -- /path/to/helloworld foo bar`
    - `/path/to/helloworld` is the path of the executable
    - `foo bar` are two arguments
- On Linux, to attach to a running process by PID, run `gdbserver 0.0.0.0:31337 --attach 1234`
    - `1234` is the PID of the target process
- For QEMU, add `-s -S` to the command line
    - For example, `qemu-system-x86_64 -drive file=disk.img,format=raw -bios bios.bin -s -S`
    - `-s` starts QEMU with a GDB server listening on TCP port 1234
    - `-S` starts QEMU in a paused state, allowing you to connect with GDB before the virtual CPU starts executing
    - You can specify a different port to listen on by replacing `-s` with `-gdb tcp::port`
- For other tools that also speak the GDB remote debugging protocol, please refer to their documentation on how to
  configure it

Recent versions of the GDB server also support a debug server mode, which can be active using
`gdbserver --multi 0.0.0.0:31337`. However, the Binary Ninja debugger does not yet support connecting to the GDB server in
this mode.


### Connecting to GDB Server (using LLDB adapter)

- Open the binary you wish to debug
- Click "Debugger" -> "Connect to Remote Process" in the main window menu bar. The `Debug adapter settings` dialog will
  popup

![](../../img/debugger/remoteprocess-lldb.png)

- Select `LLDB` as the adapter
- Navigate to the "connect" settings group (if it is not selected by default)
- Type in the `IP Address` and `Port` to connect to
- select `gdb-remote` For the `Process Plugin`
- Click `Accept`


### Connecting to GDB Server (using GDB RSP adapter)

- Open the binary you wish to debug
- Click "Debugger" -> "Connect to Remote Process" in the main window menu bar. The `Debug adapter settings` dialog will
  popup

![](../../img/debugger/remoteprocess-gdbrsp.png)

- Select `GSB RSP` as the adapter
- Navigate to the "connect" settings group (if it is not selected by default)
- Type in the `IP Address` and `Port` to connect to
- Click `Accept`


## iOS Remote Debugging

Binary Ninja debugger supports debugging an iOS app running on a real device or an emulator. The process is
similar to macOS remote debugging, except that we need to run `debugserver` on the device rather than `lldb-server`.

### Preparation

Setting up an iOS device or emulator for debugging is challenging. A step-by-step guide is out of scope here.
We assume the user can already debug an iOS app using the LLDB command line and wish to debug it within the Binary Ninja
debugger.

The high-level steps are:

- Get SSH access to the device. This can be done by either jailbreaking the device or using an emulator
- Extract the `debugserver` executable from the developer disk image that comes with the XCode
- Sign it with a proper entitlements plist to enable it to debug all processes
- Upload the signed `debugserver` to the remote system


### Launching or Attaching to the target

- SSH into the remote host
- To launch a new process, run `./debugserver 0.0.0.0:31337 /path/to/helloworld foo bar`
    - `/path/to/helloworld` is the path of the executable
    - `foo bar` are two arguments
- To attach to a running process by PID, run `./debugserver 0.0.0.0:31337 --attach=1234`
    - `1234` is the PID of the target process


### Connecting to the target

- Open the binary you wish to debug
- Click "Debugger" -> "Connect to Remote Process" in the main window menu bar. The `Debug adapter settings` dialog will
  popup

![](../../img/debugger/remoteprocess-lldb.png)

- Navigate to the "connect" settings group (if it is not selected by default)
- Type in the `IP Address` and `Port` to connect to
- select `debugserver/lldb` For the `Process Plugin`
- Click `Accept`
- The debugger will now connect to the process launched or attached to in the previous step and start debugging





## Android Remote Debugging

Binary Ninja debugger supports debugging an Android app running on a real device or an emulator. The process is
similar to GDB server remote debugging.

### Preparation

Setting up an Android device or emulator for debugging requires a few steps. A step-by-step guide is out of scope here.
We assume the user can already debug an Android app using the GDB command line and wish to debug it within the Binary
Ninja debugger.

The high-level steps are:

- Get SSH access to the device. This can be done by either rooting a real device or using an emulator
- Install the Android NDK on your computer
- Find the `gdbserver` or `gdbserver64` executable in NDK
- Upload it to the remote host


### Launching or Attaching to the target

- SSH into the remote host
- To launch a new process, run `gdbserver 0.0.0.0:31337 -- /path/to/helloworld foo bar`
    - `/path/to/helloworld` is the path of the executable
    - `foo bar` are two arguments
- To attach to a running process by PID, run `gdbserver 0.0.0.0:31337 --attach 1234`
    - `1234` is the PID of the target process


### Connecting to the target

- Open the binary you wish to debug
- Click "Debugger" -> "Connect to Remote Process" in the main window menu bar. The `Debug adapter settings` dialog will
  popup

![](../../img/debugger/remoteprocess-lldb.png)

- Navigate to the "connect" settings group (if it is not selected by default)
- Type in the `IP Address` and `Port` to connect to
- select `gdb-remote` For the `Process Plugin`
- Click `Accept`
