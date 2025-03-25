# Corellium Remote Debugging

[Corellium](https://www.corellium.com/) is a leading solution for virtual devices. It exposes a hypervisor-level
debugger that enables the debugging of the entire device. Binary Ninja debugger has a dedicated debug adapter to
connect to it. Below is a guide to set it up.


## Preparation

- Create a virtual device following the Corellium documentation
- In the "Connect" page, download the OpenVPN configuration file and connect to the [VPN](https://support.corellium.com/features/connect/vpn) 
- In the "Connect" page, find the gdb connection string, e.g., `lldb --one-line "gdb-remote 10.11.1.4:4000"`. Take
note of the IP address and port
- Download and install the [Debug Accelerator](https://support.corellium.com/features/connect/debug-accelerator)
- Run `/path/to/debug_accelerator 10.11.1.1:4000 127.0.0.1:4000`, where the first address is the remote ip:port to
connect to, and the second one is a local ip:port to listen on

## Connect to the Debugger from Binary NInja

- In Menu, click "File" -> "Create New Mapped Data"
- In the dialog that pops up, select an architecture that matches your target, which should be `aarch64`
- In Menu, click "Debugger" -> "Connect to Remote Process..."
- In the "Debug Adapter Settings" dialog, Select the `Corellium` adapter 
- Type in the local ip:port that the debug accelerator is operating on, e.g., `127.0.0.1:4000`
- Click "Accept"

Note, the above guide is for the cloud version of Corellium. If you have a
[Desktop Appliance](https://support.corellium.com/environments/desktop-appliance), then you can skip the VPN connection
and the debug accelerator -- the local connection is often times faster without it.

