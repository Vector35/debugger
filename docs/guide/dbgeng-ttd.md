# Time Travel Debugging

Time travel debugging (TTD) allows you to record an execution trace of a program or system and replay it back and forth.
It can speed up the process of reverse engineering/vulnerability research, and deal with certain tasks that are not easy to handle in regular forward debugging.

Several tools implement TTD. As of now, Binary Ninja debugger integrates with the WinDbg/DbgEng TTD so that you can replay and analyze a trace recorded by WinDbg.
The combination of TTD and your familiar reverse engineer tool would hopefully supercharge the ability to time travel and make your workflow even more effective.

Below is a guide to set it up.

## Install WinDbg

There are two ways to install and configure WinDbg to be used by Binary Ninja debugger. 
We recommend you to try the first method first. 
If it does not work, for example if your machine cannot connect to the Internet, you can follow the second method to set it up manually.
The WinDbg installation only needs to be done once.

### Install WinDbg Automatically

- Open Binary Ninja
- Click Menu -> "Debugger" -> "Install WinDbg/TTD"
- Wait for the script to finish
    - Behind the scenes, this runs the Python [script](https://github.com/Vector35/debugger/blob/dev/core/adapters/dbgeng/install_windbg.py) to download and configure WinDbg
    - The WinDbg will be installed to `%APPDATA%\Binary Ninja\windbg`
- Restart Binary Ninja


### Install WinDbg Manually

- Download https://aka.ms/windbg/download
- Open the downloaded AppInstaller file in a text editor. It is an XML file, and look for the download URL of the WinDbg MSIX bundle in it
    - The download URL should look like https://windbg.download.prss.microsoft.com/dbazure/prod/1-2402-24001-0/windbg.msixbundle
- Download the MSIX bundle using the URL found in the above step (this can take longer)
- The downloaded MSIX bundle is a Zip archive. Extract it with a tool like 7Zip
- Find the `windbg_win7-x64.msix` in it. Again it is a Zip archive, extract it
- Find the path of the DbgEng DLLs you have extracted
    - It should be inside the `amd64` folder of where you extracted the `windbg_win7-x64.msix`
    - For example, it can be `C:\Users\XXXXX\Downloads\windbg\windbg_win7-x64\amd64`
    - There should be an x64 version of `dbgeng.dll` in it
- In Binary Ninja, set `debugger.x64dbgEngPath` to the DbgEng DLL path in the last step
- Restart Binary Ninja


## Record a TTD Trace

Once we have installed and configured WinDbg, we can start recording a TTD trace. There are two ways to do it, we can either
do it from within Binary Ninja, or do it from WinDbg. Doing it from Binary Ninja is more convenient, though it does not support
all types of recording supported by WinDbg (e.g., attach to a running process and start recroding).

### Record a TTD Trace in Binary Ninja

- Open the file you wish to trace in Binary Ninja (optional)
- Click Menu -> "Debugger" -> "Install WinDbg/TTD"
- <img src="../../img/debugger/ttd_record.png" width="600px">
- In the "TTD Record" dialog, configure the recording as you wish:
    - Executable Path: the path of the executable to trace
    - Working Directory: the working directory to launch the executable in
    - Command Line Arguments: the command line arguments to pass to the executable
    - Trace Output Directory: the directory to write the trace. By default, it is equal to the working directory, but can be changed if necessary
- Click "Record". A UAC dialog will pop up to because the TTD recording requires Administrator privilege
- Accept the elevation. The program will be launched and recorded. Once it exits, find the trace file in the trace output directory


### Record a TTD Trace in WinDbg

- Find `DbgX.Shell.exe` in the WinDbg installation, run it
- Click `File` -> `Start debugging` -> `Launch Executable (advanced)`
- Select the executable file you wish to record
- Check `Record with Time Travel Debugging`, and click `Debug`
- In the popup dialog, select a folder to save the recorded trace
- Wait for the process to exit, or click `Stop and Debug` when appropriate
- WinDbg then loads the trace and indexes it
    - The index will make it faster to work with the trace
- Close WinDbg
- For other types of recording or the available options, please check out the official guide at
https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-record


## Load the TTD Trace in Binary Ninja Debugger

- Open the .exe or .dll file in Binary Ninja
- Click `Debugger` -> `Debug Adapter Settings`
- For `Adapter Type`, select `DBGENG_TTD`
- For `Executable Path`, select the trace file recorded in the previous step
    - E.g., `C:/Users/xushe/Documents/helloworld01.run`
- Click `Accept`

<img src="../../img/debugger/dbgeng_ttd.png" width="600px">


## Debug the TTD Trace

- Click `Launch` to launch the target
- Most of the debugger functionalities should work in the very same way as a forward debugging
- The control buttons in the debugger sidebar widget shows four new buttons for reverse debugging on the right side:
    - <img src="../../img/debugger/ttd_buttons.png" width="600px">
    - These new buttons are in red color and flipped
    - You can hover over the button to see what they do and the keybindings for them
- You can also control the target using commands in the debugger console. use one of these [commands](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-navigation-commands):
    - g-: go back
    - p-: step over back
    - t-: step into back
    - g-u: step out back
- The [!position](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-extension-positions) command prints the `position` of all active threads
- The [!tt](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-extension-tt) command navigates to a `position` in the trace
    - E.g., `!tt 1A0:12F`
    - While using the debugger, when the target stops, the current position will be printed in the debugger console


## Feedback and Suggestions

The TTD integration in Binary Ninja debugger is still quite new and it may have bugs or lack certain features.
The good news is the debugger is [open-source](https://github.com/Vector35/debugger) and we have a public issue repository for it: [https://github.com/Vector35/debugger/issues/](https://github.com/Vector35/debugger/issues/).
Please feel free to file bug reports, and request new features, either specifically for the TTD or more generally for the debugger. Or even better, join our public [Slack](https://slack.binary.ninja/) and talk to the developers and users!
