/*
Copyright 2020-2026 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "ptracesignal.h"
#include <csignal>

namespace BinaryNinjaDebugger {

	BNDebugStopReason StopReasonFromLinuxSignal(int signal)
	{
		// The constants are used instead of numbers, because the numbers of some signals differ between architectures
		switch (signal)
		{
		case SIGHUP:
			return SignalHup;
		case SIGINT:
			return SignalInt;
		case SIGQUIT:
			return SignalQuit;
		case SIGILL:
			return IllegalInstruction;
		case SIGABRT:
			return SignalAbrt;
		case SIGFPE:
			return SignalFpe;
		case SIGKILL:
			return SignalKill;
		case SIGBUS:
			return SignalBus;
		case SIGSEGV:
			return SignalSegv;
		case SIGSYS:
			return SignalSys;
		case SIGPIPE:
			return SignalPipe;
		case SIGALRM:
			return SignalAlrm;
		case SIGTERM:
			return SignalTerm;
		case SIGURG:
			return SignalUrg;
		case SIGSTOP:
			return SignalStop;
		case SIGTSTP:
			return SignalTstp;
		case SIGCONT:
			return SignalCont;
		case SIGCHLD:
			return SignalChld;
		case SIGTTIN:
			return SignalTtin;
		case SIGTTOU:
			return SignalTtou;
		case SIGIO:
			return SignalIo;
		case SIGXCPU:
			return SignalXcpu;
		case SIGXFSZ:
			return SignalXfsz;
		case SIGVTALRM:
			return SignalVtalrm;
		case SIGPROF:
			return SignalProf;
		case SIGWINCH:
			return SignalWinch;
		case SIGUSR1:
			return SignalUsr1;
		case SIGUSR2:
			return SignalUsr2;
#ifdef SIGSTKFLT
		case SIGSTKFLT:
			return SignalStkflt;
#endif
		default:
			return UnknownReason;
		}
	}

}  // namespace BinaryNinjaDebugger
