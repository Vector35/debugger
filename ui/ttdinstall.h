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

#pragma once

#ifdef WIN32

	#include <string>
	#include <QString>
	#include <QWidget>

// Helpers for telling the user, before anything fails, that TTD needs the WinDbg/TTD package that Binary Ninja
// downloads for itself. A WinDbg installed from the Microsoft Store or the standalone installer is never used by
// the debugger, which is a very easy assumption to make.

namespace TTDInstall {
	// The pieces of the WinDbg/TTD package that a TTD operation can depend on
	enum Component
	{
		// dbgeng.dll and friends, needed to replay a trace
		ReplayEngine,
		// TTD.exe and TTDRecord.dll, needed to record a trace
		Recorder
	};

	enum ComponentStatus
	{
		// The component is present and usable right now
		ComponentReady,
		// Nothing usable was found, the package has most likely never been downloaded
		ComponentMissing,
		// debugger.x64dbgEngPath is set, but it does not point at a usable package
		ComponentUserPathInvalid,
		// The component is on disk, but it was not picked up when Binary Ninja started
		ComponentNeedsRestart
	};

	// The folder the debugger will load the component from, or an empty string if there is no usable one. This
	// mirrors the resolution done by DbgEngAdapter::GetDbgEngPath().
	std::string GetComponentPath(Component component);

	ComponentStatus GetComponentStatus(Component component);

	// Why the component cannot be used, phrased for the user, or an empty string when it is ready
	QString DescribeUnavailableComponent(Component component);

	// Explains why TTD is not going to work and offers to download the package. Returns true when the component
	// is ready and the caller should carry on with the operation.
	bool EnsureComponentAvailable(QWidget* parent, Component component);

	// Downloads and installs the WinDbg/TTD package, or offers to update it if it is already installed
	void RunInstaller(QWidget* parent);
}

#endif
