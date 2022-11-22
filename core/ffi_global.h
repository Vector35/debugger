/*
Copyright 2020-2022 Vector 35 Inc.

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

// Define macros for defining objects exposed by the API
#define DECLARE_DEBUGGER_API_OBJECT(handle, cls) \
	namespace BinaryNinjaDebugger { \
		class cls; \
	} \
	struct handle \
	{ \
		BinaryNinjaDebugger::cls* object; \
	}
#define IMPLEMENT_DEBUGGER_API_OBJECT(handle) \
\
private: \
	handle m_apiObject; \
\
public: \
	typedef handle* APIHandle; \
	handle* GetAPIObject() \
	{ \
		return &m_apiObject; \
	} \
\
private:
#define INIT_DEBUGGER_API_OBJECT() m_apiObject.object = this;
