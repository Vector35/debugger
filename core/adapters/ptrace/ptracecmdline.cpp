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


#include "ptracecmdline.h"

namespace BinaryNinjaDebugger {

	std::optional<std::vector<std::string>> ParseCommandLineArguments(const std::string& commandLine)
	{
		enum class Quote
		{
			None,
			Single,
			Double
		};
		Quote quote = Quote::None;
		bool escaped = false;
		bool argumentStarted = false;
		std::string argument;
		std::vector<std::string> arguments;

		for (char ch : commandLine)
		{
			if (escaped)
			{
				escaped = false;
				if (ch == '\n')
					continue;
				if (quote == Quote::Double && ch != '$' && ch != '`' && ch != '"' && ch != '\\')
					argument += '\\';
				argument += ch;
				argumentStarted = true;
				continue;
			}

			if (ch == '\\' && quote != Quote::Single)
			{
				escaped = true;
				argumentStarted = true;
				continue;
			}
			if (ch == '\'' && quote != Quote::Double)
			{
				quote = quote == Quote::Single ? Quote::None : Quote::Single;
				argumentStarted = true;
				continue;
			}
			if (ch == '"' && quote != Quote::Single)
			{
				quote = quote == Quote::Double ? Quote::None : Quote::Double;
				argumentStarted = true;
				continue;
			}
			if ((ch == ' ' || ch == '\t' || ch == '\n') && quote == Quote::None)
			{
				if (argumentStarted)
				{
					arguments.push_back(argument);
					argument.clear();
					argumentStarted = false;
				}
				continue;
			}

			argument += ch;
			argumentStarted = true;
		}

		if (escaped || quote != Quote::None)
			return std::nullopt;
		if (argumentStarted)
			arguments.push_back(argument);
		return arguments;
	}

}  // namespace BinaryNinjaDebugger
