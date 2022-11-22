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

namespace BinaryNinjaDebugger {
	class ConnectionRefusedError : public std::exception
	{
		std::string m_error;

	public:
		ConnectionRefusedError(const std::string& error) : std::exception(), m_error(error) {}
#ifdef __GNUC__
		virtual const char* what() const noexcept
		{
			return m_error.c_str();
		}
#else
		virtual const char* what() const
		{
			return m_error.c_str();
		}
#endif
	};


	class ProcessStartError : public std::exception
	{
		std::string m_error;

	public:
		ProcessStartError(const std::string& error) : std::exception(), m_error(error) {}
#ifdef __GNUC__
		virtual const char* what() const noexcept
		{
			return m_error.c_str();
		}
#else
		virtual const char* what() const
		{
			return m_error.c_str();
		}
#endif
	};


	class NotExecutableError : public std::exception
	{
		std::string m_error;

	public:
		NotExecutableError(const std::string& error) : std::exception(), m_error(error) {}
#ifdef __GNUC__
		virtual const char* what() const noexcept
		{
			return m_error.c_str();
		}
#else
		virtual const char* what() const
		{
			return m_error.c_str();
		}
#endif
	};


	class NotInstalledError : public std::exception
	{
		std::string m_error;

	public:
		NotInstalledError(const std::string& error) : std::exception(), m_error(error) {}
#ifdef __GNUC__
		virtual const char* what() const noexcept
		{
			return m_error.c_str();
		}
#else
		virtual const char* what() const
		{
			return m_error.c_str();
		}
#endif
	};


	class PermissionDeniedError : public std::exception
	{
		std::string m_error;

	public:
		PermissionDeniedError(const std::string& error) : std::exception(), m_error(error) {}
#ifdef __GNUC__
		virtual const char* what() const noexcept
		{
			return m_error.c_str();
		}
#else
		virtual const char* what() const
		{
			return m_error.c_str();
		}
#endif
	};
};  // namespace BinaryNinjaDebugger
