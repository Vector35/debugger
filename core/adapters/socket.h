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
#include <atomic>
#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#else
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#endif

namespace BinaryNinjaDebugger
{
	class Socket {
		using socket_type =
	#ifdef WIN32
			SOCKET;
	#else
		std::int32_t;
	#endif

		static constexpr socket_type InvalidSocket =
	#ifdef WIN32
			INVALID_SOCKET;
	#else
			-1;
	#endif
		std::atomic<socket_type> m_socket{InvalidSocket};
		[[maybe_unused]] std::int32_t m_addressFamily{}, m_type{}, m_protocol{};
		std::uint32_t m_port{};

	public:
		Socket() = default;
		~Socket() { Close(); }
		Socket(const Socket&) = delete;
		Socket& operator=(const Socket&) = delete;

		[[nodiscard]] bool IsValid() const { return m_socket.load() != InvalidSocket; }

		bool Open(std::int32_t address_family, std::int32_t type, std::int32_t protocol)
		{
			Close();
			m_addressFamily = address_family;
			m_type = type;
			m_protocol = protocol;
			m_socket.store(::socket(address_family, type, protocol));
			if (!IsValid())
				return false;
			SetSocketReusable();
			return true;
		}

		void SetSocketReusable()
		{
		#ifndef WIN32
			int reuse = 1;
			const auto socket = m_socket.load();
			if (socket == InvalidSocket)
				return;
			if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
				printf("unable to set SO_REUSEADDR");

			if (setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0)
				printf("unable to set SO_REUSEPORT");
		#else
		// TODO: Windows
		#endif
		}

		[[nodiscard]] std::uint32_t GetPort() const {
			return this->m_port;
		}

		[[nodiscard]] socket_type GetSocket() const {
			return m_socket.load();
		}

		bool Bind(sockaddr_in& address) const {
			const auto socket = m_socket.load();
			return socket != InvalidSocket && ::bind(socket, (const sockaddr*)&address, sizeof(address)) >= 0;
		}

		bool Connect(sockaddr_in& address) const {
			const auto socket = m_socket.load();
			return socket != InvalidSocket && ::connect(socket, (const sockaddr*)&address, sizeof(address)) >= 0;
		}

		intptr_t Recv(char* data, std::int32_t size, std::int32_t flags = 0) const {
			const auto socket = m_socket.load();
			return socket == InvalidSocket ? -1 : ::recv(socket, data, size, flags);
		}

		intptr_t Send(char* data, std::int32_t size, std::int32_t flags = 0) const {
			const auto socket = m_socket.load();
			return socket == InvalidSocket ? -1 : ::send(socket, data, size, flags);
		}

		bool Close() {
			const auto socket = m_socket.exchange(InvalidSocket);
			if (socket == InvalidSocket)
				return true;
			return
				#ifdef WIN32
				::closesocket(socket)
				#else
				::close(socket)
				#endif
				>= 0;
		}

		bool Kill() {
			const auto socket = m_socket.load();
			if (socket == InvalidSocket)
				return true;
			#ifdef WIN32
			bool shutdownOk = ::shutdown(socket, 2) >= 0;
			#else
			bool shutdownOk = ::shutdown(socket, SHUT_RDWR) >= 0;
			#endif
			return Close() && shutdownOk;
		}
	};
};
