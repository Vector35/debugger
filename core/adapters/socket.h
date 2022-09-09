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

		socket_type m_socket{};
		[[maybe_unused]] std::int32_t m_addressFamily{}, m_type{}, m_protocol{};
		std::uint32_t m_port{};

	public:
		Socket() = default;

		/* if port is zero it will be bruteforced */
		Socket(std::int32_t address_family, std::int32_t type, std::int32_t protocol, std::uint32_t port = 0)
		: m_addressFamily(address_family), m_type(type), m_protocol(protocol), m_port(port) {

			if (port) {
				this->m_socket = ::socket(address_family, type, protocol);
				SetSocketReusable();
			} else {
				for (std::int32_t index = 31337; index < 31337 + 1024; index++) {
					this->m_socket = ::socket(address_family, type, protocol);
					SetSocketReusable();

					sockaddr_in address{};
					address.sin_family = AF_INET;
					address.sin_addr.s_addr = ::inet_addr("127.0.0.1");
					address.sin_port = htons(index);

					if (this->Bind(address)) {
						this->m_port = index;
						this->Close();
						break;
					}
				}
			}

			if ( !this->m_port )
				throw std::runtime_error("failed to find a usable port");
		}

		void SetSocketReusable()
		{
		#ifndef WIN32
			int reuse = 1;
			if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
				printf("unable to set SO_REUSEADDR");

			if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0)
				printf("unable to set SO_REUSEPORT");
		#else
		// TODO: Windows
		#endif
		}

		[[nodiscard]] std::uint32_t GetPort() const {
			return this->m_port;
		}

		[[nodiscard]] socket_type GetSocket() const {
			return this->m_socket;
		}

		bool Bind(sockaddr_in& address) const {
			return ::bind(this->m_socket, (const sockaddr*)&address, sizeof(address)) >= 0;
		}

		bool Connect(sockaddr_in& address) const {
			return ::connect(this->m_socket, (const sockaddr*)&address, sizeof(address)) >= 0;
		}

		intptr_t Recv(char* data, std::int32_t size, std::int32_t flags = 0) const {
			return ::recv(this->m_socket, data, size, flags);
		}

		intptr_t Send(char* data, std::int32_t size, std::int32_t flags = 0) const {
			return ::send(this->m_socket, data, size, flags);
		}

		bool Close() const {
			return
				#ifdef WIN32
				::closesocket(this->m_socket)
				#else
				::close(this->m_socket)
				#endif
				>= 0;
		}

		bool Kill() const {
			return
				#ifdef WIN32
				::shutdown(this->m_socket, 2) >= 0
				#else
				::shutdown(this->m_socket, SHUT_RDWR) >= 0
				#endif
				&& this->Close();
		}
	};
};
