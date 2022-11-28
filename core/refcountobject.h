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
#endif
#include <stddef.h>
#include <vector>
#include <atomic>

namespace BinaryNinjaDebugger {
	class DbgRefCountObject
	{
		//CORE_ALLOCATED_CLASS(RefCountObject)

	public:
		std::atomic<int> m_refs;
		DbgRefCountObject() : m_refs(0) {}
		virtual ~DbgRefCountObject() {}

		virtual void AddRef() { m_refs.fetch_add(1); }

		virtual void Release()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

		virtual void AddAPIRef() { AddRef(); }

		virtual void ReleaseAPIRef() { Release(); }
	};


	template <class T>
	class DbgRef
	{
		T* m_obj;
#ifdef BN_REF_COUNT_DEBUG
		void* m_assignmentTrace = nullptr;
#endif

	public:
		DbgRef<T>() : m_obj(NULL) {}

		DbgRef<T>(T* obj) : m_obj(obj)
		{
			if (m_obj)
			{
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		DbgRef<T>(const DbgRef<T>& obj) : m_obj(obj.m_obj)
		{
			if (m_obj)
			{
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		~DbgRef<T>()
		{
			if (m_obj)
			{
				m_obj->Release();
#ifdef BN_REF_COUNT_DEBUG
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
			}
		}

		// move constructor
		DbgRef<T>(DbgRef<T>&& other) : m_obj(other.m_obj)
		{
			other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = other.m_assignmentTrace;
#endif
		}

		// move assignment (inefficient in this case)
		// Ref<T>& operator=(Ref<T>&& other)
		// {
		// 	if (m_obj)
		//	{
		//#ifdef BN_REF_COUNT_DEBUG
		//		BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
		//#endif
		//		m_obj->Release();
		//	}
		// 	m_obj = other.m_obj;
		// 	other.m_obj = 0;
		//#ifdef BN_REF_COUNT_DEBUG
		//	m_assignmentTrace = other.m_assignmentTrace;
		//#endif
		// 	return *this;
		// }

		DbgRef<T>& operator=(const DbgRef<T>& obj)
		{
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj.m_obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T* oldObj = m_obj;
			m_obj = obj.m_obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		DbgRef<T>& operator=(T* obj)
		{
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T* oldObj = m_obj;
			m_obj = obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		operator T*() const
		{
			return m_obj;
		}

		T* operator->() const
		{
			return m_obj;
		}

		T& operator*() const
		{
			return *m_obj;
		}

		bool operator!() const
		{
			return m_obj == NULL;
		}

		T* GetPtr() const
		{
			return m_obj;
		}

		bool operator==(const DbgRef<T>& obj) const
		{
			return m_obj == obj.m_obj;
		}

		bool operator!=(const DbgRef<T>& obj) const
		{
			return m_obj != obj.m_obj;
		}

		bool operator<(const DbgRef<T>& obj) const
		{
			return m_obj < obj.m_obj;
		}

		template <typename H>
		friend H AbslHashValue(H h, const DbgRef<T>& value)
		{
			return AbslHashValue(std::move(h), value.m_obj);
		}
	};


	// Macro-like functions to manage referenced objects for the external API
	template <class T>
	static typename T::APIHandle DBG_API_OBJECT_REF(T* obj)
	{
		if (obj == nullptr)
			return nullptr;
		obj->AddAPIRef();
		return obj->GetAPIObject();
	}

	template <class T>
	static typename T::APIHandle DBG_API_OBJECT_REF(const DbgRef<T>& obj)
	{
		if (!obj)
			return nullptr;
		obj->AddAPIRef();
		return obj->GetAPIObject();
	}

	//template <class T>
	//static typename T::APIHandle DBG_API_OBJECT_REF(const APIRef<T>& obj)
	//{
	//	if (!obj)
	//		return nullptr;
	//	obj->AddAPIRef();
	//	return obj->GetAPIObject();
	//}

	template <class T>
	static T* DBG_API_OBJECT_NEW_REF(T* obj)
	{
		if (obj)
			obj->object->AddAPIRef();
		return obj;
	}

	template <class T>
	static void DBG_API_OBJECT_FREE(T* obj)
	{
		if (obj)
			obj->object->ReleaseAPIRef();
	}

};  // namespace BinaryNinjaDebugger
