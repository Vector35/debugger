#pragma once

#include "../ffi.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;

namespace BinaryNinjaDebuggerAPI
{
	template <class T>
	class DebuggerObject
	{
		void AddRefInternal()
		{
			m_refs.fetch_add(1);
		}

		void ReleaseInternal()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

	public:
		std::atomic<int> m_refs;
		T* m_object;
		DebuggerObject(): m_refs(0), m_object(nullptr) {}
		virtual ~DebuggerObject() {}

		T* GetObject() const { return m_object; }

		static T* GetObject(DebuggerObject* obj)
		{
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef()
		{
			AddRefInternal();
		}

		void Release()
		{
			ReleaseInternal();
		}

		void AddRefForRegistration()
		{
			AddRefInternal();
		}
	};


	class DebuggerController: public DebuggerObject<BNDebuggerController>
	{
	public:
		DebuggerController(BNDebuggerController* controller);
		static DebuggerController* GetController(BinaryNinja::BinaryView* data);
		Ref<BinaryView> GetLiveView();
		Ref<Architecture> GetRemoteArchitecture();
	};
};
