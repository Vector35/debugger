//**************************************************************************
//
// DbgModelClientEx.h
//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
//
// Debugger Data Model Full C++ Client / Provider
//
// This library is a full C++17 library.  Usage requires compiling with C++17
// enabled.
//
// NOTES:
//
//     The objects here in ClientEx:: and ProviderEx:: are C++ objects and not
//     COM objects.  The COM ABI is hidden inside Details::
//
//**************************************************************************

#pragma once

#ifndef _DBGMODELCLIENTEX_H_
#define _DBGMODELCLIENTEX_H_

#include <memory>
#include <type_traits>
#include <functional>
#include <utility>
#include <locale>
#include <optional>
#include <string>

#ifdef GetObject
#undef GetObject
#endif // GetObject

namespace Debugger
{
namespace DataModel
{
namespace ClientEx
{

namespace Details
{
    template<typename TArg>
    _Ret_z_ const wchar_t *ExtractString(TArg&& str);
}

//**************************************************************************
//**************************************************************************
//
// CLIENT (USAGE) SUPPORT:
//

//**************************************************************************
// Client Provided:
//
// Clients of this library need to provide implementations for these methods.  They
// acquire interfaces to the data model.
//

// GetManager():
//
// Gets the data model manager.
//
IDataModelManager *GetManager();

// GetHost():
//
// Gets the debug host.
//
IDebugHost *GetHost();

//**************************************************************************
// Exception Types:
//
// These (and a select set of std::exception derivatives will convert to HRESULT/error info
// and back
//

// hr_exception:
//
// General exception thrown for HRESULTs which do not specifically map to another std exception type.
//
class hr_exception : public std::exception
{
public:

    hr_exception(_In_ HRESULT hr, _In_ const std::string& msg) : std::exception(msg.c_str()), m_hr(hr) { }
    hr_exception(_In_ HRESULT hr, _In_z_ const char* pMsg) : std::exception(pMsg), m_hr(hr) { }
    HRESULT hr() const { return m_hr; }

private:

    HRESULT m_hr;

};

class object_detached : public std::runtime_error
{
public:

    using runtime_error::runtime_error;
    object_detached() : runtime_error("Attempt to access a detached object") { }
};

class not_implemented : public std::logic_error
{
public:

    using logic_error::logic_error;
    not_implemented() : not_implemented("Not implemented") { }
};

class unexpected_error : public std::runtime_error
{
public:

    using runtime_error::runtime_error;
    unexpected_error() : runtime_error("Unexpected error") { }
};

class illegal_operation : public std::runtime_error
{
public:

    using runtime_error::runtime_error;

};

class not_set : public std::runtime_error
{
public:

    using runtime_error::runtime_error;
    not_set() : not_set("Not set") { }
};

//*************************************************
// String Helpers:
//

namespace Details
{
    // BSTRDeleter:
    //
    // A deletion functor which deletes a BSTR returned from the model.
    //
    struct BSTRDeleter
    {
        void operator()(_In_z_ wchar_t *pwsz)
        {
            SysFreeString(reinterpret_cast<BSTR>(pwsz));
        }
    };
}

// bstr_ptr:
//
// A unique_pointer over a BSTR which deletes it with the appropriate SysFreeString call.
//
using bstr_ptr = std::unique_ptr<wchar_t, Details::BSTRDeleter>;

//**************************************************************************
// Exceptions and Conversion:
//

using namespace Microsoft::WRL;

namespace Details
{
    // StringUtils:
    //
    // String helpers:
    //

    struct StringUtils
    {
        static std::string GetNarrowString(_In_z_ const wchar_t *pString)
        {
            std::string str;
            int sz = WideCharToMultiByte(CP_ACP, 0, pString, static_cast<int>(wcslen(pString)), nullptr, 0, nullptr, nullptr);
            if (sz == 0)
            {
                return str;
            }
            str.resize(sz);
            char *pData = const_cast<char *>(str.data()); // @TODO: C++17 should have a non-const overload
            int sz2 = WideCharToMultiByte(CP_ACP, 0, pString, static_cast<int>(wcslen(pString)), pData, sz, nullptr, nullptr);
            if (sz != sz2)
            {
                throw unexpected_error();
            }
            return str;
        }

        static std::wstring GetWideString(_In_z_ const char *pString)
        {
            std::wstring str;
            int sz = MultiByteToWideChar(CP_ACP, 0, pString, static_cast<int>(strlen(pString)), nullptr, 0);
            if (sz == 0)
            {
                return str;
            }
            str.resize(sz);
            wchar_t *pData = const_cast<wchar_t *>(str.data()); // @TODO: C++17 should have a non-const overload
            int sz2 = MultiByteToWideChar(CP_ACP, 0, pString, static_cast<int>(strlen(pString)), pData, sz);
            if (sz != sz2)
            {
                throw unexpected_error();
            }
            return str;
        }
    };
    // Exceptions:
    //
    // Exception helpers:
    //

    struct Exceptions
    {
        //*************************************************
        // Conversion From HRESULT to Exception:
        //

        static void ThrowHr(_In_ HRESULT hr, _In_opt_ IModelObject *pError = nullptr)
        {
            std::string msg;

            if (pError != nullptr)
            {
                //
                // If the data model produced a specific error message, pack it into the exception which
                // is thrown.
                //
                BSTR bstrMsg;
                bstr_ptr spMsg;

                ComPtr<IStringDisplayableConcept> spStrConv;
                if (SUCCEEDED(pError->GetConcept(__uuidof(IStringDisplayableConcept), &spStrConv, nullptr)) &&
                    SUCCEEDED(spStrConv->ToDisplayString(pError, nullptr, &bstrMsg)))
                {
                    spMsg.reset(bstrMsg);
                    msg = StringUtils::GetNarrowString(reinterpret_cast<const wchar_t *>(bstrMsg));
                }
            }

            switch(hr)
            {
                case E_INVALIDARG:
                case DISP_E_TYPEMISMATCH:
                    throw std::invalid_argument(msg);

                case E_OUTOFMEMORY:
                    throw std::bad_alloc();

                case E_BOUNDS:
                    throw std::range_error(msg);

                case E_NOTIMPL:
                    throw not_implemented(msg);

                case E_UNEXPECTED:
                    throw unexpected_error(msg);

                case E_ILLEGAL_METHOD_CALL:
                    throw illegal_operation(msg);

                case E_NOT_SET:
                    throw not_set(msg);

                default:
                    throw hr_exception(hr, msg);
            }
        }

        //*************************************************
        // Conversion From Exception to HRESULT
        //

        static HRESULT ReturnResult(_In_ const std::exception_ptr& exception, _COM_Errorptr_opt_ IModelObject **ppError = nullptr)
        {
            HRESULT hr = E_FAIL;
            std::wstring errMsg;
            try
            {
                std::rethrow_exception(exception);
            }
            catch(std::invalid_argument& invalidArg)
            {
                hr = E_INVALIDARG;
                errMsg = StringUtils::GetWideString(invalidArg.what());
            }
            catch(std::bad_alloc& /*badAlloc*/)
            {
                hr = E_OUTOFMEMORY;
            }
            catch(std::range_error& rangeError)
            {
                hr = E_BOUNDS;
                errMsg = StringUtils::GetWideString(rangeError.what());
            }
            catch(not_implemented& notImplemented)
            {
                hr = E_NOTIMPL;
                errMsg = StringUtils::GetWideString(notImplemented.what());
            }
            catch(unexpected_error& unexpectedError)
            {
                hr = E_UNEXPECTED;
                errMsg = StringUtils::GetWideString(unexpectedError.what());
            }
            catch(hr_exception& hrError)
            {
                hr = hrError.hr();
                errMsg = StringUtils::GetWideString(hrError.what());
            }
            catch(illegal_operation& illegalOperation)
            {
                hr = E_ILLEGAL_METHOD_CALL;
                errMsg = StringUtils::GetWideString(illegalOperation.what());
            }
            catch(not_set& notSet)
            {
                hr = E_NOT_SET;
                errMsg = StringUtils::GetWideString(notSet.what());
            }
            catch(std::exception& exc)
            {
                hr = E_FAIL;
                errMsg = StringUtils::GetWideString(exc.what());
            }
            catch(...)
            {
                hr = E_FAIL;
            }

            if (ppError != nullptr && !errMsg.empty())
            {
                ComPtr<IModelObject> spError;
                if (SUCCEEDED(GetManager()->CreateErrorObject(hr, errMsg.c_str(), &spError)))
                {
                    *ppError = spError.Detach();
                }
            }

            return hr;
        }
    };
} // Details

//**************************************************************************
// Client Helpers:
//

// CheckHr():
//
// If the inpassed HRESULT indicates failure, this throws an exception based on the HRESULT
//
inline void CheckHr(_In_ HRESULT hr)
{
    if (FAILED(hr))
    {
        Details::Exceptions::ThrowHr(hr, nullptr);
    }
}

// CheckHr():
//
// If the inpassed HRESULT indicates failure, this throws an exception based on the HRESULT
// with extended error information out of which the exception message will be acquired.
//
inline void CheckHr(_In_ HRESULT hr, _In_ const ComPtr<IModelObject>& potentialError)
{
    if (FAILED(hr))
    {
        Details::Exceptions::ThrowHr(hr, potentialError.Get());
    }
}

// AssertCondition():
//
// This asserts that condition is true
//
inline void AssertCondition(_In_ bool condition)
{
    // Without the if (!condition) we are getting
    // a compiler error of unused parameter condition on x86fre builds
    if (!condition)
    {
#ifdef NT_ASSERT
        NT_ASSERT(condition);
#endif // NT_ASSERT
    }
}

// AssertHr():
//
// This asserts that hr succeeds
//
inline void AssertHr(_In_ HRESULT hr)
{
    AssertCondition(SUCCEEDED(hr));
}

// GetHostAs():
//
// Gets the debug host as a particular interface.  Throws if it cannot.
//
template<typename TInterface>
ComPtr<TInterface> GetHostAs()
{
    ComPtr<TInterface> spInterface;
    CheckHr(GetHost()->QueryInterface(IID_PPV_ARGS(&spInterface)));
    return spInterface;
}

//**************************************************************************
// Forward Declarations:
//

class Object;
class Metadata;
class Symbol;
class Module;
class Type;
class Field;
class BaseClass;

template<typename T> Object BoxObject(_In_ T&& obj);
template<typename T> decltype(auto) UnboxObject(_In_ const Object& src);

//**************************************************************************
// Basic Wrappers (Type System, Other Symbolic Access, Contexts, etc...):
//

// symbol_cast:
//
// Convert from a generic symbol to a more specific symbol with type checking.
//
template<typename TDestSymbol>
TDestSymbol symbol_cast(_In_ IDebugHostSymbol *pSymbol)
{
    if (!TDestSymbol::IsInstance(pSymbol))
    {
        throw std::bad_cast();
    }

    ComPtr<typename TDestSymbol::SymbolTypeInterface> spDerivedSymbolInterface;
    CheckHr(pSymbol->QueryInterface(IID_PPV_ARGS(&spDerivedSymbolInterface)));
    return TDestSymbol(std::move(spDerivedSymbolInterface));
}

template<typename TDestSymbol> TDestSymbol symbol_cast(_In_ const ComPtr<IDebugHostSymbol>& spSymbol) { return symbol_cast<TDestSymbol>(spSymbol.Get()); }
template<typename TDestSymbol> TDestSymbol symbol_cast(_In_ const Symbol& src);

namespace Details
{
    // SymbolChildrenRef:
    //
    // Returned from Children() (or another such method) to represent all (or a subset of) children of
    // a given symbol.
    //
    template<typename TSymParent, typename TSymChild>
    class SymbolChildrenRef
    {
    private:

        // SymbolIterator():
        //
        // A C++ input iterator for the children of a symbol
        //
        class SymbolIterator
        {
        public:

            using value_type = TSymChild;
            using reference = TSymChild;
            using pointer = const TSymChild *;
            using difference_type = size_t;
            using iterator_category = std::input_iterator_tag;

            SymbolIterator() : m_pos(0) { }

            SymbolIterator(_In_ IDebugHostSymbolEnumerator *pChildEnum) : SymbolIterator(pChildEnum, 0) { }

            SymbolIterator(_In_ IDebugHostSymbolEnumerator *pChildEnum, _In_ size_t pos) :
                m_spEnum(pChildEnum),
                m_pos(pos)
            {
                MoveForward();
            }

            SymbolIterator(_In_ const SymbolIterator& rhs) =default;
            SymbolIterator(SymbolIterator&& rhs) =default;
            SymbolIterator& operator=(_In_ const SymbolIterator& rhs) =default;
            SymbolIterator& operator=(SymbolIterator&& rhs) =default;

            bool operator==(_In_ const SymbolIterator& rhs)
            {
                return (m_value.GetSymbolInterface() == rhs.m_value.GetSymbolInterface() && m_pos == rhs.m_pos);
            }

            bool operator!=(_In_ const SymbolIterator& rhs)
            {
                return !operator==(rhs);
            }

            value_type operator*() const
            {
                return m_value;
            }

            pointer operator->() const
            {
                return &m_value;
            }

            SymbolIterator operator++()
            {
                MoveForward();
                return *this;
            }

            SymbolIterator operator++(int)
            {
                SymbolIterator cur = *this;
                MoveForward();
                return cur;
            }

        private:

            void MoveForward()
            {
                ComPtr<IDebugHostSymbol> spSym;
                HRESULT hr = m_spEnum->GetNext(&spSym);
                if (SUCCEEDED(hr))
                {
                    m_value = symbol_cast<value_type>(std::move(spSym));
                    ++m_pos;
                }
                else if (hr != E_BOUNDS)
                {
                    CheckHr(hr);
                }
                else
                {
                    m_value = value_type { };
                    m_pos = 0;
                }
            }

            ComPtr<IDebugHostSymbolEnumerator> m_spEnum;
            value_type m_value;
            size_t m_pos;

        };

    public:

        using iterator = SymbolIterator;

        SymbolChildrenRef(_In_ const TSymParent& sym, SymbolKind enumKind) :
            m_sym(sym),
            m_enumKind(enumKind)
        {
        }

        // operator[]:
        //
        // Returns a child symbol.
        //
        TSymChild operator[](_In_z_ const wchar_t *childName) const
        {
            ComPtr<IDebugHostSymbolEnumerator> spEnum;
            CheckHr(m_sym->EnumerateChildren(m_enumKind, childName, &spEnum));

            ComPtr<IDebugHostSymbol> spSym;
            CheckHr(spEnum->GetNext(&spSym));

            ComPtr<IDebugHostSymbol> spNext;
            if (SUCCEEDED(spEnum->GetNext(&spNext)))
            {
                //
                // The result is ambiguous.  Bail out.
                //
                throw std::runtime_error("The symbol name is not unique");
            }

            TSymChild childSymbol = symbol_cast<TSymChild>(std::move(spSym));
            return childSymbol;
        }

        TSymChild operator[](_In_ const std::wstring& fieldName) const
        {
            if (fieldName.empty())
            {
                throw std::invalid_argument("Invalid fieldName");
            }
            return operator[](fieldName.c_str());
        }

        iterator begin() const
        {
            ComPtr<IDebugHostSymbolEnumerator> spEnum;
            CheckHr(m_sym->EnumerateChildren(m_enumKind, nullptr, &spEnum));
            return iterator(spEnum.Get());
        }

        iterator end() const
        {
            return iterator();
        }

    private:

        TSymParent m_sym;
        SymbolKind m_enumKind;

    };

    // GenericArgumentsRef:
    //
    // Returned from GenericArguments() to represent a collection of the generic arguments of a given type.
    //
    template<typename TSym>
    class GenericArgumentsRef
    {
    private:

        // GenericArgumentsIterator():
        //
        // A C++ input iterator for the generic arguments of a symbol
        //
        class GenericArgumentsIterator
        {
        public:

            using value_type = TSym;
            using reference = TSym;
            using pointer = const TSym *;
            using difference_type = size_t;
            using iterator_category = std::input_iterator_tag;

            GenericArgumentsIterator() : m_pos(0) { }

            GenericArgumentsIterator(_In_ IDebugHostType *pType) : GenericArgumentsIterator(pType, 0) { }

            GenericArgumentsIterator(_In_ IDebugHostType *pType, _In_ size_t pos) :
                m_spType(pType),
                m_pos(pos)
            {
                MoveForward();
            }

            GenericArgumentsIterator(_In_ const GenericArgumentsIterator& rhs) =default;
            GenericArgumentsIterator(GenericArgumentsIterator&& rhs) =default;
            GenericArgumentsIterator& operator=(_In_ const GenericArgumentsIterator& rhs) =default;
            GenericArgumentsIterator& operator=(GenericArgumentsIterator&& rhs) =default;

            bool operator==(_In_ const GenericArgumentsIterator& rhs)
            {
                if (m_value.GetSymbolInterface() == nullptr && rhs.m_value.GetSymbolInterface() == nullptr)
                {
                    return true;
                }
                else return (m_spType.Get() == rhs.m_spType.Get() &&
                             m_value.GetSymbolInterface() == rhs.m_value.GetSymbolInterface() &&
                             m_pos == rhs.m_pos);
            }

            bool operator!=(_In_ const GenericArgumentsIterator& rhs)
            {
                return !operator==(rhs);
            }

            value_type operator*() const
            {
                return m_value;
            }

            pointer operator->() const
            {
                return &m_value;
            }

            GenericArgumentsIterator operator++()
            {
                MoveForward();
                return *this;
            }

            GenericArgumentsIterator operator++(int)
            {
                GenericArgumentsIterator cur = *this;
                MoveForward();
                return cur;
            }

        private:

            void MoveForward()
            {
                ULONG64 genericCount;
                CheckHr(m_spType->GetGenericArgumentCount(&genericCount));

                if (m_pos >= genericCount)
                {
                    m_value = value_type { };
                    m_pos = 0;
                }
                else
                {
                    ComPtr<IDebugHostSymbol> spSym;
                    CheckHr(m_spType->GetGenericArgumentAt(m_pos, &spSym));
                    m_value = std::move(spSym);
                    ++m_pos;
                }
            }

            ComPtr<IDebugHostType> m_spType;
            value_type m_value;
            size_t m_pos;

        };

    public:

        using iterator = GenericArgumentsIterator;

        GenericArgumentsRef(_In_ IDebugHostType *pType) :
            m_spType(pType)
        {
        }

        // size():
        //
        // The size of the list of generic parameters.
        //
        size_t size() const
        {
            ULONG64 argCount;
            CheckHr(m_spType->GetGenericArgumentCount(&argCount));
            return static_cast<size_t>(argCount);
        }

        // operator[]:
        //
        // Returns the n-th generic argument.
        //
        TSym operator[](_In_ size_t n) const
        {
            ComPtr<IDebugHostSymbol> spSym;
            CheckHr(m_spType->GetGenericArgumentAt(n, &spSym));
            TSym value = std::move(spSym);
            return value;
        }

        iterator begin() const
        {
            return iterator(m_spType.Get());
        }

        iterator end() const
        {
            return iterator();
        }

    private:

        ComPtr<IDebugHostType> m_spType;

    };

    // ArrayDimensionsRef:
    //
    // Returned from ArrayDimensions() to represent a collection of the array dimensions.
    //
    class ArrayDimensionsRef
    {
    private:

        // ArrayDimensionsIterator():
        //
        // A C++ input iterator for the dimensions of an array
        //
        class ArrayDimensionsIterator
        {
        public:

            using value_type = ArrayDimension;
            using reference = ArrayDimension;
            using pointer = const ArrayDimension *;
            using difference_type = size_t;
            using iterator_category = std::input_iterator_tag;

            ArrayDimensionsIterator() : m_pArrayDimensions(nullptr), m_dimsCount(0), m_pos(0) { }

            ArrayDimensionsIterator(_In_ ULONG64 dimsCount,
                                    _In_reads_(dimsCount) pointer pArrayDimensions) :
                                    ArrayDimensionsIterator(dimsCount, pArrayDimensions, 0) { }

            ArrayDimensionsIterator(_In_ ULONG64 dimsCount,
                                    _In_reads_(dimsCount) pointer pArrayDimensions,
                                    _In_ ULONG64 pos) :
                m_dimsCount(dimsCount),
                m_pArrayDimensions(pArrayDimensions),
                m_pos(pos)
            {
                MoveForward();
            }

            ArrayDimensionsIterator(_In_ const ArrayDimensionsIterator& rhs) =default;
            ArrayDimensionsIterator(ArrayDimensionsIterator&& rhs) =default;
            ArrayDimensionsIterator& operator=(_In_ const ArrayDimensionsIterator& rhs) =default;
            ArrayDimensionsIterator& operator=(ArrayDimensionsIterator&& rhs) =default;

            bool operator==(_In_ const ArrayDimensionsIterator& rhs)
            {
                return (m_dimsCount == rhs.m_dimsCount &&
                        m_pArrayDimensions == rhs.m_pArrayDimensions &&
                        m_pos == rhs.m_pos);
            }

            bool operator!=(_In_ const ArrayDimensionsIterator& rhs)
            {
                return !operator==(rhs);
            }

            value_type operator*() const
            {
                return m_value;
            }

            pointer operator->() const
            {
                return &m_value;
            }

            ArrayDimensionsIterator operator++()
            {
                MoveForward();
                return *this;
            }

            ArrayDimensionsIterator operator++(int)
            {
                ArrayDimensionsIterator cur = *this;
                MoveForward();
                return cur;
            }

        private:

            void MoveForward()
            {
                if (m_pos >= m_dimsCount)
                {
                    m_value = value_type { };
                    m_dimsCount = 0;
                    m_pArrayDimensions = nullptr;
                    m_pos = 0;
                }
                else
                {
                    m_value = m_pArrayDimensions[static_cast<size_t>(m_pos)];
                    ++m_pos;
                }
            }

            ULONG64 m_dimsCount;
            pointer m_pArrayDimensions;
            ULONG64 m_pos;
            value_type m_value;
        };

    public:

        using iterator = ArrayDimensionsIterator;

        ArrayDimensionsRef(_In_ IDebugHostType *pType) :
            m_spType(pType)
        {
            CheckHr(m_spType->GetArrayDimensionality(&m_dimsCount));
            m_spDims.reset(new ArrayDimension[static_cast<size_t>(m_dimsCount)]);
            CheckHr(m_spType->GetArrayDimensions(m_dimsCount, m_spDims.get()));
        }

        // size():
        //
        // The size of the list of dimensions.
        //
        size_t size() const { return static_cast<size_t>(m_dimsCount); }

        // operator[]:
        //
        // Returns the n-th generic argument.
        //
        ArrayDimension operator[](_In_ size_t n) const
        {
            if (n >= m_dimsCount)
            {
                CheckHr(E_BOUNDS);
            }
            return m_spDims[n];
        }

        iterator begin() const
        {
            return iterator(m_dimsCount, m_spDims.get());
        }

        iterator end() const
        {
            return iterator();
        }

    private:

        ComPtr<IDebugHostType> m_spType;
        ULONG64 m_dimsCount;
        std::unique_ptr<ArrayDimension[]> m_spDims;

    };

    // ParameterTypesRef:
    //
    // Returned from ParameterTypes() to represent a collection of the parameter types for a function type.
    //
    template<typename TSym>
    class ParameterTypesRef
    {
    private:

        // ParameterTypesIterator():
        //
        // A C++ input iterator for the parameter types of a function
        //
        class ParameterTypesIterator
        {
        public:

            using value_type = TSym;
            using reference = TSym;
            using pointer = const TSym *;
            using difference_type = size_t;
            using iterator_category = std::input_iterator_tag;

            ParameterTypesIterator() : m_pos(0) { }

            ParameterTypesIterator(_In_ IDebugHostType *pType) : ParameterTypesIterator(pType, 0) { }

            ParameterTypesIterator(_In_ IDebugHostType *pType, _In_ size_t pos) :
                m_spType(pType),
                m_pos(pos)
            {
                MoveForward();
            }

            ParameterTypesIterator(_In_ const ParameterTypesIterator& rhs) =default;
            ParameterTypesIterator(ParameterTypesIterator&& rhs) =default;
            ParameterTypesIterator& operator=(_In_ const ParameterTypesIterator& rhs) =default;
            ParameterTypesIterator& operator=(ParameterTypesIterator&& rhs) =default;

            bool operator==(_In_ const ParameterTypesIterator& rhs)
            {
                return (m_value.GetSymbolInterface() == rhs.m_value.GetSymbolInterface() && m_pos == rhs.m_pos);
            }

            bool operator!=(_In_ const ParameterTypesIterator& rhs)
            {
                return !operator==(rhs);
            }

            value_type operator*() const
            {
                return m_value;
            }

            pointer operator->() const
            {
                return &m_value;
            }

            ParameterTypesIterator operator++()
            {
                MoveForward();
                return *this;
            }

            ParameterTypesIterator operator++(int)
            {
                ParameterTypesIterator cur = *this;
                MoveForward();
                return cur;
            }

        private:

            void MoveForward()
            {
                ULONG64 paramCount;
                CheckHr(m_spType->GetFunctionParameterTypeCount(&paramCount));

                if (m_pos >= paramCount)
                {
                    m_value = value_type { };
                    m_pos = 0;
                }
                else
                {
                    ComPtr<IDebugHostType> spType;
                    CheckHr(m_spType->GetFunctionParameterTypeAt(m_pos, &spType));
                    m_value = std::move(spType);
                    ++m_pos;
                }
            }

            ComPtr<IDebugHostType> m_spType;
            value_type m_value;
            size_t m_pos;

        };

    public:

        using iterator = ParameterTypesIterator;

        ParameterTypesRef(_In_ IDebugHostType *pType) :
            m_spType(pType)
        {
        }

        // size():
        //
        // The size of the list of parameter types.
        //
        size_t size() const
        {
            ULONG64 paramCount;
            CheckHr(m_spType->GetFunctionParameterTypeCount(&paramCount));
            return static_cast<size_t>(paramCount);
        }

        // operator[]:
        //
        // Returns the n-th parameter type.
        //
        TSym operator[](_In_ size_t n) const
        {
            ComPtr<IDebugHostType> spType;
            CheckHr(m_spType->GetFunctionParameterTypeAt(n, &spType));
            TSym value = std::move(spType);
            return value;
        }

        iterator begin() const
        {
            return iterator(m_spType.Get());
        }

        iterator end() const
        {
            return iterator();
        }

    private:

        ComPtr<IDebugHostType> m_spType;

    };
}


// HostContext:
//
// Represents a host context (information about what session/process/etc... an object
// comes from)
//
class HostContext
{
public:

    HostContext() : m_isDeferred(false) { }

    HostContext(_In_ IDebugHostContext *pHostContext)
    {
        m_isDeferred = (pHostContext == USE_CURRENT_HOST_CONTEXT);
        if (!m_isDeferred)
        {
            m_spHostContext = pHostContext;
        }
    }

    HostContext(_In_ const ComPtr<IDebugHostContext>& spHostContext) : m_spHostContext(spHostContext), m_isDeferred(false) { }
    HostContext(_In_ ComPtr<IDebugHostContext>&& spHostContext) : m_spHostContext(std::move(spHostContext)), m_isDeferred(false) { }
    HostContext(_In_ const HostContext& src) : m_spHostContext(src.m_spHostContext), m_isDeferred(src.m_isDeferred) { }
    HostContext(_In_ HostContext&& src) : m_spHostContext(std::move(src.m_spHostContext)), m_isDeferred(src.m_isDeferred) { }

    HostContext& operator=(_In_ const HostContext& src) { m_spHostContext = src.m_spHostContext; m_isDeferred = src.m_isDeferred; return *this; }
    HostContext& operator=(_In_ HostContext&& src) { m_spHostContext = std::move(src.m_spHostContext); m_isDeferred = src.m_isDeferred; return *this; }

    operator IDebugHostContext* () const
    {
        if (m_isDeferred) { return USE_CURRENT_HOST_CONTEXT; }
        return m_spHostContext.Get();
    }

    IDebugHostContext* operator->() const
    {
        CheckObject();
        return (IDebugHostContext *)(*this);
    }

    // Current():
    //
    // Returns the current context of the host.
    //
    static HostContext Current()
    {
        ComPtr<IDebugHostContext> spContext;
        CheckHr(GetHost()->GetCurrentContext(&spContext));
        HostContext contextObject = std::move(spContext);
        return contextObject;
    }

    // DeferredCurrent():
    //
    // Returns an object that refers to the current context of the host *when used*.
    //
    static HostContext DeferredCurrent()
    {
        return HostContext(USE_CURRENT_HOST_CONTEXT);
    }

protected:

    bool m_isDeferred;
    ComPtr<IDebugHostContext> m_spHostContext;

    void CheckObject() const
    {
        if (m_spHostContext.Get() == nullptr)
        {
            throw unexpected_error();
        }
    }
};

// Symbol:
//
// Class for a generic symbol.  In addition to being the base class for more specific symbol types
// (e.g.: Types, Modules, Fields, etc...), this can be instantiated over top any such symbol for base symbol
// functionality.
//
class Symbol
{
public:

    using SymbolTypeInterface = IDebugHostSymbol;

    // IsInstance():
    //
    // Returns whether a given generic symbol actually refers (and can be converted) to a module.
    //
    static bool IsInstance(_In_ const Symbol& /*symbol*/)
    {
        return true;
    }

    static bool IsInstance(_In_ IDebugHostSymbol * /*pSymbol*/)
    {
        return true;
    }

    //*************************************************
    // General Symbol Methods:
    //

    Symbol() =default;
    Symbol(_In_ IDebugHostSymbol *pSymbol) : m_spSymbol(pSymbol) { }
    Symbol(_In_ ComPtr<IDebugHostSymbol> spSymbol) : m_spSymbol(std::move(spSymbol)) { }
    Symbol(_In_ const Symbol& src) =default;
    Symbol(_In_ Symbol&& src) =default;

    Symbol& operator=(_In_ IDebugHostSymbol *pSymbol) { AssignSymbol(pSymbol); return *this; }
    Symbol& operator=(_In_ ComPtr<IDebugHostSymbol> spSymbol) { MoveSymbol(std::move(spSymbol)); return *this; }
    Symbol& operator=(_In_ const Symbol& src) { AssignSymbol(src.m_spSymbol.Get()); return *this; }
    Symbol& operator=(_In_ Symbol&& src) { MoveSymbol(std::move(src.m_spSymbol)); return *this; }

    operator IDebugHostSymbol* () const { return m_spSymbol.Get(); }
    IDebugHostSymbol *operator->() const { return m_spSymbol.Get(); }

    // operator==/!=():
    //
    // Compares two symbols for equality (not equivalence).  Two different typedefs to the same type
    // will still not compare equally.
    //
    bool operator==(_In_ const IDebugHostSymbol *pOtherSymbol) const
    {
        if (m_spSymbol.Get() == pOtherSymbol) { return true; }
        if (IsEmpty() || pOtherSymbol == nullptr) { return false; }

        bool result;
        CheckHr(m_spSymbol->CompareAgainst(const_cast<IDebugHostSymbol *>(pOtherSymbol), 0, &result));
        return result;
    }
    bool operator==(_In_ const Symbol& otherSymbol) const
    {
        if (m_spSymbol.Get() == otherSymbol.m_spSymbol.Get()) { return true; }
        if (IsEmpty() || otherSymbol.IsEmpty()) { return false; }

        bool result;
        CheckHr(m_spSymbol->CompareAgainst(otherSymbol, 0, &result));
        return result;
    }

    bool operator!=(_In_ const IDebugHostSymbol *pOtherSymbol) const
    {
        return !operator==(pOtherSymbol);
    }
    bool operator!=(_In_ const Symbol& otherSymbol) const
    {
        return !operator==(otherSymbol);
    }

    // IsEmpty():
    //
    // Indicates whether there is an underlying type or not.
    //
    bool IsEmpty() const { return m_spSymbol.Get() == nullptr; }

    // SymbolKind():
    //
    // Gets the kind of symbol that this is.
    //
    SymbolKind SymbolKind() const
    {
        ::SymbolKind kind;
        CheckHr(m_spSymbol->GetSymbolKind(&kind));
        return kind;
    }

    // GetSymbolInterface():
    //
    // Gets the underlying interface for the symbol.
    //
    IDebugHostSymbol *GetSymbolInterface() const
    {
        return m_spSymbol.Get();
    }

    // Name():
    //
    // Gets the name of the symbol.
    //
    std::wstring Name() const
    {
        CheckObject();

        BSTR name;
        CheckHr(m_spSymbol->GetName(&name));
        bstr_ptr spName(name);
        return std::wstring(name);
    }

    // Type():
    //
    // Gets the type of the symbol (if such has a type; an exception is thrown otherwise)
    //
    Type Type() const;

    // ContainingModule():
    //
    // Gets the containing module of the symbol.
    //
    Module ContainingModule() const;

    // Children():
    //
    // Returns a collection of all of the children of this symbol.
    //
    Details::SymbolChildrenRef<Symbol, Symbol> Children() const
    {
        CheckObject();
        return Details::SymbolChildrenRef<Symbol, Symbol>(*this, SymbolKind::Symbol);
    }

    // Language():
    //
    // Returns the language in which the symbol is defined.  This may often return LanguageUnknown.
    //
    LanguageKind Language() const
    {
        CheckObject();
        ComPtr<IDebugHostSymbol2> spSymbol2;
        CheckHr(m_spSymbol.As(&spSymbol2));
        LanguageKind lang;
        CheckHr(spSymbol2->GetLanguage(&lang));
        return lang;
    }

protected:

    void AssignSymbol(_In_ IDebugHostSymbol *pSymbol)
    {
        CheckSymbol(pSymbol);
        m_spSymbol = pSymbol;
    }

    void MoveSymbol(_In_ ComPtr<IDebugHostSymbol>&& srcSymbol)
    {
        CheckSymbol(srcSymbol.Get());
        m_spSymbol = std::move(srcSymbol);
    }

    // VerifySymbol():
    //
    // Verifies that the given symbol can legally be assigned to the given instance.  Derived classes
    // must type check the symbol.
    //
    virtual bool VerifySymbol(_In_ IDebugHostSymbol * /*pSymbol*/) noexcept
    {
        return true;
    }

    void CheckObject() const
    {
        if (m_spSymbol.Get() == nullptr)
        {
            throw unexpected_error();
        }
    }

private:

    void CheckSymbol(_In_ IDebugHostSymbol *pSymbol)
    {
        if (pSymbol != nullptr && !VerifySymbol(pSymbol))
        {
            throw std::bad_cast();
        }
    }

    // Depending on the symbol, this *MAY* hold something which is IDebugHostSymbol derived.
    ComPtr<IDebugHostSymbol> m_spSymbol;

};

// SymbolWithOffset:
//
// A symbol paired with an offset from that symbol.
//
typedef std::pair<Symbol, ULONG64> SymbolWithOffset;

// Module:
//
// Represents a module object.
//
class Module : public Symbol
{
public:

    using SymbolTypeInterface = IDebugHostModule;

    //*************************************************
    // Factory Methods:
    //

    // IsInstance():
    //
    // Returns whether a given generic symbol actually refers (and can be converted) to a module.
    //
    static bool IsInstance(_In_ const Symbol& symbol)
    {
        return (symbol.SymbolKind() == SymbolModule);
    }

    static bool IsInstance(_In_ IDebugHostSymbol *pSymbol)
    {
        ::SymbolKind symKind;
        CheckHr(pSymbol->GetSymbolKind(&symKind));
        return (symKind == SymbolModule);
    }

    // FromLocation():
    //
    // Returns a module from a given location (address) within a context
    //
    static Module FromLocation(_In_ const HostContext& moduleContext, _In_ const Location& locationWithinModule)
    {
        ComPtr<IDebugHostSymbols> spHostSym;
        CheckHr(GetHost()->QueryInterface(IID_PPV_ARGS(&spHostSym)));

        ComPtr<IDebugHostModule> spModule;
        CheckHr(spHostSym->FindModuleByLocation(moduleContext, locationWithinModule, &spModule));
        return Module(std::move(spModule));
    }

    //*************************************************
    // Module Methods:
    //

    Module() { }
    Module(_In_ IDebugHostModule *pModule) : Symbol(pModule) { }
    Module(_In_ ComPtr<IDebugHostModule> spModule) : Symbol(spModule.Detach()) { }
    Module(_In_ const Module& src) : Symbol(src) { }
    Module(_In_ Module&& src) : Symbol(std::move(src)) { }

    Module& operator=(_In_ IDebugHostModule *pModule) { return static_cast<Module&>(Symbol::operator=(pModule)); }
    Module& operator=(_In_ ComPtr<IDebugHostModule> spModule) { return static_cast<Module&>(Symbol::operator=(spModule.Detach())); }
    Module& operator=(_In_ const Module& src) { return static_cast<Module&>(Symbol::operator=(src)); }
    Module& operator=(_In_ Module&& src) { return static_cast<Module&>(Symbol::operator=(std::move(src))); }

    operator IDebugHostModule* () const { return AsModule(); }
    IDebugHostModule *operator->() const { return AsModule(); }

    template<typename TStr>
    Module(_In_ const HostContext& moduleContext, TStr&& moduleName)
    {
        ComPtr<IDebugHostSymbols> spHostSym;
        CheckHr(GetHost()->QueryInterface(IID_PPV_ARGS(&spHostSym)));

        ComPtr<IDebugHostModule> spModule;
        CheckHr(spHostSym->FindModuleByName(moduleContext, Details::ExtractString(moduleName), &spModule));
        AssignSymbol(spModule.Detach());
    }

    // BaseLocation():
    //
    // Gets the base location of the module.
    //
    Location BaseLocation() const
    {
        CheckObject();

        Location moduleBase;
        CheckHr(AsModule()->GetBaseLocation(&moduleBase));
        return moduleBase;
    }

    // TryGetContainingSymbol():
    //
    // Attempts to lookup a symbol from a given offset into the module (an RVA).  If the symbol can be found,
    // it and the delta to the base of the symbol are returned (along with true).  If the symbol cannot be found,
    // false is returned.
    //
    std::optional<SymbolWithOffset> TryGetContainingSymbol(_In_ ULONG64 moduleOffset) const
    {
        std::optional<SymbolWithOffset> symbolWithOffset;

        ComPtr<IDebugHostModule2> spModule2;
        ComPtr<IDebugHostSymbol> spSym;
        ULONG64 offset;

        if (SUCCEEDED(AsModule()->QueryInterface(IID_PPV_ARGS(&spModule2))) &&
            SUCCEEDED(spModule2->FindContainingSymbolByRVA(moduleOffset, &spSym, &offset)))
        {
            symbolWithOffset = std::make_pair(Symbol(std::move(spSym)), offset);
        }

        return symbolWithOffset;
    }
    bool TryGetContainingSymbol(_In_ ULONG64 moduleOffset, _Out_ SymbolWithOffset *pResultSymbol) const
    {
        auto sym = TryGetContainingSymbol(moduleOffset);
        if (sym)
        {
            *pResultSymbol = sym.value();
            return true;
        }
        return false;
    }

    // GetContainingSymbol():
    //
    // Looks up a symbol from a given offset into the module and returns the symbol and the delta to the base of
    // the symbol.  If such symbol cannot be found (e.g.: symbols cannot be loaded or there is no symbol at the
    // given offset), an exception is thrown.
    //
    SymbolWithOffset GetContainingSymbol(_In_ ULONG64 moduleOffset) const
    {
        SymbolWithOffset symOffs;
        if (!TryGetContainingSymbol(moduleOffset, &symOffs))
        {
            CheckHr(E_FAIL);
        }
        return symOffs;
    }

    // FindType():
    //
    // Finds a type by name within the module.
    //
    template<typename TStr>
    ClientEx::Type FindType(_In_ TStr&& typeName) const;

    // FindSymbol():
    //
    // Finds a symbol by name within the module.
    //
    template<typename TStr>
    Symbol FindSymbol(_In_ TStr&& symbolName) const
    {
        ComPtr<IDebugHostSymbol> spSymbol;
        CheckHr(AsModule()->FindSymbolByName(Details::ExtractString(symbolName), &spSymbol));
        return Symbol(std::move(spSymbol));
    }

protected:

    virtual bool VerifySymbol(_In_ IDebugHostSymbol *pSymbol) noexcept
    {
        return pSymbol == nullptr || IsInstance(pSymbol);
    }

private:

    // AsModule():
    //
    // Returns the IDebugHostModule interface for the module.
    //
    IDebugHostModule *AsModule() const
    {
        return static_cast<IDebugHostModule *>(GetSymbolInterface());
    }

};

// Constant:
//
// Represents a constant within symbols...
//
class Constant : public Symbol
{
public:

    using SymbolTypeInterface = IDebugHostConstant;

    // IsInstance():
    //
    // Returns whether a given generic symbol actually refers (and can be converted) to a constant.
    //
    static bool IsInstance(_In_ const Symbol& symbol)
    {
        return (symbol.SymbolKind() == SymbolConstant);
    }

    static bool IsInstance(_In_ IDebugHostSymbol *pSymbol)
    {
        ::SymbolKind symKind;
        CheckHr(pSymbol->GetSymbolKind(&symKind));
        return (symKind == SymbolConstant);
    }

    //*************************************************
    // Constant Methods:
    //

    Constant() =default;
    Constant(_In_ IDebugHostConstant *pConstant) : Symbol(pConstant) { }
    Constant(_In_ ComPtr<IDebugHostConstant> spConstant) : Symbol(spConstant.Detach()) { }
    Constant(_In_ const Constant& src) : Symbol(src) { }
    Constant(_In_ Constant&& src) : Symbol(std::move(src)) { }

    Constant& operator=(_In_ IDebugHostConstant *pConstant) { return static_cast<Constant&>(Symbol::operator=(pConstant)); }
    Constant& operator=(_In_ ComPtr<IDebugHostConstant> spConstant) { return static_cast<Constant&>(Symbol::operator=(spConstant.Detach())); }
    Constant& operator=(_In_ const Constant& src) { return static_cast<Constant&>(Symbol::operator=(src)); }
    Constant& operator=(_In_ Constant&& src) { return static_cast<Constant&>(Symbol::operator=(std::move(src))); }

    operator IDebugHostConstant* () const { return AsConstant(); }
    IDebugHostConstant *operator->() const { return AsConstant(); }

    // Value():
    //
    // Returns an Object (boxed) representation of the value of the constant.
    //
    Object Value() const;

private:

    // AsConstant():
    //
    // Returns the IDebugHostConstant interface for the constant.
    //
    IDebugHostConstant *AsConstant() const
    {
        return static_cast<IDebugHostConstant *>(GetSymbolInterface());
    }
};

// Field:
//
// Represents a field of a structure/union/class/etc...
//
class Field : public Symbol
{
public:

    using SymbolTypeInterface = IDebugHostField;

    // IsInstance():
    //
    // Returns whether a given generic symbol actually refers (and can be converted) to a module.
    //
    static bool IsInstance(_In_ const Symbol& symbol)
    {
        return (symbol.SymbolKind() == SymbolField);
    }

    static bool IsInstance(_In_ IDebugHostSymbol *pSymbol)
    {
        ::SymbolKind symKind;
        CheckHr(pSymbol->GetSymbolKind(&symKind));
        return (symKind == SymbolField);
    }

    //*************************************************
    // Field Methods:
    //

    Field() =default;
    Field(_In_ IDebugHostField *pField) : Symbol(pField) { }
    Field(_In_ ComPtr<IDebugHostField> spField) : Symbol(spField.Detach()) { }
    Field(_In_ const Field& src) : Symbol(src) { }
    Field(_In_ Field&& src) : Symbol(std::move(src)) { }

    Field& operator=(_In_ IDebugHostField *pField) { return static_cast<Field&>(Symbol::operator=(pField)); }
    Field& operator=(_In_ ComPtr<IDebugHostField> spField) { return static_cast<Field&>(Symbol::operator=(spField.Detach())); }
    Field& operator=(_In_ const Field& src) { return static_cast<Field&>(Symbol::operator=(src)); }
    Field& operator=(_In_ Field&& src) { return static_cast<Field&>(Symbol::operator=(std::move(src))); }

    operator IDebugHostField* () const { return AsField(); }
    IDebugHostField *operator->() const { return AsField(); }

    // GetLocationKind():
    //
    // Returns the location kind of this field.
    //
    LocationKind GetLocationKind() const
    {
        LocationKind locKind;
        CheckHr(AsField()->GetLocationKind(&locKind));
        return locKind;
    }

    // GetLocation():
    //
    // Gets the location of a field for a field which is static.
    //
    Location GetLocation() const
    {
        Location loc;
        CheckHr(AsField()->GetLocation(&loc));
        return loc;
    }

    // GetOffset():
    //
    // Gets the offset of a field for a field which is a member.
    //
    ULONG64 GetOffset() const
    {
        ULONG64 offset;
        CheckHr(AsField()->GetOffset(&offset));
        return offset;
    }

    // GetValue():
    //
    // Gets the value of a constant field as an object.
    //
    Object GetValue() const;

    bool IsMember() const { return GetLocationKind() == LocationMember; }
    bool IsStatic() const { return GetLocationKind() == LocationStatic; }
    bool IsConstant() const { return GetLocationKind() == LocationConstant; }

protected:

    virtual bool VerifySymbol(_In_ IDebugHostSymbol *pSymbol) noexcept
    {
        return pSymbol == nullptr || IsInstance(pSymbol);
    }

private:

    // AsField():
    //
    // Returns the IDebugHostField interface for the module.
    //
    IDebugHostField *AsField() const
    {
        return static_cast<IDebugHostField *>(GetSymbolInterface());
    }
};

// BaseClass:
//
// Represents a base class
//
class BaseClass : public Symbol
{
public:

    using SymbolTypeInterface = IDebugHostBaseClass;

    // IsInstance():
    //
    // Returns whether a given generic symbol actually refers (and can be converted) to a base class.
    //
    static bool IsInstance(_In_ const Symbol& symbol)
    {
        return (symbol.SymbolKind() == SymbolBaseClass);
    }

    static bool IsInstance(_In_ IDebugHostSymbol *pSymbol)
    {
        ::SymbolKind symKind;
        CheckHr(pSymbol->GetSymbolKind(&symKind));
        return (symKind == SymbolBaseClass);
    }

    //*************************************************
    // Base Class Methods:
    //

    BaseClass() =default;
    BaseClass(_In_ IDebugHostBaseClass *pBaseClass) : Symbol(pBaseClass) { }
    BaseClass(_In_ ComPtr<IDebugHostBaseClass> spBaseClass) : Symbol(spBaseClass.Detach()) { }
    BaseClass(_In_ const BaseClass& src) : Symbol(src) { }
    BaseClass(_In_ BaseClass&& src) : Symbol(std::move(src)) { }

    BaseClass& operator=(_In_ IDebugHostBaseClass *pBaseClass) { return static_cast<BaseClass&>(Symbol::operator=(pBaseClass)); }
    BaseClass& operator=(_In_ ComPtr<IDebugHostBaseClass> spBaseClass) { return static_cast<BaseClass&>(Symbol::operator=(spBaseClass.Detach())); }
    BaseClass& operator=(_In_ const BaseClass& src) { return static_cast<BaseClass&>(Symbol::operator=(src)); }
    BaseClass& operator=(_In_ BaseClass&& src) { return static_cast<BaseClass&>(Symbol::operator=(std::move(src))); }

    operator IDebugHostBaseClass* () const { return AsBaseClass(); }
    IDebugHostBaseClass *operator->() const { return AsBaseClass(); }

    // GetOffset():
    //
    // Gets the offset of a base class within its derived class.
    //
    ULONG64 GetOffset() const
    {
        ULONG64 offset;
        CheckHr(AsBaseClass()->GetOffset(&offset));
        return offset;
    }

protected:

    virtual bool VerifySymbol(_In_ IDebugHostSymbol *pSymbol) noexcept
    {
        return pSymbol == nullptr || IsInstance(pSymbol);
    }

private:

    // AsBaseClass():
    //
    // Returns the IDebugHostBaseClass interface for the base class
    //
    IDebugHostBaseClass *AsBaseClass() const
    {
        return static_cast<IDebugHostBaseClass *>(GetSymbolInterface());
    }
};

// BitFieldInformation:
//
// Defines a bitfield type.
//
struct BitFieldInformation
{
    ULONG Lsb;
    ULONG Length;
};

// Type:
//
// Represents a type object.
//
class Type : public Symbol
{
public:

    using SymbolTypeInterface = IDebugHostType;

    // IsInstance():
    //
    // Returns whether a given generic symbol actually refers (and can be converted) to a module.
    //
    static bool IsInstance(_In_ const Symbol& symbol)
    {
        return (symbol.SymbolKind() == SymbolType);
    }

    static bool IsInstance(_In_ IDebugHostSymbol *pSymbol)
    {
        ::SymbolKind symKind;
        CheckHr(pSymbol->GetSymbolKind(&symKind));
        return (symKind == SymbolType);
    }

    Type() =default;
    Type(_In_ IDebugHostType *pType) : Symbol(pType) { }
    Type(_In_ ComPtr<IDebugHostType> spType) : Symbol(spType.Detach()) { }
    Type(_In_ const Type& src) : Symbol(src) { }
    Type(_In_ Type&& src) : Symbol(std::move(src)) { }

    Type& operator=(_In_ IDebugHostType *pType) { return static_cast<Type&>(Symbol::operator=(pType)); }
    Type& operator=(_In_ ComPtr<IDebugHostType> spType) { return static_cast<Type&>(Symbol::operator=(spType.Detach())); }
    Type& operator=(_In_ const Type& src) { return static_cast<Type&>(Symbol::operator=(src)); }
    Type& operator=(_In_ Type&& src) { return static_cast<Type&>(Symbol::operator=(std::move(src))); }

    operator IDebugHostType* () const { return AsType(); }
    IDebugHostType *operator->() const { return AsType(); }

    Type(_In_ const Module& module, _In_z_ const wchar_t *pTypeName)
    {
        ComPtr<IDebugHostType> spType;
        CheckHr(module->FindTypeByName(pTypeName, &spType));
        AssignSymbol(spType.Detach());
    }

    Type(_In_ const Module& module, _In_ const std::wstring& typeName) : Type(module, typeName.c_str()) { }

    template<typename TStr1, typename TStr2>
    Type(_In_ const HostContext& moduleContext, _In_ TStr1&& moduleName, _In_ TStr2&& typeName)
    {
        Module typeMod(moduleContext, Details::ExtractString(moduleName));
        Type ty(typeMod, Details::ExtractString(typeName));
        *this = ty;
    }

    // GetKind():
    //
    // Gets the kind of type (e.g.: struct, pointer, etc...)
    //
    TypeKind GetKind() const
    {
        CheckObject();

        TypeKind tk;
        CheckHr(AsType()->GetTypeKind(&tk));
        return tk;
    }

    // BaseType():
    //
    // Gets the base type (e.g.: pointed-to-type, array-of-type, etc...)
    //
    Type BaseType() const
    {
        CheckObject();

        ComPtr<IDebugHostType> spType;
        CheckHr(AsType()->GetBaseType(&spType));
        return Type(std::move(spType));
    }

    // Size():
    //
    // Gets the size of the type.
    //
    ULONG64 Size() const
    {
        CheckObject();

        ULONG64 size;
        CheckHr(AsType()->GetSize(&size));
        return size;
    }

    //*************************************************
    // Structure/Union/Class Methods:
    //

    // Fields():
    //
    // Returns a collection of all of the fields within this type (*NOT* including those within base classes)
    //
    Details::SymbolChildrenRef<Type, Field> Fields() const
    {
        CheckObject();
        return Details::SymbolChildrenRef<Type, Field>(*this, SymbolField);
    }

    // BaseClasses():
    //
    // Returns a collection of all of the base classes of this type (*NOT* including base classes of base classes)
    //
    Details::SymbolChildrenRef<Type, BaseClass> BaseClasses() const
    {
        CheckObject();
        return Details::SymbolChildrenRef<Type, BaseClass>(*this, SymbolBaseClass);
    }

    //*************************************************
    // Intrinsic Information:
    //

    // IsIntrinsic():
    //
    // Returns whether the type represents an intrinsic.
    //
    bool IsIntrinsic() const
    {
        CheckObject();
        return (GetKind() == TypeIntrinsic);
    }

    // IntrinsicKind():
    //
    // Returns the kind of an intrinsic.
    //
    ::IntrinsicKind IntrinsicKind() const
    {
        CheckObject();
        if (!IsIntrinsic())
        {
            throw illegal_operation("Object must be an intrinsic");
        }

        ::IntrinsicKind ik;
        VARTYPE carrier;
        CheckHr(AsType()->GetIntrinsicType(&ik, &carrier));
        return ik;
    }

    // IntrinsicCarrier():
    //
    // Returns the carrier type for an intrinsic (how it packs)
    //
    VARTYPE IntrinsicCarrier() const
    {
        CheckObject();
        if (!IsIntrinsic())
        {
            throw illegal_operation("Object must be an intrinsic");
        }

        ::IntrinsicKind ik;
        VARTYPE carrier;
        CheckHr(AsType()->GetIntrinsicType(&ik, &carrier));
        return carrier;
    }

    //*************************************************
    // BitField Information:
    //

    // IsBitField():
    //
    // Returns whether the type represents a bitfield.
    //
    bool IsBitField() const
    {
        CheckObject();
        ULONG lsb, length;
        if (FAILED(AsType()->GetBitField(&lsb, &length)))
        {
            return false;
        }
        return true;
    }

    // BitField():
    //
    // Returns information about a bit field type.
    //
    BitFieldInformation BitField() const
    {
        CheckObject();
        BitFieldInformation info;
        CheckHr(AsType()->GetBitField(&info.Lsb, &info.Length));
        return info;
    }

    //*************************************************
    // Pointer Methods:
    //

    // IsPointer():
    //
    // Returns whether the type represents any kind of pointer.
    //
    bool IsPointer() const
    {
        CheckObject();
        auto kind = GetKind();
        return (kind == TypePointer || kind == TypeMemberPointer);
    }

    // GetPointerKind()
    //
    // Gets the kind of pointer (e.g.: standard, reference, etc...).  This may only legally be called on a pointer.
    //
    PointerKind GetPointerKind() const
    {
        CheckObject();

        if (!IsPointer())
        {
            throw illegal_operation("Object must be a pointer");
        }

        PointerKind pk;
        CheckHr(AsType()->GetPointerKind(&pk));
        return pk;
    }

    // PointerMemberType():
    //
    // For pointer-to-member (of class), this returns the class which the pointer is a member of.
    //
    ClientEx::Type PointerMemberType() const
    {
        CheckObject();
        if (GetKind() != TypeMemberPointer)
        {
            throw illegal_operation("Object must be a member pointer");
        }

        ComPtr<IDebugHostType> spMemberType;
        CheckHr(AsType()->GetMemberType(&spMemberType));
        return ClientEx::Type(std::move(spMemberType));
    }

    //*************************************************
    // Array Methods:
    //

    // IsArray():
    //
    // Indicates whether the type represents any kind of array.
    //
    bool IsArray() const
    {
        CheckObject();
        return (GetKind() == TypeArray);
    }

    // ArrayDimensions():
    //
    // Returns a collection of all of the array dimensions of the type.
    //
    Details::ArrayDimensionsRef ArrayDimensions() const
    {
        CheckObject();

        if (!IsArray())
        {
            throw illegal_operation("Object must be an array");
        }

        return Details::ArrayDimensionsRef(AsType());
    }

    //*************************************************
    // Generics (Templates) Methods:
    //

    // IsGeneric():
    //
    // An indication of whether the type is a generic (e.g.: a C++ template, a C# generic, etc...)
    //
    bool IsGeneric() const
    {
        CheckObject();

        bool isGeneric;
        CheckHr(AsType()->IsGeneric(&isGeneric));
        return isGeneric;
    }

    // GenericArguments():
    //
    // Returns a collection of all of the generic arguments of this type (which are all symbols -- some may
    // be types, some may be constants)
    //
    Details::GenericArgumentsRef<Symbol> GenericArguments() const
    {
        CheckObject();

        if (!IsGeneric())
        {
            throw illegal_operation("Object must be a generic");
        }

        return Details::GenericArgumentsRef<Symbol>(AsType());
    }

    //*************************************************
    // Function Methods:
    //

    // IsFunction():
    //
    // An indication of whether the type is a function type.
    //
    bool IsFunction() const
    {
        CheckObject();
        return (GetKind() == TypeFunction);
    }

    // CallingConvention():
    //
    // Returns the calling convention of a function type.
    //
    CallingConventionKind CallingConvention() const
    {
        CheckObject();
        if (!IsFunction())
        {
            throw illegal_operation("Object must be a function");
        }

        CallingConventionKind convKind;
        CheckHr(AsType()->GetFunctionCallingConvention(&convKind));
        return convKind;
    }

    // ReturnType():
    //
    // Retunrs the return type of a function type.
    //
    ClientEx::Type ReturnType() const
    {
        CheckObject();
        if (!IsFunction())
        {
            throw illegal_operation("Object must be a function");
        }

        ComPtr<IDebugHostType> spReturnType;
        CheckHr(AsType()->GetFunctionReturnType(&spReturnType));
        return ClientEx::Type(std::move(spReturnType));
    }

    // HasInstancePointerType():
    //
    // Returns whether or not a given function type has an instance pointer (implicit 'this' argument)
    //
    bool HasInstancePointerType() const
    {
        CheckObject();
        if (!IsFunction())
        {
            throw illegal_operation("Object must be a function");
        }
        ComPtr<IDebugHostType2> spType2;
        CheckHr(AsType()->QueryInterface(IID_PPV_ARGS(&spType2)));
        ComPtr<IDebugHostType2> spInstancePointerType;
        if (FAILED(spType2->GetFunctionInstancePointerType(&spInstancePointerType)))
        {
            return false;
        }
        return true;
    }

    // InstancePointerType():
    //
    // Returns the type of any implicit instance pointer to the function type ('this' pointer)
    //
    ClientEx::Type InstancePointerType() const
    {
        CheckObject();
        if (!IsFunction())
        {
            throw illegal_operation("Object must be a function");
        }
        ComPtr<IDebugHostType2> spType2;
        CheckHr(AsType()->QueryInterface(IID_PPV_ARGS(&spType2)));
        ComPtr<IDebugHostType2> spInstancePointerType;
        CheckHr(spType2->GetFunctionInstancePointerType(&spInstancePointerType));
        return ClientEx::Type(std::move(spInstancePointerType));
    }

    // IsVarArgs():
    //
    // Returns whether a function type is varargs (of any style)
    //
    bool IsVarArgs() const
    {
        return VarArgsKind() != VarArgsNone;
    }

    // VarArgsKind():
    //
    // Returns what style of varargs a given funtion type is.
    //
    ::VarArgsKind VarArgsKind() const
    {
        CheckObject();
        if (!IsFunction())
        {
            throw illegal_operation("Object must be a function");
        }
        ComPtr<IDebugHostType2> spType2;
        CheckHr(AsType()->QueryInterface(IID_PPV_ARGS(&spType2)));
        ::VarArgsKind varKind;
        CheckHr(spType2->GetFunctionVarArgsKind(&varKind));
        return varKind;
    }

    // ParameterTypes():
    //
    // Returns a collection of the parameter types of a function type.
    //
    Details::ParameterTypesRef<ClientEx::Type> ParameterTypes() const
    {
        CheckObject();
        if (!IsFunction())
        {
            throw illegal_operation("Object must be a function");
        }
        return Details::ParameterTypesRef<ClientEx::Type>(AsType());
    }

    //*************************************************
    // Typedef Methods:
    //

    // IsTypedef():
    //
    // Returns whether the type is a typedef.  All other methods not specific to typedefs will behave
    // as they would on the final underlying type.
    //
    bool IsTypedef() const
    {
        CheckObject();
        ComPtr<IDebugHostType2> spType2;
        CheckHr(AsType()->QueryInterface(IID_PPV_ARGS(&spType2)));
        bool isTypedef;
        CheckHr(spType2->IsTypedef(&isTypedef));
        return isTypedef;
    }

    // TypedefBaseType():
    //
    // For a type which is a typedef, this will return the type that the typedef refers to (which may itself
    // be another typedef).
    //
    ClientEx::Type TypedefBaseType() const
    {
        CheckObject();
        ComPtr<IDebugHostType2> spType2;
        CheckHr(AsType()->QueryInterface(IID_PPV_ARGS(&spType2)));
        ComPtr<IDebugHostType2> spBaseType;
        CheckHr(spType2->GetTypedefBaseType(&spBaseType));
        return ClientEx::Type(std::move(spBaseType));
    }

    // TypedefFinalBaseType():
    //
    // For a type which is a typedef, this will return the final type that the typedef refers to (effectively
    // doing TypedefBaseType until reaching something which is not a typedef).
    //
    ClientEx::Type TypedefFinalBaseType() const
    {
        CheckObject();
        ComPtr<IDebugHostType2> spType2;
        CheckHr(AsType()->QueryInterface(IID_PPV_ARGS(&spType2)));
        ComPtr<IDebugHostType2> spFinalBaseType;
        CheckHr(spType2->GetTypedefFinalBaseType(&spFinalBaseType));
        return ClientEx::Type(std::move(spFinalBaseType));
    }

protected:

    virtual bool VerifySymbol(_In_ IDebugHostSymbol *pSymbol) noexcept
    {
        return pSymbol == nullptr || IsInstance(pSymbol);
    }

private:

    // AsType():
    //
    // Returns the IDebugHostType interface for the type.
    //
    IDebugHostType *AsType() const
    {
        return static_cast<IDebugHostType *>(GetSymbolInterface());
    }
};

template<typename TDestSymbol> TDestSymbol symbol_cast(_In_ const Symbol& src) { return symbol_cast<TDestSymbol>(src.GetSymbolInterface()); };

//**************************************************************************
// Internal Implementation Details for Objects and Metadata:
//

namespace Details
{
    // PointerIndexerAdapter:
    //
    // An pointer math indexer adapter.  This is *NOT* a real concept which gets attached.  Rather it is an adapter
    // such that IndexableReference<> can operate on pointers without being aware.
    //
    class PointerIndexerAdapter :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IIndexableConcept
            >
    {
    public:

        //*************************************************
        // IIndexableConcept:
        //

        IFACEMETHOD(GetDimensionality)(_In_ IModelObject * /*pContextObject*/,
                                       _In_ ULONG64 *pDimensionality)
        {
            *pDimensionality = 1;
            return S_OK;
        }

        // GetAt():
        //
        // Abstraction for pointer[i] where i is the indexer set.
        //
        IFACEMETHOD(GetAt)(_In_ IModelObject *pContextObject,
                           _In_ ULONG64 indexerCount,
                           _In_reads_(indexerCount) IModelObject **ppIndexers,
                           _COM_Errorptr_ IModelObject **ppObject,
                           _COM_Outptr_opt_result_maybenull_ IKeyStore **ppMetadata)
        {
            *ppObject = nullptr;
            if (ppMetadata != nullptr)
            {
                *ppMetadata = nullptr;
            }

            try
            {
                if (indexerCount != 1)
                {
                    throw illegal_operation("Pointer indexing may only be single dimensional");
                }

                ULONG64 ptrValue;
                ComPtr<IDebugHostType> spBaseType;
                GetAdjustedLocationAndBaseType(pContextObject, ppIndexers[0], &ptrValue, &spBaseType);


                ComPtr<IDebugHostContext> spCtx;
                CheckHr(pContextObject->GetContext(&spCtx));

                ComPtr<IModelObject> spObject;
                CheckHr(GetManager()->CreateTypedObject(spCtx.Get(), ptrValue, spBaseType.Get(), &spObject));

                *ppObject = spObject.Detach();
                return S_OK;
            }
            catch(...)
            {
                return Exceptions::ReturnResult(std::current_exception(), ppObject);
            }
        }

        // SetAt():
        //
        // Abstraction for pointer[i] = value where i is the indexer set.
        //
        IFACEMETHOD(SetAt)(_In_ IModelObject *pContextObject,
                           _In_ ULONG64 indexerCount,
                           _In_reads_(indexerCount) IModelObject **ppIndexers,
                           _In_ IModelObject *pValue)
        {
            try
            {
                if (indexerCount != 1)
                {
                    throw illegal_operation("Pointer indexing may only be single dimensional");
                }

                ULONG64 ptrValue;
                ComPtr<IDebugHostType> spBaseType;
                GetAdjustedLocationAndBaseType(pContextObject, ppIndexers[0], &ptrValue, &spBaseType);

                //
                // Create a linguistic reference to the underlying value and ask the core EE to perform
                // whatever assignment it can.
                //
                ComPtr<IDebugHostType> spRefType;
                CheckHr(spBaseType->CreatePointerTo(PointerReference, &spRefType));

                VARIANT vtPtr;
                vtPtr.ullVal = ptrValue;
                vtPtr.vt = VT_UI8;

                ComPtr<IModelObject> spObject;
                CheckHr(GetManager()->CreateTypedIntrinsicObject(&vtPtr, spRefType.Get(), &spObject));

                ComPtr<IDebugHostEvaluator2> spEval2;
                CheckHr(GetHost()->QueryInterface(IID_PPV_ARGS(&spEval2)));
                ComPtr<IModelObject> spEvalResult;
                HRESULT hr = spEval2->AssignTo(spObject.Get(), pValue, &spEvalResult, nullptr);
                CheckHr(hr, spEvalResult);

                return S_OK;
            }
            catch(...)
            {
                return Exceptions::ReturnResult(std::current_exception());
            }
        }

    private:

        // GetAdjustedLocationAndBaseType():
        //
        // Performs the underlying pointer math and returns the pointer value (location) and the underlying
        // type.
        //
        _Success_(true) void GetAdjustedLocationAndBaseType(_In_ IModelObject *pContextObject,
                                                            _In_ IModelObject *pIndex,
                                                            _Out_ ULONG64 *pAdjustedPointer,
                                                            _COM_Outptr_ IDebugHostType **ppBaseType)
        {
            *ppBaseType = nullptr;

            ComPtr<IDebugHostType> spType;
            CheckHr(pContextObject->GetTypeInfo(&spType));

            if (spType == nullptr)
            {
                throw unexpected_error();
            }

            TypeKind tk;
            CheckHr(spType->GetTypeKind(&tk));

            PointerKind pk;
            CheckHr(spType->GetPointerKind(&pk));

            if (tk != TypePointer || pk != PointerStandard)
            {
                throw unexpected_error();
            }

            ComPtr<IDebugHostType> spBaseType;
            CheckHr(spType->GetBaseType(&spBaseType));

            ULONG64 baseSize;
            CheckHr(spBaseType->GetSize(&baseSize));

            VARIANT vtPtr;
            CheckHr(pContextObject->GetIntrinsicValueAs(VT_UI8, &vtPtr));

            VARIANT vtAdjustment;
            CheckHr(pIndex->GetIntrinsicValueAs(VT_I8, &vtAdjustment));

            *pAdjustedPointer = vtPtr.ullVal + (baseSize * vtAdjustment.llVal);
            *ppBaseType = spBaseType.Detach();
        }

    };

    // IndexableReference:
    //
    // A type which represents a reference value to an index operator.  operator[] on objects
    // returns this to provide both value conversion and back assignment.
    //
    // NOTE:
    //     TObj  is expected to be ClientEx::Object
    //     TPack is parameter pack for the indexing operation (a unique pointer of ClientEx::Object>
    //
    // @TODO: Reorganize and remove template parameters
    //
    template<typename TObj, typename TPack>
    class IndexableReference
    {
    public:

        // IndexableReference():
        //
        // Creates an indexable reference taking ownership of the indexer pack and the indexable.
        //
        IndexableReference(_In_ size_t packSize,
                           _In_ TPack&& indexers,
                           _In_ ComPtr<IIndexableConcept>&& spIndexable,
                           _In_ IModelObject *pSrcObject) :
                           m_packSize(packSize),
                           m_indexers(std::move(indexers)),
                           m_spIndexable(std::move(spIndexable)),
                           m_spSrcObject(pSrcObject)
        {
        }

        // operator Object
        //
        // Performs a get of the value
        //
        operator TObj() const
        {
            return GetValue();
        }

        // operator=
        //
        // Perform assignment to another value.
        //
        template<typename T>
        void operator=(T&& assignmentValue)
        {
            TObj assignment = BoxObject(std::forward<T>(assignmentValue));
            SetValue(assignment);
        }

        // GetValue():
        //
        // Gets a value from the indexer.
        //
        TObj GetValue() const
        {
            ComPtr<IModelObject> spResult;
            HRESULT hr = m_spIndexable->GetAt(m_spSrcObject.Get(),
                                              m_packSize,
                                              reinterpret_cast<IModelObject **>(m_indexers.get()),
                                              &spResult,
                                              nullptr);
            CheckHr(hr, spResult);

            //
            // @TODO: A number of indexers have a habit of returning a reference to the underlying object
            //        since there is no such thing as an IModelIndex*Reference.  Paper over this and get the
            //        underlying value since we are creating such an abstraction in C++.
            //
            ComPtr<IModelObject> spValue;

            ModelObjectKind mk;
            CheckHr(spResult->GetKind(&mk));
            switch(mk)
            {
                case ObjectTargetObjectReference:
                    CheckHr(spResult->Dereference(&spValue));
                    break;

                default:
                    spValue = std::move(spResult);
                    break;
            }

            return TObj(std::move(spValue));
        }

        // Conversions:
        //
        template<typename TType> TType As() const { return GetValue().As<TType>(); }
        template<typename TType> explicit operator TType() const { return As<TType>(); }

    private:

        // SetValue():
        //
        // Sets a value on the indexer.
        //
        void SetValue(_In_ const TObj& value)
        {
            HRESULT hr = m_spIndexable->SetAt(m_spSrcObject.Get(),
                                              m_packSize,
                                              reinterpret_cast<IModelObject **>(m_indexers.get()),
                                              value);
            CheckHr(hr);
        }

        size_t m_packSize;
        TPack m_indexers;
        ComPtr<IIndexableConcept> m_spIndexable;
        ComPtr<IModelObject> m_spSrcObject;
    };

    // ObjectKeyRef:
    //
    // Represents a reference to a key.  Keys()[name] returns this so that both value returns
    // and back assignment to the key is supported.
    //
    template<typename TObj, typename TMeta>
    class ObjectKeyRef
    {
    public:

        ObjectKeyRef() { }

        ObjectKeyRef(_In_ TObj&& keyRef) :
            m_keyRef(std::move(keyRef))
        {
        }

        IModelObject *GetObject() const
        {
            return m_keyRef;
        }

        operator TObj() const
        {
            return GetValue();
        }

        operator TMeta() const
        {
            return GetMetadata();
        }

        template<typename T>
        ObjectKeyRef& operator=(T&& val)
        {
            TObj boxedValue = BoxObject(std::forward<T>(val));
            SetValue(boxedValue);
            return *this;
        }

        TObj GetValue() const
        {
            CheckObject();
            IModelKeyReference *pKeyRef = m_keyRef.As<IModelKeyReference *>();
            ComPtr<IModelObject> spValue;
            HRESULT hr = pKeyRef->GetKeyValue(&spValue, nullptr);
            CheckHr(hr, spValue);
            return TObj(std::move(spValue));
        }

        TMeta GetMetadata() const
        {
            CheckObject();
            IModelKeyReference *pKeyRef = m_keyRef.As<IModelKeyReference *>();
            //
            // @TODO: We should *NOT* have to get the value here.  The interface declares this _In_opt_ but
            // it AV's if you pass nullptr for the value.
            //
            ComPtr<IKeyStore> spMetadata;
            ComPtr<IModelObject> spValue;
            HRESULT hr = pKeyRef->GetKeyValue(&spValue, &spMetadata);
            CheckHr(hr);
            return TMeta(std::move(spMetadata));
        }

        // Conversions:
        //
        template<typename TType> TType As() const { return GetValue().As<TType>(); }
        template<typename TType> explicit operator TType() const { return As<TType>(); }

    private:

        void CheckObject() const
        {
            if (m_keyRef.GetObject() == nullptr)
            {
                throw ClientEx::unexpected_error();
            }
        }

        void SetValue(_In_ const TObj& val) const
        {
            CheckObject();
            IModelKeyReference *pKeyReference = m_keyRef.As<IModelKeyReference *>();
            CheckHr(pKeyReference->SetKeyValue(val));
        }

        TObj m_keyRef;
    };

    // ObjectKeysRef():
    //
    // The object returned from Keys() to reference the set of keys on an object.
    //
    template<typename TObj, typename TMeta>
    class ObjectKeysRef
    {
    public:

        // KeyIterator():
        //
        // A C++ input iterator for the keys within an object.
        //
        class KeyIterator
        {
        public:

            using value_type = std::tuple<std::wstring, ObjectKeyRef<TObj, TMeta>, TMeta>;

            KeyIterator() : m_pos(0) { }

            KeyIterator(_In_ IKeyEnumerator *pKeyEnum) : KeyIterator(pKeyEnum, 0) { }

            KeyIterator(_In_ IKeyEnumerator *pKeyEnum, _In_ size_t pos) :
                m_spEnum(pKeyEnum),
                m_pos(pos)
            {
                MoveForward();
            }

            KeyIterator(_In_ const KeyIterator& rhs) :
                m_spEnum(rhs.m_spEnum),
                m_value(rhs.m_value),
                m_pos(rhs.m_pos)
            {
            }

            KeyIterator(_In_ KeyIterator&& rhs) :
                m_spEnum(std::move(rhs.m_spEnum)),
                m_value(std::move(rhs.m_value)),
                m_pos(rhs.m_pos)
            {
                rhs.m_pos = 0;
            }

            KeyIterator& operator=(_In_ const KeyIterator& rhs)
            {
                m_spEnum = rhs.m_spEnum;
                m_value = rhs.m_value;
                m_pos = rhs.m_pos;
                return *this;
            }

            KeyIterator& operator=(KeyIterator&& rhs)
            {
                m_spEnum = std::move(rhs.m_spEnum);
                m_value = std::move(rhs.m_value);
                m_pos = rhs.m_pos;
                rhs.m_pos = 0;
                return *this;
            }

            bool operator==(_In_ const KeyIterator& rhs)
            {
                if (std::get<1>(m_value).GetObject() == nullptr && std::get<1>(rhs.m_value).GetObject() == nullptr)
                {
                    return true;
                }
                else if (std::get<1>(m_value).GetObject() != nullptr && std::get<1>(rhs.m_value).GetObject() != nullptr && m_pos == rhs.m_pos)
                {
                    return true;
                }

                return false;
            }

            bool operator!=(_In_ const KeyIterator& rhs)
            {
                return !operator==(rhs);
            }

            value_type operator*() const
            {
                return m_value;
            }

            value_type* operator->() const
            {
                return &m_value;
            }

            KeyIterator operator++()
            {
                MoveForward();
                return *this;
            }

            KeyIterator operator++(int)
            {
                KeyIterator cur = *this;
                MoveForward();
                return cur;
            }

        private:

            void MoveForward()
            {
                BSTR keyName;
                ComPtr<IModelObject> spValue;
                ComPtr<IKeyStore> spMetadata;
                HRESULT hr = m_spEnum->GetNext(&keyName, &spValue, &spMetadata);
                if (SUCCEEDED(hr))
                {
                    bstr_ptr fldPtr(keyName);
                    ObjectKeyRef<TObj, TMeta> keyRef(std::move(spValue));
                    TMeta metadata = std::move(spMetadata);
                    m_value = std::make_tuple(std::wstring(keyName), std::move(keyRef), std::move(metadata));
                    ++m_pos;
                }
                else if (hr != E_BOUNDS)
                {
                    CheckHr(hr);
                }
                else
                {
                    m_value = std::make_tuple(std::wstring(), ObjectKeyRef<TObj, TMeta>(), TMeta());
                    m_pos = 0;
                }
            }

            ComPtr<IKeyEnumerator> m_spEnum;
            value_type m_value;
            size_t m_pos;

        };

        using iterator = KeyIterator;

        ObjectKeysRef(_In_ const TObj& obj) :
            m_obj(obj)
        {
        }

        // operator[]:
        //
        // Returns a "reference" to a key.
        //
        ObjectKeyRef<TObj, TMeta> operator[](_In_z_ const wchar_t *keyName)
        {
            ComPtr<IModelObject> spKeyRef;
            HRESULT hr = m_obj->GetKeyReference(keyName, &spKeyRef, nullptr);
            CheckHr(hr, spKeyRef);
            return ObjectKeyRef<TObj, TMeta>(std::move(spKeyRef));
        }

        ObjectKeyRef<TObj, TMeta> operator[](_In_ const std::wstring& keyName)
        {
            if (keyName.empty())
            {
                throw std::invalid_argument("Invalid keyName");
            }
            return operator[](keyName.c_str());
        }

        iterator begin()
        {
            ComPtr<IKeyEnumerator> spEnum;
            CheckHr(m_obj->EnumerateKeyReferences(&spEnum));
            return iterator(spEnum.Get());
        }

        iterator end()
        {
            return iterator();
        }

    private:

        TObj m_obj;

    };

    // ObjectFieldRef:
    //
    // Represents a reference to a field as returned from Fields()[name] such that both value conversion
    // and back assignment to the field can be supported.
    //
    template<typename TObj>
    class ObjectFieldRef
    {
    public:

        ObjectFieldRef() { }

        ObjectFieldRef(_In_ TObj&& fieldRef) :
            m_fieldRef(std::move(fieldRef))
        {
        }

        operator TObj() const
        {
            return GetValue();
        }

        IModelObject *GetObject() const
        {
            return m_fieldRef;
        }

        template<typename T>
        ObjectFieldRef& operator=(T&& val)
        {
            TObj boxedValue = BoxObject(std::forward<T>(val));
            SetValue(boxedValue);
            return *this;
        }

        TObj GetValue() const
        {
            CheckObject();
            ComPtr<IModelObject> spDeref;
            CheckHr(m_fieldRef->Dereference(&spDeref));
            return TObj(std::move(spDeref));
        }

        // Conversions:
        //
        template<typename TType> TType As() const { return GetValue().As<TType>(); }
        template<typename TType> explicit operator TType() const { return As<TType>(); }

    private:

        void CheckObject() const
        {
            if (m_fieldRef.GetObject() == nullptr)
            {
                throw ClientEx::unexpected_error();
            }
        }

        void SetValue(_In_ const TObj& val) const
        {
            CheckObject();
            ComPtr<IDebugHostEvaluator2> spEval2;
            CheckHr(GetHost()->QueryInterface(IID_PPV_ARGS(&spEval2)));
            ComPtr<IModelObject> spEvalResult;
            HRESULT hr = spEval2->AssignTo(GetObject(), val, &spEvalResult, nullptr);
            CheckHr(hr, spEvalResult);
        }

        TObj m_fieldRef;
    };

    // ObjectFieldsRef():
    //
    // Returned from Fields() to represent all native fields on an object.
    //
    template<typename TObj>
    class ObjectFieldsRef
    {
    private:

        // FieldIterator():
        //
        // A C++ input iterator for the fields within an object.
        //
        class FieldIterator
        {
        public:

            using value = std::pair<std::wstring, ObjectFieldRef<TObj>>;

            FieldIterator() : m_pos(0) { }

            FieldIterator(_In_ IRawEnumerator *pRawEnum) : FieldIterator(pRawEnum, 0) { }

            FieldIterator(_In_ IRawEnumerator *pRawEnum, _In_ size_t pos) :
                m_spEnum(pRawEnum),
                m_pos(pos)
            {
                MoveForward();
            }

            FieldIterator(_In_ const FieldIterator& rhs) :
                m_spEnum(rhs.m_spEnum),
                m_value(rhs.m_value),
                m_pos(rhs.m_pos)
            {
            }

            FieldIterator(_In_ FieldIterator&& rhs) :
                m_spEnum(std::move(rhs.m_spEnum)),
                m_value(std::move(rhs.m_value)),
                m_pos(rhs.m_pos)
            {
                rhs.m_pos = 0;
            }

            FieldIterator& operator=(_In_ const FieldIterator& rhs)
            {
                m_spEnum = rhs.m_spEnum;
                m_value = rhs.m_value;
                m_pos = rhs.m_pos;
                return *this;
            }

            FieldIterator& operator=(FieldIterator&& rhs)
            {
                m_spEnum = std::move(rhs.m_spEnum);
                m_value = std::move(rhs.m_value);
                m_pos = rhs.m_pos;
                rhs.m_pos = 0;
                return *this;
            }

            bool operator==(_In_ const FieldIterator& rhs)
            {
                if (m_value.second.GetObject() == nullptr && rhs.m_value.second.GetObject() == nullptr)
                {
                    return true;
                }
                else if (m_value.second.GetObject() != nullptr && rhs.m_value.second.GetObject() != nullptr && m_pos == rhs.m_pos)
                {
                    return true;
                }

                return false;
            }

            bool operator!=(_In_ const FieldIterator& rhs)
            {
                return !operator==(rhs);
            }

            value operator*() const
            {
                return m_value;
            }

            value* operator->() const
            {
                return &m_value;
            }

            FieldIterator operator++()
            {
                MoveForward();
                return *this;
            }

            FieldIterator operator++(int)
            {
                FieldIterator cur = *this;
                MoveForward();
                return cur;
            }

        private:

            void MoveForward()
            {
                BSTR fldName;
                SymbolKind sk;
                ComPtr<IModelObject> spValue;
                HRESULT hr = m_spEnum->GetNext(&fldName, &sk, &spValue);
                if (SUCCEEDED(hr))
                {
                    bstr_ptr fldPtr(fldName);
                    ObjectFieldRef<TObj> fldRef(std::move(spValue));
                    m_value = std::make_pair(std::wstring(fldName), std::move(fldRef));
                    ++m_pos;
                }
                else if (hr != E_BOUNDS)
                {
                    CheckHr(hr);
                }
                else
                {
                    m_value = std::make_pair(std::wstring(), ObjectFieldRef<TObj>());
                    m_pos = 0;
                }
            }

            ComPtr<IRawEnumerator> m_spEnum;
            value m_value;
            size_t m_pos;

        };

    public:

        using iterator = FieldIterator;

        ObjectFieldsRef(_In_ const TObj& obj) :
            m_obj(obj)
        {
        }

        // operator[]:
        //
        // Returns a "reference" to a native field.
        //
        ObjectFieldRef<TObj> operator[](_In_z_ const wchar_t *fieldName)
        {
            ComPtr<IModelObject> spFieldRef;
            HRESULT hr = m_obj->GetRawReference(SymbolField, fieldName, RawSearchNone, &spFieldRef);
            CheckHr(hr, spFieldRef);
            return ObjectFieldRef<TObj>(std::move(spFieldRef));
        }

        TObj operator[](_In_ const std::wstring& fieldName)
        {
            if (fieldName.empty())
            {
                throw std::invalid_argument("Invalid fieldName");
            }
            return operator[](fieldName.c_str());
        }

        iterator begin()
        {
            ComPtr<IRawEnumerator> spEnum;
            CheckHr(m_obj->EnumerateRawReferences(SymbolField, RawSearchNone, &spEnum));
            return iterator(spEnum.Get());
        }

        iterator end()
        {
            return iterator();
        }

    private:

        TObj m_obj;

    };

    // DereferenceReference:
    //
    // A class which represents a reference type returned from the Dereference call.  This allows both
    // value conversion and back assignment to a dereference.
    //
    template<typename TObj>
    class DereferenceReference
    {
    public:

        DereferenceReference(_In_ const TObj& obj) : m_obj(obj) { }
        DereferenceReference(_In_ const DereferenceReference& src) : m_obj(src.m_obj) { }
        DereferenceReference(_In_ DereferenceReference&& src) : m_obj(std::move(src.m_obj)) { }

        operator TObj() const
        {
            return GetValue();
        }

        TObj GetValue() const
        {
            ComPtr<IModelObject> spDeref;
            CheckHr(m_obj->Dereference(&spDeref));
            return TObj(std::move(spDeref));
        }

        // operator=
        //
        // Perform assignment to another value.
        //
        template<typename T>
        void operator=(T&& assignmentValue)
        {
            TObj assignment = BoxObject(std::forward<T>(assignmentValue));
            SetValue(assignment);
        }

        template<typename TType> TType As() const { return GetValue().As<TType>(); }
        template<typename TType> explicit operator TType() const { return GetValue().As<TType>(); }

    private:

        void CheckObject() const
        {
            if (m_obj.GetObject() == nullptr)
            {
                throw ClientEx::unexpected_error();
            }
        }

        void SetValue(_In_ const TObj& val) const
        {
            CheckObject();

            ComPtr<IDebugHostContext> spCtx;
            ComPtr<IModelObject> spObj;
            CheckHr(m_obj->GetContext(&spCtx));

            TObj assignmentRef;

            //
            // How we "assign this" depends on what it is.  We need to convert the dereference to
            // an actual "reference" and pass that back to the evaluator to deal with as it sees fit.
            //
            ModelObjectKind mkObject = m_obj.GetKind();
            if (mkObject == ObjectIntrinsic)
            {
                //
                // If it's a pointer, get a reference to what's underneath.
                //
                Type ty = m_obj.Type();
                if (ty != nullptr && ty.GetKind() == TypePointer)
                {
                    ULONG64 addr = (ULONG64)m_obj;
                    Type baseType = ty.BaseType();
                    CheckHr(GetManager()->CreateTypedObjectReference(spCtx.Get(), addr, baseType, &spObj));
                    assignmentRef = std::move(spObj);
                }
            }
            else if (mkObject == ObjectTargetObjectReference)
            {
                assignmentRef = m_obj;
            }

            if (assignmentRef == nullptr)
            {
                TObj underlyingValue = GetValue();
                ModelObjectKind mkUnderlyingValue = underlyingValue.GetKind();
                switch(mkUnderlyingValue)
                {
                    case ObjectTargetObjectReference:
                    {
                        //
                        // Probably not.  But this is easy.
                        //
                        assignmentRef = underlyingValue;
                        break;
                    }

                    case ObjectTargetObject:
                    {
                        Location loc;
                        ComPtr<IDebugHostType> spType;
                        CheckHr(m_obj->GetTargetInfo(&loc, &spType));

                        CheckHr(GetManager()->CreateTypedObjectReference(spCtx.Get(), loc, spType.Get(), &spObj));
                        assignmentRef = std::move(spObj);
                        break;
                    }

                    default:
                        throw not_implemented();
                }
            }

            ComPtr<IDebugHostEvaluator2> spEval2;
            CheckHr(GetHost()->QueryInterface(IID_PPV_ARGS(&spEval2)));
            ComPtr<IModelObject> spEvalResult;
            HRESULT hr = spEval2->AssignTo(assignmentRef, val, &spEvalResult, nullptr);
            CheckHr(hr, spEvalResult);
        }

        TObj m_obj;

    };

    // ObjectIterator:
    //
    // A C++ forward iterator over an object.
    //
    template<typename TObj>
    class ObjectIterator
    {
    public:

        using value = TObj;

        ObjectIterator() : m_pos(0) { }
        ObjectIterator(_In_ const TObj& obj, _In_ IModelIterator *pIterator) : ObjectIterator(obj, pIterator, 0) { }

        ObjectIterator(_In_ const TObj& obj, _In_ IModelIterator *pIterator, _In_ size_t pos) :
            m_obj(obj),
            m_spIterator(pIterator),
            m_pos(pos)
        {
            MoveForward();
        }

        ObjectIterator(_In_ const ObjectIterator& rhs) :
            m_obj(rhs.m_obj),
            m_spIterator(rhs.m_spIterator),
            m_value(rhs.m_value),
            m_pos(rhs.m_pos)
        {
        }

        ObjectIterator(_In_ ObjectIterator&& rhs) :
            m_obj(std::move(rhs.m_obj)),
            m_spIterator(std::move(rhs.m_spIterator)),
            m_value(std::move(rhs.m_spValue)),
            m_pos(rhs.m_pos)
        {
            rhs.m_pos = 0;
        }

        ObjectIterator& operator=(_In_ const ObjectIterator& rhs)
        {
            m_obj = rhs.m_obj;
            m_spIterator = rhs.m_spIterator;
            m_value = rhs.m_value;
            m_pos = rhs.m_pos;
            return *this;
        }

        ObjectIterator& operator=(_In_ ObjectIterator&& rhs)
        {
            m_obj = std::move(rhs.m_obj);
            m_spIterator = std::move(rhs.m_spIterator);
            m_value = std::move(rhs.m_value);
            m_pos = rhs.m_pos;
            rhs.m_pos = 0;
            return *this;
        }

        value operator*()
        {
            return m_value;
        }

        value* operator->()
        {
            return &m_value;
        }

        bool operator==(_In_ const ObjectIterator& rhs)
        {
            if (m_value.GetObject() == nullptr && rhs.m_value.GetObject() == nullptr)
            {
                return true;
            }
            else if (m_value.GetObject() != nullptr && rhs.m_value.GetObject() != nullptr &&
                     m_pos == rhs.m_pos)
            {
                return true;
            }
            return false;
        }

        bool operator!=(_In_ const ObjectIterator& rhs)
        {
            return !operator==(rhs);
        }

        ObjectIterator operator++()
        {
            MoveForward();
            return *this;
        }

        ObjectIterator operator++(int)
        {
            ObjectIterator cur = *this;
            MoveForward();
            return cur;
        }

    private:

        void MoveForward()
        {
            ComPtr<IModelObject> spValue;
            HRESULT hr = m_spIterator->GetNext(&spValue, 0, nullptr, nullptr);
            if (SUCCEEDED(hr))
            {
                m_value = TObj(std::move(spValue));
            }
            else if (hr != E_BOUNDS)
            {
                CheckHr(hr);
            }
            else
            {
                m_value = TObj();
                m_pos = 0;
            }
        }

        TObj m_obj;
        TObj m_value;
        ComPtr<IModelIterator> m_spIterator;
        size_t m_pos;
    };

    //*************************************************
    // String Extraction:
    //

    template<typename TArg> struct StringExtractorHelper;

    template<>
    struct StringExtractorHelper<wchar_t *>
    {
        static _Ret_z_ const wchar_t *GetString(_In_z_ const wchar_t *pc) { return pc; }
    };

    template<>
    struct StringExtractorHelper<const wchar_t *>
    {
        static _Ret_z_ const wchar_t *GetString(_In_z_ const wchar_t *pc) { return pc; }
    };

    template<>
    struct StringExtractorHelper<std::wstring>
    {
        static _Ret_z_ const wchar_t *GetString(_In_ const std::wstring &str) { return str.c_str(); }
    };

    // ExtractString():
    //
    // Extracts a const wchar_t * from the incoming argument.  This allows generic passing of anything we
    // can pull a string from (e.g.: wchar_t *, std::wstring).
    //
    template<typename TArg>
    _Ret_z_ const wchar_t *ExtractString(TArg&& str)
    {
        return StringExtractorHelper<std::decay_t<TArg>>::GetString(std::forward<TArg>(str));
    }

    //*************************************************
    // Key Filling:
    //

    template<typename TBase, typename... TArgs> struct KeyFiller;

    template<typename TBase>
    struct KeyFiller<TBase>
    {
        static void Fill(_In_ TBase * /*pBase*/)
        {
        }
    };

    // KeyFiller::Fill():
    //
    // Fills an IModelObject or IKeyStore with a set of keys/values provided by the variable
    // argument pack.
    //
    // Each argument set in the pack must be: (stringExtractable, value)
    //
    //     where stringExtractable is the name and can be any type supported by ExtractString()
    //       and value is the value of that key
    //
    template<typename TBase, typename TStr, typename TArg, typename... TArgs>
    struct KeyFiller<TBase, TStr, TArg, TArgs...>
    {
        static void Fill(_In_ TBase *pBase, _In_ TStr&& keyName, _In_ TArg&& value, _In_ TArgs&&... remainingInitializers)
        {
            const wchar_t *pStr = ExtractString(keyName);
            Object obj = BoxObject(std::forward<TArg>(value));
            CheckHr(pBase->SetKey(pStr, obj, nullptr));
            KeyFiller<TBase, TArgs...>::Fill(pBase, std::forward<TArgs>(remainingInitializers)...);
        }
    };

    template<typename TBase, typename TStr, typename TArg, typename... TArgs>
    struct KeyFiller<TBase, TStr, TArg, Metadata, TArgs...>

    {
        static void Fill(_In_ TBase *pBase, _In_ TStr&& keyName, _In_ TArg&& value, _In_ Metadata&& metadata,
                         _In_ TArgs&&... remainingInitializers)
        {
            const wchar_t *pStr = ExtractString(keyName);
            Object obj = BoxObject(std::forward<TArg>(value));
            CheckHr(pBase->SetKey(pStr, obj, metadata));
            KeyFiller<TBase, TArgs...>::Fill(pBase, std::forward<TArgs>(remainingInitializers)...);
        }
    };


    //*************************************************
    // C++ operator support on objects
    //

    template<typename TObj>
    struct ObjectOperators
    {
        static TObj Increment(_In_ const TObj& src) { return Adjust(src, 1); }
        static TObj IncrementBy(_In_ const TObj& src, LONG64 increment) { return Adjust(src, increment); }
        static TObj Decrement(_In_ const TObj& src) { return Adjust(src, -1); }
        static TObj DecrementBy(_In_ const TObj& src, LONG64 decrement) { return Adjust(src, decrement); }

    private:

        static TObj Adjust(_In_ const TObj& src, _In_ LONG64 adjustment)
        {
            ModelObjectKind mk = src.GetKind();
            switch(mk)
            {
                case ObjectIntrinsic:
                {
                    Type ty = src.Type();
                    if (ty != nullptr)
                    {
                        TypeKind tk = ty.GetKind();
                        if (tk == TypePointer)
                        {
                            HostContext ctx = src;

                            ULONG64 ptrVal = (ULONG64)src;
                            return TObj::CreatePointer(ctx, ty, adjustment * ty.BaseType().Size() + ptrVal);
                        }
                    }
                    break;
                }
            }

            throw not_implemented();
        }
    };

    //*************************************************
    // Universal reference constructor overloading:
    //

    template<typename... TArgs> struct VarTraits
    {
        using FirstType = void;
    };
    template<typename TArg> struct VarTraits<TArg>
    {
        using FirstType = TArg;
    };
    template<typename TArg, typename... TArgs> struct VarTraits<TArg, TArgs...>
    {
        using FirstType = TArg;
    };

    // IsCopyMove:
    //
    // Support for keeping a copy/move constructor and a universal reference constructor.
    //
    // Usage: (For a constructor which takes a universal reference TArg&&)
    //
    // template<typename TArg,
    //          typename = std::enable_if_t<!Details::IsCopyMove_v<Object, TArg>>
    //
    template<typename T, typename... TArgs> struct IsCopyMove :
        public std::bool_constant<sizeof...(TArgs) == 1 && std::is_same_v<T, std::decay_t<typename VarTraits<TArgs...>::FirstType>>> { };
    template<typename T, typename... TArgs> constexpr bool IsCopyMove_v = IsCopyMove<T, TArgs...>::value;

    //*************************************************
    // Other Detections:

    // IsSingleType:
    //
    // Support for detecting whether an argument pack is a single argument of a given type.
    //
    template<typename TType, typename... TArgs>
    struct IsSingleType : public std::false_type { };

    template<typename TType, typename TArg>
    struct IsSingleType<TType, TArg> : public std::is_same<TArg, std::decay_t<TType>> { };

    template<typename TType, typename... TArgs> constexpr bool IsSingleType_v = IsSingleType<TType, TArgs...>::value;

    //*************************************************
    // ArgumentPacker:
    //
    // Recursive template unwind which takes a set of arbitrarily typed objects, boxes them into
    // model objects, and returns a unique_ptr of Objects.
    //
    using ParameterPack = std::unique_ptr<Object[]>;

    template<size_t i, typename... TArgs>
    struct Packer;

    template<size_t i>
    struct Packer<i>
    {
        static void PackInto(ParameterPack& /*pack*/)
        {
        }
    };

    template<size_t i, typename TArg, typename... TArgs>
    struct Packer<i, TArg, TArgs...>
    {
        static void PackInto(ParameterPack& pack, TArg&& firstArg, TArgs&&... subsequentArgs)
        {
            pack[i] = BoxObject(std::forward<TArg>(firstArg));
            return Packer<i + 1, TArgs...>::PackInto(pack, std::forward<TArgs>(subsequentArgs)...);
        }
    };

    template<typename T, typename... TArgs>
    ParameterPack PackValuesHelper(TArgs&&... args)
    {
        size_t packSize = sizeof...(args);
        ParameterPack argPack(new T[packSize]);
        Packer<0, TArgs...>::PackInto(argPack, std::forward<TArgs>(args)...);
        return argPack;
    }

    // PackValues():
    //
    // Packs a set of arguments into an allocated array of objects and returns it.
    //
    template<typename... TArgs>
    ParameterPack PackValues(TArgs&&... args)
    {
        return PackValuesHelper<Object>(std::forward<TArgs>(args)...);
    }

    template<size_t i, size_t count, typename TTuple>
    struct TuplePacker
    {
        static void PackInto(ParameterPack& pack, const TTuple& tuple)
        {
            pack[i] = BoxObject(std::get<i>(tuple));
            return TuplePacker<i + 1, count, TTuple>::PackInto(pack, tuple);
        }
    };

    template<size_t i, typename TTuple>
    struct TuplePacker<i, i, TTuple>
    {
        static void PackInto(ParameterPack& /*pack*/, const TTuple& /*tuple*/)
        {
        }
    };

    // PackTuple():
    //
    // Packs a tuple of arguments into an allocated array of objects and returns it.
    //
    template<typename TTuple>
    ParameterPack PackTuple(const TTuple& tuple)
    {
        constexpr size_t packSize = std::tuple_size_v<TTuple>;
        std::unique_ptr<Object[]> argPack(new Object[packSize]);
        TuplePacker<0, packSize, TTuple>::PackInto(argPack, tuple);
        return argPack;
    }

} // Details

//**************************************************************************
// Basic Wrappers:
//

// TypeSignature:
//
// Represents a type signature.
//
class TypeSignature
{
public:

    TypeSignature() { }
    TypeSignature(_In_ IDebugHostTypeSignature *pTypeSignature) : m_spTypeSignature(pTypeSignature) { }
    TypeSignature(_In_ const ComPtr<IDebugHostTypeSignature> &spTypeSignature) : m_spTypeSignature(spTypeSignature) { }
    TypeSignature(_In_ ComPtr<IDebugHostTypeSignature>&& spTypeSignature) : m_spTypeSignature(std::move(spTypeSignature)) { }
    TypeSignature(_In_ const TypeSignature& src) : m_spTypeSignature(src.m_spTypeSignature) { }
    TypeSignature(_In_ TypeSignature&& src) : m_spTypeSignature(std::move(src.m_spTypeSignature)) { }

    TypeSignature& operator=(_In_ const TypeSignature& src) { m_spTypeSignature = src.m_spTypeSignature; return *this; }
    TypeSignature& operator=(_In_ TypeSignature&& src) { m_spTypeSignature = std::move(src.m_spTypeSignature); return *this; }

    // TypeSignature(signature)
    //
    // Creates a type signature for a type whose name matches the supplied string signature.  This matches regardless
    // of module / version.
    //
    TypeSignature(_In_z_ const wchar_t *signature)
    {
        ComPtr<IDebugHostSymbols> spHostSym;
        ClientEx::CheckHr(ClientEx::GetHost()->QueryInterface(IID_PPV_ARGS(&spHostSym)));
        ClientEx::CheckHr(spHostSym->CreateTypeSignature(signature, nullptr, &m_spTypeSignature));
    }

    TypeSignature(_In_ std::wstring& signature)
    {
        ComPtr<IDebugHostSymbols> spHostSym;
        ClientEx::CheckHr(ClientEx::GetHost()->QueryInterface(IID_PPV_ARGS(&spHostSym)));
        ClientEx::CheckHr(spHostSym->CreateTypeSignature(signature.c_str(), nullptr, &m_spTypeSignature));
    }

    // TypeSignature(signature, module)
    //
    // Creates a type signature for a type whose name matches the supplied string signature within the given module.
    //
    template<typename TStr>
    TypeSignature(_In_ TStr&& signature, _In_ const Module& module)
    {
        const wchar_t *pSignature = Details::ExtractString(signature);
        ComPtr<IDebugHostSymbols> spHostSym;
        ClientEx::CheckHr(ClientEx::GetHost()->QueryInterface(IID_PPV_ARGS(&spHostSym)));
        ClientEx::CheckHr(spHostSym->CreateTypeSignature(pSignature, module, &m_spTypeSignature));
    }

    // TypeSignature(signature, moduleName)
    //
    // Creates a type signature for a type whose name and module name matches the supplied string signatures.
    //
    template<typename TStr1, typename TStr2,
             typename = std::enable_if_t<!std::is_same_v<typename std::decay_t<TStr2>, Module>>>
    TypeSignature(_In_ TStr1&& signature, _In_ TStr2&& moduleName)
    {
        const wchar_t *pSignature = Details::ExtractString(signature);
        const wchar_t *pModuleName = Details::ExtractString(moduleName);
        ComPtr<IDebugHostSymbols> spHostSym;
        ClientEx::CheckHr(ClientEx::GetHost()->QueryInterface(IID_PPV_ARGS(&spHostSym)));
        ClientEx::CheckHr(spHostSym->CreateTypeSignatureForModuleRange(pSignature,
                                                                                pModuleName,
                                                                                nullptr,
                                                                                nullptr,
                                                                                &m_spTypeSignature));
    }

    // TypeSignature(signature, moduleName, minVersion)
    //
    // Creates a type signature for a type whose name and module name match the supplied signatures.  The module must
    // be at least the specified version.
    //
    template<typename TStr1, typename TStr2, typename TStr3>
    TypeSignature(_In_ TStr1&& signature, _In_ TStr2&& moduleName, _In_ TStr3&& minVersion)
    {
        const wchar_t *pSignature = Details::ExtractString(signature);
        const wchar_t *pModuleName = Details::ExtractString(moduleName);
        const wchar_t *pMinVersion = Details::ExtractString(minVersion);
        ComPtr<IDebugHostSymbols> spHostSym;
        ClientEx::CheckHr(ClientEx::GetHost()->QueryInterface(IID_PPV_ARGS(&spHostSym)));
        ClientEx::CheckHr(spHostSym->CreateTypeSignatureForModuleRange(pSignature,
                                                                                pModuleName,
                                                                                pMinVersion,
                                                                                nullptr,
                                                                                &m_spTypeSignature));
    }

    // TypeSignature(signature, moduleName, minVersion, maxVersion)
    //
    // Creates a type signature for a type whose name and module name match the supplied signatures.  The module must
    // be at least the specified min version and no more than the max version.
    //
    template<typename TStr1, typename TStr2, typename TStr3, typename TStr4>
    TypeSignature(_In_ TStr1&& signature, _In_ TStr2&& moduleName, _In_ TStr3&& minVersion, _In_ TStr4&& maxVersion)
    {
        const wchar_t *pSignature = Details::ExtractString(signature);
        const wchar_t *pModuleName = Details::ExtractString(moduleName);
        const wchar_t *pMinVersion = Details::ExtractString(minVersion);
        const wchar_t *pMaxVersion = Details::ExtractString(maxVersion);
        ComPtr<IDebugHostSymbols> spHostSym;
        ClientEx::CheckHr(ClientEx::GetHost()->QueryInterface(IID_PPV_ARGS(&spHostSym)));
        ClientEx::CheckHr(spHostSym->CreateTypeSignatureForModuleRange(pSignature,
                                                                                pModuleName,
                                                                                pMinVersion,
                                                                                pMaxVersion,
                                                                                &m_spTypeSignature));
    }

    operator IDebugHostTypeSignature* () const { return m_spTypeSignature.Get(); }

protected:

    ComPtr<IDebugHostTypeSignature> m_spTypeSignature;
};

//**************************************************************************
// Metadata:
//
// Represents metadata in the object model
//

// Metadata:
//
// Represents object metadata which can be set on keys or returned in various other contexts.
//
class Metadata
{
public:

    Metadata() { }
    Metadata(_In_ const Metadata &src) : m_spKeyStore(src.m_spKeyStore) { }
    Metadata(_In_ Metadata&& src) : m_spKeyStore(std::move(src.m_spKeyStore)) { }
    Metadata(_In_ IKeyStore *pKeyStore) : m_spKeyStore(pKeyStore) { }
    Metadata(_In_ ComPtr<IKeyStore>& spKeyStore) : m_spKeyStore(spKeyStore) { }
    Metadata(_In_ const ComPtr<IKeyStore>& spKeyStore) : m_spKeyStore(spKeyStore) { }
    Metadata(_In_ ComPtr<IKeyStore>&& spKeyStore) : m_spKeyStore(std::move(spKeyStore)) { }

    Metadata& operator=(_In_ const Metadata& rhs)
    {
        m_spKeyStore = rhs.m_spKeyStore;
        return *this;
    }

    Metadata& operator=(_In_ Metadata&& rhs)
    {
        m_spKeyStore = std::move(rhs.m_spKeyStore);
        return *this;
    }

    template<typename... TArgs,
             typename = std::enable_if_t<!Details::IsCopyMove_v<Metadata, TArgs...>>>
    explicit Metadata(_In_ TArgs&&... initializers);

    operator IKeyStore *() const { return m_spKeyStore.Get(); }
    IKeyStore *operator->() const { return m_spKeyStore.Get(); }
    IKeyStore *Detach() { return m_spKeyStore.Detach(); }

    Object KeyValue(_In_z_ const wchar_t *keyName) const;

    template<typename... TArgs,
             typename = std::enable_if_t<!Details::IsCopyMove_v<Metadata, TArgs...>>>
    void SetKeys(_In_ TArgs&&... initializers);

private:

    void EnsureCreated()
    {
        if (m_spKeyStore != nullptr)
        {
            return;
        }

        CheckHr(GetManager()->CreateMetadataStore(nullptr, &m_spKeyStore));
    }

    ComPtr<IKeyStore> m_spKeyStore;

};

//**************************************************************************
//
// Object:
//
// Represents an object in the data model
//

class Deconstruction;

class Object
{
public:

    using iterator = Details::ObjectIterator<Object>;
    using const_iterator = Details::ObjectIterator<Object>;

    //*************************************************
    // Factory Methods:
    //

    // RootNamespace():
    //
    // Returns the root namespace of the host.
    //
    static Object RootNamespace()
    {
        ComPtr<IModelObject> spObj;
        CheckHr(GetManager()->GetRootNamespace(&spObj));
        return Object(std::move(spObj));
    }

    // CurrentContext():
    //
    // Returns a boxed representation of the current context of the host.
    //
    static Object CurrentContext()
    {
        ComPtr<IDebugHostContext> spCtx;
        CheckHr(GetHost()->GetCurrentContext(&spCtx));
        return Object(std::move(spCtx));
    }

    // SessionOf():
    //
    // Returns the session associated with the given object.  If no session is associated with the
    // given object, an exception is thrown.
    //
    static Object SessionOf(_In_ const Object& obj)
    {
        return RootNamespace().KeyValue(L"Debugger").KeyValue(L"Sessions")[obj];
    }

    // ProcessOf():
    //
    // Returns the process associated with the given object.  If no process is associated with the
    // given object, an exception is thrown.
    //
    static Object ProcessOf(_In_ const Object& obj)
    {
        return SessionOf(obj).KeyValue(L"Processes")[obj];
    }

    // ThreadOf():
    //
    // Returns the thread associated with the given object.  If no thread is associated with the
    // given object, an exception is thrown.
    //
    static Object ThreadOf(_In_ const Object& obj)
    {
        return ProcessOf(obj).KeyValue(L"Threads")[obj];
    }

    // CurrentSession():
    //
    // Returns the current session of the host.
    //
    static Object CurrentSession()
    {
        return SessionOf(CurrentContext());
    }

    // CurrentProcess():
    //
    // Returns the current process of the host.
    //
    static Object CurrentProcess()
    {
        return ProcessOf(CurrentContext());
    }

    // CurrentThread():
    //
    // Returns the current thread of the host.
    //
    static Object CurrentThread()
    {
        return ThreadOf(CurrentContext());
    }

    // Create():
    //
    // Creates a new empty object with the given context.
    //
    template<typename... TArgs>
    static Object Create(_In_ const HostContext& hostContext, _In_ TArgs&&... initializers)
    {
        ComPtr<IModelObject> spObj;
        CheckHr(GetManager()->CreateSyntheticObject(hostContext, &spObj));
        Details::KeyFiller<IModelObject, TArgs...>::Fill(spObj.Get(), std::forward<TArgs>(initializers)...);
        return Object(std::move(spObj));
    }

    // Create():
    //
    // Creates a new empty object from metadata (key store) with the given context .
    //
    template<typename... TArgs>
    static Object Create(_In_ const HostContext& hostContext, _In_ const Metadata& metadata, _In_ TArgs&&... initializers)
    {
        Microsoft::WRL::ComPtr<IDataModelManager4> spDataModelManager4;
        {
            Microsoft::WRL::ComPtr<IDataModelManager> spDataModelManager = GetManager();
            CheckHr(spDataModelManager.As(&spDataModelManager4));
        }

        ComPtr<IModelObject> spObj;
        CheckHr(spDataModelManager4->CreateSyntheticObjectFromKeyStore(hostContext, metadata, &spObj));
        Details::KeyFiller<IModelObject, TArgs...>::Fill(spObj.Get(), std::forward<TArgs>(initializers)...);
        return Object(std::move(spObj));
    }

    // CreateTyped():
    //
    // Creates a new typed object.
    //
    static Object CreateTyped(_In_ const Type& objectType, _In_ const Location& objectLocation)
    {
        ComPtr<IModelObject> spObj;
        CheckHr(GetManager()->CreateTypedObject(nullptr, objectLocation, objectType, &spObj));
        return Object(std::move(spObj));
    }

    // CreateTyped():
    //
    // Creates a new typed object.
    //
    static Object CreateTyped(_In_ const HostContext& hostContext, _In_ const Type& objectType, _In_ const Location& objectLocation)
    {
        ComPtr<IModelObject> spObj;
        CheckHr(GetManager()->CreateTypedObject(hostContext, objectLocation, objectType, &spObj));
        return Object(std::move(spObj));
    }

    // CreatePointer():
    //
    // Creates a new pointer object.
    //
    static Object CreatePointer(_In_ const Type& pointerType, _In_ ULONG64 ptrValue)
    {
        if (pointerType.GetKind() != TypePointer)
        {
            throw std::invalid_argument("Supplied type is not a pointer");
        }

        VARIANT vtPtr; vtPtr.vt = VT_UI8; vtPtr.ullVal = ptrValue;

        ComPtr<IModelObject> spObj;
        CheckHr(GetManager()->CreateTypedIntrinsicObject(&vtPtr, pointerType, &spObj));
        return Object(std::move(spObj));
    }

    // CreatePointer():
    //
    // Creates a new pointer object.
    //
    static Object CreatePointer(_In_ const HostContext& hostContext, _In_ const Type& pointerType, _In_ ULONG64 ptrValue)
    {
        if (pointerType.GetKind() != TypePointer)
        {
            throw std::invalid_argument("Supplied type is not a pointer");
        }

        VARIANT vtPtr; vtPtr.vt = VT_UI8; vtPtr.ullVal = ptrValue;

        ComPtr<IDataModelManager2> spManager2;
        {
            ComPtr<IDataModelManager> spManager = GetManager();

            CheckHr(spManager.As(&spManager2));
        }

        ComPtr<IModelObject> spObj;
        CheckHr(spManager2->CreateTypedIntrinsicObjectEx(hostContext, &vtPtr, pointerType, &spObj));
        return Object(std::move(spObj));
    }

    // CreateNoValue():
    //
    // Creates a "No Value" object.
    //
    static Object CreateNoValue()
    {
        ComPtr<IModelObject> spObj;
        CheckHr(GetManager()->CreateNoValue(&spObj));
        return Object(std::move(spObj));
    }

    // CreateError():
    //
    // Creates an error object from an hresult and a string.
    //
    template<typename TStr>
    static Object CreateError(_In_ HRESULT hr, _In_ TStr &&str)
    {
        ComPtr<IModelObject> spError;
        CheckHr(GetManager()->CreateErrorObject(hr, Details::ExtractString(str), &spError));
        return Object(std::move(spError));
    }

    // CreateError():
    //
    // Creates an error object from an exception pointer.
    //
    static Object CreateError(_In_ const std::exception_ptr& exptr)
    {
        ComPtr<IModelObject> spError;
        auto hr = Details::Exceptions::ReturnResult(exptr, &spError);
        if (!spError) {
            CheckHr(GetManager()->CreateErrorObject(hr, nullptr, &spError));
        }

        return Object(std::move(spError));
    }

    // FromExpressionEvaluation():
    //
    // Creates an object from a language expression evaluation.  This may only use the underlying
    // syntax of the language.  There is a guarantee that such is portable from host to host (as long as both hosts
    // debug the same language)
    //
    template<typename TStr>
    static Object FromExpressionEvaluation(_In_ const HostContext& evaluationContext, _In_ TStr&& expression)
    {
        ComPtr<IModelObject> spObj;
        ComPtr<IDebugHostEvaluator> spEval;
        CheckHr(GetHost()->QueryInterface(IID_PPV_ARGS(&spEval)));
        CheckHr(spEval->EvaluateExpression(evaluationContext, Details::ExtractString(expression), nullptr, &spObj, nullptr));
        return Object(std::move(spObj));
    }

    // FromExtendedExpressionEvaluation():
    //
    // Creates an object from a host specific expression evaluation.  This may use any syntax the underlying host supports; however,
    // there is *NO GUARANTEE* that such is portable from host to host.
    //
    template<typename TStr>
    static Object FromExtendedExpressionEvaluation(_In_ const HostContext& evaluationContext, _In_ TStr&& expression)
    {
        ComPtr<IModelObject> spObj;
        ComPtr<IDebugHostEvaluator> spEval;
        CheckHr(GetHost()->QueryInterface(IID_PPV_ARGS(&spEval)));
        CheckHr(spEval->EvaluateExtendedExpression(evaluationContext, Details::ExtractString(expression), nullptr, &spObj, nullptr));
        return Object(std::move(spObj));
    }

    //
    // @TODO: This is **NOT** complete.
    //
    static Object FromSymbol(_In_ IDebugHostSymbol *pSymbol)
    {
        SymbolKind sk;
        CheckHr(pSymbol->GetSymbolKind(&sk));

        switch(sk)
        {
            case SymbolData:
            {
                ComPtr<IDebugHostData> spData;
                CheckHr(pSymbol->QueryInterface(IID_PPV_ARGS(&spData)));

                ComPtr<IDebugHostType> spType;
                Location loc;

                CheckHr(spData->GetType(&spType));
                CheckHr(spData->GetLocation(&loc));

                ComPtr<IModelObject> spObj;
                CheckHr(GetManager()->CreateTypedObject(nullptr, loc, spType.Get(), &spObj));
                return Object(std::move(spObj));
            }

            default:
                // @TODO:
                throw not_implemented();
        }
    }

    template<typename TStr1, typename TStr2>
    static Object FromGlobalSymbol(const HostContext& symbolContext,
                                   TStr1&& moduleName,
                                   TStr2&& symbolName)
    {
        Module symMod(symbolContext, Details::ExtractString(moduleName));

        ComPtr<IDebugHostSymbols> spSymbols;
        CheckHr(GetHost()->QueryInterface(IID_PPV_ARGS(&spSymbols)));

        ComPtr<IDebugHostSymbol> spSymbol;
        CheckHr(symMod->FindSymbolByName(Details::ExtractString(symbolName), &spSymbol));

        return FromSymbol(spSymbol.Get());
    }

    // FromModelName():
    //
    // Returns an object based on a lookup from a registered model name.
    //
    template<typename TStr>
    static Object FromModelName(TStr&& modelName)
    {
        std::wstring name = Details::ExtractString(modelName);
        ComPtr<IModelObject> spModel;
        CheckHr(GetManager()->AcquireNamedModel(name.c_str(), &spModel));
        return Object(std::move(spModel));
    }

    // CreateInstanceOf():
    //
    // Creates a synthetic object which is an instance of a particular data model.
    //
    static Object CreateInstanceOf(_In_ const Object& model,
                                   _In_ const HostContext& hostContext)
    {
        Object o = Create(hostContext);
        CheckHr(o->AddParentModel(model, nullptr, false));

        return o;
    }

    // ConstructModelInstance():
    //
    // Creates an instance of a named model which supports the constructable concept.
    //
    template<typename TStr, typename... TArgs>
    static Object ConstructModelInstance(TStr&& name, TArgs&&... args)
    {
        Object dataModel = Object::FromModelName(std::forward<TStr>(name));
        return dataModel.ConstructInstance(std::forward<TArgs>(args)...);
    }

    //*************************************************
    // Object Methods:
    //

    Object() { }
    Object(_In_ IModelObject *pObject) : m_spObject(pObject) { }
    Object(_In_ const Object& src) : m_spObject(src.m_spObject) { }
    Object(_In_ Object&& src) : m_spObject(std::move(src.m_spObject)) { }
    Object(_In_ ComPtr<IModelObject>& src) : m_spObject(src) { }
    Object(_In_ const ComPtr<IModelObject>& src) : m_spObject(src) { }
    Object(_In_ ComPtr<IModelObject>&& src) : m_spObject(std::move(src)) { }
    Object(_In_ std::nullptr_t) { }

    // Constructor:
    //
    // Construct from arbitrary type.
    //
    template<typename TArg,
             typename = std::enable_if_t<!Details::IsCopyMove_v<Object, TArg>>>
    Object(_In_ TArg&& value);

    template<typename TArg> explicit operator TArg() const { return As<TArg>(); }

    IModelObject *Detach()
    {
        return Steal();
    }

    IModelObject *GetObject() const
    {
        return m_spObject.Get();
    }

    operator IModelObject *() const
    {
        return GetObject();
    }

    operator HostContext() const
    {
        ComPtr<IDebugHostContext> spCtx;
        CheckHr(m_spObject->GetContext(&spCtx));
        return HostContext(std::move(spCtx));
    }

    IModelObject *operator->() const
    {
        return GetObject();
    }

    // operator++:
    //
    // Pre-increment (for pointer types and the like)
    //
    Object& operator++()
    {
        Object incremented = Details::ObjectOperators<Object>::Increment(*this);
        *this = std::move(incremented);
        return *this;
    }

    // operator++:
    //
    // Post-increment (for pointer types and the like)
    //
    Object operator++(int)
    {
        Object original = *this;
        ++(*this);
        return original;
    }

    // operator+=:
    //
    // Increment by operation.
    //
    Object& operator+=(_In_ LONG64 offset)
    {
        Object incremented = Details::ObjectOperators<Object>::IncrementBy(*this, static_cast<LONG64>(offset));
        *this = std::move(incremented);
        return *this;
    }

    // operator--:
    //
    // Pre-decrement (for pointer types and the like)
    //
    Object& operator--()
    {
        Object decremented = Details::ObjectOperators<Object>::Decrement(*this);
        *this = std::move(decremented);
        return *this;
    }

    // operator--:
    //
    // Post-decrement (for pointer types and the like)
    //
    Object operator--(int)
    {
        Object original = *this;
        --(*this);
        return original;
    }

    // operator-=:
    //
    // Decrement by operation.
    //
    Object& operator-=(_In_ LONG64 offset)
    {
        Object decremented = Details::ObjectOperators<Object>::DecrementBy(*this, static_cast<LONG64>(offset));
        *this = std::move(decremented);
        return *this;
    }

    // operator==:
    //
    // Compare to another object for equality.
    //
    template<typename TArg>
    bool operator==(_In_ TArg&& other) const { return IsEqualTo(std::forward<TArg>(other)); }

    // operator!=
    //
    // Compare to another object for lack of equality.
    //
    template<typename TArg>
    bool operator!=(_In_ TArg&& other) const { return !operator==(std::forward<TArg>(other)); }

    // Comparison operators:
    //
    // Performs comparison with another objects.  If there is no path by which the objects can be compared,
    // an exception will be thrown.
    //
    template<typename TArg> bool operator<(_In_ TArg&& other) const { return CompareTo(std::forward<TArg>(other)) < 0; }
    template<typename TArg> bool operator>(_In_ TArg&& other) const { return CompareTo(std::forward<TArg>(other)) > 0; }
    template<typename TArg> bool operator<=(_In_ TArg&& other) const { return CompareTo(std::forward<TArg>(other)) <= 0; }
    template<typename TArg> bool operator>=(_In_ TArg&& other) const { return CompareTo(std::forward<TArg>(other)) >= 0; }

    // GetKind():
    //
    // Gets the kind of object this is (according to the data model).
    //
    ModelObjectKind GetKind() const
    {
        ModelObjectKind mk;
        ClientEx::CheckHr(m_spObject->GetKind(&mk));
        return mk;
    }

    // Type():
    //
    // The type of object.  This will return an empty Type() for objects that have no native type.
    //
    Type Type() const
    {
        ComPtr<IDebugHostType> spType;
        CheckHr(m_spObject->GetTypeInfo(&spType));
        return ClientEx::Type(std::move(spType));
    }

    // GetLocation():
    //
    // The location of the object.  This will throw for objects which have no location.
    //
    Location GetLocation() const
    {
        Location objLocation;
        CheckHr(m_spObject->GetLocation(&objLocation));
        return objLocation;
    }

    // Keys():
    //
    // Returns a collection of the keys on the object.
    //
    Details::ObjectKeysRef<Object, Metadata> Keys() const
    {
        return Details::ObjectKeysRef<Object, Metadata>(*this);
    }

    // KeyValue():
    //
    // Fetches a key value without the overhead of returning key references.
    //
    Object KeyValue(_In_z_ const wchar_t *keyName, _Out_opt_ Metadata *pMetadata = nullptr) const
    {
        if (pMetadata != nullptr)
        {
            *pMetadata = Metadata();
        }

        ComPtr<IModelObject> spValue;
        ComPtr<IKeyStore> spMetadata;
        IKeyStore **ppMetadata = (pMetadata != nullptr) ? (IKeyStore **)&spMetadata : nullptr;
        CheckHr(m_spObject->GetKeyValue(keyName, &spValue, ppMetadata));

        if (pMetadata != nullptr)
        {
            *pMetadata = Metadata(std::move(spMetadata));
        }
        return Object(std::move(spValue));
    }

    // KeyValue():
    //
    // Fetches a key value without the overhead of returning key references.
    //
    Object KeyValue(_In_ const std::wstring& keyName, _Out_opt_ Metadata *pMetadata = nullptr) const
    {
        return KeyValue(keyName.c_str(), pMetadata);
    }

    // TryGetKeyValue():
    //
    // Fetches a key value, if it exists, without the overhead of returning key references.
    //
    std::optional<Object> TryGetKeyValue(_In_z_ const wchar_t *keyName, _Out_opt_ Metadata *pMetadata = nullptr) const
    {
        if (pMetadata != nullptr)
        {
            *pMetadata = Metadata();
        }

        ComPtr<IModelObject> spValue;
        ComPtr<IKeyStore> spMetadata;
        IKeyStore **ppMetadata = (pMetadata != nullptr) ? (IKeyStore **)&spMetadata : nullptr;
        if (SUCCEEDED(m_spObject->GetKeyValue(keyName, &spValue, ppMetadata)))
        {
            if (pMetadata != nullptr)
            {
                *pMetadata = Metadata(std::move(spMetadata));
            }

            return Object(std::move(spValue));
        }

        return std::nullopt;
    }

    // TryGetKeyValue():
    //
    // Fetches a key value, if it exists, without the overhead of returning key references.
    //
    std::optional<Object> TryGetKeyValue(_In_ const std::wstring& keyName, _Out_opt_ Metadata *pMetadata = nullptr) const
    {
        return TryGetKeyValue(keyName.c_str(), pMetadata);
    }

    // Fields():
    //
    // Returns a collection of the native fields on the object.
    //
    Details::ObjectFieldsRef<Object> Fields() const
    {
        return Details::ObjectFieldsRef<Object>(*this);
    }

    // FieldValue():
    //
    // Fetches a field value without the overhead of returning field references.
    //
    Object FieldValue(_In_z_ const wchar_t *fieldName) const
    {
        ComPtr<IModelObject> spValue;
        CheckHr(m_spObject->GetRawValue(SymbolField, fieldName, RawSearchNone, &spValue));
        return Object(std::move(spValue));
    }

    // FieldValue():
    //
    // Fetches a field value without the overhead of returning field references.
    //
    Object FieldValue(_In_ const std::wstring& fieldName) const
    {
        return FieldValue(fieldName.c_str());
    }

    // TryGetFieldValue():
    //
    // Fetches a field, if it exists, without the overhead of returning field
    // references.
    //
    std::optional<Object> TryGetFieldValue(_In_z_ const wchar_t *fieldName) const
    {
        ComPtr<IModelObject> spValue;
        if (SUCCEEDED(m_spObject->GetRawValue(SymbolField, fieldName, RawSearchNone, &spValue)))
        {
            return Object(std::move(spValue));
        }

        return std::nullopt;
    }

    // TryGetFieldValue():
    //
    // Fetches a field, if it exists, without the overhead of returning field
    // references.
    //
    std::optional<Object> TryGetFieldValue(_In_ const std::wstring& fieldName) const
    {
        return TryGetFieldValue(fieldName.c_str());
    }

    // Dereference():
    //
    // Returns a "reference" to the dereferenced object.
    //
    Details::DereferenceReference<Object> Dereference() const
    {
        return Details::DereferenceReference<Object>(*this);
    }

    // operator=:
    //
    // Copy another object.
    //
    Object& operator=(const Object& src)
    {
        m_spObject = src.m_spObject;
        return *this;
    }

    // operator=:
    //
    // Move another object.
    //
    Object& operator=(Object&& src)
    {
        m_spObject = std::move(src.m_spObject);
        return *this;
    }

    // operator=:
    //
    // Perform assignment to an object.
    //
    template<typename TArg,
             typename = std::enable_if_t<!Details::IsCopyMove_v<Object, TArg>>>
    Object& operator=(TArg&& assignmentValue);

    // As():
    //
    // Converts the object too something else.
    //
    template<typename TType> TType As() const;

    // Call():
    //
    // Calls an object which represents a method and returns a new object representing the result.
    // If the object is not a method or the call fails, an exception is thrown.
    //
    // The original "this" pointer must be passed into this method.
    //
    template<typename... TArgs> Object Call(_In_ const Object& instance, TArgs&&... callArguments) const;

    // CallMethod():
    //
    // Finds a method of the given name on this object and calls it as an instance method.
    //
    template<typename... TArgs> Object CallMethod(_In_z_ const wchar_t *methodName, TArgs&&... callArguments) const
    {
        Object method = this->Keys()[methodName];
        return method.Call(*this, std::forward<TArgs>(callArguments)...);
    }
    template<typename... TArgs> Object CallMethod(_In_ const std::wstring& methodName, TArgs&&... callArguments) const
    {
        return CallMethod(methodName.c_str(), std::forward<TArgs>(callArguments)...);
    }

    // operator[]():
    //
    // Indexes an object
    //
    template<typename... TArgs> Details::IndexableReference<Object, std::unique_ptr<Object[]>> operator[](TArgs&&... indexers) const
    {
        return Index(std::forward<TArgs>(indexers)...);
    }

    template<typename... TArgs> Details::IndexableReference<Object, std::unique_ptr<Object[]>> Index(TArgs&&... indexers) const;


    // begin():
    //
    // Returns a starting iterator.  If the object is not iterable, this will throw an exception.  The returned
    // iterator is a forward iterator.
    //
    iterator begin()
    {
        ComPtr<IIterableConcept> spIterable;
        CheckHr(m_spObject->GetConcept(__uuidof(IIterableConcept), &spIterable, nullptr));
        ComPtr<IModelIterator> spIterator;
        CheckHr(spIterable->GetIterator(GetObject(), &spIterator));
        return iterator(*this, spIterator.Get());
    }
    const_iterator begin() const { return cbegin(); }

    // end():
    //
    // Returns the ending iterator.
    //
    iterator end()
    {
        return iterator();
    }
    const_iterator end() const { return cend(); }

    // cbegin():
    //
    // Returns a constant starting iterator.  If the object is not iterable, this will throw an exception.  The
    // returned iterator is a forward iterator.
    //
    const_iterator cbegin() const
    {
        ComPtr<IIterableConcept> spIterable;
        CheckHr(m_spObject->GetConcept(__uuidof(IIterableConcept), &spIterable, nullptr));
        ComPtr<IModelIterator> spIterator;
        CheckHr(spIterable->GetIterator(GetObject(), &spIterator));
        return iterator(*this, spIterator.Get());
    }

    // cend():
    //
    // Returns the constant end iterator.
    //
    const_iterator cend() const
    {
        return iterator();
    }

    // CompareTo():
    //
    // Compares this object to another.  If there is no comparison defined between the two object types, this
    // will throw.
    //
    template<typename TArg> int CompareTo(TArg&& other) const;

    // IsEqualTo():
    //
    // Compares this object to another.  If there is no equality defined between the two object types, this
    // will throw.
    //
    template<typename TArg> bool IsEqualTo(TArg&& other) const;

    // ToDisplayString():
    //
    // If the object has a string conversion, it is returned; otherwise, an exception is thrown.
    //
    std::wstring ToDisplayString(_In_ const Metadata& metadata) const
    {
        ComPtr<IStringDisplayableConcept> spStringDisplayable;
        CheckHr(m_spObject->GetConcept(__uuidof(IStringDisplayableConcept), &spStringDisplayable, nullptr));
        BSTR str;
        CheckHr(spStringDisplayable->ToDisplayString(GetObject(), metadata, &str));
        bstr_ptr spStr(str);
        return std::wstring(str);
    }
    std::wstring ToDisplayString() const { return ToDisplayString(Metadata()); }

    // TryToDisplayString():
    //
    // Check if the object has a string conversion.  If so, true is returned and the string is filled into
    // the output 'pDisplayString' argument; otherwise, false is returned.  If the string fails to fetch,
    // for reasons other than there is no display string, an exception is thrown.
    //
    std::optional<std::wstring> TryToDisplayString(_In_ const Metadata& metadata) const
    {
        std::optional<std::wstring> displayString;

        ComPtr<IStringDisplayableConcept> spStringDisplayable;
        if (SUCCEEDED(m_spObject->GetConcept(__uuidof(IStringDisplayableConcept), &spStringDisplayable, nullptr)))
        {
            BSTR str;
            HRESULT hr = spStringDisplayable->ToDisplayString(GetObject(), metadata, &str);

            //
            // E_NOT_SET is a special code which indicates that there is no display string despite the fact
            // that the concept is implemented.  This is *NOT* a failure to fetch per-se.
            //
            if (hr != E_NOT_SET)
            {
                CheckHr(hr);
            }
            bstr_ptr spStr(str);
            displayString = std::wstring(str);
        }
        return displayString;
    }
    std::optional<std::wstring> TryToDisplayString() const
    {
        return TryToDisplayString(Metadata());
    }
    bool TryToDisplayString(_Out_ std::wstring *pDisplayString, _In_ const Metadata& metadata) const
    {
        auto displayString = TryToDisplayString(metadata);
        if (displayString)
        {
            *pDisplayString = std::move(displayString.value());
            return true;
        }
        return false;
    }
    bool TryToDisplayString(_Out_ std::wstring *pDisplayString)
    {
        return TryToDisplayString(pDisplayString, Metadata());
    }

    // ConstructInstance():
    //
    // If the object is constructable, this will invoke the constructor with the given set of arguments.
    //
    template<typename... TArgs,
             typename = std::enable_if_t<!Details::IsSingleType_v<Deconstruction, TArgs...>>>
    Object ConstructInstance(_In_ TArgs&&... args)
    {
        ComPtr<IConstructableConcept> spConstructable;
        CheckHr(m_spObject->GetConcept(__uuidof(IConstructableConcept), &spConstructable, nullptr));
        Details::ParameterPack pack = Details::PackValues(std::forward<TArgs>(args)...);
        ComPtr<IModelObject> spInstance;
        CheckHr(spConstructable->CreateInstance(sizeof...(args), reinterpret_cast<IModelObject **>(pack.get()), &spInstance));
        return Object(std::move(spInstance));
    }

    Object ConstructInstance(_In_ Deconstruction& deconstruction);

    // Deconstruct():
    //
    // If the object is deconstructable, this returns a deconstruction of the object (a set of constructor
    // arguments which, if supplied back to the constructor, will recreate the object).
    //
    Deconstruction Deconstruct();

private:

    // Steal():
    //
    // Steals the reference of this object.
    //
    IModelObject *Steal()
    {
        return m_spObject.Detach();
    }

    ComPtr<IModelObject> m_spObject;

};

// IndexedValue:
//
// A value which is at a specific index.
//
template<typename TValue, typename... TIndicies>
class IndexedValue
{
public:

    using ValueType = TValue;
    using IndiciesType = std::tuple<TIndicies...>;
    static constexpr size_t Dimensionality = sizeof...(TIndicies);

    IndexedValue() { }

    IndexedValue(_In_ const TValue &value, _In_ TIndicies... indicies) :
        m_value(value),
        m_indicies(std::forward<TIndicies>(indicies)...)
    {
    }

    IndexedValue(_In_ const IndexedValue& src) : m_value(src.m_value), m_indicies(src.m_indicies) { }
    IndexedValue(_In_ IndexedValue&& src) : m_value(std::move(src.m_value)), m_indicies(std::move(src.m_indicies)) { }

    IndexedValue operator=(_In_ const IndexedValue& src) { m_value = src.m_value; m_indicies = src.m_indicies; return *this; }
    IndexedValue operator=(_In_ IndexedValue&& src) { m_value = std::move(src.m_value); m_indicies = std::move(src.m_indicies); return *this; }

    const ValueType& GetValue() const { return m_value; }
    const IndiciesType& GetIndicies() const { return m_indicies; }

private:

    ValueType m_value;
    IndiciesType m_indicies;

};

// GeneratedIterable:
//
// A value which represents the deferred acquisition of an iterable through a method call.  This is a helper
// intended to allow the adaptation of an iterable described by a C++ input iterator which can be regenerated
// to the notion of a data model iterable.  Frequently, this is used to defer the acquisition of a generator
// which is the result of a property binding or method binding.
//
// If you have a property which is bound and looks thus:
//
//     std::experimental::generator<T> MyProperty(...) { co_yield x; }
//
// When the property is fetched, the generator is boxed and the resulting object may only be iterated a single
// time.  This may or may not be the intent of the caller.
//
// Instead, if this object is used:
//
//     GeneratedIterable<std::experimental::generator<T>> MyProperty(...)
//     {
//          return GeneratedIterable<std::experimental::generator<T>>(
//              [...](){ co_yield x; }
//              );
//     }
//
// When the property is fetched, the calling of the method is deferred until the actual iterator fetch.  This way,
// while a given instance of the iterator behaves akin to a C++ input iterator, the iterator can be fetched
// multiple times.
//
// It is important that the returned iterator produce the same elements (aside any semantic manipulations between
// iterations) so that the caller's expectations are met.  In other words, a caller which operates as follows:
//
//     Object container = someObject.KeyValue(L"MyProperty");
//     int count1 = (int)container.CallMethod(L"Count");
//     int count2 = (int)container.CallMethod(L"Count");
//
// should not see differing values of count1 and count2.
//
template<typename TContainer>
class GeneratedIterable
{
public:

    explicit GeneratedIterable(_In_ std::function<TContainer(void)> acquireContainer) :
        m_acquireContainer(acquireContainer)
    {
    }

    std::function<TContainer(void)> const& GetAcquireFunction() const { return m_acquireContainer; }

private:

    std::function<TContainer(void)> m_acquireContainer;
};

template<typename TValue>
class ValueWithMetadata
{
public:

    using ValueType = TValue;

    ValueWithMetadata() = default;

    ValueWithMetadata(_In_ const TValue &value, _In_ Metadata metadata) :
        m_value(value),
        m_metadata(std::move(metadata))
    {
    }
    ValueWithMetadata(TValue&& value, Metadata metadata) :
        m_value(std::move(value)),
        m_metadata(std::move(metadata))
    {
    }

    ValueWithMetadata(_In_ const ValueWithMetadata& src) = default;
    ValueWithMetadata(_In_ ValueWithMetadata&& src) = default;

    ValueWithMetadata& operator=(_In_ const ValueWithMetadata& src) = default;
    ValueWithMetadata& operator=(_In_ ValueWithMetadata&& src) = default;

    const ValueType& GetValue() const { return m_value; }
    ValueType& GetValue() { return m_value; }
    const Metadata& GetMetadata() const { return m_metadata; }
    Metadata& GetMetadata() { return m_metadata; }

private:

    ValueType m_value;
    Metadata m_metadata;
};

// Deconstruction:
//
// Represents the deconstruction of an object from the deconstructable concept.  It is effectively a
// "limited serialization" of the object.
//
class Deconstruction
{
public:

    Deconstruction(_In_z_ const wchar_t *pConstructableModel,
                   _In_ ULONG64 argCount,
                   _In_reads_(argCount) IModelObject **ppArguments) :
        m_constructableModel(pConstructableModel),
        m_arguments(ppArguments, ppArguments + argCount)
    {
    }

    using iterator = std::vector<Object>::iterator;
    using const_iterator = std::vector<Object>::const_iterator;

    const std::wstring& GetConstructableModelName() const { return m_constructableModel; }
    iterator begin() { return m_arguments.begin(); }
    iterator end() { return m_arguments.end(); }
    const_iterator begin() const { return m_arguments.begin(); }
    const_iterator end() const { return m_arguments.end(); }

    // ConstructInstance():
    //
    // Constructs a new instance of the original object from the deconstructed set of arguments.
    //
    Object ConstructInstance()
    {
        Object model = Object::FromModelName(m_constructableModel);
        return model.ConstructInstance(*this);
    }

private:

    std::wstring m_constructableModel;
    std::vector<Object> m_arguments;

};

//
// ResourceString:
//
// A string which is dynamically pulled from the resources of the binary containing the header.
// A ResourceString is pulled from the resource file immediately upon boxing.
//
struct ResourceString
{
    explicit ResourceString(_In_ ULONG id) : Id(id),
                                             ResourceType(nullptr),
                                             Module(nullptr)
    { }

    ResourceString(_In_ ULONG id, _In_ PCWSTR resourceType) : Id(id),
                                                              ResourceType(resourceType),
                                                              Module(nullptr)
    { }

    ResourceString(_In_ ULONG id, _In_ HMODULE hModule) : Id(id),
                                                          ResourceType(nullptr),
                                                          Module(hModule)
    { }

    ResourceString(_In_ ULONG id,
                   _In_ PCWSTR resourceType,
                   _In_ HMODULE hModule) : Id(id),
                                           ResourceType(resourceType),
                                           Module(hModule)
    { }

    ResourceString(_In_ const ResourceString& src) : Id(src.Id),
                                                     ResourceType(src.ResourceType),
                                                     Module(src.Module)
    { }

    ULONG Id;
    PCWSTR ResourceType;
    HMODULE Module;
};

//
// DeferredResourceString:
//
// A string which is dynamically pulled from the resources of the binary containing the header.
// A DeferredResourceString is boxes into a property accessor which pulls from the resource
// string upon being fetched.
//
struct DeferredResourceString : public ResourceString
{
    template<typename... TArgs> DeferredResourceString(TArgs&&... args) : ResourceString(std::forward<TArgs>(args)...) { }
};

//**************************************************************************
// Private Implementation Details:
//

namespace Details
{

    //*************************************************
    // Type Traits:
    //
    // Defines common traits for auto-boxing and auto-unboxing of intrinsic (and intrinsic-like) values.
    //

    template<typename TIntrinsic> struct BaseIntrinsicTypeTraits { };

    template<> struct BaseIntrinsicTypeTraits<char>
    {
        static const VARTYPE VariantType = VT_I1;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<unsigned char>
    {
        static const VARTYPE VariantType = VT_UI1;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<short>
    {
        static const VARTYPE VariantType = VT_I2;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<unsigned short>
    {
        static const VARTYPE VariantType = VT_UI2;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<int>
    {
        static const VARTYPE VariantType = VT_I4;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<unsigned int>
    {
        static const VARTYPE VariantType = VT_UI4;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<long>
    {
        static const VARTYPE VariantType = VT_UI4;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<unsigned long>
    {
        static const VARTYPE VariantType = VT_UI4;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<__int64>
    {
        static const VARTYPE VariantType = VT_I8;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<unsigned __int64>
    {
        static const VARTYPE VariantType = VT_UI8;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<float>
    {
        static const VARTYPE VariantType = VT_R4;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<double>
    {
        static const VARTYPE VariantType = VT_R8;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<> struct BaseIntrinsicTypeTraits<bool>
    {
        static const VARTYPE VariantType = VT_BOOL;
        static const ModelObjectKind ObjectKind = ObjectIntrinsic;
    };

    template<typename TIntrinsic> struct IntrinsicTypeTraits : public BaseIntrinsicTypeTraits<TIntrinsic>
    {
        static void FillVariant(VARIANT *pVar, TIntrinsic val)
        {
            VariantInit(pVar);
            pVar->vt = BaseIntrinsicTypeTraits<TIntrinsic>::VariantType;
            TIntrinsic *pVal = reinterpret_cast<TIntrinsic *>(&pVar->bVal);
            *pVal = val;
        }

        static TIntrinsic ExtractFromVariant(VARIANT *pVar)
        {
            TIntrinsic *pVal = reinterpret_cast<TIntrinsic *>(&pVar->bVal);
            return *pVal;
        }
    };

    template<> struct IntrinsicTypeTraits<bool> : public BaseIntrinsicTypeTraits<bool>
    {

        static void FillVariant(VARIANT *pVar, bool val)
        {
            VariantInit(pVar);
            pVar->vt = VT_BOOL;
            VARIANT_BOOL *pVal = reinterpret_cast<VARIANT_BOOL *>(&pVar->boolVal);
            *pVal = val ? VARIANT_TRUE : VARIANT_FALSE;
        }

        static bool ExtractFromVariant(VARIANT *pVar)
        {
            VARIANT_BOOL *pVal = reinterpret_cast<VARIANT_BOOL *>(&pVar->boolVal);
            return *pVal == VARIANT_TRUE;
        }
    };

    //*************************************************
    // Trait Helpers for Boxing and Unboxing:
    //

    template<typename TRet, typename... TArgs, typename TClass>
    auto GetFunctionType(_In_ TRet (TClass::*)(TArgs...) const) -> std::function<TRet(TArgs...)>;

    template<typename TRet, typename... TArgs, typename TClass>
    auto GetFunctionType(_In_ TRet (TClass::*)(TArgs...)) -> std::function<TRet(TArgs...)>;

    template<size_t argNum, size_t i, typename TArg, typename... TArgs>
    struct ArgumentTraitHelper : public ArgumentTraitHelper<argNum, i + 1, TArgs...> { };

    template<size_t argNum, typename TArg, typename... TArgs>
    struct ArgumentTraitHelper<argNum, argNum, TArg, TArgs...>
    {
        using ArgumentType = TArg;
    };

    template<typename TRet, typename... TArgs>
    struct StdFunctionTraits
    {
        using ReturnType = TRet;
        template<size_t i> struct ArgumentTraits : public ArgumentTraitHelper<i, 0, TArgs...> { };
    };

    template<typename TRet, typename... TArgs>
    StdFunctionTraits<TRet, TArgs...> GetFunctionTraits(_In_ const std::function<TRet(TArgs...)>&);

    //
    // Boy wouldn't it be fun if I didn't have to workaround multiple bugs in the C++ compiler to get this to work.  It's
    // a song and dance of moving code into and out of function bodies and sprinkling the pixie dust of typename around.
    //
    template<size_t i, typename TRet, typename... TArgs>
    auto GetArgumentType(_In_ const std::function<TRet(TArgs...)>&)
    {
        using ArgumentType = typename StdFunctionTraits<TRet, TArgs...>::template ArgumentTraits<i>::ArgumentType;
        using ValueType = std::remove_reference_t<ArgumentType>;

        ValueType v{};
        ArgumentType t = v;
        return t;
    }

    template<typename TRet, typename... TArgs>
    auto GetReturnType(_In_ const std::function<TRet(TArgs...)>&) -> TRet;

    template<typename TRet, typename... TArgs> struct StdFunctionCountArguments;
    template<typename TRet, typename... TArgs>
    struct StdFunctionCountArguments<std::function<TRet(TArgs...)>>
    {
        static constexpr size_t ArgumentCount = sizeof...(TArgs);
    };

    template<typename TFunc>
    struct FunctorTraits
    {
        using FunctionType = decltype(GetFunctionType(&TFunc::operator()));
        using ReturnType = decltype(GetReturnType(FunctionType{}));
        static constexpr size_t ArgumentCount = StdFunctionCountArguments<FunctionType>::ArgumentCount;

        template<size_t i>
        struct ArgumentType
        {
            using Type = decltype(GetArgumentType<i>(FunctionType{}));
        };

        template<size_t i> using ArgumentType_t = typename ArgumentType<i>::Type;
    };

    template<typename TRet, typename... TArgs>
    struct FunctorTraits<TRet(*)(TArgs...)>
    {
        using FunctionType = std::function<TRet(TArgs...)>;
        using ReturnType = TRet;
        static constexpr size_t ArgumentCount = sizeof...(TArgs);

        template<size_t i>
        struct ArgumentType
        {
            using Type = decltype(GetArgumentType<i>(FunctionType{}));
        };

        template<size_t i> using ArgumentType_t = typename ArgumentType<i>::Type;
    };

    template<typename TClass, typename TRet, typename... TArgs>
    struct ClassMethodTraits
    {
        using FunctionType = std::function<TRet(TArgs...)>;
        using ReturnType = TRet;
        static constexpr size_t ArgumentCount = sizeof...(TArgs);

        template<size_t i>
        struct ArgumentType
        {
            using Type = decltype(GetArgumentType<i>(FunctionType{}));
        };

        template<size_t i> using ArgumentType_t = typename ArgumentType<i>::Type;
    };

    template<typename TClass, typename TRet, typename... TArgs>
    ClassMethodTraits<TClass, TRet, TArgs...> GetClassMethodTraits(_In_ TRet (TClass::*)(TArgs...));


    //
    // NOTE: The following multiple definitions of void_t (as priv_void_t1, _t2, etc...) are to work around
    //       a compiler bug involving alias templates.  Without this, only the first has_* which uses the *void_t
    //       will function correctly.
    //
    template<class ...> using priv_void_t1 = void;
    template<class ...> using priv_void_t2 = void;
    template<class ...> using priv_void_t3 = void;
    template<class ...> using priv_void_t4 = void;
    template<class ...> using priv_void_t5 = void;
    template<class ...> using priv_void_t6 = void;

    template<class, class = priv_void_t1<> > struct has_call_operator : std::false_type { };
    template<class T> struct has_call_operator<T, priv_void_t1<decltype(&T::operator())>> : std::true_type { };
    template<class T> constexpr bool has_call_operator_v = has_call_operator<T>::value;

    template<class, typename TArg, class = priv_void_t2<> > struct has_box_method : std::false_type { };
    template<class T, typename TArg> struct has_box_method<T, TArg, priv_void_t2<decltype(T::Box(std::declval<TArg>()))>> : std::true_type { };
    template<class T, typename TArg> constexpr bool has_box_method_v = has_box_method<T, TArg>::value;

    template<class, class = priv_void_t3<> > struct has_unbox_method : std::false_type { };
    template<class T> struct has_unbox_method<T, priv_void_t3<decltype(&T::Unbox)>> : std::true_type { };
    template<class T> constexpr bool has_unbox_method_v = has_unbox_method<T>::value;

    template<class, class = priv_void_t6<> > struct has_varianttype_field : std::false_type { };
    template<class T> struct has_varianttype_field<T, priv_void_t6<decltype(T::VariantType)>> : std::true_type { };
    template<class T> constexpr bool has_varianttype_field_v = has_varianttype_field<T>::value;

    template<typename T> struct ArrayTraits
    {
        using Type = T;
        static constexpr size_t Size = 0;
    };

    template<typename T, size_t N>
    struct ArrayTraits<T[N]>
    {
        using Type = T;
        static constexpr size_t Size = N;
    };

    template<typename T> using ArrayTraits_t = typename ArrayTraits<T>::Type;

    template<typename T> struct MetadataTraits
    {
        static void FillMetadata(T const&, _Outptr_opt_result_maybenull_ IKeyStore **ppMetadata)
        {
            if (ppMetadata)
            {
                *ppMetadata = nullptr;
            }
        }
    };

    template<typename TVal> struct MetadataTraits<ValueWithMetadata<TVal>>
    {
        static void FillMetadata(ValueWithMetadata<TVal>& val, _Outptr_opt_result_maybenull_ IKeyStore **ppMetadata)
        {
            if (ppMetadata)
            {
                *ppMetadata = val.GetMetadata().Detach();
            }
        }

        // For boxed arrays, metadata might end up copied out multiple times, rather than being a transient object that can be detached
        static void FillMetadata(ValueWithMetadata<TVal> const& val, _Outptr_opt_result_maybenull_ IKeyStore **ppMetadata)
        {
            if (ppMetadata)
            {
                *ppMetadata = val.GetMetadata();
                val.GetMetadata()->AddRef();
            }
        }
    };

    // Enable IndexedValue<ValueWithMetadata<...>, ...>
    template<typename TVal, typename... TIndices> struct MetadataTraits<IndexedValue<TVal, TIndices...>>
    {
        static void FillMetadata(IndexedValue<TVal, TIndices...>& val, _Outptr_opt_result_maybenull_ IKeyStore **ppMetadata)
        {
            MetadataTraits<TVal>::FillMetadata(val.GetValue(), ppMetadata);
        }
    };

    template<typename T, typename = void> struct IsIterable : std::false_type { };
    template<typename T> struct IsIterable<T, ClientEx::Details::priv_void_t4<decltype(std::declval<T>().begin()), decltype(std::declval<T>().end())>> : std::true_type { };

    template<typename TCatTag> struct IsRandomAccessTag : std::false_type {};
    template<> struct IsRandomAccessTag<std::random_access_iterator_tag> : std::true_type { };

    template<typename T, typename = void> struct IsRandomAccessIterator : std::false_type { };
    template<typename T> struct IsRandomAccessIterator<T, ClientEx::Details::priv_void_t5<typename std::iterator_traits<T>::iterator_category>> :
        IsRandomAccessTag<typename std::iterator_traits<T>::iterator_category> { };

    template<typename T> struct IsRandomAccessIterable : IsRandomAccessIterator<decltype(std::declval<T>().begin())> { };

    template<typename T> constexpr bool IsIterable_v = IsIterable<T>::value;
    template<typename T> constexpr bool IsRandomAccessTag_v = IsRandomAccessTag<T>::value;
    template<typename T> constexpr bool IsRandomAccessIterator_v = IsRandomAccessIterator<T>::value;
    template<typename T> constexpr bool IsRandomAccessIterable_v = IsRandomAccessIterable<T>::value;

    template<typename TVal, typename TIter, bool IsRandom>
    struct IndexerTraits
    {
        static bool CheckDimensions(_In_ ULONG64 dimensionality)
        {
            return dimensionality == 0;
        }

        static void CreateIndexers(_In_ const TVal& /*val*/,
                                   _In_ const TIter& /*itBegin*/,
                                   _In_ const TIter& /*itCur*/,
                                   _In_ ULONG64 /*dimensionality*/,
                                   _Out_opt_ ClientEx::Object * /*pIndexers*/)
        {
        }

        static void FillIndexers(_In_ ULONG64 /*dimensionality*/,
                                 _In_ ClientEx::Object * /*pIndexers*/,
                                 _Out_ IModelObject ** /*ppIndexers*/)
        {
        }

        static constexpr ULONG64 Dimensionality = 0;
    };

    //
    // An iterable which returns IndexedValue<> is declaring that it **DIRECTLY** supports providing the indicies
    // itself.
    //
    template<typename TIter, bool IsRandom, typename TVal, typename... TIndicies>
    struct IndexerTraits<ClientEx::IndexedValue<TVal, TIndicies...>, TIter, IsRandom>
    {
        static bool CheckDimensions(_In_ ULONG64 dimensionality)
        {
            return (dimensionality == 0 || dimensionality == sizeof...(TIndicies));
        }

        static void CreateIndexers(_In_ const ClientEx::IndexedValue<TVal, TIndicies...>& indexedValue,
                                   _In_ const TIter& /*itBegin*/,
                                   _In_ const TIter& /*itCur*/,
                                   _In_ ULONG64 dimensionality,
                                   _Out_opt_ ClientEx::Object *pIndexers)
        {
            if (dimensionality == sizeof...(TIndicies))
            {
                ClientEx::Details::ParameterPack pack = ClientEx::Details::PackTuple(indexedValue.GetIndicies());
                for (ULONG64 i = 0; i < dimensionality; ++i)
                {
                    pIndexers[static_cast<size_t>(i)] = std::move(pack[static_cast<size_t>(i)]);
                }
            }
        }

        static void FillIndexers(_In_ ULONG64 dimensionality,
                                 _In_reads_(dimensionality) ClientEx::Object *pIndexers,
                                 _Out_writes_opt_(dimensionality) IModelObject ** ppIndexers)
        {
            if (dimensionality == sizeof...(TIndicies))
            {
                for (ULONG64 i = 0; i < dimensionality; ++i)
                {
                    ppIndexers[i] = pIndexers[i].Detach();
                }
            }
        }

        static constexpr ULONG64 Dimensionality = sizeof...(TIndicies);
    };

    template<typename TVal, typename TIter>
    struct IndexerTraits<TVal, TIter, true>
    {
        static bool CheckDimensions(_In_ ULONG64 dimensionality)
        {
            return (dimensionality == 0 || dimensionality == 1);
        }

        static void CreateIndexers(_In_ const TVal& /*val*/,
                                   _In_ const TIter& itBegin,
                                   _In_ const TIter& itCur,
                                   _In_ ULONG64 dimensionality,
                                   _Out_opt_ ClientEx::Object *pIndexers)
        {
            if (dimensionality == 1)
            {
                ClientEx::Object idx;
                idx = static_cast<ULONG64>(itCur - itBegin);
                pIndexers[0] = std::move(idx);
            }
        }

        static void FillIndexers(_In_ ULONG64 dimensionality,
                                 _In_reads_(dimensionality) ClientEx::Object *pIndexers,
                                 _Out_writes_opt_(dimensionality) IModelObject ** ppIndexers)
        {
            if (dimensionality == 1)
            {
                ppIndexers[0] = pIndexers[0].Detach();
            }
        }

        static const ULONG64 Dimensionality = 1;
    };

    //*************************************************
    // VarArgs unpack analysis:
    //
    // If the last two arguments to any method we bind to are
    //
    //     (size_t, Object *)
    //
    // the function is varargs. We unpack and type match the static types before
    // the size_t, Object * and then put the remainder of the arguments in the
    // list defined by those two arguments.
    //
    // These helpers analyze the type signature of a method to determine if it is
    // a var args method and whether a given position is the var args position.
    //

    // bool IsVariableArgumentPosition_v<TArgs...>
    //     determines whether the position at TArgs is a variable argument position (a size_t, Object *) at the end of pack
    //
    // bool HasVariableArguments_v<TArgs...>
    //     determines whether the pack contains a terminating (size_t, Object *) -- a signature of varargs

    template<typename... TArgs> struct IsVariableArgumentPosition : public std::false_type { };
    template<> struct IsVariableArgumentPosition<size_t, Object *> : public std::true_type { };
    template<typename... TArgs> struct HasVariableArgumentHelper2;
    template<typename TArg1, typename TArg2, typename... TArgs> struct HasVariableArgumentHelper2<TArg1, TArg2, TArgs...> : public HasVariableArgumentHelper2<TArg2, TArgs...> { };
    template<typename TArg1, typename TArg2> struct HasVariableArgumentHelper2<TArg1, TArg2> : public IsVariableArgumentPosition<TArg1, TArg2> { };
    template<size_t i, typename... TArgs> struct HasVariableArgumentHelper : public HasVariableArgumentHelper2<TArgs...> {};
    template<typename... TArgs> struct HasVariableArgumentHelper<0, TArgs...> : public std::false_type { };
    template<typename... TArgs> struct HasVariableArgumentHelper<1, TArgs...> : public std::false_type { };
    template<typename... TArgs> struct HasVariableArguments : public HasVariableArgumentHelper<sizeof...(TArgs), TArgs...> {};

    template<typename... TArgs> constexpr bool IsVariableArgumentPosition_v = IsVariableArgumentPosition<TArgs...>::value;
    template<typename... TArgs> constexpr bool HasVariableArguments_v = HasVariableArguments<TArgs...>::value;

    //*************************************************
    // Optional unpack analysis:
    //
    // If any argument in the function is std::optional<T>, it is optional and does not need an
    // argument in the incoming dynamic pack to bind against the static one.  This performs analysis
    // to determine optional arguments, positions, and whether there is illegality (static arguments
    // after optional ones)
    //

    // bool IsOptionalArgument_v<T>
    //     true iff T is std::optional<TOpt>
    //
    // bool IsNonOptionalARgument_v<T>
    //     true iff T is not std::optional<TOpt>

    template<typename T> struct IsOptionalArgument : public std::false_type { };
    template<typename TOpt> struct IsOptionalArgument<std::optional<TOpt>> : public std::true_type { };
    template<typename T> struct IsNonOptionalArgument : public std::true_type { };
    template<typename TOpt> struct IsNonOptionalArgument<std::optional<TOpt>> : public std::false_type { };

    template<typename T> constexpr bool IsOptionalArgument_v = IsOptionalArgument<T>::value;
    template<typename T> constexpr bool IsNonOptionalArgument_v = IsNonOptionalArgument<T>::value;

    // bool HasNonOptionalArguments_v<TArgs...>
    //     determines whether the argument pack in TArgs contains a non optional argument.  That is, it contains a
    //     non std::optional<TOpt> **UNLESS** that non optional argument is a final size_t, Object * in the
    //     argument pack.

    template<typename... TArgs> struct HasNonOptionalArguments : public std::true_type { };
    template<typename T> struct HasNonOptionalArguments<T> : public IsNonOptionalArgument<T> { };
    template<typename T, typename... TArgs> struct HasNonOptionalArguments<T, TArgs...>
    {
    private:

        static constexpr bool GetHasNonOptional()
        {
            //
            // If the argument set <T, TArgs...> is VarArgs (size_t, Object *) with nothing following, there are no non-optional arguments
            //
            if (IsVariableArgumentPosition_v<T, TArgs...>) { return false; }

            //
            // If the current argument is non-optional (we've already checked a VarArgs slot), we have non-optional arguments in the set.
            //
            if (IsNonOptionalArgument_v<T>) { return true; }

            //
            // Subsequently, everything is repeated recursively on TArgs... as an argument set.
            //
            return HasNonOptionalArguments<TArgs...>::value;
        }

    public:

        static constexpr bool value = GetHasNonOptional();
    };
    template<typename... TArgs> constexpr bool HasNonOptionalArguments_v = HasNonOptionalArguments<TArgs...>::value;

    // bool HasOptionalArguments_v<TArgs...>
    //     determines whether the argument pack contains a legal optional argument (one or more std::optional<TOpt>
    //     arguments after which there are no non std::optional<TOpt> arguments unless those arguments are a varargs
    //     pack -- a final size_t, Object *)
    //
    //     If there is a violation of ordering of the std::optional<TOpt>, this will fire a static assert.
    //

    template<typename... TArgs> struct HasOptionalArguments : public std::false_type { };
    template<typename T> struct HasOptionalArguments<T> : public IsOptionalArgument<T> { };
    template<typename T, typename... TArgs> struct HasOptionalArguments<T, TArgs...>
    {
    public:
        static constexpr bool isCurrentOptional = IsOptionalArgument_v<T>;
        static constexpr bool HasNextOptional()
        {
            constexpr bool nextOptional = HasOptionalArguments<TArgs...>::value;
            constexpr bool allNextOptional = !HasNonOptionalArguments_v<TArgs...>;
            static_assert(!isCurrentOptional || allNextOptional, "Any std::optional<T> must come before any non optional (or non varArgs) argument");
            return nextOptional;
        }

    public:
        static constexpr bool value = (isCurrentOptional | HasNextOptional());
    };
    template<typename... TArgs> constexpr bool HasOptionalArguments_v = HasOptionalArguments<TArgs...>::value;

    // size_t FirstOptionalArgumentPosition_v<TArgs...>
    //
    // Gives the 0-based position of the first std::optional<T> within the pack.  If there is no such value, the
    // size of the pack is returned in lieu.
    //

    template<size_t i, typename... TArgs> struct FirstOptionalArgumentPositionHelper : public std::integral_constant<size_t, i + sizeof...(TArgs)> { };
    template<size_t i, typename T, typename... TArgs> struct FirstOptionalArgumentPositionHelper<i, T, TArgs...> : public FirstOptionalArgumentPositionHelper<i + 1, TArgs...> { };
    template<size_t i, typename T> struct FirstOptionalArgumentPositionHelper<i, T> : public std::integral_constant<size_t, i + 1> { };
    template<size_t i, typename TOpt> struct FirstOptionalArgumentPositionHelper<i, std::optional<TOpt>> : public std::integral_constant<size_t, i> { };
    template<size_t i, typename TOpt, typename... TArgs> struct FirstOptionalArgumentPositionHelper<i, std::optional<TOpt>, TArgs...> : public std::integral_constant<size_t, i> { };
    template<typename... TArgs> struct FirstOptionalArgumentPosition : public FirstOptionalArgumentPositionHelper<0, TArgs...> { };
    template<typename... TArgs> constexpr size_t FirstOptionalArgumentPosition_v = FirstOptionalArgumentPosition<TArgs...>::value;

    //*************************************************
    // General unpack
    //

    // size_t PackMatchingSize_v<TArgs...>
    //
    // Computes how many static arguments we need to have within a dynamic argument set to statically bind against
    // a given argument pack.
    //
    // In effect, this set of templates is looking at a C++ method signature which is comprised of three things:
    //
    //     - Some types T
    //     - Some optional types, std::optional<T>
    //     - VarArgs at the end (size_t, Object *)
    //
    // and determining how many *REQUIRED* arguments there are in order to make a call to the method from the data model.
    // The number of required arguments is the number of types T that come before any optional argument or VarArgs position.
    //
    template<typename... TArgs> struct PackMatchingSize
    {
    private:

        static constexpr size_t GetMatchingSize()
        {
            //
            // If we have a std::optional<T>, we can stop there.  It is illegal to have static arguments
            // after that.  If not, and we have variable arguments defined by (size_t, Object *) at the
            // end, the position is the pack size minus two (for the two varargs "arguments")
            //
            constexpr bool hasOptional = HasOptionalArguments_v<TArgs...>;
            constexpr bool hasVarArgs = HasVariableArguments_v<TArgs...>;

            if (hasOptional)
            {
                return FirstOptionalArgumentPosition_v<TArgs...>;
            }

            if (hasVarArgs)
            {
                return sizeof...(TArgs) - 2;
            }

            return sizeof...(TArgs);
        }

    public:

        static constexpr size_t value = GetMatchingSize();
    };
    template<typename... TArgs> constexpr size_t PackMatchingSize_v = PackMatchingSize<TArgs...>::value;

    // size_t PackMatchingSize_WithIgnore_v<size_t ignoreCount, TArgs...>
    //
    // Ignores the first 'ignoreCount' arguments in TArgs... and then computes PackMatchingSize_v of the remaining
    // argument pack.
    //
    template<size_t i, size_t ignoreCount, typename... TArgs> struct PackMatchingSize_WithIgnore_Helper;
    template<size_t i, size_t ignoreCount, typename TArg1, typename... TArgs> struct PackMatchingSize_WithIgnore_Helper2 : public PackMatchingSize_WithIgnore_Helper<i + 1, ignoreCount, TArgs...> { };
    template<size_t i, size_t ignoreCount, typename... TArgs> struct PackMatchingSize_WithIgnore_Helper : public PackMatchingSize_WithIgnore_Helper2<i, ignoreCount, TArgs...> { };
    template<size_t i, typename... TArgs> struct PackMatchingSize_WithIgnore_Helper<i, i, TArgs...> : public PackMatchingSize<TArgs...> { };
    template<size_t ignoreCount, typename... TArgs> struct PackMatchingSize_WithIgnore : public PackMatchingSize_WithIgnore_Helper<0, ignoreCount, TArgs...> { };
    template<typename... TArgs> struct PackMatchingSize_WithIgnore<0, TArgs...> : public PackMatchingSize<TArgs...> { };
    template<size_t ignoreCount, typename... TArgs> constexpr size_t PackMatchingSize_WithIgnore_v = PackMatchingSize_WithIgnore<ignoreCount, TArgs...>::value;

    // Unpack helpers:

    template<typename TTuple, size_t i, size_t remaining>
    struct RegularUnpacker
    {
        static void UnpackInto(_In_ size_t packSize,
                               _In_reads_(packSize) IModelObject **ppArgumentPack,
                               TTuple& tuple);
    };

    template<typename TTuple, size_t i, size_t remaining> struct Unpacker : public RegularUnpacker<TTuple, i, remaining> { };

    template<typename TTuple, size_t i, size_t remaining>
    struct VariableUnpacker
    {
        static void UnpackInto(_In_ size_t packSize, _In_reads_(packSize) IModelObject **ppArgumentPack, TTuple& tuple)
        {
            if (i >= packSize)
            {
                return;
            }

            size_t variableArgumentCount = packSize - i;
            std::get<i>(tuple) = variableArgumentCount;

            //
            // @TODO: Perhaps Object * isn't the right thing.  This reinterpret is *PROBABLY* safe given the structural
            // requirements on Object (it must lay out in memory as a single IModelObject *.
            //
            std::get<i + 1>(tuple) = reinterpret_cast<Object *>(ppArgumentPack + i);
        }
    };

    //
    // If the last 2 arguments are a variable argument pack, perform a special packing.
    //
    template<typename TTuple, size_t i>
    struct Unpacker<TTuple, i, 2> : std::conditional_t<IsVariableArgumentPosition_v<typename std::tuple_element_t<i, TTuple>, std::tuple_element_t<i + 1, TTuple>>, VariableUnpacker<TTuple, i, 2>, RegularUnpacker<TTuple, i, 2>>
    {
    };

    template<typename TTuple, size_t i>
    struct Unpacker<TTuple, i, 0>
    {
        static void UnpackInto(_In_ size_t /*packSize*/, _In_ IModelObject ** /*ppArgumentPack*/, TTuple& /*tuple*/)
        {
        }
    };

    template<size_t i, size_t extractCount, typename... TArgs> struct TupleTypeExtractorHelper;

    template<size_t i, size_t extractCount, typename TArg1, typename... TArgs>
    struct TupleTypeExtractorHelper2
    {
        using Type = typename TupleTypeExtractorHelper<i + 1, extractCount, TArgs...>::Type;
    };

    template<size_t i, size_t extractCount, typename... TArgs>
    struct TupleTypeExtractorHelper
    {
        using Type = typename TupleTypeExtractorHelper2<i, extractCount, TArgs...>::Type;
    };

    template<size_t i, typename... TArgs>
    struct TupleTypeExtractorHelper<i, i, TArgs...>
    {
        using Type = std::tuple<TArgs...>;
    };

    // TupleTypeExtractor:
    //
    // Removes the first 'extractCount' arguments from TArgs... and returns a tuple of said
    // arguments.
    //
    template<size_t extractCount, typename... TArgs>
    struct TupleTypeExtractor
    {
        using Type = typename TupleTypeExtractorHelper<0, extractCount, TArgs...>::Type;
    };

    template<typename... TArgs>
    struct TupleTypeExtractor<0, TArgs...>
    {
        using Type = typename std::tuple<TArgs...>;
    };

    template<size_t tupleExtractionCount, typename... TArgs>
    using TupleTypeExtractor_t = typename TupleTypeExtractor<tupleExtractionCount, TArgs...>::Type;

    // UnpackValues():
    //
    // Takes a model parameter pack and expands it out into a std::tuple with extraction by type
    // as determined by the TArgs... types.  The first "tupleExtractionCount" arguments will be
    // skipped when creating the tuple.
    //
    template<size_t tupleExtractionCount, typename... TArgs>
    decltype(auto) UnpackValues(_In_ size_t packSize, _In_reads_(packSize) IModelObject **ppArgumentPack)
    {
        using ArgumentTypes = TupleTypeExtractor_t<tupleExtractionCount, std::decay_t<TArgs>...>;
        ArgumentTypes tuple;
        Unpacker<ArgumentTypes, 0, sizeof...(TArgs) - tupleExtractionCount>::UnpackInto(packSize, ppArgumentPack, tuple);
        return tuple;
    }

//
// @TODO: The compiler insists that 't' is unreferenced in the below.  It is not.  Remove the warning
//        by pragma for now.
//
#pragma warning(push)
#pragma warning(disable: 4100)

    template <class F, class Tuple, std::size_t... I, typename... TExtraValues>
    constexpr decltype(auto) ApplyImpl(F&& f,
                                       const Object& contextObj,
                                       Tuple&& t,
                                       std::index_sequence<I...>,
                                       TExtraValues&&... extraValues)
    {
        return std::invoke(std::forward<F>(f), contextObj, std::forward<TExtraValues>(extraValues)..., std::get<I>(std::forward<Tuple>(t))...);
    }

    template <class F, class Tuple, std::size_t... I>
    constexpr decltype(auto) LiteralApplyImpl(F&& f, Tuple&& t, std::index_sequence<I...>)
    {
        return std::invoke(std::forward<F>(f), std::get<I>(std::forward<Tuple>(t))...);
    }

    template<class T>
    struct ConstructorApplyImpl
    {
        template<class Tuple, std::size_t... I>
        static constexpr decltype(auto) Apply(Tuple&& t, std::index_sequence<I...>)
        {
            return T(std::get<I>(std::forward<Tuple>(t))...);
        }
    };

    template <class F, class Tuple, typename... TExtraValues>
    constexpr decltype(auto) Apply(F&& f, const Object& contextObj, Tuple&& t, TExtraValues&&... extraValues)
    {
        return ApplyImpl(
            std::forward<F>(f), contextObj, std::forward<Tuple>(t),
            std::make_index_sequence<std::tuple_size_v<std::decay_t<Tuple>>>{},
            std::forward<TExtraValues>(extraValues)...);
    }

    template <class F, class Tuple>
    constexpr decltype(auto) LiteralApply(F&& f, Tuple&& t)
    {
        return LiteralApplyImpl(
            std::forward<F>(f), std::forward<Tuple>(t),
            std::make_index_sequence<std::tuple_size_v<std::decay_t<Tuple>>>{});
    }

    template <class T, class Tuple>
    constexpr decltype(auto) ConstructorApply(Tuple&& t)
    {
        return ConstructorApplyImpl<T>::Apply(
            std::forward<Tuple>(t),
            std::make_index_sequence<std::tuple_size_v<std::decay_t<Tuple>>>{}
            );
    }

#pragma warning(pop)

    // InvokeAndBox():
    //
    // Calls a function with a tuple of arguments and boxes the return value into an Object.
    //
    template<typename TRet, typename TFunc, typename TTuple>
    struct InvokeAndBox
    {
        template<typename... TExtraValues>
        static Object Call(_In_ const TFunc& func,
                           _In_ const Object& contextObj,
                           _In_ const TTuple& parameters,
                           _Outptr_opt_result_maybenull_ IKeyStore **ppMetadata,
                           _In_ TExtraValues&&... extraValues)
        {
            TRet result = Apply(func, contextObj, parameters, std::forward<TExtraValues>(extraValues)...);
            Object resultObject = BoxObject(std::move(result));
            MetadataTraits<TRet>::FillMetadata(result, ppMetadata);
            return resultObject;
        }
    };

    // InvokeAndBox():
    //
    // Calls a void returning function with a tuple of arguments.  Boxes "NoValue" into an Object
    // and returns it to represent the void value.
    //
    template<typename TFunc, typename TTuple>
    struct InvokeAndBox<void, TFunc, TTuple>
    {
        template<typename... TExtraValues>
        static Object Call(_In_ const TFunc& func,
                           _In_ const Object& contextObj,
                           _In_ const TTuple& parameters,
                           _Outptr_opt_result_maybenull_ IKeyStore **ppMetadata,
                           _In_ TExtraValues&&... extraValues)
        {
            Apply(func, contextObj, parameters, std::forward<TExtraValues>(extraValues)...);
            if (ppMetadata)
            {
                *ppMetadata = nullptr;
            }
            ComPtr<IModelObject> spNoValue;
            CheckHr(GetManager()->CreateNoValue(&spNoValue));
            return Object(std::move(spNoValue));
        }
    };


    // LiteralInvokeAndBox():
    //
    // Calls a function with a tuple of arguments and boxes the result into an Object.  This does not
    // inject the usual "methods" signature bindings of the data model's "context object" and any such
    // extra parameters.
    //
    template<typename TRet, typename TFunc, typename TTuple>
    struct LiteralInvokeAndBox
    {
        static Object Call(_In_ const TFunc& func, _In_ const TTuple& parameters)
        {
            TRet result = LiteralApply(func, parameters);
            Object resultObject = BoxObject(result);
            return resultObject;
        }
    };

    // ConstructAndBox:
    //
    // Calls a constructor and boxes the resulting object into an Object.
    //
    template<typename TInstance, typename TTuple>
    struct ConstructAndBox
    {
        static Object Construct(_In_ const TTuple& arguments)
        {
            TInstance result = ConstructorApply(arguments);
            Object resultObject = BoxObject(result);
            return resultObject;
        }

    };

    // InvokeFunctionFromPack:
    //
    // For a std::function<TRet(TArgs...), convert a dynamic set of arguments from the data model and
    // a set of static additional arguments to the types within the TArgs... signature, call the function,
    // and box the result.
    //
    // The expected signature of the function is TRet(const Object&, convert_if_possible<TExtraValues>..., convert_if_possible<UNPACK>)
    //
    template<typename TRet, typename... TArgs, typename... TExtraValues>
    Object InvokeFunctionFromPack(_In_ const std::function<TRet(TArgs...)>& func,
                                  _In_ const Object& contextObj,
                                  _In_ size_t packSize,
                                  _In_reads_(packSize) IModelObject **ppArgumentPack,
                                  _Outptr_opt_result_maybenull_ IKeyStore **ppMetadata,
                                  _In_ TExtraValues&&... extraValues)

    {
        // We need to determine the minimum number of arguments which will correctly match against the incoming
        // argument list.  The signature of the std::function must be Object&, TExtraValues(convertable)..., TArgs...
        //
        // There can be std::optional<T> arguments (which stops the mandatory static argument count)
        // There can be VarArgs (a TArgs... which ends with size_t, Object *)
        //

        //
        // Compute the minimum pack size via a helper:
        //
        constexpr size_t extraArgumentCount = sizeof...(extraValues);
        constexpr size_t packIgnoreCount = extraArgumentCount + 1;          // + 1 == const Object& (instanceObject)
        constexpr size_t minPackSize = PackMatchingSize_WithIgnore_v<packIgnoreCount, TArgs...>;

        //
        // Compute the maximum pack size (it's either the static size of the pack minus the ignore count or it's infinite
        // (if we have varargs)
        //
        constexpr size_t maxStaticPack = sizeof...(TArgs) - packIgnoreCount;
        constexpr bool isVarArgs = HasVariableArguments_v<TArgs...>;

        //
        // If the caller has not passed an argument list which can match the pack via size, immediately throw.
        //
        if (packSize < minPackSize || (packSize > maxStaticPack && !isVarArgs))
        {
            throw std::invalid_argument("Illegal number of arguments to method call");
        }

        auto parameters = UnpackValues<packIgnoreCount, TArgs...>(packSize, ppArgumentPack);

        return InvokeAndBox<TRet, decltype(func), decltype(parameters)>::
            template Call<TExtraValues...>(func, contextObj, parameters, ppMetadata, std::forward<TExtraValues>(extraValues)...);
    }

    // LiteralInvokeFunctionFromPack:
    //
    // For a std::function<TRet(TArgs...), convert a dynamic set of arguments from the data model to the types
    // within the TArgs... signature, call the function, and box the result.
    //
    // The expected signature of the function is TRet(convert_if_possible<UNPACK>)
    //
    template<typename TRet, typename... TArgs>
    Object LiteralInvokeFunctionFromPack(_In_ const std::function<TRet(TArgs...)>& func,
                                         _In_ size_t packSize,
                                         _In_reads_(packSize) IModelObject **ppArgumentPack)
    {
        // We need to determine the minimum number of arguments which will correctly match against the incoming
        // argument list.  The signature of the std::function must be TArgs...
        //
        // There can be std::optional<T> arguments (which stops the mandatory static argument count)
        // There can be VarArgs (a TArgs... which ends with size_t, Object *)
        //

        //
        // Compute the minimum pack size via a helper:
        //
        constexpr size_t extraArgumentCount = 0;
        constexpr size_t packIgnoreCount = extraArgumentCount + 0;
        constexpr size_t minPackSize = PackMatchingSize_WithIgnore_v<packIgnoreCount, TArgs...>;

        //
        // Compute the maximum pack size (it's either the static size of the pack minus the ignore count or it's infinite
        // (if we have varargs)
        //
        constexpr size_t maxStaticPack = sizeof...(TArgs) - packIgnoreCount;
        constexpr bool isVarArgs = HasVariableArguments_v<TArgs...>;

        //
        // If the caller has not passed an argument list which can match the pack via size, immediately throw.
        //
        if (packSize < minPackSize || (packSize > maxStaticPack && !isVarArgs))
        {
            throw std::invalid_argument("Illegal number of arguments to method call");
        }

        auto parameters = UnpackValues<packIgnoreCount, TArgs...>(packSize, ppArgumentPack);
        return LiteralInvokeAndBox<TRet, decltype(func), decltype(parameters)>::Call(func, parameters);
    }

    // InvokeMethodFromPack:
    //
    // Invokes a functor from a data model parameter pack matching all the static types.  In addition,
    // passes a set of extra arguments as determined by TExtraValues... to the function.
    //
    template<typename TFunc, typename... TExtraValues>
    Object InvokeMethodFromPack(_In_ const TFunc& func,
                                _In_ const Object& contextObj,
                                _In_ size_t packSize,
                                _In_reads_(packSize) IModelObject **pArgumentPack,
                                _Outptr_opt_result_maybenull_ IKeyStore **ppMetadata,
                                _In_ TExtraValues&&... extraValues)
    {
        return InvokeFunctionFromPack(FunctorTraits<TFunc>::FunctionType(func),
                                      contextObj,
                                      packSize,
                                      pArgumentPack,
                                      ppMetadata,
                                      std::forward<TExtraValues>(extraValues)...);
    }

    //*************************************************
    // Instance Data Packer:
    //

    template<typename TInstance, typename TType>
    struct is_member_data_pointer_of : std::false_type { };

    template<typename TInstance, typename TData>
    struct is_member_data_pointer_of<TInstance, TData TInstance::*> : std::true_type { };

    template<typename TInstance, typename TData>
    constexpr bool is_member_data_pointer_of_v = is_member_data_pointer_of<TInstance, TData>::value;

    template<typename TArg>
    struct MemberPointerDataTypeExtractor
    {
    };

    template<typename TInstance, typename TData>
    struct MemberPointerDataTypeExtractor<TData TInstance::*>
    {
        using DataType = TData;
    };

    template<typename TInstance, typename TData>
    struct MemberPointerDataTypeExtractor<TData TInstance::* const>
    {
        using DataType = TData;
    };

    template<typename... TArgs>
    struct MemberPointerCollectionTupleTypeExtractor
    {
        using TupleType = std::tuple<typename MemberPointerDataTypeExtractor<std::decay_t<TArgs>>::DataType...>;
    };

    template<size_t i, typename TInstance, typename TTuple, typename... TArgs>
    struct TupleInstancePacker;

    template<size_t i, typename TInstance, typename TTuple>
    struct TupleInstancePacker<i, TInstance, TTuple>
    {
        static void PackInto(TTuple& /* tuple */, TInstance * /*pInstance*/)
        {
        }
    };

    template<size_t i, typename TInstance, typename TTuple, typename TArg, typename... TArgs>
    struct TupleInstancePacker<i, TInstance, TTuple, TArg, TArgs...>
    {
        static void PackInto(TTuple& tuple, TInstance *pInstance, TArg&& firstArg, TArgs&&... subsequentArgs)
        {
            static_assert(is_member_data_pointer_of_v<TInstance, std::decay_t<TArg>>, "Supplied data must be a pointer-to-member of the instance type");

            std::get<i>(tuple) = pInstance->*firstArg;
            TupleInstancePacker<i + 1, TInstance, TTuple, TArgs...>::PackInto(tuple, pInstance, std::forward<TArgs>(subsequentArgs)...);
        }
    };

    // PackTupleInstanceData():
    //
    // Takes a series of "pointer-to-member-data" of TInstance, resolves them into data, and packs that data
    // into a tuple<DataTypes...> and returns it.
    //
    template<typename TInstance, typename... TArgs>
    decltype(auto) PackTupleInstanceData(TInstance *pInstance, TArgs&&... args)
    {
        using TupleType = typename MemberPointerCollectionTupleTypeExtractor<TArgs...>::TupleType;

        TupleType tuple;
        TupleInstancePacker<0, TInstance, TupleType, TArgs...>::PackInto(
            tuple, pInstance, std::forward<TArgs>(args)...
            );
        return tuple;
    }

    //*************************************************
    // Box and Unbox Helpers:
    //

    // BoxedProperty:
    //
    // A data model implementation of a property which is bound to a C++ functor.
    //
    template<typename TGetter, typename TSetter>
    class BoxedProperty : public
        Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IModelPropertyAccessor
            >
    {
    public:

        BoxedProperty(_In_ const TGetter& getterFunc, _In_ const TSetter& setterFunc) :
            m_getterFunc(getterFunc), m_setterFunc(setterFunc)
        {
            using TGetRet = std::decay_t<typename FunctorTraits<TGetter>::ReturnType>;
            using TSetRet = typename FunctorTraits<TSetter>::ReturnType;
            static_assert(!std::is_same_v<TGetRet, void>, L"Property getter must return a value");
            static_assert(std::is_same_v<TSetRet, void>, L"Property setter must not return a value");
        }

        //*************************************************
        // IModelPropertyAccessor:
        //

        // GetValue():
        //
        // Gets the value of the underlying property by calling the functor.
        //
        IFACEMETHOD(GetValue)(_In_ PCWSTR /*propertyName*/, _In_opt_ IModelObject *pContextObject, _COM_Outptr_ IModelObject **ppValue)
        {
            try
            {
                auto result = m_getterFunc(ClientEx::Object(pContextObject));
                ClientEx::Object resultObject = ClientEx::BoxObject(std::move(result));
                *ppValue = resultObject.Detach();
            }
            catch(...)
            {
                return Exceptions::ReturnResult(std::current_exception(), ppValue);
            }

            return S_OK;
        }

        // SetValue():
        //
        // Sets the value of the underlying property by calling the functor.
        //
        IFACEMETHOD(SetValue)(_In_ PCWSTR /*propertyName*/, _In_opt_ IModelObject *pContextObject, _In_ IModelObject *pValue)
        {
            //
            // The function must have a signature of (Object[&], T) where T is the value being set.  Unbox to T.
            //
            try
            {
                using ArgumentType = typename FunctorTraits<TSetter>::template ArgumentType_t<1>;
                ArgumentType val = ClientEx::UnboxObject<ArgumentType>(pValue);
                m_setterFunc(ClientEx::Object(pContextObject), val);
            }
            catch(...)
            {
                return Exceptions::ReturnResult(std::current_exception());
            }

            return S_OK;
        }

    private:

        TGetter m_getterFunc;
        TSetter m_setterFunc;

    };

    // BoxedMethod:
    //
    // A data model implementation of a method which is bound to a C++ functor.
    //
    template<typename TFunc>
    class BoxedMethod : public
        Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IModelMethod
            >
    {
    public:

        BoxedMethod(_In_ const TFunc& func) :
            m_func(func)
        {
        }

        //*************************************************
        // IModelMethod:
        //

        // Call():
        //
        // Calls the method.
        //
        IFACEMETHOD(Call)(_In_opt_ IModelObject *pContextObject,
                          _In_ ULONG64 argCount,
                          _In_reads_(argCount) IModelObject **ppArguments,
                          _COM_Errorptr_ IModelObject ** ppResult,
                          _COM_Outptr_opt_result_maybenull_ IKeyStore **ppMetadata)
        {
            Object result;
            try
            {
                Object contextObj = pContextObject;
                result = InvokeMethodFromPack(m_func, contextObj, static_cast<size_t>(argCount), ppArguments, ppMetadata);
            }
            catch(...)
            {
                return Exceptions::ReturnResult(std::current_exception(), ppResult);
            }

            *ppResult = result.Detach();
            return S_OK;
        }

    private:

        TFunc m_func;

    };

    // BoxedArray:
    //
    // A class which represents the conceptual structure necessary to represent a boxed array
    // of some type T.
    //
    template<typename T>
    class BoxedArray :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IIterableConcept,
            IIndexableConcept
            >
    {
    public:

        // BoxedArray:
        //
        // Construct a new boxed array.
        //
        BoxedArray(_In_ const Object &arrayObject,_In_ const T *pArray, _In_ size_t arraySize) :
            m_spArray(new T[arraySize]),
            m_arraySize(arraySize)
        {
            std::copy(pArray, pArray + arraySize, m_spArray.get());
            CheckHr(arrayObject->SetConcept(__uuidof(IIterableConcept), static_cast<IIterableConcept *>(this), nullptr));
            CheckHr(arrayObject->SetConcept(__uuidof(IIndexableConcept), static_cast<IIndexableConcept *>(this), nullptr));
            m_allowWrite = true;
        }

        //*************************************************
        // IIterableConcept:
        //

        IFACEMETHOD(GetDefaultIndexDimensionality)(_In_ IModelObject * /*pContextObject*/,
                                                   _Out_ ULONG64 *pDimensionality)
        {
            *pDimensionality = 1;
            return S_OK;
        }

        IFACEMETHOD(GetIterator)(_In_ IModelObject * /*pContextObject*/,
                                 _Out_ IModelIterator **ppIterator)
        {
            *ppIterator = nullptr;
            try
            {
                ComPtr<Iterator> spIterator = Make<Iterator>(this, m_spArray.get(), m_arraySize);
                *ppIterator = spIterator.Detach();
            }
            catch(...)
            {
                return ClientEx::Details::Exceptions::ReturnResult(std::current_exception());
            }
            return S_OK;
        }

        //*************************************************
        // IIndexableConcept:
        //

        IFACEMETHOD(GetDimensionality)(_In_ IModelObject * /*pContextObject*/,
                                       _Out_ ULONG64 *pDimensionality)
        {
            *pDimensionality = 1;
            return S_OK;
        }

        IFACEMETHOD(GetAt)(_In_ IModelObject * /*pContextObject*/,
                           _In_ ULONG64 indexerCount,
                           _In_reads_(indexerCount) IModelObject **ppIndexers,
                           _COM_Errorptr_ IModelObject **ppObject,
                           _COM_Outptr_opt_result_maybenull_ IKeyStore **ppMetadata)
        {
            *ppObject = nullptr;
            if (ppMetadata != nullptr)
            {
                *ppMetadata = nullptr;
            }

            try
            {
                if (indexerCount != 1)
                {
                    return E_INVALIDARG;
                }

                Object idxObj = ppIndexers[0];
                ULONG64 idx = (ULONG64)idxObj;
                if (idx >= m_arraySize)
                {
                    throw std::range_error("Out of bounds array index");
                }

                T const& val = m_spArray[static_cast<size_t>(idx)];
                ClientEx::Object result = val;

                MetadataTraits<T>::FillMetadata(val, ppMetadata);
                *ppObject = result.Detach();
            }
            catch(...)
            {
                return ClientEx::Details::Exceptions::ReturnResult(std::current_exception(), ppObject);
            }

            return S_OK;
        }

        IFACEMETHOD(SetAt)(_In_ IModelObject * /*pContextObject*/,
                           _In_ ULONG64 indexerCount,
                           _In_reads_(indexerCount) IModelObject **ppIndexers,
                           _In_ IModelObject *pValue)
        {
            if (!m_allowWrite)
            {
                return E_NOTIMPL;
            }

            try
            {
                if (indexerCount != 1)
                {
                    return E_INVALIDARG;
                }

                Object idxObj = ppIndexers[0];
                ULONG64 idx = (ULONG64)idxObj;
                if (idx >= m_arraySize)
                {
                    throw std::range_error("Out of bounds array index");
                }

                Object val = pValue;
                m_spArray[static_cast<size_t>(idx)] = (T)val;
            }
            catch(...)
            {
                return ClientEx::Details::Exceptions::ReturnResult(std::current_exception());
            }

            return S_OK;
        }

    private:

        // Iterator:
        //
        // A model based iterator for boxed arrays.
        //
        class Iterator :
            public Microsoft::WRL::RuntimeClass<
                Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
                IModelIterator
                >
        {
        public:

            Iterator(_In_ IIterableConcept *pIterable, _In_ T *pArray, _In_ size_t arraySize) :
                m_spIterable(pIterable), m_pArray(pArray), m_arraySize(arraySize), m_pos(0)
            {
            }

            //*************************************************
            // IModelIterator
            //

            IFACEMETHOD(Reset)()
            {
                m_pos = 0;
                return S_OK;
            }

            IFACEMETHOD(GetNext)(_In_ IModelObject ** ppObject,
                                 _In_ ULONG64 dimensions,
                                 _Out_writes_opt_(dimensions) IModelObject ** ppIndexers,
                                 _COM_Outptr_opt_result_maybenull_ IKeyStore ** ppMetadata)
            {
                *ppObject = nullptr;
                if (dimensions > 0)
                {
                    for (ULONG64 i = 0; i < dimensions; ++i)
                    {
                        ppIndexers[i] = nullptr;
                    }
                }
                if (ppMetadata != nullptr)
                {
                    *ppMetadata = nullptr;
                }

                if (dimensions != 0 && dimensions != 1)
                {
                    return E_INVALIDARG;
                }

                try
                {
                    if (m_pos >= m_arraySize)
                    {
                        return E_BOUNDS;
                    }

                    T const& val = m_pArray[m_pos];
                    ClientEx::Object objVal = val;

                    if (dimensions == 1)
                    {
                        Object idx = (ULONG64)m_pos;
                        ppIndexers[0] = idx.Detach();
                    }

                    ++m_pos;
                    MetadataTraits<T>::FillMetadata(val, ppMetadata);
                    *ppObject = objVal.Detach();
                }
                catch(...)
                {
                    return ClientEx::Details::Exceptions::ReturnResult(std::current_exception());
                }

                return S_OK;
            }

        private:

            ComPtr<IIterableConcept> m_spIterable;
            T *m_pArray;
            size_t m_arraySize;
            size_t m_pos;

        };

        std::unique_ptr<T[]> m_spArray;
        size_t m_arraySize;
        bool m_allowWrite;

    };

    //*************************************************
    // Class Link References
    //

    struct DataModelReferenceInfo
    {
        DataModelReferenceInfo() : TypeIsLive(true) { }

        bool TypeIsLive;
    };

    using DataModelReference = std::shared_ptr<DataModelReferenceInfo>;

    inline void ThrowIfDetached(_In_ const DataModelReference& linkRef)
    {
        if (!linkRef->TypeIsLive)
        {
            throw ClientEx::object_detached();
        }
    }

    //*************************************************
    // Iterators:
    //

    template<typename TGen, typename TIter, typename TProjector, bool IsRandom>
    class BoundIterator :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IModelIterator
            >
    {
    public:

        using TGenBaseType = std::decay_t<TGen>;

        BoundIterator(_In_ DataModelReference&& transferredLinkReference,
                      _In_ TGenBaseType& generator,
                      _In_ const TIter& itBegin,
                      _In_ const TIter& itEnd,
                      _In_ const ClientEx::Object& srcObject,
                      _In_ const TProjector& projectionFunction
                      ) :
            m_generator(generator),
            m_itBegin(itBegin),
            m_itEnd(itEnd),
            m_itCur(itBegin),
            m_srcObject(srcObject),
            m_projector(projectionFunction),
            m_linkReference(std::move(transferredLinkReference))
        {
        }

        BoundIterator(_In_ DataModelReference&& transferredLinkReference,
                      _In_ TGenBaseType&& generator,
                      _In_ const TIter& itBegin,
                      _In_ const TIter& itEnd,
                      _In_ const ClientEx::Object& srcObject,
                      _In_ const TProjector& projectionFunction
                      ) :
            m_generator(std::move(generator)),
            m_itBegin(itBegin),
            m_itEnd(itEnd),
            m_itCur(itBegin),
            m_srcObject(srcObject),
            m_projector(projectionFunction),
            m_linkReference(std::move(transferredLinkReference))
        {
        }

        //*************************************************
        // IModelIterator():
        //

        IFACEMETHOD(Reset)()
        {
            m_itCur = m_itBegin;
            return S_OK;
        }

        IFACEMETHOD(GetNext)(_In_ IModelObject ** ppObject,
                             _In_ ULONG64 dimensions,
                             _Out_writes_opt_(dimensions) IModelObject ** ppIndexers,
                             _COM_Outptr_opt_result_maybenull_ IKeyStore ** ppMetadata)
        {
            *ppObject = nullptr;
            if (dimensions > 0)
            {
                for (ULONG64 i = 0; i < dimensions; ++i)
                {
                    ppIndexers[i] = nullptr;
                }
            }
            if (ppMetadata != nullptr)
            {
                *ppMetadata = nullptr;
            }

            using TVal = decltype(m_projector(*m_itCur));
            IndexerTraits<TVal, TIter, IsRandom>::CheckDimensions(dimensions);

            try
            {
                ThrowIfDetached(m_linkReference);

                //
                // It is illegal to reference a generator iterator which has rethrown.  Make
                // sure that a throw out of the underlying iterator continues to throw the
                // same exception if it is rereferenced.
                //
                if (m_thrown)
                {
                    std::rethrow_exception(m_thrown);
                }

                if (m_itCur == m_itEnd)
                {
                    return E_BOUNDS;
                }

                auto val = m_projector(*m_itCur);

                ClientEx::Object objVal = ClientEx::BoxObject(val);

                Object idx;
                std::unique_ptr<Object[]> idxs;
                Object *pIdxs = &idx;
                if (dimensions > 1)
                {
                    idxs.reset(new Object[static_cast<size_t>(dimensions)]);
                    pIdxs = idxs.get();
                }

                IndexerTraits<TVal, TIter, IsRandom>::CreateIndexers(val, m_itBegin, m_itCur, dimensions, pIdxs);
                ++m_itCur;

                IndexerTraits<TVal, TIter, IsRandom>::FillIndexers(dimensions, pIdxs, ppIndexers);
                MetadataTraits<TVal>::FillMetadata(val, ppMetadata);
                *ppObject = objVal.Detach();
            }
            catch(...)
            {
                m_thrown = std::current_exception();
                return ClientEx::Details::Exceptions::ReturnResult(m_thrown);
            }

            return S_OK;
        }

    private:

        //
        // If this is instance data for a TypedInstanceData<T>, this should be a T& (or the underlying U of T where T is
        // std::shared_ptr<U> or std::unique_ptr<U>.
        //
        // It is imperative that this **STAYS** a reference if the generator returned a reference and a value if the generator
        // returned a value.  Otherwise, we will incur a significant number of copies.
        //
        // For generators that return a value, is a move constructed version of that data.
        //
        TGen m_generator;

        std::exception_ptr m_thrown;
        TIter m_itBegin;
        TIter m_itEnd;
        TIter m_itCur;
        TProjector m_projector;
        ClientEx::Object m_srcObject;
        DataModelReference m_linkReference;
    };

    template<typename TClass, typename TGenProjector, typename TItemProjector>
    class BoundIterableBase :
        public Microsoft::WRL::Implements<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IIterableConcept
            >
    {
    public:

        using ItemProjectorFunction = typename FunctorTraits<TItemProjector>::FunctionType;
        using GenProjectorFunction = typename FunctorTraits<TGenProjector>::FunctionType;
        using GeneratorType = typename FunctorTraits<TGenProjector>::ReturnType;
        using CIterator = decltype(std::declval<GeneratorType>().begin());
        using CIteratorValue = std::decay_t<decltype(*(std::declval<CIterator>()))>;
        using ModelIndexerTraits = IndexerTraits<CIteratorValue, CIterator, IsRandomAccessIterator_v<CIterator>>;

        //*************************************************
        // IIterableConcept:
        //

        // GetDefaultIndexDimensionality():
        //
        // Gets the dimensionality of the indexer.  For random access iterators, we provide a linear
        // implementation; otherwise, we provide no indexer and the return is zero.
        //
        IFACEMETHOD(GetDefaultIndexDimensionality)(_In_ IModelObject * /*pContextObject*/,
                                                   _Out_ ULONG64 *pDimensionality)
        {
            *pDimensionality = ModelIndexerTraits::Dimensionality;
            return S_OK;
        }

        // GetIterator():
        //
        // Gets an iterator for a given object.
        //
        IFACEMETHOD(GetIterator)(_In_ IModelObject *pContextObject,
                                 _Out_ IModelIterator **ppIterator)
        {
            *ppIterator = nullptr;
            try
            {
                ThrowIfDetached(m_linkReference);
                Object obj(pContextObject);

                //
                // Subtle semantics:
                //
                // If GetGenerator() returns a reference, it must be preserved as a reference into BoundIterator<>.  We must
                // hold the reference and not *MOVE* the underlying object into the iterator.  The reference may be the underlying
                // data of a TTypedInstance<...> to which we are bound.
                //
                // On the other hand, if GetGenerator() returns a value, the value *MUST* be moved into BoundIterator().  It
                // may be a generator that cannot be copy constructed.
                //
                GeneratorType generator = GetGenerator(obj);

                using TGenBase = std::decay_t<GeneratorType>;
                using TGenPass = std::conditional_t<std::is_reference_v<GeneratorType>, GeneratorType, GeneratorType&&>;

                using ModelIterator = BoundIterator<GeneratorType,
                                                    CIterator,
                                                    ItemProjectorFunction,
                                                    IsRandomAccessIterator_v<CIterator>>;

                auto itBegin = generator.begin();
                auto itEnd = generator.end();

                DataModelReference iterRef = GetLinkReference();
                ComPtr<ModelIterator> spIter = Make<ModelIterator>(std::move(iterRef), (TGenPass)generator, itBegin, itEnd, obj, m_itemProjector);
                if (spIter == nullptr)
                {
                    throw std::bad_alloc();
                }

                *ppIterator = spIter.Detach();
            }
            catch(...)
            {
                return Exceptions::ReturnResult(std::current_exception());
            }

            return S_OK;
        }

        //*************************************************
        // Internal Methods
        //

        const DataModelReference& GetLinkReference() const
        {
            return m_linkReference;
        }

    protected:

        virtual IModelObject *GetObject(_In_opt_ IModelObject *pOverrideObject = nullptr)
        {
            if (pOverrideObject != nullptr)
            {
                return pOverrideObject;
            }

            return m_pClass->GetObject();
        }

        GeneratorType GetGenerator(_In_ const Object& instanceObject)
        {
            return m_genProjector(instanceObject);
        }

        virtual void Apply(_In_opt_ IModelObject *pOverrideObject = nullptr)
        {
            GetObject(pOverrideObject)->SetConcept(__uuidof(IIterableConcept), static_cast<IIterableConcept *>(this), nullptr);
        }

        TClass *m_pClass;
        GenProjectorFunction m_genProjector;
        ItemProjectorFunction m_itemProjector;
        DataModelReference m_linkReference;

    };

    // BoundIterableIndexableBase:
    //
    // A class which implements both iterator and indexer based solely on an iterator (one which is a C++ random access iterator).
    // The indexer is a linear 0-based indexer as an offset from the base iterator (.begin())
    //
    template<typename TClass, typename TGenProjector, typename TItemProjector>
    class BoundIterableIndexableBase :
        public Microsoft::WRL::Implements<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IIndexableConcept,
            BoundIterableBase<TClass, TGenProjector, TItemProjector>
            >
    {
    private:

        using Base = Microsoft::WRL::Implements<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IIndexableConcept,
            BoundIterableBase<TClass, TGenProjector, TItemProjector>
            >;

    public:

        //*************************************************
        // IIndexableConcept:
        //

        IFACEMETHOD(GetDimensionality)(_In_ IModelObject * /*pContextObject*/,
                                       _Out_ ULONG64 *pDimensionality)
        {
            *pDimensionality = 1;
            return S_OK;
        }

        IFACEMETHOD(GetAt)(_In_ IModelObject *pContextObject,
                           _In_ ULONG64 indexerCount,
                           _In_reads_(indexerCount) IModelObject **ppIndexers,
                           _COM_Errorptr_ IModelObject **ppObject,
                           _COM_Outptr_opt_result_maybenull_ IKeyStore **ppMetadata)
        {
            *ppObject = nullptr;
            if (ppMetadata != nullptr)
            {
                *ppMetadata = nullptr;
            }

            try
            {
                ThrowIfDetached(this->m_linkReference);
                if (indexerCount != 1)
                {
                    return E_INVALIDARG;
                }

                Object obj = pContextObject;
                auto&& instanceRef = this->GetGenerator(obj);
                auto itBegin = instanceRef.begin();

                VARIANT vtIdx;
                CheckHr(ppIndexers[0]->GetIntrinsicValueAs(VT_UI8, &vtIdx));
                size_t stIdx = static_cast<size_t>(vtIdx.ullVal);
                size_t delta = instanceRef.end() - itBegin;
                if (stIdx > delta)
                {
                    return E_BOUNDS;
                }

                auto itCur = itBegin + stIdx;
                auto val = this->m_itemProjector(*itCur);
                Object valObject = BoxObject(val);

                MetadataTraits<std::decay_t<decltype(val)>>::FillMetadata(val, ppMetadata);
                *ppObject = valObject.Detach();
            }
            catch(...)
            {
                return Exceptions::ReturnResult(std::current_exception(), ppObject);
            }

            return S_OK;
        }

        IFACEMETHOD(SetAt)(_In_ IModelObject * /*pContextObject*/,
                           _In_ ULONG64 indexerCount,
                           _In_reads_(indexerCount) IModelObject ** /*ppIndexers*/,
                           _In_ IModelObject * /*pValue*/)
        {
            UNREFERENCED_PARAMETER(indexerCount);
            return E_NOTIMPL;
        }

    protected:

        virtual void Apply(_In_opt_ IModelObject *pOverrideObject = nullptr)
        {
            Base::Apply(pOverrideObject);
            this->GetObject(pOverrideObject)->SetConcept(__uuidof(IIndexableConcept), static_cast<IIndexableConcept *>(this), nullptr);
        }

    };

    template<typename TClass, typename TGenProjector, typename TItemProjector, typename TGetAt, typename TSetAt>
    class BoundIterableWithIndexable :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            BoundIterableBase<TClass, TGenProjector, TItemProjector>,
            IIndexableConcept
            >
    {
    public:

        using TGeneratorType = typename FunctorTraits<TGenProjector>::ReturnType;
        using TIterator = decltype(std::declval<TGeneratorType>().begin());
        using TIndexedValue = decltype(*(std::declval<TIterator>()));
        using TIndexedValueBase = std::decay_t<TIndexedValue>;
        using TIndicies = typename TIndexedValueBase::IndiciesType;
        static constexpr ULONG64 Dimensionality = (ULONG64)(TIndexedValueBase::Dimensionality);

        using TGetAtFunction = typename FunctorTraits<TGetAt>::FunctionType;
        using TSetAtFunction = typename FunctorTraits<TSetAt>::FunctionType;

        BoundIterableWithIndexable(_In_ DataModelReference&& transferredLinkReference,
                                   _In_ TClass *pClass,
                                   _In_ const TGenProjector& genProjectionFunction,
                                   _In_ const TItemProjector& itemProjectionFunction,
                                   _In_ const TGetAt& getAtProjectionFunction,
                                   _In_ const TSetAt& setAtProjectionFunction)
        {
            //
            // This isn't done through base initializers because of the flow through WRL::RuntimeClass.
            //
            this->m_pClass = pClass;
            this->m_itemProjector = itemProjectionFunction;
            this->m_genProjector = genProjectionFunction;
            this->m_getAtFunction = getAtProjectionFunction;
            this->m_setAtFunction = setAtProjectionFunction;
            this->m_linkReference = std::move(transferredLinkReference);
            this->Apply();
        }

        //*************************************************
        // IIndexableConcept:
        //

        IFACEMETHOD(GetDimensionality)(_In_ IModelObject * /*pContextObject*/,
                                       _Out_ ULONG64 *pDimensionality)
        {
            *pDimensionality = Dimensionality;
            return S_OK;
        }

        IFACEMETHOD(GetAt)(_In_ IModelObject *pContextObject,
                           _In_ ULONG64 indexerCount,
                           _In_reads_(indexerCount) IModelObject **ppIndexers,
                           _COM_Errorptr_ IModelObject **ppObject,
                           _COM_Outptr_opt_result_maybenull_ IKeyStore **ppMetadata)
        {
            *ppObject = nullptr;
            if (ppMetadata != nullptr)
            {
                *ppMetadata = nullptr;
            }

            try
            {
                ThrowIfDetached(this->m_linkReference);
                if (indexerCount != Dimensionality)
                {
                    return E_INVALIDARG;
                }

                Object contextObj = pContextObject;
                Object idxVal = InvokeFunctionFromPack(m_getAtFunction, contextObj, static_cast<size_t>(indexerCount), ppIndexers, ppMetadata);

                *ppObject = idxVal.Detach();
            }
            catch(...)
            {
                return Exceptions::ReturnResult(std::current_exception(), ppObject);
            }

            return S_OK;
        }

        IFACEMETHOD(SetAt)(_In_ IModelObject *pContextObject,
                           _In_ ULONG64 indexerCount,
                           _In_reads_(indexerCount) IModelObject **ppIndexers,
                           _In_ IModelObject *pValue)
        {
            try
            {
                ThrowIfDetached(this->m_linkReference);
                if (indexerCount != Dimensionality)
                {
                    return E_INVALIDARG;
                }

                //
                // The value has to be type matched to the second argument of the functor.  A setAt signature is
                // (const Object& contextObject, TValue val, <indexers>)
                //
                using ValueType = typename FunctorTraits<TSetAt>::template ArgumentType_t<1>;

                Object valueObj = pValue;
                ValueType val = (ValueType)valueObj;

                Object contextObj = pContextObject;
                Object dummyReturn = InvokeFunctionFromPack(m_setAtFunction, contextObj, static_cast<size_t>(indexerCount), ppIndexers, nullptr, val);
            }
            catch(...)
            {
                return Exceptions::ReturnResult(std::current_exception());
            }
            return S_OK;
        }

    protected:

        virtual void Apply(_In_opt_ IModelObject *pOverrideObject = nullptr)
        {
            BoundIterableBase<TClass, TGenProjector, TItemProjector>::Apply(pOverrideObject);
            this->GetObject(pOverrideObject)->SetConcept(__uuidof(IIndexableConcept), static_cast<IIndexableConcept *>(this), nullptr);
        }

    private:

        TGetAtFunction m_getAtFunction;
        TSetAtFunction m_setAtFunction;

    };

    template<typename TClass, typename TGenProjector, typename TItemProjector>
    class BoundIterable :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            std::conditional_t<IsRandomAccessIterable_v<typename FunctorTraits<TGenProjector>::ReturnType>,
                               BoundIterableIndexableBase<TClass, TGenProjector, TItemProjector>,
                               BoundIterableBase<TClass, TGenProjector, TItemProjector>>
            >
    {
    public:

        BoundIterable(_In_ DataModelReference&& transferredLinkReference,
                      _In_ const TGenProjector& genProjectionFunction,
                      _In_ const TItemProjector& itemProjectionFunction,
                      _In_ IModelObject *pOverrideObject) : BoundIterable(std::move(transferredLinkReference),
                                                                          nullptr,
                                                                          genProjectionFunction,
                                                                          itemProjectionFunction,
                                                                          pOverrideObject) { }

        BoundIterable(_In_ DataModelReference&& transferredLinkReference,
                      _In_ TClass *pClass,
                      _In_ const TGenProjector& genProjectionFunction,
                      _In_ const TItemProjector& itemProjectionFunction) : BoundIterable(std::move(transferredLinkReference),
                                                                                         pClass,
                                                                                         genProjectionFunction,
                                                                                         itemProjectionFunction,
                                                                                         nullptr) { }

        BoundIterable(_In_ DataModelReference&& transferredLinkReference,
                      _In_ TClass *pClass,
                      _In_ const TGenProjector& genProjectionFunction,
                      _In_ const TItemProjector& itemProjectionFunction,
                      _In_ IModelObject *pOverrideObject)
        {
            //
            // This isn't done through base initializers because of the flow through WRL::RuntimeClass.
            //
            this->m_pClass = pClass;
            this->m_itemProjector = itemProjectionFunction;
            this->m_genProjector = genProjectionFunction;
            this->m_linkReference = std::move(transferredLinkReference);
            this->Apply(pOverrideObject);
        }
    };

    //*************************************************
    // Custom Comparison and Equality:
    //

    template<typename TClass, typename TEquatableProjector>
    class BoundEquatable :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IEquatableConcept
            >
    {
    public:

        using EquatableProjectorFunction = typename ClientEx::Details::FunctorTraits<TEquatableProjector>::FunctionType;

        BoundEquatable(_In_ TClass *pClass,
                       _In_ const TEquatableProjector& equatableProjectorFunction)
        {
            m_pClass = pClass;
            m_equatableProjector = equatableProjectorFunction;
            Apply();
        }

        //*************************************************
        // IEquatableConcept:
        //

        // AreObjectsEqual():
        //
        // Compares this object to another (of arbitrary type) for equality.  If
        // the comparison cannot be performed, E_NOT_SET should be returned.
        //
        IFACEMETHOD(AreObjectsEqual)(_In_ IModelObject *pContextObject,
                                     _In_ IModelObject *pOtherObject,
                                     _Out_ bool *pIsEqual)
        {
            try
            {
                ClientEx::Object contextObj = pContextObject;
                ClientEx::Object otherObj = pOtherObject;
                *pIsEqual = m_equatableProjector(contextObj, otherObj);
            }
            catch(...)
            {
                return ClientEx::Details::Exceptions::ReturnResult(std::current_exception());
            }
            return S_OK;
        }

    private:

        void Apply()
        {
            m_pClass->GetObject()->SetConcept(__uuidof(IEquatableConcept), static_cast<IEquatableConcept *>(this), nullptr);
        }

        TClass *m_pClass;
        EquatableProjectorFunction m_equatableProjector;
    };

    template<typename TClass, typename TComparableProjector>
    class BoundComparable :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IComparableConcept
            >
    {
    public:

        using ComparableProjectorFunction = typename ClientEx::Details::FunctorTraits<TComparableProjector>::FunctionType;

        BoundComparable(_In_ TClass *pClass,
                       _In_ const TComparableProjector& comparableProjectorFunction)
        {
            m_pClass = pClass;
            m_comparableProjector = comparableProjectorFunction;
            Apply();
        }

        //*************************************************
        // IComparableConcept:
        //

        // CompareObjects():
        //
        // Compares this object to another (of arbitrary type).  If the comparison
        // cannot be performed, E_NOT_SET should be returned.
        //
        // The return value passed in comparison result has the following meaning:
        //
        //    < 0 : contextObject < otherObject
        //      0 : contextObject == otherObject
        //    > 0 : contextObject > otherObject
        //
        IFACEMETHOD(CompareObjects)(_In_ IModelObject *pContextObject,
                                    _In_ IModelObject *pOtherObject,
                                    _Out_ int *pComparisonResult)
        {
            try
            {
                ClientEx::Object contextObj = pContextObject;
                ClientEx::Object otherObj = pOtherObject;
                *pComparisonResult = m_comparableProjector(contextObj, otherObj);
            }
            catch(...)
            {
                return ClientEx::Details::Exceptions::ReturnResult(std::current_exception());
            }
            return S_OK;
        }

    private:

        void Apply()
        {
            m_pClass->GetObject()->SetConcept(__uuidof(IComparableConcept), static_cast<IComparableConcept *>(this), nullptr);
        }

        TClass *m_pClass;
        ComparableProjectorFunction m_comparableProjector;
    };

    // BoxObjectBase:
    //
    // Base class for the object boxer.  Provides a set of helpers for unboxing.
    //
    struct BoxObjectBase
    {
    protected:

        // CheckType():
        //
        // Checks whether the object is of a "kind" as passed in.  If not, throws
        // InvalidArgument.
        //
        static void CheckType(_In_ const Object& src, _In_ ModelObjectKind requiredKind)
        {
            ModelObjectKind mk;
            HRESULT hr = src->GetKind(&mk);
            CheckHr(hr);

            if (mk != requiredKind)
            {
                throw std::invalid_argument("Illegal object type");
            }
        }

        // ExtractInterface():
        //
        // Extracts a raw interface from a boxed interface.
        //
        template<typename TInterface>
        static TInterface *ExtractInterface(_In_ const Object& src)
        {
            VARIANT vtVal;
            HRESULT hr = src->GetIntrinsicValue(&vtVal);
            CheckHr(hr);
            if (vtVal.vt != VT_UNKNOWN)
            {
                VariantClear(&vtVal);
                throw std::invalid_argument("Illegal object type");
            }

            //
            // It is safe to VariantClear and return the raw interface because it is still held by src.
            //
            TInterface *pRawInterface = static_cast<TInterface *>(vtVal.punkVal);
            VariantClear(&vtVal);
            return pRawInterface;
        }
    };

    // BoxObjectIntrinsic:
    //
    // For a given T which is intrinsic, box/unbox the intrinsic
    //
    template<typename T>
    struct BoxObjectIntrinsic : public BoxObjectBase
    {
        static Object Box(_In_ const T& obj)
        {
            using ValueType = std::remove_reference_t<T>;
            using IntrinsicTraits = IntrinsicTypeTraits<ValueType>;
            static_assert(has_varianttype_field_v<IntrinsicTraits>, "No BoxObject<T>::Box exists for the given type.  Unable to box.");

            VARIANT vtVal;
            IntrinsicTraits::FillVariant(&vtVal, obj);

            ComPtr<IModelObject> spObj;
            HRESULT hr = GetManager()->CreateIntrinsicObject(IntrinsicTraits::ObjectKind, &vtVal, &spObj);
            CheckHr(hr, spObj);

            return Object(std::move(spObj));
        }

        static T Unbox(_In_ const Object& src)
        {
            using IntrinsicTraits = IntrinsicTypeTraits<T>;
            static_assert(has_varianttype_field_v<IntrinsicTraits>, "No BoxObject<T>::Unbox exists for the given type.  Unable to unbox.");

            VARIANT vtVal;
            HRESULT hr = src->GetIntrinsicValueAs(IntrinsicTraits::VariantType, &vtVal);
            CheckHr(hr);
            T val = IntrinsicTraits::ExtractFromVariant(&vtVal);
            VariantClear(&vtVal);
            return val;
        }
    };

    // MethodBoxer:
    //
    // For an object which is a functor, box/unbox the functor.
    //
    template<typename T>
    struct BoxObjectMethod
    {
        static Object Box(_In_ const T& obj)
        {
            ComPtr<BoxedMethod<T>> spMethodInterface = Make<BoxedMethod<T>>(obj);
            if (spMethodInterface == nullptr)
            {
                throw std::bad_alloc();
            }

            // @TODO: This should be part of the boxer.
            VARIANT vtVal;
            vtVal.vt = VT_UNKNOWN;
            vtVal.punkVal = static_cast<IModelMethod *>(spMethodInterface.Get());
            ComPtr<IModelObject> spMethod;
            CheckHr(GetManager()->CreateIntrinsicObject(ObjectMethod, &vtVal, &spMethod));
            return Object(std::move(spMethod));
        }
    };

    // NotImplementedSetFunction:
    //
    // A set function that throws not-implemented, used for read-only
    // properties.
    //

    inline void NotImplementedSetFunction(_In_ const Object& /*instanceObject*/, _In_ const Object& /*value*/)
    {
        throw not_implemented();
    }

    // BoxProperty:
    //
    // For a pair of get/set functors, make a property and box it.
    //
    template<typename TGetFunc, typename TSetFunc>
    inline Object BoxProperty(_In_ const TGetFunc& getFunc, _In_ const TSetFunc& setFunc)
    {
        using GetterTraits = FunctorTraits<TGetFunc>;
        using SetterTraits = FunctorTraits<TSetFunc>;
        using Getter0Decay = std::decay_t<typename SetterTraits::template ArgumentType_t<0>>;
        using Setter0Decay = std::decay_t<typename SetterTraits::template ArgumentType_t<0>>;

        static_assert(SetterTraits::ArgumentCount == 2, "Invalid signature for property set functor");
        static_assert(GetterTraits::ArgumentCount == 1, "Invalid signature for property get functor");
        static_assert(std::is_same_v<Getter0Decay, Object>, "Invalid signature for property get functor");
        static_assert(std::is_same_v<Setter0Decay, Object>, "Invalid signature for property set functor");

        ComPtr<BoxedProperty<TGetFunc, TSetFunc>> spPropertyInterface = Make<BoxedProperty<TGetFunc, TSetFunc>>(getFunc, setFunc);
        if (spPropertyInterface == nullptr)
        {
            throw std::bad_alloc();
        }

        // @TODO: This should be part of the boxer.
        VARIANT vtVal;
        vtVal.vt = VT_UNKNOWN;
        vtVal.punkVal = static_cast<IModelPropertyAccessor *>(spPropertyInterface.Get());
        ComPtr<IModelObject> spProperty;
        CheckHr(GetManager()->CreateIntrinsicObject(ObjectPropertyAccessor, &vtVal, &spProperty));
        return Object(std::move(spProperty));
    }

    // BoxProperty:
    //
    // For a get functor, make a property and box it. The implicit set functor
    // will throw not_implemented.
    //
    template <typename TGetFunc>
    inline Object BoxProperty(_In_ const TGetFunc& getFunc)
    {
        return BoxProperty(getFunc, &NotImplementedSetFunction);
    }

    // BoxObjectArray:
    //
    // For a T[N] array, box/unbox it.
    //
    template<typename T, size_t N>
    struct BoxObjectArray
    {
        static Object Box(_In_ const T tArray[N])
        {
            Object arrayObject = Object::Create(HostContext());
            Microsoft::WRL::Make<BoxedArray<T>>(arrayObject, tArray, N);
            return arrayObject;
        }
    };

    template<typename T>
    struct InterfaceTraits
    {
    };

    template<> struct InterfaceTraits<IModelMethod>
    {
        static const ModelObjectKind ObjectKind = ObjectMethod;
    };

    template<> struct InterfaceTraits<IModelPropertyAccessor>
    {
        static const ModelObjectKind ObjectKind = ObjectPropertyAccessor;
    };

    template<> struct InterfaceTraits<IModelKeyReference>
    {
        static const ModelObjectKind ObjectKind = ObjectKeyReference;
    };

    template<> struct InterfaceTraits<IDebugHostContext>
    {
        static const ModelObjectKind ObjectKind = ObjectContext;
    };

    // BoxObjectInterface:
    //
    // Helper class which acts as a boxer/unboxer for various interfaces.
    //
    template<typename TInterface>
    struct BoxObjectInterface : public BoxObjectBase
    {
        static Object Box(_In_ TInterface *interfacePointer)
        {
            ModelObjectKind mk = Details::InterfaceTraits<TInterface>::ObjectKind;
            VARIANT vtUnk; vtUnk.vt = VT_UNKNOWN; vtUnk.punkVal = interfacePointer;
            ComPtr<IModelObject> spInterface;
            CheckHr(GetManager()->CreateIntrinsicObject(mk, &vtUnk, &spInterface));
            return Object(std::move(spInterface));
        }

        static TInterface *Unbox(_In_ const Object& src)
        {
            CheckType(src, InterfaceTraits<TInterface>::ObjectKind);
            return ExtractInterface<TInterface>(src);
        }
    };

    // SpotLinkReference:
    //
    // Link reference helper class for bindings without an associated model class.
    //
    class SpotLinkReference
    {
    public:

        SpotLinkReference() : m_dataRef(std::make_shared<DataModelReferenceInfo>()) { }
        SpotLinkReference(_In_ SpotLinkReference&& src) : m_dataRef(std::move(src.m_dataRef)) { }
        SpotLinkReference& operator=(_In_ SpotLinkReference&& src) { m_dataRef = std::move(src.m_dataRef); return *this; }

        ~SpotLinkReference()
        {
            if (m_dataRef != nullptr)
            {
                m_dataRef->TypeIsLive = false;
            }
        }

        const DataModelReference& GetLinkReference() const
        {
            return m_dataRef;
        }

    private:

        SpotLinkReference(_In_ const SpotLinkReference&) =delete;
        SpotLinkReference& operator=(_In_ const SpotLinkReference&) =delete;

        DataModelReference m_dataRef;
    };

    // EmptyBinding:
    //
    // Helper class for bindings without an associated model class.
    //
    struct EmptyBinding
    {
        IModelObject *GetObject() { throw not_implemented(); }
    };

    // BoxObjectIterable:
    //
    // Helper class which acts as a boxer for iterables which have no other specific
    // boxer.
    //
    template<typename TIterable>
    struct BoxObjectIterable : public BoxObjectBase
    {
    public:

        //
        // We have some move only iterables (e.g.: generators).  Deal with boxing them by moving the container
        // into the projector and requiring that it live for the lifetime of the iterable (via a linkref)
        //
        template<typename TObj>
        static Object Box(_In_ TObj&& iterable)
        {
            static_assert(
                std::is_same_v<std::decay_t<TObj>, std::decay_t<TIterable>> ||
                std::is_same_v<std::decay_t<TObj>, std::shared_ptr<TIterable>>,
                "Illegal argument to BoxObject<T>::Box for an iterable");
            //
            // genProjectorFunc is the *HOLDER* of the iterable until such time as it is
            // used.  It remains the holder during iteration.
            //
            // Because we embody the functors in std::function, the lambdas must be copy constructable.  We
            // cannot directly move iterable into the lambda body.  We must enclose it in something which can be
            // copied but holds a singular unique moved reference to iterable.
            //
            std::shared_ptr<TIterable> spSharedIterable;
            if constexpr(std::is_same_v<std::decay_t<TObj>, std::shared_ptr<TIterable>>)
            {
                spSharedIterable = std::forward<TObj>(iterable);
            }
            else
            {
                spSharedIterable.reset(new TIterable(std::forward<TObj>(iterable)));
            }
            std::shared_ptr<SpotLinkReference> spSpotRef = std::make_shared<SpotLinkReference>();

            DataModelReference linkRef = spSpotRef->GetLinkReference();

            auto genProjectorFunc = [heldSpotRef = std::move(spSpotRef),
                                     mvIterable = std::move(spSharedIterable)](_In_ const Object& /*emptyObject*/) -> TIterable&
            {
                return *(mvIterable.get());
            };

            using TItem = decltype(*(std::declval<std::decay_t<TIterable>>().begin()));
            auto itemProjectorFunc = [](_In_ TItem eref) { return eref; };

            //
            // Create an empty object which represents this container and place and iterable upon it.
            // @TODO: It might be better performance to create a data model with this and attach.
            //
            Object container = Object::Create(HostContext());

            using TGenProjector = decltype(genProjectorFunc);
            using TItemProjector = decltype(itemProjectorFunc);

            ComPtr<BoundIterable<EmptyBinding, TGenProjector, TItemProjector>> spIterable;

            // NOTE:
            //
            // The construction of the binding will apply it to the object 'container'.  After
            // the below line, the iterable concept on 'container' is spIterable.
            //
            spIterable = Make<BoundIterable<EmptyBinding, TGenProjector, TItemProjector>>(
                std::move(linkRef), genProjectorFunc, itemProjectorFunc, container
                );

            return container;
        }
    };

} // Details

//**************************************************************************
// Object Boxing and Unboxing
//

namespace Boxing
{
    namespace Details = Debugger::DataModel::ClientEx::Details;

    // Function and Method Boxing and Unboxing:
    //

    template<typename T, typename = void>
    struct BoxObject : public std::conditional_t<Details::has_call_operator_v<T>,
                                                 Details::BoxObjectMethod<T>,
                                                 std::conditional_t<Details::IsIterable_v<T>,
                                                                    Details::BoxObjectIterable<T>,
                                                                    Details::BoxObjectIntrinsic<T>>>
    {
    };

    template<typename T>
    struct BoxObject<std::shared_ptr<T>, std::enable_if_t<Details::IsIterable_v<T>>> : Details::BoxObjectIterable<T>
    {
    };

    template<typename TRet, typename... TArgs>
    struct BoxObject<TRet (*)(TArgs...)> : public Details::BoxObjectMethod<TRet (*)(TArgs...)>
    {
    };

    template<typename TRet, typename... TArgs>
    struct BoxObject<TRet(TArgs...)> : public Details::BoxObjectMethod<TRet (*)(TArgs...)>
    {
    };

    // Details Reference Type Boxing/Unboxing:
    //
    // Specializations of BoxObject<T> for types returned as C++ references.
    //

    template<typename TVal, typename... TIndicies>
    struct BoxObject<IndexedValue<TVal, TIndicies...>>
    {
        static Object Box(_In_ const IndexedValue<TVal, TIndicies...>& src)
        {
            return BoxObject<TVal>::Box(src.GetValue());
        }
    };

    template<typename TVal>
    struct BoxObject<ValueWithMetadata<TVal>>
    {
        static Object Box(_In_ const ValueWithMetadata<TVal>& src)
        {
            return BoxObject<TVal>::Box(src.GetValue());
        }
    };

    template<>
    struct BoxObject<Details::ObjectKeyRef<Object, Metadata>>
    {
        static Object Box(_In_ const Details::ObjectKeyRef<Object, Metadata>& keyRef)
        {
            return keyRef.GetValue();
        }
    };

    template<>
    struct BoxObject<Details::ObjectFieldRef<Object>>
    {
        static Object Box(_In_ const Details::ObjectFieldRef<Object>& fieldRef)
        {
            return fieldRef.GetValue();
        }
    };

    template<>
    struct BoxObject<Details::DereferenceReference<Object>>
    {
        static Object Box(_In_ const Details::DereferenceReference<Object>& derefRef)
        {
            return derefRef.GetValue();
        }
    };

    template<typename TPack>
    struct BoxObject<Details::IndexableReference<Object, TPack>>
    {
        static Object Box(_In_ const Details::IndexableReference<Object, TPack>& indexableRef)
        {
            return indexableRef.GetValue();
        }
    };

    // String Boxing/Unboxing:
    //
    // Specializations of BoxObject<T> for string types.
    //
    template<>
    struct BoxObject<const wchar_t *>
    {
        static Object Box(_In_z_ const wchar_t *pString)
        {
            //
            // @TODO: It would be nice to have a better mechanism of string creation in DbgModel.  This is a double
            // alloc.  Wasteful.
            //
            BSTR bstrStr = SysAllocString(pString);
            if (bstrStr == nullptr)
            {
                throw std::bad_alloc();
            }
            bstr_ptr spStr(bstrStr);

            VARIANT vtVal;
            vtVal.vt = VT_BSTR;
            vtVal.bstrVal = bstrStr;
            ComPtr<IModelObject> spString;
            ClientEx::CheckHr(GetManager()->CreateIntrinsicObject(ObjectIntrinsic, &vtVal, &spString));
            return Object(std::move(spString));
        }
    };

    template<>
    struct BoxObject<wchar_t *>
    {
        static Object Box(_In_z_ const wchar_t *pString)
        {
            return BoxObject<const wchar_t *>::Box(pString);
        }
    };

    template<>
    struct BoxObject<std::wstring>
    {
        static Object Box(_In_ const std::wstring& str)
        {
            const wchar_t * pStr = str.c_str();
            return BoxObject<const wchar_t *>::Box(pStr);
        }

        static std::wstring Unbox(_In_ const Object& src)
        {
            VARIANT vtVal;
            CheckHr(src->GetIntrinsicValueAs(VT_BSTR, &vtVal));
            bstr_ptr spvVal(vtVal.bstrVal);
            return std::wstring(vtVal.bstrVal);
        }
    };

    template<>
    struct BoxObject<std::string>
    {
        static Object Box(_In_ const std::string& str)
        {
            std::wstring wstr = Details::StringUtils::GetWideString(str.c_str());
            const wchar_t * pStr = wstr.c_str();
            return BoxObject<const wchar_t *>::Box(pStr);
        }

        static std::string Unbox(_In_ const Object& src)
        {
            VARIANT vtVal;
            CheckHr(src->GetIntrinsicValueAs(VT_BSTR, &vtVal));
            bstr_ptr spvVal(vtVal.bstrVal);
            std::wstring wstrVal(vtVal.bstrVal);
            std::string strVal = Details::StringUtils::GetNarrowString(wstrVal.c_str());
            return strVal;
        }
    };

    //
    // Enum class Boxing/Unboxing:
    //
    // TEnum is an enum class
    //
    // Example use (make TTD::SequenceId projectable to data model):
    //     namespace Debugger::DataModel::ClientEx::Boxing
    //     {
    //         template <> struct BoxObject<TTD::SequenceId> : UnderlyingTypeBoxObject<TTD::SequenceId> {};
    //     }

    template <typename TEnum>
    struct UnderlyingTypeBoxObject
    {
        static Object Box(_In_ const TEnum& obj)
        {
            return BoxObject<std::underlying_type_t<TEnum>>::Box(static_cast<std::underlying_type_t<TEnum>>(obj));
        }

        static TEnum Unbox(_In_ const Object& src)
        {
            return static_cast<TEnum>(static_cast<std::underlying_type_t<TEnum>>(src));
        }
    };

    //
    // String Resource Boxing/Unboxing:
    //
    // ResourceString is pulled upon boxing
    // DeferredResourceString is boxed into a property which pulls upon GetValue.
    //

    template<>
    struct BoxObject<ResourceString>
    {
        static Object Box(_In_ const ResourceString& rscString)
        {
            struct LibraryUnloader
            {
                void operator()(_In_ void * hModule)
                {
                    HMODULE hMod = reinterpret_cast<HMODULE>(hModule);
                    if (hMod != nullptr)
                    {
                        FreeLibrary(hMod);
                    }
                }
            };

            using hmodule_ptr = std::unique_ptr<void, LibraryUnloader>;
            hmodule_ptr spModuleHandle;

            HMODULE hModule = rscString.Module;

            if (hModule == nullptr)
            {
                if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                       reinterpret_cast<LPCTSTR>(Box),
                                       &hModule))
                {
                    throw hr_exception(HRESULT_FROM_WIN32(GetLastError()), "Unable to retrieve resource string");
                }

                spModuleHandle.reset(hModule);
            }

            std::wstring extractedString;

            if (rscString.ResourceType == nullptr)
            {
                PWSTR pString;
                INT result = ::LoadStringW(hModule, rscString.Id, reinterpret_cast<PWSTR>(&pString), 0);
                if (!result)
                {
                    throw hr_exception(HRESULT_FROM_WIN32(GetLastError()), "Unable to retrieve resource string");
                }

                extractedString.append(pString, static_cast<size_t>(result));
            }
            else
            {
                HRSRC resourceInfo = FindResourceW(hModule, MAKEINTRESOURCEW(rscString.Id), rscString.ResourceType);

                if (resourceInfo == NULL)
                {
                    throw hr_exception(HRESULT_FROM_WIN32(GetLastError()), "Unable to retrieve find resource");
                }

                DWORD dwResourceSize = SizeofResource(hModule, resourceInfo);
                if (dwResourceSize == 0)
                {
                    throw hr_exception(HRESULT_FROM_WIN32(GetLastError()), "Failed to get length of the resource");
                }

                HGLOBAL resourceHandle = LoadResource(hModule, resourceInfo);
                if (resourceHandle == NULL)
                {
                    throw hr_exception(HRESULT_FROM_WIN32(GetLastError()), "Failed to load resource for module.");
                }

                LPWSTR data = static_cast<LPWSTR>(LockResource(resourceHandle));
                if (data == nullptr)
                {
                    throw hr_exception(HRESULT_FROM_WIN32(GetLastError()), "Failed to lock resource");
                }

                DWORD cchData = dwResourceSize / sizeof(wchar_t);

                // Check for a UTF-16 little endian byte-order mark and skip it if there is one
                if ((cchData > 0) && (data[0] == 0xfeff))
                {
                    data += 1;
                    cchData -= 1;

                    BSTR resourceString = SysAllocStringLen(data, cchData);
                    if (resourceString == nullptr)
                    {
                        throw hr_exception(E_OUTOFMEMORY, "Failed to allocate string memory for resource");
                    }
                    bstr_ptr spResourceString(resourceString);

                    extractedString = resourceString;
                }
                else
                {
                    LPSTR stringData = reinterpret_cast<LPSTR>(data);
                    cchData = dwResourceSize;

                    std::string strResource(stringData, cchData);
                    extractedString = Details::StringUtils::GetWideString(strResource.c_str());
                }
            }
            return BoxObject<std::wstring>::Box(extractedString);
        }
    };

    template<>
    struct BoxObject<DeferredResourceString>
    {
        static Object Box(_In_ const DeferredResourceString& rscString)
        {
            auto getFunc = [rscString](_In_ const Object& /*instanceObject*/)
            {
                ResourceString activePull = rscString;
                return BoxObject<ResourceString>::Box(activePull);
            };

            auto setFunc = [](_In_ const Object& /*instanceObject*/, _In_ const Object& /*value*/)
            {
                throw not_implemented();
            };

            return Details::BoxProperty(getFunc, setFunc);
        }
    };

    // Interface Boxing/Unboxing:
    //
    // Specializations of BoxObject<T> for known interface pointers.
    //

    template<> struct BoxObject<IDebugHostContext *> : public Details::BoxObjectInterface<IDebugHostContext> { };
    template<> struct BoxObject<IModelMethod *> : public Details::BoxObjectInterface<IModelMethod> { };
    template<> struct BoxObject<IModelPropertyAccessor *> : public Details::BoxObjectInterface<IModelPropertyAccessor> { };
    template<> struct BoxObject<IModelKeyReference *> : public Details::BoxObjectInterface<IModelKeyReference> { };

    // ComPtr<T>
    //
    // Specializations of BoxObject<T> for ComPtr<Known Interface>
    //

    template<typename T>
    struct BoxObject<ComPtr<T>>
    {
        static Object Box(_In_ const ComPtr<T>& cptr)
        {
            return BoxObject<T*>::Box(cptr.Get());
        }

        static ComPtr<T> Unbox(_In_ const Object& src)
        {
            T *pRawInterface = BoxObject<T*>::Unbox(src);
            return ComPtr<T>(pRawInterface);
        }
    };

    // No Operation Boxing/Unboxing
    //
    // Specializations of BoxObject<T> for objects and interfaces which are already boxed.
    //

    template<>
    struct BoxObject<IModelObject *>
    {
        static Object Box(_In_ IModelObject * src)
        {
            return Object(src);
        }

        static IModelObject *Unbox(_In_ const Object& src)
        {
            return src.GetObject();
        }
    };

    template<>
    struct BoxObject<Object>
    {
        static Object Box(_In_ const Object& src)
        {
            return src;
        }

        static Object Unbox(_In_ const Object& src)
        {
            return src;
        }
    };

    template<> struct BoxObject<const Object&> : public BoxObject<Object> { };

    template<> struct BoxObject<std::nullptr_t>
    {
        static Object Box(_In_ std::nullptr_t)
        {
            return Object();
        }

        static std::nullptr_t Unbox(_In_ const Object& src)
        {
            if (src.GetObject() != nullptr)
            {
                throw std::invalid_argument("Only an empty object can unbox to nullptr_t");
            }
            return nullptr;
        }
    };

    //
    // Optional Boxing/Unboxing:
    //

    template<typename T>
    struct BoxObject<std::optional<T>>
    {
        static Object Box(_In_ const std::optional<T>& src)
        {
            if (src.has_value())
            {
                return BoxObject<T>::Box(src.value());
            }
            else
            {
                return Object::CreateNoValue();
            }
        }

        static Object Box(_Inout_ std::optional<T>&& src)
        {
            if (src.has_value())
            {
                return BoxObject<T>::Box(*std::move(src));
            }
            else
            {
                return Object::CreateNoValue();
            }
        }

        static std::optional<T> Unbox(_In_ const Object& src)
        {
            ModelObjectKind mk;
            CheckHr(src->GetKind(&mk));
            if (mk == ObjectNoValue)
            {
                return std::nullopt;
            }
            else
            {
                return BoxObject<T>::Unbox(src);
            }
        }
    };

    template<>
    struct BoxObject<HostContext>
    {
        static Object Box(_In_ const HostContext& src)
        {
            Object boxedObject = static_cast<IDebugHostContext *>(src);
            return boxedObject;
        }

        static HostContext Unbox(_In_ const Object& src)
        {
            return src;
        }
    };

    //
    // Deferred container boxing for generators:
    //
    template<typename TContainer>
    struct BoxObject<GeneratedIterable<TContainer>>
    {
        //
        // We have some move only iterables (e.g.: generators).  Deal with boxing them by moving the container
        // into the projector and requiring that it live for the lifetime of the iterable (via a linkref)
        //
        template<typename TContainer>
        static Object Box(_In_ const GeneratedIterable<TContainer>& src)
        {
            //
            // genProjectorFunc holds the functor and calls it to produce the iterable for the
            // BoundIterable.
            //
            std::shared_ptr<Details::SpotLinkReference> spSpotRef = std::make_shared<Details::SpotLinkReference>();
            std::function<TContainer(void)> acquireFunction = src.GetAcquireFunction();

            Details::DataModelReference linkRef = spSpotRef->GetLinkReference();

            auto genProjectorFunc = [heldSpotRef = std::move(spSpotRef),
                                     acquireFunction = std::move(acquireFunction)](_In_ const Object& /*emptyObject*/) -> TContainer
            {
                return acquireFunction();
            };

            using TItem = decltype(*(std::declval<std::decay_t<TContainer>>().begin()));
            auto itemProjectorFunc = [](_In_ TItem eref) { return eref; };

            //
            // Create an empty object which represents this container and place and iterable upon it.
            // @TODO: It might be better performance to create a data model with this and attach.
            //
            Object container = Object::Create(HostContext());

            using TGenProjector = decltype(genProjectorFunc);
            using TItemProjector = decltype(itemProjectorFunc);

            ComPtr<Details::BoundIterable<Details::EmptyBinding, TGenProjector, TItemProjector>> spIterable;

            // NOTE:
            //
            // The construction of the binding will apply it to the object 'container'.  After
            // the below line, the iterable concept on 'container' is spIterable.
            //
            spIterable = Make<Details::BoundIterable<Details::EmptyBinding, TGenProjector, TItemProjector>>(
                std::move(linkRef), genProjectorFunc, itemProjectorFunc, container
                );

            return container;
        }
    };

#ifdef DBGMODELCLIENTEX_NO_GENERATOR_BOXING

    template<typename TGen>
    struct IsGenerator : public std::false_type { };

    template<typename TGen>
    struct IsGenerator<std::experimental::generator<TGen>> : public std::true_type { };

    template<typename TGen> constexpr bool IsGenerator_v = IsGenerator<TGen>::value;

    template<typename TGen>
    struct BoxObject<std::experimental::generator<TGen>>
    {
        static Object Box(_In_ const std::experimental::generator<TGen>& src)
        {
            static_assert(!IsGenerator_v<std::experimental::generator<TGen>>, "Boxing of a std::experimental::generator<T> results in an object which can only ever be iterated once!");
            return Object();
        }
    };

#endif // DBGMODELCLIENTEX_NO_GENERATOR_BOXING

} // Boxing

namespace Details
{
    //
    // char[] and wchar_t[] will box as strings rather than arrays of characters!
    //
    template<size_t N> struct BoxObjectArray<char, N> : public Boxing::BoxObject<const char *> { };
    template<size_t N> struct BoxObjectArray<const char, N> : public Boxing::BoxObject<const char *> { };
    template<size_t N> struct BoxObjectArray<wchar_t, N> : public Boxing::BoxObject<const wchar_t *> { };
    template<size_t N> struct BoxObjectArray<const wchar_t, N> : public Boxing::BoxObject<const wchar_t *> { };

    // BoxSelector:
    //
    // Class which redirects array types to BoxObjectArray if T is an array and to BoxObject<std::decay_t<T>> for non
    // array types.
    //
    template<typename T> struct BoxSelector :
        public std::conditional_t<std::is_array_v<T>,
                                  typename Details::BoxObjectArray<Details::ArrayTraits_t<T>, Details::ArrayTraits<T>::Size>,
                                  Boxing::BoxObject<std::decay_t<T>>>
    {
    };
} // Boxing

//*************************************************
// Direct Boxing and Unboxing Method Calls:
//

// BoxObject():
//
// Takes any object and packs it into a data model object, returning an Object instance.
//
// New types can be added to the boxer by adding an explicit template specialization.
//
template<typename T>
Object BoxObject(T&& obj)
{
    //
    // template<typename T> ... T&& can bind T to TX& or TX.  We want the base type.
    // We do *NOT* want to std::decay_t<T> to get the base because we want to preserve any
    // array types.  Instead, we effectively want std::remove_cvref_t.  Unfortunately, that
    // is C++20 and this is a C++17 lib.  Go the verbose route.
    //
    using TBase = std::remove_cv_t<std::remove_reference_t<T>>;

    //
    // We do not want to decay arrays in order to box them.  Delegate to a box selector which will specially
    // handle array types.
    //
    using TBox = Details::BoxSelector<TBase>;
    using TFwd = decltype(std::forward<T>(obj));
    static_assert(Details::has_box_method_v<TBox, TFwd>, "No BoxObject<T>::Box exists for the given type.  Unable to box.");

    return TBox::Box(std::forward<T>(obj));
}

// UnboxObject():
//
// Takes a data model Object instance and unboxes it into a value of the type T.
//
// New types can be added to the unboxer by adding an explicit template specialization.
//
template<typename T>
decltype(auto) UnboxObject(_In_ const Object& src)
{
    using TBox = Boxing::BoxObject<T>;
    static_assert(Details::has_unbox_method_v<TBox>, "No BoxObject<T>::Unbox exists for the given type.  Unable to unbox.");

    return TBox::Unbox(src);
};

//**************************************************************************
// Forward Implementations:
//

inline Type Symbol::Type() const
{
    ComPtr<IDebugHostType> spType;
    CheckHr(m_spSymbol->GetType(&spType));
    return ClientEx::Type(std::move(spType));
}

inline Module Symbol::ContainingModule() const
{
    ComPtr<IDebugHostModule> spModule;
    CheckHr(m_spSymbol->GetContainingModule(&spModule));
    return Module(std::move(spModule));
}

//**************************************************************************
// Template Function Implementations:
//

template<typename TStr>
Type Module::FindType(_In_ TStr&& typeName) const
{
    ComPtr<IDebugHostType> spType;
    CheckHr(AsModule()->FindTypeByName(ClientEx::Details::ExtractString(typeName), &spType));
    return ClientEx::Type(std::move(spType));
}

inline Object Constant::Value() const
{
    VARIANT vtValue;
    CheckHr(AsConstant()->GetValue(&vtValue));
    ComPtr<IModelObject> spObj;
    HRESULT hr = GetManager()->CreateIntrinsicObject(ObjectIntrinsic, &vtValue, &spObj);
    VariantClear(&vtValue);
    CheckHr(hr);
    return Object(std::move(spObj));
}

inline Object Field::GetValue() const
{
    VARIANT vtValue;
    CheckHr(AsField()->GetValue(&vtValue));
    ComPtr<IModelObject> spObj;
    HRESULT hr = GetManager()->CreateIntrinsicObject(ObjectIntrinsic, &vtValue, &spObj);
    VariantClear(&vtValue);
    CheckHr(hr);
    return Object(std::move(spObj));
}

inline Object Metadata::KeyValue(_In_z_ const wchar_t *keyName) const
{
    ComPtr<IModelObject> spValue;
    CheckHr(m_spKeyStore->GetKeyValue(keyName, &spValue, nullptr));
    Object value = std::move(spValue);
    return value;
}

template<typename TArg, typename TEnable>
Object::Object(TArg&& value)
{
    Object assignment = BoxObject(std::forward<TArg>(value));
    m_spObject.Attach(assignment.Steal());
}

template<typename TArg, typename TEnable>
Object& Object::operator=(TArg&& assignmentValue)
{
    Object assignment = BoxObject(std::forward<TArg>(assignmentValue));
    m_spObject.Attach(assignment.Steal());
    return *this;
}

template<typename TType>
TType Object::As() const
{
    return UnboxObject<TType>(m_spObject.Get());
}

template<typename... TArgs>
Object Object::Call(_In_ const Object& instance, TArgs&&... callArguments) const
{
    Details::ParameterPack pack = Details::PackValues(std::forward<TArgs>(callArguments)...);

    ComPtr<IModelObject> spObject;
    HRESULT hr = As<IModelMethod *>()->Call(instance, sizeof...(callArguments), reinterpret_cast<IModelObject **>(pack.get()), &spObject, nullptr);
    CheckHr(hr, spObject);

    Object result(std::move(spObject));
    return result;
}

template<typename... TArgs>
Details::IndexableReference<Object, Details::ParameterPack> Object::Index(TArgs&&... indexers) const
{
    Details::ParameterPack pack = Details::PackValues(std::forward<TArgs>(indexers)...);

    ComPtr<IIndexableConcept> spIndexable;
    HRESULT hr = m_spObject->GetConcept(__uuidof(IIndexableConcept), &spIndexable, nullptr);
    if (FAILED(hr))
    {
        ClientEx::Type objectType = Type();

        //
        // If the type is a pointer and the pack size is one and it's a standard pointer (not a C++ reference or other
        // pseudo-pointer), we can still deal with this as "indexable" through plain old pointer math.
        //
        // Create an adapter object that makes it look like any other indexable object to the underlying IndexableReference<>
        //
#pragma warning(push)
#pragma warning(disable: 4127)
        if (sizeof...(indexers) == 1 && objectType.GetKind() == TypePointer && objectType.GetPointerKind() == PointerStandard)
        {
            spIndexable = Make<Details::PointerIndexerAdapter>();
            hr = S_OK;
        }
#pragma warning(pop)
    }
    CheckHr(hr);

    return Details::IndexableReference<Object, Details::ParameterPack>(sizeof...(indexers), std::move(pack), std::move(spIndexable), GetObject());
}

template<typename TArg>
int Object::CompareTo(TArg&& other) const
{
    Object otherObj = BoxObject(other);
    ComPtr<IModelObject> spResult;
    CheckHr(m_spObject->Compare(otherObj, &spResult));
    Object resultObj = std::move(spResult);
    return (int)resultObj;
}

template<typename TArg>
bool Object::IsEqualTo(TArg&& other) const
{
    Object otherObj = BoxObject(other);
    if (GetObject() == otherObj.GetObject()) { return true; }
    if (GetObject() == nullptr || otherObj.GetObject() == nullptr) { return false; }
    bool isEqual;
    CheckHr(m_spObject->IsEqualTo(otherObj, &isEqual));
    return isEqual;
}

template<typename... TArgs, typename TEnable>
Metadata::Metadata(_In_ TArgs&&... initializers)
{
    SetKeys(std::forward<TArgs>(initializers)...);
}

template<typename... TArgs, typename TEnable>
void Metadata::SetKeys(_In_ TArgs&&... initializers)
{
    EnsureCreated();
    Details::KeyFiller<IKeyStore, TArgs...>::Fill(m_spKeyStore.Get(), std::forward<TArgs>(initializers)...);
}

inline Deconstruction Object::Deconstruct()
{
    ComPtr<IDeconstructableConcept> spDeconstructable;
    CheckHr(m_spObject->GetConcept(__uuidof(IDeconstructableConcept), &spDeconstructable, nullptr));

    ULONG64 argCount;
    CheckHr(spDeconstructable->GetConstructorArgumentCount(m_spObject.Get(), &argCount));

    BSTR ctorName;
    CheckHr(spDeconstructable->GetConstructableModelName(m_spObject.Get(), &ctorName));
    bstr_ptr spCtorName(ctorName);

    std::unique_ptr<Object[]> spArgs(new Object[static_cast<size_t>(argCount)]);
    CheckHr(spDeconstructable->GetConstructorArguments(m_spObject.Get(), argCount, reinterpret_cast<IModelObject **>(spArgs.get())));

    return Deconstruction(ctorName, argCount, reinterpret_cast<IModelObject **>(spArgs.get()));
}

inline Object Object::ConstructInstance(Deconstruction& deconstruction)
{
    ComPtr<IConstructableConcept> spConstructable;
    CheckHr(m_spObject->GetConcept(__uuidof(IConstructableConcept), &spConstructable, nullptr));

    const size_t size = static_cast<size_t>(std::distance(deconstruction.begin(), deconstruction.end()));

    Details::ParameterPack pack(new Object[size]);
    size_t i = 0;
    for (auto&& param : deconstruction)
    {
        pack[i++] = param;
    }

    ComPtr<IModelObject> spInstance;
    CheckHr(spConstructable->CreateInstance(size, reinterpret_cast<IModelObject **>(pack.get()), &spInstance));
    return Object(std::move(spInstance));
}

namespace Details
{
    template<typename TTuple, size_t i, size_t remaining>
    void RegularUnpacker<TTuple, i, remaining>::UnpackInto(_In_ size_t packSize,
                                                           _In_reads_(packSize) IModelObject **ppArgumentPack,
                                                           TTuple& tuple)
    {
        using ArgType = std::tuple_element_t<i, TTuple>;

        // As we have already checked the pack size matches the minimum static argument set before
        // reaching this point, a 0 packSize is a non-supplied argument in the dynamic pack
        // matching against a std::optional<TOpt> in the argument pack.
        //
        // The tuple will have default constructed the std::optional<TOpt>.  Simply not touching
        // that value will leave it as no value (std::nullopt).  This is exactly the behavior
        // that we want.
        //
        if (i < packSize)
        {
            Object obj = ppArgumentPack[i];
            std::get<i>(tuple) = UnboxObject<ArgType>(obj);
        }

        Unpacker<TTuple, i + 1, remaining - 1>::UnpackInto(packSize, ppArgumentPack, tuple);
    }
}

} // ClientEx

//**************************************************************************
//**************************************************************************
//
// PROVIDER SUPPORT:
//
// Notes on terminology:
//
// The abstractions within the ProviderEx namespace fall into supporting two different categories of data
// models:
//
// - Ones which are extension models (they extend something else)
// - Ones which represent a native type 'TInstance' projected into the data model
//
// The methods on the data model classes are named in one of two manners:
//
// - Add<*>:
//       Adding refers to placing a method on the data model class which is passed the instance object and potentialy
//       the 'TInstance'.  The data model class returns the result by accessing those arguments as needed.
//
// - Bind<*>:
//       Binding refers to directly binding a data model property, method, or concept to an attribute of the 'TInstance'
//       which a data model represents.  Bindings can take one of several forms:
//
//       - Item:     Maps a field, method, or concept on TInstance directly to the data model.  Properties are mapped
//                   by "pointer-to-data-member".  Methods are mapped by "pointer-to-member-function".  Concepts like
//                   iterable are mapped directly to C++ iterator patterns.
//
//       - Accessor: Maps a field, method, or concept on TInstance to a method which returns the expected result.  Properties
//                   are mapped by a getter method accessed via "pointer-to-member-function" on TInstance.  Concepts like
//                   iterable are mapped to C++ iterator patterns on objects returned by methods accessed via
//                   "pointer-to-member-function"
//
// It is important to note that many of the objects created to represent a binding contain a back pointer to the implementation
// class (TClass * in various objects).  The instance of the implementation class may die before the binding does.  Every object
// which has such a back pointer has a "weak link" back to the original implementation object via a DataModelReference.  When
// the original class object dies, it indicates this in the DataModelReference.  All binding implementations must call
// ThrowIfDetached on the DataModelReference object before using the implementation class.
//

namespace ProviderEx
{

using namespace Microsoft::WRL;

namespace Details
{
    template<typename TClass, typename TRet, typename... TArgs>
    struct MethodInvocationHelper
    {
        static TRet Call(_In_ TClass *pDerived,
                         _In_ TRet (TClass::*classMethod)(TArgs...),
                         _In_ TArgs... methodArgs)
        {
            return (pDerived->*classMethod)(std::forward<TArgs>(methodArgs)...);
        }
    };

    template<typename TClass, typename... TArgs>
    struct MethodInvocationHelper<TClass, void, TArgs...>
    {
        static ClientEx::Object Call(_In_ TClass *pDerived,
                                     _In_ void (TClass::*classMethod)(TArgs...),
                                     _In_ TArgs... methodArgs)
        {
            (pDerived->*classMethod)(std::forward<TArgs>(methodArgs)...);
            ComPtr<IModelObject> spNoValue;
            ClientEx::CheckHr(ClientEx::GetManager()->CreateNoValue(&spNoValue));
            return ClientEx::Object(std::move(spNoValue));
        }
    };

    template<typename T> struct is_object : public std::is_same<std::decay_t<T>, ClientEx::Object> { };
    template<typename T> constexpr bool is_object_v = is_object<T>::value;

    template<typename T> struct is_metadata : public std::is_same<std::decay_t<T>, ClientEx::Metadata> { };
    template<typename T> constexpr bool is_metadata_v = is_metadata<T>::value;
} // Details

//*************************************************
// Registration Record Types
//

class TypeSignatureRegistration : public ClientEx::TypeSignature
{
public:

    template<typename... TArgs> TypeSignatureRegistration(TArgs&&... args) : TypeSignature(std::forward<TArgs>(args)...) { }
    template<typename... TArgs> TypeSignatureRegistration& operator=(TArgs&&... args)
    {
        TypeSignature::operator=(std::forward<TArgs>(args)...);
        return *this;
    }

    void Apply(_In_ const ClientEx::Object& model)
    {
        if (m_spTypeSignature == nullptr)
        {
            throw ClientEx::unexpected_error();
        }

        ClientEx::CheckHr(ClientEx::GetManager()->RegisterModelForTypeSignature(m_spTypeSignature.Get(), model));
    }

    void Unapply(_In_ const ClientEx::Object& model)
    {
        if (m_spTypeSignature == nullptr)
        {
            ClientEx::AssertCondition(false);
            return;
        }

        ClientEx::AssertHr(ClientEx::GetManager()->UnregisterModelForTypeSignature(model, m_spTypeSignature.Get()));
    }

};

class TypeSignatureExtension : public ClientEx::TypeSignature
{
public:

    template<typename... TArgs> TypeSignatureExtension(TArgs&&... args) : TypeSignature(std::forward<TArgs>(args)...) { }
    template<typename... TArgs> TypeSignatureExtension& operator=(TArgs&&... args)
    {
        TypeSignature::operator=(std::forward<TArgs>(args)...);
        return *this;
    }

    void Apply(_In_ const ClientEx::Object& model)
    {
        if (m_spTypeSignature == nullptr)
        {
            throw ClientEx::unexpected_error();
        }

        ClientEx::CheckHr(ClientEx::GetManager()->RegisterExtensionForTypeSignature(m_spTypeSignature.Get(), model));
    }

    void Unapply(_In_ const ClientEx::Object& model)
    {
        if (m_spTypeSignature == nullptr)
        {
            ClientEx::AssertCondition(false);
            return;
        }

        ClientEx::AssertHr(ClientEx::GetManager()->UnregisterExtensionForTypeSignature(model, m_spTypeSignature.Get()));
    }
};

class NamedModelParent
{
public:

    NamedModelParent() { }
    NamedModelParent(_In_z_ const wchar_t* parentModelName) : m_parentModelName(parentModelName) { }
    NamedModelParent(_In_ const std::wstring& parentModelName) : m_parentModelName(parentModelName) { }
    NamedModelParent(_In_ std::wstring&& parentModelName) : m_parentModelName(std::move(parentModelName)) { }
    NamedModelParent(_In_ const NamedModelParent& src) : m_parentModelName(src.m_parentModelName) { }
    NamedModelParent(_In_ NamedModelParent&& src) : m_parentModelName(std::move(src.m_parentModelName)) { }

    NamedModelParent& operator=(_In_ const NamedModelParent& src) { m_parentModelName = src.m_parentModelName; return *this; }
    NamedModelParent& operator=(_In_ NamedModelParent&& src) { m_parentModelName = std::move(src.m_parentModelName); return *this; }

    const std::wstring& GetParentModelName() const { return m_parentModelName; }

    void Apply(_In_ const ClientEx::Object& model)
    {
        if (m_parentModelName.empty())
        {
            throw ClientEx::unexpected_error();
        }

        ComPtr<IModelObject> spParent;
        ClientEx::CheckHr(ClientEx::GetManager()->AcquireNamedModel(m_parentModelName.c_str(), &spParent));
        ClientEx::CheckHr(spParent->AddParentModel(model, nullptr, false));
    }

    void Unapply(_In_ const ClientEx::Object& model)
    {
        if (m_parentModelName.empty())
        {
            ClientEx::AssertCondition(false);
            return;
        }

        ComPtr<IModelObject> spParent;
        ClientEx::AssertHr(ClientEx::GetManager()->AcquireNamedModel(m_parentModelName.c_str(), &spParent));
        ClientEx::AssertHr(spParent->RemoveParentModel(model));
    }

private:

    std::wstring m_parentModelName;

};

class NamedModelRegistration
{
public:

    NamedModelRegistration() { }
    NamedModelRegistration(_In_z_ const wchar_t* modelName) : m_modelName(modelName) { }
    NamedModelRegistration(_In_ const std::wstring& modelName) : m_modelName(modelName) { }
    NamedModelRegistration(_In_ std::wstring&& modelName) : m_modelName(std::move(modelName)) { }
    NamedModelRegistration(_In_ const NamedModelRegistration& src) : m_modelName(src.m_modelName) { }
    NamedModelRegistration(_In_ NamedModelRegistration&& src) : m_modelName(std::move(src.m_modelName)) { }

    NamedModelRegistration& operator=(_In_ const NamedModelRegistration& src) { m_modelName = src.m_modelName; return *this; }
    NamedModelRegistration& operator=(_In_ NamedModelRegistration&& src) { m_modelName = std::move(src.m_modelName); return *this; }

    const std::wstring& GetModelName() const { return m_modelName; }

//
// @TODO: The compiler insists that model is an unreferenced parameter in both methods below.
//        It is not.  Pragma out the warning.
//
#pragma warning(push)
#pragma warning(disable: 4100)

    void Apply(_In_ const ClientEx::Object& model)
    {
        if (m_modelName.empty())
        {
            throw ClientEx::unexpected_error();
        }

        ClientEx::CheckHr(ClientEx::GetManager()->RegisterNamedModel(m_modelName.c_str(), model));
    }

    void Unapply(_In_ const ClientEx::Object& model)
    {
        if (m_modelName.empty())
        {
            ClientEx::AssertCondition(false);
            return;
        }

        ClientEx::AssertHr(ClientEx::GetManager()->UnregisterNamedModel(m_modelName.c_str()));
    }

#pragma warning(pop)

private:

    std::wstring m_modelName;
};

class NamespacePropertyParent
{
public:

    NamespacePropertyParent() { }

    NamespacePropertyParent(_In_ const NamespacePropertyParent& src) :
        m_modelName(src.m_modelName),
        m_namespaceName(src.m_namespaceName),
        m_propertyName(src.m_propertyName),
        m_metadata(src.m_metadata)
    {
    }

    NamespacePropertyParent(_In_ NamespacePropertyParent&& src) :
        m_modelName(std::move(src.m_modelName)),
        m_namespaceName(std::move(src.m_namespaceName)),
        m_propertyName(std::move(src.m_propertyName)),
        m_metadata(std::move(src.m_metadata))
    {
    }

    template<typename TStr1, typename TStr2, typename TStr3>
    NamespacePropertyParent(_In_ TStr1&& modelName, _In_ TStr2&& namespaceName, _In_ TStr3&& propertyName) :
        m_metadata(ClientEx::Metadata())
    {
        m_modelName = ClientEx::Details::ExtractString(modelName);
        m_namespaceName = ClientEx::Details::ExtractString(namespaceName);
        m_propertyName = ClientEx::Details::ExtractString(propertyName);
    }

    template<typename TStr1, typename TStr2, typename TStr3>
    NamespacePropertyParent(_In_ TStr1&& modelName, _In_ TStr2&& namespaceName, _In_ TStr3&& propertyName, _In_ ClientEx::Metadata metadata) :
        m_metadata(std::move(metadata))
    {
        m_modelName = ClientEx::Details::ExtractString(modelName);
        m_namespaceName = ClientEx::Details::ExtractString(namespaceName);
        m_propertyName = ClientEx::Details::ExtractString(propertyName);
    }

    NamespacePropertyParent& operator=(_In_ const NamespacePropertyParent& src)
    {
        m_modelName = src.m_modelName;
        m_namespaceName = src.m_namespaceName;
        m_propertyName = src.m_propertyName;
        m_metadata = src.m_metadata;
        return *this;
    }

    NamespacePropertyParent& operator=(_In_ NamespacePropertyParent&& src)
    {
        m_modelName = std::move(src.m_modelName);
        m_namespaceName = std::move(src.m_namespaceName);
        m_propertyName = std::move(src.m_propertyName);
        m_metadata = std::move(src.m_metadata);
        return *this;
    }

    const std::wstring& GetModelName() const { return m_modelName; }
    const std::wstring& GetNamespaceName() const { return m_namespaceName; }
    const std::wstring& GetPropertyName() const { return m_propertyName; }
    const ClientEx::Metadata& GetMetadata() const { return m_metadata; }

    void Apply(_In_ const ClientEx::Object& model)
    {
        if (m_modelName.empty() || m_namespaceName.empty() || m_propertyName.empty())
        {
            throw ClientEx::unexpected_error();
        }

        ComPtr<IDataModelManager2> spManager2;
        ClientEx::CheckHr(ClientEx::GetManager()->QueryInterface(IID_PPV_ARGS(&spManager2)));

        ComPtr<IModelObject> spNamespace;
        ClientEx::CheckHr(spManager2->AcquireSubNamespace(m_modelName.c_str(),
                                                          m_namespaceName.c_str(),
                                                          m_propertyName.c_str(),
                                                          m_metadata,
                                                          &spNamespace));
        ClientEx::CheckHr(spNamespace->AddParentModel(model, nullptr, false));
    }

    void Unapply(_In_ const ClientEx::Object& model)
    {
        if (m_modelName.empty() || m_namespaceName.empty() || m_propertyName.empty())
        {
            ClientEx::AssertCondition(false);
            return;
        }

        ComPtr<IModelObject> spNamespace;
        ClientEx::AssertHr(ClientEx::GetManager()->AcquireNamedModel(m_namespaceName.c_str(), &spNamespace));
        ClientEx::AssertHr(spNamespace->RemoveParentModel(model));
    }

private:

    std::wstring m_modelName;
    std::wstring m_namespaceName;
    std::wstring m_propertyName;
    ClientEx::Metadata m_metadata;
};

class FilteredNamespacePropertyParent
{
public:

    using ApplyT = void (*)(_In_ const ClientEx::Object& model);

    FilteredNamespacePropertyParent() { }

    FilteredNamespacePropertyParent(_In_ const FilteredNamespacePropertyParent& src) :
        m_modelName(src.m_modelName),
        m_namespaceName(src.m_namespaceName),
        m_propertyName(src.m_propertyName),
        m_createFilter(src.m_createFilter),
        m_spToken(src.m_spToken)
    {
    }

    FilteredNamespacePropertyParent(_In_ FilteredNamespacePropertyParent&& src) :
        m_modelName(std::move(src.m_modelName)),
        m_namespaceName(std::move(src.m_namespaceName)),
        m_propertyName(std::move(src.m_propertyName)),
        m_createFilter(std::move(src.m_createFilter)),
        m_spToken(std::move(src.m_spToken))
    {
    }

    template<typename TStr1, typename TStr2, typename TStr3, typename TObj, typename TClass>
    FilteredNamespacePropertyParent(_In_ TStr1&& modelName,
                                    _In_ TStr2&& namespaceName,
                                    _In_ TStr3&& propertyName,
                                    _In_ TClass *pInstance,
                                    _In_ bool (TClass::*validateClassMethod)(_In_ TObj))
    {
        m_modelName = ClientEx::Details::ExtractString(modelName);
        m_namespaceName = ClientEx::Details::ExtractString(namespaceName);
        m_propertyName = ClientEx::Details::ExtractString(propertyName);

        static_assert(Details::is_object_v<TObj>, "Bound property getter must take (const) Object (&) as first argument");

        // We need createFilter to postpone creation of the filter as pInstance is not fully constructed yet
        auto createFilter = [pInstance, validateClassMethod]()
        {
            ClientEx::Details::DataModelReference callLinkRef = pInstance->GetLinkReference();
            auto callFilter = [linkRef = std::move(callLinkRef), pInstance, validateClassMethod](TObj contextObj)
            {
                ClientEx::Details::ThrowIfDetached(linkRef);
                return Details::MethodInvocationHelper<TClass, bool, TObj>::Call(
                    pInstance,
                    validateClassMethod,
                    contextObj
                );
            };

            ClientEx::Object filterObj = callFilter;
            return filterObj;
        };

        m_createFilter = createFilter;
    }

    FilteredNamespacePropertyParent& operator=(_In_ const FilteredNamespacePropertyParent& src)
    {
        m_modelName = src.m_modelName;
        m_namespaceName = src.m_namespaceName;
        m_propertyName = src.m_propertyName;
        m_createFilter = src.m_createFilter;
        m_spToken = src.m_spToken;
        return *this;
    }

    FilteredNamespacePropertyParent& operator=(_In_ FilteredNamespacePropertyParent&& src)
    {
        m_modelName = std::move(src.m_modelName);
        m_namespaceName = std::move(src.m_namespaceName);
        m_propertyName = std::move(src.m_propertyName);
        m_createFilter = std::move(src.m_createFilter);
        m_spToken = std::move(src.m_spToken);
        return *this;
    }

    const std::wstring& GetModelName() const { return m_modelName; }
    const std::wstring& GetNamespaceName() const { return m_namespaceName; }
    const std::wstring& GetPropertyName() const { return m_propertyName; }
    IFilteredNamespacePropertyToken* GetToken() const { return m_spToken.Get(); }

    void Apply(_In_ const ClientEx::Object& model)
    {
        if (m_modelName.empty() || m_namespaceName.empty() || m_propertyName.empty() ||
            !m_createFilter || (m_spToken.Get() != nullptr))
        {
            throw ClientEx::unexpected_error();
        }

        ClientEx::Object filterObj = m_createFilter();
        m_createFilter = nullptr;

        ComPtr<IModelMethod> filter = filterObj.As<IModelMethod *>();

        if (filter.Get() == nullptr)
        {
            throw ClientEx::unexpected_error();
        }

        ComPtr<IDataModelManager3> spManager3;
        ClientEx::CheckHr(ClientEx::GetManager()->QueryInterface(IID_PPV_ARGS(&spManager3)));

        ComPtr<IModelObject> spNamespace;
        ClientEx::CheckHr(spManager3->AcquireFilteredSubNamespace(m_modelName.c_str(),
                                                                  m_namespaceName.c_str(),
                                                                  m_propertyName.c_str(),
                                                                  nullptr,
                                                                  filter.Get(),
                                                                  &spNamespace,
                                                                  &m_spToken));
        ClientEx::CheckHr(spNamespace->AddParentModel(model, nullptr, false));
    }

    void Unapply(_In_ const ClientEx::Object& model)
    {
        if (m_modelName.empty() || m_namespaceName.empty() || m_propertyName.empty())
        {
            ClientEx::AssertCondition(false);
            return;
        }

        ComPtr<IModelObject> spNamespace;
        ClientEx::AssertHr(ClientEx::GetManager()->AcquireNamedModel(m_namespaceName.c_str(), &spNamespace));
        ClientEx::AssertHr(spNamespace->RemoveParentModel(model));
        if (m_spToken.Get() != nullptr)
        {
            ClientEx::AssertHr(m_spToken->RemoveFilter());
        }
    }

private:

    std::wstring m_modelName;
    std::wstring m_namespaceName;
    std::wstring m_propertyName;
    std::function< ClientEx::Object(void)> m_createFilter;
    ComPtr<IFilteredNamespacePropertyToken> m_spToken;
};

namespace Details
{
    //*************************************************
    // Instance Data Storage Helpers:
    //

    // 0x21d50b4e, 0x5ed1, 0x4357, 0x9d, 0x3b, 0x25, 0x3b, 0xd8, 0xc4, 0x5e, 0xe7);
    struct DECLSPEC_UUID("21D50B4E-5ED1-4357-9D3B-253BD8C45EE7") IPrivateTypeQuery : public IUnknown
    {
        IFACEMETHOD_(ULONG64, GetTypeHash)() PURE;
    };

    template<typename TInstance>
    struct StorageInterface :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IPrivateTypeQuery
            >
    {
        using InstanceData = TInstance;

        virtual TInstance& GetInstance() = 0;
    };

    template<typename TInstance>
    struct BasicStorage : StorageInterface<TInstance>
    {
    public:
        using InstanceData = TInstance;
        using StorageData = TInstance;

        BasicStorage(_In_ const TInstance& instance, _In_ ULONG64 typeHash) :
            m_instance(instance),
            m_typeHash(typeHash)
        {
        }

        BasicStorage(_In_ TInstance&& instance, _In_ ULONG64 typeHash) :
            m_instance(std::move(instance)),
            m_typeHash(typeHash)
        {
        }

        TInstance& GetInstance() override
        {
            return m_instance;
        }

        //*************************************************
        // IPrivateTypeQuery:
        //

        IFACEMETHOD_(ULONG64, GetTypeHash)()
        {
            return m_typeHash;
        }

    private:

        TInstance m_instance;
        ULONG64 m_typeHash;
    };

    template<typename TInstance>
    struct SharedStorage : StorageInterface<TInstance>
    {
    public:
        using InstanceData = TInstance;
        using StorageData = std::shared_ptr<TInstance>;

        SharedStorage(_In_ std::shared_ptr<TInstance> sharedInstance, _In_ ULONG64 typeHash) :
            m_spSharedInstance(std::move(sharedInstance)),
            m_typeHash(typeHash)
        {
        }

        TInstance& GetInstance()
        {
            return *(m_spSharedInstance.get());
        }

        //*************************************************
        // IPrivateTypeQuery:
        //

        IFACEMETHOD_(ULONG64, GetTypeHash)()
        {
            return m_typeHash;
        }

    private:

        std::shared_ptr<TInstance> m_spSharedInstance;
        ULONG64 m_typeHash;
    };

    template<typename TInstance>
    struct UniqueStorage : StorageInterface<TInstance>
    {
    public:
        using InstanceData = TInstance;
        using StorageData = std::unique_ptr<TInstance>;

        UniqueStorage(_In_ std::unique_ptr<TInstance> uniqueInstance, _In_ ULONG64 typeHash) :
            m_spUniqueInstance(std::move(uniqueInstance)),
            m_typeHash(typeHash)
        {
        }

        TInstance& GetInstance()
        {
            return *(m_spUniqueInstance.get());
        }

        //*************************************************
        // IPrivateTypeQuery:
        //

        IFACEMETHOD_(ULONG64, GetTypeHash)()
        {
            return m_typeHash;
        }

    private:

        std::unique_ptr<TInstance> m_spUniqueInstance;
        ULONG64 m_typeHash;
    };

    template<typename TInstance>
    struct StorageTraits
    {
        using StorageType = typename BasicStorage<TInstance>;
        using InstanceData = TInstance;
    };

    template<typename TInstance>
    struct StorageTraits<std::shared_ptr<TInstance>>
    {
        using StorageType = typename SharedStorage<TInstance>;
        using InstanceData = TInstance;
    };

    template<typename TInstance>
    struct StorageTraits<std::unique_ptr<TInstance>>
    {
        using StorageType = typename UniqueStorage<TInstance>;
        using InstanceData = TInstance;
    };

    //*************************************************
    // Data Models:
    //

    // DataModelConcept:
    //
    // An implementation of the data model concept.
    //
    template<typename TClass>
    class DataModelConcept :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IDataModelConcept
            >
    {
    public:

        typedef const std::wstring& (TClass::*NameMethod)() const;

        DataModelConcept(_In_ TClass *pClass, _In_ NameMethod nameMethod) : m_pClass(pClass), m_nameMethod(nameMethod) { }

        //*************************************************
        // IDataModelConcept:
        //

        IFACEMETHOD(InitializeObject)(_In_ IModelObject * /*pModelObject*/,
                                      _In_opt_ IDebugHostTypeSignature * /*pMatchingTypeSignature*/,
                                      _In_opt_ IDebugHostSymbolEnumerator * /*pWildcardMatches*/)
        {
            return S_OK;
        }

        IFACEMETHOD(GetName)(_Out_ BSTR *pModelName)
        {
            *pModelName = nullptr;

            const std::wstring& modelName = (m_pClass->*m_nameMethod)();
            if (modelName.empty())
            {
                return E_NOTIMPL;
            }

            *pModelName = SysAllocString(modelName.c_str());
            if (*pModelName == nullptr)
            {
                return E_OUTOFMEMORY;
            }

            return S_OK;
        }

    private:

        TClass *m_pClass;
        NameMethod m_nameMethod;


    };

    template<typename TClass, typename TStringProjector>
    class BoundStringDisplayable :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IStringDisplayableConcept
            >
    {
    public:

        using StringProjectorFunction = typename ClientEx::Details::FunctorTraits<TStringProjector>::FunctionType;

        BoundStringDisplayable(_In_ TClass *pClass,
                               _In_ const TStringProjector& stringProjectorFunction)
        {
            m_pClass = pClass;
            m_stringProjector = stringProjectorFunction;
            Apply();
        }

        //*************************************************
        // IStringDisplayableConcept:
        //

        IFACEMETHOD(ToDisplayString)(_In_ IModelObject *pContextObject,
                                     _In_opt_ IKeyStore *pMetadata,
                                     _Out_ BSTR *pDisplayString)
        {
            try
            {
                ClientEx::Object contextObj = pContextObject;
                ClientEx::Metadata metadata = pMetadata;
                auto result = m_stringProjector(contextObj, metadata);
                *pDisplayString = SysAllocString(ClientEx::Details::ExtractString(result));
                if (*pDisplayString == nullptr)
                {
                    throw std::bad_alloc();
                }
            }
            catch(...)
            {
                return ClientEx::Details::Exceptions::ReturnResult(std::current_exception());
            }
            return S_OK;
        }

    private:

        void Apply()
        {
            m_pClass->GetObject()->SetConcept(__uuidof(IStringDisplayableConcept), static_cast<IStringDisplayableConcept *>(this), nullptr);
        }

        TClass *m_pClass;
        StringProjectorFunction m_stringProjector;
    };


    template<typename TClass, typename TConstructableProjector, typename... TArgs>
    class BoundConstructable :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IConstructableConcept
            >
    {
    public:

        using ConstructableProjectorFunction = typename ClientEx::Details::FunctorTraits<TConstructableProjector>::FunctionType;

        BoundConstructable(_In_ TClass *pClass,
                           _In_ const TConstructableProjector& constructableProjectorFunction)
        {
            m_pClass = pClass;
            m_constructableProjector = constructableProjectorFunction;
            Apply();
        }

        //*************************************************
        // IConstructableConcept:
        //

        IFACEMETHOD(CreateInstance)(_In_ ULONG64 argCount,
                                    _In_reads_(argCount) IModelObject **ppArguments,
                                    _COM_Errorptr_ IModelObject **ppInstance)
        {
            *ppInstance = nullptr;

            try
            {
                ClientEx::Object result = ClientEx::Details::LiteralInvokeFunctionFromPack(m_constructableProjector,
                                                                                           static_cast<size_t>(argCount),
                                                                                           ppArguments);
                *ppInstance = result.Detach();
            }
            catch(...)
            {
                return ClientEx::Details::Exceptions::ReturnResult(std::current_exception());
            }
            return S_OK;
        }

    private:

        void Apply()
        {
            m_pClass->GetObject()->SetConcept(__uuidof(IConstructableConcept), static_cast<IConstructableConcept *>(this), nullptr);
        }

        TClass *m_pClass;
        ConstructableProjectorFunction m_constructableProjector;
    };

    template<typename TClass, typename TDeconstructableProjector>
    class BoundDeconstructable :
        public Microsoft::WRL::RuntimeClass<
            Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
            IDeconstructableConcept
            >
    {
    public:

        using DeconstructableProjectorFunction = typename ClientEx::Details::FunctorTraits<TDeconstructableProjector>::FunctionType;

        BoundDeconstructable(_In_ TClass *pClass,
                             _In_z_ const wchar_t *pConstructableModelName,
                             _In_ const TDeconstructableProjector& deconstructableProjectorFunction)
        {
            m_pClass = pClass;
            m_constructableModelName = pConstructableModelName;
            m_deconstructableProjector = deconstructableProjectorFunction;
            Apply();
        }

        //*************************************************
        // IDeconstructableConcept:
        //

        IFACEMETHOD(GetConstructableModelName)(_In_ IModelObject * /*pContextObject*/,
                                               _Out_ BSTR *pConstructableModelName)
        {
            *pConstructableModelName = SysAllocString(m_constructableModelName.c_str());
            if (*pConstructableModelName == nullptr)
            {
                return E_OUTOFMEMORY;
            }

            return S_OK;
        }

        IFACEMETHOD(GetConstructorArgumentCount)(_In_ IModelObject *pContextObject,
                                                 _Out_ ULONG64 *pArgCount)
        {
            try
            {
                ClientEx::Object contextObject = pContextObject;
                auto arbitraryArgs = m_deconstructableProjector(contextObject);
                *pArgCount = std::tuple_size_v<decltype(arbitraryArgs)>;
            }
            catch(...)
            {
                return ClientEx::Details::Exceptions::ReturnResult(std::current_exception());
            }
            return S_OK;
        }

        IFACEMETHOD(GetConstructorArguments)(_In_ IModelObject *pContextObject,
                                             _In_ ULONG64 argCount,
                                             _Out_writes_(argCount) IModelObject **ppConstructorArguments)
        {
            try
            {
                for (size_t x = 0; x < argCount; ++x)
                {
                    ppConstructorArguments[x] = nullptr;
                }

                ClientEx::Object contextObject = pContextObject;
                auto arbitraryArgs = m_deconstructableProjector(contextObject);
                size_t computedArgCount = std::tuple_size_v<decltype(arbitraryArgs)>;

                if (computedArgCount != argCount)
                {
                    throw std::invalid_argument("Inappropriate number of output arguments passed to object deconstructor");
                }

                ClientEx::Details::ParameterPack pack = ClientEx::Details::PackTuple(arbitraryArgs);

                for (size_t i = 0; i < argCount; ++i)
                {
                    ppConstructorArguments[i] = pack[i].Detach();
                }
            }
            catch(...)
            {
                return ClientEx::Details::Exceptions::ReturnResult(std::current_exception());
            }
            return S_OK;
        }

    private:

        void Apply()
        {
            m_pClass->GetObject()->SetConcept(__uuidof(IDeconstructableConcept), static_cast<IDeconstructableConcept *>(this), nullptr);
        }

        TClass *m_pClass;
        DeconstructableProjectorFunction m_deconstructableProjector;
        std::wstring m_constructableModelName;

    };

    constexpr ULONG64 GetSigHash(_In_z_ const char *pc)
    {
        ULONG64 hash = 2166136261u; // FNV offset basis
        while(*pc)
        {
            hash ^= *pc;
             hash = hash * 16777619u; // FNV prime
            ++pc;
        }
        return hash;
    };

    class ExtensionRegistrationListBase
    {
    public:

        virtual ~ExtensionRegistrationListBase() { }
    };

    template<typename TList, size_t i, size_t remaining>
    struct ExtensionUnapplication
    {
        static void Unapply(_In_ TList& registrationList)
        {
            try
            {
                std::get<i>(registrationList.GetRecords()).Unapply(registrationList.GetModel());
            }
            catch (...)
            {
                ClientEx::AssertCondition(false);
            }
            ExtensionUnapplication<TList, i + 1, remaining - 1>::Unapply(registrationList);
        }
    };

    template<typename TList, size_t i>
    struct ExtensionUnapplication<TList, i, 0>
    {
        static void Unapply(_In_ TList& /*registrationList*/)
        {
        }
    };

    template<typename... TArgs>
    class ExtensionRegistrationList : public ExtensionRegistrationListBase
    {
    public:

        using RecordList = std::tuple<TArgs...>;

        ExtensionRegistrationList(_In_ const ClientEx::Object& model) : m_model(model)
        {
        }

        ~ExtensionRegistrationList()
        {
            ExtensionUnapplication<decltype(*this), 0, std::tuple_size_v<RecordList>>::Unapply(*this);
        }

        const ClientEx::Object& GetModel() const { return m_model; }
        RecordList& GetRecords() { return m_records; }

    private:

        ClientEx::Object m_model;
        RecordList m_records;
    };

    template<typename TList, size_t i, typename... TArgs> struct ExtensionApplication;

    template<typename TList, size_t i, typename TArg, typename... TArgs>
    struct ExtensionApplication<TList, i, TArg, TArgs...>
    {
        static void Apply(_In_ TList& registrationList, _In_ TArg record, _In_ TArgs&&... records)
        {
            record.Apply(registrationList.GetModel());
            std::get<i>(registrationList.GetRecords()) = std::move(record);
            ExtensionApplication<TList, i + 1, TArgs...>::Apply(registrationList, std::forward<TArgs>(records)...);
        }
    };

    template<typename TList, size_t i>
    struct ExtensionApplication<TList, i>
    {
        static void Apply(_In_ TList& /*registrationList*/) { }
    };

    template<typename... TArgs>
    struct ExtensionNameAcquisition
    {
        static void FillName(_Inout_ std::wstring& /*modelName*/)
        {
        }
    };

    template<typename TArg, typename... TArgs>
    struct ExtensionNameAcquisition<TArg, TArgs...>
    {
        static void FillName(_Inout_ std::wstring& modelName, _In_ TArg record, _In_ const TArgs&... records)
        {
            return ExtensionNameAcquisition<TArgs...>::FillName(modelName, records...);
        }
    };

    template<typename... TArgs>
    struct ExtensionNameAcquisition<NamedModelRegistration, TArgs...>
    {
        static void FillName(_Inout_ std::wstring& modelName, _In_ const NamedModelRegistration& nameRegistration, _In_ const TArgs&... records)
        {
            if (modelName.empty())
            {
                modelName = nameRegistration.GetModelName();
            }
        }
    };

    // IsValidTypedInstanceRegistrationType:
    //
    // Support for detecting whether a given registration record for a TypedInstanceModel is valid or not
    //
    template<typename TReg> 
    struct IsValidTypedInstanceRegistrationType : std::false_type { };

    template<> 
    struct IsValidTypedInstanceRegistrationType<NamedModelRegistration> : std::true_type { };

    template<typename TReg> constexpr bool IsValidTypedInstanceRegistrationType_v = 
        IsValidTypedInstanceRegistrationType<TReg>::value;

    template<typename TReg>
    struct TypedInstanceRegistrationVerification
    {
        static void Verify()
        {
            static_assert(IsValidTypedInstanceRegistrationType_v<TReg>, 
                          "Illegal registration kind for a TypedInstanceModel<T>");
        }
    };

    struct EmptyVerification { static void Verify() { } };

    //
    // Legal Registration Records for TypedInstanceModel<T>:
    //
    template<typename... TArgs> struct VerifyTypedInstanceRegistrations : public EmptyVerification { };

    template<typename TArg, typename... TArgs>
    struct VerifyTypedInstanceRegistrations<TArg, TArgs...>
    {
        static void Verify()
        {
            TypedInstanceRegistrationVerification<TArg>::Verify();
            VerifyTypedInstanceRegistrations<TArgs...>::Verify();
        }
    };

}

//**************************************************************************
// Data Models:
//

// BaseDataModel():
//
// All data models are derived from BaseDataModel.  A client should not directly derive from this class.  Rather,
// a derivation should be made from one of the following:
//
// TypedInstanceModel<T>:
//
//     - You want to project a native type into the data model.  The TypedInstanceModel<T> becomes the "type factory" for
//       the type T.  In addition to defining this class, the following traits classes should be provided for composability
//       with Object.  These traits are within "Debugger::DataModel::ClientEx::Boxing"
//
//       template<>
//       struct BoxObject<T>
//       {
//           static Object Box(_In_ const T& val) {...}
//           static T Unbox(_In_ const Object& obj) {...}
//       };
//
// ExtensionModel:
//
//     - You want to create an extension to the data model.
//
class BaseDataModel
{
public:

    virtual ~BaseDataModel()
    {
        //
        // Because the lifetime of the objects are inverted (the type object which is C++ and non reference counted
        // is holding onto the data model, if the type object goes away, detach every linkage back to the C++ object)
        //
        // @TODO: If properties are copied!
        //
        if (m_object != nullptr)
        {
            m_object->ClearKeys();
            m_object->ClearConcepts();
        }

        if (m_dataRef != nullptr)
        {
            m_dataRef->TypeIsLive = false;
        }
    }

    BaseDataModel(_In_ const ClientEx::Metadata & metadata)
    {
        m_dataRef = std::make_shared<ClientEx::Details::DataModelReferenceInfo>();

        ComPtr<Details::DataModelConcept<BaseDataModel>> spConcept = Make<Details::DataModelConcept<BaseDataModel>>(this, &BaseDataModel::GetName);
        if (spConcept == nullptr)
        {
            throw std::bad_alloc();
        }

        ClientEx::Object object = ClientEx::Object::Create(ClientEx::HostContext());
        ClientEx::CheckHr(object->SetConcept(__uuidof(IDataModelConcept), static_cast<IDataModelConcept *>(spConcept.Get()), metadata));

        m_object = std::move(object);
    }

    const ClientEx::Object& GetObject() const
    {
        return m_object;
    }

    // GetModelName():
    //
    // Gets the name of the data model.  If the string is empty, there is no registration.  If it is not empty, the data model
    // will be registered under this name.
    //
    virtual const std::wstring& GetName() const
    {
        return m_modelName;
    }

    static ClientEx::Metadata CreateDocMetadata(_In_ ULONG id, _In_ bool inOwnPage)
    {
        ClientEx::Metadata metadata = ClientEx::Metadata(L"Doc", ClientEx::DeferredResourceString{ id });

        if (inOwnPage)
        {
            ClientEx::Object ownPageObj = inOwnPage;
            ClientEx::CheckHr(metadata->SetKey(L"DocInOwnPage", ownPageObj, nullptr));
        }

        return metadata;
    }

    const ClientEx::Details::DataModelReference& GetLinkReference() const
    {
        return m_dataRef;
    }

protected:

    std::wstring m_modelName;

private:

    //
    // We "partially" own the lifetime of the data model.  It is shared with any instances
    //
    ClientEx::Object m_object;

    //
    // The stub which is passed around amongst all shared ownership objects which can refer back to the
    // type object.  If the linkage is broken, TypeIsLive is false and anything still holding onto
    // this ref should throw (the weak link is broken)
    //
    ClientEx::Details::DataModelReference m_dataRef;
};

//**************************************************************************
// Extension Models
//

// ExtensionModel:
//
// Intended to be a base class for a C++ class which will serve as an extension to the data model.
//
class ExtensionModel : public BaseDataModel
{
public:

    // ExtensionModel():
    //
    // Construct an extension model and have it register against the data model in the manners specified by
    // the arguments.  Such must be registration records such as TypeSignatureRegistration, etc...
    //
    // If delayedInitialization is true then InitializeModel must be used in the derived constructor
    //
    ExtensionModel(_In_ ClientEx::Metadata && metadata) : BaseDataModel(metadata)
    {
    }

    ExtensionModel() : BaseDataModel(ClientEx::Metadata())
    {
    }

    // ExtensionModel():
    //
    // Construct an extension model and have it register against the data model in the manners specified by
    // the arguments.  Such must be registration records such as TypeSignatureRegistration, etc...
    //

    template<typename... TArgs>
    ExtensionModel(_In_ ClientEx::Metadata && metadata, _In_ TArgs&&... registrations) : BaseDataModel(metadata)
    {
        CompleteExtensionModelInitialization(std::forward<TArgs>(registrations)...);
    }

    template<typename... TArgs>
    ExtensionModel(_In_ TArgs&&... registrations) : BaseDataModel(ClientEx::Metadata())
    {
        CompleteExtensionModelInitialization(std::forward<TArgs>(registrations)...);
    }

    // GetModelName():
    //
    // Returns the name of this model.  The canonical name is the first name registration record passed to our
    // constructor.
    //
    virtual const std::wstring& GetModelName() const
    {
        return m_modelName;
    }

    // AddProperty():
    //
    // Adds a new property.
    //
    template<typename TGetFunc, typename TSetFunc>
    void AddProperty(_In_z_ const wchar_t *propertyName,
                     _In_ const TGetFunc& getFunction,    // TValue getFunction([const] Object [&]);
                     _In_ const TSetFunc& setFunction,    // void setFunction([const] Object [&], [const] TValue [&]);
                     _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(std::is_invocable_v<TGetFunc, ClientEx::Object>, "Bound property getter must take (const) Object (&) as first argument");
        if constexpr (std::is_invocable_v<TGetFunc, ClientEx::Object>) // Prevent noise from failure of the assertion above
        {
            using TValue = std::invoke_result_t<TGetFunc, ClientEx::Object>;
            static_assert(std::is_invocable_v<TSetFunc, ClientEx::Object, TValue>, "Bound property setter must take (const) Object (&) as first argument");

            ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunction, setFunction);
            ClientEx::CheckHr(GetObject()->SetKey(propertyName, propertyAccessor, metadata));
        }
    }

    template<typename TObjGet, typename TObjSet, typename TClass, typename TRet, typename TSetValue>
    void AddProperty(_In_z_ const wchar_t *propertyName,
                     _In_ TClass *pDerived,
                     _In_ TRet (TClass::*getClassMethod)(_In_ TObjGet),
                     _In_ void (TClass::*setClassMethod)(_In_ TObjSet, _In_ TSetValue),
                     _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(Details::is_object_v<TObjGet>, "Bound property getter must take (const) Object (&) as first argument");
        static_assert(Details::is_object_v<TObjSet>, "Bound property setter must take (const) Object (&) as first argument");

        ClientEx::Details::DataModelReference getLinkRef = GetLinkReference();
        auto getFunc = [linkRef = std::move(getLinkRef), pDerived, getClassMethod](_In_ TObjGet instanceObject)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*getClassMethod)(instanceObject);
        };

        ClientEx::Details::DataModelReference setLinkRef = GetLinkReference();
        auto setFunc = [linkRef = std::move(setLinkRef), pDerived, setClassMethod](_In_ TObjSet instanceObject, _In_ TSetValue val)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            (pDerived->*setClassMethod)(instanceObject, val);
        };

        ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunc, setFunc);
        ClientEx::CheckHr(GetObject()->SetKey(propertyName, propertyAccessor, metadata));
    }

    template<typename TGetFunc>
    void AddReadOnlyProperty(_In_z_ const wchar_t *propertyName,
                             _In_ const TGetFunc& getFunction,    // TValue getFunction([const] Object [&]);
                             _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(std::is_invocable_v<TGetFunc, ClientEx::Object>, "Bound property getter must take (const) Object (&) as first argument");
        if constexpr (std::is_invocable_v<TGetFunc, ClientEx::Object>) // Prevent noise from failure of the assertion above
        {
            ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunction);
            ClientEx::CheckHr(GetObject()->SetKey(propertyName, propertyAccessor, metadata));
        }
    }

    template<typename TObj, typename TClass, typename TRet>
    void AddReadOnlyProperty(_In_z_ const wchar_t *propertyName,
                             _In_ TClass *pDerived,
                             _In_ TRet (TClass::*getClassMethod)(_In_ TObj),
                             _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(Details::is_object_v<TObj>, "Bound property getter must take (const) Object (&) as first argument");

        ClientEx::Details::DataModelReference getLinkRef = GetLinkReference();
        auto getFunc = [linkRef = std::move(getLinkRef), pDerived, getClassMethod](_In_ TObj instanceObject)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*getClassMethod)(instanceObject);
        };

        ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunc);
        ClientEx::CheckHr(GetObject()->SetKey(propertyName, propertyAccessor, metadata));
    }

    template<typename TObj, typename TClass, typename TRet>
    void AddReadOnlyProperty(_In_z_ const wchar_t *propertyName,
                             _In_ const TClass *pDerived,
                             _In_ TRet (TClass::*getClassMethod)(_In_ TObj) const,
                             _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        AddReadOnlyProperty(propertyName, const_cast<TClass *>(pDerived), reinterpret_cast<TRet(TClass::*)(TObj)>(getClassMethod), metadata);
    }

    // AddMethod():
    //
    // Adds a new method.
    //
    template<typename TObj, typename TClass, typename TRet, typename... TArgs>
    void AddMethod(_In_z_ const wchar_t *methodName,
                   _In_ TClass *pDerived,
                   _In_ TRet (TClass::*classMethod)(TObj, TArgs...),
                   _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(Details::is_object_v<TObj>, "Bound property getter must take (const) Object (&) as first argument");

        //
        // The signature of the method must be Object, ...
        //
        ClientEx::Details::DataModelReference callLinkRef = GetLinkReference();
        auto callDest = [linkRef = std::move(callLinkRef), pDerived, classMethod](TObj contextObj, TArgs... methodArgs)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return Details::MethodInvocationHelper<TClass, TRet, TObj, TArgs...>::Call(
                pDerived,
                classMethod,
                contextObj,
                std::forward<TArgs>(methodArgs)...
                );
        };

        ClientEx::Object methodObject;
        methodObject = callDest;
        ClientEx::CheckHr(GetObject()->SetKey(methodName, methodObject, metadata));
    }

    template<typename TObj, typename TClass, typename TRet, typename... TArgs>
    void AddMethod(_In_z_ const wchar_t *methodName,
                   _In_ const TClass *pDerived,
                   _In_ TRet (TClass::*classMethod)(TObj, TArgs...) const,
                   _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        AddMethod(methodName, const_cast<TClass *>(pDerived), reinterpret_cast<TRet (TClass::*)(TObj, TArgs...)>(classMethod), metadata);
    }

    // AddStringDisplayableFunction():
    //
    // Adds the string displayable implementation on this object to a method of signature const Object&, const Metadata&
    //
    template<typename TObj, typename TMeta, typename TRet, typename TClass>
    void AddStringDisplayableFunction(_In_ TClass *pDerived, _In_ TRet (TClass::*classMethod)(_In_ TObj, _In_ TMeta))
    {
        static_assert(Details::is_object_v<TObj>, "Bound string converter must take (const) Object (&) as first argument");
        static_assert(Details::is_metadata_v<TMeta>, "Bound string converter must take (const) Metadata (&) as second argument");

        ClientEx::Details::DataModelReference stringLinkRef = GetLinkReference();
        auto stringProjectorFunc = [linkRef = std::move(stringLinkRef), pDerived, classMethod](TObj contextObj,
                                                                                               TMeta metadata) -> TRet
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*classMethod)(contextObj, metadata);
        };

        using TStringProjector = decltype(stringProjectorFunc);

        ComPtr<Details::BoundStringDisplayable<TClass, TStringProjector>> spStringDisplayable;
        spStringDisplayable = Make<Details::BoundStringDisplayable<TClass, TStringProjector>>(
            pDerived, stringProjectorFunc
            );
    }

    template<typename TObj, typename TMeta, typename TRet, typename TClass>
    void AddStringDisplayableFunction(_In_ const TClass *pDerived, _In_ TRet (TClass::*classMethod)(_In_ TObj, _In_ TMeta) const)
    {
        AddStringDisplayableFunction(const_cast<TClass *>(pDerived), reinterpret_cast<TRet(TClass::*)(TObj, TMeta)>(classMethod));
    }

    // AddEquatableFunction():
    //
    // Adds the equatable implementation on this object to a method of signature bool(const Object&, const Object&)
    //
    template<typename TObj1, typename TObj2, typename TClass>
    void AddEquatableFunction(_In_ TClass *pDerived, _In_ bool (TClass::*classMethod)(_In_ TObj1, _In_ TObj2))
    {
        static_assert(Details::is_object_v<TObj1>, "Bound equatable function must take (const) Object (&) as first argument");
        static_assert(Details::is_object_v<TObj2>, "Bound equatable function must take (const) Object (&) as second argument");
        ClientEx::Details::DataModelReference equatableLinkRef = GetLinkReference();
        auto equatableProjectorFunc = [linkRef = std::move(equatableLinkRef), pDerived, classMethod](TObj1 contextObj,
                                                                                                     TObj2 otherObj)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*classMethod)(contextObj, otherObj);
        };

        using TEquatableProjector = decltype(equatableProjectorFunc);

        ComPtr<ClientEx::Details::BoundEquatable<TClass, TEquatableProjector>> spEquatable;
        spEquatable = Make<ClientEx::Details::BoundEquatable<TClass, TEquatableProjector>>(
            pDerived, equatableProjectorFunc
            );
    }

    template<typename TObj1, typename TObj2, typename TClass>
    void AddEquatableFunction(_In_ const TClass *pDerived, _In_ bool (TClass::*classMethod)(_In_ TObj1, _In_ TObj2) const)
    {
        AddEquatableFunction(const_cast<TClass *>(pDerived), reinterpret_cast<bool(TClass::*)(TObj1, TObj2)>(classMethod));
    }

    // AddComparableFunction():
    //
    // Adds the comparable implementation on this object to a method of signature int(const Object&, const Object&)
    //
    template<typename TObj1, typename TObj2, typename TClass>
    void AddComparableFunction(_In_ TClass *pDerived, _In_ int (TClass::*classMethod)(_In_ TObj1, _In_ TObj2))
    {
        static_assert(Details::is_object_v<TObj1>, "Bound comparable function must take (const) Object (&) as first argument");
        static_assert(Details::is_object_v<TObj2>, "Bound comparable function must take (const) Object (&) as second argument");
        ClientEx::Details::DataModelReference comparableLinkRef = GetLinkReference();
        auto comparableProjectorFunc = [linkRef = std::move(comparableLinkRef), pDerived, classMethod](TObj1 contextObj,
                                                                                                       TObj2 otherObj)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*classMethod)(contextObj, otherObj);
        };

        using TComparableProjector = decltype(comparableProjectorFunc);

        ComPtr<ClientEx::Details::BoundComparable<TClass, TComparableProjector>> spComparable;
        spComparable = Make<ClientEx::Details::BoundComparable<TClass, TComparableProjector>>(
            pDerived, comparableProjectorFunc
            );
    }

    template<typename TObj1, typename TObj2, typename TClass>
    void AddComparableFunction(_In_ const TClass *pDerived, _In_ int (TClass::*classMethod)(_In_ TObj1, _In_ TObj2) const)
    {
        AddComparableFunction(const_cast<TClass *>(pDerived), reinterpret_cast<int(TClass::*)(TObj1, TObj2)>(classMethod));
    }

    // AddGeneratorFunction():
    //
    // Adds the iterable implementation on this object to the generator (or iterable) returned from the
    // bound class method.  The supplied generator must be copyable into the resulting data model iterator.
    //
    template<typename TObj, typename TGen, typename TClass>
    void AddGeneratorFunction(_In_ TClass *pDerived, _In_ TGen (TClass::*classMethod)(_In_ TObj))
    {
        static_assert(Details::is_object_v<TObj>, "Bound generator function must take (const) Object (&) as first argument");

        //
        // genProjectorFunc must preserve the l-value refness of its return value:
        //     - If it returns a T&, preserve it into the bound iterator
        //     - If it returns a T, T&&, move it into the bound iterator
        //
        using TRet = TGen; // decltype((pDerived->*classMethod)(ClientEx::Object()));
        using TRetBaseType = std::decay_t<TRet>;
        using TLamRet = std::conditional_t<std::is_lvalue_reference_v<TRet>, TRetBaseType&, TRetBaseType>;

        ClientEx::Details::DataModelReference genLinkRef = GetLinkReference();
        auto genProjectorFunc = [linkRef = std::move(genLinkRef), pDerived, classMethod](TObj contextObj) -> TLamRet
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*classMethod)(contextObj);
        };

        using TItem = decltype(*(std::declval<TGen>().begin()));
        auto itemProjectorFunc = [](_In_ TItem eref) { return eref; };

        using TGenProjector = decltype(genProjectorFunc);
        using TItemProjector = decltype(itemProjectorFunc);

        ClientEx::Details::DataModelReference iterLinkRef = GetLinkReference();
        ComPtr<ClientEx::Details::BoundIterable<TClass, TGenProjector, TItemProjector>> spIterable;

        static_assert(std::is_base_of_v<std::decay_t<decltype(*this)>, std::decay_t<TClass>>,
                      "Implementation class must derive from ProviderEx:: model class");

        TClass *pDerivedThis = static_cast<TClass *>(this);
        spIterable = Make<ClientEx::Details::BoundIterable<TClass, TGenProjector, TItemProjector>>(
            std::move(iterLinkRef), pDerivedThis, genProjectorFunc, itemProjectorFunc
            );
    }

    // AddReadOnlyIndexableGeneratorFunction():
    //
    // Adds the iterable and indexable implementation on this object to the generator (or iterable) returned from
    // the first bound class method.  The supplied generator must return IndexableValue<TValue, TIndicies...>.  The
    // TIndicies... must match the indicies arguments of the bound indexer method.
    //
    template<typename TObjGen, typename TObjGet, typename TGen, typename TClass, typename TValue, typename... TIndicies>
    void AddReadOnlyIndexableGeneratorFunction(_In_ TClass *pDerived,
                                               _In_ TGen (TClass::*generatorMethod)(_In_ TObjGen),
                                               _In_ TValue (TClass::*getAtMethod)(_In_ TObjGet, _In_ TIndicies... indicies))
    {
        static_assert(Details::is_object_v<TObjGen>, "Bound generator function must take (const) Object (&) as first argument");
        static_assert(Details::is_object_v<TObjGet>, "Bound indexer function must take (const) Object (&) as first argument");

        using TIdx = ClientEx::IndexedValue<TValue, TIndicies...>;
        using TIVal = typename TIdx::ValueType;
        using TGVal = decltype(*(std::declval<TGen>().begin()));
        using TIdxBase = std::decay_t<TIdx>;
        using TGValBase = std::decay_t<TGVal>;
        static_assert(std::is_same_v<TIdxBase, TGValBase>, "Type mismatch between iterator indicies and indexer indicies");

        //
        // genProjectorFunc must preserve the l-value refness of its return value:
        //     - If it returns a T&, preserve it into the bound iterator
        //     - If it returns a T, T&&, move it into the bound iterator
        //
        using TRet = TGen;
        using TRetBaseType = std::decay_t<TRet>;
        using TLamRet = std::conditional_t<std::is_lvalue_reference_v<TRet>, TRetBaseType&, TRetBaseType>;

        ClientEx::Details::DataModelReference genLinkRef = GetLinkReference();
        auto genProjectorFunc = [linkRef = std::move(genLinkRef), pDerived, generatorMethod](TObjGen contextObj) -> TLamRet
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*generatorMethod)(contextObj);
        };

        using TItem = decltype(*(std::declval<TGen>().begin()));
        auto itemProjectorFunc = [](_In_ TItem eref) { return eref; };

        using TGenProjector = decltype(genProjectorFunc);
        using TItemProjector = decltype(itemProjectorFunc);

        ClientEx::Details::DataModelReference getLinkRef = GetLinkReference();
        auto getProjectorFunc = [linkRef = std::move(getLinkRef), pDerived, getAtMethod](_In_ TObjGet contextObj, _In_ TIndicies... indicies)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*getAtMethod)(contextObj, std::forward<TIndicies>(indicies)...);
        };

        ClientEx::Details::DataModelReference setLinkRef = GetLinkReference();
        auto setProjectorFunc = [linkRef = std::move(setLinkRef), pDerived, getAtMethod](_In_ const ClientEx::Object& /*contextObj*/,
                                                                                         _In_ const ClientEx::Object& /*value*/,
                                                                                         _In_ TIndicies... /*indicies*/)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            throw ClientEx::not_implemented();
        };

        using TGetAtProjector = decltype(getProjectorFunc);
        using TSetAtProjector = decltype(setProjectorFunc);

        ClientEx::Details::DataModelReference iterLinkRef = GetLinkReference();
        ComPtr<ClientEx::Details::BoundIterableWithIndexable<TClass, TGenProjector, TItemProjector, TGetAtProjector, TSetAtProjector>> spIterableIndexable;

        static_assert(std::is_base_of_v<std::decay_t<decltype(*this)>, std::decay_t<TClass>>,
                      "Implementation class must derive from ProviderEx:: model class");

        TClass *pDerivedThis = static_cast<TClass *>(this);
        spIterableIndexable = Make<ClientEx::Details::BoundIterableWithIndexable<TClass, TGenProjector, TItemProjector, TGetAtProjector, TSetAtProjector>>(
            std::move(iterLinkRef), pDerivedThis, genProjectorFunc, itemProjectorFunc, getProjectorFunc, setProjectorFunc
            );
    }

    // AddIndexableGeneratorFunction():
    //
    // Adds the iterable and indexable implementation on this object to the generator (or iterable) returned from
    // the first bound class method.  The supplied generator must return IndexableValue<TValue, TIndicies...>.  The
    // TIndicies... must match the indicies arguments of the bound indexer method.
    //
    template<typename TObjGen, typename TObjGet, typename TObjSet, typename TGen, typename TClass, typename TValue, typename... TIndicies>
    void AddIndexableGeneratorFunction(_In_ TClass *pDerived,
                                       _In_ TGen (TClass::*generatorMethod)(_In_ TObjGen),
                                       _In_ TValue (TClass::*getAtMethod)(_In_ TObjGet, _In_ TIndicies... indicies),
                                       _In_ void (TClass::*setAtMethod)(_In_ TObjSet, _In_ TValue value, _In_ TIndicies... indicies))

    {
        static_assert(Details::is_object_v<TObjGen>, "Bound generator function must take (const) Object (&) as first argument");
        static_assert(Details::is_object_v<TObjGet>, "Bound indexer function must take (const) Object (&) as first argument");
        static_assert(Details::is_object_v<TObjSet>, "Bound indexer function must take (const) Object (&) as first argument");

        using TIdx = ClientEx::IndexedValue<TValue, TIndicies...>;
        using TIVal = typename TIdx::ValueType;
        using TGVal = decltype(*(std::declval<TGen>().begin()));
        using TIdxBase = std::decay_t<TIdx>;
        using TGValBase = std::decay_t<TGVal>;
        static_assert(std::is_same_v<TIdxBase, TGValBase>, "Type mismatch between iterator indicies and indexer indicies");

        //
        // genProjectorFunc must preserve the l-value refness of its return value:
        //     - If it returns a T&, preserve it into the bound iterator
        //     - If it returns a T, T&&, move it into the bound iterator
        //
        using TRet = TGen;
        using TRetBaseType = std::decay_t<TRet>;
        using TLamRet = std::conditional_t<std::is_lvalue_reference_v<TRet>, TRetBaseType&, TRetBaseType>;

        ClientEx::Details::DataModelReference genLinkRef = GetLinkReference();
        auto genProjectorFunc = [linkRef = std::move(genLinkRef), pDerived, generatorMethod](const ClientEx::Object& contextObj) -> TLamRet
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*generatorMethod)(contextObj);
        };

        using TItem = decltype(*(std::declval<TGen>().begin()));
        auto itemProjectorFunc = [](_In_ TItem eref) { return eref; };

        using TGenProjector = decltype(genProjectorFunc);
        using TItemProjector = decltype(itemProjectorFunc);

        ClientEx::Details::DataModelReference getLinkRef = GetLinkReference();
        auto getProjectorFunc = [linkRef = std::move(getLinkRef), pDerived, getAtMethod](_In_ const ClientEx::Object& contextObj, _In_ TIndicies... indicies)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*getAtMethod)(contextObj, std::forward<TIndicies>(indicies)...);
        };

        ClientEx::Details::DataModelReference setLinkRef = GetLinkReference();
        auto setProjectorFunc = [linkRef = std::move(setLinkRef), pDerived, setAtMethod](_In_ const ClientEx::Object& contextObj,
                                                                                         _In_ TValue value,
                                                                                         _In_ TIndicies... indicies)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            (pDerived->*setAtMethod)(contextObj, value, std::forward<TIndicies>(indicies)...);
        };

        using TGetAtProjector = decltype(getProjectorFunc);
        using TSetAtProjector = decltype(setProjectorFunc);

        ClientEx::Details::DataModelReference iterLinkRef = GetLinkReference();
        ComPtr<ClientEx::Details::BoundIterableWithIndexable<TClass, TGenProjector, TItemProjector, TGetAtProjector, TSetAtProjector>> spIterableIndexable;

        static_assert(std::is_base_of_v<std::decay_t<decltype(*this)>, std::decay_t<TClass>>,
                      "Implementation class must derive from ProviderEx:: model class");

        TClass *pDerivedThis = static_cast<TClass *>(this);
        spIterableIndexable = Make<ClientEx::Details::BoundIterableWithIndexable<TClass, TGenProjector, TItemProjector, TGetAtProjector, TSetAtProjector>>(
            std::move(iterLinkRef), pDerivedThis, genProjectorFunc, itemProjectorFunc, getProjectorFunc, setProjectorFunc
            );
    }

    std::function<void()> VerifyIsAliveFunction()
    {
        ClientEx::Details::DataModelReference objLinkRef = GetLinkReference();
        auto validatorLambda = [linkRef = std::move(objLinkRef)]()
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
        };

        return validatorLambda;
    }

private:

    template<typename... TArgs>
    void CompleteExtensionModelInitialization(_In_ TArgs&&... registrations)
    {
        //
        // The first NamedModelRegistration is the canonical name.  Extract it.
        //
        Details::ExtensionNameAcquisition<TArgs...>::FillName(m_modelName, registrations...);

        //
        // Keep a list of the registrations, heap allocated, within our object.  The registration record
        // only gets moved into this list once it has SUCCESSFULLY applied.
        //
        // Destruction of this list will unapply everything.
        //
        using RegistrationList = Details::ExtensionRegistrationList<TArgs...>;
        RegistrationList *pList = new RegistrationList(GetObject());
        std::unique_ptr<Details::ExtensionRegistrationListBase> spRegistrationList(pList);
        Details::ExtensionApplication<RegistrationList, 0, TArgs...>::Apply(*pList, std::forward<TArgs>(registrations)...);
        m_spRegistrationList = std::move(spRegistrationList);
    }

    std::unique_ptr<Details::ExtensionRegistrationListBase> m_spRegistrationList;
};

//**************************************************************************
// Typed Models (Type Factories):
//

template<typename TInstance>
class BaseTypedInstanceModel : public BaseDataModel
{
public:

    using StorageType = typename Details::StorageTraits<TInstance>::StorageType;
    using InstanceType = typename Details::StorageTraits<TInstance>::InstanceData;

     // BaseTypedInstanceModel:
     //
     // Construct a typed model base
     //
     // If delayedInitialization is true then InitializeModel must be used in the derived constructor
     //
    BaseTypedInstanceModel() : BaseTypedInstanceModel(ClientEx::Metadata())
    {
    }

    BaseTypedInstanceModel(_In_ const ClientEx::Metadata & metadata) : BaseDataModel(metadata)
    {
        m_typeHash = Details::GetSigHash(__FUNCSIG__);
    }

    InstanceType& GetStoredInstance(_In_ const ClientEx::Object& instanceObject)
    {
        ComPtr<IUnknown> spStorage;
        ClientEx::CheckHr(instanceObject->GetContextForDataModel(GetObject(), &spStorage));
        if (spStorage == nullptr)
        {
            throw std::bad_alloc();
        }

        return (static_cast<Details::StorageInterface<InstanceType> *>(spStorage.Get()))->GetInstance();
    }

protected:

    ULONG64 GetTypeHash() const
    {
        return m_typeHash;
    }

private:

    ULONG64 m_typeHash;
};

template<typename TInstance>
class IterableTypedInstanceModel : public BaseTypedInstanceModel<TInstance>
{
public:

    IterableTypedInstanceModel(_In_ const ClientEx::Metadata & metadata) : BaseTypedInstanceModel<TInstance>(metadata)
    {
    }

    IterableTypedInstanceModel() : IterableTypedInstanceModel(ClientEx::Metadata())
    {
    }

protected:

    using IteratorType = decltype(std::declval<BaseTypedInstanceModel<TInstance>::InstanceType>().begin());
    using ElementReference = typename std::iterator_traits<IteratorType>::reference;
    using ElementValue = typename std::iterator_traits<IteratorType>::value_type;

    // BindIterator():
    //
    // Binds the C++ iterator for the instance data to the model iterator.  Each element is a direct boxing
    // of the element type returned from the iterator.
    //
    void BindIterator()
    {
        return BindIterator([](_In_ ElementReference eref) { return eref; });
    }

    // BindIterator<TItemProjector>():
    //
    // Binds the C++ iterator for a projection of the instance data to the model iterator.  Each element is a boxing
    // of a projection of the element type returned from the iterator.
    //
    template<typename TItemProjector>
    void BindIterator(_In_ const TItemProjector& itemProjectorFunc);
};

template<typename TInstance>
class TypedInstanceModelBaseSelector : public std::conditional_t<ClientEx::Details::IsIterable_v<typename Details::StorageTraits<TInstance>::InstanceData>,
                                                                 IterableTypedInstanceModel<TInstance>,
                                                                 BaseTypedInstanceModel<TInstance>>
{
public:
    TypedInstanceModelBaseSelector(_In_ const ClientEx::Metadata & metadata) :
        std::conditional_t<ClientEx::Details::IsIterable_v<typename Details::StorageTraits<TInstance>::InstanceData>,
                           IterableTypedInstanceModel<TInstance>,
                           BaseTypedInstanceModel<TInstance>>(metadata)
    {
    }

    TypedInstanceModelBaseSelector() : TypedInstanceModelBaseSelector(ClientEx::Metadata())
    {
    }

};

// TypedInstanceModel:
//
// Represents a data model which presents a native type, TInstance.  Instance objects with this model attached are
// expected to be created through this object as a "type factory".
//
template<typename TInstance>
class TypedInstanceModel : public TypedInstanceModelBaseSelector<TInstance>
{
    using StorageType = typename TypedInstanceModelBaseSelector<TInstance>::StorageType;
    using StorageData = typename StorageType::StorageData;

public:

    // TypedInstanceModel():
    //
    // Creates a data model representing a wrapping of some type (or some type of instance data).
    //
    // If delayedInitialization is true then InitializeModel must be used in the derived constructor
    //
    TypedInstanceModel(_In_ ClientEx::Metadata && metadata) :
        TypedInstanceModelBaseSelector<TInstance>(metadata)
    {
    }

    TypedInstanceModel() : TypedInstanceModelBaseSelector<TInstance>(ClientEx::Metadata())
    {
    }

    // TypedInstanceModel():
    //
    // Creates a data model representing a wrapping of some type (or some type of instance data).
    //
    template<typename... TArgs>
    TypedInstanceModel(_In_ ClientEx::Metadata && metadata, _In_ TArgs&&... registrations) :
        TypedInstanceModelBaseSelector<TInstance>(metadata)
    {
        CompleteTypedInstanceModelInitialization(std::forward<TArgs>(registrations)...);
    }

    template<typename... TArgs>
    TypedInstanceModel(_In_ TArgs&&... registrations) :
        TypedInstanceModelBaseSelector<TInstance>(ClientEx::Metadata())
    {
        CompleteTypedInstanceModelInitialization(std::forward<TArgs>(registrations)...);
    }

    // CreateInstance():
    //
    // Creates an instance of the typed instance model.
    //
    ClientEx::Object CreateInstance(_In_ const TInstance& instanceData)
    {
        ComPtr<StorageType> spStorage = Make<StorageType>(instanceData, this->GetTypeHash());
        if (spStorage == nullptr)
        {
            throw std::bad_alloc();
        }
        return ObjectForStorage(spStorage.Get());
    }

    ClientEx::Object CreateInstance(_In_ TInstance&& instanceData)
    {
        ComPtr<StorageType> spStorage = Make<StorageType>(std::move(instanceData), this->GetTypeHash());
        if (spStorage == nullptr)
        {
            throw std::bad_alloc();
        }
        return ObjectForStorage(spStorage.Get());
    }

    std::enable_if_t<std::is_same_v<StorageData, TInstance>, ClientEx::Object>
    CreateInstance(_In_ std::shared_ptr<TInstance> instanceData)
    {
        auto spStorage = Make<Details::SharedStorage<TInstance>>(std::move(instanceData), this->GetTypeHash());
        if (spStorage == nullptr)
        {
            throw std::bad_alloc();
        }
        return ObjectForStorage(spStorage.Get());
    }

    std::enable_if_t<std::is_same_v<StorageData, TInstance>, ClientEx::Object>
    CreateInstance(_In_ std::unique_ptr<TInstance> instanceData)
    {
        auto spStorage = Make<Details::UniqueStorage<TInstance>>(std::move(instanceData), this->GetTypeHash());
        if (spStorage == nullptr)
        {
            throw std::bad_alloc();
        }
        return ObjectForStorage(spStorage.Get());
    }

    // IsObjectInstance():
    //
    // Returns whether a given object is an instance of a type created by this (or another type equivalent)
    // factory.  This method *MUST* be called before any GetStoredInstance() call is made.
    //
    bool IsObjectInstance(_In_ const ClientEx::Object& obj)
    {
        ComPtr<IUnknown> spUnk;
        if (FAILED(obj->GetContextForDataModel(this->GetObject(), &spUnk)))
        {
            return false;
        }

        ComPtr<Details::IPrivateTypeQuery> spTypeQuery;
        if (FAILED(spUnk.As(&spTypeQuery)))
        {
            return false;
        }

        return spTypeQuery->GetTypeHash() == this->GetTypeHash();
    }

protected:

    // AddProperty():
    //
    // Adds a new property.
    //
    template<typename TGetFunc, typename TSetFunc>
    void AddProperty(_In_z_ const wchar_t *propertyName,
                     _In_ const TGetFunc& getFunction,    // TValue getFunction([const] Object [&], [const] TInstance [&]);
                     _In_ const TSetFunc& setFunction,    // void setFunction([const] Object [&], [const] TInstance [&], [const] TValue [&]);
                     _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(std::is_invocable_v<TGetFunc, ClientEx::Object, TInstance&>, "Bound property getter must take (const) Object (&) as first argument and the instance type as the second");
        if constexpr (std::is_invocable_v<TGetFunc, ClientEx::Object, TInstance&>) // Prevent noise from failure of the assertion above
        {
            using TValue = std::invoke_result_t<TGetFunc, ClientEx::Object, TInstance&>;
            static_assert(std::is_invocable_v<TSetFunc, ClientEx::Object, TInstance&, TValue>, "Bound property setter must take (const) Object (&) as first argument and the instance type as the second");

            ClientEx::Details::DataModelReference getLinkRef = this->GetLinkReference();
            auto getFunc = [linkRef = std::move(getLinkRef), this, getFunction](_In_ const ClientEx::Object& instanceObject)
            {
                ClientEx::Details::ThrowIfDetached(linkRef);
                return getFunction(instanceObject, this->GetStoredInstance(instanceObject));
            };

            ClientEx::Details::DataModelReference setLinkRef = this->GetLinkReference();
            auto setFunc = [linkRef = std::move(setLinkRef), this, setFunction](_In_ const ClientEx::Object& instanceObject, _In_ TValue val)
            {
                ClientEx::Details::ThrowIfDetached(linkRef);
                setFunction(instanceObject, this->GetStoredInstance(instanceObject), val);
            };

            ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunc, setFunc);
            ClientEx::CheckHr(this->GetObject()->SetKey(propertyName, propertyAccessor, metadata));
        }
    }

    template<typename TObjGet, typename TObjSet, typename TClass, typename TRet, typename TSetValue, typename TData1, typename TData2>
    void AddProperty(_In_z_ const wchar_t *propertyName,
                     _In_ TClass *pDerived,
                     _In_ TRet (TClass::*getClassMethod)(_In_ TObjGet, _In_ TData1),
                     _In_ void (TClass::*setClassMethod)(_In_ TObjSet, _In_ TData2, _In_ TSetValue),
                     _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(Details::is_object_v<TObjGet>, "Bound property getter must take (const) Object (&) as first argument");
        static_assert(Details::is_object_v<TObjSet>, "Bound property setter must take (const) Object (&) as first argument");

        ClientEx::Details::DataModelReference getLinkRef = this->GetLinkReference();
        auto getFunc = [linkRef = std::move(getLinkRef), pDerived, getClassMethod](_In_ const ClientEx::Object& instanceObject)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*getClassMethod)(instanceObject, pDerived->GetStoredInstance(instanceObject));
        };

        ClientEx::Details::DataModelReference setLinkRef = this->GetLinkReference();
        auto setFunc = [linkRef = std::move(setLinkRef), pDerived, setClassMethod](_In_ const ClientEx::Object& instanceObject, _In_ TSetValue val)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            (pDerived->*setClassMethod)(instanceObject, pDerived->GetStoredInstance(instanceObject), val);
        };

        ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunc, setFunc);
        ClientEx::CheckHr(this->GetObject()->SetKey(propertyName, propertyAccessor, metadata));
    }

    template<typename TGetFunc>
    void AddReadOnlyProperty(_In_z_ const wchar_t *propertyName,
                             _In_ const TGetFunc& getFunction,    // TValue getFunction([const] Object [&]);
                             _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(std::is_invocable_v<TGetFunc, ClientEx::Object, TInstance&>, "Bound property getter must take (const) Object (&) as first argument and the instance type as the second");
        if constexpr (std::is_invocable_v<TGetFunc, ClientEx::Object, TInstance&>) // Prevent noise from failure of the assertion above
        {
            ClientEx::Details::DataModelReference getLinkRef = this->GetLinkReference();
            auto getFunc = [linkRef = std::move(getLinkRef), this, getFunction](_In_ const ClientEx::Object& instanceObject)
            {
                ClientEx::Details::ThrowIfDetached(linkRef);
                return getFunction(instanceObject, this->GetStoredInstance(instanceObject));
            };

            ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunc);
            ClientEx::CheckHr(this->GetObject()->SetKey(propertyName, propertyAccessor, metadata));
        }
    }

    template<typename TObj, typename TClass, typename TRet, typename TData>
    void AddReadOnlyProperty(_In_z_ const wchar_t *propertyName,
                             _In_ TClass *pDerived,
                             _In_ TRet (TClass::*getClassMethod)(_In_ TObj, _In_ TData),
                             _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(Details::is_object_v<TObj>, "Bound property getter must take (const) Object (&) as first argument");

        ClientEx::Details::DataModelReference getLinkRef = this->GetLinkReference();
        auto getFunc = [linkRef = std::move(getLinkRef), pDerived, getClassMethod](_In_ TObj instanceObject)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*getClassMethod)(instanceObject, pDerived->GetStoredInstance(instanceObject));
        };

        ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunc);
        ClientEx::CheckHr(this->GetObject()->SetKey(propertyName, propertyAccessor, metadata));
    }

    template<typename TObj, typename TClass, typename TRet, typename TData>
    void AddReadOnlyProperty(_In_z_ const wchar_t *propertyName,
                             _In_ const TClass *pDerived,
                             _In_ TRet (TClass::*getClassMethod)(_In_ TObj, _In_ TData) const,
                             _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        AddReadOnlyProperty(propertyName, const_cast<TClass *>(pDerived), reinterpret_cast<TRet(TClass::*)(TObj, TData)>(getClassMethod), metadata);
    }

    // BindProperty():
    //
    // Binds a data model property to a field within the instance data.
    //
    template<typename TData, typename TClass>
    void BindProperty(_In_z_ const wchar_t *propertyName,
                      _In_  TData TClass::* bindingPointer,
                      _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(std::is_base_of_v<TClass, TInstance>, "Must use a pointer to member of the instance type to bind a property");
        if constexpr (std::is_base_of_v<TClass, TInstance>)
        {
            ClientEx::Details::DataModelReference getLinkRef = this->GetLinkReference();
            auto getFunc = [linkRef = std::move(getLinkRef), this, bindingPointer](_In_ const ClientEx::Object& instanceObject)
            {
                ClientEx::Details::ThrowIfDetached(linkRef);
                auto& data = this->GetStoredInstance(instanceObject);
                return data.*bindingPointer;
            };

            ClientEx::Details::DataModelReference setLinkRef = this->GetLinkReference();
            auto setFunc = [linkRef = std::move(setLinkRef), this, bindingPointer](_In_ const ClientEx::Object& instanceObject, _In_ TData &val)
            {
                ClientEx::Details::ThrowIfDetached(linkRef);
                auto& data = this->GetStoredInstance(instanceObject);
                data.*bindingPointer = val;
            };

            ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunc, setFunc);
            ClientEx::CheckHr(this->GetObject()->SetKey(propertyName, propertyAccessor, metadata));
        }
    }

    // BindPropertyFunction():
    //
    // Binds a data model property to a getter/setter method within the instance data.
    //
    template<typename TRet, typename TSetValue, typename TClass>
    void BindPropertyFunction(_In_z_ const wchar_t *propertyName,
                              _In_ TRet (TClass::*getClassMethod)(),
                              _In_ void (TClass::*setClassMethod)(_In_ TSetValue),
                              _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(std::is_base_of_v<TClass, TInstance>, "Must use a pointer to member of the instance type to bind a property");
        if constexpr (std::is_base_of_v<TClass, TInstance>)
        {
            ClientEx::Details::DataModelReference getLinkRef = this->GetLinkReference();
            auto getFunc = [linkRef = std::move(getLinkRef), this, getClassMethod](_In_ const ClientEx::Object& instanceObject)
            {
                ClientEx::Details::ThrowIfDetached(linkRef);
                auto& data = this->GetStoredInstance(instanceObject);
                return (data.*getClassMethod)();
            };

            ClientEx::Details::DataModelReference setLinkRef = this->GetLinkReference();
            auto setFunc = [linkRef = std::move(setLinkRef), this, setClassMethod](_In_ const ClientEx::Object& instanceObject, _In_ TSetValue &val)
            {
                ClientEx::Details::ThrowIfDetached(linkRef);
                auto& data = this->GetStoredInstance(instanceObject);
                (data.*setClassMethod)(val);
            };

            ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunc, setFunc);
            ClientEx::CheckHr(this->GetObject()->SetKey(propertyName, propertyAccessor, metadata));
        }
    }

    // BindReadOnlyProperty():
    //
    // Binds a data model property to a field within the instance data in a read-only manner.
    //
    template<typename TData, typename TClass>
    void BindReadOnlyProperty(_In_z_ const wchar_t *propertyName,
                              _In_  TData TClass::* bindingPointer,
                              _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(std::is_base_of_v<TClass, TInstance>, "Must use a pointer to member of the instance type to bind a property");
        if constexpr (std::is_base_of_v<TClass, TInstance>)
        {
            ClientEx::Details::DataModelReference getLinkRef = this->GetLinkReference();
            auto getFunc = [linkRef = std::move(getLinkRef), this, bindingPointer](_In_ const ClientEx::Object& instanceObject)
            {
                ClientEx::Details::ThrowIfDetached(linkRef);
                auto& data = this->GetStoredInstance(instanceObject);
                return data.*bindingPointer;
            };

            ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunc);
            ClientEx::CheckHr(this->GetObject()->SetKey(propertyName, propertyAccessor, metadata));
        }
    }

    // BindReadOnlyPropertyFunction():
    //
    // Binds a data model property to a getter method within the instance data in a read-only manner.
    //
    template<typename TRet, typename TClass>
    void BindReadOnlyPropertyFunction(_In_z_ const wchar_t *propertyName,
                                      _In_ TRet (TClass::*classMethod)(),
                                      _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(std::is_base_of_v<TClass, TInstance>, "Must use a pointer to member of the instance type to bind a property");
        if constexpr (std::is_base_of_v<TClass, TInstance>)
        {
            ClientEx::Details::DataModelReference getLinkRef = this->GetLinkReference();
            auto getFunc = [linkRef = std::move(getLinkRef), this, classMethod](_In_ const ClientEx::Object& instanceObject)
            {
                ClientEx::Details::ThrowIfDetached(linkRef);
                auto& data = this->GetStoredInstance(instanceObject);
                return (data.*classMethod)();
            };

            ClientEx::Object propertyAccessor = ClientEx::Details::BoxProperty(getFunc);
            ClientEx::CheckHr(this->GetObject()->SetKey(propertyName, propertyAccessor, metadata));
        }
    }

    template<typename TRet, typename TClass>
    void BindReadOnlyPropertyFunction(_In_z_ const wchar_t *propertyName,
                                      _In_ TRet (TClass::*classMethod)() const,
                                      _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(std::is_base_of_v<TClass, TInstance>, "Must use a pointer to member of the instance type to bind a property");
        if constexpr (std::is_base_of_v<TClass, TInstance>)
        {
            BindReadOnlyPropertyFunction(propertyName, reinterpret_cast<TRet (TInstance::*)()>(classMethod), metadata);
        }
    }

    // AddMethod():
    //
    // Adds a new method.
    //
    template<typename TObj, typename TInstanceType, typename TClass, typename TRet, typename... TArgs>
    void AddMethod(_In_z_ const wchar_t *methodName,
                   _In_ TClass *pDerived,
                   _In_ TRet (TClass::*classMethod)(TObj, TInstanceType&, TArgs...),
                   _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        static_assert(Details::is_object_v<TObj>, "Bound method must take (const) Object (&) as first argument");

        //
        // The signature of the method must be Object, InstanceData, ...
        //
        ClientEx::Details::DataModelReference callLinkRef = this->GetLinkReference();
        auto callDest = [linkRef = std::move(callLinkRef), pDerived, classMethod](TObj contextObj, TArgs... methodArgs)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return Details::MethodInvocationHelper<TClass, TRet, TObj, TInstanceType&, TArgs...>::Call(
                pDerived,
                classMethod,
                contextObj,
                pDerived->GetStoredInstance(contextObj),
                std::forward<TArgs>(methodArgs)...
                );
        };

        ClientEx::Object methodObject;
        methodObject = callDest;
        ClientEx::CheckHr(this->GetObject()->SetKey(methodName, methodObject, metadata));
    }

    template<typename TObj, typename TInstanceType, typename TClass, typename TRet, typename... TArgs>
    void AddMethod(_In_z_ const wchar_t *methodName,
                   _In_ const TClass *pDerived,
                   _In_ TRet (TClass::*classMethod)(TObj, TInstanceType&, TArgs...) const,
                   _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        AddMethod(methodName, const_cast<TClass *>(pDerived), reinterpret_cast<TRet(TClass::*)(TObj, TInstanceType&, TArgs...)>(classMethod), metadata);
    }

    // BindMethod():
    //
    // Binds a data model method to a method on the instance data.
    //
    template<typename TClass, typename TRet, typename... TArgs>
    void BindMethod(_In_z_ const wchar_t *methodName,
                    _In_ TRet (TClass::*classMethod)(TArgs...),
                    _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        ClientEx::Details::DataModelReference callLinkRef = this->GetLinkReference();
        auto callDest = [linkRef = std::move(callLinkRef), this, classMethod](const ClientEx::Object& contextObj, TArgs... methodArgs)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            TClass *pInstance = &(this->GetStoredInstance(contextObj));

            return Details::MethodInvocationHelper<TClass, TRet, TArgs...>::Call(
                pInstance,
                classMethod,
                std::forward<TArgs>(methodArgs)...
                );
        };

        ClientEx::Object methodObject;
        methodObject = callDest;
        ClientEx::CheckHr(this->GetObject()->SetKey(methodName, methodObject, metadata));
    }

    template<typename TClass, typename TRet, typename... TArgs>
    void BindMethod(_In_z_ const wchar_t *methodName,
                    _In_ TRet (TClass::*classMethod)(TArgs...) const,
                    _In_ const ClientEx::Metadata& metadata = ClientEx::Metadata())
    {
        BindMethod(methodName, reinterpret_cast<TRet (TClass::*)(TArgs...)>(classMethod), metadata);
    }

    // BindStringConversion():
    //
    // Binds the string conversion of this type to a field within the instance data.
    //
    template<typename TData, typename TClass>
    void BindStringConversion(_In_ TData TClass::* bindingPointer)
    {
        static_assert(std::is_base_of_v<TClass, TInstance>, "Must use a pointer to member of the instance type to bind a property");
        if constexpr (std::is_base_of_v<TClass, TInstance>)
        {
            ClientEx::Details::DataModelReference stringLinkRef = this->GetLinkReference();
            auto stringProjectorFunc = [linkRef = std::move(stringLinkRef), this, bindingPointer](_In_ const ClientEx::Object& instanceObject,
                                                                                                _In_ const ClientEx::Metadata& metadata)
            {
                ClientEx::Details::ThrowIfDetached(linkRef);

                //
                // This can be optimized if the return value is wchar_t * / std::wstring.  In order to make this as *FAITHFUL* as possible
                // to a model based string conversion with automatic metadata handling, we box the value and take it through
                // the standard intrinsic string conversion with the given metadata.
                //
                // @TODO: Remove the extra boxing for string returns.
                //
                auto& data = this->GetStoredInstance(instanceObject);
                ClientEx::Object valueObj = data.*bindingPointer;
                return valueObj.ToDisplayString(metadata);
            };

            using TStringProjector = decltype(stringProjectorFunc);

            ComPtr<Details::BoundStringDisplayable<TypedInstanceModel<TInstance>, TStringProjector>> spStringDisplayable;
            spStringDisplayable = Make<Details::BoundStringDisplayable<TypedInstanceModel<TInstance>, TStringProjector>>(
                this, stringProjectorFunc
                );
        }
    }

    // BindEquatable():
    //
    // Binds custom equality on this type to C++ operator== / operator!= within the instance data.
    //
    void BindEquatable()
    {
        ClientEx::Details::DataModelReference equatableLinkRef = this->GetLinkReference();
        auto equatableProjectorFunc = [linkRef = std::move(equatableLinkRef), this](_In_ const ClientEx::Object& instanceObject,
                                                                                    _In_ const ClientEx::Object& otherObject)
        {
            auto& data = this->GetStoredInstance(instanceObject);
            using DataType = std::remove_reference_t<decltype(data)>;
            return data == (DataType)otherObject;
        };

        using TEquatableProjector = decltype(equatableProjectorFunc);

        ComPtr<ClientEx::Details::BoundEquatable<TypedInstanceModel<TInstance>, TEquatableProjector>> spEquatable;
        spEquatable = Make<ClientEx::Details::BoundEquatable<TypedInstanceModel<TInstance>, TEquatableProjector>>(
            this, equatableProjectorFunc
            );
    }

    // BindComparable():
    //
    // Binds custom comparison on typs type to C++ comparison < / > operators within the instance data.
    //
    void BindComparable()
    {
        ClientEx::Details::DataModelReference comparableLinkRef = this->GetLinkReference();
        auto comparableProjectorFunc = [linkRef = std::move(comparableLinkRef), this](_In_ const ClientEx::Object& instanceObject,
                                                                                      _In_ const ClientEx::Object& otherObject)
        {
            auto& data = this->GetStoredInstance(instanceObject);
            if (!this->IsObjectInstance(otherObject))
            {
                throw ClientEx::not_set();
            }
            auto& otherData = this->GetStoredInstance(otherObject);

            int result;
            if (data < otherData)
            {
                result = -1;
            }
            else if (data > otherData)
            {
                result = 1;
            }
            else if (data == otherData)
            {
                result = 0;
            }
            else
            {
                throw ClientEx::unexpected_error();
            }

            return result;
        };

        using TComparableProjector = decltype(comparableProjectorFunc);

        ComPtr<ClientEx::Details::BoundComparable<TypedInstanceModel<TInstance>, TComparableProjector>> spComparable;
        spComparable = Make<ClientEx::Details::BoundComparable<TypedInstanceModel<TInstance>, TComparableProjector>>(
            this, comparableProjectorFunc
            );
    }

    // BindConstructable():
    //
    // Binds a certain form of the constructor as given by the inpassed template pack to the constructable
    // concept.
    //
    template<typename... TArgs>
    void BindConstructable()
    {
        ClientEx::Details::DataModelReference constructableLinkRef = this->GetLinkReference();
        auto constructableProjectorFunc = [linkRef = std::move(constructableLinkRef), this](_In_ TArgs... args)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);

            auto parameters = std::make_tuple(std::forward<TArgs>(args)...);
            auto instance = ClientEx::Details::ConstructorApply<TInstance>(parameters);
            ClientEx::Object instanceObject = this->CreateInstance(instance);
            return instanceObject;
        };

        using TConstructableProjector = decltype(constructableProjectorFunc);

        ComPtr<Details::BoundConstructable<TypedInstanceModel<TInstance>,
                                           TConstructableProjector,
                                           TArgs...>> spConstructable;

        spConstructable = Make<Details::BoundConstructable<TypedInstanceModel<TInstance>, TConstructableProjector, TArgs...>>(
            this, constructableProjectorFunc
            );
    }

    // BindDeconstructable():
    //
    // Directly binds the deconstruction of an object to a set of pointer-to-data-member fields of the underlying
    // instance data.
    //
    template<typename TStr, typename... TArgs>
    void BindDeconstructable(_In_ TStr&& str, _In_ TArgs&&... args)
    {
        const wchar_t *pStr = ClientEx::Details::ExtractString(str);

        ClientEx::Details::DataModelReference deconstructableLinkRef = this->GetLinkReference();
        auto deconstructableProjectorFunc = [linkRef = std::move(deconstructableLinkRef), this, args...](
            _In_ const ClientEx::Object& instanceObject
            )
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            auto& instanceData = this->GetStoredInstance(instanceObject);
            return ClientEx::Details::PackTupleInstanceData(&instanceData, args...);
        };

        using TDeconstructableProjector = decltype(deconstructableProjectorFunc);

        ComPtr<Details::BoundDeconstructable<TypedInstanceModel<TInstance>, TDeconstructableProjector>> spDeconstructable;
        spDeconstructable = Make<Details::BoundDeconstructable<TypedInstanceModel<TInstance>, TDeconstructableProjector>>(
            this, pStr, deconstructableProjectorFunc
            );
    }

    //*************************************************
    // Function Binders (ExtensionModel style with instance argument):
    //

    // AddStringDisplayableFunction():
    //
    // Binds the string displayable implementation on this object to a method of signature const Object&, TInstance&, const Metadata&
    //
    template<typename TObj, typename TMeta, typename TRet, typename TClass, typename TData>
    void AddStringDisplayableFunction(_In_ TClass *pDerived,
                                      _In_ TRet (TClass::*stringConvClassMethod)(_In_ TObj, _In_ TData, _In_ TMeta))

    {
        static_assert(Details::is_object_v<TObj>, "Bound string converter must take (const) Object (&) as first argument");
        static_assert(Details::is_metadata_v<TMeta>, "Bound string converter must take (const) Metadata (&) as second argument");

        ClientEx::Details::DataModelReference stringLinkRef = this->GetLinkReference();
        auto stringProjectorFunc = [linkRef = std::move(stringLinkRef), pDerived, stringConvClassMethod]
            (TObj instanceObject, TMeta metadata) -> TRet
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*stringConvClassMethod)(instanceObject, pDerived->GetStoredInstance(instanceObject), metadata);
        };

        using TStringProjector = decltype(stringProjectorFunc);

        ComPtr<Details::BoundStringDisplayable<TClass, TStringProjector>> spStringDisplayable;
        spStringDisplayable = Make<Details::BoundStringDisplayable<TClass, TStringProjector>>(
            pDerived, stringProjectorFunc
            );
    }

    template<typename TObj, typename TMeta, typename TRet, typename TClass, typename TData>
    void AddStringDisplayableFunction(_In_ const TClass *pDerived,
                                      _In_ TRet (TClass::*stringConvClassMethod)(_In_ TObj, _In_ TData, _In_ TMeta) const)
    {
        AddStringDisplayableFunction(const_cast<TClass *>(pDerived), reinterpret_cast<TRet(TClass::*)(TObj, TData, TMeta)>(stringConvClassMethod));
    }

    // AddEquatableFunction():
    //
    // Adds the equatable implementation on this object to a method of signature bool(const Object&, TInstance&, const Object&)
    //
    template<typename TObj, typename TClass, typename TData, typename TOther>
    void AddEquatableFunction(_In_ TClass *pDerived,
                              _In_ bool (TClass::*equatableClassMethod)(_In_ TObj, _In_ TData, _In_ TOther))
    {
        static_assert(Details::is_object_v<TObj>, "Bound equatable function must take (const) Object (&) as first argument");

        ClientEx::Details::DataModelReference equatableLinkRef = this->GetLinkReference();
        auto equatableProjectorFunc = [linkRef = std::move(equatableLinkRef), pDerived, equatableClassMethod]
            (TObj instanceObject, TObj otherObj)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*equatableClassMethod)(instanceObject,
                                                     pDerived->GetStoredInstance(instanceObject),
                                                     ClientEx::UnboxObject<TOther>(otherObj));
        };

        using TEquatableProjector = decltype(equatableProjectorFunc);

        ComPtr<ClientEx::Details::BoundEquatable<TClass, TEquatableProjector>> spEquatable;
        spEquatable = Make<ClientEx::Details::BoundEquatable<TClass, TEquatableProjector>>(
            pDerived, equatableProjectorFunc
            );
    }

    // AddComparableFunction():
    //
    // Adds the equatable implementation on this object to a method of signature bool(const Object&, TInstance&, const Object&)
    //
    template<typename TObj, typename TClass, typename TData, typename TOther>
    void AddComparableFunction(_In_ TClass *pDerived,
                               _In_ int (TClass::*comparableClassMethod)(_In_ TObj, _In_ TData, _In_ TOther))
    {
        static_assert(Details::is_object_v<TObj>, "Bound equatable function must take (const) Object (&) as first argument");

        ClientEx::Details::DataModelReference comparableLinkRef = this->GetLinkReference();
        auto comparableProjectorFunc = [linkRef = std::move(comparableLinkRef), pDerived, comparableClassMethod]
            (TObj instanceObject, TObj otherObj)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*comparableClassMethod)(instanceObject,
                                                      pDerived->GetStoredInstance(instanceObject),
                                                      ClientEx::UnboxObject<TOther>(otherObj));
        };

        using TComparableProjector = decltype(comparableProjectorFunc);

        ComPtr<ClientEx::Details::BoundComparable<TClass, TComparableProjector>> spComparable;
        spComparable = Make<ClientEx::Details::BoundComparable<TClass, TComparableProjector>>(
            pDerived, comparableProjectorFunc
            );
    }

    // AddConstructableFunction():
    //
    // Binds the constructable implementation on this object to a method of signature TArgs...
    //
    template<typename TClass, typename TRet, typename... TArgs>
    void AddConstructableFunction(_In_ TClass *pDerived,
                                  _In_ TRet (TClass::*constructableMethod)(_In_ TArgs...))
    {
        ClientEx::Details::DataModelReference constructableLinkRef = this->GetLinkReference();
        auto constructableProjectorFunc = [linkRef = std::move(constructableLinkRef), pDerived, constructableMethod]
            (_In_ TArgs... args)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);

            auto instance = (pDerived->*constructableMethod)(std::forward<TArgs>(args)...);
            ClientEx::Object instanceObject = pDerived->CreateInstance(instance);
            return instanceObject;
        };

        using TConstructableProjector = decltype(constructableProjectorFunc);

        ComPtr<Details::BoundConstructable<TClass, TConstructableProjector, TArgs...>> spConstructable;
        spConstructable = Make<Details::BoundConstructable<TClass, TConstructableProjector, TArgs...>>(
            pDerived, constructableProjectorFunc
            );
    }

    template<typename TClass, typename TRet, typename... TArgs>
    void AddConstructableFunction(_In_ const TClass *pDerived,
                                  _In_ TRet (TClass::*constructableMethod)(_In_ TArgs...) const)
    {
        AddConstructableFunction(const_cast<TClass *>(pDerived), reinterpret_cast<TRet(TClass::*)(TArgs...)>(constructableMethod));
    }

    // AddDeconstructableFunction():
    //
    // Binds the deconstructable implementation on this object to a method of signature
    // std::tuple<TArgs...>(const Object&, TInstance&)
    //
    template<typename TStr, typename TObj, typename TClass, typename TData, typename... TArgs>
    void AddDeconstructableFunction(_In_ TStr&& constructableModelName,
                                    _In_ TClass *pDerived,
                                    _In_ std::tuple<TArgs...> (TClass::*deconstructableMethod)(_In_ TObj, _In_ TData))
    {
        static_assert(Details::is_object_v<TObj>, "Bound deconstructor function must take (const) Object (&) as first argument");

        ClientEx::Details::DataModelReference deconstructableLinkRef = this->GetLinkReference();
        auto deconstructableProjectorFunc = [linkRef = std::move(deconstructableLinkRef), pDerived, deconstructableMethod]
            (TObj instanceObject)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);

            return (pDerived->*deconstructableMethod)(instanceObject, pDerived->GetStoredInstance(instanceObject));
        };

        using TDeconstructableProjector = decltype(deconstructableProjectorFunc);

        ComPtr<Details::BoundDeconstructable<TypedInstanceModel<TInstance>, TDeconstructableProjector>> spDeconstructable;
        spDeconstructable = Make<Details::BoundDeconstructable<TypedInstanceModel<TInstance>, TDeconstructableProjector>>(
            this, ClientEx::Details::ExtractString(constructableModelName), deconstructableProjectorFunc
            );
    }

    template<typename TStr, typename TObj, typename TClass, typename TData, typename... TArgs>
    void AddDeconstructableFunction(_In_ TStr&& constructableModelName,
                                    _In_ const TClass *pDerived,
                                    _In_ std::tuple<TArgs...> (TClass::*deconstructableMethod)(_In_ TObj, _In_ TData) const)
    {
        return AddDeconstructableFunction(std::forward<TStr>(constructableModelName),
                                          const_cast<TClass *>(pDerived),
                                          reinterpret_cast<std::tuple<TArgs...> (TClass::*)(_In_ TObj, _In_ TData)>(deconstructableMethod));
    }

    // AddGeneratorFunction():
    //
    // Adds the iterable implementation on this object to the generator (or iterable) returned from the
    // bound class method.  The supplied generator must be copyable into the resulting data model iterator.
    //
    template<typename TObj, typename TGen, typename TClass, typename TData>
    void AddGeneratorFunction(_In_ TClass *pDerived,
                              _In_ TGen (TClass::*genClassMethod)(_In_ TObj, _In_ TData))
    {
        static_assert(Details::is_object_v<TObj>, "Bound generator function must take (const) Object (&) as first argument");

        //
        // genProjectorFunc must preserve the l-value refness of its return value:
        //     - If it returns a T&, preserve it into the bound iterator
        //     - If it returns a T, T&&, move it into the bound iterator
        //
        using TRet = TGen; // decltype((pDerived->*genClassMethod)(ClientEx::Object(), std::declval<InstanceType>()));
        using TRetBaseType = std::decay_t<TRet>;
        using TLamRet = std::conditional_t<std::is_lvalue_reference_v<TRet>, TRetBaseType&, TRetBaseType>;

        ClientEx::Details::DataModelReference genLinkRef = this->GetLinkReference();
        auto genProjectorFunc = [linkRef = std::move(genLinkRef), pDerived, genClassMethod](TObj instanceObject) -> TLamRet
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*genClassMethod)(instanceObject, pDerived->GetStoredInstance(instanceObject));
        };

        using TItem = decltype(*(std::declval<TGen>().begin()));
        auto itemProjectorFunc = [](_In_ TItem eref) { return eref; };

        using TGenProjector = decltype(genProjectorFunc);
        using TItemProjector = decltype(itemProjectorFunc);

        ClientEx::Details::DataModelReference iterLinkRef = this->GetLinkReference();
        ComPtr<ClientEx::Details::BoundIterable<TClass, TGenProjector, TItemProjector>> spIterable;

        static_assert(std::is_base_of_v<std::decay_t<decltype(*this)>, std::decay_t<TClass>>,
                      "Implementation class must derive from ProviderEx:: model class");

        TClass *pDerivedThis = static_cast<TClass *>(this);
        spIterable = Make<ClientEx::Details::BoundIterable<TClass, TGenProjector, TItemProjector>>(
            std::move(iterLinkRef), pDerivedThis, genProjectorFunc, itemProjectorFunc
            );
    }

    // AddReadOnlyIndexableGeneratorFunction():
    //
    // Adds the iterable and indexable implementation on this object to the generator (or iterable) returned from
    // the first bound class method.  The supplied generator must return IndexableValue<TValue, TIndicies...>.  The
    // TIndicies... must match the indicies arguments of the bound indexer method.
    //
    template<typename TObjGen, typename TObjGet, typename TGen, typename TClass, typename TData, typename TValue, typename... TIndicies>
    void AddReadOnlyIndexableGeneratorFunction(_In_ TClass *pDerived,
                                               _In_ TGen (TClass::*generatorMethod)(_In_ TObjGen, _In_ TData),
                                               _In_ TValue (TClass::*getAtMethod)(_In_ TObjGet, _In_ TData, _In_ TIndicies... indicies))
    {
        static_assert(Details::is_object_v<TObjGen>, "Bound generator function must take (const) Object (&) as first argument");
        static_assert(Details::is_object_v<TObjGet>, "Bound indexer function must take (const) Object (&) as first argument");

        using TIdx = ClientEx::IndexedValue<TValue, TIndicies...>;
        using TIVal = typename TIdx::ValueType;
        using TGVal = decltype(*(std::declval<TGen>().begin()));
        using TIdxBase = std::decay_t<TIdx>;
        using TGValBase = std::decay_t<TGVal>;
        static_assert(std::is_same_v<TIdxBase, TGValBase>, "Type mismatch between iterator indicies and indexer indicies");

        //
        // genProjectorFunc must preserve the l-value refness of its return value:
        //     - If it returns a T&, preserve it into the bound iterator
        //     - If it returns a T, T&&, move it into the bound iterator
        //
        using TRet = TGen;
        using TRetBaseType = std::decay_t<TRet>;
        using TLamRet = std::conditional_t<std::is_lvalue_reference_v<TRet>, TRetBaseType&, TRetBaseType>;

        ClientEx::Details::DataModelReference genLinkRef = this->GetLinkReference();
        auto genProjectorFunc = [linkRef = std::move(genLinkRef), pDerived, generatorMethod](TObjGen instanceObject) -> TLamRet
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*generatorMethod)(instanceObject, pDerived->GetStoredInstance(instanceObject));
        };

        using TItem = decltype(*(std::declval<TGen>().begin()));
        auto itemProjectorFunc = [](_In_ TItem eref) { return eref; };

        using TGenProjector = decltype(genProjectorFunc);
        using TItemProjector = decltype(itemProjectorFunc);

        ClientEx::Details::DataModelReference getLinkRef = this->GetLinkReference();
        auto getProjectorFunc = [linkRef = std::move(getLinkRef), pDerived, getAtMethod](_In_ TObjGet instanceObject, _In_ TIndicies... indicies)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*getAtMethod)(instanceObject, pDerived->GetStoredInstance(instanceObject), std::forward<TIndicies>(indicies)...);
        };

        ClientEx::Details::DataModelReference setLinkRef = this->GetLinkReference();
        auto setProjectorFunc = [linkRef = std::move(setLinkRef), pDerived, getAtMethod](_In_ const ClientEx::Object& /*contextObj*/,
                                                                                         _In_ const ClientEx::Object& /*value*/,
                                                                                         _In_ TIndicies... /*indicies*/)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            throw ClientEx::not_implemented();
        };

        using TGetAtProjector = decltype(getProjectorFunc);
        using TSetAtProjector = decltype(setProjectorFunc);

        ClientEx::Details::DataModelReference iterLinkRef = this->GetLinkReference();
        ComPtr<ClientEx::Details::BoundIterableWithIndexable<TClass, TGenProjector, TItemProjector, TGetAtProjector, TSetAtProjector>> spIterableIndexable;

        static_assert(std::is_base_of_v<std::decay_t<decltype(*this)>, std::decay_t<TClass>>,
                      "Implementation class must derive from ProviderEx:: model class");

        TClass *pDerivedThis = static_cast<TClass *>(this);
        spIterableIndexable = Make<ClientEx::Details::BoundIterableWithIndexable<TClass, TGenProjector, TItemProjector, TGetAtProjector, TSetAtProjector>>(
            std::move(iterLinkRef), pDerivedThis, genProjectorFunc, itemProjectorFunc, getProjectorFunc, setProjectorFunc
            );
    }

    // AddIndexableGeneratorFunction():
    //
    // Adds the iterable and indexable implementation on this object to the generator (or iterable) returned from
    // the first bound class method.  The supplied generator must return IndexableValue<TValue, TIndicies...>.  The
    // TIndicies... must match the indicies arguments of the bound indexer method.
    //
    template<typename TObjGen, typename TObjGet, typename TObjSet,
             typename TGen, typename TClass, typename TData1, typename TData2, typename TData3,
             typename TGetValue, typename TSetValue, typename... TIndicies>
    void AddIndexableGeneratorFunction(_In_ TClass *pDerived,
                                       _In_ TGen (TClass::*generatorMethod)(_In_ TObjGen, _In_ TData1),
                                       _In_ TGetValue (TClass::*getAtMethod)(_In_ TObjGet, _In_ TData2, _In_ TIndicies...),
                                       _In_ void (TClass::*setAtMethod)(_In_ TObjSet, _In_ TData3, _In_ TSetValue, _In_ TIndicies...))

    {
        static_assert(Details::is_object_v<TObjGen>, "Bound generator function must take (const) Object (&) as first argument");
        static_assert(Details::is_object_v<TObjGet>, "Bound indexer function must take (const) Object (&) as first argument");
        static_assert(Details::is_object_v<TObjSet>, "Bound indexer function must take (const) Object (&) as first argument");

        using TIdx = ClientEx::IndexedValue<TGetValue, TIndicies...>;
        using TIVal = typename TIdx::ValueType;
        using TGVal = decltype(*(std::declval<TGen>().begin()));
        using TIdxBase = std::decay_t<TIdx>;
        using TGValBase = std::decay_t<TGVal>;
        static_assert(std::is_same_v<TIdxBase, TGValBase>, "Type mismatch between iterator indicies and indexer indicies");

        //
        // genProjectorFunc must preserve the l-value refness of its return value:
        //     - If it returns a T&, preserve it into the bound iterator
        //     - If it returns a T, T&&, move it into the bound iterator
        //
        using TRet = TGen;
        using TRetBaseType = std::decay_t<TRet>;
        using TLamRet = std::conditional_t<std::is_lvalue_reference_v<TRet>, TRetBaseType&, TRetBaseType>;

        ClientEx::Details::DataModelReference genLinkRef = this->GetLinkReference();
        auto genProjectorFunc = [linkRef = std::move(genLinkRef), pDerived, generatorMethod](const ClientEx::Object& instanceObject) -> TLamRet
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*generatorMethod)(instanceObject, pDerived->GetStoredInstance(instanceObject));
        };

        using TItem = decltype(*(std::declval<TGen>().begin()));
        auto itemProjectorFunc = [](_In_ TItem eref) { return eref; };

        using TGenProjector = decltype(genProjectorFunc);
        using TItemProjector = decltype(itemProjectorFunc);

        ClientEx::Details::DataModelReference getLinkRef = this->GetLinkReference();
        auto getProjectorFunc = [linkRef = std::move(getLinkRef), pDerived, getAtMethod](_In_ const ClientEx::Object& instanceObject,
                                                                                         _In_ TIndicies... indicies)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            return (pDerived->*getAtMethod)(instanceObject, pDerived->GetStoredInstance(instanceObject), std::forward<TIndicies>(indicies)...);
        };

        ClientEx::Details::DataModelReference setLinkRef = this->GetLinkReference();
        auto setProjectorFunc = [linkRef = std::move(setLinkRef), pDerived, setAtMethod](_In_ const ClientEx::Object& instanceObject,
                                                                                         _In_ TSetValue value,
                                                                                         _In_ TIndicies... indicies)
        {
            ClientEx::Details::ThrowIfDetached(linkRef);
            (pDerived->*setAtMethod)(instanceObject,
                                     pDerived->GetStoredInstance(instanceObject),
                                     std::forward<TSetValue>(value),
                                     std::forward<TIndicies>(indicies)...);
        };

        using TGetAtProjector = decltype(getProjectorFunc);
        using TSetAtProjector = decltype(setProjectorFunc);

        ClientEx::Details::DataModelReference iterLinkRef = this->GetLinkReference();
        ComPtr<ClientEx::Details::BoundIterableWithIndexable<TClass, TGenProjector, TItemProjector, TGetAtProjector, TSetAtProjector>> spIterableIndexable;

        static_assert(std::is_base_of_v<std::decay_t<decltype(*this)>, std::decay_t<TClass>>,
                      "Implementation class must derive from ProviderEx:: model class");

        TClass *pDerivedThis = static_cast<TClass *>(this);
        spIterableIndexable = Make<ClientEx::Details::BoundIterableWithIndexable<TClass, TGenProjector, TItemProjector, TGetAtProjector, TSetAtProjector>>(
            std::move(iterLinkRef), pDerivedThis, genProjectorFunc, itemProjectorFunc, getProjectorFunc, setProjectorFunc
            );
    }

private:

    // @TODO: Why is _In_ StorageType *pStorage not okay below.  It's a typedef in the base class.  The compiler
    //        blows up on this.
    //
    template<typename TStorage>
    ClientEx::Object ObjectForStorage(_In_ TStorage *pStorage)
    {
        ComPtr<IModelObject> spObject;
        ClientEx::CheckHr(ClientEx::GetManager()->CreateSyntheticObject(nullptr, &spObject));
        ClientEx::CheckHr(spObject->AddParentModel(this->GetObject(), nullptr, false));
        ClientEx::CheckHr(spObject->SetContextForDataModel(this->GetObject(), pStorage));
        return ClientEx::Object(std::move(spObject));
    }

    template<typename... TArgs>
    void CompleteTypedInstanceModelInitialization(_In_ TArgs&&... registrations)
    {
        //
        // The first NamedModelRegistration is the canonical name.  Extract it.
        //
        Details::VerifyTypedInstanceRegistrations<TArgs...>::Verify();
        Details::ExtensionNameAcquisition<TArgs...>::FillName(this->m_modelName, registrations...);

        //
        // Keep a list of the registrations, heap allocated, within our object.  The registration record
        // only gets moved into this list once it has SUCCESSFULLY applied.
        //
        // Destruction of this list will unapply everything.
        //
        using RegistrationList = Details::ExtensionRegistrationList<TArgs...>;
        RegistrationList *pList = new RegistrationList(this->GetObject());
        std::unique_ptr<Details::ExtensionRegistrationListBase> spRegistrationList(pList);
        Details::ExtensionApplication<RegistrationList, 0, TArgs...>::Apply(*pList, std::forward<TArgs>(registrations)...);
        m_spRegistrationList = std::move(spRegistrationList);
    }

    std::unique_ptr<Details::ExtensionRegistrationListBase> m_spRegistrationList;
};

//**************************************************************************
// Forward Implementations:
//

template<typename TInstance>
template<typename TItemProjector>
void IterableTypedInstanceModel<TInstance>::BindIterator(_In_ const TItemProjector& itemProjectorFunc)
{
    //
    // The generator for this is simply a returned binding of the instance data.
    //
    ClientEx::Details::DataModelReference genLinkRef = this->GetLinkReference();
    auto genProjectorFunc = [linkRef = std::move(genLinkRef), this](_In_ const ClientEx::Object& instanceObject) -> TInstance&
    {
        ClientEx::Details::ThrowIfDetached(linkRef);
        return this->GetStoredInstance(instanceObject);
    };

    using TGenProjector = decltype(genProjectorFunc);

    ClientEx::Details::DataModelReference iterLinkRef = this->GetLinkReference();
    ComPtr<ClientEx::Details::BoundIterable<TypedInstanceModel<TInstance>, TGenProjector, TItemProjector>> spIterable;

    TypedInstanceModel<TInstance> *pDerivedThis = static_cast<TypedInstanceModel<TInstance> *>(this);
    spIterable = Make<ClientEx::Details::BoundIterable<TypedInstanceModel<TInstance>, TGenProjector, TItemProjector>>(
        std::move(iterLinkRef), pDerivedThis, genProjectorFunc, itemProjectorFunc
        );
}

}; // ProviderEx

} // DataModel
} // Debugger

#endif // _DBGMODELCLIENTEX_H_

