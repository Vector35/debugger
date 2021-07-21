#include "debugadapter.h"
#include <binaryninjacore.h>
#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>
#include <highlevelilinstruction.h>

bool DebugAdapter::StepOut() {
    using namespace BinaryNinja;

    const auto last_rsp = this->ReadRegister("rsp");
    auto current_rsp = this->ReadRegister("rsp");
    while (last_rsp.m_value <= current_rsp.m_value) {
        current_rsp = this->ReadRegister("rsp");

        const auto instruction_offset = this->ReadRegister("rip").m_value;
        if ( !instruction_offset )
            return false;

        const auto architecture = Architecture::GetByName( this->GetTargetArchitecture());
        if ( !architecture )
            return false;

        const auto data = this->ReadMemoryTy<std::array<std::uint8_t, 16>>( instruction_offset );
        if ( !data.has_value())
            return false;

        const auto data_value = data.value();
        std::size_t size{ data_value.size() };
        std::vector<BinaryNinja::InstructionTextToken> instruction_tokens{};
        if ( !architecture->GetInstructionText( data.value().data(), instruction_offset, size, instruction_tokens )) {
            printf( "failed to disassemble\n" );
            return false;
        }

        auto data_buffer = DataBuffer( data_value.data(), size );
        Ref<BinaryData> bd = new BinaryData( new FileMetadata(), data_buffer );
        Ref<BinaryView> bv;
        for ( const auto& type : BinaryViewType::GetViewTypes()) {
            if ( type->IsTypeValidForData( bd ) && type->GetName() == "Raw" ) {
                bv = type->Create( bd );
                break;
            }
        }

        bv->UpdateAnalysisAndWait();

        Ref<Platform> plat = nullptr;
        auto arch_list = Platform::GetList();
        for ( const auto& arch : arch_list ) {
            constexpr auto os =
#ifdef WIN32
                    "windows";
#else
            "linux";
#endif

            using namespace std::string_literals;
            if ( arch->GetName() == os + "-"s + this->GetTargetArchitecture()) {
                plat = arch;
                break;
            }
        }

        bv->AddFunctionForAnalysis( plat, 0 );

        bool is_ret{ false };
        for ( auto& func : bv->GetAnalysisFunctionList()) {
            if ( is_ret )
                break;

            Ref<LowLevelILFunction> llil = func->GetLowLevelIL();
            if ( !llil )
                continue;

            for ( const auto& llil_block : llil->GetBasicBlocks()) {
                if ( is_ret )
                    break;

                for ( std::size_t llil_index = llil_block->GetStart();
                      llil_index < llil_block->GetEnd(); llil_index++ ) {
                    const auto current_llil_instruction = llil->GetInstruction( llil_index );
                    const auto op = current_llil_instruction.operation;
                    if ( op == LLIL_RET ) {
                        is_ret = true;
                        break;
                    }
                }
            }
        }

        if ( is_ret ) {
            this->StepInto();
            return true;
        }
        else
            this->StepInto();
    }

    return false;
}
