#ifndef ANTI_DEBUG_SDK_ADD
#define ANTI_DEBUG_SDK_ADD 1
#include "struct.h"
#include "code_gen_help.h"

namespace anti_debug_sdk_util
{

	class anti_debug_sdk_util
	{
	private:
		PIMAGE_NT_HEADERS  nt_headers = NULL;
		PIMAGE_SECTION_HEADER sections = NULL;

		auto va_to_rva(uint64_t va) -> uint64_t
		{
			for (size_t i = NULL; i < nt_headers->FileHeader.NumberOfSections; i++)
			{
				if (sections[i].PointerToRawData <= va && (sections[i].PointerToRawData + sections[i].SizeOfRawData) > va)
				{
					return va - sections[i].PointerToRawData + sections[i].VirtualAddress;
				}
			}
			return NULL;
		}

		NO_INLINE auto add_list_ref_imp(PE_INFO* pe, CONST CHAR* name_dll, CONST CHAR* name_imp, uint32_t code_rva) -> BOOLEAN
		{

			BOOLEAN is_add_ref = FALSE;
			for (size_t i = NULL; !is_add_ref && i < pe->import_info.imp_dis.size(); i++)
			{
				if (!_strcmpi(name_dll, pe->import_info.imp_dis[i].name_dll) && !_strcmpi(name_imp, pe->import_info.imp_dis[i].name_api))
				{
					pe->import_info.imp_dis[i].code_rva.push_back(code_rva);
					is_add_ref = TRUE;
				}
			}
			for (size_t i = NULL; !is_add_ref && i < pe->import_info.imp_manual.size(); i++)
			{
				if (!_strcmpi(name_dll, pe->import_info.imp_manual[i].name_dll) && !_strcmpi(name_imp, pe->import_info.imp_manual[i].name_api))
				{
					pe->import_info.imp_manual[i].code_rva.push_back(code_rva);
					is_add_ref = TRUE;
				}
			}
			return is_add_ref;
		}

		auto anti_debug_check_x64(PE_INFO* pe, CodeHolder* code, x86::Assembler* ass, int32_t va) -> VOID
		{
			uint32_t offset_max_stack = NULL;
			uint32_t offset_cur_stack = NULL;
			Label detect = ass->newLabel();
			Label skip_check_thread = ass->newLabel();
			Label exit_check = ass->newLabel();
			ZydisRegister reg_use = { ZYDIS_REGISTER_NONE };

			if (pe->file_info.type_file == STATUS_DLL || pe->file_info.type_file == STATUS_EXE)
			{
				cg_util::ger_rand_reg(&reg_use, sizeof(PVOID));


				offset_max_stack = sizeof(PVOID) * 7;
				offset_cur_stack = offset_max_stack - sizeof(PVOID);

				x86::Mem mem_segment = x86::qword_ptr(0x60);
				mem_segment.setSegment(x86::SReg::Id::kIdGs);

				cg_util::push_eflag(ass);
				cg_util::push_all_reg(ass, TRUE);

				ass->sub(current_vsp, offset_max_stack);
				ass->mov(x86::qword_ptr(current_vsp, offset_cur_stack), FALSE);

				ass->mov(cg_util::reg_conv(reg_use), mem_segment);
				ass->cmp(x86::byte_ptr(cg_util::reg_conv(reg_use), offsetof(_PEB, BeingDebugged)), NULL);
				ass->jne(detect);

				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_RCX), NtCurrentThread);
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_EDX), ThreadHideFromDebugger);
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_R8), NULL);
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_R9D), NULL);

				add_list_ref_imp(pe, "NTDLL.DLL", "NtSetInformationThread", va_to_rva(va) + code->codeSize());
				ass->call(x86::qword_ptr(current_vip));

				ass->cmp(cg_util::reg_conv(ZYDIS_REGISTER_EAX), NULL);
				ass->js(skip_check_thread);

				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_RCX), NtCurrentThread);
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_EDX), ThreadHideFromDebugger);
				ass->mov(x86::byte_ptr(current_vsp, offset_cur_stack - sizeof(PVOID)), NULL);
				ass->lea(cg_util::reg_conv(ZYDIS_REGISTER_R8), x86::qword_ptr(current_vsp, offset_cur_stack - sizeof(PVOID)));
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_R9D), sizeof(BOOLEAN));
				ass->mov(x86::dword_ptr(current_vsp, offset_cur_stack - sizeof(PVOID) * 2), NULL);

				add_list_ref_imp(pe, "NTDLL.DLL", "NtQueryInformationThread", va_to_rva(va) + code->codeSize());
				ass->call(x86::qword_ptr(current_vip));

				ass->cmp(cg_util::reg_conv(ZYDIS_REGISTER_EAX), NULL);
				ass->js(skip_check_thread);

				ass->cmp(x86::byte_ptr(current_vsp, offset_cur_stack - sizeof(PVOID)), TRUE);
				ass->jne(detect);


				ass->bind(skip_check_thread);

				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_RCX), NtCurrentProcess);
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_EDX), ProcessDebugObjectHandle);
				ass->mov(x86::dword_ptr(current_vsp, offset_cur_stack - sizeof(PVOID)), NULL);
				ass->lea(cg_util::reg_conv(ZYDIS_REGISTER_R8), x86::qword_ptr(current_vsp, offset_cur_stack - sizeof(PVOID)));
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_R9D), sizeof(PVOID));
				ass->mov(x86::dword_ptr(current_vsp, offset_cur_stack - sizeof(PVOID) * 2), NULL);

				add_list_ref_imp(pe, "NTDLL.DLL", "NtQueryInformationProcess", va_to_rva(va) + code->codeSize());
				ass->call(x86::qword_ptr(current_vip));

				ass->cmp(cg_util::reg_conv(ZYDIS_REGISTER_EAX), STATUS_PORT_NOT_SET);
				ass->jne(detect);
				ass->cmp(x86::dword_ptr(current_vsp, offset_cur_stack - sizeof(PVOID)), NULL);
				ass->jne(detect);

				//Detect TitanHide
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_RCX), NULL);
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_EDX), ProcessDebugObjectHandle);
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_R8), 1);
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_R9D), sizeof(PVOID));
				ass->mov(x86::dword_ptr(current_vsp, offset_cur_stack - sizeof(PVOID) * 2), NULL);

				add_list_ref_imp(pe, "NTDLL.DLL", "NtQueryInformationProcess", va_to_rva(va) + code->codeSize());
				ass->call(x86::qword_ptr(current_vip));
				ass->cmp(cg_util::reg_conv(ZYDIS_REGISTER_EAX), STATUS_INVALID_HANDLE);
				ass->je(detect);


				ass->jmp(exit_check);

				ass->bind(detect);
				ass->mov(x86::byte_ptr(current_vsp, offset_cur_stack), TRUE);

				ass->bind(exit_check);
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_AL).r8(), x86::byte_ptr(current_vsp, offset_cur_stack));

				ass->add(current_vsp, offset_max_stack);
				cg_util::pop_all_reg(ass, TRUE);
				cg_util::pop_eflag(ass);
			}
			else if (pe->file_info.type_file == STATUS_DRIVER)
			{
				offset_max_stack = sizeof(PVOID) * 7;
				offset_cur_stack = offset_max_stack - sizeof(PVOID);

				cg_util::push_eflag(ass);
				cg_util::push_all_reg(ass, TRUE);

				ass->mov(x86::dword_ptr(current_vsp, offset_cur_stack - sizeof(PVOID)), NULL);
				ass->mov(x86::byte_ptr(current_vsp, offset_cur_stack), FALSE);

				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_ECX), SystemKernelDebuggerInformation);
				ass->lea(cg_util::reg_conv(ZYDIS_REGISTER_RDX), x86::qword_ptr(current_vsp, offset_cur_stack - sizeof(PVOID)));
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_R8D), sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION));
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_R9), NULL);

				add_list_ref_imp(pe, "ntoskrnl.exe", "NtQuerySystemInformation", va_to_rva(va) + code->codeSize());
				ass->call(x86::qword_ptr(current_vip));
				ass->js(exit_check);

				ass->cmp(x86::byte_ptr(current_vsp, offset_cur_stack - sizeof(PVOID) + offsetof(SYSTEM_KERNEL_DEBUGGER_INFORMATION, KernelDebuggerEnabled)), TRUE);
				ass->jne(exit_check);
				ass->cmp(x86::byte_ptr(current_vsp, offset_cur_stack - sizeof(PVOID) + offsetof(SYSTEM_KERNEL_DEBUGGER_INFORMATION, KernelDebuggerNotPresent)), FALSE);
				ass->jne(exit_check);
				ass->jmp(detect);


				ass->bind(detect);
				ass->mov(x86::byte_ptr(current_vsp, offset_cur_stack), TRUE);
				//ass->jmp(exit_check);

				ass->bind(exit_check);
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_AL).r8(), x86::byte_ptr(current_vsp, offset_cur_stack));

				cg_util::pop_all_reg(ass, TRUE);
				cg_util::pop_eflag(ass);
			}
			else
			{
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_AL).r8(), FALSE);
			}
			ass->ret();
		}

		auto anti_debug_check_x32(PE_INFO* pe, x86::Assembler* ass) -> VOID
		{
			if (pe->file_info.type_file == STATUS_DLL || pe->file_info.type_file == STATUS_EXE)
			{
				x86::Mem mem_segment = x86::dword_ptr(0x30);
				mem_segment.setSegment(x86::SReg::Id::kIdFs);

				ass->mov(asmjit::x86::eax, mem_segment);
				ass->movzx(cg_util::reg_conv(ZYDIS_REGISTER_EAX), x86::byte_ptr(cg_util::reg_conv(ZYDIS_REGISTER_EAX), offsetof(_PEB, BeingDebugged)));
			}
			else
			{
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_AL).r8(), FALSE);
			}
			ass->ret();
		}
	public:
		NO_INLINE auto add_code(PE_INFO* pe, uint32_t va) -> uint32_t
		{
			uint32_t code_size = NULL;
			PVOID code_gen = NULL;
			JitRuntime rt;
			CodeHolder code;

			nt_headers = pe->file_info.headers;
			sections = pe->file_info.sections;

			if (!va)
			{
				return FALSE;
			}

			code.init(rt.environment(), rt.cpuFeatures());
			x86::Assembler ass(&code);

#ifdef _WIN64
			anti_debug_check_x64(pe, &code, &ass, va);
#else
			anti_debug_check_x32(pe, &ass);
#endif // !_WIN64

			if (rt.add(&code_gen, &code))//cg_alloce - alloceted code
			{
				return FALSE;
			}
			code_size = code.codeSize();
			memcpy(reinterpret_cast<CHAR*>(pe->file_info.alloced_mem) + va, code_gen, code.codeSize());


			rt.release(code_gen);
			code.~CodeHolder();
			ass.~Assembler();
			return  code_size;
		}

		auto update_info(PE_INFO* pe, uint32_t va) -> VOID
		{
			nt_headers = pe->file_info.headers;
			sections = pe->file_info.sections;

			for (size_t i = NULL; i < pe->import_info.imp_sdk.size(); i++)
			{
				if (pe->import_info.imp_sdk[i].sdk_type == sdk_anti_debug)
				{
					pe->import_info.imp_sdk[i].import_rva_new = va_to_rva(va);
				}
			}
		}

		auto count_exist_sdk(PE_INFO* pe) -> uint32_t
		{
			uint32_t count = NULL;
			for (size_t i = NULL; i < pe->import_info.imp_sdk.size(); i++)
			{
				if (pe->import_info.imp_sdk[i].sdk_type == sdk_anti_debug)
				{
					count++;
				}
			}
			return count;
		}
	};

}
#endif // !ANTI_DEBUG_SDK_ADD
