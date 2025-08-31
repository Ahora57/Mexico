#ifndef ANTI_VM_SDK_ADD
#define ANTI_VM_SDK_ADD 1
#include "struct.h"
#include "code_gen_help.h"

namespace anti_vm_sdk_util
{

	class anti_vm_sdk_util
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

		auto anti_vm_check(PE_INFO* pe, x86::Assembler* ass) -> VOID
		{
			cg_util::push_correct(ass, ZYDIS_REGISTER_ECX);
			cg_util::push_correct(ass, ZYDIS_REGISTER_EBX);
			cg_util::push_correct(ass, ZYDIS_REGISTER_EDX);

			ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_EAX), 1);
			ass->cpuid();
			ass->sar(cg_util::reg_conv(ZYDIS_REGISTER_ECX), 31);
			ass->and_(cg_util::reg_conv(ZYDIS_REGISTER_ECX), 1);
			ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_EAX).r8(), cg_util::reg_conv(ZYDIS_REGISTER_ECX).r8());

			cg_util::pop_correct(ass, ZYDIS_REGISTER_EDX);
			cg_util::pop_correct(ass, ZYDIS_REGISTER_EBX);
			cg_util::pop_correct(ass, ZYDIS_REGISTER_ECX);

			ass->ret();


		}

	public:
		auto add_code(PE_INFO* pe, uint32_t va) -> uint32_t
		{
			uint32_t code_size = NULL;
			uint32_t crc_table[256] = { NULL };
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

			anti_vm_check(pe, &ass);
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
				if (pe->import_info.imp_sdk[i].sdk_type == sdk_anti_vm)
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
				if (pe->import_info.imp_sdk[i].sdk_type == sdk_anti_vm)
				{
					count++;
				}
			}
			return count;
		}
	};

}
#endif // !ANTI_VM_SDK_ADD
