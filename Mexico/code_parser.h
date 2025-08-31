#ifndef CODE_PARSE
#define CODE_PARSE

#include "struct.h"
#include "disassembly_util.h"

#ifndef MAX_ALINGHT_BP
#define MAX_ALINGHT_BP 2
#endif // !MAX_ALINGHT_BP

namespace code_parse
{

	class code_parse
	{
	private:
		uint64_t image_base = NULL;
		PVOID memory_file = NULL;
		PVOID memory_module = NULL;

		PIMAGE_NT_HEADERS  headers = NULL;
		PIMAGE_SECTION_HEADER sections = NULL;

		auto malloc(size_t size) -> PVOID
		{
			return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		}

		VOID free(PVOID ptr)
		{
			if (ptr)
				VirtualFree(ptr, NULL, MEM_RELEASE);
		}


		auto rva_to_va(uint64_t rva) -> uint64_t
		{

			headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(memory_file) + static_cast<PIMAGE_DOS_HEADER>(memory_file)->e_lfanew);
			sections = IMAGE_FIRST_SECTION(headers);

			for (size_t i = NULL; i < headers->FileHeader.NumberOfSections; i++)
			{
				if (sections[i].VirtualAddress <= rva && (sections[i].VirtualAddress + sections[i].Misc.VirtualSize) >= rva)
				{
					return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
				}
			}
			return NULL;
		}

		auto va_to_rva(uint64_t va) -> uint64_t
		{

			headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(memory_file) + static_cast<PIMAGE_DOS_HEADER>(memory_file)->e_lfanew);
			sections = IMAGE_FIRST_SECTION(headers);

			for (size_t i = NULL; i < headers->FileHeader.NumberOfSections; i++)
			{
				if ((sections[i].PointerToRawData <= va) && (sections[i].PointerToRawData + sections[i].SizeOfRawData) >= va)
				{
					return va + sections[i].VirtualAddress - sections[i].PointerToRawData;
				}
			}
			return NULL;
		}

		auto no_exist_use_imp(PE_INFO* pe, uint64_t rva_use_imp) -> BOOLEAN
		{
			for (size_t i = NULL; i < pe->import_info.imp_dis.size(); i++)
			{
				for (size_t j = NULL; j < pe->import_info.imp_dis[i].code_rva.size(); j++)
				{
					if (pe->import_info.imp_dis[i].code_rva[j] == rva_use_imp)
					{
						return FALSE;
					}
				}
			}
			return TRUE;
		}

		auto is_import(PE_INFO* pe, LIST_DIS_API* dis_api, CHAR* cur_addr, uint64_t offset_point) -> BOOLEAN
		{
			size_t addr_imp = NULL;
#ifndef _WIN64
			addr_imp = offset_point - pe->file_info.headers->OptionalHeader.ImageBase;
#else
			addr_imp = va_to_rva(reinterpret_cast<uint64_t>(cur_addr) - reinterpret_cast<uint64_t>(memory_file)) + offset_point;
#endif // !_WIN64


			for (size_t i = NULL; i < pe->import_info.imp.size(); i++)
			{
				if (pe->import_info.imp[i].import_rva == addr_imp)
				{
					for (size_t j = NULL; j < pe->import_info.imp_dis.size(); j++)
					{
						if (pe->import_info.imp_dis[j].import_rva == addr_imp)
						{
							pe->import_info.imp_dis[j].code_rva.push_back(va_to_rva(cur_addr - memory_file));
							return TRUE;
						}
					}
					dis_api->hint = pe->import_info.imp[i].hint;
					dis_api->sdk_type = pe->import_info.imp[i].sdk_type;
					dis_api->code_rva.push_back(va_to_rva(cur_addr - memory_file));
					dis_api->import_rva = pe->import_info.imp[i].import_rva;

					dis_api->is_ordinal = pe->import_info.imp[i].is_ordinal;
					dis_api->ordinal = pe->import_info.imp[i].ordinal;

					memcpy(dis_api->name_dll, pe->import_info.imp[i].name_dll, strlen(pe->import_info.imp[i].name_dll));
					memcpy(dis_api->name_api, pe->import_info.imp[i].name_api, strlen(pe->import_info.imp[i].name_api));
					if (dis_api->sdk_type == sdk_unk)
					{
						pe->import_info.imp_dis.push_back(*dis_api);
					}
					else
					{
						pe->import_info.imp_sdk.push_back(*dis_api);
					}

					return TRUE;
				}
			}
			return FALSE;
		}



		auto is_export(PE_INFO* pe, LIST_DIS_EXP* dis_api, CHAR* cur_addr, uint64_t offset_point) -> BOOLEAN
		{
			uint64_t addr_imp = NULL;
			addr_imp = va_to_rva(reinterpret_cast<uint64_t>(cur_addr) - reinterpret_cast<uint64_t>(memory_file)) + offset_point;

			for (size_t i = NULL; i < pe->export_info.exp.size(); i++)
			{
				if (pe->export_info.exp[i].export_rva == addr_imp)
				{
					dis_api->code_va = cur_addr - memory_file;
					dis_api->code_rva = va_to_rva(cur_addr - memory_file);
					dis_api->export_va = pe->export_info.exp[i].export_va;
					dis_api->export_rva = pe->export_info.exp[i].export_rva;

					memcpy(dis_api->name_exp, pe->export_info.exp[i].name_exp, strlen(pe->import_info.imp[i].name_dll));

					return TRUE;
				}
			}
			return FALSE;
		}

		NO_INLINE auto get_len_fun(CHAR* runtime_address) -> uint32_t
		{

			uint8_t* mem = NULL;
			uint8_t* mem_pos = NULL;
			uint8_t* mem_max_pos = NULL;
			DIS_FUN dis_fun = { NULL };
			ZydisDisassembledInstruction info_instr = { NULL };

			mem = (uint8_t*)(runtime_address);


			while (ZYAN_SUCCESS(ZydisDisassembleIntel
			(
				dis_mode,
				reinterpret_cast<ZyanU64>(mem),
				mem,
				MAX_LENGHT_INSTR,
				&info_instr
			)))
			{
				switch (info_instr.info.mnemonic)
				{
				case ZYDIS_MNEMONIC_INT3:
				{
					if ((dis_fun.is_jcc || dis_fun.is_ret) && mem >= mem_max_pos)
					{
						return dis_fun.lenght_fun;
					}

					if (!dis_fun.aling_break)
					{
						dis_fun.aling_break++; // fist change
					}

					if (dis_fun.aling_break && dis_fun.is_last_bp)
					{
						dis_fun.aling_break++; //change
					}

					if (
						dis_fun.is_last_bp &&
						dis_fun.aling_break >= MAX_ALINGHT_BP &&
						mem >= mem_max_pos
						)
					{
						return dis_fun.lenght_fun - dis_fun.aling_break + 1;
					}
					dis_fun.is_last_bp = TRUE;
					dis_fun.is_last_exit = FALSE;
					dis_fun.is_jcc = FALSE;
					dis_fun.is_ret = FALSE;

					dis_fun.lenght_fun += info_instr.info.length;
					mem += info_instr.info.length;

					break;
				}

				case ZYDIS_MNEMONIC_NOP:
				{
					if (
						info_instr.info.length >= sizeof(uint16_t) || // 0x66 ... 0x90
						info_instr.info.operand_count_visible >= sizeof(uint16_t) //nop qword [rax], eax
						)
					{
						if (dis_fun.is_last_exit && mem >= mem_max_pos)
						{
							return dis_fun.lenght_fun - dis_fun.aling_break;
						}
					}

					dis_fun.is_last_exit = FALSE;
					dis_fun.is_last_bp = FALSE;
					dis_fun.is_jcc = FALSE;
					dis_fun.is_ret = FALSE;

					dis_fun.lenght_fun += info_instr.info.length;
					mem += info_instr.info.length;
					break;
				}

				case ZYDIS_MNEMONIC_SUB:
				{
					if (dis_fun.is_last_bp || dis_fun.is_last_exit)
					{
						if (info_instr.operands[0].mem.base == ZYDIS_REGISTER_RSP &&
							info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY
							)
						{
							return dis_fun.lenght_fun - dis_fun.aling_break + 1;
						}
					}
					dis_fun.is_last_exit = FALSE;
					dis_fun.is_last_bp = FALSE;
					dis_fun.is_jcc = FALSE;
					dis_fun.is_ret = FALSE;

					dis_fun.lenght_fun += info_instr.info.length;
					mem += info_instr.info.length;
					break;
				}

				case ZYDIS_MNEMONIC_RET:
				{
					dis_fun.is_last_exit = TRUE;
					dis_fun.is_last_bp = FALSE;
					dis_fun.is_jcc = FALSE;
					dis_fun.is_ret = TRUE;

					dis_fun.aling_break = NULL;


					if (!dis_fun.jcc_count || (dis_fun.jcc_count && mem >= mem_max_pos)) //Functhion don't have jcc
					{

						return dis_fun.lenght_fun + info_instr.info.length;
					}
					dis_fun.lenght_fun += info_instr.info.length;
					mem += info_instr.info.length;


					break;
				}



				case ZYDIS_MNEMONIC_JMP:
				case ZYDIS_MNEMONIC_JB:
				case ZYDIS_MNEMONIC_JBE:
				case ZYDIS_MNEMONIC_JCXZ:
				case ZYDIS_MNEMONIC_JECXZ:
				case ZYDIS_MNEMONIC_JKNZD:
				case ZYDIS_MNEMONIC_JKZD:
				case ZYDIS_MNEMONIC_JL:
				case ZYDIS_MNEMONIC_JLE:
				case ZYDIS_MNEMONIC_JNB:
				case ZYDIS_MNEMONIC_JNBE:
				case ZYDIS_MNEMONIC_JNL:
				case ZYDIS_MNEMONIC_JNLE:
				case ZYDIS_MNEMONIC_JNO:
				case ZYDIS_MNEMONIC_JNP:
				case ZYDIS_MNEMONIC_JNS:
				case ZYDIS_MNEMONIC_JNZ:
				case ZYDIS_MNEMONIC_JO:
				case ZYDIS_MNEMONIC_JP:
				case ZYDIS_MNEMONIC_JRCXZ:
				case ZYDIS_MNEMONIC_JS:
				case ZYDIS_MNEMONIC_JZ:
				{

					dis_fun.is_last_exit = FALSE;
					dis_fun.is_last_bp = FALSE;
					dis_fun.is_jcc = TRUE;
					dis_fun.is_ret = FALSE;

					if (info_instr.info.mnemonic == ZYDIS_MNEMONIC_JMP)
					{
						if (dis_fun.lenght_fun == NULL)
						{
							//if(is_import){}
							return info_instr.info.length;
						}

						dis_fun.is_last_exit = TRUE;

						mem_pos = reinterpret_cast<uint8_t*>(dis::get_absolute_address(&info_instr, reinterpret_cast<CHAR*>(mem)));
						if (mem_pos &&
							mem >= mem_max_pos &&
							mem >= mem_pos)
						{
							return dis_fun.lenght_fun + info_instr.info.length;
						}
					}
					else
					{
						//Fix for DLL main
						mem_pos = reinterpret_cast<uint8_t*>(dis::get_absolute_address(&info_instr, reinterpret_cast<CHAR*>(mem)));

						if (mem_pos && mem_pos > mem)
						{
							if (mem_max_pos == NULL)
							{
								mem_max_pos = mem_pos;
							}
							else if (mem_pos > mem_max_pos)
							{
								mem_max_pos = max(mem_max_pos, mem_pos);
							}
						}
						dis_fun.jcc_count++;
					}
					mem_pos = NULL;
					dis_fun.aling_break = NULL;


					dis_fun.lenght_fun += info_instr.info.length;
					mem += info_instr.info.length;

					break;
				}
				default:
				{
					if (*mem == NULL)
					{
						return dis_fun.lenght_fun - dis_fun.aling_break;
					}
					dis_fun.is_last_bp = FALSE;
					dis_fun.is_ret = FALSE;
					dis_fun.is_last_exit = FALSE;
					dis_fun.is_jcc = FALSE;
					dis_fun.aling_break = NULL;

					dis_fun.lenght_fun += info_instr.info.length;
					mem += info_instr.info.length;
					break;
				}
				}
			}
			return NULL;
		}

	public:


		NO_INLINE auto get_code(PE_INFO* pe) -> BOOLEAN
		{
			CHAR* addr_dis = NULL;
			uint32_t sec_size = NULL;
			LIST_DIS_API dis_api = { NULL };
			LIST_DIS_EXP dis_exp = { NULL };

			memory_file = pe->file_info.alloced_mem;
			headers = pe->file_info.headers;
			sections = pe->file_info.sections;

			ZydisDisassembledInstruction dis_instr = { NULL };

			for (size_t sec_id = NULL; sec_id < headers->FileHeader.NumberOfSections; sec_id++)
			{
				if (sections[sec_id].SizeOfRawData)
				{
					sec_size = sections[sec_id].SizeOfRawData;
				}
				else
				{
					return FALSE;
				}


				if (sections[sec_id].PointerToRawData && (sections[sec_id].Characteristics & IMAGE_SCN_MEM_READ) && (sections[sec_id].Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(sections[sec_id].Characteristics & IMAGE_SCN_MEM_WRITE))
				{
					addr_dis = reinterpret_cast<CHAR*>(memory_file) + sections[sec_id].PointerToRawData;

					for (size_t i = NULL; i < sec_size; i += dis_instr.info.length)
					{
						if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, addr_dis)))
						{
							if (dis::is_pos_import(&dis_instr))
							{
								if (is_import(pe, &dis_api, addr_dis, dis::get_absolute_address(&dis_instr, NULL)))
								{
									memset(&dis_api, NULL, sizeof(dis_api));
									dis_api.code_rva.clear();
								}

							}
							else if (dis::is_pos_exp(&dis_instr))
							{
								if (is_export(pe, &dis_exp, addr_dis, dis::get_absolute_address(&dis_instr, NULL)))
								{
									pe->export_info.exp_dis.push_back(dis_exp);

									memset(&dis_exp, NULL, sizeof(dis_exp));
								}
							}
							addr_dis += dis_instr.info.length;
						}
						else
						{
							return FALSE;
						}
					}

				}

			}

			return TRUE;
		}

	};
}
#endif // !CODE_PARSE
