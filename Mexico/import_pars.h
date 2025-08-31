#ifndef IMPORT_PARSE
#define IMPORT_PARSE
#include "struct.h"
#include "disassembly_util.h"
#include "code_gen_help.h"




namespace import_pars
{

	class import_pars
	{
	private:
		uint64_t image_base = NULL;
		PVOID memory_file = NULL;
		PVOID memory_module = NULL;

		PIMAGE_NT_HEADERS  headers = NULL;
		PIMAGE_SECTION_HEADER sections = NULL;
		PIMAGE_BASE_RELOCATION va_reloce = NULL;
		PIMAGE_BASE_RELOCATION size_reloce = NULL;


		auto malloc(size_t size) -> PVOID
		{
			return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		}

		VOID free(PVOID ptr)
		{
			if (nullptr != ptr)
				VirtualFree(ptr, NULL, MEM_RELEASE);
		}


		uint32_t align_correct(DWORD address, uint32_t alignment)
		{
			if (address % alignment != NULL)
			{
				address += (alignment - (address % alignment));
			}
			return address;
		}

		auto rva_to_va(uint64_t rva) -> uint64_t
		{


			for (size_t i = NULL; i < headers->FileHeader.NumberOfSections; i++)
			{
				if (sections[i].VirtualAddress <= rva && (sections[i].VirtualAddress + sections[i].Misc.VirtualSize) > rva)
				{
					return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
				}
			}
			return NULL;
		}

		auto va_to_rva(uint64_t va) -> uint64_t
		{

			for (size_t i = NULL; i < headers->FileHeader.NumberOfSections; i++)
			{
				if ((sections[i].PointerToRawData <= va) && (sections[i].PointerToRawData + sections[i].SizeOfRawData) > va)
				{
					return va + sections[i].VirtualAddress - sections[i].PointerToRawData;
				}
			}
			return NULL;
		}


		auto rva_to_va_file(uint64_t rva) -> uint64_t
		{

			rva -= reinterpret_cast<uint64_t>(memory_file);

			for (size_t i = NULL; i < headers->FileHeader.NumberOfSections; i++)
			{
				if (sections[i].VirtualAddress <= rva && (sections[i].VirtualAddress + sections[i].Misc.VirtualSize) > rva)
				{
					return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
				}
			}
			return NULL;
		}

		auto va_to_rva_file(uint64_t va) -> uint64_t
		{
			va -= reinterpret_cast<uint64_t>(memory_file);
			for (size_t i = NULL; i < headers->FileHeader.NumberOfSections; i++)
			{
				if ((sections[i].PointerToRawData <= va) && (sections[i].PointerToRawData + sections[i].SizeOfRawData) > va)
				{
					return va + sections[i].VirtualAddress - sections[i].PointerToRawData;
				}
			}
			return NULL;
		}



		auto get_count_mod_imp(PE_INFO* pe, std::vector<LIST_DIS_API_USE>& cur_imp, CHAR* name_dll, uint32_t imp_id) -> uint32_t
		{
			uint32_t count = NULL;
			for (size_t i = imp_id; i < cur_imp.size(); i++)
			{
				if (!_stricmp(cur_imp[i].name_dll, name_dll))
				{
					count++;
				}
				else
				{
					break;
				}
			}
			return count;
		}

		NO_INLINE auto update_imp_info(PE_INFO* pe, LIST_DIS_API_USE* cur_imp) -> VOID
		{
			if (cur_imp->is_manual_imp)
			{
				pe->import_info.imp_manual[cur_imp->index].import_rva_new = cur_imp->import_rva_new;
				pe->import_info.imp_manual[cur_imp->index].import_rva_imp_by_name = cur_imp->import_rva_imp_by_name;
			}
			else
			{
				pe->import_info.imp_dis[cur_imp->index].import_rva_new = cur_imp->import_rva_new;
				pe->import_info.imp_dis[cur_imp->index].import_rva_imp_by_name = cur_imp->import_rva_imp_by_name;
			}
		}

		auto fix_instr_use_imp(PE_INFO* pe, ZydisDisassembledInstruction* dis_instr, uint32_t import_rva_new, uint32_t code_rva, BOOLEAN is_sdk = FALSE) -> BOOLEAN
		{
			uint32_t code_size = NULL;
			PVOID code_gen = NULL;
			uint8_t opcode[MAX_LENGHT_INSTR] = { NULL };
			JitRuntime rt;
			CodeHolder code;


			if (!import_rva_new || !code_rva)
			{
				return FALSE;
			}

			code.init(rt.environment(), rt.cpuFeatures());
			x86::Assembler ass(&code);

#ifdef _WIN64

			if (
				dis_instr->info.operand_count_visible == 1 &&
				dis_instr->operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY &&
				dis::is_rip_instr(dis_instr)

				)
			{
				if (is_sdk)
				{

					if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_JMP)
					{
						opcode[NULL] = 0xE9;

						*reinterpret_cast<uint32_t*>(opcode + 1) = import_rva_new - code_rva - INSTR_LEN_IMM_JMP; //5 - size jmp imm instr

						for (size_t i = NULL; i < INSTR_LEN_IMM_JMP; i++)
						{
							ass.db(opcode[i]);
						}
						ass.nop();
					}
					else if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_CALL)
					{
						opcode[NULL] = 0xE8;

						*reinterpret_cast<uint32_t*>(opcode + 1) = import_rva_new - code_rva - INSTR_LEN_IMM_CALL; //5 - size call imm instr

						for (size_t i = NULL; i < INSTR_LEN_IMM_CALL; i++)
						{
							ass.db(opcode[i]);
						}
						ass.nop();
					}
				}
				else
				{

					if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_JMP)
					{
						//Correct work if import_rva_new > code_rva or  code_rva > import_rva_new
						ass.jmp(x86::qword_ptr(current_vip, import_rva_new - code_rva - dis_instr->info.length));
					}
					else if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_CALL)
					{
						//Correct work if import_rva_new > code_rva or  code_rva > import_rva_new
						ass.call(x86::qword_ptr(current_vip, import_rva_new - code_rva - dis_instr->info.length));
					}
				}
			}

			if (dis_instr->info.operand_count_visible == 2)
			{
				if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_MOV)
				{
					if (
						dis_instr->operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
						dis_instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
						)
					{
						ass.mov(cg_util::reg_conv(dis_instr->operands[NULL].reg.value), x86::qword_ptr(current_vip, import_rva_new - code_rva - dis_instr->info.length));
					}
					else if
						(
							dis_instr->operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY &&
							dis_instr->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
							)
					{
						ass.mov(x86::qword_ptr(current_vip, import_rva_new - code_rva - dis_instr->info.length), cg_util::reg_conv(dis_instr->operands[NULL].reg.value));

					}
				}
				else if
					(
						dis_instr->info.mnemonic == ZYDIS_MNEMONIC_LEA &&
						dis_instr->operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
						dis_instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
						)
				{
					ass.lea(cg_util::reg_conv(dis_instr->operands[NULL].reg.value), x86::qword_ptr(current_vip, import_rva_new - code_rva - dis_instr->info.length));
				}
			}
#else 

			if (
				dis_instr->info.operand_count_visible == 1 &&
				dis_instr->operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY &&
				dis::is_rip_instr(dis_instr)

				)
			{
				if (is_sdk)
				{

					if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_JMP)
					{
						opcode[NULL] = 0xE9;

						*reinterpret_cast<uint32_t*>(opcode + 1) = import_rva_new - code_rva - INSTR_LEN_IMM_JMP; //5 - size call imm instr

						for (size_t i = NULL; i < INSTR_LEN_IMM_JMP; i++)
						{
							ass.db(opcode[i]);
						}
						ass.nop();
					}
					else if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_CALL)
					{
						opcode[NULL] = 0xE8;

						*reinterpret_cast<uint32_t*>(opcode + 1) = import_rva_new - code_rva - INSTR_LEN_IMM_CALL; //5 - size jmp imm instr

						for (size_t i = NULL; i < INSTR_LEN_IMM_CALL; i++)
						{
							ass.db(opcode[i]);
						}
						ass.nop();
					}
				}
				else
				{

					if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_JMP)
					{
						//Correct work if import_rva_new > code_rva or  code_rva > import_rva_new (pe->file_info.headers->OptionalHeader.ImageBase need fix in reloke work)
						ass.jmp(x86::dword_ptr(import_rva_new + pe->file_info.headers->OptionalHeader.ImageBase));
					}
					else if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_CALL)
					{
						//Correct work if import_rva_new > code_rva or  code_rva > import_rva_new
						ass.call(x86::dword_ptr(import_rva_new + pe->file_info.headers->OptionalHeader.ImageBase));
					}
					else if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_PUSH)
					{
						ass.push(import_rva_new + pe->file_info.headers->OptionalHeader.ImageBase);
					}
				}
			}

			if (dis_instr->info.operand_count_visible == 2)
			{
				if (
					dis_instr->info.mnemonic == ZYDIS_MNEMONIC_MOV &&
					dis_instr->operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
					dis_instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
					)
				{
					ass.mov(cg_util::reg_conv(dis_instr->operands[NULL].reg.value), x86::qword_ptr(current_vip, import_rva_new));
				}
			}
			//add list reloce
			//__debugbreak();
#endif // _WIN64

			if (rt.add(&code_gen, &code))//cg_alloce - alloceted code
			{
				return FALSE;
			}
			code_size = code.codeSize();
			memcpy(reinterpret_cast<CHAR*>(pe->file_info.alloced_mem) + rva_to_va(code_rva), code_gen, code.codeSize());

			rt.release(code_gen);
			code.~CodeHolder();
			ass.~Assembler();
			return  code_size;
		}

		NO_INLINE auto remove_reloce_by_rva(PE_INFO* pe, uint32_t rva) -> BOOLEAN
		{
			ZydisDisassembledInstruction dis_instr = { NULL };

			for (size_t i = NULL; i < pe->reloce_info.list.size(); i++)
			{
				//fix manual aadd reloce va for use
				if (!pe->reloce_info.list[i].va)
				{
					pe->reloce_info.list[i].va = rva_to_va(pe->reloce_info.list[i].rva);
				}

				if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, reinterpret_cast<CHAR*>(memory_file) + rva_to_va(rva))))
				{
					if (pe->reloce_info.list[i].rva >= rva && rva + dis_instr.info.length >= pe->reloce_info.list[i].rva + pe->reloce_info.list[i].size)
					{
						pe->reloce_info.list.erase(pe->reloce_info.list.begin() + i);
						return TRUE;
					}
				}
			}
			return FALSE;
		}


		NO_INLINE auto remove_reloce_code_imp(PE_INFO* pe) -> BOOLEAN
		{
			for (size_t i = NULL; i < pe->import_info.imp_dis.size(); i++)
			{
				for (size_t j = NULL; j < pe->import_info.imp_dis[i].code_rva.size(); j++)
				{
					if (!remove_reloce_by_rva(pe, pe->import_info.imp_dis[i].code_rva[j]) && pe->file_info.is_log)
					{
						printf("not remove reloce ->\t%p\n", pe->import_info.imp_dis[i].code_rva[j]);
					}
				}
			}
			return FALSE;
		}

		NO_INLINE auto get_imp_reloce_correct(PE_INFO* pe, uint32_t rva) -> uint32_t
		{
			ZydisDisassembledInstruction dis_instr = { NULL };
			if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, reinterpret_cast<CHAR*>(memory_file) + rva_to_va(rva))))
			{
				if (dis::is_rip_instr(&dis_instr))
				{
					if (dis_instr.info.mnemonic == ZYDIS_MNEMONIC_CALL || dis_instr.info.mnemonic == ZYDIS_MNEMONIC_JMP)
					{
						return rva + sizeof(uint8_t) * 2;
					}
					else if (dis_instr.info.mnemonic == ZYDIS_MNEMONIC_MOV && dis_instr.info.operand_count_visible == 2)
					{
						return rva + sizeof(uint8_t) * 2;
					}

				}
			}
			return NULL;
		}

		NO_INLINE auto add_reloce_code_imp(PE_INFO* pe) -> BOOLEAN
		{
			BOOLEAN is_fix = TRUE;
			RELOCE_TYPE rel_info = { NULL };
			for (size_t i = NULL; i < pe->import_info.imp_dis.size(); i++)
			{
				for (size_t j = NULL; j < pe->import_info.imp_dis[i].code_rva.size(); j++)
				{
					rel_info.rva = get_imp_reloce_correct(pe, pe->import_info.imp_dis[i].code_rva[j]);
					rel_info.va = rva_to_va(rel_info.rva);
					rel_info.type = RELOCE_USE;
					rel_info.size = sizeof(PVOID);

					pe->reloce_info.list.push_back(rel_info);
				}
			}

			for (size_t i = NULL; i < pe->import_info.imp_manual.size(); i++)
			{
				for (size_t j = NULL; j < pe->import_info.imp_manual[i].code_rva.size(); j++)
				{
					rel_info.rva = get_imp_reloce_correct(pe, pe->import_info.imp_manual[i].code_rva[j]);
					rel_info.va = rva_to_va(rel_info.rva);
					rel_info.type = RELOCE_USE;
					rel_info.size = sizeof(PVOID);

					pe->reloce_info.list.push_back(rel_info);
				}
			}
			return is_fix;
		}

	public:

		NO_INLINE auto get_not_find_dis_imp(PE_INFO* pe) -> BOOLEAN
		{
			bool is_find = FALSE;
			bool is_all_find = TRUE;
			for (size_t i = NULL; i < pe->import_info.imp.size(); i++)
			{

				for (size_t j = NULL; j < pe->import_info.imp_dis.size(); j++)
				{
					if (pe->import_info.imp_dis[j].import_rva == pe->import_info.imp[i].import_rva)
					{
						is_find = TRUE;
					}
				}

				for (size_t j = NULL; j < pe->import_info.imp_sdk.size(); j++)
				{
					if (pe->import_info.imp_sdk[j].import_rva == pe->import_info.imp[i].import_rva)
					{
						is_find = TRUE;
					}
				}

				if (!is_find)
				{
					is_all_find = FALSE;
					printf("import name not find ->\t%s\n", pe->import_info.imp[i].name_api);
				}
				is_find = FALSE;
			}
			return !is_all_find;
		}

		NO_INLINE auto get_sdk_by_name(CHAR* name_dll, CHAR* name_api) -> SDK_TYPE
		{
			if (!_stricmp(name_dll, "Meh.dll"))
			{
				if (!_stricmp(name_api, SDK_ANTI_CRC_PATCH))
				{
					return sdk_anti_crc;
				}
				else if (!_stricmp(name_api, SDK_ANTI_VM))
				{
					return sdk_anti_vm;
				}
				else if (!_stricmp(name_api, SDK_ANTI_DEBUG))
				{
					return sdk_anti_debug;
				}
			}
			return sdk_unk;
		}

		/*

		https://github.com/TheCruZ/Simple-Manual-Map-Injector/blob/ae4bf482920e8f26ff6fdc99544b27c20b9c5312/Manual%20Map%20Injector/injector.cpp#L314
		https://github.com/DarthTon/Blackbone/blob/master/src/BlackBone/PE/PEImage.cpp

		*/
		NO_INLINE auto get_import(PE_INFO* pe, BOOLEAN remove_info = TRUE) -> BOOLEAN
		{
			CHAR* name_imp = NULL;
			uint32_t sec_addr = NULL;
			uint32_t sec_size = NULL;
			size_t* orig_first_thunk = NULL;
			size_t* first_funk = NULL;

			PIMAGE_IMPORT_BY_NAME imp_by_name = NULL;
			PIMAGE_IMPORT_DESCRIPTOR imp_descriptor = NULL;
			IMPORT_INFO_LIST imp_list = { NULL };

			memory_file = pe->file_info.alloced_mem;
			headers = pe->file_info.headers;
			sections = pe->file_info.sections;


			if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size && headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
			{
				imp_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
				for (; imp_descriptor->Name; ++imp_descriptor)
				{
					name_imp = reinterpret_cast<CHAR*>(memory_file) + rva_to_va(imp_descriptor->Name);

					orig_first_thunk = reinterpret_cast<size_t*>(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(imp_descriptor->OriginalFirstThunk));
					first_funk = reinterpret_cast<size_t*>(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(imp_descriptor->FirstThunk));

					if (!imp_descriptor->OriginalFirstThunk && !imp_descriptor->FirstThunk)
					{
						return FALSE;
					}
					if (!orig_first_thunk)
						orig_first_thunk = first_funk;

					for (; *orig_first_thunk; ++orig_first_thunk, ++first_funk)
					{
						if (IMAGE_SNAP_BY_ORDINAL(*orig_first_thunk))
						{
							memset(&imp_list, NULL, sizeof(imp_list));
							memcpy(imp_list.name_dll, name_imp, strlen(name_imp));
							imp_list.is_ordinal = TRUE;

							imp_list.sdk_type = sdk_unk;
							imp_list.ordinal = *orig_first_thunk;

							imp_list.import_va = reinterpret_cast<size_t>(first_funk) - reinterpret_cast<size_t>(memory_file);
							imp_list.import_rva = va_to_rva_file(reinterpret_cast<size_t>(first_funk));
							pe->import_info.imp.push_back(imp_list);

							//if (remove_info)
							//{
							//	memset(name_imp, OPCODE_INT3, strlen(name_imp));
							//	memset(name_imp, OPCODE_INT3, sizeof(PVOID));
							//}
						}
						else
						{

							imp_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(*orig_first_thunk));

							if (imp_by_name->Name)
							{
								imp_list.is_ordinal = FALSE;
								imp_list.ordinal = NULL;

								memset(&imp_list, NULL, sizeof(imp_list));
								imp_list.hint = imp_by_name->Hint;
								memcpy(imp_list.name_api, imp_by_name->Name, strlen(imp_by_name->Name));
								memcpy(imp_list.name_dll, name_imp, strlen(name_imp));
								imp_list.sdk_type = get_sdk_by_name(imp_list.name_dll, imp_list.name_api);

								imp_list.import_va = reinterpret_cast<size_t>(first_funk) - reinterpret_cast<size_t>(memory_file);
								imp_list.import_rva = va_to_rva_file(reinterpret_cast<size_t>(first_funk));
								pe->import_info.imp.push_back(imp_list);


								//if (remove_info)
								//{
								//	memset(name_imp, OPCODE_INT3, strlen(name_imp));
								//	memset(&imp_by_name->Hint, OPCODE_INT3, sizeof(imp_by_name->Hint));
								//	memset(imp_by_name->Name, OPCODE_INT3, strlen(imp_by_name->Name));
								//}
							}

						}

					}

				}

				if (remove_info)
				{
					imp_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
					for (; imp_descriptor->Name; ++imp_descriptor)
					{
						name_imp = reinterpret_cast<CHAR*>(memory_file) + rva_to_va(imp_descriptor->Name);
						memset(name_imp, OPCODE_INT3, strlen(name_imp));

						orig_first_thunk = reinterpret_cast<size_t*>(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(imp_descriptor->OriginalFirstThunk));
						first_funk = reinterpret_cast<size_t*>(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(imp_descriptor->FirstThunk));

						if (!imp_descriptor->OriginalFirstThunk && !imp_descriptor->FirstThunk)
						{
							return FALSE;
						}
						if (!orig_first_thunk)
							orig_first_thunk = first_funk;


						for (; *orig_first_thunk; ++orig_first_thunk, ++first_funk)
						{
							if (IMAGE_SNAP_BY_ORDINAL(*orig_first_thunk))
							{

								memset(orig_first_thunk, OPCODE_INT3, sizeof(PVOID));
							}
							else
							{

								imp_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(*orig_first_thunk));

								if (imp_by_name->Name)
								{
									if (remove_info)
									{
										memset(orig_first_thunk, OPCODE_INT3, sizeof(PVOID));
										memset(&imp_by_name->Hint, OPCODE_INT3, sizeof(imp_by_name->Hint));
										memset(imp_by_name->Name, OPCODE_INT3, strlen(imp_by_name->Name));
									}
								}

							}

						}

					}
				}
			}
			else
			{
				pe->file_info.file_status |= FILE_STATUS_NO_IMPORT;
				return TRUE;
			}
			return pe->import_info.imp.size() != NULL;


		}

		NO_INLINE auto get_export(PE_INFO* pe) -> BOOLEAN
		{
			CHAR* name_imp = NULL;
			uint32_t sec_addr = NULL;
			IMPORT_EXPORT_LIST dis_api = { NULL };

			memory_file = pe->file_info.alloced_mem;
			headers = pe->file_info.headers;
			sections = pe->file_info.sections;

			return TRUE;
			if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
			{
				auto p1 = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
				for (size_t i = NULL; i < p1->NumberOfFunctions; i++)
				{
					auto names = (PDWORD)(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(p1->AddressOfNames));
					auto ordinals = (PWORD)(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(p1->AddressOfNameOrdinals));
					auto functions = (PDWORD)(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(p1->AddressOfFunctions));

					if (!names || !ordinals || !functions)
						return NULL;

					for (uint32_t i = NULL; i < p1->NumberOfFunctions; ++i)
					{
						auto name = reinterpret_cast<CHAR*>(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(names[i]));

						dis_api.export_rva = functions[ordinals[i]];
						dis_api.export_va = rva_to_va(dis_api.export_rva);
						memcpy(&dis_api.name_exp, name, strlen(name));

						pe->export_info.exp.push_back(dis_api);
						memset(&dis_api, NULL, sizeof(dis_api));
					}
				}


			}
			else
			{
				pe->file_info.file_status |= FILE_STATUS_NO_EXPORT;
				return FALSE;
			}
			return TRUE;

		}

		NO_INLINE auto set_new_import(PE_INFO* pe, uint32_t va) -> uint32_t
		{


			uint32_t rva_old = NULL;
			uint32_t rva = NULL;
			uint32_t imp_iat_offset = NULL;
			uint32_t imp_iat_offset_old = NULL;
			uint32_t imp_str_offset = NULL;
			uint32_t imp_rva_list_offset = NULL;
			uint32_t disp_start_offset = NULL;
			uint32_t old_disp_start_offset = NULL;
			uint32_t new_size_iat = NULL;
			uint32_t init_size = NULL;
			size_t copy_offset = NULL;
			CHAR* old_name_dll = NULL;

			memory_file = pe->file_info.alloced_mem;
			headers = pe->file_info.headers;
			sections = pe->file_info.sections;

			IMAGE_IMPORT_BY_NAME imp_by_name = { NULL };
			IMAGE_IMPORT_DESCRIPTOR new_imp_descriptor = { NULL };
			LIST_DIS_API_USE cur_dis_api_use = { NULL };
			std::vector< IMAGE_IMPORT_DESCRIPTOR> imp_descriptor_list;
			std::vector<LIST_DIS_API_USE> cur_imp;

			imp_descriptor_list.clear();
			//try just add exist
			//new_imp_descriptor.FirstThunk; // first save imp rva(in runtime)
			//new_imp_descriptor.OriginalFirstThunk; // rva string
			rva = va_to_rva(va);
			rva_old = rva;

			if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size && headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
			{
				if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size && headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress)
				{
					//save calc number rva
					//memset(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + rva_to_va(headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress), 0xCC, headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
					//headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = va_to_rva(va);

					if (pe->import_info.imp_dis.size())
					{
#ifndef _WIN64
						remove_reloce_code_imp(pe);
#endif // !_WIN64


						for (size_t i = NULL; i < pe->import_info.imp_dis.size(); i++)
						{
							cur_dis_api_use.is_manual_imp = FALSE;
							cur_dis_api_use.index = i;
							memcpy(reinterpret_cast<CHAR*>(&cur_dis_api_use.name_api), &pe->import_info.imp_dis[i], sizeof(pe->import_info.imp_dis[i]));

							//ignore copy code_rva(not need)
							cur_imp.push_back(cur_dis_api_use);
						}

						for (size_t i = NULL; i < pe->import_info.imp_manual.size(); i++)
						{
							cur_dis_api_use.is_manual_imp = TRUE;
							cur_dis_api_use.index = i;
							memcpy(reinterpret_cast<CHAR*>(&cur_dis_api_use.name_api), &pe->import_info.imp_manual[i], sizeof(pe->import_info.imp_manual[i]));

							//ignore copy code_rva(not need)
							cur_imp.push_back(cur_dis_api_use);
						}

						std::sort(cur_imp.begin(), cur_imp.end(), [](LIST_DIS_API_USE& cur, LIST_DIS_API_USE& next) {return _stricmp(cur.name_dll, next.name_dll) < NULL; });

						//PE list
						for (size_t i = NULL; i < cur_imp.size(); i++)
						{
							if ((!old_name_dll || _stricmp(cur_imp[i].name_dll, old_name_dll)))
							{
								imp_descriptor_list.push_back(new_imp_descriptor);

							}
							old_name_dll = cur_imp[i].name_dll;
						}

						if (!imp_descriptor_list.size())
						{
							cur_imp.clear();
							return FALSE;
						}



						//init FirstThunk
						old_name_dll = NULL;
						imp_iat_offset_old = imp_iat_offset;
						for (size_t i = NULL, imp_descriptor_id = NULL; i < cur_imp.size(); i++)
						{
							if (!old_name_dll)
							{
								imp_descriptor_list[imp_descriptor_id].FirstThunk = rva + imp_iat_offset;
								memset(reinterpret_cast<CHAR*>(memory_file) + va + imp_iat_offset, NULL, sizeof(PVOID));

							}
							else if (_stricmp(cur_imp[i].name_dll, old_name_dll))
							{
								imp_descriptor_id += 1;
								imp_iat_offset += sizeof(PVOID);

								//fix
								imp_descriptor_list[imp_descriptor_id].FirstThunk = rva + imp_iat_offset;
								memset(reinterpret_cast<CHAR*>(memory_file) + va + imp_iat_offset, NULL, sizeof(PVOID));

							}
							cur_imp[i].import_rva_new = rva + imp_iat_offset;
							update_imp_info(pe, &cur_imp[i]);
							imp_iat_offset += sizeof(PVOID);

							old_name_dll = cur_imp[i].name_dll;
						}


						//aligment (NEXT NULL)
						imp_iat_offset += sizeof(PVOID);
						memset(reinterpret_cast<CHAR*>(memory_file) + va + imp_iat_offset, NULL, sizeof(PVOID));

						//Remove old info
						memset(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress), OPCODE_INT3, headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);

						headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = rva;
						headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = imp_iat_offset;

						old_name_dll = NULL;

						//init name DLL

						//aligment imp_iat_offset by PVOID if not NULL
						imp_str_offset = align_correct(imp_iat_offset + sizeof(PVOID), sizeof(PVOID)); //ignore NULL aligment 

						//Init name_dll
						for (size_t i = NULL, imp_descriptor_id = NULL; i < cur_imp.size(); i++)
						{

							if (!old_name_dll || _stricmp(cur_imp[i].name_dll, old_name_dll))
							{

								imp_descriptor_list[imp_descriptor_id].Name = rva + imp_str_offset;
								memset(reinterpret_cast<CHAR*>(memory_file) + va + imp_str_offset, NULL, strlen(cur_imp[i].name_dll) + 1);
								memcpy(reinterpret_cast<CHAR*>(memory_file) + va + imp_str_offset, cur_imp[i].name_dll, strlen(cur_imp[i].name_dll));

								imp_str_offset += strlen(cur_imp[i].name_dll) + 2; //NULL end next
								//aligment by PVOID 
								imp_str_offset = align_correct(imp_str_offset, sizeof(PVOID)); //ignore NULL aligment 

								imp_descriptor_id += 1;


							}
							old_name_dll = cur_imp[i].name_dll;
						}

						old_name_dll = NULL;


						imp_str_offset = align_correct(imp_str_offset + sizeof(PVOID), sizeof(PVOID));
						imp_rva_list_offset = imp_str_offset;
						for (size_t i = NULL, imp_descriptor_id = NULL, imp_count = NULL; i < cur_imp.size(); i++)
						{

							if (!old_name_dll || _stricmp(cur_imp[i].name_dll, old_name_dll))
							{
								imp_descriptor_list[imp_descriptor_id].OriginalFirstThunk = rva + imp_rva_list_offset;

								imp_count = get_count_mod_imp(pe, cur_imp, cur_imp[i].name_dll, i);
								memset(reinterpret_cast<CHAR*>(memory_file) + va + imp_rva_list_offset, NULL, ((imp_count + 2) * sizeof(PVOID)));
								imp_str_offset += ((imp_count + 2) * sizeof(PVOID));
								for (size_t j = NULL; j < imp_count; j++)
								{
									if (!cur_imp[i + j].is_ordinal)
									{

										copy_offset = rva + imp_str_offset;
										memcpy(reinterpret_cast<CHAR*>(memory_file) + va + imp_rva_list_offset, &copy_offset, sizeof(PVOID));

										cur_imp[i + j].import_rva_imp_by_name = rva + imp_str_offset;
										update_imp_info(pe, &cur_imp[i + j]);
										memset(reinterpret_cast<CHAR*>(memory_file) + va + imp_str_offset, NULL, sizeof(cur_imp[i + j].hint) + strlen(cur_imp[i].name_api) + 1);

										//Copy hint
										memcpy(reinterpret_cast<CHAR*>(memory_file) + va + imp_str_offset, &cur_imp[i].hint, sizeof(cur_imp[i + j].hint));

										//Copy name api
										memcpy(reinterpret_cast<CHAR*>(memory_file) + va + imp_str_offset + sizeof(cur_imp[i].hint), cur_imp[i + j].name_api, strlen(cur_imp[i + j].name_api));

										imp_str_offset = align_correct(imp_str_offset + strlen(cur_imp[i + j].name_api) + sizeof(cur_imp[i].hint) + sizeof(PVOID), sizeof(PVOID));
									}
									else
									{
										cur_imp[i + j].import_rva_imp_by_name = NULL;
										update_imp_info(pe, &cur_imp[i + j]);

										copy_offset = cur_imp[i + j].ordinal;
										memcpy(reinterpret_cast<CHAR*>(memory_file) + va + imp_rva_list_offset, &copy_offset, sizeof(PVOID));
									}
									imp_rva_list_offset += sizeof(PVOID);
								}
								imp_rva_list_offset = imp_str_offset;
								imp_descriptor_id += 1;
							}
							old_name_dll = cur_imp[i].name_dll;
						}

						disp_start_offset = align_correct(imp_rva_list_offset + sizeof(PVOID), sizeof(IMAGE_IMPORT_DESCRIPTOR));
						old_disp_start_offset = disp_start_offset;

						//Init new IMAGE_IMPORT_DESCRIPTOR
						memset(reinterpret_cast<CHAR*>(memory_file) + va + disp_start_offset, NULL, imp_descriptor_list.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_IMPORT_DESCRIPTOR));

						for (size_t i = NULL; i < imp_descriptor_list.size(); i++)
						{
							memcpy(reinterpret_cast<CHAR*>(memory_file) + va + disp_start_offset, &imp_descriptor_list[i], sizeof(IMAGE_IMPORT_DESCRIPTOR));
							disp_start_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
						}

						memset(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), OPCODE_INT3, headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

						init_size = old_disp_start_offset + imp_descriptor_list.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_IMPORT_DESCRIPTOR);
						headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = rva + old_disp_start_offset;
						headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = imp_descriptor_list.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_IMPORT_DESCRIPTOR);

						//fix IAT rva point in correct rva list to name export
						for (size_t i = NULL; i < cur_imp.size(); i++)
						{
							if (!cur_imp[i].is_ordinal)
							{
								copy_offset = cur_imp[i].import_rva_imp_by_name;
								memcpy(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(cur_imp[i].import_rva_new), &copy_offset, sizeof(PVOID));
							}
							else
							{
								copy_offset = cur_imp[i].ordinal;
								memcpy(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(cur_imp[i].import_rva_new), &copy_offset, sizeof(PVOID));
							}

						}
						for (size_t i = NULL; i < pe->import_info.imp_dis.size(); i++)
						{
							if (pe->import_info.imp_dis[i].import_rva_new && pe->import_info.imp_dis[i].import_rva_new != pe->import_info.imp_dis[i].import_rva)
							{
								pe->import_info.imp_dis[i].import_rva = pe->import_info.imp_dis[i].import_rva_new;
							}
						}
						for (size_t i = NULL; i < pe->import_info.imp_manual.size(); i++)
						{
							if (pe->import_info.imp_manual[i].import_rva_new && pe->import_info.imp_manual[i].import_rva_new != pe->import_info.imp_manual[i].import_rva)
							{
								pe->import_info.imp_manual[i].import_rva = pe->import_info.imp_manual[i].import_rva_new;
							}

						}

#ifndef _WIN64
						add_reloce_code_imp(pe);
#endif // !_WIN64 

					}

				}
				else
				{
					printf("some bad imp next!\n");
					cur_imp.clear();
					return NULL;
				}

			}
			else
			{

			}
			cur_imp.clear();
			return init_size;
		}

		NO_INLINE auto fix_new_import(PE_INFO* pe) -> BOOLEAN
		{

			BOOLEAN success_fix_imp = TRUE;
			ZydisDisassembledInstruction dis_instr = { NULL };

			memory_file = pe->file_info.alloced_mem;
			headers = pe->file_info.headers;
			sections = pe->file_info.sections;


			for (size_t i = NULL; i < pe->import_info.imp_dis.size(); i++)
			{
				for (size_t j = NULL; j < pe->import_info.imp_dis[i].code_rva.size(); j++)
				{
					if (pe->import_info.imp_dis[i].import_rva_new && ZYAN_SUCCESS(dis::get_dis(&dis_instr, reinterpret_cast<CHAR*>(memory_file) + rva_to_va(pe->import_info.imp_dis[i].code_rva[j]))))
					{
						if (!fix_instr_use_imp(pe, &dis_instr, pe->import_info.imp_dis[i].import_rva_new, pe->import_info.imp_dis[i].code_rva[j]))
						{
							success_fix_imp = FALSE;
						}
					}
					else
					{
						success_fix_imp = FALSE;
					}

				}
			}

			for (size_t i = NULL; i < pe->import_info.imp_manual.size(); i++)
			{
				for (size_t j = NULL; j < pe->import_info.imp_manual[i].code_rva.size(); j++)
				{
					if (pe->import_info.imp_manual[i].import_rva_new && ZYAN_SUCCESS(dis::get_dis(&dis_instr, reinterpret_cast<CHAR*>(memory_file) + rva_to_va(pe->import_info.imp_manual[i].code_rva[j]))))
					{
						if (!fix_instr_use_imp(pe, &dis_instr, pe->import_info.imp_manual[i].import_rva_new, pe->import_info.imp_manual[i].code_rva[j]))
						{
							success_fix_imp = FALSE;
						}
					}
					else
					{
						success_fix_imp = FALSE;
					}

				}
			}
			return success_fix_imp;
		}


		NO_INLINE auto fix_sdk(PE_INFO* pe) -> BOOLEAN
		{

			BOOLEAN success_fix_imp = TRUE;
			ZydisDisassembledInstruction dis_instr = { NULL };

			memory_file = pe->file_info.alloced_mem;
			headers = pe->file_info.headers;
			sections = pe->file_info.sections;


			for (size_t i = NULL; i < pe->import_info.imp_sdk.size(); i++)
			{
				for (size_t j = NULL; j < pe->import_info.imp_sdk[i].code_rva.size(); j++)
				{
					if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, reinterpret_cast<CHAR*>(memory_file) + rva_to_va(pe->import_info.imp_sdk[i].code_rva[j]))))
					{
						if (!fix_instr_use_imp(pe, &dis_instr, pe->import_info.imp_sdk[i].import_rva_new, pe->import_info.imp_sdk[i].code_rva[j], TRUE))
						{
							success_fix_imp = FALSE;
						}
					}
					else
					{
						success_fix_imp = FALSE;
					}

				}
			}

			return success_fix_imp;
		}

		NO_INLINE auto add_imp(PE_INFO* pe, CONST CHAR* name_dll, CONST CHAR* name_api) -> BOOLEAN
		{
			BOOLEAN is_imp_exist = FALSE;
			LIST_DIS_API dis_api = { NULL };

			for (size_t i = NULL; !is_imp_exist && i < pe->import_info.imp_dis.size(); i++)
			{
				if (!_strcmpi(name_dll, pe->import_info.imp_dis[i].name_dll) && !_strcmpi(name_api, pe->import_info.imp_dis[i].name_api))
				{
					is_imp_exist = TRUE;
				}
			}
			for (size_t i = NULL; !is_imp_exist && i < pe->import_info.imp_manual.size(); i++)
			{
				if (!_strcmpi(name_dll, pe->import_info.imp_manual[i].name_dll) && !_strcmpi(name_api, pe->import_info.imp_manual[i].name_api))
				{
					is_imp_exist = TRUE;
				}
			}
			if (!is_imp_exist)
			{
				dis_api.sdk_type = sdk_unk;
				memcpy(dis_api.name_dll, name_dll, strlen(name_dll));
				memcpy(dis_api.name_api, name_api, strlen(name_api));
				pe->import_info.imp_manual.push_back(dis_api);
			}
			return TRUE;
		}
	};
}
#endif // !IMPORT_PARSE
