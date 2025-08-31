#ifndef CRC_SDK_ADD
#define CRC_SDK_ADD 1
#include "struct.h"
#include "code_gen_help.h"


#define POLYMAIL_CRC_32 0xEDB88320

namespace crc_sdk_util
{
	uint32_t crc32_tab[] =
	{
		0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
		0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
		0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
		0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
		0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
		0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
		0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
		0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
		0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
		0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
		0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
		0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
		0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
		0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
		0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
		0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
		0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
		0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
		0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
		0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
		0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
		0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
		0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
		0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
		0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
		0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
		0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
		0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
		0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
		0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
		0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
		0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
		0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
		0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
		0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
		0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
		0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
		0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
		0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
		0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
		0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
		0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
		0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
		0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
		0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
		0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
		0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
		0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
		0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
		0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
		0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
		0x2d02ef8dL
	};

	class crc_sdk_util
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

		auto crc32(uint8_t* crc_addr, uint32_t crc_size) -> uint32_t
		{
			uint32_t crc_res = ~NULL;

			for (uint32_t i = NULL; i < crc_size; i++)
			{
				crc_res = crc32_tab[(crc_res ^ crc_addr[i]) & 0xFF] ^ ((crc_res >> 8) & 0x00FFFFFF);
			}

			return ~crc_res;
		}



		NO_INLINE auto add_malual_crc_list(PE_INFO* pe, x86::Assembler* ass, uint32_t crc_rva, uint32_t crc_size) -> VOID
		{
			//ass->bufferData
			printf("bufferData ->\t%p\n", ass->bufferData());
			printf("crc_size ->\t%p\n", crc_size);


			pe->crc_info.list.push_back({ crc_rva,crc_size, crc32(reinterpret_cast<uint8_t*>(ass->bufferData()),crc_size) });
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
				if (!_strcmpi(name_dll, pe->import_info.imp_manual[i].name_dll) && !_strcmpi("VirtualQuery", pe->import_info.imp_manual[i].name_api))
				{
					pe->import_info.imp_manual[i].code_rva.push_back(code_rva);
					is_add_ref = TRUE;
				}
			}
			return is_add_ref;
		}

		auto crc_read_create(x86::Assembler* ass, uint32_t vsp_offset) -> VOID
		{
			Label end_crc = ass->newLabel();
			Label rep_loop = ass->newLabel();
			Label bit_crc = ass->newLabel();
			ZydisRegister reg_use[5] = { ZYDIS_REGISTER_NONE };
			std::vector<ZydisRegister> ignore_reg;
			ignore_reg.clear();



			for (size_t i = NULL; i < _countof(reg_use); i++)
			{
				cg_util::ger_rand_reg(&reg_use[i], sizeof(PVOID), ignore_reg);
			}

			cg_util::push_correct(ass, &reg_use[NULL]);
			cg_util::push_correct(ass, &reg_use[1]);
			cg_util::push_correct(ass, &reg_use[2]);
			cg_util::push_correct(ass, &reg_use[3]);
			cg_util::push_correct(ass, &reg_use[4]);

			vsp_offset += sizeof(PVOID) * 5;


			ass->mov(cg_util::reg_conv(reg_use[NULL]), NULL);
			ass->mov(cg_util::reg_conv(reg_use[1]), NULL);
			ass->mov(cg_util::reg_conv(reg_use[2]), NULL);
			ass->mov(cg_util::reg_conv(reg_use[3]), NULL);
			ass->mov(cg_util::reg_conv(reg_use[4]), NULL);

			ass->mov(cg_util::reg_conv(reg_use[NULL]).r32(), x86::qword_ptr(current_vsp, vsp_offset - sizeof(PVOID)));
			ass->mov(cg_util::reg_conv(reg_use[1]), x86::qword_ptr(current_vsp, vsp_offset));
			ass->mov(cg_util::reg_conv(reg_use[2]).r32(), -1);
			ass->sub(x86::dword_ptr(current_vsp, vsp_offset - sizeof(PVOID)), NULL);
			ass->je(end_crc);

			ass->bind(rep_loop);

			ass->movzx(cg_util::reg_conv(reg_use[3]).r32(), x86::byte_ptr(cg_util::reg_conv(reg_use[1])));

			ass->add(cg_util::reg_conv(reg_use[1]), 1);
			ass->sub(cg_util::reg_conv(reg_use[NULL]), 1);

			ass->xor_(cg_util::reg_conv(reg_use[3]).r32(), cg_util::reg_conv(reg_use[2]).r32());
			ass->movzx(cg_util::reg_conv(reg_use[3]).r32(), cg_util::reg_conv(reg_use[3]).r8());

			ass->mov(cg_util::reg_conv(reg_use[4]), 8);
			ass->bind(bit_crc);

			ass->mov(x86::dword_ptr(current_vsp, vsp_offset - sizeof(PVOID)), cg_util::reg_conv(reg_use[3]).r32());
			ass->mov(x86::dword_ptr(current_vsp, vsp_offset), cg_util::reg_conv(reg_use[3]).r32());
			ass->shr(x86::dword_ptr(current_vsp, vsp_offset - sizeof(PVOID)), 1);
			ass->mov(cg_util::reg_conv(reg_use[3]).r32(), x86::dword_ptr(current_vsp, vsp_offset - sizeof(PVOID)));
			ass->xor_(cg_util::reg_conv(reg_use[3]).r32(), POLYMAIL_CRC_32);

			ass->and_(x86::byte_ptr(current_vsp, vsp_offset), UCHAR_MAX);

			ass->test(x86::byte_ptr(current_vsp, vsp_offset), 1);
			ass->cmovz(cg_util::reg_conv(reg_use[3]).r32(), x86::dword_ptr(current_vsp, vsp_offset - sizeof(PVOID)));
			ass->sub(cg_util::reg_conv(reg_use[4]), 1);
			ass->jnz(bit_crc);
			ass->shr(cg_util::reg_conv(reg_use[2]).r32(), 8);
			ass->xor_(cg_util::reg_conv(reg_use[2]).r32(), cg_util::reg_conv(reg_use[3]).r32());
			ass->test(cg_util::reg_conv(reg_use[NULL]), cg_util::reg_conv(reg_use[NULL]));
			ass->jnz(rep_loop);

			ass->bind(end_crc);
			ass->not_(cg_util::reg_conv(reg_use[2]).r32());
			ass->mov(x86::dword_ptr(current_vsp, vsp_offset - sizeof(PVOID) * 2), cg_util::reg_conv(reg_use[2]).r32());
			cg_util::pop_correct(ass, &reg_use[4]);
			cg_util::pop_correct(ass, &reg_use[3]);
			cg_util::pop_correct(ass, &reg_use[2]);
			cg_util::pop_correct(ass, &reg_use[1]);
			cg_util::pop_correct(ass, &reg_use[NULL]);

			ass->ret();


		}
		auto loop_get_res_crc(PE_INFO* pe, CodeHolder* code, x86::Assembler* ass, import_pars::import_pars* import_pe, crc_res_calc::crc_res_calc* crc_res_calc, uint32_t va, uint32_t polymail) -> VOID
		{
			uint32_t diff_size = NULL;
			uint32_t offset_max_stack = NULL;
			uint32_t offset_cur_stack = NULL;
			ZydisRegister reg_use[6] = { ZYDIS_REGISTER_NONE };
			Label crc32_read = ass->newLabel();
			Label crc_res = ass->newLabel();
			Label end_reg = ass->newLabel();
			Label detect = ass->newLabel();
			Label rep_loop = ass->newLabel();
			Label self_call = ass->newLabel();

			std::vector<ZydisRegister> ignore_reg;
			if (pe->file_info.type_file == STATUS_DLL || pe->file_info.type_file == STATUS_EXE || pe->file_info.type_file == STATUS_DRIVER)
			{
				ignore_reg.clear();
				offset_max_stack = sizeof(PVOID) * 5 + sizeof(PVOID) * 4 + sizeof(MEMORY_BASIC_INFORMATION);
				offset_cur_stack = offset_max_stack - sizeof(PVOID);

				cg_util::push_eflag(ass);
				cg_util::push_all_reg(ass, TRUE);

				for (size_t i = NULL; i < _countof(reg_use); i++)
				{
					cg_util::ger_rand_reg(&reg_use[i], sizeof(PVOID), ignore_reg);
				}


				ass->sub(current_vsp, offset_max_stack);


				ass->mov(x86::byte_ptr(current_vsp, offset_cur_stack - sizeof(PVOID) * 3), TRUE);



				ass->mov(cg_util::reg_conv(reg_use[1]), NULL);
				ass->lea(cg_util::reg_conv(reg_use[NULL]), x86::qword_ptr(crc_res)); //x86:change to mov and use reloce

				ass->mov(cg_util::reg_conv(reg_use[2]).r32(), x86::dword_ptr(cg_util::reg_conv(reg_use[NULL])));
				ass->mov(x86::dword_ptr(current_vsp, offset_cur_stack), cg_util::reg_conv(reg_use[2]).r32());
				ass->add(cg_util::reg_conv(reg_use[NULL]), sizeof(uint32_t));

				ass->call(self_call);
				ass->bind(self_call);
				diff_size = code->codeSize();

				cg_util::pop_correct(ass, &reg_use[2]);

				ass->sub(cg_util::reg_conv(reg_use[2]), va_to_rva(va) + diff_size);

				ass->cmp(x86::qword_ptr(current_vsp, offset_cur_stack), NULL);
				ass->jz(end_reg);

				ass->bind(rep_loop);
				ass->xor_(cg_util::reg_conv(reg_use[3]), cg_util::reg_conv(reg_use[3]));

				ass->mov(cg_util::reg_conv(reg_use[3]).r32(), x86::qword_ptr(cg_util::reg_conv(reg_use[NULL])));
				ass->add(cg_util::reg_conv(reg_use[3]), cg_util::reg_conv(reg_use[2]));
				ass->mov(cg_util::reg_conv(reg_use[4]).r32(), x86::qword_ptr(cg_util::reg_conv(reg_use[NULL]), 4));

				cg_util::push_correct(ass, &reg_use[3]);
				cg_util::push_correct(ass, &reg_use[4]);
				cg_util::push_correct(ass, &reg_use[5]);

				ass->call(crc32_read);

				cg_util::pop_correct(ass, &reg_use[5]);
				cg_util::pop_correct(ass, &reg_use[4]);
				cg_util::pop_correct(ass, &reg_use[3]);

				ass->cmp(cg_util::reg_conv(reg_use[5]).r32(), x86::qword_ptr(cg_util::reg_conv(reg_use[NULL]), 8));
				ass->jne(detect);

				ass->add(cg_util::reg_conv(reg_use[1]), sizeof(CHAR));
				ass->add(cg_util::reg_conv(reg_use[NULL]), sizeof(CRC_INFO));
				ass->cmp(cg_util::reg_conv(reg_use[1]), x86::qword_ptr(current_vsp, offset_cur_stack));
				ass->jne(rep_loop);


#ifndef _WIN64


#else
				//VMP use this trick
				//This is a detection of the creation of a new section (mbi.Type will not be equal to MEM_IMAGE if there is no new section)
				//SizeOfImage - rva next section
				if (pe->file_info.type_file == STATUS_DLL || pe->file_info.type_file == STATUS_EXE)
				{

					ass->mov(x86::qword_ptr(current_vsp, offset_cur_stack), cg_util::reg_conv(reg_use[2]));

					ass->mov(cg_util::reg_conv(reg_use[5]), pe->file_info.headers->OptionalHeader.SizeOfImage);
					ass->add(cg_util::reg_conv(reg_use[5]), cg_util::reg_conv(reg_use[2]));

					ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_RCX), cg_util::reg_conv(reg_use[5]));
					ass->lea(cg_util::reg_conv(ZYDIS_REGISTER_RDX), x86::qword_ptr(current_vsp, sizeof(PVOID) * 4));
					ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_R8), sizeof(MEMORY_BASIC_INFORMATION));

					add_list_ref_imp(pe, "KERNEL32.DLL", "VirtualQuery", va_to_rva(va) + code->codeSize());
					ass->call(x86::qword_ptr(current_vip)); //To-do: change to NtQueryVirtualMemory


					ass->cmp(cg_util::reg_conv(ZYDIS_REGISTER_EAX), NULL);
					ass->jz(end_reg);

					//ass->cmp(x86::qword_ptr(current_vsp, sizeof(PVOID) * 4 + offsetof(MEMORY_BASIC_INFORMATION, Type)), MEM_IMAGE); //present for self-remapping and add end code manual map
					//ass->jne(end_reg);

					ass->mov(cg_util::reg_conv(reg_use[2]), x86::qword_ptr(current_vsp, offset_cur_stack));
					ass->cmp(x86::qword_ptr(current_vsp, sizeof(PVOID) * 4 + offsetof(MEMORY_BASIC_INFORMATION, AllocationBase)), cg_util::reg_conv(reg_use[2]));
					ass->je(detect);
				}
#endif // !_WIN64


				ass->jmp(end_reg);


				ass->bind(detect);
				ass->mov(x86::byte_ptr(current_vsp, offset_cur_stack - sizeof(PVOID) * 3), FALSE);

				ass->bind(end_reg);
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_AL).r8(), x86::byte_ptr(current_vsp, offset_cur_stack - sizeof(PVOID) * 3));

				ass->add(current_vsp, offset_max_stack);

				cg_util::pop_all_reg(ass, TRUE);
				cg_util::pop_eflag(ass);

				ass->ret();

				//some byte change in compilethion -> manual add to table
				//add_malual_crc_list(pe, ass, va_to_rva(va), code->codeSize());


				ass->bind(crc32_read);
				crc_read_create(ass, sizeof(PVOID) * 3);


				ass->bind(crc_res);
			}
			else
			{
				ass->mov(cg_util::reg_conv(ZYDIS_REGISTER_AL).r8(), TRUE);
				ass->ret();
			}
		}


	public:
		NO_INLINE auto add_code(PE_INFO* pe, import_pars::import_pars* import_pe, reloce_info_pe::reloce_info_pe* reloce_pe, crc_res_calc::crc_res_calc* crc_res_calc, uint32_t old_va, uint32_t va) -> uint32_t
		{
			uint32_t count_crc = NULL;
			uint32_t code_size = NULL;
			uint32_t crc_table[256] = { NULL };
			PVOID code_gen = NULL;
			JitRuntime rt;
			CodeHolder code;
			CRC_IGNORE_INFO crc_ignore = { NULL };

			nt_headers = pe->file_info.headers;
			sections = pe->file_info.sections;

			if (!va)
			{
				return FALSE;
			}

			code.init(rt.environment(), rt.cpuFeatures());
			x86::Assembler ass(&code);

			loop_get_res_crc(pe, &code, &ass, import_pe, crc_res_calc, va, POLYMAIL_CRC_32);
			if (rt.add(&code_gen, &code))//cg_alloce - alloceted code
			{
				return FALSE;
			}
			code_size = code.codeSize();
			memcpy(reinterpret_cast<CHAR*>(pe->file_info.alloced_mem) + va, code_gen, code.codeSize());


			import_pe->fix_new_import(pe);
			crc_res_calc->disk_calc_static_crc(pe); //need get for correct calc ignore size
			reloce_pe->create_reloce_list(pe, old_va);

			crc_ignore.va = va + code_size;
			crc_ignore.rva = va_to_rva(crc_ignore.va);
			crc_ignore.size = sizeof(count_crc) + (pe->crc_info.list.size() + 2) * sizeof(CRC_INFO);
			pe->crc_info.mem_ignore.push_back(crc_ignore);


			crc_res_calc->disk_calc_static_crc(pe);
			count_crc = pe->crc_info.list.size();
			if (pe->file_info.type_file == STATUS_DLL || pe->file_info.type_file == STATUS_EXE || pe->file_info.type_file == STATUS_DRIVER)
			{
				memcpy(reinterpret_cast<CHAR*>(pe->file_info.alloced_mem) + va + code_size, &count_crc, pe->crc_info.list.size());
				memcpy(reinterpret_cast<CHAR*>(pe->file_info.alloced_mem) + va + code_size + sizeof(count_crc), reinterpret_cast<uint8_t*>(pe->crc_info.list.data()), pe->crc_info.list.size() * sizeof(CRC_INFO));
			}

			rt.release(code_gen);
			code.~CodeHolder();
			ass.~Assembler();
			return  code_size + sizeof(count_crc) + (pe->crc_info.list.size() + 2) * sizeof(CRC_INFO);
		}

		NO_INLINE auto update_info(PE_INFO* pe, uint32_t va) -> VOID
		{
			nt_headers = pe->file_info.headers;
			sections = pe->file_info.sections;

			for (size_t i = NULL; i < pe->import_info.imp_sdk.size(); i++)
			{
				if (pe->import_info.imp_sdk[i].sdk_type == sdk_anti_crc)
				{
					pe->import_info.imp_sdk[i].import_rva_new = va_to_rva(va);
				}
			}
		}

		NO_INLINE auto count_exist_sdk(PE_INFO* pe) -> uint32_t
		{
			uint32_t count = NULL;

			nt_headers = pe->file_info.headers;
			sections = pe->file_info.sections;

			for (size_t i = NULL; i < pe->import_info.imp_sdk.size(); i++)
			{
				if (pe->import_info.imp_sdk[i].sdk_type == sdk_anti_crc)
				{
					count++;
				}
			}
			return count;
		}
	};

}
#endif // !CRC_SDK_ADD
