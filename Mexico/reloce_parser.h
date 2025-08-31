#ifndef RELOCE_PARSER
#define RELOCE_PARSER
#include "struct.h"



namespace reloce_info_pe
{
	class reloce_info_pe
	{
	private:
		uint64_t image_base = NULL;
		PVOID memory_file = NULL;
		PVOID memory_module = NULL;
		PIMAGE_NT_HEADERS  nt_headers = NULL;
		PIMAGE_SECTION_HEADER sections = NULL;

		PIMAGE_BASE_RELOCATION va_reloce = NULL;
		PIMAGE_BASE_RELOCATION size_reloce = NULL;


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


			for (size_t i = NULL; i < nt_headers->FileHeader.NumberOfSections; i++)
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


			for (size_t i = NULL; i < nt_headers->FileHeader.NumberOfSections; i++)
			{
				if ((sections[i].PointerToRawData <= va) && (sections[i].PointerToRawData + sections[i].SizeOfRawData) >= va)
				{
					return va + sections[i].VirtualAddress - sections[i].PointerToRawData;
				}
			}
			return NULL;
		}

		uint32_t align_correct(DWORD address, uint32_t alignment)
		{
			if (address % alignment != NULL)
			{
				address += (alignment - (address % alignment));
			}
			return address;
		}

		NO_INLINE auto get_next_min_rva(uint32_t cur_rva, uint32_t rva_min) -> uint32_t
		{
			uint32_t cur_rva_min = NULL;

			cur_rva = cur_rva & ~(PAGE_SIZE - 0x1);
			if (!rva_min)
			{
				cur_rva_min = cur_rva & ~(PAGE_SIZE - 0x1);
			}
			else
			{
				cur_rva_min = rva_min & ~(PAGE_SIZE - 0x1);
			}
			if (cur_rva != cur_rva_min)
			{
				cur_rva_min = cur_rva;
			}
			return cur_rva_min;
		}
		auto get_count_rva_list(PE_INFO* pe, uint32_t rva_min) -> uint32_t
		{
			uint32_t count = NULL;
			uint32_t rva_max = rva_min + PAGE_SIZE - 1;
			for (size_t i = NULL; i < pe->reloce_info.list.size(); i++)
			{
				if (pe->reloce_info.list[i].rva >= rva_min && rva_max >= pe->reloce_info.list[i].rva)
				{
					count += 1;
				}
			}
			return count;
		}


	public:

		auto get_reloca_table(PE_INFO* pe) -> BOOLEAN
		{

			uint32_t rva_rel = NULL;
			uint32_t va_rel = NULL;
			uint32_t end_reloce = NULL;
			uint16_t* relative_info = NULL;
			uint64_t* addr_reloce = NULL;
			RELOCE_TYPE cur_reloce = { NULL };

			memory_file = pe->file_info.alloced_mem;
			nt_headers = pe->file_info.headers;
			sections = pe->file_info.sections;

			if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			{
				va_reloce = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint8_t*>(memory_file) + rva_to_va(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
				size_reloce = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(va_reloce) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

				while (va_reloce < size_reloce && va_reloce->SizeOfBlock)
				{
					end_reloce = (va_reloce->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
					relative_info = reinterpret_cast<uint16_t*>(va_reloce + 1);

					for (uint32_t i = NULL; i != end_reloce; ++i, ++relative_info)
					{
						switch ((*relative_info) >> SHIFT_RELOCE)//https://github.com/DarthTon/Blackbone/blob/5ede6ce50cd8ad34178bfa6cae05768ff6b3859b/src/BlackBoneDrv/ldrreloc.c#L252
						{
						case IMAGE_REL_BASED_DIR64:
						{
							cur_reloce.size = sizeof(uint64_t);
							cur_reloce.rva = va_reloce->VirtualAddress + ((*relative_info) & (PAGE_SIZE - 1));
							cur_reloce.va = rva_to_va(cur_reloce.rva);
							cur_reloce.type = IMAGE_REL_BASED_DIR64;
							pe->reloce_info.list.push_back(cur_reloce);
							break;
						}
						case IMAGE_REL_BASED_HIGHLOW:
						{
							cur_reloce.size = sizeof(uint32_t);
							cur_reloce.rva = va_reloce->VirtualAddress + ((*relative_info) & (PAGE_SIZE - 1));
							cur_reloce.va = rva_to_va(cur_reloce.rva);
							cur_reloce.type = IMAGE_REL_BASED_HIGHLOW;
							pe->reloce_info.list.push_back(cur_reloce);
							break;
						}
						case IMAGE_REL_BASED_LOW:
						{
							cur_reloce.size = sizeof(uint16_t);
							cur_reloce.rva = va_reloce->VirtualAddress + ((*relative_info) & (PAGE_SIZE - 1));
							cur_reloce.va = rva_to_va(cur_reloce.rva);
							cur_reloce.type = IMAGE_REL_BASED_LOW;
							pe->reloce_info.list.push_back(cur_reloce);
							break;
						}
						case IMAGE_REL_BASED_ABSOLUTE:
						{
							//cur_reloce.size = NULL;
							//cur_reloce.rva = va_reloce->VirtualAddress;
							//cur_reloce.va = rva_to_va(cur_reloce.rva);
							//cur_reloce.type = IMAGE_REL_BASED_ABSOLUTE;
							break;
						}
						default:
						{
							if (pe->file_info.is_log)
							{
								printf("[BAD] unknown type ->\t%x", (*relative_info) >> SHIFT_RELOCE);
							}
							return FALSE;
							break;
						}
						}
					}
					va_reloce = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<CHAR*>(va_reloce) + va_reloce->SizeOfBlock);
				}

			}
			else
			{
				pe->file_info.file_status |= FILE_STATUS_NO_RELOCE;
			}
			return TRUE;
		}

		auto create_reloce_list(PE_INFO* pe, uint32_t va) -> BOOLEAN
		{
			uint16_t builded_reloce = NULL;
			uint32_t reloce_size = NULL;
			uint32_t count_cur_list = NULL;
			uint32_t reloce_rva_min = NULL;
			uint32_t reloce_cur_rva_min = NULL;
			uint32_t rva = NULL;
			IMAGE_BASE_RELOCATION reloce_list_info = { NULL };

			memory_file = pe->file_info.alloced_mem;
			nt_headers = pe->file_info.headers;
			sections = pe->file_info.sections;

			if (pe->reloce_info.list.size())
			{
				va = align_correct(va + sizeof(PVOID), sizeof(PVOID));
				rva = va_to_rva(va);

				std::sort(pe->reloce_info.list.begin(), pe->reloce_info.list.end(), [](RELOCE_TYPE& cur, RELOCE_TYPE& next) {return cur.rva < next.rva; });
				count_cur_list = get_count_rva_list(pe, reloce_rva_min);

				for (size_t i = NULL; i < pe->reloce_info.list.size(); i++)
				{


					reloce_cur_rva_min = get_next_min_rva(pe->reloce_info.list[i].rva, reloce_rva_min);

					if (reloce_cur_rva_min && reloce_cur_rva_min > reloce_rva_min)
					{

						count_cur_list = get_count_rva_list(pe, reloce_cur_rva_min);
						reloce_list_info.VirtualAddress = reloce_cur_rva_min;
						reloce_list_info.SizeOfBlock = (count_cur_list * sizeof(uint16_t)) + sizeof(reloce_list_info);
						memcpy(reinterpret_cast<CHAR*>(memory_file) + va + reloce_size, &reloce_list_info, sizeof(reloce_list_info));
						reloce_size += sizeof(reloce_list_info);
						for (size_t j = NULL; j < count_cur_list; j++)
						{
							if (pe->reloce_info.list[i + j].type == IMAGE_REL_BASED_ABSOLUTE)
							{
								builded_reloce = NULL;
							}
							else
							{
								builded_reloce = pe->reloce_info.list[i + j].type;
								builded_reloce <<= SHIFT_RELOCE;
								builded_reloce |= pe->reloce_info.list[i + j].rva;
							}
							memcpy(reinterpret_cast<CHAR*>(memory_file) + va + reloce_size, &builded_reloce, sizeof(builded_reloce));
							reloce_size += sizeof(uint16_t);
						}
						reloce_rva_min = reloce_cur_rva_min;

					}

				}

				memset(reinterpret_cast<CHAR*>(memory_file) + rva_to_va(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress), OPCODE_INT3, nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
				nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = va_to_rva(va);
				nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = reloce_size;

			}
			else
			{
				return TRUE;
			}
			return TRUE;
		}


	};
}
#endif // !RELOCE_PARSER
