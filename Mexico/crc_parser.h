#ifndef CRC_RES_CALC
#define CRC_RES_CALC 1
#include "struct.h"
#include <algorithm>


namespace crc_res_calc
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

	class crc_res_calc
	{
	private:
		PIMAGE_NT_HEADERS  nt_headers = NULL;
		PIMAGE_SECTION_HEADER sections = NULL;

		auto malloc(size_t size) -> PVOID
		{
			return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		}

		auto free(PVOID ptr) -> VOID
		{
			if (ptr)
				VirtualFree(ptr, NULL, MEM_RELEASE);
		}


		//https://github.com/gityf/crc/blob/ac358396a20c77cf664076c5844e656acb5978f2/crc/crc32.c#L72
		auto crc32(uint8_t* crc_addr, uint32_t crc_size) -> uint32_t
		{
			uint32_t crc_res = ~NULL;

			for (uint32_t i = NULL; i < crc_size; i++)
			{
				crc_res = crc32_tab[(crc_res ^ crc_addr[i]) & 0xFF] ^ ((crc_res >> 8) & 0x00FFFFFF);
			}

			return ~crc_res;
		}

		auto rva_to_va(uint64_t rva) -> uint64_t
		{
			for (size_t i = NULL; i < nt_headers->FileHeader.NumberOfSections; i++)
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
			for (size_t i = NULL; i < nt_headers->FileHeader.NumberOfSections; i++)
			{
				if (sections[i].PointerToRawData <= va && (sections[i].PointerToRawData + sections[i].SizeOfRawData) > va)
				{
					return va - sections[i].PointerToRawData + sections[i].VirtualAddress;
				}
			}
			return NULL;
		}
		auto is_ignore_sec(PE_INFO* pe, uint32_t id_sec) -> BOOLEAN
		{
			for (size_t i = 0; i < pe->crc_info.sec_ignore.size(); i++)
			{
				if (pe->crc_info.sec_ignore[i] == id_sec)
				{
					return TRUE;
				}
			}
			return FALSE;
		}

	public:
		auto disk_calc_static_crc(PE_INFO* pe) -> BOOLEAN
		{
			BOOLEAN fisrt_crc_init = FALSE;
			BOOLEAN ignore_first_sec_byte = FALSE;
			BOOLEAN any_crc_ignore = FALSE;
			uint32_t end_reloce = NULL;

			CHAR* name_imp_dll = NULL;
			uint16_t* relative_info = NULL;
			uint64_t* orig_first_thunk = NULL;
			uint64_t* first_thunk = NULL;

			PIMAGE_BASE_RELOCATION va_reloce = NULL;
			PIMAGE_BASE_RELOCATION size_reloce = NULL;
			PIMAGE_IMPORT_DESCRIPTOR imp_descript = NULL;
			PIMAGE_IMPORT_BY_NAME import_name = NULL;
			CRC_INFO crc_cur_file = { NULL };
			std::vector<CRC_IGNORE_INFO> crc_ignore;

			nt_headers = pe->file_info.headers;
			sections = pe->file_info.sections;


			pe->crc_info.list.clear();
			crc_ignore.clear();
			if (!pe->obf_info.obf_reloce)
			{
				for (size_t i = NULL; i < pe->reloce_info.list.size(); i++)
				{
					if (pe->reloce_info.list[i].type != IMAGE_REL_BASED_ABSOLUTE)
					{
						crc_ignore.push_back({ pe->reloce_info.list[i].rva, (uint32_t)(rva_to_va(pe->reloce_info.list[i].rva)), pe->reloce_info.list[i].size });
					}
				}
			}
			else
			{
				__debugbreak();
			}

			if (!pe->obf_info.obf_imp)
			{
				if (pe->import_info.imp_dis.size())
				{
					for (size_t i = NULL; i < pe->import_info.imp_dis.size(); i++)
					{
						crc_ignore.push_back({ pe->import_info.imp_dis[i].import_rva, (uint32_t)(rva_to_va(pe->import_info.imp_dis[i].import_rva)), sizeof(PVOID) });
					}
					for (size_t i = NULL; i < pe->import_info.imp_manual.size(); i++)
					{
						crc_ignore.push_back({ pe->import_info.imp_manual[i].import_rva, (uint32_t)(rva_to_va(pe->import_info.imp_manual[i].import_rva)), sizeof(PVOID) });
					}
				}
				else
				{
					for (size_t i = NULL; i < pe->import_info.imp.size(); i++)
					{
						crc_ignore.push_back({ pe->import_info.imp[i].import_rva, (uint32_t)(rva_to_va(pe->import_info.imp[i].import_rva)), sizeof(PVOID) });
					}
				}
			}
			else
			{
				__debugbreak();
			}

			for (size_t i = NULL; i < pe->crc_info.mem_ignore.size(); i++)
			{
				crc_ignore.push_back({ pe->crc_info.mem_ignore[i].rva, (uint32_t)(rva_to_va(pe->crc_info.mem_ignore[i].rva)), pe->crc_info.mem_ignore[i].size });
			}


			std::sort(crc_ignore.begin(), crc_ignore.end(), [](CRC_IGNORE_INFO& cur, CRC_IGNORE_INFO& next) {return cur.rva < next.rva; });


			for (size_t i = NULL; i < nt_headers->FileHeader.NumberOfSections; i++)
			{
				fisrt_crc_init = FALSE;
				if ((sections[i].Characteristics & IMAGE_SCN_MEM_READ) && !(sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) && !is_ignore_sec(pe, i) && sections[i].SizeOfRawData > sizeof(CHAR))
				{
					any_crc_ignore = TRUE;
					for (size_t j = NULL; j < crc_ignore.size(); j++)
					{
						if (crc_ignore[j].rva >= sections[i].VirtualAddress && (sections[i].VirtualAddress + sections[i].Misc.VirtualSize - sizeof(CHAR)) > crc_ignore[j].rva)
						{
							any_crc_ignore = FALSE;
							break;
						}
					}

					if (any_crc_ignore)	//crc res all secthion
					{
						crc_cur_file.crc_addr_rva = sections[i].VirtualAddress;
						crc_cur_file.crc_size = sections[i].SizeOfRawData;
						crc_cur_file.crc_res = crc32(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + rva_to_va(crc_cur_file.crc_addr_rva), crc_cur_file.crc_size);

						pe->crc_info.list.push_back(crc_cur_file);

					}
					else //get crc
					{
						fisrt_crc_init = TRUE;

						for (size_t j = NULL; j < crc_ignore.size(); j++)
						{
							if (crc_ignore[j].rva >= sections[i].VirtualAddress && (sections[i].VirtualAddress + sections[i].Misc.VirtualSize - sizeof(CHAR)) > crc_ignore[j].rva)
							{
								ignore_first_sec_byte = FALSE;
								if (crc_ignore[j].rva == sections[i].VirtualAddress)
								{
									ignore_first_sec_byte = TRUE;
								}

								if (!ignore_first_sec_byte)
								{
									if (fisrt_crc_init)
									{


										if (j == NULL && crc_ignore[j].rva - sections[i].VirtualAddress > NULL)
										{
											if (crc_ignore.size() > j && crc_ignore[j + 1].rva - crc_ignore[j].rva > NULL)
											{
												crc_cur_file.crc_addr_rva = sections[i].VirtualAddress;
												crc_cur_file.crc_size = crc_ignore[j].rva - sections[i].VirtualAddress;
												crc_cur_file.crc_res = crc32(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + rva_to_va(crc_cur_file.crc_addr_rva), crc_cur_file.crc_size);
												pe->crc_info.list.push_back(crc_cur_file);

												fisrt_crc_init = FALSE;

											}
										}
										else
										{
											if (crc_ignore.size() > j && crc_ignore[j + 1].rva - (crc_ignore[j].rva + crc_ignore[j].size) > NULL)
											{
												if (crc_ignore[j + 1].rva >= sections[i].VirtualAddress && (sections[i].VirtualAddress + sections[i].Misc.VirtualSize) > crc_ignore[j + 1].rva)
												{
													crc_cur_file.crc_addr_rva = crc_ignore[j].rva + crc_ignore[j].size;
													crc_cur_file.crc_size = crc_ignore[j + 1].rva - crc_cur_file.crc_addr_rva;
													crc_cur_file.crc_res = crc32(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + rva_to_va(crc_cur_file.crc_addr_rva), crc_cur_file.crc_size);
													fisrt_crc_init = FALSE;
													pe->crc_info.list.push_back(crc_cur_file);
												}
												else
												{

													crc_cur_file.crc_addr_rva = sections[i].VirtualAddress;
													crc_cur_file.crc_size = crc_ignore[j].rva - crc_cur_file.crc_addr_rva;
													crc_cur_file.crc_res = crc32(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + sections[i].PointerToRawData, crc_cur_file.crc_size);
													pe->crc_info.list.push_back(crc_cur_file);


													crc_cur_file.crc_addr_rva = crc_ignore[j].rva + crc_ignore[j].size;
													crc_cur_file.crc_size = sections[i].SizeOfRawData - crc_cur_file.crc_size - crc_ignore[j].size;
													crc_cur_file.crc_res = crc32(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + rva_to_va(crc_cur_file.crc_addr_rva), crc_cur_file.crc_size);
													pe->crc_info.list.push_back(crc_cur_file);
													fisrt_crc_init = FALSE;

													break;
												}

											}
											else if (crc_ignore.size() == 1)
											{
												crc_cur_file.crc_addr_rva = sections[i].VirtualAddress;
												crc_cur_file.crc_size = crc_ignore[j].rva - crc_cur_file.crc_addr_rva;
												crc_cur_file.crc_res = crc32(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + sections[i].PointerToRawData, crc_cur_file.crc_size);
												pe->crc_info.list.push_back(crc_cur_file);


												crc_cur_file.crc_addr_rva = crc_ignore[j].rva + crc_ignore[j].size;
												crc_cur_file.crc_size = sections[i].SizeOfRawData - crc_cur_file.crc_size - crc_ignore[j].size;
												crc_cur_file.crc_res = crc32(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + rva_to_va(crc_cur_file.crc_addr_rva), crc_cur_file.crc_size);
												pe->crc_info.list.push_back(crc_cur_file);
												fisrt_crc_init = FALSE;

											}
										}
									}
									else
									{
										if (crc_ignore.size() > j)
										{
											if (crc_ignore[j + 1].rva - (crc_ignore[j].rva + crc_ignore[j].size) > NULL)
											{
												if (crc_ignore[j + 1].rva >= sections[i].VirtualAddress && (sections[i].VirtualAddress + sections[i].Misc.VirtualSize) > crc_ignore[j + 1].rva + crc_ignore[j + 1].size)
												{
													if (crc_ignore[j + 1].rva > crc_ignore[j].rva && crc_ignore[j + 1].rva > crc_ignore[j].rva + crc_ignore[j].size)
													{
														crc_cur_file.crc_addr_rva = crc_ignore[j].rva + crc_ignore[j].size;
														crc_cur_file.crc_size = crc_ignore[j + 1].rva - crc_cur_file.crc_addr_rva;
														crc_cur_file.crc_res = crc32(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + rva_to_va(crc_cur_file.crc_addr_rva), crc_cur_file.crc_size);
														fisrt_crc_init = FALSE;

														pe->crc_info.list.push_back(crc_cur_file);
													}
												}
												else  if (sections[i].VirtualAddress + sections[i].SizeOfRawData - (crc_ignore[j].rva + crc_ignore[j].size) > NULL)
												{
													crc_cur_file.crc_addr_rva = crc_ignore[j].rva + crc_ignore[j].size;
													crc_cur_file.crc_size = sections[i].VirtualAddress + sections[i].SizeOfRawData - crc_cur_file.crc_addr_rva;
													crc_cur_file.crc_res = crc32(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + rva_to_va(crc_cur_file.crc_addr_rva), crc_cur_file.crc_size);
													fisrt_crc_init = FALSE;

													pe->crc_info.list.push_back(crc_cur_file);
													break;
												}
												else
												{
													break;
												}
											}
										}
										else if (crc_ignore.size() == 1)
										{
											__debugbreak();
										}
									}
								}
								else//start by cur and next rva
								{
									if (crc_ignore.size() > j)
									{
										if (crc_ignore[j + 1].rva - (crc_ignore[j].rva + crc_ignore[j].size) > NULL)
										{
											if (crc_ignore[j + 1].rva > crc_ignore[j].rva && crc_ignore[j + 1].rva > crc_ignore[j].rva + crc_ignore[j].size)
											{
												crc_cur_file.crc_addr_rva = crc_ignore[j].rva + crc_ignore[j].size;
												crc_cur_file.crc_size = crc_ignore[j + 1].rva - crc_cur_file.crc_addr_rva;
												crc_cur_file.crc_res = crc32(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + rva_to_va(crc_cur_file.crc_addr_rva), crc_cur_file.crc_size);

												pe->crc_info.list.push_back(crc_cur_file);
											}
										}
									}
									else if (crc_ignore.size() == 1)
									{

										//not check code
										crc_cur_file.crc_addr_rva = crc_ignore[j].rva + crc_ignore[j].size;
										crc_cur_file.crc_size = sections[i].VirtualAddress + sections[i].SizeOfRawData - crc_ignore[j].size;
										crc_cur_file.crc_res = crc32(reinterpret_cast<uint8_t*>(pe->file_info.alloced_mem) + rva_to_va(crc_cur_file.crc_addr_rva), crc_cur_file.crc_size);
										pe->crc_info.list.push_back(crc_cur_file);
										fisrt_crc_init = FALSE;

									}
									else
									{
										__debugbreak();
									}
								}
							}
						}

					}
				}
			}


			crc_ignore.clear();
			return TRUE;
		}





	};

}
#endif // !CRC_RES_CALC