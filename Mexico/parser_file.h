#ifndef PARSER_FILE
#define PARSER_FILE 1
#include "struct.h"
#include <string>

#define SECTHION_READ_ONLY ( IMAGE_SCN_MEM_READ  | IMAGE_SCN_CNT_INITIALIZED_DATA)
#define SECTHION_RX (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)
#define SECTHION_RWX (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)
namespace pe_parse
{

	class pe_parse
	{
	private:

		uint32_t status_type_file = NULL;
		DWORD file_size = NULL;
		DWORD file_new_size = NULL;
		PVOID memory_file = NULL;
		std::wstring path_file = L"";

		PVOID malloc(size_t size)
		{
			return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		}

		VOID free(PVOID ptr)
		{
			if (nullptr != ptr)
				VirtualFree(ptr, NULL, MEM_RELEASE);
		}

		auto get_rand() -> uint64_t
		{
			return __rdtsc() % INT_MAX;
		}

		auto set_rand_buf(CHAR* addr, uint32_t size)
		{
			for (size_t i = 0; i < size; i++)
			{
				*reinterpret_cast<uint8_t*>(addr + i) = get_rand();
			}
		}

 

		NO_INLINE auto get_type_file(PE_INFO* pe) -> BOOLEAN
		{

			if (pe->file_info.headers->FileHeader.Characteristics & IMAGE_FILE_DLL)
			{
				if (pe->file_info.headers->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI)
				{
					status_type_file = STATUS_DLL;
					return TRUE;
				}
				else if (pe->file_info.headers->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER)
				{
					status_type_file = STATUS_EFI;
					return TRUE;
				}

			}
			else if (pe->file_info.headers->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
			{
				if (pe->file_info.headers->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE)
				{
					status_type_file = STATUS_DRIVER;
					return TRUE;
				}
				else if
					(
						pe->file_info.headers->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI ||
						pe->file_info.headers->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI
						)
				{
					status_type_file = STATUS_EXE;
					return TRUE;
				}
			}
			return FALSE;
		}



	public:
		NO_INLINE auto get_va_by_sec_id(PE_INFO* pe, uint32_t sec_id) -> uint32_t
		{
			return pe->file_info.sections[sec_id].PointerToRawData;
		}

		NO_INLINE auto is_file_valid(PE_INFO* pe) -> BOOLEAN
		{
			BOOLEAN is_correct_pe = FALSE;
			DWORD num_read = NULL;
			HANDLE access_file = NULL;

			path_file = pe->path_pe;
			access_file = CreateFileW(path_file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

			if (access_file != INVALID_HANDLE_VALUE)
			{
				file_size = GetFileSize(access_file, NULL);
				if (file_size)
				{
					memory_file = malloc(file_size + sizeof(IMAGE_SECTION_HEADER));
					if (memory_file)
					{
						memset(memory_file, NULL, file_size);
						if (ReadFile(access_file, memory_file, file_size, &num_read, NULL))
						{
							if (static_cast<PIMAGE_DOS_HEADER>(memory_file)->e_magic == IMAGE_DOS_SIGNATURE)
							{

								pe->file_info.alloced_mem = memory_file;
								pe->file_info.file_size = file_size;
								pe->file_info.file_status = NULL;
								pe->file_info.file_size = file_size;

								pe->file_info.headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(memory_file) + static_cast<PIMAGE_DOS_HEADER>(memory_file)->e_lfanew);

								if (pe->file_info.headers->Signature == IMAGE_NT_SIGNATURE && get_type_file(pe))
								{
									pe->file_info.sections = IMAGE_FIRST_SECTION(pe->file_info.headers);
									pe->file_info.oep = pe->file_info.headers->OptionalHeader.AddressOfEntryPoint;
									pe->file_info.type_file = status_type_file;
									if (pe->file_info.headers->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
									{
										pe->file_info.arch_file = ARCH_X64;
										is_correct_pe = TRUE;
									}
									else if (pe->file_info.headers->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
									{
										pe->file_info.arch_file = ARCH_X32;
										is_correct_pe = TRUE;
									}
								}
							}
						}
					}
				}
				CloseHandle(access_file);
			}
			if (!is_correct_pe)
				free(memory_file);
			return is_correct_pe;
		}

		NO_INLINE auto set_ep(PE_INFO* pe, uint32_t rva) -> bool
		{
			pe->file_info.headers->OptionalHeader.AddressOfEntryPoint = rva;
			pe->file_info.new_oep = rva;

		}
		NO_INLINE uint32_t align(uint32_t address, uint32_t alignment)
		{
			address += (alignment - (address % alignment));
			return address;
		}

		NO_INLINE uint32_t align_correct(DWORD address, uint32_t alignment)
		{
			if (address % alignment != NULL)
			{
				address += (alignment - (address % alignment));
			}
			return address;
		}

		NO_INLINE auto write_sec_info(PIMAGE_OPTIONAL_HEADER optional_header, PIMAGE_SECTION_HEADER new_section_header, PIMAGE_SECTION_HEADER last_section, uint32_t size) -> VOID
		{
			//new_section_header->Misc.VirtualSize = size; 
			new_section_header->Misc.VirtualSize = align_correct(size, optional_header->SectionAlignment); //Aligning VirtualSize is not mandatory, but my eye twitches a little when SizeOfRawData > VirtualSize
			new_section_header->VirtualAddress = align_correct(last_section->VirtualAddress + last_section->Misc.VirtualSize, optional_header->SectionAlignment);
			new_section_header->SizeOfRawData = align_correct(size /* + sizeof(uint32_t) + 1*/, optional_header->FileAlignment);
			new_section_header->PointerToRawData = align_correct(last_section->PointerToRawData + last_section->SizeOfRawData, optional_header->FileAlignment);
			new_section_header->PointerToRelocations = NULL;
			new_section_header->PointerToLinenumbers = NULL;
			new_section_header->NumberOfRelocations = NULL;
			new_section_header->NumberOfLinenumbers = NULL;
		}

		// https://github.com/weak1337/Alcatraz/blob/739e65ebadaeb3f8206fb2199700725331465abb/Alcatraz/pe/pe.cpp#L85
		NO_INLINE auto  create_section(PE_INFO* pe, CONST CHAR* name, uint32_t size, uint32_t characteristic) -> uint32_t
		{
			uint32_t cur_size_size_header = NULL;
			uint32_t new_size_size_header = NULL;
			PVOID copy_alloce = NULL;
			if (strlen(name) > IMAGE_SIZEOF_SHORT_NAME)
				return INT_MAX;
			PIMAGE_FILE_HEADER file_header = NULL;
			PIMAGE_OPTIONAL_HEADER optional_header = NULL;
			PIMAGE_SECTION_HEADER section_header = NULL;
			PIMAGE_SECTION_HEADER last_section = NULL;
			PIMAGE_SECTION_HEADER new_section_header = NULL;

			file_header = &pe->file_info.headers->FileHeader;
			optional_header = &pe->file_info.headers->OptionalHeader;
			section_header = IMAGE_FIRST_SECTION(pe->file_info.headers);
			last_section = &section_header[file_header->NumberOfSections - 1];

			//or reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<CHAR*>(&last_section->Name[NULL]) + sizeof(IMAGE_SECTION_HEADER));
			//new_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<CHAR*>(&last_section->Characteristics) + sizeof(last_section->Characteristics));
			new_section_header = &section_header[file_header->NumberOfSections];

			memcpy(new_section_header->Name, name, strlen(name));
			new_section_header->Characteristics = characteristic;
			write_sec_info(optional_header, new_section_header, last_section, size);


			file_header->NumberOfSections += 1;

			cur_size_size_header = align_correct(reinterpret_cast<PIMAGE_DOS_HEADER>(pe->file_info.alloced_mem)->e_lfanew + file_header->SizeOfOptionalHeader + (file_header->NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER), optional_header->FileAlignment);
			new_size_size_header = align_correct(reinterpret_cast<PIMAGE_DOS_HEADER>(pe->file_info.alloced_mem)->e_lfanew + file_header->SizeOfOptionalHeader + file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER), optional_header->FileAlignment);

			//need re-check(костыль с IMAGE_DOS_HEADER)
			//https://stackoverflow.com/questions/76815878/understanding-sizeofheaders
			optional_header->SizeOfHeaders = new_size_size_header;

			if (optional_header->SizeOfHeaders > section_header[NULL].PointerToRawData)
			{
				printf("will be copy first section");
				getchar();
			}

			optional_header->SizeOfImage = align_correct(optional_header->SizeOfImage + new_section_header->Misc.VirtualSize, optional_header->SectionAlignment);

			pe->file_info.file_new_size = align_correct(pe->file_info.file_size + new_section_header->SizeOfRawData, optional_header->FileAlignment);
			file_new_size = pe->file_info.file_new_size;
			//copy buffer
			copy_alloce = malloc(pe->file_info.file_new_size * 2);
			memset(copy_alloce, NULL, pe->file_info.file_size);

			memcpy(copy_alloce, pe->file_info.alloced_mem, pe->file_info.file_size);


			free(pe->file_info.alloced_mem);
			pe->file_info.alloced_mem = copy_alloce;


			memory_file = pe->file_info.alloced_mem;
			pe->file_info.file_size = pe->file_info.file_new_size;
			pe->file_info.headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(memory_file) + static_cast<PIMAGE_DOS_HEADER>(memory_file)->e_lfanew);
			pe->file_info.sections = IMAGE_FIRST_SECTION(pe->file_info.headers);
			pe->file_info.oep = pe->file_info.headers->OptionalHeader.AddressOfEntryPoint;


			return pe->file_info.headers->FileHeader.NumberOfSections - 1;
		}

		NO_INLINE auto save_file(PE_INFO* pe) -> BOOLEAN
		{
			BOOLEAN is_create = FALSE;
			HANDLE new_access = NULL;
			memory_file = pe->file_info.alloced_mem;

			if (status_type_file == STATUS_EXE)
			{
				path_file = path_file + L"_new.exe";
			}
			else if (status_type_file == STATUS_DLL)
			{
				path_file = path_file + L"_new.dll";
			}
			else if (status_type_file == STATUS_DRIVER)
			{
				path_file = path_file + L"_new.sys";
			}
			else if (status_type_file == STATUS_EFI)
			{
				path_file = path_file + L"_new.efi";
			}
			new_access = CreateFileW
			(
				path_file.c_str(),
				GENERIC_READ | GENERIC_WRITE,
				NULL,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL
			);
			if (new_access)
			{
				if (WriteFile(new_access, memory_file, file_new_size, NULL, NULL))
				{
					is_create = TRUE;
				}
				CloseHandle(new_access);
			}
			return is_create;
		}
	};
}

#endif // !PARSER_FILE
