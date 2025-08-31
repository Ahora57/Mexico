#include <iostream>
#include "import_pars.h"
#include "reloce_parser.h"
#include "parser_file.h"
#include "crc_parser.h"
#include "code_parser.h"
#include "crc_add.h"
#include "anti_vm_add.h"
#include "anti_debug_add.h"

NO_INLINE auto get_file_pre_test(PE_INFO* pe) -> BOOLEAN
{ 
    BOOLEAN is_success_get = FALSE;
    uint32_t buffer_size = NULL;
    WCHAR path_file[MAX_PATH] = { NULL }; 
    buffer_size = GetModuleFileNameW(NULL , path_file, sizeof(path_file));
    if (buffer_size)
    {
        for (INT i = buffer_size; i > NULL; i--)
        {
            if (path_file[i] == '\\')
            {
                memset(&path_file[i], NULL, buffer_size - i);
                break;
            }
        }

        pe->path_pe = path_file;
        pe->path_pe += L"\\pre_test_exe.exe";
        is_success_get = pe->path_pe.size() != NULL;
    }
    return is_success_get;
}

int main()
{

    PE_INFO pe;
    pe_parse::pe_parse file_pe_parse;
    code_parse::code_parse code_pars;
    reloce_info_pe::reloce_info_pe reloce_pe;
    import_pars::import_pars import_pe;
    crc_res_calc::crc_res_calc crc_res_calc;
    crc_sdk_util::crc_sdk_util crc_calc;
    anti_debug_sdk_util::anti_debug_sdk_util anti_deb;
    anti_vm_sdk_util::anti_vm_sdk_util anti_vm;

    //Util
    uint32_t cur_add_va_use = NULL;
    uint32_t cur_va_use = NULL;
    uint32_t cur_va_use_old = NULL;
    uint32_t new_sec_code[5] = { INT_MAX };
    uint32_t crc_count = NULL, anti_deb_count = NULL, anti_vm_count = NULL;

    pe.path_pe = L"";

    SetConsoleTitleW(L"Mexico");

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    memset(&pe.file_info, NULL, sizeof(pe.file_info));


    pe.obf_info.obf_reloce = FALSE;
    pe.obf_info.obf_imp = FALSE;

    printf("\n");
    if (get_file_pre_test(&pe) && file_pe_parse.is_file_valid(&pe) && reloce_pe.get_reloca_table(&pe))
    {

        if (pe.file_info.arch_file == ARCH_X64)
        {
            printf("Arch file x64!\n");
        }
        else if (pe.file_info.arch_file == ARCH_X32)
        {
            printf("Arch file x32!\n");
        }

        if (pe.file_info.type_file == STATUS_EXE)
        {
            printf("File type .exe!\n");
            printf("supported file!\n");
        }
        else if (pe.file_info.type_file == STATUS_DLL)
        {
            printf("File type .dll!\n");
            printf("supported file!\n");

        }
        else if (pe.file_info.type_file == STATUS_DRIVER)
        {
            printf("File type .sys!\n");
            //I haven't done any checks or fix code
            printf("supported file?\n");

        }
        else if (pe.file_info.type_file == STATUS_EFI)
        {
            printf("File type .efi!\n");
            printf("unsupported file!\n");
            getchar();
            exit(EXIT_FAILURE);
        }

        if (import_pe.get_import(&pe))
        {

        }



        if (code_pars.get_code(&pe))
        {
            for (size_t i = NULL; i < pe.import_info.imp_dis.size(); i++)
            {
                printf("\nimport name ->\t%s\n", pe.import_info.imp_dis[i].name_api);
                printf("dll name ->\t%s\n", pe.import_info.imp_dis[i].name_dll);
                printf("import rva ->\t%p\n", pe.import_info.imp_dis[i].import_rva);
                for (size_t j = NULL; j < pe.import_info.imp_dis[i].code_rva.size(); j++)
                {
                    printf("import rva use ->\t%p\n", pe.import_info.imp_dis[i].code_rva[j]);
                }
            }

            for (size_t i = NULL; i < pe.import_info.imp_sdk.size(); i++)
            {
                printf("\nSDK name ->\t%s\n", pe.import_info.imp_sdk[i].name_api);
                printf("import rva ->\t%p\n", pe.import_info.imp_sdk[i].import_rva);
                for (size_t j = NULL; j < pe.import_info.imp_sdk[i].code_rva.size(); j++)
                {
                    printf("SDK rva use ->\t%p\n", pe.import_info.imp_sdk[i].code_rva[j]);
                }
            }
            import_pe.get_not_find_dis_imp(&pe);

        }

        crc_count = crc_calc.count_exist_sdk(&pe);
        anti_deb_count = anti_deb.count_exist_sdk(&pe);
        anti_vm_count = anti_vm.count_exist_sdk(&pe);


        if (crc_count)
        {
            if (pe.file_info.type_file == STATUS_DLL || pe.file_info.type_file == STATUS_EXE)
            {
                import_pe.add_imp(&pe, "KERNEL32.DLL", "VirtualQuery");
            }
        }
        if (anti_deb_count)
        {
            if (pe.file_info.type_file == STATUS_DLL || pe.file_info.type_file == STATUS_EXE)
            {
                import_pe.add_imp(&pe, "NTDLL.DLL", "NtQueryInformationProcess");
                import_pe.add_imp(&pe, "NTDLL.DLL", "NtSetInformationThread");
                import_pe.add_imp(&pe, "NTDLL.DLL", "NtQueryInformationThread");
            }
            else if (pe.file_info.type_file == STATUS_DRIVER)
            {
                import_pe.add_imp(&pe, "ntoskrnl.exe", "NtQuerySystemInformation");
            }
        }
        if (anti_vm_count)
        {

        }

        new_sec_code[1] = file_pe_parse.create_section(&pe, ".test1", 0x1337, SECTHION_READ_ONLY);
        cur_va_use = file_pe_parse.get_va_by_sec_id(&pe, new_sec_code[1]);

        cur_add_va_use = import_pe.set_new_import(&pe, cur_va_use);
        if (cur_add_va_use)
        {
            cur_va_use += cur_add_va_use;
            import_pe.fix_new_import(&pe);
            cur_va_use_old = cur_va_use;
            cur_add_va_use = NULL;
        }
        else
        {
            printf("Bad init new import table!\n");
            getchar();
            return EXIT_SUCCESS;
        }



        if (new_sec_code[1] == INT_MAX)
        {
            printf("bad name sec!\n");
            getchar();
            return EXIT_SUCCESS;
        }

        if (crc_count || anti_deb_count || anti_vm_count)
        {
            new_sec_code[NULL] = file_pe_parse.create_section(&pe, ".test0", 0x1337, SECTHION_RX);

            if (new_sec_code[NULL] == INT_MAX)
            {
                printf("bad name sec!\n");
                getchar();
                return EXIT_SUCCESS;
            }



            // pe.crc_info.sec_ignore.push_back(new_sec_code[NULL]);
            // pe.crc_info.sec_ignore.push_back(new_sec_code[1]);

            cur_va_use = file_pe_parse.get_va_by_sec_id(&pe, new_sec_code[NULL]);
            if (!cur_va_use)
            {
                printf("bad get va sec!\n");
                getchar();
                return EXIT_SUCCESS;
            }


            if (anti_deb_count)
            {
                cur_add_va_use = anti_deb.add_code(&pe, cur_va_use);
                anti_deb.update_info(&pe, cur_va_use);
                import_pe.fix_new_import(&pe);
            }
            if (cur_add_va_use)
            {
                cur_va_use += cur_add_va_use;
                cur_add_va_use = NULL;
            }


            if (anti_vm_count)
            {
                cur_add_va_use = anti_vm.add_code(&pe, cur_va_use);
                anti_vm.update_info(&pe, cur_va_use);
                import_pe.fix_new_import(&pe);
            }
            if (cur_add_va_use)
            {
                cur_va_use += cur_add_va_use;
                cur_add_va_use = NULL;
            }

            if (crc_count)
            {
                crc_calc.update_info(&pe, cur_va_use);
                import_pe.fix_sdk(&pe);
                cur_add_va_use = crc_calc.add_code(&pe, &import_pe, &reloce_pe, &crc_res_calc, cur_va_use_old, cur_va_use);

            }
            if (cur_add_va_use)
            {
                cur_va_use += cur_add_va_use;
                cur_add_va_use = NULL;
            }
            if (!crc_count)
            {
                import_pe.fix_sdk(&pe);
                reloce_pe.create_reloce_list(&pe, cur_va_use);
            }
        }
        else
        {
            reloce_pe.create_reloce_list(&pe, cur_va_use);
        }



        file_pe_parse.save_file(&pe);

    }
    else
    {
        printf("bad!\n");
    }

    pe.path_pe.clear();
    pe.reloce_info.list.clear();
    pe.import_info.imp.clear();
    pe.import_info.imp_manual.clear();
    pe.import_info.imp_sdk.clear();
    pe.crc_info.list.clear();
    pe.crc_info.mem_ignore.clear();
    pe.crc_info.sec_ignore.clear();

    printf("\n");
    getchar();

    return EXIT_SUCCESS;
}