#ifndef ZYDIS_DISASSEMBLY_UTIL
#define ZYDIS_DISASSEMBLY_UTIL
#include <Zydis/Zydis.h>
#include <Windows.h>

#define MAX_LENGHT_INSTR 15

#ifndef _WIN64
#define dis_mode ZYDIS_MACHINE_MODE_LONG_COMPAT_32
#else
#define dis_mode ZYDIS_MACHINE_MODE_LONG_64
#endif // !_WIN64

#ifndef ELEMENT_64
#define ELEMENT_64 0x40
#endif 

#ifndef ELEMENT_32
#define ELEMENT_32 0x20
#endif 

#ifndef ELEMENT_16
#define ELEMENT_16 0x10
#endif 

#ifndef ELEMENT_8
#define ELEMENT_8 0x8
#endif 

namespace dis
{
    auto get_reg_size(ZydisRegister* reg) -> uint32_t
    {
        uint32_t num_reg = NULL;
        if (*reg >= ZYDIS_REGISTER_RAX && ZYDIS_REGISTER_R15 >= *reg)
        {
            return sizeof(PVOID);

        }
        else if (*reg >= ZYDIS_REGISTER_EAX && ZYDIS_REGISTER_R15D >= *reg)
        {
            return sizeof(ULONG);

        }
        else if (*reg >= ZYDIS_REGISTER_AX && ZYDIS_REGISTER_R15W >= *reg)
        {
            return sizeof(USHORT);
        }
        else if (*reg >= ZYDIS_REGISTER_AL && ZYDIS_REGISTER_R15B >= *reg)
        {
            return sizeof(CHAR);
        }
    }

    auto get_pointer_size(ZydisDisassembledInstruction* dis_instr) -> uint32_t
    {
        uint32_t size_reg = NULL;
        uint32_t size_point = NULL;
        uint32_t size_element = NULL;
        for (size_t i = NULL; i < dis_instr->info.operand_count_visible; i++)
        {
            if (!size_reg && dis_instr->operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                size_reg = get_reg_size(&dis_instr->operands[i].reg.value);
            }
            if (!size_point && dis_instr->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                size_point = get_reg_size(&dis_instr->operands[i].mem.base);
                size_element = dis_instr->operands[i].element_size;
            }
        }
        if (size_reg && size_point)
        {
            if (size_reg == size_point)
            {
                return size_point;
            }
            else if (size_reg > size_point)
            {
                return size_point;
            }
            else //error via mov rax,qword ptr ds:[eax]
            {
                return NULL;
            }
        }
        else if (size_point && size_element)
        {
            if (size_element == ELEMENT_64)
            {
                return sizeof(ULONG) * 2;
            }
            else if (size_element == ELEMENT_32)
            {
                return sizeof(ULONG);

            }
            else if (size_element == ELEMENT_16)
            {
                return sizeof(USHORT);

            }
            else if (size_element == ELEMENT_8)
            {
                return sizeof(CHAR);
            }
        }
        return NULL;
    }

    auto get_dis(ZydisDisassembledInstruction* instruction, CHAR* runtime_address) -> ZyanStatus
    {
        return ZydisDisassembleIntel
        (
            dis_mode,
            reinterpret_cast<ZyanU64>(runtime_address),
            runtime_address,
            MAX_LENGHT_INSTR,
            instruction
        );
    }

    auto is_rip_instr(ZydisDisassembledInstruction* instruction) -> bool
    {

        for (UINT i = NULL; i < instruction->info.operand_count_visible; i++)
        {
            if (instruction->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
#ifndef _WIN64
                if (instruction->operands[i].mem.base == ZYDIS_REGISTER_NONE)
                {
                    return TRUE;
                }
#else
                if (instruction->operands[i].mem.base == ZYDIS_REGISTER_RIP)
                {
                    return TRUE;
                }
#endif
            }
        }

        return FALSE;

    }

    //add lea,mov and other
    auto is_pos_import(ZydisDisassembledInstruction* instruction) -> bool
    {
        if ((instruction->info.mnemonic == ZYDIS_MNEMONIC_JMP && instruction->info.operand_count == 2) ||
            (instruction->info.mnemonic == ZYDIS_MNEMONIC_CALL && instruction->info.operand_count == 4) ||
            instruction->info.mnemonic == ZYDIS_MNEMONIC_MOV ||
            instruction->info.mnemonic == ZYDIS_MNEMONIC_LEA
            )
        {
            if (is_rip_instr(instruction))
            {
                return TRUE;
            }

        }
        return FALSE;
    }

    auto is_pos_exp(ZydisDisassembledInstruction* instruction) -> bool
    {
        if ((instruction->info.mnemonic == ZYDIS_MNEMONIC_JMP && instruction->info.operand_count == 2) ||
            (instruction->info.mnemonic == ZYDIS_MNEMONIC_CALL && instruction->info.operand_count == 4)
            )
        {
            if (instruction->operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                return TRUE;
            }
        }
        return FALSE;
    }
    auto is_jmp(ZydisDisassembledInstruction* instr) -> bool
    {
        switch (instr->info.mnemonic)
        {
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
        case ZYDIS_MNEMONIC_JMP:
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
            return ZYAN_TRUE;
        default:
            break;
        }
        return ZYAN_FALSE;
    }

    auto is_call(ZydisDisassembledInstruction* instr) -> bool
    {
        switch (instr->info.mnemonic)
        {
        case ZYDIS_MNEMONIC_CALL:
            return ZYAN_TRUE;
        default:
            break;
        }
        return ZYAN_FALSE;
    }

    bool is_selector(ZydisDisassembledInstruction* instr)
    {
        switch (instr->operands->reg.value)
        {
        case ZYDIS_REGISTER_SS:
        case ZYDIS_REGISTER_GS:
        case ZYDIS_REGISTER_FS:
        case ZYDIS_REGISTER_DS:
        case ZYDIS_REGISTER_ES:
        case ZYDIS_REGISTER_CS:
            return ZYAN_TRUE;
        default:
            break;
        }
        return ZYAN_FALSE;
    }


    ZyanU64 get_absolute_address(ZydisDisassembledInstruction* instruction, CHAR* runtime_address)
    {

        ZyanU64 destination = 0ULL;

        for (UINT i = NULL; i < instruction->info.operand_count; i++)
        {
            if ((instruction->operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && instruction->operands[i].imm.is_relative == TRUE) || instruction->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                ZydisCalcAbsoluteAddress(&instruction->info, &instruction->operands[i], reinterpret_cast<ZyanU64>(runtime_address), &destination);
                break;
            }

            if (instruction->operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && instruction->operands[i].imm.is_relative == FALSE)
            {
                destination = instruction->operands[i].imm.value.u;
                break;
            }
        }

        return destination;
    }

}

#endif 