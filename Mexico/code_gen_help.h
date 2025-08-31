#ifndef CODE_GEN_UTIL
#define CODE_GEN_UTIL 
#include <vector>
#include "disassembly_util.h" 
#include <asmjit/asmjit.h>

#ifndef USE_ASMJIT
#define USE_ASMJIT 1
#define CALL_SIZE 0x5
using namespace asmjit;
#endif // !USE_ASMJIT

#ifndef _WIN64
#define MIN_REG_PLAT ZYDIS_REGISTER_EAX
#define MAX_REG_PLAT ZYDIS_REGISTER_EDI
#define REG_VSP ZYDIS_REGISTER_ESP
#else 
#define MIN_REG_PLAT ZYDIS_REGISTER_RAX
#define MAX_REG_PLAT ZYDIS_REGISTER_R15
#define REG_VSP ZYDIS_REGISTER_RSP
#endif // !_WIN64


#ifndef _WIN64
auto current_vsp = x86::esp;
auto current_vip = x86::rip;
#else 
auto current_vsp = x86::rsp;
auto current_vip = x86::rip;
#endif // !_WIN64

namespace cg_util
{

	NO_INLINE auto reg_correct(ZydisRegister* reg) -> BOOLEAN
	{
		return  *reg >= MIN_REG_PLAT && MAX_REG_PLAT > *reg;
	}

	NO_INLINE auto ger_rand_reg(ZydisRegister* reg, uint32_t size) -> BOOLEAN
	{
		BOOLEAN is_create = FALSE;
		if (size == sizeof(ULONG) * 2)
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_RAX + __rdtsc() % (ZYDIS_REGISTER_R15 - ZYDIS_REGISTER_RAX));
				is_create = TRUE;
				if (ZYDIS_REGISTER_RSP == *reg)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(ULONG))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_EAX + __rdtsc() % (ZYDIS_REGISTER_EDI - ZYDIS_REGISTER_EAX));
				is_create = TRUE;
				if (ZYDIS_REGISTER_ESP == *reg)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(USHORT))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_AX + __rdtsc() % (ZYDIS_REGISTER_DI - ZYDIS_REGISTER_AX));
				is_create = TRUE;
				if (ZYDIS_REGISTER_SP == *reg)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(CHAR))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_AL + __rdtsc() % (ZYDIS_REGISTER_BH - ZYDIS_REGISTER_AL));
				is_create = TRUE;
				if (ZYDIS_REGISTER_SPL == *reg)
				{
					is_create = FALSE;
				}
			}
		}
		return is_create;

	}


	NO_INLINE auto ger_rand_reg(ZydisRegister* reg, uint32_t size, std::vector<ZydisRegister>& ignore_reg) -> BOOLEAN
	{
		BOOLEAN is_create = FALSE;
		if (size == sizeof(ULONG) * 2)
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_RAX + __rdtsc() % (ZYDIS_REGISTER_R15 - ZYDIS_REGISTER_RAX));
				is_create = TRUE;

				for (size_t i = 0; i < ignore_reg.size(); i++)
				{
					if (ignore_reg[i] == *reg)
					{
						is_create = FALSE;
					}
				}
				if (ZYDIS_REGISTER_RSP == *reg)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(ULONG))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_EAX + __rdtsc() % (ZYDIS_REGISTER_EDI - ZYDIS_REGISTER_EAX));
				is_create = TRUE;
				for (size_t i = 0; i < ignore_reg.size(); i++)
				{
					if (ignore_reg[i] == *reg)
					{
						is_create = FALSE;
					}
				}
				if (ZYDIS_REGISTER_ESP == *reg)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(USHORT))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_AX + __rdtsc() % (ZYDIS_REGISTER_DI - ZYDIS_REGISTER_AX));
				is_create = TRUE;

				for (size_t i = 0; i < ignore_reg.size(); i++)
				{
					if (ignore_reg[i] == *reg)
					{
						is_create = FALSE;
					}
				}
				if (ZYDIS_REGISTER_SP == *reg)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(CHAR))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_AL + __rdtsc() % (ZYDIS_REGISTER_BH - ZYDIS_REGISTER_AL));
				is_create = TRUE;

				for (size_t i = 0; i < ignore_reg.size(); i++)
				{
					if (ignore_reg[i] == *reg)
					{
						is_create = FALSE;
					}
				}
				if (ZYDIS_REGISTER_SPL == *reg)
				{
					is_create = FALSE;
				}
			}
		}

		if (is_create)
		{
			ignore_reg.push_back(*reg);
		}
		return is_create;

	}
	NO_INLINE auto reg_conv(ZydisRegister* reg) -> x86::Gp //aye trick
	{
		uint32_t reg_size = NULL;
		uint32_t num_reg = NULL;

		if (*reg >= ZYDIS_REGISTER_RAX && ZYDIS_REGISTER_R15 > *reg)
		{
			//.r64()  
			num_reg = *reg - ZYDIS_REGISTER_RAX;
			return x86::Gp::make_r64(num_reg).r64(); //see x86::rax

		}
		else if (*reg >= ZYDIS_REGISTER_EAX && ZYDIS_REGISTER_R15D > *reg)
		{
			num_reg = *reg - ZYDIS_REGISTER_EAX;
			return x86::Gp::make_r32(num_reg).r32(); //see x86::rax
		}
		else if (*reg >= ZYDIS_REGISTER_AX && ZYDIS_REGISTER_R15W > *reg)
		{
			num_reg = *reg - ZYDIS_REGISTER_AX;
			return x86::Gp::make_r16(num_reg).r16(); //see x86::rax
		}
		else if (*reg >= ZYDIS_REGISTER_AL && ZYDIS_REGISTER_R15B > *reg)
		{
			num_reg = *reg - ZYDIS_REGISTER_AL;
			return x86::Gp::make_r8(num_reg).r8(); //see x86::rax
		}
	}

	NO_INLINE auto reg_conv(ZydisRegister reg) -> x86::Gp //aye trick
	{
		uint32_t reg_size = NULL;
		uint32_t num_reg = NULL;

		if (reg >= ZYDIS_REGISTER_RAX && ZYDIS_REGISTER_R15 >= reg)
		{
			//.r64()  
			num_reg = reg - ZYDIS_REGISTER_RAX;
			return x86::Gp::make_r64(num_reg).r64(); //see x86::rax

		}
		else if (reg >= ZYDIS_REGISTER_EAX && ZYDIS_REGISTER_R15D >= reg)
		{
			num_reg = reg - ZYDIS_REGISTER_EAX;
			return x86::Gp::make_r32(num_reg).r32(); //see x86::rax
		}
		else if (reg >= ZYDIS_REGISTER_AX && ZYDIS_REGISTER_R15W >= reg)
		{
			num_reg = reg - ZYDIS_REGISTER_AX;
			return x86::Gp::make_r16(num_reg).r16(); //see x86::rax
		}
		else if (reg >= ZYDIS_REGISTER_AL && ZYDIS_REGISTER_R15B >= reg)
		{
			num_reg = reg - ZYDIS_REGISTER_AL;
			return x86::Gp::make_r8(num_reg).r8(); //see x86::rax
		}
	}

	NO_INLINE auto push_correct(x86::Assembler* ass, ZydisDisassembledInstruction* dis_instr, uint32_t id_reg) -> VOID
	{
#ifndef _WIN64
		ass->push(cg_util::reg_conv(&dis_instr->operands[id_reg].reg.value).r32());

#else
		ass->push(cg_util::reg_conv(&dis_instr->operands[id_reg].reg.value).r64());
#endif // !_WIN64 
	}

	NO_INLINE auto push_correct(x86::Assembler* ass, ZydisRegister reg) -> VOID
	{
#ifndef _WIN64
		ass->push(cg_util::reg_conv(reg).r32());

#else
		ass->push(cg_util::reg_conv(reg).r64());
#endif // !_WIN64 
	}

	NO_INLINE auto push_correct(x86::Assembler* ass, ZydisRegister* reg) -> VOID
	{
#ifndef _WIN64
		ass->push(cg_util::reg_conv(reg).r32());

#else
		ass->push(cg_util::reg_conv(reg).r64());
#endif // !_WIN64 
	}



	NO_INLINE auto pop_correct(x86::Assembler* ass, ZydisDisassembledInstruction* dis_instr, uint32_t id_reg) -> VOID
	{
#ifndef _WIN64
		ass->pop(cg_util::reg_conv(&dis_instr->operands[id_reg].reg.value).r32());

#else
		ass->pop(cg_util::reg_conv(&dis_instr->operands[id_reg].reg.value).r64());
#endif // !_WIN64 
	}

	NO_INLINE auto pop_correct(x86::Assembler* ass, ZydisRegister reg) -> VOID
	{
#ifndef _WIN64
		ass->pop(cg_util::reg_conv(reg).r32());

#else
		ass->pop(cg_util::reg_conv(reg).r64());
#endif // !_WIN64 
	}

	NO_INLINE auto pop_correct(x86::Assembler* ass, ZydisRegister* reg) -> VOID
	{
#ifndef _WIN64
		ass->pop(cg_util::reg_conv(*reg).r32());
#else
		ass->pop(cg_util::reg_conv(*reg).r64());
#endif // !_WIN64 
	}

	NO_INLINE auto push_eflag(x86::Assembler* ass) -> VOID
	{
#ifndef _WIN64
		ass->pushfd();

#else
		ass->pushfq();
#endif // !_WIN64 
	}

	NO_INLINE auto pop_eflag(x86::Assembler* ass) -> VOID
	{
#ifndef _WIN64
		ass->popfd();

#else
		ass->popfq();
#endif // !_WIN64 
	}

	NO_INLINE auto push_all_reg(x86::Assembler* ass, BOOLEAN ignore_rax) -> VOID
	{
		uint32_t reg_pushed = NULL;
		ZydisRegister reg_use[MAX_REG_PLAT - MIN_REG_PLAT] = { ZYDIS_REGISTER_NONE };

		for (size_t i = NULL, cur_reg = MIN_REG_PLAT; i <= (MAX_REG_PLAT - MIN_REG_PLAT); i++)
		{
			if (cur_reg + i != REG_VSP)
			{
				if (!(ignore_rax && cur_reg + i == MIN_REG_PLAT))
				{
					reg_use[reg_pushed] = (ZydisRegister)(cur_reg + i);
					reg_pushed++;
				}
			}
		}
		for (size_t i = NULL; i < reg_pushed; i++)
		{
			push_correct(ass, reg_use[i]);
		}
	}

	NO_INLINE auto pop_all_reg(x86::Assembler* ass, BOOLEAN ignore_rax) -> VOID
	{
		uint32_t reg_pushed = NULL;
		ZydisRegister reg_use[MAX_REG_PLAT - MIN_REG_PLAT] = { ZYDIS_REGISTER_NONE };

		for (size_t i = NULL, cur_reg = MIN_REG_PLAT; i <= (MAX_REG_PLAT - MIN_REG_PLAT); i++)
		{
			if (cur_reg + i != REG_VSP)
			{
				if (!(ignore_rax && cur_reg + i == MIN_REG_PLAT))
				{
					reg_use[reg_pushed] = (ZydisRegister)(cur_reg + i);
					reg_pushed++;
				}
			}
		}

		for (size_t i = reg_pushed - 1; ; i--)
		{
			pop_correct(ass, reg_use[i]);
			if (i == NULL)
			{
				break;
			}
		}
	}

	NO_INLINE auto reg_conv_to(ZydisRegister* reg, uint32_t size) -> ZydisRegister
	{
		uint32_t reg_size = NULL;
		uint32_t num_reg = NULL;

		if (*reg >= ZYDIS_REGISTER_RAX && ZYDIS_REGISTER_R15 >= *reg)
		{
			num_reg = *reg - ZYDIS_REGISTER_RAX;
		}
		else if (*reg >= ZYDIS_REGISTER_EAX && ZYDIS_REGISTER_R15D >= *reg)
		{
			num_reg = *reg - ZYDIS_REGISTER_EAX;
		}
		else if (*reg >= ZYDIS_REGISTER_AX && ZYDIS_REGISTER_R15W >= *reg)
		{
			num_reg = *reg - ZYDIS_REGISTER_AX;
		}
		else if (*reg >= ZYDIS_REGISTER_AL && ZYDIS_REGISTER_R15B >= *reg)
		{
			num_reg = *reg - ZYDIS_REGISTER_AL;
		}
		else
		{
			return ZYDIS_REGISTER_NONE;
		}

		if (size == sizeof(ULONG) * 2)
		{
			num_reg += ZYDIS_REGISTER_RAX;
		}
		else if (size == sizeof(ULONG))
		{
			num_reg += ZYDIS_REGISTER_EAX;
		}
		else if (size == sizeof(USHORT))
		{
			num_reg += ZYDIS_REGISTER_AX;
		}
		else if (size == sizeof(CHAR))
		{
			num_reg += ZYDIS_REGISTER_AL;
		}
		return (ZydisRegister)num_reg;
	}

	NO_INLINE auto reg_conv_to(ZydisRegister reg, uint32_t size) -> ZydisRegister
	{
		uint32_t reg_size = NULL;
		uint32_t num_reg = NULL;

		if (reg >= ZYDIS_REGISTER_RAX && ZYDIS_REGISTER_R15 >= reg)
		{
			num_reg = reg - ZYDIS_REGISTER_RAX;
		}
		else if (reg >= ZYDIS_REGISTER_EAX && ZYDIS_REGISTER_R15D >= reg)
		{
			num_reg = reg - ZYDIS_REGISTER_EAX;
		}
		else if (reg >= ZYDIS_REGISTER_AX && ZYDIS_REGISTER_R15W >= reg)
		{
			num_reg = reg - ZYDIS_REGISTER_AX;
		}
		else if (reg >= ZYDIS_REGISTER_AL && ZYDIS_REGISTER_R15B >= reg)
		{
			num_reg = reg - ZYDIS_REGISTER_AL;
		}
		else
		{
			return ZYDIS_REGISTER_NONE;
		}

		if (size == sizeof(ULONG) * 2)
		{
			num_reg += ZYDIS_REGISTER_RAX;
		}
		else if (size == sizeof(ULONG))
		{
			num_reg += ZYDIS_REGISTER_EAX;
		}
		else if (size == sizeof(USHORT))
		{
			num_reg += ZYDIS_REGISTER_AX;
		}
		else if (size == sizeof(CHAR))
		{
			num_reg += ZYDIS_REGISTER_AL;
		}
		return (ZydisRegister)num_reg;
	}

}

#endif // !CODE_GEN_UTIL