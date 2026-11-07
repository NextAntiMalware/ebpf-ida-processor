# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <clement (dot) berthaux (at) synacktiv (dot) com> wrote this file.  As long as you
# retain this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.    Clement Berthaux
# ----------------------------------------------------------------------------
# Modified: Solana-specific features removed, generic eBPF only.
# ----------------------------------------------------------------------------

from idaapi import (PR_ASSEMBLE, PR_SEGS, PR_DEFSEG32, PR_USE32, PRN_HEX, PR_RNAMESOK, PR_NO_SEGMOVE,
                    ASH_HEXF3, AS_UNEQU, AS_COLON, ASB_BINF4, AS_N2CHR,
                    SN_NOCHECK, SN_FORCE, STKVAR_VALID_SIZE,
                    CF_USE1, CF_USE2, CF_USE3, CF_CHG1, 
                    CF_JUMP, CF_CALL, CF_STOP,
                    o_reg, o_imm, dt_dword, dt_qword, 
                    o_near, o_displ, dt_word, o_phrase, o_mem,
                    REF_OFF32,
                    dr_O, dr_R,
                    fl_F, fl_CN, fl_CF, fl_JN,
                    STRTYPE_TERMCHR,
                    OOF_SIGNED, OOFS_NEEDSIGN, OOFW_IMM, OOFW_64, OOFW_32, OOFW_16)


import idaapi
import idautils
import idc
import ctypes
import os

from ebpf.relocations import parse_relocation, process_relocations, apply_rel_mods, apply_relocation
from ebpf.helpers import decode_name
from ebpf.strings import add_string, recover_known_strings
from ebpf.constants import *
from ebpf.helper_names import HELPER_NAMES
from ebpf.config import *

class DecodingError(Exception):
    pass

class EBPFProc(idaapi.processor_t):
    id = 0x8000 + 247 # 0x8000+ are reserved for third party plugins
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE
    cnbits = 8
    dnbits = 8
    psnames = ['EBPF']
    plnames = ['eBPF Byte Code']
    segreg_size = 0
    instruc_start = 0
    assembler = {
        'flag':  ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,
        "uflag": 0,
        "name": "eBPF",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": "db",
        "a_byte": "db",
        "a_word": "dw",
        'a_dword': "dd",
        'a_qword': "dq",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",

    }

    def __init__(self):
        idaapi.processor_t.__init__(self)
        
        self.init_instructions()
        self.init_registers()

        self.relocations = {}
        self.functions = {}
        self.sorted_strings = []

    def ev_loader_elf_machine(self, li, machine_type, p_procname, p_pd, loader, reader): # doesn't work from ida python for some reason
        if machine_type == 247:
            p_procname = 'eBPF'
        return machine_type
    
    def ev_newfile(self, fname):
        for ea, name in idautils.Names():
            name = decode_name(name)
            self.functions[name] = ea
            idaapi.set_name(ea, name, SN_NOCHECK | SN_FORCE) # demangle function names
            seg = idaapi.getseg(ea)
            if seg.type == idaapi.SEG_XTRN: # create external functions
                idaapi.add_func(ea, ea+8)
        
        self.relocations, self.funcs, self.rodata, self.symtab = process_relocations(fname)
        self.sorted_strings = recover_known_strings(self.sorted_strings, self.symtab)
        
        return True
    
    ''' ----- Instructions processing -----'''

    def init_instructions(self):
        # https://github.com/solana-labs/rbpf/blob/179a0f94b68ae0bef892b214750a54448d61b1be/src/ebpf.rs#L205

        self.OPCODES = {
            # MEM
            BPF_LD | BPF_IMM | BPF_DW: ('lddw', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_LDX | BPF_MEM | BPF_W: ('ldxw', self._ana_reg_regdisp, CF_USE1|CF_USE2|CF_CHG1),
            BPF_LDX | BPF_MEM | BPF_H: ('ldxh', self._ana_reg_regdisp, CF_USE1|CF_USE2|CF_CHG1),
            BPF_LDX | BPF_MEM | BPF_B: ('ldxb', self._ana_reg_regdisp, CF_USE1|CF_USE2|CF_CHG1),
            BPF_LDX | BPF_MEM | BPF_DW: ('ldxdw', self._ana_reg_regdisp, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ST | BPF_MEM | BPF_W: ('stw', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ST | BPF_MEM | BPF_H: ('sth', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ST | BPF_MEM | BPF_B: ('stb', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ST | BPF_MEM | BPF_DW: ('stdw', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_STX | BPF_MEM | BPF_W: ('stxw', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),    
            BPF_STX | BPF_MEM | BPF_H: ('stxh', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_STX | BPF_MEM | BPF_B: ('stxb', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_STX | BPF_MEM | BPF_DW: ('stxdw', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),

            # ALU 32
            BPF_ALU | BPF_K | BPF_ADD: ('add32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_ADD: ('add32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_SUB: ('sub32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_SUB: ('sub32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_MUL: ('mul32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_MUL: ('mul32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_DIV: ('div32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_DIV: ('div32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_OR: ('or32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_OR: ('or32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_AND: ('and32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_AND: ('and32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_LSH: ('lsh32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_LSH: ('lsh32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_RSH: ('rsh32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_RSH: ('rsh32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_NEG: ('neg32', self._ana_1reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_MOD: ('mod32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_MOD: ('mod32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_XOR: ('xor32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_XOR: ('xor32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_MOV: ('mov32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_MOV: ('mov32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_ARSH: ('arsh32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_ARSH: ('arsh32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),

            BPF_ALU | BPF_K | BPF_END: ('le', self._ana_reg_imm, CF_USE1|CF_CHG1),
            BPF_ALU | BPF_X | BPF_END: ('be', self._ana_reg_imm, CF_USE1|CF_CHG1),

            # ALU 64
            BPF_ALU64 | BPF_K | BPF_ADD: ('add64', self._ana_reg_imm, CF_USE1 | CF_USE2 | CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_ADD: ('add64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_SUB: ('sub64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_SUB: ('sub64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_MUL: ('mul64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_MUL: ('mul64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_DIV: ('div64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_DIV: ('div64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_OR: ('or64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_OR: ('or64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_AND: ('and64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_AND: ('and64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_LSH: ('lsh64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_LSH: ('lsh64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_RSH: ('rsh64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_RSH: ('rsh64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_NEG: ('neg64', self._ana_1reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_MOD: ('mod64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_MOD: ('mod64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_XOR: ('xor64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_XOR: ('xor64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_MOV: ('mov64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_MOV: ('mov64', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_ARSH: ('arsh64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_ARSH: ('arsh64', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),

            # BRANCHES
            BPF_JMP | BPF_JA: ('ja', self._ana_jmp, CF_USE1|CF_JUMP),
            BPF_JMP | BPF_K | BPF_JEQ: ('jeq', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JEQ: ('jeq', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JGT: ('jgt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JGT: ('jgt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JGE: ('jge', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JGE: ('jge', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JLT: ('jlt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JLT: ('jlt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JLE: ('jle', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP), # new
            BPF_JMP | BPF_X | BPF_JLE: ('jle', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP), # new
            BPF_JMP | BPF_K | BPF_JSET: ('jset', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JSET: ('jset', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JNE: ('jne', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JNE: ('jne', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),

            BPF_JMP | BPF_K | BPF_JSGT: ('jsgt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JSGT: ('jsgt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JSGE: ('jsge', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JSGE: ('jsge', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),            
            BPF_JMP | BPF_K | BPF_JSLT: ('jslt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JSLT: ('jslt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP), # new
            BPF_JMP | BPF_K | BPF_JSLE: ('jsle', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP), # new
            BPF_JMP | BPF_X | BPF_JSLE: ('jsle', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP), # new

            BPF_JMP | BPF_CALL: ('call', self._ana_call, CF_USE1|CF_CALL), # call imm
            BPF_JMP | BPF_X | BPF_CALL: ('callx', self._ana_callx, CF_USE1|CF_CALL), # tail call
            BPF_JMP | BPF_EXIT: ('exit', self._ana_nop, CF_STOP) # return r0
        }

        self.instruc_end = 0xff
        self.instruc = [({'name':self.OPCODES[i][0], 'feature':self.OPCODES[i][2]} if i in self.OPCODES else {'name':'unknown_opcode', 'feature':0}) for i in range(0xff)]
        
    def init_registers(self):
        self.reg_names = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'CS', 'DS']

        self.reg_cs = 0
        self.reg_ds = 1

        self.reg_first_sreg = self.reg_cs
        self.reg_last_sreg = self.reg_ds

        self.reg_code_sreg = self.reg_cs
        self.reg_data_sreg = self.reg_ds

    def ev_ana_insn(self, insn):
        try:
            return self._ana(insn)
        except DecodingError:
            return 0

    def _ana(self, insn):
        self.opcode = insn.get_next_byte()
        registers = insn.get_next_byte()

        self.src = (registers >> 4) & 15
        self.dst = registers & 15
        
        self.off = insn.get_next_word()
            
        self.imm = insn.get_next_dword()
        
        if self.opcode == BPF_LD | BPF_IMM | BPF_DW:
            insn.get_next_dword()
            imm2 = insn.get_next_dword()
            self.imm += imm2 << 32

        insn.itype = self.opcode

        if self.opcode not in self.OPCODES:
            raise DecodingError("wuut")

        self.OPCODES[self.opcode][1](insn)
        
        return insn.size

    def _ana_nop(self, insn):
        pass
    
    def _ana_reg_imm(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst

        insn[1].type = o_imm
        # special quad-word load
        if self.opcode == BPF_LD | BPF_IMM | BPF_DW:
            insn[1].dtype = dt_qword
        else:
            insn[1].dtype = dt_dword
            
        insn[1].value = self.imm

        insn[0].addr = insn.ea
        insn[1].addr = insn.ea
        
    def _ana_1reg(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst

    def _ana_2regs(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst
        
        insn[1].type = o_reg
        insn[1].dtype = dt_dword
        insn[1].reg = self.src

    def _ana_call(self, insn):
        offset = ctypes.c_int32(self.imm).value

        if self.src == 0:
            # Linux eBPF：src_reg == 0 是 helper 调用，imm 是 helper id
            insn[0].type = o_imm
            insn[0].dtype = dt_dword
            insn[0].value = offset
            return

        # src_reg != 0：bpf-to-bpf 调用，imm 是相对偏移（单位 8 字节）
        insn[0].type = o_near
        insn[0].dtype = dt_dword
        insn[0].value = self.imm
        insn[0].offb = 4

        target = None
        if insn.ea in self.relocations:
            r = self.relocations[insn.ea]
            target = r.get('target')
            name = r.get('name') or ''
            if target is None and name:
                target = self.functions.get(name)
                if target is None:
                    seg = idaapi.get_segm_by_name("extern")
                    if seg is not None:
                        target = idaapi.get_name_ea(seg.start_ea, name)
                        if target == idaapi.BADADDR:
                            target = idaapi.get_name_ea(0, name)
                        if target == idaapi.BADADDR:
                            target = None

        if target is None:
            # 节符号/未解析符号：退回到相对偏移
            target = insn.ea + 8 + 8 * offset

        insn[0].addr = target

    def _ana_callx(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.imm

    def _ana_jmp(self, insn):
        insn[0].type = o_near
        offset = ctypes.c_int16(self.off).value
        if offset < 0:
            pass
        insn[0].addr = 8*offset + insn.ea + 8
        insn[0].dtype = dt_word

    def _ana_cond_jmp_reg_imm(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst

        insn[1].type = o_imm
        insn[1].value = self.imm
        insn[1].dtype = dt_dword
        
        offset = ctypes.c_int16(self.off).value
        if offset < 0:
            pass
        insn[2].type = o_near
        insn[2].addr = 8 * offset + insn.ea + 8
        insn[2].dtype = dt_dword

    def _ana_cond_jmp_reg_reg(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst

        insn[1].type = o_reg
        insn[1].dtype = dt_dword
        insn[1].reg = self.src

        offset = ctypes.c_int16(self.off).value
        if offset < 0:
            pass
        insn[2].type = o_near
        insn[2].addr = 8 * offset + insn.ea + 8
        insn[2].dtype = dt_dword

    def _ana_regdisp_reg(self, insn):
        insn[0].type = o_displ
        insn[0].dtype = dt_word
        insn[0].value = self.off
        insn[0].phrase = self.dst

        insn[1].type = o_reg
        insn[1].dtype = dt_dword
        insn[1].reg = self.src

    def _ana_reg_regdisp(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst

        insn[1].type = o_displ
        insn[1].dtype = dt_word
        insn[1].value = self.off
        insn[1].phrase = self.src

    def ev_emu_insn(self, insn):
        Feature = insn.get_canon_feature()

        # helper 调用：把数字 id 注释成函数名（call 0x19 ; bpf_perf_event_output）
        if insn.itype == 0x85 and insn[0].type == o_imm:
            hid = insn[0].value & 0xffffffff
            idc.set_cmt(insn.ea, HELPER_NAMES.get(hid, 'unknown helper 0x%x' % hid), 0)

        if Feature & CF_JUMP:
            dst_op_index = 0 if insn.itype == 0x5 else 2
            insn.add_cref(insn[dst_op_index].addr, insn[dst_op_index].offb, fl_JN)
            idaapi.remember_problem(idaapi.PR_JUMP, insn.ea)

        if insn[0].type == o_displ or insn[1].type == o_displ:
            op_ind = 0 if insn[0].type == o_displ else 1
            # TODO: trace sp when it changes and call add_auto_stkpnt
            if idaapi.may_create_stkvars():
                val = ctypes.c_int16(insn[op_ind].value).value # create_stkvar takes signed value
                if insn.create_stkvar(insn[op_ind], val, STKVAR_VALID_SIZE):
                    idaapi.op_stkvar(insn.ea, op_ind)
        
        if insn[1].type == o_imm and insn[1].dtype == dt_qword:
            if insn.ea in self.relocations:
                self.sorted_strings = apply_relocation(self.functions, self.rodata, self.sorted_strings, insn, self.relocations[insn.ea])
        
        abort = False
        if Feature & CF_CALL:
            if insn.ea in self.relocations:
                self.sorted_strings = apply_relocation(self.functions, self.rodata, self.sorted_strings, insn, self.relocations[insn.ea])
                if self.relocations[insn.ea]['name'] == 'abort':
                    abort = True
            elif insn[0].type == o_near:
                insn.add_cref(insn[0].addr, insn[0].offb, fl_CF)

        # continue execution flow if not stop instruction (exit), not abort, and not unconditional jump
        flow = (Feature & CF_STOP == 0) and not abort and not insn.itype == 0x5
        
        if flow:
            insn.add_cref(insn.ea + insn.size, 0, fl_F)
        
        for op in insn:
            if op.type == o_imm and op.dtype == dt_qword:
                addr = op.value
                seg = idaapi.getseg(addr)
                if seg:
                    if seg.sclass == 6: # CONST .rodata
                        try:
                            s = idaapi.get_strlit_contents(addr, -1, STRTYPE_TERMCHR).decode()
                            idaapi.add_dref(op.addr, addr, dr_R)
                        except Exception as e:
                            pass

        return True

    def ev_out_insn(self, ctx):
        cmd = ctx.insn
        ft = cmd.get_canon_feature()
        buf = ctx.outbuf

        # handle byteswap instruction suffix encoded in immediate, don't print immediate
        if cmd.itype == 0xd4 or cmd.itype == 0xdc:
            # directly use immediate as suffix in decimal
            # analysis function sets second operand as immediate
            if cmd.ops[1].type == o_imm:
                ctx.out_mnem(15, f"{cmd.ops[1].value}")
            else:
                print("[ev_out_insn] analysis error: invalid 2nd operand type for byteswap instruction")
        else:
            ctx.out_mnem(15)
        
        if ft & CF_USE1:
            if ft & CF_CALL:
                pass
            ctx.out_one_operand(0)
        if ft & CF_USE2:
            ctx.out_char(',')
            ctx.out_char(' ')
            ctx.out_one_operand(1)
        if ft & CF_USE3:
            ctx.out_char(',')
            ctx.out_char(' ')
            ctx.out_one_operand(2)
        idaapi.idaapi_Cvar().gl_comm = 1
        ctx.flush_outbuf()

    def ev_out_operand(self, ctx, op):
        if op.type == o_reg:
            ctx.out_register(self.reg_names[op.reg])

        elif op.type == o_imm:
            if op.dtype == dt_qword:
                addr = op.value
                name = idaapi.get_name(addr)
                if name:
                    ctx.out_name_expr(op, addr, idaapi.BADADDR) #1D1E8
                else:
                    ctx.out_value(op, OOF_SIGNED|OOFW_IMM|OOFW_64)
            elif op.dtype == dt_dword:
                ctx.out_value(op, OOF_SIGNED|OOFW_IMM|OOFW_32)
            else:
                print(f"[ev_out_operand] immediate operand, unhandled dtype: {op.dtype:#8x}")
                ctx.out_value(op, OOF_SIGNED|OOFW_IMM|OOFW_32)

        elif op.type in [o_near, o_mem]:
            #print(f"[{hex(ctx.insn_ea)}] op.type: {op.type}, op.addr: {hex(op.addr)}")
            target_addr = idaapi.get_next_cref_from(ctx.insn_ea, 0)
            if target_addr != idaapi.BADADDR:
                ok = ctx.out_name_expr(op, target_addr, idaapi.BADADDR)
            else:
                ok = ctx.out_name_expr(op, op.addr, idaapi.BADADDR)
            if not ok:
                #print(f'[{hex(ctx.insn_ea)}] out_name_expr[0] failed: {op.addr}')
                ctx.out_tagon(idaapi.COLOR_ERROR)
                ctx.out_value(op, OOF_SIGNED|OOFW_IMM|OOFW_32)
                ctx.out_tagoff(idaapi.COLOR_ERROR)
                
                
        elif op.type == o_phrase:
            ctx.out_printf('skb') # text color is a bit off. fix later.
            ctx.out_symbol('[')
            ctx.out_value(op, OOF_SIGNED|OOFW_IMM|OOFW_32) # "OpDecimal" fails on this, figure out why & fix it.
            ctx.out_symbol(']')
            
        elif op.type == o_displ:
            if op.dtype == dt_dword:
                ctx.out_printf('skb')
            ctx.out_symbol('[')
            ctx.out_register(self.reg_names[op.phrase])
            if op.value:
                if op.dtype == dt_word:
                    ctx.out_value(op, OOFS_NEEDSIGN|OOF_SIGNED|OOFW_IMM|OOFW_16)
                elif op.dtype == dt_dword:
                    ctx.out_value(op, OOFS_NEEDSIGN|OOF_SIGNED|OOFW_IMM|OOFW_32)
                else:
                    print("[ev_out_operand] unexpected displacement dtype: {op.dtype:#8x}")
                    ctx.out_value(op, OOFS_NEEDSIGN|OOF_SIGNED|OOFW_IMM)
            ctx.out_symbol(']')
        else:
            return False
        return True
    
    def ev_endbinary(self, *args):
        print(f'[INFO] ev_endbinary: {args}')

def PROCESSOR_ENTRY():
    return EBPFProc()
