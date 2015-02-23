# -*- coding: cp949 -*-
try:
    from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits
except:
    print 'Inline function hook finder need to distorm3.'

# Copyright by n0fate
# License : GPLv2
# Only Working for Mountain Lion and Mavericks (IA-32e)
# This plugin will be used to find the general method of inline code modification
#
#
# The most instruction for hooking is JMP, CALL and RET
############### example #####################
# PUSH + RET - (Signature<Prologue> : C3(RETN))
# 68 00104000   PUSH 00401000
# C3            RETN
########################################
# MOV + JMP - Most used technique (Signature<Prologue/Epilogue> : FFE0)
#
# 32bit
# B8 00104000   MOV EAX, 00401000
# FFE0          JMP EAX
#
# 64bit
# 48C7C0 35084000       MOV RAX, 0x00400835
# or
# 48B8 3508400000000000 MOV RAX, 0x0000000000400835
# FFE0                  JMP RAX
########################################
# JMP - (Signature<Prologue/Epilogue> : E9 JMP)
# E9 XXXXXXXX   JMP XXXXXXXX (target address - address of current instruction - 5), 5 is length of current instruction
########################################


class INLINEHOOK():
    def __init__(self, x86_mem_pae, arch, os_version, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.base_address = base_address

    def check_prologue(self, address):
        base_pointer = address + self.base_address

        buf = self.x86_mem_pae.read(base_pointer, 12)

        code = Decode(base_pointer, buf, Decode64Bits)

        # code[0] format : (address, instruction size, instruction, hex string)
        call_address = 0
        inst_opcode2 = code[1][2].split(' ')[0]
        inst_opcode = code[0][2].split(' ')[0]

        if inst_opcode == 'MOV':
            if inst_opcode2 == 'JMP' or inst_opcode2 == 'CALL' or inst_opcode2 == 'RET':
                call_address = code[0][2].split(' ')[2]  # operand

        elif inst_opcode == 'JMP':
            call_address = code[0][2].split(' ')[1] # operand

        if call_address == 0:
            print 'No Prologue hook'
        else:
            print 'JMP Address : %x'%(call_address)

        return call_address

    def find_function_in_code(self, caller_addr, callee_addr):
        #print 'Callie Address : %x'%(callie_addr+self.base_address)
        base_pointer = caller_addr + self.base_address
        buf = self.x86_mem_pae.read(base_pointer, 256)
        code = Decode(base_pointer, buf, Decode64Bits)

        findit = []
        function_inst = []
        for instruction in code:
            function_inst.append(instruction)
            if instruction[2].split(' ')[0] == 'RET':
                break

            inst_split = instruction[2].split(' ')
            if inst_split[0] == 'CALL':
                try:
                    if int(inst_split[1], 16) == callee_addr+self.base_address:
                        #print 'Find Function : %x'%instruction[0]
                        findit.append(instruction)
                except ValueError:
                    continue    # bypass 'CALL reg/64'

        return findit, function_inst


# Korean comments
# inline_quick - Checking JMP instruction in function prologue considered as MOV-JMP instructions
def inline_quick(x86_mem_pae, sym_addr, arch, os_version, base_address):
    inline = INLINEHOOK(x86_mem_pae, arch, os_version, base_address)
    call_address = inline.check_prologue(sym_addr)
    return call_address

# Return : function counter, instruction set
def find_function_in_code(x86_mem_pae, caller_addr, callee_addr, arch, os_version, base_address):
    inline = INLINEHOOK(x86_mem_pae, arch, os_version, base_address)
    ret, code = inline.find_function_in_code(caller_addr, callee_addr)
    return ret, code