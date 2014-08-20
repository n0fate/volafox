# -*- coding: cp949 -*-

from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits

# Copyright by n0fate
# License : GPLv2
# Only Working for Mountain Lion and Mavericks (IA-32e)
# This plugin will be used to find the general method of inline code modification
#
# following text is a Korean-language comment
#
# 후킹에 사용하는 명령어는 JMP, CALL, RET이 있음
############### 예제 #####################
# PUSH + RET - 리턴 시 스택에 저장된 주소로 제어를 이전하는 방법을 사용 (Signature<Prologue> : C3(RETN))
# 68 00104000   PUSH 00401000
# C3            RETN
########################################
# MOV + JMP - 가장 많이 사용하는 방법 (Signature<Prologue/Epilogue> : FFE0)
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
# JMP - 상대주소 점프 시 사용(커널 루트킷도 사용) (Signature<Prologue/Epilogue> : E9 JMP)
# E9 XXXXXXXX   JMP XXXXXXXX (점프할 주소 - 현재 명령어 주소 - 5), 5는 현재 명령어 크기
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
# inline_quick - 함수 프롤로그를 체크하여 JMP가 있는지 확인하는 방법
# 5바이트를 체크하여 점프하는 방법이 있지만, MOV-JMP 를 고려하여 작성
def inline_quick(x86_mem_pae, sym_addr, arch, os_version, base_address):
    inline = INLINEHOOK(x86_mem_pae, arch, os_version, base_address)
    call_address = inline.check_prologue(sym_addr)
    return call_address

# Return : function counter, instruction set
def find_function_in_code(x86_mem_pae, caller_addr, callee_addr, arch, os_version, base_address):
    inline = INLINEHOOK(x86_mem_pae, arch, os_version, base_address)
    ret, code = inline.find_function_in_code(caller_addr, callee_addr)
    return ret, code