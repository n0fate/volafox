from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits

# Copyright by n0fate
# License : GPLv2
# Only Working for Mountain Lion and Mavericks (IA-32e)
# This plugin will be used to find the general method of inline code modification
#
# following text is a Korean-language comment
#
# 후킹 가능한 명령어는 JMP, CALL, RETN이 있음
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
    def __init__(self, x86_mem_pae, arch, os_version, build, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.base_address = base_address

    def check_hook_code(self, address):



def inline_quick(x86_mem_pae, sym_addr, arch, os_version, build, base_address):
    INLINEHOOK()



def inline_detail():
