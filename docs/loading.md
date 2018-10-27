# 加载二进制文件 - CLE and angr Projects

前面，我们只看到了angr加载程序最基本的能力，先加载了`/bin/true`，后面又禁止加载它的共享库的情况下加载了它。也看到`proj.loader`可以做的一些事情。现在我们要深入探讨这些接口的细微差别以及它们能够做什么。

我们简单提过angr的二进制加载组件CLE。它表示"CLE Loads Everything"，负责加载二进制（以及它依赖的其他库），并且以易于使用的方式传递给angr的其他部分。

## 加载器

让我们重新加载`/bin/true`并深入了解如何与加载器进行交互。

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> proj.loader
<Loaded true, maps [0x400000:0x5008000]>
```

### Loaded Objects

CLE加载器（`cle.Loader`）代表整个加载的二进制对象，加载映射到一个单独的内存空间。
每个二进制对象被能够处理它这种文件类型的加载器后端加载。比如`cle.ELF`用来加载ELF二进制文件的。

内存中也有不代表任何加载的二进制文件的对象。比如，提供本地线程存储支持的对象，提供未解析符号支持的扩展对象。

可以用loader.all_objects获取到CLE加载的对象的完整列表，以及几个更有针对性的分类。

```python
# 所有加载的对象
>>> proj.loader.all_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>,
 <ELF Object ld-linux-x86-64.so.2, maps [0x2000000:0x22241c7]>,
 <ELFTLSObject Object cle##tls, maps [0x3000000:0x300d010]>,
 <KernelObject Object cle##kernel, maps [0x4000000:0x4008000]>,
 <ExternObject Object cle##externs, maps [0x5000000:0x5008000]>

# 这是“主”对象，是你在加载项目时直接指定的对象
>>> proj.loader.main_object
<ELF Object true, maps [0x400000:0x60105f]>

# 这是从共享对象名称到对象的字典映射
>>> proj.loader.shared_objects
{ 'libc.so.6': <ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>
  'ld-linux-x86-64.so.2': <ELF Object ld-linux-x86-64.so.2, maps [0x2000000:0x22241c7]>}

# 这是所有从ELF文件加载的对象
# 如果是windows程序使用all_pe_objects!
>>> proj.loader.all_elf_objects
[<ELF Object true, maps [0x400000:0x60105f]>,
 <ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>,
 <ELF Object ld-linux-x86-64.so.2, maps [0x2000000:0x22241c7]>]
 
# 这是“扩展对象”，我们用它来为未解析的导入和angr内部提供地址
>>> proj.loader.extern_object
<ExternObject Object cle##externs, maps [0x5000000:0x5008000]>

# 此对象用于为模拟的系统调用提供地址
>>> proj.loader.kernel_object
<KernelObject Object cle##kernel, maps [0x4000000:0x4008000]>

# 最后，你可以获得对给定地址的对象的引用
>>> proj.loader.find_object_containing(0x400000)
<ELF Object true, maps [0x400000:0x60105f]>
```

您可以直接与这些对象进行交互以从中提取元数据：

```python
>>> obj = proj.loader.main_object

# The entry point of the object
>>> obj.entry
0x400580

>>> obj.min_addr, obj.max_addr
(0x400000, 0x60105f)

# 获取ELF的segment和section
>>> obj.segments
<Regions: [<ELFSegment offset=0x0, flags=0x5, filesize=0xa74, vaddr=0x400000, memsize=0xa74>,
           <ELFSegment offset=0xe28, flags=0x6, filesize=0x228, vaddr=0x600e28, memsize=0x238>]>
>>> obj.sections
<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>,
           <.interp | offset 0x238, vaddr 0x400238, size 0x1c>,
           <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>,
            ...etc
            
# 您可以按其包含的地址获取单独的segment和section：
>>> obj.find_segment_containing(obj.entry)
<ELFSegment offset=0x0, flags=0x5, filesize=0xa74, vaddr=0x400000, memsize=0xa74>
>>> obj.find_section_containing(obj.entry)
<.text | offset 0x580, vaddr 0x400580, size 0x338>

# 获取符号的PLT存根的地址
>>> addr = obj.plt['abort']
>>> addr
0x400540
>>> obj.reverse_plt[addr]
'abort'

# 显示对象的预链接基础以及CLE实际映射到内存的位置
>>> obj.linked_base
0x400000
>>> obj.mapped_base
0x400000
```

### 符号和重定位

您还可以在使用CLE时使用符号。

符号是可执行格式世界中的基本概念，它有效地将名称映射到地址。

从CLE获取符号的最简单方法是使用`loader.find_symbol`，它接受名称或地址并返回Symbol对象。

```python
>>> malloc = proj.loader.find_symbol('malloc')
>>> malloc
<Symbol "malloc" in libc.so.6 at 0x1054400>
```

符号上最有用的属性是它的名称，所有者和地址，但符号的地址可能是不明确的。
Symbol对象有三种获取其地址的方式：

- `.rebased_addr`是它在全局地址空间的地址。这是打印输出显示的内容。
- `.linked_addr`是相对于二进制的预链接基址的地址。 这是例如`readelf(1)`获取到的地址，。
- `.relative_addr`是它相对于对象基址的地址。 这在书籍（特别是Windows书籍）中称为RVA（相对虚拟地址）。

```python
>>> malloc.name
'malloc'

>>> malloc.owner_obj
<ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>

>>> malloc.rebased_addr
0x1054400
>>> malloc.linked_addr
0x54400
>>> malloc.relative_addr
0x54400
```

除了提供调试信息之外，符号还支持动态链接的概念。
libc在导出符号提供malloc，主二进制文件依赖于它。
如果我们要求CLE直接从主对象给我们一个malloc符号，它会告诉我们这是一个导入符号。
导入符号没有与之关联的有意义的地址，但它们确实提供了用于解析它们的符号的引用，如`.resolvedby`。

```python
>>> malloc.is_export
True
>>> malloc.is_import
False

# 在Loader上，方法是find_symbol，因为它执行搜索操作来查找符号。
# 在单个对象上，方法是get_symbol，因为只能有一个具有给定名称的符号。
>>> main_malloc = proj.loader.main_object.get_symbol("malloc")
>>> main_malloc
<Symbol "malloc" in true (import)>
>>> main_malloc.is_export
False
>>> main_malloc.is_import
True
>>> main_malloc.resolvedby
<Symbol "malloc" in libc.so.6 at 0x1054400>
```

The specific ways that the links between imports and exports should be registered in memory are handled by another notion called _relocations_. 
A relocation says, "when you match _\[import\]_ up with an export symbol, please write the export's address to _\[location\]_, formatted as _\[format\]_."
We can see the full list of relocations for an object (as `Relocation` instances) as `obj.relocs`, or just a mapping from symbol name to Relocation as `obj.imports`.
There is no corresponding list of export symbols.

A relocation's corresponding import symbol can be accessed as `.symbol`.
The address the relocation will write to is accessable through any of the address identifiers you can use for Symbol, and you can get a reference to the object requesting the relocation with `.owner_obj` as well.

```python
# Relocations don't have a good pretty-printing, so those addresses are python-internal, unrelated to our program
>>> proj.loader.shared_objects['libc.so.6'].imports
{u'__libc_enable_secure': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4221fb0>,
 u'__tls_get_addr': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x425d150>,
 u'_dl_argv': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4254d90>,
 u'_dl_find_dso_for_object': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x425d130>,
 u'_dl_starting_up': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x42548d0>,
 u'_rtld_global': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4221e70>,
 u'_rtld_global_ro': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4254210>}
```

If an import cannot be resolved to any export, for example, because a shared library could not be found, CLE will automatically update the externs object (`loader.extern_obj`) to claim it provides the symbol as an export.

## Loading Options

If you are loading something with `angr.Project` and you want to pass an option to the `cle.Loader` instance that Project implicitly creates, you can just pass the keyword argument directly to the Project constructor, and it will be passed on to CLE.
You should look at the [CLE API docs.](http://angr.io/api-doc/cle.html) if you want to know everything that could possibly be passed in as an option, but we will go over some important and frequently used options here.

#### Basic Options

We've discussed `auto_load_libs` already - it enables or disables CLE's attempt to automatically resolve shared library dependencies, and is on by default.
Additionally, there is the opposite, `except_missing_libs`, which, if set to true, will cause an exception to be thrown whenever a binary has a shared library dependency that cannot be resolved.

You can pass a list of strings to `force_load_libs` and anything listed will be treated as an unresolved shared library dependency right out of the gate, or you can pass a list of strings to `skip_libs` to prevent any library of that name from being resolved as a dependency.
Additionally, you can pass a list of strings \(or a single string\) to `ld_path`, which will be used as an additional search path for shared libraries, before any of the defaults: the same directory as the loaded program, the current working directory, and your system libraries.

#### Per-Binary Options

If you want to specify some options that only apply to a specific binary object, CLE will let you do that too. The parameters `main_ops` and `lib_opts` do this by taking dictionaries of options. `main_opts` is a mapping from option names to option values, while `lib_opts` is a mapping from library name to dictionaries mapping option names to option values.

The options that you can use vary from backend to backend, but some common ones are:

* `backend` - which backend to use, as either a class or a name
* `base_addr` - a base address to use
* `entry_point` - an entry point to use
* `arch` - the name of an architecture to use

Example:

```python
angr.Project(main_opts={'backend': 'ida', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
```

### Backends

CLE currently has backends for statically loading ELF, PE, CGC, Mach-O and ELF core dump files, as well as loading binaries with IDA and loading files into a flat address space. CLE will automatically detect the correct backend to use in most cases, so you shouldn't need to specify which backend you're using unless you're doing some pretty weird stuff.

You can force CLE to use a specific backend for an object by by including a key in its options dictionary, as described above. Some backends cannot autodetect which architecture to use and _must_ have a `arch` specified. The key doesn't need to match any list of architectures; angr will identify which architecture you mean given almost any common identifier for any supported arch.

To refer to a backend, use the name from this table:

| backend name | description | requires `arch`? |
| --- | --- | --- |
| elf | Static loader for ELF files based on PyELFTools | no |
| pe | Static loader for PE files based on PEFile | no |
| mach-o | Static loader for Mach-O files. Does not support dynamic linking or rebasing. | no |
| cgc | Static loader for Cyber Grand Challenge binaries | no |
| backedcgc | Static loader for CGC binaries that allows specifying memory and register backers | no |
| elfcore | Static loader for ELF core dumps | no |
| ida | Launches an instance of IDA to parse the file | yes |
| blob | Loads the file into memory as a flat image | yes |

## Symbolic Function Summaries

By default, Project tries to replace external calls to library functions by using symbolic summaries termed _SimProcedures_ - effectively just python functions that imitate the library function's effect on the state. We've implemented [a whole bunch of functions](https://github.com/angr/angr/tree/master/angr/procedures) as SimProcedures. These builtin procedures are available in the `angr.SIM_PROCEDURES` dictionary, which is two-leveled, keyed first on the package name \(libc, posix, win32, stubs\) and then on the name of the library function. Executing a SimProcedure instead of the actual library function that gets loaded from your system makes analysis a LOT more tractable, at the cost of [some potential inaccuracies](/docs/gotchas.md).

When no such summary is available for a given function:

* if `auto_load_libs` is `True` \(this is the default\), then the _real_ library function is executed instead. This may or may not be what you want, depending on the actual function. For example, some of libc's functions are extremely complex to analyze and will most likely cause an explosion of the number of states for the path trying to execute them.
* if `auto_load_libs` is `False`, then external functions are unresolved, and Project will resolve them to a generic "stub" SimProcedure called `ReturnUnconstrained`. It does what its name says: it returns a unique unconstrained symbolic value each time it is called.
* if `use_sim_procedures` \(this is a parameter to `angr.Project`, not `cle.Loader`\) is `False` \(it is `True` by default\), then only symbols provided by the extern object will be replaced with SimProcedures, and they will be replaced by a stub `ReturnUnconstrained`, which does nothing but return a symbolic value.
* you may specify specific symbols to exclude from being replaced with SimProcedures with the parameters to `angr.Project`: `exclude_sim_procedures_list` and `exclude_sim_procedures_func`.
* Look at the code for `angr.Project._register_object` for the exact algorithm.

#### Hooking

The mechanism by which angr replaces library code with a python summary is called hooking, and you can do it too! When performing simulation, at every step angr checks if the current address has been hooked, and if so, runs the hook instead of the binary code at that address. The API to let you do this is `proj.hook(addr, hook)`, where `hook` is a SimProcedure instance. You can manage your project's hooks with `.is_hooked`, `.unhook`, and `.hooked_by`, which should hopefully not require explanation.

There is an alternate API for hooking an address that lets you specify your own off-the-cuff function to use as a hook, by using `proj.hook(addr)` as a function decorator. If you do this, you can also optionally specify a `length` keyword argument to make execution jump some number of bytes forward after your hook finishes.

```python
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.unhook(0x10000)
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```

Furthermore, you can use `proj.hook_symbol(name, hook)`, providing the name of a symbol as the first argument, to hook the address where the symbol lives.
One very important usage of this is to extend the behavior of angr's built-in library SimProcedures.
Since these library functions are just classes, you can subclass them, overriding pieces of their behavior, and then use your subclass in a hook.

## So far so good!

By now, you should have a reasonable understanding of how to control the environment in which your analysis happens, on the level of the CLE loader and the angr Project.
You should also understand that angr makes a reasonable attempt to simplify its analysis by hooking complex library functions with SimProcedures that summarize the effects of the functions.

In order to see all the things you can do with the CLE loader and its backends, look at the [CLE API docs.](http://angr.io/api-doc/cle.html)

[摘要](./SUMMARY.md) | 下一节：[Solver引擎](./solver.md)