# 核心概念

在开始使用angr之前，您需要对一些基本的angr概念以及如何构建一些基本的angr对象有一些基本的了解。

使用angr的第一个操作肯定是加载一个二进制文件生成 _project_。我们使用`/bin/true`作为演示。

```python
>>> import angr
>>> proj = angr.Project('/bin/true')
```

在angr中project是控制的基础。你可以使用angr对加载的可执行文件进行分析和模拟。

## 基本属性

首先，了解一下project的一些基本属性：CPU架构，文件名，入口地址。

```python
>>> import monkeyhex # 数值结果将以十六进制显示
>>> proj.arch
<Arch AMD64 (LE)>
>>> proj.entry
0x401670
>>> proj.filename
'/bin/true'
```

* _arch_ 是`archinfo.Arch`对象的一个实例，表示表示编译程序的体系结构，本例中是amd64小端模式。它包含了大量有关运行CPU的文书数据，你可以在[闲暇时](https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py)仔细阅读。你通常关心的是`arch.bits`, `arch.bytes` （这个是[主 `Arch` 类](https://github.com/angr/archinfo/blob/master/archinfo/arch.py)的一个`@property`声明）, `arch.name`和`arch.memory_endness`.
* _entry_ 是入口地址
* _filename_ 是二进制文件的绝对路径。

## 加载器

从二进制文件到虚拟地址空间中的表示非常复杂！我们有个叫CLE的模块来处理这个。CLE的结果称为加载器，通过`.loader`属性来调用。我们[很快]（./loading.md）将详细介绍如何使用，现在只需要直到可以使用它来查看与程序一起加载的共享库和查询加载的地址空间。

```python
>>> proj.loader
<Loaded true, maps [0x400000:0x5004000]>

>>> proj.loader.shared_objects # may look a little different for you!
{'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
 'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}

>>> proj.loader.min_addr
0x400000
>>> proj.loader.max_addr
0x5004000

>>> proj.loader.main_object  # 主模块
<ELF Object true, maps [0x400000:0x60721f]>

>>> proj.loader.main_object.execstack  # 是否有可执行堆栈
False
>>> proj.loader.main_object.pic  # 是否位置无关
True
```

## The factory

angr中有很多类，大多需要实例化的project。为了不让你到处传递project，我们提供了`project.factory`，有几个方便的你经常会使用的常见对象的构造函数。

本节还将介绍几种基本的angr概念。

#### Blocks

首先，`project.factory.block()`用来提取给定地址代码的基本块（[basic block](https://en.wikipedia.org/wiki/Basic_block)）。angr就是以基本块为单位进行代码分析。你可以用Block对象来获取到很多有关代码块的有趣的东西。

```python
>>> block = proj.factory.block(proj.entry) # 提取程序入口的一段代码
<Block for 0x401670, 42 bytes>

>>> block.pp()                          # pretty-print打印反汇编
0x401670:       xor     ebp, ebp
0x401672:       mov     r9, rdx
0x401675:       pop     rsi
0x401676:       mov     rdx, rsp
0x401679:       and     rsp, 0xfffffffffffffff0
0x40167d:       push    rax
0x40167e:       push    rsp
0x40167f:       lea     r8, [rip + 0x2e2a]
0x401686:       lea     rcx, [rip + 0x2db3]
0x40168d:       lea     rdi, [rip - 0xd4]
0x401694:       call    qword ptr [rip + 0x205866]

>>> block.instructions                  # 有多少指令？
0xb
>>> block.instruction_addrs             # 每条指令的地址？
[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]
```

此外，您可以使用Block对象来获取代码块的其他表示形式：

```python
>>> block.capstone                       # capstone disassembly
<CapstoneBlock for 0x401670>
>>> block.vex                            # VEX IRSB (这是一个python内部地址，而不是程序地址)
<pyvex.block.IRSB at 0x7706330>
```

#### States

另外，`Project`对象只代表程序的一个初始镜像。在执行angr分析时，是通过表示_simulated program state_的特殊对象`SimState`进行工作的。

```python
>>> state = proj.factory.entry_state()
<SimState @ 0x401670>
```
SimState包括程序的内存、寄存器、文件系统数据...任何可通过执行改变的“实时数据”都能在SimState中找到。我们将在后面讨论如何与state进行深入交互，但是现在，让我们使用`state.regs`和`state.mem`来访问state的寄存器和内存：

```python
>>> state.regs.rip        # 获取当前指令指针
<BV64 0x401670>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved  # 将入口点的内存解释为C int
<BV32 0x8949ed31>
```

这些不是python的int！而是_bitvectors_。python的整形和CPU中没有相同的语义，比如包装溢出，所以我们使用bitvector，您可以将其视为由一系列位表示的整数，以表示angr中的CPU数据。注意，每个bitvector都有`.length`属性来表述位的宽度。

我们将很快了解如何使用它们，但是现在，先看看如何从python int转换为bitvectors，再转换回去：
We'll learn all about how to work with them soon, but for now, here's how to convert from python ints to bitvectors and back again:

```python
>>> bv = state.solver.BVV(0x1234, 32)       # create a 32-bit-wide bitvector with value 0x1234
<BV32 0x1234>                               # BVV stands for bitvector value
>>> state.solver.eval(bv)                # convert to python int
0x1234
```

您可以将这些位bitvector存储回寄存器和内存，也可以直接存储python整数，它会被转换为适当大小的bitvector：

```python
>>> state.regs.rsi = state.solver.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>

>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>
```

`mem`接口看起来有点让人困惑，因为它使用了一些python的语法糖，下面是使用它的简单方法：

* 使用array\[index\]表示指定地址
* 使用`.<type>`指定内存应解释为&lt;数据类型&gt; \（常用值：char，short，int，long，size_t，uint8_t，uint16_t ...... \）
* 还可以:
  * 设置它的值，可以是bitvector或python int
  * 使用`.resolved`按bitvector来读取值
  * 使用`.concrete`按python int来读取值

有更多高级用法将在稍后介绍！

最后，如果您尝试读取其他寄存器，您可能会遇到一个看起来奇怪的值：

```python
>>> state.regs.rdi
<BV64 reg_48_11_64{UNINITIALIZED}>
```

这仍然是64位bitvector，但它不包含数值。
但它有个名字。
这种叫做符号变量（_symbolic variable_），它是符号执行的基本。
别急！我们将从现在开始会用这两个章节详细讨论这些。

#### 模拟管理器（Simulation Managers）

state表示一个指定时间的程序运行状态，需要有一种方法将它及时传给_next_点。simulation manager在angr中是主要接口，用于执行，模拟，通过state你可以想怎么调用它干啥都行。为简要介绍，让我们展示如何tick我们之前创建的state转发给几个基本块。

首先，创建一个simulation manager。构造函数可以传入一个state或一个state的列表。

```python
>>> simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
>>> simgr.active
[<SimState @ 0x401670>]
```

simulation manager可以包含多个_stash_状态。默认的stash是`active`，是我们传入的state初始化的。我们可以通过`simgr.active[0]`来查看更多的状态。

现在，我们会做一些执行。

```python
>>> simgr.step()
```

刚刚只是执行了一个基本块的符号执行！我们可以再看看active的stash，发现它已经被更新，但它没有修改我们原始的状态。SimState对象执行中是不可变的，你可以安全地在多轮执行中使用单个state。

```python
>>> simgr.active
[<SimState @ 0x1020300>]
>>> simgr.active[0].regs.rip                 # new and exciting!
<BV64 0x1020300>
>>> state.regs.rip                           # 依然和之前相同
<BV64 0x401670>
```

`/bin/true`不是描述如何用符号执行做有趣事情的一个很好的例子，我们这里不在深入。

## 分析（Analyses）

angr预先打包了几个内置分析，您可以使用它们从程序中提取一些有趣的信息。 他们是：

```
>>> proj.analyses.            # Press TAB here in ipython to get an autocomplete-listing of everything:
 proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses       
 proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker          
 proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery      
 proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast  
 proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting           
 proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG                   
 proj.analyses.CFGEmulated          proj.analyses.LoopFinder           proj.analyses.VSA_DDG               
 proj.analyses.CFGFast              proj.analyses.Reassembler
```

在本书后面会介绍其中一些内容，但通常你可以通过[api 文档](http://angr.io/api-doc/angr.html?highlight=cfg#module-angr.analysis)来看如何使用一个内置的分析。作为一个非常简短的例子：下面看看如何构建和使用快速控制流图：

```python
# 本来，当我们加载这个二进制文件时，它还将所有依赖项加载到同一个虚拟地址空间中
# 大多数分析是不需要的，所以指定auto_load_libs=false
>>> proj = angr.Project('/bin/true', auto_load_libs=False)
>>> cfg = proj.analyses.CFGFast()
<CFGFast Analysis Result at 0x2d85130>

# cfg.graph是一个完整CFGNode实例的networkx DiGraph
# 可以查看networkx API以了解如何使用它！
>>> cfg.graph
<networkx.classes.digraph.DiGraph at 0x2da43a0>
>>> len(cfg.graph.nodes())
951

# 使用cfg.get_any_node获取给定地址的CFGNode
>>> entry_node = cfg.get_any_node(proj.entry)
>>> len(list(cfg.graph.successors(entry_node)))
2
```

## Now what?

阅读本页后，您现在应该了解几个重要的angr概念：基本块，状态，位向量(bitvectors)，模拟管理器和分析。 除了不能使用angr作为一个很好的调试器之外，你真的做任何有趣的事情！ 继续阅读，你将解锁更深层次的能力......

[摘要](./SUMMARY.md) | 下一节：[加载二进制文件](./loading.md)