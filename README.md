# 什么是angr，如何使用它？

angr是一个多架构二进制分析工具包，具有执行动态符号执行的能力（如Mayhem，KLEE等等）和对二进制文件的各种静态分析。 如果你想学习如何使用它，那么你来对地方了！

我们试图让angr使用起来尽可能没有那么痛苦 - 我们的目标是创建一个用户友好的二进制分析套件，允许用户简单地启动iPython并使用几个命令轻松执行复杂的二进制分析。话虽如此，二进制分析是复杂的，这使得angr变得复杂。 本文档试图帮助解决这个问题，提供对angr及其设计的叙述性解释和探索。

必须克服几个挑战才能以编程的方式分析二进制文件。 它们大致是：

* 将二进制文件加载到分析程序中。
* 将二进制转换为中间表示语言\（IR \）。
* 进行实际分析。 如下：
  * 部分或全程序静态分析\（如依赖性分析，程序切片\）。
  * 对程序状态空间的象征性探索\（如“我们可以执行它直到找到溢出？”）。
  * 上面的一些组合\（如“让我们只执行写内存的程序块，以找到溢出。”\）

angr提供克服所有这些挑战的组件。 这本书将解释每一个部分如何工作的，以及它们如何被用来实现你的邪恶目标。

## 开始

安装说明可以看[这里](./INSTALL.md)。

要深入研究angr的功能，请从[top level methods](./docs/toplevel.md)开始，然后从那里开始阅读。

[docs.angr.io](https://docs.angr.io/)提供了一个可搜索的HTML版本的文档, 在[angr.io/api-doc](https://angr.io/api-doc/)可以找到HTML API的参考.

如果你喜欢玩CTF并且想以类似的方式学习angr，[angr_ctf](https://github.com/jakespringer/angr_ctf)提供一个有趣的途径让你熟悉angr的大部分符号执行能力。[The angr_ctf repo](https://github.com/jakespringer/angr_ctf)由[@jakespringer](https://github.com/jakespringer)维护。


## 引用angr

如果您在学术工作中使用angr，请引用它开发时的相关论文：

```bibtex
@article{shoshitaishvili2016state,
  title={SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Salls, Christopher and Stephens, Nick and Polino, Mario and Dutcher, Audrey and Grosen, John and Feng, Siji and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={IEEE Symposium on Security and Privacy},
  year={2016}
}

@article{stephens2016driller,
  title={Driller: Augmenting Fuzzing Through Selective Symbolic Execution},
  author={Stephens, Nick and Grosen, John and Salls, Christopher and Dutcher, Audrey and Wang, Ruoyu and Corbetta, Jacopo and Shoshitaishvili, Yan and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2016}
}

@article{shoshitaishvili2015firmalice,
  title={Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2015}
}
```

## 支持

要获得有关angr的帮助，您可以通过以下方式询问：

* slack频道: [angr.slack.com](https://angr.slack.com), 从[这里](https://angr.io/invite/)获取账号.
* 在github中提交问题
* 邮件泪飙: angr@lists.cs.ucsb.edu

## 更进一步：

你可以阅读[论文](https://www.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf), 解释一些内部，算法和使用的技术，以更好地了解背后发生的事情。

