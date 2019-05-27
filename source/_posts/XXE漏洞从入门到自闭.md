---
title: XXE漏洞从入门到自闭
date: 2019-05-17 16:37:04
tags: [XXE,OOB]
categories: 漏洞分析
---

好久没有更新博客了，这半个月都在写自己的扫描器，也没有follow一些新出的漏洞。曾计划写一个OWASP TOP10系列，讲述常见web漏洞的简单利用和一些绕过姿势，帮助感兴趣的人入门，同时提高自己。现在发现要做的事有好多，必须一件一件来，贵在坚持！

<!-- more -->

XML和Json可以算现代Web应用通信中使用最多的两种数据格式。XML文件看似简单，但我们可能对它没有那么“了解“。日常的开发中，我们关注点可能更多在XML元素上，而忽略了XML实体。而这些实体正是构造攻击代码的主要工具。想玩转XXE（XML External Entity Injection，XML外部实体攻击）漏洞，必须先了解实体的用法。

## 基础知识

一个常规的XML文档主要有三部分构成：文档声明、文档类型定义、文档元素，如下图（借一下别人的图）：

![](XXE漏洞从入门到自闭\1.gif)

* 文档声明：定义版本号，编码格式等信息
* 文档类型定义：用来定义MXL文档的合法构建模块，**这里便是定义实体的地方**
* 文档元素：就是将对象的属性以标签的形式记录下来，其中标签内部不可以出现`<`特殊字符，如需要使用，则采用实体编码方式（和HTML相同：`< => &lt;  > => &gt; & => &amp; ' => &apos; " => &quot; `）

### 文档类型定义

DTD（Document Type Definition）里定义了实体，







## 参考文章

1. [https://xz.aliyun.com/t/2571#toc-9]()
2. [https://www.cnblogs.com/backlion/p/9302528.html]()
3. [https://www.freebuf.com/vuls/175451.html]()
4. [https://www.acunetix.com/blog/articles/xml-external-entity-xxe-vulnerabilities/]()
5. [https://www.anquanke.com/post/id/178339]()

