---
title: Ysoserial工具解读（六）
date: 2019-11-19 14:45:24
tags: [Java, RCE,反序列化]
categories: 漏洞分析
---

## 基础知识

### RMI是什么

RMI（Remote Method Invocation，远程方法调用）类似于RPC（Remote Process Call，远程过程调用），常被用在分布式环境中（如阿里的Dubbo框架）。假设A主机需要处理大量的计算任务，而B主机这会儿没有任务，这时可以用RMI将一部分任务分给B来做，提高效率。

客户端（A主机）和服务端（B主机）之间的通信实际交给位于各自JVM的Stub（存根）和Skeleton（不知道怎么翻译，但官方说明jdk8以后不再依赖这个组件）执行，而在这期间，RMI registry注册表扮演着图书管理员的角色。具体的实现过程如下图：

1. 当Server有一个Service对象提供给外部调用时，它需要先向注册表登记
2. 当Client需要调用Service对象时，就要先去注册表查询可用的对象名称
3. 注册表会将该对象的存根Stub发送给Client
4. Client根据事先获知的接口调用需要的方法，参数实际上是交给了自己JVM中的Stub
5. Stub会将参数序列化后发送给Server上的JVM中的Skeleton
6. Skeleton将参数反序列化后呈递给Service对象
7. JVM结合方法声明和参数并将运算结果返回Skeleton
8. Skeleton再将运算结果发送给Client对象

![](Ysoserial工具解读（六）\rmi.JPG)

### 代码示例

Server端：



## 利用姿势

## References

* https://xz.aliyun.com/t/6660 
* https://xz.aliyun.com/t/2649
* https://xz.aliyun.com/t/2651 
* https://xz.aliyun.com/t/2650 
* https://www.anquanke.com/post/id/194384 
* https://www.anquanke.com/post/id/190468

