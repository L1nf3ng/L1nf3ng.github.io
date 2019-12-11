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

要求：Server端和Client端之间共享一个接口。

```java
/**
**	通用接口：
**/
import java.rmi.Remote;
import java.rmi.RemoteException;

//远程接口
public interface ImInterface extends Remote {
    public String hello(String a) throws RemoteException;
}
```
可以用`javac`将编译成class文件发给对方，或者直接告诉其源码内容（类名称、方法名称必须相同）
```java
/**
**	Server端：Rmf_server.java
**/
import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;

public class Rmf_server{

    public class RemoteHelloWorld extends UnicastRemoteObject implements ImInterface {
        private RemoteHelloWorld() throws RemoteException {
            super();
            System.out.println("you're in construction.");
        }

        public String hello(String a) throws RemoteException {
            System.out.println("call from");
            return "Hello world";
        }
    }

    //注册远程对象
    private void start() throws Exception {
        //远程对象实例
        RemoteHelloWorld h = new RemoteHelloWorld();
        //创建注册中心
        Registry registry = LocateRegistry.createRegistry(5599);
        //绑定对象实例到注册中心
        registry.bind("Hello", h);
    }

    public static void main(String[] args)throws Exception{
        new Rmf_server().start();
    }

}


/**
**	Client端：HappyEnding.java
**/
import java.lang.System;
import java.rmi.Naming;

public class HappyEnding{

    public static void main(String[] args) throws Exception {
        // list()方法用来查询目标主机上注册机中可用的对象名
        String[] names = Naming.list("rmi://10.10.10.136:5599/");
        for( String name : names){
            System.out.println(name);
        }
        // lookup()方法获取目标对象的Stub
        ImInterface ss = (ImInterface)Naming.lookup(names[0]);
        String result = ss.hello("ni hao!");
        System.out.println(result);

    }        

}
```

在启动server端后，用client端去连，可以看到调用成功返回的结果：

```powershell
F:\Studio>java HappyEnding
//10.10.10.136:5599/Hello
Hello world
```

## 利用姿势



## References

* https://xz.aliyun.com/t/6660 
* https://xz.aliyun.com/t/2649
* https://xz.aliyun.com/t/2651 
* https://xz.aliyun.com/t/2650 
* https://www.anquanke.com/post/id/194384 
* https://www.anquanke.com/post/id/190468

