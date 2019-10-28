---
title: Ysoserial工具解读（一）
date: 2019-10-23 16:31:10
tags: [java, RCE,反序列化]
categories: 漏洞分析
---

## 前言

虽然，[ysoserial](https://github.com/frohoff/ysoserial.git)这个工具从发布到现在有3、4年了。但它在构造序列化对象时使用了很多精巧的方法，重读一遍它的代码，对于提升java基础还是很有帮助的。这里计划写一个系列，将该工具所用到的一些类和特殊方法归类总结。如果有网友懒得自己读代码，可以读我写的这些文章。

准确来说，本系列的第一篇的文章应该是之前写的那篇：[Java反序列化漏洞解析](https://l1nf3ng.github.io/2019/03/27/Java反序列化漏洞解析/) 。今天主要说的第一个类是`AnnotationInvocationHandler`。

## 基础知识

### 反射机制

如上一篇所说，**反射机制**允许程序在运行态时*获取一个类的所有属性和方法，也能调用一个对象的所有方法，还能修改其属性*。具体的`Class`对象的各种方法都请参考上一篇文章，这里贴一下ysoserial这个工具对用到的反射机制的代码封装：

```java
/*全部实现在一个叫Reflections的类中*/
public class Reflections {

    // 获取某个类的某一字段，也就是成员变量；
    // 这里因为使用的getDeclaredField()方法，所以除了父类的字段，别的（private、public、protocted）均能获取到
    // 这一方法被后面两个方法调用
	public static Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
	    try {
	        field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
        }
        catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null)
                field = getField(clazz.getSuperclass(), fieldName);
        }
		return field;
	}

    // 设置字段值
	public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
		final Field field = getField(obj.getClass(), fieldName);
		field.set(obj, value);
	}

    // 获取字段值
	public static Object getFieldValue(final Object obj, final String fieldName) throws Exception {
		final Field field = getField(obj.getClass(), fieldName);
		return field.get(obj);
	}
    
    // 获取声明的第一个构造函数
    public static Constructor<?> getFirstCtor(final String name) throws Exception {
		final Constructor<?> ctor = Class.forName(name).getDeclaredConstructors()[0];
	    ctor.setAccessible(true);
	    return ctor;
	}

    // 根据构造函数构建实例
	public static Object newInstance(String className, Object ... args) throws Exception {
        return getFirstCtor(className).newInstance(args);
    }
    * * * *
```

因为在后面的代码中ysoserial调用了好多这个类的静态方法，就不再一一解释。

### 动态代理



## References:

1. [ https://www.cnblogs.com/Welk1n/p/10511145.html ]()
2.  [http://www.vuln.cn/6295 ]()

