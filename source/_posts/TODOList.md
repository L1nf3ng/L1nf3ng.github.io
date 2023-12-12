---
title: TODOList
date: 2021-07-29 00:10:37
tags: TODO
categories: [学习计划]
---

# 数据安全学习

## 书籍

《数据安全架构设计与实战》 作者：郑云文

### 引申内容

1. 网站劫持原理

### 经验之谈

> **TIP1:**
>
> - 对于“业务代码访问数据”这块耦合过高，未采用【前端-业务逻辑-DAL】分层结构的存量业务系统，可采用[DB Proxy](https://tech.meituan.com/2016/09/09/dbproxy-introduction.html)的改造方式。
>
>   原理如下图：![](TODOList/DB_Proxy.gif)