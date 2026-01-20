# 文件保护者

中文名：文件保护者
英文名：File_Protector

## 需求

1.用户自定义的被保护文件/目录清单（必须填写绝对路径）
2.用户自定义的进程白名单（必须填写绝对路径）
3.拦截白名单外的进程对访问被保护文件/目录的操作
4.保存日志信息：时间戳，操作类型，发起进程，目标文件/目录，执行结果（允许/拦截）
5.只在类UNIX平台使用

## 依赖

依赖个人开发的OL库：[https://github.com/1613661434/OL](https://github.com/1613661434/OL)

## 注意事项

OL库关于XML是简单实现，就是依据标签来查找的，所以不支持注释等等功能，而且是一行一行读取

## 编译

记得自己改下**配置路径和日志路径**
```cpp
const string g_configPath = "";
const string g_logPath = "";
```

```bash
make
```


## 测试

```bash
make test
```

## 使用

通过LD_PRELOAD注入动态库

```bash
source export.sh
```

取消注入

```bash
source unset.sh
```