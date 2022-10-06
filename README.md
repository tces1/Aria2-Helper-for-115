# Aria2-Helper-for-115

### 首先感谢@showmethemoney2022大神提供的加密算法！

### 主要功能
* 免115浏览器下载大文件
* 远程卸货到NAS
* Aria2支持目录下载

### 项目背景
这个脚本是参考一个三年没更新的脚本，原来的底子很好，废弃太可惜了，把url提取方法进行了修复，并对UI进行了细微的调整，尽量做到原汁原味

### 使用方法
* 点击aria2按钮，勾选的项目下载请求发送至aria2服务器
* 按住Ctrl(WIN)/Command(MAC)点击aria2按钮，将直接使用浏览器下载，不发送aria2下载请求
* 按住Alt点击aria2按钮，仅复制下载链接，不进行下载操作
* 第一次使用要点击允许访问域，否则会出现问题  
![](https://greasyfork.s3.us-east-2.amazonaws.com/14w05agsu0p99axyp1lkp5wcbaur '')

### TODO
~~* 支持目录下载~~

### 如何修改aria2服务器信息
aria2的配置在代码里修改，位置如下
```
let Configs = {
    'debug_mode'    : true, // 是否开启调试模式
    "sync_clipboard": true, // 是否将下载链接同步到剪贴板，部分浏览器（如 Safari ）不支持
    'use_http'      : false, // 115 下载链接是否从 https 转换为 http （老版本 Aria2 需要）
    "rpc_path"      : 'http://你的ip或域名:你的rpc端口/jsonrpc', // RPC 地址
    "rpc_user"      : '', // RPC 用户名（若设置密码，请填写至 token 项）
    "rpc_token"     : '你的token', // RPC Token ，v1.18.4+ 支持，与用户名认证方式互斥
    "notification"  : true, // 是否开启推送通知
};
```

### 常见问题
1. Edge浏览器行不行?  
目前仅测试了chrome，别的浏览器不保证成功
2. 已经设置了aria2的地址，为什么还会失败？  
注意一下白名单的设置，添加*或者你要访问的域名，要不然访问会失败的，修改位置参考下图中红圈
![](https://greasyfork.s3.us-east-2.amazonaws.com/b617lxg1cteix9wiusbikcdq4o8s '')
3. 复制的地址为啥迅雷下载不来？  
因为此115链接下载不仅需要地址还需要对应的cookies, 发送到aria2的请求中包含了这个cookies，所以可以远程下载，你使用浏览器自带的下载器是可以下载成功的，但是想要更多玩法需要自己去研究复制cookies了
4. 使用IDM？  
参考使用浏览器下载的方法
