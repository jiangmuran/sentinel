# Sentinel —— AI 智能体支付的运行时执行层

*[English](README.md) · 中文*

**给会花钱的 AI 智能体的实时盗刷断路器。** Visa、万事达、谷歌正在修 agent 付钱的
*轨道*(x402 / AP2 / MPP)和给纠纷用的*事后记录*(Verifiable Intent)。**但没人在
运行时、结算前**校验一笔交易是否越权、是否被操纵。Sentinel 就是这块缺失的层——坐在
agent 和支付轨道之间,对每一笔交易,在钱转出去之前:

- 💳 **执行签名 mandate** —— 金额上限 / 收款白名单 / 有效期;HMAC 签名、防篡改。
- 🧬 **追踪 provenance** —— 拦下任何"金额或收款方溯源到注入内容"的支付。这正是
  EchoLeak(CVE-2025-32711)背后的 *LLM 作用域越权*,在**动作层**拦截。
- 🧾 **产出签名回执** —— approve/block 的防篡改记录,与 Verifiable Intent **互补**,
  但在**结算前**产生。
- 🛡️ **(底座)** 检测提示注入(中英文,20+ 类)+ 最小权限。

轨道无关(AP2 / x402 / MPP);MCP 是首个支持的接入面。无需改动客户端。

**材料:**
🌐 [在线网页](https://claude.ai/code/artifact/286e9fc5-02af-4d71-a000-72a5b1eb2335)(含浏览器内实时注入测试器) ·
📊 [Pitch Deck](https://claude.ai/code/artifact/01e08b6b-a511-4f78-9c6e-c3560df487a4) ·
📄 [白皮书](WHITEPAPER.md) ·
🇨🇳 [中文一页纸](https://claude.ai/code/artifact/e3640a5e-bd39-48ba-986e-1967349f8554)

---

## 60 秒看它拦下一次盗刷

```bash
python examples/commerce_demo.py
```

一个购物 agent 持有签名 mandate(*"≤ ¥50,只付给 acct-MERCHANT-001"*),读到一个把收款方
改成 `acct-EVIL-6666`、金额改成 ¥9999 的投毒页面。Sentinel **在三条独立理由上拦下**——
超额度、不在白名单、provenance 溯源到投毒页——并产出一张签名 blocked 回执;而合法的
¥49 付给真实商户则**正常放行**。精度("不是一刀切禁支付")才是重点。

> **状态:** 早期 alpha(v0.1)。支付执行(签名 mandate + provenance + 签名回执)、签名
> 检测器、stdio 代理、SentinelBench 均已就绪并测试(46 单测 + 对官方 MCP SDK 的真机集成
> 测试)。为 GOAI 世界人工智能开源大赛而建;Apache-2.0,欢迎贡献。

## 核心:运行时执行层

签名过滤器问的是*"这段文字像不像坏的"*——脆弱的代理指标。运行时执行层问一个更好的问题:

> **这个不可逆的动作,是不是源自不可信内容、是否越权?**

每笔高危交易在**结算前**跑三道独立检查(签名 mandate + provenance + 签名回执),
只要有一条不符就熔断,并把因果链写进审计日志。

```python
from mcp_sentinel import Sentinel, Mandate, TransactionGuard, ToolCall

mandate = Mandate.issue(SECRET, agent_id="shopper", max_amount=50, currency="CNY",
                        allowed_recipients=("acct-MERCHANT-001",), expires_at=..., nonce="n1")
guard = TransactionGuard(Sentinel(), mandate, SECRET)
receipt = guard.authorize(ToolCall(tool="create_payment",
                                   arguments={"to": "acct-EVIL-6666", "amount": "9999"}))
# receipt.decision == "blocked"; receipt.reasons 列出三条独立理由; receipt.verify(SECRET) 可验签
```

## SentinelBench

一个开放、分档的攻防基准,**同时**衡量检出率与误报率(良性对照是一等公民)。

```
71 用例 / 21 类 · 映射 OWASP MCP Top 10
核心档检出 100% (41/41) · 误报 0% (0/22) · 困难档 0/8(诚实标注,留给 LLM 检测层)
```

困难档(语义 / 德语 / 角色扮演 / base64)**没有签名特征**——签名层预期漏掉,如实报告,
这才是它存在的意义。`python -m benchmark.runner`。

## 在真实 MCP 协议上验证

真实的 `mcp.ClientSession` 经过 Sentinel 代理,与真实 FastMCP server 通信:中毒工具被隔离、
注入结果被拦、攻击者支付在真实协议上被熔断、良性调用原样通过。克隆即跑,零运行时依赖。

```bash
pip install -e ".[test]"
python -m unittest tests.integration.test_payment_provenance -v
```

## 与巨头互补,不竞争

他们是路,我们是安全气囊。我们不拼支付轨道——我们**接入**他们的轨道(消费 AP2 /
Verifiable-Intent 的 mandate),补上他们都缺的那道"运行时预防"闸。对口蚂蚁 / 支付风控。

## 路线图

- [x] 签名 mandate + provenance + 签名回执的支付执行层
- [x] 中英文签名检测 · 真 MCP SDK 集成 · SentinelBench
- [ ] 参考 LLM 检测器适配器(把困难档拉起来)
- [ ] HTTP/SSE 传输,然后 A2A(agent 间)provenance
- [ ] 公开的 SentinelBench 榜单

## 许可证

Apache-2.0,见 [LICENSE](LICENSE)。

*防御性安全工具。仓库内所有"攻击"载荷均为惰性测试样本,仅用于验证检测,不会被执行。*
