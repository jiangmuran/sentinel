# 初赛提交操作单(照着点)

> 截止 **2026-08-16**。赛道 **新智基座 / Agent Infra**,方向 #4 金融风控与理赔自动化。
> 我(AI)无法用你的实名账号登录 goaihz.com 替你报名/上传——**下面每一步的材料我都已备好**,你只需登录官网、复制、上传。

## 你必须亲自做的两件事

1. **报名**:打开 https://www.goaihz.com/ → 「立即报名」→ 选 **新智基座** 赛道 → 建队(≤3 人)。
2. **提交**:提交通道已于 7/21 开放,在赛道提交页上传下面三样(前两样必交,第三样可选但强烈建议交)。

## 交什么(材料已就绪)

### ① 作品简介(必交,≤500 字)
直接复制 **[`初赛-作品简介.txt`](初赛-作品简介.txt)**(498 字,已含官方六要素:项目名称/问题场景/核心方案/创新/开放复用/进展)。粘进官网文本框即可。

### ② 方案 PPT/PDF(必交)
用现成的 14 页 Pitch Deck 导出 PDF:
1. 浏览器打开 **https://jiangmuran.github.io/sentinel/pitch.html**
2. `Ctrl/Cmd + P` → 目标选「**另存为 PDF**」→ 版式**横向(Landscape)**、背景图形**开启** → 保存。
   (已加打印样式:会把全部 14 页平铺、浅色底、每页一张,直接可用。)
   覆盖官方要求的所有内容点:场景价值、架构、AgentTeams 能力映射(角色编排/任务分解/上下文传递/状态追踪)、Skill 与工具集成、结果校验、异常处理、安全边界与风控、开源计划。

### ③ 可执行代码包(可选,建议交 = 加分)
初赛不强制,但我们代码完整、是硬加分项。两种交法任选:
- **给仓库链接**:`https://github.com/jiangmuran/sentinel`(README 有一键运行、CI 常绿)。
- **给压缩包**:在仓库根目录执行 `git archive -o sentinel.zip HEAD` 生成 zip 上传。

一键自证(评委/你都能跑,零依赖):
```bash
python examples/guardteam_demo.py     # 4 Agent 闭环:欺诈拦截 / 高风险暂缓 / 正常放款
python -m guardteam bench             # 核心检出 100% · 误报 0% · CommerceBench 10/10
python -m unittest discover -s tests  # 80 测试全绿
```

## 开源合规栏(官网通常要填)
- **开源协议**:Apache-2.0
- **第三方依赖**:运行时**零依赖**(纯标准库);`mcp`(仅测试/起 Skill 服务用),`anthropic`(仅可选 LLM)
- **知识产权**:自研;仓库内攻击样本均为**惰性防御性测试夹具**,不含任何真实凭据
- **可运行 Demo**:在线站点 https://jiangmuran.github.io/sentinel/ · 交互控制台 /guardteam.html · 合规报告样例 /sample-report.html

## 提交前自查
- [ ] 简介 ≤500 字、六要素齐(已 498 字)
- [ ] PDF 14 页完整、横向、能看清
- [ ] 仓库 public、CI 绿、License 文件在
- [ ] 队伍 ≤3 人、赛道选对(新智基座)
