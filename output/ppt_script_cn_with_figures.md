# 讲者备注

## Slide 1. AgentMaster：用 A2A + MCP 组织多智能体检索

开场先说明：这是一篇 EMNLP 2025 system demonstration，核心不是提出新模型，而是把 A2A 与 MCP 放进同一个多智能体检索框架，并用原型系统验证。

## Slide 2. 现有 LLM-MAS 的瓶颈集中在协作与工具接入

这里把研究动机讲清楚：单个 LLM 不够，传统 MAS 又容易静态路由、缺共享上下文、工具接入碎片化。

## Slide 3. AgentMaster 的核心假设：A2A 与 MCP 分工互补

强调两个协议的角色：A2A 面向智能体之间的消息与任务协作；MCP 面向工具、资源、上下文和状态的标准接口。

## Slide 4. 总框架把会话、协调、协议和状态层串成闭环

这页讲 Fig.1。注意四层结构：统一会话入口、多智能体中心、协议层、状态管理层。

## Slide 5. 案例系统把检索任务落到 Flask + Coordinator + Retrieval Agents

这页讲 Fig.2。它比 Fig.1 更工程化：Flask 入口、复杂度检测、Agent Clients/MCP Clients、四类检索代理。

## Slide 6. 端到端流程的关键在“先判断复杂度，再选择路径”

这里不用原图，转成汇报流程：用户输入后，Coordinator 做复杂度判断；简单任务直达 MCP client，复杂任务进入 agent clients。

## Slide 7. 复杂查询被拆成可验证的子任务

这页用 Fig.3 的前端回答和后端日志说明系统怎样处理复杂问题。

## Slide 8. 复杂任务评估围绕“拆解路径是否正确”展开

这页把 Table 1 重绘成 PPT 表。Q3 原文表中数量与列出的 agent path 有排版截断风险，因此用 mixed IR/SQL routing 表述。

## Slide 9. 量化结果显示语义一致性高，但复杂/图像任务较弱

这页讲 Table 2。平均 G-Eval 87.1%，BERTScore F1 96.3%；Image/Complex QA 低于 SQL/IR。

## Slide 10. 对比表明 A2A + MCP 的优势来自协议组合

这页讲 Table 3 的核心，不照搬整表。突出 AgentMaster 在记忆、协作、容错、架构上的组合优势。

## Slide 11. 多模态能力来自专门代理，而不是单个大模型包打天下

用 image agent 截图说明系统支持图像输入，但这部分也暴露了对底层模型和检索语料的依赖。

## Slide 12. 局限性提示：这更像可行性原型，而非充分验证的通用平台

这页要讲得中性：成绩不错，但评价集小，安全机制缺失，复杂查询误分类会影响结果。

## Slide 13. 汇报结论：AgentMaster 的价值在协议化多智能体工程

最后收束：方法贡献、证据、可讨论问题。不要把它讲成 SOTA benchmark，而要讲成协议组合与系统工程原型。
