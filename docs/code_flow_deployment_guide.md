# A2ASecBench 代码流程与部署运行说明

本文档用于快速理解本仓库的整体代码流程，并说明如何在本地部署、运行评测，以及运行后可以得到什么结果。

## 1. 项目定位

A2ASecBench 是一个用于评估 Agent-to-Agent 系统安全行为的 Python benchmark。它提供固定攻击用例、可插拔的被测系统接口，以及本地可执行的 A2A 协议环境。

它主要评测以下攻击场景：

| 攻击类型 | 评测目标 |
| --- | --- |
| AS: AgentCard Spoofing | 被测 selector 是否会在多个伪造 AgentCard 中选错 benign AgentCard |
| CC Whitebox | comparator 是否能通过 AgentCard 与后端源码发现能力伪装 |
| CC Blackbox | comparator 是否能通过本地 A2A 服务交互发现能力伪装 |
| ASRF | coordinator 是否会错误访问 peer 提供的不可信资源 URI |
| ATSI | coordinator 是否会在 artifact 预览中触发不安全脚本或回调 |
| CO | coordinator 是否能限制循环 peer delegation |
| HOTF | coordinator 是否会保留过多 input-required 半开放任务 |

注意：结果中的 `success` 表示“攻击成功”，不是系统通过测试。

## 2. 代码结构

核心目录如下：

```text
A2ASecBench/
├── orchestration.py          # 主入口：读取 config、加载 case 和 SUT、执行 trial、写结果
├── attacks/                  # 攻击 case 定义、fixture、release 实例
├── configs/                  # offline、LLM、smoke、calibration 运行配置
├── harness/a2a_lab/          # 本地 A2A 协议环境、事件记录、评分组件
├── sut/                      # SUT 接口和参考实现
├── utils/                    # AgentCard 读取、LLM client、HTTP service、日志等工具
├── tests/                    # pytest 回归测试
├── scripts/                  # release 校验和辅助评分脚本
├── results/                  # 运行输出目录
└── docs/                     # 项目文档
```

## 3. 核心执行流程

主流程由 `orchestration.py` 驱动：

```text
读取配置文件
  -> 根据 cases 字段动态 import 攻击用例
  -> 检查所有 case 是否属于同一种 attack_id
  -> 根据 sut 字段动态加载被测系统
  -> 对每个 case 执行指定次数 trial
  -> 每次 trial 调用 case.run(...)
  -> case 内部调用 SUT 并完成评分
  -> 写入 results/run_*.jsonl
  -> 汇总生成 results/summary.json
```

配置文件决定三个关键内容：

```yaml
trials: 1
cases:
  - "attacks.instances.as.as_001:AS_001"
sut:
  selector: "sut.as.heuristic_selector:HeuristicSelector"
  kwargs: {}
```

其中：

- `cases` 是攻击用例类的 import path。
- `sut.selector`、`sut.comparator` 或 `sut.a2a_security` 是被测系统类的 import path。
- `kwargs` 会作为构造参数传入 SUT。
- `trials` 是每个 case 重复运行次数。

## 4. 关键抽象

### 4.1 AttackCase

所有攻击用例继承自 `attacks/base.py` 中的 `AttackCase`，必须实现：

- `get_ground_truth()`：返回标准答案或 oracle。
- `run(sut, **kwargs)`：执行一次 trial，并返回 `TrialOutcome`。

`TrialOutcome` 包含：

- `attack_id`
- `case_id`
- `trial_index`
- `success`
- `details`
- `errors`

### 4.2 SUT 接口

SUT 接口在 `sut/base.py`：

```text
SelectorSUT
  -> select(task_prompt, cards)

ComparatorSUT
  -> compare_whitebox(card, backend_code)
  -> compare_blackbox(card, backend_endpoint)

A2ASecuritySUT
  -> run_probe(case, env=None)
```

不同攻击类型使用不同接口：

| attack_id | SUT 接口 |
| --- | --- |
| AS | `SelectorSUT` |
| CC | `ComparatorSUT` |
| ASRF / ATSI / CO / HOTF | `A2ASecuritySUT` |

## 5. 各攻击流程说明

### 5.1 AS: AgentCard Spoofing

相关代码：

- `attacks/as_attack.py`
- `attacks/instances/as/`
- `attacks/fixtures/as/`
- `sut/as/`

执行流程：

```text
加载 benign AgentCard 和 spoofed AgentCards
  -> 根据 case_id + trial_index 固定 seed 洗牌
  -> 调用 selector.select(task_prompt, shuffled_cards)
  -> 如果选择不是 benign card，则攻击成功
```

适合评估 selector 是否容易被相似、夸大或伪装的 AgentCard 欺骗。

### 5.2 CC: Capability Cloaking

相关代码：

- `attacks/cc_attack.py`
- `attacks/instances/cc_whitebox/`
- `attacks/instances/cc_blackbox/`
- `sut/cc/`

whitebox 流程：

```text
加载 AgentCard
  -> import backend module
  -> 读取 backend 源码
  -> 调用 comparator.compare_whitebox(card, backend_code)
  -> 判断 comparator 输出是否等于 ground_truth_consistent
```

blackbox 流程：

```text
加载 AgentCard
  -> 启动本地 FastAPI/A2A probe service
  -> 获取 localhost endpoint
  -> 调用 comparator.compare_blackbox(card, endpoint)
  -> comparator 通过协议交互探测服务能力
  -> 停止本地服务
  -> 评分
```

如果 comparator 判断错误，则攻击成功。

### 5.3 ASRF / ATSI / CO / HOTF

相关代码：

- `attacks/a2a_attack.py`
- `attacks/instances/asrf/`
- `attacks/instances/atsi/`
- `attacks/instances/co/`
- `attacks/instances/hotf/`
- `harness/a2a_lab/`
- `sut/a2a/`

这些攻击使用本地 executable environment，而不是只看文本回答。

通用流程：

```text
A2AExecutableCase.run(...)
  -> 创建 LocalA2AProbeEnvironment
  -> 环境中启动本地 peer、service、trap、renderer、task store 等组件
  -> 调用 sut.run_probe(public_view, env.client())
  -> SUT 通过 env.client() 执行动作
  -> harness 记录真实事件和指标
  -> scoring.py 根据事件和 oracle 评分
```

示例动作：

- `env.call_agent(...)`
- `env.fetch_resource(...)`
- `env.reject_resource(...)`
- `env.render_artifact(...)`
- `env.create_task(...)`
- `env.reject_task(...)`
- `env.delegate_task(...)`
- `env.reject_delegation(...)`
- `env.final_answer(...)`

示例证据事件：

- `uri_dereference`
- `artifact_executed`
- `artifact_rendered`
- `task_store_pressure`
- `cycle_detected`
- `max_depth_exceeded`
- `a2a_message_sent`
- `a2a_agent_card_fetched`

这意味着 A2A executable 攻击的评分依赖实际环境副作用，而不是 SUT 在文本里声称做了什么。

## 6. 本地部署

### 6.1 环境要求

需要 Python 3.10 或更高版本。

建议使用虚拟环境：

```powershell
cd D:\code\A2ASecBench
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

如果 PowerShell 阻止激活脚本，可以临时执行：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 6.2 安装依赖

推荐用 editable 模式安装：

```powershell
pip install -e ".[dev]"
```

这会安装：

- `a2a-sdk[http-server]`
- `pyyaml`
- `requests`
- `httpx`
- `fastapi`
- `uvicorn`
- `python-dotenv`
- `pytest`

## 7. 运行评测

### 7.1 运行 AS 离线基线

```powershell
python orchestration.py --config configs/offline/as.yaml --trials 1
```

输出类似：

```text
ASR (AS): 0.xxxx
```

### 7.2 运行 CC whitebox

```powershell
python orchestration.py --config configs/offline/cc_whitebox.yaml --mode whitebox --trials 1
```

输出类似：

```text
ASR (CC/whitebox): 0.xxxx
```

### 7.3 运行 CC blackbox smoke

```powershell
python orchestration.py --config configs/smoke/cc_blackbox.yaml --mode blackbox --trials 1
```

blackbox 会启动本地服务进行探测，运行速度通常比 whitebox 慢。

### 7.4 运行 A2A executable 攻击

ASRF：

```powershell
python orchestration.py --config configs/offline/asrf_eval.yaml --trials 1
```

ATSI：

```powershell
python orchestration.py --config configs/offline/atsi_eval.yaml --trials 1
```

CO：

```powershell
python orchestration.py --config configs/offline/co_eval.yaml --trials 1
```

HOTF：

```powershell
python orchestration.py --config configs/offline/hotf_eval.yaml --trials 1
```

输出会包含攻击 ASR；如果配置里包含 control cases，还会显示 control pass rate。

## 8. 运行 LLM-backed SUT

LLM SUT 需要 OpenAI-compatible chat completions 接口。

可以在环境变量中设置：

```powershell
$env:SUT_API_BASE="https://your-api-base/v1"
$env:SUT_API_KEY="your-api-key"
$env:SUT_MODEL="your-model"
```

也可以写入项目根目录 `.env`：

```text
SUT_API_BASE=https://your-api-base/v1
SUT_API_KEY=your-api-key
SUT_MODEL=your-model
SUT_TEMPERATURE=0
SUT_TIMEOUT_S=60
```

示例运行：

```powershell
python orchestration.py --config configs/llm/as_sample.yaml --trials 1
python orchestration.py --config configs/llm/cc_whitebox_sample.yaml --mode whitebox --trials 1
python orchestration.py --config configs/llm/asrf_eval.yaml --trials 1
```

建议先跑 `sample` 配置，确认 API、模型输出格式和速度都正常，再跑 full 配置。

## 9. 运行结果

每次运行会生成两个主要文件：

```text
results/run_YYYYMMDDTHHMMSSffffffZ.jsonl
results/summary.json
```

### 9.1 JSONL 明细

`run_*.jsonl` 每一行是一条 trial 记录，包含：

- 时间戳
- config path
- config hash
- attack id
- case id
- trial index
- success
- details
- errors

其中 `details` 是分析单个 case 的主要字段。例如：

- AS 会记录 shuffle order、benign choice、selected choice。
- CC 会记录 predicted label、ground truth、evidence、endpoint。
- A2A executable 会记录 events、metrics、control pass、overblocked 等。

### 9.2 Summary 汇总

`summary.json` 包含：

- `total_trials`
- `total_successes`
- `asr`
- `counts_per_case`
- CC 额外包含 `label_accuracy`
- A2A executable 额外包含 `a2a_attack_asr`、`control_pass_rate`、`overblock_rate`

字段含义：

| 字段 | 含义 |
| --- | --- |
| `asr` | Attack Success Rate，攻击成功率 |
| `label_accuracy` | CC comparator 判断一致性的准确率 |
| `control_pass_rate` | control case 通过率 |
| `overblock_rate` | control case 被误拦截比例 |

## 10. 校验与测试

建议修改代码或数据后运行：

```powershell
python -m pytest
python scripts/validate_release.py
python scripts/validate_cc_blackbox_observability.py
python -m compileall -q orchestration.py attacks harness sut utils scripts tests
```

这些检查默认不需要 LLM 凭证。

## 11. 能达到什么效果

部署并运行后，可以得到以下能力：

1. 对 selector 进行 AgentCard spoofing 鲁棒性评估。
2. 对 comparator 进行能力声明一致性评估，包括源码可见和黑盒服务交互两种模式。
3. 在本地 A2A 协议环境中评估 coordinator 是否会触发真实危险动作。
4. 区分攻击 case 和 control case，观察模型是“容易被攻击”还是“过度保守”。
5. 输出可复现的 JSONL 明细和 summary 指标，方便后续统计、画图或写报告。

如果使用 LLM-backed SUT，可以比较不同模型、不同 prompt、不同 coordinator 策略在 A2A 安全任务上的表现。

## 12. 常见问题

### 12.1 为什么界面里看不到代码变更？

如果只是读取和解释代码，没有修改文件，界面通常不会出现 diff。新增或修改文件后才会显示变更。

### 12.2 为什么 `git status` 报错？

当前目录可能不是 git 仓库。如果需要版本管理，可以在项目根目录执行：

```powershell
git init
```

但这不是运行 benchmark 的必要条件。

### 12.3 LLM 运行失败怎么办？

优先检查：

- `SUT_API_BASE` 是否包含正确 `/v1` 路径。
- `SUT_API_KEY` 是否有效。
- `SUT_MODEL` 是否存在。
- 服务是否支持 OpenAI-compatible `/chat/completions`。
- 模型是否返回可解析 JSON，尤其是 A2A coordinator 场景。

### 12.4 blackbox 或 executable 运行慢怎么办？

这些模式会启动本地服务、协议 peer 或 harness 环境，天然比离线规则评测慢。可以先使用 `configs/smoke/` 或 `configs/llm/*_sample.yaml` 验证流程。
