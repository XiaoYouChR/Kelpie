# CLAUDE.md

## 思想（宪法——遇到下面任何规则没覆盖的场景，回到这里判断）

- **Simple is better than complex.** (Zen)
- **Flat is better than nested.** (Zen) — 函数优于类、内联优于跳转、三行重复优于过早抽象
- **Explicit is better than implicit.** (Zen) — 依赖显式传入、配置显式注入、不靠模块级全局状态做隐式耦合
- **Readability counts.** (Zen) — 代码被读 > 被写。从业务角度命名，不用生僻词；「注释只写 Why」的前提是代码本身能说明 What
- **Message-driven actors.** — actor 拥有私有状态，对外只收发消息；结构见 docs/adr/0005
- **YAGNI — trust internals, validate at boundaries.** — 不写 hypothetical 防御，删除胜于注释掉，不留向后兼容别名
- **If the implementation is hard to explain, it's a bad idea.** (Zen) — 解释起来绕的设计，多半是错的

## 命名

- 类名 PascalCase，函数和变量 camelCase
- 函数名用动词前缀（PowerShell 风格）：`kelpie.remove()`、`link.Parse()`
- 选短词、常见词，第一次读代码的人也能看懂
- 类名提供了上下文后，去掉冗余名词：`server.ParseMet()` 不写 `ParseServerMet()`
- 名词锁定到 CONTEXT.md，不用近义词：`Transfer` 不写 `download`，`Run` 不写 `session`
- 不用 `_` 前缀标记模块内部函数——模块边界本身就是封装
- Actor 以它拥有的业务概念命名，禁用 manager、controller、coordinator、provider、repository、facade、pipeline、context
- 布尔值用 `is*` / `has*` / `can*` / `should*` 前缀
- 消息类型用名词（`HandshakeCompleted`、`SourcesFound`），对消息的反应用 `On{Noun}`
- 名词查找用名词形式：`runById(id)`、`transferByHash(hash)`。`find*` 留给磁盘/PATH 搜索
- 文件系统词：`folder`（确定是目录）、`file`（确定是文件）、`path`（可能是文件或目录）

## 动词表

封闭词汇表——函数名只能从这里选动词。选不出说明职责不清或 seam 错了。

| 动词 | 语义 |
|---|---|
| `load` | 读取本地持久化数据或资源。非 fetch |
| `save` | 持久化应用状态 |
| `fetch` | 一次网络请求获取数据。非 load |
| `probe` | 查询能力或元数据，不创建任务 |
| `parse` | 将文本/协议输出转为应用对象 |
| `match` | 判断候选是否符合规则 |
| `find` | 搜索本地磁盘或 PATH |
| `build` | 从已知数据纯构造，无副作用。非 create |
| `create` | 创建真实资源（spawn、allocate、connect）。非 build |
| `to*` | 转换表示：`toSafeFilename`、`toPosixPath` |
| `set` | 赋值本地状态，调用者提供最终值。非 update |
| `update` | 从调用者输入重算状态。非 refresh |
| `refresh` | 自发重查，无调用者输入。非 update |
| `add` | 添加业务对象 |
| `start` / `pause` / `stop` | 开始执行 / 用户可见暂停 / 停止当前执行 |
| `resume` | 启动恢复 |
| `remove` | 从内存/模型/UI 脱离，不删磁盘。非 delete |
| `delete` | 从磁盘或持久记录破坏性删除。非 remove |
| `clear` | 清空集合、输入、选择或缓存 |
| `mount` / `unmount` | 创建/回收进出视口的懒管理控件 |
| `flush` | 将缓冲状态写入磁盘 |
| `cancel` | 放弃异步工作，不删记录 |
| `open` / `close` | 打开/关闭文件、URL、socket、dialog |
| `reveal` | 在文件管理器中显示 |
| `run` | 执行当前 actor 拥有的工作流步骤 |
| `supervise` | worker 内部监管器：采样进度、存恢复数据 |
| `patch` | 对已有二进制结构做定点修改。非 update |
| `install` | 将运行时或二进制放到磁盘 |
| `send` | 向另一系统推送数据，单向无响应 |
| `request` | 请求另一 actor 执行动作 |
| `on*` | 对消息或事件的反应 |

## Go

- 导出名 PascalCase，未导出名 camelCase；动词同样取自上表（`OnPacket`、`ParseMet`、`Post`）
- 纯状态机（`peer`、`transfer`、`upload`、`server`）不做 I/O、不起 goroutine、不 import `engine`；对事件的反应命名为 `On*`，返回要执行的动作
- 只有 `engine` 和 `kad` 两个持状态 actor，消息都经 `Post` 进去，Engine 只从 `engine.Start` 启动；阻塞发送只能流向这两个 actor（ADR-0005）
- `wire` 编解码：一个包一个 struct，`Build` 写出协议字节、opcode 和正文，各族 `Parse` 解码
- 外部依赖只经 `transport`、`disk`、`clock` 三个接缝；测试用它们的 fake，不 mock 其他东西。例外写在 `internal/archtest`：`store` 直接写 `state.json`，`nat` 自己是通往路由器的接缝
- 测试跑 `go test -race ./...`，只用 fake，不碰真实网络；真实网络的验证用 `bench/`
- engine 测试各自 `t.Parallel()` 并跑在 `synctest.Test` 气泡里：fake 时钟等引擎的 goroutine 都空闲了才往前走，不靠真实时间等待
- 从 goed2k 搬来的代码保留 MIT 出处（见 NOTICE）；eMule、aMule（GPL）只提供协议知识，不抄代码

## Python

- `kelpie/` 只依赖标准库
- 协议的唯一事实来源是 docs/protocol.md；Go 和 Python 两侧都按它实现
- 链接解析的测试向量在 testdata/links.json，两侧共用

## 反模式（看到就改）

**违反 Flat is better than nested：**
- 只做 if/elif 分发的包装函数 → 让调用方直接调对应函数
- 把类嵌在方法里但不用闭包 → 提升为模块级
- 类名已提供上下文时函数名还重复名词 → 砍掉名词

**违反 Explicit is better than implicit：**
- 模块级 `global` 可变状态伪装成单例 → 提升为类，或 frozen dataclass 显式注入
- 用 dict 传结构化数据 → 用 dataclass
- 传整个对象但只用其中一个方法 → 传 callable，依赖保持最窄

**违反 YAGNI：**
- 多处文档描述同一个事实 → 一个事实一个位置，其余用链接

**违反 Simple is better than complex：**
- 把不属于本模块职责的逻辑混进来"顺手做了" → 保持单一职责

**违反 Readability counts：**
- 注释或文档复述代码已经说明的事 → 删掉，代码自己说 What
