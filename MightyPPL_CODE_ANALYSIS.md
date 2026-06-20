# MightyPPL 项目系统性精读分析

## 1. 项目总体概览

MightyPPL 是一个 C++17 命令行工具，核心目标是把 MITPPL/MITL 公式转换为定时自动机（Timed Automata, TA），用于可满足性检查和模型检查。输入是一个纯文本公式文件，例如 `(p1 U[1, 2] p2) && G[1, 3] (!p2)`；输出可以是 TChecker `.tck` 模型、Uppaal XML 模型及查询文件，也可以不输出文件而直接调用 MoniTAal/PARDIBAAL 的 DBM fixpoint 算法做有限/无限 timed word 上的判空。项目本身不是 fuzzing harness，也没有 Python 主流程；它更像一个“逻辑公式 -> 自动机网络/乘积自动机 -> 外部验证器或内置判空”的形式化验证工具链。

典型工作流：

```text
MITPPL/MITL 公式文件
-> ANTLR 解析为 parse tree
-> 标注时序类型与语义属性
-> 改写为 NNF
-> 时序子公式编号
-> 生成 BDD 标签
-> 为总公式、时间发散、每个时序子公式、模型 M 构造 TA
-> 输出 TChecker/Uppaal，或构造同步乘积 TA
-> MoniTAal fixpoint 判空并输出 SAT/UNSAT
```

## 2. 目录结构解读

| 路径 | 类型 | 作用 | 是否核心 |
| -- | -- | -- | ---- |
| `MightyPPL/README.md` | 文档 | 项目目标、语法概览、运行方式、构建说明、实验结果 | 是 |
| `MightyPPL/CMakeLists.txt` | 构建脚本 | 配置 C++17、ANTLR、BuDDy、MoniTAal、链接目标 `mitppl` | 是 |
| `MightyPPL/main.cpp` | C++ 源文件 | 命令行入口、参数解析、读公式、调用 `build_ta_from_main()`、输出或判空 | 是 |
| `MightyPPL/MightyPPL.{h,cpp}` | C++ 核心模块 | 全局状态、BDD 编码、公共建边函数、整体自动机构造管线 | 是 |
| `MightyPPL/Mitl.g4` | ANTLR 语法 | 定义 MITPPL/MITL 公式语法、interval、temporal atoms | 是 |
| `MightyPPL/Mitl*Visitor.{h,cpp}` | C++ visitor | 解析树检查、类型标注、NNF 改写、编号、收集时序子公式、BDD 生成 | 是 |
| `MightyPPL/Finally.cpp` 等基本模态文件 | C++ 构造器 | 为 `F/O/G/H/U/S/R/T` 构造 tester TA | 是 |
| `MightyPPL/Pnueli*.cpp` | C++ 构造器 | 为 `Fn/On/Gn/Hn` Pnueli 模态构造 tester/序列化组件 | 是 |
| `MightyPPL/Count*.cpp` | C++ 构造器 | 为 `CFn/COn/CGn/CHn` 计数模态构造 tester/序列化组件 | 是 |
| `MightyPPL/TAwithBDDEdges.{h,cpp}` | C++ 自动机封装 | 在 MoniTAal TA 上增加 BDD 边标签、求交、投影、时间发散 TA | 是 |
| `MightyPPL/AtomCmp.h` | 头文件 | 按 `AtomContext::id` 排序时序 atom 指针 | 是 |
| `MightyPPL/EnumAtoms.h` | 头文件 | 时序 atom 类型枚举 | 是 |
| `MightyPPL/external/buddy/` | 第三方源码 | BuDDy BDD 库源码/子模块 | 是 |
| `MightyPPL/external/monitaal/` | 第三方安装产物 | MoniTAal 头文件和静态库安装位置 | 是 |
| `MightyPPL/cmake/` | CMake 模块 | ANTLR C++ runtime、ANTLR generator 查找和生成逻辑 | 是 |
| `MightyPPL/testcases/` | 测试输入 | 示例 `.mitl` 公式和 benchmark 输入 | 辅助 |
| `MightyPPL/MightyPPL_new_*.cpp` | 历史/实验源文件 | 未进入当前 `add_executable(mitppl ...)`，像是实验版本或备份 | 否 |
| `MightyPPL/*.patch` | 补丁文件 | 本地实验/历史差异补丁，当前构建不直接使用 | 否 |
| `MightyPPL/LICENSE.md`, `COPYING*` | 许可证 | LGPL/MIT 相关声明 | 辅助 |

## 3. 项目依赖库分析

### 3.1 Python 依赖

| 库名 | 标准库/第三方库 | 使用位置 | 作用 |
| -- | -------- | ---- | -- |
| 未发现 | - | 当前 MightyPPL 源码未发现 Python 主流程或 Python import | MightyPPL 本身是 C++/CMake 项目 |

### 3.2 C/C++ 依赖

| 库名/头文件 | 标准库/第三方库/系统库 | 使用位置 | 作用 |
| ------ | ------------ | ---- | -- |
| `<iostream>`, `<fstream>`, `<sstream>` | C++ 标准库 | `main.cpp`, `MightyPPL.cpp` | 控制台输出、读写公式/模型文件、拼接输出 |
| `<map>`, `<set>`, `<vector>`, `<string>` | C++ 标准库 | 多数源码 | 保存 propositions、temporals、locations、edges、状态集合 |
| `<optional>` | C++ 标准库 | `main.cpp`, `MightyPPL.h` | `out_format` 表示是否输出文件及格式 |
| `<chrono>` | C++ 标准库 | `main.cpp` | 统计构造和 fixpoint 耗时 |
| `<numeric>` | C++ 标准库 | `MightyPPL.cpp`, `TAwithBDDEdges.cpp` | `std::gcd` 计算时间常数 GCD |
| `<cmath>` | C++ 标准库 | `MitlAtomNumberingVisitor.h` | 计算 Pnueli/Count 编码位数 |
| `antlr4-runtime.h` | 第三方库 | visitor 头文件、生成解析器 | ANTLR C++ runtime |
| `MitlLexer.h`, `MitlParser.h`, `MitlVisitor.h` | ANTLR 生成代码 | `MightyPPL.h`, visitor | 根据 `Mitl.g4` 生成词法、语法、visitor 基类 |
| `bdd.h` | 第三方库 BuDDy | `MightyPPL.cpp`, visitors, TA wrapper | BDD 变量、布尔标签、allsat、投影 |
| `types.h`, `TA.h`, `Fixpoint.h` | 第三方库 MoniTAal/PARDIBAAL | `main.cpp`, `MightyPPL.cpp`, `TAwithBDDEdges.cpp` | 定时自动机、DBM/federation、可达性和 Büchi fixpoint |
| `pugixml`, `pardibaal` | 第三方库 | `CMakeLists.txt` 链接 | MoniTAal 依赖，XML/DBM 支撑 |
| `Threads::Threads` | 系统库 | `CMakeLists.txt` | ANTLR runtime 在 Unix 上需要 pthread |

### 3.3 外部工具与构建依赖

| 工具/文件 | 作用 | 影响 |
| ----- | -- | -- |
| CMake >= 3.10 | 配置构建 | 生成 `mitppl` 构建系统 |
| C++17 编译器 | 编译源码 | 项目设置 `CMAKE_CXX_STANDARD 17` |
| Java + ANTLR complete jar | 从 `Mitl.g4` 生成 C++ parser/lexer/visitor | `ANTLR_EXECUTABLE` 可通过 CMake 参数或环境变量指定 |
| BuDDy | BDD 操作库 | 表示 proposition/temporal bit 的布尔约束 |
| MoniTAal | TA、DBM、fixpoint 后端 | 构造和分析定时自动机 |
| PARDIBAAL | DBM/约束底层库 | MoniTAal 依赖 |
| TChecker | 外部模型检查器 | 对 `.tck` 输出执行 `tck-reach` 或 `tck-liveness` |
| Uppaal/verifyta | 外部模型检查器 | 对 XML 输出执行有限词可达性查询 |
| opaal_ltsmin/LTSmin | 外部模型检查器 | 对 Uppaal XML 进行无限词 Büchi/liveness 检查 |

## 4. 主入口与运行方式

1. 主入口文件是 `MightyPPL/main.cpp`，函数是 `int main(int argc, const char **argv)`。
2. README 给出的典型命令：

```console
mitppl <in_spec_file> --{fin|inf} [out_file --{tck|xml} [--{noflatten|compflatten}]] [--debug] [--noback]
```

3. 启动后首先解析参数：`argv[1]` 是公式文件；`--fin/--inf` 决定有限 timed word 还是无限 timed word；若给出 `out_file --tck/--xml`，则写模型文件；否则直接调用内置 fixpoint 判空。
4. 参数影响：
   - `--fin`：接受条件用有限词可达性，内置后端调用 `Fixpoint::accept_states()`/`Fixpoint::reach()`。
   - `--inf`：接受条件用 Büchi，内置后端调用 `Fixpoint::buchi_accept_fixpoint()`。
   - `--tck`：输出 TChecker 模型，并打印 `tck-reach` 或 `tck-liveness` 命令。
   - `--xml`：输出 Uppaal XML；有限词生成 `.q` 查询，无限词生成 `.ltl` 查询。
   - `--noflatten`：输出多个 tester/component 自动机，不做单体乘积。
   - `--compflatten`：每个复杂 temporal 子公式内部先压平为一个 tester TA，再作为组件输出。
   - `--debug`：在解析、BDD、组件构造等阶段暂停等待输入。
   - `--noback`：禁用用于简化 tester TA 的 backward analysis；对 `--noflatten` 无效。
   - `ANTLR_EXECUTABLE`：构建时指定 ANTLR complete jar 路径。

## 5. 核心文件逐个精读

### 5.1 文件：`MightyPPL/main.cpp`

**文件职责：**

命令行入口，负责解析参数、读入公式、初始化 BuDDy、调用总构造函数、选择输出后端或内置判空后端。

**核心对象/函数列表：**

| 函数/类/结构体 | 作用 | 输入 | 输出 | 调用关系 |
| -------- | -- | -- | -- | ---- |
| `main()` | 程序入口 | `argc/argv` | 进程退出码 | 调用 ANTLR parser、`build_ta_from_main()`、MoniTAal fixpoint、文件输出 |
| 全局 `spec_file/out_file/out_format` | 保存命令行配置 | 参数解析结果 | 被后续模块读取 | 被 `main()` 写，被 `MightyPPL.cpp` 和构造器读 |
| 全局 `varphi/div/temporal_components/model` | 保存构造出的 TA 组件 | 构造函数返回 | 参与乘积/输出 | `build_ta_from_main()` 写 |

**关键逻辑解释：**

`main()` 先做手写参数解析，之后打开公式文件，把全文读入字符串；`bdd_init(1000, 100)` 初始化 BuDDy；用 `ANTLRInputStream -> MitlLexer -> CommonTokenStream -> MitlParser` 生成 parse tree；核心工作交给 `build_ta_from_main(original_formula)`。如果没有指定输出格式，就把返回的 `monitaal::TA pos` 作为乘积自动机进行 fixpoint 判空；如果指定输出格式，就把返回字符串或 `pos` 序列化成 TChecker/Uppaal 文件。

### 5.2 文件：`MightyPPL/MightyPPL.cpp` 和 `MightyPPL/MightyPPL.h`

**文件职责：**

这是项目的中枢模块：定义全局状态、BDD 编码辅助函数、将 BDD 边转换成 TChecker/Uppaal 文本的 helper，以及 `build_ta_from_main()` 这条完整编译管线。

**核心对象/函数列表：**

| 函数/类/结构体 | 作用 | 输入 | 输出 | 调用关系 |
| -------- | -- | -- | -- | ---- |
| `encode(i, offset, bits)` | 将整数编码为 BDD bit pattern | 整数、起始 BDD 变量、位数 | `bdd` | Pnueli/Count 构造和 BDD visitor 调用 |
| `allsat_print_handler()` | BuDDy `bdd_allsat` 回调 | `char* varset`, `size` | 写入 `sat_paths` | 输出转换 helper 调用 |
| `build_untimed_edge()` | 创建无时钟约束 BDD 边并可同步生成文本输出 | 边集合、location map、label | 更新边集合/输出流 | `build_*` 构造器调用 |
| `build_edge()` | 创建带 guard/reset 的 BDD 边并可同步生成文本输出 | source/target、guard_x/y、reset、BDD label | 更新边集合/输出流 | 几乎所有 `build_*` 调用 |
| `build_ta_from_atom()` | 按 atom 类型派发到具体构造器 | `AtomContext*` | TA 组件列表和文本 | `build_ta_from_main()` 调用 |
| `build_ta_from_main()` | 完整公式到 TA 的核心流水线 | `MainContext*` | `pair<monitaal::TA,string>` | `main()` 调用 |

**关键逻辑解释：**

`build_ta_from_main()` 先打印原始 parse tree，然后运行 visitor 管线：typing、NNF 检查、NNF 改写、重新 parse、重新 typing、时序 atom 编号、收集时序 atom、BDD 生成。随后计算所有时间区间常数的 GCD，构造 `TA_0`、`TA_div`、每个 temporal tester 和默认模型 `M`。若需要内置判空或 flattened 输出，它会把组件放入 `TAwithBDDEdges::intersection()` 做同步乘积，再对临时 BDD 变量做投影，最终返回普通 `monitaal::TA`。

### 5.3 文件：`MightyPPL/Mitl.g4`

**文件职责：**

定义 MITPPL 输入语言。顶层 `main` 是 `formula EOF`；`formula` 支持 atom、非、与、或、等价、蕴含；`atom` 支持未来/过去 MITL 模态、Pnueli 模态、Count 模态、布尔常量和原子命题。

**核心对象/函数列表：**

| 函数/类/结构体 | 作用 | 输入 | 输出 | 调用关系 |
| -------- | -- | -- | -- | ---- |
| `main` rule | 顶层公式 | 文本 token | `MainContext` | `parser.main()` 创建 |
| `formula` rule | 布尔公式 | atom/Not/And/Or/Iff/Implies | `FormulaContext` | visitor 遍历 |
| `interval` rule | 时间区间 | `[`, `(`, bound, comma, bound, `]`, `)` | `IntervalContext` | 构造器读取上下界 |
| `atom` rule | 时序/命题原子 | `F/O/G/H/U/S/R/T/Fn/...` | `AtomContext` | visitor 标注 `type/id/weak/...` |

**关键逻辑解释：**

ANTLR 的 `locals` 给 context 增加字段，例如 `props`、`temporals`、`repeats`、`id`、`type`、`weak`、`top`、`existential`、`overline/star/tilde/hat`。这让后续 visitor 可以直接把语义属性写回 parse tree 节点。语法中 `Star` 表示弱语义版本，例如 `F*`、`U*`。

### 5.4 文件：`MightyPPL/MitlTypingVisitor.cpp`

**文件职责：**

遍历 parse tree，标注每个 temporal atom 的 `type`、`weak`、`top`、`existential`。这些属性决定后续 BDD 编码和 tester 构造策略。

**核心对象/函数列表：**

| 函数/类/结构体 | 作用 | 输入 | 输出 | 调用关系 |
| -------- | -- | -- | -- | ---- |
| `visitMain()` | 从顶层公式开始 | `MainContext*` | `nullptr` | `build_ta_from_main()` 调用 |
| `visitAtomF/O/G/H()` | 标注一元时序模态 | atom context | 写 `type/weak/top/existential` | 递归 visit 子 atom |
| `visitAtomU/S/R/T()` | 标注二元时序模态 | atom context | 写 `type/weak/top/existential` | 递归 visit 左右子 atom |
| `visitAtomFn/On/Gn/Hn()` | 标注 Pnueli 模态 | 多个 atom | 写 `type` 与存在性传播 | 递归 visit `atoms` |
| `visitAtomCFn/...` | 标注 Count 模态 | 两个 atom | 写 `type`、`weak`、`num_pairs` 相关字段 | 递归 visit 子 atom |

**关键逻辑解释：**

`top` 表示公式最外层或当前语义关键位置，`existential` 表示该 temporal 子公式是否可用存在式 tester 简化。比如 `F`/`O` 对子公式保留 existential，而 `G`/`H` 会在子公式中切换 existential，因为全局类模态与最终类模态对偶。

### 5.5 文件：`MightyPPL/MitlCheckNNFVisitor.cpp` 和 `MitlToNNFVisitor.cpp`

**文件职责：**

`MitlCheckNNFVisitor` 判断公式是否处于 negation normal form，并检查一些容易歧义的优先级写法；`MitlToNNFVisitor` 把 `!`、`->`、`<->` 和 temporal 对偶展开到 NNF 字符串，然后重新解析。

**核心对象/函数列表：**

| 函数/类/结构体 | 作用 | 输入 | 输出 | 调用关系 |
| -------- | -- | -- | -- | ---- |
| `MitlCheckNNFVisitor::visitMain()` | 检查 NNF | `MainContext*` | `bool` | `build_ta_from_main()` 调用 |
| `visitInterval()` | 检查 interval 形态并返回是否 unary/uni | `IntervalContext*` | `bool` | temporal atom visit 调用 |
| `MitlToNNFVisitor::visitFormulaAnd/Or/Not/Implies/Iff()` | 用德摩根/蕴含等价改写 | formula context | NNF 字符串 | `build_ta_from_main()` 调用 |
| `MitlToNNFVisitor::visitAtomF/G/U/R/...` | temporal 对偶改写 | atom context | NNF 字符串 | 递归调用 |

**关键逻辑解释：**

NNF 改写不是直接修改原 parse tree，而是生成新公式字符串 `nnf_in`，再用 ANTLR 重新 parse。这样后续阶段只面对 `&&`、`||` 和命题前的 `!`。`visitInterval()` 还会拒绝当前不支持的 `(0, b>` 形式，并给 `ctx->uni` 提供信息；非 `[0,u]` 或 `[0,infty)` 这类一般区间通常会被改写为 Count 模态或进入更复杂构造。

### 5.6 文件：`MightyPPL/MitlAtomNumberingVisitor.cpp`

**文件职责：**

为每个不同的 temporal 子公式分配 BDD 变量编号；命题变量也在同一个编号空间中登记。重复出现的 temporal 子公式复用编号并记录在 `MainContext::repeats`。

**核心对象/函数列表：**

| 函数/类/结构体 | 作用 | 输入 | 输出 | 调用关系 |
| -------- | -- | -- | -- | ---- |
| `visitMain()` | 初始化 root/current_id 并返回总编号数 | `MainContext*` | `int` | `build_ta_from_main()` 调用 |
| `visitAtomF/O/G/H/U/S/R/T()` | 给普通 temporal atom 编号 | atom context | 新增 1 个编号或复用 | 递归 visit 子 atom |
| `visitAtomFn/On/Gn/Hn()` | 给 Pnueli atom 分配一段 bit | atom context | 新增 `bits` 个编号 | 使用 `ceil(log2(n+1))` |
| `visitAtomCFn/...` | 给 Count atom 分配 in/out 编码 bit | atom context | 新增一段编号 | 依赖 interval 与 pair 数 |
| `visitAtomIdfr()` | 登记原子命题 | identifier atom | 新 prop 编号或复用 | leaf 节点 |

**关键逻辑解释：**

普通 temporal atom 用一个 BDD 变量代表“这个子公式当前是否被声明为真”。Pnueli/Count 模态需要表达多个 obligation 的进入/退出，所以分配一段 bit 编码，例如 in/out 两半区间；`encode()` 会把整数 obligation 编号变成 BDD 位模式。

### 5.7 文件：`MightyPPL/MitlCollectTemporalVisitor.cpp` 和 `MitlGetBDDVisitor.cpp`

**文件职责：**

`MitlCollectTemporalVisitor` 收集所有 temporal atom 指针，并按 `id` 排序；`MitlGetBDDVisitor` 为每个公式/atom 计算四类 BDD 标签：`overline`、`star`、`tilde`、`hat`。

**核心对象/函数列表：**

| 函数/类/结构体 | 作用 | 输入 | 输出 | 调用关系 |
| -------- | -- | -- | -- | ---- |
| `MitlCollectTemporalVisitor::visitMain()` | 收集所有 temporal atom | `MainContext*` | `set<AtomContext*, atom_cmp>` | `build_ta_from_main()` 调用 |
| `MitlGetBDDVisitor::visitFormulaAnd()` | 组合 conjunction 的 BDD | 左右公式 BDD | 写当前 formula BDD | 递归 visit |
| `MitlGetBDDVisitor::visitFormulaOr()` | 组合 disjunction 的 BDD | 左右公式 BDD | 写当前 formula BDD | 递归 visit |
| `MitlGetBDDVisitor::visitAtomF/O/...` | 普通 temporal atom BDD | atom id/repeats | 写 `overline/star/tilde/hat` | 构造器读取 |
| `MitlGetBDDVisitor::visitAtomFn/...` | Pnueli/Count BDD 编码 | bit range | 写整体或 component BDD | 构造器读取 |

**关键逻辑解释：**

可以把 BDD 看成“事件字母上的布尔条件”。`hat` 常表示当前点触发/满足，`star` 表示可停留/非触发，`tilde = !overline & star` 用于构造 tester 的中间状态。构造器中的边标签常写成 `bdd_ithvar(phi->id) & phi->atom()->hat` 或 `!bdd_ithvar(phi->id) & phi->atom()->star`，即“当前 temporal bit 的选择”与“子公式字母条件”的组合。

### 5.8 文件：`Finally/Once/Globally/Historically/Until/Since/Release/Trigger.cpp`

**文件职责：**

这些文件按 temporal 模态构造 tester TA。每个函数签名都是：

```cpp
std::pair<std::vector<monitaal::TAwithBDDEdges>, std::string>
build_xxx(const MitlParser::AtomContext* phi_)
```

**核心对象/函数列表：**

| 函数/类/结构体 | 作用 | 输入 | 输出 | 调用关系 |
| -------- | -- | -- | -- | ---- |
| `build_finally()` | 构造 `F` tester | `AtomFContext*` | 1 个 TA + 输出文本 | `build_ta_from_atom()` 调用 |
| `build_once()` | 构造过去版 `O` tester | `AtomOContext*` | 1 个 TA + 输出文本 | `build_ta_from_atom()` 调用 |
| `build_globally()` | 构造 `G` tester | `AtomGContext*` | 1 个 TA + 输出文本 | `build_ta_from_atom()` 调用 |
| `build_historically()` | 构造过去版 `H` tester | `AtomHContext*` | 1 个 TA + 输出文本 | `build_ta_from_atom()` 调用 |
| `build_until()/build_since()` | 构造 `U/S` tester | 二元 atom | 1 个 TA + 输出文本 | `build_ta_from_atom()` 调用 |
| `build_release()/build_trigger()` | 构造 `R/T` tester | 二元 atom | 1 个 TA + 输出文本 | `build_ta_from_atom()` 调用 |

**关键逻辑解释：**

这些构造器的共性是：解析 interval 上下界和开闭端点；创建 `clock_map_t`、`locations_t`、`name_id_map`、`bdd_edges_t`；按强/弱语义、无界/有界区间、未来/过去方向建立状态和边。`build_edge()` 把字符串 guard 如 `<= 5`、`> 3` 转成 MoniTAal `constraint_t`，同时在输出模式下写 TChecker/Uppaal transition。过去模态并不是用双向 TA，而是利用定时正则语言对 reversal 闭包的思想做普通 TA 构造。

### 5.9 文件：`PnueliFn/On/Gn/Hn.cpp`

**文件职责：**

构造 Pnueli 模态 tester，例如 `Fn[0,u](phi1,...,phin)` 表示在时间窗口内按顺序出现多个子公式事件。`On/Hn` 是过去版本，`Gn/Hn` 是对偶/全局类版本。

**核心对象/函数列表：**

| 函数/类/结构体 | 作用 | 输入 | 输出 | 调用关系 |
| -------- | -- | -- | -- | ---- |
| `build_pnuelifn()` | 构造未来 existential/通用 Pnueli tester | `AtomFnContext*` | 1 个或多个 TA | `build_ta_from_atom()` |
| `build_pnuelion()` | 构造过去 Pnueli tester | `AtomOnContext*` | 1 个或多个 TA | `build_ta_from_atom()` |
| `build_pnuelign()` | 构造 `Gn` 对偶 tester | `AtomGnContext*` | 1 个或多个 TA | `build_ta_from_atom()` |
| `build_pnuelihn()` | 构造过去 `Hn` tester | `AtomHnContext*` | 1 个或多个 TA | `build_ta_from_atom()` |

**关键逻辑解释：**

Pnueli 构造器用 `in_null/out_null/in_i/out_i` 这类 BDD 编码表示 obligation 是否进入或退出。若 `phi->existential` 或 `comp_flatten`，通常生成较少组件；否则为每个位置生成组件，并可能生成 `seq_in_<id>`、`seq_out_<id>` 这类序列化自动机，避免多个 obligation 重叠导致组合爆炸。

### 5.10 文件：`CountFn/On/Gn/Hn.cpp`

**文件职责：**

构造 Count 模态 tester，例如 `CFn interval (p, q)` 这类形式会监控成对事件在时间区间内的关系。Count 构造比普通 MITL 更复杂，通常需要两个时钟 `x/y` 表示一个 pair 的开始和结束。

**核心对象/函数列表：**

| 函数/类/结构体 | 作用 | 输入 | 输出 | 调用关系 |
| -------- | -- | -- | -- | ---- |
| `build_countfn()` | 构造未来 count tester | `AtomCFnContext*` | 多个 TA 或压平 TA | `build_ta_from_atom()` |
| `build_counton()` | 构造过去 count tester | `AtomCOnContext*` | 多个 TA 或压平 TA | `build_ta_from_atom()` |
| `build_countgn()` | 构造对偶 count tester | `AtomCGnContext*` | 多个 TA 或压平 TA | `build_ta_from_atom()` |
| `build_counthn()` | 构造过去对偶 count tester | `AtomCHnContext*` | 多个 TA 或压平 TA | `build_ta_from_atom()` |

**关键逻辑解释：**

Count 构造器同样使用 in/out BDD 编码，但 bit 数比 Pnueli 多，用于表示 pair 编号和触发位。`single` 全局变量会临时影响 `build_edge()` 中第二时钟 `y` 是否映射到同一个物理 clock。非 existential 情况下会生成多个 pair tester、`seq_in`、`seq_out` 和一个 trigger/管理组件；若 `out_flatten` 或 `comp_flatten`，这些组件会被内部求交成较少自动机。

### 5.11 文件：`TAwithBDDEdges.{h,cpp}`

**文件职责：**

在 MoniTAal `TA` 上增加 BDD 边标签，支持用布尔公式同步多个自动机，并提供投影为普通 `TA` 的能力。

**核心对象/函数列表：**

| 函数/类/结构体 | 作用 | 输入 | 输出 | 调用关系 |
| -------- | -- | -- | -- | ---- |
| `bdd_edge_t` | 带 BDD label 的 edge | from/to/guard/reset/bdd | edge 对象 | 所有构造器创建 |
| `TAwithBDDEdges` ctor | 建立前向/后向 BDD edge map | name/clocks/locations/edges/initial | 自动机对象 | 构造器和 product 创建 |
| `bdd_edges_from/to()` | 查边 | location id | 边列表引用 | product/output 使用 |
| `intersection(vector<TAwithBDDEdges>)` | 构造同步乘积 | 组件自动机 | product TAwithBDDEdges | `build_ta_from_main()` 调用 |
| `projection()` | 去掉临时 BDD 变量并转普通 TA | props_to_remove | `monitaal::TA` | 最终返回给 fixpoint |
| `projection_bdd()` | 去掉临时变量但保留 BDD edge | props_to_remove | `TAwithBDDEdges` | Pnueli/Count 内部压平使用 |
| `time_divergence_ta()` | 构造时间发散约束 TA | `bdd any` | `TAwithBDDEdges` | `build_ta_from_main()` 调用 |

**关键逻辑解释：**

`intersection(vector)` 从初始 location tuple 做前向可达展开，而不是先构造完整笛卡尔积。每次枚举各组件当前 location 的 outgoing edge 组合，把 BDD labels 相与；若变成 `bdd_false()`，说明这组边不能同步，直接剪枝。有限词接受要求所有组件接受；无限词接受用 `curr_i/new_i` 轮转实现 generalized Büchi 的接受集合追踪。最后 `projection()` 使用 BuDDy 存在量化隐藏内部 temporal bits，只保留原始命题 bits。

## 6. 核心函数逐个解释

### 6.1 `main`

* 所在文件：`MightyPPL/main.cpp`
* 函数作用：程序入口，选择输入、输出和判空模式。
* 输入参数：`argc/argv`。
* 返回值：`0` 成功，`1` 参数或文件错误。
* 核心步骤：
  1. 手写解析 `--fin/--inf`、输出格式、flatten 模式、debug/back 开关。
  2. 打开公式文件并读入 `std::stringstream`。
  3. 初始化 BuDDy：`bdd_init(1000, 100)`。
  4. ANTLR 解析得到 `MitlParser::MainContext*`。
  5. 调用 `build_ta_from_main()`。
  6. 无输出文件时调用 MoniTAal fixpoint；有输出文件时写 `.tck` 或 `.xml/.q/.ltl`。
* 调用了哪些函数：ANTLR 构造函数、`build_ta_from_main()`、`Fixpoint::reach()`、`Fixpoint::buchi_accept_fixpoint()`。
* 被哪些函数调用：操作系统启动调用。
* 在整体工作流中的位置：入口和后端选择器。
* 潜在问题：参数解析非常脆弱，选项顺序基本固定，不支持常见 CLI 任意顺序解析。

### 6.2 `build_ta_from_main`

* 所在文件：`MightyPPL/MightyPPL.cpp`
* 函数作用：把公式 parse tree 转成最终 TA 或输出文本。
* 输入参数：`MitlParser::MainContext* phi_`。
* 返回值：`pair<monitaal::TA, string>`，前者用于内置判空/flatten 输出，后者用于非 flatten 输出文本。
* 核心步骤：
  1. 打印原始 parse tree。
  2. 运行 typing、NNF 检查、NNF 改写并重新 parse。
  3. 编号 temporal/proposition bits。
  4. 收集 temporal atoms 并处理 repeats。
  5. `bdd_setvarnum(num_all_props + 1)` 后生成 BDD。
  6. 计算所有区间常数 GCD。
  7. 构造 `TA_0`、`TA_div`、每个 temporal tester、默认 `M`。
  8. 若 flatten/内置判空，调用 `TAwithBDDEdges::intersection()` 并 `projection()`。
* 调用了哪些函数：所有 visitor、`build_ta_from_atom()`、`TAwithBDDEdges::intersection()`、`projection()`。
* 被哪些函数调用：`main()`。
* 在整体工作流中的位置：核心编译管线。
* 潜在问题：函数非常长，混合了编译、输出、日志和模型构造，维护成本高。

### 6.3 `build_ta_from_atom`

* 所在文件：`MightyPPL/MightyPPL.cpp`
* 函数作用：根据 `phi_->type` 分派到具体 temporal 构造器。
* 输入参数：`const MitlParser::AtomContext* phi_`。
* 返回值：`pair<vector<TAwithBDDEdges>, string>`。
* 核心步骤：
  1. 检查 `FINALLY/ONCE/.../COUNTHN` 枚举。
  2. 调用对应 `build_*()`。
  3. unsupported 类型触发 `assert(false)`。
* 调用了哪些函数：`build_finally()`、`build_once()`、`build_pnuelifn()`、`build_countfn()` 等。
* 被哪些函数调用：`build_ta_from_main()`。
* 在整体工作流中的位置：temporal atom 到 tester TA 的派发层。
* 潜在问题：依赖前序 visitor 正确设置 `type`，否则断言失败。

### 6.4 `build_edge`

* 所在文件：`MightyPPL/MightyPPL.cpp`
* 函数作用：创建一条带时钟 guard/reset 和 BDD label 的边，并在输出模式下生成 TChecker/Uppaal transition 文本。
* 输入参数：边集合、location map、输出流、`base_id/offset_id`、source/target 名、`guard_x/guard_y`、reset 编号、BDD label。
* 返回值：无；通过引用修改 `bdd_edges` 和 `out_s`。
* 核心步骤：
  1. 把 reset 编号 0/1/2/3 映射到 reset clock 集合。
  2. 把 guard 字符串如 `<= 5` 转成 MoniTAal `constraint_t`。
  3. 创建 `bdd_edge_t`。
  4. 若非 flattened 输出，调用 `bdd_allsat()` 展开 BDD label 并写 TChecker/XML transition。
* 调用了哪些函数：`bdd_allsat()`、`allsat_print_handler()`。
* 被哪些函数调用：所有 `build_*` 构造器。
* 在整体工作流中的位置：构造 tester 边的基础 API。
* 潜在问题：guard 使用字符串解析，错误输入基本靠 assert/隐式假设。

### 6.5 `encode`

* 所在文件：`MightyPPL/MightyPPL.cpp`
* 函数作用：把整数编号转成从 `offset` 开始的二进制 BDD 条件。
* 输入参数：`i`、`offset`、`bits`。
* 返回值：`bdd`。
* 核心步骤：
  1. 断言 `i` 能被 `bits` 位表达。
  2. 逐位生成 `bdd_ithvar(offset+j)` 或其取反。
  3. 高位补 0。
* 调用了哪些函数：BuDDy `bdd_true()`、`bdd_ithvar()`。
* 被哪些函数调用：`MitlGetBDDVisitor`、Pnueli/Count 构造器。
* 在整体工作流中的位置：复杂模态的 obligation 编码。
* 潜在问题：二进制低位优先编码，读代码时容易误以为是高位优先。

### 6.6 `MitlToNNFVisitor::visitMain`

* 所在文件：`MightyPPL/MitlToNNFVisitor.cpp`
* 函数作用：生成 NNF 公式字符串。
* 输入参数：`MainContext*`。
* 返回值：`std::string`。
* 核心步骤：
  1. 从 `formula()` 开始递归。
  2. 遇到 negated context 时用德摩根和 temporal 对偶。
  3. 对非 unary interval 的 `F/G/...` 可能转为 Count 模态表示。
* 调用了哪些函数：本 visitor 的各 `visitFormula*`/`visitAtom*`。
* 被哪些函数调用：`build_ta_from_main()`。
* 在整体工作流中的位置：前端规范化。
* 潜在问题：通过字符串再 parse 简单直接，但会丢失原始源码位置，不利于精准报错。

### 6.7 `MitlAtomNumberingVisitor::visitMain`

* 所在文件：`MightyPPL/MitlAtomNumberingVisitor.cpp`
* 函数作用：给命题和 temporal bits 分配全局编号。
* 输入参数：`MainContext*`。
* 返回值：编号总数。
* 核心步骤：
  1. 设置 `root` 和 `current_id`。
  2. 遍历公式。
  3. 对重复 temporal 文本复用编号并写入 `root->repeats`。
  4. 对 Pnueli/Count 分配多 bit 区间。
* 调用了哪些函数：递归 visit。
* 被哪些函数调用：`build_ta_from_main()`。
* 在整体工作流中的位置：BDD 变量布局阶段。
* 潜在问题：重复判断基于 `ctx->getText()`，不同但等价的公式不会合并。

### 6.8 `MitlGetBDDVisitor::visitFormulaAnd/visitFormulaOr`

* 所在文件：`MightyPPL/MitlGetBDDVisitor.cpp`
* 函数作用：组合子公式的 BDD 标签。
* 输入参数：formula context。
* 返回值：无；写 `ctx->overline/star/tilde/hat`。
* 核心步骤：
  1. 先递归生成左右子公式 BDD。
  2. `And` 用交组合 `overline/star/hat`。
  3. `Or` 用并组合 `overline`，并按事件触发语义组合 `hat`。
* 调用了哪些函数：递归 visit、BuDDy 布尔运算。
* 被哪些函数调用：`MitlGetBDDVisitor::visitMain()`。
* 在整体工作流中的位置：生成 TA 边标签前的布尔语义汇总。
* 潜在问题：四类 BDD 的语义没有集中注释，理解门槛高。

### 6.9 `TAwithBDDEdges::intersection`

* 所在文件：`MightyPPL/TAwithBDDEdges.cpp`
* 函数作用：构造多个 BDD-label TA 的同步乘积。
* 输入参数：`vector<TAwithBDDEdges>`。
* 返回值：`TAwithBDDEdges product`。
* 核心步骤：
  1. 合并 clock map 并记录每个组件 clock offset。
  2. 从初始 location tuple 建立第一个 product location。
  3. 用 fringe 做前向可达搜索。
  4. 枚举各组件 outgoing edge 的组合。
  5. BDD label 相与，矛盾则剪枝。
  6. 合并 guard/reset/invariant，并创建目标 product location/edge。
  7. 无限词时用轮转接受计数追踪 generalized Büchi。
  8. 可选做 backward 简化。
* 调用了哪些函数：BuDDy 运算、MoniTAal `location_t/constraint_t`、可能调用 `projection()`/fixpoint 辅助。
* 被哪些函数调用：`build_ta_from_main()`，复杂模态内部也可能调用。
* 在整体工作流中的位置：flatten 和内置判空前的核心同步器。
* 潜在问题：输出大量 `std::cout`，大模型下日志可能非常吵；组合边枚举仍可能爆炸。

### 6.10 `TAwithBDDEdges::projection`

* 所在文件：`MightyPPL/TAwithBDDEdges.cpp`
* 函数作用：把 BDD-label TA 转成普通 MoniTAal TA，并隐藏不需要的临时 proposition bits。
* 输入参数：`props_to_remove`。
* 返回值：`monitaal::TA`。
* 核心步骤：
  1. 构造要消去的 BDD 变量集合。
  2. 对每条 BDD edge 做存在量化/投影。
  3. 可满足的标签变成普通 TA edge。
* 调用了哪些函数：BuDDy quantification/sat 相关函数。
* 被哪些函数调用：`build_ta_from_main()`。
* 在整体工作流中的位置：内置 fixpoint 前的后处理。
* 潜在问题：投影后标签信息丢失，后续只能做 TA 可达性/接受性，不能再恢复完整事件约束。

## 7. 模块调用关系

```text
main.cpp
 ├── 参数解析，设置全局 out_fin/out_format/out_flatten/comp_flatten/debug/back
 ├── 读取 spec_file
 ├── bdd_init()
 ├── ANTLRInputStream -> MitlLexer -> MitlParser -> parser.main()
 ├── build_ta_from_main()
 │    ├── MitlTypingVisitor::visitMain()
 │    ├── MitlCheckNNFVisitor::visitMain()
 │    ├── MitlToNNFVisitor::visitMain()
 │    ├── 重新 parse NNF 公式
 │    ├── MitlAtomNumberingVisitor::visitMain()
 │    ├── MitlCollectTemporalVisitor::visitMain()
 │    ├── bdd_setvarnum()
 │    ├── MitlGetBDDVisitor::visitMain()
 │    ├── 构造 TA_0
 │    ├── TAwithBDDEdges::time_divergence_ta() -> TA_div
 │    ├── for each temporal atom:
 │    │    └── build_ta_from_atom()
 │    │         ├── build_finally()/build_once()/...
 │    │         ├── build_pnuelifn()/...
 │    │         └── build_countfn()/...
 │    ├── 构造默认模型 M
 │    └── TAwithBDDEdges::intersection()
 │         └── projection()
 ├── 无 out_file:
 │    ├── Fixpoint::reach() for --fin
 │    └── Fixpoint::buchi_accept_fixpoint() for --inf
 └── 有 out_file:
      ├── 写 TChecker .tck
      └── 写 Uppaal .xml + .q/.ltl
```

包含和编译关系：

```text
CMakeLists.txt
 ├── antlr_target(MitlGrammar Mitl.g4 VISITOR PACKAGE mightypplcpp)
 ├── add_subdirectory(external/buddy)
 ├── ExternalProject_add(monitaal)
 └── add_executable(mitppl
      main.cpp, MightyPPL.cpp, TAwithBDDEdges.cpp,
      Mitl*Visitor.cpp, Finally/Once/.../Count*.cpp,
      ${ANTLR_MitlGrammar_CXX_OUTPUTS})
```

## 8. 数据流与工作流

```text
Step 1: 输入阶段
- 输入是什么：一个 `.mitl` 或任意文本公式文件，以及命令行参数。
- 由哪个文件/函数读取：`main.cpp::main()` 用 `std::ifstream` 读取。
- 形成什么数据结构：`std::string nnf_in` 初始保存原公式文本。

Step 2: 解析阶段
- 做了什么：ANTLR 将文本转为 `MitlParser::MainContext` parse tree。
- 调用了哪些函数：`ANTLRInputStream`、`MitlLexer`、`CommonTokenStream`、`MitlParser::main()`。

Step 3: 规范化阶段
- 做了什么：标注 temporal 类型，检查 NNF，生成 NNF 字符串，重新 parse。
- 调用了哪些函数：`MitlTypingVisitor`、`MitlCheckNNFVisitor`、`MitlToNNFVisitor`。

Step 4: 编码阶段
- 做了什么：为命题和 temporal bits 编号，收集 temporal atoms，生成 BDD 标签。
- 关键数据结构是什么：`props`、`temporals`、`repeats`、`AtomContext::id/type/overline/star/tilde/hat`。

Step 5: 自动机构造阶段
- 核心算法/逻辑是什么：为总公式建 `TA_0`，为时间发散建 `TA_div`，为每个 temporal 子公式建 tester TA，再加模型 `M`。
- 关键数据结构是什么：`TAwithBDDEdges`、`bdd_edge_t`、`location_t`、`constraint_t`。

Step 6: 同步或输出阶段
- 做了什么：若需要 flatten/内置判空，构造前向可达同步乘积；否则写 component automata。
- 调用了哪些函数：`TAwithBDDEdges::intersection()`、`projection()`、输出 helper。

Step 7: 判空/验证阶段
- 输出是什么：SAT/UNSAT 控制台结果，或 `.tck`/`.xml`/`.q`/`.ltl` 文件。
- 写到哪里：`out_file` 指定路径；查询文件追加 `.q` 或 `.ltl`。
- 由哪个函数完成：`main()` 完成最终后端调用或文件写入。
```

形式化验证语义补充：

* 被监控/验证对象：一个 timed word 或与公式同步的模型 `M`。当前 `M` 在 `build_ta_from_main()` 中默认硬编码为单状态自循环真模型。
* 被验证性质：输入 MITPPL/MITL 公式是否存在 finite/infinite timed word 满足；输出到外部工具时可进一步做模型检查。
* trace/event 如何生成：MightyPPL 不直接生成 concrete trace；它用 BDD label 抽象事件字母，用 TA 接受语言表示所有满足公式的 timed words。
* monitor 如何消费 trace：项目依赖 MoniTAal TA/DBM 后端做符号可达和 Büchi 判空，不是在线逐事件 monitor。
* verdict 如何产生：内置模式下，初始 symbolic state 是否包含于可接受 fixpoint；包含则打印 SAT，否则打印 NOT SAT。
* fuzzing 连接：当前 MightyPPL 目录未发现 fuzzing harness。若工作区有 fuzzing 与 MoniTAal 连接逻辑，需要分析 MightyPPL 外部目录。

## 9. 关键数据结构和状态变量

| 名称 | 类型 | 定义位置 | 含义 | 生命周期 | 被谁读写 |
| -- | -- | ---- | -- | ---- | ---- |
| `spec_file` | `const char*` | `main.cpp` | 输入公式文件路径 | 进程全局 | `main()` 写 |
| `out_file` | `const char*` | `main.cpp`/`MightyPPL.h` | 输出模型文件路径 | 进程全局 | `main()` 写，输出逻辑读 |
| `out_format` | `optional<bool>` | `main.cpp`/`MightyPPL.h` | `true=tck`, `false=xml`, 空=内置判空 | 进程全局 | 多模块读 |
| `out_flatten` | `bool` | `main.cpp` | 是否输出/使用单体乘积 TA | 进程全局 | 构造器读 |
| `comp_flatten` | `bool` | `main.cpp` | 是否每个 temporal 组件内部压平 | 进程全局 | Pnueli/Count/BDD visitor 读 |
| `out_fin` | `bool` | `main.cpp` | finite/infinite timed word 接受语义 | 进程全局 | 构造器、product、fixpoint 读 |
| `debug` | `bool` | `main.cpp` | 是否暂停显示中间信息 | 进程全局 | `build_ta_from_main()` 读 |
| `back` | `bool` | `main.cpp`/`TAwithBDDEdges.h` | 是否做 backward 简化 | 进程全局 | product 读写 |
| `gcd` | `int` | `MightyPPL.cpp` | 公式时间常数最大公约数 | 单次构造 | `build_ta_from_main()` 写，`TA_div/product` 读 |
| `num_all_props` | `size_t` | `MightyPPL.cpp` | BDD 变量总数，不含变量 0 | 单次构造 | numbering 写，BDD/output 读 |
| `components_counter` | `size_t` | `MightyPPL.cpp` | 输出 component 同步轮转编号 | 单次构造 | `build_ta_from_main()` 和构造器读写 |
| `props_to_keep` | `set<int>` | `MightyPPL.cpp` | 最终保留的 proposition/temporal bits | 单次构造 | BDD visitor 写，projection/output 读 |
| `sat_paths` | `vector<string>` | `MightyPPL.cpp` | `bdd_allsat` 展开的赋值模式 | 临时 | 输出 helper 写后清空 |
| `varphi` | `TAwithBDDEdges` | `main.cpp` | 总公式 tester `TA_0` | 单次构造 | `build_ta_from_main()` 写 |
| `div` | `TAwithBDDEdges` | `main.cpp` | 时间发散自动机 `TA_div` | 单次构造 | `build_ta_from_main()` 写 |
| `temporal_components` | `vector<TAwithBDDEdges>` | `main.cpp` | 每个 temporal 子公式 tester | 单次构造 | `build_ta_from_main()` 写 |
| `model` | `TAwithBDDEdges` | `main.cpp` | 硬编码模型 `M` | 单次构造 | `build_ta_from_main()` 写 |
| `AtomContext::id/type/weak/top/existential` | ANTLR context locals | `Mitl.g4` | temporal atom 的编号和构造属性 | parse tree 生命周期 | visitors 写，构造器读 |
| `AtomContext::overline/star/tilde/hat` | `bdd` | `Mitl.g4` | 公式事件语义标签 | BDD 生命周期 | `MitlGetBDDVisitor` 写，构造器读 |
| `bdd_edge_t` | struct/class | `TAwithBDDEdges.h` | MoniTAal edge + BDD label | TA 生命周期 | 构造器创建，product 读取 |

## 10. 项目的整体架构总结

MightyPPL 属于 C++ 命令行批处理程序、编译/翻译工具链、运行时监控器生成器、定时自动机模型检查前端的混合体。它不是 Web 服务，也不是交互式仿真器；主要输入是公式文件，主要输出是自动机模型或 SAT/UNSAT 判空结果。

架构上可以分成四层：

* 前端层：ANTLR grammar 和 visitor，把文本公式变成规范化 parse tree。
* 语义编码层：为 propositions/temporal obligations 分配 BDD bit，并计算 BDD 标签。
* 自动机构造层：每个 temporal 模态对应一个或多个 tester TA；复杂模态使用序列化组件。
* 后端层：输出 TChecker/Uppaal，或用 MoniTAal/PARDIBAAL 做符号 reachability/Büchi fixpoint。

该项目有明显的流水线结构，也有状态机系统特征：每个 `build_*` 函数都手工构造一个带 locations、guards、resets、accepting states 的 tester 自动机。同步机制由 `turn` 变量和 `event:a` 输出约束，以及内存中的 `TAwithBDDEdges::intersection()` 实现。

## 11. 初学者理解路线

1. 先看 `README.md`：先理解 MightyPPL 做的是 MITPPL/MITL 到 TA 的转换，以及 `--fin/--inf`、`--tck/--xml`、flatten 模式。
2. 再看 `Mitl.g4`：掌握输入公式语法，尤其 temporal atom 的名称、interval 写法和 `Star` 弱语义。
3. 然后看 `main.cpp::main()`：理解命令行参数、ANTLR parse、输出/判空分支。
4. 接着看 `MightyPPL.cpp::build_ta_from_main()`：这是全局工作流地图，不必先纠结每条边。
5. 再看 visitor：按 `Typing -> CheckNNF -> ToNNF -> AtomNumbering -> CollectTemporal -> GetBDD` 的顺序读。
6. 之后看 `Finally.cpp` 或 `Globally.cpp`：先从一元简单模态理解 tester TA 的状态/边/BDD label。
7. 再看 `Until.cpp`/`Release.cpp`：理解二元时序模态。
8. 最后看 `PnueliFn.cpp` 和 `CountFn.cpp`：它们最复杂，适合在理解 BDD 编码和 `build_edge()` 后阅读。
9. 读 `TAwithBDDEdges.cpp`：理解 flattened product、BDD 同步和 projection。

## 12. 潜在问题、风险与改进建议

1. 参数解析脆弱：`main.cpp` 手写分支多，选项顺序固定，建议改为 `CLI11`、`cxxopts` 或至少表驱动解析。
2. `build_ta_from_main()` 过长：混合预处理、输出声明、TA 构造、product、日志，建议拆成 `parse_and_normalize()`、`build_components()`、`emit_model()`、`run_fixpoint()`。
3. 大量 `assert()` 用作用户输入错误处理：release 编译可能失效，debug 编译会直接 abort；建议替换为异常和带位置的诊断。
4. 错误信息缺少源码位置：NNF 通过字符串重写再 parse，ANTLR token 位置信息没有用于错误报告。
5. `MitlFormulaVisitor` 基本是返回 `"Test"` 的占位实现，却仍参与编译，容易误导读者。
6. 历史文件 `MightyPPL_new_*.cpp` 和 `*.patch` 混在源码根目录，容易让维护者误判当前构建入口；建议移入 `archive/` 或删减。
7. 全局变量较多：`gcd`、`components_counter`、`props_to_keep`、`single` 等跨文件共享，扩展多线程或多公式批处理会困难。
8. 输出逻辑重复：TChecker/XML 的 BDD 展开、guard/assignment 字符串拼接在多个函数重复，建议抽象 `Emitter`。
9. Product 构造可能状态爆炸：虽然后向可达和 BDD 剪枝能缓解，但 outgoing edge 组合枚举仍可能成为瓶颈。
10. 日志过多：`TAwithBDDEdges::intersection()` 对 location/edge 都 `std::cout`，大 benchmark 可能拖慢并污染输出；建议增加 verbosity 级别。
11. `M` 当前是硬编码单状态真模型：README 也说模型检查需要编辑生成文件或硬编码 `MightyPPL.cpp`，建议提供模型输入接口。
12. 当前 MightyPPL 目录未发现 fuzzing 链接逻辑：若要把 fuzzing 产生的 trace 接入 monitor，需要另建 trace parser/online monitor 或调用 MoniTAal monitor API。

扩展建议：

* 新增语法：先改 `Mitl.g4`，再补 visitor 标注、NNF 改写、编号、BDD 生成和 `build_ta_from_atom()` 分派。
* 新增输出格式：优先抽象 `build_edge()` 中 TChecker/XML emitter，再添加新 emitter。
* 新增模型输入：从 `build_ta_from_main()` 中抽出 `build_default_model()`，替换为 parser/loader。
* 调试某个公式错误：开启 `--debug`，观察 NNF、编号、temporal atoms、BDD 和每个 component 的状态/边数。

## 13. 最终总结

* MightyPPL 的核心是把 MITPPL/MITL 公式翻译为定时自动机，而不是直接解释执行公式。
* `main.cpp` 是入口，`build_ta_from_main()` 是全项目最重要的主流程。
* `Mitl.g4` 不只是语法，还通过 ANTLR locals 给 parse tree 节点挂载语义字段。
* visitor 管线负责从“文本公式”过渡到“带类型、编号和 BDD 标签的公式树”。
* 每个 temporal 子公式都会被转换成一个或多个 tester TA。
* BDD 表示事件字母上的布尔条件，`TAwithBDDEdges` 把这些条件保留到同步乘积阶段。
* `TA_0` 检查总公式，`TA_div` 强制时间发散，`M` 是当前硬编码模型。
* flattened 模式会做前向可达同步乘积，并投影掉内部 temporal bits。
* 无输出文件时，MoniTAal fixpoint 直接给出 finite/infinite timed word 上的 SAT/UNSAT。
* 代码的主要维护风险来自超长函数、全局状态、assert 式错误处理和重复输出逻辑。

