# 签名/路径白名单与注入细粒度分类

本扩展在不改变 HollowsHunter 既有扫描引擎（PE-sieve）和既有输出字段的前提下，新增三层能力：

1. **按模块签名与加载路径的白名单**，用于消除安全软件（AV/EDR）造成的误报；
2. **注入类型的细粒度分类**，把笼统的 "suspicious" 拆成 8 类可解释结论；
3. **完全向后兼容的输出**：原有文本/JSON 字段保持不变，新信息只以追加块的形式出现。

## 1. 命令行用法

```
hollows_hunter.exe /wlist <whitelist-file> [/json]
```

- `/wlist` 指向一个 UTF-8 文本规则文件（示例见 `whitelist/hollows_hunter.wlist.example`）。
- 不带 `/wlist` 时行为与原版完全一致：不做任何抑制，只保留原有报告。
- 该能力在标准扫描与 `/etw` 监听两种模式下都生效（两者都经由同一个 `HHScanner::scan()` 流程）。

## 2. 规则文件语法

`#` 开头为注释，匹配大小写不敏感。支持三种匹配指令：

| 指令 | 含义 |
| --- | --- |
| `signer:<子串>` | 匹配 Authenticode 证书主题（CN）子串 |
| `path:<前缀或通配符>` | 匹配模块在磁盘上的加载路径（`*`/`?` 通配，或目录前缀） |
| `name:<文件名>` | 仅匹配模块文件名 |

可选的作用域前缀：

| 前缀 | 含义 |
| --- | --- |
| `sig:` | 仅当模块签名验证为**有效可信**时规则才生效 |
| `nosig:` | 仅当模块未签名/签名不可信时生效 |
| `strict:` | 任何情况下都要求签名有效（最严格） |

示例：

```
signer:Microsoft Corporation
sig:path:C:\Program Files\TrustedAV
strict:path:C:\Windows\System32\drivers
nosig:name:legacy_avhelper.dll
```

## 3. 细粒度注入分类与判定依据

分类完全由 PE-sieve 已产出的模块级指示符推导，不新增任何有风险的内存启发式。多指示符并存时按**危险程度从高到低**取第一个匹配类型。

| 类型 | 判定依据（PE-sieve 字段） | 可否白名单 |
| --- | --- | --- |
| `hollowing` | `headers_scan.is_pe_replaced=1`：内存映像节区头与磁盘文件不同，原 PE 被替换 | 否 |
| `implanted_pe` | artefact/workingset 报告私有内存中存在完整 PE，且不在加载器模块表（手动映射/反射加载） | 否 |
| `thread_shellcode` | `thread_scan` 可疑：线程调用栈进入不属于任何模块的可执行内存 | 否 |
| `shellcode` | `workingset_scan` 可疑：无私属模块的可执行私有内存，命中 shellcode 模式/熵特征 | 否 |
| `header_modified` | `headers_scan` 报告 DOS/NT/文件/可选头/EP 被改，但 `is_pe_replaced=0` | 是 |
| `iat_hook` | `iat_scan` 可疑：IAT 表项指向预期模块范围之外 | 是 |
| `code_patch` | `code_scan` 可疑：模块内存字节与磁盘映像不一致（内联 hook/补丁） | 是 |
| `unreachable_file` | `unreachable_scan`：模块后备文件无法打开/读取，无法与原始映像比对 | 是 |

### 为什么这样划分能保证零漏报

- 前四类是**高置信注入技术**（hollowing、手动映射 PE、两类 shellcode），在 `isWhitelistable()` 中被硬编码为**永不抑制**。即使恶意样本伪造了受信厂商的路径和签名，也仍然报警（验收语料中的两个对抗样本专门覆盖这一点）。
- 后四类是 AV/EDR 产品正常运行时最常见的低置信指示符（用户态 hook、IAT 埋点、自保护锁文件、头部触碰），只有它们允许被白名单解释。
- 签名作用域 `sig:`/`strict:` 进一步保证：未签名或签名失效的模块不会因路径相同而被放行。

## 4. 输出兼容性

- **文本输出**：原有 `>> Detected: <pid>`、SUMMARY 段落完全不变；白名单审计以附加行打印。
- **JSON 输出**：顶层所有既有字段（`scan_date_time`、`scanned_count`、`suspicious_count`、`suspicious[]` 及其内部 `replaced`/`hdr_modified`/`patched`/...）一字不动。新增一个独立的 `whitelist_audit` 数组，旧解析器会直接忽略它。
- 当某进程的全部指示符都被白名单解释后，该 PID 从可操作的 `suspicious` 列表移除（同时保留在审计块中可追溯）；原始 pe-sieve 计数字段不被改写。

审计块每个发现包含：`inject_type`、`inject_type_id`、`whitelistable`、`signature`、`signer`、`whitelist_decision`、`matched_rule`、`suppressed`、`rationale`。

## 5. 平台隔离与可测试性

- `whitelist/` 下的分类器、规则引擎、JSON 解析器、报告适配器、输出器均为**平台无关的纯 C++17**，可直接在 Linux/macOS 用原生工具链测试。
- 唯一的平台相关代码是 `whitelist/hh_signature_win.cpp`，通过 `WinVerifyTrust` + `CryptQueryObject` 做 Authenticode 校验并读取签名者；它实现 `SignatureVerifier` 抽象接口，测试时用 `FakeSignatureVerifier` 替代。

## 6. 验收方法与结果

```
./whitelist/tests/run_tests.sh
```

该脚本编译并运行：

- `unit_tests`：50 项断言，覆盖 JSON 解析、8 类分类优先级、路径归一化/通配、规则作用域、安全边界、端到端流水线；
- `acceptance`：**100 个样本**的确定性语料（60 个良性安全软件场景 + 40 个真实注入，含 2 个伪造受信路径/签名的对抗样本）。

验收指标（最新一次运行）：

| 指标 | 结果 |
| --- | --- |
| 良性样本误报率（白名单前） | 100.0%（60/60） |
| 良性样本误报率（白名单后） | 0.0%（0/60） |
| 误报相对下降 | 100%（-100 个百分点） |
| 真实注入检出率（召回） | 100.0%（40/40） |
| 真实注入漏报数 | 0 |

在真实主机上接入 `WinSignatureVerifier` 后，分类与决策逻辑与该语料完全相同；差异只在于签名状态由系统 API 而非假验证器提供。
