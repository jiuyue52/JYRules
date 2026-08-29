# JYRules

JYRules 是一个纯 Mihomo 规则仓库。每个 `tasks/*.toml` 文件定义一个合并任务：下载或读取多个规则源，按语义归一化、合并和去重，再应用排除集并生成明文规则与 MRS。

仓库不保存策略组、路由顺序或 Mihomo 主配置。如何使用主规则和 `NO_` 规则由使用者在自己的 Mihomo 配置中决定。

## 目录与产物

```text
tasks/                         任务定义，自动扫描直接位于此目录的 *.toml
scripts/                       构建器
tests/                         单元测试
rules/domain/<output>.mrs      Domain 主规则 MRS
rules/domain/<output>.txt      Domain 主规则明文
rules/domain/NO_<output>.mrs   Domain 完整排除集 MRS（E 非空时）
rules/domain/NO_<output>.txt   Domain 完整排除集明文
rules/ip/<output>.mrs          IP CIDR 主规则 MRS
rules/ip/<output>.txt          IP CIDR 主规则明文
rules/ip/NO_<output>.mrs       IP CIDR 完整排除集 MRS（E 非空时）
rules/ip/NO_<output>.txt       IP CIDR 完整排除集明文
reports/conversion-report.json 本次构建的统计、丢弃项、集合操作和文件校验和
```

`rules/` 和 `reports/` 都是生成目录。工作流先在临时目录完成全部构建和 MRS 回读校验，成功后才整体替换它们，因此删除任务时不会遗留过期产物。

`domain` 任务固定写入 `rules/domain/`；`ipcidr` 任务及其 `ip` 别名固定写入 `rules/ip/`。主文件与对应的 `NO_<output>` 始终位于同一分类目录。没有产物的分类目录不会创建；旧版 `rules/<output>.*` 扁平路径也不会保留兼容副本。首次使用新布局成功构建后，请同步修改 Mihomo 配置中的规则 URL。

## 集合语义

对每个任务：

- **S**：所有 `[[sources]]` 中可接受规则的语义归一化并集。
- **E**：所有 `[[exclude]]` 中可接受规则的语义归一化并集。
- **主文件**：构建器能准确表达的 `S - E`。
- **NO 文件**：完整的 E，固定命名为 `NO_<output>`；它不是 `S ∩ E`。

IP CIDR 可以拆分为精确的差集，因此 `ipcidr` 任务不会产生无法表达的局部重叠。Domain 任务使用三种原子：精确域名 `example.com`、包含根域的后缀 `+.example.com`、仅子域 `.example.com`。构建器会执行以下处理：

- 被 E 完整覆盖的 S 原子从主集删除。
- `+.example.com - example.com` 可精确转换为 `.example.com`。
- `+.example.com - .example.com` 可精确转换为 `example.com`。
- 其他无法用有限上述原子表达的局部孔洞会保留原 S 原子，并在报告的 `partial_overlap_retained` 中列出，不会导致构建失败。

例如 S 含 `+.example.com`，E 含 `ads.example.com`，单个 domain MRS 无法表达“整个后缀减去一个子域”。主文件会保留 `+.example.com`，`NO_<output>` 保存完整 E。若要在路由中实现排除效果，应在 Mihomo 主配置里先匹配 `NO_<output>`，再匹配主文件。

## 任务格式

任务是 TOML 文件，文件名是报告中的任务名。顶层仅允许以下字段：

| 字段 | 必填 | 含义 |
| --- | --- | --- |
| `version` | 是 | 必须是整数 `1`。 |
| `enabled` | 否 | 默认 `true`。`false` 保留定义但不生成产物。 |
| `behavior` | 是 | `domain` 或 `ipcidr`；`ip` 是 `ipcidr` 的别名。前者输出到 `rules/domain/`，后两者输出到 `rules/ip/`。 |
| `output` | 是 | 安全的单个文件名 stem，不带路径、`.mrs` 或 `.txt`。 |
| `[[sources]]` | 是 | 至少一个合并源。 |
| `[[exclude]]` | 否 | 任意数量的排除源。 |

每个 `[[sources]]` 和 `[[exclude]]` 仅允许：

| 字段 | 必填 | 含义 |
| --- | --- | --- |
| `name` | 否 | 报告中使用的非空名称。 |
| `url` / `path` | 二选一 | `url` 必须是合法 HTTPS URL，且不能带用户信息、使用 `localhost` 或非公网 IP 字面量；域名不会预先做 DNS 公网性判定。`path` 必须是仓库内的相对路径且不能穿越目录。 |
| `format` | 否 | `auto` / `mrs` / `yaml` / `text` / `list`，默认 `auto`。 |
| `optional` | 否 | 默认 `false`。可选源下载、解析或“无有效规则”失败时会记录为 `skipped` 并继续。 |

字段名是严格的，出现未知字段会使构建失败。同一分类目录内的输出名称会按不区分大小写检查冲突，包括派生的 `NO_<output>`；`domain` 与 `ip` 分类可以使用相同的 `output`。

### 源格式

- `mrs`：MRS 内的 behavior 必须与任务一致。Domain MRS 由构建器无损读取其 DomainSet，能区分 `.example.com` 与 `+.example.com`；IP MRS 使用已校验的 Mihomo 二进制反向导出。
- `yaml`：接受顶层列表，或含 `payload` / `rules` 列表的映射。
- `text` / `list`：每行一条规则；空行以及 `#`、`//`、`;`、`!` 注释会被忽略。
- `auto`：按内容区分 MRS/结构化 YAML/普通文本，不仅依赖文件后缀。当远程后缀与内容不一致或来源容易变化时，建议显式填写 `format`。

Domain 任务接受原生精确域名、`+.` / `.` 原子，以及 classical 的 `DOMAIN` / `DOMAIN-SUFFIX`。IP 任务接受 CIDR，以及 classical 的 `IP-CIDR` / `IP-CIDR6`。`DOMAIN-KEYWORD`、复杂通配符、`IP-ASN`、`SRC-IP-CIDR`、进程和端口等不能无损放入 domain/ipcidr MRS，会在报告里按原因计数并保留少量样例。只要一个源仍有有效规则，单条不支持的规则不会导致整个源失败。

## 新增、停用和删除任务

1. 将 [`tasks/CN_Domain.toml.example`](tasks/CN_Domain.toml.example) 复制为 `tasks/CN_Domain.toml`。`.toml.example` 不会被扫描。
2. 设置 `behavior`、`output`、`[[sources]]` 和可选的 `[[exclude]]`。可以任意增删源，无需修改工作流。
3. 提交任务文件。推送到 `main` 后会自动测试和构建。

示例中的 `example.invalid` 是故意不可访问的占位域名，复制成正式 `.toml` 后必须替换为实际规则 URL。

临时停用时设置 `enabled = false`。彻底删除时直接删除对应 `.toml`；下次成功构建会自动删除它之前的主文件、`NO_` 文件和报告记录。

## 本地验证

需要 Python 3.11+ 和对应平台的 Mihomo `v1.19.30`。

```bash
python -m pip install --requirement requirements.txt
MIHOMO_BIN=/path/to/mihomo python -B -m unittest discover -s tests -v
python scripts/build_rules.py \
  --tasks tasks \
  --output-root /tmp/jyrules-build \
  --repo-root "$PWD" \
  --mihomo /path/to/mihomo \
  --mihomo-version v1.19.30
```

`--output-root` 必须位于仓库目录树之外。构建器会在首次创建的新目录中写入所有权标记；再次使用时只会清理带有有效标记的 staging 目录，拒绝已有的普通目录，因此不会误删其中同名的 `rules/` 或 `reports/`。MRS 生成后会立即反向导出并比较语义集合，回读不一致时整个构建失败。

## GitHub Actions

`.github/workflows/update-rules.yml` 会在以下时机运行：

- 每 6 小时的第 23 分钟；
- `main` 分支中除生成的 `rules/**`、`reports/**` 外任意文件发生变化；这也覆盖任务引用在任意仓库相对路径下的本地规则源；
- 在 Actions 页面手动运行。

工作流的只读构建任务会安装 `requirements.txt`，运行全部单元测试，下载并用 SHA256 校验固定的 Mihomo `v1.19.30`，再把 staging 产物作为短期 artifact 交给独立发布任务。只有发布任务拥有写权限，并且仅在 `main` 未于构建期间变化、生成内容确有变化时，才由 `github-actions[bot]` 提交并推送。

仓库初次使用时，还需在 **Settings → Actions → General → Workflow permissions** 中选择 **Read and write permissions**。工作流内已声明 `contents: write`，但仓库级权限仍必须允许写入。

## 报告与失败原则

`reports/conversion-report.json` 当前使用 schema version 2，记录 Mihomo 版本、任务数、每个任务的分类目录、每个源的最终 URL/检测格式/接受与拒绝计数、可选源跳过原因、S/E/主集规模、完全重复/父规则覆盖/语义合并统计、删除/转换/局部重叠样例，以及每个输出的完整相对路径和 SHA256。报告样例列表及每个样例内的替换项/重叠项都会截断到 100 条，并保留完整计数与截断标记。

以下情况会使整个构建失败，且不替换已发布产物：任务格式错误、必需源失败、所有主源都被跳过、排除后主集为空、输出名冲突、IP 精确差集膨胀到超过 100 万条生成规则、Mihomo 转换或回读校验失败。
