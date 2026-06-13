# free-pool-finder

`free-pool-finder` 用 GitHub Actions 每周日 12:00（北京时间，Asia/Shanghai）从 GitHub 发现「免费节点池 / 机场订阅源」候选仓库，生成候选周报，并通过 Vercel 托管成静态网页，帮助给 OpenClash/mihomo 的多源免费池补充新订阅源。

## 做什么

- 每周日 12:00 北京时间自动搜索 GitHub 仓库。
- 按最近 push 时间过滤死仓库。
- 在候选仓库里寻找像订阅文件的 `txt/yaml/yml` 路径。
- 读取每个候选文件前 3MB，识别 `base64`、`plain`、`clash` 三类可用订阅格式。
- 丢弃 `singbox`、`http/socks` 列表和无法识别的文件。
- 用 `known_sources.json` 做台账，新增源标记为 `candidate`。
- 把周报提交到 `reports/{date}.md` 和 `reports/latest.md`。
- 同步生成 `reports/{date}.json`、`reports/latest.json` 和 `reports/index.json`，供 Vercel 页面展示。

## 不做什么

这个项目不做节点存活检测，也不在 GitHub Actions 里做 alive/health-check。

原因很直接：OpenClash/mihomo 的实际用途是中国大陆出口环境；GitHub Actions 跑在海外，测出来只是「海外可达性」，对国内路由器使用没有判断价值。周报只提供候选短名单，最终是否可用需要你在路由器面板里手动验证。

## 一次性设置

1. 新建 GitHub 仓库 `free-pool-finder`。
2. 把本项目文件推到仓库默认分支。
3. 进入仓库的 **Actions** 页面，确认 workflow 已启用。
4. 不需要手动配置密钥；workflow 使用 GitHub Actions 内置的 `GITHUB_TOKEN`。
5. 在 Vercel 里导入这个 GitHub 仓库：
   - Framework Preset 选择 `Other`。
   - Build Command 留空。
   - Output Directory 留空或使用默认值。
   - Root Directory 保持仓库根目录。
6. 首次部署后，Vercel 会给出类似 `https://free-pool-finder.vercel.app/` 的地址。实际地址以 Vercel 项目页面显示为准。
7. 如需调整搜索范围，编辑 `config.yaml`：
   - `keywords`：GitHub 搜索关键词。
   - `days_active`：只保留最近 N 天有 push 的仓库。
   - `per_page`：每个关键词读取的搜索结果数。
   - `max_repos`：去重排序后最多扫描的仓库数。
   - `min_nodes`：订阅文件最少节点数。
   - `mirror`：输出订阅 URL 的 jsdelivr 镜像模板。

## 周报怎么看

每次运行后查看：

- Vercel 首页：展示最新周报、在用源体检和历史归档。
- `reports/latest.md`：最新周报。
- `reports/{date}.md`：历史周报。

「🆕 本周新候选」表里的 `订阅URL(jsdelivr)` 可以直接复制到 OpenClash/mihomo 的多源订阅配置中试用。

「📉 在用源体检」只检查对应 GitHub 仓库是否久未更新。它不是节点存活结果；如果一个在用源超过 10 天没更新，只表示需要留意替补。

## 手动验证后的台账维护

验证候选源后，手动编辑 `known_sources.json`：

- 可用：把该仓库的 `status` 改为 `in-use`。
- 不可用：把 `status` 改为 `rejected`，并加上 `note` 记录原因。
- 继续观察：保持 `candidate`。

台账以 `owner/repo` 为键。脚本重新发现已知仓库时只更新 `last_seen` 和仓库元数据，不会自动改变你手动维护的 `status`。

## 本地运行

```bash
python -m pip install requests pyyaml
GITHUB_TOKEN=你的_token python finder.py
```

本地运行时 `GITHUB_TOKEN` 可选，但没有 token 更容易触发 GitHub API 限速。GitHub Actions 中不需要额外配置。
