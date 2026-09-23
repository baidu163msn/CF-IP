# CF-IP 优化版

一个基于 Cloudflare IP 源、历史节点池和 TLS/WS 健康检查的 VLESS/Mihomo 节点生成项目。

<!-- CF-IP-STATS:START -->

## 📊 当前节点统计

> 本区域由 GitHub Actions 自动更新。
> 仅当统计数据发生变化时，README 的统计内容才会变化。

### 🌍 地区节点

| 地区 | VLESS TXT | Mihomo YAML |
|:---|---:|---:|
| 🇭🇰 香港 HK | 10 | 10 |
| 🇯🇵 日本 JP | 4 | 4 |
| 🇸🇬 新加坡 SG | 10 | 10 |
| 🇰🇷 韩国 KR | 2 | 2 |
| 🇹🇼 台湾 TW | 1 | 1 |
| 🇺🇸 美国 US | 10 | 10 |
| 🌐 其他 OTHER | 10 | 10 |

### 📡 运营商节点

| 运营商 | VLESS TXT | Mihomo YAML |
|:---|---:|---:|
| 📱 中国移动 CMCC | 10 | 10 |
| 🔗 中国联通 CU | 10 | 10 |
| ☎️ 中国电信 CT | 10 | 10 |

### 📦 总计

- **VLESS：51 个节点**
- **Mihomo：51 个节点**
- **历史 IP 池：200 / 200**
- **DE / CN：排除，不占用节点池名额**

<!-- CF-IP-STATS:END -->

## ⚙️ 核心逻辑

- 历史 IP 池上限：**200**
- 连续 **3 次**健康检查失败后淘汰。
- 当前源中的节点优先于历史备用节点。
- 节点选择顺序：**新鲜度 → 健康度 → TCP/TLS 延迟**。
- HK / JP / SG / KR / TW / US 在历史池满时各保留最低备用库存。
- DE / CN 节点直接排除，不进入当前候选池，也不进入历史池。
- 支持地区别名，例如 `HKG → HK`、`LAX → US`、`SIN → SG`、`NRT/HND/TYO → JP`。
- 每个地区默认最多输出 10 个节点。
- 同时生成 VLESS Base64 订阅和 Mihomo YAML。

## 📁 主要文件

- `src/generator.py`：节点抓取、地区识别、健康检查、历史池和订阅生成。
- `config/config.yml`：数据源、VLESS 模板、测速参数、历史池和输出配置。
- `.github/workflows/generate.yml`：每小时第 24 分钟尝试运行，并部署 GitHub Pages。
- `data/ip_history.json`：历史健康节点池。
- `output/`：生成的 VLESS/Mihomo 订阅文件。

## ⏱️ GitHub Actions

当前计划任务：

```yaml
schedule:
  - cron: '24 * * * *'
```

这是 GitHub Actions 的 UTC 定时任务。GitHub 的 schedule 属于尽力调度，并不保证精确到分钟；如需更强的定时可靠性，可以继续使用 cron-job.org 触发 `workflow_dispatch`。

## 🌐 GitHub Pages

每次成功运行后会部署：

- `all.txt`：全部 VLESS 节点
- `all.yaml`：全部 Mihomo 节点
- 各地区 `.txt` / `.yaml`
- 各运营商 `.txt` / `.yaml`（只有识别到对应运营商节点时才会有实际节点）

> 运营商分类目前依据源数据中的运营商标签（如 CMCC、CU、CT、中国移动、中国联通、中国电信）识别；如果上游数据没有运营商信息，则节点会归入 `OTHER`，不会凭 IP 猜测运营商。
