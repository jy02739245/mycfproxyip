# mycfproxyip

批量收集 ProxyIP 候选并检测可用性，两个彼此独立的源、各自独立产出：

| 源 | 配置 | 产出 |
| --- | --- | --- |
| 域名（CF-Workers-CheckProxyIP `/resolve-batch`） | `domains.txt` | `proxyip.txt` |
| TXT 链接（纯文本列表） | `links.txt` | `proxyip2.txt` |

两条流水线互不影响：一个源失败不会阻断另一个，产物分别提交。

## 文件

| 文件 | 说明 |
| --- | --- |
| `domains.txt` | 域名清单，一行一个，支持 `#` 注释、`域名:端口` |
| `links.txt` | TXT 链接清单，一行一个 URL，支持 `#` 注释 |
| `proxyip_pipeline.py` | 主流程，`--source domains` 或 `--source links` |
| `proxyip.txt` | 域名源产物，每行一条可用 `ip:port` |
| `proxyip2.txt` | 链接源产物，每行一条可用 `ip:port` |
| `.github/workflows/proxyip.yml` | 每日定时任务 |

## 本地运行

```bash
python3 proxyip_pipeline.py                    # 域名源 -> proxyip.txt
python3 proxyip_pipeline.py --source links     # 链接源 -> proxyip2.txt

python3 proxyip_pipeline.py --domains a.com,b.com
python3 proxyip_pipeline.py --source links --links https://x.com/all.txt
python3 proxyip_pipeline.py --rounds 3 --min-ratio 0.66
python3 proxyip_pipeline.py --no-unique-ip     # 同一 IP 保留多个端口
```

输出文件名按源自动决定（也可用 `--out` 覆盖），明细写到同名 `*_detail.json`。

## 参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--source` | `domains` | `domains` 走域名解析，`links` 走 TXT 链接 |
| `--domain-file` | `domains.txt` | 域名清单 |
| `--domains` | — | 逗号分隔的域名，指定后忽略清单文件 |
| `--links-file` | `links.txt` | TXT 链接清单 |
| `--links` | — | 逗号分隔的链接，指定后忽略清单文件 |
| `--base` | `https://check.iori3.pp.ua` | 检测服务地址，可用 `CHECK_BASE` 覆盖 |
| `--rounds` | 2 | 检测轮次 |
| `--min-ratio` | 0.5 | 判为可用的最低成功率 |
| `--chunk` | 20 | 单次 `/check` 提交数，上限约 25 |
| `--dedupe-before` | 开启 | 检测前按 IP 去重，同 IP 只留优先级最高的端口 |
| `--port-preference` | `443,2053,2083,2087,2096,8443` | 同 IP 多端口时的保留顺序 |
| `--unique-ip` | 开启 | 检测后按 IP 去重，保证每个 IP 只出现一次 |
| `--max-candidates` | 0 | 候选数量上限，0 为不限制 |
| `--min-usable` | 0 | 可用数低于该值则不覆盖输出，退出码 3（CI 防抖） |
| `--out` / `--detail` | 按源自动 | 输出文件与明细文件 |

## 去重规则

1. **规范化去重**：`1.2.3.4` 与 `1.2.3.4:443`、`2001:db8::1` 与 `[2001:db8::1]:443`、大小写不同的域名视为同一条
2. **按 IP 预去重**（`--dedupe-before`）：同一 IP 的多个端口只保留优先级最高的一个，检测前就砍掉，省时间
3. **按 IP 后去重**（`--unique-ip`）：检测后再兜一次，输出文件里每个 IP 只出现一次

端口不同视为不同服务。若某 IP 的 443 不可用而 8443 可用，预去重会先保留 443；要覆盖这种情况用 `--no-dedupe-before`，让所有端口都参与检测。

## 定时任务

- 每天 UTC 00:17（北京时间 08:17）运行两个步骤：域名源、链接源
- 任一步骤失败不阻断另一步骤；两个都失败时任务标记为失败
- 产物有变化才提交，提交信息带两份文件各自的条数
- 运行日志在 Actions 运行详情页查看，不落盘
- `proxyip_detail.json` / `proxyip2_detail.json` 作为 artifact 保留 7 天，不进仓库
- 全量跑约 15–20 分钟（域名 ~450 + 链接 ~660 候选，各 2 轮），任务超时设为 45 分钟

## 判定说明

`/check` 对每个候选执行：TCP 连接 → 用 `ipv4.090227.xyz` / `ipv6.090227.xyz` 作 SNI 做 TLS 握手（校验证书）→ 请求探针取出口 IP。`success: true` 表示该 `ip:port` 能作为 TLS 反代入口且能出网。
