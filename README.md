# mycfproxyip

基于 [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP) 的接口，批量解析多个 ProxyIP 域名并检测可用性，每天自动刷新 `proxyip.txt`。

## 文件

| 文件 | 说明 |
| --- | --- |
| `domains.txt` | 域名清单，一行一个，支持 `#` 注释、`域名:端口` |
| `proxyip_pipeline.py` | 主流程：解析 → 去重 → 批量检测 → 过滤 → 写文件 |
| `proxyip.txt` | 产物，每行一条可用的 `ip:port` |
| `.github/workflows/proxyip.yml` | 每日定时任务 |

## 本地运行

```bash
python3 proxyip_pipeline.py                       # 读 domains.txt，默认 2 轮
python3 proxyip_pipeline.py --rounds 3 --min-ratio 0.66
python3 proxyip_pipeline.py --domains a.com,b.com --out my.txt
python3 proxyip_pipeline.py --no-unique-ip        # 允许同一 IP 保留多个端口
```

## 参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--base` | `https://check.iori3.pp.ua` | 检测服务地址，可用 `CHECK_BASE` 环境变量覆盖 |
| `--rounds` | 2 | 检测轮次 |
| `--min-ratio` | 0.5 | 判为可用的最低成功率 |
| `--chunk` | 20 | 单次 `/check` 提交数，上限约 25 |
| `--min-usable` | 0 | 可用数低于该值则不覆盖输出，退出码 3（CI 防抖） |
| `--unique-ip` | 开启 | 同一 IP 只保留成功率最高、延迟最低的端口，用 `--no-unique-ip` 关闭 |

## 定时任务

- 每天 UTC 00:17（北京时间 08:17）自动运行，产物变化才提交
- Actions 页面可手动 `Run workflow`，并覆盖轮次、成功率、去重开关
- 运行日志在 Actions 运行详情页查看，不落盘
- `proxyip_detail.json` 作为 artifact 保留 7 天，不提交进仓库

## 判定说明

`/check` 对每个候选执行：TCP 连接 → 用 `ipv4.090227.xyz` / `ipv6.090227.xyz` 作 SNI 做 TLS 握手（校验证书）→ 请求探针取出口 IP。`success: true` 表示该 `ip:port` 能作为 TLS 反代入口且能出网。
