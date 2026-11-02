#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProxyIP 批量流水线，两个彼此独立的源：

  域名源（--source domains，默认）
    1. 读 domains.txt / --domains
    2. POST /resolve-batch 解析（单次 <= 15 个域名，处理 TXT/A/AAAA 记录）
    3. 汇总 -> 规范化去重 -> 按 IP 预去重 -> /check 多轮检测 -> 按成功率过滤
    4. 写入 proxyip.txt

  TXT 链接源（--source links）
    1. 读 links.txt / --links
    2. 拉取每个链接的纯文本列表（ip:port / ip / [v6]:port，支持 # 后备注）
    3. 汇总 -> 规范化去重 -> 按 IP 预去重 -> /check 多轮检测 -> 按成功率过滤
    4. 写入 proxyip2.txt

用法:
  python3 proxyip_pipeline.py                      # 域名源 -> proxyip.txt
  python3 proxyip_pipeline.py --source links       # 链接源 -> proxyip2.txt
  python3 proxyip_pipeline.py --domains a.com,b.com --out x.txt
  python3 proxyip_pipeline.py --source links --links https://x.com/all.txt
  python3 proxyip_pipeline.py --rounds 3 --min-ratio 0.66
  python3 proxyip_pipeline.py --no-unique-ip       # 同一 IP 保留多端口
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

DEFAULT_BASE = "https://check.iori3.pp.ua"
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36")
RESOLVE_BATCH_LIMIT = 15   # Worker 端硬限制
CHECK_CHUNK = 20           # 每候选 2 个子请求，免费版 50 -> 建议 <= 25
SUBREQ_MARK = "Too many subrequests"
MAX_FETCH_BYTES = 8 * 1024 * 1024
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


# ---------------------------------------------------------------- HTTP helpers
def http_json(url, data=None, timeout=180):
    body = json.dumps(data).encode() if data is not None else None
    headers = {"User-Agent": UA}
    if body:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _fetch_with_curl(url, timeout):
    """优先用 curl：对 HTTP/2、压缩、IPv6 回退、TLS 指纹的兼容性比 urllib 好"""
    cmd = ["curl", "-fsSL", "--max-time", str(timeout), "--connect-timeout", "12",
           "--max-filesize", str(MAX_FETCH_BYTES), "-A", UA,
           "-H", "Accept: text/plain,*/*", url]
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise RuntimeError(f"curl 退出码 {proc.returncode}: {err[-1] if err else 'unknown'}")
    return proc.stdout


def _fetch_with_urllib(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/plain,*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(MAX_FETCH_BYTES)


def fetch_text(url, retries=3, timeout=30):
    """拉取纯文本列表，返回字符串。HTML 页面视为错误（通常是拦截页/404 页）。"""
    use_curl = shutil.which("curl") is not None
    last = None
    for attempt in range(1, retries + 1):
        try:
            raw = _fetch_with_curl(url, timeout) if use_curl else _fetch_with_urllib(url, timeout)
            text = raw.decode("utf-8", errors="replace").lstrip("\ufeff")
            head = text[:2000].lstrip().lower()
            if head.startswith(("<!doctype html", "<html")):
                raise ValueError("返回的是 HTML 而不是纯文本（可能是拦截页或 404 页）")
            return text
        except Exception as exc:
            last = exc
            print(f"  ! 拉取失败(第{attempt}次) {url}: {exc}", file=sys.stderr, flush=True)
            if attempt < retries:
                time.sleep(1.5 * attempt)
    raise RuntimeError(f"拉取失败: {url}: {last}")


def resolve_batch(base, domains, retries=3):
    """POST /resolve-batch，单次 <= 15 个域名；返回 {domain: [targets...]}"""
    out = {}
    for i in range(0, len(domains), RESOLVE_BATCH_LIMIT):
        chunk = domains[i:i + RESOLVE_BATCH_LIMIT]
        payload = None
        for attempt in range(1, retries + 1):
            try:
                payload = http_json(f"{base}/resolve-batch", {"targets": chunk})
                break
            except Exception as exc:
                print(f"  ! resolve-batch 失败(第{attempt}次): {exc}", file=sys.stderr)
                time.sleep(1.5 * attempt)
        if not payload:
            for d in chunk:
                out[d] = {"targets": [], "error": "request failed"}
            continue
        for item in payload.get("results", []):
            out[item.get("input")] = {
                "targets": item.get("targets") or [],
                "error": item.get("error"),
            }
        print(f"  resolve-batch {i + len(chunk)}/{len(domains)} 完成", flush=True)
        time.sleep(0.4)
    return out


def check_batch(base, candidates, timeout=180):
    """GET /check 批量检测；返回统一为 list"""
    url = f"{base}/check?proxyip={','.join(candidates)}"
    try:
        data = http_json(url, timeout=timeout)
    except Exception as exc:
        return [{"candidate": c, "success": False, "error": str(exc)} for c in candidates]
    return data if isinstance(data, list) else [data]


def probe_info(res):
    probe = res.get("probe_results") or {}
    errs = [str(v.get("error")) for v in probe.values() if not v.get("ok")]
    if res.get("success"):
        exit_info = (probe.get("ipv4") or {}).get("exit") or (probe.get("ipv6") or {}).get("exit") or {}
        return {
            "ok": True,
            "rt": res.get("responseTime"),
            "stack": res.get("inferred_stack"),
            "exit_ip": exit_info.get("ip"),
            "colo": exit_info.get("colo"),
            "country": exit_info.get("country"),
            "city": exit_info.get("city"),
            "org": exit_info.get("asOrganization") or exit_info.get("org"),
            "asn": exit_info.get("asn"),
        }
    sublimit = any(SUBREQ_MARK in e for e in errs)
    return {
        "ok": False,
        "sublimit": sublimit,
        "error": "SUBLIMIT" if sublimit else (errs[0] if errs else str(res.get("error"))),
    }


# ---------------------------------------------------------------- 去重 / 规范化
def canon_target(raw):
    """把候选规范化成 (去重键, 输出形式)。

    合并这些写法差异：
      1.2.3.4            == 1.2.3.4:443      （补默认端口）
      2001:db8::1        == [2001:db8::1]:443（裸 IPv6 补方括号）
      Host.Example.com   == host.example.com （主机名小写、去尾点）
      1.2.3.4:8443       != 1.2.3.4:443      （端口不同视为不同服务）
    """
    s = str(raw or "").strip().split("#")[0].strip()
    if not s:
        return None

    host, port = s, "443"
    if s.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", s)
        if not m:
            return None
        host, port = m.group(1), m.group(2) or "443"
    elif s.count(":") == 1:
        h, p = s.rsplit(":", 1)
        if p.isdigit():
            host, port = h, p
    elif s.count(":") > 1:          # 裸 IPv6，没写端口
        host, port = s, "443"

    host = host.lower().rstrip(".")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        return None

    try:
        ip = ipaddress.ip_address(host)
        key_host = ip.compressed
        out = f"[{key_host}]:{port}" if ip.version == 6 else f"{key_host}:{port}"
    except ValueError:
        key_host, out = host, f"{host}:{port}"
    return f"{key_host}|{port}", out


def is_valid_target(token):
    """过滤掉备注、协议链接、HTML 片段等噪声"""
    parsed = canon_target(token)
    if not parsed:
        return False
    host = parsed[0].split("|", 1)[0]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(DOMAIN_RE.match(host))


def parse_target_list(text):
    """解析 TXT 列表内容，返回 (候选列表, 跳过行数)。

    兼容：ip、ip:port、[v6]:port、逗号/分号/空格分隔、# 后备注、空行、注释行。
    vless:// 之类的订阅链接与无法识别的行计入跳过。
    """
    found, skipped = [], 0
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("//"):
            continue
        for token in re.split(r"[,;\s]+", line):
            token = token.strip().strip("\"'")
            if not token:
                continue
            if "://" in token or not is_valid_target(token):
                skipped += 1
                continue
            found.append(token)
    return found, skipped


def dedupe_targets(raw_targets):
    """按规范化键去重，保留首次出现的输出形式"""
    seen, out = set(), []
    for item in raw_targets:
        parsed = canon_target(item)
        if not parsed:
            continue
        key, candidate = parsed
        if key in seen:
            continue
        seen.add(key)
        out.append(candidate)
    return out


def ip_key(candidate):
    """取候选的 IP 部分（忽略端口）"""
    parsed = canon_target(candidate)
    return parsed[0].split("|", 1)[0] if parsed else str(candidate or "")


def port_rank(candidate, preferred_ports):
    parsed = canon_target(candidate)
    port = parsed[0].split("|", 1)[1] if parsed else ""
    return preferred_ports.index(port) if port in preferred_ports else len(preferred_ports)


def dedupe_by_ip(candidates, preferred_ports):
    """检测前按 IP 去重：同一 IP 的多个端口只保留优先级最高的一个。

    端口优先级由 --port-preference 决定（默认 443 优先），
    这样既省掉大量无用检测，又能保住最常见可用的 443。
    """
    groups, order = {}, []
    for cand in candidates:
        key = ip_key(cand)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(cand)

    out, dropped = [], 0
    for key in order:
        cands = groups[key]
        if len(cands) == 1:
            out.append(cands[0])
            continue
        dropped += len(cands) - 1
        best = min(cands, key=lambda x: (port_rank(x, preferred_ports), cands.index(x)))
        out.append(best)
    return out, dropped


def unique_by_ip(records):
    """检测后按 IP 去重（安全网），保留列表中靠前的一条。

    调用方需先把 records 按优先级排好（成功率高的在前、延迟低的在前）。
    """
    seen, out = set(), []
    for rec in records:
        key = ip_key(rec.get("candidate", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


# ---------------------------------------------------------------- pipeline
def detect(base, candidates, rounds, chunk, sleep, retries):
    """多轮检测，返回 {candidate: {ok, runs, ...}}；子请求超限不计入 runs 并重试"""
    stats = {c: {"candidate": c, "ok": 0, "runs": 0} for c in candidates}
    for rnd in range(1, rounds + 1):
        print(f"\n[检测轮次 {rnd}/{rounds}] {len(candidates)} 个候选", flush=True)
        for i in range(0, len(candidates), chunk):
            batch = candidates[i:i + chunk]
            pending = list(batch)
            for attempt in range(1, retries + 2):
                if not pending:
                    break
                results = check_batch(base, pending)
                retry_next = []
                for res in results:
                    cand = res.get("candidate")
                    if cand not in stats:
                        cand = pending[0] if len(pending) == 1 else cand
                        stats.setdefault(cand, {"candidate": cand, "ok": 0, "runs": 0})
                    info = probe_info(res)
                    rec = stats[cand]
                    if info.get("sublimit"):
                        retry_next.append(cand)   # 配额问题，不算一次真实检测
                        continue
                    rec["runs"] += 1
                    if info["ok"]:
                        rec["ok"] += 1
                        rec.update({k: v for k, v in info.items() if k != "ok"})
                    else:
                        rec["last_error"] = info["error"]
                pending = retry_next
                if pending:
                    print(f"  子请求超限，{len(pending)} 个降级为单批重试(第{attempt}次)", flush=True)
                    time.sleep(1.0)
            done = min(i + chunk, len(candidates))
            print(f"  {done}/{len(candidates)} 已检测", flush=True)
            time.sleep(sleep)
    return stats


def read_entries(path, inline=None):
    """读配置行：给了 inline 就用 inline（逗号分隔），否则读文件"""
    if inline:
        return [x.strip() for x in inline.split(",") if x.strip()]
    if not path or not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]


def load_domains(path, inline=None):
    """域名清单：忽略误写进来的 URL"""
    seen, out = set(), []
    for item in read_entries(path, inline):
        if item.lower().startswith(("http://", "https://")):
            print(f"  ! 忽略非域名行（应放到 links.txt）: {item}", file=sys.stderr, flush=True)
            continue
        key = item.split("#")[0].strip().lower().rstrip(".")
        if key and key not in seen:
            seen.add(key)
            out.append(item)
    return out


def load_links(path, inline=None):
    """TXT 链接清单：只保留 http(s) 开头的行"""
    out = []
    for item in read_entries(path, inline):
        if not item.lower().startswith(("http://", "https://")):
            print(f"  ! 忽略非链接行（应放到 domains.txt）: {item}", file=sys.stderr, flush=True)
            continue
        if item not in out:
            out.append(item)
    return out


def main():
    ap = argparse.ArgumentParser(description="ProxyIP 批量检测流水线（域名源 / TXT 链接源）")
    ap.add_argument("--base", default=os.environ.get("CHECK_BASE", DEFAULT_BASE))
    ap.add_argument("--source", choices=("domains", "links"), default="domains",
                    help="数据源：domains=域名解析（默认输出 proxyip.txt），"
                         "links=TXT 链接（默认输出 proxyip2.txt）")
    ap.add_argument("--domains", help="逗号分隔的域名，指定后忽略 --domain-file")
    ap.add_argument("--domain-file", default="domains.txt", help="域名清单，默认 domains.txt")
    ap.add_argument("--links", help="逗号分隔的 TXT 链接，指定后忽略 --links-file")
    ap.add_argument("--links-file", default="links.txt", help="TXT 链接清单，默认 links.txt")
    ap.add_argument("--rounds", type=int, default=2, help="检测轮次，默认 2")
    ap.add_argument("--min-ratio", type=float, default=0.5,
                    help="判为可用的最低成功率，默认 0.5（2 轮里至少通 1 次）")
    ap.add_argument("--chunk", type=int, default=CHECK_CHUNK, help="单次 /check 提交数，默认 20")
    ap.add_argument("--sleep", type=float, default=0.3)
    ap.add_argument("--retries", type=int, default=3, help="网络/配额重试次数，默认 3")
    ap.add_argument("--out", help="输出文件，默认 domains->proxyip.txt，links->proxyip2.txt")
    ap.add_argument("--detail", help="明细输出，默认与输出文件同名的 _detail.json")
    ap.add_argument("--min-usable", type=int, default=0,
                    help="可用数量低于该值时视为异常，不覆盖输出文件并以 3 退出（供 CI 防抖）")
    ap.add_argument("--max-candidates", type=int, default=0,
                    help="检测数量上限，超出则截断（0 表示不限制）")
    ap.add_argument("--port-preference", default="443,2053,2083,2087,2096,8443",
                    help="同 IP 多端口时的优先顺序，默认 443,2053,2083,2087,2096,8443")
    ap.add_argument("--dedupe-before", action=argparse.BooleanOptionalAction, default=True,
                    help="检测前按 IP 去重，省掉同 IP 的其他端口（默认开启）")
    ap.add_argument("--unique-ip", action=argparse.BooleanOptionalAction, default=True,
                    help="检测后按 IP 去重，保证输出里每个 IP 只出现一次（默认开启）")
    args = ap.parse_args()

    if not args.out:
        args.out = "proxyip.txt" if args.source == "domains" else "proxyip2.txt"
    if not args.detail:
        args.detail = os.path.splitext(args.out)[0] + "_detail.json"
    port_pref = [p.strip() for p in args.port_preference.split(",") if p.strip()]

    # ---- 1. 采集候选
    sources_detail = {}
    raw_targets = []

    if args.source == "domains":
        domains = load_domains(args.domain_file, args.domains)
        if not domains:
            print("域名清单为空：请配置 domains.txt 或使用 --domains", file=sys.stderr)
            return 2
        print(f"[1/3] 域名源：{len(domains)} 个待解析", flush=True)
        resolved = resolve_batch(args.base, domains, args.retries)
        for d in domains:
            item = resolved.get(d) or {"targets": [], "error": "not returned"}
            sources_detail[d] = item
            if item.get("error"):
                print(f"  ✗ {d}: {item['error']}", flush=True)
            else:
                print(f"  ✓ {d}: {len(item['targets'])} 个候选", flush=True)
            raw_targets.extend(item["targets"])
    else:
        links = load_links(args.links_file, args.links)
        if not links:
            print("链接清单为空：请配置 links.txt 或使用 --links", file=sys.stderr)
            return 2
        print(f"[1/3] 链接源：{len(links)} 个 TXT 链接", flush=True)
        for url in links:
            try:
                text = fetch_text(url, retries=args.retries)
                found, skipped = parse_target_list(text)
                sources_detail[url] = {"count": len(found), "skipped": skipped}
                print(f"  ✓ {url}: {len(found)} 个候选"
                      f"（{len(text.splitlines())} 行，跳过 {skipped} 行）", flush=True)
                raw_targets.extend(found)
            except Exception as exc:
                sources_detail[url] = {"error": str(exc)}
                print(f"  ✗ {url}: {exc}", flush=True)

    # ---- 2. 汇总去重
    targets = dedupe_targets(raw_targets)
    print(f"[2/3] 汇总 {len(raw_targets)} 个候选，规范化去重后 {len(targets)} 个"
          f"（去掉重复 {len(raw_targets) - len(targets)} 个）", flush=True)

    if args.dedupe_before and targets:
        before = len(targets)
        targets, dropped = dedupe_by_ip(targets, port_pref)
        print(f"      按 IP 预去重：{before} -> {len(targets)}（合并 {dropped} 个同 IP 多端口）",
              flush=True)

    if args.max_candidates and len(targets) > args.max_candidates:
        print(f"      ! 候选超过 --max-candidates {args.max_candidates}，截断", file=sys.stderr)
        targets = targets[:args.max_candidates]

    if not targets:
        print("没有解析到任何候选，退出", file=sys.stderr)
        return 1

    chunks = -(-len(targets) // max(1, args.chunk))
    print(f"      预计耗时约 {chunks * max(1, args.rounds) * 8 / 60:.1f} 分钟"
          f"（{chunks} 批 × {args.rounds} 轮）", flush=True)

    # ---- 3. 检测
    stats = detect(args.base, targets, args.rounds, args.chunk, args.sleep, args.retries)

    usable, rejected = [], []
    for cand, rec in stats.items():
        ratio = rec["ok"] / rec["runs"] if rec["runs"] else 0
        if rec["ok"] and ratio >= args.min_ratio:
            usable.append({**rec, "ratio": round(ratio, 2)})
        else:
            rejected.append({**rec, "ratio": round(ratio, 2)})
    usable.sort(key=lambda x: (-x["ratio"], x.get("rt") or 9999))

    if args.unique_ip:
        before = len(usable)
        usable = unique_by_ip(usable)
        if before != len(usable):
            print(f"\n[*] 检测后按 IP 去重：{before} -> {len(usable)} 条", flush=True)

    # ---- 4. 防抖：可用数异常偏低时不覆盖上次结果
    if len(usable) < args.min_usable:
        print(f"\n[!] 可用数量 {len(usable)} 低于 --min-usable {args.min_usable}，"
              f"保留原有 {args.out} 不覆盖（退出码 3）", file=sys.stderr)
        with open(args.detail, "w", encoding="utf-8") as fh:
            json.dump({"source": args.source, "sources": sources_detail,
                       "usable": usable, "rejected": rejected, "aborted": True},
                      fh, ensure_ascii=False, indent=1)
        return 3

    # ---- 5. 落盘
    with open(args.out, "w", encoding="utf-8") as fh:
        for rec in usable:
            fh.write(rec["candidate"] + "\n")
    with open(args.detail, "w", encoding="utf-8") as fh:
        json.dump({"source": args.source, "sources": sources_detail,
                   "usable": usable, "rejected": rejected},
                  fh, ensure_ascii=False, indent=1)

    print(f"\n[3/3] 可用 {len(usable)} / {len(targets)}，已写入 {args.out}")
    print(f"      明细 -> {args.detail}")
    print(f"\n{'proxyip':24}{'成功率':>8}{'延迟':>8}  {'栈':<11}{'colo':6}{'机房'}")
    for rec in usable:
        print(f"{rec['candidate']:24}{rec['ok']}/{rec['runs']:<6}{str(rec.get('rt')) + 'ms':>8}  "
              f"{str(rec.get('stack')):<11}{str(rec.get('colo')):6}{rec.get('org')}")
    if rejected:
        print(f"\n未通过 {len(rejected)} 个：")
        for rec in rejected[:15]:
            print(f"  {rec['candidate']:24}{rec['ok']}/{rec['runs']}  {rec.get('last_error', '')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
