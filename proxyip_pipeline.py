#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProxyIP 批量流水线：域名 -> /resolve-batch 解析 -> /check 批量检测 -> proxyip.txt

流程:
  1. 读取 domains.txt（或 --domains / --domain-file），每行一个域名，支持 # 注释
  2. POST /resolve-batch 解析，每次最多 15 个域名（Worker 端 RESOLVE_BATCH_LIMIT）
  3. 汇总去重所有 ip:port / [v6]:port 候选
  4. GET /check?proxyip=a,b,c 批量检测，每次最多 20 个（避开 CF 免费版 50 子请求上限）
  5. 多轮复测，按成功率过滤，可用结果写入 proxyip.txt（每行 ip:port）

用法:
  python3 proxyip_pipeline.py                          # 用 domains.txt
  python3 proxyip_pipeline.py --domains a.com,b.com    # 直接指定
  python3 proxyip_pipeline.py --rounds 3 --min-ratio 0.66 --out proxyip.txt
  python3 proxyip_pipeline.py --unique-ip              # 同一 IP 只保留最优端口
"""

import argparse
import ipaddress
import json
import os
import re
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


# ---------------------------------------------------------------- HTTP helpers
def http_json(url, data=None, timeout=180):
    body = json.dumps(data).encode() if data is not None else None
    headers = {"User-Agent": UA}
    if body:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


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
        print(f"  resolve-batch {i + len(chunk)}/{len(domains)} 完成")
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
      1.2.3.4:8443       != 1.2.3.4:443      （端口不同视为不同服务，保留）
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
    if not host or not port.isdigit():
        return None

    try:
        ip = ipaddress.ip_address(host)
        key_host = ip.compressed
        out = f"[{key_host}]:{port}" if ip.version == 6 else f"{key_host}:{port}"
    except ValueError:
        key_host, out = host, f"{host}:{port}"
    return f"{key_host}|{port}", out


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
    """取候选的 IP 部分（忽略端口），用于 --unique-ip"""
    parsed = canon_target(candidate)
    return parsed[0].split("|", 1)[0] if parsed else str(candidate or "")


def unique_by_ip(records):
    """按 IP 去重，忽略端口；保留列表中靠前的一条。

    调用方需先把 records 按优先级排好（成功率高的在前、延迟低的在前），
    这样同一 IP 的多个端口里留下的就是最优的那条。
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
        print(f"\n[检测轮次 {rnd}/{rounds}] {len(candidates)} 个候选")
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
                    print(f"  子请求超限，{len(pending)} 个降级为单批重试(第{attempt}次)")
                    time.sleep(1.0)
            done = min(i + chunk, len(candidates))
            print(f"  {done}/{len(candidates)} 已检测", flush=True)
            time.sleep(sleep)
    return stats


def main():
    ap = argparse.ArgumentParser(description="ProxyIP 域名解析 + 批量检测流水线")
    ap.add_argument("--base", default=os.environ.get("CHECK_BASE", DEFAULT_BASE))
    ap.add_argument("--domains", help="逗号分隔的域名列表")
    ap.add_argument("--domain-file", default="domains.txt", help="域名列表文件，默认 domains.txt")
    ap.add_argument("--rounds", type=int, default=2, help="检测轮次，默认 2")
    ap.add_argument("--min-ratio", type=float, default=0.5,
                    help="判为可用的最低成功率，默认 0.5（2 轮里至少通 1 次）")
    ap.add_argument("--chunk", type=int, default=CHECK_CHUNK, help="单次 /check 提交数，默认 20")
    ap.add_argument("--sleep", type=float, default=0.3)
    ap.add_argument("--retries", type=int, default=3, help="网络/配额重试次数，默认 3")
    ap.add_argument("--out", default="proxyip.txt", help="可用列表输出，默认 proxyip.txt")
    ap.add_argument("--detail", default="proxyip_detail.json", help="明细输出")
    ap.add_argument("--min-usable", type=int, default=0,
                    help="可用数量低于该值时视为异常，不覆盖输出文件并以 3 退出（供 CI 防抖）")
    ap.add_argument("--unique-ip", action=argparse.BooleanOptionalAction, default=True,
                    help="按 IP 去重：同一 IP 的多个端口只保留成功率最高、延迟最低的那条"
                         "（默认开启，--no-unique-ip 关闭）")
    args = ap.parse_args()

    # ---- 1. 域名清单
    if args.domains:
        domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    elif os.path.exists(args.domain_file):
        with open(args.domain_file, encoding="utf-8") as fh:
            domains = [ln.strip() for ln in fh
                       if ln.strip() and not ln.strip().startswith("#")]
    else:
        print(f"未找到 {args.domain_file}，也没有 --domains", file=sys.stderr)
        return 2
    # 域名层面也去重（大小写不敏感，DNS 不区分大小写），保留首次写法
    seen_domains, uniq_domains = set(), []
    for d in domains:
        key = d.split("#")[0].strip().lower().rstrip(".")
        if key and key not in seen_domains:
            seen_domains.add(key)
            uniq_domains.append(d)
    domains = uniq_domains
    print(f"[1/3] 待解析域名 {len(domains)} 个")

    # ---- 2. 解析
    resolved = resolve_batch(args.base, domains, args.retries)
    per_domain, raw_targets = {}, []
    for d in domains:
        item = resolved.get(d) or {"targets": [], "error": "not returned"}
        per_domain[d] = item
        if item.get("error"):
            print(f"  ✗ {d}: {item['error']}")
        else:
            print(f"  ✓ {d}: {len(item['targets'])} 个候选")
        raw_targets.extend(item["targets"])

    targets = dedupe_targets(raw_targets)
    dup = len(raw_targets) - len(targets)
    print(f"[2/3] 汇总 {len(raw_targets)} 个候选，规范化去重后 {len(targets)} 个"
          f"（去掉重复 {dup} 个）")
    if not targets:
        print("没有解析到任何候选，退出", file=sys.stderr)
        return 1

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

    # ---- 3.5 可选：按 IP 去重（忽略端口），保留排序后最优的那条
    multi_port = {}
    if args.unique_ip:
        for rec in usable:
            multi_port.setdefault(ip_key(rec["candidate"]), []).append(rec["candidate"])
        before = len(usable)
        usable = unique_by_ip(usable)
        print(f"\n[*] --unique-ip 按 IP 去重：{before} -> {len(usable)} 条"
              f"（合并掉 {before - len(usable)} 个同 IP 不同端口）")
        for key, cands in multi_port.items():
            if len(cands) > 1:
                print(f"    {key}: {', '.join(cands)}")

    # ---- 4. 防抖：可用数异常偏低时不覆盖上次结果
    if len(usable) < args.min_usable:
        print(f"\n[!] 可用数量 {len(usable)} 低于 --min-usable {args.min_usable}，"
              f"保留原有 {args.out} 不覆盖（退出码 3）", file=sys.stderr)
        with open(args.detail, "w", encoding="utf-8") as fh:
            json.dump({"domains": per_domain, "usable": usable, "rejected": rejected,
                       "aborted": True}, fh, ensure_ascii=False, indent=1)
        return 3

    # ---- 5. 落盘
    with open(args.out, "w", encoding="utf-8") as fh:
        for rec in usable:
            fh.write(rec["candidate"] + "\n")
    with open(args.detail, "w", encoding="utf-8") as fh:
        json.dump({"domains": per_domain, "usable": usable, "rejected": rejected},
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
