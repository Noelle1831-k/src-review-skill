---
name: src-review
description: >
  Bytedance SRC vulnerability review automation. Filters volcano engine apps with 待审核 status,
  then dispatches parallel sub-agents to fetch each vulnerability's detail page.
  Trigger: "看看今天我要审核哪些漏洞", "帮我看SRC待审核", "SRC审核清单".
  Depends on chrome-debug skill for browser automation.
---

# SRC 审核清单

自动打开 SRC 管理平台，筛选火山引擎应用 + 待审核状态的漏洞，并为每条漏洞打开详情页供后续审核。

## 依赖

[[chrome-debug]] — 确保 Chrome 调试端口 `http://127.0.0.1:9222` 可访问。

## 数据文件

| 文件 | 用途 |
|------|------|
| `/tmp/src_ids.json` | 当前待审核漏洞 ID 列表（Phase A 输出） |
| `/tmp/src_details.json` | 详情页正文 + 附件索引（Phase B 输出） |
| `/tmp/src_cache.json` | 详情抓取缓存，含 `reproduced` 字段 |
| `/tmp/src_excluded.json` | 被 Phase C 筛掉的漏洞，下次自动跳过 |
| `/tmp/src_attachments/` | 附件下载目录 |
| `/tmp/volc_cookies.txt` | 火山引擎 console cookie（CDP 提取） |
| `/tmp/volc_csrf.txt` | CSRF token（CDP 提取） |

### cache.json schema

```json
{
  "35502": {
    "title": "...",
    "url": "https://src.bytedance.net/vul-detail/35502",
    "fetched_at": "2026-07-26T22:00:00+08:00",
    "has_attachments": true,
    "body_size": 5000,
    "reproduced": true
  }
}
```

### excluded.json schema

```json
{
  "hard_params": {
    "35456": { "reason": "需要上传文件返回的随机链接", "excluded_at": "2026-07-26T..." }
  },
  "click_heavy": {
    "35311": { "reason": "需要开通服务+创建实例+多页面操作", "excluded_at": "2026-07-26T..." }
  }
}
```

## 执行流程

### Phase A: 列表收集

运行 `/tmp/src_review_v4.py` — 五步完成：

| Step | 功能 |
|------|------|
| A1-A4 | 筛选火山引擎 + 待审核 → 50条/页 → 读取表格 |
| **A5** | **🆕 后处理：剔除 excluded.json 中的漏洞 + cache.json 中 reproduced=true 的漏洞 + 清理 excluded.json 中已审核完成的旧记录** |

输出 `/tmp/src_ids.json`（只包含需要处理的漏洞）

### Phase B: 详情抓取 + 附件处理

运行 `/tmp/src_detail_batch.py`，分四个子阶段：

| 阶段 | 功能 |
|------|------|
| **B0: 缓存同步** | 对比 `/tmp/src_cache.json` 与当前 ID 列表，确定三类：**cached**（跳过）、**new**（需抓取）、**stale**（已不在待审核列表，删除文件夹和缓存） |
| **B1: 增量抓取** | 仅对 new ID 开 tab → 提取标题+正文 → 下载附件。cached ID 直接复用已有数据 |
| **B2: 后处理** | 解压 .zip（GBK 编码修复）→ PyMuPDF 转 .pdf 为 .md → 清理 macOS 垃圾文件 |
| **B3: 更新缓存** | 写入 `/tmp/src_cache.json`，记录标题、抓取时间、附件状态。**🆕 保留已有 `reproduced` 字段** |

缓存策略：以漏洞编号为 key，已获取过的漏洞不再重复请求 Chrome，已离开待审核列表的自动清理。首次运行全量抓取，后续运行只抓增量。

### Phase C: 分析与复现 🆕

**仅在 Phase B 有 new IDs 时运行**。分三个串行子阶段，由 Workflow 编排。

#### C1: 不可枚举参数筛选（单 agent）

读取所有 new IDs 的详情（`/tmp/src_details.json`）和附件 MD 文件。

**判断标准**：漏洞利用是否需要"纯随机不可枚举参数"？

> ⚠️ 这里的"不可枚举参数"是指：**上传文件返回的随机链接、系统随机生成的序列号、一次性校验 token** 等 —— 即除了受害者本人主动泄露之外，没有任何其他方式能获取到。这些参数没有窃取价值（攻击者不会刻意去偷），所以利用路径不成立。
>
> ❌ **不筛**的：AK/SK、session cookie、登录密码、可枚举 ID（如数字自增）、可爆破参数 —— 这些要么可以被枚举/爆破，要么具有重大窃取价值，攻击者有动机去获取。

输出：
- 写入 `/tmp/src_excluded.json["hard_params"]`，记录排除原因
- 剩余漏洞 ID 列表传给 C2

#### C2: 点击量筛选（单 agent）

读取 C1 剩余漏洞的详情和附件。

**判断标准**：漏洞复现是否需要大量 UI 点击操作？

> - 需要在控制台创建多个资源（开通服务 → 创建实例 → 配置参数 → ...）
> - 需要跨多个页面跳转
> - 需要填写复杂表单
> - 需要等待审批或异步流程
>
> 简单操作（1-2 次点击、单页面的 API 调用）不在此列。

输出：
- 写入 `/tmp/src_excluded.json["click_heavy"]`，记录排除原因
- 剩余漏洞 ID 列表传给 C3

#### C3: 复现 Dispatcher（单 dispatcher agent → N 个子 agent）

Dispatcher agent 自身不做复现，只读取 C2 剩余漏洞列表，**为每个漏洞派发一个子 agent**。

**子 agent 行为**：
1. 读取漏洞详情 + 附件
2. 优先使用报告中已有的 PoC（curl 命令 / Python 脚本 / 请求包）
3. 无现成 PoC → 自行分析并生成 PoC
4. **操作约束**：
   - ✅ **允许**：读取操作（GET/LIST/DESCRIBE/SELECT）
   - ✅ **允许**：非破坏性写入（创建自己的测试资源、添加无害标记/评论）
   - ✅ **允许**：最小验证范围内的他人数据修改（证明越权即可，禁止覆盖配置/篡改核心数据）
   - ✅ **允许**：纯验证性 RCE / 容器逃逸 / 提权（执行无害命令如 whoami/id/hostname 证明成功即可，禁止进一步利用）
   - ❌ **禁止**：删除任何数据（DELETE/DROP/TRUNCATE）
   - ❌ **禁止**：覆盖他人配置、篡改核心业务数据

**子 agent 限制**：
- 最多 **50 个 tool call**
- 最多 **10 分钟**
- 超时自动关闭，标记为 failed

**子 agent 成功后**：
- 更新 `/tmp/src_cache.json` 中该漏洞的 `reproduced = true`

**并发数**：控制在 5-8 个。

### 手动复现入口

- "重新复现 ID 35455" → 单独对某个漏洞跑 C3
- "重新评估这批漏洞" → 忽略 excluded.json，全量跑 Phase C
- "把 ID 35455 从排除列表移除" → 手动编辑 excluded.json

## DOM 速查

| 控件 | ID | 类型 |
|------|-----|------|
| 填报应用 | `submit_app_name_input` | `arco-select-multiple` + search |
| 状态 | `state_input` | `arco-select-multiple` |
| 填报应用 popup | 动态生成，通过 `[id*="arco-select-popup"]` 查找 | 虚拟滚动列表 |
| 状态 popup | `arco-select-popup-1` | 普通列表 |
| 分页选择器 | `[class*=pagination] .arco-select` | 下拉 |

## 关键坑

1. **reload 后必须重连 WebSocket**：页面导航导致旧的 WS 连接失效
2. **虚拟滚动**：`list.scrollTop = N` + `dispatchEvent(new Event("scroll"))` 才能触发加载更多选项
3. **checkbox 点击目标**：必须点 `<label class="arco-checkbox">`，不是 `<li>`。选项文字在 label 外部
4. **状态筛选需要 dispatch change 事件**：`cb.dispatchEvent(new Event("change", {bubbles: true}))` 才能触发 Arco 的响应
5. **筛选自动生效**：关闭 popup 后自动触发查询，无需点按钮
6. **详情页新 tab 要用 Page.navigate**：`PUT /json/new?url=...` 可能被 SSO 拦截；先开空白 tab 再 `Page.navigate` 更可靠
7. **详情 tab 需等待 SSO 重定向**：首次访问可能跳 SSO，轮询 `document.title` 直到非空非 SSO

## 工作脚本

### Phase A 主脚本：`/tmp/src_review_v4.py`

```python
import json, urllib.request, time, sys, os
from websocket import create_connection

CDP = 'http://127.0.0.1:9222'
EXCLUDED_FILE = '/tmp/src_excluded.json'
CACHE_FILE = '/tmp/src_cache.json'

def get_src_ws():
    tabs = json.loads(urllib.request.urlopen(CDP + '/json').read())
    pages = [t for t in tabs if t['type'] == 'page' and 'src.bytedance.net' in t.get('url', '')]
    if not pages:
        urllib.request.urlopen(urllib.request.Request(CDP + '/json/new?url=https://src.bytedance.net/home', method='PUT'))
        time.sleep(4)
        tabs = json.loads(urllib.request.urlopen(CDP + '/json').read())
        pages = [t for t in tabs if t['type'] == 'page' and 'src.bytedance.net' in t.get('url', '')]
    if not pages:
        sys.exit('No SRC tab - please login first')
    return create_connection(pages[0]['webSocketDebuggerUrl']), pages[0]

def js(ws, expr):
    ws.send(json.dumps({'id': 1, 'method': 'Runtime.evaluate', 'params': {
        'expression': expr, 'returnByValue': True
    }}))
    return json.loads(ws.recv()).get('result', {}).get('result', {}).get('value')

# --- Main ---
ws, page = get_src_ws()
title = page.get('title', '')
if 'SSO' in title or title == '':
    print('Waiting for SSO redirect...')
    time.sleep(4)
    ws.close()
    ws, page = get_src_ws()

js(ws, 'location.reload()')
time.sleep(4)
ws.close()
ws, page = get_src_ws()

for _ in range(15):
    if js(ws, 'document.getElementById("submit_app_name_input") ? "ok" : ""') == 'ok':
        break
    time.sleep(0.5)

# === Phase 1 ===
print('[1/4] Application = volcano engine')
js(ws, 'document.getElementById("submit_app_name_input").click()')
time.sleep(0.4)
js(ws, '(function(){var s=document.getElementById("submit_app_name_input");var i=s.querySelector("input");i.focus();document.execCommand("insertText",false,"火山引擎")})()')
time.sleep(1.5)

for rnd in range(15):
    count_js = '(function(){var ps=document.querySelectorAll(\'[id*="arco-select-popup"]\');var c=0;for(var i=0;i<ps.length;i++){if(!ps[i].offsetParent)continue;ps[i].querySelectorAll("li.arco-select-option-wrapper").forEach(function(li){var text=li.textContent.trim();if(text.indexOf("火山引擎")!==0)return;var l=li.querySelector("label.arco-checkbox");if(l&&!l.querySelector("input").checked){l.click();c++}})}return c})()'
    clicked = int(js(ws, count_js) or 0)
    if clicked == 0 and rnd > 1:
        break
    scroll_val = rnd * 700
    scroll_js = '(function(){var ps=document.querySelectorAll(\'[id*="arco-select-popup"]\');for(var i=0;i<ps.length;i++){if(!ps[i].offsetParent)continue;var l=ps[i].querySelector(\'[class*="list"]\')||ps[i];l.scrollTop=' + str(scroll_val) + ';l.dispatchEvent(new Event("scroll",{bubbles:true}))}})()'
    js(ws, scroll_js)
    time.sleep(0.3)

js(ws, 'document.body.click()')
time.sleep(0.5)
app_count = js(ws, 'document.getElementById("submit_app_name_input").querySelectorAll(".arco-tag").length')
print('  Apps selected: ' + str(app_count))

# === Phase 2 ===
print('[2/4] Status = pending review')
js(ws, 'document.getElementById("state_input").querySelector(".arco-select-suffix").click()')
time.sleep(0.6)
js(ws, '(function(){var p=document.getElementById("arco-select-popup-1");if(!p||!p.offsetParent)return;var lis=p.querySelectorAll("li.arco-select-option-wrapper");for(var i=0;i<lis.length;i++){if(lis[i].textContent.trim().indexOf("待审核")===0){var l=lis[i].querySelector("label.arco-checkbox");if(l){l.click();l.querySelector("input").dispatchEvent(new Event("change",{bubbles:true}))}}}})()')
js(ws, 'document.body.click()')
time.sleep(1.5)

# === Phase 3: 50/page ===
print('[3/4] Page size = 50')
js(ws, '(function(){var pag=document.querySelector("[class*=pagination]");if(!pag)return;var sel=pag.querySelector(".arco-select");if(sel)sel.click()})()')
time.sleep(0.5)

r = js(ws, '(function(){var ps=document.querySelectorAll(\'[id*="arco-select-popup"]\');for(var i=0;i<ps.length;i++){if(!ps[i].offsetParent)continue;var opts=ps[i].querySelectorAll(\'li[role="option"]\');for(var j=0;j<opts.length;j++){if(opts[j].textContent.trim().indexOf("50")>=0){opts[j].click();return"50/page"}}}return"not found"})()')
print('  ' + str(r))
time.sleep(2)

# Reconnect after reload
ws.close()
ws, page = get_src_ws()
time.sleep(1)

# === Phase 4 ===
print('[4/4] Reading results')

pagination = js(ws, '(function(){var p=document.querySelector("[class*=pagination]");return p?p.textContent.trim().substring(0,200):"none"})()')

rows = json.loads(js(ws, """(function() {
    var result = [];
    document.querySelectorAll(".arco-table-tr").forEach(function(r) {
        if (!r.offsetParent || !r.querySelector("td")) return;
        var tds = r.querySelectorAll("td");
        if (tds.length < 10) return;
        var texts = [];
        tds.forEach(function(td) { texts.push(td.textContent.trim()); });
        result.push({
            id: texts[1], title: texts[2].substring(0, 80),
            app: texts[3].substring(0, 40), vulnType: texts[5].substring(0, 40),
            reporter: texts[6], team: texts[7], severity: texts[8],
            reviewer: texts[9], status: texts[10], submitTime: texts[16]
        });
    });
    return JSON.stringify(result);
})()"""))
ws.close()

# ============================================================
# A5: Post-process — filter excluded & reproduced, clean stale
# ============================================================
print('\n[A5] Post-processing...')

# Load excluded list
excluded = {}
if os.path.exists(EXCLUDED_FILE):
    with open(EXCLUDED_FILE) as f:
        excluded = json.load(f)

# Load cache for reproduced status
cache = {}
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE) as f:
        cache = json.load(f)

# Collect IDs to exclude
excluded_ids = set()
for category in ('hard_params', 'click_heavy'):
    for vid in (excluded.get(category, {}) or {}):
        excluded_ids.add(vid)

reproduced_ids = set(vid for vid, v in cache.items() if v.get('reproduced'))

all_skip = excluded_ids | reproduced_ids
print(f'  Excluded (hard_params + click_heavy): {len(excluded_ids)}')
print(f'  Already reproduced: {len(reproduced_ids)}')
print(f'  Total to skip: {len(all_skip)}')

# Filter rows
current_ids = set(r['id'] for r in rows)
filtered_rows = [r for r in rows if r['id'] not in all_skip]

# Clean stale entries from excluded.json
for category in ('hard_params', 'click_heavy'):
    if category in excluded:
        stale_excluded = [vid for vid in excluded[category] if vid not in current_ids]
        for vid in stale_excluded:
            del excluded[category][vid]
        if stale_excluded:
            print(f'  Cleaned {len(stale_excluded)} stale entries from excluded.{category}')
        if not excluded[category]:
            del excluded[category]

# Also clean stale reproduced from cache
stale_cache = [vid for vid in cache if vid not in current_ids and cache[vid].get('reproduced')]
for vid in stale_cache:
    cache[vid]['reproduced'] = False
if stale_cache:
    print(f'  Reset reproduced for {len(stale_cache)} stale cache entries')

with open(EXCLUDED_FILE, 'w') as f:
    json.dump(excluded, f, ensure_ascii=False, indent=2)
with open(CACHE_FILE, 'w') as f:
    json.dump(cache, f, ensure_ascii=False, indent=2)

# Print summary
print('\n' + '=' * 80)
print('SRC Review Queue')
print('Apps: volcano engine (' + str(app_count) + ') | Status: pending review | ' + str(pagination))
if all_skip:
    print('Skipped (excluded/reproduced): ' + str(len(all_skip)) + ' IDs')
print('=' * 80 + '\n')

sev_map = {'严重': '\033[91m', '高危': '\033[93m', '中危': '\033[33m', '低危': '\033[90m'}
for r in filtered_rows:
    icon = {'严重': 'R', '高危': 'H', '中危': 'M', '低危': 'L'}.get(r['severity'], '?')
    print('[' + icon + '] [' + r['id'] + '] ' + r['severity'] + ' | ' + r['title'][:60])
    print('     Reporter: ' + r['reporter'].ljust(14) + ' Team: ' + r['team'].ljust(14) + ' Status: ' + r['status'])
    print()

# Save IDs
ids = [r['id'] for r in filtered_rows]
with open('/tmp/src_ids.json', 'w') as f:
    json.dump({'count': len(ids), 'ids': ids, 'rows': filtered_rows,
               'skipped_excluded': len(excluded_ids),
               'skipped_reproduced': len(reproduced_ids)}, f, ensure_ascii=False)
print('IDs saved to /tmp/src_ids.json (' + str(len(ids)) + ' vulns, ' + str(len(all_skip)) + ' skipped)')
```

### Phase B 详情批量脚本：`/tmp/src_detail_batch.py`

分批处理（每批 5 个 tab），等全部加载完成再提取。输出到 `/tmp/src_details.json`。

**B3 缓存更新逻辑（已内置于脚本）**：写入 cache 时保留已有 `reproduced` 字段，不覆盖。

关键逻辑：
- `fetch_batch(ids)` — 打开 tab → 全部 navigate → 轮询标题直到全部就绪 → sleep 2s → 提取 → 关闭
- 标题回退：若 `document.title` 为空，正则提取 `标签管理(.+?)(?:待审核|编辑)`
- 批次间隔 1 秒，避免 Chrome 超载

### Phase C 复现 Workflow 脚本

执行时调用 Workflow 工具，传入脚本路径或内联脚本。核心结构：

```javascript
// Phase C: 分析与复现
// 只处理 /tmp/src_details.json 中 Phase B 标记为 'new' 的漏洞
// 读取 new IDs → C1 → C2 → C3

const SCHEMA_C12 = {
  type: 'object',
  properties: {
    passed: { type: 'array', items: { type: 'string' } },
    excluded: { type: 'array', items: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        reason: { type: 'string' }
      },
      required: ['id', 'reason']
    }}
  },
  required: ['passed', 'excluded']
}

const SCHEMA_REPRO = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    status: { type: 'string', enum: ['SUCCESS', 'FAILED', 'BLOCKED'] },
    evidence: { type: 'string' },
    poc_command: { type: 'string' }
  },
  required: ['id', 'status', 'evidence', 'poc_command']
}

// --- C1: Hard Parameters Filter ---
phase('C1: Hard Parameters Filter')

const c1Prompt = `你是安全漏洞分析专家。读取 /tmp/src_details.json 中以下 new IDs 的详情...`

const c1Result = await agent(c1Prompt, { label: 'c1-filter', schema: SCHEMA_C12 })

// Write excluded to /tmp/src_excluded.json
// ...

// --- C2: Click-Heavy Filter ---
phase('C2: Click-Heavy Filter')

const c2Prompt = `你是安全漏洞分析专家。读取 C1 筛选后剩余的漏洞详情...`

const c2Result = await agent(c2Prompt, { label: 'c2-filter', schema: SCHEMA_C12 })

// Write excluded to /tmp/src_excluded.json
// ...

// --- C3: Reproduction Dispatcher ---
phase('C3: Reproduction')

const c3Results = await pipeline(
  c2Result.passed,
  function(vid) {
    return agent(
      '复现漏洞 ' + vid + '。只读约束。优先用已有PoC。',
      { label: 'repro-' + vid, schema: SCHEMA_REPRO }
    )
  }
)

// Update cache.json[reproduced] = true for SUCCESS
// ...
```

## 执行顺序总览

```
每次运行:         Phase A → Phase B → (有 new?) → Phase C (仅 new IDs)
手动复现:         直接触发 Phase C3 针对指定 ID
重新评估:         Phase A → Phase B → Phase C (ignore excluded)
```
