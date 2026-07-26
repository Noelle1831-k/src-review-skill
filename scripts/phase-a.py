import json, urllib.request, time, sys, os
from websocket import create_connection

CDP = 'http://127.0.0.1:9222'
EXCLUDED_FILE = '/tmp/src_excluded.json'
CACHE_FILE = '/tmp/src_cache.json'

def get_src_ws():
    tabs = json.loads(urllib.request.urlopen(CDP + '/json').read())
    pages = [t for t in tabs if t['type'] == 'page' and 'src.bytedance.net' in t.get('url', '')]
    # Prefer the home page (not detail pages)
    home = [t for t in pages if '/home' in t.get('url', '') or t.get('url', '').endswith('src.bytedance.net')]
    if not home:
        urllib.request.urlopen(urllib.request.Request(CDP + '/json/new?url=https://src.bytedance.net/home', method='PUT'))
        time.sleep(4)
        tabs = json.loads(urllib.request.urlopen(CDP + '/json').read())
        pages = [t for t in tabs if t['type'] == 'page' and 'src.bytedance.net' in t.get('url', '')]
        home = [t for t in pages if '/home' in t.get('url', '') or t.get('url', '').endswith('src.bytedance.net')]
    if not home:
        sys.exit('No SRC tab - please login first')
    return create_connection(home[0]['webSocketDebuggerUrl']), home[0]

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
    cat = excluded.get(category, {})
    if isinstance(cat, dict):
        for vid in cat:
            excluded_ids.add(vid)

reproduced_ids = set(vid for vid, v in cache.items() if v.get('reproduced'))

all_skip = excluded_ids | reproduced_ids
print(f'  Excluded (hard_params + click_heavy): {len(excluded_ids)}')
print(f'  Already reproduced: {len(reproduced_ids)}')
print(f'  Total to skip: {len(all_skip)}')

# Filter rows
current_ids = set(r['id'] for r in rows)
filtered_rows = [r for r in rows if r['id'] not in all_skip]

# Clean stale entries from excluded.json (removed from pending review)
for category in ('hard_params', 'click_heavy'):
    cat = excluded.get(category, {})
    if isinstance(cat, dict):
        stale_excluded = [vid for vid in cat if vid not in current_ids]
        for vid in stale_excluded:
            del excluded[category][vid]
        if stale_excluded:
            print(f'  Cleaned {len(stale_excluded)} stale entries from excluded.{category}')
        if not excluded[category]:
            del excluded[category]

# Clean stale reproduced flags from cache (vuln no longer in pending review)
cache_changed = False
stale_repro = [vid for vid in cache if vid not in current_ids and cache[vid].get('reproduced')]
for vid in stale_repro:
    cache[vid]['reproduced'] = False
    cache_changed = True
if stale_repro:
    print(f'  Reset reproduced for {len(stale_repro)} stale cache entries')

with open(EXCLUDED_FILE, 'w') as f:
    json.dump(excluded, f, ensure_ascii=False, indent=2)
if cache_changed:
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

# Print summary
print('\n' + '=' * 80)
print('SRC Review Queue')
print('Apps: volcano engine (' + str(app_count) + ') | Status: pending review | ' + str(pagination))
if all_skip:
    print('Skipped (excluded/reproduced): ' + str(len(all_skip)) + ' IDs')
print('=' * 80 + '\n')

for r in filtered_rows:
    icon = {'严重': 'R', '高危': 'H', '中危': 'M', '低危': 'L'}.get(r['severity'], '?')
    print('[' + icon + '] [' + r['id'] + '] ' + r['severity'] + ' | ' + r['title'][:60])
    print('     Reporter: ' + r['reporter'].ljust(14) + ' Team: ' + r['team'].ljust(14) + ' Status: ' + r['status'])
    print()

# Save filtered IDs
ids = [r['id'] for r in filtered_rows]
with open('/tmp/src_ids.json', 'w') as f:
    json.dump({
        'count': len(ids), 'ids': ids, 'rows': filtered_rows,
        'all_count': len(rows), 'all_ids': [r['id'] for r in rows], 'all_rows': rows,
        'skipped_excluded': len(excluded_ids),
        'skipped_reproduced': len(reproduced_ids)
    }, f, ensure_ascii=False)
print('IDs saved to /tmp/src_ids.json (' + str(len(ids)) + ' vulns, ' + str(len(all_skip)) + ' skipped)')
