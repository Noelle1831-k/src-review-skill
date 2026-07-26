"""SRC Detail Batch Fetcher - processes vuln IDs in batches of 5.

Phase B0: Cache sync — skip already-fetched IDs, delete stale data
Phase B1: Fetch details + download attachments (new IDs only)
Phase B2: Unzip + PDF->MD post-processing
Phase B3: Update cache

Usage: python3 /tmp/src_detail_batch.py
Reads /tmp/src_ids.json, maintains /tmp/src_cache.json
"""
import json, urllib.request, time, sys, os, re, zipfile, shutil
from datetime import datetime
from websocket import create_connection

CDP = 'http://127.0.0.1:9222'
BATCH_SIZE = 5
ATTACH_DIR = '/tmp/src_attachments'
CACHE_FILE = '/tmp/src_cache.json'
DETAILS_FILE = '/tmp/src_details.json'

with open('/tmp/src_ids.json') as f:
    data = json.load(f)
    current_ids = data['ids']  # filtered IDs for fetching
    all_src_ids = set(data.get('all_ids', data['ids']))  # ALL IDs from SRC page for stale detection


# ============================================================
#  Cache management (Phase B0)
# ============================================================

def load_cache():
    """Load the cache file or return empty dict."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE) as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_cache(cache):
    """Save cache to disk."""
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def delete_stale_data(stale_ids):
    """Delete attachment folders and detail entries for IDs no longer in review list."""
    deleted = []
    for vid in stale_ids:
        # Remove attachment folder
        for entry in os.listdir(ATTACH_DIR) if os.path.exists(ATTACH_DIR) else []:
            if entry.startswith(f'{vid}_'):
                folder = os.path.join(ATTACH_DIR, entry)
                shutil.rmtree(folder, ignore_errors=True)
                deleted.append(folder)
    return deleted


def sync_cache(current_ids, all_ids=None):
    """Compare current IDs with cache. Returns (new_ids, stale_ids, cached_results).
    current_ids: filtered IDs to fetch (from A5)
    all_ids: ALL IDs from SRC page (before A5 filtering), used for stale detection.
             If None, falls back to current_ids."""
    cache = load_cache()

    current_set = set(current_ids)
    cached_set = set(cache.keys())

    new_ids = sorted(current_set - cached_set)

    # Stale = in cache but NOT in the FULL SRC pending list
    # (only delete cache when the vuln is truly gone from SRC, not just filtered by A5)
    all_set = set(all_ids) if all_ids else current_set
    stale_ids = sorted(cached_set - all_set)
    kept_ids = sorted(current_set & cached_set)

    # Build cached results from existing data
    cached_results = {}
    for vid in kept_ids:
        entry = cache[vid]
        # Load body from details file if it exists
        body = ''
        attachments = []
        if os.path.exists(DETAILS_FILE):
            try:
                with open(DETAILS_FILE) as f:
                    old_details = json.load(f)
                if vid in old_details:
                    body = old_details[vid].get('body_preview', '')
                    attachments = old_details[vid].get('attachments', [])
            except:
                pass

        cached_results[vid] = {
            'id': vid,
            'title': entry.get('title', '(unknown)'),
            'url': entry.get('url', ''),
            'body_preview': body[:3000] if body else '',
            'attachments': attachments,
            '_cached': True
        }

    return new_ids, stale_ids, cached_results


# ============================================================
#  CDP helpers
# ============================================================

def js(ws, expr, await_promise=False):
    ws.send(json.dumps({'id': 1, 'method': 'Runtime.evaluate', 'params': {
        'expression': expr, 'returnByValue': True, 'awaitPromise': await_promise
    }}))
    return json.loads(ws.recv()).get('result', {}).get('result', {}).get('value')


def get_cookies(ws):
    ws.send(json.dumps({'id': 50, 'method': 'Network.getCookies',
        'params': {'urls': ['https://src.bytedance.net']}}))
    resp = json.loads(ws.recv())
    cookies = resp.get('result', {}).get('cookies', [])
    return '; '.join(f"{c['name']}={c['value']}" for c in cookies)


# ============================================================
#  Attachment download (Phase B1)
# ============================================================

def download_attachments(ws, vid, title, cookie_str):
    captured = js(ws, '''(function() {
        return new Promise(function(resolve) {
            var result = [];
            var containers = document.querySelectorAll('[class*="attachment-operation-container"]');
            if (containers.length === 0) { resolve(result); return; }
            var origOpen = window.open;
            var pending = containers.length;
            containers.forEach(function(container, idx) {
                var nameEl = container.querySelector('[class*="attachment-name"]');
                var filename = nameEl ? nameEl.textContent.trim() : ('attachment_' + idx);
                window.open = function(url) {
                    result.push({filename: filename, url: url});
                    pending--;
                    if (pending === 0) { window.open = origOpen; resolve(result); }
                    return null;
                };
                container.click();
            });
            setTimeout(function() { window.open = origOpen; resolve(result); }, 3000);
        });
    })()''', await_promise=True)

    if not captured:
        return []

    attachments = []
    safe_title = re.sub(r'[<>:"/\\\\|?*]', '_', title)[:80]
    folder = os.path.join(ATTACH_DIR, f'{vid}_{safe_title}')
    os.makedirs(folder, exist_ok=True)

    for att in captured:
        full_url = 'https://src.bytedance.net' + att['url']
        filename = att['filename']
        try:
            req = urllib.request.Request(full_url, headers={'Cookie': cookie_str})
            data = urllib.request.urlopen(req, timeout=30).read()
            filepath = os.path.join(folder, filename)
            with open(filepath, 'wb') as f:
                f.write(data)
            attachments.append({
                'filename': filename, 'url': att['url'],
                'local_path': filepath, 'size': len(data)
            })
        except Exception as e:
            attachments.append({
                'filename': filename, 'url': att['url'], 'error': str(e)[:200]
            })

    return attachments


# ============================================================
#  Post-processing (Phase B2): unzip + PDF->MD
# ============================================================

def extract_zips(folder):
    extracted = []
    for root, dirs, files in os.walk(folder):
        for f in files:
            if f.lower().endswith('.zip'):
                zip_path = os.path.join(root, f)
                extract_dir = os.path.join(root, 'extracted')
                os.makedirs(extract_dir, exist_ok=True)
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        for member in zf.infolist():
                            try:
                                name = member.filename.encode('cp437').decode('gbk')
                            except:
                                try:
                                    name = member.filename.encode('cp437').decode('utf-8')
                                except:
                                    name = member.filename
                            target = os.path.join(extract_dir, name)
                            if member.is_dir():
                                os.makedirs(target, exist_ok=True)
                            else:
                                os.makedirs(os.path.dirname(target), exist_ok=True)
                                with zf.open(member) as src, open(target, 'wb') as dst:
                                    dst.write(src.read())
                    extracted.append(extract_dir)
                except Exception as e:
                    print(f'    [WARN] Failed to extract {f}: {e}')
    return extracted


def convert_pdfs_in_folder(folder):
    import fitz as pymupdf
    converted = []
    for root, dirs, files in os.walk(folder):
        if '__MACOSX' in root:
            continue
        for f in files:
            if not f.lower().endswith('.pdf'):
                continue
            pdf_path = os.path.join(root, f)
            if os.path.basename(pdf_path).startswith('._'):
                continue
            md_path = pdf_path.rsplit('.', 1)[0] + '.md'
            if os.path.exists(md_path):
                continue

            try:
                doc = pymupdf.open(pdf_path)
                md_lines = []
                for page in doc:
                    blocks = page.get_text('dict', flags=pymupdf.TEXT_PRESERVE_WHITESPACE)['blocks']
                    try:
                        tabs = page.find_tables()
                        if tabs and tabs.tables:
                            for table in tabs.tables:
                                data = table.extract()
                                if data:
                                    lines = []
                                    for ri, row in enumerate(data):
                                        cells = [str(c).replace('\n', ' ') if c else '' for c in row]
                                        lines.append('| ' + ' | '.join(cells) + ' |')
                                        if ri == 0:
                                            lines.append('| ' + ' | '.join(['---'] * len(cells)) + ' |')
                                    md_lines.append('\n'.join(lines) + '\n')
                    except:
                        pass

                    for block in blocks:
                        if block.get('type') == 1:
                            continue
                        if block.get('type') != 0:
                            continue
                        lines = block.get('lines', [])
                        if not lines:
                            continue
                        spans = lines[0].get('spans', [])
                        if spans:
                            size = spans[0].get('size', 12)
                            text = spans[0].get('text', '').strip()
                            font = spans[0].get('font', '') or ''
                            bold = 'Bold' in font
                            flags = spans[0].get('flags', 0)
                            is_bold = bold or bool(flags & 2)
                            is_short = len(text) < 100 and not text.endswith('.')
                            if size >= 18 and is_short:
                                md_lines.append(f'\n# {text}\n')
                                continue
                            elif size >= 16 and is_short:
                                level = 1 if is_bold else 2
                                md_lines.append(f'\n{"#" * level} {text}\n')
                                continue
                            elif size >= 14 and is_bold and is_short:
                                md_lines.append(f'\n### {text}\n')
                                continue
                            elif size >= 13 and is_bold and is_short and len(text) < 60:
                                md_lines.append(f'\n#### {text}\n')
                                continue

                        para_parts = []
                        for line in lines:
                            for s in line.get('spans', []):
                                t = s.get('text', '')
                                fnt = s.get('font', '') or ''
                                flg = s.get('flags', 0)
                                b = 'Bold' in fnt or bool(flg & 2)
                                i = 'Italic' in fnt or 'Oblique' in fnt or bool(flg & 1)
                                t = re.sub(r'\s+', ' ', t)
                                if b and i:
                                    t = f'***{t}***'
                                elif b:
                                    t = f'**{t}**'
                                elif i:
                                    t = f'*{t}*'
                                para_parts.append(t)
                        if para_parts:
                            text = ' '.join(para_parts).strip()
                            text = re.sub(r'\s+', ' ', text)
                            if text:
                                md_lines.append(f'\n{text}\n')

                doc.close()
                with open(md_path, 'w', encoding='utf-8') as outf:
                    outf.write('\n'.join(md_lines))
                size_kb = os.path.getsize(md_path) / 1024
                converted.append({'pdf': pdf_path, 'md': md_path, 'size_kb': size_kb})
            except Exception as e:
                print(f'    [WARN] Failed to convert {f}: {e}')

    return converted


def cleanup_junk(folder):
    for root, dirs, files in os.walk(folder):
        if '__MACOSX' in dirs:
            shutil.rmtree(os.path.join(root, '__MACOSX'), ignore_errors=True)
        for f in files:
            if f.startswith('._'):
                try:
                    os.remove(os.path.join(root, f))
                except:
                    pass


def process_attachments():
    print('\n--- Phase B2: Post-processing attachments ---')
    total_unzipped = 0
    total_converted = 0

    for entry in os.listdir(ATTACH_DIR):
        folder = os.path.join(ATTACH_DIR, entry)
        if not os.path.isdir(folder):
            continue

        extracted = extract_zips(folder)
        if extracted:
            total_unzipped += len(extracted)
            print(f'  Unzipped {len(extracted)} archive(s) in {entry}')

        converted = convert_pdfs_in_folder(folder)
        if converted:
            total_converted += len(converted)
            for c in converted:
                rel = os.path.relpath(c['md'], folder)
                print(f'  PDF->MD: {rel} ({c["size_kb"]:.0f} KB)')

        cleanup_junk(folder)

    return total_unzipped, total_converted


# ============================================================
#  Batch fetch (Phase B1) — for NEW IDs only
# ============================================================

def fetch_batch(batch_ids):
    tabs = {}

    for vid in batch_ids:
        resp = json.loads(urllib.request.urlopen(
            urllib.request.Request(f'{CDP}/json/new', method='PUT')
        ).read())
        ws = create_connection(resp['webSocketDebuggerUrl'])
        tabs[vid] = ws

        ws.send(json.dumps({'id': 1, 'method': 'Page.navigate',
            'params': {'url': f'https://src.bytedance.net/vul-detail/{vid}'}}))
        json.loads(ws.recv())
        time.sleep(0.3)

    for _ in range(40):
        all_ready = True
        for vid, ws in tabs.items():
            title = js(ws, 'document.title')
            if not title or 'SSO' in title or title == 'about:blank':
                all_ready = False
                break
            body_len = js(ws, 'document.body?document.body.textContent.length:0') or 0
            if body_len < 500:
                all_ready = False
                break
        if all_ready:
            break
        time.sleep(0.5)

    time.sleep(2)

    results = {}
    for vid, ws in tabs.items():
        for attempt in range(3):
            title = js(ws, 'document.title')
            body = js(ws, 'document.body?document.body.textContent.trim().substring(0,8000):""')
            url = js(ws, 'window.location.href')

            if not title or title in ('', 'about:blank'):
                m = re.search(r'标签管理(.+?)(?:待审核|编辑)', body) if body else None
                if m and m.group(1).strip() and m.group(1).strip() != '-':
                    title = m.group(1).strip()[:120]
                else:
                    m2 = re.search(r'漏洞标题(.+?)(?:漏洞类型|漏洞等级)', body, re.DOTALL) if body else None
                    if m2:
                        title = m2.group(1).strip()[:120]

            if title and title != '(unknown)' and len(body) > 500:
                break
            if attempt < 2:
                ws.send(json.dumps({'id': 99, 'method': 'Page.navigate',
                    'params': {'url': f'https://src.bytedance.net/vul-detail/{vid}'}}))
                json.loads(ws.recv())
                time.sleep(3)

        if not title or title in ('', 'about:blank'):
            title = '(unknown)'

        cookie_str = get_cookies(ws)
        attachments = download_attachments(ws, vid, title, cookie_str)

        results[vid] = {
            'id': vid,
            'title': title,
            'url': url or '',
            'body_preview': (body or '')[:3000],
            'attachments': attachments
        }

    for vid, ws in tabs.items():
        try:
            ws.send(json.dumps({'id': 99, 'method': 'Page.close'}))
            json.loads(ws.recv())
        except:
            pass
        ws.close()

    return results


# ============================================================
#  Attachment-only refresh (Phase B1.5) — lighter than full fetch
# ============================================================

def fetch_attachments_only(batch_ids):
    """Open detail pages and extract ONLY attachment links (skip body extraction).
    Returns (results, cookie_str) — attachment URLs dict and cookies for downloading."""

    tabs = {}

    # Open tabs — same as fetch_batch but skip body extraction
    for vid in batch_ids:
        resp = json.loads(urllib.request.urlopen(
            urllib.request.Request(f'{CDP}/json/new', method='PUT')
        ).read())
        ws = create_connection(resp['webSocketDebuggerUrl'])
        tabs[vid] = ws
        ws.send(json.dumps({'id': 1, 'method': 'Page.navigate',
            'params': {'url': f'https://src.bytedance.net/vul-detail/{vid}'}}))
        json.loads(ws.recv())
        time.sleep(0.3)

    # Wait for pages to load (match B1 timeout: 40 × 0.5s = 20s)
    for _ in range(40):
        all_ready = True
        for vid, ws in tabs.items():
            try:
                title = js(ws, 'document.title') or ''
                if not title or 'SSO' in title or title == 'about:blank':
                    all_ready = False
                    break
            except:
                all_ready = False
                break
        if all_ready:
            break
        time.sleep(0.5)

    time.sleep(1.5)

    # Retry any tabs that didn't load properly
    for vid, ws in list(tabs.items()):
        try:
            title = js(ws, 'document.title') or ''
            if not title or 'SSO' in title or title == 'about:blank':
                ws.send(json.dumps({'id': 99, 'method': 'Page.navigate',
                    'params': {'url': f'https://src.bytedance.net/vul-detail/{vid}'}}))
                json.loads(ws.recv())
                time.sleep(3)
        except:
            pass

    # Extract attachment links and cookies (one cookie_str for all, same domain)
    results = {}
    cookie_str = ''
    for vid, ws in tabs.items():
        try:
            if not cookie_str:
                cookie_str = get_cookies(ws)
            captured = js(ws, '''(function() {
                return new Promise(function(resolve) {
                    var result = [];
                    var containers = document.querySelectorAll('[class*="attachment-operation-container"]');
                    if (containers.length === 0) { resolve(result); return; }
                    var origOpen = window.open;
                    var pending = containers.length;
                    containers.forEach(function(container, idx) {
                        var nameEl = container.querySelector('[class*="attachment-name"]');
                        var filename = nameEl ? nameEl.textContent.trim() : ('attachment_' + idx);
                        window.open = function(url) {
                            result.push({filename: filename, url: url});
                            pending--;
                            if (pending === 0) { window.open = origOpen; resolve(result); }
                            return null;
                        };
                        container.click();
                    });
                    setTimeout(function() { window.open = origOpen; resolve(result); }, 3000);
                });
            })()''', await_promise=True)

            if captured:
                for att in captured:
                    att['url'] = 'https://src.bytedance.net' + att['url']
                results[vid] = captured
        except Exception as e:
            print(f'    [!] {vid}: attachment check error: {e}')

    # Close tabs
    for vid, ws in tabs.items():
        try:
            ws.send(json.dumps({'id': 99, 'method': 'Page.close'}))
            json.loads(ws.recv())
        except:
            pass
        ws.close()

    return results, cookie_str


# ============================================================
#  Main
# ============================================================

# --- Phase B0: Cache sync ---
print('--- Phase B0: Cache sync ---')
new_ids, stale_ids, cached_results = sync_cache(current_ids, all_src_ids)

if stale_ids:
    deleted = delete_stale_data(stale_ids)
    print(f'  Deleted {len(stale_ids)} stale entries: {stale_ids}')
    for d in deleted:
        print(f'    Removed: {d}')

if cached_results:
    print(f'  Cached (skip): {len(cached_results)} IDs — {sorted(cached_results.keys())}')

if new_ids:
    print(f'  New (fetch):   {len(new_ids)} IDs — {new_ids}')
else:
    print(f'  New (fetch):   0 IDs — nothing to fetch')

# --- Phase B1: Fetch new IDs ---
all_results = dict(cached_results)  # start with cached

if new_ids:
    batches = [new_ids[i:i+BATCH_SIZE] for i in range(0, len(new_ids), BATCH_SIZE)]
    for i, batch in enumerate(batches):
        print(f'\n=== Fetch batch {i+1}/{len(batches)}: {batch} ===')
        results = fetch_batch(batch)
        all_results.update(results)
        for vid, r in sorted(results.items()):
            status = 'OK' if r['title'] and r['title'] != '(unknown)' else 'NO_TITLE'
            n_attach = len(r.get('attachments', []))
            attach_str = f' | {n_attach} attachments' if n_attach > 0 else ''
            print(f'  [{status}] {vid}: {r["title"][:60]}{attach_str}')
        time.sleep(1)
else:
    print('\n  (no fetching needed)')

# --- Phase B1.5: Refresh attachments for cached IDs ---
cache = load_cache()  # ensure cache is loaded for B1.5 reference
ATTACH_REFRESH_COOLDOWN_H = 4  # don't re-check attachments within 4 hours
now_ts = datetime.now().timestamp()

if cached_results:
    # Determine which cached IDs need attachment re-check
    recheck_ids = []
    for vid in sorted(cached_results.keys()):
        entry = cache.get(vid, {})
        last_check = entry.get('attachments_checked_at')
        # Re-check if: never checked, or cooldown passed
        if not last_check or (now_ts - last_check) > ATTACH_REFRESH_COOLDOWN_H * 3600:
            recheck_ids.append(vid)

    if recheck_ids:
        print(f'\n--- Phase B1.5: Attachment refresh for {len(recheck_ids)} cached IDs ---')
        batches = [recheck_ids[i:i+BATCH_SIZE] for i in range(0, len(recheck_ids), BATCH_SIZE)]
        new_attach_total = 0
        for i, batch in enumerate(batches):
            print(f'  Refresh batch {i+1}/{len(batches)}: {batch}')
            refreshed, cookie_str = fetch_attachments_only(batch)
            for vid, new_atts in refreshed.items():
                if new_atts:
                    existing = all_results.get(vid, {}).get('attachments', [])
                    existing_names = {a['filename'] for a in existing}
                    fresh = [a for a in new_atts if a['filename'] not in existing_names]
                    if fresh:
                        # Download new attachments
                        safe_title = re.sub(r'[<>:"/\\|?*]', '_', all_results[vid]["title"])[:80]
                        folder = os.path.join(ATTACH_DIR, f'{vid}_{safe_title}')
                        os.makedirs(folder, exist_ok=True)
                        for att in fresh:
                            full_url = att['url']
                            try:
                                req = urllib.request.Request(full_url, headers={'Cookie': cookie_str})
                                data = urllib.request.urlopen(req, timeout=30).read()
                                filepath = os.path.join(folder, att['filename'])
                                with open(filepath, 'wb') as f:
                                    f.write(data)
                                att['local_path'] = filepath
                                att['size'] = len(data)
                            except Exception as e:
                                att['error'] = str(e)[:200]
                        new_attach_total += len(fresh)
                        if vid in all_results:
                            all_results[vid].setdefault('attachments', []).extend(fresh)
                        print(f'    [{vid}] +{len(fresh)} new attachments')
                # Update last check timestamp regardless
                if vid in cache:
                    cache[vid]['attachments_checked_at'] = now_ts
                    cache[vid]['attachment_names'] = [
                        a['filename'] for a in all_results.get(vid, {}).get('attachments', [])
                    ]
            time.sleep(1)
        # Save cache after B1.5 so B3 doesn't lose B1.5 metadata
        save_cache(cache)
        if new_attach_total == 0:
            print(f'  No new attachments found')
        else:
            print(f'  Total new attachments: {new_attach_total}')
    else:
        print(f'\n--- Phase B1.5: Attachment refresh skipped (all within {ATTACH_REFRESH_COOLDOWN_H}h cooldown) ---')

# --- Phase B2: Post-process attachments ---
n_unzipped, n_converted = process_attachments()

# --- Phase B3: Update cache ---
cache = load_cache()
now = datetime.now().isoformat(timespec='seconds')

# Remove stale entries
for vid in stale_ids:
    cache.pop(vid, None)

# Upsert current entries (preserve existing reproduced flag + B1.5 metadata)
for vid, r in all_results.items():
    prev = cache.get(vid, {})
    cache[vid] = {
        'title': r['title'],
        'url': r.get('url', ''),
        'fetched_at': now,
        'has_attachments': len(r.get('attachments', [])) > 0,
        'body_size': len(r.get('body_preview', ''))
    }
    # Preserve reproduced flag if already set
    if prev.get('reproduced'):
        cache[vid]['reproduced'] = True
    # Preserve B1.5 attachment tracking fields
    if prev.get('attachments_checked_at'):
        cache[vid]['attachments_checked_at'] = prev['attachments_checked_at']
    if prev.get('attachment_names'):
        cache[vid]['attachment_names'] = prev['attachment_names']
save_cache(cache)

# Save details
with open(DETAILS_FILE, 'w') as f:
    json.dump(all_results, f, ensure_ascii=False, indent=2)

# --- Summary ---
new_count = len(new_ids)
cached_count = len(cached_results)
stale_count = len(stale_ids)
total_attachments = sum(len(r.get('attachments', [])) for r in all_results.values())
total_size = sum(
    sum(a.get('size', 0) for a in r.get('attachments', []))
    for r in all_results.values()
)
ok = sum(1 for r in all_results.values() if r['title'] and r['title'] != '(unknown)')

print(f'\n{"="*60}')
print(f'Phase B0 - Cache sync:     {stale_count} deleted, {cached_count} cached, {new_count} new')
print(f'Phase B1 - Fetch:          {ok}/{len(all_results)} details, {total_attachments} attachments ({total_size/1024:.0f} KB)')
print(f'Phase B2 - Post-process:   {n_unzipped} unzipped, {n_converted} PDFs converted')
print(f'Phase B3 - Cache updated:  {len(cache)} entries in {CACHE_FILE}')
print(f'Saved to {ATTACH_DIR}/')
print(f'Details: {DETAILS_FILE}')
