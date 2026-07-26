export const meta = {
  name: 'src-phase-c-reproduce',
  description: 'Phase C: Analyze and reproduce SRC vulnerabilities. C1 filters hard-params, C2 filters click-heavy, C3 dispatches reproduction agents.',
  phases: [
    { title: 'C1: Hard Params Filter', detail: 'Filter vulnerabilities requiring unguessable parameters' },
    { title: 'C2: Click-Heavy Filter', detail: 'Filter vulnerabilities requiring heavy UI interaction' },
    { title: 'C3: Reproduction', detail: 'Dispatch per-vulnerability reproduction agents' },
    { title: 'Update State', detail: 'Write excluded.json and update cache.json via agent' }
  ]
}

// IDs come from args
var allIds = (args && Array.isArray(args)) ? args.map(String) : []
if (allIds.length === 0) {
  log('ERROR: No IDs provided via args')
  throw new Error('No IDs to process')
}

log('Phase C: ' + allIds.length + ' IDs — ' + JSON.stringify(allIds))

// --- Schemas ---
var SCHEMA_C12 = {
  type: 'object',
  properties: {
    passed: { type: 'array', items: { type: 'string' } },
    excluded: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, reason: { type: 'string' } }, required: ['id', 'reason'] } }
  },
  required: ['passed', 'excluded']
}

var SCHEMA_REPRO = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    status: { type: 'string', enum: ['SUCCESS', 'FAILED', 'BLOCKED'] },
    evidence: { type: 'string' },
    poc_command: { type: 'string' },
    risk_assessment: { type: 'string' },
    notes: { type: 'string' }
  },
  required: ['id', 'status', 'evidence', 'poc_command']
}

// ============================================================
// C1: Hard Parameters Filter
// ============================================================
phase('C1: Hard Params Filter')

var c1Prompt = '你是安全漏洞分析专家。筛选出利用需要"纯随机不可枚举参数"的漏洞。\n\n' +
  '筛掉条件（全部满足）:\n' +
  '1. 参数纯随机生成 (上传返回链接 / 32位token / 随机序列号 / 一次性校验码)\n' +
  '2. 不可枚举/不可爆破，只能靠受害者主动泄露\n' +
  '3. 参数没有窃取价值 (不像 AK/SK/密码)\n\n' +
  '不筛: AK/SK/cookie/密码 (有窃取价值) | 可枚举ID | 公开参数\n\n' +
  '读取 /tmp/src_details.json 中以下 IDs 的 body_preview。\n' +
  '同时检查 /tmp/src_cache.json — 跳过已 reproduced=true 的ID（不处理，归入 passed）。\n' +
  '判断每个未复现的漏洞。返回 {passed, excluded}。\n\n' +
  'IDs: ' + JSON.stringify(allIds)

var c1Result = await agent(c1Prompt, { label: 'c1-hard-params', schema: SCHEMA_C12 })
if (!c1Result) { c1Result = { passed: allIds, excluded: [] } }
log('C1: ' + c1Result.passed.length + ' passed, ' + c1Result.excluded.length + ' excluded')

// ============================================================
// C2: Click-Heavy Filter
// ============================================================
phase('C2: Click-Heavy Filter')

var c2Input = c1Result.passed
var c2Result = { passed: [], excluded: [] }

if (c2Input.length > 0) {
  var c2Prompt = '你是安全漏洞分析专家。筛选出需要大量 UI 点击操作才能复现的漏洞。\n\n' +
    '筛掉 (任一):\n' +
    '1. 需开通/购买服务→创建资源→等待→复杂配置\n' +
    '2. 跨3+页面操作\n' +
    '3. 需创建IAM子用户/切换账号\n' +
    '4. 需等待审批或后台任务\n' +
    '5. 复杂表单(5+字段,非单API可替代)\n\n' +
    '不筛: 直接POST API | 1-2点击 | 访问已有页面无需创建资源\n\n' +
    '读取 /tmp/src_details.json 中以下 IDs 的 body_preview。\n' +
    '同时检查 /tmp/src_cache.json — 跳过已 reproduced=true 的ID。\n' +
    '判断每个未复现的漏洞。返回 {passed, excluded}。\n\n' +
    'IDs: ' + JSON.stringify(c2Input)

  c2Result = await agent(c2Prompt, { label: 'c2-click-heavy', schema: SCHEMA_C12 })
  if (!c2Result) { c2Result = { passed: c2Input, excluded: [] } }
}

log('C2: ' + c2Result.passed.length + ' passed, ' + c2Result.excluded.length + ' excluded')

// ============================================================
// C3: Reproduction
// ============================================================
phase('C3: Reproduction')

var c3Input = c2Result.passed
var c3Results = []

if (c3Input.length === 0) {
  log('C3: No IDs (all filtered)')
} else {
  log('Dispatching ' + c3Input.length + ' agents...')

  try {
    c3Results = await pipeline(
      c3Input,
      function(vid) {
        return agent(
          '复现漏洞 ' + vid + '。操作约束。\n' +
          '1. 读 /tmp/src_details.json ID=' + vid + ' 的 body_preview\n' +
          '2. 读 /tmp/src_attachments/ 下该漏洞 .md (如有)\n' +
          '3. 优先用已有PoC，无则自行生成\n' +
          '4. 允许: 读操作 + 非破坏性写入 + 他人数据最小验证修改(不改配置) + 验证性RCE/逃逸/提权(whoami/id/hostname即可)\n' +
          '5. 禁止: DELETE/DROP/TRUNCATE + 覆盖他人配置/核心数据 + 验证后进一步利用\n' +
          '6. SQLi: 可SELECT+INSERT无害标记, 禁UPDATE/DELETE他人行\n' +
          '7. SSRF: 验证用icanhazip.com/httpbin.org, 内网可达即止\n' +
          '8. Cookie在/tmp/volc_cookies.txt, CSRF在/tmp/volc_csrf.txt\n' +
          '返回: {id, status, evidence, poc_command, risk_assessment, notes}',
          { label: 'repro-' + vid, schema: SCHEMA_REPRO }
        )
      }
    )
  } catch (e) {
    log('C3 pipeline error (continuing with partial results): ' + (e.message || e))
    c3Results = []
  }
}

// ============================================================
// Update State
// ============================================================
phase('Update State')

var c1Excluded = c1Result.excluded
var c2Excluded = c2Result.excluded
var reproSuccess = c3Results ? c3Results.filter(Boolean).filter(function(r) { return r.status === 'SUCCESS' }).map(function(r) { return r.id }) : []

var ts = new Date().toISOString().replace('T', ' ').substring(0, 19)
var statePrompt = '用 Bash 执行以下 python3 命令更新 JSON 文件。**只执行，不要修改代码。**\n\n' +
  'python3 -c "\n' +
  'import json\n' +
  'from datetime import datetime\n' +
  'now = datetime.now().isoformat(timespec=\"seconds\")\n' +
  '\n' +
  '# 1. Update /tmp/src_excluded.json\n' +
  'with open(\"/tmp/src_excluded.json\") as f:\n' +
  '    exc = json.load(f)\n' +
  'c1_items = ' + JSON.stringify(c1Excluded) + '\n' +
  'c2_items = ' + JSON.stringify(c2Excluded) + '\n' +
  'for item in c1_items:\n' +
  '    exc.setdefault(\"hard_params\", {})[item[\"id\"]] = {\"reason\": item[\"reason\"], \"excluded_at\": now}\n' +
  'for item in c2_items:\n' +
  '    exc.setdefault(\"click_heavy\", {})[item[\"id\"]] = {\"reason\": item[\"reason\"], \"excluded_at\": now}\n' +
  'with open(\"/tmp/src_excluded.json\", \"w\") as f:\n' +
  '    json.dump(exc, f, ensure_ascii=False, indent=2)\n' +
  '\n' +
  '# 2. Update /tmp/src_cache.json\n' +
  'with open(\"/tmp/src_cache.json\") as f:\n' +
  '    cache = json.load(f)\n' +
  'repro_ids = ' + JSON.stringify(reproSuccess) + '\n' +
  'for vid in repro_ids:\n' +
  '    if vid in cache:\n' +
  '        cache[vid][\"reproduced\"] = True\n' +
  'with open(\"/tmp/src_cache.json\", \"w\") as f:\n' +
  '    json.dump(cache, f, ensure_ascii=False, indent=2)\n' +
  '\n' +
  'print(f\"excluded.json: +{len(c1_items)} hard_params, +{len(c2_items)} click_heavy\")\n' +
  'print(f\"cache.json: +{len(repro_ids)} reproduced\")\n' +
  '"'

await agent(statePrompt, { label: 'update-state' })

// --- Final Summary ---
var succeeded = c3Results ? c3Results.filter(Boolean).filter(function(r) { return r.status === 'SUCCESS' }) : []
var failed = c3Results ? c3Results.filter(Boolean).filter(function(r) { return r.status === 'FAILED' }) : []
var blocked = c3Results ? c3Results.filter(Boolean).filter(function(r) { return r.status === 'BLOCKED' }) : []

log('')
log('========================================')
log('  Phase C Complete')
log('  C1 excluded: ' + c1Excluded.length + '  C2 excluded: ' + c2Excluded.length)
log('  C3 SUCCESS: ' + succeeded.length + '  FAILED: ' + failed.length + '  BLOCKED: ' + blocked.length)
log('========================================')

for (var i = 0; i < succeeded.length; i++) {
  log('SUCCESS [' + succeeded[i].id + ']: ' + (succeeded[i].evidence || '').substring(0, 150))
}
for (var j = 0; j < failed.length; j++) {
  log('FAILED [' + failed[j].id + ']: ' + (failed[j].notes || ''))
}
for (var k = 0; k < blocked.length; k++) {
  log('BLOCKED [' + blocked[k].id + ']: ' + (blocked[k].notes || ''))
}

return {
  c1: { passed: c1Result.passed.length, excluded: c1Excluded.length },
  c2: { passed: c2Result.passed.length, excluded: c2Excluded.length },
  c3: { succeeded: succeeded.length, failed: failed.length, blocked: blocked.length },
  succeeded: succeeded, failed: failed, blocked: blocked
}
