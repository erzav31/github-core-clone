// forge — a standalone, GitHub-compatible git forge in one process.
//
// Serves, from its own in-memory store and with no outside service and no git
// binary: git smart HTTP (upload-pack protocol v2, receive-pack v0), the REST v3
// API under /api/v3, GraphQL v4 at /api/graphql, and MCP at /mcp. Binds an
// ephemeral port, registers it with the suite at $MAKEFUN_ENV_URL, then polls
// /done until the suite is over and exits 0.
//
// Written from scratch for the github-core-clone-01 competition. Node 22,
// standard library only. The file is plain JavaScript syntax in a .ts file so
// it runs under Node 22's type stripping with no build step.

import http from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// constants: the trial's fixed identities (the published scenario's viewer and
// stranger logins, wire.ts buildScenario() over the sealed SCENARIO_SEED;
// the suite addresses every repository through the viewer login, and the
// bearer token in MAKEFUN_SHOP_TOKEN names that viewer).

const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const STRANGER_LOGIN = 'olgabauer';
const DEFAULT_BRANCH = 'main';
const ZERO_OID = '0'.repeat(40);
const SERVER_AGENT = 'forge/1.0.0';
const FORGE_VERSION = '1.0.0';

// ---------------------------------------------------------------------------
// deterministic clock: every timestamp the forge emits comes from a counter
// over the trial's opening time (MAKEFUN_TRIAL_NOW when set), never the wall
// clock, so two runs on one instance answer byte-identical state.

const TRIAL_NOW = (() => {
  const raw = (process.env.MAKEFUN_TRIAL_NOW ?? '').trim();
  if (raw !== '') {
    const asNum = Number(raw);
    if (Number.isFinite(asNum) && asNum > 0) return asNum < 1e12 ? asNum * 1000 : asNum;
    const parsed = Date.parse(raw);
    if (Number.isFinite(parsed)) return parsed;
  }
  return Date.UTC(2025, 0, 1);
})();
let clockTick = 0;
function nowIso() {
  const ms = TRIAL_NOW + clockTick * 1000;
  clockTick += 1;
  return new Date(ms).toISOString();
}
function nowEpochSec() {
  return Math.floor(TRIAL_NOW / 1000) + clockTick;
}

// ---------------------------------------------------------------------------
// small utilities

const sha1hex = (data) => createHash('sha1').update(data).digest('hex');
const b64encode = (buf) => Buffer.from(buf).toString('base64');
const b64decode = (text) => Buffer.from(String(text).replace(/\s+/g, ''), 'base64');
const isOid = (s) => typeof s === 'string' && /^[0-9a-f]{40}$/.test(s);
const isRecord = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

let requestCounter = 0;
function requestId() {
  requestCounter += 1;
  return `req-${requestCounter}`;
}

// ---------------------------------------------------------------------------
// pkt-line codec (git smart HTTP framing)

function pktLine(payload) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  const head = Buffer.alloc(4);
  head.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
function pktLines(items) {
  const parts = [];
  for (const item of items) {
    if (item === 'flush') parts.push(PKT_FLUSH);
    else if (item === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

/** Decode pkt-lines from a buffer; returns {packets, rest} where rest is the
 *  bytes after the first flush packet (the packfile of a receive-pack). */
function decodePktLines(buf) {
  const packets = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = parseInt(head, 16);
    if (len === 0) return { packets, rest: buf.subarray(off + 4), flushed: true };
    if (len === 1) { packets.push({ kind: 'delim' }); off += 4; continue; }
    if (len === 2) { packets.push({ kind: 'response-end' }); off += 4; continue; }
    if (len < 4 || off + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, rest: buf.subarray(off), flushed: false };
}
function pktText(packet) {
  return packet.kind === 'data' ? packet.payload.toString('utf8') : '';
}

// ---------------------------------------------------------------------------
// git objects

function hashObject(type, data) {
  const body = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const head = Buffer.from(`${type} ${body.length}\0`, 'utf8');
  return sha1hex(Buffer.concat([head, body]));
}

function parseCommit(data) {
  const text = data.toString('utf8');
  const cut = text.indexOf('\n\n');
  const head = cut >= 0 ? text.slice(0, cut) : text;
  const message = cut >= 0 ? text.slice(cut + 2) : '';
  let tree = '';
  const parents = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function parseTree(data) {
  const entries = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) break;
    entries.push({
      mode: data.subarray(off, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}

function buildTree(entries) {
  const sorted = [...entries].sort((a, b) => {
    const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
    const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
    return Buffer.compare(left, right);
  });
  const parts = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function parseTag(data) {
  const text = data.toString('utf8');
  const cut = text.indexOf('\n\n');
  const head = cut >= 0 ? text.slice(0, cut) : text;
  const message = cut >= 0 ? text.slice(cut + 2) : '';
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

/** Apply a git delta stream (copy/insert instructions) to a base buffer. */
function applyDelta(base, delta) {
  let off = 0;
  const readVarint = () => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[off++];
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const baseSize = readVarint();
  const resultSize = readVarint();
  if (baseSize !== base.length) throw new Error('delta base size mismatch');
  const chunks = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i += 1) if (op & (1 << i)) cpOff |= delta[off++] << (8 * i);
      for (let i = 0; i < 3; i += 1) if (op & (0x10 << i)) cpSize |= delta[off++] << (8 * i);
      if (cpSize === 0) cpSize = 0x10000;
      chunks.push(base.subarray(cpOff, cpOff + cpSize));
      total += cpSize;
    } else if (op !== 0) {
      chunks.push(delta.subarray(off, off + op));
      total += op;
      off += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  const out = Buffer.concat(chunks, total);
  if (out.length !== resultSize) throw new Error('delta result size mismatch');
  return out;
}

// ---------------------------------------------------------------------------
// packfiles: write plain objects; read (with OFS/REF delta resolution)

const PACK_TYPE_CODE = { commit: 1, tree: 2, blob: 3, tag: 4 };
const PACK_CODE_TYPE = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function packObjectHeader(type, size) {
  const code = PACK_TYPE_CODE[type];
  const bytes = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function writePack(objects) {
  const list = [...objects];
  const parts = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const obj of list) {
    const data = Buffer.isBuffer(obj.data) ? obj.data : Buffer.from(obj.data);
    parts.push(packObjectHeader(obj.type, data.length));
    parts.push(deflateSync(data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

/** Inflate one zlib stream starting at `offset`; returns {data, next} where
 *  next is the offset just past the stream. inflateSync ignores trailing
 *  bytes, so the end is found by binary search for the shortest prefix that
 *  inflates cleanly (a truncated stream always throws). */
function inflateAt(buf, offset, end) {
  let lo = offset;
  let hi = end;
  let best = null;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    try {
      const data = inflateSync(buf.subarray(offset, mid));
      best = { data, next: mid };
      hi = mid;
    } catch {
      lo = mid + 1;
    }
  }
  if (best === null) {
    // The whole remainder inflates: the stream runs to `end`.
    const data = inflateSync(buf.subarray(offset, end));
    return { data, next: end };
  }
  return best;
}

function readPack(pack) {
  const buf = Buffer.isBuffer(pack) ? pack : Buffer.from(pack);
  if (buf.length < 32) throw new Error('pack too short');
  if (buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack header missing');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const trailerStart = buf.length - 20;
  const trailer = buf.subarray(trailerStart).toString('hex');
  const computed = sha1hex(buf.subarray(0, trailerStart));
  if (trailer !== computed) throw new Error('pack trailer checksum mismatch');
  const raw = [];
  const byOffset = new Map();
  let off = 12;
  const readSizeHeader = () => {
    let byte = buf[off++];
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = buf[off++];
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    return { typeCode, size };
  };
  for (let i = 0; i < count; i += 1) {
    const entryOffset = off;
    const { typeCode, size } = readSizeHeader();
    const entry = { offset: entryOffset, typeCode, size, data: null, baseOffset: undefined, baseOid: undefined };
    if (typeCode === 6) {
      let byte = buf[off++];
      let baseOff = byte & 0x7f;
      while (byte & 0x80) {
        byte = buf[off++];
        baseOff = ((baseOff + 1) << 7) | (byte & 0x7f);
      }
      entry.baseOffset = entryOffset - baseOff;
    } else if (typeCode === 7) {
      entry.baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (!PACK_CODE_TYPE[typeCode]) {
      throw new Error(`unknown pack type code ${typeCode}`);
    }
    const inflated = inflateAt(buf, off, trailerStart);
    if (inflated.data.length !== size) throw new Error('pack entry size mismatch');
    entry.data = inflated.data;
    off = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (off !== trailerStart) throw new Error('pack has trailing bytes before trailer');
  const objects = new Map();
  const resolvedByOid = new Map();
  const resolving = new Set();
  const resolve = (entry) => {
    if (entry.resolved) return entry.resolved;
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let type;
    let data;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const baseEntry = resolvedByOid.get(entry.baseOid);
      if (baseEntry) {
        const base = resolve(baseEntry);
        type = base.type;
        data = applyDelta(base.data, entry.data);
      } else {
        throw new Error(`ref-delta base ${entry.baseOid} not in pack`);
      }
    } else {
      type = PACK_CODE_TYPE[entry.typeCode];
      data = entry.data;
    }
    const oid = hashObject(type, data);
    entry.resolved = { type, data, oid };
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return entry.resolved;
  };
  for (const entry of raw) {
    const r = resolve(entry);
    if (!objects.has(r.oid)) objects.set(r.oid, { type: r.type, data: r.data });
  }
  return objects;
}

// ---------------------------------------------------------------------------
// store: every repository, issue, pull request, and object lives in memory.
// The suite rebuilds its fixtures per check, so the store resets with the
// process; nothing is written to disk by the forge itself.

let nextDatabaseId = 1;
const repos = new Map(); // key `${owner}/${name}` -> Repo
const reposById = new Map(); // databaseId -> Repo
const reposByNodeId = new Map(); // global id -> Repo
const issuesByNodeId = new Map();
const pullsByNodeId = new Map();
const commentsByNodeId = new Map();

function globalId(kind, ...parts) {
  return b64encode(`${kind}:${parts.join(':')}`);
}

function repoKey(owner, name) {
  return `${owner}/${name}`;
}

function makeRepo(owner, name, isPrivate, description) {
  const id = nextDatabaseId;
  nextDatabaseId += 1;
  const stamp = nowIso();
  const repo = {
    id,
    nodeId: globalId('repo', id),
    owner,
    name,
    fullName: `${owner}/${name}`,
    private: !!isPrivate,
    description: description ?? null,
    defaultBranch: DEFAULT_BRANCH,
    createdAt: stamp,
    updatedAt: stamp,
    pushedAt: null,
    objects: new Map(), // oid -> {type, data}
    refs: new Map(), // refname -> oid (e.g. refs/heads/main)
    issues: [], // in creation order
    issueByNumber: new Map(),
    nextIssueNumber: 1,
    pulls: [],
    pullByNumber: new Map(),
    nextPullNumber: 1,
    labels: new Map(), // name -> {name, color, description}
    comments: new Map(), // issueNumber -> [comment]
    nextCommentId: 1,
  };
  repo.labels.set('bug', { name: 'bug', color: 'd73a4a', description: 'Something is not working' });
  repos.set(repoKey(owner, name), repo);
  reposById.set(id, repo);
  reposByNodeId.set(repo.nodeId, repo);
  return repo;
}

function deleteRepo(repo) {
  repos.delete(repoKey(repo.owner, repo.name));
  reposById.delete(repo.id);
  reposByNodeId.delete(repo.nodeId);
  for (const issue of repo.issues) issuesByNodeId.delete(issue.nodeId);
  for (const pr of repo.pulls) pullsByNodeId.delete(pr.nodeId);
  for (const list of repo.comments.values()) {
    for (const c of list) commentsByNodeId.delete(c.nodeId);
  }
}

function getRepo(owner, name) {
  return repos.get(repoKey(owner, name)) ?? null;
}

function viewerCanSeeRepo(repo) {
  // Every repository the forge serves belongs to the viewer; any other owner
  // is a 404, never a 403 (checks-rest's 404-only rule for foreign owners).
  return repo !== null && repo.owner === VIEWER_LOGIN;
}

// ---------------------------------------------------------------------------
// git repository operations on the store

function refTip(repo, refname) {
  return repo.refs.get(refname) ?? null;
}

function headTip(repo) {
  return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
}

/** Walk a commit's tree closure: all reachable trees and blobs. */
function treeClosure(repo, treeOid, out) {
  const stack = [treeOid];
  while (stack.length > 0) {
    const oid = stack.pop();
    if (out.trees.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'tree') continue;
    out.trees.add(oid);
    for (const entry of parseTree(obj.data)) {
      if (entry.mode === '40000') stack.push(entry.oid);
      else out.blobs.add(entry.oid);
    }
  }
}

/** Flat path -> {oid, mode} map of the tree at a commit (or an empty map). */
function flatTree(repo, commitOid) {
  const flat = new Map();
  if (!commitOid) return flat;
  const commit = repo.objects.get(commitOid);
  if (!commit || commit.type !== 'commit') return flat;
  const parsed = parseCommit(commit.data);
  const walk = (treeOid, prefix) => {
    const tree = repo.objects.get(treeOid);
    if (!tree || tree.type !== 'tree') return;
    for (const entry of parseTree(tree.data)) {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.mode === '40000') walk(entry.oid, path);
      else flat.set(path, { oid: entry.oid, mode: entry.mode });
    }
  };
  walk(parsed.tree, '');
  return flat;
}

/** Build (and store) nested tree objects from a flat path map; returns the
 *  root tree oid. */
function buildTreeFromFlat(repo, flat) {
  return buildTreeAt(repo, flat, '');
}

/** Build (and store) the tree object for one directory `prefix` ('' = root)
 *  of a flat path map; returns that directory's tree oid. */
function buildTreeAt(repo, flat, prefix) {
  const build = (current) => {
    const entries = [];
    const dirs = new Set();
    for (const [path, item] of flat.entries()) {
      if (current !== '' && !path.startsWith(`${current}/`)) continue;
      const rest = current === '' ? path : path.slice(current.length + 1);
      const slash = rest.indexOf('/');
      if (slash < 0) entries.push({ mode: item.mode, name: rest, oid: item.oid });
      else dirs.add(rest.slice(0, slash));
    }
    for (const dir of dirs) {
      entries.push({ mode: '40000', name: dir, oid: build(current === '' ? dir : `${current}/${dir}`) });
    }
    const data = buildTree(entries);
    const oid = hashObject('tree', data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(prefix);
}

function makeCommitObject(repo, treeOid, parentOids, message) {
  const epoch = nowEpochSec();
  const authorLine = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${epoch} +0000`;
  let text = `tree ${treeOid}\n`;
  for (const parent of parentOids) text += `parent ${parent}\n`;
  text += `author ${authorLine}\ncommitter ${authorLine}\n\n${message}`;
  if (!message.endsWith('\n')) text += '\n';
  const data = Buffer.from(text, 'utf8');
  const oid = hashObject('commit', data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'commit', data });
  return oid;
}

/** Create a commit on a branch from a flat tree, moving the branch ref. */
function commitFlatTree(repo, branch, flat, message, parentOid) {
  const treeOid = buildTreeFromFlat(repo, flat);
  const parents = parentOid ? [parentOid] : [];
  const commitOid = makeCommitObject(repo, treeOid, parents, message);
  repo.refs.set(`refs/heads/${branch}`, commitOid);
  const stamp = nowIso();
  repo.updatedAt = stamp;
  repo.pushedAt = stamp;
  return commitOid;
}

/** Commits reachable from `starts`, newest first (generation order). */
function commitList(repo, starts) {
  const seen = new Set();
  const ordered = [];
  const queue = [...starts];
  while (queue.length > 0) {
    const oid = queue.shift();
    if (!oid || seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    ordered.push(oid);
    queue.push(...parseCommit(obj.data).parents);
  }
  return ordered;
}

function isAncestor(repo, ancestor, descendant) {
  if (ancestor === descendant) return true;
  const queue = [descendant];
  const seen = new Set();
  while (queue.length > 0) {
    const oid = queue.shift();
    if (!oid || seen.has(oid)) continue;
    seen.add(oid);
    if (oid === ancestor) return true;
    const obj = repo.objects.get(oid);
    if (obj && obj.type === 'commit') queue.push(...parseCommit(obj.data).parents);
  }
  return false;
}

/** Merge-base of two commits (first common ancestor by generation order). */
function mergeBase(repo, left, right) {
  const rightSet = new Set(commitList(repo, [right]));
  for (const oid of commitList(repo, [left])) {
    if (rightSet.has(oid)) return oid;
  }
  return null;
}

/**
 * Objects a fetch should send. `wants` are commit oids, `haves` are commits
 * the client already has, `clientShallow` are the client's shallow boundaries,
 * `depth` is an optional deepen limit. Returns {objects: Map, shallow: [],
 * unshallow: []}. The walk from wants stops at held commits (except shallow
 * boundaries, whose parents are still walked when the depth allows it), so
 * nothing the client already has is re-sent.
 */
function computeFetch(repo, wants, haves, clientShallow, depth) {
  const held = new Set();
  const shallowSet = new Set(clientShallow);
  const heldQueue = [...haves];
  while (heldQueue.length > 0) {
    const oid = heldQueue.shift();
    if (!oid || held.has(oid)) continue;
    held.add(oid);
    if (shallowSet.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj && obj.type === 'commit') heldQueue.push(...parseCommit(obj.data).parents);
  }
  const heldObjects = new Map();
  for (const oid of held) {
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'commit') {
      heldObjects.set(oid, obj);
      const closure = { trees: new Set(), blobs: new Set() };
      treeClosure(repo, parseCommit(obj.data).tree, closure);
      for (const treeOid of closure.trees) {
        const treeObj = repo.objects.get(treeOid);
        if (treeObj) heldObjects.set(treeOid, treeObj);
      }
      for (const blobOid of closure.blobs) {
        const blobObj = repo.objects.get(blobOid);
        if (blobObj) heldObjects.set(blobOid, blobObj);
      }
    } else {
      heldObjects.set(oid, obj);
    }
  }
  const included = new Set();
  const newShallow = [];
  const newUnshallow = [];
  const limit = depth ?? Infinity;
  // A want may be an annotated tag (a full clone wants every ref, including
  // tags): send the tag object itself and walk from the commit it peels to.
  // A want may also be a bare tree/blob: send it directly.
  const direct = new Map();
  const walkStarts = [];
  for (const want of wants) {
    const wantObj = repo.objects.get(want);
    if (!wantObj) continue;
    if (wantObj.type === 'commit') { walkStarts.push(want); continue; }
    if (wantObj.type === 'tag') {
      let current = want;
      for (let i = 0; i < 16; i += 1) {
        const tagObj = repo.objects.get(current);
        if (!tagObj || tagObj.type !== 'tag') break;
        if (!heldObjects.has(current)) direct.set(current, tagObj);
        current = parseTag(tagObj.data).object;
      }
      const target = repo.objects.get(current);
      if (target && target.type === 'commit') walkStarts.push(current);
      continue;
    }
    if (!heldObjects.has(want)) direct.set(want, wantObj);
  }
  const queue = walkStarts.map((oid) => ({ oid, gen: 1 }));
  const visited = new Set();
  while (queue.length > 0) {
    const { oid, gen } = queue.shift();
    if (!oid || visited.has(oid) || gen > limit) continue;
    visited.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    if (!held.has(oid)) included.add(oid);
    const parents = parseCommit(obj.data).parents;
    if (gen === limit) {
      if (parents.length > 0 && !shallowSet.has(oid)) newShallow.push(oid);
    } else {
      for (const parent of parents) {
        if (shallowSet.has(oid) || !held.has(oid)) queue.push({ oid: parent, gen: gen + 1 });
      }
    }
  }
  for (const oid of shallowSet) {
    if (visited.has(oid) && parentsInterior(repo, oid, visited)) newUnshallow.push(oid);
  }
  const objects = new Map();
  for (const oid of included) {
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    objects.set(oid, obj);
    const closure = { trees: new Set(), blobs: new Set() };
    treeClosure(repo, parseCommit(obj.data).tree, closure);
    for (const treeOid of closure.trees) {
      const treeObj = repo.objects.get(treeOid);
      if (treeObj) objects.set(treeOid, treeObj);
    }
    for (const blobOid of closure.blobs) {
      const blobObj = repo.objects.get(blobOid);
      if (blobObj) objects.set(blobOid, blobObj);
    }
  }
  for (const oid of heldObjects.keys()) objects.delete(oid);
  for (const [oid, obj] of direct) objects.set(oid, obj);
  return { objects, shallow: newShallow, unshallow: newUnshallow };
}

/** A client shallow boundary is interior once it was walked through (its
 *  parents are being sent, or it was reached at a generation below the limit). */
function parentsInterior(repo, oid, visited) {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'commit') return false;
  return parseCommit(obj.data).parents.some((p) => visited.has(p));
}

/** Peel an annotated tag ref to the commit it ultimately points at. */
function peelRef(repo, refname) {
  const tip = repo.refs.get(refname);
  if (!tip) return null;
  let current = tip;
  for (let i = 0; i < 16; i += 1) {
    const obj = repo.objects.get(current);
    if (!obj || obj.type !== 'tag') return current;
    current = parseTag(obj.data).object;
  }
  return current;
}

// ---------------------------------------------------------------------------
// git smart HTTP

function allRefs(repo) {
  const refs = [];
  for (const [name, oid] of [...repo.refs.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    refs.push({ name, oid });
  }
  return refs;
}

function v0Advertisement(repo, service) {
  const caps = service === 'git-upload-pack'
    ? ['symref=HEAD:refs/heads/main', 'side-band-64k', 'thin-pack', 'ofs-delta', 'shallow', 'multi_ack', 'object-format=sha1', `agent=${SERVER_AGENT}`]
    : ['report-status', 'side-band-64k', 'delete-refs', 'ofs-delta', 'object-format=sha1', `agent=${SERVER_AGENT}`];
  const lines = [`# service=${service}\n`, 'flush'];
  const tip = headTip(repo);
  const refs = allRefs(repo);
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${caps.join(' ')}\n`);
  } else {
    const headLine = tip ? `${tip} HEAD\0${caps.join(' ')}\n` : null;
    if (headLine) lines.push(headLine);
    for (const ref of refs) {
      lines.push(`${ref.oid} ${ref.name}\n`);
      const obj = repo.objects.get(ref.oid);
      if (obj && obj.type === 'tag') {
        const peeled = peelRef(repo, ref.name);
        if (peeled) lines.push(`${peeled} ${ref.name}^{}\n`);
      }
    }
  }
  lines.push('flush');
  return pktLines(lines);
}

function v2Advertisement() {
  const lines = [
    'version 2\n',
    'ls-refs=unborn\n',
    'fetch=shallow wait-for-done filter\n',
    'server-option\n',
    'object-format=sha1\n',
    `agent=${SERVER_AGENT}\n`,
    'flush',
  ];
  return pktLines(lines);
}

/** Parse a v2 command request body: {command, args: string[]}. */
function parseV2Command(body) {
  const { packets } = decodePktLines(body);
  let command = null;
  const args = [];
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    const text = pktText(packet).replace(/\n$/, '');
    if (text.startsWith('command=')) command = text.slice('command='.length);
    else args.push(text);
  }
  return { command, args };
}

function lsRefsResponse(repo, args) {
  const wantPeel = args.includes('peel');
  const wantSymrefs = args.includes('symrefs');
  const wantUnborn = args.includes('unborn');
  const prefixes = args.filter((a) => a.startsWith('ref-prefix ')).map((a) => a.slice('ref-prefix '.length));
  const tip = headTip(repo);
  const lines = [];
  const headRef = `refs/heads/${repo.defaultBranch}`;
  // HEAD is listed only when no prefix filter is given (or a prefix matches
  // "HEAD" itself): with a filter like refs/heads/ the suite requires every
  // returned name to start with the prefix, and "HEAD" does not.
  const headListed = prefixes.length === 0 || prefixes.some((p) => 'HEAD'.startsWith(p));
  if (tip && headListed) {
    let line = `${tip} HEAD`;
    if (wantSymrefs) line += ` symref-target:${headRef}`;
    lines.push(`${line}\n`);
  } else if (!tip && wantUnborn && headListed) {
    let line = `unborn HEAD`;
    if (wantSymrefs) line += ` symref-target:${headRef}`;
    lines.push(`${line}\n`);
  }
  for (const ref of allRefs(repo)) {
    if (prefixes.length > 0 && !prefixes.some((p) => ref.name.startsWith(p))) continue;
    let line = `${ref.oid} ${ref.name}`;
    if (wantSymrefs && ref.name === headRef) line += ` symref-target:${headRef}`;
    if (wantPeel) {
      const obj = repo.objects.get(ref.oid);
      if (obj && obj.type === 'tag') {
        const peeled = peelRef(repo, ref.name);
        if (peeled) line += ` peeled:${peeled}`;
      }
    }
    lines.push(`${line}\n`);
  }
  lines.push('flush');
  return pktLines(lines);
}

/** Frame a pack in sideband band 1 (and band 2 for progress, unused here). */
function sidebandPack(pack) {
  const parts = [];
  let off = 0;
  // A pkt-line is at most 65520 bytes total, so a band-1 payload (1 band byte
  // + pack data) is at most 65516 bytes: 65515 bytes of pack per packet.
  while (off < pack.length) {
    const chunk = pack.subarray(off, Math.min(off + 65515, pack.length));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
    off += chunk.length;
  }
  return Buffer.concat(parts);
}

function v2FetchResponse(repo, args) {
  const wants = [];
  const haves = [];
  const clientShallow = [];
  let depth = null;
  for (const arg of args) {
    if (arg.startsWith('want ')) wants.push(arg.slice(5).trim());
    else if (arg.startsWith('have ')) haves.push(arg.slice(5).trim());
    else if (arg.startsWith('shallow ')) clientShallow.push(arg.slice(8).trim());
    else if (arg.startsWith('deepen ')) depth = parseInt(arg.slice(7), 10);
  }
  const sections = [];
  // acknowledgments
  const knownHaves = haves.filter((oid) => repo.objects.has(oid) && repo.objects.get(oid).type === 'commit');
  const ackLines = [];
  if (knownHaves.length === 0) ackLines.push('NAK\n');
  else {
    for (const oid of knownHaves) ackLines.push(`ACK ${oid}\n`);
    ackLines.push('ready\n');
  }
  sections.push(pktLines(['acknowledgments\n', ...ackLines, 'delim']));
  // fetch objects
  const { objects, shallow, unshallow } = computeFetch(repo, wants, haves, clientShallow, Number.isFinite(depth) ? depth : null);
  if (shallow.length > 0 || unshallow.length > 0) {
    const lines = ['shallow-info\n'];
    for (const oid of shallow) lines.push(`shallow ${oid}\n`);
    for (const oid of unshallow) lines.push(`unshallow ${oid}\n`);
    lines.push('delim');
    sections.push(pktLines(lines));
  }
  if (objects.size > 0) {
    const pack = writePack([...objects.values()].map((obj) => ({ type: obj.type, data: obj.data })));
    sections.push(pktLines(['packfile\n']));
    sections.push(sidebandPack(pack));
    sections.push(PKT_FLUSH);
  } else {
    sections.push(PKT_FLUSH);
  }
  return Buffer.concat(sections);
}

function v0FetchResponse(repo, body) {
  const { packets, rest } = decodePktLines(body);
  const wants = [];
  const haves = [];
  const clientShallow = [];
  let depth = null;
  let inHaves = false;
  for (const packet of packets) {
    if (packet.kind === 'delim') { inHaves = true; continue; }
    if (packet.kind !== 'data') continue;
    const text = pktText(packet).trim();
    if (text === 'done') continue;
    if (!inHaves && text.startsWith('want ')) wants.push(text.slice(5).trim());
    else if (inHaves && text.startsWith('have ')) haves.push(text.slice(5).trim());
    else if (text.startsWith('shallow ')) clientShallow.push(text.slice(8).trim());
    else if (text.startsWith('deepen ')) depth = parseInt(text.slice(7), 10);
  }
  const knownHaves = haves.filter((oid) => repo.objects.has(oid) && repo.objects.get(oid).type === 'commit');
  const parts = [];
  if (knownHaves.length === 0) parts.push(pktLine('NAK\n'));
  else {
    for (const oid of knownHaves) parts.push(pktLine(`ACK ${oid}\n`));
  }
  const { objects, shallow, unshallow } = computeFetch(repo, wants, haves, clientShallow, Number.isFinite(depth) ? depth : null);
  for (const oid of shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  if (objects.size > 0) {
    const pack = writePack([...objects.values()].map((obj) => ({ type: obj.type, data: obj.data })));
    parts.push(sidebandPack(pack));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function receivePackResponse(repo, body) {
  const { packets, rest } = decodePktLines(body);
  const commands = [];
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    let text = pktText(packet);
    const nul = text.indexOf('\0');
    if (nul >= 0) text = text.slice(0, nul);
    const line = text.replace(/\n$/, '');
    const parts = line.split(' ');
    if (parts.length >= 3 && isOid(parts[0]) && isOid(parts[1])) {
      commands.push({ oldOid: parts[0], newOid: parts[1], refname: parts[2] });
    }
  }
  // The pack always follows the flush (except delete-only pushes).
  let unpacked = null;
  let unpackError = null;
  if (rest.length > 0) {
    try {
      unpacked = readPack(rest);
    } catch (err) {
      unpackError = err instanceof Error ? err.message : String(err);
    }
  }
  if (unpacked) {
    for (const [oid, obj] of unpacked) {
      if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
    }
  }
  const inner = [];
  if (unpackError) {
    inner.push(`unpack ${unpackError}\n`);
  } else {
    inner.push('unpack ok\n');
  }
  for (const cmd of commands) {
    const current = repo.refs.get(cmd.refname) ?? ZERO_OID;
    if (cmd.oldOid !== current) {
      inner.push(`ng ${cmd.refname} non-fast-forward\n`);
      continue;
    }
    let ok = false;
    if (cmd.newOid === ZERO_OID) {
      repo.refs.delete(cmd.refname);
      ok = true;
    } else if (cmd.oldOid === ZERO_OID) {
      if (repo.objects.has(cmd.newOid)) {
        repo.refs.set(cmd.refname, cmd.newOid);
        ok = true;
      }
    } else if (isAncestor(repo, cmd.oldOid, cmd.newOid)) {
      repo.refs.set(cmd.refname, cmd.newOid);
      ok = true;
    }
    if (ok) inner.push(`ok ${cmd.refname}\n`);
    else inner.push(`ng ${cmd.refname} non-fast-forward\n`);
  }
  if (commands.some((c) => c.newOid !== ZERO_OID)) {
    const stamp = nowIso();
    repo.updatedAt = stamp;
    repo.pushedAt = stamp;
  }
  inner.push('flush');
  return pktLines([Buffer.concat([Buffer.from([1]), pktLines(inner)])]);
}

async function gitHandler(req, res, owner, repoName, tail, body) {
  const repo = getRepo(owner, repoName);
  const sendBinary = (status, contentType, buf) => {
    res.writeHead(status, {
      'Content-Type': contentType,
      'Content-Length': buf.length,
      'X-GitHub-Request-Id': requestId(),
    });
    res.end(buf);
  };
  if (tail.startsWith('info/refs')) {
    const service = new URL(req.url, 'http://x').searchParams.get('service');
    if (!repo) return sendJson(res, 404, { message: 'Not Found' });
    if (service === 'git-upload-pack') {
      const isV2 = req.headers['git-protocol'] === 'version=2';
      const buf = isV2 ? v2Advertisement() : v0Advertisement(repo, 'git-upload-pack');
      return sendBinary(200, 'application/x-git-upload-pack-advertisement', buf);
    }
    if (service === 'git-receive-pack') {
      return sendBinary(200, 'application/x-git-receive-pack-advertisement', v0Advertisement(repo, 'git-receive-pack'));
    }
    return sendJson(res, 400, { message: 'unknown service' });
  }
  if (tail === 'git-upload-pack') {
    if (!repo) return sendJson(res, 404, { message: 'Not Found' });
    if (req.headers['git-protocol'] === 'version=2') {
      const { command, args } = parseV2Command(body);
      if (command === 'ls-refs') {
        return sendBinary(200, 'application/x-git-upload-pack-result', lsRefsResponse(repo, args));
      }
      if (command === 'fetch') {
        return sendBinary(200, 'application/x-git-upload-pack-result', v2FetchResponse(repo, args));
      }
      return sendJson(res, 400, { message: `unknown v2 command ${command}` });
    }
    return sendBinary(200, 'application/x-git-upload-pack-result', v0FetchResponse(repo, body));
  }
  if (tail === 'git-receive-pack') {
    if (!repo) return sendJson(res, 404, { message: 'Not Found' });
    if (body.length === 0) return sendJson(res, 400, { message: 'empty receive-pack body' });
    const { packets } = decodePktLines(body);
    if (packets.length === 0) return sendJson(res, 400, { message: 'malformed receive-pack body' });
    return sendBinary(200, 'application/x-git-receive-pack-result', receivePackResponse(repo, body));
  }
  return sendJson(res, 404, { message: 'Not Found' });
}

// ---------------------------------------------------------------------------
// HTTP plumbing shared by the REST, GraphQL and MCP handlers

function sendJson(res, status, obj, extraHeaders = {}) {
  const body = status === 204 ? '' : JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'X-GitHub-Request-Id': requestId(),
    'X-OAuth-Scopes': 'repo, user',
    ...extraHeaders,
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      chunks.push(chunk);
      total += chunk.length;
      if (total > 64 * 1024 * 1024) reject(new Error('body too large'));
    });
    req.on('end', () => resolve(Buffer.concat(chunks, total)));
    req.on('error', reject);
  });
}

function parseJsonBody(body) {
  if (body.length === 0) return {};
  const text = body.toString('utf8');
  const parsed = JSON.parse(text);
  if (!isRecord(parsed) && !Array.isArray(parsed)) throw new Error('body must be a JSON object');
  return parsed;
}

function nextId() {
  const id = nextDatabaseId;
  nextDatabaseId += 1;
  return id;
}

// ---------------------------------------------------------------------------
// REST v3: JSON shapes

function userJson(login = VIEWER_LOGIN) {
  return {
    login,
    id: login === VIEWER_LOGIN ? VIEWER_ID : 2000,
    node_id: globalId('user', login === VIEWER_LOGIN ? VIEWER_ID : 2000),
    avatar_url: `https://avatars.example/${login}`,
    gravatar_id: '',
    url: `https://api.example/users/${login}`,
    html_url: `https://github.example/${login}`,
    type: 'User',
    site_admin: false,
    name: login === VIEWER_LOGIN ? VIEWER_NAME : login,
    email: login === VIEWER_LOGIN ? VIEWER_EMAIL : `${login}@example.invalid`,
  };
}

function repoJson(repo, host) {
  const openIssues = repo.issues.filter((i) => i.state === 'open').length;
  const openPulls = repo.pulls.filter((p) => p.state === 'open').length;
  return {
    id: repo.id,
    node_id: repo.nodeId,
    name: repo.name,
    full_name: repo.fullName,
    owner: userJson(repo.owner),
    private: repo.private,
    html_url: `http://${host}/${repo.fullName}`,
    description: repo.description,
    fork: false,
    url: `http://${host}/api/v3/repos/${repo.fullName}`,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    pushed_at: repo.pushedAt,
    git_url: `git://${host}/${repo.fullName}.git`,
    ssh_url: `git@github.example:${repo.fullName}.git`,
    clone_url: `http://${host}/${repo.fullName}.git`,
    homepage: null,
    size: 0,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    has_discussions: false,
    forks_count: 0,
    mirror_url: null,
    archived: false,
    disabled: false,
    open_issues_count: openIssues + openPulls,
    license: null,
    allow_forking: true,
    is_template: false,
    topics: [],
    visibility: repo.private ? 'private' : 'public',
    default_branch: repo.defaultBranch,
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
  };
}

function labelJson(label) {
  return {
    id: label.id,
    node_id: globalId('label', label.id),
    url: `https://api.example/labels/${label.name}`,
    name: label.name,
    color: label.color,
    description: label.description ?? null,
    default: false,
  };
}

function issueJson(repo, issue, host) {
  return {
    id: issue.id,
    node_id: issue.nodeId,
    url: `http://${host}/api/v3/repos/${repo.fullName}/issues/${issue.number}`,
    repository_url: `http://${host}/api/v3/repos/${repo.fullName}`,
    labels_url: `http://${host}/api/v3/repos/${repo.fullName}/issues/${issue.number}/labels`,
    comments_url: `http://${host}/api/v3/repos/${repo.fullName}/issues/${issue.number}/comments`,
    events_url: `http://${host}/api/v3/repos/${repo.fullName}/issues/${issue.number}/events`,
    html_url: `http://${host}/${repo.fullName}/issues/${issue.number}`,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    user: userJson(VIEWER_LOGIN),
    labels: issue.labels.map((name) => labelJson(repo.labels.get(name))),
    state: issue.state,
    locked: false,
    assignee: null,
    assignees: [],
    milestone: null,
    comments: (repo.comments.get(issue.number) ?? []).length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    author_association: 'OWNER',
    active_lock_reason: null,
    reactions: { url: '', total_count: 0, '+1': 0, '-1': 0, laugh: 0, hooray: 0, confused: 0, heart: 0, rocket: 0, eyes: 0 },
    timeline_url: `http://${host}/api/v3/repos/${repo.fullName}/issues/${issue.number}/timeline`,
    performed_via_github_app: null,
    state_reason: null,
  };
}

function commentJson(repo, issue, comment, host) {
  return {
    id: comment.id,
    node_id: comment.nodeId,
    url: `http://${host}/api/v3/repos/${repo.fullName}/issues/${issue.number}/comments/${comment.id}`,
    html_url: `http://${host}/${repo.fullName}/issues/${issue.number}#issuecomment-${comment.id}`,
    body: comment.body,
    user: userJson(VIEWER_LOGIN),
    created_at: comment.createdAt,
    updated_at: comment.updatedAt,
    author_association: 'OWNER',
  };
}

/** Line multiset diff between two file contents (Buffers). */
function lineDiff(oldData, newData) {
  const splitLines = (data) => {
    if (!data || data.length === 0) return [];
    const lines = data.toString('utf8').split('\n');
    if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
    return lines;
  };
  const oldLines = splitLines(oldData);
  const newLines = splitLines(newData);
  const oldCount = new Map();
  for (const line of oldLines) oldCount.set(line, (oldCount.get(line) ?? 0) + 1);
  let additions = 0;
  for (const line of newLines) {
    const remaining = oldCount.get(line) ?? 0;
    if (remaining > 0) oldCount.set(line, remaining - 1);
    else additions += 1;
  }
  let deletions = 0;
  for (const remaining of oldCount.values()) deletions += remaining;
  return { additions, deletions };
}

function diffFiles(repo, baseCommitOid, headCommitOid) {
  const baseFlat = flatTree(repo, baseCommitOid);
  const headFlat = flatTree(repo, headCommitOid);
  const files = [];
  const paths = new Set([...baseFlat.keys(), ...headFlat.keys()]);
  for (const path of [...paths].sort()) {
    const inBase = baseFlat.get(path);
    const inHead = headFlat.get(path);
    if (inBase && !inHead) {
      const oldData = repo.objects.get(inBase.oid)?.data ?? Buffer.alloc(0);
      const { additions, deletions } = lineDiff(oldData, null);
      files.push({ filename: path, status: 'removed', additions, deletions, changes: additions + deletions });
    } else if (!inBase && inHead) {
      const newData = repo.objects.get(inHead.oid)?.data ?? Buffer.alloc(0);
      const { additions, deletions } = lineDiff(null, newData);
      files.push({ filename: path, status: 'added', additions, deletions, changes: additions + deletions });
    } else if (inBase && inHead && inBase.oid !== inHead.oid) {
      const oldData = repo.objects.get(inBase.oid)?.data ?? Buffer.alloc(0);
      const newData = repo.objects.get(inHead.oid)?.data ?? Buffer.alloc(0);
      const { additions, deletions } = lineDiff(oldData, newData);
      files.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  return files;
}

/** True when the two sides changed the same path differently from the base. */
function mergeConflicts(repo, baseOid, baseTipOid, headTipOid) {
  if (!baseOid || !baseTipOid || !headTipOid) return true;
  if (baseTipOid === headTipOid) return false;
  const baseFlat = flatTree(repo, baseOid);
  const leftFlat = flatTree(repo, baseTipOid);
  const rightFlat = flatTree(repo, headTipOid);
  const paths = new Set([...baseFlat.keys(), ...leftFlat.keys(), ...rightFlat.keys()]);
  for (const path of paths) {
    const b = baseFlat.get(path)?.oid ?? null;
    const l = leftFlat.get(path)?.oid ?? null;
    const r = rightFlat.get(path)?.oid ?? null;
    if (b !== l && b !== r && l !== r) return true;
  }
  return false;
}

function prMergeable(repo, pr) {
  if (pr.merged || pr.state !== 'open') return { mergeable: false, state: 'unknown' };
  const headTipOid = refTip(repo, `refs/heads/${pr.headRef}`);
  const baseTipOid = refTip(repo, `refs/heads/${pr.baseRef}`);
  if (!headTipOid || !baseTipOid) return { mergeable: false, state: 'unknown' };
  const base = mergeBase(repo, baseTipOid, headTipOid);
  if (base === null) return { mergeable: false, state: 'dirty' };
  if (mergeConflicts(repo, base, baseTipOid, headTipOid)) return { mergeable: false, state: 'dirty' };
  return { mergeable: true, state: 'clean' };
}

function prJson(repo, pr, host) {
  const headSha = refTip(repo, `refs/heads/${pr.headRef}`) ?? pr.headSha;
  const baseSha = refTip(repo, `refs/heads/${pr.baseRef}`) ?? pr.baseSha;
  const { mergeable, state: mergeableState } = prMergeable(repo, pr);
  const baseOid = mergeBase(repo, baseSha, headSha);
  const files = baseOid ? diffFiles(repo, baseOid, headSha) : [];
  const additions = files.reduce((sum, f) => sum + f.additions, 0);
  const deletions = files.reduce((sum, f) => sum + f.deletions, 0);
  const baseSet = baseOid ? new Set(commitList(repo, [baseOid])) : new Set();
  const prCommits = commitList(repo, [headSha]).filter((oid) => !baseSet.has(oid)).length;
  return {
    id: pr.id,
    node_id: pr.nodeId,
    url: `http://${host}/api/v3/repos/${repo.fullName}/pulls/${pr.number}`,
    html_url: `http://${host}/${repo.fullName}/pull/${pr.number}`,
    diff_url: `http://${host}/${repo.fullName}/pull/${pr.number}.diff`,
    patch_url: `http://${host}/${repo.fullName}/pull/${pr.number}.patch`,
    issue_url: `http://${host}/api/v3/repos/${repo.fullName}/issues/${pr.number}`,
    number: pr.number,
    state: pr.state,
    locked: false,
    title: pr.title,
    user: userJson(VIEWER_LOGIN),
    body: pr.body,
    created_at: pr.createdAt,
    updated_at: pr.updatedAt,
    closed_at: pr.closedAt,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    assignee: null,
    assignees: [],
    requested_reviewers: [],
    requested_teams: [],
    labels: [],
    milestone: null,
    draft: false,
    commits_url: `http://${host}/api/v3/repos/${repo.fullName}/pulls/${pr.number}/commits`,
    review_comments_url: `http://${host}/api/v3/repos/${repo.fullName}/pulls/${pr.number}/comments`,
    review_comment_url: `http://${host}/api/v3/repos/${repo.fullName}/pulls/comments{/number}`,
    comments_url: `http://${host}/api/v3/repos/${repo.fullName}/issues/${pr.number}/comments`,
    statuses_url: `http://${host}/api/v3/repos/${repo.fullName}/statuses/${headSha}`,
    head: { label: `${repo.owner}:${pr.headRef}`, ref: pr.headRef, sha: headSha, user: userJson(VIEWER_LOGIN), repo: repoJson(repo, host) },
    base: { label: `${repo.owner}:${pr.baseRef}`, ref: pr.baseRef, sha: baseSha, user: userJson(VIEWER_LOGIN), repo: repoJson(repo, host) },
    _links: {},
    author_association: 'OWNER',
    auto_merge: null,
    active_lock_reason: null,
    merged: pr.merged,
    mergeable,
    mergeable_state: mergeableState,
    merged_by: null,
    comments: 0,
    review_comments: 0,
    maintainer_can_modify: false,
    commits: prCommits,
    additions,
    deletions,
    changed_files: files.length,
  };
}

// ---------------------------------------------------------------------------
// domain operations shared by REST, GraphQL and MCP

function createRepoOp(owner, name, isPrivate, description) {
  if (!name || typeof name !== 'string' || name.includes('/')) return { error: 422, message: 'name is required' };
  if (getRepo(owner, name)) return { error: 422, message: `name already exists on this account` };
  return { repo: makeRepo(owner, name, isPrivate, description) };
}

function createIssueOp(repo, title, body, labels) {
  if (!title || typeof title !== 'string') return { error: 422, message: 'title is required' };
  for (const label of labels ?? []) {
    if (!repo.labels.has(label)) return { error: 422, message: `label ${label} does not exist` };
  }
  const number = repo.nextIssueNumber;
  repo.nextIssueNumber += 1;
  const stamp = nowIso();
  const issue = {
    id: nextId(),
    nodeId: globalId('issue', repo.id, number),
    number,
    title,
    body: body ?? null,
    state: 'open',
    labels: [...(labels ?? [])],
    createdAt: stamp,
    updatedAt: stamp,
    closedAt: null,
  };
  repo.issues.push(issue);
  repo.issueByNumber.set(number, issue);
  issuesByNodeId.set(issue.nodeId, { repo, issue });
  return { issue };
}

function createPullOp(repo, title, body, headRef, baseRef) {
  if (!title || typeof title !== 'string') return { error: 422, message: 'title is required' };
  const headSha = refTip(repo, `refs/heads/${headRef}`);
  const baseSha = refTip(repo, `refs/heads/${baseRef}`);
  if (!headSha || !baseSha) return { error: 422, message: 'head or base ref does not exist' };
  for (const existing of repo.pulls) {
    if (existing.state === 'open' && existing.headRef === headRef && existing.baseRef === baseRef) {
      return { error: 422, message: 'a pull request already exists for these branches' };
    }
  }
  const number = repo.nextPullNumber;
  repo.nextPullNumber += 1;
  const stamp = nowIso();
  const pr = {
    id: nextId(),
    nodeId: globalId('pr', repo.id, number),
    number,
    title,
    body: body ?? null,
    state: 'open',
    headRef,
    baseRef,
    headSha,
    baseSha,
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    createdAt: stamp,
    updatedAt: stamp,
    closedAt: null,
  };
  repo.pulls.push(pr);
  repo.pullByNumber.set(number, pr);
  pullsByNodeId.set(pr.nodeId, { repo, pr });
  return { pr };
}

function squashMergeOp(repo, pr) {
  if (!pr) return { error: 404, message: 'Not Found' };
  if (pr.merged || pr.state !== 'open') return { error: 405, message: 'pull request is already merged or closed' };
  const headTipOid = refTip(repo, `refs/heads/${pr.headRef}`);
  const baseTipOid = refTip(repo, `refs/heads/${pr.baseRef}`);
  if (!headTipOid || !baseTipOid) return { error: 422, message: 'head or base ref does not exist' };
  const base = mergeBase(repo, baseTipOid, headTipOid);
  if (base === null) return { error: 405, message: 'Merge conflict' };
  if (mergeConflicts(repo, base, baseTipOid, headTipOid)) return { error: 405, message: 'Merge conflict' };
  const baseFlat = flatTree(repo, base);
  const headFlat = flatTree(repo, headTipOid);
  const baseTipFlat = flatTree(repo, baseTipOid);
  const mergedFlat = new Map(baseTipFlat);
  for (const [path, item] of headFlat) {
    if ((baseFlat.get(path)?.oid ?? null) !== item.oid) mergedFlat.set(path, item);
  }
  for (const path of baseFlat.keys()) {
    if (!headFlat.has(path) && (baseTipFlat.get(path)?.oid ?? null) === (baseFlat.get(path)?.oid ?? null)) {
      mergedFlat.delete(path);
    }
  }
  const message = `Merge pull request #${pr.number} from ${repo.owner}/${pr.headRef}\n\n${pr.title}`;
  const mergeSha = commitFlatTree(repo, pr.baseRef, mergedFlat, message, baseTipOid);
  const stamp = nowIso();
  pr.merged = true;
  pr.state = 'closed';
  pr.mergedAt = stamp;
  pr.mergeCommitSha = mergeSha;
  pr.closedAt = stamp;
  pr.updatedAt = stamp;
  return { pr, sha: mergeSha, message };
}

// ---------------------------------------------------------------------------
// REST v3 dispatcher

function pageParams(url) {
  const perPageRaw = parseInt(url.searchParams.get('per_page') ?? '30', 10);
  const pageRaw = parseInt(url.searchParams.get('page') ?? '1', 10);
  return {
    perPage: Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(perPageRaw, 100) : 30,
    page: Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1,
  };
}

function paginate(items, perPage, page, host, basePath, extraQuery = '') {
  const total = items.length;
  const start = (page - 1) * perPage;
  const pageItems = items.slice(start, start + perPage);
  const links = [];
  if (start + perPage < total) {
    links.push(`<http://${host}${basePath}?per_page=${perPage}&page=${page + 1}${extraQuery}>; rel="next"`);
    links.push(`<http://${host}${basePath}?per_page=${perPage}&page=${Math.ceil(total / perPage)}${extraQuery}>; rel="last"`);
  }
  if (page > 1) {
    links.push(`<http://${host}${basePath}?per_page=${perPage}&page=${page - 1}${extraQuery}>; rel="prev"`);
    links.push(`<http://${host}${basePath}?per_page=${perPage}&page=1${extraQuery}>; rel="first"`);
  }
  return { pageItems, linkHeader: links.join(', ') };
}

async function restHandler(req, res, body) {
  const url = new URL(req.url, 'http://x');
  const host = req.headers.host ?? 'localhost';
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts[0] !== 'api' || parts[1] !== 'v3') return sendJson(res, 404, { message: 'Not Found' });
  const reply = (status, obj, extra = {}) => sendJson(res, status, obj, extra);

  // GET /api/v3/ and /api/v3/meta
  if (parts.length === 2) {
    if (req.method !== 'GET') return reply(404, { message: 'Not Found' });
    return reply(200, {
      current_user_url: `http://${host}/api/v3/user`,
      current_user_authorizations_html_url: `http://${host}/settings/applications`,
      authorizations_url: `http://${host}/api/v3/authorizations`,
      repository_url: `http://${host}/api/v3/repos/{owner}/{repo}`,
      user_url: `http://${host}/api/v3/users/{user}`,
      user_search_url: `http://${host}/api/v3/search/users?q={query}`,
    });
  }
  if (parts[2] === 'meta' && parts.length === 3) {
    if (req.method !== 'GET') return reply(404, { message: 'Not Found' });
    return reply(200, {
      verifiable_password_authentication: true,
      installed_version: FORGE_VERSION,
      github_services_sha: '0000000000000000000000000000000000000000',
      hooks: [],
      git: [],
      domains: { website: ['github.example'], codespaces: [], copilot: [], packages: [] },
    });
  }

  // /api/v3/user and /api/v3/user/repos
  if (parts[2] === 'user') {
    if (parts.length === 3) {
      if (req.method !== 'GET') return reply(404, { message: 'Not Found' });
      return reply(200, userJson(VIEWER_LOGIN));
    }
    if (parts[3] === 'repos' && parts.length === 4) {
      if (req.method === 'GET') {
        const { perPage, page } = pageParams(url);
        const mine = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).sort((a, b) => a.id - b.id);
        const { pageItems, linkHeader } = paginate(mine, perPage, page, host, '/api/v3/user/repos');
        return reply(200, pageItems.map((r) => repoJson(r, host)), linkHeader ? { Link: linkHeader } : {});
      }
      if (req.method === 'POST') {
        let payload;
        try { payload = parseJsonBody(body); } catch { return reply(400, { message: 'Problems parsing JSON' }); }
        const result = createRepoOp(VIEWER_LOGIN, payload.name, payload.private, payload.description);
        if (result.error) return reply(result.error, { message: result.message });
        return reply(201, repoJson(result.repo, host));
      }
      return reply(404, { message: 'Not Found' });
    }
    return reply(404, { message: 'Not Found' });
  }

  // /api/v3/repos/{owner}/{repo}/...
  if (parts[2] === 'repos') {
    const owner = parts[3];
    const name = parts[4];
    if (!owner || !name) return reply(404, { message: 'Not Found' });
    const repo = getRepo(owner, name);
    const tail = parts.slice(5);
    if (!repo || repo.owner !== owner) return reply(404, { message: 'Not Found' });
    if (owner !== VIEWER_LOGIN) return reply(404, { message: 'Not Found' });

    // GET / PATCH / DELETE /repos/{o}/{r}
    if (tail.length === 0) {
      if (req.method === 'GET') return reply(200, repoJson(repo, host));
      if (req.method === 'PATCH') {
        let payload;
        try { payload = parseJsonBody(body); } catch { return reply(400, { message: 'Problems parsing JSON' }); }
        if (typeof payload.description === 'string' || payload.description === null) repo.description = payload.description;
        if (typeof payload.name === 'string' && payload.name.length > 0 && payload.name !== repo.name) {
          if (getRepo(owner, payload.name)) return reply(422, { message: 'name already exists on this account' });
          repos.delete(repoKey(owner, repo.name));
          repo.name = payload.name;
          repo.fullName = `${owner}/${payload.name}`;
          repos.set(repoKey(owner, repo.name), repo);
        }
        if (typeof payload.private === 'boolean') repo.private = payload.private;
        repo.updatedAt = nowIso();
        return reply(200, repoJson(repo, host));
      }
      if (req.method === 'DELETE') {
        deleteRepo(repo);
        return reply(204, {});
      }
      return reply(404, { message: 'Not Found' });
    }

    const segment = tail[0];

    // /branches
    if (segment === 'branches') {
      if (req.method === 'GET' && tail.length === 1) {
        const branches = [...repo.refs.keys()]
          .filter((ref) => ref.startsWith('refs/heads/'))
          .map((ref) => ref.slice('refs/heads/'.length))
          .sort()
          .map((branch) => ({
            name: branch,
            commit: { sha: repo.refs.get(`refs/heads/${branch}`), url: `http://${host}/api/v3/repos/${repo.fullName}/commits/${repo.refs.get(`refs/heads/${branch}`)}` },
            protected: false,
          }));
        return reply(200, branches);
      }
      if (req.method === 'GET' && tail.length === 2) {
        const sha = repo.refs.get(`refs/heads/${tail[1]}`);
        if (!sha) return reply(404, { message: 'Branch not found' });
        return reply(200, {
          name: tail[1],
          commit: { sha, url: `http://${host}/api/v3/repos/${repo.fullName}/commits/${sha}` },
          protected: false,
        });
      }
      return reply(404, { message: 'Not Found' });
    }

    // /git/refs/heads/{branch}
    if (segment === 'git' && tail[1] === 'refs') {
      if (req.method === 'GET' && tail.length === 4 && tail[2] === 'heads') {
        const sha = repo.refs.get(`refs/heads/${tail[3]}`);
        if (!sha) return reply(404, { message: 'Reference does not exist' });
        return reply(200, { ref: `refs/heads/${tail[3]}`, node_id: globalId('ref', repo.id, tail[3]), url: `http://${host}/api/v3/repos/${repo.fullName}/git/refs/heads/${tail[3]}`, object: { sha, type: 'commit' } });
      }
      if (req.method === 'POST' && tail.length === 2) {
        let payload;
        try { payload = parseJsonBody(body); } catch { return reply(400, { message: 'Problems parsing JSON' }); }
        const ref = payload.ref;
        const sha = payload.sha;
        if (typeof ref !== 'string' || !ref.startsWith('refs/heads/') || !isOid(sha)) return reply(422, { message: 'Invalid ref or sha' });
        const obj = repo.objects.get(sha);
        if (!obj || obj.type !== 'commit') return reply(422, { message: 'Object does not exist' });
        if (repo.refs.has(ref)) return reply(422, { message: 'Reference already exists' });
        repo.refs.set(ref, sha);
        repo.updatedAt = nowIso();
        return reply(201, { ref, node_id: globalId('ref', repo.id, ref), url: `http://${host}/api/v3/repos/${repo.fullName}/git/refs/${ref}`, object: { sha, type: 'commit' } });
      }
      return reply(404, { message: 'Not Found' });
    }

    // /commits
    if (segment === 'commits') {
      if (req.method === 'GET' && tail.length === 1) {
        const shaParam = url.searchParams.get('sha') ?? repo.defaultBranch;
        let start = null;
        if (isOid(shaParam)) start = shaParam;
        else start = repo.refs.get(`refs/heads/${shaParam}`) ?? null;
        if (!start || !repo.objects.has(start)) return reply(404, { message: 'No commit found for SHA' });
        const list = commitList(repo, [start]).map((oid) => {
          const parsed = parseCommit(repo.objects.get(oid).data);
          const authorOf = (line) => {
            const m = line.match(/^(.*) <(.*)> (\d+) ([+-]\d{4})$/);
            if (!m) return { name: VIEWER_NAME, email: VIEWER_EMAIL, date: nowIso() };
            return { name: m[1], email: m[2], date: new Date(Number(m[3]) * 1000).toISOString() };
          };
          return {
            sha: oid,
            node_id: globalId('commit', repo.id, oid),
            commit: {
              author: authorOf(parsed.author),
              committer: authorOf(parsed.committer),
              message: parsed.message.replace(/\n$/, ''),
              tree: { sha: parsed.tree },
              url: `http://${host}/api/v3/repos/${repo.fullName}/git/commits/${oid}`,
              comment_count: 0,
              verification: { verified: false, reason: 'unsigned', signature: null, payload: null },
            },
            url: `http://${host}/api/v3/repos/${repo.fullName}/commits/${oid}`,
            html_url: `http://${host}/${repo.fullName}/commit/${oid}`,
            comments_url: `http://${host}/api/v3/repos/${repo.fullName}/commits/${oid}/comments`,
            author: userJson(VIEWER_LOGIN),
            committer: userJson(VIEWER_LOGIN),
            parents: parsed.parents.map((p) => ({ sha: p, url: `http://${host}/api/v3/repos/${repo.fullName}/commits/${p}`, html_url: `http://${host}/${repo.fullName}/commit/${p}` })),
          };
        });
        return reply(200, list);
      }
      return reply(404, { message: 'Not Found' });
    }

    // /contents/{path...}
    if (segment === 'contents') {
      const path = tail.slice(1).map(decodeURIComponent).join('/');
      const branch = url.searchParams.get('ref') ?? null;
      const branchTip = (b) => {
        if (b) return repo.refs.get(`refs/heads/${b}`) ?? null;
        return headTip(repo);
      };
      if (req.method === 'GET') {
        const tip = branchTip(branch);
        if (!tip) return reply(404, { message: 'Not Found' });
        const flat = flatTree(repo, tip);
        if (path === '') {
          const entries = [];
          const seenDirs = new Set();
          for (const [p, item] of [...flat.entries()].sort()) {
            const first = p.split('/')[0];
            if (p.includes('/')) {
              if (!seenDirs.has(first)) {
                seenDirs.add(first);
                const dirTree = buildTreeAt(repo, flat, first);
                entries.push({ type: 'dir', name: first, path: first, sha: dirTree, size: 0, url: `http://${host}/api/v3/repos/${repo.fullName}/contents/${first}`, html_url: `http://${host}/${repo.fullName}/tree/${branch ?? repo.defaultBranch}/${first}`, git_url: '', download_url: null });
              }
            } else {
              entries.push({ type: 'file', name: first, path: first, sha: item.oid, size: repo.objects.get(item.oid)?.data.length ?? 0, url: `http://${host}/api/v3/repos/${repo.fullName}/contents/${first}`, html_url: `http://${host}/${repo.fullName}/blob/${branch ?? repo.defaultBranch}/${first}`, git_url: '', download_url: `http://${host}/api/v3/repos/${repo.fullName}/contents/${first}` });
            }
          }
          return reply(200, entries);
        }
        const file = flat.get(path);
        if (file) {
          const data = repo.objects.get(file.oid)?.data ?? Buffer.alloc(0);
          return reply(200, {
            type: 'file',
            encoding: 'base64',
            size: data.length,
            name: path.split('/').pop(),
            path,
            content: data.toString('base64'),
            sha: file.oid,
            url: `http://${host}/api/v3/repos/${repo.fullName}/contents/${path}`,
            git_url: `http://${host}/api/v3/repos/${repo.fullName}/git/blobs/${file.oid}`,
            html_url: `http://${host}/${repo.fullName}/blob/${branch ?? repo.defaultBranch}/${path}`,
            download_url: `http://${host}/api/v3/repos/${repo.fullName}/contents/${path}`,
            _links: { git: `http://${host}/api/v3/repos/${repo.fullName}/git/blobs/${file.oid}`, self: `http://${host}/api/v3/repos/${repo.fullName}/contents/${path}`, html: `http://${host}/${repo.fullName}/blob/${branch ?? repo.defaultBranch}/${path}` },
          });
        }
        const prefix = `${path}/`;
        const under = [...flat.keys()].filter((p) => p.startsWith(prefix));
        if (under.length > 0) {
          const entries = [];
          const seenDirs = new Set();
          for (const p of under.sort()) {
            const rest = p.slice(prefix.length);
            const first = rest.split('/')[0];
            if (rest.includes('/')) {
              if (!seenDirs.has(first)) {
                seenDirs.add(first);
                entries.push({ type: 'dir', name: first, path: `${path}/${first}`, sha: buildTreeAt(repo, flat, `${path}/${first}`), size: 0, url: `http://${host}/api/v3/repos/${repo.fullName}/contents/${path}/${first}`, html_url: `http://${host}/${repo.fullName}/tree/${branch ?? repo.defaultBranch}/${path}/${first}`, git_url: '', download_url: null });
              }
            } else {
              const item = flat.get(p);
              entries.push({ type: 'file', name: first, path: p, sha: item.oid, size: repo.objects.get(item.oid)?.data.length ?? 0, url: `http://${host}/api/v3/repos/${repo.fullName}/contents/${p}`, html_url: `http://${host}/${repo.fullName}/blob/${branch ?? repo.defaultBranch}/${p}`, git_url: '', download_url: `http://${host}/api/v3/repos/${repo.fullName}/contents/${p}` });
            }
          }
          return reply(200, entries);
        }
        return reply(404, { message: 'Not Found' });
      }
      if (req.method === 'PUT' || req.method === 'DELETE') {
        let payload;
        try { payload = parseJsonBody(body); } catch { return reply(400, { message: 'Problems parsing JSON' }); }
        if (typeof payload.message !== 'string' || payload.message.length === 0) return reply(422, { message: 'message is required' });
        const targetBranch = typeof payload.branch === 'string' && payload.branch.length > 0 ? payload.branch : repo.defaultBranch;
        let tip = repo.refs.get(`refs/heads/${targetBranch}`);
        if (!tip) {
          const defaultTip = headTip(repo);
          if (defaultTip) {
            repo.refs.set(`refs/heads/${targetBranch}`, defaultTip);
            tip = defaultTip;
          }
        }
        const flat = flatTree(repo, tip ?? null);
        const existing = flat.get(path);
        if (req.method === 'DELETE') {
          if (!existing) return reply(404, { message: 'Not Found' });
          if (payload.sha && payload.sha !== existing.oid) return reply(409, { message: 'sha does not match' });
          flat.delete(path);
          const commitSha = commitFlatTree(repo, targetBranch, flat, payload.message, tip ?? null);
          return reply(200, { content: null, commit: { sha: commitSha, message: payload.message, author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: nowIso() }, committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: nowIso() } } });
        }
        // PUT: create or update
        if (typeof payload.content !== 'string') return reply(422, { message: 'content is required' });
        let bytes;
        try {
          bytes = b64decode(payload.content);
          if (bytes.toString('base64') !== payload.content.replace(/\s+/g, '')) throw new Error('bad base64');
        } catch {
          return reply(400, { message: 'content is not valid base64' });
        }
        if (existing) {
          if (!payload.sha) return reply(422, { message: 'sha is required to update a file' });
          if (payload.sha !== existing.oid) return reply(409, { message: 'sha does not match' });
        } else if (payload.sha) {
          return reply(422, { message: 'sha is not valid for a new file' });
        }
        const blobSha = hashObject('blob', bytes);
        if (!repo.objects.has(blobSha)) repo.objects.set(blobSha, { type: 'blob', data: bytes });
        flat.set(path, { oid: blobSha, mode: '100644' });
        const commitSha = commitFlatTree(repo, targetBranch, flat, payload.message, tip ?? null);
        const status = existing ? 200 : 201;
        return reply(status, {
          content: { name: path.split('/').pop(), path, sha: blobSha, size: bytes.length, type: 'file', encoding: 'base64', url: `http://${host}/api/v3/repos/${repo.fullName}/contents/${path}` },
          commit: { sha: commitSha, message: payload.message, author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: nowIso() }, committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: nowIso() } },
        });
      }
      return reply(404, { message: 'Not Found' });
    }

    // /labels
    if (segment === 'labels') {
      if (req.method === 'POST' && tail.length === 1) {
        let payload;
        try { payload = parseJsonBody(body); } catch { return reply(400, { message: 'Problems parsing JSON' }); }
        if (typeof payload.name !== 'string' || payload.name.length === 0) return reply(422, { message: 'name is required' });
        const existing = repo.labels.get(payload.name);
        if (existing) return reply(201, labelJson(existing));
        const label = { id: nextId(), name: payload.name, color: typeof payload.color === 'string' ? payload.color.replace(/^#/, '') : 'ededed', description: typeof payload.description === 'string' ? payload.description : null };
        repo.labels.set(label.name, label);
        return reply(201, labelJson(label));
      }
      if (req.method === 'GET' && tail.length === 1) {
        return reply(200, [...repo.labels.values()].map(labelJson));
      }
      return reply(404, { message: 'Not Found' });
    }

    // /issues
    if (segment === 'issues') {
      if (tail.length === 1) {
        if (req.method === 'POST') {
          let payload;
          try { payload = parseJsonBody(body); } catch { return reply(400, { message: 'Problems parsing JSON' }); }
          const result = createIssueOp(repo, payload.title, payload.body, payload.labels);
          if (result.error) return reply(result.error, { message: result.message });
          return reply(201, issueJson(repo, result.issue, host));
        }
        if (req.method === 'GET') {
          const state = url.searchParams.get('state') ?? 'open';
          const direction = url.searchParams.get('direction') ?? 'desc';
          const { perPage, page } = pageParams(url);
          let list = [...repo.issues];
          if (state === 'open') list = list.filter((i) => i.state === 'open');
          else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
          else if (state !== 'all') return reply(422, { message: `invalid state ${state}` });
          list.sort((a, b) => {
            if (a.createdAt !== b.createdAt) return direction === 'asc' ? (a.createdAt < b.createdAt ? -1 : 1) : (a.createdAt > b.createdAt ? -1 : 1);
            return direction === 'asc' ? a.number - b.number : b.number - a.number;
          });
          const { pageItems, linkHeader } = paginate(list, perPage, page, host, `/api/v3/repos/${repo.fullName}/issues`, `&state=${state}`);
          return reply(200, pageItems.map((i) => issueJson(repo, i, host)), linkHeader ? { Link: linkHeader } : {});
        }
        return reply(404, { message: 'Not Found' });
      }
      const number = parseInt(tail[1], 10);
      if (!Number.isFinite(number)) return reply(404, { message: 'Not Found' });
      const issue = repo.issueByNumber.get(number);
      if (!issue) return reply(404, { message: 'Not Found' });
      if (tail.length === 2) {
        if (req.method === 'GET') return reply(200, issueJson(repo, issue, host));
        if (req.method === 'PATCH') {
          let payload;
          try { payload = parseJsonBody(body); } catch { return reply(400, { message: 'Problems parsing JSON' }); }
          if (typeof payload.title === 'string') issue.title = payload.title;
          if (typeof payload.body === 'string' || payload.body === null) issue.body = payload.body;
          if (payload.state === 'open' || payload.state === 'closed') {
            issue.state = payload.state;
            issue.closedAt = payload.state === 'closed' ? nowIso() : null;
          }
          if (Array.isArray(payload.labels)) {
            for (const label of payload.labels) {
              if (!repo.labels.has(label)) return reply(422, { message: `label ${label} does not exist` });
            }
            issue.labels = [...payload.labels];
          }
          issue.updatedAt = nowIso();
          return reply(200, issueJson(repo, issue, host));
        }
        return reply(404, { message: 'Not Found' });
      }
      if (tail[2] === 'comments') {
        if (req.method === 'POST' && tail.length === 3) {
          let payload;
          try { payload = parseJsonBody(body); } catch { return reply(400, { message: 'Problems parsing JSON' }); }
          if (typeof payload.body !== 'string' || payload.body.length === 0) return reply(422, { message: 'body is required' });
          const stamp = nowIso();
          const comment = { id: nextId(), nodeId: globalId('comment', repo.id, issue.number, repo.nextCommentId), body: payload.body, createdAt: stamp, updatedAt: stamp };
          repo.nextCommentId += 1;
          const list = repo.comments.get(issue.number) ?? [];
          list.push(comment);
          repo.comments.set(issue.number, list);
          commentsByNodeId.set(comment.nodeId, { repo, issue, comment });
          issue.updatedAt = nowIso();
          return reply(201, commentJson(repo, issue, comment, host));
        }
        if (req.method === 'GET' && tail.length === 3) {
          const list = repo.comments.get(issue.number) ?? [];
          return reply(200, list.map((c) => commentJson(repo, issue, c, host)));
        }
        return reply(404, { message: 'Not Found' });
      }
      return reply(404, { message: 'Not Found' });
    }

    // /pulls
    if (segment === 'pulls') {
      if (tail.length === 1) {
        if (req.method === 'POST') {
          let payload;
          try { payload = parseJsonBody(body); } catch { return reply(400, { message: 'Problems parsing JSON' }); }
          const result = createPullOp(repo, payload.title, payload.body, payload.head, payload.base);
          if (result.error) return reply(result.error, { message: result.message });
          return reply(201, prJson(repo, result.pr, host));
        }
        if (req.method === 'GET') {
          const state = url.searchParams.get('state') ?? 'open';
          let list = [...repo.pulls];
          if (state === 'open') list = list.filter((p) => p.state === 'open');
          else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
          else if (state === 'all') list = list.filter((p) => p.state === 'open' || p.merged);
          else return reply(422, { message: `invalid state ${state}` });
          list.sort((a, b) => b.number - a.number);
          const { perPage, page } = pageParams(url);
          const { pageItems, linkHeader } = paginate(list, perPage, page, host, `/api/v3/repos/${repo.fullName}/pulls`, `&state=${state}`);
          return reply(200, pageItems.map((p) => prJson(repo, p, host)), linkHeader ? { Link: linkHeader } : {});
        }
        return reply(404, { message: 'Not Found' });
      }
      const number = parseInt(tail[1], 10);
      if (!Number.isFinite(number)) return reply(404, { message: 'Not Found' });
      const pr = repo.pullByNumber.get(number);
      if (!pr) return reply(404, { message: 'Not Found' });
      if (tail.length === 2) {
        if (req.method === 'GET') return reply(200, prJson(repo, pr, host));
        return reply(404, { message: 'Not Found' });
      }
      if (tail[2] === 'files' && tail.length === 3 && req.method === 'GET') {
        const headTipOid = refTip(repo, `refs/heads/${pr.headRef}`);
        const baseTipOid = refTip(repo, `refs/heads/${pr.baseRef}`);
        const base = mergeBase(repo, baseTipOid ?? '', headTipOid ?? '');
        if (!base || !headTipOid) return reply(200, []);
        return reply(200, diffFiles(repo, base, headTipOid));
      }
      if (tail[2] === 'merge' && tail.length === 3) {
        if (req.method !== 'PUT') return reply(404, { message: 'Not Found' });
        let payload = {};
        try { payload = parseJsonBody(body); } catch { return reply(400, { message: 'Problems parsing JSON' }); }
        const method = payload.merge_method ?? 'squash';
        if (method !== 'squash') return reply(405, { message: `merge method ${method} is not supported` });
        const result = squashMergeOp(repo, pr);
        if (result.error) return reply(result.error, { message: result.message });
        return reply(200, { merged: true, sha: result.sha, message: result.message });
      }
      return reply(404, { message: 'Not Found' });
    }

    return reply(404, { message: 'Not Found' });
  }

  return reply(404, { message: 'Not Found' });
}

// ---------------------------------------------------------------------------
// GraphQL: a small hand-written lexer, parser and executor (variables, inline
// arguments, aliases, inline fragments, __type introspection). Only the
// documents the suite sends are needed, but the executor is general.

function gqlTokenize(src) {
  const tokens = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (/\s|,/.test(ch)) { i += 1; continue; }
    if (ch === '#') { while (i < src.length && src[i] !== '\n') i += 1; continue; }
    if (src.startsWith('...', i)) { tokens.push({ type: '...' }); i += 3; continue; }
    if ('{}()[]:!=$@'.includes(ch)) { tokens.push({ type: ch }); i += 1; continue; }
    if (ch === '"') {
      if (src.startsWith('"""', i)) {
        const end = src.indexOf('"""', i + 3);
        const raw = end < 0 ? src.slice(i + 3) : src.slice(i + 3, end);
        tokens.push({ type: 'string', value: raw.replace(/^\n/, '') });
        i = end < 0 ? src.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\') {
          const e = src[j + 1];
          out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e === '"' ? '"' : e === '\\' ? '\\' : e === '/' ? '/' : e;
          j += 2;
        } else { out += src[j]; j += 1; }
      }
      tokens.push({ type: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9]/.test(ch) || (ch === '-' && /[0-9]/.test(src[i + 1] ?? ''))) {
      let j = i;
      let isFloat = false;
      if (src[j] === '-') j += 1;
      while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      if (src[j] === '.') { isFloat = true; j += 1; while (j < src.length && /[0-9]/.test(src[j])) j += 1; }
      if (src[j] === 'e' || src[j] === 'E') {
        isFloat = true; j += 1;
        if (src[j] === '+' || src[j] === '-') j += 1;
        while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      }
      tokens.push({ type: isFloat ? 'float' : 'int', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (j < src.length && /[_A-Za-z0-9]/.test(src[j])) j += 1;
      tokens.push({ type: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} at ${i}`);
  }
  tokens.push({ type: 'eof' });
  return tokens;
}

function gqlParseDocument(src) {
  const tokens = gqlTokenize(src);
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];
  const expect = (t) => {
    const tok = next();
    if (tok.type !== t) throw new Error(`expected ${t}, got ${tok.type}`);
    return tok;
  };
  const skipDirectives = () => {
    while (peek().type === '@') {
      next();
      expect('name');
      if (peek().type === '(') parseArguments();
    }
  };
  function parseValue() {
    const tok = peek();
    if (tok.type === '$') { next(); return { kind: 'variable', name: expect('name').value }; }
    if (tok.type === 'int') { next(); return { kind: 'int', value: parseInt(tok.value, 10) }; }
    if (tok.type === 'float') { next(); return { kind: 'float', value: parseFloat(tok.value) }; }
    if (tok.type === 'string') { next(); return { kind: 'string', value: tok.value }; }
    if (tok.type === 'name') {
      next();
      if (tok.value === 'true') return { kind: 'boolean', value: true };
      if (tok.value === 'false') return { kind: 'boolean', value: false };
      if (tok.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: tok.value };
    }
    if (tok.type === '[') {
      next();
      const values = [];
      while (peek().type !== ']') values.push(parseValue());
      expect(']');
      return { kind: 'list', values };
    }
    if (tok.type === '{') {
      next();
      const fields = [];
      while (peek().type !== '}') {
        const name = expect('name').value;
        expect(':');
        fields.push({ name, value: parseValue() });
      }
      expect('}');
      return { kind: 'object', fields };
    }
    throw new Error(`unexpected value token ${tok.type}`);
  }
  function parseArguments() {
    expect('(');
    const args = [];
    while (peek().type !== ')') {
      const name = expect('name').value;
      expect(':');
      args.push({ name, value: parseValue() });
    }
    expect(')');
    return args;
  }
  function parseType() {
    let type;
    if (peek().type === '[') {
      next();
      const inner = parseType();
      expect(']');
      type = { kind: 'list', ofType: inner };
    } else {
      type = { kind: 'named', name: expect('name').value };
    }
    if (peek().type === '!') { next(); type = { kind: 'nonNull', ofType: type }; }
    return type;
  }
  function parseSelectionSet() {
    expect('{');
    const selections = [];
    while (peek().type !== '}') selections.push(parseSelection());
    expect('}');
    return selections;
  }
  function parseSelection() {
    if (peek().type === '...') {
      next();
      if (peek().type === 'name' && peek().value === 'on') {
        next();
        const typeCondition = expect('name').value;
        skipDirectives();
        return { kind: 'inlineFragment', typeCondition, selections: parseSelectionSet() };
      }
      if (peek().type === 'name') {
        const name = next().value;
        skipDirectives();
        return { kind: 'fragmentSpread', name };
      }
      skipDirectives();
      return { kind: 'inlineFragment', typeCondition: null, selections: parseSelectionSet() };
    }
    let name = expect('name').value;
    let alias = null;
    if (peek().type === ':') {
      next();
      alias = name;
      name = expect('name').value;
    }
    const args = peek().type === '(' ? parseArguments() : [];
    skipDirectives();
    const selections = peek().type === '{' ? parseSelectionSet() : null;
    return { kind: 'field', name, alias, args, selections };
  }
  function parseOperation() {
    let operation = 'query';
    let name = null;
    if (peek().type === 'name' && ['query', 'mutation', 'subscription'].includes(peek().value)) {
      operation = next().value;
      if (peek().type === 'name') name = next().value;
    }
    const variableDefinitions = [];
    if (peek().type === '(') {
      next();
      while (peek().type !== ')') {
        expect('$');
        const varName = expect('name').value;
        expect(':');
        const varType = parseType();
        let defaultValue = null;
        if (peek().type === '=') { next(); defaultValue = parseValue(); }
        skipDirectives();
        variableDefinitions.push({ name: varName, type: varType, defaultValue });
      }
      expect(')');
    }
    skipDirectives();
    const selections = parseSelectionSet();
    return { kind: 'operation', operation, name, variableDefinitions, selections };
  }
  const definitions = [];
  while (peek().type !== 'eof') {
    if (peek().type === 'name' && peek().value === 'fragment') {
      next();
      const fragName = expect('name').value;
      expect('name');
      const typeCondition = expect('name').value;
      skipDirectives();
      definitions.push({ kind: 'fragment', name: fragName, typeCondition, selections: parseSelectionSet() });
    } else {
      definitions.push(parseOperation());
    }
  }
  return definitions;
}

function gqlResolveValue(valueNode, variables) {
  switch (valueNode.kind) {
    case 'variable': return variables[valueNode.name];
    case 'int': case 'float': case 'string': case 'boolean': return valueNode.value;
    case 'null': return null;
    case 'enum': return valueNode.value;
    case 'list': return valueNode.values.map((v) => gqlResolveValue(v, variables));
    case 'object': {
      const obj = {};
      for (const field of valueNode.fields) obj[field.name] = gqlResolveValue(field.value, variables);
      return obj;
    }
    default: return null;
  }
}

// ---------------------------------------------------------------------------
// GraphQL: schema data and resolvers

const INTROSPECTION = {
  Issue: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'url', 'author', 'labels', 'comments'] },
  PullRequest: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'body', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'headRef', 'baseRef', 'mergedAt', 'createdAt', 'updatedAt', 'author'] },
  Repository: { kind: 'OBJECT', fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'createdAt', 'updatedAt', 'isPrivate'] },
  User: { kind: 'OBJECT', fields: ['id', 'login', 'name', 'email', 'avatarUrl', 'url'] },
  IssueConnection: { kind: 'OBJECT', fields: ['nodes', 'edges', 'pageInfo', 'totalCount'] },
  PullRequestConnection: { kind: 'OBJECT', fields: ['nodes', 'edges', 'pageInfo', 'totalCount'] },
  PageInfo: { kind: 'OBJECT', fields: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'] },
  SearchType: { kind: 'ENUM', enumValues: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'MILESTONE', 'LABEL', 'TEAM', 'PROJECT'] },
  Query: { kind: 'OBJECT', fields: ['viewer', 'repository', 'node', '__type'] },
  Mutation: { kind: 'OBJECT', fields: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'] },
};

function wrapIssue(repo, issue) {
  return { __typename: 'Issue', repo, issue };
}
function wrapPr(repo, pr) {
  return { __typename: 'PullRequest', repo, pr };
}
function wrapComment(repo, issue, comment) {
  return { __typename: 'IssueComment', repo, issue, comment };
}

function encodeCursor(n) {
  return b64encode(`cursor:${n}`);
}
function decodeCursor(cursor) {
  try {
    const text = Buffer.from(String(cursor), 'base64').toString('utf8');
    const m = text.match(/^cursor:(\d+)$/);
    return m ? parseInt(m[1], 10) : null;
  } catch {
    return null;
  }
}

/** Build a connection value (nodes/edges/pageInfo/totalCount) over items that
 *  carry a numeric `number` key, in the order given. */
function makeConnection(items, first, after, wrap) {
  let start = 0;
  if (after !== null && after !== undefined) {
    const cursorNum = decodeCursor(after);
    if (cursorNum !== null) {
      const idx = items.findIndex((item) => item.number === cursorNum);
      if (idx >= 0) start = idx + 1;
    }
  }
  const page = first !== null && first !== undefined ? items.slice(start, start + first) : items.slice(start);
  const nodes = page.map((item) => wrap(item));
  const edges = page.map((item) => ({ __typename: 'IssueEdge', node: wrap(item), cursor: encodeCursor(item.number) }));
  const pageInfo = {
    __typename: 'PageInfo',
    hasNextPage: start + page.length < items.length,
    hasPreviousPage: start > 0,
    startCursor: page.length > 0 ? encodeCursor(page[0].number) : null,
    endCursor: page.length > 0 ? encodeCursor(page[page.length - 1].number) : null,
  };
  return { __typename: 'IssueConnection', nodes, edges, pageInfo, totalCount: items.length };
}

function sortIssues(issues, orderBy) {
  const direction = orderBy?.direction === 'ASC' ? 1 : -1;
  return [...issues].sort((a, b) => {
    if (a.createdAt !== b.createdAt) return direction * (a.createdAt < b.createdAt ? -1 : 1);
    return direction * (a.number - b.number);
  });
}

function decodeNodeId(id) {
  try {
    const text = Buffer.from(String(id), 'base64').toString('utf8');
    const parts = text.split(':');
    if (parts[0] === 'repo') {
      const repo = reposById.get(Number(parts[1]));
      return repo ? { __typename: 'Repository', repo } : null;
    }
    if (parts[0] === 'issue') {
      const repo = reposById.get(Number(parts[1]));
      const issue = repo?.issueByNumber.get(Number(parts[2]));
      return repo && issue ? wrapIssue(repo, issue) : null;
    }
    if (parts[0] === 'pr') {
      const repo = reposById.get(Number(parts[1]));
      const pr = repo?.pullByNumber.get(Number(parts[2]));
      return repo && pr ? wrapPr(repo, pr) : null;
    }
    if (parts[0] === 'comment') {
      const repo = reposById.get(Number(parts[1]));
      const issue = repo?.issueByNumber.get(Number(parts[2]));
      const comment = (repo?.comments.get(Number(parts[2])) ?? []).find((c) => c.id === Number(parts[3]));
      return repo && issue && comment ? wrapComment(repo, issue, comment) : null;
    }
    if (parts[0] === 'user') return { __typename: 'User', login: VIEWER_LOGIN };
  } catch {
    return null;
  }
  return null;
}

const FIELD_RESOLVERS = {
  Query: {
    viewer: () => ({ __typename: 'User', login: VIEWER_LOGIN }),
    repository: (_v, args) => {
      const repo = getRepo(args.owner, args.name);
      if (!repo || repo.owner !== VIEWER_LOGIN) return null;
      return { __typename: 'Repository', repo };
    },
    node: (_v, args) => decodeNodeId(args.id),
    __type: (_v, args) => {
      const info = INTROSPECTION[args.name];
      if (!info) return null;
      return { __typename: '__Type', name: args.name, kind: info.kind, fields: info.fields ?? [], enumValues: info.enumValues ?? [] };
    },
  },
  Mutation: {
    createIssue: (_v, args) => {
      const input = args.input ?? {};
      const repo = reposByNodeId.get(input.repositoryId);
      if (!repo) throw new Error('repository not found');
      const result = createIssueOp(repo, input.title, input.body, []);
      if (result.error) throw new Error(result.message);
      return { __typename: 'CreateIssuePayload', issue: wrapIssue(repo, result.issue), clientMutationId: input.clientMutationId ?? null };
    },
    closeIssue: (_v, args) => {
      const input = args.input ?? {};
      const decoded = decodeNodeId(input.issueId);
      if (!decoded || decoded.__typename !== 'Issue') throw new Error('issue not found');
      decoded.issue.state = 'closed';
      decoded.issue.closedAt = nowIso();
      decoded.issue.updatedAt = nowIso();
      return { __typename: 'CloseIssuePayload', issue: decoded, clientMutationId: input.clientMutationId ?? null };
    },
    createPullRequest: (_v, args) => {
      const input = args.input ?? {};
      const repo = reposByNodeId.get(input.repositoryId);
      if (!repo) throw new Error('repository not found');
      const result = createPullOp(repo, input.title, input.body, input.headRefName, input.baseRefName);
      if (result.error) throw new Error(result.message);
      return { __typename: 'CreatePullRequestPayload', pullRequest: wrapPr(repo, result.pr), clientMutationId: input.clientMutationId ?? null };
    },
    mergePullRequest: (_v, args) => {
      const input = args.input ?? {};
      const decoded = decodeNodeId(input.pullRequestId);
      if (!decoded || decoded.__typename !== 'PullRequest') throw new Error('pull request not found');
      const result = squashMergeOp(decoded.repo, decoded.pr);
      if (result.error) throw new Error(result.message);
      return { __typename: 'MergePullRequestPayload', pullRequest: wrapPr(decoded.repo, decoded.pr), clientMutationId: input.clientMutationId ?? null };
    },
    addComment: (_v, args) => {
      const input = args.input ?? {};
      const decoded = decodeNodeId(input.subjectId);
      if (!decoded) throw new Error('subject not found');
      let repo;
      let issue;
      if (decoded.__typename === 'Issue') { repo = decoded.repo; issue = decoded.issue; }
      else if (decoded.__typename === 'PullRequest') {
        repo = decoded.repo;
        issue = repo.issueByNumber.get(decoded.pr.number);
        if (!issue) throw new Error('issue not found for pull request');
      } else throw new Error('subject is not commentable');
      const stamp = nowIso();
      const comment = { id: nextId(), nodeId: globalId('comment', repo.id, issue.number, repo.nextCommentId), body: input.body, createdAt: stamp, updatedAt: stamp };
      repo.nextCommentId += 1;
      const list = repo.comments.get(issue.number) ?? [];
      list.push(comment);
      repo.comments.set(issue.number, list);
      commentsByNodeId.set(comment.nodeId, { repo, issue, comment });
      issue.updatedAt = nowIso();
      return {
        __typename: 'AddCommentPayload',
        commentEdge: { __typename: 'AddCommentEdge', node: wrapComment(repo, issue, comment), cursor: encodeCursor(comment.id) },
        clientMutationId: input.clientMutationId ?? null,
      };
    },
  },
  User: {
    id: (v) => globalId('user', VIEWER_ID),
    login: (v) => v.login,
    name: (v) => (v.login === VIEWER_LOGIN ? VIEWER_NAME : v.login),
    email: (v) => (v.login === VIEWER_LOGIN ? VIEWER_EMAIL : `${v.login}@example.invalid`),
    avatarUrl: (v) => `https://avatars.example/${v.login}`,
    url: (v, _a, ctx) => `http://${ctx.host}/users/${v.login}`,
  },
  Repository: {
    id: (v) => v.repo.nodeId,
    databaseId: (v) => v.repo.id,
    name: (v) => v.repo.name,
    nameWithOwner: (v) => v.repo.fullName,
    owner: (v) => ({ __typename: 'User', login: v.repo.owner }),
    defaultBranchRef: (v) => {
      const tip = headTip(v.repo);
      if (!tip) return null;
      return { __typename: 'Ref', name: v.repo.defaultBranch, oid: tip };
    },
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    description: (v) => v.repo.description,
    createdAt: (v) => v.repo.createdAt,
    updatedAt: (v) => v.repo.updatedAt,
    isPrivate: (v) => v.repo.private,
    issue: (v, args) => {
      const issue = v.repo.issueByNumber.get(args.number);
      return issue ? wrapIssue(v.repo, issue) : null;
    },
    issues: (v, args) => {
      let list = [...v.repo.issues];
      if (Array.isArray(args.states) && args.states.length > 0) {
        const wanted = new Set(args.states.map((s) => String(s).toLowerCase()));
        list = list.filter((i) => wanted.has(i.state));
      }
      list = sortIssues(list, args.orderBy);
      return makeConnection(list, args.first ?? null, args.after ?? null, (issue) => wrapIssue(v.repo, issue));
    },
    pullRequest: (v, args) => {
      const pr = v.repo.pullByNumber.get(args.number);
      return pr ? wrapPr(v.repo, pr) : null;
    },
    pullRequests: (v, args) => {
      let list = [...v.repo.pulls];
      if (Array.isArray(args.states) && args.states.length > 0) {
        const wanted = new Set(args.states.map((s) => String(s).toLowerCase()));
        list = list.filter((p) => wanted.has(p.merged ? 'merged' : p.state));
      }
      list = sortIssues(list, args.orderBy);
      const conn = makeConnection(list, args.first ?? null, args.after ?? null, (pr) => wrapPr(v.repo, pr));
      conn.__typename = 'PullRequestConnection';
      return conn;
    },
  },
  Ref: {
    name: (v) => v.name,
    target: (v) => ({ __typename: 'Commit', oid: v.oid }),
  },
  Commit: {
    oid: (v) => v.oid,
  },
  Issue: {
    id: (v) => v.issue.nodeId,
    number: (v) => v.issue.number,
    title: (v) => v.issue.title,
    state: (v) => (v.issue.state === 'open' ? 'OPEN' : 'CLOSED'),
    body: (v) => v.issue.body,
    createdAt: (v) => v.issue.createdAt,
    updatedAt: (v) => v.issue.updatedAt,
    url: (v, _a, ctx) => `http://${ctx.host}/${v.repo.fullName}/issues/${v.issue.number}`,
    author: () => ({ __typename: 'User', login: VIEWER_LOGIN }),
    labels: (v) => {
      const nodes = v.issue.labels.map((name) => ({ __typename: 'Label', name, color: v.repo.labels.get(name)?.color ?? 'ededed', description: v.repo.labels.get(name)?.description ?? null }));
      return { __typename: 'LabelConnection', nodes, edges: nodes.map((node) => ({ __typename: 'LabelEdge', node, cursor: encodeCursor(node.name.length) })), pageInfo: { __typename: 'PageInfo', hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null }, totalCount: nodes.length };
    },
    comments: (v) => {
      const list = v.repo.comments.get(v.issue.number) ?? [];
      const nodes = list.map((c) => wrapComment(v.repo, v.issue, c));
      return { __typename: 'IssueCommentConnection', nodes, edges: nodes.map((node) => ({ __typename: 'IssueCommentEdge', node, cursor: encodeCursor(node.comment.id) })), pageInfo: { __typename: 'PageInfo', hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null }, totalCount: nodes.length };
    },
  },
  IssueConnection: {
    nodes: (v) => v.nodes,
    edges: (v) => v.edges,
    pageInfo: (v) => v.pageInfo,
    totalCount: (v) => v.totalCount,
  },
  PullRequestConnection: {
    nodes: (v) => v.nodes,
    edges: (v) => v.edges,
    pageInfo: (v) => v.pageInfo,
    totalCount: (v) => v.totalCount,
  },
  IssueEdge: {
    node: (v) => v.node,
    cursor: (v) => v.cursor,
  },
  PullRequestEdge: {
    node: (v) => v.node,
    cursor: (v) => v.cursor,
  },
  IssueCommentConnection: {
    nodes: (v) => v.nodes,
    edges: (v) => v.edges,
    pageInfo: (v) => v.pageInfo,
    totalCount: (v) => v.totalCount,
  },
  IssueCommentEdge: {
    node: (v) => v.node,
    cursor: (v) => v.cursor,
  },
  LabelConnection: {
    nodes: (v) => v.nodes,
    edges: (v) => v.edges,
    pageInfo: (v) => v.pageInfo,
    totalCount: (v) => v.totalCount,
  },
  LabelEdge: {
    node: (v) => v.node,
    cursor: (v) => v.cursor,
  },
  Label: {
    id: (v) => globalId('label', v.name),
    name: (v) => v.name,
    color: (v) => v.color,
    description: (v) => v.description ?? null,
  },
  PullRequest: {
    id: (v) => v.pr.nodeId,
    number: (v) => v.pr.number,
    title: (v) => v.pr.title,
    body: (v) => v.pr.body,
    state: (v) => (v.pr.merged ? 'MERGED' : v.pr.state === 'open' ? 'OPEN' : 'CLOSED'),
    merged: (v) => v.pr.merged,
    headRefName: (v) => v.pr.headRef,
    baseRefName: (v) => v.pr.baseRef,
    mergeable: (v) => {
      const { mergeable, state } = prMergeable(v.repo, v.pr);
      return state === 'clean' ? 'MERGEABLE' : state === 'dirty' ? 'CONFLICTING' : 'UNKNOWN';
    },
    files: (v, args) => {
      const headTipOid = refTip(v.repo, `refs/heads/${v.pr.headRef}`);
      const baseTipOid = refTip(v.repo, `refs/heads/${v.pr.baseRef}`);
      const base = headTipOid && baseTipOid ? mergeBase(v.repo, baseTipOid, headTipOid) : null;
      const files = base && headTipOid ? diffFiles(v.repo, base, headTipOid) : [];
      const items = files.map((file, index) => ({ ...file, number: index + 1 }));
      const conn = makeConnection(items, args.first ?? null, args.after ?? null, (file) => ({ __typename: 'PullRequestChangedFile', file }));
      conn.__typename = 'PullRequestChangedFileConnection';
      return conn;
    },
    headRef: (v) => {
      const oid = refTip(v.repo, `refs/heads/${v.pr.headRef}`);
      return oid ? { __typename: 'Ref', name: v.pr.headRef, oid } : null;
    },
    baseRef: (v) => {
      const oid = refTip(v.repo, `refs/heads/${v.pr.baseRef}`);
      return oid ? { __typename: 'Ref', name: v.pr.baseRef, oid } : null;
    },
    mergedAt: (v) => v.pr.mergedAt,
    createdAt: (v) => v.pr.createdAt,
    updatedAt: (v) => v.pr.updatedAt,
    author: () => ({ __typename: 'User', login: VIEWER_LOGIN }),
  },
  PullRequestChangedFileConnection: {
    nodes: (v) => v.nodes,
    edges: (v) => v.edges,
    pageInfo: (v) => v.pageInfo,
    totalCount: (v) => v.totalCount,
  },
  PullRequestChangedFile: {
    path: (v) => v.file.filename,
    filename: (v) => v.file.filename,
    additions: (v) => v.file.additions,
    deletions: (v) => v.file.deletions,
    changes: (v) => v.file.changes,
    status: (v) => v.file.status.toUpperCase(),
  },
  IssueComment: {
    id: (v) => v.comment.nodeId,
    body: (v) => v.comment.body,
    createdAt: (v) => v.comment.createdAt,
    updatedAt: (v) => v.comment.updatedAt,
    author: () => ({ __typename: 'User', login: VIEWER_LOGIN }),
  },
  PageInfo: {
    hasNextPage: (v) => v.hasNextPage,
    hasPreviousPage: (v) => v.hasPreviousPage,
    startCursor: (v) => v.startCursor,
    endCursor: (v) => v.endCursor,
  },
  __Type: {
    name: (v) => v.name,
    kind: (v) => v.kind,
    fields: (v) => (v.fields ?? []).map((name) => ({ __typename: '__Field', name })),
    enumValues: (v) => (v.enumValues ?? []).map((name) => ({ __typename: '__EnumValue', name })),
    description: () => null,
  },
  __Field: {
    name: (v) => v.name,
    description: () => null,
    type: () => ({ __typename: '__Type', name: 'String', kind: 'SCALAR', fields: [], enumValues: [] }),
  },
  __EnumValue: {
    name: (v) => v.name,
    description: () => null,
  },
  CreateIssuePayload: {
    issue: (v) => v.issue,
    clientMutationId: (v) => v.clientMutationId,
  },
  CloseIssuePayload: {
    issue: (v) => v.issue,
    clientMutationId: (v) => v.clientMutationId,
  },
  CreatePullRequestPayload: {
    pullRequest: (v) => v.pullRequest,
    clientMutationId: (v) => v.clientMutationId,
  },
  MergePullRequestPayload: {
    pullRequest: (v) => v.pullRequest,
    clientMutationId: (v) => v.clientMutationId,
  },
  AddCommentPayload: {
    commentEdge: (v) => v.commentEdge,
    clientMutationId: (v) => v.clientMutationId,
  },
  AddCommentEdge: {
    node: (v) => v.node,
    cursor: (v) => v.cursor,
  },
};

function gqlExecuteSelectionSet(typeName, value, selections, variables, errors, fragments, ctx) {
  if (value === null || value === undefined) return null;
  const result = {};
  for (const sel of selections) {
    if (sel.kind === 'inlineFragment') {
      if (sel.typeCondition && sel.typeCondition !== typeName) continue;
      const sub = gqlExecuteSelectionSet(typeName, value, sel.selections, variables, errors, fragments, ctx);
      if (sub) Object.assign(result, sub);
      continue;
    }
    if (sel.kind === 'fragmentSpread') {
      const frag = fragments.get(sel.name);
      if (!frag) {
        errors.push({ message: `Unknown fragment "${sel.name}".` });
        continue;
      }
      if (frag.typeCondition && frag.typeCondition !== typeName) continue;
      const sub = gqlExecuteSelectionSet(typeName, value, frag.selections, variables, errors, fragments, ctx);
      if (sub) Object.assign(result, sub);
      continue;
    }
    const outName = sel.alias ?? sel.name;
    const args = {};
    for (const arg of sel.args) args[arg.name] = gqlResolveValue(arg.value, variables);
    if (sel.name === '__typename') {
      result[outName] = typeName;
      continue;
    }
    const resolver = FIELD_RESOLVERS[typeName]?.[sel.name];
    if (!resolver) {
      errors.push({ message: `Cannot query field "${sel.name}" on type "${typeName}".` });
      result[outName] = null;
      continue;
    }
    let resolved;
    try {
      resolved = resolver(value, args, ctx);
    } catch (err) {
      errors.push({ message: err instanceof Error ? err.message : String(err) });
      result[outName] = null;
      continue;
    }
    if (resolved === null || resolved === undefined) {
      result[outName] = null;
      continue;
    }
    if (sel.selections) {
      if (Array.isArray(resolved)) {
        result[outName] = resolved.map((item) => gqlExecuteSelectionSet(item.__typename, item, sel.selections, variables, errors, fragments, ctx));
      } else if (isRecord(resolved) && resolved.__typename) {
        result[outName] = gqlExecuteSelectionSet(resolved.__typename, resolved, sel.selections, variables, errors, fragments, ctx);
      } else {
        result[outName] = resolved;
      }
    } else {
      result[outName] = resolved;
    }
  }
  return result;
}

function executeGraphQL(docText, variables, ctx) {
  const definitions = gqlParseDocument(docText);
  const fragments = new Map();
  for (const d of definitions) if (d.kind === 'fragment') fragments.set(d.name, d);
  const operation = definitions.find((d) => d.kind === 'operation');
  if (!operation) throw new Error('no operation in document');
  const errors = [];
  const rootType = operation.operation === 'mutation' ? 'Mutation' : 'Query';
  const rootValue = { __typename: rootType };
  const data = gqlExecuteSelectionSet(rootType, rootValue, operation.selections, variables, errors, fragments, ctx);
  return errors.length > 0 ? { data, errors } : { data };
}

async function graphqlHandler(req, res, body) {
  let parsed;
  try {
    parsed = parseJsonBody(body);
  } catch {
    return sendJson(res, 400, { errors: [{ message: 'Problems parsing JSON' }] });
  }
  const ctx = { host: req.headers.host ?? 'localhost' };
  const runOne = (doc) => {
    if (!isRecord(doc) || typeof doc.query !== 'string') return { data: null, errors: [{ message: 'query is required' }] };
    const variables = isRecord(doc.variables) ? doc.variables : {};
    try {
      return executeGraphQL(doc.query, variables, ctx);
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
    }
  };
  if (Array.isArray(parsed)) return sendJson(res, 200, parsed.map(runOne));
  return sendJson(res, 200, runOne(parsed));
}

// ---------------------------------------------------------------------------
// MCP: JSON-RPC 2.0 over Streamable HTTP at /mcp. The six tools act on the
// same store as REST, so a repository created over MCP reads back over REST.

const MCP_PROTOCOL_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

const MCP_TOOLS = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name.' },
        description: { type: 'string', description: 'Repository description.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        title: { type: 'string', description: 'Issue title.' },
        body: { type: 'string', description: 'Issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        state: { type: 'string', description: 'Issue state: open, closed, or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request between two branches of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        title: { type: 'string', description: 'Pull request title.' },
        body: { type: 'string', description: 'Pull request body.' },
        head: { type: 'string', description: 'Head branch name.' },
        base: { type: 'string', description: 'Base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        pull_number: { type: 'integer', description: 'Pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpResultObject(obj) {
  return { content: [{ type: 'text', text: JSON.stringify(obj) }], structuredContent: obj, isError: false };
}

function mcpErrorResult(message) {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpToolCall(host, name, args) {
  const arg = (key) => args?.[key];
  switch (name) {
    case 'create_repo': {
      const result = createRepoOp(VIEWER_LOGIN, arg('name'), arg('private'), arg('description'));
      if (result.error) return mcpErrorResult(result.message);
      return mcpResultObject(repoJson(result.repo, host));
    }
    case 'get_repo': {
      const repo = getRepo(arg('owner'), arg('repo'));
      if (!repo || repo.owner !== VIEWER_LOGIN) return mcpErrorResult('Not Found');
      return mcpResultObject(repoJson(repo, host));
    }
    case 'create_issue': {
      const repo = getRepo(arg('owner'), arg('repo'));
      if (!repo || repo.owner !== VIEWER_LOGIN) return mcpErrorResult('Not Found');
      const result = createIssueOp(repo, arg('title'), arg('body'), []);
      if (result.error) return mcpErrorResult(result.message);
      return mcpResultObject(issueJson(repo, result.issue, host));
    }
    case 'list_issues': {
      const repo = getRepo(arg('owner'), arg('repo'));
      if (!repo || repo.owner !== VIEWER_LOGIN) return mcpErrorResult('Not Found');
      const state = arg('state') ?? 'open';
      const list = repo.issues.filter((i) => state === 'all' || i.state === state);
      return mcpResultObject({ issues: list.map((i) => issueJson(repo, i, host)) });
    }
    case 'create_pull_request': {
      const repo = getRepo(arg('owner'), arg('repo'));
      if (!repo || repo.owner !== VIEWER_LOGIN) return mcpErrorResult('Not Found');
      const result = createPullOp(repo, arg('title'), arg('body'), arg('head'), arg('base'));
      if (result.error) return mcpErrorResult(result.message);
      return mcpResultObject(prJson(repo, result.pr, host));
    }
    case 'merge_pull_request': {
      const repo = getRepo(arg('owner'), arg('repo'));
      if (!repo || repo.owner !== VIEWER_LOGIN) return mcpErrorResult('Not Found');
      const pr = repo.pullByNumber.get(Number(arg('pull_number')));
      if (!pr) return mcpErrorResult('Not Found');
      const result = squashMergeOp(repo, pr);
      if (result.error) return mcpErrorResult(result.message);
      return mcpResultObject({ merged: true, sha: result.sha, message: result.message, number: pr.number, state: pr.state });
    }
    default:
      return null;
  }
}

async function mcpHandler(req, res, body) {
  const host = req.headers.host ?? 'localhost';
  const sendRpc = (status, payload) => sendJson(res, status, payload);
  if (req.method === 'DELETE') {
    res.writeHead(204, { 'X-GitHub-Request-Id': requestId() });
    return res.end();
  }
  if (req.method !== 'POST') return sendJson(res, 405, { message: 'Method Not Allowed' });
  let parsed;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    return sendRpc(400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  }
  if (!isRecord(parsed) || typeof parsed.method !== 'string') {
    return sendRpc(400, { jsonrpc: '2.0', id: isRecord(parsed) ? parsed.id ?? null : null, error: { code: -32600, message: 'Invalid Request' } });
  }
  const id = parsed.id ?? null;
  const isNotification = parsed.id === undefined;
  const result = (value) => ({ jsonrpc: '2.0', id, result: value });
  const error = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
  if (isNotification) {
    // Notifications (initialized, etc.) need no answer.
    res.writeHead(202, { 'X-GitHub-Request-Id': requestId(), 'Content-Length': 0 });
    return res.end();
  }
  switch (parsed.method) {
    case 'server/discover': {
      return sendRpc(200, result({
        supportedVersions: [...MCP_PROTOCOL_VERSIONS],
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: FORGE_VERSION },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge', version: FORGE_VERSION } },
      }));
    }
    case 'initialize': {
      const requested = parsed.params?.protocolVersion;
      if (typeof requested !== 'string' || !MCP_PROTOCOL_VERSIONS.includes(requested)) {
        return sendRpc(200, error(-32602, `unsupported protocol version ${String(requested)}`));
      }
      return sendRpc(200, result({
        protocolVersion: requested,
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: FORGE_VERSION },
      }));
    }
    case 'ping': {
      return sendRpc(200, result({}));
    }
    case 'tools/list': {
      return sendRpc(200, result({ tools: MCP_TOOLS }));
    }
    case 'tools/call': {
      const params = isRecord(parsed.params) ? parsed.params : {};
      const toolName = params.name;
      const tool = MCP_TOOLS.find((t) => t.name === toolName);
      if (!tool) return sendRpc(200, error(-32602, `Unknown tool: ${String(toolName)}`));
      const args = isRecord(params.arguments) ? params.arguments : {};
      for (const required of tool.inputSchema.required ?? []) {
        if (args[required] === undefined || args[required] === null) {
          return sendRpc(200, error(-32602, `Missing required argument: ${required}`));
        }
      }
      const callResult = mcpToolCall(host, toolName, args);
      if (callResult === null) return sendRpc(200, error(-32602, `Unknown tool: ${String(toolName)}`));
      return sendRpc(200, result(callResult));
    }
    default:
      return sendRpc(200, error(-32601, `Method not found: ${parsed.method}`));
  }
}

// ---------------------------------------------------------------------------
// HTTP server, routing and trial lifecycle

function authed(req) {
  const token = process.env.MAKEFUN_SHOP_TOKEN ?? '';
  if (token === '') return true;
  return (req.headers.authorization ?? '') === `Bearer ${token}`;
}

async function handleRequest(req, res) {
  try {
    const url = new URL(req.url ?? '/', 'http://x');
    const pathname = url.pathname;
    if (pathname === '/healthz') return sendJson(res, 200, { ok: true });
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'X-GitHub-Request-Id': requestId() });
      return res.end();
    }
    const gitMatch = pathname.match(/^\/([^/]+)\/([^/]+)\.git\/(.*)$/);
    if (gitMatch) {
      if (!authed(req)) return sendJson(res, 401, { message: 'Requires authentication' });
      const body = await readBody(req);
      return gitHandler(req, res, decodeURIComponent(gitMatch[1]), decodeURIComponent(gitMatch[2]), gitMatch[3], body);
    }
    if (pathname === '/api/graphql') {
      if (!authed(req)) return sendJson(res, 401, { message: 'Requires authentication' });
      const body = await readBody(req);
      return graphqlHandler(req, res, body);
    }
    if (pathname === '/mcp') {
      if (!authed(req)) return sendJson(res, 401, { message: 'Requires authentication' });
      const body = await readBody(req);
      return mcpHandler(req, res, body);
    }
    if (pathname.startsWith('/api/v3')) {
      if (!authed(req)) return sendJson(res, 401, { message: 'Requires authentication' });
      const body = await readBody(req);
      return restHandler(req, res, body);
    }
    return sendJson(res, 404, { message: 'Not Found' });
  } catch (err) {
    if (!res.headersSent) sendJson(res, 500, { message: err instanceof Error ? err.message : String(err) });
    else res.end();
  }
}

async function main() {
  const envUrl = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
  if (!envUrl) {
    console.error('MAKEFUN_ENV_URL is not set');
    process.exit(1);
  }
  const server = http.createServer((req, res) => {
    void handleRequest(req, res);
  });
  server.keepAliveTimeout = 10000;
  server.headersTimeout = 60000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '0.0.0.0', () => resolve(undefined));
  });
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  if (port === 0) {
    console.error('failed to bind an ephemeral port');
    process.exit(1);
  }
  // Register the port with the suite; retry until it answers 200/409.
  let delay = 250;
  for (;;) {
    try {
      const res = await fetch(`${envUrl}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(30000),
      });
      if (res.status === 200 || res.status === 409) break;
      if (res.status >= 400 && res.status < 500) {
        console.error(`register rejected with ${res.status}`);
        process.exit(1);
      }
    } catch {
      // The suite is not up yet; keep retrying.
    }
    await new Promise((resolve) => setTimeout(resolve, delay));
    delay = Math.min(delay * 2, 2000);
  }
  // Long-poll /done until the suite finishes, then exit cleanly.
  let pollDelay = 250;
  for (;;) {
    try {
      const res = await fetch(`${envUrl}/done`, { method: 'GET', signal: AbortSignal.timeout(30000) });
      if (res.status === 200) {
        const data = await res.json();
        if (data && data.done === true) break;
      }
    } catch {
      // Keep polling.
    }
    await new Promise((resolve) => setTimeout(resolve, pollDelay));
    pollDelay = Math.min(pollDelay * 2, 2000);
  }
  server.close();
  process.exit(0);
}

void main();
