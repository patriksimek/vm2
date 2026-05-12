#!/usr/bin/env node
// List non-published GitHub Security Advisories on patriksimek/vm2.
//
// Uses the same session cookie as scripts/read-ghsa-thread.mjs. See that file
// for cookie acquisition instructions.
//
// Usage:
//   node scripts/list-advisories.mjs              # non-published (default)
//   node scripts/list-advisories.mjs --all        # published too
//   node scripts/list-advisories.mjs --published  # only published

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const OWNER = 'patriksimek';
const REPO = 'vm2';
const ENV_FILE = resolve(dirname(fileURLToPath(import.meta.url)), '..', '.env');

function loadDotenv(path) {
  if (!existsSync(path)) return;
  for (const rawLine of readFileSync(path, 'utf8').split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = val;
  }
}

loadDotenv(ENV_FILE);

function die(msg, code = 1) {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(code);
}

function loadCookie() {
  const c = process.env.GH_SESSION_COOKIE?.trim();
  if (!c) die(`GH_SESSION_COOKIE not set. Add it to ${ENV_FILE} or export in your shell.`);
  return c;
}

function decodeEntities(s) {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)));
}

function stripTags(s) {
  return decodeEntities(s.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();
}

async function fetchPage(url, cookie) {
  const res = await fetch(url, {
    redirect: 'manual',
    headers: {
      cookie,
      'user-agent': 'vm2-maintainer ghsa-list',
      accept: 'text/html',
    },
  });
  if (res.status >= 300 && res.status < 400) {
    const loc = res.headers.get('location') || '';
    if (loc.includes('/login')) {
      die(`cookie expired. Refresh GH_SESSION_COOKIE (see scripts/read-ghsa-thread.mjs header).`);
    }
    die(`unexpected redirect to ${loc}`);
  }
  if (!res.ok) die(`HTTP ${res.status} fetching ${url}`);
  const html = await res.text();
  if (/<title>Sign in to GitHub/i.test(html)) {
    die(`got login page despite 200 OK — cookie likely stale.`);
  }
  return html;
}

// Each row is an <li class="Box-row..."> containing a status icon, title link,
// id, opened-by metadata, status label, and severity label.
function parseRows(html) {
  const rows = [];
  const liRe = /<li\b[^>]*class="[^"]*Box-row[^"]*"[^>]*>([\s\S]*?)<\/li>/gi;
  let m;
  while ((m = liRe.exec(html)) !== null) {
    const block = m[1];

    const idM = block.match(/href="\/[^"]+\/security\/advisories\/(GHSA-[a-z0-9-]+)"/i);
    if (!idM) continue;
    const ghsa = idM[1];

    const titleM = block.match(
      /<a\b[^>]*href="\/[^"]+\/security\/advisories\/GHSA-[a-z0-9-]+"[^>]*class="[^"]*Link--primary[^"]*"[^>]*>([\s\S]*?)<\/a>/i,
    );
    const title = titleM ? stripTags(titleM[1]) : '(no title)';

    const statusM = block.match(/aria-label="([A-Za-z]+) advisory"/i);
    const status = statusM ? statusM[1] : null;

    const sevM = block.match(/title="Severity:\s*([^"]+)"/i);
    const severity = sevM ? sevM[1] : null;

    const dateM = block.match(/<relative-time\b[^>]*datetime="([^"]+)"/i);
    const date = dateM ? dateM[1] : null;

    const verbM = block.match(/<span\b[^>]*class="opened-by"[^>]*>\s*([A-Za-z]+)\s*<relative-time/i);
    const verb = verbM ? verbM[1] : null;

    const authorM = block.match(/<a\b[^>]*class="author[^"]*"[^>]*href="\/([A-Za-z0-9-]+)"/i)
      || block.match(/data-hovercard-url="\/users\/([A-Za-z0-9-]+)\/hovercard"/i);
    const author = authorM ? authorM[1] : null;

    // Fine-grained sub-status label (e.g. "Triage", "Draft") sits in a small
    // <span title="X" class="Label Label--secondary">X</span> next to severity.
    const subM = block.match(/<span\b[^>]*title="([^"]+)"[^>]*class="Label Label--secondary"/i);
    const subStatus = subM ? subM[1] : null;

    rows.push({ ghsa, title, status, subStatus, severity, verb, date, author });
  }
  return rows;
}

function parseNextPage(html, currentUrl) {
  const m = html.match(/<a\b[^>]*aria-label="Next page"[^>]*href="([^"]+)"/i)
    || html.match(/<a\b[^>]*href="([^"]+)"[^>]*aria-label="Next page"/i);
  if (!m) return null;
  return new URL(decodeEntities(m[1]), currentUrl).toString();
}

async function fetchAll(stateParam, cookie) {
  const base = `https://github.com/${OWNER}/${REPO}/security/advisories`;
  let url = stateParam ? `${base}?state=${stateParam}` : base;
  const all = [];
  const seen = new Set();
  while (url) {
    const html = await fetchPage(url, cookie);
    const rows = parseRows(html);
    for (const r of rows) {
      if (seen.has(r.ghsa)) continue;
      seen.add(r.ghsa);
      all.push(r);
    }
    const next = parseNextPage(html, url);
    if (!next || next === url) break;
    url = next;
  }
  return all;
}

function fmtDate(iso) {
  if (!iso) return '';
  return iso.replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

function renderTable(rows) {
  if (rows.length === 0) return '_No advisories matched._';
  const lines = [];
  lines.push('| GHSA | Title | Status | Severity | Opened | By |');
  lines.push('|------|-------|--------|----------|--------|----|');
  for (const r of rows) {
    const status = r.subStatus || r.status || '?';
    const sev = r.severity || '?';
    const title = r.title.replace(/\|/g, '\\|');
    const opened = fmtDate(r.date);
    const verb = r.verb ? ` (${r.verb})` : '';
    lines.push(`| ${r.ghsa} | ${title} | ${status} | ${sev} | ${opened}${verb} | ${r.author ? '@' + r.author : ''} |`);
  }
  return lines.join('\n');
}

async function main() {
  const args = process.argv.slice(2);
  let mode = 'non-published';
  if (args.includes('--all')) mode = 'all';
  else if (args.includes('--published')) mode = 'published';

  const cookie = loadCookie();

  let rows = [];
  if (mode === 'published') {
    rows = await fetchAll('published', cookie);
  } else if (mode === 'all') {
    const a = await fetchAll('triage', cookie);
    const b = await fetchAll('published', cookie);
    rows = [...a, ...b];
  } else {
    rows = await fetchAll('triage', cookie);
  }

  // Sort newest first.
  rows.sort((a, b) => (b.date || '').localeCompare(a.date || ''));

  const heading = mode === 'published'
    ? `Published advisories — ${OWNER}/${REPO}`
    : mode === 'all'
      ? `All advisories — ${OWNER}/${REPO}`
      : `Non-published advisories — ${OWNER}/${REPO}`;

  process.stdout.write(`# ${heading}\n\n`);
  process.stdout.write(`Total: ${rows.length}\n\n`);
  process.stdout.write(renderTable(rows) + '\n');
}

main().catch((e) => die(e.stack || String(e)));
