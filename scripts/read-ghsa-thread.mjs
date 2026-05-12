#!/usr/bin/env node
// Read the private comment thread of a GitHub Security Advisory.
//
// GitHub's REST/GraphQL API does not expose advisory comments, so this scrapes
// the authenticated web UI using a session cookie copied from a logged-in
// browser. The `user_session` cookie with "Remember me" lasts ~12 months.
//
// Usage:
//   GH_SESSION_COOKIE='user_session=...; _gh_sess=...' \
//     node scripts/read-ghsa-thread.mjs GHSA-xxxx-xxxx-xxxx
//
//   # full advisory URL also accepted (repo segment is ignored):
//   node scripts/read-ghsa-thread.mjs https://github.com/patriksimek/vm2/security/advisories/GHSA-xxxx-xxxx-xxxx
//
// How to refresh the cookie when it expires:
//   1. Open github.com in a logged-in browser (check "Remember me")
//   2. DevTools -> Application -> Cookies -> https://github.com
//   3. Copy the values of `user_session` and `_gh_sess`
//   4. Put in .env at repo root: GH_SESSION_COOKIE='user_session=VALUE; _gh_sess=VALUE'
//      (or export the same env var in your shell)

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const OWNER = 'patriksimek';
const REPO = 'vm2';
const ENV_FILE = resolve(dirname(fileURLToPath(import.meta.url)), '..', '.env');

function loadDotenv(path) {
  if (!existsSync(path)) return;
  const text = readFileSync(path, 'utf8');
  for (const rawLine of text.split('\n')) {
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
  if (!c) die(`GH_SESSION_COOKIE not set. Add it to ${ENV_FILE} or export in your shell. See script header.`);
  return c;
}

function parseArgs(argv) {
  const args = argv.slice(2);
  if (args.length !== 1) {
    die(`usage: read-ghsa-thread.mjs <GHSA-id-or-url>`);
  }
  const arg = args[0];
  if (arg.startsWith('http')) {
    const m = arg.match(/\/security\/advisories\/(GHSA-[a-z0-9-]+)/i);
    if (!m) die(`could not parse advisory URL: ${arg}`);
    return { ghsa: m[1] };
  }
  if (!/^GHSA-[a-z0-9-]+$/i.test(arg)) die(`expected GHSA-id, got: ${arg}`);
  return { ghsa: arg };
}

async function fetchAdvisory({ ghsa }, cookie) {
  const url = `https://github.com/${OWNER}/${REPO}/security/advisories/${ghsa}`;
  const res = await fetch(url, {
    redirect: 'manual',
    headers: {
      cookie,
      'user-agent': 'vm2-maintainer ghsa-thread-reader',
      accept: 'text/html,application/xhtml+xml',
    },
  });

  if (res.status >= 300 && res.status < 400) {
    const loc = res.headers.get('location') || '';
    if (loc.includes('/login')) {
      die(
        `cookie expired or invalid (redirected to ${loc}).\n` +
        `Refresh: open github.com in a logged-in browser, copy user_session + _gh_sess cookies, ` +
        `then update GH_SESSION_COOKIE.`,
      );
    }
    die(`unexpected redirect to ${loc}`);
  }
  if (res.status === 404) die(`advisory not found (404). Check the GHSA id and that your account has access to ${OWNER}/${REPO}.`);
  if (!res.ok) die(`HTTP ${res.status} fetching ${url}`);

  const html = await res.text();
  if (/<title>Sign in to GitHub/i.test(html)) {
    die(`got login page despite 200 OK — cookie likely stale. Refresh and retry.`);
  }
  return { url, html };
}

// --- HTML extraction -------------------------------------------------------
// GitHub's markup changes over time; these regexes target stable signals.
// If output looks wrong, dump html with --debug and adjust.

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

function htmlToMarkdown(html) {
  let out = html;

  out = out.replace(/<pre[^>]*>\s*<code[^>]*>([\s\S]*?)<\/code>\s*<\/pre>/gi, (_, code) => {
    return '\n```\n' + decodeEntities(code.replace(/<[^>]+>/g, '')) + '\n```\n';
  });
  out = out.replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, (_, c) => '`' + decodeEntities(c.replace(/<[^>]+>/g, '')) + '`');

  out = out.replace(/<a [^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi, (_, href, text) => {
    const t = decodeEntities(text.replace(/<[^>]+>/g, '')).trim();
    return t ? `[${t}](${href})` : href;
  });

  out = out.replace(/<(strong|b)[^>]*>([\s\S]*?)<\/\1>/gi, '**$2**');
  out = out.replace(/<(em|i)[^>]*>([\s\S]*?)<\/\1>/gi, '_$2_');
  out = out.replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, '- $1\n');
  out = out.replace(/<br\s*\/?>/gi, '\n');
  out = out.replace(/<\/(p|div|ul|ol|h[1-6])>/gi, '\n\n');
  out = out.replace(/<[^>]+>/g, '');
  out = decodeEntities(out);
  out = out.replace(/\n{3,}/g, '\n\n').trim();
  return out;
}

function extractTitle(html) {
  const m = html.match(/<h1[^>]*class="[^"]*gh-header-title[^"]*"[^>]*>([\s\S]*?)<\/h1>/i)
    || html.match(/<title>([\s\S]*?)<\/title>/i);
  if (!m) return null;
  return decodeEntities(m[1].replace(/<[^>]+>/g, '')).trim();
}

function extractSeverity(html) {
  const m = html.match(/data-severity="([^"]+)"/i)
    || html.match(/Severity[\s\S]{0,200}?(Critical|High|Moderate|Low)/i);
  return m ? m[1] : null;
}

function extractStatus(html) {
  const m = html.match(/title="Advisory status:\s*([^"]+)"/i);
  return m ? m[1].trim() : null;
}

// The advisory's initial report. Rendered above the comment timeline as the
// "Description" block, with the reporter listed in the Credits sidebar.
function extractInitialPost(html) {
  const bodyM = html.match(
    /<h2[^>]*class="Box-title[^"]*"[^>]*>\s*Description\s*<\/h2>[\s\S]*?<div\b[^>]*class="[^"]*markdown-body[^"]*comment-body[^"]*"[^>]*>([\s\S]*?)<\/div>\s*<\/div>/i,
  );
  if (!bodyM) return null;
  const body = htmlToMarkdown(bodyM[1]);
  if (!body) return null;

  // Reporter login: scope to the Credits sidebar section, then grab the
  // first user hovercard URL inside it. `data-hovercard-url="/users/<login>/hovercard"`
  // is the most stable signal.
  let author = '(reporter)';
  const credSection = html.match(/aria-label="Advisory Credits"[\s\S]{0,3000}/i);
  if (credSection) {
    const u = credSection[0].match(/data-hovercard-url="\/users\/([A-Za-z0-9-]+)\/hovercard"/i);
    if (u) author = u[1];
  }

  // Earliest <relative-time datetime="..."> on the page = advisory creation.
  const dates = [...html.matchAll(/<relative-time\b[^>]*datetime="([^"]+)"/gi)]
    .map((m) => m[1])
    .filter(Boolean)
    .sort();
  const date = dates[0] || null;

  return { author, date, body };
}

// Split HTML into comment blocks. Each comment lives in a div whose id starts
// with `discussion_r` or `repository_advisory_comment_`, or has class
// `timeline-comment`. We anchor on `timeline-comment` for reliability.
//
// IMPORTANT: match the bare `timeline-comment` class only, not BEM-suffixed
// variants like `timeline-comment-wrapper`, `-header`, `-action`. The reply
// composer is wrapped in `timeline-comment-wrapper` and contains an empty
// `comment-body js-preview-body` ("Nothing to preview") preview pane, which
// would otherwise be parsed as a phantom final comment on advisories with
// no real replies.
function extractComments(html) {
  const comments = [];
  // Find all <div class="...timeline-comment[ws|"]..." ...> openings and pair
  // with their closing tag by counting nested <div>s. The `(?=\s|")` lookahead
  // ensures we match the standalone class, not a prefix.
  const openRe = /<div\b[^>]*class="[^"]*\btimeline-comment(?=\s|")[^"]*"[^>]*>/gi;
  let m;
  while ((m = openRe.exec(html)) !== null) {
    const start = m.index;
    let i = openRe.lastIndex;
    let depth = 1;
    const tagRe = /<\/?div\b[^>]*>/gi;
    tagRe.lastIndex = i;
    let t;
    while ((t = tagRe.exec(html)) !== null) {
      if (t[0].startsWith('</')) depth--;
      else depth++;
      if (depth === 0) {
        i = tagRe.lastIndex;
        break;
      }
    }
    const block = html.slice(start, i);
    const c = parseCommentBlock(block);
    if (c) comments.push(c);
    openRe.lastIndex = i;
  }
  return comments;
}

function parseCommentBlock(block) {
  const authorM = block.match(/<a\b[^>]*class="[^"]*author[^"]*"[^>]*>([\s\S]*?)<\/a>/i)
    || block.match(/<a\b[^>]*href="\/([^"\/]+)"[^>]*class="[^"]*Link--primary[^"]*"[^>]*>([\s\S]*?)<\/a>/i);
  const author = authorM ? decodeEntities((authorM[1] || authorM[2]).replace(/<[^>]+>/g, '')).trim() : '(unknown)';

  const dateM = block.match(/<relative-time\b[^>]*datetime="([^"]+)"/i);
  const date = dateM ? dateM[1] : null;

  // Comment body: GitHub uses several class combos; `js-comment-body` is the
  // most stable signal across issue/PR/advisory views.
  let bodyM = block.match(/<(?:td|div)\b[^>]*class="[^"]*(?:js-comment-body|comment-body)[^"]*"[^>]*>([\s\S]*?)<\/(?:td|div)>/i);
  if (!bodyM) return null;
  const body = htmlToMarkdown(bodyM[1]);
  if (!body) return null;
  return { author, date, body };
}

// --- main ------------------------------------------------------------------

async function main() {
  const debug = process.argv.includes('--debug');
  const argv = process.argv.filter((a) => a !== '--debug');
  const target = parseArgs(argv);
  const cookie = loadCookie();

  const { url, html } = await fetchAdvisory(target, cookie);

  if (debug) {
    const tmp = `/tmp/ghsa-${target.ghsa}.html`;
    (await import('node:fs/promises')).writeFile(tmp, html);
    process.stderr.write(`debug: wrote ${tmp} (${html.length} bytes)\n`);
  }

  const title = extractTitle(html);
  const severity = extractSeverity(html);
  const status = extractStatus(html);
  const initial = extractInitialPost(html);
  const comments = extractComments(html);
  const thread = initial ? [initial, ...comments] : comments;

  const lines = [];
  lines.push(`# ${target.ghsa}${title ? ` — ${title}` : ''}`);
  lines.push('');
  lines.push(`Source: ${url}`);
  if (status) lines.push(`Status: ${status}`);
  if (severity) lines.push(`Severity: ${severity}`);
  lines.push(`Messages: ${thread.length}${initial ? ' (1 initial report + ' + comments.length + ' comments)' : ''}`);
  lines.push('');
  lines.push('---');
  lines.push('');

  if (thread.length === 0) {
    lines.push('_No content found. If you expected messages, re-run with --debug and inspect the saved HTML._');
  } else {
    for (const c of thread) {
      lines.push(`## @${c.author}${c.date ? ` — ${c.date}` : ''}`);
      lines.push('');
      lines.push(c.body);
      lines.push('');
    }
  }

  process.stdout.write(lines.join('\n') + '\n');
}

main().catch((e) => die(e.stack || String(e)));
