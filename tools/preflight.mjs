import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = process.cwd();
const errors = [];
const warnings = [];

const read = (p) => readFileSync(join(root, p), 'utf8');
const fail = (m) => errors.push(m);
const warn = (m) => warnings.push(m);

for (const required of [
  'package.json', 'package-lock.json', 'next.config.ts', 'tsconfig.json',
  'src/app/layout.tsx', 'src/app/page.tsx', 'src/middleware.ts',
  'public/site.webmanifest', 'public/manifest.json', 'public/nadir-mark.svg',
]) if (!existsSync(join(root, required))) fail(`Missing required file: ${required}`);

for (const manifest of ['public/site.webmanifest', 'public/manifest.json']) {
  try {
    const data = JSON.parse(read(manifest));
    if (data.name !== 'NADIR — Global Intelligence Platform') fail(`${manifest}: unexpected name`);
    if (data.short_name !== 'NADIR') fail(`${manifest}: unexpected short_name`);
    if (data.theme_color !== '#D4AF37' || data.background_color !== '#04040A') fail(`${manifest}: theme colors drifted`);
  } catch (error) { fail(`${manifest}: invalid JSON (${error.message})`); }
}

const layout = read('src/app/layout.tsx');
if (layout.includes('http://localhost:3000')) fail('Production metadata still falls back to localhost');
if (!layout.includes('process.env.NEXT_PUBLIC_SITE_URL')) fail('NEXT_PUBLIC_SITE_URL is not used for metadata');
if (!layout.includes('type: "image/svg+xml"')) fail('NADIR SVG icon type is incorrect or missing');

const middleware = read('src/middleware.ts');
if (/https?:\/\/[^'"`\s]+/.test(middleware.replace('https://', ''))) warn('Review external URLs in middleware');
if (middleware.includes('100.68.100.15')) fail('Private scanner address is hard-coded');
if (/umami\.example|analytics\.example/i.test(middleware)) fail('Placeholder analytics endpoint remains');

const publicDir = join(root, 'public');
const hashes = new Map();
function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) walk(p);
    else {
      const h = createHash('sha256').update(readFileSync(p)).digest('hex');
      const list = hashes.get(h) ?? [];
      list.push(relative(root, p)); hashes.set(h, list);
    }
  }
}
walk(publicDir);
for (const files of hashes.values()) {
  if (files.length < 2) continue;
  const normalized = new Set(files.map((f) => f.replace(/^public\//, '')));
  const intentional = normalized.size === 2 && (normalized.has('favicon.svg') && normalized.has('nadir-mark.svg') || normalized.has('manifest.json') && normalized.has('site.webmanifest'));
  if (!intentional) warn(`Duplicate public assets: ${files.join(', ')}`);
}

const sourceFiles = [];
function walkSource(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) walkSource(p);
    else if (/\.(ts|tsx|css|md)$/.test(entry.name)) sourceFiles.push(p);
  }
}
walkSource(join(root, 'src'));
for (const file of sourceFiles) {
  const text = readFileSync(file, 'utf8');
  // OSIRIS_* variables are retained intentionally as backwards-compatible runtime contracts.
  const visible = text.replace(/OSIRIS_[A-Z0-9_]+/g, 'ENV_CONTRACT');
  if (/(^|[^A-Za-z0-9_])OSIRIS(?![A-Za-z0-9_])/.test(visible)) {
    const rel = relative(root, file);
    if (!rel.includes('/api/') && !rel.includes('/lib/')) warn(`Legacy product-name reference: ${rel}`);
  }
}

if (errors.length) {
  console.error('NADIR PREFLIGHT: FAILED');
  for (const e of errors) console.error(`  ✖ ${e}`);
  process.exit(1);
}
console.log('NADIR PREFLIGHT: PASSED');
if (warnings.length) {
  console.log(`Warnings: ${warnings.length}`);
  for (const w of warnings) console.log(`  • ${w}`);
} else console.log('Warnings: 0');
