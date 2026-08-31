import { describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { spawn } from 'bun';
import path from 'node:path';

const docsRoot = path.resolve(import.meta.dirname, '..');
const outputPath = path.join(docsRoot, 'src/content/docs/whitepaper.mdx');

const render = async () => {
  const process = spawn({
    cmd: ['bun', 'scripts/render-whitepaper.mjs'],
    cwd: docsRoot,
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const exitCode = await process.exited;
  const stderr = await new Response(process.stderr).text();
  expect(stderr).toBe('');
  expect(exitCode).toBe(0);
  return readFile(outputPath, 'utf8');
};

describe('whitepaper citations', () => {
  let generated;

  test('render as linked citations with a generated bibliography', async () => {
    generated = await render();

    expect(generated).toContain('<a class="pk-citation" href="#citation-Spartan">[1]</a>');
    expect(generated).toContain('<a class="pk-citation" href="#citation-WHIR">[2]</a>');
    expect(generated).toMatch(/<span class="pk-citation-group">\[<a class="pk-citation" href="#citation-Basefold:LDR">\d+<\/a>, Section 6\.4\]<\/span>/);
    expect(generated).toContain('<h2 id="references">References</h2>');
    expect(generated).toContain('<li id="citation-Spartan" class="pk-bibliography-entry">');
    expect(generated).toContain('Spartan: Efficient and General-Purpose');
    expect(generated).toContain('Ulrich Haböck, Adrian Hamelink, Andrew Milson');
    expect(generated).not.toContain('[ProximityGaps:improved]');
  });
});
