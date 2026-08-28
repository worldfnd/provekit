import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const docsRoot = path.resolve(import.meta.dirname, '..');
const repoRoot = path.resolve(docsRoot, '..');
const sourceRoot = path.join(repoRoot, 'whitepaper');
const outputPath = path.join(docsRoot, 'src/content/docs/whitepaper.mdx');

const sourceFiles = new Map([
  ['Correlated agreement', 'Correlated agreement.tex'],
  ['IOPP soundness', 'IOPP soundness.tex'],
  ['IOPP-zk', 'IOPP-zk.tex'],
  ['Veil', 'Veil.tex'],
  ['oldstuff', 'oldstuff.tex'],
]);

const theoremLabels = {
  thm: 'Theorem',
  'thm*': 'Theorem',
  cor: 'Corollary',
  lem: 'Lemma',
  prop: 'Proposition',
  protocol: 'Protocol',
  defn: 'Definition',
  conj: 'Conjecture',
  rem: 'Remark',
  proof: 'Proof',
};

const theoremEnvironments = new Set(Object.keys(theoremLabels));
const mathEnvironments = new Set([
  'equation', 'equation*', 'align', 'align*',
  'gather', 'gather*', 'multline', 'multline*',
]);

const htmlEscape = (value) => value
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll('{', '&#123;')
  .replaceAll('}', '&#125;');

const htmlAttributeEscape = (value) => value
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;');

const findClosingBrace = (value, openIndex) => {
  let depth = 0;
  for (let index = openIndex; index < value.length; index += 1) {
    if (value[index] === '\\' && value[index + 1] === '{') {
      index += 1;
      continue;
    }
    if (value[index] === '{') depth += 1;
    if (value[index] === '}') {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
};

const takeArgument = (value, startIndex) => {
  const openIndex = value.indexOf('{', startIndex);
  if (openIndex === -1) return null;
  const closeIndex = findClosingBrace(value, openIndex);
  if (closeIndex === -1) return null;
  return { content: value.slice(openIndex + 1, closeIndex), end: closeIndex + 1 };
};

const stripComments = (value) => value.split('\n').flatMap((line) => {
  if (line.trimStart().startsWith('%')) return [];
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    if (line[index] === '%' && !escaped) return [line.slice(0, index)];
    escaped = line[index] === '\\' && !escaped;
    if (line[index] !== '\\') escaped = false;
  }
  return [line];
}).join('\n');

const removeInternalNotes = (value) => {
  let result = value;
  for (const command of ['ulrich', 'remco', 'marcin', 'albert', 'footnotetext']) {
    let index = result.indexOf('\\' + command);
    while (index !== -1) {
      const argument = takeArgument(result, index + command.length + 1);
      if (!argument) break;
      result = result.slice(0, index) + result.slice(argument.end);
      index = result.indexOf('\\' + command);
    }
  }
  return result.replaceAll('\\footnotemark', '');
};

const inlineInputs = async (value) => {
  let result = value;
  for (const [inputName, fileName] of sourceFiles) {
    const input = await readFile(path.join(sourceRoot, fileName), 'utf8');
    result = result.replaceAll('\\input{' + inputName + '}', '\n' + input + '\n');
  }
  return result;
};

const texForMath = (value) => value
  .replace(/\\label\{[^}]*\}/g, '')
  .replace(/\\tag\{[^}]*\}/g, '')
  .replace(/\\notag\b/g, '')
  .replace(/(?<!\\)\$/g, '')
  .replace(/\\textcolor\{[^}]*\}\{([^{}]*)\}/g, '$1')
  .replace(/\\\{/g, '\\lbrace')
  .replace(/\\\}/g, '\\rbrace')
  .replace(/\\sample\b/g, '\\mathrel{\\leftarrow}')
  .replace(/[ \t]+$/gm, '')
  .trim();

const mathMarkup = (value, inline = false) => {
  const formula = htmlAttributeEscape(texForMath(value));
  if (inline) return '<span class="pk-inline-math" data-tex="' + formula + '"></span>';
  return '<div class="pk-equation"><span data-display-math="true" data-tex="' + formula + '"></span></div>';
};

const extractBlocks = (value) => {
  const blocks = new Map();
  let blockNumber = 0;
  const addBlock = (content, type) => {
    const token = '@@' + type + '_' + blockNumber + '@@';
    blockNumber += 1;
    blocks.set(token, content);
    return '\n' + token + '\n';
  };

  let result = value;
  const pattern = /\\\[|\\begin\{([^}]+)\}/g;
  let match = pattern.exec(result);
  while (match) {
    const start = match.index;
    const environment = match[1];
    if (environment && !mathEnvironments.has(environment)) {
      match = pattern.exec(result);
      continue;
    }

    let end;
    let content;
    if (environment) {
      const endMarker = '\\end{' + environment + '}';
      const endIndex = result.indexOf(endMarker, start + match[0].length);
      if (endIndex === -1) break;
      content = result.slice(start + match[0].length, endIndex);
      end = endIndex + endMarker.length;
    } else {
      const endIndex = result.indexOf('\\]', start + 2);
      if (endIndex === -1) break;
      content = result.slice(start + 2, endIndex);
      end = endIndex + 2;
    }

    const token = addBlock(mathMarkup(content), 'MATH');
    result = result.slice(0, start) + token + result.slice(end);
    pattern.lastIndex = start + token.length;
    match = pattern.exec(result);
  }

  return { result, blocks };
};

const inlineMarkup = (value, blocks) => {
  let result = value;
  const htmlTokens = new Map();
  const tokenise = (html) => {
    const token = '@@HTML_' + htmlTokens.size + '@@';
    htmlTokens.set(token, html);
    return token;
  };

  result = result.replace(/(?<!\\)\$(?!\$)([\s\S]*?)(?<!\\)\$(?!\$)/g, (_, content) =>
    tokenise(mathMarkup(content, true)));

  const replaceOneArgument = (commands, render) => {
    let commandIndex = -1;
    do {
      commandIndex = -1;
      let commandName = '';
      for (const command of commands) {
        const candidate = result.indexOf('\\' + command);
        if (candidate !== -1 && (commandIndex === -1 || candidate < commandIndex)) {
          commandIndex = candidate;
          commandName = command;
        }
      }
      if (commandIndex === -1) break;
      const argument = takeArgument(result, commandIndex + commandName.length + 1);
      if (!argument) break;
      result = result.slice(0, commandIndex)
        + tokenise(render(argument.content))
        + result.slice(argument.end);
    } while (commandIndex !== -1);
  };

  replaceOneArgument(['textcolor'], (content) => inlineMarkup(content, blocks));
  replaceOneArgument(['textit', 'emph'], (content) => '<em>' + inlineMarkup(content, blocks) + '</em>');
  replaceOneArgument(['textbf'], (content) => '<strong>' + inlineMarkup(content, blocks) + '</strong>');
  replaceOneArgument(['texttt'], (content) => '<code>' + htmlEscape(content) + '</code>');
  replaceOneArgument(['textsf', 'text'], (content) => inlineMarkup(content, blocks));

  let linkIndex = result.indexOf('\\href');
  while (linkIndex !== -1) {
    const url = takeArgument(result, linkIndex + 5);
    const label = url ? takeArgument(result, url.end) : null;
    if (!url || !label) break;
    const html = '<a href="' + htmlEscape(url.content) + '">'
      + inlineMarkup(label.content, blocks) + '</a>';
    result = result.slice(0, linkIndex) + tokenise(html) + result.slice(label.end);
    linkIndex = result.indexOf('\\href');
  }

  replaceOneArgument(['url'], (content) => {
    const url = htmlEscape(content);
    return '<a href="' + url + '">' + url + '</a>';
  });
  replaceOneArgument(['footnote'], (content) =>
    '<span class="pk-footnote">' + inlineMarkup(content, blocks) + '</span>');

  const unmatchedDollar = result.match(/(?<!\\)\$(?!\$)/);
  if (unmatchedDollar && unmatchedDollar.index !== undefined) {
    const start = unmatchedDollar.index;
    const tail = result.slice(start + 1);
    if (/^\s*(?:\\[A-Za-z]+|[A-Za-z][\w]*\s*[=(])/.test(tail)) {
      result = result.slice(0, start) + tokenise(mathMarkup(tail, true));
    } else {
      result = result.slice(0, start) + result.slice(start + 1);
    }
  }

  result = result.replace(/\\cite(?:\[[^\]]*\])?\{([^}]*)\}/g, (_, keys) =>
    tokenise('<span class="pk-citation">[' + htmlEscape(keys.replaceAll(',', ', ')) + ']</span>'));
  result = result.replace(/\\(?:eq)?ref\{([^}]*)\}/g, (_, reference) =>
    tokenise('<span class="pk-reference">[' + htmlEscape(reference) + ']</span>'));
  result = result.replace(/\\(?:noindent|small|xspace|hfill|quad|qquad)\b/g, ' ');
  result = result.replace(/\\(?:hspace|vspace)\*?\{[^}]*\}/g, ' ');
  result = result.replace(/\\([%&_#])/g, '$1').replace(/\\\\/g, ' ');

  result = htmlEscape(result);
  for (const [token, html] of blocks) result = result.replaceAll(token, html);
  for (const [token, html] of htmlTokens) result = result.replaceAll(token, html);
  return result.replace(/\s+/g, ' ').trim();
};

const headingMarkup = (level, title, blocks) => {
  const cleanTitle = title.replace(/\\textcolor\{[^}]*\}\{([^{}]*)\}/g, '$1').trim();
  const id = cleanTitle.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  return '<h' + level + ' id="' + id + '">' + inlineMarkup(cleanTitle, blocks) + '</h' + level + '>';
};

const renderDocument = (value, blocks) => {
  let source = value
    .replace(/\\(?:frontmatter|mainmatter|backmatter|appendix|maketitle|tableofcontents|cleardoublepage|newpage)\b/g, '')
    .replace(/\\(?:bibliographystyle|bibliography)\{[^}]*\}/g, '')
    .replace(/\\(?:begin|end)\{document\}/g, '')
    .replace(/\\label\{[^}]*\}/g, '')
    .replace(/\\textcolor\{[^}]*\}\{([^{}]*)\}/g, '$1')
    .replace(/\\begin\{(itemize|enumerate)\}/g, '\n@@LIST_START_$1@@\n')
    .replace(/\\end\{(itemize|enumerate)\}/g, '\n@@LIST_END@@\n')
    .replace(/^\s*\\item\s*/gm, '\n@@ITEM@@\n');

  for (const environment of theoremEnvironments) {
    const startPattern = new RegExp('\\\\begin\\{' + environment + '\\}(?:\\[([^\\]]*)\\])?', 'g');
    source = source.replace(startPattern, (_, title = '') =>
      '\n@@THEOREM_START_' + environment + '_' + title.replaceAll('|', '/') + '@@\n');
    source = source.replaceAll('\\end{' + environment + '}', '\n@@THEOREM_END@@\n');
  }

  const output = [];
  const listStack = [];
  let listItemOpen = false;
  let theoremOpen = false;
  let paragraph = [];

  const flushParagraph = () => {
    const text = paragraph.join(' ').replace(/\s+/g, ' ').trim();
    paragraph = [];
    if (!text) return;
    if (/^@@MATH_\d+@@$/.test(text)) {
      output.push(blocks.get(text));
      return;
    }
    output.push('<p>' + inlineMarkup(text, blocks) + '</p>');
  };
  const closeListItem = () => {
    if (listItemOpen) {
      output.push('</li>');
      listItemOpen = false;
    }
  };

  for (const rawLine of source.split('\n')) {
    const line = rawLine.trim();
    if (!line) {
      flushParagraph();
      continue;
    }

    const heading = line.match(/^\\(section|subsection|subsubsection|paragraph)\*?\{(.*)\}$/);
    if (heading) {
      flushParagraph();
      const level = { section: 2, subsection: 3, subsubsection: 4, paragraph: 5 }[heading[1]];
      output.push(headingMarkup(level, heading[2], blocks));
      continue;
    }

    const listStart = line.match(/^@@LIST_START_(itemize|enumerate)@@$/);
    if (listStart) {
      flushParagraph();
      closeListItem();
      const tag = listStart[1] === 'itemize' ? 'ul' : 'ol';
      output.push('<' + tag + ' class="pk-paper-list">');
      listStack.push(tag);
      continue;
    }
    if (line === '@@LIST_END@@') {
      flushParagraph();
      closeListItem();
      const tag = listStack.pop();
      if (tag) output.push('</' + tag + '>');
      continue;
    }
    if (line === '@@ITEM@@') {
      flushParagraph();
      closeListItem();
      if (listStack.length) {
        output.push('<li>');
        listItemOpen = true;
      }
      continue;
    }

    const theoremStart = line.match(/^@@THEOREM_START_([^_]+)_(.*)@@$/);
    if (theoremStart) {
      flushParagraph();
      const kind = theoremStart[1];
      const title = theoremStart[2] || theoremLabels[kind] || kind;
      const label = theoremLabels[kind] || kind;
      const asideTitle = title !== label ? label + ': ' + title : label;
      output.push('<Aside type="note" title="' + htmlEscape(asideTitle) + '">');
      theoremOpen = true;
      continue;
    }
    if (line === '@@THEOREM_END@@') {
      flushParagraph();
      if (theoremOpen) {
        output.push('</Aside>');
        theoremOpen = false;
      }
      continue;
    }

    if (/^@@MATH_\d+@@$/.test(line)) {
      flushParagraph();
      output.push(blocks.get(line));
      continue;
    }

    paragraph.push(line);
  }

  flushParagraph();
  closeListItem();
  while (listStack.length) output.push('</' + listStack.pop() + '>');
  if (theoremOpen) output.push('</Aside>');
  return output.join('\n\n');
};

const mainSource = await readFile(path.join(sourceRoot, 'main.tex'), 'utf8');
const mainMatterIndex = mainSource.lastIndexOf('\\mainmatter');
const body = mainMatterIndex === -1 ? mainSource : mainSource.slice(mainMatterIndex + '\\mainmatter'.length);
const expanded = await inlineInputs(body);
const cleaned = removeInternalNotes(stripComments(expanded));
const extracted = extractBlocks(cleaned);
const rendered = renderDocument(extracted.result, extracted.blocks);

const template = await readFile(outputPath, 'utf8');
const startMarker = '{/* GENERATED WHITEPAPER BODY */}';
const endMarker = '{/* END GENERATED WHITEPAPER BODY */}';
const startIndex = template.indexOf(startMarker);
const endIndex = template.indexOf(endMarker);
if (startIndex === -1 || endIndex === -1 || endIndex < startIndex) {
  throw new Error('Whitepaper template markers are missing or out of order');
}
const output = template.slice(0, startIndex + startMarker.length)
  + '\n\n' + rendered + '\n\n'
  + template.slice(endIndex);
await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, output, 'utf8');
console.log('Rendered whitepaper to ' + path.relative(repoRoot, outputPath));
