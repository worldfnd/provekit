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
let referenceLabels = new Map();
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
  .replaceAll('"', '&quot;')
  .replaceAll('\r', '')
  .replaceAll('\n', '&#10;');

const referenceKinds = {
  e: 'Equation',
  i: 'Step',
  lem: 'Lemma',
  prot: 'Protocol',
  rem: 'Remark',
  s: 'Section',
  thm: 'Theorem',
};

const indexReferences = (value) => {
  const counters = new Map();
  const labels = new Map();
  for (const match of value.matchAll(/\\label\{([^}]*)\}/g)) {
    const key = match[1];
    if (!key || labels.has(key)) continue;
    const prefix = key.split(':', 1)[0];
    const kind = referenceKinds[prefix] || 'Reference';
    const count = (counters.get(kind) || 0) + 1;
    counters.set(kind, count);
    labels.set(key, { kind, number: count });
  }

  let appendixMode = false;
  let sectionNumber = 0;
  let subsectionNumber = 0;
  let subsubsectionNumber = 0;
  let currentSection = '';
  const sectionTokens = /\\appendix\b|\\(section|subsection|subsubsection)(\*)?\{[^}]*\}|\\label\{([^}]*)\}/g;
  for (const match of value.matchAll(sectionTokens)) {
    if (match[0].startsWith('\\appendix')) {
      appendixMode = true;
      sectionNumber = 0;
      subsectionNumber = 0;
      subsubsectionNumber = 0;
      currentSection = '';
      continue;
    }
    if (match[1]) {
      if (match[2]) {
        currentSection = '';
        continue;
      }
      if (match[1] === 'section') {
        sectionNumber += 1;
        subsectionNumber = 0;
        subsubsectionNumber = 0;
        currentSection = appendixMode ? String.fromCharCode(64 + sectionNumber) : String(sectionNumber);
      } else if (match[1] === 'subsection') {
        subsectionNumber += 1;
        subsubsectionNumber = 0;
        const sectionLabel = appendixMode ? String.fromCharCode(64 + sectionNumber) : String(sectionNumber);
        currentSection = sectionLabel + '.' + subsectionNumber;
      } else {
        subsubsectionNumber += 1;
        const sectionLabel = appendixMode ? String.fromCharCode(64 + sectionNumber) : String(sectionNumber);
        currentSection = sectionLabel + '.' + subsectionNumber + '.' + subsubsectionNumber;
      }
      continue;
    }
    if (match[3]?.startsWith('s:') && currentSection) {
      labels.set(match[3], { kind: 'Section', number: currentSection });
    }
  }

  const environmentCounters = new Map();
  const environmentLabelPrefixes = {
    thm: new Set(['thm']),
    cor: new Set(['cor']),
    lem: new Set(['lem']),
    prop: new Set(['prop']),
    protocol: new Set(['prot']),
    defn: new Set(['defn']),
    conj: new Set(['conj']),
    rem: new Set(['rem']),
  };
  for (const environment of theoremEnvironments) {
    if (environment === 'proof' || environment === 'thm*') continue;
    const escapedEnvironment = environment.replace('*', '\\*');
    const environmentPattern = new RegExp(
      '\\\\begin\\{' + escapedEnvironment + '\\}(?:\\[[^\\]]*\\])?([\\s\\S]*?)\\\\end\\{' + escapedEnvironment + '\\}',
      'g',
    );
    for (const match of value.matchAll(environmentPattern)) {
      const number = (environmentCounters.get(environment) || 0) + 1;
      environmentCounters.set(environment, number);
      const kind = theoremLabels[environment] || 'Reference';
      for (const label of match[1].matchAll(/\\label\{([^}]*)\}/g)) {
        const prefix = label[1].split(':', 1)[0];
        if (environmentLabelPrefixes[environment]?.has(prefix)) {
          labels.set(label[1], { kind, number });
        }
      }
    }
  }
  return labels;
};

const referenceMarkup = (key, equation = false, precedingKind = '') => {
  if (!key) return '<span class="pk-reference pk-reference--pending">reference pending</span>';
  const reference = referenceLabels.get(key);
  if (!reference) return '<span class="pk-reference pk-reference--missing">[' + htmlEscape(key) + ']</span>';
  const text = equation
    ? '(' + reference.number + ')'
    : (precedingKind || reference.kind) + ' ' + reference.number;
  return '<a class="pk-reference" href="#' + htmlAttributeEscape(key) + '">' + text + '</a>';
};

const plainReferenceText = (value) => value
  .replace(/((?:Equation|Lemma|Protocol|Remark|Section|Step|Theorem)\s+)?\\(?:eq)?ref\{([^}]*)\}/g,
    (_, precedingKind = '', key) => {
    if (!key) return 'reference pending';
    const reference = referenceLabels.get(key);
    if (!reference) return '[' + key + ']';
    return precedingKind ? precedingKind + reference.number : reference.kind + ' ' + reference.number;
  })
  .replace(/\\cite(?:\[[^\]]*\])?\{([^}]*)\}/g, (_, keys) =>
    keys ? '[' + keys.replaceAll(',', ', ') + ']' : '[citation pending]');

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

const intertextRow = (content) => {
  const parts = content
    .replace(/\s+/g, ' ')
    .trim()
    .split(/(?<!\\)\$/);
  const row = parts.map((part, index) => {
    if (index % 2 === 1) return part.trim();
    if (!part) return '';
    return '\\text{' + part + '}';
  }).filter(Boolean).join('');
  return '& ' + row + ' \\\\';
};

const normalizeIntertext = (value) => {
  let result = value;
  let commandIndex = result.indexOf('\\intertext');
  while (commandIndex !== -1) {
    const argument = takeArgument(result, commandIndex + '\\intertext'.length);
    if (!argument) throw new Error('Malformed \\intertext in display math');
    result = result.slice(0, commandIndex)
      + intertextRow(argument.content)
      + result.slice(argument.end);
    commandIndex = result.indexOf('\\intertext', commandIndex);
  }
  return result;
};

const texForMath = (value) => normalizeIntertext(value)
  .replace(/\\label\{[^}]*\}/g, '')
  .replace(/\\tag\{[^}]*\}/g, '')
  .replace(/\\notag\b/g, '')
  .replace(/(?<!\\)\$/g, '')
  .replace(/\\textcolor\{[^}]*\}\{([^{}]*)\}/g, '$1')
  // Keep a token boundary: `\\lbracez` is parsed as an unknown command,
  // whereas `\\lbrace z` is the intended delimiter followed by a variable.
  .replace(/\\\{/g, '\\lbrace ')
  .replace(/\\\}/g, '\\rbrace ')
  .replace(/\\sample\b/g, '\\mathrel{\\leftarrow}')
  // Page-layout spacing has no semantic value in the web rendering and can
  // produce MathJax errors (especially negative or malformed dimensions).
  .replace(/\\(?:hspace|vspace)\*?\s*\{[^{}]*\}/g, ' ')
  .replace(/[ \t]+$/gm, '')
  .trim();

const mathMarkup = (value, inline = false, environment = '') => {
  const labels = [...value.matchAll(/\\label\{([^}]*)\}/g)].map((match) => match[1]);
  let tex = texForMath(value);
  if (!inline && /^(?:align|align\*)$/.test(environment)) {
    tex = '\\begin{aligned}' + tex + '\\end{aligned}';
  } else if (!inline && /^(?:gather|gather\*|multline|multline\*)$/.test(environment)) {
    tex = '\\begin{gathered}' + tex + '\\end{gathered}';
  }
  const formula = htmlAttributeEscape(tex);
  // Starlight applies document-flow margins to adjacent custom elements unless
  // they are inside a `not-content` boundary. MathJax uses adjacent custom
  // elements for radicals, fractions, matrices, and scripts, so isolate every
  // generated formula from those prose styles.
  if (inline) return '<span class="pk-inline-math not-content" data-tex="' + formula + '"></span>';
  const id = labels[0] ? ' id="' + htmlAttributeEscape(labels[0]) + '"' : '';
  const equationReference = labels.map((label) => referenceLabels.get(label)).find(Boolean);
  const equationNumber = equationReference
    ? '<span class="pk-equation-number" aria-hidden="true">(' + equationReference.number + ')</span>'
    : '';
  const additionalAnchors = labels.slice(1).map((label) =>
    '<span class="pk-reference-anchor" id="' + htmlAttributeEscape(label) + '"></span>').join('');
  return '<div class="pk-equation"' + id + '>' + additionalAnchors
    + '<span class="not-content" data-display-math="true" data-tex="' + formula + '"></span>'
    + equationNumber + '</div>';
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

    const token = addBlock(mathMarkup(content, false, environment), 'MATH');
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

  result = result.replace(/\\(?:ldots|cdots|dots)\b/g, (command) =>
    tokenise(mathMarkup(command, true)));

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
    tokenise('<span class="pk-citation">['
      + (keys ? htmlEscape(keys.replaceAll(',', ', ')) : 'citation pending') + ']</span>'));
  result = result.replace(/\\eqref\{([^}]*)\}/g, (_, reference) =>
    tokenise(referenceMarkup(reference, true)));
  result = result.replace(/((?:Equation|Lemma|Protocol|Remark|Section|Step|Theorem)\s+)?\\ref\{([^}]*)\}/g,
    (_, precedingKind = '', reference) =>
      tokenise(referenceMarkup(reference, false, precedingKind.trim())));
  result = result.replace(/\\label\{([^}]*)\}/g, (_, label) =>
    tokenise('<span class="pk-reference-anchor" id="' + htmlAttributeEscape(label) + '"></span>'));
  result = result.replace(/\\(?:noindent|small|xspace|hfill|quad|qquad)\b/g, ' ');
  result = result.replace(/\\(?:hspace|vspace)\*?\{[^}]*\}/g, ' ');
  result = result.replace(/\\([%&_#])/g, '$1').replace(/\\\\/g, ' ');

  result = htmlEscape(result);
  for (const [token, html] of blocks) result = result.replaceAll(token, html);
  for (const [token, html] of htmlTokens) result = result.replaceAll(token, html);
  return result.replace(/\s+/g, ' ').trim();
};

const headingMarkup = (level, title, blocks, number = '') => {
  const cleanTitle = title.replace(/\\textcolor\{[^}]*\}\{([^{}]*)\}/g, '$1').trim();
  const id = cleanTitle.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const numberMarkup = number
    ? '<span class="pk-heading-number" aria-hidden="true">' + number + '</span>'
    : '';
  return '<h' + level + ' id="' + id + '">' + numberMarkup
    + inlineMarkup(cleanTitle, blocks) + '</h' + level + '>';
};

const romanNumeral = (value) => {
  const numerals = [
    [1000, 'm'], [900, 'cm'], [500, 'd'], [400, 'cd'], [100, 'c'], [90, 'xc'],
    [50, 'l'], [40, 'xl'], [10, 'x'], [9, 'ix'], [5, 'v'], [4, 'iv'], [1, 'i'],
  ];
  let remaining = value;
  let output = '';
  for (const [amount, symbol] of numerals) {
    while (remaining >= amount) {
      output += symbol;
      remaining -= amount;
    }
  }
  return output;
};

const orderedListMarker = (value, depth) => {
  if (depth % 3 === 2) return String.fromCharCode(96 + value) + '.';
  if (depth % 3 === 0) return romanNumeral(value) + '.';
  return value + '.';
};

const renderDocument = (value, blocks) => {
  let source = value
    .replace(/\\appendix\b/g, '\n@@APPENDIX@@\n')
    .replace(/\\(?:frontmatter|mainmatter|backmatter|maketitle|tableofcontents|cleardoublepage|newpage)\b/g, '')
    .replace(/\\(?:bibliographystyle|bibliography)\{[^}]*\}/g, '')
    .replace(/\\(?:begin|end)\{document\}/g, '')
    .replace(/\\textcolor\{[^}]*\}\{([^{}]*)\}/g, '$1')
    .replace(/\\begin\{(itemize|enumerate)\}/g, '\n@@LIST_START_$1@@\n')
    .replace(/\\end\{(itemize|enumerate)\}/g, '\n@@LIST_END@@\n')
    .replace(/^\s*\\item\s*/gm, '\n@@ITEM@@\n');

  const theoremCounters = new Map();
  for (const environment of theoremEnvironments) {
    const escapedEnvironment = environment.replace('*', '\\*');
    const environmentPattern = new RegExp(
      '\\\\begin\\{' + escapedEnvironment + '\\}(?:\\[([^\\]]*)\\])?([\\s\\S]*?)\\\\end\\{' + escapedEnvironment + '\\}',
      'g',
    );
    source = source.replace(environmentPattern, (_, title = '', content) => {
      const numbered = environment !== 'proof' && environment !== 'thm*';
      const number = numbered ? (theoremCounters.get(environment) || 0) + 1 : '';
      if (numbered) theoremCounters.set(environment, number);
      return '\n@@THEOREM_START_' + environment + '_' + number + '_'
        + title.replaceAll('|', '/') + '@@\n' + content + '\n@@THEOREM_END@@\n';
    });
  }

  const output = [];
  const listStack = [];
  let listItemOpen = false;
  let theoremOpen = false;
  let paragraph = [];
  let appendixMode = false;
  let sectionNumber = 0;
  let subsectionNumber = 0;
  let subsubsectionNumber = 0;

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

    if (line === '@@APPENDIX@@') {
      flushParagraph();
      appendixMode = true;
      sectionNumber = 0;
      subsectionNumber = 0;
      subsubsectionNumber = 0;
      continue;
    }

    const heading = line.match(/^\\(section|subsection|subsubsection|paragraph)(\*)?\{(.*)\}$/);
    if (heading) {
      flushParagraph();
      const level = { section: 2, subsection: 3, subsubsection: 4, paragraph: 5 }[heading[1]];
      const numbered = !heading[2];
      let number = '';
      if (numbered && heading[1] === 'section') {
        sectionNumber += 1;
        subsectionNumber = 0;
        subsubsectionNumber = 0;
        number = appendixMode ? String.fromCharCode(64 + sectionNumber) : String(sectionNumber);
      } else if (numbered && heading[1] === 'subsection') {
        subsectionNumber += 1;
        subsubsectionNumber = 0;
        const sectionLabel = appendixMode ? String.fromCharCode(64 + sectionNumber) : String(sectionNumber);
        number = sectionLabel + '.' + subsectionNumber;
      } else if (numbered && heading[1] === 'subsubsection') {
        subsubsectionNumber += 1;
        const sectionLabel = appendixMode ? String.fromCharCode(64 + sectionNumber) : String(sectionNumber);
        number = sectionLabel + '.' + subsectionNumber + '.' + subsubsectionNumber;
      }
      output.push(headingMarkup(level, heading[3], blocks, number));
      continue;
    }

    const listStart = line.match(/^@@LIST_START_(itemize|enumerate)@@$/);
    if (listStart) {
      flushParagraph();
      closeListItem();
      const tag = listStart[1] === 'itemize' ? 'ul' : 'ol';
      output.push('<' + tag + ' class="pk-paper-list">');
      listStack.push({ tag, count: 0 });
      continue;
    }
    if (line === '@@LIST_END@@') {
      flushParagraph();
      closeListItem();
      const list = listStack.pop();
      if (list) output.push('</' + list.tag + '>');
      continue;
    }
    if (line === '@@ITEM@@') {
      flushParagraph();
      closeListItem();
      if (listStack.length) {
        output.push('<li>');
        const list = listStack.at(-1);
        list.count += 1;
        if (list.tag === 'ol') {
          output.push('<span class="pk-list-marker" aria-hidden="true">'
            + orderedListMarker(list.count, listStack.length) + '</span>');
        }
        listItemOpen = true;
      }
      continue;
    }

    const theoremStart = line.match(/^@@THEOREM_START_([^_]+)_([0-9]*)_(.*)@@$/);
    if (theoremStart) {
      flushParagraph();
      const kind = theoremStart[1];
      const number = theoremStart[2];
      const title = plainReferenceText(theoremStart[3]);
      const label = theoremLabels[kind] || kind;
      const asideTitle = kind === 'proof'
        ? label + (title ? ' ' + title : '') + '.'
        : label + (number ? ' ' + number : '') + (title ? '. ' + title : '.');
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
  while (listStack.length) output.push('</' + listStack.pop().tag + '>');
  if (theoremOpen) output.push('</Aside>');
  return output.join('\n\n');
};

const mainSource = await readFile(path.join(sourceRoot, 'main.tex'), 'utf8');
const mainMatterIndex = mainSource.lastIndexOf('\\mainmatter');
const body = mainMatterIndex === -1 ? mainSource : mainSource.slice(mainMatterIndex + '\\mainmatter'.length);
const expanded = await inlineInputs(body);
const cleaned = removeInternalNotes(stripComments(expanded));
referenceLabels = indexReferences(cleaned);
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

const generatedMath = [...output.matchAll(/data-tex="([\s\S]*?)"/g)].map((match) => match[1]);
const invalidMath = generatedMath.filter((formula) => {
  const decoded = formula
    .replaceAll('&#10;', '\n')
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&amp;', '&');
  const hasAlignmentContainer = /\\begin\{(?:aligned|gathered|matrix|pmatrix|bmatrix|vmatrix|Vmatrix)\}/.test(decoded);
  const hasUnwrappedAlignment = decoded.includes('&') && !hasAlignmentContainer;
  return hasUnwrappedAlignment
    || /\\(?:hspace|vspace)\*?\s*\{/.test(decoded)
    || decoded.includes('\\intertext');
});
if (invalidMath.length) {
  throw new Error('Generated whitepaper contains unsupported MathJax input:\n' + invalidMath.join('\n---\n'));
}
const proseOutput = output.replace(/data-tex="[\s\S]*?"/g, '');
const rawProseCommands = [...new Set(proseOutput.match(/\\[A-Za-z]+/g) || [])];
if (rawProseCommands.length) {
  throw new Error('Generated whitepaper contains raw TeX commands in prose: '
    + rawProseCommands.join(', '));
}
const missingReferences = [...output.matchAll(/pk-reference--missing[^>]*>\[([^\]]+)\]/g)]
  .map((match) => match[1]);
if (missingReferences.length) {
  throw new Error('Generated whitepaper contains unresolved references: '
    + [...new Set(missingReferences)].join(', '));
}
const referenceTargets = [...output.matchAll(/href="#([^"]+)"/g)].map((match) => match[1]);
const renderedIds = new Set([...output.matchAll(/id="([^"]+)"/g)].map((match) => match[1]));
const missingTargets = [...new Set(referenceTargets.filter((target) => !renderedIds.has(target)))];
if (missingTargets.length) {
  throw new Error('Generated whitepaper contains references without targets: '
    + missingTargets.join(', '));
}
await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, output, 'utf8');
console.log('Rendered whitepaper to ' + path.relative(repoRoot, outputPath));
