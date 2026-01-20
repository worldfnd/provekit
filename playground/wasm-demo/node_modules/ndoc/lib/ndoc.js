/**
 * class NDoc
 *
 * Handles documentation tree.
 **/


'use strict';


const path      = require('path');
const _         = require('lodash');
const template  = require('./ndoc/common').template;


////////////////////////////////////////////////////////////////////////////////


let NDoc = {
  renderers: {},
  parsers:   {}
};


module.exports = NDoc;

////////////////////////////////////////////////////////////////////////////////


// parse all files and prepare a "raw list of nodes
function parse_files(files, options) {
  let nodes = {
    // root section node
    '': {
      id: '',
      type: 'section',
      children: [],
      description: '',
      short_description: '',
      href: '#',
      root: true,
      file: '',
      line: 0
    }
  };

  files.forEach(file => {
    let fn = NDoc.parsers[path.extname(file)];

    if (!fn) return;

    /* eslint-disable no-console */
    console.info('Parsing file: ' + file);

    let file_nodes = fn(file, options);

    // TODO:  fail on name clash here as well -- as we might get name clash
    //        from different parsers, or even differnret files
    _.extend(nodes, file_nodes);
  });

  return nodes;
}


function build_tree(nodes, options) {
  let tree, parted, sections, children;

  //
  // preprocess nodes
  //

  _.each(nodes, node => {
    if (!node.href && !node.root && options.linkFormat) {
      node.href = template(options.linkFormat, {
        package: options.package,
        file:    node.file.replace(/\\/g, '/'),
        line:    node.line
      });
    }
  });

  //
  // for each element with undefined section try to guess the section
  // E.g. for ".Ajax.Updater" we try to find "SECTION.Ajax" element.
  // If found, rename ".Ajax.Updater" to "SECTION.Ajax.Updater"
  //


  // prepare nodes of sections
  // N.B. starting with 1 we skip "" section
  parted = _.keys(nodes).sort().slice(1).map(id =>
    ({ id, parted: id.split(/[.#@]/), node: nodes[id] }));

  _.each(parted, data => {
    let found;

    // leave only ids without defined section
    if (data.parted[0] !== '') return;

    found = _.find(parted, other =>
      !!other.parted[0] && other.parted[1] === data.parted[1]);

    if (found) {
      delete nodes[data.id];

      data.node.id    = found.parted[0] + data.id;
      data.parted[0]  = found.parted[0];

      nodes[data.node.id] = data.node;
    }
  });

  // sort elements in case-insensitive manner
  tree = {};

  sections = _.keys(nodes).sort((a, b) => {
    a = a.toLowerCase();
    b = b.toLowerCase();
    return a === b ? 0 : a < b ? -1 : 1;
  });

  sections.forEach(id => { tree[id] = nodes[id]; });

  // rebuild the tree from the end to beginning.
  // N.B. since the nodes we iterate over is sorted, we can determine precisely
  // the parent of any element.
  _.each(sections.slice(0).reverse(), id => {
    let idx, parent;

    // parent name is this element's name without portion after
    // the last '.' for class member, last '#' for instance member,
    // or first '@' for events
    // first check for event, because event name can contain '.', '#' and '@'
    idx = id.indexOf('@');

    if (idx === -1) {
      idx = Math.max(id.lastIndexOf('.'), id.lastIndexOf('#'));
    }

    // get parent element
    parent = tree[id.substring(0, idx)];

    // no '.' or '#' or '@' found or no parent? -- top level section. skip it
    if (idx === -1 || !parent) return;

    // parent element found. move this element to parent's children nodes,
    // maintaing order
    parent.children.unshift(tree[id]);
    delete tree[id];
  });

  // cleanup nodes, reassign right ids after we resolved
  // to which sections every element belongs
  _.each(nodes, (node, id) => {
    delete nodes[id];

    // compose new id
    node.id = id.replace(/^[^.]*\./, '');

    // First check for event, because event name can contain '.' and '#'
    let idx = node.id.indexOf('@'); // get position of @event start

    // Otherwise get property/method delimiter position
    if (idx === -1) {
      idx = Math.max(node.id.lastIndexOf('.'), node.id.lastIndexOf('#'));
    }

    if (idx === -1) {
      node.name =  node.id;
    } else {
      node.name = node.id.substring(idx + 1);
      node.name_prefix = node.id.substring(0, idx + 1);
    }

    // sections have lowercased ids, to not clash with other elements
    if (node.type === 'section') {
      node.id = node.id.toLowerCase();
    }

    // prototype members have different paths
    node.path = node.id.replace(/#/g, '.prototype.');

    // events have different paths as well, but only first '@' separates event name
    node.path = node.path.replace(/@/, '.event.');

    delete node.section;

    // prune sections from nodes
    if (node.type !== 'section') {
      nodes[node.id] = node;
    }
  });

  // assign aliases, subclasses, constructors
  // correct method types (class or entity)
  _.each(nodes, node /*, id*/ => {
    // aliases
    if (node.alias_of && nodes[node.alias_of]) {
      nodes[node.alias_of].aliases.push(node.id);
    }

    // classes hierarchy
    if (node.type === 'class') {
      //if (d.superclass) console.log('SUPER', id, d.superclass)
      if (node.superclass && nodes[node.superclass]) {
        nodes[node.superclass].subclasses.push(node.id);
      }

      return;
    }

    if (node.type === 'constructor') {
      node.id = 'new ' + node.id.replace(/\.new$/, '');
      return;
    }

    // methods and properties
    if (node.type === 'method' || node.type === 'property') {
      // FIXME: shouldn't it be assigned by parser?

      if (node.id.match(/^\$/)) {
        node.type = 'utility';
        return;
      }

      // first check for event, because event name can contain '.' and '#'
      if (node.id.indexOf('@') >= 0) {
        node.type = 'event';
        return;
      }

      if (node.id.indexOf('#') >= 0) {
        node.type = 'instance ' + node.type;
        return;
      }

      if (node.id.indexOf('.') >= 0) {
        node.type = 'class ' + node.type;
        return;
      }
    }
  });

  // tree is hash of sections.
  // convert sections to uniform children array of tree top level
  children = [];

  _.each(tree, (node, id) => {
    if (id === '') children = children.concat(node.children);
    else children.push(node);

    delete tree[id];
  });

  tree.children = children;

  return { list: nodes, tree };
}


////////////////////////////////////////////////////////////////////////////////


/**
 *  NDoc.parse(files, options) -> AST
 *  - files (Array): Files to be parsed
 *  - options (Object): Parser options
 *
 *  Execute `name` parser against `files` with given options.
 *
 *
 *  ##### Options
 *
 *  - **linkFormat**: Format for link to source file. This can have variables:
 *    - `{file}`: Current file
 *    - `{line}`: Current line
 *    - `{package.*}`: Any package.json variable
 **/
NDoc.parse = function parse(files, options) {
  return build_tree(parse_files(files, options), options);
};


/**
 *  NDoc.render(name, ast, options) -> Void
 *  - name (String): Renderer name
 *  - ast (Object): Parsed AST (should consist of `list` and `tree`)
 *  - options (Object): Renderer options
 *
 *  Execute `name` renderer for `ast` with given options.
 **/
NDoc.render = function render(name, ast, options) {
  if (!NDoc.renderers[name]) throw new Error(`Unknown renderer: ${name}`);

  NDoc.renderers[name](ast, options);
};


/**
 *  NDoc.cli -> cli
 **/
NDoc.cli = require('./ndoc/cli');
NDoc.cli.ndoc = NDoc;


/**
 *  NDoc.VERSION -> String
 *
 *  NDoc version.
 **/
NDoc.VERSION = require('./ndoc/version');


/**
 *  NDoc.use(plugin) -> Void
 *  - plugin (Function): Infection `plugin(NDocClass)`
 *
 *  Runs given `plugin` against NDoc base class.
 *
 *
 *  ##### Examples
 *
 *  ```js
 *  NDoc.use(require('my-renderer'));
 *  ```
 **/
NDoc.use = function use(plugin) { plugin(this); };


/**
 *  NDoc.registerRenderer(name, func) -> Void
 *  - name (String): Name of the renderer, e.g. `'html'`
 *  - func (Function): Renderer function `func(ast, options)`
 *
 *  Registers given function as `name` renderer.
 **/
NDoc.registerRenderer = function (name, func) { NDoc.renderers[name] = func; };


/**
 *  NDoc.registerParser(extension, func) -> Void
 *  - extension (String): Extension suitable for the parser, e.g. `'js'`
 *  - func (Function): Parser function `func(source, options)`
 *
 *  Registers given function as `name` renderer.
 **/
NDoc.registerParser = function (extension, func) {
  extension = path.extname('name.' + extension);

  Object.defineProperty(NDoc.parsers, extension, {
    get() { return func; },
    configurable: true
  });
};


/**
 *  NDoc.extensionAlias(alias, extension) -> Void
 *  - alias (String): Extension as for the parser, e.g. `'cc'`
 *  - extension (String): Extension as for the parser, e.g. `'js'`
 *
 *  Registers `alias` of the `extension` parser.
 *
 *
 *  ##### Example
 *
 *  Parse all `*.cc` files with parser registered for `*.js`
 *
 *  ```js
 *  ndoc.extensionAlias('cc', 'js');
 *  ```
 *
 *
 *  ##### See Also
 *
 *  - [[NDoc.registerParser]]
 **/
NDoc.extensionAlias = function (alias, extension) {
  alias     = path.extname('name.' + alias);
  extension = path.extname('name.' + extension);

  Object.defineProperty(NDoc.parsers, alias, {
    get() { return NDoc.parsers[extension]; },
    configurable: true
  });
};


//
// require base plugins
//


NDoc.use(require(path.join(__dirname, 'ndoc/plugins/parsers/javascript')));
NDoc.use(require(path.join(__dirname, 'ndoc/plugins/renderers/html')));
NDoc.use(require(path.join(__dirname, 'ndoc/plugins/renderers/json')));
