/** internal, section: Plugins
 *  Renderers.html(NDoc) -> Void
 *
 *  Registers HTML renderer as `html`.
 *
 *
 *  ##### Example
 *
 *      NDoc.render('html', ast, options);
 *
 *
 *  ##### Options
 *
 *  - **output** (String): Directory where to output rendered documentation.
 *  - **title** (String): Page title template. You can use `{package.*}`
 *    variables here.
 *    Default: `'{package.name} {package.version} API documentation'`
 *  - **index** (String): Intro text.
 *  - **github** (String): URL to a project on GitHub. If given, a nice ribbon
 *    with link to given URL will be added. You can use `{package.*}`
 *    variables here.
 *    Default: `Null`
 *  - **brokenLinks** (show|hide|throw): What to do if broken link occurred.
 *    Default: `'show'`
 **/


'use strict';


// stdlib
const fs   = require('fs');
const path = require('path');


// 3rd-party
const _         = require('lodash');
const mkdir     = require('mkdirp').sync;
const md        = require('markdown-it')();
const hljs      = require('highlight.js');
const stylus    = require('stylus');
const pug       = require('pug');
const template  = require('../../common').template;
const resolve   = require('resolve');

////////////////////////////////////////////////////////////////////////////////


function npmResolverPlugin() {
  return {
    resolve(filename, source /*, options */) {
      return resolve.sync(filename, { basedir: path.dirname(source) });
    }
  };
}


function render_html(ndoc, options) {
  let id, obj;

  options.github = template(options.github || '', { package: options.package });

  // it's illegal to have slashes in HTML elements ids.
  // replace them with dashes
  let list = ndoc.list;

  for (id in list) {
    if (!list.hasOwnProperty(id)) continue;
    obj = list[id];
    // path should be HTML valid id
    obj.path = obj.path.replace(/\//g, '-');
  }

  // render link
  // N.B. logic is way tricky to move to templates.
  // beside, this function is used as parameter in some Array#map() operations
  function link(obj, short, classes) {
    if (typeof obj === 'string') obj = list[obj] || { id: obj };

    // broken link. `options.brokenLinks` define action
    if (!obj.path) {
      return obj.id;
      /*if (options.brokenLinks === 'throw') {
        throw 'Link is broken: ' + obj.id;
      }
      return options.brokenLinks === 'show' ? '[[' + obj.id + ']]' : obj.id;*/
    }
    //
    let r = `<a href="#${obj.path}" ` +
            `class="${(classes || []).join(' ')}" ` +
            'title="' + obj.id + (obj.type ? ` (${obj.type})` : '') + '" ' +
            `data-id="${obj.id.toLowerCase()}">`;
    r += typeof short === 'string' ? short : short ? obj.name : obj.id;
    r += '</a>';
    return r;
  }

  // convert markdown to HTML
  function markdown(text, nohl) {
    let r, codes;

    md.set({
      highlight: (str, lang) => {
        let esc = md.utils.escapeHtml;

        try {
          if (lang && lang !== 'auto' && hljs.getLanguage(lang)) {
            return '<pre class="hljs language-' + esc(lang.toLowerCase()) + '"><code>' +
                   hljs.highlight(str, { language: lang, ignoreIllegals: true }).value +
                   '</code></pre>';

          } else if (!lang || lang === 'auto') {
            let result = hljs.highlightAuto(str);

            return '<pre class="hljs language-' + esc(result.language) + '"><code>' +
                   result.value +
                   '</code></pre>';
          }
        } catch (__) { /**/ }

        return '<pre class="hljs"><code>' + esc(str) + '</code></pre>';
      }
    });

    md.renderer.rules['code_block'] = function (tokens, idx /*, options, env */) {
      let esc = md.utils.escapeHtml;
      return '<pre class="hljs"><code>' + esc(tokens[idx].content) + '</code></pre>\n';
    };

    if (nohl) md.set({ highlight: null });

    r = md.render(text);

    // FIXME
    // desugar [[foo#bar]] tokens into local links
    // N.B. in order to not apply conversion in <code> blocks,
    // we first store replace code blocks with nonces
    codes = {};
    r = r.replace(/(<code>[\s\S]*?<\/code>)/g, (all, def) => {
      let nonce = Math.random().toString().substring(2);
      codes[nonce] = def;
      return `@-=@=-@${nonce}@-=@=-@`;
    });

    // convert [[link]] to links
    r = r.replace(/\[\[([\s\S]+?)\]\]/g, (all, def) => {
      def = def.split(/\s+/);
      id = def.shift();
      // invalid references don't produce links
      if (!list[id]) {
        if (options.brokenLinks === 'throw') {
          throw new Error(`Link is broken: ${all}\n${r}`);
        }
        return options.brokenLinks === 'show' ? all : id;
      }

      let obj = _.extend({ name: def.join(' ') || id }, list[id]);
      return link(obj, false, [ 'link-short' ]);
    });
    // restore code blocks, given previously stored nonces
    r = r.replace(/@-=@=-@(\d+)@-=@=-@/g, (all, nonce) => codes[nonce]);
    //
    return r;
  }

  // given signature object, recompose its textual representation
  function signature(obj, sig) {
    if (typeof obj === 'string') obj = list[obj];

    let r = obj.id;

    if (sig.args) {
      r += '(';
      sig.args.forEach((arg, idx) => {
        let skip_first, a, value;
        // skip the first bound argument for prototype methods
        skip_first = obj.bound && obj.id.indexOf('#') >= 0;
        a = arg.name;
        // argument can be callback
        if (arg.args) a = signature({ id: a }, arg);

        if (!idx && skip_first) return; //a = '@' + a;

        if (typeof arg.default_value !== 'undefined') {
          // apply custom stringifier
          value = JSON.stringify(arg.default_value, function (k, v) {
            // FIXME: get rid of quotes, if possible
            if (v instanceof RegExp) v = v.source;
            else if (v === 'null') v = null;
            return v;
          });
          a = a + ' = ' + value;
        }
        // compensate for possibly skipped first argument
        if (idx > (skip_first ? 1 : 0)) a = ', ' + a;
        if (arg.ellipsis) a += '...';
        if (arg.optional) a = '[' + a + ']';
        r += a;
      });
      r += ')';
    }
    return r;
  }

  const stylesPath   = path.join(__dirname, 'html/stylesheets/main.css.styl');
  const templatePath = path.join(__dirname, 'html/templates/layout.pug');

  let err, css, html;

  // Render CSS
  stylus(fs.readFileSync(stylesPath, 'utf8'))
    .set('filename', stylesPath)
    .set('include css', true)
    .define('url', stylus.url())
    .render((e, val) => { // hack to make sync rendering
      if (e) err = e;
      css = val;
    });

  if (err) throw err;

  // collect context for rendering function
  let vars = _.extend({}, options, {
    // data
    list: ndoc.list,
    tree: ndoc.tree,
    css,
    // helpers
    date: (new Date()).toUTCString(),
    link,
    markdown,
    signature,
    showInternals:  !!options.showInternals,
    // options
    filename: templatePath,
    plugins: [ npmResolverPlugin() ]
  });

  // render HTML
  pug.render(fs.readFileSync(templatePath, 'utf8'), vars, (e, val) => {
    if (e) err = e;
    html = val;
  });

  if (err) throw err;

  if (fs.existsSync(options.output)) {
    throw new Error(`Output directory '${options.output}' already exists`);
  }

  mkdir(options.output);

  fs.writeFileSync(path.join(options.output, 'index.html'), html);
}


////////////////////////////////////////////////////////////////////////////////


module.exports = function html(NDoc) {
  NDoc.registerRenderer('html', render_html);

  NDoc.cli.add_argument('--gh-ribbon', {
    help:         'Add "Fork me on GitHub" ribbon with given URL. You can use ' +
                  'any of `{package.*}` variables for interpolation.',
    dest:         'github',
    metavar:      'URL',
    default:      null
  });

  NDoc.cli.add_argument('--broken-links', {
    dest:         'brokenLinks',
    help:         'What to do if broken link occurred (show, hide, throw). ' +
                  'DEFAULT: `show`.',
    choices:      [ 'show', 'hide', 'throw' ],
    metavar:      'ACTION',
    default:      'show'
  });
};
