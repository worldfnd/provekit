'use strict';


const fs = require('fs');
const Action = require('argparse').Action;


////////////////////////////////////////////////////////////////////////////////


class ReadJSON extends Action {
  constructor(options) {
    options = options || {};
    options.nargs = 1;

    super(options);
  }

  call(parser, namespace, values) {
    let str = fs.readFileSync(values.shift(), 'utf8');
    namespace[this.dest] = JSON.parse(str);
  }
}


module.exports = ReadJSON;
