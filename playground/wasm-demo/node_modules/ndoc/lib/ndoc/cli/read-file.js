'use strict';


const fs = require('fs');
const Action = require('argparse').Action;


////////////////////////////////////////////////////////////////////////////////


class ReadFile extends Action {
  constructor(options) {
    options = options || {};
    options.nargs = 1;
    super(options);
  }

  call(parser, namespace, values) {
    namespace[this.dest] = fs.readFileSync(values.shift(), 'utf8');
  }
}


module.exports = ReadFile;
