'use strict';


const Action = require('argparse').Action;


////////////////////////////////////////////////////////////////////////////////


class LazyChoices extends Action {
  constructor(options) {
    options = options || {};

    let choices = options.choices;
    delete options.choices;

    super(options);

    this._get_choices = choices;
  }

  call(parser, namespace, value, option_string) {
    let choices = this._get_choices();

    if (!choices.includes(value)) {
      let choices_str = choices.map(c => `'${c}'`).join(', ');
      parser.error(`argument ${option_string}: invalid choice: '${value}' (choose from ${choices_str})`);
    }

    namespace[this.dest] = value;
  }
}


module.exports = LazyChoices;
