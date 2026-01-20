'use strict';


// 3rd-party
const _ = require('lodash');


////////////////////////////////////////////////////////////////////////////////


module.exports.template = function template(str, data, options) {
  return _.template(str, _.extend({ interpolate: /\{(.+?)\}/g }, options))(data);
};
