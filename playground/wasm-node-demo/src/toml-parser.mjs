/**
 * TOML parser for Noir Prover.toml files.
 *
 * Uses the '@iarna/toml' npm package for robust parsing of TOML files,
 * including multi-line arrays, dotted keys, and nested structures.
 */

import toml from "@iarna/toml";

/**
 * Parse a Prover.toml file content into a JavaScript object.
 */
export function parseProverToml(content) {
  return toml.parse(content);
}
