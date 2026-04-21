#!/usr/bin/env python3
"""Generate Mavros vs ProveKit witness count comparison table.

Usage: python3 generate_witness_comparison.py <witness_csv> <output_dir>

Reads provekit_witness_counts.csv produced by run_noir_execution_success.sh,
joins against Mavros Cols from the live reilabs/mavros STATUS.md (with
hardcoded fallback for any entries absent from the live file), and writes
witness_comparison.md to <output_dir>.
"""

import csv
import sys
import urllib.request
from pathlib import Path

from noir_execution_helpers import load_skip_tests

# Mavros Cols — extracted from reilabs/mavros STATUS.md (column "Cols"),
# noir/test_programs/execution_success/* rows only. Keys are bare circuit names.
MAVROS_COLS: dict[str, int] = {
    "a_1327_concrete_in_generic": 4,
    "a_1_mul": 577,
    "a_2_div": 610,
    "a_3_add": 567,
    "a_4_sub": 670,
    "a_5_over": 798,
    "a_6_array": 5619,
    "arithmetic_binary_operations": 654,
    "array_dedup_regression": 523,
    "array_eq": 161,
    "array_neq": 161,
    "array_oob_regression_7965": 551,
    "array_oob_regression_7975": 6,
    "array_rc_regression_7842": 1,
    "array_with_refs_from_param": 3,
    "as_witness": 3,
    "assert": 4,
    "assert_statement": 3,
    "assign_ex": 3,
    "bit_and": 1840,
    "bit_not": 523,
    "bool_not": 2,
    "bool_or": 5,
    "break_and_continue": 1,
    "brillig_acir_as_brillig": 541,
    "brillig_array_ifelse": 8,
    "brillig_arrays": 4,
    "brillig_block_parameter_liveness": 14119,
    "brillig_calls": 541,
    "brillig_calls_array": 550,
    "brillig_calls_conditionals": 577,
    "brillig_conditional": 5,
    "brillig_constant_reference_regression": 532,
    "brillig_cow": 543,
    "brillig_cow_assign": 1,
    "brillig_fns_as_values": 593,
    "brillig_identity_function": 8,
    "brillig_loop_size_regression": 3,
    "brillig_nested_arrays": 533,
    "brillig_not": 9,
    "brillig_recursion": 532,
    "brillig_recursive_main": 525,
    "brillig_recursive_main_indirect": 525,
    "brillig_uninitialized_arrays": 790,
    "cast_bool": 5,
    "cast_to_i8_regression_7776": 648,
    "cast_to_u64_regression_7776": 662,
    "cast_to_u8_regression_7776": 648,
    "comptime_println": 1,
    "comptime_println_fmtstr_with_quoted": 1,
    "comptime_variable_at_runtime": 1,
    "conditional_regression_547": 3,
    "conditional_regression_underflow": 517,
    "custom_entry": 2,
    "databus": 610,
    "databus_two_calldata_simple": 619,
    "debug_logs": 3,
    "diamond_deps_0": 4,
    "division_by_max": 528,
    "do_not_capture_comptime_locals": 1,
    "double_neg_cond_bool_input": 4,
    "double_neg_cond_global_var": 809,
    "dual_constrained_lambdas": 3,
    "field_attribute": 533,
    "fmtstr_with_global": 1,
    "fold_after_inlined_calls": 539,
    "fold_basic": 9,
    "fold_basic_nested_call": 7,
    "fold_distinct_return": 540,
    "generics": 3,
    "global_consts": 175,
    "global_nested_array_regression_9270": 526,
    "global_var_entry_point_used_in_another_entry": 3,
    "global_var_func_with_multiple_entry_points": 3,
    "global_var_multiple_entry_points_nested": 3,
    "inline_never_basic": 5,
    "integer_array_indexing": 527,
    "lambda_taking_lambda_with_variant": 548,
    "last_uses_regression_8935": 524,
    "loop": 524,
    "loop_break_regression_8319": 1,
    "loop_invariant_nested_deep": 2,
    "loop_invariant_regression_8586": 2,
    "loop_small_break": 2,
    "main_return": 3,
    "modules": 5,
    "modules_more": 5,
    "modulus": 864,
    "mutate_array_copy": 1,
    "negated_jmpif_condition": 5,
    "negative_associated_constants": 1,
    "nested_array_with_refs": 2,
    "nested_array_with_refs_from_param": 3,
    "nested_arrays_from_brillig": 19,
    "nested_fmtstr": 1,
    "no_predicates_basic": 5,
    "no_predicates_brillig": 532,
    "poseidon_bn254_hash_width_3": 552,
    "poseidonsponge_x5_254": 608,
    "pred_eq": 5,
    "prelude": 1,
    "reference_alias_in_array": 1,
    "regression_10197": 523,
    "regression_10307": 531,
    "regression_10466": 1,
    "regression_10516": 1,
    "regression_10690": 1,
    "regression_10917": 3,
    "regression_10923": 5,
    "regression_2660": 572,
    "regression_3051": 1,
    "regression_3394": 1,
    "regression_3607": 596,
    "regression_3889": 5,
    "regression_4088": 2,
    "regression_4124": 2,
    "regression_4202": 550,
    "regression_4663": 1,
    "regression_5435": 3,
    "regression_5615": 1,
    "regression_6451": 11,
    "regression_6674_1": 1,
    "regression_6674_2": 1,
    "regression_6734": 1,
    "regression_6990": 1,
    "regression_7143": 532,
    "regression_7195": 12,
    "regression_7451": 1304,
    "regression_7962": 1461,
    "regression_8174": 569,
    "regression_8212": 524,
    "regression_8235": 4,
    "regression_8329": 7,
    "regression_8519": 677,
    "regression_8558": 657,
    "regression_8739": 1,
    "regression_8761": 2,
    "regression_8874": 524,
    "regression_8890": 6,
    "regression_8926": 532,
    "regression_8975": 2,
    "regression_9037": 3,
    "regression_9047": 521,
    "regression_9102": 5,
    "regression_9116": 1,
    "regression_9160": 3,
    "regression_9193": 2,
    "regression_9206": 532,
    "regression_9243": 1,
    "regression_9294": 1,
    "regression_9329": 523,
    "regression_9546": 529,
    "regression_9657": 523,
    "regression_9725_1": 1,
    "regression_9725_2": 2,
    "regression_9907": 3,
    "regression_method_cannot_be_found": 1,
    "return_twice": 5,
    "shift_right_overflow": 517,
    "shl_signed_regression_9661": 520,
    "signed_bitshift": 1,
    "signed_overflow_in_else_regression_8617": 660,
    "signed_truncation": 918,
    "simple_2d_array": 13,
    "simple_add_and_ret_arr": 3,
    "simple_array_param": 4,
    "simple_bitwise": 1355,
    "simple_comparison": 784,
    "simple_mut": 3,
    "simple_not": 3,
    "simple_print": 3,
    "simple_program_addition": 3,
    "struct": 5,
    "struct_array_inputs": 8,
    "struct_fields_ordering": 524,
    "submodules": 4,
    "trait_as_return_type": 523,
    "trait_associated_constant": 1,
    "trait_impl_base_type": 523,
    "traits_in_crates_1": 3,
    "traits_in_crates_2": 3,
    "tuple_inputs": 845,
    "tuples": 657,
    "type_aliases": 5,
    "unsafe_range_constraint": 527,
    "unsigned_to_signed_cast": 918,
    "while_loop_break_regression_8521": 541,
    "wildcard_type": 7,
    "witness_compression": 6,
    "workspace_default_member": 3,
    "wrapping_operations": 908,
    "xor": 1367,
}


_MAVROS_STATUS_URL = (
    "https://raw.githubusercontent.com/reilabs/mavros/main/STATUS.md"
)
_EXEC_SUCCESS_PREFIX = "noir/test_programs/execution_success/"

# Skip list is shared with scripts/run_noir_execution_success.sh via
# scripts/noir_skip_tests.txt; these circuits are excluded from both sides
# of the witness comparison.
SKIP_TESTS: set[str] = load_skip_tests()


def _fetch_live_mavros_cols() -> dict[str, int]:
    """Parse Mavros Cols from the live reilabs/mavros STATUS.md.

    Returns an empty dict on any network or parse failure so the caller
    can fall back gracefully to the hardcoded table.
    """
    try:
        with urllib.request.urlopen(_MAVROS_STATUS_URL, timeout=15) as resp:
            content = resp.read().decode("utf-8")
    except Exception as exc:
        print(
            f"Warning: could not fetch live Mavros STATUS.md ({exc}); "
            "falling back to hardcoded data.",
            file=sys.stderr,
        )
        return {}

    result: dict[str, int] = {}
    for line in content.splitlines():
        if _EXEC_SUCCESS_PREFIX not in line:
            continue
        parts = line.split("|")
        # Table row: | test | Compiled | R1CS | Rows | Cols | ...
        # After split: parts[1]=test, parts[5]=Cols (1-indexed, 0 is empty)
        if len(parts) < 6:
            continue
        name_field = parts[1].strip()
        cols_field = parts[5].strip()
        if _EXEC_SUCCESS_PREFIX not in name_field:
            continue
        circuit = name_field.split(_EXEC_SUCCESS_PREFIX, 1)[1].strip()
        if circuit and cols_field.isdigit():
            result[circuit] = int(cols_field)

    if result:
        print(f"Fetched {len(result)} Mavros entries from live STATUS.md.")
    else:
        print("Warning: live STATUS.md parsed 0 entries; using hardcoded data.", file=sys.stderr)
    return result


def main(csv_path: Path, out_dir: Path) -> None:
    # Live data takes precedence; hardcoded fills any gaps.
    live = _fetch_live_mavros_cols()
    mavros_cols = {
        name: cols
        for name, cols in {**MAVROS_COLS, **live}.items()
        if name not in SKIP_TESTS
    }

    provekit: dict[str, int] = {}
    with csv_path.open() as f:
        for row in csv.DictReader(f):
            leaf = row["test_name"].split("/")[-1]
            if leaf in SKIP_TESTS:
                continue
            try:
                provekit[leaf] = int(row["provekit_witnesses"])
            except (ValueError, KeyError):
                continue

    all_names = sorted(set(mavros_cols) | set(provekit))
    comparable = [
        (name, mavros_cols[name], provekit[name])
        for name in all_names
        if name in mavros_cols and name in provekit
    ]
    missing_in_provekit = sum(1 for name in all_names if name in mavros_cols and name not in provekit)
    missing_in_mavros = sum(1 for name in all_names if name in provekit and name not in mavros_cols)

    equal = sum(1 for _, m, p in comparable if m == p)
    mavros_better = sum(1 for _, m, p in comparable if m < p)
    provekit_better = sum(1 for _, m, p in comparable if p < m)

    lines = [
        "# Mavros vs Provekit Witnesses Count",
        "",
        f"Union {len(all_names)} circuits: {len(comparable)} comparable, "
        f"{missing_in_provekit} missing in Provekit, {missing_in_mavros} missing in Mavros.",
        f"Among comparable: {equal} equal, {mavros_better} Mavros better, "
        f"{provekit_better} Provekit better.",
        "",
        "| Test | Mavros Cols | Provekit Post-GE | Delta | Better | Factor |",
        "|------|-------------|------------------|-------|--------|--------|",
    ]

    for name in all_names:
        mavros = mavros_cols.get(name)
        pk = provekit.get(name)

        if mavros is None:
            lines.append(f"| {name} | - | {pk} | - | missing_mavros | - |")
            continue

        if pk is None:
            lines.append(f"| {name} | {mavros} | - | - | missing_provekit | - |")
            continue

        delta = pk - mavros
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        if mavros == pk:
            better = "equal"
            factor = "1.00x"
        elif pk < mavros:
            better = "provekit"
            factor = "inf" if pk == 0 else f"{mavros / pk:.2f}x"
        else:
            better = "mavros"
            factor = "inf" if mavros == 0 else f"{pk / mavros:.2f}x"
        lines.append(f"| {name} | {mavros} | {pk} | {delta_str} | {better} | {factor} |")

    out_path = out_dir / "witness_comparison.md"
    out_path.write_text("\n".join(lines) + "\n")
    print(
        f"Wrote {out_path} "
        f"({len(all_names)} total circuits, {len(comparable)} comparable)"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <witness_csv> <output_dir>", file=sys.stderr)
        sys.exit(1)
    main(Path(sys.argv[1]), Path(sys.argv[2]))
