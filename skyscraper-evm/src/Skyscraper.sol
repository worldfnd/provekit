// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {console} from "forge-std/console.sol";

contract Skyscraper {
    // BN254 field modulus
    uint256 internal constant P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 internal constant SIGMA_INV =
        9915499612839321149637521777990102151350674507940716049588462388200839649614;

    // Non-zero round constants
    uint256 internal constant RC_1 =
        17829420340877239108687448009732280677191990375576158938221412342251481978692;
    uint256 internal constant RC_2 =
        5852100059362614845584985098022261541909346143980691326489891671321030921585;
    uint256 internal constant RC_3 =
        17048088173265532689680903955395019356591870902241717143279822196003888806966;
    uint256 internal constant RC_4 =
        71577923540621522166602308362662170286605786204339342029375621502658138039;
    uint256 internal constant RC_5 =
        1630526119629192105940988602003704216811347521589219909349181656165466494167;
    uint256 internal constant RC_6 =
        7807402158218786806372091124904574238561123446618083586948014838053032654983;
    uint256 internal constant RC_7 =
        13329560971460034925899588938593812685746818331549554971040309989641523590611;
    uint256 internal constant RC_8 =
        16971509144034029782226530622087626979814683266929655790026304723118124142299;
    uint256 internal constant RC_9 =
        8608910393531852188108777530736778805001620473682472554749734455948859886057;
    uint256 internal constant RC_10 =
        10789906636021659141392066577070901692352605261812599600575143961478236801530;
    uint256 internal constant RC_11 =
        18708129585851494907644197977764586873688181219062643217509404046560774277231;
    uint256 internal constant RC_12 =
        8383317008589863184762767400375936634388677459538766150640361406080412989586;
    uint256 internal constant RC_13 =
        10555553646766747611187318546907885054893417621612381305146047194084618122734;
    uint256 internal constant RC_14 =
        18278062107303135832359716534360847832111250949377506216079581779892498540823;
    uint256 internal constant RC_15 =
        9307964587880364850754205696017897664821998926660334400055925260019288889718;
    uint256 internal constant RC_16 =
        13066217995902074168664295654459329310074418852039335279433003242098078040116;

    uint256 internal constant MASK_L1 =
        0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;
    uint256 internal constant MASK_H1 =
        0x8080808080808080808080808080808080808080808080808080808080808080;
    uint256 internal constant MASK_L2 =
        0x3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F;
    uint256 internal constant MASK_H2 =
        0xC0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0;
    uint256 internal constant MASK_L3 =
        0x1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F;
    uint256 internal constant MASK_H3 =
        0xE0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0;

    function compress(uint256 l, uint256 r) public pure returns (uint256) {
        uint256 t = l;
        (l, r) = permute(l, r);
        return addmod(t, l, P);
    }

    function compress_sigma(
        uint256 l,
        uint256 r
    ) public pure returns (uint256) {
        uint256 t = l;
        (l, r) = permute_sigma(l, r);
        return addmod(t, l, P);
    }

    // SkyscraperV2 over Bn254 scalar field with no Montgomery factor.
    // Requires l and r to be in the range [0, P-1].
    function permute(
        uint256 l,
        uint256 r
    ) internal pure returns (uint256, uint256) {
        (l, r) = ss(l, r, 0, RC_1);
        (l, r) = ss(l, r, RC_2, RC_3);
        (l, r) = ss_reduce_l(l, r, RC_4, RC_5);
        (l, r) = bb(l, r, RC_6, RC_7);
        (l, r) = ss_reduce_l(l, r, RC_8, RC_9);
        (l, r) = bb(l, r, RC_10, RC_11);
        (l, r) = ss(l, r, RC_12, RC_13);
        (l, r) = ss(l, r, RC_14, RC_15);
        (l, r) = ss(l, r, RC_16, 0);
        return (l, r);
    }

    // SkyscraperV2 over Bn254 scalar field with Montgomery factor.
    // Requires l and r to be in the range [0, P-1].
    function permute_sigma(
        uint256 l,
        uint256 r
    ) internal pure returns (uint256, uint256) {
        (l, r) = sss(l, r, 0, RC_1);
        (l, r) = sss(l, r, RC_2, RC_3);
        (l, r) = sss_reduce_l(l, r, RC_4, RC_5);
        (l, r) = bb(l, r, RC_6, RC_7);
        (l, r) = sss_reduce_l(l, r, RC_8, RC_9);
        (l, r) = bb(l, r, RC_10, RC_11);
        (l, r) = sss(l, r, RC_12, RC_13);
        (l, r) = sss(l, r, RC_14, RC_15);
        (l, r) = sss(l, r, RC_16, 0);
        return (l, r);
    }

    function ss(
        uint256 l,
        uint256 r,
        uint256 rc_a,
        uint256 rc_b
    ) internal pure returns (uint256, uint256) {
        unchecked {
            r = rc_a + addmod(mulmod(l, l, P), r, P);
            l = rc_b + addmod(mulmod(r, r, P), l, P);
        }
        return (l, r);
    }

    function ss_reduce_l(
        uint256 l,
        uint256 r,
        uint256 rc_a,
        uint256 rc_b
    ) internal pure returns (uint256, uint256) {
        unchecked {
            r = rc_a + addmod(mulmod(l, l, P), r, P);
        }
        l = addmod(rc_b, addmod(mulmod(r, r, P), l, P), P);
        return (l, r);
    }

    function sss(
        uint256 l,
        uint256 r,
        uint256 rc_a,
        uint256 rc_b
    ) internal pure returns (uint256, uint256) {
        unchecked {
            r = rc_a + addmod(mulmod(mulmod(l, l, P), SIGMA_INV, P), r, P);
            l = rc_b + addmod(mulmod(mulmod(r, r, P), SIGMA_INV, P), l, P);
        }
        return (l, r);
    }

    function sss_reduce_l(
        uint256 l,
        uint256 r,
        uint256 rc_a,
        uint256 rc_b
    ) internal pure returns (uint256, uint256) {
        unchecked {
            r = rc_a + addmod(mulmod(mulmod(l, l, P), SIGMA_INV, P), r, P);
        }
        l = addmod(
            rc_b,
            addmod(mulmod(mulmod(r, r, P), SIGMA_INV, P), l, P),
            P
        );
        return (l, r);
    }

    // Requires l to be reduced.
    function bb(
        uint256 l,
        uint256 r,
        uint256 rc_a,
        uint256 rc_b
    ) internal pure returns (uint256, uint256) {
        uint256 x = (l << 128) | (l >> 128); // Rotate left by 128 bits
        uint256 x1 = ((x & MASK_L1) << 1) | ((x & MASK_H1) >> 7); // Bytewise rotate left 1
        uint256 x2 = ((x1 & MASK_L1) << 1) | ((x1 & MASK_H1) >> 7);
        uint256 x3 = x1 & x2;
        uint256 x4 = ((x3 & MASK_L2) << 2) | ((x3 & MASK_H2) >> 6);
        x = x1 ^ ((~x2) & x4);
        r = addmod(rc_a, addmod(x, r, P), P);

        x = (r << 128) | (r >> 128); // Rotate left by 128 bits
        x1 = ((x & MASK_L1) << 1) | ((x & MASK_H1) >> 7); // Bytewise rotate left 1
        x2 = ((x1 & MASK_L1) << 1) | ((x1 & MASK_H1) >> 7);
        x3 = x1 & x2;
        x4 = ((x3 & MASK_L2) << 2) | ((x3 & MASK_H2) >> 6);
        x = x1 ^ ((~x2) & x4);
        unchecked {
            l = rc_b + addmod(x, l, P);
        }
        return (l, r);
    }

    function bar(uint256 x) internal pure returns (uint256) {
        x = (x << 128) | (x >> 128); // Rotate left by 128 bits
        uint256 x1 = ((x & MASK_L1) << 1) | ((x & MASK_H1) >> 7); // Bytewise rotate left 1
        uint256 x2 = ((x1 & MASK_L1) << 1) | ((x1 & MASK_H1) >> 7);
        uint256 x3 = x1 & x2;
        uint256 x4 = ((x3 & MASK_L2) << 2) | ((x3 & MASK_H2) >> 6);
        return x1 ^ ((~x2) & x4);
    }

    // SWAR 32-byte parallel SBOX.
    function sbox(uint256 x) internal pure returns (uint256) {
        uint256 x1 = ((x & MASK_L1) << 1) | ((x & MASK_H1) >> 7);
        uint256 x2 = ((x1 & MASK_L1) << 1) | ((x1 & MASK_H1) >> 7);

        uint256 t = x & x1;
        t = ((t & MASK_L3) << 3) | ((t & MASK_H3) >> 5);

        return x1 ^ ((~x2) & t);
    }

    // Bitwise rotate a byte left one place, rotates 32 bytes in parallel using SWAR.
    function rot1(uint256 x) internal pure returns (uint256) {
        uint256 left = (x & MASK_L1) << 1;
        uint256 right = (x & MASK_H1) >> 7;
        return left | right;
    }
}
