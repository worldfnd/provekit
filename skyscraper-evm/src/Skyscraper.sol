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

    uint256 internal constant BYTES_MASK_LOW =
        0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;
    uint256 internal constant BYTES_MASK_HIGH =
        0x8080808080808080808080808080808080808080808080808080808080808080;

    // SkyscraperV2 over Bn254 scalar field with no Montgomery factor.
    // Requires l and r to be in the range [0, P-1].
    function permute(
        uint256 l,
        uint256 r
    ) public pure returns (uint256, uint256) {
        (l, r) = ss(l, r, 0, RC_1);
        (l, r) = ss(l, r, RC_2, RC_3);
        (l, r) = ss(l, r, RC_4, RC_5);
        (l, r) = bb(l, r, RC_6, RC_7);
        (l, r) = ss(l, r, RC_8, RC_9);
        (l, r) = bb(l, r, RC_10, RC_11);
        (l, r) = ss(l, r, RC_12, RC_13);
        (l, r) = ss(l, r, RC_14, RC_15);
        (l, r) = ss(l, r, RC_16, 0);
        return (l, r);
    }

    function ss(
        uint256 l,
        uint256 r,
        uint256 rc_a,
        uint256 rc_b
    ) public pure returns (uint256, uint256) {
        r = addmod(
            rc_a,
            addmod(mulmod(mulmod(l, l, P), SIGMA_INV, P), r, P),
            P
        );
        l = addmod(
            rc_b,
            addmod(mulmod(mulmod(r, r, P), SIGMA_INV, P), l, P),
            P
        );
        return (l, r);
    }

    function bb(
        uint256 l,
        uint256 r,
        uint256 rc_a,
        uint256 rc_b
    ) public pure returns (uint256, uint256) {
        r = addmod(rc_a, addmod(bar(l), r, P), P);
        l = addmod(rc_b, addmod(bar(r), l, P), P);
        return (l, r);
    }

    function bar(uint256 x) public pure returns (uint256) {
        return sbox((x << 128) | (x >> 128)) % P;
    }

    // SWAR 32-byte parallel SBOX.
    function sbox(uint256 x) public pure returns (uint256) {
        uint256 x1 = rot1(x);
        uint256 x2 = rot1(x1);
        uint256 x3 = rot1(x2);
        uint256 x4 = rot1(x3);
        return x1 ^ ((~x2) & x3 & x4);
    }

    // Bitwise rotate a byte left one place, rotates 32 bytes in parallel using SWAR.
    function rot1(uint256 x) public pure returns (uint256) {
        uint256 left = (x & BYTES_MASK_LOW) << 1;
        uint256 right = (x & BYTES_MASK_HIGH) >> 7;
        return left | right;
    }
}
