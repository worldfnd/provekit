// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Skyscraper} from "../src/Skyscraper.sol";
import {console} from "forge-std/console.sol";

contract SkyscraperTest is Test, Skyscraper {
    function test_rot_1() public {
        uint256 result = rot1(0x010203);
        assertEq(result, 0x020406);
    }

    function test_sbox() public {
        uint256 result = sbox(0xcd1783142b1e);
        assertEq(result, 0xd30e172846bc);
    }

    function test_bar() public {
        uint256 result = bar(
            13251711941470795978907268022756015766767985221093713388330058285942871890923
        );
        assertEq(
            result % P,
            8538086118276539577536391439548092640553835458646834916786764569256164366265
        );
    }

    function test_ss_2() public {
        uint256 l = 11818428481613126259506041491792444971306025298632020312923851211664140080269;
        uint256 r = 16089984100220651117533376273482359701319211672522891227502963383930673183481;
        (uint256 l_out, uint256 r_out) = sss(l, r, RC_2, RC_3);
        assertEq(
            l_out % P,
            2897520731550929941842826131888578795995028656093850302425034320680216166225
        );
        assertEq(
            r_out % P,
            10274752619072178425540318899508997829349102488123199431506343228471746115261
        );
    }

    function test_bb_6() public {
        uint256 l = 13251711941470795978907268022756015766767985221093713388330058285942871890923;
        uint256 r = 1017722258958995329580328739423576514309327442471989504101393158056883989572;
        (uint256 l_out, uint256 r_out) = bb(l, r, RC_6, RC_7);
        assertEq(
            l_out % P,
            3193610555912363022088172260048956988022957239290210718020144819371540058981
        );
        assertEq(
            r_out % P,
            17363210535454321713488811303876243393424286347736908007836172565366081010820
        );
    }

    function test_zero() public {
        (uint256 l, uint256 r) = permute_sigma(0, 0);
        assertEq(
            l % P,
            5793276905781313965269111743763131906666794041798623267477617572701829069290
        );
        assertEq(
            r % P,
            12296274483727574983376829575121280934973829438414198530604912453551798647077
        );
    }

    function test_bench_ss() public {
        uint256 startGas = gasleft();
        uint256 l = 0;
        uint256 r = 0;
        for (uint256 i = 0; i < 1000; i++) {
            (l, r) = ss(l, r, RC_2, RC_3);
        }
        uint256 gasUsed = startGas - gasleft();
        emit log_named_uint("gas per call", gasUsed / 1000);
    }

    function test_bench_ss_sigma() public {
        uint256 startGas = gasleft();
        uint256 l = 0;
        uint256 r = 0;
        for (uint256 i = 0; i < 1000; i++) {
            (l, r) = sss(l, r, RC_2, RC_3);
        }
        uint256 gasUsed = startGas - gasleft();
        emit log_named_uint("gas per call", gasUsed / 1000);
    }

    function test_bench_bb() public {
        uint256 startGas = gasleft();
        uint256 l = 0;
        uint256 r = 0;
        for (uint256 i = 0; i < 1000; i++) {
            (l, r) = bb(l, r, RC_6, RC_7);
        }
        uint256 gasUsed = startGas - gasleft();
        emit log_named_uint("gas per call", gasUsed / 1000);
    }

    function test_bench_compress() public {
        uint256 startGas = gasleft();
        uint256 l = RC_5;
        uint256 r = RC_8;
        for (uint256 i = 0; i < 1000; i++) {
            l = compress(l, r);
        }
        uint256 gasUsed = startGas - gasleft();
        emit log_named_uint("gas per call", gasUsed / 1000);
    }

    function test_bench_compress_sigma() public {
        uint256 startGas = gasleft();
        uint256 l = RC_5;
        uint256 r = RC_8;
        for (uint256 i = 0; i < 1000; i++) {
            l = compress_sigma(l, r);
        }
        uint256 gasUsed = startGas - gasleft();
        emit log_named_uint("gas per call", gasUsed / 1000);
    }

    function test_bench_sha3() public {
        uint256 startGas = gasleft();
        uint256 l = RC_5;
        uint256 r = RC_8;
        for (uint256 i = 0; i < 1000; i++) {
            l = uint256(keccak256(abi.encodePacked(l, r)));
        }
        uint256 gasUsed = startGas - gasleft();
        emit log_named_uint("gas per call", gasUsed / 1000);
    }

    function test_bench_sha256() public {
        uint256 startGas = gasleft();
        uint256 l = RC_5;
        uint256 r = RC_8;
        for (uint256 i = 0; i < 1000; i++) {
            l = uint256(sha256(abi.encodePacked(l, r)));
        }
        uint256 gasUsed = startGas - gasleft();
        emit log_named_uint("gas per call", gasUsed / 1000);
    }

    function test_bench_ripemd160() public {
        uint256 startGas = gasleft();
        uint256 l = RC_5;
        uint256 r = RC_8;
        for (uint256 i = 0; i < 1000; i++) {
            l = uint256(bytes32(ripemd160(abi.encodePacked(l, r))));
        }
        uint256 gasUsed = startGas - gasleft();
        emit log_named_uint("gas per call", gasUsed / 1000);
    }
}
