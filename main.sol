// GreenComputeX — a compute-match + escrow router with adjudication rails.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title GreenComputeX
 * @notice Compute matching platform primitives: provider registry, job escrow, settlement, and disputes.
 * @dev Mainnet-safe patterns: checks-effects-interactions, reentrancy guard, explicit roles, minimal external calls.
 */

// ----------------------------- Interfaces -----------------------------

interface IERC20Minimal {
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

interface IGreenComputeXOracleLike {
    function attest(bytes32 attestationId, bytes calldata payload) external;
}

// ----------------------------- Libraries -----------------------------

library GCXMath {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }

    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return a == 0 ? 0 : ((a - 1) / b) + 1;
        }
    }

    function mulDivDown(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) {
        return (x * y) / d;
    }

    function mulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) {
        unchecked {
            uint256 z = x * y;
            return z == 0 ? 0 : ((z - 1) / d) + 1;
        }
    }
}

library GCXBytes {
    function toBytes32(bytes memory b, uint256 offset) internal pure returns (bytes32 out) {
        if (b.length < offset + 32) revert GCX_BadBytesSlice();
        assembly {
            out := mload(add(add(b, 0x20), offset))
        }
    }

    function slice(bytes memory b, uint256 offset, uint256 len) internal pure returns (bytes memory out) {
        if (b.length < offset + len) revert GCX_BadBytesSlice();
        out = new bytes(len);
