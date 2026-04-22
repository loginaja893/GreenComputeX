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
        for (uint256 i = 0; i < len; ++i) out[i] = b[offset + i];
    }
}

library GCXAddress {
    function isContract(address a) internal view returns (bool) {
        return a.code.length != 0;
    }
}

library GCXSafeTransfer {
    error GCX_ERC20TransferFailed();
    error GCX_ERC20TransferFromFailed();
    error GCX_ERC20ApproveFailed();
    error GCX_ETHER_TRANSFER_FAILED();

    function safeTransfer(IERC20Minimal token, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20Minimal.transfer.selector, to, amount)
        );
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert GCX_ERC20TransferFailed();
    }

    function safeTransferFrom(IERC20Minimal token, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20Minimal.transferFrom.selector, from, to, amount)
        );
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert GCX_ERC20TransferFromFailed();
    }

    function safeApprove(IERC20Minimal token, address spender, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20Minimal.approve.selector, spender, amount)
        );
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert GCX_ERC20ApproveFailed();
    }

    function safeTransferETH(address to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert GCX_ETHER_TRANSFER_FAILED();
    }
}

library GCXECDSA {
    error GCX_BadSig();
    error GCX_BadSigS();
    error GCX_BadSigV();

    function recover(bytes32 digest, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) revert GCX_BadSig();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) revert GCX_BadSigS();
        if (v != 27 && v != 28) revert GCX_BadSigV();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert GCX_BadSig();
        return signer;
    }

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}

abstract contract GCXReentrancy {
    uint256 private _gcxGate;
    modifier nonReentrant() {
        if (_gcxGate == 2) revert GCX_ReentrancyTripwire();
        _gcxGate = 2;
