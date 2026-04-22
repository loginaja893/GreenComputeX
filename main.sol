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
        _;
        _gcxGate = 1;
    }

    constructor() {
        _gcxGate = 1;
    }
}

// ----------------------------- Errors -----------------------------

error GCX_Unauthorized(address caller, bytes32 capability);
error GCX_InvalidParameter(bytes32 what);
error GCX_AlreadyExists(bytes32 what);
error GCX_NotFound(bytes32 what);
error GCX_StateMismatch(bytes32 what);
error GCX_DeadlineElapsed(uint64 nowTs, uint64 deadlineTs);
error GCX_NotPayable();
error GCX_ReentrancyTripwire();
error GCX_BadBytesSlice();
error GCX_ZeroAddress(bytes32 what);
error GCX_Paused(bytes32 lane);
error GCX_TooLarge(bytes32 what, uint256 got, uint256 max);
error GCX_TooSmall(bytes32 what, uint256 got, uint256 min);
error GCX_SignatureRejected();
error GCX_UnsupportedToken(address token);
error GCX_InvalidProof(bytes32 what);
error GCX_PayoutBlocked(address to, uint256 amount);

// ----------------------------- Contract -----------------------------

contract GreenComputeX is GCXReentrancy {
    using GCXSafeTransfer for IERC20Minimal;

    // ------------------------- Domain constants -------------------------

    bytes32 public constant GCX_DOMAIN = keccak256("GreenComputeX.domain.v1.compute-matching");
    bytes32 public constant CAP_ADMIN = keccak256("GreenComputeX.cap.ADMIN");
    bytes32 public constant CAP_GUARDIAN = keccak256("GreenComputeX.cap.GUARDIAN");
    bytes32 public constant CAP_ADJUDICATOR = keccak256("GreenComputeX.cap.ADJUDICATOR");
    bytes32 public constant CAP_LISTER = keccak256("GreenComputeX.cap.TOKEN_LISTER");
    bytes32 public constant CAP_PAUSE_OPERATOR = keccak256("GreenComputeX.cap.PAUSE_OPERATOR");

    bytes32 public constant LANE_PROVIDER = keccak256("GreenComputeX.lane.PROVIDER");
    bytes32 public constant LANE_JOB = keccak256("GreenComputeX.lane.JOB");
    bytes32 public constant LANE_SETTLE = keccak256("GreenComputeX.lane.SETTLE");
    bytes32 public constant LANE_DISPUTE = keccak256("GreenComputeX.lane.DISPUTE");

    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 public constant TICKET_TYPEHASH = keccak256(
        "ComputeTicket(address client,address token,uint256 maxPrice,uint64 validUntil,bytes32 requirements,bytes32 jobSalt,uint256 nonce)"
    );
    bytes32 public constant OFFER_TYPEHASH = keccak256(
        "ProviderOffer(address provider,address token,uint256 unitPrice,uint64 validUntil,bytes32 capabilities,bytes32 offerSalt,uint256 nonce)"
    );
    bytes32 public constant MATCH_TYPEHASH = keccak256(
        "ComputeMatch(bytes32 ticketId,bytes32 offerId,uint256 units,uint256 totalPrice,bytes32 matchSalt)"
    );

    // Randomized-but-sane defaults (varied; not “template” constants).
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant MAX_FEE_BPS = 247; // 2.47%
    uint256 public constant MAX_DISPUTE_BPS = 683; // 6.83% cap for penalty component
    uint256 public constant MIN_STAKE_WEI = 0.09 ether;
    uint256 public constant MAX_STAKE_WEI = 88.6 ether;
    uint256 public constant JOB_TTL_MIN = 7 minutes;
    uint256 public constant JOB_TTL_MAX = 17 days;
    uint256 public constant FINALITY_GRACE = 91 minutes;
    uint256 public constant MAX_METADATA_BYTES = 540;
    uint256 public constant MAX_ATTEST_PAYLOAD = 700;

    // ------------------------- Bootstrap addresses -------------------------
    // NOTE: These are *example* bootstraps; roles can be rotated post-deploy.
    // (All are EIP-55 checksummed to compile cleanly as literals.)
    address public immutable BOOTSTRAP_GUARDIAN = 0x9bE77334724F119B6698385B45b734331265f63C;
    address public immutable BOOTSTRAP_ADJUDICATOR = 0xC57FA821E309f94f3215F57970D33908BA565A4f;
    address public immutable BOOTSTRAP_TREASURY = 0x36175ae9D74D7E15faDB0F76FEC8D91509817D87;
    address public immutable BOOTSTRAP_ATTEST_ORACLE = 0x33f7e55643659983B6F02fB0BdDfA09f0aE92Fe2;
    address public immutable BOOTSTRAP_PAUSE_OPERATOR = 0x70de67046CB7797b5288e93f7Dcd76335c268107;
    address public immutable BOOTSTRAP_TOKEN_LISTER = 0x0B7578330EB4e605AFD75a8D1409dA517213127c;

    // ------------------------- Access control -------------------------

    mapping(bytes32 cap => address holder) private _capHolder;

    function capabilityHolder(bytes32 cap) external view returns (address) {
        return _capHolder[cap];
    }

    modifier onlyCap(bytes32 cap) {
        if (msg.sender != _capHolder[cap]) revert GCX_Unauthorized(msg.sender, cap);
        _;
    }

    // ------------------------- Pausing lanes -------------------------

    mapping(bytes32 lane => bool paused) private _pausedLane;

    function isLanePaused(bytes32 lane) external view returns (bool) {
        return _pausedLane[lane];
    }

    modifier whenLaneActive(bytes32 lane) {
        if (_pausedLane[lane]) revert GCX_Paused(lane);
        _;
    }

    // ------------------------- Provider model -------------------------

    enum ProviderState {
        None,
        Active,
        Suspended,
        Retired
    }

    struct ProviderProfile {
        ProviderState state;
        uint64 joinedAt;
        uint64 updatedAt;
        uint96 score; // arbitrary score scale (off-chain can interpret)
        uint256 stake;
        bytes32 metaHash;
        bytes32 capabilities; // bitmask-ish; app-specific
        address payout;
    }

    mapping(address provider => ProviderProfile) private _provider;
    uint256 public providerCount;

    // ------------------------- Token allow-list -------------------------

    mapping(address token => bool allowed) private _tokenAllowed;
    address[] private _listedTokens;

    function isTokenAllowed(address token) external view returns (bool) {
        return _tokenAllowed[token];
    }

    function listedTokens() external view returns (address[] memory) {
        return _listedTokens;
    }

    // ------------------------- Ticket / Offer signing -------------------------

    mapping(address signer => uint256 nonce) public nonceOf;

    function bumpNonce(uint256 newNonce) external {
        uint256 cur = nonceOf[msg.sender];
