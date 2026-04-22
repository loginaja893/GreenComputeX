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
        if (newNonce <= cur) revert GCX_InvalidParameter(keccak256("nonce.non_increasing"));
        nonceOf[msg.sender] = newNonce;
        emit NonceBumped(msg.sender, cur, newNonce);
    }

    function _eip712DomainSeparator() internal view returns (bytes32) {
        // Uses a per-contract salt so domain differs even across same name/version.
        bytes32 salt = keccak256(abi.encodePacked(GCX_DOMAIN, block.chainid, address(this)));
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("GreenComputeX")),
                keccak256(bytes("1")),
                block.chainid,
                address(this),
                salt
            )
        );
    }

    function _hashTicket(
        address client,
        address token,
        uint256 maxPrice,
        uint64 validUntil,
        bytes32 requirements,
        bytes32 jobSalt,
        uint256 nonce
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(TICKET_TYPEHASH, client, token, maxPrice, validUntil, requirements, jobSalt, nonce));
    }

    function _hashOffer(
        address provider,
        address token,
        uint256 unitPrice,
        uint64 validUntil,
        bytes32 capabilities,
        bytes32 offerSalt,
        uint256 nonce
    ) internal pure returns (bytes32) {
        return
            keccak256(abi.encode(OFFER_TYPEHASH, provider, token, unitPrice, validUntil, capabilities, offerSalt, nonce));
    }

    function _hashMatch(bytes32 ticketId, bytes32 offerId, uint256 units, uint256 totalPrice, bytes32 matchSalt)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(MATCH_TYPEHASH, ticketId, offerId, units, totalPrice, matchSalt));
    }

    function _toTypedDataHash(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _eip712DomainSeparator(), structHash));
    }

    function _validateEOAor1271(address signer, bytes32 digest, bytes memory signature) internal view {
        if (GCXAddress.isContract(signer)) {
            bytes4 ok = IERC1271(signer).isValidSignature(digest, signature);
            if (ok != 0x1626ba7e) revert GCX_SignatureRejected();
        } else {
            address rec = GCXECDSA.recover(digest, signature);
            if (rec != signer) revert GCX_SignatureRejected();
        }
    }

    // ------------------------- Jobs / Escrows -------------------------

    enum JobState {
        Null,
        Posted,
        Matched,
        Delivered,
        Finalized,
        Disputed,
        Cancelled
    }

    struct JobSpec {
        address client;
        address provider;
        address token; // address(0) indicates native ETH
        uint256 totalPrice;
        uint64 postedAt;
        uint64 validUntil;
        uint64 deliverBy;
        uint32 units;
        uint16 feeBps;
        bytes32 requirements;
        bytes32 matchSalt;
        bytes32 jobSalt;
        bytes32 offerSalt;
        bytes32 ticketId;
        bytes32 offerId;
        bytes32 matchId;
        bytes32 resultHash;
        bytes32 metaHash;
        JobState state;
    }

    mapping(bytes32 jobId => JobSpec) private _job;

    // tracking escrow balance per job for safe pull-based payout
    mapping(bytes32 jobId => uint256 locked) private _jobEscrow;

    // per-provider pending credits (to allow fail-open in case payout address blocks)
    mapping(address provider => mapping(address token => uint256 amount)) public providerCredits;
    mapping(address client => mapping(address token => uint256 amount)) public clientCredits;

    // ------------------------- Disputes -------------------------

    enum DisputeRuling {
        Unset,
        ClientWins,
        ProviderWins,
        Split
    }

    struct DisputeCase {
        uint64 openedAt;
        uint64 closeAfter;
        uint96 clientPenaltyBps;
        uint96 providerPenaltyBps;
        bytes32 disputeSalt;
        bytes32 clientClaim;
        bytes32 providerClaim;
        DisputeRuling ruling;
        bool resolved;
    }

    mapping(bytes32 jobId => DisputeCase) private _dispute;

    // ------------------------- Events -------------------------

    event CapabilityShifted(bytes32 indexed cap, address indexed prior, address indexed next);
    event LanePaused(bytes32 indexed lane, address indexed operator);
    event LaneResumed(bytes32 indexed lane, address indexed operator);

    event TokenListed(address indexed token, address indexed lister);
    event TokenDelisted(address indexed token, address indexed lister);

    event ProviderJoined(address indexed provider, address indexed payout, uint256 stake, bytes32 metaHash, bytes32 caps);
    event ProviderUpdated(address indexed provider, address indexed payout, bytes32 metaHash, bytes32 caps, uint256 stake);
    event ProviderStateSet(address indexed provider, ProviderState prior, ProviderState next);

    event NonceBumped(address indexed signer, uint256 prior, uint256 next);

    event JobPosted(bytes32 indexed jobId, address indexed client, address token, uint256 totalPrice, uint64 deliverBy);
    event JobMatched(bytes32 indexed jobId, address indexed provider, bytes32 ticketId, bytes32 offerId, bytes32 matchId);
    event JobDelivered(bytes32 indexed jobId, bytes32 indexed resultHash, bytes32 metaHash);
    event JobFinalized(bytes32 indexed jobId, address indexed beneficiary, uint256 paid, uint256 feePaid);
    event JobCancelled(bytes32 indexed jobId, address indexed client, uint256 refund);

    event DisputeOpened(bytes32 indexed jobId, address indexed opener, bytes32 clientClaim, bytes32 providerClaim);
    event DisputeEvidence(bytes32 indexed jobId, address indexed submitter, bytes32 claimHash);
    event DisputeRuled(bytes32 indexed jobId, DisputeRuling ruling, uint256 clientAmount, uint256 providerAmount, uint256 treasuryFee);

    event CreditAccrued(address indexed who, address indexed token, uint256 amount, bytes32 indexed reason);
    event CreditWithdrawn(address indexed who, address indexed token, uint256 amount, address to);

    event OracleAttested(bytes32 indexed attestationId, address indexed oracle, bytes32 indexed jobId);

    // ------------------------- Constructor -------------------------

    constructor() payable {
        if (msg.value != 0) revert GCX_NotPayable();

        _capHolder[CAP_ADMIN] = msg.sender;
        _capHolder[CAP_GUARDIAN] = BOOTSTRAP_GUARDIAN;
        _capHolder[CAP_ADJUDICATOR] = BOOTSTRAP_ADJUDICATOR;
        _capHolder[CAP_LISTER] = BOOTSTRAP_TOKEN_LISTER;
        _capHolder[CAP_PAUSE_OPERATOR] = BOOTSTRAP_PAUSE_OPERATOR;

        // Native ETH always allowed.
        _tokenAllowed[address(0)] = true;
        _listedTokens.push(address(0));

        emit CapabilityShifted(CAP_ADMIN, address(0), msg.sender);
        emit CapabilityShifted(CAP_GUARDIAN, address(0), BOOTSTRAP_GUARDIAN);
        emit CapabilityShifted(CAP_ADJUDICATOR, address(0), BOOTSTRAP_ADJUDICATOR);
        emit CapabilityShifted(CAP_LISTER, address(0), BOOTSTRAP_TOKEN_LISTER);
        emit CapabilityShifted(CAP_PAUSE_OPERATOR, address(0), BOOTSTRAP_PAUSE_OPERATOR);
    }

    // ------------------------- Admin / Roles -------------------------

    function shiftCapability(bytes32 cap, address next) external onlyCap(CAP_ADMIN) {
        if (next == address(0)) revert GCX_ZeroAddress(keccak256("cap.holder"));
        address prior = _capHolder[cap];
        _capHolder[cap] = next;
        emit CapabilityShifted(cap, prior, next);
    }

    function pauseLane(bytes32 lane) external onlyCap(CAP_PAUSE_OPERATOR) {
        _pausedLane[lane] = true;
        emit LanePaused(lane, msg.sender);
    }

    function resumeLane(bytes32 lane) external onlyCap(CAP_PAUSE_OPERATOR) {
        _pausedLane[lane] = false;
        emit LaneResumed(lane, msg.sender);
    }

    // ------------------------- Token management -------------------------

    function listToken(address token) external onlyCap(CAP_LISTER) {
        if (token == address(0)) revert GCX_InvalidParameter(keccak256("token.zero_not_needed"));
        if (_tokenAllowed[token]) revert GCX_AlreadyExists(keccak256("token.listed"));
        _tokenAllowed[token] = true;
        _listedTokens.push(token);
        emit TokenListed(token, msg.sender);
    }

    function delistToken(address token) external onlyCap(CAP_LISTER) {
        if (token == address(0)) revert GCX_InvalidParameter(keccak256("token.native_cannot_delist"));
        if (!_tokenAllowed[token]) revert GCX_NotFound(keccak256("token.not_listed"));
        _tokenAllowed[token] = false;
        emit TokenDelisted(token, msg.sender);
    }

    // ------------------------- Provider lifecycle -------------------------

    function getProvider(address provider) external view returns (ProviderProfile memory) {
        return _provider[provider];
    }

    function joinProvider(address payout, bytes32 metaHash, bytes32 capabilities) external payable whenLaneActive(LANE_PROVIDER) {
        if (payout == address(0)) revert GCX_ZeroAddress(keccak256("provider.payout"));
        if (msg.value < MIN_STAKE_WEI) revert GCX_TooSmall(keccak256("stake.min"), msg.value, MIN_STAKE_WEI);
        if (msg.value > MAX_STAKE_WEI) revert GCX_TooLarge(keccak256("stake.max"), msg.value, MAX_STAKE_WEI);

        ProviderProfile storage p = _provider[msg.sender];
        if (p.state != ProviderState.None) revert GCX_AlreadyExists(keccak256("provider.exists"));

        uint64 nowTs = uint64(block.timestamp);
        p.state = ProviderState.Active;
        p.joinedAt = nowTs;
        p.updatedAt = nowTs;
        p.score = uint96(1_000_000); // non-zero baseline
        p.stake = msg.value;
        p.metaHash = metaHash;
        p.capabilities = capabilities;
        p.payout = payout;

        unchecked {
            providerCount += 1;
        }

        emit ProviderJoined(msg.sender, payout, msg.value, metaHash, capabilities);
    }

    function topUpStake() external payable whenLaneActive(LANE_PROVIDER) {
        ProviderProfile storage p = _provider[msg.sender];
        if (p.state != ProviderState.Active) revert GCX_StateMismatch(keccak256("provider.not_active"));
        if (msg.value == 0) revert GCX_InvalidParameter(keccak256("stake.zero"));
        uint256 newStake = p.stake + msg.value;
        if (newStake > MAX_STAKE_WEI) revert GCX_TooLarge(keccak256("stake.max"), newStake, MAX_STAKE_WEI);
        p.stake = newStake;
        p.updatedAt = uint64(block.timestamp);
        emit ProviderUpdated(msg.sender, p.payout, p.metaHash, p.capabilities, p.stake);
    }

    function updateProvider(address payout, bytes32 metaHash, bytes32 capabilities) external whenLaneActive(LANE_PROVIDER) {
        ProviderProfile storage p = _provider[msg.sender];
        if (p.state != ProviderState.Active) revert GCX_StateMismatch(keccak256("provider.not_active"));
        if (payout == address(0)) revert GCX_ZeroAddress(keccak256("provider.payout"));
        p.payout = payout;
        p.metaHash = metaHash;
        p.capabilities = capabilities;
        p.updatedAt = uint64(block.timestamp);
        emit ProviderUpdated(msg.sender, payout, metaHash, capabilities, p.stake);
    }

    function setProviderState(address provider, ProviderState next) external onlyCap(CAP_GUARDIAN) {
        ProviderProfile storage p = _provider[provider];
        if (p.state == ProviderState.None) revert GCX_NotFound(keccak256("provider.missing"));
        ProviderState prior = p.state;
        p.state = next;
        p.updatedAt = uint64(block.timestamp);
        emit ProviderStateSet(provider, prior, next);
    }

    function retireAndWithdrawStake(address to, uint256 amount) external nonReentrant whenLaneActive(LANE_PROVIDER) {
        ProviderProfile storage p = _provider[msg.sender];
        if (p.state != ProviderState.Retired) revert GCX_StateMismatch(keccak256("provider.not_retired"));
        if (to == address(0)) revert GCX_ZeroAddress(keccak256("withdraw.to"));
        if (amount == 0) revert GCX_InvalidParameter(keccak256("withdraw.zero"));
        if (amount > p.stake) revert GCX_TooLarge(keccak256("withdraw.amount"), amount, p.stake);
        p.stake -= amount;
        p.updatedAt = uint64(block.timestamp);
        GCXSafeTransfer.safeTransferETH(to, amount);
    }

    // ------------------------- Job creation -------------------------

    function postJobETH(
        uint64 validUntil,
        uint64 deliverBy,
        uint32 units,
        uint16 feeBps,
        bytes32 requirements,
        bytes32 metaHash,
        bytes32 jobSalt
    ) external payable nonReentrant whenLaneActive(LANE_JOB) returns (bytes32 jobId) {
        if (!_tokenAllowed[address(0)]) revert GCX_UnsupportedToken(address(0));
        if (msg.value == 0) revert GCX_InvalidParameter(keccak256("price.zero"));
        jobId = _storeJob(
            msg.sender,
            address(0),
            msg.value,
            validUntil,
            deliverBy,
            units,
            feeBps,
            requirements,
            metaHash,
            jobSalt
        );
        _jobEscrow[jobId] = msg.value;
        emit JobPosted(jobId, msg.sender, address(0), msg.value, deliverBy);
    }

    function postJobERC20(
        address token,
        uint256 totalPrice,
        uint64 validUntil,
        uint64 deliverBy,
        uint32 units,
        uint16 feeBps,
        bytes32 requirements,
        bytes32 metaHash,
        bytes32 jobSalt
    ) external nonReentrant whenLaneActive(LANE_JOB) returns (bytes32 jobId) {
        if (token == address(0)) revert GCX_InvalidParameter(keccak256("token.use_eth_method"));
        if (!_tokenAllowed[token]) revert GCX_UnsupportedToken(token);
        if (totalPrice == 0) revert GCX_InvalidParameter(keccak256("price.zero"));
        jobId = _storeJob(
            msg.sender,
            token,
            totalPrice,
            validUntil,
            deliverBy,
            units,
            feeBps,
            requirements,
            metaHash,
            jobSalt
        );
        _jobEscrow[jobId] = totalPrice;
        IERC20Minimal(token).safeTransferFrom(msg.sender, address(this), totalPrice);
        emit JobPosted(jobId, msg.sender, token, totalPrice, deliverBy);
    }

    function _storeJob(
        address client,
        address token,
        uint256 totalPrice,
        uint64 validUntil,
        uint64 deliverBy,
        uint32 units,
        uint16 feeBps,
        bytes32 requirements,
        bytes32 metaHash,
        bytes32 jobSalt
    ) internal returns (bytes32 jobId) {
        if (client == address(0)) revert GCX_ZeroAddress(keccak256("job.client"));
        if (feeBps > MAX_FEE_BPS) revert GCX_TooLarge(keccak256("fee.bps"), feeBps, MAX_FEE_BPS);
        if (units == 0) revert GCX_InvalidParameter(keccak256("units.zero"));

        uint64 nowTs = uint64(block.timestamp);
        if (validUntil <= nowTs) revert GCX_DeadlineElapsed(nowTs, validUntil);

        if (deliverBy <= nowTs) revert GCX_DeadlineElapsed(nowTs, deliverBy);
        if (deliverBy - nowTs < JOB_TTL_MIN) revert GCX_TooSmall(keccak256("deliverBy.min_ttl"), deliverBy - nowTs, JOB_TTL_MIN);
        if (deliverBy - nowTs > JOB_TTL_MAX) revert GCX_TooLarge(keccak256("deliverBy.max_ttl"), deliverBy - nowTs, JOB_TTL_MAX);

        jobId = keccak256(abi.encodePacked(GCX_DOMAIN, client, token, totalPrice, validUntil, deliverBy, units, requirements, metaHash, jobSalt));
        if (_job[jobId].state != JobState.Null) revert GCX_AlreadyExists(keccak256("job.id_collision"));

        JobSpec storage j = _job[jobId];
        j.client = client;
        j.token = token;
        j.totalPrice = totalPrice;
        j.postedAt = nowTs;
        j.validUntil = validUntil;
        j.deliverBy = deliverBy;
        j.units = units;
        j.feeBps = feeBps;
        j.requirements = requirements;
        j.metaHash = metaHash;
        j.jobSalt = jobSalt;
        j.state = JobState.Posted;
    }

    function getJob(bytes32 jobId) external view returns (JobSpec memory spec, uint256 escrowed, DisputeCase memory dispute) {
        spec = _job[jobId];
        escrowed = _jobEscrow[jobId];
        dispute = _dispute[jobId];
    }

    function cancelJob(bytes32 jobId) external nonReentrant whenLaneActive(LANE_JOB) {
        JobSpec storage j = _job[jobId];
        if (j.state != JobState.Posted) revert GCX_StateMismatch(keccak256("job.not_posted"));
        if (msg.sender != j.client) revert GCX_Unauthorized(msg.sender, keccak256("job.cancel"));

        // Deadline guard: allow cancel after ticket expiry or after deliverBy/2 for safety.
        uint64 nowTs = uint64(block.timestamp);
        bool ticketExpired = nowTs > j.validUntil;
        bool midLife = nowTs > j.postedAt + uint64((j.deliverBy - j.postedAt) / 2);
        if (!ticketExpired && !midLife) revert GCX_StateMismatch(keccak256("job.cancel.not_allowed_yet"));

        j.state = JobState.Cancelled;

        uint256 refund = _jobEscrow[jobId];
        _jobEscrow[jobId] = 0;
        _creditClient(j.client, j.token, refund, keccak256("job.cancel.refund"));

        emit JobCancelled(jobId, j.client, refund);
    }

    // ------------------------- Matching -------------------------

    struct MatchParams {
        bytes32 jobId;

        // ticket
        address client;
        address ticketToken;
        uint256 ticketMaxPrice;
        uint64 ticketValidUntil;
        bytes32 requirements;
        bytes32 jobSalt;
        uint256 clientNonce;
        bytes clientSig;

        // offer
        address provider;
        address offerToken;
        uint256 unitPrice;
        uint64 offerValidUntil;
        bytes32 capabilities;
        bytes32 offerSalt;
        uint256 providerNonce;
        bytes providerSig;

        // match
        uint256 units;
        uint256 totalPrice;
        bytes32 matchSalt;
    }

    function matchJob(MatchParams calldata p) external nonReentrant whenLaneActive(LANE_JOB) returns (bytes32 matchId) {
        JobSpec storage j = _job[p.jobId];
        if (j.state != JobState.Posted) revert GCX_StateMismatch(keccak256("job.not_matchable"));

        if (j.client != p.client) revert GCX_InvalidParameter(keccak256("ticket.client_mismatch"));
        if (j.token != p.ticketToken) revert GCX_InvalidParameter(keccak256("ticket.token_mismatch"));
        if (j.totalPrice != p.ticketMaxPrice) revert GCX_InvalidParameter(keccak256("ticket.price_mismatch"));
        if (j.validUntil != p.ticketValidUntil) revert GCX_InvalidParameter(keccak256("ticket.validUntil_mismatch"));
        if (j.requirements != p.requirements) revert GCX_InvalidParameter(keccak256("ticket.requirements_mismatch"));
        if (j.jobSalt != p.jobSalt) revert GCX_InvalidParameter(keccak256("ticket.jobSalt_mismatch"));

        if (j.token != p.offerToken) revert GCX_InvalidParameter(keccak256("offer.token_mismatch"));
        if (p.units == 0 || p.units > j.units) revert GCX_InvalidParameter(keccak256("match.units_bad"));
        if (p.totalPrice == 0 || p.totalPrice > j.totalPrice) revert GCX_InvalidParameter(keccak256("match.price_bad"));

        uint64 nowTs = uint64(block.timestamp);
        if (p.ticketValidUntil <= nowTs) revert GCX_DeadlineElapsed(nowTs, p.ticketValidUntil);
        if (p.offerValidUntil <= nowTs) revert GCX_DeadlineElapsed(nowTs, p.offerValidUntil);
        if (j.deliverBy <= nowTs) revert GCX_DeadlineElapsed(nowTs, j.deliverBy);

        ProviderProfile storage prov = _provider[p.provider];
        if (prov.state != ProviderState.Active) revert GCX_StateMismatch(keccak256("provider.not_active"));
        if (prov.capabilities & p.capabilities != p.capabilities) revert GCX_InvalidParameter(keccak256("provider.capabilities_missing"));

        // Nonces must match current.
        if (nonceOf[p.client] != p.clientNonce) revert GCX_StateMismatch(keccak256("nonce.client_mismatch"));
        if (nonceOf[p.provider] != p.providerNonce) revert GCX_StateMismatch(keccak256("nonce.provider_mismatch"));

        // Verify signatures.
        bytes32 ticketStructHash = _hashTicket(
            p.client,
            p.ticketToken,
            p.ticketMaxPrice,
            p.ticketValidUntil,
            p.requirements,
            p.jobSalt,
            p.clientNonce
        );
        bytes32 offerStructHash = _hashOffer(
            p.provider,
            p.offerToken,
            p.unitPrice,
            p.offerValidUntil,
            p.capabilities,
            p.offerSalt,
            p.providerNonce
        );
        bytes32 ticketDigest = _toTypedDataHash(ticketStructHash);
        bytes32 offerDigest = _toTypedDataHash(offerStructHash);
        _validateEOAor1271(p.client, ticketDigest, p.clientSig);
        _validateEOAor1271(p.provider, offerDigest, p.providerSig);

        bytes32 ticketId = keccak256(abi.encodePacked("T", ticketDigest));
        bytes32 offerId = keccak256(abi.encodePacked("O", offerDigest));
        matchId = keccak256(abi.encodePacked("M", _toTypedDataHash(_hashMatch(ticketId, offerId, p.units, p.totalPrice, p.matchSalt))));

        if (j.matchId != bytes32(0)) revert GCX_AlreadyExists(keccak256("job.already_matched"));

        // Commit match
        j.provider = p.provider;
        j.ticketId = ticketId;
        j.offerId = offerId;
        j.matchId = matchId;
        j.offerSalt = p.offerSalt;
        j.matchSalt = p.matchSalt;
        j.state = JobState.Matched;

        // Lock only what is needed; refund remainder to client credits.
        uint256 escrowed = _jobEscrow[p.jobId];
        if (escrowed != j.totalPrice) revert GCX_StateMismatch(keccak256("escrow.corrupt"));

        if (p.totalPrice < j.totalPrice) {
            uint256 remainder = j.totalPrice - p.totalPrice;
            _jobEscrow[p.jobId] = p.totalPrice;
            _creditClient(j.client, j.token, remainder, keccak256("job.match.remainder"));
        }

        // Consume nonces: bump to avoid replay.
        nonceOf[p.client] = p.clientNonce + 1;
        nonceOf[p.provider] = p.providerNonce + 1;
        emit NonceBumped(p.client, p.clientNonce, p.clientNonce + 1);
        emit NonceBumped(p.provider, p.providerNonce, p.providerNonce + 1);

        emit JobMatched(p.jobId, p.provider, ticketId, offerId, matchId);
    }

    // ------------------------- Delivery / Settlement -------------------------

    function deliverResult(bytes32 jobId, bytes32 resultHash, bytes32 metaHash) external whenLaneActive(LANE_SETTLE) {
        JobSpec storage j = _job[jobId];
        if (j.state != JobState.Matched) revert GCX_StateMismatch(keccak256("job.not_deliverable"));
        if (msg.sender != j.provider) revert GCX_Unauthorized(msg.sender, keccak256("job.deliver"));

        uint64 nowTs = uint64(block.timestamp);
        if (nowTs > j.deliverBy) revert GCX_DeadlineElapsed(nowTs, j.deliverBy);

        j.resultHash = resultHash;
        j.metaHash = metaHash;
        j.state = JobState.Delivered;
        emit JobDelivered(jobId, resultHash, metaHash);
    }

    function finalize(bytes32 jobId) external nonReentrant whenLaneActive(LANE_SETTLE) {
        JobSpec storage j = _job[jobId];
        if (j.state != JobState.Delivered) revert GCX_StateMismatch(keccak256("job.not_finalizable"));

        // Either client finalizes, or provider finalizes after grace.
        uint64 nowTs = uint64(block.timestamp);
        bool byClient = msg.sender == j.client;
        bool byProviderAfterGrace = msg.sender == j.provider && nowTs >= j.deliverBy + uint64(FINALITY_GRACE);
        if (!byClient && !byProviderAfterGrace) revert GCX_Unauthorized(msg.sender, keccak256("job.finalize"));

        (uint256 paid, uint256 feePaid) = _settleToProvider(jobId, j.provider, keccak256("job.finalize"));

        j.state = JobState.Finalized;
        emit JobFinalized(jobId, j.provider, paid, feePaid);
    }

    function _settleToProvider(bytes32 jobId, address provider, bytes32 reason) internal returns (uint256 paid, uint256 feePaid) {
        JobSpec storage j = _job[jobId];
        uint256 escrowed = _jobEscrow[jobId];
        if (escrowed == 0) revert GCX_StateMismatch(keccak256("escrow.empty"));

        _jobEscrow[jobId] = 0;

        feePaid = (escrowed * uint256(j.feeBps)) / BPS_DENOMINATOR;
        paid = escrowed - feePaid;

        // Pull-based credits.
        _creditProvider(provider, j.token, paid, reason);
        _creditTreasury(j.token, feePaid, keccak256("fee.treasury"));
    }

    // ------------------------- Disputes -------------------------

    function openDispute(bytes32 jobId, bytes32 clientClaim, bytes32 providerClaim, bytes32 disputeSalt)
        external
        nonReentrant
        whenLaneActive(LANE_DISPUTE)
    {
        JobSpec storage j = _job[jobId];
        if (j.state != JobState.Delivered) revert GCX_StateMismatch(keccak256("job.not_disputable"));
        if (msg.sender != j.client && msg.sender != j.provider) revert GCX_Unauthorized(msg.sender, keccak256("dispute.open"));

        DisputeCase storage d = _dispute[jobId];
        if (d.openedAt != 0) revert GCX_AlreadyExists(keccak256("dispute.exists"));

        uint64 nowTs = uint64(block.timestamp);
