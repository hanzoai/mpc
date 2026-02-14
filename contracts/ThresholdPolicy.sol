// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title ThresholdPolicy
 * @notice On-chain policy definition for MPC threshold signing.
 * @dev Policies defined here are enforced by the T-Chain (MPC network).
 *
 * Architecture:
 *   X-Chain: Assets locked with policy hash
 *   T-Chain: MPC nodes verify policy before signing
 *   This contract: Defines unlock conditions
 */
contract ThresholdPolicy is AccessControl {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ============================================================
    // ROLES
    // ============================================================

    bytes32 public constant POLICY_ADMIN_ROLE = keccak256("POLICY_ADMIN_ROLE");
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    // ============================================================
    // TYPES
    // ============================================================

    // Rule opcodes (must match pkg/threshold/policy_vm.go)
    uint8 public constant OP_CHECK_AMOUNT_LT = 0x01;
    uint8 public constant OP_CHECK_AMOUNT_GT = 0x02;
    uint8 public constant OP_CHECK_AMOUNT_RANGE = 0x03;
    uint8 public constant OP_CHECK_CUMULATIVE = 0x04;
    uint8 public constant OP_CHECK_WHITELIST = 0x10;
    uint8 public constant OP_CHECK_BLACKLIST = 0x11;
    uint8 public constant OP_CHECK_TIME_WINDOW = 0x20;
    uint8 public constant OP_CHECK_TIME_LOCK = 0x21;
    uint8 public constant OP_CHECK_COOLDOWN = 0x22;
    uint8 public constant OP_REQUIRE_SIGNATURES = 0x30;
    uint8 public constant OP_CHECK_VESTING = 0x40;
    uint8 public constant OP_CHECK_STREAM_RATE = 0x41;

    // Result actions
    uint8 public constant RESULT_ALLOW = 0x00;
    uint8 public constant RESULT_DENY = 0x01;
    uint8 public constant RESULT_REQUIRE_SIGS = 0x02;
    uint8 public constant RESULT_DELAY = 0x03;
    uint8 public constant RESULT_PARTIAL_UNLOCK = 0x04;

    struct Rule {
        bytes8 ruleId;
        uint8 opcode;
        bytes[] operands;
        uint8 resultAction;
        bool enabled;
    }

    struct Policy {
        bytes32 walletId;
        uint64 chainId;
        uint64 version;
        Rule[] rules;
        address[] signers;
        uint256 requiredSignatures;
        uint256 createdAt;
        uint256 expiresAt;
        bool active;
    }

    struct VestingSchedule {
        uint256 totalAmount;
        uint256 startTime;
        uint256 duration;
        uint256 cliffDuration;
        uint256 released;
    }

    struct StreamConfig {
        uint256 ratePerSecond;
        uint256 startTime;
        uint256 totalStreamed;
    }

    // ============================================================
    // STATE
    // ============================================================

    // walletId => Policy
    mapping(bytes32 => Policy) public policies;

    // walletId => vesting schedule
    mapping(bytes32 => VestingSchedule) public vestingSchedules;

    // walletId => streaming config
    mapping(bytes32 => StreamConfig) public streamConfigs;

    // walletId => destination => whitelisted
    mapping(bytes32 => mapping(address => bool)) public whitelists;

    // walletId => destination => blacklisted
    mapping(bytes32 => mapping(address => bool)) public blacklists;

    // walletId => daily cumulative amount
    mapping(bytes32 => uint256) public dailyCumulative;
    mapping(bytes32 => uint256) public dailyCumulativeReset;

    // walletId => last transaction timestamp
    mapping(bytes32 => uint256) public lastTxTimestamp;

    // ============================================================
    // EVENTS
    // ============================================================

    event PolicyRegistered(
        bytes32 indexed walletId,
        bytes32 indexed policyHash,
        uint64 version,
        address indexed registrar
    );

    event PolicyUpdated(
        bytes32 indexed walletId,
        bytes32 indexed newPolicyHash,
        uint64 newVersion
    );

    event PolicyDeactivated(bytes32 indexed walletId);

    event RuleAdded(
        bytes32 indexed walletId,
        bytes8 ruleId,
        uint8 opcode,
        uint8 resultAction
    );

    event SignerAdded(bytes32 indexed walletId, address indexed signer);
    event SignerRemoved(bytes32 indexed walletId, address indexed signer);

    event WhitelistUpdated(bytes32 indexed walletId, address indexed destination, bool whitelisted);
    event BlacklistUpdated(bytes32 indexed walletId, address indexed destination, bool blacklisted);

    event VestingConfigured(
        bytes32 indexed walletId,
        uint256 totalAmount,
        uint256 startTime,
        uint256 duration,
        uint256 cliffDuration
    );

    event StreamConfigured(
        bytes32 indexed walletId,
        uint256 ratePerSecond,
        uint256 startTime
    );

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(POLICY_ADMIN_ROLE, msg.sender);
    }

    // ============================================================
    // POLICY MANAGEMENT
    // ============================================================

    /**
     * @notice Register a new policy for a wallet
     * @param walletId The MPC wallet identifier
     * @param signers Array of authorized signers
     * @param requiredSignatures Number of signatures required
     * @param expiresAt Policy expiration timestamp (0 = never)
     */
    function registerPolicy(
        bytes32 walletId,
        address[] calldata signers,
        uint256 requiredSignatures,
        uint256 expiresAt
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        require(signers.length >= requiredSignatures, "Invalid threshold");
        require(!policies[walletId].active, "Policy exists");

        Policy storage policy = policies[walletId];
        policy.walletId = walletId;
        policy.chainId = uint64(block.chainid);
        policy.version = 1;
        policy.signers = signers;
        policy.requiredSignatures = requiredSignatures;
        policy.createdAt = block.timestamp;
        policy.expiresAt = expiresAt;
        policy.active = true;

        bytes32 policyHash = computePolicyHash(walletId);

        emit PolicyRegistered(walletId, policyHash, 1, msg.sender);
    }

    /**
     * @notice Add a rule to a policy
     */
    function addRule(
        bytes32 walletId,
        bytes8 ruleId,
        uint8 opcode,
        bytes[] calldata operands,
        uint8 resultAction
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        require(policies[walletId].active, "Policy not active");

        Policy storage policy = policies[walletId];
        policy.rules.push(Rule({
            ruleId: ruleId,
            opcode: opcode,
            operands: operands,
            resultAction: resultAction,
            enabled: true
        }));
        policy.version++;

        emit RuleAdded(walletId, ruleId, opcode, resultAction);
        emit PolicyUpdated(walletId, computePolicyHash(walletId), policy.version);
    }

    /**
     * @notice Configure amount limit rule
     */
    function setAmountLimit(
        bytes32 walletId,
        uint256 maxAmount,
        uint8 resultAction
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        bytes[] memory operands = new bytes[](1);
        operands[0] = abi.encodePacked(maxAmount);

        Policy storage policy = policies[walletId];
        policy.rules.push(Rule({
            ruleId: bytes8(keccak256(abi.encodePacked("AMOUNT_LIMIT", block.timestamp))),
            opcode: OP_CHECK_AMOUNT_GT,
            operands: operands,
            resultAction: resultAction,
            enabled: true
        }));
        policy.version++;
    }

    /**
     * @notice Configure daily cumulative limit
     */
    function setDailyLimit(
        bytes32 walletId,
        uint256 dailyLimit,
        uint8 resultAction
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        bytes[] memory operands = new bytes[](1);
        operands[0] = abi.encodePacked(dailyLimit);

        Policy storage policy = policies[walletId];
        policy.rules.push(Rule({
            ruleId: bytes8(keccak256(abi.encodePacked("DAILY_LIMIT", block.timestamp))),
            opcode: OP_CHECK_CUMULATIVE,
            operands: operands,
            resultAction: resultAction,
            enabled: true
        }));
        policy.version++;
    }

    /**
     * @notice Configure time lock (no transactions before unlock time)
     */
    function setTimeLock(
        bytes32 walletId,
        uint256 unlockTime,
        uint8 resultAction
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        bytes[] memory operands = new bytes[](1);
        operands[0] = abi.encodePacked(uint64(unlockTime));

        Policy storage policy = policies[walletId];
        policy.rules.push(Rule({
            ruleId: bytes8(keccak256(abi.encodePacked("TIME_LOCK", block.timestamp))),
            opcode: OP_CHECK_TIME_LOCK,
            operands: operands,
            resultAction: resultAction,
            enabled: true
        }));
        policy.version++;
    }

    /**
     * @notice Configure cooldown period between transactions
     */
    function setCooldown(
        bytes32 walletId,
        uint256 cooldownSeconds,
        uint8 resultAction
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        bytes[] memory operands = new bytes[](1);
        operands[0] = abi.encodePacked(uint64(cooldownSeconds));

        Policy storage policy = policies[walletId];
        policy.rules.push(Rule({
            ruleId: bytes8(keccak256(abi.encodePacked("COOLDOWN", block.timestamp))),
            opcode: OP_CHECK_COOLDOWN,
            operands: operands,
            resultAction: resultAction,
            enabled: true
        }));
        policy.version++;
    }

    // ============================================================
    // VESTING & STREAMING
    // ============================================================

    /**
     * @notice Configure vesting schedule for a wallet
     */
    function configureVesting(
        bytes32 walletId,
        uint256 totalAmount,
        uint256 startTime,
        uint256 duration,
        uint256 cliffDuration
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        require(policies[walletId].active, "Policy not active");
        require(duration > 0, "Duration must be > 0");
        require(cliffDuration <= duration, "Cliff > duration");

        vestingSchedules[walletId] = VestingSchedule({
            totalAmount: totalAmount,
            startTime: startTime,
            duration: duration,
            cliffDuration: cliffDuration,
            released: 0
        });

        // Add vesting rule
        bytes[] memory operands = new bytes[](4);
        operands[0] = abi.encodePacked(totalAmount);
        operands[1] = abi.encodePacked(uint64(startTime));
        operands[2] = abi.encodePacked(uint64(duration));
        operands[3] = abi.encodePacked(uint64(cliffDuration));

        Policy storage policy = policies[walletId];
        policy.rules.push(Rule({
            ruleId: bytes8(keccak256(abi.encodePacked("VESTING", block.timestamp))),
            opcode: OP_CHECK_VESTING,
            operands: operands,
            resultAction: RESULT_PARTIAL_UNLOCK,
            enabled: true
        }));
        policy.version++;

        emit VestingConfigured(walletId, totalAmount, startTime, duration, cliffDuration);
    }

    /**
     * @notice Configure streaming payments
     */
    function configureStream(
        bytes32 walletId,
        uint256 ratePerSecond,
        uint256 startTime
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        require(policies[walletId].active, "Policy not active");
        require(ratePerSecond > 0, "Rate must be > 0");

        streamConfigs[walletId] = StreamConfig({
            ratePerSecond: ratePerSecond,
            startTime: startTime,
            totalStreamed: 0
        });

        // Add streaming rule
        bytes[] memory operands = new bytes[](2);
        operands[0] = abi.encodePacked(ratePerSecond);
        operands[1] = abi.encodePacked(uint64(startTime));

        Policy storage policy = policies[walletId];
        policy.rules.push(Rule({
            ruleId: bytes8(keccak256(abi.encodePacked("STREAM", block.timestamp))),
            opcode: OP_CHECK_STREAM_RATE,
            operands: operands,
            resultAction: RESULT_PARTIAL_UNLOCK,
            enabled: true
        }));
        policy.version++;

        emit StreamConfigured(walletId, ratePerSecond, startTime);
    }

    /**
     * @notice Calculate vested amount available
     */
    function vestedAmount(bytes32 walletId) public view returns (uint256) {
        VestingSchedule storage schedule = vestingSchedules[walletId];
        if (schedule.totalAmount == 0) return 0;
        if (block.timestamp < schedule.startTime + schedule.cliffDuration) return 0;

        uint256 elapsed = block.timestamp - schedule.startTime;
        if (elapsed >= schedule.duration) {
            return schedule.totalAmount - schedule.released;
        }

        uint256 vested = (schedule.totalAmount * elapsed) / schedule.duration;
        return vested - schedule.released;
    }

    /**
     * @notice Calculate streamable amount available
     */
    function streamableAmount(bytes32 walletId) public view returns (uint256) {
        StreamConfig storage config = streamConfigs[walletId];
        if (config.ratePerSecond == 0) return 0;
        if (block.timestamp < config.startTime) return 0;

        uint256 elapsed = block.timestamp - config.startTime;
        uint256 total = config.ratePerSecond * elapsed;
        return total - config.totalStreamed;
    }

    // ============================================================
    // WHITELIST / BLACKLIST
    // ============================================================

    function addToWhitelist(bytes32 walletId, address destination) external onlyRole(POLICY_ADMIN_ROLE) {
        whitelists[walletId][destination] = true;
        emit WhitelistUpdated(walletId, destination, true);
    }

    function removeFromWhitelist(bytes32 walletId, address destination) external onlyRole(POLICY_ADMIN_ROLE) {
        whitelists[walletId][destination] = false;
        emit WhitelistUpdated(walletId, destination, false);
    }

    function addToBlacklist(bytes32 walletId, address destination) external onlyRole(POLICY_ADMIN_ROLE) {
        blacklists[walletId][destination] = true;
        emit BlacklistUpdated(walletId, destination, true);
    }

    function removeFromBlacklist(bytes32 walletId, address destination) external onlyRole(POLICY_ADMIN_ROLE) {
        blacklists[walletId][destination] = false;
        emit BlacklistUpdated(walletId, destination, false);
    }

    // ============================================================
    // SIGNER MANAGEMENT
    // ============================================================

    function addSigner(bytes32 walletId, address signer) external onlyRole(POLICY_ADMIN_ROLE) {
        require(policies[walletId].active, "Policy not active");
        policies[walletId].signers.push(signer);
        policies[walletId].version++;
        emit SignerAdded(walletId, signer);
    }

    function removeSigner(bytes32 walletId, address signer) external onlyRole(POLICY_ADMIN_ROLE) {
        require(policies[walletId].active, "Policy not active");
        Policy storage policy = policies[walletId];

        for (uint i = 0; i < policy.signers.length; i++) {
            if (policy.signers[i] == signer) {
                policy.signers[i] = policy.signers[policy.signers.length - 1];
                policy.signers.pop();
                policy.version++;
                emit SignerRemoved(walletId, signer);
                return;
            }
        }
        revert("Signer not found");
    }

    function setRequiredSignatures(bytes32 walletId, uint256 required) external onlyRole(POLICY_ADMIN_ROLE) {
        require(policies[walletId].active, "Policy not active");
        require(required <= policies[walletId].signers.length, "Invalid threshold");
        policies[walletId].requiredSignatures = required;
        policies[walletId].version++;
    }

    // ============================================================
    // VERIFICATION (Called by MPC nodes)
    // ============================================================

    /**
     * @notice Compute policy hash for verification
     */
    function computePolicyHash(bytes32 walletId) public view returns (bytes32) {
        Policy storage policy = policies[walletId];

        bytes memory encoded = abi.encodePacked(
            walletId,
            policy.chainId,
            policy.version
        );

        for (uint i = 0; i < policy.rules.length; i++) {
            Rule storage rule = policy.rules[i];
            if (rule.enabled) {
                encoded = abi.encodePacked(
                    encoded,
                    rule.ruleId,
                    rule.opcode,
                    rule.resultAction
                );
            }
        }

        return keccak256(encoded);
    }

    /**
     * @notice Get policy data for MPC verification
     */
    function getPolicyData(bytes32 walletId) external view returns (
        bytes32 policyHash,
        uint64 version,
        address[] memory signers,
        uint256 requiredSignatures,
        uint256 expiresAt,
        bool active
    ) {
        Policy storage policy = policies[walletId];
        return (
            computePolicyHash(walletId),
            policy.version,
            policy.signers,
            policy.requiredSignatures,
            policy.expiresAt,
            policy.active
        );
    }

    /**
     * @notice Get all rules for a policy
     */
    function getRules(bytes32 walletId) external view returns (Rule[] memory) {
        return policies[walletId].rules;
    }

    /**
     * @notice Check if address is whitelisted
     */
    function isWhitelisted(bytes32 walletId, address destination) external view returns (bool) {
        return whitelists[walletId][destination];
    }

    /**
     * @notice Check if address is blacklisted
     */
    function isBlacklisted(bytes32 walletId, address destination) external view returns (bool) {
        return blacklists[walletId][destination];
    }

    // ============================================================
    // STATE UPDATES (Called after MPC signing)
    // ============================================================

    /**
     * @notice Record a transaction (called by bridge after successful signing)
     */
    function recordTransaction(
        bytes32 walletId,
        uint256 amount,
        address destination
    ) external onlyRole(SIGNER_ROLE) {
        // Reset daily cumulative if new day
        if (block.timestamp / 1 days > dailyCumulativeReset[walletId]) {
            dailyCumulative[walletId] = 0;
            dailyCumulativeReset[walletId] = block.timestamp / 1 days;
        }

        // Update cumulative
        dailyCumulative[walletId] += amount;

        // Update last tx timestamp
        lastTxTimestamp[walletId] = block.timestamp;

        // Update vesting released
        VestingSchedule storage vesting = vestingSchedules[walletId];
        if (vesting.totalAmount > 0) {
            vesting.released += amount;
        }

        // Update streaming
        StreamConfig storage stream = streamConfigs[walletId];
        if (stream.ratePerSecond > 0) {
            stream.totalStreamed += amount;
        }
    }
}
