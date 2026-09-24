// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/AuditLog.sol";

contract AuditLogTest is Test {
    AuditLog public auditLog;
    address public owner;

    function setUp() public {
        owner = address(this);
        auditLog = new AuditLog();
    }

    function _logEntry(
        bytes32 sessionId,
        uint256 user,
        uint8 threatLevel
    ) internal returns (uint256) {
        return auditLog.logEntry(
            sessionId,
            user,
            keccak256("query"),
            keccak256("response"),
            threatLevel,
            "dan",
            "rule_engine"
        );
    }

    function test_ConstructorAuthorizesOwner() public view {
        assertEq(auditLog.owner(), owner);
        assertTrue(auditLog.authorizedLoggers(owner));
    }

    function test_LogEntryReturnsIndex() public {
        bytes32 sessionId = keccak256("session-1");
        uint256 index = _logEntry(sessionId, 42, 0);
        assertEq(index, 0);
        assertEq(auditLog.getLogCount(), 1);

        uint256 index2 = _logEntry(sessionId, 42, 1);
        assertEq(index2, 1);
        assertEq(auditLog.getLogCount(), 2);
    }

    function test_LogEntryStoresHashedStrings() public {
        bytes32 sessionId = keccak256("session-2");
        auditLog.logEntry(
            sessionId,
            7,
            keccak256("query-hash"),
            keccak256("response-hash"),
            2,
            "prompt_leak",
            "rule1,rule2"
        );

        AuditLog.LogEntry memory entry = auditLog.getLog(0);
        assertEq(entry.sessionId, sessionId);
        assertEq(entry.userId, 7);
        assertEq(entry.queryHash, keccak256("query-hash"));
        assertEq(entry.responseHash, keccak256("response-hash"));
        assertEq(entry.threatLevel, 2);
        assertEq(entry.jailbreakType, keccak256("prompt_leak"));
        assertEq(entry.triggeredDefenses, keccak256("rule1,rule2"));
        assertEq(entry.logger, owner);
        assertEq(entry.timestamp, block.timestamp);
    }

    function test_RevertsWhenInvalidThreatLevel() public {
        uint8 invalidLevel = auditLog.MAX_THREAT_LEVEL() + 1;
        vm.expectRevert("Invalid threat level");
        _logEntry(keccak256("session"), 0, invalidLevel);
    }

    function test_RevertsWhenUnauthorizedLogger() public {
        address unauthorized = address(0xBEEF);
        vm.prank(unauthorized);
        vm.expectRevert("Not authorized");
        _logEntry(keccak256("session"), 0, 0);
    }

    function test_AuthorizedLoggerCanLog() public {
        address newLogger = address(0x1234);
        vm.expectEmit(true, false, false, true);
        emit AuditLog.LoggerAuthorized(newLogger, true);
        auditLog.authorizeLogger(newLogger, true);
        assertTrue(auditLog.authorizedLoggers(newLogger));

        vm.prank(newLogger);
        uint256 index = _logEntry(keccak256("session"), 0, 0);
        assertEq(index, 0);

        AuditLog.LogEntry memory entry = auditLog.getLog(0);
        assertEq(entry.logger, newLogger);
    }

    function test_RevertsWhenAuthorizingZeroAddress() public {
        vm.expectRevert("invalid sender address");
        auditLog.authorizeLogger(address(0), true);
    }

    function test_RevertsWhenNonOwnerAuthorizes() public {
        address nonOwner = address(0xDEAD);
        vm.prank(nonOwner);
        vm.expectRevert("Only owner");
        auditLog.authorizeLogger(address(0x1234), true);
    }

    function test_EmitsLoggedEvent() public {
        bytes32 sessionId = keccak256("session-event");
        vm.expectEmit(true, true, true, true);
        emit AuditLog.Logged(sessionId, block.timestamp, 1, "dan", "rule_engine");
        _logEntry(sessionId, 0, 1);
    }

    function test_EmitsThreatAlertAtThreshold() public {
        bytes32 sessionId = keccak256("attack-session");
        vm.expectEmit(true, true, true, true);
        emit AuditLog.ThreatAlert(sessionId, auditLog.ALERT_THRESHOLD(), block.timestamp);
        _logEntry(sessionId, 0, auditLog.ALERT_THRESHOLD());
    }

    function test_NoThreatAlertBelowThreshold() public {
        bytes32 sessionId = keccak256("low-session");
        vm.expectEmit(true, true, false, true);
        emit AuditLog.Logged(sessionId, block.timestamp, 3, "dan", "rule_engine");
        _logEntry(sessionId, 0, auditLog.ALERT_THRESHOLD() - 1);
    }

    function test_ThreatCounters() public {
        // level 0 -> no threat
        _logEntry(keccak256("s1"), 0, 0);
        // level 2 -> threat but not high
        _logEntry(keccak256("s2"), 0, 2);
        // level 4 -> threat, alert, not high (< HIGH_THREAT_THRESHOLD = 5)
        _logEntry(keccak256("s3"), 0, 4);
        // level 5 -> threat, alert, high
        _logEntry(keccak256("s4"), 0, 5);

        (uint256 totalThreats, uint256 highThreats, uint256 count) = auditLog.getStats();
        assertEq(totalThreats, 3);
        assertEq(highThreats, 1);
        assertEq(count, 4);
        assertEq(auditLog.highThreatCount(), 1);
    }

    function test_GetLogOutOfBounds() public {
        vm.expectRevert("Index out of bounds");
        auditLog.getLog(0);
    }

    function test_GetLogsBySession() public {
        bytes32 sessionId = keccak256("multi-log-session");
        uint256 index1 = _logEntry(sessionId, 1, 1);
        uint256 index2 = _logEntry(sessionId, 2, 2);
        _logEntry(keccak256("other-session"), 3, 0);

        AuditLog.LogEntry[] memory entries = auditLog.getLogsBySession(sessionId);
        assertEq(entries.length, 2);
        assertEq(entries[0].userId, 1);
        assertEq(entries[1].userId, 2);
        assertTrue(index1 < index2);
    }

    function test_GetLogsByUnknownSessionEmpty() public view {
        AuditLog.LogEntry[] memory entries = auditLog.getLogsBySession(keccak256("nope"));
        assertEq(entries.length, 0);
    }

    function test_RevertsWhenNonOwnerReads() public {
        address nonOwner = address(0xDEAD);
        vm.prank(nonOwner);
        vm.expectRevert("Only owner");
        auditLog.getLogCount();
    }
}