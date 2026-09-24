// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract AuditLog {
    uint8 public constant MAX_THREAT_LEVEL = 5;
    uint8 public constant ALERT_THRESHOLD = 4;
    uint8 public constant HIGH_THREAT_THRESHOLD = 5;

    struct LogEntry {
        bytes32 sessionId;
        bytes32 queryHash;
        bytes32 responseHash;
        bytes32 jailbreakType;
        bytes32 triggeredDefenses;
        uint256 timestamp;
        uint256 userId;

        address logger;
        uint8 threatLevel;
    }

    LogEntry[] public logs;
    mapping(bytes32 => uint256[]) private sessionToLogIndices;
    mapping(address => bool) public authorizedLoggers;
    address public owner;
    uint256 public totalThreats;
    uint256 public highThreatCount;

    event Logged(
        bytes32 indexed sessionId,
        uint256 timestamp,
        uint8 threatLevel,
        string jailbreakType,
        string triggeredDefenses
    );
    event ThreatAlert(bytes32 indexed sessionId, uint8 threatLevel, uint256 timestamp);
    event LoggerAuthorized(address indexed logger, bool status);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedLoggers[msg.sender] = true;
        emit LoggerAuthorized(msg.sender, true);
    }

    function authorizeLogger(address _logger, bool _status) external onlyOwner {
        require(_logger!=address(0),'invalid sender address');
        authorizedLoggers[_logger] = _status;
        emit LoggerAuthorized(_logger, _status);
    }

    function logEntry(
        bytes32 _sessionId,
        uint256 _user,
        bytes32 _queryHash,
        bytes32 _responseHash,
        uint8 _threatLevel,
        string calldata _jailbreakType,
        string calldata _triggeredDefenses
    ) external returns (uint256) {
        require(authorizedLoggers[msg.sender], "Not authorized");
        require(_threatLevel <= MAX_THREAT_LEVEL, "Invalid threat level");

        uint256 index = logs.length;
        logs.push(LogEntry({
            sessionId: _sessionId,
            userId: _user,
            logger: msg.sender,
            queryHash: _queryHash,
            responseHash: _responseHash,
            threatLevel: _threatLevel,
            jailbreakType: keccak256(bytes(_jailbreakType)),
            triggeredDefenses: keccak256(bytes(_triggeredDefenses)),
            timestamp: block.timestamp
        }));
        sessionToLogIndices[_sessionId].push(index);

        if (_threatLevel > 0) {
            totalThreats++;
        }
        if (_threatLevel >= HIGH_THREAT_THRESHOLD) {
            highThreatCount++;
        }

        emit Logged(_sessionId, block.timestamp, _threatLevel, _jailbreakType, _triggeredDefenses);
        if (_threatLevel >= ALERT_THRESHOLD) {
            emit ThreatAlert(_sessionId, _threatLevel, block.timestamp);
        }
        return index;
    }

    function getLog(uint256 index) external view onlyOwner returns (LogEntry memory) {
        require(index < logs.length, "Index out of bounds");
        return logs[index];
    }

    function getLogCount() external view onlyOwner returns (uint256) {
        return logs.length;
    }

    function getLogsBySession(bytes32 _sessionId) external view onlyOwner returns (LogEntry[] memory) {
        uint256[] memory indices = sessionToLogIndices[_sessionId];
        LogEntry[] memory result = new LogEntry[](indices.length);
        for (uint256 i = 0; i < indices.length; i++) {
            result[i] = logs[indices[i]];
        }
        return result;
    }

    function getStats() external view onlyOwner returns (uint256 total, uint256 highThreat, uint256 count) {
        return (totalThreats, highThreatCount, logs.length);
    }
}
