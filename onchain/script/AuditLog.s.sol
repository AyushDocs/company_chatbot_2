// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {AuditLog} from "../src/AuditLog.sol";

contract AuditLogScript is Script {
    AuditLog public auditLog;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        auditLog = new AuditLog();

        vm.stopBroadcast();
    }
}
