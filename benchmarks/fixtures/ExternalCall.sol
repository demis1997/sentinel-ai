// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Authored for Sentinel. Intentionally unsafe ordering; lexical evidence alone does
// not establish exploitation. Do not deploy this educational contract.
contract ExternalCall {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
