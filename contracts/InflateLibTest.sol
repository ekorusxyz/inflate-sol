// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "./InflateLib.sol";

contract InflateLibTest {
    uint x = 0;
    function puff(bytes calldata source, uint256 destlen)
        external
        pure
        returns (InflateLib.ErrorCode, bytes memory)
    {
        return InflateLib.puff(source, destlen);
    }
    function puff_gas(bytes calldata source, uint256 destlen) //convoluted annoying way to get the testing to actually give me the gas usage, because it just counts it as 0 gas if it doesn't change the state, i guess... i'm sure someone out there knows how to do it better, but I don't!
        external
        returns (InflateLib.ErrorCode a, bytes memory b)
    {
        x = 1;
        (a,b) = InflateLib.puff(source, destlen);
        delete x;
    }
}
