// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/utils/introspection/IERC165Upgradeable.sol";

///
/// @dev Interface for token permits for ERC-721
///
interface IERC721PermitUpgradeable is IERC165Upgradeable {
  /// ERC165 bytes to add to interface array - set in parent contract
  ///
  /// _INTERFACE_ID_ERC4494 = 0x5604e225

  /// @notice Function to approve by way of owner signature
  /// @param spender the address to approve
  /// @param tokenId the index of the NFT to approve the spender on
  /// @param deadline a timestamp expiry for the permit
  /// @param sig a traditional or EIP-2098 signature
  function permit(
    address owner,
    address spender,
    uint256 tokenId,
    uint256 deadline,
    bytes memory sig
  ) external;

  /// @notice Returns the nonce of an NFT - useful for creating permits
  /// @param owner nonce based on wallet address
  /// @return the uint256 representation of the nonce
  function nonces(address owner) external view returns (uint256);

  /// @notice Returns the domain separator used in the encoding of the signature for permits, as defined by EIP-712
  /// @return the bytes32 domain separator
  // solhint-disable-next-line func-name-mixedcase
  function DOMAIN_SEPARATOR() external view returns (bytes32);
}
