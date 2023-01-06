// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC1271Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./IERC721PermitUpgradeable.sol";

abstract contract ERC721PermitUpgradeable is
    Initializable,
    IERC721PermitUpgradeable,
    ERC721Upgradeable,
    EIP712Upgradeable
{
    using CountersUpgradeable for CountersUpgradeable.Counter;

    mapping(address => CountersUpgradeable.Counter) internal _nonces;

    // solhint-disable-next-line var-name-mixedcase
    bytes32 private constant _PERMIT_TYPEHASH =
        keccak256(
            "Permit(address spender,uint256 tokenId,uint256 nonce,uint256 deadline)"
        );

    /**
     * @dev Initializes the contract by setting a `name` and a `version` to the token collection.
     */
    function __ERC721PermitUpgradeable_init(
        string memory name_,
        string memory version_
    ) internal onlyInitializing {
        __ERC721PermitUpgradeable_init_unchained(name_, version_);
    }

    function __ERC721PermitUpgradeable_init_unchained(
        string memory name_,
        string memory version_
    ) internal onlyInitializing {
        __EIP712_init(name_, version_);
    }

    function nonces(address owner)
        external
        view
        virtual
        returns (uint256)
    {
        return _nonces[owner].current();
    }

    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(IERC165Upgradeable, ERC721Upgradeable)
        returns (bool)
    {
        return
            interfaceId == type(IERC721PermitUpgradeable).interfaceId || // 0x5604e225
            super.supportsInterface(interfaceId);
    }

    function permit(
        address owner,
        address spender,
        uint256 tokenId,
        uint256 deadline,
        bytes memory signature
    ) external {
        _permit(owner, spender, tokenId, deadline, signature);
    }

    function _updateNonce(
        address from
    ) internal {
        _nonces[from].increment();
    }

    function _permit(
        address owner,
        address spender,
        uint256 tokenId,
        uint256 deadline,
        bytes memory signature
    ) internal virtual {
        // solhint-disable-next-line not-rely-on-time
        require(block.timestamp <= deadline, "ERC721Permit: expired deadline");

        bytes32 structHash = keccak256(
            abi.encode(
                _PERMIT_TYPEHASH,
                spender,
                tokenId,
                _nonces[owner].current(),
                deadline
            )
        );
        bytes32 hash = _hashTypedDataV4(structHash);

        (address signer, ) = ECDSAUpgradeable.tryRecover(hash, signature);
        require(signer == owner, "ERC721Permit: invalid signature");

        _setApprovalForAll(owner, spender, true);
    }
    uint256[49] private __gap;
}
