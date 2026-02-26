// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title DocumentSharing
 * @dev Decentralized document sharing, certificate storage, and verification system.
 *      Uses IPFS hashes for file references and keccak256 for integrity verification.
 *
 * NEW in this version:
 *  - fileHash field for on-chain integrity verification
 *  - description / category fields per document
 *  - Access expiry timestamps (0 = no expiry)
 *  - verifyDocument()  – public verification without needing access
 *  - getAccessDetails() – returns grantedAt + expiresAt for an address
 *  - DocumentVerified event
 *  - isAccessExpired() helper
 */
contract DocumentSharing {

    // ─────────────────────────────────────────────
    //  Data structures
    // ─────────────────────────────────────────────

    struct Document {
        string  ipfsHash;       // IPFS CID of the document
        string  fileName;       // Original file name
        string  description;    // Short description or certificate title
        string  category;       // e.g. "certificate", "contract", "identity"
        bytes32 fileHash;       // keccak256 of file bytes for integrity check
        uint256 timestamp;      // Upload timestamp
        address owner;          // Document owner
        bool    exists;         // Soft-delete flag
    }

    struct AccessPermission {
        bool    canView;
        uint256 grantedAt;
        uint256 expiresAt;   // Unix timestamp; 0 = never expires
    }

    // ─────────────────────────────────────────────
    //  State
    // ─────────────────────────────────────────────

    mapping(uint256 => Document)                              public documents;
    mapping(uint256 => mapping(address => AccessPermission))  public accessPermissions;
    mapping(address => uint256[])                             public ownerDocuments;
    mapping(address => uint256[])                             public sharedWithMe;

    uint256 public documentCount;

    // ─────────────────────────────────────────────
    //  Events
    // ─────────────────────────────────────────────

    event DocumentUploaded(
        uint256 indexed documentId,
        string  ipfsHash,
        string  fileName,
        bytes32 fileHash,
        address indexed owner,
        uint256 timestamp
    );

    event AccessGranted(
        uint256 indexed documentId,
        address indexed owner,
        address indexed recipient,
        uint256 grantedAt,
        uint256 expiresAt
    );

    event AccessRevoked(
        uint256 indexed documentId,
        address indexed owner,
        address indexed recipient,
        uint256 timestamp
    );

    event DocumentDeleted(
        uint256 indexed documentId,
        address indexed owner,
        uint256 timestamp
    );

    event DocumentVerified(
        uint256 indexed documentId,
        address indexed verifier,
        bool    success,
        uint256 timestamp
    );

    // ─────────────────────────────────────────────
    //  Modifiers
    // ─────────────────────────────────────────────

    modifier onlyOwner(uint256 _documentId) {
        require(documents[_documentId].exists, "Document does not exist");
        require(documents[_documentId].owner == msg.sender, "Not the document owner");
        _;
    }

    modifier documentExists(uint256 _documentId) {
        require(documents[_documentId].exists, "Document does not exist");
        _;
    }

    modifier hasAccess(uint256 _documentId) {
        require(
            documents[_documentId].owner == msg.sender ||
            _isAccessValid(_documentId, msg.sender),
            "No access to this document"
        );
        _;
    }

    // ─────────────────────────────────────────────
    //  Internal helpers
    // ─────────────────────────────────────────────

    function _isAccessValid(uint256 _documentId, address _user) internal view returns (bool) {
        AccessPermission memory perm = accessPermissions[_documentId][_user];
        if (!perm.canView) return false;
        if (perm.expiresAt == 0) return true;           // Never expires
        return block.timestamp <= perm.expiresAt;
    }

    // ─────────────────────────────────────────────
    //  Write functions
    // ─────────────────────────────────────────────

    /**
     * @notice Upload a new document / certificate.
     * @param _ipfsHash   IPFS CID of the file.
     * @param _fileName   Original file name.
     * @param _description Short human-readable title / description.
     * @param _category   Category string (e.g. "certificate", "contract").
     * @param _fileHash   keccak256 of raw file bytes, computed client-side.
     */
    function uploadDocument(
        string  memory _ipfsHash,
        string  memory _fileName,
        string  memory _description,
        string  memory _category,
        bytes32        _fileHash
    ) public returns (uint256) {
        require(bytes(_ipfsHash).length   > 0, "IPFS hash cannot be empty");
        require(bytes(_fileName).length   > 0, "File name cannot be empty");

        documentCount++;

        documents[documentCount] = Document({
            ipfsHash:    _ipfsHash,
            fileName:    _fileName,
            description: _description,
            category:    _category,
            fileHash:    _fileHash,
            timestamp:   block.timestamp,
            owner:       msg.sender,
            exists:      true
        });

        ownerDocuments[msg.sender].push(documentCount);

        emit DocumentUploaded(
            documentCount, _ipfsHash, _fileName, _fileHash,
            msg.sender, block.timestamp
        );

        return documentCount;
    }

    /**
     * @notice Grant view access to a recipient, optionally with an expiry.
     * @param _documentId  ID of the document.
     * @param _recipient   Address to grant access to.
     * @param _expiresAt   Unix timestamp for expiry; pass 0 for no expiry.
     */
    function grantAccess(
        uint256 _documentId,
        address _recipient,
        uint256 _expiresAt
    ) public onlyOwner(_documentId) {
        require(_recipient != address(0), "Invalid recipient address");
        require(_recipient != msg.sender, "Cannot grant access to yourself");
        require(
            !accessPermissions[_documentId][_recipient].canView,
            "Access already granted"
        );
        require(
            _expiresAt == 0 || _expiresAt > block.timestamp,
            "Expiry must be in the future"
        );

        accessPermissions[_documentId][_recipient] = AccessPermission({
            canView:   true,
            grantedAt: block.timestamp,
            expiresAt: _expiresAt
        });

        sharedWithMe[_recipient].push(_documentId);

        emit AccessGranted(
            _documentId, msg.sender, _recipient,
            block.timestamp, _expiresAt
        );
    }

    /**
     * @notice Revoke view access from a recipient.
     */
    function revokeAccess(uint256 _documentId, address _recipient)
        public
        onlyOwner(_documentId)
    {
        require(
            accessPermissions[_documentId][_recipient].canView,
            "Access not granted"
        );

        accessPermissions[_documentId][_recipient].canView = false;

        // Remove from sharedWithMe array
        uint256[] storage shared = sharedWithMe[_recipient];
        for (uint256 i = 0; i < shared.length; i++) {
            if (shared[i] == _documentId) {
                shared[i] = shared[shared.length - 1];
                shared.pop();
                break;
            }
        }

        emit AccessRevoked(_documentId, msg.sender, _recipient, block.timestamp);
    }

    /**
     * @notice Soft-delete a document (only owner).
     */
    function deleteDocument(uint256 _documentId) public onlyOwner(_documentId) {
        documents[_documentId].exists = false;

        uint256[] storage owned = ownerDocuments[msg.sender];
        for (uint256 i = 0; i < owned.length; i++) {
            if (owned[i] == _documentId) {
                owned[i] = owned[owned.length - 1];
                owned.pop();
                break;
            }
        }

        emit DocumentDeleted(_documentId, msg.sender, block.timestamp);
    }

    // ─────────────────────────────────────────────
    //  View / Verification functions
    // ─────────────────────────────────────────────

    /**
     * @notice Retrieve full document details. Caller must be owner or have valid access.
     */
    function getDocument(uint256 _documentId)
        public
        view
        documentExists(_documentId)
        hasAccess(_documentId)
        returns (
            string  memory ipfsHash,
            string  memory fileName,
            string  memory description,
            string  memory category,
            bytes32        fileHash,
            uint256        timestamp,
            address        owner
        )
    {
        Document memory doc = documents[_documentId];
        return (
            doc.ipfsHash, doc.fileName, doc.description,
            doc.category, doc.fileHash, doc.timestamp, doc.owner
        );
    }

    /**
     * @notice Verify a document by matching the provided IPFS hash and/or file hash.
     *         This is public — anyone can call it for certificate verification.
     * @param _documentId    ID of the document to verify.
     * @param _ipfsHash      IPFS CID to compare against the stored one.
     * @param _fileHash      keccak256 of file bytes; pass bytes32(0) to skip check.
     * @return valid         True if both provided values match stored values.
     * @return storedOwner   The owner address recorded on-chain.
     * @return uploadTime    When the document was originally uploaded.
     */
    function verifyDocument(
        uint256        _documentId,
        string  memory _ipfsHash,
        bytes32        _fileHash
    )
        public
        returns (
            bool    valid,
            address storedOwner,
            uint256 uploadTime,
            string  memory fileName,
            string  memory category
        )
    {
        if (!documents[_documentId].exists) {
            emit DocumentVerified(_documentId, msg.sender, false, block.timestamp);
            return (false, address(0), 0, "", "");
        }

        Document memory doc = documents[_documentId];

        bool ipfsMatch = keccak256(bytes(doc.ipfsHash)) == keccak256(bytes(_ipfsHash));
        bool hashMatch = (_fileHash == bytes32(0)) || (doc.fileHash == _fileHash);
        valid = ipfsMatch && hashMatch;

        emit DocumentVerified(_documentId, msg.sender, valid, block.timestamp);

        return (valid, doc.owner, doc.timestamp, doc.fileName, doc.category);
    }

    /**
     * @notice Check if an address currently has valid (non-expired) access.
     */
    function checkAccess(uint256 _documentId, address _user)
        public
        view
        documentExists(_documentId)
        returns (bool)
    {
        return documents[_documentId].owner == _user ||
               _isAccessValid(_documentId, _user);
    }

    /**
     * @notice Check whether an address's access has expired.
     */
    function isAccessExpired(uint256 _documentId, address _user)
        public
        view
        documentExists(_documentId)
        returns (bool)
    {
        AccessPermission memory perm = accessPermissions[_documentId][_user];
        if (!perm.canView)        return false;   // was never granted
        if (perm.expiresAt == 0)  return false;   // no expiry set
        return block.timestamp > perm.expiresAt;
    }

    /**
     * @notice Get full access details for a user on a document.
     */
    function getAccessDetails(uint256 _documentId, address _user)
        public
        view
        documentExists(_documentId)
        returns (
            bool    canView,
            uint256 grantedAt,
            uint256 expiresAt,
            bool    expired
        )
    {
        AccessPermission memory perm = accessPermissions[_documentId][_user];
        bool exp = (perm.expiresAt != 0 && block.timestamp > perm.expiresAt);
        return (perm.canView, perm.grantedAt, perm.expiresAt, exp);
    }

    /**
     * @notice Get all document IDs owned by an address.
     */
    function getMyDocuments(address _owner) public view returns (uint256[] memory) {
        return ownerDocuments[_owner];
    }

    /**
     * @notice Get all document IDs shared with an address.
     */
    function getSharedWithMe(address _user) public view returns (uint256[] memory) {
        return sharedWithMe[_user];
    }

    /**
     * @notice Total number of documents ever uploaded.
     */
    function getTotalDocuments() public view returns (uint256) {
        return documentCount;
    }
}
