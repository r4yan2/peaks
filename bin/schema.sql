--
-- Table structure for table `gpg_keyserver`
--

CREATE TABLE IF NOT EXISTS `gpg_keyserver` (
  `version` tinyint(3) unsigned NOT NULL,
  `ID` bigint(20) unsigned NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `hash` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `is_unpacked` tinyint(4) NOT NULL DEFAULT '0',
  `error_code` int(11) NOT NULL DEFAULT '0',
  `filename` TEXT NOT NULL,
  `origin` int(11) NOT NULL,
  `len` int(11) NOT NULL,
  KEY `fingerprint` (`fingerprint`, `version`),
  KEY `id` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table structure for table `Pubkey`
--

CREATE TABLE IF NOT EXISTS `Pubkey` (
  `keyId` bigint(20) unsigned NOT NULL,
  `version` tinyint(3) unsigned NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `PriFingerprint` binary(20) DEFAULT NULL,
  `pubAlgorithm` smallint(5) unsigned NOT NULL,
  `creationTime` datetime NOT NULL,
  `expirationTime` datetime DEFAULT NULL,
  `revocationTime` datetime DEFAULT NULL,
  `e` blob,
  `n` blob,
  `p` blob,
  `q` blob,
  `g` blob,
  `y` blob,
  `curveOID` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `is_analyzed` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`fingerprint`, `version`),
  KEY `n` (`n`(200)),
  KEY `keyId` (`keyId`,`fingerprint`),
  KEY `Pubkey_cert` (`PriFingerprint`, `version`),
  KEY `is_analyzed` (`is_analyzed`),
  FOREIGN KEY `Pubkey_Certificate_binding` (`fingerprint`) REFERENCES `gpg_keyserver` (`fingerprint`) ON DELETE CASCADE,
  FOREIGN KEY `Primarykey_Subkey_binding` (`PriFingerprint`) REFERENCES `Pubkey` (`fingerprint`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table structure for table `KeyStatus`
--

CREATE TABLE IF NOT EXISTS `KeyStatus` (
  `version` tinyint(3) unsigned NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `vulnerabilityCode` tinyint(4) NOT NULL,
  `vulnerabilityDescription` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`fingerprint`,`version`,`vulnerabilityCode`),
  FOREIGN KEY `KeyStatus_Pubkey_binding` (`fingerprint`, `version`) REFERENCES Pubkey(`fingerprint`, `version`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


--
-- Table structure for table `Signatures`
--

CREATE TABLE IF NOT EXISTS `Signatures` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `type` smallint(5) unsigned NOT NULL,
  `pubAlgorithm` smallint(5) unsigned NOT NULL,
  `hashAlgorithm` smallint(5) unsigned NOT NULL,
  `version` smallint(5) unsigned NOT NULL,
  `issuingKeyId` bigint(20) unsigned NOT NULL,
  `signedKeyId` bigint(20) unsigned NOT NULL,
  `issuingFingerprint` binary(20) DEFAULT NULL,
  `signedFingerprint` binary(20) NOT NULL,
  `signedUsername` varchar(750) DEFAULT NULL,
  `sign_Uatt_id` int(11) DEFAULT NULL,
  `issuingUsername` varchar(750) DEFAULT NULL,
  `regex` varchar(40) DEFAULT NULL,
  `creationTime` datetime NOT NULL,
  `expirationTime` datetime DEFAULT NULL,
  `r` blob,
  `s` blob,
  `flags` blob,
  `hashHeader` binary(2) DEFAULT NULL,
  `signedHash` blob,
  `hashMismatch` tinyint(4) DEFAULT '0',
  `keyExpirationTime` datetime DEFAULT NULL,
  `revocationCode` smallint(5) unsigned DEFAULT NULL,
  `revocationReason` varchar(500) DEFAULT NULL,
  `revocationSigId` int(10) unsigned DEFAULT NULL,
  `isRevocable` tinyint(4) NOT NULL DEFAULT '1',
  `isExportable` tinyint(1) NOT NULL,
  `isExpired` tinyint(4) NOT NULL DEFAULT '0',
  `isValid` tinyint(4) NOT NULL DEFAULT '0',
  `isRevoked` int(11) NOT NULL DEFAULT '0',
  `isRevocation` tinyint(4) NOT NULL DEFAULT '0',
  `is_analyzed` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `signedFingerprint` (`signedFingerprint`),
  UNIQUE KEY `Unique_index` (`issuingKeyId`,`signedKeyId`,`signedUsername`(255),`signedFingerprint`,`r`(255),`s`(255)),
  KEY `is_analyzed` (`is_analyzed`),
  KEY `isRevocation` (`isRevocation`),
  FOREIGN KEY `Signatures_Pubkey_binding` (`signedFingerprint`) REFERENCES `Pubkey` (`fingerprint`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table structure for table `SignatureStatus`
--

CREATE TABLE IF NOT EXISTS `SignatureStatus` (
  `signature_id` int(10) unsigned NOT NULL,
  `vulnerabilityCode` tinyint(4) NOT NULL,
  `vulnerabilityDescription` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`signature_id`,`vulnerabilityCode`),
  FOREIGN KEY `SignatureStatus_Signatures_binding` (`signature_id`) REFERENCES Signatures(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table structure for table `UserAttribute`
--

CREATE TABLE IF NOT EXISTS `UserAttribute` (
  `id` int(11) NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `name` varchar(750) CHARACTER SET utf8 NOT NULL,
  `encoding` int(11) DEFAULT NULL,
  `image` longblob,
  PRIMARY KEY (`id`,`fingerprint`,`name`(200)),
  KEY `fingerprint` (`fingerprint`,`name`(200),`image`(60)),
  FOREIGN KEY `UserAttribute_Pubkey_binding` (`fingerprint`) REFERENCES `Pubkey` (`fingerprint`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table structure for table `UserID`
--

CREATE TABLE IF NOT EXISTS `UserID` (
  `ownerkeyID` bigint(20) unsigned NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `name` varchar(750) NOT NULL,
  `is_analyze` tinyint(4) DEFAULT NULL,
  `bindingAuthentic` tinyint(4) NOT NULL,
  PRIMARY KEY (`fingerprint`,`name`(191)),
  FULLTEXT (`name`(191)),
  FOREIGN KEY `UserID_Pubkey_binding` (`fingerprint`) REFERENCES `Pubkey` (`fingerprint`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


--
-- Table structure for table `Unpacker_errors`
--

CREATE TABLE IF NOT EXISTS `Unpacker_errors` (
  `version` tinyint(3) unsigned NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `error` text COLLATE utf8mb4_unicode_ci NOT NULL,
  FOREIGN KEY `UnpackerErrors_Certificate_Binding` (`fingerprint`) REFERENCES `gpg_keyserver` (`fingerprint`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table structure for table `blocklist`
--

CREATE TABLE IF NOT EXISTS `blocklist` (
  `ID` bigint(20) unsigned NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- View structure for `revocationSignatures`
--

CREATE OR REPLACE VIEW `revocationSignatures` (`issuingKeyId`,`signedFingerprint`, `signedUsername`) AS
 SELECT issuingKeyId, signedFingerprint, signedUsername
 FROM Signatures
 WHERE isRevocation = 1;

--
-- Table structure for table `selfSignaturesMetadata`
--

CREATE TABLE IF NOT EXISTS `selfSignaturesMetadata` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `type` smallint(5) unsigned NOT NULL,
  `pubAlgorithm` smallint(5) unsigned NOT NULL,
  `hashAlgorithm` smallint(5) unsigned NOT NULL,
  `version` smallint(5) unsigned NOT NULL,
  `issuingKeyId` bigint(20) unsigned NOT NULL,
  `issuingFingerprint` binary(20) NOT NULL,
  `preferedHash` blob,
  `preferedCompression` blob,
  `preferedSymmetric` blob,
  `trustLevel` smallint(5) unsigned DEFAULT NULL,
  `keyExpirationTime` datetime DEFAULT NULL,
  `isPrimaryUserId` tinyint(1) NOT NULL,
  `signedUserId` varchar(750) DEFAULT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY `selfSignaturesMetadata_Pubkey_binding` (`issuingKeyId`) REFERENCES `Pubkey` (`keyId`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `ptree` (
  `node_key` BLOB NOT NULL,
  `key_size` INT NOT NULL,
  `node_svalues` BLOB NOT NULL,
  `num_elements` INT NOT NULL,
  `leaf` TINYINT(1) NOT NULL,
  `node_elements` BLOB NOT NULL,
  PRIMARY KEY (`node_key`(767), `key_size`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `stash` (
    `name` VARCHAR(255) NOT NULL,
    `value` TEXT NOT NULL,
    `created` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 
-- CREATE TRIGGER update_issuing_fingerprint
-- AFTER INSERT ON Pubkey
-- FOR EACH ROW
-- BEGIN
-- UPDATE Signatures
-- SET issuingFingerprint = new.fingerprint
-- WHERE issuingKeyId = new.KeyId and isnull(issuingFingerprint);
-- END;;
-- 
-- 
-- CREATE TRIGGER `update_issuing_username`
-- AFTER INSERT ON UserID
-- FOR EACH ROW
-- BEGIN
-- UPDATE Signatures
-- SET issuingUsername = new.name
-- WHERE issuingFingerprint = new.fingerprint and isnull(issuingUsername);
-- END;;

-- CREATE TRIGGER `update_revoked_1`
-- AFTER INSERT ON Signatures
-- FOR EACH ROW
-- BEGIN
-- IF new.isRevocation = 1 THEN
-- BEGIN
-- INSERT IGNORE INTO revocationSignatures VALUES (new.issuingKeyID, new.signedFingerprint, new.signedUsername);
-- END; END IF;
-- END;;

-- CREATE TRIGGER `update_revoked_2`
-- AFTER INSERT ON Signatures
-- FOR EACH ROW
-- BEGIN
--     UPDATE Signatures JOIN revocationSignatures on (
--         Signatures.issuingKeyId = revocationSignatures.issuingKeyId and 
--         Signatures.signedFingerprint = revocationSignatures.signedFingerprint and 
--         Signatures.signedUsername = revocationSignatures.signedUsername
--     ) set isRevoked = 1, isValid = -1 where isRevoked = 0 and isRevocation = 0;
-- END;;
-- 
-- 
CREATE EVENT `update_validity` ON SCHEDULE EVERY 1 DAY
COMMENT 'update isExpired,isValid,isRevoked attribute on Signatures'
DO BEGIN
    UPDATE Signatures SET isExpired = 1, isValid = -1 WHERE expirationTime < NOW() AND isExpired != 1;
    UPDATE Signatures SET isValid = -1 WHERE isValid != -1 AND isRevoked = 1;
    UPDATE Signatures INNER JOIN revocationSignatures on (Signatures.issuingKeyId = revocationSignatures.issuingKeyId and Signatures.signedFingerprint = revocationSignatures.signedFingerprint and Signatures.signedUsername = revocationSignatures.signedUsername) SET isRevoked = 1, isValid = -1 WHERE isRevoked = 0 AND isRevocation = 0;
END
