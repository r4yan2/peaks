-- phpMyAdmin SQL Dump
-- version 4.7.8
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generation Time: Mar 13, 2018 at 03:43 PM
-- Server version: 5.7.21
-- PHP Version: 7.2.3

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `gpg_keyserver`
--

-- --------------------------------------------------------

--
-- Table structure for table `broken_keys`
--

DROP TABLE IF EXISTS `broken_keys`;
CREATE TABLE `broken_keys` (
  `id` int(11) NOT NULL,
  `certificate` longblob,
  `log` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `gpg_keyserver`
--

DROP TABLE IF EXISTS `gpg_keyserver`;
CREATE TABLE `gpg_keyserver` (
  `version` tinyint(3) UNSIGNED NOT NULL,
  `ID` bigint(20) UNSIGNED NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `certificate` longblob,
  `hash` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `is_unpacked` tinyint(4) NOT NULL DEFAULT '0',
  `is_synchronized` tinyint(4) NOT NULL DEFAULT '0',
  `error_code` int(11) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggers `gpg_keyserver`
--
DROP TRIGGER IF EXISTS `save_hash`;
DELIMITER $$
CREATE TRIGGER `save_hash` AFTER UPDATE ON `gpg_keyserver` FOR EACH ROW IF (OLD.is_synchronized = 1 and OLD.hash != NEW.hash) THEN
            INSERT IGNORE INTO removed_hash VALUES(OLD.hash);
      END IF
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `KeyStatus`
--

DROP TABLE IF EXISTS `KeyStatus`;
CREATE TABLE `KeyStatus` (
  `version` tinyint(3) UNSIGNED NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `vulnerabilityCode` tinyint(4) NOT NULL,
  `vulnerabilityDescription` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Stand-in structure for view `key_primary_userID`
-- (See below for the actual view)
--
DROP VIEW IF EXISTS `key_primary_userID`;
CREATE TABLE `key_primary_userID` (
`version` smallint(5) unsigned
,`fingerprint` binary(20)
,`name` varchar(750)
,`isPrimaryUserId` tinyint(1)
,`trustLevel` smallint(5) unsigned
);

-- --------------------------------------------------------

--
-- Table structure for table `Pubkey`
--

DROP TABLE IF EXISTS `Pubkey`;
CREATE TABLE `Pubkey` (
  `keyId` bigint(20) UNSIGNED NOT NULL,
  `version` tinyint(3) UNSIGNED NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `PriFingerprint` binary(20) DEFAULT NULL,
  `pubAlgorithm` smallint(5) UNSIGNED NOT NULL,
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
  `sccIndex` int(10) UNSIGNED DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `removed_hash`
--

DROP TABLE IF EXISTS `removed_hash`;
CREATE TABLE `removed_hash` (
  `hash` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `selfSignaturesMetadata`
--

DROP TABLE IF EXISTS `selfSignaturesMetadata`;
CREATE TABLE `selfSignaturesMetadata` (
  `id` int(10) UNSIGNED NOT NULL,
  `type` smallint(5) UNSIGNED NOT NULL,
  `pubAlgorithm` smallint(5) UNSIGNED NOT NULL,
  `hashAlgorithm` smallint(5) UNSIGNED NOT NULL,
  `version` smallint(5) UNSIGNED NOT NULL,
  `issuingKeyId` bigint(20) UNSIGNED NOT NULL,
  `issuingFingerprint` binary(20) NOT NULL,
  `preferedHash` blob,
  `preferedCompression` blob,
  `preferedSymmetric` blob,
  `trustLevel` smallint(5) UNSIGNED DEFAULT NULL,
  `keyExpirationTime` datetime DEFAULT NULL,
  `isPrimaryUserId` tinyint(1) NOT NULL,
  `signedUserId` varchar(750) CHARACTER SET utf8 DEFAULT NULL,
  `userRole` varchar(40) COLLATE utf8mb4_unicode_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `Signatures`
--

DROP TABLE IF EXISTS `Signatures`;
CREATE TABLE `Signatures` (
  `id` int(10) UNSIGNED NOT NULL,
  `type` smallint(5) UNSIGNED NOT NULL,
  `pubAlgorithm` smallint(5) UNSIGNED NOT NULL,
  `hashAlgorithm` smallint(5) UNSIGNED NOT NULL,
  `version` smallint(5) UNSIGNED NOT NULL,
  `issuingKeyId` bigint(20) UNSIGNED NOT NULL,
  `signedKeyId` bigint(20) UNSIGNED NOT NULL,
  `issuingFingerprint` binary(20) DEFAULT NULL,
  `signedFingerprint` binary(20) NOT NULL,
  `signedUsername` varchar(750) CHARACTER SET utf8 DEFAULT NULL,
  `sign_Uatt_id` int(11) DEFAULT NULL,
  `issuingUsername` varchar(750) CHARACTER SET utf8 DEFAULT NULL,
  `regex` varchar(40) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `creationTime` datetime NOT NULL,
  `expirationTime` datetime DEFAULT NULL,
  `r` blob,
  `s` blob,
  `flags` blob,
  `hashHeader` binary(2) DEFAULT NULL,
  `signedHash` blob,
  `hashMismatch` tinyint(4) DEFAULT '0',
  `keyExpirationTime` datetime DEFAULT NULL,
  `revocationCode` smallint(5) UNSIGNED DEFAULT NULL,
  `revocationReason` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `revocationSigId` int(10) UNSIGNED DEFAULT NULL,
  `isRevocable` tinyint(4) NOT NULL DEFAULT '1',
  `isExportable` tinyint(1) NOT NULL,
  `isExpired` tinyint(4) NOT NULL DEFAULT '0',
  `isValid` tinyint(4) NOT NULL DEFAULT '0',
  `isRevocation` tinyint(4) NOT NULL DEFAULT '0',
  `is_analyzed` tinyint(3) UNSIGNED NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `SignatureStatus`
--

DROP TABLE IF EXISTS `SignatureStatus`;
CREATE TABLE `SignatureStatus` (
  `signature_id` int(10) UNSIGNED NOT NULL,
  `vulnerabilityCode` tinyint(4) NOT NULL,
  `vulnerabilityDescription` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Stand-in structure for view `Signature_no_issuing_fp`
-- (See below for the actual view)
--
DROP VIEW IF EXISTS `Signature_no_issuing_fp`;
CREATE TABLE `Signature_no_issuing_fp` (
`id` int(10) unsigned
,`fp` binary(20)
);

-- --------------------------------------------------------

--
-- Table structure for table `Unpacker_errors`
--

DROP TABLE IF EXISTS `Unpacker_errors`;
CREATE TABLE `Unpacker_errors` (
  `idx` int(11) NOT NULL,
  `version` tinyint(3) UNSIGNED NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `error` text COLLATE utf8mb4_unicode_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `UserAttribute`
--

DROP TABLE IF EXISTS `UserAttribute`;
CREATE TABLE `UserAttribute` (
  `id` int(11) NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `name` varchar(750) CHARACTER SET utf8 NOT NULL,
  `encoding` int(11) DEFAULT NULL,
  `image` longblob
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `UserID`
--

DROP TABLE IF EXISTS `UserID`;
CREATE TABLE `UserID` (
  `ownerkeyID` bigint(20) UNSIGNED NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `name` varchar(750) CHARACTER SET utf8 NOT NULL,
  `email` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_analyze` tinyint(4) DEFAULT NULL,
  `bindingAuthentic` tinyint(4) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Structure for view `key_primary_userID`
--
DROP TABLE IF EXISTS `key_primary_userID`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `key_primary_userID`  AS  (select `selfSignaturesMetadata`.`version` AS `version`,`selfSignaturesMetadata`.`issuingFingerprint` AS `fingerprint`,`selfSignaturesMetadata`.`signedUserId` AS `name`,`selfSignaturesMetadata`.`isPrimaryUserId` AS `isPrimaryUserId`,`selfSignaturesMetadata`.`trustLevel` AS `trustLevel` from `selfSignaturesMetadata` group by `selfSignaturesMetadata`.`version`,`selfSignaturesMetadata`.`issuingFingerprint` order by `selfSignaturesMetadata`.`isPrimaryUserId` desc,`selfSignaturesMetadata`.`trustLevel` desc) ;

-- --------------------------------------------------------

--
-- Structure for view `Signature_no_issuing_fp`
--
DROP TABLE IF EXISTS `Signature_no_issuing_fp`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `Signature_no_issuing_fp`  AS  (select `Signatures`.`id` AS `id`,`Pubkey`.`fingerprint` AS `fp` from (`Signatures` join `Pubkey` on((`Signatures`.`issuingKeyId` = `Pubkey`.`keyId`))) where (`Signatures`.`issuingFingerprint` = NULL)) ;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `broken_keys`
--
ALTER TABLE `broken_keys`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `gpg_keyserver`
--
ALTER TABLE `gpg_keyserver`
  ADD PRIMARY KEY (`version`,`fingerprint`),
  ADD KEY `ID` (`ID`,`fingerprint`) USING BTREE;

--
-- Indexes for table `KeyStatus`
--
ALTER TABLE `KeyStatus`
  ADD PRIMARY KEY (`version`,`fingerprint`,`vulnerabilityCode`);

--
-- Indexes for table `Pubkey`
--
ALTER TABLE `Pubkey`
  ADD PRIMARY KEY (`version`,`fingerprint`),
  ADD KEY `n` (`n`(1024)),
  ADD KEY `p` (`p`(1024)),
  ADD KEY `q` (`q`(1024)),
  ADD KEY `y` (`y`(1024)),
  ADD KEY `sccIndex` (`sccIndex`),
  ADD KEY `keyId` (`keyId`,`fingerprint`) USING BTREE,
  ADD KEY `fingerprint` (`fingerprint`),
  ADD KEY `Pubkey_cert` (`version`,`PriFingerprint`);

--
-- Indexes for table `removed_hash`
--
ALTER TABLE `removed_hash`
  ADD PRIMARY KEY (`hash`);

--
-- Indexes for table `selfSignaturesMetadata`
--
ALTER TABLE `selfSignaturesMetadata`
  ADD PRIMARY KEY (`id`),
  ADD KEY `type` (`type`),
  ADD KEY `hashAlgorithm` (`hashAlgorithm`),
  ADD KEY `issuingKey` (`issuingKeyId`,`issuingFingerprint`) USING BTREE,
  ADD KEY `issuingFingerprint` (`issuingFingerprint`,`signedUserId`),
  ADD KEY `signedUserId` (`signedUserId`),
  ADD KEY `version` (`version`,`issuingFingerprint`,`trustLevel`,`isPrimaryUserId`);

--
-- Indexes for table `Signatures`
--
ALTER TABLE `Signatures`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `r_2` (`r`(1024),`s`(1024)) USING BTREE,
  ADD KEY `type` (`type`),
  ADD KEY `hashAlgorithm` (`hashAlgorithm`),
  ADD KEY `issuingKeyId` (`issuingKeyId`),
  ADD KEY `signedKeyId` (`signedKeyId`),
  ADD KEY `issuingFingerprint` (`issuingFingerprint`),
  ADD KEY `signedFingerprint` (`signedFingerprint`),
  ADD KEY `r` (`r`(1024)),
  ADD KEY `s` (`s`(1024)),
  ADD KEY `Unique_index` (`issuingKeyId`,`signedKeyId`,`signedUsername`,`creationTime`) USING BTREE,
  ADD KEY `version` (`version`),
  ADD KEY `signed_key` (`signedKeyId`,`signedFingerprint`),
  ADD KEY `issuing_key` (`issuingKeyId`,`issuingFingerprint`),
  ADD KEY `issuing_uid` (`issuingUsername`),
  ADD KEY `signed_uid` (`signedUsername`),
  ADD KEY `sign_Uatt_id` (`sign_Uatt_id`,`signedFingerprint`) USING BTREE;

--
-- Indexes for table `SignatureStatus`
--
ALTER TABLE `SignatureStatus`
  ADD PRIMARY KEY (`signature_id`,`vulnerabilityCode`);

--
-- Indexes for table `Unpacker_errors`
--
ALTER TABLE `Unpacker_errors`
  ADD PRIMARY KEY (`idx`),
  ADD KEY `external key` (`version`,`fingerprint`) USING BTREE;

--
-- Indexes for table `UserAttribute`
--
ALTER TABLE `UserAttribute`
  ADD PRIMARY KEY (`id`,`fingerprint`,`name`),
  ADD UNIQUE KEY `fingerprint` (`fingerprint`(10),`name`,`image`(60)) USING BTREE,
  ADD KEY `userID` (`fingerprint`,`name`);

--
-- Indexes for table `UserID`
--
ALTER TABLE `UserID`
  ADD PRIMARY KEY (`fingerprint`,`name`) USING BTREE,
  ADD KEY `ownerkeyID` (`ownerkeyID`,`fingerprint`),
  ADD KEY `name` (`name`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `broken_keys`
--
ALTER TABLE `broken_keys`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `selfSignaturesMetadata`
--
ALTER TABLE `selfSignaturesMetadata`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=93;

--
-- AUTO_INCREMENT for table `Signatures`
--
ALTER TABLE `Signatures`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=221;

--
-- AUTO_INCREMENT for table `Unpacker_errors`
--
ALTER TABLE `Unpacker_errors`
  MODIFY `idx` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `KeyStatus`
--
ALTER TABLE `KeyStatus`
  ADD CONSTRAINT `vuln_key` FOREIGN KEY (`version`,`fingerprint`) REFERENCES `Pubkey` (`version`, `fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION;

--
-- Constraints for table `Pubkey`
--
ALTER TABLE `Pubkey`
  ADD CONSTRAINT `Pubkey_cert` FOREIGN KEY (`version`,`PriFingerprint`) REFERENCES `gpg_keyserver` (`version`, `fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION;

--
-- Constraints for table `selfSignaturesMetadata`
--
ALTER TABLE `selfSignaturesMetadata`
  ADD CONSTRAINT `SelfSign_key` FOREIGN KEY (`issuingKeyId`,`issuingFingerprint`) REFERENCES `Pubkey` (`keyId`, `fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION,
  ADD CONSTRAINT `SelfSign_userID` FOREIGN KEY (`signedUserId`) REFERENCES `UserID` (`name`);

--
-- Constraints for table `Signatures`
--
ALTER TABLE `Signatures`
  ADD CONSTRAINT `issuing_key` FOREIGN KEY (`issuingKeyId`,`issuingFingerprint`) REFERENCES `Pubkey` (`keyId`, `fingerprint`) ON DELETE CASCADE,
  ADD CONSTRAINT `issuing_uid` FOREIGN KEY (`issuingUsername`) REFERENCES `UserID` (`name`),
  ADD CONSTRAINT `signed_key` FOREIGN KEY (`signedKeyId`,`signedFingerprint`) REFERENCES `Pubkey` (`keyId`, `fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION,
  ADD CONSTRAINT `signed_uatt` FOREIGN KEY (`sign_Uatt_id`,`signedFingerprint`) REFERENCES `UserAttribute` (`id`, `fingerprint`),
  ADD CONSTRAINT `signed_uid` FOREIGN KEY (`signedUsername`) REFERENCES `UserID` (`name`);

--
-- Constraints for table `SignatureStatus`
--
ALTER TABLE `SignatureStatus`
  ADD CONSTRAINT `vuln_signature` FOREIGN KEY (`signature_id`) REFERENCES `Signatures` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION;

--
-- Constraints for table `Unpacker_errors`
--
ALTER TABLE `Unpacker_errors`
  ADD CONSTRAINT `error_certificate` FOREIGN KEY (`version`,`fingerprint`) REFERENCES `gpg_keyserver` (`version`, `fingerprint`);

--
-- Constraints for table `UserAttribute`
--
ALTER TABLE `UserAttribute`
  ADD CONSTRAINT `userID` FOREIGN KEY (`fingerprint`,`name`) REFERENCES `UserID` (`fingerprint`, `name`) ON UPDATE NO ACTION;

--
-- Constraints for table `UserID`
--
ALTER TABLE `UserID`
  ADD CONSTRAINT `uid_key` FOREIGN KEY (`ownerkeyID`,`fingerprint`) REFERENCES `gpg_keyserver` (`ID`, `fingerprint`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;

