-- MySQL dump 10.13  Distrib 5.6.39, for Linux (x86_64)
--
-- Host: localhost    Database: gpg_keyserver
-- ------------------------------------------------------
-- Server version	5.6.39-log

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `gpg_keyserver`
--

SET GLOBAL sql_mode=(SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY',''));

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `gpg_keyserver` /*!40100 DEFAULT CHARACTER SET utf8 */;

USE `gpg_keyserver`;

--
-- Table structure for table `KeyStatus`
--

DROP TABLE IF EXISTS `KeyStatus`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `KeyStatus` (
  `version` tinyint(3) unsigned NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `vulnerabilityCode` tinyint(4) NOT NULL,
  `vulnerabilityDescription` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`version`,`fingerprint`,`vulnerabilityCode`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Pubkey`
--

DROP TABLE IF EXISTS `Pubkey`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Pubkey` (
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
  `sccIndex` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`version`,`fingerprint`),
  KEY `n` (`n`(200)),
  KEY `p` (`p`(200)),
  KEY `q` (`q`(200)),
  KEY `y` (`y`(200)),
  KEY `sccIndex` (`sccIndex`),
  KEY `keyId` (`keyId`,`fingerprint`) USING BTREE,
  KEY `fingerprint` (`fingerprint`),
  KEY `Pubkey_cert` (`version`,`PriFingerprint`),
  KEY `is_analyzed` (`is_analyzed`),
  KEY `is_analyzed_2` (`is_analyzed`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SignatureStatus`
--

DROP TABLE IF EXISTS `SignatureStatus`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SignatureStatus` (
  `signature_id` int(10) unsigned NOT NULL,
  `vulnerabilityCode` tinyint(4) NOT NULL,
  `vulnerabilityDescription` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`signature_id`,`vulnerabilityCode`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Temporary table structure for view `Signature_no_issuing_fp`
--

DROP TABLE IF EXISTS `Signature_no_issuing_fp`;
/*!50001 DROP VIEW IF EXISTS `Signature_no_issuing_fp`*/;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
/*!50001 CREATE VIEW `Signature_no_issuing_fp` AS SELECT 
 1 AS `id`,
 1 AS `fp`*/;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `Signatures`
--

DROP TABLE IF EXISTS `Signatures`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Signatures` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `type` smallint(5) unsigned NOT NULL,
  `pubAlgorithm` smallint(5) unsigned NOT NULL,
  `hashAlgorithm` smallint(5) unsigned NOT NULL,
  `version` smallint(5) unsigned NOT NULL,
  `issuingKeyId` bigint(20) unsigned NOT NULL,
  `signedKeyId` bigint(20) unsigned NOT NULL,
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
  `revocationCode` smallint(5) unsigned DEFAULT NULL,
  `revocationReason` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `revocationSigId` int(10) unsigned DEFAULT NULL,
  `isRevocable` tinyint(4) NOT NULL DEFAULT '1',
  `isExportable` tinyint(1) NOT NULL,
  `isExpired` tinyint(4) NOT NULL DEFAULT '0',
  `isValid` tinyint(4) NOT NULL DEFAULT '0',
  `isRevoked` int(11) NOT NULL DEFAULT '0',
  `isRevocation` tinyint(4) NOT NULL DEFAULT '0',
  `is_analyzed` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `r_2` (`r`(200),`s`(200)) USING BTREE,
  KEY `type` (`type`),
  KEY `hashAlgorithm` (`hashAlgorithm`),
  KEY `issuingKeyId` (`issuingKeyId`),
  KEY `signedKeyId` (`signedKeyId`),
  KEY `issuingFingerprint` (`issuingFingerprint`),
  KEY `signedFingerprint` (`signedFingerprint`),
  KEY `r` (`r`(200)),
  KEY `s` (`s`(200)),
  KEY `Unique_index` (`issuingKeyId`,`signedKeyId`,`signedUsername`(255),`creationTime`) USING BTREE,
  KEY `version` (`version`),
  KEY `signed_key` (`signedKeyId`,`signedFingerprint`),
  KEY `issuing_key` (`issuingKeyId`,`issuingFingerprint`),
  KEY `issuing_uid` (`issuingUsername`(255)),
  KEY `signed_uid` (`signedUsername`(255)),
  KEY `sign_Uatt_id` (`sign_Uatt_id`,`signedFingerprint`) USING BTREE,
  KEY `is_analyzed` (`is_analyzed`),
  KEY `isRevocation` (`isRevocation`),
  KEY `hashMismatch` (`hashMismatch`),
  KEY `find_revok` (`issuingKeyId`,`signedKeyId`,`issuingFingerprint`,`signedFingerprint`,`signedUsername`(255)),
  KEY `creationTime` (`creationTime`)
) ENGINE=InnoDB AUTO_INCREMENT=18141142 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Unpacker_errors`
--

DROP TABLE IF EXISTS `Unpacker_errors`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Unpacker_errors` (
  `version` tinyint(3) unsigned NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `error` text COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`version`,`fingerprint`)
) ENGINE=InnoDB AUTO_INCREMENT=327309 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `UserAttribute`
--

DROP TABLE IF EXISTS `UserAttribute`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `UserAttribute` (
  `id` int(11) NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `name` varchar(750) CHARACTER SET utf8 NOT NULL,
  `encoding` int(11) DEFAULT NULL,
  `image` longblob,
  PRIMARY KEY (`id`,`fingerprint`,`name`(200)),
  UNIQUE KEY `fingerprint` (`fingerprint`(10),`name`(200),`image`(60)) USING BTREE,
  KEY `userID` (`fingerprint`,`name`(200))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `UserID`
--

DROP TABLE IF EXISTS `UserID`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `UserID` (
  `ownerkeyID` bigint(20) unsigned NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `name` varchar(750) NOT NULL,
  `is_analyze` tinyint(4) DEFAULT NULL,
  `bindingAuthentic` tinyint(4) NOT NULL,
  PRIMARY KEY (`fingerprint`,`name`(200)) USING BTREE,
  KEY `ownerkeyID` (`ownerkeyID`,`fingerprint`),
  FULLTEXT (`name`))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `broken_keys`
--

DROP TABLE IF EXISTS `broken_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `broken_keys` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `certificate` longblob,
  `log` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=11366 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `gpg_keyserver`
--

DROP TABLE IF EXISTS `gpg_keyserver`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `gpg_keyserver` (
  `version` tinyint(3) unsigned NOT NULL,
  `ID` bigint(20) unsigned NOT NULL,
  `fingerprint` binary(20) NOT NULL,
  `certificate` longblob,
  `hash` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `is_unpacked` tinyint(4) NOT NULL DEFAULT '0',
  `is_synchronized` tinyint(4) NOT NULL DEFAULT '0',
  `error_code` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`version`,`fingerprint`),
  KEY `ID` (`ID`,`fingerprint`) USING BTREE,
  KEY `HASH` (`hash` ASC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'NO_AUTO_VALUE_ON_ZERO' */ ;
/*!50003 CREATE TRIGGER `save_hash` AFTER DELETE ON `gpg_keyserver` FOR EACH ROW INSERT IGNORE INTO removed_hash VALUES(OLD.hash) */ ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;

--
-- Temporary table structure for view `key_primary_userID`
--

DROP TABLE IF EXISTS `key_primary_userID`;
/*!50001 DROP VIEW IF EXISTS `key_primary_userID`*/;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
/*!50001 CREATE VIEW `key_primary_userID` AS SELECT 
 1 AS `version`,
 1 AS `fingerprint`,
 1 AS `name`,
 1 AS `isPrimaryUserId`,
 1 AS `trustLevel`*/;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `removed_hash`
--

DROP TABLE IF EXISTS `removed_hash`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `removed_hash` (
  `hash` varchar(255) NOT NULL,
  PRIMARY KEY (`hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `revocationSignatures`
--

DROP TABLE IF EXISTS `revocationSignatures`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `revocationSignatures` (
  `issuingKeyId` bigint(20) unsigned NOT NULL DEFAULT '0',
  `signedFingerprint` binary(20) NOT NULL DEFAULT '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
  `signedUsername` varchar(750) NOT NULL DEFAULT '',
  PRIMARY KEY (`issuingKeyId`,`signedFingerprint`,`signedUsername`(250))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `selfSignaturesMetadata`
--

DROP TABLE IF EXISTS `selfSignaturesMetadata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `selfSignaturesMetadata` (
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
  `signedUserId` varchar(750) CHARACTER SET utf8 DEFAULT NULL,
  `userRole` varchar(40) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `type` (`type`),
  KEY `hashAlgorithm` (`hashAlgorithm`),
  KEY `issuingKey` (`issuingKeyId`,`issuingFingerprint`) USING BTREE,
  KEY `issuingFingerprint` (`issuingFingerprint`,`signedUserId`(255)),
  KEY `signedUserId` (`signedUserId`(255)),
  KEY `version` (`version`,`issuingFingerprint`,`trustLevel`,`isPrimaryUserId`)
) ENGINE=InnoDB AUTO_INCREMENT=10701766 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

DROP TABLE IF EXISTS `ptree`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ptree` (
  `node_key` VARCHAR(200) NOT NULL,
  `node_svalues` BLOB NOT NULL,
  `num_elements` INT NOT NULL,
  `leaf` TINYINT(1) NOT NULL,
  `node_elements` BLOB NOT NULL,
  PRIMARY KEY (`node_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping routines for database 'gpg_keyserver'
--

--
-- Current Database: `gpg_keyserver`
--

USE `gpg_keyserver`;

--
-- Final view structure for view `Signature_no_issuing_fp`
--

/*!50001 DROP VIEW IF EXISTS `Signature_no_issuing_fp`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8 */;
/*!50001 SET character_set_results     = utf8 */;
/*!50001 SET collation_connection      = utf8_general_ci */;
/*!50001 CREATE VIEW `Signature_no_issuing_fp` AS (select `Signatures`.`id` AS `id`,`Pubkey`.`fingerprint` AS `fp` from (`Signatures` join `Pubkey` on((`Signatures`.`issuingKeyId` = `Pubkey`.`keyId`))) where isnull(`Signatures`.`issuingFingerprint`)) */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;

--
-- Final view structure for view `key_primary_userID`
--

/*!50001 DROP VIEW IF EXISTS `key_primary_userID`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb4 */;
/*!50001 SET character_set_results     = utf8mb4 */;
/*!50001 SET collation_connection      = utf8mb4_general_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED VIEW `key_primary_userID` AS (select `selfSignaturesMetadata`.`version` AS `version`,`selfSignaturesMetadata`.`issuingFingerprint` AS `fingerprint`,`selfSignaturesMetadata`.`signedUserId` AS `name`,`selfSignaturesMetadata`.`isPrimaryUserId` AS `isPrimaryUserId`,`selfSignaturesMetadata`.`trustLevel` AS `trustLevel` from `selfSignaturesMetadata` group by `selfSignaturesMetadata`.`version`,`selfSignaturesMetadata`.`issuingFingerprint` order by `selfSignaturesMetadata`.`isPrimaryUserId` desc,`selfSignaturesMetadata`.`trustLevel` desc) */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;


/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-04-24 11:54:22
