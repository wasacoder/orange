
# Dump of table encrypt
# ------------------------------------------------------------

DROP TABLE IF EXISTS `encrypt`;

CREATE TABLE `encrypt` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `key` varchar(255) NOT NULL DEFAULT '',
  `value` varchar(2000) NOT NULL DEFAULT '',
  `type` varchar(11) DEFAULT '0',
  `op_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_key` (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

LOCK TABLES `encrypt` WRITE;
/*!40000 ALTER TABLE `encrypt` DISABLE KEYS */;

INSERT INTO `encrypt` (`id`, `key`, `value`, `type`, `op_time`)
VALUES
    (1,'1','{}','meta','2016-11-11 11:11:11');

/*!40000 ALTER TABLE `encrypt` ENABLE KEYS */;
UNLOCK TABLES;
