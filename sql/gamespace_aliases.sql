CREATE TABLE `gamespace_aliases` (
  `record_id` int(11) NOT NULL AUTO_INCREMENT,
  `gamespace_name` varchar(64) CHARACTER SET utf8 NOT NULL DEFAULT '',
  `gamespace_id` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`record_id`),
  UNIQUE KEY `gamespace_name` (`gamespace_name`),
  KEY `gamespace_id` (`gamespace_id`),
  CONSTRAINT `gamespace_aliases_ibfk_1` FOREIGN KEY (`gamespace_id`) REFERENCES `gamespace` (`gamespace_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
