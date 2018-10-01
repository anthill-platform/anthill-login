CREATE TABLE `account_access` (
  `account_id` int(11) unsigned NOT NULL,
  `gamespace_id` int(11) unsigned NOT NULL DEFAULT '0',
  `scopes` varchar(512) DEFAULT NULL,
  KEY `gamespace_id` (`gamespace_id`),
  KEY `account_id` (`account_id`),
  CONSTRAINT `account_access_ibfk_1` FOREIGN KEY (`gamespace_id`) REFERENCES `gamespace` (`gamespace_id`),
  CONSTRAINT `account_access_ibfk_2` FOREIGN KEY (`account_id`) REFERENCES `accounts` (`account_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;