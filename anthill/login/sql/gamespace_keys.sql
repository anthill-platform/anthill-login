CREATE TABLE `gamespace_keys` (
  `key_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `gamespace_id` int(11) unsigned NOT NULL,
  `key_name` varchar(255) NOT NULL DEFAULT '',
  `key_data` text NOT NULL,
  PRIMARY KEY (`key_id`),
  KEY `gamespace_id` (`gamespace_id`),
  CONSTRAINT `gamespace_keys_ibfk_1` FOREIGN KEY (`gamespace_id`) REFERENCES `gamespace` (`gamespace_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;