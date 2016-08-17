CREATE TABLE `account_credentials` (
  `credential` varchar(255) NOT NULL,
  `account_id` int(11) unsigned NOT NULL,
  PRIMARY KEY (`credential`,`account_id`),
  KEY `account_id` (`account_id`),
  CONSTRAINT `account_credentials_ibfk_1` FOREIGN KEY (`account_id`) REFERENCES `accounts` (`account_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
