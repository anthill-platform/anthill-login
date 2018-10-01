CREATE TABLE `gamespace` (
  `gamespace_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `gamespace_scopes` varchar(512) NOT NULL DEFAULT '',
  `gamespace_title` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`gamespace_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;