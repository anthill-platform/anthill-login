CREATE TABLE `credential_passwords` (
  `credential` varchar(128) NOT NULL,
  `algorithm` varchar(16) NOT NULL DEFAULT 'SHA256',
  `password` varchar(128) NOT NULL,
  PRIMARY KEY (`credential`,`password`),
  UNIQUE KEY `credential_UNIQUE` (`credential`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;