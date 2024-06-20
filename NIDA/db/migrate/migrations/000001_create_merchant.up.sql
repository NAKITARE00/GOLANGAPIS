CREATE TABLE IF NOT EXISTS merchants (
   `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
   `firstName` VARCHAR(255) NOT NULL,
   `lastName` VARCHAR(255) NOT NULL,
   `telephone` VARCHAR(255) NOT NULL,
   `NIN`      INT UNSIGNED NOT NULL,
   `email` VARCHAR(255) NOT NULL,
   `status` ENUM('active', 'inactive') NOT NULL DEFAULT 'inactive',
   `verification_attempts` INT UNSIGNED NOT NULL AUTO_INCREMENT,
   `createdAt` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  PRIMARY KEY (id),
  UNIQUE KEY (email)
)

--Adding index for columns that maybe frequently queried
CREATE INDEX idx_merchant_firstName ON merchants (firstName);
CREATE INDEX idx_merchant_lastName ON merchants (lastName);
CREATE INDEX idx_merchant_telephone ON merchants (telephone);
CREATE INDEX idx_merchant_NIN ON merchants (NIN);
CREATE INDEX idx_merchant_email ON merchants (email);

--Adding index for columns that are frequently updated
CREATE INDEX idx_merchant_createdAt ON merchants (createdAt);