-- confirm is empty once an email address has been confirmed, and otherwise is the confirmation key
-- status
--    initializes to 0
--    is set to 1 after a public key with (confirm='', status=0) has been imported
--    is set to 2 if a key should be deleted (will be deleted based on email address)
-- publickey is the ASCII-armored PGP public key; can be cleared to save space if status > 0
CREATE TABLE gpgmw_keys (id INT NOT NULL PRIMARY KEY AUTO_INCREMENT, email VARCHAR(256), publickey TEXT, confirm VARCHAR(32), status INT NOT NULL DEFAULT 0, time TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

-- see include/lock.php for documentation
CREATE TABLE gpgmw_locks (id INT NOT NULL PRIMARY KEY AUTO_INCREMENT, ip VARCHAR(16), time INT, action VARCHAR(16), num INT);
