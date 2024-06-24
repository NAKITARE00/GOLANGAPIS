CREATE TABLE IF NOT EXISTS answers{
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    nin INT UNSIGNED NOT NULL,
    answer VARCHAR(255) NOT NULL,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, 

    PRIMARY KEY (id),
    UNIQUE KEY (answer)
}

--Adding index for columns that maybe frequently queried
CREATE INDEX idx_answers_answer ON answers (answer);
CREATE INDEX idx_answers_nin ON answers (nin);

--Adding index for columns that are frequently updated
CREATE INDEX idx_answers_createdAt ON answers (createdAt);