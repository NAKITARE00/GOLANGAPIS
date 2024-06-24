CREATE TABLE IF NOT EXISTS questions{
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    nin INT UNSIGNED NOT NULL,
    question VARCHAR(255) NOT NULL,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, 
    PRIMARY KEY (id),
    UNIQUE KEY (question)
}

--Adding index for columns that maybe frequently queried
CREATE INDEX idx_questions_nin ON questions (nin);
CREATE INDEX idx_questions_question ON questions (question);

--Adding index for columns that are frequently updated
CREATE INDEX idx_questions_createdAt ON questions (createdAt);