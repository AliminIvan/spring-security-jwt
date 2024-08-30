CREATE TABLE users
(
    id       UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email    VARCHAR(255) NOT NULL UNIQUE,
    role     VARCHAR(50)  NOT NULL,
    failed_attempts INT DEFAULT 0 NOT NULL,
    account_locked_until TIMESTAMP NULL
);

