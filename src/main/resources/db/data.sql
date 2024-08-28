INSERT INTO users (id, username, password)
VALUES ('7a7d2b6a-667d-448b-ac97-c9fbe5fd0592', 'admin', 'adminpassword'),
       ('9bdcacb7-6267-4e07-b5f1-0580e786bcfa', 'user1', 'user1password'),
       ('2ff786c1-ac2a-484e-b90f-825b35f5c724', 'user2', 'user2password');

INSERT INTO user_role (user_id, role)
VALUES ((SELECT id FROM users WHERE username = 'admin'), 'ROLE_ADMIN'),
       ((SELECT id FROM users WHERE username = 'user1'), 'ROLE_USER'),
       ((SELECT id FROM users WHERE username = 'user2'), 'ROLE_USER');
