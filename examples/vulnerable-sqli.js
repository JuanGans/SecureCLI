/**
 * Example: SQL Injection Vulnerabilities
 * These are intentionally vulnerable patterns for testing purposes
 */

const express = require('express');
const app = express();

app.use(express.json());

// ❌ VULNERABLE: UNION-Based SQL Injection
app.get('/search', (req, res) => {
  const searchTerm = req.query.search;
  const query = "SELECT id, username FROM users WHERE name LIKE '" + searchTerm + "'";
  
  // Attacker can inject: ' UNION SELECT password, email FROM admin_users --
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// ❌ VULNERABLE: Time-Based Blind SQL Injection
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  const query = "SELECT id FROM users WHERE username = '" + username + 
                "' AND password = '" + password + "'";
  // Attacker can inject: ' OR IF(1=1,SLEEP(5),0) --
  
  db.query(query, (err, results) => {
    if (results.length > 0) {
      res.json({ status: 'success' });
    } else {
      res.json({ status: 'failed' });
    }
  });
});

// ❌ VULNERABLE: Error-Based SQL Injection
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  // Attacker can inject: 1 AND extractvalue(1,concat(0x7e,(SELECT version())))
  
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// ❌ VULNERABLE: Stacked Queries
app.post('/update-profile', (req, res) => {
  const email = req.body.email;
  const userId = req.body.id;
  
  const query = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;
  // Attacker can inject: ; DROP TABLE users; --
  
  db.query(query, (err) => {
    res.json({ status: 'updated' });
  });
});

module.exports = app;
