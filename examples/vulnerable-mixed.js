/**
 * Mixed Real-Life Vulnerability Examples
 * Demonstrates multiple vulnerability patterns found in production code
 */

const express = require('express');
const mysql = require('mysql');
const app = express();

// =====================================================
// CASE 1: String Concatenation SQLi
// =====================================================
app.get('/user', (req, res) => {
  const userId = req.query.id;
  // VULNERABLE: Simple string concatenation
  const query = "SELECT * FROM users WHERE id = " + userId;
  const connection = mysql.createConnection({});
  connection.query(query, (err, results) => {
    if (!err) res.json(results);
  });
});

// =====================================================
// CASE 2: Template Literal SQLi
// =====================================================
app.post('/search', (req, res) => {
  const searchTerm = req.body.search;
  const db = mysql.createConnection({});
  
  // VULNERABLE: Template literal in query
  const sql = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
  
  db.query(sql, (err, results) => {
    if (!err) res.send(results);
  });
});

// =====================================================
// CASE 3: innerHTML XSS
// =====================================================
const displayXSS = `
  <script>
    function showComment(text) {
      // VULNERABLE: innerHTML with user input
      document.getElementById('comments').innerHTML = text;
    }
  </script>
`;

// =====================================================
// CASE 4: Response XSS with Template
// =====================================================
app.get('/search-results', (req, res) => {
  const query = req.query.q;
  const results = req.query.results || '0';
  
  // VULNERABLE: Unescaped user data in response
  const html = `
    <html>
      <body>
        <h1>Results for: ${query}</h1>
        <p>Found ${results} results</p>
      </body>
    </html>
  `;
  
  res.send(html);
});

// =====================================================
// CASE 5: Dynamic WHERE Clause
// =====================================================
app.get('/filter', (req, res) => {
  const minPrice = req.query.minPrice;
  const maxPrice = req.query.maxPrice;
  const db = mysql.createConnection({});
  
  // VULNERABLE: Building WHERE clause dynamically
  let query = "SELECT * FROM products WHERE 1=1";
  
  if (minPrice) {
    query += " AND price >= " + minPrice;
  }
  if (maxPrice) {
    query += " AND price <= " + maxPrice;
  }
  
  db.query(query, (err, results) => {
    res.json(results || []);
  });
});

// =====================================================
// CASE 6: INSERT with Concatenation
// =====================================================
app.post('/create-user', (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const db = mysql.createConnection({});
  
  // VULNERABLE: INSERT with user data concatenation
  const sql = "INSERT INTO users (username, email) VALUES " +
              "('" + username + "', '" + email + "')";
  
  db.query(sql, (err, result) => {
    if (err) res.status(500).json({ error: err });
    else res.json({ id: result.insertId });
  });
});

// =====================================================
// CASE 7: UPDATE with WHERE
// =====================================================
app.put('/update-user/:id', (req, res) => {
  const userId = req.params.id;
  const newName = req.body.name;
  const db = mysql.createConnection({});
  
  // VULNERABLE: UPDATE with concatenation
  const sql = "UPDATE users SET name = '" + newName + 
              "' WHERE id = " + userId;
  
  db.query(sql, (err, result) => {
    res.json({ updated: result ? result.affectedRows : 0 });
  });
});

// =====================================================
// CASE 8: Conditional Query Building
// =====================================================
app.post('/advanced-search', (req, res) => {
  const name = req.body.name;
  const city = req.body.city;
  const db = mysql.createConnection({});
  
  // VULNERABLE: Conditional concatenation
  let query = "SELECT * FROM users WHERE 1=1";
  
  if (name) {
    query += " AND name LIKE '%" + name + "%'";
  }
  if (city) {
    query += " AND city = '" + city + "'";
  }
  
  db.query(query, (err, results) => {
    res.json(results || []);
  });
});

// =====================================================
// CASE 9: Nested Function Calls
// =====================================================
function queryUser(userId) {
  const db = mysql.createConnection({});
  // VULNERABLE: User input in function call
  return executeQuery(
    "SELECT * FROM users WHERE id = " + userId,
    db
  );
}

function executeQuery(query, connection) {
  return new Promise((resolve, reject) => {
    connection.query(query, (err, results) => {
      if (err) reject(err);
      else resolve(results);
    });
  });
}

// =====================================================
// CASE 10: DOM Element XSS
// =====================================================
const xssExample = `
  <script>
    function createLink(url) {
      const link = document.createElement('a');
      // VULNERABLE: Unescaped URL attribute
      link.href = url;
      link.textContent = 'Click here';
      document.body.appendChild(link);
    }
  </script>
`;

module.exports = {
  app,
  note: 'Examples only - never deploy vulnerable code'
};
