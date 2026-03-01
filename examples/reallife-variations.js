/**
 * REAL-LIFE TEST CASES
 * Various vulnerability patterns found in production code
 * Tests the adaptive system with real-world variations
 */

// =====================================================
// CASE 1: String Concatenation (Simple Style)
// =====================================================
const express = require('express');
const mysql = require('mysql');

app.get('/user', (req, res) => {
  const userId = req.query.id;
  // VULNERABLE: Simple string concatenation
  const query = "SELECT * FROM users WHERE id = " + userId;
  connection.query(query, (err, results) => {
    res.json(results);
  });
});

// =====================================================
// CASE 2: String Concatenation (Complex Style)
// =====================================================
app.post('/search', (req, res) => {
  const searchTerm = req.body.search;
  const category = req.query.category;
  const limit = 10;
  
  // VULNERABLE: Multiple concatenations
  const query = "SELECT * FROM products WHERE " +
                "name LIKE '%" + searchTerm + "%' " +
                "AND category = '" + category + "' " +
                "LIMIT " + limit;
  
  db.query(query, (err, results) => {
    if (!err) res.send(results);
  });
});

// =====================================================
// CASE 3: Template Literal (Simple)
// =====================================================
app.get('/profile', (req, res) => {
  const username = req.query.username;
  // VULNERABLE: Template literal in query
  const sql = `SELECT * FROM users WHERE username = '${username}'`;
  connection.query(sql, (err, rows) => {
    res.json(rows);
  });
});

// =====================================================
// CASE 4: Template Literal (Complex HTML context)
// =====================================================
app.get('/search-results', (req, res) => {
  const query = req.query.q;
  const sort = req.query.sort || 'date';
  
  // VULNERABLE: Template literal with HTML
  const html = `
    <html>
    <body>
      <h1>Search Results for: ${query}</h1>
      <p>Sorted by: ${sort}</p>
      <script>
        var searchTerm = '${query}';
        displayResults(searchTerm);
      </script>
    </body>
    </html>
  `;
  
  res.send(html);
});

// =====================================================
// CASE 5: In-place Query Construction
// =====================================================
app.post('/filter', (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const age = req.body.age;
  
  // VULNERABLE: Inline concatenation in function call
  db.query("SELECT * FROM users WHERE " +
           "name = '" + name + "' " +
           "AND email = '" + email + "' " +
           "AND age > " + age, 
    (err, results) => {
      res.json(results);
    }
  );
});

// =====================================================
// CASE 6: innerHTML with Direct Assignment
// =====================================================
function displayUserName() {
  const name = document.getElementById('userName').value;
  // VULNERABLE: Direct innerHTML assignment
  document.getElementById('display').innerHTML = name;
}

// =====================================================
// CASE 7: innerHTML in Complex Component
// =====================================================
class CommentDisplay {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
  }
  
  renderComment(comment) {
    const author = comment.author;
    const content = comment.content;
    const date = comment.date;
    
    // VULNERABLE: innerHTML with multiple user inputs
    this.container.innerHTML = `
      <div class="comment">
        <span class="author">${author}</span>
        <p class="content">${content}</p>
        <time>${date}</time>
      </div>
    `;
  }
}

// =====================================================
// CASE 8: document.write with Data
// =====================================================
app.get('/page', (req, res) => {
  const title = req.query.title;
  const content = req.query.content;
  
  // VULNERABLE: Unescaped output in HTML
  const html = `<html>
    <head><title>${title}</title></head>
    <body>
      <h1>${title}</h1>
      <div>${content}</div>
    </body>
  </html>`;
  
  res.send(html);
});

// =====================================================
// CASE 9: Dynamic Attribute Assignment
// =====================================================
function createLink(userURL) {
  const link = document.createElement('a');
  // VULNERABLE: URL attribute without encoding
  link.href = userURL;
  link.textContent = 'Click here';
  document.body.appendChild(link);
}

// =====================================================
// CASE 10: Form Input Display (No Encoding)
// =====================================================
app.post('/save', (req, res) => {
  const userName = req.body.username;
  const userEmail = req.body.email;
  
  // VULNERABLE: User data in form without encoding
  const confirmForm = `
    <form>
      <input type="text" value="${userName}">
      <input type="email" value="${userEmail}">
      <input type="checkbox"> I confirm this is correct
      <button type="submit">Save</button>
    </form>
  `;
  
  res.send(confirmForm);
});

// =====================================================
// CASE 11: Concatenation with Incomplete WHERE Clause
// =====================================================
app.get('/filter-advanced', (req, res) => {
  const minPrice = req.query.minPrice;
  const maxPrice = req.query.maxPrice;
  const keyword = req.query.keyword;
  
  // VULNERABLE: Building WHERE clause dynamically
  let where = "WHERE 1=1";
  
  if (minPrice) {
    where += " AND price >= " + minPrice; // String concatenation
  }
  if (maxPrice) {
    where += " AND price <= " + maxPrice;
  }
  if (keyword) {
    where += " AND name LIKE '%" + keyword + "%'";
  }
  
  const sql = "SELECT * FROM products " + where;
  db.query(sql, (err, results) => {
    res.json(results);
  });
});

// =====================================================
// CASE 12: Nested Function Calls with Concatenation
// =====================================================
function getUserData(userId, connection) {
  // VULNERABLE: Identifier passed to function
  return queryDatabase(
    "SELECT * FROM users WHERE id = " + userId,
    connection
  );
}

function queryDatabase(query, conn) {
  return conn.query(query, (err, results) => {
    return results;
  });
}

// =====================================================
// CASE 13: INSERT with Multiple Values
// =====================================================
app.post('/create-record', (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const role = req.body.role;
  
  // VULNERABLE: INSERT with concatenation
  const sql = "INSERT INTO users (username, email, role) VALUES " +
              "('" + username + "', '" + email + "', '" + role + "')";
  
  db.query(sql, (err, result) => {
    if (err) res.status(500).json({ error: err });
    else res.json({ id: result.insertId });
  });
});

// =====================================================
// CASE 14: UPDATE with WHERE Clause
// =====================================================
app.put('/update-profile', (req, res) => {
  const userId = req.params.id;
  const newName = req.body.name;
  const newEmail = req.body.email;
  
  // VULNERABLE: UPDATE with concatenation
  const sql = "UPDATE users SET " +
              "name = '" + newName + "', " +
              "email = '" + newEmail + "' " +
              "WHERE id = " + userId;
  
  conn.query(sql, (err, result) => {
    res.json({ updated: result.affectedRows });
  });
});

// =====================================================
// CASE 15: Mixed Single and Double Quotes
// =====================================================
app.get('/search-mixed', (req, res) => {
  const category = req.query.cat;
  const brand = req.query.brand;
  
  // VULNERABLE: Mixed quote styles
  const query = 'SELECT * FROM products WHERE ' +
                "category = '" + category + "' " +
                'AND brand = "' + brand + '"';
  
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// =====================================================
// CASE 16: Dynamic HTML Content in Response
// =====================================================
app.get('/user-profile', (req, res) => {
  const userId = req.query.id;
  const userData = getUserById(userId);
  
  if (userData) {
    // VULNERABLE: Embedding user data in response HTML
    res.send(`
      <html>
        <body>
          <h1>${userData.firstName} ${userData.lastName}</h1>
          <p>Email: ${userData.email}</p>
          <p>Bio: ${userData.bio}</p>
          <img src="${userData.profilePic}">
        </body>
      </html>
    `);
  }
});

// =====================================================
// CASE 17: Conditional Query Building
// =====================================================
app.post('/advanced-search', (req, res) => {
  const name = req.body.name;
  const city = req.body.city;
  const hasFilters = name || city;
  
  // VULNERABLE: Conditional concatenation
  let query = "SELECT * FROM users WHERE 1=1";
  
  if (name) {
    query += " AND name LIKE '%" + name + "%'";
  }
  if (city) {
    query += " AND city = '" + city + "'";
  }
  
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// =====================================================
// CASE 18: Array/List Processing
// =====================================================
app.post('/batch-update', (req, res) => {
  const ids = req.body.ids; // Array of IDs from user
  const status = req.body.status;
  
  // VULNERABLE: Building IN clause with concatenation
  const idList = ids.join(','); // Direct concatenation
  const sql = "UPDATE users SET status = '" + status + 
              "' WHERE id IN (" + idList + ")";
  
  db.query(sql, (err, result) => {
    res.json(result);
  });
});

// =====================================================
// CASE 19: Redirect with User Input
// =====================================================
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  // VULNERABLE: Unvalidated redirect
  res.redirect(url);
});

// =====================================================
// CASE 20: Script Tag Injection
// =====================================================
app.post('/comment', (req, res) => {
  const comment = req.body.text;
  
  // VULNERABLE: Comment with potential script tags
  const html = `<div class="comment">
    <p>${comment}</p>
  </div>`;
  
  db.saveComment({
    content: html,
    timestamp: new Date()
  });
  
  res.json({ saved: true });
});

module.exports = { 
  // These are example cases - never deploy vulnerable code!
  note: 'This file contains example vulnerabilities for testing only'
};
