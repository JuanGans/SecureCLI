/**
 * Comprehensive Test File
 * Demonstrates context-aware fix recommendations
 */

const express = require('express');
const mysql = require('mysql');
const app = express();

// Test 1: mysqli-style (should suggest mysqli_prepared)
function testMysqli() {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  mysqli_query(conn, query);
}

// Test 2: PDO-style (should suggest pdo_prepared)
function testPDO() {
  const email = req.body.email;
  const sql = "SELECT * FROM users WHERE email = '" + email + "'";
  pdo.query(sql);
}

// Test 3: Node.js db.query (should suggest orm_parameterized)
app.get('/user', (req, res) => {
  const username = req.query.username;
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// Test 4: Connection.query (should suggest orm_parameterized)
app.get('/product', (req, res) => {
  const productId = req.params.id;
  const sql = "SELECT * FROM products WHERE id = " + productId;
  connection.query(sql, (err, rows) => {
    res.json(rows);
  });
});

// Test 5: XSS with innerHTML (should suggest textContent_replacement)
function displayMessage() {
  const msg = location.search;
  document.getElementById('output').innerHTML = msg;
}

// Test 6: XSS with document.write (should suggest safe_encoding)
function showGreeting() {
  const name = location.href;
  document.write("<h1>Hello " + name + "</h1>");
}

// Test 7: XSS with res.send (should suggest generic_escape)
app.get('/greet', (req, res) => {
  const greeting = req.query.msg;
  res.send(greeting);
});
