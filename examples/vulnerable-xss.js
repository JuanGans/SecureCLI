/**
 * Example: XSS Vulnerabilities
 * These are intentionally vulnerable patterns for testing purposes
 */

const express = require('express');
const app = express();

app.use(express.json());

// ❌ VULNERABLE: Reflected XSS
app.get('/search', (req, res) => {
  const query = req.query.q;
  
  // User input directly reflected in response
  const html = `
    <html>
      <body>
        <h1>Search Results for: ${query}</h1>
        <p>We found some results...</p>
      </body>
    </html>
  `;
  
  // Attacker can inject: <script>fetch('/steal?cookie='+document.cookie)</script>
  res.send(html);
});

// ❌ VULNERABLE: Stored XSS
app.post('/comment', (req, res) => {
  const comment = req.body.comment;
  const userId = req.body.userId;
  
  // Save to database without sanitization
  db.saveComment({
    userId: userId,
    content: comment, // Direct storage
    timestamp: new Date(),
  });
  
  // Later, when user views comments:
  app.get('/view-comments/:id', (req, res) => {
    const comments = db.getComments(req.params.id);
    
    let html = '<div class="comments">';
    comments.forEach(c => {
      html += `<div class="comment">${c.content}</div>`;
    });
    html += '</div>';
    
    // Stored malicious script executes for all users
    // Attacker injected: <img src=x onerror="alert('XSS from ' + document.cookie)">
    res.send(html);
  });
  
  res.json({ status: 'saved' });
});

// ❌ VULNERABLE: DOM-Based XSS
app.get('/page', (req, res) => {
  const name = req.query.name;
  
  const html = `
    <html>
      <body>
        <h1>Welcome</h1>
        <script>
          const userName = '${name}';
          document.getElementById('greeting').innerHTML = '<h2>Hello, ' + userName + '!</h2>';
        </script>
        <div id="greeting"></div>
      </body>
    </html>
  `;
  
  // Attacker can inject: <img src=x onerror="alert('DOM XSS')">
  res.send(html);
});

// ❌ VULNERABLE: Event Handler Injection
app.get('/form', (req, res) => {
  const userValue = req.query.value;
  
  const html = `
    <html>
      <body>
        <form>
          <input type="text" value="${userValue}" />
        </form>
      </body>
    </html>
  `;
  
  // Attacker can inject: " onerror="alert('XSS in attribute')
  res.send(html);
});

module.exports = app;
