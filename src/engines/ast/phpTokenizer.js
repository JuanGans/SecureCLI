/**
 * PHP Tokenizer - Lexical Analysis for PHP Code
 * Breaks PHP code into meaningful tokens for analysis
 * 
 * STAGE 1: Regex Lexical Scanner (tokenization layer)
 */

class PHPTokenizer {
  constructor() {
    this.tokens = [];
    this.position = 0;
  }

  /**
   * Tokenize PHP code into meaningful units
   * Returns array of tokens with type, value, line number
   */
  tokenize(code) {
    this.tokens = [];
    this.position = 0;
    const lines = code.split('\n');
    
    let currentLine = 1;
    let charIndex = 0;
    let inPHPTag = false;
    let inString = false;
    let stringChar = null;
    
    for (let i = 0; i < code.length; i++) {
      const char = code[i];
      
      // Track line numbers
      if (char === '\n') {
        currentLine++;
        charIndex = 0;
      } else {
        charIndex++;
      }
      
      // PHP tag detection
      if (code.substr(i, 5) === '<?php') {
        inPHPTag = true;
        this.addToken('PHP_OPEN_TAG', '<?php', currentLine, i);
        i += 4;
        continue;
      }
      
      if (code.substr(i, 2) === '<?') {
        inPHPTag = true;
        this.addToken('PHP_OPEN_TAG', '<?', currentLine, i);
        i += 1;
        continue;
      }
      
      if (code.substr(i, 2) === '?>') {
        inPHPTag = false;
        this.addToken('PHP_CLOSE_TAG', '?>', currentLine, i);
        i += 1;
        continue;
      }
      
      if (!inPHPTag) continue;
      
      // String detection
      if ((char === '"' || char === "'") && !inString) {
        inString = true;
        stringChar = char;
        this.addToken('STRING_START', char, currentLine, i);
        continue;
      }
      
      if (char === stringChar && inString) {
        inString = false;
        this.addToken('STRING_END', char, currentLine, i);
        stringChar = null;
        continue;
      }
      
      if (inString) {
        // String content collection
        if (!this.isStringContent()) {
          let stringContent = '';
          let startPos = i;
          while (i < code.length && code[i] !== stringChar) {
            stringContent += code[i];
            i++;
          }
          this.addToken('STRING_CONTENT', stringContent, currentLine, startPos);
          i--; // Back one to let the outer loop handle the closing quote
        }
        continue;
      }
      
      // Variable detection ($variable)
      if (char === '$' && this.isValidIdentifierStart(code[i + 1])) {
        let variable = '$';
        let startPos = i;
        i++;
        while (i < code.length && this.isValidIdentifierChar(code[i])) {
          variable += code[i];
          i++;
        }
        this.addToken('VARIABLE', variable, currentLine, startPos);
        i--; // Back one since the outer loop will increment
        continue;
      }
      
      // Superglobal detection
      if (this.isSuperGlobal(code, i)) {
        const match = this.matchSuperGlobal(code, i);
        if (match) {
          this.addToken('SUPERGLOBAL', match.value, currentLine, i);
          i += match.value.length - 1;
          continue;
        }
      }
      
      // Function call detection
      if (this.isFunctionCall(code, i)) {
        const match = this.matchFunctionCall(code, i);
        if (match) {
          this.addToken('FUNCTION', match.value, currentLine, i);
          i += match.value.length - 1;
          continue;
        }
      }
      
      // Operators and symbols
      if (this.isOperator(char)) {
        let operator = char;
        // Check for multi-char operators
        if (i + 1 < code.length) {
          const twoChar = code.substr(i, 2);
          if (this.isMultiCharOperator(twoChar)) {
            operator = twoChar;
            i++;
          }
        }
        this.addToken('OPERATOR', operator, currentLine, i);
        continue;
      }
      
      // Array/bracket detection
      if (char === '[') {
        this.addToken('BRACKET_OPEN', '[', currentLine, i);
        continue;
      }
      if (char === ']') {
        this.addToken('BRACKET_CLOSE', ']', currentLine, i);
        continue;
      }
      
      // Parenthesis detection
      if (char === '(') {
        this.addToken('PAREN_OPEN', '(', currentLine, i);
        continue;
      }
      if (char === ')') {
        this.addToken('PAREN_CLOSE', ')', currentLine, i);
        continue;
      }
      
      // Skip whitespace (but track it)
      if (this.isWhitespace(char)) {
        continue;
      }
      
      // Skip unknown characters for now
    }
    
    return this.tokens;
  }

  /**
   * Check if this position starts a superglobal
   */
  isSuperGlobal(code, pos) {
    const superglobals = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES', '$_SESSION', '$_ENV'];
    for (const sg of superglobals) {
      if (code.substr(pos, sg.length) === sg) {
        return true;
      }
    }
    return false;
  }

  /**
   * Match superglobal at position
   */
  matchSuperGlobal(code, pos) {
    const superglobals = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES', '$_SESSION', '$_ENV'];
    for (const sg of superglobals) {
      if (code.substr(pos, sg.length) === sg) {
        return { value: sg, type: 'SUPERGLOBAL' };
      }
    }
    return null;
  }

  /**
   * Check if this position starts a function call
   */
  isFunctionCall(code, pos) {
    const functions = [
      'echo', 'print', 'printf', 'sprintf',
      'mysqli_query', 'mysql_query', 'query',
      'htmlspecialchars', 'htmlentities', 'urlencode',
      'isset', 'empty', 'is_array', 'count',
      'file_get_contents', 'file_put_contents',
      'eval', 'assert', 'system', 'exec',
      'header', 'setcookie', 'session_start',
      'include', 'require', 'include_once', 'require_once'
    ];
    
    for (const fn of functions) {
      if (code.substr(pos, fn.length) === fn && 
          (pos + fn.length >= code.length || !this.isValidIdentifierChar(code[pos + fn.length]))) {
        return true;
      }
    }
    return false;
  }

  /**
   * Match function call at position
   */
  matchFunctionCall(code, pos) {
    const functions = [
      'echo', 'print', 'printf', 'sprintf',
      'mysqli_query', 'mysql_query', 'query',
      'htmlspecialchars', 'htmlentities', 'urlencode',
      'isset', 'empty', 'is_array', 'count',
      'file_get_contents', 'file_put_contents',
      'eval', 'assert', 'system', 'exec',
      'header', 'setcookie', 'session_start',
      'include', 'require', 'include_once', 'require_once'
    ];
    
    for (const fn of functions) {
      if (code.substr(pos, fn.length) === fn) {
        return { value: fn, type: 'FUNCTION' };
      }
    }
    return null;
  }

  /**
   * Check if character is valid identifier
   */
  isValidIdentifierStart(char) {
    return char && /[a-zA-Z_]/.test(char);
  }

  isValidIdentifierChar(char) {
    return char && /[a-zA-Z0-9_]/.test(char);
  }

  /**
   * Check if character is operator
   */
  isOperator(char) {
    return '=.+-*/%<>!&|^~?:;,'.includes(char);
  }

  /**
   * Check if two-char sequence is operator
   */
  isMultiCharOperator(twoChar) {
    const multiOps = ['==', '!=', '<=', '>=', '=>', '.=', '++', '--', '&&', '||', '<<', '>>'];
    return multiOps.includes(twoChar);
  }

  /**
   * Check if character is whitespace
   */
  isWhitespace(char) {
    return /\s/.test(char);
  }

  /**
   * Check if current position is within a string
   */
  isStringContent() {
    // This should be implemented based on current context
    return false;
  }

  /**
   * Add token to array
   */
  addToken(type, value, line, position) {
    this.tokens.push({
      type,
      value,
      line,
      position,
      context: null // Will be filled during analysis
    });
  }

  /**
   * Get all tokens
   */
  getTokens() {
    return this.tokens;
  }

  /**
   * Get tokens by type
   */
  getTokensByType(type) {
    return this.tokens.filter(t => t.type === type);
  }

  /**
   * Get next token from position
   */
  getNextToken(fromIndex) {
    if (fromIndex + 1 < this.tokens.length) {
      return this.tokens[fromIndex + 1];
    }
    return null;
  }

  /**
   * Get previous token from position
   */
  getPreviousToken(fromIndex) {
    if (fromIndex - 1 >= 0) {
      return this.tokens[fromIndex - 1];
    }
    return null;
  }
}

module.exports = PHPTokenizer;
