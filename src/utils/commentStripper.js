/**
 * Comment Stripper - Remove comments from source code before analysis
 * Prevents false positives from commented-out code
 */

class CommentStripper {
  /**
   * Strip all comments from PHP code
   * Supports: //, #, /* *\/
   */
  static stripPHPComments(code) {
    let result = '';
    let i = 0;
    const length = code.length;
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inMultilineComment = false;
    
    while (i < length) {
      const char = code[i];
      const nextChar = code[i + 1];
      
      // Handle string literals (preserve them as-is)
      if (char === "'" && !inDoubleQuote && code[i - 1] !== '\\') {
        inSingleQuote = !inSingleQuote;
        result += char;
        i++;
        continue;
      }
      
      if (char === '"' && !inSingleQuote && code[i - 1] !== '\\') {
        inDoubleQuote = !inDoubleQuote;
        result += char;
        i++;
        continue;
      }
      
      // Skip if we're inside a string
      if (inSingleQuote || inDoubleQuote) {
        result += char;
        i++;
        continue;
      }
      
      // Multi-line comment start: /*
      if (char === '/' && nextChar === '*' && !inMultilineComment) {
        inMultilineComment = true;
        i += 2;
        continue;
      }
      
      // Multi-line comment end: */
      if (char === '*' && nextChar === '/' && inMultilineComment) {
        inMultilineComment = false;
        result += '  '; // Preserve spacing for line numbers
        i += 2;
        continue;
      }
      
      // Skip content inside multi-line comment
      if (inMultilineComment) {
        result += char === '\n' ? '\n' : ' '; // Preserve line breaks
        i++;
        continue;
      }
      
      // Single-line comment: // or #
      if ((char === '/' && nextChar === '/') || char === '#') {
        // Skip until end of line
        while (i < length && code[i] !== '\n') {
          result += ' '; // Replace with space to preserve line numbers
          i++;
        }
        if (i < length && code[i] === '\n') {
          result += '\n';
          i++;
        }
        continue;
      }
      
      // Regular character
      result += char;
      i++;
    }
    
    return result;
  }

  /**
   * Strip JavaScript/TypeScript comments
   */
  static stripJSComments(code) {
    // Similar logic to PHP but without # comment support
    let result = '';
    let i = 0;
    const length = code.length;
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inTemplateString = false;
    let inMultilineComment = false;
    
    while (i < length) {
      const char = code[i];
      const nextChar = code[i + 1];
      
      // Handle string literals
      if (char === "'" && !inDoubleQuote && !inTemplateString && code[i - 1] !== '\\') {
        inSingleQuote = !inSingleQuote;
        result += char;
        i++;
        continue;
      }
      
      if (char === '"' && !inSingleQuote && !inTemplateString && code[i - 1] !== '\\') {
        inDoubleQuote = !inDoubleQuote;
        result += char;
        i++;
        continue;
      }
      
      if (char === '`' && !inSingleQuote && !inDoubleQuote && code[i - 1] !== '\\') {
        inTemplateString = !inTemplateString;
        result += char;
        i++;
        continue;
      }
      
      // Skip if inside string
      if (inSingleQuote || inDoubleQuote || inTemplateString) {
        result += char;
        i++;
        continue;
      }
      
      // Multi-line comment
      if (char === '/' && nextChar === '*' && !inMultilineComment) {
        inMultilineComment = true;
        i += 2;
        continue;
      }
      
      if (char === '*' && nextChar === '/' && inMultilineComment) {
        inMultilineComment = false;
        result += '  ';
        i += 2;
        continue;
      }
      
      if (inMultilineComment) {
        result += char === '\n' ? '\n' : ' ';
        i++;
        continue;
      }
      
      // Single-line comment: //
      if (char === '/' && nextChar === '/') {
        while (i < length && code[i] !== '\n') {
          result += ' ';
          i++;
        }
        if (i < length && code[i] === '\n') {
          result += '\n';
          i++;
        }
        continue;
      }
      
      // Regular character
      result += char;
      i++;
    }
    
    return result;
  }

  /**
   * Strip comments based on language
   */
  static strip(code, language) {
    if (language === 'php') {
      return this.stripPHPComments(code);
    } else if (['javascript', 'typescript', 'jsx', 'tsx'].includes(language)) {
      return this.stripJSComments(code);
    } else {
      // Default: no stripping
      return code;
    }
  }
}

module.exports = CommentStripper;
