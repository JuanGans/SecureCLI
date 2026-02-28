/**
 * File Loader and Iterator
 */

const fs = require('fs');
const path = require('path');

class FileLoader {
  /**
   * Get all JavaScript files from target
   */
  static loadFiles(target, maxSize = 10 * 1024 * 1024) {
    const files = [];

    if (fs.statSync(target).isDirectory()) {
      this.walkDirectory(target, files, maxSize);
    } else {
      files.push(target);
    }

    return files;
  }

  /**
   * Recursively walk directory
   */
  static walkDirectory(dir, files = [], maxSize) {
    try {
      const entries = fs.readdirSync(dir);

      entries.forEach(entry => {
        const fullPath = path.join(dir, entry);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
          this.walkDirectory(fullPath, files, maxSize);
        } else if ((entry.endsWith('.js') || entry.endsWith('.php') || entry.endsWith('.jsx')) &&
                   stat.size <= maxSize) {
          files.push(fullPath);
        }
      });
    } catch (error) {
      console.error(`Error reading directory ${dir}: ${error.message}`);
    }

    return files;
  }
}

module.exports = FileLoader;
