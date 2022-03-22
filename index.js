if (parseInt(process.versions.node.split('.')[0]) < 6) throw new Error('vm2 requires Node.js version 6 or newer.');

/**
 * Adds import helper for packaging
 */
try { require('./lib/contextify') } catch(_) {}
try { require('./lib/fixasync') } catch(_) {}
try { require('./lib/sandbox') } catch(_) {}
try { require('./lib/setup-sandbox') } catch(_) {}

module.exports = require('./lib/main');
