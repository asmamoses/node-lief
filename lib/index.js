/**
 * LIEF Node.js Bindings
 *
 * This is the main JavaScript entry point that loads the native addon
 * and exports the LIEF API for use from JavaScript/TypeScript.
 */

const { join } = require('path');

// Use node-gyp-build to load prebuilt binaries or fall back to building
const binding = require('node-gyp-build')(join(__dirname, '..'));

// Export the binding directly - it already has the proper structure
module.exports = binding;
