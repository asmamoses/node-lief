# LIEF Node.js Bindings

Node.js bindings for [LIEF](https://lief.quarkslab.com/) - the Library to Instrument Executable Formats.

Parse and manipulate binary executables (ELF, PE, Mach-O, etc.) from JavaScript/TypeScript with full access to LIEF's comprehensive API.

## Features

- **Format Support**: ELF (Linux), PE (Windows), Mach-O (macOS/iOS)
- **Binary Parsing**: Automatically detect and parse binary format
- **Symbol & Relocation Access**: Read symbols, relocations, and section information
- **Binary Modification**: Patch addresses, modify sections, extend segments, and more
- **Format-Agnostic API**: Work with the generic Binary interface
- **Format-Specific APIs**: Access format-specific details (MachO segments, code signatures, etc.)
- **TypeScript Support**: Full type definitions included
- **Prebuilt Binaries**: Fast installation with prebuilt binaries for common platforms

## Installation

```bash
pnpm install node-lief
```

For most platforms, prebuilt binaries will be automatically installed. If no prebuilt binary is available, the package will compile from source automatically.

## Prerequisites

**For prebuilt binaries (recommended):**
- Node.js 14+

**For building from source:**
- Node.js 14+
- CMake 3.15+
- Ninja build system
- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- Git (for cloning LIEF submodule)

## Quick Start

```javascript
const LIEF = require('node-lief');

// Parse a binary file (auto-detects format)
const binary = LIEF.parse('/bin/ls');

console.log(`Format: ${binary.format}`);              // 'ELF', 'PE', 'MachO', or 'UNKNOWN'
console.log(`Entrypoint: 0x${binary.entrypoint.toString(16)}`);
console.log(`PIE: ${binary.isPie}`);
console.log(`NX: ${binary.hasNx}`);

// Access sections
const sections = binary.sections();
sections.forEach(section => {
  console.log(`Section: ${section.name} @ 0x${section.virtualAddress.toString(16)}`);
});

// Access symbols
const symbols = binary.symbols();
symbols.forEach(symbol => {
  console.log(`Symbol: ${symbol.name} @ 0x${symbol.value.toString(16)}`);
});

// Get a specific symbol by name
const mainSymbol = binary.getSymbol('main');
if (mainSymbol) {
  console.log(`main @ 0x${mainSymbol.value.toString(16)}`);
}

// Patch an address with new bytes
binary.patchAddress(0x1000n, [0x90, 0x90, 0x90]); // NOP sled

// Write modified binary
binary.write('./output');
```

## TypeScript Example

```typescript
import * as LIEF from 'node-lief';

// Parse with auto-detection
const binary = LIEF.parse('/bin/ls');

// Type-safe access to properties
const entrypoint: bigint = binary.entrypoint;
const isPie: boolean = binary.isPie;
const format: 'ELF' | 'PE' | 'MachO' | 'UNKNOWN' = binary.format;

// Format-specific operations
if (binary.format === 'ELF') {
  // ELF-specific code here
  const elfBinary = binary as LIEF.ELF.Binary;
}

// Work with sections, symbols, and relocations
const sections: LIEF.Abstract.Section[] = binary.sections();
const symbols: LIEF.Abstract.Symbol[] = binary.symbols();
const relocations: LIEF.Abstract.Relocation[] = binary.relocations();

// Modify and write
binary.patchAddress(0x1000n, Buffer.from([0x90, 0x90]));
binary.write('./output');
```

## API Documentation

### Main Functions

#### `LIEF.parse(filename: string)`

Parse a binary file and return format-specific binary object. Automatically detects the format and returns the appropriate type.

**Returns:** `ELF.Binary | PE.Binary | MachO.Binary | Abstract.Binary`

#### `LIEF.MachO.parse(filename: string)`

Parse a MachO file and return a FatBinary object (which may contain single or multiple architectures).

**Returns:** `MachO.FatBinary`

### `Abstract.Binary`

Generic binary interface that works across all formats.

#### Properties

- `format: string` - Binary format ('ELF', 'PE', 'MachO', 'UNKNOWN')
- `entrypoint: bigint` - Entry point address
- `isPie: boolean` - Whether binary is position-independent
- `hasNx: boolean` - Whether binary has NX protection
- `header: Header` - Binary header information

#### Methods

- `sections(): Section[]` - Get all sections
- `symbols(): Symbol[]` - Get all symbols
- `relocations(): Relocation[]` - Get all relocations
- `segments(): Segment[]` - Get all segments (empty for Abstract, implemented for MachO)
- `getSymbol(name: string): Symbol | null` - Get a specific symbol by name
- `patchAddress(address: number | bigint, patch: Buffer | number[]): void` - Patch bytes at address
- `write(outputPath: string): void` - Write the binary to disk

### `Section`

Represents a section in a binary.

- `name: string` - Section name
- `type: string` - Section type
- `virtualAddress: bigint` - Virtual address
- `size: bigint` - Section size (read/write)
- `virtualSize: bigint` - Virtual size (read/write)
- `fileOffset: bigint` - Offset in file
- `offset: bigint` - File offset (alias)
- `content: number[] | Buffer` - Section content (read/write)

### `Symbol`

Represents a symbol in a binary.

- `name: string` - Symbol name
- `value: bigint` - Symbol value/address
- `size: bigint` - Symbol size

### `Relocation`

Represents a relocation in a binary.

- `address: bigint` - Relocation address
- `size: number` - Relocation size

### Format-Specific Classes

#### `ELF.Binary`

ELF-specific binary class with all Abstract.Binary methods.

#### `PE.Binary`

PE (Windows) specific binary class with all Abstract.Binary methods.

#### `MachO.Binary`

MachO-specific binary class with additional methods:

- `hasCodeSignature: boolean` - Whether the binary has a code signature
- `getSegment(name: string): Segment | null` - Get a segment by name
- `removeSignature(): void` - Remove code signature
- `extendSegment(segment: Segment, size: bigint | number): boolean` - Extend a segment

#### `MachO.Segment`

Represents a MachO segment.

- `name: string` - Segment name
- `type: string` - Segment type
- `virtualAddress: bigint` - Virtual address
- `virtualSize: bigint` - Virtual size
- `fileOffset: bigint` - File offset
- `fileSize: bigint` - File size
- `sections(): Section[]` - Get sections in this segment
- `getSection(name: string): Section | null` - Get a section by name

#### `MachO.FatBinary`

Universal/Fat binary containing multiple architectures.

- `size(): number` - Number of architectures
- `at(index: number): Binary | null` - Get binary at index
- `take(index: number): Binary | null` - Get and take ownership of binary at index

### Logging

- `LIEF.logging.disable()` - Disable LIEF logging output
- `LIEF.logging.enable()` - Enable LIEF logging output

## Building from Source

The package includes LIEF as a git submodule and uses a two-stage build process:

```bash
# Clone with submodules
git clone --recursive https://github.com/Piebald-AI/node-lief.git
cd node-lief

# Install dependencies
pnpm install

# Build (this runs both stages automatically)
pnpm build
```

### Build Process Details

1. **Stage 1: Build LIEF library** (`pnpm build:lief`)
   - Runs `scripts/build-lief.sh`
   - Uses CMake + Ninja to build LIEF C++ library
   - Produces `lief-build/libLIEF.a` (or `LIEF.lib` on Windows)
   - Configured for minimal build (disables Python/Rust APIs, OAT, DEX, etc.)

2. **Stage 2: Build Node addon** (`node-gyp rebuild`)
   - Links against the pre-built LIEF static library
   - Compiles C++ sources in `src/` directory
   - Produces `build/Release/node_lief.node`

### Build Commands

```bash
# Full build (LIEF + addon)
pnpm build

# Clean build artifacts
pnpm clean

# Build only LIEF library
pnpm build:lief

# Create prebuilt binaries for distribution
pnpm prebuildify
```

### Build Requirements

- **CMake 3.15+** with Ninja generator
- **C++17 compiler** with RTTI support enabled
- **Git** for LIEF submodule
- **node-gyp** for native addon compilation

The build is configured in:
- `binding.gyp` - node-gyp configuration
- `scripts/build-lief.sh` - LIEF CMake configuration

## Supported Node.js Versions

- Node.js 14+ (BigInt support required)
- Node.js 16+ (recommended)
- All current LTS versions

## Platform Support

- **Linux** (x86-64, ARM64)
- **macOS** (Intel x86-64, Apple Silicon ARM64) - requires macOS 13.0+
- **Windows** (x86-64)

Prebuilt binaries are provided for common platforms via `prebuildify`. For unsupported platforms, the package will automatically compile from source.

## Performance

The Node.js bindings are compiled to native code with minimal overhead:

- Binary parsing: Near C++ native performance
- Symbol/section enumeration: Fast iteration via N-API
- Memory efficient: Smart pointers ensure proper cleanup
- No serialization overhead: Direct access to LIEF's C++ objects

For production use cases:
- Parsing typical executables: < 100ms
- Large binaries (100MB+): A few seconds
- Comparable performance to LIEF's Python bindings

## Advanced Usage

### Working with MachO Fat Binaries

MachO files can contain multiple architectures. Use `MachO.parse()` to handle them:

```javascript
const LIEF = require('node-lief');

// Parse as Fat binary
const fat = LIEF.MachO.parse('./universal-binary');
console.log(`Architectures: ${fat.size()}`);

// Access individual architectures
for (let i = 0; i < fat.size(); i++) {
  const binary = fat.at(i);
  console.log(`Arch ${i}: ${binary.format}`);
  // Work with binary...
}
```

### Modifying Section Content

```javascript
const binary = LIEF.parse('./binary');
const sections = binary.sections();

// Find and modify a section
const textSection = sections.find(s => s.name === '.text' || s.name === '__text');
if (textSection) {
  // Read content
  const content = textSection.content;

  // Modify content (as array or Buffer)
  const newContent = Buffer.from([0x90, 0x90, 0x90]);
  textSection.content = newContent;
  textSection.size = BigInt(newContent.length);

  // Write modified binary
  binary.write('./modified-binary');
}
```

### MachO Code Signature Removal

```javascript
const binary = LIEF.MachO.parse('./signed-macho').at(0);

if (binary.hasCodeSignature) {
  console.log('Removing code signature...');
  binary.removeSignature();
  binary.write('./unsigned-macho');
}
```

### Error Handling

```javascript
const LIEF = require('node-lief');

try {
  const binary = LIEF.parse('./binary');

  // Perform operations
  binary.patchAddress(0x1000n, [0x90, 0x90]);
  binary.write('./output');

} catch (error) {
  console.error('Error:', error.message);
  // Handle parse errors, invalid addresses, I/O errors, etc.
}
```

## Current Limitations

This is an actively developed project. Current limitations:

- **Format coverage**: ELF, PE, and MachO are well-supported; OAT, DEX, VDEX, and ART are not included in the build
- **API coverage**: Core functionality implemented; some advanced LIEF features not yet exposed
- **Debug info**: DWARF and PDB parsing not yet implemented
- **Async operations**: Currently synchronous only; async API planned
- **Streaming**: No support for streaming large files; entire binary loaded into memory

Contributions welcome! See CLAUDE.md for development guidance.

## Contributing

Contributions are welcome! This project is actively developed and there are many opportunities to expand functionality.

### Priority Areas

1. **Format-specific APIs**: Expose more ELF, PE, and MachO-specific features
2. **Debug information**: DWARF and PDB parsing support
3. **Async operations**: Add async/await API for I/O operations
4. **Documentation**: Usage examples, tutorials, API docs
5. **Performance**: Optimize hot paths, add benchmarks

### Development Setup

```bash
# Clone with submodules
git clone --recursive https://github.com/Piebald-AI/node-lief.git
cd node-lief

# Install and build
pnpm install
pnpm build

# Make changes to src/...

# Rebuild
pnpm build
```

See [CLAUDE.md](CLAUDE.md) for detailed development guidelines and architecture documentation.

### Project Structure

```
node-lief/
├── src/
│   ├── init.cpp              # Module initialization
│   ├── abstract/             # Format-agnostic API
│   │   ├── binary.{h,cpp}
│   │   ├── section.{h,cpp}
│   │   ├── segment.{h,cpp}
│   │   └── symbol.{h,cpp}
│   ├── elf/                  # ELF-specific
│   │   └── binary.{h,cpp}
│   ├── pe/                   # PE-specific
│   │   └── binary.{h,cpp}
│   └── macho/                # MachO-specific
│       ├── binary.{h,cpp}
│       ├── fat_binary.{h,cpp}
│       └── parse.cpp
├── lib/
│   ├── index.js              # Entry point
│   └── index.d.ts            # TypeScript definitions
├── scripts/
│   └── build-lief.sh         # LIEF build script
├── binding.gyp               # node-gyp configuration
└── LIEF/                     # Git submodule
```

### Adding New Features

See CLAUDE.md for detailed instructions on:
- Adding new methods to existing classes
- Creating new wrapper classes
- Working with LIEF types
- Memory management patterns
- Error handling conventions

## License

Apache License 2.0 (same as LIEF)

## Related Projects

- [LIEF Project](https://lief.quarkslab.com/) - The underlying C++ library
- [LIEF Documentation](https://lief.quarkslab.com/doc/index.html) - Comprehensive LIEF docs
- [LIEF GitHub](https://github.com/lief-project/LIEF) - LIEF source code
- [node-addon-api](https://github.com/nodejs/node-addon-api) - N-API wrapper used by this project

## Support and Resources

- **Issues**: Report bugs and request features on GitHub Issues
- **Documentation**: See CLAUDE.md, USAGE.md, and ARCHITECTURE.md
- **Examples**: Check USAGE.md and QUICK_START.md for usage examples
- **LIEF Help**: Refer to [LIEF documentation](https://lief.quarkslab.com/doc/) for underlying functionality

## Acknowledgments

This project is built on top of [LIEF](https://lief.quarkslab.com/) by Quarkslab. LIEF is a comprehensive library for parsing and manipulating executable formats, and this package aims to make that functionality easily accessible to the Node.js ecosystem.
