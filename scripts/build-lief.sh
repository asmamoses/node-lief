#!/bin/bash
set -e

# Build LIEF library with CMake before building the Node addon

BUILD_DIR="lief-build"
LIEF_SRC="LIEF"

# Initialize submodules if running in GitHub Actions or /usr/workspace exists
if [ -n "$GITHUB_ACTIONS" ] || [ -d "/usr/workspace" ]; then
  echo "Running in CI environment, configuring git and initializing submodules..."
  git config --global --add safe.directory /usr/workspace
  git config --global --add safe.directory /usr/workspace/LIEF
  git submodule update --init --recursive

  # Install CMake on Linux if needed
  if [[ $(uname -s) == "Linux" ]]; then
    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
      x86_64)
        CMAKE_ARCH="x86_64"
        ;;
      aarch64|arm64)
        CMAKE_ARCH="aarch64"
        ;;
      *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
    esac
    echo "Detected architecture: $ARCH (CMake: $CMAKE_ARCH)"

    echo "Installing CMake 4.1.2 for $CMAKE_ARCH..."
    mkdir -p /cmake
    curl -fsSL https://github.com/Kitware/CMake/releases/download/v4.1.2/cmake-4.1.2-linux-${CMAKE_ARCH}.sh -o install-cmake.sh
    chmod +x install-cmake.sh
    ./install-cmake.sh --skip-license --prefix=/cmake
    rm install-cmake.sh
    export PATH="/cmake/bin:$PATH"
    echo "CMake installed to /cmake"
  fi
fi

echo "Building LIEF library..."

# Use Ninja generator only in local development, not in CI
if [ -z "$GITHUB_ACTIONS" ] && [ ! -d "/usr/workspace" ]; then
  export CMAKE_GENERATOR="Ninja"
  echo "Using Ninja generator for local build..."
fi

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure LIEF with CMake (minimal build for speed)
cmake "../$LIEF_SRC" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
  -DLIEF_PYTHON_API=OFF \
  -DLIEF_RUST_API=OFF \
  -DLIEF_C_API=OFF \
  -DLIEF_OAT=OFF \
  -DLIEF_DEX=OFF \
  -DLIEF_VDEX=OFF \
  -DLIEF_ART=OFF \
  -DLIEF_ASM=OFF \
  -DLIEF_TESTS=OFF \
  -DLIEF_EXAMPLES=OFF \
  -DLIEF_DOC=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON

# Build LIEF
cmake --build . --config Release

cd ..

echo "LIEF build complete!"
