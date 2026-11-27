#!/usr/bin/env bash
set -euo pipefail

# Usage: ./build.sh <kernel-version>
# Example: JOBS=8 ./build.sh 6.12.1
# ARCH and CROSS_COMPILE can be supplied for cross-compilation.

if [[ $# -ne 1 || ! $1 =~ ^([3-9]|[1-9][0-9]+)\.[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Usage: $0 <kernel-version> (for example, 6.12.1)" >&2
    exit 1
fi

version=$1
major=${version%%.*}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
config="$script_dir/.config"
source_dir="$script_dir/linux-$version"
build_dir="$script_dir/build-$version"
archive="$script_dir/linux-$version.tar.xz"
url="https://cdn.kernel.org/pub/linux/kernel/v${major}.x/linux-$version.tar.xz"

if [[ ! -f "$config" ]]; then
    echo "Missing kernel configuration: $config" >&2
    exit 1
fi

for tool in curl tar xz make; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required command not found: $tool" >&2
        exit 1
    fi
done

# Download atomically so an interrupted transfer is never reused.
if [[ ! -f "$archive" ]]; then
    trap 'rm -f -- "$archive.part"' EXIT
    echo "Downloading Linux $version..."
    curl --fail --location --retry 3 --output "$archive.part" "$url"
    mv -- "$archive.part" "$archive"
    trap - EXIT
fi

# Extract into a temporary directory to avoid reusing a partial extraction.
if [[ ! -d "$source_dir" ]]; then
    extract_dir=$(mktemp -d "$script_dir/.extract-XXXXXX")
    trap 'rm -rf -- "$extract_dir"' EXIT
    echo "Extracting Linux $version..."
    tar -xJf "$archive" -C "$extract_dir"
    mv -- "$extract_dir/linux-$version" "$source_dir"
    rmdir -- "$extract_dir"
    trap - EXIT
fi

mkdir -p -- "$build_dir"
cp -- "$config" "$build_dir/.config"

# Keep the supplied configuration intact, but build module-selected features
# as disabled: no modules are compiled or installed.
"$source_dir/scripts/config" --file "$build_dir/.config" --disable MODULES
make -C "$source_dir" O="$build_dir" olddefconfig

echo "Building Linux $version with $(nproc) parallel jobs (no modules)..."
make -C "$source_dir" O="$build_dir" -j$(nproc) all
echo "Kernel build complete: $build_dir"
echo "On x86, the bootable image is $build_dir/arch/x86/boot/bzImage"