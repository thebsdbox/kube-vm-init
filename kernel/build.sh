#!/usr/bin/env bash
set -euo pipefail

# Usage: ./build.sh <kernel-version>
# Example: JOBS=8 ./build.sh 6.12.1
# The configuration targets x86-64 and the script builds only bzImage.
# Set ARCH=x86_64 and CROSS_COMPILE to cross-compile from another host.

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
build_config="$build_dir/.config"
modular_options="$build_dir/modular-options.txt"
cp -- "$config" "$build_config"

# The kernel is built without loadable modules, and options selected as
# modules (=m) are left out rather than built in. Disabling MODULES on its own
# would make Kconfig promote every =m option to =y. Instead, resolve the
# configuration with module support first, switch every =m option off, and
# then disable module support.
"$source_dir/scripts/config" --file "$build_config" --enable MODULES
make -C "$source_dir" O="$build_dir" olddefconfig
{ grep -E '^CONFIG_[A-Za-z0-9_]+=m$' "$build_config" || true; } |
    sed 's/=m$/=y/' > "$modular_options"
sed -i -E 's/^(CONFIG_[A-Za-z0-9_]+)=m$/# \1 is not set/' "$build_config"
"$source_dir/scripts/config" --file "$build_config" --disable MODULES
make -C "$source_dir" O="$build_dir" olddefconfig

# Fail if Kconfig would still build any former module into the kernel.
if [[ -s "$modular_options" ]] && grep -Fx -f "$modular_options" "$build_config"; then
    echo "The options above resolve to modules (=m) but would be built into the" \
        "kernel. Set them to =y in $config to build them in, or disable the" \
        "options that enable them." >&2
    exit 1
fi

echo "Building Linux $version bzImage with $(nproc) parallel jobs (no modules)..."
make -C "$source_dir" O="$build_dir" -j"$(nproc)" bzImage
echo "Kernel build complete: $build_dir"
echo "Bootable image: $build_dir/arch/x86/boot/bzImage"
