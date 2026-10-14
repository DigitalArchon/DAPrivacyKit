#!/bin/bash
# Makes the wallets in this folder with KWallet's own backend library (make-wallet.cpp), in a
# clean Arch container, so the app's reader (src/daprivacyscanner/kwallet.py) is tested against
# what KWallet really writes:
#   podman run --rm -v "$PWD/tests/samples/kwallet:/out:Z" docker.io/library/archlinux:latest /out/build.sh
# The new wallets land in tests/samples/kwallet/wallets/ (owned by the container's user; copy them
# out with `podman unshare`). Each one is checked to open with its password and not with another.
set -e
pacman -Syu --noconfirm -q kwallet gcc git pkgconf gpgmepp qt6-base >/dev/null 2>&1 || pacman -Syu --noconfirm -q kwallet gcc git pkgconf gpgme qt6-base >/dev/null
ver=$(pacman -Q kwallet | awk '{print $2}' | cut -d- -f1)
echo "kwallet $ver"
git clone -q --depth 1 --branch v$ver https://invent.kde.org/frameworks/kwallet.git /src
B=/src/src/runtime/kwalletbackend
printf '#define KWALLETBACKEND_EXPORT __attribute__((visibility("default")))\n' > /tmp/kwalletbackend_export.h
ls /usr/lib/libKF6WalletBackend.so* 
ls /usr/include/gpgme++/key.h
g++ -std=c++20 -fPIC -DHAVE_GPGMEPP -I/tmp -I$B -I/usr/include/KF6/KWallet $(pkg-config --cflags Qt6Core Qt6Gui) \
    /out/make-wallet.cpp -o /tmp/make-wallet /usr/lib/libKF6WalletBackend.so.6 $(pkg-config --libs Qt6Core) -lgpgmepp
useradd -m w
mkdir -p /out/wallets && chown w /out/wallets
for pw in "" "correct horse"; do
  n=$([ -z "$pw" ] && echo blank || echo protected)
  runuser -u w -- env XDG_DATA_HOME=/tmp/wd-$n QT_QPA_PLATFORM=offscreen /tmp/make-wallet $n "$pw"
  cp /tmp/wd-$n/kwalletd/$n.kwl /tmp/wd-$n/kwalletd/$n.salt /out/wallets/
done
ls -la /out/wallets
