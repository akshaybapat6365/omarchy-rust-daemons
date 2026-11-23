# Maintainer: Akshay Bapat <https://github.com/akshaybapat6365>
pkgname=omarchy-rust-daemons
pkgver=0.1.0
pkgrel=1
pkgdesc='Native Rust desktop telemetry, screenshot gallery, and omnibar search daemons (vitalsd, screenshotd, everythingd)'
arch=('x86_64' 'aarch64')
url='https://github.com/akshaybapat6365/omarchy-rust-daemons'
license=('MIT')
depends=('gcc-libs' 'glibc')
makedepends=('cargo')
optdepends=(
  'wl-clipboard: clipboard image copy in screenshotd'
  'hyprland: window & workspace indexing in everythingd'
  'tmux: session/pane indexing in everythingd'
)
source=()

build() {
  cd "${startdir}"
  cargo build --release --workspace --locked
}

package() {
  local srcroot="${startdir}"
  for bin in vitalsd screenshotd everythingd; do
    install -Dm755 "$srcroot/target/release/$bin" "$pkgdir/usr/bin/$bin"
  done
  install -Dm644 "$srcroot/LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
