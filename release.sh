#!/bin/bash
mkdir -p release/share-coin
cd release
../configure --libdir=/src/share-coin/release/share-coin --bindir=/src/share-coin/release/share-coin --sbindir=/src/share-coin/release/share-coin --docdir=/src/share-coin/release/share-coin --with-libshare=/h/src/sharelib/build
make
make install
tar -cpf sharecoin-`arch`.tar share-coin
gzip -f sharecoin-`arch`.tar
