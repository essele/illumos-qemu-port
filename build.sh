#!/bin/bash
#
# Copyright (c) 2011, Joyent Inc., All rights reserved.
#

for dir in seabios vgabios kvm/test; do
    cp roms/${dir}/config.mak.tmpl roms/${dir}/config.mak
done

PNGDIR="${PWD}/libpng-1.5.4"
PNGINC="${PNGDIR}/proto/usr/local/include"
PNGLIB="${PNGDIR}/proto/usr/local/lib"

if [[ ! -d ${PNGDIR} ]]; then
    (curl -k https://download.joyent.com/pub/kvm-cmd/libpng-1.5.4.tar.gz | \
        gtar -zxf -)
    if [[ $? != "0" || ! -d ${PNGDIR} ]]; then
        echo "Failed to get libpng."
        rm -rf ${PNGDIR}
        exit 1
    fi
fi

if [[ ! -e ${PNGLIB}/libpng.a ]]; then
    (cd ${PNGDIR} && \
        LDFLAGS=-m64 CFLAGS=-m64 ./configure --disable-shared && \
        make && \
        mkdir -p ${PNGDIR}/proto && \
        make DESTDIR=${PNGDIR}/proto install)
fi

   # --kerneldir=$(cd `pwd`/../kvm; pwd) \
echo "==> Running configure"
#    --enable-kvm-pit \
#    --disable-kvm-device-assignment \
#    --enable-trace-backend=dtrace \
#		--target-list=x86_64-softmmu \
#    --extra-cflags="-I${PNGDIR}/proto/usr/local/include -I/root/dev/kvm -DDEBUG_KVM -DDEBUG_IOPORT -DDEBUG_UNUSED_IOPORT -DDEBUG_IRQ" \
./configure \
    --extra-cflags="-I${PNGDIR}/proto/usr/local/include" \
    --extra-ldflags="-L${PNGDIR}/proto/usr/local/lib -lz -lm" \
    --prefix=/smartdc \
		--datadir=/roms \
    --audio-card-list=ac97 \
    --audio-drv-list= \
    --disable-bluez \
    --disable-brlapi \
    --disable-curl \
    --enable-debug \
    --enable-kvm \
    --enable-vnc-png \
    --disable-sdl \
    --disable-vnc-jpeg \
    --disable-vnc-sasl \
    --disable-vnc-tls \
    --enable-trace-backend=nop \
    --enable-spice \
    --disable-curses \
		--target-list="x86_64-softmmu" \
    --cpu=x86_64

if [[ $? != 0 ]]; then
	echo "Failed to configure, bailing"
	exit 1
fi


#
# Make sure ctf utilities are in our path
#
KERNEL_SOURCE=$(pwd)/../../illumos
CTFBINDIR=$KERNEL_SOURCE/usr/src/tools/proto/root_i386-nd/opt/onbld/bin/i386
export PATH=$PATH:$CTFBINDIR

echo "==> Make"
gmake
