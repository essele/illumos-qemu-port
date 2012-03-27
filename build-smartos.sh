#!/bin/bash

#
# Simple script to build the /smartdc2 directory structure
#
ZONEDIR="`pwd`/zone_dataset"

#
# clean the old one
#
rm -fr ${ZONEDIR}

#
# Initial setup
#
mkdir ${ZONEDIR}
chmod 700 ${ZONEDIR}
mkdir ${ZONEDIR}/root

# install all the stuff we need...
make DESTDIR="${ZONEDIR}/root" install || exit 1

#
# make the lib dir, if needed
#
if [ ! -d "${ZONEDIR}/root/smartdc2/lib" ]; then
  mkdir ${ZONEDIR}/root/smartdc2/lib
fi

#
# Now figure out the libs we need to copy...
#
LIBS=$(ldd x86_64-softmmu/qemu-system-x86_64 | grep "=>" | awk '{ print $3 }')

for LIB in $LIBS; do
  ISOPT=$(echo "${LIB}" | egrep -e "^/opt/")
  if test -n "$ISOPT"; then
    echo "Copying ${LIB}"
    cp ${LIB} ${ZONEDIR}/root/smartdc2/lib || exit 1
  fi
done

#
# And the startvm.zone script
#
cp startvm.zone ${ZONEDIR}/root/ || exit 1

