BUILDDIR=${1:-/tmp/build}
python3 secrets_to_c_header.py /secrets/global.secrets ${HSM_PIN} ${PERMISSIONS}
make BUILDDIR=${BUILDDIR}
make BUILDIR=${BUILDIR} clangd-db
cp ${BUILDDIR}/hsm.elf ${BUILDDIR}/hsm.bin ${BUILDDIR}/hsm.map  ${BUILDDIR}/*.su /out
