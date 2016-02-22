## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include

noinst_dynamicpreprocessordir = ${libdir}/snort_dynamicpreprocessor

noinst_dynamicpreprocessor_LTLIBRARIES = libsf_modsecurity_preproc.la

libsf_modsecurity_preproc_la_LDFLAGS = -export-dynamic

# BUILT_SOURCES = \
# sf_dynamic_preproc_lib.c  \
# sfPolicyUserData.c

nodist_libsf_modsecurity_preproc_la_SOURCES = \
sf_dynamic_preproc_lib.c \
sfPolicyUserData.c

libsf_modsecurity_preproc_la_SOURCES = \
spp_modsecurity.c \
spp_modsecurity.h

# EXTRA_DIST = \
# spp_example.c \
# sf_preproc_info.h

all-local: $(LTLIBRARIES)
	$(MAKE) DESTDIR=`pwd`/../build install-dynamicpreprocessorLTLIBRARIES
