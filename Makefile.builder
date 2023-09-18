ifeq ($(filter $(DIST),centos7 centos8 centos-stream8 fc32),)
RPM_SPEC_FILES := rpm-oxide.spec
endif
ifeq ($(filter $(DIST),jessie buster bullseye),)
DEBIAN_BUILD_DIRS = debian
endif

# vim: set ft=make:
