# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020-2021 DAYUZIPU

if not is_linux
	build = false
	reason = 'only supported on linux'
endif

inc_dir = ''
if get_option('libpci-ep') != ''
	path = get_option('libpci-ep')
	lib_dir = path + '/lib'
	inc_dir = path + '/include'
	libpci_ep = cc.find_library('pci_ep',dirs: lib_dir, required: true)
else
	libpci_ep = cc.find_library('pci_ep', required: true)
endif
libyaml = cc.find_library('yaml', required: true)

if  not libyaml.found() or not cc.has_header('pci-ep.h')
	build = false
	reason = 'missing dependency, "libpci_ep"'
	subdir_done()
endif

sources = files(
		'agiep_dirty_log.c',
		'agiep_dma.c',
		'agiep_lib.c',
		'agiep_mng.c',
		'agiep_pci.c',
		'agiep_reg_poller.c',
		'agiep_virtio.c',
		'agiep_reg_expand.c',
		'agiep_vring_split_predict.c',
		'agiep_vring.c',
		'agiep_virtio_legacy.c',
		'agiep_vring_packed.c',
		'agiep_vring_packed_cache.c',
		'agiep_vring_split.c',
		'agiep_vring_split_cache.c',
    )

deps += ['kvargs', 'ring', 'eal', 'mempool', 'eventdev', 'rawdev', 'cfgfile']
ext_deps += [libpci_ep, libyaml]

includes += include_directories('../../raw/dpaa2_qdma')
if inc_dir != ''
	includes += include_directories(inc_dir)
endif

headers = files(
               'agiep_pci.h',
               'agiep_dma.h',
       )

install_headers(headers)


cflags += '-Werror'
cflags += '-Wdeprecated-declarations'
cflags += '-O3'
allow_experimental_apis = true
