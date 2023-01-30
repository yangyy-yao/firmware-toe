# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Intel Corporation

#libfstack = cc.find_library('fstack', required: true)
libcrypto = cc.find_library('crypto', required: true)
libssl = cc.find_library('ssl', required: true)

sources = files('toe_engine.c',
		'toe_dev.c',
		'toe_dma.c',
		'toe_pcie.c',
		)
deps += ['common_agiep', 'bus_vdev', 'pmd_dpaa2']
#ext_deps += [libfstack, libcrypto, libssl]
ext_deps += [libcrypto, libssl]

includes += include_directories('../dpaa2')
includes += include_directories('../dpaa2/mc')
includes += include_directories('../../bus/fslmc')
includes += include_directories('../../common/dpaax')
includes += include_directories('../../bus/fslmc/mc')
includes += include_directories('../../bus/fslmc/portal')
includes += include_directories('../../bus/fslmc/qbman/include')
includes += include_directories('../../../lib/librte_tcpstack')
cflags += '-O3'


headers = files('toe_engine.h', 'toe_dev.h', 'toe_dma.h', 'toe_pcie.h', 'toe_engine.h')
install_headers(headers)
aallow_experimental_apis = true
