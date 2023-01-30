# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Intel Corporation

sources = files('agiep_accel_engine.c',
		'agiep_accel_net.c',
		'agiep_accel_soft.c',
		'agiep_ctrl.c',
		'agiep_frep_loopback_net.c',
		'agiep_frep_loopback_rxtx.c',
		'agiep_frep_task.c',
		'agiep_mbuf_iov.c',
		'agiep_task.c',
		'agiep_vdev.c',
		'agiep_vendor_ctrl.c',
		'agiep_vendor_net.c',
		'agiep_vendor_port.c',
		'agiep_vendor_regpoll.c',
		'agiep_virtio_ctrl.c',
		'agiep_virtio_net.c',
		'agiep_virtio_port.c',
		'agiep_virtio_rxtx.c',
		)
deps += ['common_agiep', 'bus_vdev', 'pmd_dpaa2']

includes += include_directories('../dpaa2')
includes += include_directories('../dpaa2/mc')
includes += include_directories('../../bus/fslmc')
includes += include_directories('../../common/dpaax')
includes += include_directories('../../bus/fslmc/mc')
includes += include_directories('../../bus/fslmc/portal')
includes += include_directories('../../bus/fslmc/qbman/include')
cflags += '-O3'
allow_experimental_apis = true
