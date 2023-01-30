cmd_testpipeline = gcc -o testpipeline  -pthread -I/home/yyy/firmware-toe/lib/librte_eal/linux/eal/include  -march=armv8-a+crc -mtune=cortex-a72 -mtls-dialect=trad -DRTE_MACHINE_CPUFLAG_NEON -DRTE_MACHINE_CPUFLAG_CRC32  -I/home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include -DRTE_USE_FUNCTION_VERSIONING -include /home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -O3 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wno-error=pedantic -Werror -Wimplicit-fallthrough=2 -Wno-format-truncation -O3 -Wno-unused-parameter -Wno-discarded-qualifiers -Wno-undef -Wno-switch -fPIC -I/home/yyy/firmware-toe/../agile_install/include/ -shared main.o config.o init.o runtime.o pipeline_stub.o pipeline_hash.o pipeline_lpm.o pipeline_lpm_ipv6.o pipeline_acl.o -L/home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/lib -Wl,-lrte_flow_classify -Wl,--whole-archive -Wl,-lrte_pipeline -Wl,--no-whole-archive -Wl,--whole-archive -Wl,-lrte_table -Wl,--no-whole-archive -Wl,--whole-archive -Wl,-lrte_port -Wl,--no-whole-archive -Wl,-lrte_pdump -Wl,-lrte_distributor -Wl,-lrte_ip_frag -Wl,-lrte_meter -Wl,-lrte_fib -Wl,-lrte_rib -Wl,-lrte_lpm -Wl,-lrte_acl -Wl,-lrte_jobstats -Wl,-lrte_metrics -Wl,-lrte_bitratestats -Wl,-lrte_latencystats -Wl,-lrte_power -Wl,-lrte_efd -Wl,-lrte_bpf -Wl,-lrte_ipsec -Wl,--whole-archive -Wl,-lrte_cfgfile -Wl,-lrte_gro -Wl,-lrte_gso -Wl,-lrte_hash -Wl,-lrte_member -Wl,-lrte_vhost -Wl,-lrte_kvargs -Wl,-lrte_mbuf -Wl,-lrte_net -Wl,-lrte_ethdev -Wl,-lrte_bbdev -Wl,-lrte_cryptodev -Wl,-lrte_security -Wl,-lrte_compressdev -Wl,-lrte_eventdev -Wl,-lrte_rawdev -Wl,-lrte_timer -Wl,-lrte_mempool -Wl,-lrte_stack -Wl,-lrte_mempool_ring -Wl,-lrte_mempool_octeontx2 -Wl,-lrte_ring -Wl,-lrte_pci -Wl,-lrte_eal -Wl,-lrte_cmdline -Wl,-lrte_reorder -Wl,-lrte_sched -Wl,-lrte_rcu -Wl,-lrte_common_cpt -Wl,-lrte_common_octeontx2 -Wl,-lrte_common_dpaax -Wl,-lrte_common_agiep -Wl,-lrte_bus_pci -Wl,-lrte_bus_vdev -Wl,-lrte_bus_dpaa -Wl,-lrte_bus_fslmc -Wl,-lrte_mempool_bucket -Wl,-lrte_mempool_stack -Wl,-lrte_mempool_dpaa -Wl,-lrte_mempool_dpaa2 -Wl,-lrte_pmd_af_packet -Wl,-lrte_pmd_agile_ep -Wl,-lpci_ep -Wl,-lyaml -Wl,-lrte_pmd_atlantic -Wl,-lrte_pmd_dpaa -Wl,-lrte_pmd_dpaa2 -Wl,-lrte_pmd_enetc -Wl,-lrte_pmd_failsafe -Wl,-lrte_pmd_hinic -Wl,-lrte_pmd_memif -Wl,-lrte_pmd_null -Wl,-lrte_pmd_octeontx2 -Wl,-lrte_pmd_pfe -Wl,-lrte_pmd_ring -Wl,-lrte_pmd_tap -Wl,-lrte_pmd_vdev_netvsc -Wl,-lrte_pmd_virtio -Wl,-lrte_pmd_vhost -Wl,-lrte_bus_vmbus -Wl,-lrte_pmd_netvsc -Wl,-lrte_pmd_bbdev_null -Wl,-lrte_pmd_bbdev_fpga_lte_fec -Wl,-lrte_pmd_bbdev_turbo_sw -Wl,-lrte_pmd_null_crypto -Wl,-lrte_pmd_nitrox -Wl,-lrte_pmd_octeontx_crypto -Wl,-lrte_pmd_octeontx2_crypto -Wl,-lrte_pmd_crypto_scheduler -Wl,-lrte_pmd_dpaa2_sec -Wl,-lrte_pmd_dpaa_sec -Wl,-lrte_pmd_caam_jr -Wl,-lrte_pmd_virtio_crypto -Wl,-lrte_pmd_octeontx_zip -Wl,-lrte_pmd_skeleton_event -Wl,-lrte_pmd_sw_event -Wl,-lrte_pmd_dsw_event -Wl,-lrte_pmd_dpaa_event -Wl,-lrte_pmd_dpaa2_event -Wl,-lrte_pmd_octeontx2_event -Wl,-lrte_pmd_opdl_event -Wl,-lrte_rawdev_skeleton -Wl,-lrte_rawdev_dpaa2_cmdif -Wl,-lrte_rawdev_dpaa2_qdma -Wl,-lrte_bus_ifpga -Wl,-lrte_rawdev_ntb -Wl,-lrte_rawdev_octeontx2_dma -Wl,--no-whole-archive -Wl,-lrt -Wl,-lm -Wl,-ldl -Wl,-export-dynamic -Wl,-export-dynamic -Wl,-export-dynamic -L/home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/lib -Wl,--as-needed -Wl,-lnuma -L/home/yyy/firmware-toe/../agile_install/lib/libpci_ep.a -Wl,-lyaml -Wl,-Map=testpipeline.map -Wl,--cref 
