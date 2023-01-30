export RTE_TARGET=arm64-agile-linuxapp-gcc
export RTE_SDK=/home/yyy/firmware-toe

cd /home/yyy/firmware-toe
./build-agiep.sh

if [ $? -eq 0 ];then
	echo "DPDK Compile Finish"
	cd /home/yyy/firmware-toe/examples/l3fwd
	make clean ; make T=arm64-agile-linuxapp-gcc
else
	cd /home/yyy/firmware-toe/examples/l3fwd
fi

