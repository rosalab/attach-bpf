BASE_PROJ ?= $(shell pwd)
LINUX ?= ${BASE_PROJ}/linux
SSH_PORT ?= "64000"
NET_PORT ?= "64001"
GDB_PORT ?= "64002"
DOCKER ?= attach-bpf
.ALWAYS:

all: vmlinux 

docker: .ALWAYS
	docker buildx build --network=host --progress=plain -t ${DOCKER} .

qemu-run: 
	docker run --privileged --rm \
	--device=/dev/kvm:/dev/kvm \
	-v ${BASE_PROJ}:/linux-dev-env -v ${LINUX}:/linux \
	-w /linux \
	-p 127.0.0.1:${SSH_PORT}:52222 \
	-p 127.0.0.1:${NET_PORT}:52223 \
	-p 127.0.0.1:${GDB_PORT}:1234 \
	-it ${DOCKER}:latest \
	/linux-dev-env/q-script/yifei-q -s

# connect running qemu by ssh
qemu-ssh:
	ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -t root@127.0.0.1 -p ${SSH_PORT}

vmlinux: 
	docker run --rm -v ${LINUX}:/linux -w /linux ${DOCKER}  make -j`nproc` bzImage 

headers-install: 
	docker run --rm -v ${LINUX}:/linux -w /linux ${DOCKER}  make -j`nproc` headers_install 

modules-install: 
	docker run --rm -v ${LINUX}:/linux -w /linux ${DOCKER}  make -j`nproc` modules
	docker run --rm -v ${LINUX}:/linux -w /linux ${DOCKER}  make -j`nproc` modules_install

kernel:
	docker run --rm -v ${LINUX}:/linux -w /linux ${DOCKER}  make -j`nproc` 

linux-clean:
	docker run --rm -v ${LINUX}:/linux -w /linux ${DOCKER} make distclean

enter-docker:
	docker run --rm -v ${BASE_PROJ}:/linux-dev-env -w /linux-dev-env -it ${DOCKER} /bin/bash

libbpf:
	docker run --rm -v ${LINUX}:/linux -w /linux/tools/lib/bpf ${DOCKER} make -j`nproc`
libbpf-clean:
	docker run --rm -v ${LINUX}:/linux -w /linux/tools/lib/bpf ${DOCKER} make clean -j`nproc`
bpftool:
	docker run --rm -v ${LINUX}:/linux -w /linux/tools/bpf/bpftool ${DOCKER} make -j`nproc`
bpftool-clean:
	docker run --rm -v ${LINUX}:/linux -w /linux/tools/bpf/bpftool ${DOCKER} make clean -j`nproc`
