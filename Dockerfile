# Build a docker container for re-hosting with FirmSolo

# Build: docker build -t fs .
# Run: docker run -v $(pwd):/output --rm -it --privileged fs /bin/bash

FROM firmsolo_dev:latest

# Install dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
	build-essential \
	zlib1g-dev \
	pkg-config \
	libglib2.0-dev \
	binutils-dev \
	libboost-all-dev \
	autoconf \
	libtool \
	libssl-dev \
	libpixman-1-dev \
	libpython3-dev \
	python3-pip \
	python3-capstone \
	python-is-python3 \
	virtualenv \
	sudo \
	gcc \
	make \
	g++ \
	python3 \
	python2 \
	flex \
	bison \
	dwarves \
	kmod \
	universal-ctags \
	kpartx \
	fdisk \
	fakeroot \
	git \
	dmsetup \
	netcat-openbsd \
	nmap \
	python3-psycopg2 \
	snmp \
	uml-utilities \
	util-linux \
	vlan \
	busybox-static \
	postgresql \
	wget \
	cscope \
	gcc-5-mips-linux-gnu \
	gcc-5-mipsel-linux-gnu \
	qemu \
	qemu-system-arm \
	qemu-system-mips \
	qemu-system-mipsel \
	qemu-utils

# Ingnore pip's warnings for root
ENV PIP_ROOT_USER_ACTION=ignore

RUN pip3 install ply anytree sympy requests pexpect scipy tqdm

# Install binwalk also patch a bug with sasquatch
RUN git clone -b v2.3.2 --depth 1 https://github.com/ReFirmLabs/binwalk.git /root/binwalk && \
	cd /root/binwalk && \
	sed -i 's/cd sasquatch \&\& \$SUDO .\/build.sh/cd sasquatch \&\& wget https:\/\/github.com\/devttys0\/sasquatch\/pull\/51.patch \&\& patch -p1 <51.patch \&\& \$SUDO .\/build.sh/' ./deps.sh && \
	sed -i '254d' ./deps.sh && \
	./deps.sh --yes && \
	python3 ./setup.py install && \
	pip3 install pylzma && \
	pip3 install git+https://github.com/ahupp/python-magic && \
	pip3 install git+https://github.com/sviehb/jefferson

RUN git clone https://github.com/BUseclab/TriforceAFL.git /TriforceAFL && \
	cd /TriforceAFL && \
	make

RUN git clone https://github.com/BUseclab/TriforceLinuxSyscallFuzzer.git /TriforceLinuxSyscallFuzzer && \
	cd TriforceLinuxSyscallFuzzer && \
	./compile_harnesses.sh

RUN git clone --recursive https://github.com/BUseclab/firmadyne.git /firmadyne

RUN service postgresql start && \
	sudo -u postgres createuser firmadyne && \
	sudo -u postgres createdb -O firmadyne firmware && \
	sudo -u postgres psql -d firmware < /firmadyne/database/schema && \
	echo "ALTER USER firmadyne PASSWORD 'firmadyne'" | sudo -u postgres psql

# Install FirmSolo
RUN git clone --recursive https://github.com/BUseclab/FirmSolo.git /FirmSolo && \
	cd /FirmSolo && \
	git clone https://github.com/BUseclab/FirmSolo-data.git && \
	mv ./FirmSolo-data/buildroot_fs.tar.gz . && rm -rf ./FirmSolo-data && \
	tar xvf buildroot_fs.tar.gz && rm buildroot_fs.tar.gz

# Set the symlinks for mips gcc-5
RUN ln -s /bin/mips-linux-gnu-gcc-5 /bin/mips-linux-gnu-gcc && \
	ln -s /bin/mipsel-linux-gnu-gcc-5 /bin/mipsel-linux-gnu-gcc

ENTRYPOINT ["/bin/bash", "-l", "-c"]
