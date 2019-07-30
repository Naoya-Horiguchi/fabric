FROM hyperledger/fabric-baseimage:amd64-0.4.15
RUN apt-get update
RUN apt-get install -y libssl1.0.0

ADD https://download.01.org/intel-sgx/linux-2.3.1/ubuntu16.04/sgx_linux_x64_sdk_2.3.101.46683.bin /opt
ADD https://download.01.org/intel-sgx/linux-2.3.1/ubuntu16.04/libsgx-enclave-common_2.3.101.46683-1_amd64.deb /opt

RUN bash -c "chmod +x /opt/sgx_linux_x64_sdk_2.3.101.46683.bin ; printf 'no\n/opt/intel\n' | /opt/sgx_linux_x64_sdk_2.3.101.46683.bin"

RUN apt-get update -q -q && \
  apt-get install wget python git patch build-essential ocaml automake autoconf libtool libssl-dev libcurl4-openssl-dev protobuf-compiler protobuf-c-compiler libprotobuf-dev libprotobuf-c0-dev alien uuid-dev libxml2-dev cmake pkg-config --yes --force-yes
RUN mkdir -p /tmp/icls && \
  cd /tmp/icls && \
   wget -q http://registrationcenter-download.intel.com/akdlm/irc_nas/11414/iclsClient-1.45.449.12-1.x86_64.rpm && \
   alien --scripts iclsClient-1.45.449.12-1.x86_64.rpm && \
   dpkg -i iclsclient_1.45.449.12-2_amd64.deb && \
 rm -rf /tmp/icls

RUN dpkg -i /opt/libsgx-enclave-common_2.3.101.46683-1_amd64.deb
RUN cat /opt/Intel/iclsClient/log/iclsClient.log
