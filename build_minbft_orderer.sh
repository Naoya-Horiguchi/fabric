THISDIR=$(readlink -f $(dirname $BASH_SOURCE))
export GO111MODULE=on

cd $THISDIR

if [ "$SGX_MODE" == HW ] ; then
	export SGX_MODE=HW
	TAG=1.4.1-minbft-hw
else
	export SGX_MODE=SIM
	TAG=1.4.1-minbft-sim
fi
echo "Build orderer container with Intel SGX in $SGX_MODE mode"

if [ ! -d /opt/intel ] ; then
	echo "You need install SGX SDK to /opt/intel"
	exit 1
fi

. /opt/intel/sgxsdk/environment

rm -rf .build
docker images | grep hyperledger/fabric-orderer | grep $TAG | awk '{print $3}' | sort | uniq | xargs -r docker rmi -f

rm -rf "$GOPATH/pkg/mod/github.com/hyperledger-labs"
rm -rf "$GOPATH/pkg/mod/github.com/!naoya-!horiguchi"

# update hyperledger/fabric-baseimage for build environment
docker build --tag=hyperledger/fabric-baseimage:minbft images/minbft || exit 1

[ ! "$GOPATH" ] && export GOPATH=$HOME/go

[ -d .build/docker/orderer ] && rm -rf .build/docker/orderer
mkdir -p .build/docker
ln -sf $GOPATH $THISDIR/.build/docker/orderer || exit 1
echo "===> go mod download github.com/hyperledger-labs/minbft"
go mod download github.com/hyperledger-labs/minbft || exit 1
MINBFTVER=$(ls -1t $GOPATH/pkg/mod/github.com/hyperledger-labs/ | head -1)

# MinBFT needs to run 'make build' to generate SGX related files. But currenty
# this is not kicked via 'go build' in the calling module, so explicitly do it here.
echo "===> MINBFTVER: $MINBFTVER"
pushd "$GOPATH/pkg/mod/github.com/hyperledger-labs/${MINBFTVER}" || exit 1
SGX_MODE=$SGX_MODE make clean
SGX_MODE=$SGX_MODE make || true
SGX_MODE=$SGX_MODE ./sample/build/keytool generate -u usig/sgx/enclave/libusig.signed.so -o sample/keys.yaml || exit 1
mkdir -p $THISDIR/minbft-artifacts/
cp usig/sgx/enclave/libusig.signed.so $THISDIR/minbft-artifacts/
cp sample/keys.yaml $THISDIR/minbft-artifacts/
popd
echo "---> make SGX_MODE=$SGX_MODE orderer-docker"
make V=1 SGX_MODE=$SGX_MODE orderer-docker || exit 1
echo "<--- make SGX_MODE=$SGX_MODE orderer-docker done"

NEW_ORDERER_IMAGE_ID=$(docker images | grep fabric-orderer | head -n1 | awk '{print $3}')

if [ ! "$NEW_ORDERER_IMAGE_ID" ] ; then
	echo Failed to build orderer-docker >&2
	exit 1
fi
echo "NEW_ORDERER_IMAGE_ID: $NEW_ORDERER_IMAGE_ID"

docker tag "$NEW_ORDERER_IMAGE_ID" hyperledger/fabric-orderer:1.4.1-minbft
docker build -f images/minbft/Dockerfile.push_usig_keys --tag=hyperledger/fabric-orderer:$TAG .
echo done
