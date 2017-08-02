# Usage: package.sh darwin 3.3.0

CURR_DIR=${PWD##*/}

if [ "$CURR_DIR" != "build" ];then
	echo "Run this script from 'build' directory"
	exit;
fi

TYPE=$1
VERSION=$2

if [ "$TYPE" = "" ] || [ "$VERSION" = "" ];then
	echo "Usage: $0 <type> version>"
	echo "  example: $0 darwin 3.3.0"
	exit;
fi

PACK=ripe-$VERSION-x86_64-$TYPE

if [ -d "$PACK" ];then
	echo "$PACK already exist. Remove $PACK first"
	exit;
fi


cmake -DCMAKE_BUILD_TYPE=Release ..
make

mkdir $PACK
cp ripe-$VERSION $PACK/ripe

if [ -f "libripe.$VERSION.dylib" ];then
	cp libripe.$VERSION.dylib $PACK/
	cd $PACK
	ln -s libripe.$VERSION.dylib libripe.dylib
elif [ -f "libripe.so.$VERSION" ];then
	cp libripe.so.$VERSION $PACK/
	cd $PACK
	ln -s libripe.so.$VERSION libripe.so
	cp /usr/lib64/libstdc++.so.6.0.22 $PACK/
	ln -s libstdc++.so.6.0.22 libstdc++.so.6
fi
cd ..


