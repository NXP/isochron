#!/bin/bash

CC="$1"
CFLAGS="$2"
EXTRA_CFLAGS=""

${CC} ${CFLAGS} -x c -c -o $(mktemp) - > /dev/null 2>&1 << EOF
#include <linux/net_tstamp.h>

int main(void)
{
	return SOF_TIMESTAMPING_OPT_TX_SWHW;
}
EOF
if [ $? = 0 ]; then
	EXTRA_CFLAGS="${EXTRA_CFLAGS} -DHAVE_TX_SWHW"
fi

echo ${EXTRA_CFLAGS}
