// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <net/libeth/xdp.h>

#include "priv.h"

/* Tx buffer completion */

DEFINE_STATIC_CALL_NULL(bulk, libeth_xdp_return_buff_bulk);
DEFINE_STATIC_CALL_NULL(xsk, libeth_xsk_buff_free_slow);

void libeth_tx_complete_any(struct libeth_sqe *sqe, struct libeth_cq_pp *cp)
{
	if (sqe->type >= __LIBETH_SQE_XDP_START)
		__libeth_xdp_complete_tx(sqe, cp, static_call(bulk),
					 static_call(xsk));
	else
		libeth_tx_complete(sqe, cp);
}
EXPORT_SYMBOL_NS_GPL(libeth_tx_complete_any, LIBETH);

void libeth_attach_xdp(const struct libeth_xdp_ops *ops)
{
	static_call_update(bulk, ops ? ops->bulk : NULL);
	static_call_update(xsk, ops ? ops->xsk : NULL);
}
EXPORT_SYMBOL_NS_GPL(libeth_attach_xdp, LIBETH);
