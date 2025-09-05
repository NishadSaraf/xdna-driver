/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_DEBUG_H_
#define _AMDXDNA_DEBUG_H_

#include <linux/kernel.h>
#include <linux/timer.h>

#include "amdxdna_mgmt.h"

#define AMDXDNA_DEBUG_FOOTER_SIZE	SZ_4K

struct amdxdna_debug_footer {
	u8			minor;
	u8			major;
	u8			type;
	u8			reserved1;
	u32			payload_version;
	u8			reserved2[56];
	u32			tail;
};

struct amdxdna_debug {
	bool				enabled;
	char				name[20];
	struct amdxdna_dev		*xdna;
	struct amdxdna_mgmt_dma_hdl	*dma_hdl;
	void			__iomem *io_base;
	int				irq;
	u32				msi_idx;
	u32				msi_address;
	u64				tail;
//	struct workqueue_struct	*wq;
//	struct work_struct	work;
//	struct timer_list	poll_timer;
};

int amdxdna_fw_log_init(struct amdxdna_dev *xdna);
int amdxdna_fw_log_fini(struct amdxdna_dev *xdna);
int amdxdna_fw_log_resume(struct amdxdna_dev *xdna);
int amdxdna_fw_log_suspend(struct amdxdna_dev *xdna);

#endif /* _AMDXDNA_DEBUG_H_ */
