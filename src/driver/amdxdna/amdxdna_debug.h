/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_DEBUG_H_
#define _AMDXDNA_DEBUG_H_

#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

#include "amdxdna_mgmt.h"

#define AMDXDNA_DEBUG_FOOTER_SIZE	SZ_4K
#define AMDXDNA_DEBUG_FW_LOG_NAME	"xdna_fw_log"
#define AMDXDNA_FW_LOG_MSG_ALIGN	8
#define AMDXDNA_POLL_INTERVAL_MS	50

struct amdxdna_debug_footer {
	u8				minor;
	u8				major;
	u8				type;
	u8				reserved1;
	u32				payload_version;
	u8				reserved2[56];
	u32				tail;
} __packed;

struct amdxdna_debug {
	bool				enabled;
	char				name[20];
	struct amdxdna_dev		*xdna;
	struct amdxdna_mgmt_dma_hdl	*dma_hdl;
	struct wait_queue_head		wait;
	bool				polling;
	struct work_struct		work;
	struct timer_list		timer;
	void			__iomem *io_base;
	int				irq;
	u32				msi_idx;
	u32				msi_address;
	u8				minor;
	u8				major;
	u32				payload_version;
	spinlock_t			lock;
	u64				tail;
	u64				head;
};

int amdxdna_fw_log_init(struct amdxdna_dev *xdna);
int amdxdna_fw_log_fini(struct amdxdna_dev *xdna);
int amdxdna_fw_log_resume(struct amdxdna_dev *xdna);
int amdxdna_fw_log_suspend(struct amdxdna_dev *xdna);
void amdxdna_debug_enable_polling(struct amdxdna_debug *debug_hdl, bool enable);

#endif /* _AMDXDNA_DEBUG_H_ */
