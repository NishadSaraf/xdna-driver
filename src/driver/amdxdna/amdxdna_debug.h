/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_DEBUG_H_
#define _AMDXDNA_DEBUG_H_

#include <linux/kernel.h>
#include <linux/timer.h>

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
	struct amdxdna_dev	*xdna;
//	struct workqueue_struct	*wq;
//	struct work_struct	work;
//	struct timer_list	poll_timer;
	u32			msi_idx;
	u32			msi_address;
	u64			tail;
	bool			enabled;
};

int amdxdna_fw_log_init(struct amdxdna_dev *xdna);
void amdxdna_fw_log_fini(struct amdxdna_dev *xdna);
void amdxdna_fw_log_resume(struct amdxdna_dev *xdna);
void amdxdna_fw_log_suspend(struct amdxdna_dev *xdna);

#endif /* _AMDXDNA_DEBUG_H_ */
