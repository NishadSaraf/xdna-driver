// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/moduleparam.h>
#include <linux/sizes.h>
#include <linux/slab.h>

#include "amdxdna_drm.h"
#include "amdxdna_debug.h"

u64 fw_log_size = SZ_1M;
module_param(fw_log_size, ullong, 0444);
MODULE_PARM_DESC(fw_log_size, "Size of firmware log. Default 1MB. Min 8KB, Max 4MB");

u8 fw_log_level = 1;
module_param(fw_log_level, byte, 0444);
MODULE_PARM_DESC(fw_log_level,
		 " Firmware log verbosity: 0: NONE 1: ERROR (Default) 2: WARN 3: INFO 4: DEBUG");

void amdxdna_fw_log_resume(struct amdxdna_dev *xdna)
{

}

void amdxdna_fw_log_suspend(struct amdxdna_dev *xdna)
{

}

int amdxdna_fw_log_init(struct amdxdna_dev *xdna)
{
	int ret;

	if (!xdna->dev_info->ops->fw_log_init) {
		ret = -EOPNOTSUPP;
		goto exit;
	}

	ret = xdna->dev_info->ops->fw_log_init(xdna, fw_log_size, fw_log_level);
	if (ret) {
		XDNA_ERR(xdna, "Failed to configure fw logging: %d", ret);
		goto exit;
	}

	// Init ISR and setup timers and worker threads
exit:
	return ret;
}

void amdxdna_fw_log_fini(struct amdxdna_dev *xdna)
{
	if (xdna->dev_info->ops->fw_log_fini)
		xdna->dev_info->ops->fw_log_fini(xdna);

}
