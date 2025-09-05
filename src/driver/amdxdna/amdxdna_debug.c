// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/interrupt.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
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

#define FW_LOG_NAME		"xdna_fw_log"

static irqreturn_t debug_irq_handler(int irq, void *data)
{
	struct amdxdna_debug *debug_hdl = (struct amdxdna_debug *)data;

	XDNA_INFO(debug_hdl->xdna, "Received %s IRQ", debug_hdl->name);

	/* Clear the interrupt */
	writel(0, debug_hdl->io_base + debug_hdl->msi_address);

	return IRQ_HANDLED;
}

static int amdxdna_debug_irq_init(struct amdxdna_debug *debug_hdl)
{
	struct amdxdna_dev *xdna = debug_hdl->xdna;
	int ret;

	ret = pci_irq_vector(to_pci_dev(xdna->ddev.dev), debug_hdl->msi_idx);
	if (ret < 0) {
		XDNA_ERR(xdna, "Failed to get IRQ number, %d", ret);
		return ret;
	}
	debug_hdl->irq = ret;

	ret = request_irq(debug_hdl->irq, debug_irq_handler, 0, debug_hdl->name, debug_hdl);
	if (ret) {
		XDNA_ERR(xdna, "Failed to register irq %d ret %d", debug_hdl->irq, ret);
		return ret;
	}

	return 0;
}

static void amdxdna_debug_irq_fini(struct amdxdna_debug *debug_hdl)
{
	if (debug_hdl->irq)
		free_irq(debug_hdl->irq, debug_hdl);
}

int amdxdna_fw_log_resume(struct amdxdna_dev *xdna)
{
	return  amdxdna_fw_log_init(xdna);
}

int amdxdna_fw_log_suspend(struct amdxdna_dev *xdna)
{
	return amdxdna_fw_log_fini(xdna);
}

int amdxdna_fw_log_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_debug *fw_log_hdl = &xdna->fw_log;
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

	strncpy(fw_log_hdl->name, FW_LOG_NAME, sizeof(fw_log_hdl->name));
	fw_log_hdl->xdna = xdna;

	ret = amdxdna_debug_irq_init(fw_log_hdl);
	if (ret) {
		XDNA_ERR(xdna, "Failed to configure fw logging: %d", ret);
		goto exit;
	}

	fw_log_hdl->enabled = true;
exit:
	return ret;
}

int amdxdna_fw_log_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_debug *fw_log_hdl = &xdna->fw_log;
	int ret;

	if (!fw_log_hdl->enabled)
		return 0;

	amdxdna_debug_irq_fini(&xdna->fw_log);
	if (xdna->dev_info->ops->fw_log_fini) {
		ret = xdna->dev_info->ops->fw_log_fini(xdna);
		if (ret) {
			XDNA_ERR(xdna, "Failed to disable fw logging: %d", ret);
			return ret;
		}
	}

	fw_log_hdl->enabled = false;
	return 0;
}
