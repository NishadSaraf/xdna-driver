// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <drm/drm_cache.h>
#include <linux/interrupt.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/sizes.h>
#include <linux/slab.h>

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
	struct amdxdna_debug_footer *footer;
	u32 offset;
	u64 tail;

	/* Clear the interrupt */
	writel(0, debug_hdl->io_base + debug_hdl->msi_address);

	offset = debug_hdl->dma_hdl->size - AMDXDNA_DEBUG_FOOTER_SIZE;
	footer = debug_hdl->dma_hdl->vaddr + offset;

	amdxdna_mgmt_buff_clflush(debug_hdl->dma_hdl, offset, sizeof(*footer));

	/* Extend 32-bit firmware pointer to a 64-bit value */
	tail = (debug_hdl->tail & ~GENMASK_ULL(31, 0)) | footer->tail;
	if (tail < debug_hdl->tail)
		tail += BIT_ULL(32);

	WRITE_ONCE(debug_hdl->tail, tail);

	return IRQ_HANDLED;
}

static void amdxdna_debug_read_metadata(struct amdxdna_debug *debug_hdl)
{
	struct amdxdna_debug_footer *footer;
	u32 offset;

	offset = debug_hdl->dma_hdl->size - AMDXDNA_DEBUG_FOOTER_SIZE;
	footer = debug_hdl->dma_hdl->vaddr + offset;

	amdxdna_mgmt_buff_clflush(debug_hdl->dma_hdl, offset, sizeof(*footer));

	debug_hdl->payload_version = footer->payload_version;
	debug_hdl->minor = footer->minor;
	debug_hdl->major = footer->major;

	XDNA_INFO(debug_hdl->xdna, "%s: version: %d.%d",
		  debug_hdl->name, debug_hdl->major, debug_hdl->minor);
	XDNA_INFO(debug_hdl->xdna, "%s: payload version: %d",
		  debug_hdl->name, debug_hdl->payload_version);
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

	debug_hdl->msi_address = 0;
	debug_hdl->msi_idx = 0;
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
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	struct amdxdna_debug *log_hdl;
	void *vaddr;
	int ret;

	if (!xdna->dev_info->ops->fw_log_init)
		return -EOPNOTSUPP;

	if (fw_log_size < SZ_8K) {
		XDNA_ERR(xdna, "Invalid fw log buffer size: 0x%llx", fw_log_size);
		return -EINVAL;
	}

	log_hdl = kzalloc(sizeof(*log_hdl), GFP_KERNEL);
	if (!log_hdl)
		return -ENOMEM;

	dma_hdl = kzalloc(sizeof(*dma_hdl), GFP_KERNEL);
	if (!dma_hdl)
		return -ENOMEM;

	vaddr = amdxdna_mgmt_buff_alloc(xdna, dma_hdl, fw_log_size, DMA_FROM_DEVICE);
	if (!vaddr) {
		XDNA_ERR(xdna, "Failed to allocate fw log buffer of size: 0x%llx", fw_log_size);
		ret = -ENOMEM;
		goto exit;
	}

	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);

	strncpy(log_hdl->name, FW_LOG_NAME, sizeof(log_hdl->name));
	log_hdl->dma_hdl = dma_hdl;
	log_hdl->xdna = xdna;
	log_hdl->tail = 0;
	xdna->fw_log = log_hdl;

	ret = xdna->dev_info->ops->fw_log_init(xdna, fw_log_size, fw_log_level);
	if (ret) {
		XDNA_ERR(xdna, "Failed to configure fw logging: %d", ret);
		goto exit;
	}

	ret = amdxdna_debug_irq_init(log_hdl);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw logging IRQ: %d", ret);
		goto exit;
	}

	amdxdna_debug_read_metadata(log_hdl);

	log_hdl->enabled = true;
	return 0;
exit:
	amdxdna_mgmt_buff_free(dma_hdl);
	kfree(dma_hdl);
	kfree(log_hdl);
	return ret;
}

int amdxdna_fw_log_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_debug *log_hdl = xdna->fw_log;
	int ret;

	if (!log_hdl->enabled)
		return 0;

	amdxdna_debug_irq_fini(log_hdl);
	if (xdna->dev_info->ops->fw_log_fini) {
		ret = xdna->dev_info->ops->fw_log_fini(xdna);
		if (ret) {
			XDNA_ERR(xdna, "Failed to disable fw logging: %d", ret);
			return ret;
		}
	}
	log_hdl->enabled = false;

	amdxdna_mgmt_buff_free(log_hdl->dma_hdl);
	kfree(log_hdl->dma_hdl);
	kfree(log_hdl);
	return 0;
}
