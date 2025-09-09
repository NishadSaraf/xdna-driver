// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <drm/drm_cache.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

#include "amdxdna_debug.h"
#include "aie2_msg_priv.h"

u8 fw_log_level = 1;
module_param(fw_log_level, byte, 0444);
MODULE_PARM_DESC(fw_log_level,
		 " Firmware log verbosity: 0: DISABLE 1: ERROR (Default) 2: WARN 3: INFO 4: DEBUG");

u64 fw_log_size = SZ_4M;
module_param(fw_log_size, ullong, 0444);
MODULE_PARM_DESC(fw_log_size, " Size of firmware log (Default 4MB). Min 8KB, Max 4MB");

bool fw_log_poll;
module_param(fw_log_poll, bool, 0444);
MODULE_PARM_DESC(fw_log_poll, " Enable FW log polling (Default false)");

static bool amdxdna_update_tail(struct amdxdna_debug *debug_hdl)
{
	struct amdxdna_debug_footer *footer;
	u32 offset;
	u64 tail;

	offset = debug_hdl->dma_hdl->size - AMDXDNA_DEBUG_FOOTER_SIZE;
	footer = debug_hdl->dma_hdl->vaddr + offset;

	amdxdna_mgmt_buff_clflush(debug_hdl->dma_hdl, offset, sizeof(*footer));

	/* Extend 32-bit firmware pointer to a 64-bit value */
	tail = (debug_hdl->tail & ~GENMASK_ULL(31, 0)) | footer->tail;
	if (tail < debug_hdl->tail)
		tail += BIT_ULL(32);

	drm_WARN_ONCE(&debug_hdl->xdna->ddev, tail - debug_hdl->tail > BIT_ULL(31),
		      "Unexpceted jump in tail pointer. Missed IRQ or bug");

	if (debug_hdl->tail != tail) {
		WRITE_ONCE(debug_hdl->tail, tail);
		wake_up(&debug_hdl->wait);
		return true;
	}
	return false;
}

static const char * const fw_log_level_str[] = {
	"OFF",
	"ERR",
	"WRN",
	"INF",
	"DBG",
	"MAX"
};

static void amdxdna_fw_log_print(struct amdxdna_debug *log, u8 *buffer, size_t size)
{
	u8 *end = buffer + size;

	if (!size)
		return;

	while (buffer < end) {
		struct fw_log_header {
			u64 timestamp;
			u32 format      : 1;
			u32 reserved_1  : 7;
			u32 level       : 3;
			u32 reserved_11 : 5;
			u32 appn        : 8;
			u32 argc        : 8;
			u32 line        : 16;
			u32 module      : 16;
		} *header;
		const u32 header_size = sizeof(struct fw_log_header);
		char appid[20];
		u32 msg_size;

		header = (struct fw_log_header *)buffer;

		if (header->format != FW_LOG_FORMAT_FULL || !header->argc || header->level > 4) {
			XDNA_ERR(log->xdna, "Potential buffer overflow or corruption!\n");
			buffer += AMDXDNA_FW_LOG_MSG_ALIGN;
			continue;
		}

		msg_size = (header->argc) * sizeof(u32);
		if (msg_size + header_size > size) {
			XDNA_ERR(log->xdna, "Log entry size exceeds available buffer size");
			return;
		}

		if (header->appn > 15)
			scnprintf(appid, sizeof(appid), "MGMNT");
		else
			scnprintf(appid, sizeof(appid), "APP%2d", header->appn);

		XDNA_INFO(log->xdna, "[%lld] [%s] [%s]: %s", header->timestamp,
			  fw_log_level_str[header->level], appid, (char*)(buffer + header_size));

		buffer += ALIGN(header_size + msg_size, AMDXDNA_FW_LOG_MSG_ALIGN);
	}
	return;
}

static int amdxdna_debug_fetch_payload(struct amdxdna_debug *debug_hdl, u8 *buffer, size_t *size)
{
	struct amdxdna_dev *xdna = debug_hdl->xdna;
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	size_t req_size, log_size;
	u32 start, aligned, end;
	u64 tail;

	dma_hdl = debug_hdl->dma_hdl;
	log_size = dma_hdl->size;

	tail = READ_ONCE(debug_hdl->tail);
	start = debug_hdl->head % log_size;
	end = tail % log_size;

	if (start == end)
		return 0;

	if (!IS_ALIGNED(start, AMDXDNA_FW_LOG_MSG_ALIGN)) {
		XDNA_WARN(xdna, "Start offset of fw log is not 8-Byte aligned");
		aligned = ALIGN(start, AMDXDNA_FW_LOG_MSG_ALIGN);
		start = aligned > log_size ? 0 : aligned;
	}

	req_size = (end > start) ? (end - start) : (log_size - end + start);

	if (req_size > *size)
		return -ENOSPC;

	if (start > end) {
		/* First chuck: Copy from start point until the end of log buffer */
		amdxdna_mgmt_buff_clflush(dma_hdl, start, log_size - start);
		memcpy(buffer, amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, start), log_size - start);
		/* Last chuck: Wrap around and copy from the start of log buffer to end */
		amdxdna_mgmt_buff_clflush(dma_hdl, 0, end);
		memcpy(buffer + (log_size - start),
		       amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0), end);
	} else {
		amdxdna_mgmt_buff_clflush(dma_hdl, start, end - start);
		memcpy(buffer, amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, start), end - start);
	}

	*size = req_size;
	debug_hdl->head = tail;
	return 0;

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

	XDNA_DBG(debug_hdl->xdna, "%s: version: %d.%d",
		 debug_hdl->name, debug_hdl->major, debug_hdl->minor);
	XDNA_DBG(debug_hdl->xdna, "%s: payload version: %d",
		 debug_hdl->name, debug_hdl->payload_version);
}

static irqreturn_t debug_irq_handler(int irq, void *data)
{
	struct amdxdna_debug *debug_hdl = (struct amdxdna_debug *)data;

	/* Clear the interrupt */
	writel(0, debug_hdl->io_base + debug_hdl->msi_address);

	spin_lock(&debug_hdl->lock);
	amdxdna_update_tail(debug_hdl);
	spin_unlock(&debug_hdl->lock);

	return IRQ_HANDLED;
}

static int amdxdna_debug_irq_init(struct amdxdna_debug *debug_hdl)
{
	struct amdxdna_dev *xdna = debug_hdl->xdna;
	int ret;

	if (!debug_hdl->msi_idx || !debug_hdl->msi_address) {
		XDNA_ERR(xdna, "MSI ID or address undefined");
		return -EINVAL;
	}

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
	return amdxdna_fw_log_init(xdna);
}

int amdxdna_fw_log_suspend(struct amdxdna_dev *xdna)
{
	/*
	 * Cache the current state FW polling to fw_log_poll to retain the polling state across
	 * suspend/resume
	 */
	fw_log_poll = xdna->fw_log->polling;

	return amdxdna_fw_log_fini(xdna);
}

static void amdxdna_debug_worker(struct work_struct *w)
{
	struct amdxdna_debug *debug_hdl = container_of(w, struct amdxdna_debug, work);
	unsigned long flags;
	size_t size = SZ_4M;
	u8 *buffer;
	int ret;

	spin_lock_irqsave(&debug_hdl->lock, flags);
	ret = amdxdna_update_tail(debug_hdl);
	spin_unlock_irqrestore(&debug_hdl->lock, flags);
	if (!ret)
		return;

	buffer = kzalloc(size, GFP_KERNEL);
	if (!buffer)
		XDNA_ERR(debug_hdl->xdna, "Failed to allocate fw fetch buffer");

	ret = amdxdna_debug_fetch_payload(debug_hdl, buffer, &size);
	if (ret) {
		XDNA_ERR(debug_hdl->xdna, "Failed to fetch fw buffer");
		goto exit;
	}

	amdxdna_fw_log_print(debug_hdl, buffer, size);
exit:
	kfree(buffer);
}

static void amdxdna_debug_timer(struct timer_list *t)
{
	struct amdxdna_debug *debug_hdl = container_of(t, struct amdxdna_debug, timer);

	queue_work(system_wq, &debug_hdl->work);
	mod_timer(&debug_hdl->timer, jiffies + msecs_to_jiffies(AMDXDNA_POLL_INTERVAL_MS));
}

void amdxdna_debug_enable_polling(struct amdxdna_debug *debug_hdl, bool enable)
{
	if (debug_hdl->polling == enable)
		return;

	if (enable) {
		INIT_WORK(&debug_hdl->work, amdxdna_debug_worker);
		timer_setup(&debug_hdl->timer, amdxdna_debug_timer, 0);
		mod_timer(&debug_hdl->timer, jiffies + msecs_to_jiffies(AMDXDNA_POLL_INTERVAL_MS));
	} else {
		timer_delete_sync(&debug_hdl->timer);
		cancel_work_sync(&debug_hdl->work);
	}

	debug_hdl->polling = enable;
}

int amdxdna_fw_log_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	struct amdxdna_debug *log_hdl;
	int ret;

	if (!xdna->dev_info->ops->fw_log_init)
		return -EOPNOTSUPP;

	if (!fw_log_level) {
		XDNA_WARN(xdna, "FW logging disabled. Default level: %d", fw_log_level);
		return 0;
	}

	if (fw_log_size < SZ_8K || fw_log_size > SZ_4M) {
		XDNA_ERR(xdna, "Invalid fw log buffer size: 0x%llx", fw_log_size);
		return -EINVAL;
	}

	log_hdl = kzalloc(sizeof(*log_hdl), GFP_KERNEL);
	if (!log_hdl)
		return -ENOMEM;

	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, fw_log_size, DMA_FROM_DEVICE);
	if (IS_ERR(dma_hdl)) {
		XDNA_ERR(xdna, "Failed to allocate fw log buffer of size: 0x%llx", fw_log_size);
		ret = PTR_ERR(dma_hdl);
		goto kfree;
	}

	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);

	strncpy(log_hdl->name, AMDXDNA_DEBUG_FW_LOG_NAME, sizeof(log_hdl->name));
	log_hdl->dma_hdl = dma_hdl;
	log_hdl->xdna = xdna;
	log_hdl->tail = 0;
	log_hdl->head = 0;
	init_waitqueue_head(&log_hdl->wait);
	spin_lock_init(&log_hdl->lock);
	xdna->fw_log = log_hdl;

	ret = xdna->dev_info->ops->fw_log_init(xdna, fw_log_size, fw_log_level);
	if (ret) {
		XDNA_ERR(xdna, "Failed to configure fw logging: %d", ret);
		goto mfree;
	}

	ret = amdxdna_debug_irq_init(log_hdl);
	if (ret)
		XDNA_ERR(xdna, "Failed to init fw logging IRQ: %d", ret);

	/* Enabling polling, if IRQ initialization fails or enabled by default */
	if (ret || fw_log_poll)
		amdxdna_debug_enable_polling(log_hdl, true);

	amdxdna_debug_read_metadata(log_hdl);

	log_hdl->enabled = true;
	return 0;
mfree:
	amdxdna_mgmt_buff_free(dma_hdl);
kfree:
	kfree(log_hdl);
	return ret;
}

int amdxdna_fw_log_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_debug *log_hdl = xdna->fw_log;
	int ret;

	if (!xdna->dev_info->ops->fw_log_fini)
		return -EOPNOTSUPP;

	if (!log_hdl || !log_hdl->enabled)
		return 0;

	ret = xdna->dev_info->ops->fw_log_fini(xdna);
	if (ret)
		XDNA_ERR(xdna, "Failed to disable fw logging: %d", ret);

	amdxdna_debug_irq_fini(log_hdl);
	amdxdna_debug_enable_polling(log_hdl, false);
	amdxdna_mgmt_buff_free(log_hdl->dma_hdl);
	kfree(log_hdl);
	xdna->fw_log = NULL;
	log_hdl->enabled = false;
	return 0;
}
