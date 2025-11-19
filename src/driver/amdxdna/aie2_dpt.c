// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "aie2_pci.h"
#include "aie2_msg_priv.h"
#include "amdxdna_mgmt.h"

#define AIE2_MGMT_APP_ID		0xFF

static const char * const fw_log_level_str[] = {
	"OFF",
	"ERR",
	"WRN",
	"INF",
	"DBG",
	"MAX"
};

void aie2_fw_log_parse(struct amdxdna_dev *xdna, char *buffer, size_t size)
{
	struct fw_log_header {
#define AIE2_DPT_ENTRY_MAGIC_HEAD	0xCA
		u8 magic;
		u8 data_word_len;
		u16 seq_num;
		u32 reserved;
	} *header;
	struct fw_log_data {
		u64 timestamp;
		u32 format      : 1;
		u32 reserved_1  : 7;
		u32 level       : 3;
		u32 reserved_11 : 5;
		u32 appn        : 8;
		u32 argc        : 8;
		u32 line        : 16;
		u32 module      : 16;
	} *payload;
	struct fw_log_footer {
		u32 reserved;
		u16 seq_num;
		u8 data_word_len;
#define AIE2_DPT_ENTRY_MAGIC_FOOTER	0xBA
		u8 magic;
	} *footer;
	size_t bytes_read = 0;
	char *data = buffer;
	u16 seq_num = 0;

	if (!size)
		return;

	while (size - bytes_read > sizeof(fw_log_header)) {
		u32 increment = 4;
		bool valid;

		header = data;

		if (header->magic != AIE2_DPT_ENTRY_MAGIC_HEAD) {
			XDNA_ERR(xdna, "Potential buffer overflow or corruption!\n");
			data += increment;
			bytes_read += increment;
			continue;
		}

		payload = data + sizeof(*header);
		footer = data + header->data_word_len * sizeof(u32);

		if (footer + sizeof(*footer) > buffer + size) {
			/* Partial/Corrupted entry */
			XDNA_ERR(xdna, "Log entry size exceeds available buffer size");
			data += increment;
			bytes_read += increment;
			continue;
		}

		valid = footer->magic == AIE2_DPT_ENTRY_MAGIC_FOOTER &&
			header->seq_num && header->seq_num == footer->seq_num;
		if (!valid) {
			XDNA_ERR(xdna, "Potential buffer overflow or corruption!\n");
			data += increment;
			bytes_read += increment;
			continue;
		}

		if (!seq_num || (header->seq_num == seq_num + 1)) {
			seq_num++;
		}
		const u32 data_size = sizeof(struct fw_log_data);
		char appid[20];
		u32 msg_size;

		if (data->format != FW_LOG_FORMAT_FULL || !data->argc || data->level > 4) {
			XDNA_ERR(xdna, "Potential buffer overflow or corruption!\n");
			buffer += AMDXDNA_DPT_FW_LOG_MSG_ALIGN;
			continue;
		}

		msg_size = (data->argc) * sizeof(u32);
		if (msg_size + data_size > size) {
			XDNA_ERR(xdna, "Log entry size exceeds available buffer size");
			return;
		}

		if (data->appn == AIE2_MGMT_APP_ID)
			scnprintf(appid, sizeof(appid), "MGMNT");
		else
			scnprintf(appid, sizeof(appid), "APP%2d", data->appn);

		XDNA_INFO(xdna, "[%lld] [%s] [%s]: %s", data->timestamp,
			  fw_log_level_str[data->level], appid, (char *)(buffer + data_size));

		buffer += ALIGN(data_size + msg_size, AMDXDNA_DPT_FW_LOG_MSG_ALIGN);
	}
}

int aie2_fw_log_init(struct amdxdna_dev *xdna, size_t size, u8 level)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl = xdna->fw_log->dma_hdl;
	u32 msi_idx, msi_address;
	int ret;

	if (level >= MAX_FW_LOG_LEVEL) {
		XDNA_ERR(xdna,  "Invalid firmware log level: %d", level);
		return -EINVAL;
	}

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_config_fw_log(xdna->dev_handle, dma_hdl, size, &msi_idx, &msi_address);
	if (ret) {
		/* Sliently fail for device generation that don't support FW logging */
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to init fw log buffer: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_set_log_level(xdna->dev_handle, level);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log level: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_set_log_format(xdna->dev_handle, FW_LOG_FORMAT_FULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log format: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_set_log_destination(xdna->dev_handle, FW_LOG_DESTINATION_DRAM);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log destination: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);

	xdna->fw_log->io_base = xdna->dev_handle->mbox_base;
	xdna->fw_log->msi_address = msi_address & AIE2_DPT_MSI_ADDR_MASK;
	xdna->fw_log->msi_idx = msi_idx;

	return ret;
}

int aie2_fw_log_config(struct amdxdna_dev *xdna, u8 level)
{
	int ret;

	if (level == FW_LOG_LEVEL_NONE || level >= MAX_FW_LOG_LEVEL) {
		XDNA_ERR(xdna,  "Invalid firmware log level: %d", level);
		return -EINVAL;
	}

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_set_log_level(xdna->dev_handle, level);
	if (ret)
		XDNA_ERR(xdna, "Failed to init fw log level: %d", ret);
	mutex_unlock(&xdna->dev_handle->aie2_lock);

	return ret;
}

int aie2_fw_log_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl = xdna->fw_log->dma_hdl;
	int ret;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_set_log_destination(xdna->dev_handle, FW_LOG_DESTINATION_FIXED);
	if (ret) {
		/* Sliently fail for device generation that don't support FW logging */
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to reset fw log destination: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_config_fw_log(xdna->dev_handle, dma_hdl, 0, NULL, NULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to reset fw log buffer: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);
	return 0;
}

void aie2_fw_trace_parse(struct amdxdna_dev *xdna, char *buffer, size_t size)
{
	if (!size)
		return;

	print_hex_dump(KERN_INFO, "[FW TRACE]: ", DUMP_PREFIX_OFFSET, 16, 4, buffer, size, false);
}

int aie2_fw_trace_init(struct amdxdna_dev *xdna, size_t size, u32 categories)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl = xdna->fw_trace->dma_hdl;
	u32 msi_idx, msi_address;
	int ret;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_start_fw_trace(xdna->dev_handle, dma_hdl, size, categories, &msi_idx,
				  &msi_address);
	if (ret) {
		/* Sliently fail for device generation that don't support FW tracing */
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to init fw trace buffer: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);

	xdna->fw_trace->io_base = xdna->dev_handle->mbox_base;
	xdna->fw_trace->msi_address = msi_address & AIE2_DPT_MSI_ADDR_MASK;
	xdna->fw_trace->msi_idx = msi_idx;

	return ret;
}

int aie2_fw_trace_config(struct amdxdna_dev *xdna, u32 categories)
{
	int ret;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_set_trace_categories(xdna->dev_handle, categories);
	if (ret)
		XDNA_ERR(xdna, "Failed to init fw trace categories: %d", ret);
	mutex_unlock(&xdna->dev_handle->aie2_lock);

	return ret;
}

int aie2_fw_trace_fini(struct amdxdna_dev *xdna)
{
	int ret;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_stop_fw_trace(xdna->dev_handle);
	if (ret) {
		XDNA_ERR(xdna, "Failed to stop fw trace: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);
	return 0;
}
