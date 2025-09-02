// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

void amdxdna_fw_log_resume(struct amdxdna_dev *xdna)
{

}

void amdxdna_fw_log_suspend(struct amdxdna_dev *xdna)
{

}

int amdxdna_fw_log_init(struct amdxdna_dev *xdna)
{
	// Allocate struct amdxdna_debug and init driver attributes
	// Allocate fw buffer for logging and send it down to device
	// Set logging configs to FULL_LOG, LEVEL_ERROR, and DEST_DRAM
	// Init ISR and setup timers and worker threads
	return 0;
}

void amdxdna_fw_log_fini(struct amdxdna_dev *xdna)
{

}
