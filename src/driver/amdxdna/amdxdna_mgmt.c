// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <drm/drm_cache.h>

#include "amdxdna_mgmt.h"

void *amdxdna_mgmt_buff_alloc(struct amdxdna_dev *xdna, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			      size_t size, enum dma_data_direction dir)
{
	if (!size)
		return NULL;

	/*
	 * The aligned size calculation is implemented to work around a known firmware issue that
	 * can cause the system to hang. By aligning the size to the nearest power of two and then
	 * doubling it, we ensure that the memory allocation is compatible with the firmware's
	 * requirements, thus preventing potential system instability.
	 */
	dma_hdl->aligned_size = PAGE_ALIGN(size);
	dma_hdl->aligned_size = roundup_pow_of_two(dma_hdl->aligned_size);
	dma_hdl->aligned_size *= 2;

	/*
	 * The behavior of dma_alloc_noncoherent() was tested on the 6.13 kernel.
	 * 1. This function eventually calls __alloc_frozen_pages_noprof().
	 * 2. The maximum allocatable size is 4MB, constrained by MAX_PAGE_ORDER 10.
	 *    Exceeding this limit results in a NULL pointer return.
	 * 3. For valid sizes, this function provides physically contiguous memory.
	 *
	 * If there is a requirement for physical contiguous memory larger than 4MB,
	 * consider allocating the buffer from carved-out memory.
	 */
	dma_hdl->vaddr = dma_alloc_noncoherent(xdna->ddev.dev, dma_hdl->aligned_size,
					       &dma_hdl->dma_hdl, dir, GFP_KERNEL);
	if (!dma_hdl->vaddr)
		return NULL;

	dma_hdl->size = size;
	dma_hdl->xdna = xdna;
	dma_hdl->dir = dir;

	return dma_hdl->vaddr;
}

int amdxdna_mgmt_buff_clflush(struct amdxdna_mgmt_dma_hdl *dma_hdl, u32 offset, size_t size)
{
	if (offset + size > dma_hdl->size)
		return -EINVAL;

	/*
	 * After flushing the buffer and handing it over to the device,
	 * the user must wait for the device to complete its operations and return
	 * control before attempting to write to the buffer again.
	 */
	drm_clflush_virt_range(dma_hdl->vaddr + offset, size ? size : dma_hdl->size);
	return 0;
}

dma_addr_t amdxdna_mgmt_buff_get_dma_addr(struct amdxdna_mgmt_dma_hdl *dma_hdl)
{
	if (!dma_hdl->aligned_size)
		return 0;

	return dma_hdl->dma_hdl;
}

void *amdxdna_mgmt_buff_get_cpu_addr(struct amdxdna_mgmt_dma_hdl *dma_hdl)
{
	if (!dma_hdl->aligned_size)
		return ERR_PTR(-EINVAL);

	return dma_hdl->vaddr;
}

void amdxdna_mgmt_buff_free(struct amdxdna_mgmt_dma_hdl *dma_hdl)
{
	dma_free_noncoherent(dma_hdl->xdna->ddev.dev, dma_hdl->aligned_size, dma_hdl->vaddr,
			     dma_hdl->dma_hdl, dma_hdl->dir);
}
