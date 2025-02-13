// SPDX-License-Identifier: GPL-2.0
/*
 * Synopsys DesignWare PCIe controller debugfs driver
 *
 * Copyright (C) 2025 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Author: Shradha Todi <shradha.t@samsung.com>
 */

#include <linux/debugfs.h>

#include "pcie-designware.h"

#define SD_STATUS_L1LANE_REG		0xb0
#define PIPE_RXVALID			BIT(18)
#define PIPE_DETECT_LANE		BIT(17)
#define LANE_SELECT			GENMASK(3, 0)

#define ERR_INJ0_OFF			0x34
#define EINJ_VAL_DIFF			GENMASK(28, 16)
#define EINJ_VC_NUM			GENMASK(14, 12)
#define EINJ_TYPE_SHIFT			8
#define EINJ0_TYPE			GENMASK(11, 8)
#define EINJ1_TYPE			BIT(8)
#define EINJ2_TYPE			GENMASK(9, 8)
#define EINJ3_TYPE			GENMASK(10, 8)
#define EINJ4_TYPE			GENMASK(10, 8)
#define EINJ5_TYPE			BIT(8)
#define EINJ_COUNT			GENMASK(7, 0)

#define ERR_INJ_ENABLE_REG		0x30

#define DWC_DEBUGFS_BUF_MAX		128

struct dwc_pcie_vendor_id {
	u16 vendor_id;
	u16 vsec_rasdes_cap_id;
};

static const struct dwc_pcie_vendor_id dwc_pcie_vendor_ids[] = {
	{PCI_VENDOR_ID_SAMSUNG,	0x2},
	{} /* terminator */
};

/**
 * struct dwc_pcie_rasdes_info - Stores controller common information
 * @ras_cap_offset: RAS DES vendor specific extended capability offset
 * @reg_lock: Mutex used for RASDES shadow event registers
 * @rasdes_dir: Top level debugfs directory entry
 *
 * Any parameter constant to all files of the debugfs hierarchy for a single controller
 * will be stored in this struct. It is allocated and assigned to controller specific
 * struct dw_pcie during initialization.
 */
struct dwc_pcie_rasdes_info {
	u32 ras_cap_offset;
	struct mutex reg_lock;
	struct dentry *rasdes_dir;
};

/**
 * struct dwc_pcie_rasdes_priv - Stores file specific private data information
 * @pci: Reference to the dw_pcie structure
 * @idx: Index to point to specific file related information in array of structs
 *
 * All debugfs files will have this struct as its private data.
 */
struct dwc_pcie_rasdes_priv {
	struct dw_pcie *pci;
	int idx;
};

/**
 * struct dwc_pcie_err_inj - Store details about each error injection supported by DWC RASDES
 * @name: Name of the error that can be injected
 * @err_inj_group: Group number to which the error belongs to. Value can range from 0 - 5
 * @err_inj_type: Each group can have multiple types of error
 */
struct dwc_pcie_err_inj {
	const char *name;
	u32 err_inj_group;
	u32 err_inj_type;
};

static const struct dwc_pcie_err_inj err_inj_list[] = {
	{"tx_lcrc", 0x0, 0x0},
	{"b16_crc_dllp", 0x0, 0x1},
	{"b16_crc_upd_fc", 0x0, 0x2},
	{"tx_ecrc", 0x0, 0x3},
	{"fcrc_tlp", 0x0, 0x4},
	{"parity_tsos", 0x0, 0x5},
	{"parity_skpos", 0x0, 0x6},
	{"rx_lcrc", 0x0, 0x8},
	{"rx_ecrc", 0x0, 0xb},
	{"tlp_err_seq", 0x1, 0x0},
	{"ack_nak_dllp_seq", 0x1, 0x1},
	{"ack_nak_dllp", 0x2, 0x0},
	{"upd_fc_dllp", 0x2, 0x1},
	{"nak_dllp", 0x2, 0x2},
	{"inv_sync_hdr_sym", 0x3, 0x0},
	{"com_pad_ts1", 0x3, 0x1},
	{"com_pad_ts2", 0x3, 0x2},
	{"com_fts", 0x3, 0x3},
	{"com_idl", 0x3, 0x4},
	{"end_edb", 0x3, 0x5},
	{"stp_sdp", 0x3, 0x6},
	{"com_skp", 0x3, 0x7},
	{"posted_tlp_hdr", 0x4, 0x0},
	{"non_post_tlp_hdr", 0x4, 0x1},
	{"cmpl_tlp_hdr", 0x4, 0x2},
	{"posted_tlp_data", 0x4, 0x4},
	{"non_post_tlp_data", 0x4, 0x5},
	{"cmpl_tlp_data", 0x4, 0x6},
	{"duplicate_dllp", 0x5, 0x0},
	{"nullified_tlp", 0x5, 0x1},
};

static const u32 err_inj_type_mask[] = {
	EINJ0_TYPE,
	EINJ1_TYPE,
	EINJ2_TYPE,
	EINJ3_TYPE,
	EINJ4_TYPE,
	EINJ5_TYPE,
};

static ssize_t lane_detect_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct dw_pcie *pci = file->private_data;
	struct dwc_pcie_rasdes_info *rinfo = pci->rasdes_info;
	char debugfs_buf[DWC_DEBUGFS_BUF_MAX];
	ssize_t off = 0;
	u32 val;

	val = dw_pcie_readl_dbi(pci, rinfo->ras_cap_offset + SD_STATUS_L1LANE_REG);
	val = FIELD_GET(PIPE_DETECT_LANE, val);
	if (val)
		off += scnprintf(debugfs_buf, DWC_DEBUGFS_BUF_MAX - off, "Lane Detected\n");
	else
		off += scnprintf(debugfs_buf, DWC_DEBUGFS_BUF_MAX - off, "Lane Undetected\n");

	return simple_read_from_buffer(buf, count, ppos, debugfs_buf, off);
}

static ssize_t lane_detect_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct dw_pcie *pci = file->private_data;
	struct dwc_pcie_rasdes_info *rinfo = pci->rasdes_info;
	u32 lane, val;

	val = kstrtou32_from_user(buf, count, 0, &lane);
	if (val)
		return val;

	val = dw_pcie_readl_dbi(pci, rinfo->ras_cap_offset + SD_STATUS_L1LANE_REG);
	val &= ~(LANE_SELECT);
	val |= FIELD_PREP(LANE_SELECT, lane);
	dw_pcie_writel_dbi(pci, rinfo->ras_cap_offset + SD_STATUS_L1LANE_REG, val);

	return count;
}

static ssize_t rx_valid_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct dw_pcie *pci = file->private_data;
	struct dwc_pcie_rasdes_info *rinfo = pci->rasdes_info;
	char debugfs_buf[DWC_DEBUGFS_BUF_MAX];
	ssize_t off = 0;
	u32 val;

	val = dw_pcie_readl_dbi(pci, rinfo->ras_cap_offset + SD_STATUS_L1LANE_REG);
	val = FIELD_GET(PIPE_RXVALID, val);
	if (val)
		off += scnprintf(debugfs_buf, DWC_DEBUGFS_BUF_MAX - off, "RX Valid\n");
	else
		off += scnprintf(debugfs_buf, DWC_DEBUGFS_BUF_MAX - off, "RX Invalid\n");

	return simple_read_from_buffer(buf, count, ppos, debugfs_buf, off);
}

static ssize_t rx_valid_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	return lane_detect_write(file, buf, count, ppos);
}

static ssize_t err_inj_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct dwc_pcie_rasdes_priv *pdata = file->private_data;
	struct dw_pcie *pci = pdata->pci;
	struct dwc_pcie_rasdes_info *rinfo = pci->rasdes_info;
	u32 val, counter, vc_num, err_group, type_mask;
	int val_diff = 0;
	char *kern_buf;

	err_group = err_inj_list[pdata->idx].err_inj_group;
	type_mask = err_inj_type_mask[err_group];

	kern_buf = memdup_user_nul(buf, count);
	if (IS_ERR(kern_buf))
		return PTR_ERR(kern_buf);

	if (err_group == 4) {
		val = sscanf(kern_buf, "%u %d %u", &counter, &val_diff, &vc_num);
		if ((val != 3) || (val_diff < -4095 || val_diff > 4095)) {
			kfree(kern_buf);
			return -EINVAL;
		}
	} else if (err_group == 1) {
		val = sscanf(kern_buf, "%u %d", &counter, &val_diff);
		if ((val != 2) || (val_diff < -4095 || val_diff > 4095)) {
			kfree(kern_buf);
			return -EINVAL;
		}
	} else {
		val = kstrtou32(kern_buf, 0, &counter);
		if (val) {
			kfree(kern_buf);
			return val;
		}
	}

	val = dw_pcie_readl_dbi(pci, rinfo->ras_cap_offset + ERR_INJ0_OFF + (0x4 * err_group));
	val &= ~(type_mask | EINJ_COUNT);
	val |= ((err_inj_list[pdata->idx].err_inj_type << EINJ_TYPE_SHIFT) & type_mask);
	val |= FIELD_PREP(EINJ_COUNT, counter);

	if (err_group == 1 || err_group == 4) {
		val &= ~(EINJ_VAL_DIFF);
		val |= FIELD_PREP(EINJ_VAL_DIFF, val_diff);
	}
	if (err_group == 4) {
		val &= ~(EINJ_VC_NUM);
		val |= FIELD_PREP(EINJ_VC_NUM, vc_num);
	}

	dw_pcie_writel_dbi(pci, rinfo->ras_cap_offset + ERR_INJ0_OFF + (0x4 * err_group), val);
	dw_pcie_writel_dbi(pci, rinfo->ras_cap_offset + ERR_INJ_ENABLE_REG, (0x1 << err_group));

	kfree(kern_buf);
	return count;
}

#define dwc_debugfs_create(name)			\
debugfs_create_file(#name, 0644, rasdes_debug, pci,	\
			&dbg_ ## name ## _fops)

#define DWC_DEBUGFS_FOPS(name)					\
static const struct file_operations dbg_ ## name ## _fops = {	\
	.open = simple_open,				\
	.read = name ## _read,				\
	.write = name ## _write				\
}

DWC_DEBUGFS_FOPS(lane_detect);
DWC_DEBUGFS_FOPS(rx_valid);

static const struct file_operations dwc_pcie_err_inj_ops = {
	.open = simple_open,
	.write = err_inj_write,
};

void dwc_pcie_rasdes_debugfs_deinit(struct dw_pcie *pci)
{
	struct dwc_pcie_rasdes_info *rinfo = pci->rasdes_info;

	debugfs_remove_recursive(rinfo->rasdes_dir);
	mutex_destroy(&rinfo->reg_lock);
}

int dwc_pcie_rasdes_debugfs_init(struct dw_pcie *pci)
{
	struct dentry *dir, *rasdes_debug, *rasdes_err_inj;
	struct dwc_pcie_rasdes_info *rasdes_info;
	struct dwc_pcie_rasdes_priv *priv_tmp;
	const struct dwc_pcie_vendor_id *vid;
	char dirname[DWC_DEBUGFS_BUF_MAX];
	struct device *dev = pci->dev;
	int ras_cap, i, ret;

	for (vid = dwc_pcie_vendor_ids; vid->vendor_id; vid++) {
		ras_cap = dw_pcie_find_vsec_capability(pci, vid->vendor_id,
							vid->vsec_rasdes_cap_id);
		if (ras_cap)
			break;
	}
	if (!ras_cap) {
		dev_dbg(dev, "No RASDES capability available\n");
		return -ENODEV;
	}

	rasdes_info = devm_kzalloc(dev, sizeof(*rasdes_info), GFP_KERNEL);
	if (!rasdes_info)
		return -ENOMEM;

	/* Create main directory for each platform driver */
	snprintf(dirname, DWC_DEBUGFS_BUF_MAX, "dwc_pcie_%s", dev_name(dev));
	dir = debugfs_create_dir(dirname, NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	/* Create subdirectories for Debug, Error injection, Statistics */
	rasdes_debug = debugfs_create_dir("rasdes_debug", dir);
	rasdes_err_inj = debugfs_create_dir("rasdes_err_inj", dir);

	mutex_init(&rasdes_info->reg_lock);
	rasdes_info->ras_cap_offset = ras_cap;
	rasdes_info->rasdes_dir = dir;
	pci->rasdes_info = rasdes_info;

	/* Create debugfs files for Debug subdirectory */
	dwc_debugfs_create(lane_detect);
	dwc_debugfs_create(rx_valid);

	/* Create debugfs files for Error injection subdirectory */
	for (i = 0; i < ARRAY_SIZE(err_inj_list); i++) {
		priv_tmp = devm_kzalloc(dev, sizeof(*priv_tmp), GFP_KERNEL);
		if (!priv_tmp) {
			ret = -ENOMEM;
			goto err_deinit;
		}

		priv_tmp->idx = i;
		priv_tmp->pci = pci;
		debugfs_create_file(err_inj_list[i].name, 0200, rasdes_err_inj, priv_tmp,
				    &dwc_pcie_err_inj_ops);
	}
	return 0;

err_deinit:
	dwc_pcie_rasdes_debugfs_deinit(pci);
	return ret;
}
