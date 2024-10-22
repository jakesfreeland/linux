// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Non-physical true random number generator based on timing jitter --
 * Linux kernel character device specific code
 *
 * Copyright Stephan Mueller <smueller@chronox.de>, 2015 - 2023
 * Copyright NIKSUN Inc <support@niksun.com>, 2024
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU General Public License, in which case the provisions of the GPL2 are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <crypto/hash.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fips.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/uio.h>

#include "jitterentropy.h"

#define	DRIVER_NAME	"jentdev"
#define	DRIVER_DESC	"jitterentropy chardev"
#define	DRIVER_VERSION	"0.1"

#define	JENT_CONDITIONING_HASH	"sha3-256-generic"
#define	JENT_CLASSNAME		"jitter_rng"
#define	JENT_DEVNAME		"jitter_rng"
#define	JENT_BLOCK_SIZE		32

#define	jent_msg(type, msg, ...)	\
	pr_##type(DRIVER_NAME ": " msg "\n" __VA_OPT__(,) __VA_ARGS__)

#define	jent_err(msg, ...)	jent_msg(err, msg, __VA_ARGS__)
#define	jent_info(msg, ...)	jent_msg(info, msg, __VA_ARGS__)
#define	jent_debug(msg, ...)	jent_msg(debug, msg, __VA_ARGS__)

#define	jent_warn_ratelimited(msg, ...)	\
	jent_msg(warn_ratelimited, msg, __VA_ARGS__)

struct jentdev {
	dev_t devt;
	struct cdev cdev;
	struct class *class;
	struct device *dev;
} jentdev;

struct jentrng {
	struct mutex lock;
	struct crypto_shash *hash;
	struct shash_desc *sdesc;
	struct rand_data *entropy_collector;
};

static int jent_read_error(int err)
{
	switch (err) {
	case -3:
		/* Handle permanent health test error */
		/*
		 * If the kernel was booted with fips=1, it implies that
		 * the entire kernel acts as a FIPS 140 module. In this case
		 * an SP800-90B permanent health test error is treated as
		 * a FIPS module error.
		 */
		if (fips_enabled)
			panic("Jitter RNG permanent health test failure. "
					"Jose says you're out of entropy!\n");

		jent_err("Jitter RNG permanent health test failure");
		return -EFAULT;
	case -2:
		/* Handle intermittent health test error */
		jent_warn_ratelimited("Reset Jitter RNG due to intermittent "
				"health test failure");
		return -EAGAIN;
	case -1:
	default:
		/* Handle other errors */
		jent_err("Failed to read entropy (%d)", err);
		return -EINVAL;
	}
}

static ssize_t jent_read_iter(struct kiocb *kiocb, struct iov_iter *iter)
{
	struct jentrng *rng = kiocb->ki_filp->private_data;
	u8 block[JENT_BLOCK_SIZE];
	ssize_t ret = 0;

	if (unlikely(!iov_iter_count(iter)))
		return 0;

	mutex_lock(&rng->lock);
	for (;;) {
		size_t copied;
		int err;

		err = jent_read_entropy(rng->entropy_collector, block,
				sizeof(block));
		if (err < 0) {
			ret = jent_read_error(err);
			break;
		}

		copied = copy_to_iter(block, sizeof(block), iter);
		ret += copied;
		if (!iov_iter_count(iter) || copied != sizeof(block))
			break;
	}
	mutex_unlock(&rng->lock);

	memzero_explicit(block, sizeof(block));
	return ret ? ret : -EFAULT;
}

static long jent_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case RNDGETENTCNT:
	case RNDADDTOENTCNT:
	case RNDADDENTROPY:
	case RNDZAPENTCNT:
	case RNDCLEARPOOL:
	case RNDRESEEDCRNG:
		return 0;
	default:
		return -EINVAL;
	}
}

static int jent_release(struct inode *inode, struct file *file)
{
	struct jentrng *rng = file->private_data;

	mutex_lock(&rng->lock);
	jent_entropy_collector_free(rng->entropy_collector);
	shash_desc_zero(rng->sdesc);
	kfree(rng->sdesc);
	crypto_free_shash(rng->hash);
	mutex_unlock(&rng->lock);

	kfree(rng);

	return 0;
}

static int jent_open(struct inode *inode, struct file *file)
{
	struct jentrng *rng;
	size_t size;

	rng = kzalloc(sizeof(*rng), GFP_KERNEL);
	if (!rng) {
		jent_err("Failed to allocate jentrng");
		return -ENOMEM;
	}

	mutex_init(&rng->lock);

	/*
	 * Use SHA3-256 as conditioner. We allocate only the generic
	 * implementation as we are not interested in high-performance. The
	 * execution time of the SHA3 operation is measured and adds to the
	 * Jitter RNG's unpredictable behavior. If we have a slower hash
	 * implementation, the execution timing variations are larger. When
	 * using a fast implementation, we would need to call it more often
	 * as its variations are lower.
	 */
	rng->hash = crypto_alloc_shash(JENT_CONDITIONING_HASH, 0, 0);
	if (IS_ERR(rng->hash)) {
		long err = PTR_ERR(rng->hash);

		jent_err("Failed to allocate conditioning digest");
		kfree(rng);
		return err;
	}

	size = sizeof(*rng->sdesc) + crypto_shash_descsize(rng->hash);
	rng->sdesc = kmalloc(size, GFP_KERNEL);
	if (!rng->sdesc) {
		jent_err("Failed to allocate digest handle");
		crypto_free_shash(rng->hash);
		kfree(rng);
		return -ENOMEM;
	}

	rng->sdesc->tfm = rng->hash;
	crypto_shash_init(rng->sdesc);

	rng->entropy_collector =
		jent_entropy_collector_alloc(CONFIG_CRYPTO_JITTERENTROPY_OSR, 0,
					     rng->sdesc);
	if (!rng->entropy_collector) {
		jent_err("Failed to allocate entropy collector");
		shash_desc_zero(rng->sdesc);
		kfree(rng->sdesc);
		crypto_free_shash(rng->hash);
		kfree(rng);
		return -ENOMEM;
	}

	file->private_data = rng;
	return 0;
}

static struct file_operations jent_fops = {
	.owner = THIS_MODULE,
	.llseek = noop_llseek,
	.read_iter = jent_read_iter,
	.unlocked_ioctl = jent_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.open = jent_open,
	.release = jent_release,
};

static int jent_enabled;

static int jent_enable(char *str)
{
	get_option(&str, &jent_enabled);
	if (jent_enabled) {
		random_fops = jent_fops;
		urandom_fops = jent_fops;
	}
	return 1;
}

__setup("jent=", jent_enable);

#if defined(CONFIG_SYSCTL)

#include <linux/sysctl.h>

/* The same as proc_dointvec, but writes don't change anything. */
static int proc_do_rointvec(struct ctl_table *table, int write, void *buf,
			    size_t *lenp, loff_t *ppos)
{
	return write ? 0 : proc_dointvec(table, 0, buf, lenp, ppos);
}

static struct ctl_table jent_table[] = {
	{
		.procname	= "jent",
		.data		= &jent_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_do_rointvec,
	},
};

#endif /* CONFIG_SYSCTL */

static int __init jentdev_init(void)
{
	SHASH_DESC_ON_STACK(sdesc, tfm);
	struct crypto_shash *hash;
	int ret;

	hash = crypto_alloc_shash(JENT_CONDITIONING_HASH, 0, 0);
	if (IS_ERR(hash)) {
		jent_err("Failed to allocate digest handle");
		return PTR_ERR(hash);
	}

	sdesc->tfm = hash;
	crypto_shash_init(sdesc);
	ret = jent_entropy_init(CONFIG_CRYPTO_JITTERENTROPY_OSR, 0,
			sdesc, NULL);
	shash_desc_zero(sdesc);
	crypto_free_shash(hash);
	if (ret) {
		/* Handle permanent health test error */
		if (fips_enabled)
			panic(DRIVER_NAME ": Initialization failed with host "
			    "not compliant with requirements: %d\n", ret);

		jent_err("Initialization failed with host not compliant with "
		    "requirements: %d", ret);
		return -EFAULT;
	}

	ret = alloc_chrdev_region(&jentdev.devt, 0, 1, DRIVER_NAME);
	if (ret != 0) {
		jent_err("Failed to allocate character device number");
		return ret;
	}

	cdev_init(&jentdev.cdev, &jent_fops);
	ret = cdev_add(&jentdev.cdev, jentdev.devt, 1);
	if (ret) {
		jent_err("Failed to add cdev to system");
		unregister_chrdev_region(jentdev.devt, 1);
		return ret;
	}

	jentdev.class = class_create(THIS_MODULE, JENT_CLASSNAME);
	if (IS_ERR(jentdev.class)) {
		jent_err("Failed to register " JENT_CLASSNAME " class");
		cdev_del(&jentdev.cdev);
		unregister_chrdev_region(jentdev.devt, 1);
		return PTR_ERR(jentdev.class);
	}

	jentdev.dev = device_create(jentdev.class, NULL, jentdev.devt, &jentdev,
			JENT_DEVNAME);
	if (IS_ERR(jentdev.dev)) {
		jent_err("Failed to register " JENT_DEVNAME " device");
		class_destroy(jentdev.class);
		cdev_del(&jentdev.cdev);
		unregister_chrdev_region(jentdev.devt, 1);
		return PTR_ERR(jentdev.dev);
	}

#if defined(CONFIG_SYSCTL)
	register_sysctl_init("kernel/random", jent_table);
#endif

	jent_info(DRIVER_DESC ", version: " DRIVER_VERSION);
	return 0;
}

static void __exit jentdev_cleanup(void)
{
	device_destroy(jentdev.class, jentdev.devt);
	class_destroy(jentdev.class);
	cdev_del(&jentdev.cdev);
	unregister_chrdev_region(jentdev.devt, 1);
	jent_debug("Exiting now");
}

module_init(jentdev_init);
module_exit(jentdev_cleanup);

MODULE_AUTHOR("Jake Freeland <jfree@FreeBSD.org");
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRIVER_VERSION);
