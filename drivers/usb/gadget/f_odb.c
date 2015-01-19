/*
 * Gadget Driver for Android ADB
 *
 * Copyright (C) 2008 Google, Inc.
 * Author: Mike Lockwood <lockwood@android.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/miscdevice.h>

#define ODB_BULK_BUFFER_SIZE           4096

/* number of tx requests to allocate */
#define TX_REQ_MAX 4

static const char odb_shortname[] = "android_odb";

struct odb_dev {
	struct usb_function function;
	struct usb_composite_dev *cdev;
	spinlock_t lock;

	struct usb_ep *ep_in;
	struct usb_ep *ep_out;

	atomic_t online;
	atomic_t error;

	atomic_t read_excl;
	atomic_t write_excl;
	atomic_t open_excl;

	struct list_head tx_idle;

	wait_queue_head_t read_wq;
	wait_queue_head_t write_wq;
	struct usb_request *rx_req;
	int rx_done;
	bool notify_close;
	bool close_notified;
};

static struct usb_interface_descriptor odb_interface_desc = {
	.bLength                = USB_DT_INTERFACE_SIZE,
	.bDescriptorType        = USB_DT_INTERFACE,
	.bInterfaceNumber       = 0,
	.bNumEndpoints          = 2,
	.bInterfaceClass        = 0xFF,
	.bInterfaceSubClass     = 0x45,
	.bInterfaceProtocol     = 1,
};

static struct usb_endpoint_descriptor odb_superspeed_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor odb_superspeed_in_comp_desc = {
	.bLength =		sizeof odb_superspeed_in_comp_desc,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,

	/* the following 2 values can be tweaked if necessary */
	/* .bMaxBurst =		0, */
	/* .bmAttributes =	0, */
};

static struct usb_endpoint_descriptor odb_superspeed_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor odb_superspeed_out_comp_desc = {
	.bLength =		sizeof odb_superspeed_out_comp_desc,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,

	/* the following 2 values can be tweaked if necessary */
	/* .bMaxBurst =		0, */
	/* .bmAttributes =	0, */
};

static struct usb_endpoint_descriptor odb_highspeed_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor odb_highspeed_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor odb_fullspeed_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
};

static struct usb_endpoint_descriptor odb_fullspeed_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
};

static struct usb_descriptor_header *fs_odb_descs[] = {
	(struct usb_descriptor_header *) &odb_interface_desc,
	(struct usb_descriptor_header *) &odb_fullspeed_in_desc,
	(struct usb_descriptor_header *) &odb_fullspeed_out_desc,
	NULL,
};

static struct usb_descriptor_header *hs_odb_descs[] = {
	(struct usb_descriptor_header *) &odb_interface_desc,
	(struct usb_descriptor_header *) &odb_highspeed_in_desc,
	(struct usb_descriptor_header *) &odb_highspeed_out_desc,
	NULL,
};

static struct usb_descriptor_header *ss_odb_descs[] = {
	(struct usb_descriptor_header *) &odb_interface_desc,
	(struct usb_descriptor_header *) &odb_superspeed_in_desc,
	(struct usb_descriptor_header *) &odb_superspeed_in_comp_desc,
	(struct usb_descriptor_header *) &odb_superspeed_out_desc,
	(struct usb_descriptor_header *) &odb_superspeed_out_comp_desc,
	NULL,
};

static void odb_ready_callback(void);
static void odb_closed_callback(void);

/* temporary variable used between odb_open() and odb_gadget_bind() */
static struct odb_dev *_odb_dev;

static inline struct odb_dev *func_to_odb(struct usb_function *f)
{
	return container_of(f, struct odb_dev, function);
}


static struct usb_request *odb_request_new(struct usb_ep *ep, int buffer_size)
{
	struct usb_request *req = usb_ep_alloc_request(ep, GFP_KERNEL);
	if (!req)
		return NULL;

	/* now allocate buffers for the requests */
	req->buf = kmalloc(buffer_size, GFP_KERNEL);
	if (!req->buf) {
		usb_ep_free_request(ep, req);
		return NULL;
	}

	return req;
}

static void odb_request_free(struct usb_request *req, struct usb_ep *ep)
{
	if (req) {
		kfree(req->buf);
		usb_ep_free_request(ep, req);
	}
}

static inline int odb_lock(atomic_t *excl)
{
	if (atomic_inc_return(excl) == 1) {
		return 0;
	} else {
		atomic_dec(excl);
		return -1;
	}
}

static inline void odb_unlock(atomic_t *excl)
{
	atomic_dec(excl);
}

/* add a request to the tail of a list */
void odb_req_put(struct odb_dev *dev, struct list_head *head,
		struct usb_request *req)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	list_add_tail(&req->list, head);
	spin_unlock_irqrestore(&dev->lock, flags);
}

/* remove a request from the head of a list */
struct usb_request *odb_req_get(struct odb_dev *dev, struct list_head *head)
{
	unsigned long flags;
	struct usb_request *req;

	spin_lock_irqsave(&dev->lock, flags);
	if (list_empty(head)) {
		req = 0;
	} else {
		req = list_first_entry(head, struct usb_request, list);
		list_del(&req->list);
	}
	spin_unlock_irqrestore(&dev->lock, flags);
	return req;
}

static void odb_complete_in(struct usb_ep *ep, struct usb_request *req)
{
	struct odb_dev *dev = _odb_dev;

	if (req->status != 0)
		atomic_set(&dev->error, 1);

	odb_req_put(dev, &dev->tx_idle, req);

	wake_up(&dev->write_wq);
}

static void odb_complete_out(struct usb_ep *ep, struct usb_request *req)
{
	struct odb_dev *dev = _odb_dev;

	dev->rx_done = 1;
	if (req->status != 0 && req->status != -ECONNRESET)
		atomic_set(&dev->error, 1);

	wake_up(&dev->read_wq);
}

static int odb_create_bulk_endpoints(struct odb_dev *dev,
				struct usb_endpoint_descriptor *in_desc,
				struct usb_endpoint_descriptor *out_desc)
{
	struct usb_composite_dev *cdev = dev->cdev;
	struct usb_request *req;
	struct usb_ep *ep;
	int i;

	DBG(cdev, "create_bulk_endpoints dev: %p\n", dev);

	ep = usb_ep_autoconfig(cdev->gadget, in_desc);
	if (!ep) {
		DBG(cdev, "usb_ep_autoconfig for ep_in failed\n");
		return -ENODEV;
	}
	DBG(cdev, "usb_ep_autoconfig for ep_in got %s\n", ep->name);
	ep->driver_data = dev;		/* claim the endpoint */
	dev->ep_in = ep;

	ep = usb_ep_autoconfig(cdev->gadget, out_desc);
	if (!ep) {
		DBG(cdev, "usb_ep_autoconfig for ep_out failed\n");
		return -ENODEV;
	}
	DBG(cdev, "usb_ep_autoconfig for odb ep_out got %s\n", ep->name);
	ep->driver_data = dev;		/* claim the endpoint */
	dev->ep_out = ep;

	/* now allocate requests for our endpoints */
	req = odb_request_new(dev->ep_out, ODB_BULK_BUFFER_SIZE);
	if (!req)
		goto fail;
	req->complete = odb_complete_out;
	dev->rx_req = req;

	for (i = 0; i < TX_REQ_MAX; i++) {
		req = odb_request_new(dev->ep_in, ODB_BULK_BUFFER_SIZE);
		if (!req)
			goto fail;
		req->complete = odb_complete_in;
		odb_req_put(dev, &dev->tx_idle, req);
	}

	return 0;

fail:
	printk(KERN_ERR "odb_bind() could not allocate requests\n");
	return -1;
}

static ssize_t odb_read(struct file *fp, char __user *buf,
				size_t count, loff_t *pos)
{
	struct odb_dev *dev = fp->private_data;
	struct usb_request *req;
	int r = count, xfer;
	int ret;

	pr_debug("odb_read(%d)\n", count);
	if (!_odb_dev)
		return -ENODEV;

	if (count > ODB_BULK_BUFFER_SIZE)
		return -EINVAL;

	if (odb_lock(&dev->read_excl))
		return -EBUSY;

	/* we will block until we're online */
	while (!(atomic_read(&dev->online) || atomic_read(&dev->error))) {
		pr_debug("odb_read: waiting for online state\n");
		ret = wait_event_interruptible(dev->read_wq,
			(atomic_read(&dev->online) ||
			atomic_read(&dev->error)));
		if (ret < 0) {
			odb_unlock(&dev->read_excl);
			return ret;
		}
	}
	if (atomic_read(&dev->error)) {
		r = -EIO;
		goto done;
	}

requeue_req:
	/* queue a request */
	req = dev->rx_req;
	req->length = ODB_BULK_BUFFER_SIZE;
	dev->rx_done = 0;
	ret = usb_ep_queue(dev->ep_out, req, GFP_ATOMIC);
	if (ret < 0) {
		pr_debug("odb_read: failed to queue req %p (%d)\n", req, ret);
		r = -EIO;
		atomic_set(&dev->error, 1);
		goto done;
	} else {
		pr_debug("rx %p queue\n", req);
	}

	/* wait for a request to complete */
	ret = wait_event_interruptible(dev->read_wq, dev->rx_done ||
				atomic_read(&dev->error));
	if (ret < 0) {
		if (ret != -ERESTARTSYS)
		atomic_set(&dev->error, 1);
		r = ret;
		usb_ep_dequeue(dev->ep_out, req);
		goto done;
	}
	if (!atomic_read(&dev->error)) {
		/* If we got a 0-len packet, throw it back and try again. */
		if (req->actual == 0)
			goto requeue_req;

		pr_debug("rx %p %d\n", req, req->actual);
		xfer = (req->actual < count) ? req->actual : count;
		if (copy_to_user(buf, req->buf, xfer))
			r = -EFAULT;

	} else
		r = -EIO;

done:
	if (atomic_read(&dev->error))
		wake_up(&dev->write_wq);

	odb_unlock(&dev->read_excl);
	pr_debug("odb_read returning %d\n", r);
	return r;
}

static ssize_t odb_write(struct file *fp, const char __user *buf,
				 size_t count, loff_t *pos)
{
	struct odb_dev *dev = fp->private_data;
	struct usb_request *req = 0;
	int r = count, xfer;
	int ret;

	if (!_odb_dev)
		return -ENODEV;
	pr_debug("odb_write(%d)\n", count);

	if (odb_lock(&dev->write_excl))
		return -EBUSY;

	while (count > 0) {
		if (atomic_read(&dev->error)) {
			pr_debug("odb_write dev->error\n");
			r = -EIO;
			break;
		}

		/* get an idle tx request to use */
		req = 0;
		ret = wait_event_interruptible(dev->write_wq,
			((req = odb_req_get(dev, &dev->tx_idle)) ||
			 atomic_read(&dev->error)));

		if (ret < 0) {
			r = ret;
			break;
		}

		if (req != 0) {
			if (count > ODB_BULK_BUFFER_SIZE)
				xfer = ODB_BULK_BUFFER_SIZE;
			else
				xfer = count;
			if (copy_from_user(req->buf, buf, xfer)) {
				r = -EFAULT;
				break;
			}

			req->length = xfer;
			ret = usb_ep_queue(dev->ep_in, req, GFP_ATOMIC);
			if (ret < 0) {
				pr_debug("odb_write: xfer error %d\n", ret);
				atomic_set(&dev->error, 1);
				r = -EIO;
				break;
			}

			buf += xfer;
			count -= xfer;

			/* zero this so we don't try to free it on error exit */
			req = 0;
		}
	}

	if (req)
		odb_req_put(dev, &dev->tx_idle, req);

	if (atomic_read(&dev->error))
		wake_up(&dev->read_wq);

	odb_unlock(&dev->write_excl);
	pr_debug("odb_write returning %d\n", r);
	return r;
}

static int odb_open(struct inode *ip, struct file *fp)
{
	static DEFINE_RATELIMIT_STATE(rl, 10*HZ, 1);
	pr_err("%s: odb_open OK\n", __func__);
	if (__ratelimit(&rl))
		pr_info("odb_open\n");
	if (!_odb_dev)
		return -ENODEV;

	if (odb_lock(&_odb_dev->open_excl))
		return -EBUSY;

	fp->private_data = _odb_dev;

	/* clear the error latch */
	atomic_set(&_odb_dev->error, 0);

	if (_odb_dev->close_notified) {
		_odb_dev->close_notified = false;
		odb_ready_callback();
	}

	_odb_dev->notify_close = true;
	return 0;
}

static int odb_release(struct inode *ip, struct file *fp)
{
	static DEFINE_RATELIMIT_STATE(rl, 10*HZ, 1);
	pr_err("%s: odb_release OK\n", __func__);
	if (__ratelimit(&rl))
		pr_info("odb_release\n");

	/*
	 * ODB daemon closes the device file after I/O error.  The
	 * I/O error happen when Rx requests are flushed during
	 * cable disconnect or bus reset in configured state.  Disabling
	 * USB configuration and pull-up during these scenarios are
	 * undesired.  We want to force bus reset only for certain
	 * commands like "odb root" and "odb usb".
	 */
	if (_odb_dev->notify_close) {
		odb_closed_callback();
		_odb_dev->close_notified = true;
	}

	odb_unlock(&_odb_dev->open_excl);
	return 0;
}

/* file operations for ODB device /dev/android_odb */
static const struct file_operations odb_fops = {
	.owner = THIS_MODULE,
	.read = odb_read,
	.write = odb_write,
	.open = odb_open,
	.release = odb_release,
};

static struct miscdevice odb_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = odb_shortname,
	.fops = &odb_fops,
};




static int
odb_function_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct odb_dev	*dev = func_to_odb(f);
	int			id;
	int			ret;

	dev->cdev = cdev;
	DBG(cdev, "odb_function_bind dev: %p\n", dev);

	/* allocate interface ID(s) */
	id = usb_interface_id(c, f);
	if (id < 0)
		return id;
	odb_interface_desc.bInterfaceNumber = id;

	/* allocate endpoints */
	ret = odb_create_bulk_endpoints(dev, &odb_fullspeed_in_desc,
			&odb_fullspeed_out_desc);
	if (ret)
		return ret;

	/* support high speed hardware */
	if (gadget_is_dualspeed(c->cdev->gadget)) {
		odb_highspeed_in_desc.bEndpointAddress =
			odb_fullspeed_in_desc.bEndpointAddress;
		odb_highspeed_out_desc.bEndpointAddress =
			odb_fullspeed_out_desc.bEndpointAddress;
	}
	/* support super speed hardware */
	if (gadget_is_superspeed(c->cdev->gadget)) {
		odb_superspeed_in_desc.bEndpointAddress =
			odb_fullspeed_in_desc.bEndpointAddress;
		odb_superspeed_out_desc.bEndpointAddress =
			odb_fullspeed_out_desc.bEndpointAddress;
	}

	DBG(cdev, "%s speed %s: IN/%s, OUT/%s\n",
			gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full",
			f->name, dev->ep_in->name, dev->ep_out->name);
	return 0;
}

static void
odb_function_unbind(struct usb_configuration *c, struct usb_function *f)
{
	struct odb_dev	*dev = func_to_odb(f);
	struct usb_request *req;


	atomic_set(&dev->online, 0);
	atomic_set(&dev->error, 1);

	wake_up(&dev->read_wq);

	odb_request_free(dev->rx_req, dev->ep_out);
	while ((req = odb_req_get(dev, &dev->tx_idle)))
		odb_request_free(req, dev->ep_in);
}

static int odb_function_set_alt(struct usb_function *f,
		unsigned intf, unsigned alt)
{
	struct odb_dev	*dev = func_to_odb(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	int ret;

	DBG(cdev, "odb_function_set_alt intf: %d alt: %d\n", intf, alt);

	ret = config_ep_by_speed(cdev->gadget, f, dev->ep_in);
	if (ret) {
		dev->ep_in->desc = NULL;
		ERROR(cdev, "config_ep_by_speed failes for ep %s, result %d\n",
				dev->ep_in->name, ret);
		return ret;
	}
	ret = usb_ep_enable(dev->ep_in);
	if (ret) {
		ERROR(cdev, "failed to enable ep %s, result %d\n",
			dev->ep_in->name, ret);
		return ret;
	}

	ret = config_ep_by_speed(cdev->gadget, f, dev->ep_out);
	if (ret) {
		dev->ep_out->desc = NULL;
		ERROR(cdev, "config_ep_by_speed failes for ep %s, result %d\n",
			dev->ep_out->name, ret);
		usb_ep_disable(dev->ep_in);
		return ret;
	}
	ret = usb_ep_enable(dev->ep_out);
	if (ret) {
		ERROR(cdev, "failed to enable ep %s, result %d\n",
				dev->ep_out->name, ret);
		usb_ep_disable(dev->ep_in);
		return ret;
	}
	atomic_set(&dev->online, 1);

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);
	return 0;
}

static void odb_function_disable(struct usb_function *f)
{
	struct odb_dev	*dev = func_to_odb(f);
	struct usb_composite_dev	*cdev = dev->cdev;

	DBG(cdev, "odb_function_disable cdev %p\n", cdev);
	/*
	 * Bus reset happened or cable disconnected.  No
	 * need to disable the configuration now.  We will
	 * set noify_close to true when device file is re-opened.
	 */
	dev->notify_close = false;
	atomic_set(&dev->online, 0);
	atomic_set(&dev->error, 1);
	usb_ep_disable(dev->ep_in);
	usb_ep_disable(dev->ep_out);

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);

	VDBG(cdev, "%s disabled\n", dev->function.name);
}

static int odb_bind_config(struct usb_configuration *c)
{
	struct odb_dev *dev = _odb_dev;
	pr_err("%s: odb_bind_config OK\n", __func__);
	pr_debug("odb_bind_config\n");

	dev->cdev = c->cdev;
	dev->function.name = "odb";
	dev->function.descriptors = fs_odb_descs;
	dev->function.hs_descriptors = hs_odb_descs;
	if (gadget_is_superspeed(c->cdev->gadget))
		dev->function.ss_descriptors = ss_odb_descs;
	dev->function.bind = odb_function_bind;
	dev->function.unbind = odb_function_unbind;
	dev->function.set_alt = odb_function_set_alt;
	dev->function.disable = odb_function_disable;

	return usb_add_function(c, &dev->function);
}

static int odb_setup(void)
{
	struct odb_dev *dev;
	int ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	spin_lock_init(&dev->lock);

	init_waitqueue_head(&dev->read_wq);
	init_waitqueue_head(&dev->write_wq);

	atomic_set(&dev->open_excl, 0);
	atomic_set(&dev->read_excl, 0);
	atomic_set(&dev->write_excl, 0);

	/* config is disabled by default if odb is present. */
	dev->close_notified = true;

	INIT_LIST_HEAD(&dev->tx_idle);

	_odb_dev = dev;

	ret = misc_register(&odb_device);
	if (ret)
		goto err;

	return 0;

err:
	kfree(dev);
	printk(KERN_ERR "odb gadget driver failed to initialize\n");
	return ret;
}

static void odb_cleanup(void)
{
	misc_deregister(&odb_device);

	kfree(_odb_dev);
	_odb_dev = NULL;
}
