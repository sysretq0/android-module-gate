// SPDX-License-Identifier: GPL-2.0-only
/*
 * ModuleGate - audit + gate kernel module loads.
 *
 * A tiny LSM hooking kernel_post_load_data() for LOADING_MODULE, the single
 * choke point every insmod/modprobe/init/autoload path converges on
 * (finit_module). The hook receives the full module blob, so decisions are
 * made on the SHA256 of the actual bytes, not on spoofable names.
 *
 * Modes (sysfs `mode`, default 0):
 *   0 audit   - unknown hashes auto-enroll (TOFU), load allowed, logged.
 *   1 enforce - unknown hashes denied with -EPERM, logged, counted.
 * Boot phase (system_state < SYSTEM_RUNNING) never enforces: vendor init
 * loads dozens of modules before userspace exists, and a wrong list must
 * not brick boot. Audit/TOFU still records them, so the list is complete.
 *
 * No hooks on any hot path: fires once per module load (dozens at boot,
 * ~zero after), not per syscall or per open. List lookup under a mutex;
 * sysfs show capped like its sibling Partition Guard.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/version.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mm.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/kdev_t.h>

#define MG_HASH_LEN	32
#define MG_HEX_LEN	(MG_HASH_LEN * 2)
#define MG_MAX_ENROLLED	256
#define MG_SHOW_CAP	(PAGE_SIZE - 64)
/* Worst-case bytes of the "# ... N more" trailer; reserved up front. */
#define MG_TRUNC_RESERVE	64

struct mg_entry {
	struct list_head node;
	u8 hash[MG_HASH_LEN];
};

static LIST_HEAD(mg_list);
static unsigned int mg_count;
static DEFINE_MUTEX(mg_lock);
static int mg_mode; /* 0 audit, 1 enforce */
static atomic_t mg_denied = ATOMIC_INIT(0);
static struct kobject *mg_kobj;

static int mg_hash(const char *buf, loff_t size, u8 out[MG_HASH_LEN])
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int err, dsize;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	dsize = sizeof(*desc) + crypto_shash_descsize(tfm);
	desc = kmalloc(dsize, GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}
	desc->tfm = tfm;
	err = crypto_shash_init(desc) ? : crypto_shash_update(desc, buf, size) ? :
	      crypto_shash_final(desc, out);
	kfree(desc);
	crypto_free_shash(tfm);
	return err;
}

static bool mg_known(const u8 hash[MG_HASH_LEN])
{
	struct mg_entry *e;

	lockdep_assert_held(&mg_lock);
	list_for_each_entry(e, &mg_list, node) {
		if (!memcmp(e->hash, hash, MG_HASH_LEN))
			return true;
	}
	return false;
}

/* Caller holds mg_lock. 0 = enrolled or already present, -errno. */
static int mg_enroll_locked(const u8 hash[MG_HASH_LEN])
{
	struct mg_entry *e;

	if (mg_known(hash))
		return 0;
	if (mg_count >= MG_MAX_ENROLLED)
		return -ENOSPC;
	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;
	memcpy(e->hash, hash, MG_HASH_LEN);
	list_add_tail(&e->node, &mg_list);
	mg_count++;
	return 0;
}

static void mg_log(const u8 *hash, const char *what, const char *claimed)
{
	/* Who loaded it: exe path + comm/pid/uid, all kernel-owned. The
	 * module filename is spoofable and ELF-parsing it here would be new
	 * attack surface in the LSM, so loader identity (not module name)
	 * is what gets logged. comm alone is prctl-spoofable; the exe path
	 * is not. */
	{
		struct file *exe;
		char *page = (char *)__get_free_page(GFP_KERNEL);
		char *path = NULL;

		/* current->mm is NULL for kernel threads / exiting tasks and
		 * get_mm_exe_file() has no NULL guard: check first, or the
		 * LSM becomes the crash vector. */
		exe = current->mm ? get_mm_exe_file(current->mm) : NULL;
		if (exe && page)
			path = d_path(&exe->f_path, page, PAGE_SIZE);
		/* init_user_ns, not current_user_ns: the log is global, so the
		 * uid must be host-meaningful even if the caller sits in a
		 * userns. `claimed` is the hook's description string, printed
		 * verbatim and untrusted (grep aid, not identity). */
		if (hash)
			pr_info("module-gate: %s module sha256:%*phN claimed=%s exe=%s comm=%s pid=%d uid=%u\n",
				what, MG_HASH_LEN, hash, claimed ? claimed : "?",
				IS_ERR_OR_NULL(path) ? "?" : path,
				current->comm, task_pid_nr(current),
				from_kuid(&init_user_ns, current_uid()));
		else
			pr_info("module-gate: %s module (hash unavailable) claimed=%s exe=%s comm=%s pid=%d uid=%u\n",
				what, claimed ? claimed : "?",
				IS_ERR_OR_NULL(path) ? "?" : path,
				current->comm, task_pid_nr(current),
				from_kuid(&init_user_ns, current_uid()));
		if (exe)
			fput(exe);
		if (page)
			free_page((unsigned long)page);
	}
}

static int mg_post_load_data(char *buf, loff_t size,
			     enum kernel_load_data_id id, char *description)
{
	u8 hash[MG_HASH_LEN];
	bool have_hash, known;
	const char *what = NULL;
	int rc = 0;

	if (id != LOADING_MODULE)
		return 0;
	if (!buf || size <= 0)
		return 0;
	/* Decide under lock, log after unlock: the dcache walk and page
	 * allocation in mg_log() touch nothing the lock protects. */
	/* The hash-failure path needs no lock (atomic + READ_ONCE only);
	 * the list path below does. */
	have_hash = !mg_hash(buf, size, hash);
	if (!have_hash) {
		/* Hashing failed (allocation pressure): fail closed under
		 * enforce mode once userspace runs -- an allocation failure
		 * must not be a free pass. Audit/boot phases stay fail-open. */
		if (READ_ONCE(mg_mode) == 1 && system_state >= SYSTEM_RUNNING) {
			atomic_inc(&mg_denied);
			what = "denied";
			rc = -EPERM;
		}
	} else {
		int erc;

		mutex_lock(&mg_lock);
		known = mg_known(hash);
		if (!known && (READ_ONCE(mg_mode) == 0 || system_state < SYSTEM_RUNNING)) {
			erc = mg_enroll_locked(hash);
			/* A dropped enrollment must be loud: the header's
			 * completeness claim depends on every load being
			 * recorded. The module still loads (rc stays 0). */
			what = erc ? "enroll-failed" : "enrolled";
		} else if (!known) {
			atomic_inc(&mg_denied);
			what = "denied";
			rc = -EPERM;
		}
		mutex_unlock(&mg_lock);
	}
	if (what)
		mg_log(have_hash ? hash : NULL, what, description);
	return rc;
}

static struct security_hook_list mg_hooks[] = {
	LSM_HOOK_INIT(kernel_post_load_data, mg_post_load_data),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
static struct lsm_id mg_lsmid = {
	.name = "module_gate",
	.id = LSM_ID_UNDEF,
};

static void mg_add_hooks(void)
{
	security_add_hooks(mg_hooks, ARRAY_SIZE(mg_hooks), &mg_lsmid);
}
#else
static void mg_add_hooks(void)
{
	security_add_hooks(mg_hooks, ARRAY_SIZE(mg_hooks),
			   "module_gate");
}
#endif

/* --- sysfs --- */

static ssize_t mode_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(mg_mode));
}

static ssize_t mode_store(struct kobject *k, struct kobj_attribute *a,
			  const char *buf, size_t n)
{
	if (buf[0] == '0')
		WRITE_ONCE(mg_mode, 0);
	else if (buf[0] == '1')
		WRITE_ONCE(mg_mode, 1);
	else
		return -EINVAL;
	return n;
}

static ssize_t enrolled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
	struct mg_entry *e;
	unsigned int shown = 0;
	ssize_t n;

	mutex_lock(&mg_lock);
	n = scnprintf(buf, MG_SHOW_CAP, "# %u enrolled\n", mg_count);
	list_for_each_entry(e, &mg_list, node) {
		if (n + MG_HEX_LEN + 2 + MG_TRUNC_RESERVE > MG_SHOW_CAP) {
			n += scnprintf(buf + n, MG_SHOW_CAP - n,
				       "# ... %u more (one-page cap)\n",
				       mg_count - shown);
			break;
		}
		n += scnprintf(buf + n, MG_SHOW_CAP - n, "%*phN\n",
			       MG_HASH_LEN, e->hash);
		shown++;
	}
	mutex_unlock(&mg_lock);
	return n;
}

static int mg_hex(const char *s, u8 out[MG_HASH_LEN])
{
	int i;

	for (i = 0; i < MG_HEX_LEN; i++) {
		if (!isxdigit(s[i]))
			return -EINVAL;
	}
	for (i = 0; i < MG_HASH_LEN; i++) {
		unsigned int v;
		if (sscanf(s + 2 * i, "%2x", &v) != 1)
			return -EINVAL;
		out[i] = v;
	}
	return 0;
}

static ssize_t add_store(struct kobject *k, struct kobj_attribute *a,
			 const char *buf, size_t n)
{
	u8 hash[MG_HASH_LEN];
	int rc;

	if (n < MG_HEX_LEN || mg_hex(buf, hash))
		return -EINVAL;
	mutex_lock(&mg_lock);
	rc = mg_enroll_locked(hash);
	mutex_unlock(&mg_lock);
	return rc ? rc : n;
}

static ssize_t remove_store(struct kobject *k, struct kobj_attribute *a,
			    const char *buf, size_t n)
{
	u8 hash[MG_HASH_LEN];
	struct mg_entry *e, *tmp;
	bool found = false;

	if (n < MG_HEX_LEN || mg_hex(buf, hash))
		return -EINVAL;
	mutex_lock(&mg_lock);
	list_for_each_entry_safe(e, tmp, &mg_list, node) {
		if (!memcmp(e->hash, hash, MG_HASH_LEN)) {
			list_del(&e->node);
			kfree(e);
			mg_count--;
			found = true;
			break;
		}
	}
	mutex_unlock(&mg_lock);
	return found ? n : -ENOENT;
}

static ssize_t denied_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
	return sysfs_emit(buf, "%d\n", atomic_read(&mg_denied));
}

static struct kobj_attribute mg_mode_attr = __ATTR(mode, 0600, mode_show, mode_store);
static struct kobj_attribute mg_enrolled_attr = __ATTR(enrolled, 0400, enrolled_show, NULL);
static struct kobj_attribute mg_add_attr = __ATTR(add, 0200, NULL, add_store);
static struct kobj_attribute mg_remove_attr = __ATTR(remove, 0200, NULL, remove_store);
static struct kobj_attribute mg_denied_attr = __ATTR(denied, 0400, denied_show, NULL);

static struct attribute *mg_attrs[] = {
	&mg_mode_attr.attr,
	&mg_enrolled_attr.attr,
	&mg_add_attr.attr,
	&mg_remove_attr.attr,
	&mg_denied_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(mg);

static int __init module_gate_init(void)
{
	mg_add_hooks();
	mg_kobj = kobject_create_and_add("module_gate", kernel_kobj);
	if (!mg_kobj)
		return 0; /* hooks live on; sysfs is convenience */
	if (sysfs_create_groups(mg_kobj, mg_groups)) {
		kobject_put(mg_kobj);
		mg_kobj = NULL;
	}
	pr_info("module-gate: active (audit mode)\n");
	return 0;
}
device_initcall(module_gate_init);
