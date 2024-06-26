#include <linux/syscalls.h>
#include <linux/pgtable.h>
#include <linux/vmalloc.h>
#include <linux/mmap_lock.h>
#include <linux/mm_types.h>
#include <linux/kmview.h>
#include <linux/pagewalk.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/memory.h>
#include <linux/cpu.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/text-patching.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mmu_context.h>

#define dbgexp(fmt, exp)						\
	printk(KERN_INFO "DBGEXP: " __FILE__ ":%d [%s]: [%s] " #exp ": " \
	       fmt "\n", __LINE__, __func__, #fmt, exp)

#define TEXT_START ((unsigned long)(_text))
#define TEXT_END ((unsigned long)(_etext))

struct kmview init_kmview = {
	.id = 0,
	.list = LIST_HEAD_INIT(init_kmview.list),
	.users = ATOMIC_INIT(1),
	.pud = NULL,
};

struct kmview_pgd init_kmview_pgd = {
	.kmview = &init_kmview,
	.list = LIST_HEAD_INIT(init_kmview_pgd.list),
	.pgd = swapper_pg_dir,
};

/* List of all kmviews, */
struct list_head kmview_list = LIST_HEAD_INIT(kmview_list);

__cacheline_aligned DEFINE_RWLOCK(kmview_list_lock);

static pud_t *kmview_shallow_clone_range(unsigned long start)
{
	pgd_t *src_pgd;
	p4d_t *src_p4d;
	pud_t *src_pud;
	pud_t *dst_pud;

	src_pgd = pgd_offset_pgd(init_mm.pgd, start);
	src_p4d = p4d_offset(src_pgd, start);
	// FIXME: Currently: Assume folded p4d -- only 4-level
	src_pud = pud_offset(src_p4d, start);
	dst_pud = pud_alloc_one(&init_mm, start);
	if (!dst_pud)
		return NULL;

	spin_lock(&init_mm.page_table_lock);
	memcpy(dst_pud, src_pud, PTRS_PER_PUD * sizeof(pud_t));
	spin_unlock(&init_mm.page_table_lock);

	return dst_pud;
}

static int
copy_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end)
{
	pte_t *src_pte, *dst_pte;

	// Get the whole pte
	src_pte = (pte_t *)pmd_page_vaddr(*pmd);
	dst_pte = pte_alloc_one_kernel(&init_mm);
	if (!dst_pte)
		return -ENOMEM;

	// Copy and populate all pte entries
	memcpy(dst_pte, src_pte, PTRS_PER_PTE * sizeof(pte_t));
	pmd_populate_kernel(&init_mm, pmd, dst_pte);

	// Jump to pte entry of the address
	src_pte += pte_index(addr);
	dst_pte += pte_index(addr);

	do {
		struct page *dst_page;
		void *dst_addr;
		pte_t entry;

		if (pte_none(*dst_pte))
			continue;

		/* printk(KERN_INFO "C PTE: %lx  (%lx)\n", */
		/*        addr, */
		/*        pte_val(*dst_pte)); */

		// Copy page
		dst_page = alloc_pages(GFP_PGTABLE_KERNEL, 0);
		dst_addr = page_address(dst_page);
		memcpy(dst_addr, (void*)addr, PAGE_SIZE);

		// Set page
		entry = mk_pte(dst_page, __pgprot(pte_flags(*dst_pte)));
		/* entry = mk_pte(dst_page, __pgprot(__PAGE_KERNEL_EXEC)); */
		/* entry = mk_pte(dst_page, __pgprot(__PAGE_KERNEL)); */
		set_pte_at(&init_mm, addr, dst_pte, entry);

	} while (dst_pte++, addr += PAGE_SIZE, addr < end);

	return 0;
}

static inline int
copy_pmd_range(pud_t *pud, unsigned long addr, unsigned long end)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;

	// Get the whole pmd
	src_pmd = pud_pgtable(*pud);
	dst_pmd = pmd_alloc_one(&init_mm, addr);
	if (!dst_pmd)
		return -ENOMEM;

	// Copy and populate all pmd entries
	memcpy(dst_pmd, src_pmd, PTRS_PER_PMD * sizeof(pmd_t));
	pud_populate(&init_mm, pud, dst_pmd);

	// Jump to pmd entry of the address
	src_pmd += pmd_index(addr);
	dst_pmd += pmd_index(addr);

	do {
		next = pmd_addr_end(addr, end);

		if (pmd_none(*dst_pmd))
			continue;

		if (pmd_large(*dst_pmd)) {
			struct page *dst_page;
			void *dst_addr;
			pmd_t entry;

			/* printk(KERN_INFO "C LARGE PMD: %lx  (%lx)\n", */
			/*        addr, */
			/*        pmd_val(*dst_pmd)); */

			// Copy huge page
			dst_page = alloc_pages(GFP_PGTABLE_KERNEL, HUGETLB_PAGE_ORDER);
			dst_addr = page_address(dst_page);
			memcpy(dst_addr, (void*)addr, HPAGE_SIZE);

			// Set huge page
			entry = mk_pmd(dst_page, __pgprot(pmd_flags(*dst_pmd)));
			/* entry = mk_pmd(dst_page, __pgprot(__PAGE_KERNEL_EXEC)); */
			/* entry = mk_pmd(dst_page, __pgprot(__PAGE_KERNEL)); */
			set_pmd_at(&init_mm, addr, dst_pmd, entry);
		} else {
			int err;
			/* printk(KERN_INFO "C PMD: %lx  (%lx)\n", */
			/*        addr, */
			/*        pmd_val(*dst_pmd)); */
			err = copy_pte_range(dst_pmd, addr, next);
			if (err)
				return err;
		}
	} while (dst_pmd++, addr = next, addr < end);

	return 0;
}

static int
copy_pud_range(pud_t *pud, unsigned long addr, unsigned long end)
{
	unsigned long next;
	pud += pud_index(addr);

	do {
		next = pud_addr_end(addr, end);

		if (pud_none(*pud))
			continue;

		if (pud_large(*pud)) {
			/* printk(KERN_INFO "C LARGE PUD: %lx  (%lx)\n", */
			/*        addr, */
			/*        pud_val(*pud)); */
			// TODO copy huge page
			BUG();
		} else {
			int err;
			/* printk(KERN_INFO "C PUD: %lx  (%lx)\n", */
			/*        addr, */
			/*        pud_val(*pud)); */
			err = copy_pmd_range(pud, addr, next);
			if (err)
				return err;
		}
	} while (pud++, addr = next, addr < end);

	return 0;
}

static pud_t *replace_kernel_pud(pgd_t *target_pgd, pud_t *new) {
	unsigned long entry_start = TEXT_START & P4D_MASK;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *old_pud;

	pgd = pgd_offset_pgd(target_pgd, entry_start);
	p4d = p4d_offset(pgd, entry_start);
	// FIXME: Currently: Assume folded p4d -- only 4-level
	old_pud = pud_offset(p4d, entry_start);

	/* p4d_populate(mm, p4d, new); */
	WRITE_ONCE(*p4d, __p4d(_PAGE_TABLE | __pa(new)));

	return old_pud;
}

struct kmview *kmview_create(void)
{
	int error;
	struct kmview *new;

	// FIXME
	static atomic_t curr_id = ATOMIC_INIT(0);

	// FIXME Needs CONFIG_PGTABLE_LEVELS >= 4  (64 bit AS)
	BUG_ON(CONFIG_PGTABLE_LEVELS < 4);
	/* printk(KERN_INFO "text segment: %lx, %lx\n", TEXT_START, TEXT_END); */

	new = kmalloc(sizeof(struct kmview), GFP_KERNEL);

	mutex_lock(&text_mutex);

	new->pud = kmview_shallow_clone_range(TEXT_START & P4D_MASK);

	error = copy_pud_range(new->pud, TEXT_START, TEXT_END);
	if (error)
		goto error_unlock;

	new->id = atomic_inc_return(&curr_id);
	atomic_set(&new->users, 1);

	write_lock(&kmview_list_lock);
	list_add_tail(&new->list, &kmview_list);
	write_unlock(&kmview_list_lock);

	/* Make a kmview_pgd for poking_mm for the newely created kmview.
	   We cannot do this on demand in __text_poke. */
	mm_get_kmview_pgd(poking_mm, new);

	mutex_unlock(&text_mutex);

	return new;
error_unlock:
	mutex_unlock(&text_mutex);
	kfree(new);
	return ERR_PTR(error);
}

struct kmview_pgd *mm_get_kmview_pgd(struct mm_struct *mm,
				     struct kmview *kmview) {
	struct kmview_pgd *kmview_pgd = NULL;

	mmap_write_lock(mm);

	// Check if kmview_pgd for this already exists
	list_for_each_entry(kmview_pgd, &mm->kmview_pgds, list) {
		if (kmview_pgd->kmview == kmview)
			break;
	}

	if (list_entry_is_head(kmview_pgd, &mm->kmview_pgds, list)) {
		// Found no suitable kmview_pgd -> make a new one
		kmview_pgd = kmalloc(sizeof(struct kmview_pgd), GFP_KERNEL);
		if (unlikely(!kmview_pgd))
			goto out;

		kmview_pgd->kmview = kmview;

		/* Get a new pgd with the kernelspace already cloned */
		kmview_pgd->pgd = pgd_dup_kernel(mm);
		if (unlikely(!kmview_pgd->pgd)) {
			kfree(kmview_pgd);
			goto out;
		}

		/* Clone userspace entries and add it to the kmview_pgd list */
		spin_lock(&mm->page_table_lock);
		/* FIXME: This works only for x86_64 at the moment (most likely) */
		clone_pgd_range(kmview_pgd->pgd, mm->pgd,
				KERNEL_PGD_BOUNDARY);
		list_add_tail(&kmview_pgd->list, &mm->kmview_pgds);
		spin_unlock(&mm->page_table_lock);

		replace_kernel_pud(kmview_pgd->pgd, kmview->pud);
	}

out:
	mmap_write_unlock(mm);
	return kmview_pgd;
}

int kmview_mm_init(struct mm_struct *mm) {
	struct kmview_pgd *kmview_pgd;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;

	kmview_pgd = kmalloc(sizeof(struct kmview_pgd), GFP_KERNEL);
	if (unlikely(!kmview_pgd))
		return -ENOMEM;

	pgd = pgd_offset_pgd(mm->pgd, TEXT_START & P4D_MASK);
	p4d = p4d_offset(pgd, TEXT_START & P4D_MASK);
	pud = pud_offset(p4d, TEXT_START & P4D_MASK);
	BUG_ON(init_kmview.pud != pud);
	kmview_pgd->kmview = &init_kmview;
	kmview_pgd->pgd = mm->pgd;
	INIT_LIST_HEAD(&mm->kmview_pgds);
	list_add_tail(&kmview_pgd->list, &mm->kmview_pgds);
	return 0;
}

void kmview_mm_release(struct mm_struct *mm) {
	struct kmview_pgd *kmview_pgd, *tmp;

	list_for_each_entry_safe(kmview_pgd, tmp, &mm->kmview_pgds, list) {
		if (kmview_pgd->pgd != mm->pgd)
			kmview_pgd_pgd_free(kmview_pgd->pgd);
		list_del(&kmview_pgd->list);
		kfree(kmview_pgd);
	}
}

void __init kmview_init(void) {
	pgd_t *pgd = pgd_offset_pgd(init_mm.pgd, TEXT_START & P4D_MASK);
	p4d_t *p4d = p4d_offset(pgd, TEXT_START & P4D_MASK);
	pud_t *pud = pud_offset(p4d, TEXT_START & P4D_MASK);
	BUG_ON(init_kmview.pud);
	kmview_get(&init_kmview);
	init_kmview.pud = pud;
	list_add_tail(&init_kmview.list, &kmview_list);
	list_add_tail(&init_kmview_pgd.list, &init_mm.kmview_pgds);
	/* init_kmview_pgd.pgd = init_mm.pgd; */
}

void kmview_put(struct kmview *kmview)
{
	if (atomic_dec_and_test(&kmview->users)) {
		write_lock(&kmview_list_lock);
		list_del(&kmview->list);
		write_unlock(&kmview_list_lock);
		// TODO: free the pud
		kfree(kmview);
	}
}

/* This is the kmview version of vmalloc_to_page */
struct page *kmview_vmalloc_to_page(struct kmview *kmview,
				    const void *vmalloc_addr)
{
	unsigned long addr = (unsigned long) vmalloc_addr;
	struct page *page = NULL;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;

	/*
	 * XXX we might need to change this if we add VIRTUAL_BUG_ON for
	 * architectures that do not vmalloc module space
	 */
	VIRTUAL_BUG_ON(!is_vmalloc_or_module_addr(vmalloc_addr));

	pud = kmview->pud + pud_index(addr);
	if (pud_none(*pud))
		return NULL;
	if (pud_leaf(*pud))
		return pud_page(*pud) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	if (WARN_ON_ONCE(pud_bad(*pud)))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;
	if (pmd_leaf(*pmd))
		return pmd_page(*pmd) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	if (WARN_ON_ONCE(pmd_bad(*pmd)))
		return NULL;

	ptep = pte_offset_map(pmd, addr);
	pte = *ptep;
	if (pte_present(pte))
		page = pte_page(pte);
	pte_unmap(ptep);

	return page;
}

static struct proc_dir_entry* kmview_stats_file;

static int kmview_stats_show(struct seq_file *m, void *v)
{
	struct task_struct *proc, *thread;
	struct kmview *item;

	read_lock(&kmview_list_lock);
	read_lock(&tasklist_lock);

	seq_printf(m, "kmviews:\n");
	BUG_ON(list_empty(&kmview_list));
	list_for_each_entry(item, &kmview_list, list) {
		seq_printf(m, "\t%lu\tusers:%d\n",
			   item->id, atomic_read(&item->users));
	}
	seq_printf(m, "\n");

	seq_printf(m, "tasks:\n");
	for_each_process_thread(proc, thread) {
		seq_printf(m, "\t%d\t%d\tmm: %p\tkmview: %lu\n",
			   proc->pid, thread->pid, thread->mm,
			   thread->kmview_pgd->kmview->id);
	}

	read_unlock(&tasklist_lock);
	read_unlock(&kmview_list_lock);

	return 0;
}
static int kmview_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, kmview_stats_show, NULL);
}

static const struct proc_ops kmview_stats_fops = {
	.proc_open	 = kmview_stats_open,
	.proc_read	 = seq_read,
	.proc_lseek	 = seq_lseek,
	.proc_release = single_release,
};

static int __init kmview_stats_init(void) {
	kmview_stats_file = proc_create("kmview_stats", 0, NULL, &kmview_stats_fops);
	return 0;
}

subsys_initcall(kmview_stats_init);


static struct proc_dir_entry* kmview_switch_pid_file;

static ssize_t kmview_switch_pid_write(struct file *file, const char __user *buf,
				       size_t count, loff_t *ppos)
{
	pid_t pid;
	struct kmview *kmview, *old_kmview;
	struct kmview_pgd *kmview_pgd;
	struct task_struct *task;

	long ret = kstrtoint_from_user(buf, count, 10, &pid);
	if (ret != 0)
		return ret;

	/* Create a new kmview */
	kmview = kmview_create();
	if (!kmview)
		return -ENOMEM;

	/* patch_something(kmview); */

	/* Get the task by pid */
	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (!task) {
		rcu_read_unlock();
		return -EINVAL;
	}
	get_task_struct(task);
	rcu_read_unlock();

	kmview_get(kmview);

	/* Set the task's kmview to the newly created kmview.
	   It will be used after a context switch. */
	kmview_pgd = mm_get_kmview_pgd(task->mm, kmview);
	if (!kmview_pgd) {
		put_task_struct(task);
		return -ENOMEM;
	}
	old_kmview = task->kmview_pgd->kmview;
	task->kmview_pgd = kmview_pgd;
	kmview_put(old_kmview);

	put_task_struct(task);

	printk(KERN_INFO "kmview: switch thread:%d to kmview:%lu\n", pid, kmview->id);

	return count;
}

static const struct proc_ops kmview_switch_pid_fops = {
	.proc_write	= kmview_switch_pid_write,
	.proc_lseek	= noop_llseek,
};

static int __init kmview_switch_pid_init(void) {
	kmview_switch_pid_file = proc_create("kmview_switch_pid", S_IWUSR, NULL, &kmview_switch_pid_fops);
	return 0;
}

subsys_initcall(kmview_switch_pid_init);


SYSCALL_DEFINE0(kmview)
{
	struct kmview *kmview, *old_kmview;
	struct kmview_pgd *kmview_pgd_current;
	unsigned long flags;

	/* Create a new kmview */
	kmview = kmview_create();
	if (!kmview)
		return -ENOMEM;

	kmview_get(kmview);

	kmview_pgd_current = mm_get_kmview_pgd(current->mm, kmview);
	if (!kmview_pgd_current)
		return -ENOMEM;

	local_irq_save(flags);
	lockdep_assert_irqs_disabled();
	old_kmview = current->kmview_pgd->kmview;
	current->kmview_pgd = kmview_pgd_current;
	switch_mm_irqs_off(current->mm, current->mm, old_kmview,
			   kmview_pgd_current, current);
	local_irq_restore(flags);

	printk(KERN_INFO "kmview: Switched to kmview %lu\n", kmview->id);

	return 0;
}
