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

#define dbgexp(fmt, exp)						\
	printk(KERN_INFO "DBGEXP: " __FILE__ ":%d [%s]: [%s] " #exp ": " \
	       fmt "\n", __LINE__, __func__, #fmt, exp)

extern u8 _text;
extern u8 _etext;
#define TEXT_START ((unsigned long)(&_text))
#define TEXT_END ((unsigned long)(&_etext))

struct kmview init_kmview = {
	.id = 0,
	.list = LIST_HEAD_INIT(init_kmview.list),
	.users = ATOMIC_INIT(1),
	.pud = NULL,
};

static struct list_head kmview_list = LIST_HEAD_INIT(kmview_list);

__cacheline_aligned DEFINE_RWLOCK(kmview_lock);

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

/* Replace a single pud at addr. Return the old pud.
 * Must be called with text_mutex and with cpus_read_lock
 * Kernel tlb range must be flushed afterwards */
static pud_t *replace_kernel_pud(struct mm_struct *mm, pud_t *new,
				 unsigned long addr) {
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *old_pud;

	spin_lock(&mm->page_table_lock);

	pgd = pgd_offset_pgd(mm->pgd, addr);
	p4d = p4d_offset(pgd, addr);
	// FIXME: Currently: Assume folded p4d -- only 4-level
	old_pud = pud_offset(p4d, addr);

	/* p4d_populate(mm, p4d, new); */
	WRITE_ONCE(*p4d, __p4d(_PAGE_TABLE | __pa(new)));  // intentionally no PTI, FIXME: pv?

	spin_unlock(&mm->page_table_lock);
	return old_pud;
}

int kmview_test_function(int xy)
{
	return xy + 42;
}
EXPORT_SYMBOL_GPL(kmview_test_function);

struct kmview *kmview_create(void)
{
	int error;
	struct kmview *new;

	// FIXME
	atomic_t curr_id = ATOMIC_INIT(0);

	// FIXME Needs CONFIG_PGTABLE_LEVELS >= 4  (64 bit AS)
	BUG_ON(CONFIG_PGTABLE_LEVELS < 4);
	/* printk(KERN_INFO "text segment: %lx, %lx\n", TEXT_START, TEXT_END); */

	new = kmalloc(sizeof(struct kmview), GFP_KERNEL);

	cpus_read_lock();
	mutex_lock(&text_mutex);

	new->pud = kmview_shallow_clone_range(TEXT_START & P4D_MASK);

	error = copy_pud_range(new->pud, TEXT_START, TEXT_END);
	if (error)
		goto error_unlock;

	mutex_unlock(&text_mutex);
	cpus_read_unlock();

	new->id = atomic_inc_return(&curr_id);
	atomic_set(&new->users, 1);

	write_lock(&kmview_lock);
	list_add_tail(&new->list, &kmview_list);
	write_unlock(&kmview_lock);

	return new;
error_unlock:
	mutex_unlock(&text_mutex);
	cpus_read_unlock();
	kfree(new);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(kmview_create);

void kmview_switch(struct kmview *kmview) {
	struct kmview *old_kmview;
	unsigned long entry_start = TEXT_START & P4D_MASK;
	unsigned long entry_end = entry_start + (P4D_SIZE - 1);
	struct mm_struct *mm = current->mm;

	cpus_read_lock();
	mutex_lock(&text_mutex);
	mmap_write_lock(mm);
	if (mm->kmview == kmview) {
		mmap_write_unlock(mm);
		mutex_unlock(&text_mutex);
		cpus_read_unlock();
		return;
	}
	kmview_get(kmview);
	old_kmview = mm->kmview;
	mm->kmview = kmview;

	replace_kernel_pud(mm, kmview->pud, entry_start);

	mmap_write_unlock(mm);
	mutex_unlock(&text_mutex);
	cpus_read_unlock();

	kmview_put(old_kmview);

	// FIXME: only flush cpus with this mm
	// ... on_each_cpu_mask(mm_cpumask(mm), ..., info, 1);
	flush_tlb_kernel_range(entry_start, entry_end);
}
EXPORT_SYMBOL_GPL(kmview_switch);

void kmview_switch_all(struct kmview *kmview) {
	struct task_struct *proc;
	unsigned long entry_start = TEXT_START & P4D_MASK;
	unsigned long entry_end = entry_start + (P4D_SIZE - 1);

	// TODO dec users, inc users (in replace_kernel_pud)
	cpus_read_lock();
	mutex_lock(&text_mutex);
	read_lock(&tasklist_lock);

	/* mmap_write_lock(&init_mm); */
	if (init_mm.kmview != kmview) {
		struct kmview *old_kmview;
		kmview_get(kmview);
		old_kmview = init_mm.kmview;
		init_mm.kmview = kmview;
		replace_kernel_pud(&init_mm, kmview->pud, entry_start);
		/* _replace_kernel_pud(poking_mm, kmview->pud, entry_start); */
		kmview_put(old_kmview);
	}
	/* mmap_write_unlock(&init_mm); */

	for_each_process(proc) {
		struct kmview *old_kmview;
		struct mm_struct *mm = proc->mm;
		if (proc->flags & PF_KTHREAD)
			continue;
		if (proc->group_leader != proc)
			continue;
		BUG_ON(!mm);
		/* mmap_write_lock(mm); */
		if (mm->kmview == kmview) {
			/* mmap_write_unlock(mm); */
			continue;
		}
		kmview_get(kmview);
		old_kmview = mm->kmview;
		mm->kmview = kmview;
		replace_kernel_pud(mm, kmview->pud, entry_start);
		/* mmap_write_unlock(mm); */
		kmview_put(old_kmview);
	}

	read_unlock(&tasklist_lock);
	mutex_unlock(&text_mutex);
	cpus_read_unlock();

	flush_tlb_kernel_range(entry_start, entry_end);
}
EXPORT_SYMBOL_GPL(kmview_switch_all);

void kmview_mm_init(struct mm_struct *mm) {
	struct kmview *kmview;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;

	// FIXME: kernel text is copied in
	// mm_init->mm_alloc_pgd->pgd_alloc->pgd_ctor
	// but this seems not to be protected...
	mmap_read_lock(&init_mm);
	kmview = init_mm.kmview;
	kmview_get(kmview);

	pgd = pgd_offset_pgd(mm->pgd, TEXT_START & P4D_MASK);
	p4d = p4d_offset(pgd, TEXT_START & P4D_MASK);
	pud = pud_offset(p4d, TEXT_START & P4D_MASK);
	/* kmview->pud gets set in init_ */
	BUG_ON(kmview->pud && kmview->pud != pud);

	mm->kmview = kmview;
	mmap_read_unlock(&init_mm);
}

void kmview_mm_release(struct mm_struct *mm) {
	kmview_put(mm->kmview);
}

void __init kmview_init(void) {
	pgd_t *pgd = pgd_offset_pgd(init_mm.pgd, TEXT_START & P4D_MASK);
	p4d_t *p4d = p4d_offset(pgd, TEXT_START & P4D_MASK);
	pud_t *pud = pud_offset(p4d, TEXT_START & P4D_MASK);
	BUG_ON(init_kmview.pud);
	kmview_get(&init_kmview);
	init_kmview.pud = pud;
	list_add_tail(&init_kmview.list, &kmview_list);
}

void kmview_put(struct kmview *kmview)
{
	if (atomic_dec_and_test(&kmview->users)) {
		write_lock(&kmview_lock);
		list_del(&kmview->list);
		write_unlock(&kmview_lock);
		// TODO: free the pud
		kfree(kmview);
	}
}

static struct proc_dir_entry* kmview_stats_file;

static int kmview_stats_show(struct seq_file *m, void *v)
{
	struct task_struct *proc;
	struct kmview *item;

	read_lock(&kmview_lock);
	read_lock(&tasklist_lock);

	seq_printf(m, "kmviews:\n");
	item = &init_kmview;
	list_for_each_entry_from(item, &kmview_list, list) {
		seq_printf(m, "\t%lu\tusers:%lu\n",
			   item->id, atomic_read(&item->users));
	}
	seq_printf(m, "\n");

	seq_printf(m, "tasks:\n");
	for_each_process(proc) {
		seq_printf(m, "\t%lu\tmm: %p", proc->pid, proc->mm);
		if (proc->mm)
			seq_printf(m, "\t kmview: %lu\n", proc->mm->kmview->id);
		else
			seq_printf(m, "\t kmview: n/a\n");
	}

	read_unlock(&tasklist_lock);
	read_unlock(&kmview_lock);

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
	long ret = kstrtoint_from_user(buf, count, 10, &pid);
	if (ret != 0)
		return ret;

	printk(KERN_INFO "kmview: switch pid: %d\n", pid);

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
