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

static pud_t *do_replace_kernel_pud(struct mm_struct *mm, pud_t *new,
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

// Muste be called with text_mutex and with cpus_read_lock
static pud_t *replace_kernel_pud(pud_t *new, unsigned long addr)
{
	pud_t *old_pud_init, *old_pud_poking;
	struct task_struct *proc;

	unsigned long entry_start = addr & P4D_MASK;
	unsigned long entry_end = entry_start + (P4D_SIZE - 1);

	old_pud_init = do_replace_kernel_pud(&init_mm, new, entry_start);
	old_pud_poking = do_replace_kernel_pud(poking_mm, new, entry_start);
	BUG_ON((pud_val(*old_pud_init) & pud_pfn_mask(*old_pud_init)) !=
	       (pud_val(*old_pud_poking) & pud_pfn_mask(*old_pud_poking)));

	read_lock(&tasklist_lock);
	for_each_process(proc) {
		pud_t* old_pud;
		struct mm_struct *mm;

		if (proc->flags & PF_KTHREAD)
			continue;
		if (proc->group_leader != proc)
			continue;

		mm = proc->mm;
		old_pud = do_replace_kernel_pud(mm, new, entry_start);
		BUG_ON((pud_val(*old_pud_init) & pud_pfn_mask(*old_pud_init)) !=
		       (pud_val(*old_pud) & pud_pfn_mask(*old_pud)));
	}
	read_unlock(&tasklist_lock);

	flush_tlb_kernel_range(entry_start, entry_end);

	return old_pud_init;
}

int kmview_create(void)
{
	extern u8 _text;
	extern u8 _etext;
	const unsigned long start = (unsigned long)(&_text);
	const unsigned long end = (unsigned long)(&_etext);

	pud_t *new_pud;
	int ret;

	// FIXME Needs CONFIG_PGTABLE_LEVELS >= 4  (64 bit AS)
	BUG_ON(CONFIG_PGTABLE_LEVELS < 4);

	printk(KERN_INFO "text segment: %lx, %lx\n", start, end);

	cpus_read_lock();
	mutex_lock(&text_mutex);

	new_pud = kmview_shallow_clone_range(start & P4D_MASK);
	printk(KERN_INFO "PUD %px", new_pud);

	ret = copy_pud_range(new_pud, start, end);
	if (ret)
		printk(KERN_INFO "ERROR");

	replace_kernel_pud(new_pud, start);

	mutex_unlock(&text_mutex);
	cpus_read_unlock();

	printk(KERN_INFO "Replaced PUD\n");

	return 0;
}
EXPORT_SYMBOL_GPL(kmview_create);
