#ifndef _KMVIEW_H
#define _KMVIEW_H

#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <asm/pgtable_types.h>

struct kmview {
     /* Unique id of the kmview, currently not used */
     unsigned long id;

     /* Global list of all kmviews */
     struct list_head list;

     /* Reference count; modify via kmview_{put, set}
      * kmviews start with a value of 1; increases for mm_struct that uses it */
     atomic_t users;

     /* The directory */
     pud_t *pud;
};

struct kmview_pgd {
     /* The parent kmview of this instance */
     struct kmview *kmview;

     /* Connects all kmview_pgds of a mm */
     struct list_head list;

     /* The pgd of this kmview */
     pgd_t *pgd;
};

extern struct list_head kmview_list;
extern rwlock_t kmview_list_lock;

extern struct kmview init_kmview;
extern struct kmview_pgd init_kmview_pgd;

struct kmview *kmview_create(void);

int kmview_mm_init(struct mm_struct *mm);
void kmview_mm_release(struct mm_struct *mm);

void __init kmview_init(void);

static inline void kmview_get(struct kmview *kmview) {
     atomic_inc(&kmview->users);
}

void kmview_put(struct kmview *mm);

struct kmview_pgd *mm_get_kmview_pgd(struct mm_struct *mm,
				     struct kmview *kmview);

struct page *kmview_vmalloc_to_page(struct kmview *kmview,
				    const void *vmalloc_addr);

#endif
