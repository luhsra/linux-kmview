#ifndef _KMVIEW_H
#define _KMVIEW_H

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

extern struct kmview init_kmview;

void kmview_walk_pages(void);
struct kmview *kmview_create(void);
void kmview_switch(struct kmview *kmview);
void kmview_switch_all(struct kmview *kmview);

void kmview_mm_init(struct mm_struct *mm);
void kmview_mm_release(struct mm_struct *mm);

void __init kmview_init(void);

static inline void kmview_get(struct kmview *kmview) {
     atomic_inc(&kmview->users);
}

void kmview_put(struct kmview *mm);

int kmview_test_function(int xy);

#endif
