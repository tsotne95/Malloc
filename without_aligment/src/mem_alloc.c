#include "mem_alloc.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "mem_alloc_types.h"
#include "my_mmap.h"

/* pointer to the beginning of the memory region to manage */
void *heap_start;

/* Pointer to the first free block in the heap */
mem_free_block_t *first_free;

//defines
#define ULONG(x) ((long unsigned int)(x))
#define MAX(x, y) ((x > y) ? x : y)
#define MIN_FREE_BLOCK_SIZE (sizeof(mem_free_block_t))
#define MIN_USED_BLOCK_SIZE (sizeof(mem_used_block_t))

#if defined(FIRST_FIT)

/* TODO: code specific to the FIRST FIT allocation policy can be
 * inserted here */

/* You can define here functions that will be compiled only if the
 * symbol FIRST_FIT is defined, that is, only if the selected policy
 * is FF */
mem_free_block_t *get_free_block(size_t size)
{
  mem_free_block_t *tmp = first_free;
  //check every next position
  //while don't find enough one
  //which is free
  while (tmp && !(tmp->size + MIN_FREE_BLOCK_SIZE >= MAX(size + MIN_USED_BLOCK_SIZE, MIN_FREE_BLOCK_SIZE)))
    tmp = tmp->next;

  return tmp;
}
#elif defined(BEST_FIT)

/* TODO: code specific to the BEST FIT allocation policy can be
 * inserted here */
mem_free_block_t *get_free_block(size_t size)
{
  mem_free_block_t *tmp = first_free;
  mem_free_block_t *best_one = NULL;

  while (tmp)
  {
    if (tmp->size + MIN_FREE_BLOCK_SIZE >= MAX(size + MIN_USED_BLOCK_SIZE, MIN_FREE_BLOCK_SIZE))
    {
      if (!best_one || tmp->size < best_one->size)
        best_one = tmp;
    }
    tmp = tmp->next;
  }

  return best_one;
}
#elif defined(NEXT_FIT)

/* TODO: code specific to the NEXT FIT allocation policy can be
 * inserted here */
mem_free_block_t *next_free;
mem_free_block_t *get_free_block(size_t size)
{
  mem_free_block_t *tmp = next_free;
  int flag = 0;

  while (tmp && !(tmp->size + MIN_FREE_BLOCK_SIZE >= MAX(size + MIN_USED_BLOCK_SIZE, MIN_FREE_BLOCK_SIZE)))
  {
    if (flag && (unsigned char *)tmp == (unsigned char *)next_free)
      return NULL;

    if (tmp->next)
      tmp = tmp->next;
    else
    {
      flag = 1;
      tmp = first_free;
    }
  }

  return tmp;
}
#endif

//add new block between two blocks
void add_free_block(mem_free_block_t *new_b, mem_free_block_t *left, mem_free_block_t *right)
{
  if (right)
    right->prev = new_b;
  new_b->next = right;
  new_b->prev = left;
  if (left)
    left->next = new_b;
  else
    first_free = new_b;
}

//delete free block from free list
void delete_free_block(mem_free_block_t *block)
{
  if (!block->prev)
    first_free = block->next;
  else
    block->prev->next = block->next;

  if (block->next)
    block->next->prev = block->prev;
}

void split(mem_free_block_t *current, size_t desired_size)
{
  mem_free_block_t *new_b = (mem_free_block_t *)((unsigned char *)current + MAX(MIN_USED_BLOCK_SIZE + desired_size, MIN_FREE_BLOCK_SIZE));
  new_b->size = current->size - MAX(MIN_USED_BLOCK_SIZE + desired_size, MIN_FREE_BLOCK_SIZE);

  add_free_block(new_b, current, current->next);

  delete_free_block(current);

#if defined(NEXT_FIT)
  next_free = new_b;
#endif
}

void coalesce(mem_free_block_t *block)
{
  if (block->prev && (unsigned char *)block == (unsigned char *)block->prev + block->prev->size + MIN_FREE_BLOCK_SIZE)
  {
    block->prev->size += MIN_FREE_BLOCK_SIZE + block->size;

    delete_free_block(block);

    block = block->prev;
  }

  if (block->next && (unsigned char *)block->next == (unsigned char *)block + block->size + MIN_FREE_BLOCK_SIZE)
  {
    block->size += MIN_FREE_BLOCK_SIZE + block->next->size;
#if defined(NEXT_FIT)

    if ((unsigned char *)block->next == (unsigned char *)next_free)
      next_free = block;
#endif

    delete_free_block(block->next);
  }
}

void run_at_exit(void)
{
  fprintf(stderr, "YEAH B-)\n");

  /* TODO: insert your code here */
}

void memory_init(void)
{
  /* register the function that will be called when the programs exits */
  atexit(run_at_exit);

  /* TODO: insert your code here */

  /* TODO: start by using the provided my_mmap function to allocate
     * the memory region you are going to manage */

  first_free = my_mmap(MEMORY_SIZE);
  first_free->size = MEMORY_SIZE - MIN_FREE_BLOCK_SIZE;
  first_free->next = NULL;
  first_free->prev = NULL;

#if defined(NEXT_FIT)
  next_free = first_free;
#endif

  heap_start = first_free;
}

void *memory_alloc(size_t size)
{

  /* TODO: insert your code here */

  /* TODO : don't forget to call the function print_alloc_info()
     * appropriately */

  mem_free_block_t *new_b = get_free_block(size);

  if (!new_b)
  {
    fprintf(stderr, "%s", "Sufficiently large block cannot be allocated\n");
    exit(0);
  }
  mem_used_block_t *used_b = (mem_used_block_t *)new_b;

  //so because we should return valid address for zero
  //I use >= not >
  //
  if (new_b->size >= MAX(MIN_USED_BLOCK_SIZE + size, MIN_FREE_BLOCK_SIZE))
  {
    split(new_b, size);
    used_b->size = size;
  }
  else
  {
    delete_free_block(new_b);

    used_b->size = new_b->size + MIN_FREE_BLOCK_SIZE - MIN_USED_BLOCK_SIZE;

#if defined(NEXT_FIT)
    mem_free_block_t *prev_next = new_b->next;

    if (prev_next)
      next_free = prev_next;
    else if (first_free)
      next_free = first_free;
    else
      next_free = NULL;
#endif
  }

  used_b++;

  print_alloc_info(used_b, size);

  return used_b;
}

void memory_free(void *p)
{

  /* TODO: insert your code here */

  /* TODO : don't forget to call the function print_free_info()
     * appropriately */

  mem_free_block_t *new_b = (mem_free_block_t *)((unsigned char *)p - MIN_USED_BLOCK_SIZE);

  new_b->size = MAX(memory_get_allocated_block_size(p) + MIN_USED_BLOCK_SIZE, MIN_FREE_BLOCK_SIZE) - MIN_FREE_BLOCK_SIZE;
  new_b->prev = NULL;
  new_b->next = NULL;

  mem_free_block_t *tmp = first_free;
  mem_free_block_t *prev = NULL;
  while (tmp && tmp < new_b)
  {
    prev = tmp;
    tmp = tmp->next;
  }

  if (tmp)
  {
    add_free_block(new_b, tmp->prev, tmp);
  }
  else
  {
    if (first_free)
      add_free_block(new_b, prev, NULL);
    else
    {
      new_b->next = NULL;
      new_b->prev = NULL;
      first_free = new_b;
#if defined(NEXT_FIT)
      next_free = first_free;
#endif
    }
  }

  coalesce(new_b);
  print_free_info(p);
}

size_t memory_get_allocated_block_size(void *addr)
{
  /* TODO: insert your code here */
  mem_used_block_t *used_b = (mem_used_block_t *)((unsigned char *)addr - MIN_USED_BLOCK_SIZE);
  return used_b->size;
}

//used bytes with '#' symbol
//free bytes with '.'
void print_mem_state(void)
{
  /* TODO: insert your code here */
  size_t j, sum = 0;
  if (!first_free)
  {
    for (j = 0; j < MEMORY_SIZE; j++)
      fprintf(stderr, "%c", '#');
  }
  else
  {
    for (j = 0; j < (unsigned char *)first_free - (unsigned char *)heap_start; j++)
      sum++, fprintf(stderr, "%c", '#');

    mem_free_block_t *tmp = first_free;

    while (tmp)
    {
      for (j = 0; j < MIN_FREE_BLOCK_SIZE; j++)
        sum++, fprintf(stderr, "%c", '.');

      for (j = 0; j < tmp->size; j++)
        sum++, fprintf(stderr, "%c", '.');

      if (tmp->next)
      {
        for (j = 0; j < (unsigned char *)tmp->next - ((unsigned char *)tmp + MIN_FREE_BLOCK_SIZE + tmp->size); j++)
          sum++, fprintf(stderr, "%c", '#');
      }
      tmp = tmp->next;
    }

    for (j = sum; j < MEMORY_SIZE; j++)
      fprintf(stderr, "%c", '#');
  }
  fprintf(stderr, "%c", '\n');
}

void print_info(void)
{
  fprintf(stderr, "Memory : [%lu %lu] (%lu bytes)\n", (long unsigned int)heap_start, (long unsigned int)(heap_start + MEMORY_SIZE), (long unsigned int)(MEMORY_SIZE));
}

void print_free_info(void *addr)
{
  if (addr)
  {
    fprintf(stderr, "FREE  at : %lu \n", ULONG(addr - heap_start));
  }
  else
  {
    fprintf(stderr, "FREE  at : %lu \n", ULONG(0));
  }
}

void print_alloc_info(void *addr, int size)
{
  if (addr)
  {
    fprintf(stderr, "ALLOC at : %lu (%d byte(s))\n",
            ULONG(addr - heap_start), size);
  }
  else
  {
    fprintf(stderr, "Warning, system is out of memory\n");
  }
}

void print_alloc_error(int size)
{
  fprintf(stderr, "ALLOC error : can't allocate %d bytes\n", size);
}

#ifdef MAIN
int main(int argc, char **argv)
{

  /* The main can be changed, it is *not* involved in tests */
  memory_init();
  print_info();
  int i;
  for (i = 0; i < 10; i++)
  {
    char *b = memory_alloc(rand() % 8);
    memory_free(b);
  }

  char *a = memory_alloc(15);
  memory_free(a);

  a = memory_alloc(10);
  memory_free(a);

  fprintf(stderr, "%lu\n", (long unsigned int)(memory_alloc(9)));
  return EXIT_SUCCESS;
}
#endif
