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

//Get aligned size
size_t get_aligned_size(size_t size);

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
  while (tmp && !(tmp->size + get_aligned_size(MIN_FREE_BLOCK_SIZE) >= MAX(get_aligned_size(size) + get_aligned_size(MIN_USED_BLOCK_SIZE), get_aligned_size(MIN_FREE_BLOCK_SIZE))))
  {
    tmp = tmp->next;
  }

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
    if (tmp->size + get_aligned_size(MIN_FREE_BLOCK_SIZE) >= MAX(get_aligned_size(size) + get_aligned_size(MIN_USED_BLOCK_SIZE), get_aligned_size(MIN_FREE_BLOCK_SIZE)))
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

  while (tmp && !(tmp->size + get_aligned_size(MIN_FREE_BLOCK_SIZE) >= MAX(get_aligned_size(size) + get_aligned_size(MIN_USED_BLOCK_SIZE), get_aligned_size(MIN_FREE_BLOCK_SIZE))))
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

//check free and used block metadatas // are they corupted or not
void check_corruption()
{
  mem_free_block_t *f_block;
  mem_free_block_t *prev_f_block;
  mem_used_block_t *u_block;

  if (first_free)
  {
    if ((unsigned char *)heap_start != (unsigned char *)first_free)
    {
      u_block = (mem_used_block_t *)heap_start;
      while ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) < (unsigned char *)first_free)
      {
        u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
      }

      assert((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) == (unsigned char *)first_free);
    }

    f_block = first_free;
    assert(f_block->prev == NULL);
    while (f_block && (unsigned char *)f_block >= (unsigned char *)heap_start && (unsigned char *)f_block <= (unsigned char *)heap_start + MEMORY_SIZE)
    {
      if (f_block->prev)
        assert(f_block->prev < f_block);

      if (f_block->next)
      {
        assert(f_block->next->prev == f_block);
        u_block = (mem_used_block_t *)((unsigned char *)f_block + get_aligned_size(MIN_FREE_BLOCK_SIZE) + f_block->size);
        while ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) <= (unsigned char *)f_block->next)
        {
          u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
        }
        assert((unsigned char *)u_block == (unsigned char *)f_block->next);
      }
      prev_f_block = f_block;
      f_block = f_block->next;
    }

    assert(f_block == NULL || (unsigned char *)f_block >= (unsigned char *)heap_start);
    assert(f_block == NULL || (unsigned char *)f_block <= (unsigned char *)heap_start + MEMORY_SIZE);

    if ((unsigned char *)prev_f_block + get_aligned_size(MIN_FREE_BLOCK_SIZE) + prev_f_block->size != (unsigned char *)heap_start + MEMORY_SIZE)
    {
      u_block = (mem_used_block_t *)((unsigned char *)prev_f_block + get_aligned_size(MIN_FREE_BLOCK_SIZE) + prev_f_block->size);

      while ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) <= (unsigned char *)heap_start + MEMORY_SIZE)
      {
        u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
      }

      assert((unsigned char *)u_block == (unsigned char *)heap_start + MEMORY_SIZE);
    }
  }
  else
  {
    u_block = (mem_used_block_t *)heap_start;
    while ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) <= (unsigned char *)heap_start + MEMORY_SIZE)
    {
      u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
    }

    assert((unsigned char *)u_block == (unsigned char *)heap_start + MEMORY_SIZE);
  }
}

//Get aligned size
size_t get_aligned_size(size_t size)
{
  if (!(size % MEM_ALIGNMENT))
    return size;

  return (size / MEM_ALIGNMENT) * MEM_ALIGNMENT + MEM_ALIGNMENT;
}
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

//delete block from free list
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
  mem_free_block_t *new_b = (mem_free_block_t *)((unsigned char *)current + MAX(get_aligned_size(MIN_USED_BLOCK_SIZE) + get_aligned_size(desired_size), get_aligned_size(MIN_FREE_BLOCK_SIZE)));

  new_b->size = current->size - MAX(get_aligned_size(MIN_USED_BLOCK_SIZE) + get_aligned_size(desired_size), get_aligned_size(MIN_FREE_BLOCK_SIZE));

  add_free_block(new_b, current, current->next);

  delete_free_block(current);

#if defined(NEXT_FIT)
  next_free = new_b;
#endif
}

void coalesce(mem_free_block_t *block)
{
  if (block->prev && (unsigned char *)block == (unsigned char *)block->prev + block->prev->size + get_aligned_size(MIN_FREE_BLOCK_SIZE))
  {
    block->prev->size += get_aligned_size(MIN_FREE_BLOCK_SIZE) + block->size;

    delete_free_block(block);

    block = block->prev;
  }

  if (block->next && (unsigned char *)block->next == (unsigned char *)block + block->size + get_aligned_size(MIN_FREE_BLOCK_SIZE))
  {
    block->size += get_aligned_size(MIN_FREE_BLOCK_SIZE) + block->next->size;
#if defined(NEXT_FIT)

    if ((unsigned char *)block->next == (unsigned char *)next_free)
      next_free = block;
#endif
    delete_free_block(block->next);
  }
}

//for the more detail for the that phrases, read my report
void run_at_exit(void)
{
  int flag = 1;

  mem_free_block_t *f_block;
  mem_free_block_t *prev_f_block;
  mem_used_block_t *u_block;

  if (first_free)
  {
    if ((unsigned char *)heap_start != (unsigned char *)first_free)
    {
      u_block = (mem_used_block_t *)heap_start;
      while ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) <= (unsigned char *)first_free)
      {
        if (flag)
        {
          flag = 0;
          fprintf(stderr, "What they were teaching you in the school?!\nThere are still used blocks, what you must(should) free:\n");
        }

        fprintf(stderr, "Addr: %p\n", (unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE));
        u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
      }
    }

    f_block = first_free;
    while (f_block)
    {
      if (f_block->next)
      {
        u_block = (mem_used_block_t *)((unsigned char *)f_block + get_aligned_size(MIN_FREE_BLOCK_SIZE) + f_block->size);
        while ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) <= (unsigned char *)f_block->next)
        {
          if (flag)
          {
            flag = 0;
            fprintf(stderr, "What they were teaching you in the school?!\nThere are still used blocks, what you must(should) free:\n");
          }

          fprintf(stderr, "Addr: %p\n", (unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE));
          u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
        }
      }
      prev_f_block = f_block;
      f_block = f_block->next;
    }

    if ((unsigned char *)prev_f_block + get_aligned_size(MIN_FREE_BLOCK_SIZE) + prev_f_block->size != (unsigned char *)heap_start + MEMORY_SIZE)
    {
      u_block = (mem_used_block_t *)((unsigned char *)prev_f_block + get_aligned_size(MIN_FREE_BLOCK_SIZE) + prev_f_block->size);

      while ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) <= (unsigned char *)heap_start + MEMORY_SIZE)
      {
        if (flag)
        {
          flag = 0;
          fprintf(stderr, "What they were teaching you in the school?!\nThere are still used blocks, what you must(should) free:\n");
        }

        fprintf(stderr, "Addr: %p\n", (unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE));
        u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
      }
    }
  }
  else
  {
    u_block = (mem_used_block_t *)heap_start;
    while ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) <= (unsigned char *)heap_start + MEMORY_SIZE)
    {
      if (flag)
      {
        flag = 0;
        fprintf(stderr, "What they were teaching you in the school?!\nThere are still used blocks, what you must(should) free:\n");
      }

      fprintf(stderr, "Addr: %p\n", (unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE));
      u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
    }
  }
}

void memory_init(void)
{
  atexit(run_at_exit);

  first_free = my_mmap(MEMORY_SIZE);
  first_free->size = MEMORY_SIZE - get_aligned_size(MIN_FREE_BLOCK_SIZE);
  first_free->next = NULL;
  first_free->prev = NULL;

#if defined(NEXT_FIT)
  next_free = first_free;
#endif

  heap_start = first_free;
}

void *memory_alloc(size_t size)
{
  //check if something corrupted
  check_corruption();

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
  if (new_b->size >= MAX(get_aligned_size(MIN_USED_BLOCK_SIZE) + get_aligned_size(size), get_aligned_size(MIN_FREE_BLOCK_SIZE)))
  {
    split(new_b, size);
    used_b->size = get_aligned_size(size);
  }
  else
  {
    delete_free_block(new_b);

    used_b->size = new_b->size + get_aligned_size(MIN_FREE_BLOCK_SIZE) - get_aligned_size(MIN_USED_BLOCK_SIZE);

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

  print_alloc_info((unsigned char *)(used_b) + get_aligned_size(MIN_USED_BLOCK_SIZE), size);

  return (unsigned char *)(used_b) + get_aligned_size(MIN_USED_BLOCK_SIZE);
}

void memory_free(void *p)
{
  //check if something corrupted
  check_corruption();

  if ((unsigned char *)p < (unsigned char *)heap_start || (unsigned char *)p >= (unsigned char *)heap_start + MEMORY_SIZE)
  {
    fprintf(stderr, "this address is out of range of possible memory space\n");
    exit(-1);
  }

  if (get_aligned_size((size_t)p) != (size_t)p)
  {
    fprintf(stderr, "this address is not allocated by my memory allocator\n");
    exit(-4);
  }

  mem_free_block_t *f_check = first_free;

  while (f_check && (unsigned char *)f_check <= (unsigned char *)p)
  {
    if ((unsigned char *)p >= (unsigned char *)f_check && (unsigned char *)p < (unsigned char *)f_check + get_aligned_size(MIN_FREE_BLOCK_SIZE) + f_check->size)
    {
      //explanation for this case read report
      if ((unsigned char *)p == (unsigned char *)f_check)
      {
        if ((unsigned char *)heap_start != (unsigned char *)p)
        {
          if (f_check->prev)
          {
            mem_used_block_t *tmp = (mem_used_block_t *)((unsigned char *)f_check->prev + get_aligned_size(MIN_FREE_BLOCK_SIZE) + f_check->prev->size);
            while ((unsigned char *)tmp + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)tmp + get_aligned_size(MIN_USED_BLOCK_SIZE)) != (unsigned char *)f_check)
              tmp = (mem_used_block_t *)((unsigned char *)tmp + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)tmp + get_aligned_size(MIN_USED_BLOCK_SIZE)));

            if (!memory_get_allocated_block_size((unsigned char *)tmp + get_aligned_size(MIN_USED_BLOCK_SIZE)))
              break;
            else
              goto print_err;
          }
          else
          {
            mem_used_block_t *tmp = (mem_used_block_t *)((unsigned char *)heap_start);
            while ((unsigned char *)tmp + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)tmp + get_aligned_size(MIN_USED_BLOCK_SIZE)) != (unsigned char *)f_check)
              tmp = (mem_used_block_t *)((unsigned char *)tmp + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)tmp + get_aligned_size(MIN_USED_BLOCK_SIZE)));

            if (!memory_get_allocated_block_size((unsigned char *)tmp + get_aligned_size(MIN_USED_BLOCK_SIZE)))
              break;
            else
              goto print_err;
          }
        }
      }
    print_err:
      fprintf(stderr, "You try free already free memory\n");
      exit(-2);
    }
    f_check = f_check->next;
  }

  int flag = 0;

  mem_free_block_t *f_block;
  mem_free_block_t *prev_f_block;
  mem_used_block_t *u_block;

  if (first_free)
  {
    if ((unsigned char *)heap_start != (unsigned char *)first_free)
    {
      u_block = (mem_used_block_t *)heap_start;
      while ((unsigned char *)u_block != (unsigned char *)first_free && (unsigned char *)u_block <= (unsigned char *)p)
      {
        if ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) == (unsigned char *)p)
        {
          flag = 1;
          break;
        }
        u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
      }
    }

    if (!flag)
    {
      f_block = first_free;
      while (f_block && (unsigned char *)f_block <= (unsigned char *)p)
      {
        if (f_block->next)
        {
          u_block = (mem_used_block_t *)((unsigned char *)f_block + get_aligned_size(MIN_FREE_BLOCK_SIZE) + f_block->size);
          while ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) <= (unsigned char *)f_block->next)
          {
            if ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) == (unsigned char *)p)
            {
              flag = 1;
              break;
            }
            u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
          }
        }
        prev_f_block = f_block;
        f_block = f_block->next;
      }
    }

    if (!flag)
    {
      u_block = (mem_used_block_t *)((unsigned char *)prev_f_block + get_aligned_size(MIN_FREE_BLOCK_SIZE) + prev_f_block->size);

      while ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) <= (unsigned char *)heap_start + MEMORY_SIZE && (unsigned char *)u_block <= (unsigned char *)p)
      {
        if ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) == (unsigned char *)p)
        {
          flag = 1;
          break;
        }
        u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
      }
    }
  }
  else
  {
    u_block = (mem_used_block_t *)heap_start;
    while ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)) <= (unsigned char *)heap_start + MEMORY_SIZE && (unsigned char *)u_block <= (unsigned char *)p)
    {
      if ((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) == (unsigned char *)p)
      {
        flag = 1;
        break;
      }
      u_block = (mem_used_block_t *)((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE) + memory_get_allocated_block_size((unsigned char *)u_block + get_aligned_size(MIN_USED_BLOCK_SIZE)));
    }
  }

  if (!flag)
  {
    fprintf(stderr, "That address is not start address of allocated block\n");
    exit(-3);
  }

  mem_free_block_t *new_b = (mem_free_block_t *)((unsigned char *)p - get_aligned_size(MIN_USED_BLOCK_SIZE));

  new_b->size = MAX(memory_get_allocated_block_size(p) + get_aligned_size(MIN_USED_BLOCK_SIZE), get_aligned_size(MIN_FREE_BLOCK_SIZE)) - get_aligned_size(MIN_FREE_BLOCK_SIZE);
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
  mem_used_block_t *used_b = (mem_used_block_t *)((unsigned char *)addr - get_aligned_size(MIN_USED_BLOCK_SIZE));

  return used_b->size;
}

//used bytes with '#' symbol
//free bytes with '.'
void print_mem_state(void)
{
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
      for (j = 0; j < get_aligned_size(MIN_FREE_BLOCK_SIZE); j++)
        sum++, fprintf(stderr, "%c", '.');

      for (j = 0; j < tmp->size; j++)
        sum++, fprintf(stderr, "%c", '.');

      if (tmp->next)
      {
        for (j = 0; j < (unsigned char *)tmp->next - ((unsigned char *)tmp + get_aligned_size(MIN_FREE_BLOCK_SIZE) + tmp->size); j++)
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

  //sanity checks

  /*
   //free memory address out of possible range of my malloc
  unsigned char * tmp;
  tmp=(unsigned char*)heap_start-1;
  memory_free(tmp);
  */

  /*
   //free memory address that is not aligned
  unsigned char * tmp;
  tmp=(unsigned char*)heap_start+MEM_ALIGNMENT+1;
  memory_free(tmp);
  */

  /*
   //free memory from free list
  unsigned char * tmp;
  tmp=(unsigned char*)memory_alloc(15);
  memory_free((unsigned char*)heap_start+3*MEM_ALIGNMENT);
  */

  /*
   //double free
  unsigned char * tmp;
  tmp=(unsigned char*)memory_alloc(15);
  memory_free(tmp);
  memory_free(tmp);
  */

  /*
   //Do not free allocated memory
  unsigned char *tmp, *tmp2, *tmp3, *tmp4;
  tmp=(unsigned char*)memory_alloc(15);
  tmp2=(unsigned char*)memory_alloc(15);
  memory_free(tmp2);
  tmp3=(unsigned char*)memory_alloc(15);
  tmp4=(unsigned char*)memory_alloc(15);
  memory_free(tmp3);
  */

  /*
   //try to free used block address, but when its't start of block
  unsigned char *tmp, *tmp2;
  tmp=(unsigned char*)memory_alloc(15);
  tmp2=(unsigned char*)memory_alloc(100);
  memory_free(tmp);
  memory_free((unsigned char*)tmp2+MEM_ALIGNMENT);
  */

  /*
   //Modified size in used block metadata
  unsigned char *tmp, *tmp2, *tmp3, *tmp4;
  tmp=(unsigned char*)memory_alloc(15);
  tmp2=(unsigned char*)memory_alloc(34);
  tmp3=(unsigned char*)memory_alloc(26);
  ((mem_used_block_t*)((unsigned char*)tmp2-get_aligned_size(MIN_USED_BLOCK_SIZE)))->size=65;
  tmp4=(unsigned char*)memory_alloc(67);
  */

  /*
   //Modified size in free block metadata
  unsigned char *tmp, *tmp2;
  tmp=(unsigned char*)memory_alloc(15);
  ((mem_free_block_t*)((unsigned char*)tmp+get_aligned_size(15)))->size=65;
  tmp2=(unsigned char*)memory_alloc(67);
  */

  /*
   //Modified link in free block metadata
  unsigned char *tmp, *tmp2,*tmp3,*tmp4;
  tmp=(unsigned char*)memory_alloc(15);
  tmp2=(unsigned char*)memory_alloc(67);
  tmp3=(unsigned char*)memory_alloc(33);
  memory_free(tmp);
  tmp4=(unsigned char*)memory_alloc(67);
  ((mem_free_block_t*)((unsigned char*)heap_start))->next=tmp3;
  memory_free(tmp2);
  */

  /*
   //Modified link in free block metadata
  unsigned char *tmp, *tmp2,*tmp3,*tmp4;
  tmp=(unsigned char*)memory_alloc(15);
  tmp2=(unsigned char*)memory_alloc(67);
  tmp3=(unsigned char*)memory_alloc(33);
  memory_free(tmp);
  memory_free(tmp3);
  tmp4=(unsigned char*)memory_alloc(99);
  ((mem_free_block_t*)((unsigned char*)first_free->next))->prev=tmp;
  memory_free(tmp2);
  */

  return EXIT_SUCCESS;
}
#endif
