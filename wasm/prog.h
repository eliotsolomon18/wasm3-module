#ifndef PROG_H
#define PROG_H

#include <stdint.h>

#include "../packet.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Convert between WASM pages and bytes
#define PAGE_SIZE (64 * 1024)
#define PAGES_TO_BYTES(p) (p * PAGE_SIZE)
#define BYTES_TO_PAGES(b) ((b + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE)

#ifdef DEBUG_MALLOC
/* When DEBUG is defined, these form aliases to useful functions */
#define dbg_printf(...) ((void)printf(__VA_ARGS__))
#define dbg_requires(expr) assert(expr)
#define dbg_assert(expr) assert(expr)
#define dbg_ensures(expr) assert(expr)
#define dbg_printheap(...) print_heap(__VA_ARGS__)
#else
/* When DEBUG is not defined, no code gets generated for these */
/* The sizeof() hack is used to avoid "unused variable" warnings */
#define dbg_printf(...) ((void)sizeof(__VA_ARGS__))
#define dbg_requires(expr) ((void)sizeof(expr))
#define dbg_assert(expr) ((void)sizeof(expr))
#define dbg_ensures(expr) ((void)sizeof(expr))
#define dbg_printheap(...) ((void)sizeof(__VA_ARGS__))
#endif



// Prototype for print_int() function exposed by the runtime.
int32_t print_int(int32_t i) __attribute__((
    __import_module__("custom"),
    __import_name__("print_int")
));

// Linker-provided symbol that represents the base of the heap.
extern unsigned char __heap_base;

// Pointer to the end of the heap, initially the address of the __heap_base symbol (0 size heap)
char *heap_end = &__heap_base;

// Assign global header pointer to the base of the heap
struct packet_header *header = (struct packet_header *)&__heap_base;





void *wmalloc(size_t size);
void wfree(void *ptr);
void *wrealloc(void *ptr, size_t size);
void *wcalloc(size_t nmemb, size_t size);
bool mm_init(void);
bool mm_checkheap(int line);

void *mem_heap_lo(void) {
    return (void *)&__heap_base;
}

void *mem_heap_hi(void) {
    return (void *)heap_end;
}

/* Basic constants */

typedef uint32_t word_t;

/** @brief Word and header size (bytes) */
static const size_t wsize = sizeof(word_t);

/** @brief Double word size (bytes) */
static const size_t dsize = 2 * wsize;

/** @brief Minimum block size (bytes) */
static const size_t min_block_size = 2 * dsize;

/**
 * (Must be divisible by dsize)
 * chunksize is the size by which we should grow the heap when there is no space
 * in which we can allocate a requested block of memory. In this case it is 4096
 * and is divisible by 16 = dsize.
 */
static const size_t chunksize = (1 << 12);

/**
 * alloc_mask is a mask that when applied to the header will return the bit that
 * indicates whether the block is allocated or not. If applied to a footer, we
 * should have the same behavior. If we remove footers for allocated blocks, we
 * should have the invariant that alloc_mask & header == 0.
 */
static const word_t alloc_mask = 0x1;

/**
 * This mask, will return the size when applied to the header. It 0's out the
 * last 4 bits of the number in the header.
 */
static const word_t size_mask = ~(word_t)0xF;

/** @brief Represents the header and payload of one block in the heap */
typedef struct block {
    /** @brief Header contains size + allocation flag */
    word_t header;

    /**
     * @brief A pointer to the block payload.
     *
     * TODO: feel free to delete this comment once you've read it carefully.
     * We don't know what the size of the payload will be, so we will declare
     * it as a zero-length array, which is a GNU compiler extension. This will
     * allow us to obtain a pointer to the start of the payload. (The similar
     * standard-C feature of "flexible array members" won't work here because
     * those are not allowed to be members of a union.)
     *
     * WARNING: A zero-length array must be the last element in a struct, so
     * there should not be any struct fields after it. For this lab, we will
     * allow you to include a zero-length array in a union, as long as the
     * union is the last field in its containing struct. However, this is
     * compiler-specific behavior and should be avoided in general.
     *
     * WARNING: DO NOT cast this pointer to/from other types! Instead, you
     * should use a union to alias this zero-length array with another struct,
     * in order to store additional types of data in the payload memory.
     */

    union {
        struct {
            struct block *next;
            struct block *prev;
        } list_node;
        char payload[0];
    } contents;
} block_t;

/* Global variables */

/** @brief Pointer to first block in the heap */
static block_t *heap_start = NULL;

block_t *free_lists[15] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                           NULL, NULL, NULL, NULL, NULL, NULL, NULL};

/*
 * ---------------------------------------------------------------------------
 *                        BEGIN SHORT HELPER FUNCTIONS
 * ---------------------------------------------------------------------------
 */

/**
 * @brief Returns the maximum of two integers.
 * @param[in] x
 * @param[in] y
 * @return `x` if `x > y`, and `y` otherwise.
 */
static size_t max(size_t x, size_t y) {
    return (x > y) ? x : y;
}

/**
 * @brief Rounds `size` up to next multiple of n
 * @param[in] size
 * @param[in] n
 * @return The size after rounding up
 */
static size_t round_up(size_t size, size_t n) {
    return n * ((size + (n - 1)) / n);
}

/**
 * @brief Packs the `size` and `alloc` of a block into a word suitable for
 *        use as a packed value.
 *
 * Packed values are used for both headers and footers.
 *
 * The allocation status is packed into the lowest bit of the word.
 *
 * @param[in] size The size of the block being represented
 * @param[in] alloc True if the block is allocated
 * @return The packed value
 */
static word_t pack(size_t size, bool alloc) {
    word_t word = size;
    if (alloc) {
        word |= alloc_mask;
    }
    return word;
}

/**
 * @brief Extracts the size represented in a packed word.
 *
 * This function simply clears the lowest 4 bits of the word, as the heap
 * is 16-byte aligned.
 *
 * @param[in] word
 * @return The size of the block represented by the word
 */
static size_t extract_size(word_t word) {
    return (word & size_mask);
}

/**
 * @brief Extracts the size of a block from its header.
 * @param[in] block
 * @return The size of the block
 */
static size_t get_size(block_t *block) {
    return extract_size(block->header);
}

/**
 * @brief Given a payload pointer, returns a pointer to the corresponding
 *        block.
 * @param[in] bp A pointer to a block's payload
 * @return The corresponding block
 */
static block_t *payload_to_header(void *bp) {
    return (block_t *)((char *)bp - offsetof(block_t, contents.payload));
}

/**
 * @brief Given a block pointer, returns a pointer to the corresponding
 *        payload.
 * @param[in] block
 * @return A pointer to the block's payload
 * @pre The block must be a valid block, not a boundary tag.
 */
static void *header_to_payload(block_t *block) {
    dbg_requires(get_size(block) != 0);
    return (void *)(block->contents.payload);
}

/**
 * @brief Given a block pointer, returns a pointer to the corresponding
 *        footer.
 * @param[in] block
 * @return A pointer to the block's footer
 * @pre The block must be a valid block, not a boundary tag.
 */
static word_t *header_to_footer(block_t *block) {
    dbg_requires(get_size(block) != 0 &&
                 "Called header_to_footer on the epilogue block");
    return (word_t *)(block->contents.payload + get_size(block) - dsize);
}

/**
 * @brief Given a block footer, returns a pointer to the corresponding
 *        header.
 * @param[in] footer A pointer to the block's footer
 * @return A pointer to the start of the block
 * @pre The footer must be the footer of a valid block, not a boundary tag.
 */
static block_t *footer_to_header(word_t *footer) {
    size_t size = extract_size(*footer);
    dbg_assert(size != 0 && "Called footer_to_header on the prologue block");
    return (block_t *)((char *)footer + wsize - size);
}

/**
 * @brief Returns the payload size of a given block.
 *
 * The payload size is equal to the entire block size minus the sizes of the
 * block's header and footer.
 *
 * @param[in] block
 * @return The size of the block's payload
 */
static size_t get_payload_size(block_t *block) {
    size_t asize = get_size(block);
    return asize - dsize;
}

/**
 * @brief Returns the allocation status of a given header value.
 *
 * This is based on the lowest bit of the header value.
 *
 * @param[in] word
 * @return The allocation status correpsonding to the word
 */
static bool extract_alloc(word_t word) {
    return (bool)(word & alloc_mask);
}

/**
 * @brief Returns the allocation status of a block, based on its header.
 * @param[in] block
 * @return The allocation status of the block
 */
static bool get_alloc(block_t *block) {
    return extract_alloc(block->header);
}

/**
 * @brief Writes an epilogue header at the given address.
 *
 * The epilogue header has size 0, and is marked as allocated.
 *
 * @param[out] block The location to write the epilogue header
 */
static void write_epilogue(block_t *block) {
    dbg_requires(block != NULL);
    // dbg_requires((char *)block == (char *)mem_heap_hi() - 7);
    block->header = pack(0, true);
}

/**
 * @brief Writes a block starting at the given address.
 *
 * This function writes both a header and footer, where the location of the
 * footer is computed in relation to the header.
 *
 * TODO: Are there any preconditions or postconditions?
 *
 * @param[out] block The location to begin writing the block header
 * @param[in] size The size of the new block
 * @param[in] alloc The allocation status of the new block
 */
static void write_block(block_t *block, size_t size, bool alloc) {
    dbg_requires(block != NULL);
    dbg_requires(size > 0);
    block->header = pack(size, alloc);
    word_t *footerp = header_to_footer(block);
    *footerp = pack(size, alloc);
}

/**
 * @brief Finds the next consecutive block on the heap.
 *
 * This function accesses the next block in the "implicit list" of the heap
 * by adding the size of the block.
 *
 * @param[in] block A block in the heap
 * @return The next consecutive block on the heap
 * @pre The block is not the epilogue
 */
static block_t *find_next(block_t *block) {
    dbg_requires(block != NULL);
    dbg_requires(get_size(block) != 0 &&
                 "Called find_next on the last block in the heap");
    return (block_t *)((char *)block + get_size(block));
}

/**
 * @brief Finds the footer of the previous block on the heap.
 * @param[in] block A block in the heap
 * @return The location of the previous block's footer
 */
static word_t *find_prev_footer(block_t *block) {
    // Compute previous footer position as one word before the header
    return &(block->header) - 1;
}

/**
 * @brief Finds the previous consecutive block on the heap.
 *
 * This is the previous block in the "implicit list" of the heap.
 *
 * If the function is called on the first block in the heap, NULL will be
 * returned, since the first block in the heap has no previous block!
 *
 * The position of the previous block is found by reading the previous
 * block's footer to determine its size, then calculating the start of the
 * previous block based on its size.
 *
 * @param[in] block A block in the heap
 * @return The previous consecutive block in the heap.
 */
static block_t *find_prev(block_t *block) {
    dbg_requires(block != NULL);
    word_t *footerp = find_prev_footer(block);

    // Return NULL if called on first block in the heap
    if (extract_size(*footerp) == 0) {
        return NULL;
    }

    return footer_to_header(footerp);
}

/*
 * ---------------------------------------------------------------------------
 *                        END SHORT HELPER FUNCTIONS
 * ---------------------------------------------------------------------------
 */

/******** The remaining content below are helper and debug routines ********/

static size_t pick_min_index_of_array_of_lists(size_t asize) {
    if (asize <= 32) {
        return 0;
    } else if (asize <= 48) {
        return 1;
    } else if (asize <= 80) {
        return 2;
    } else if (asize <= 128) {
        return 3;
    } else if (asize <= 208) {
        return 4;
    } else if (asize <= 336) {
        return 5;
    } else if (asize <= 544) {
        return 6;
    } else if (asize <= 880) {
        return 7;
    } else if (asize <= 1424) {
        return 8;
    } else if (asize <= 2304) {
        return 9;
    } else if (asize <= 3728) {
        return 10;
    } else if (asize <= 6032) {
        return 11;
    } else if (asize <= 9760) {
        return 12;
    } else if (asize <= 15792) {
        return 13;
    } else {
        return 14;
    }
}

/*static size_t pick_min_index_of_array_of_lists(size_t asize) {
    if (asize <= 32) {
        return 0;
    } else if (asize <= 64) {
        return 1;
    } else if (asize <= 128) {
        return 2;
    } else if (asize <= 256) {
        return 3;
    } else if (asize <= 512) {
        return 4;
    } else if (asize <= 1024) {
        return 5;
    } else if (asize <= 2048) {
        return 6;
    } else if (asize <= 4096) {
        return 7;
    } else if (asize <= 8192) {
        return 8;
    } else if (asize <= 16384) {
        return 9;
    } else if (asize <= 32768) {
        return 10;
    } else if (asize <= 65536) {
        return 11;
    } else if (asize <= 131072) {
        return 12;
    } else if (asize <= 262144) {
        return 13;
    } else {
        return 14;
    }
}*/

static void remove_from_list(block_t *block, size_t i) {
    if (block->contents.list_node.prev == block &&
        block->contents.list_node.next == block) {
        free_lists[i] = NULL;
        // free_list_read = NULL;
    } else {
        block_t *prev_block = block->contents.list_node.prev;
        block_t *next_block = block->contents.list_node.next;

        prev_block->contents.list_node.next = next_block;
        next_block->contents.list_node.prev = prev_block;

        if (free_lists[i] == block) {
            free_lists[i] = next_block;
        }
        /*if (free_list_read == block) {
            free_list_read = next_block;
        }*/
    }
    return;
}

static void insert_into_list(block_t *block, size_t i) {
    if (free_lists[i] == NULL) {
        free_lists[i] = block;
        // free_list_read = block;

        block->contents.list_node.prev = block;
        block->contents.list_node.next = block;
    } else {
        block_t *next_block = free_lists[i];
        block_t *prev_block = next_block->contents.list_node.prev;

        next_block->contents.list_node.prev = block;
        block->contents.list_node.next = next_block;

        prev_block->contents.list_node.next = block;
        block->contents.list_node.prev = prev_block;

        free_lists[i] = block;
    }
    return;
}

static void insert_into_array_of_lists(block_t *block) {
    size_t size = get_size(block);
    size_t i = pick_min_index_of_array_of_lists(size);
    insert_into_list(block, i);
}

static void remove_from_array_of_lists(block_t *block) {
    size_t size = get_size(block);
    size_t i = pick_min_index_of_array_of_lists(size);
    remove_from_list(block, i);
}

/**
 * @brief
 *
 * <What does this function do?>
 * <What are the function's arguments?>
 * <What is the function's return value?>
 * <Are there any preconditions or postconditions?>
 *
 * @param[in] block
 * @return
 */
static block_t *coalesce_block(block_t *block) {

    size_t size = get_size(block);

    block_t *prev_block = find_prev(block);
    block_t *next_block = find_next(block);

    bool prev_alloc;
    if (prev_block == NULL) {
        prev_alloc = true;
    } else {
        prev_alloc = get_alloc(prev_block);
    }

    bool next_alloc = get_alloc(next_block);

    // previous block is free
    if (!prev_alloc) {
        block = prev_block;
        size += get_size(prev_block);
        remove_from_array_of_lists(prev_block);
    }

    // next block is free
    if (!next_alloc) {
        size += get_size(next_block);
        remove_from_array_of_lists(next_block);
    }

    write_block(block, size, false);
    insert_into_array_of_lists(block);
    return block;
}

/**
 * @brief
 *
 * <What does this function do?>
 * <What are the function's arguments?>
 * <What is the function's return value?>
 * <Are there any preconditions or postconditions?>
 *
 * @param[in] size
 * @return
 */
static block_t *extend_heap(size_t size) {
    void *bp;

    // Allocate an even number of words to maintain alignment
    size = round_up(size, dsize);
    if(__builtin_wasm_memory_grow(0, BYTES_TO_PAGES(size)) == -1) {
        return NULL;
    }

    heap_end = heap_end + size;
    bp = heap_end;

    // Initialize free block header/footer
    block_t *block = payload_to_header(bp);
    write_block(block, size, false);

    // Create new epilogue header
    block_t *block_next = find_next(block);
    write_epilogue(block_next);

    // Coalesce in case the previous block was free
    block = coalesce_block(block);

    return block;
}

/**
 * @brief
 *
 * <What does this function do?>
 * <What are the function's arguments?>
 * <What is the function's return value?>
 * <Are there any preconditions or postconditions?>
 *
 * @param[in] block
 * @param[in] asize
 */
static void split_block(block_t *block, size_t asize) {
    dbg_requires(!get_alloc(block));
    dbg_requires(asize >= min_block_size);

    remove_from_array_of_lists(block);
    size_t block_size = get_size(block);

    if ((block_size - asize) >= min_block_size) {
        block_t *block_next;
        write_block(block, asize, true);

        block_next = find_next(block);
        write_block(block_next, block_size - asize, false);
        insert_into_array_of_lists(block_next);
    } else {
        write_block(block, block_size, true);
    }

    dbg_ensures(get_alloc(block));
    return;
}

/**
 * @brief
 *
 * <What does this function do?>
 * <What are the function's arguments?>
 * <What is the function's return value?>
 * Assumes valid size. Returns ptr to free block, in free_list if it will fit
 * size, else returns NULL
 *
 * @param[in] asize
 * @return
 */
static block_t *find_fit(size_t asize) {

    for (size_t i = pick_min_index_of_array_of_lists(asize); i < 15; i++) {
        block_t *free_list_start = free_lists[i];
        // If free_list is not empty we want to explore it, else move on
        if (free_list_start != NULL) {

            // If first element of circular free list satisfies, return it
            block_t *reader = free_list_start;
            if (get_size(reader) >= asize) {
                return reader;
            }

            // Increment reader to not be first. Loop until we reach the
            // beginnin of list again. If we find block with size > asize return
            // ptr to that block. reader = reader->contents.list_node.next;
            for (reader = reader->contents.list_node.next;
                 reader != free_list_start;
                 reader = reader->contents.list_node.next) {
                if (get_size(reader) >= asize) {
                    return reader;
                }
            }
        }
    }

    return NULL; // no fit found
}

// This function takes in a block in a free list, a pointer to the stack
// allocated variable sum, a line number and the index of the free list the
// block is in. It then returns a bool describing whether the block invariants
// are true. We check things such as, is the block actually free, is the block
// in the right free list given its size, are the pointers to the block, that
// the pointers in the block all pointing to values within the heap, and that
// the next/previous pointers of blocks next to each other in the same linked
// list are consistent. Other properties about the block itself, such as
// comparisons of the header and footer are addressed in a function that
// observes blocks in the implicit list of the heap. Parity between this
// function and that function is established by a later check that the number of
// free blocks is the same in botht he linked list and the implicit list. If an
// error is encountered, a message describing the error and the line number is
// printed.
static bool is_list_block_valid(block_t *block, size_t *sum_free_list, int line,
                                size_t i) {
    // check that block is free
    if (get_alloc(block) == true) {
        printf("allocated block on free list %d\n", line);
        return false;
    }
    // check that pointers are consistent
    if (block->contents.list_node.next->contents.list_node.prev != block) {
        printf("next block doesn't point back to current block %d\n", line);
        return false;
    }
    if (block->contents.list_node.prev->contents.list_node.next != block) {
        printf("previous block doesn't point forward to current block %d\n",
               line);
        return false;
    }
    // check that based on the size of the block, the earliest free list we can
    // put it in is the one it is in
    size_t size = get_size(block);
    if (pick_min_index_of_array_of_lists(size) != i) {
        printf("block in wrong list free_list, %d\n", line);
        return false;
    }
    // check that all pointers point to within the heap
    if (block < (block_t *)mem_heap_lo() || block > (block_t *)mem_heap_hi()) {
        printf("block ptr outside of heap line %d\n", line);
        return false;
    }
    if (block->contents.list_node.next < (block_t *)mem_heap_lo() ||
        block->contents.list_node.next > (block_t *)mem_heap_hi()) {
        printf("previous ptr outside of heap %d\n", line);
        return false;
    }
    if (block->contents.list_node.prev < (block_t *)mem_heap_lo() ||
        block->contents.list_node.prev > (block_t *)mem_heap_hi()) {
        printf("previous ptr outside of heap, ptr = %p, line %d\n",
               (void *)block, line);
        return false;
    }
    // increment number of free blocks in the array of free lists
    (*sum_free_list)++;
    return true;
}
// This function takes in a pointer to a block, a pointer to a stack variable
// holding the sum of free blocks in the implicit list, and the line number. It
// returns whether a block in the implicit list structure is valid. For example
// it confirms such things like that the header and the footer match in all
// aspects, that contiguous free blocks do not occur, that payload addresses
// are aligned and that block sizes are correct.
static bool is_heap_block_valid(block_t *block, size_t *sum, int line) {
    word_t *footer = header_to_footer(block);
    size_t size = get_size(block);
    // check headers and footers are valid
    if (get_size(block) != (*footer & size_mask)) {
        printf("footer and header sizes are not the same %d\n", line);
        return false;
    }
    if (get_alloc(block) != (*footer & alloc_mask)) {
        printf("footer and header alloc encoding not the same %d\n", line);
        return false;
    }
    if (block->header != *footer) {
        printf("header != footer %d", line);
        return false;
    }
    // check block size is valid
    if (size % 16 != 0) {
        printf("size not a multiple of 16 %d\n", line);
        return false;
    }
    if (size < min_block_size) {
        printf("size of block is too small, invalid %d\n", line);
        return false;
    }
    // check location of blocks is valid
    if (block > (block_t *)mem_heap_hi() || block < (block_t *)mem_heap_lo()) {
        printf("block on heap is outside of bounds %d", line);
        return false;
    }
    // since we iterate through the list, we claim that checking if the next
    // block is free for every free block will cover all cases where contiguous
    // blocks are free. If previous block to a free block is free, we would have
    // caught error, when checking that block.
    if (get_alloc(block) == false) {
        if (get_alloc(find_next(block)) == false) {
            printf("contiguous free blocks %d", line);
            return false;
        }
    }
    // check payload is aligned
    void *bp = header_to_payload(block);
    if (((uintptr_t)bp % 16) != 0) {
        printf("payload pointer not aligned %d", line);
        return false;
    }
    // increment number of free blocks in the implicit list
    if (get_alloc(block) == false) {
        (*sum)++;
    }

    return true;
}

/**
 * @brief
 *
 * This function iterates through each the array of linked list structures and
 * the implicit list structure. At each block in either structure the function
 * calls methods to confirm that the block is valid with respect to itself, the
 * blocks around it, and the structure it is in. It also ensures that the
 * number of free blocks in the array of linked lists is equivalent to the
 * number of free blocks in the implicit list.
 * This function takes a line number as an arguement, error messages print the
 * line number at which the function failed.
 * The function returns whether the two heap structures are valid
 * We assume that the "small helper" functions are correct with respect to
 * their function. We have the postcondition that will return a bool given the
 * pre-conditions.
 *
 * @param[in] line
 * @return
 */
bool mm_checkheap(int line) {

    size_t num_free_blocks_lists = 0;
    size_t num_free_blocks_heap = 0;
    // loop through array of linked lists
    for (size_t i = 0; i < 15; i++) {
        block_t *reader = free_lists[i];
        if (reader != NULL) {
            if (is_list_block_valid(reader, &num_free_blocks_lists, line, i) ==
                false) {
                return false;
            }
            for (reader = reader->contents.list_node.next;
                 reader != free_lists[i];
                 reader = reader->contents.list_node.next) {
                if (is_list_block_valid(reader, &num_free_blocks_lists, line,
                                        i) == false) {
                    return false;
                }
            }
        }
    }

    // loop through heap from right after prologue to right before epilogue
    for (block_t *block = heap_start; get_size(block) > 0;
         block = find_next(block)) {
        if (is_heap_block_valid(block, &num_free_blocks_heap, line) == false) {
            printf("Heap block invalid %d\n", line);
        }
    }
    // check that number of free blocks is same across the implicit list and the
    // array of linked lists
    if (num_free_blocks_lists != num_free_blocks_heap) {
        printf("number of free blocks in list not equal to number of free "
               "blocks in the heap, %lu, %lu, %d",
               num_free_blocks_heap, num_free_blocks_lists, line);
        return false;
    }

    // check prologue
    if (*(word_t *)(((char *)heap_start) - wsize) != pack(0, true)) {
        printf("prologue is invalid %d", line);
        return false;
    }

    // check epilogue
    if (*(word_t *)(((char *)heap_start) + mem_heapsize() - dsize) !=
        pack(0, true)) {
        printf("epilogue is invalid %d", line);
        return false;
    }

    return true;
}

/**
 * @brief
 *
 * <What does this function do?>
 * <What are the function's arguments?>
 * <What is the function's return value?>
 * <Are there any preconditions or postconditions?>
 *
 * @return
 */
bool mm_init(void) {
    // Create the initial empty heap

    if(__builtin_wasm_memory_grow(0, BYTES_TO_PAGES(2 * wsize)) == -1) {
        return false;
    }

    heap_end = heap_end + (2 * wsize);
    
    word_t *start = (word_t *)&__heap_base

    if (start == (void *)-1) {
        return false;
    }

    start[0] = pack(0, true); // Heap prologue (block footer)
    start[1] = pack(0, true); // Heap epilogue (block header)

    // Heap starts with first "block header", currently the epilogue
    heap_start = (block_t *)&(start[1]);

    // reset free list pointers
    // memset(free_lists, 0, 120);
    for (int i = 0; i < 15; i++) {
        free_lists[i] = NULL;
    }

    // Extend the empty heap with a free block of chunksize bytes
    if (extend_heap(chunksize) == NULL) {
        return false;
    }

    return true;
}

static void *allocate_block(size_t asize) {
    dbg_requires(mm_checkheap(__LINE__));

    size_t extendsize; // Amount to extend heap if no fit is found
    block_t *block;
    void *bp = NULL;

    // Search the free list for a fit
    block = find_fit(asize);

    // If no fit is found, request more memory, and then and place the block
    if (block == NULL) {
        // Always request at least chunksize
        extendsize = max(asize, chunksize);
        block = extend_heap(extendsize);
        // extend_heap returns an error
        if (block == NULL) {
            return bp;
        }
    }

    // At this point we know block points to valid free block, either from
    // initial free list, or from extending the heap

    // The block should be marked as free
    dbg_assert(!get_alloc(block));

    // Try to split the block if too large, also sets block to allocated
    split_block(block, asize);

    bp = header_to_payload(block);

    dbg_ensures(mm_checkheap(__LINE__));
    return bp;
}

/**
 * @brief
 *
 * <What does this function do?>
 * <What are the function's arguments?>
 * <What is the function's return value?>
 * <Are there any preconditions or postconditions?>
 *
 * @param[in] size
 * @return
 */
void *wmalloc(size_t size) {
    dbg_requires(mm_checkheap(__LINE__));

    size_t asize; // Adjusted block size
    void *bp;

    // Initialize heap if it isn't initialized
    if (heap_start == NULL) {
        mm_init();
    }

    // Ignore spurious request
    if (size == 0) {
        dbg_ensures(mm_checkheap(__LINE__));
        return NULL;
    }

    // Adjust block size to include overhead and to meet alignment requirements
    asize = round_up(size + dsize, dsize);

    // Find and allocate block, extending heap if necesarry, NULL if impossible
    bp = allocate_block(asize);

    dbg_ensures(mm_checkheap(__LINE__));
    return bp;
}

/**
 * @brief
 *
 * <What does this function do?>
 * <What are the function's arguments?>
 * <What is the function's return value?>
 * <Are there any preconditions or postconditions?>
 *
 * @param[in] bp
 */
void wfree(void *bp) {
    dbg_requires(mm_checkheap(__LINE__));

    if (bp == NULL) {
        return;
    }

    block_t *block = payload_to_header(bp);
    size_t size = get_size(block);

    // The block should be marked as allocated
    dbg_assert(get_alloc(block));

    // Mark the block as free
    write_block(block, size, false);

    // Try to coalesce the block with its neighbors, and insert into free_list
    coalesce_block(block);

    dbg_ensures(mm_checkheap(__LINE__));
    return;
}

/**
 * @brief
 *
 * <What does this function do?>
 * <What are the function's arguments?>
 * <What is the function's return value?>
 * <Are there any preconditions or postconditions?>
 *
 * @param[in] ptr
 * @param[in] size
 * @return
 */
void *wrealloc(void *ptr, size_t size) {
    block_t *block = payload_to_header(ptr);
    size_t copysize;
    void *newptr;

    // If size == 0, then free block and return NULL
    if (size == 0) {
        wfree(ptr);
        return NULL;
    }

    // If ptr is NULL, then equivalent to malloc
    if (ptr == NULL) {
        return wmalloc(size);
    }

    // Otherwise, proceed with reallocation
    newptr = wmalloc(size);

    // If malloc fails, the original block is left untouched
    if (newptr == NULL) {
        return NULL;
    }

    // Copy the old data
    copysize = get_payload_size(block); // gets size of old payload
    if (size < copysize) {
        copysize = size;
    }
    memcpy(newptr, ptr, copysize);

    // Free the old block
    wfree(ptr);

    return newptr;
}

/**
 * @brief
 *
 * <What does this function do?>
 * <What are the function's arguments?>
 * <What is the function's return value?>
 * <Are there any preconditions or postconditions?>
 *
 * @param[in] elements
 * @param[in] size
 * @return
 */
void *wcalloc(size_t elements, size_t size) {
    void *bp;
    size_t asize = elements * size;

    if (elements == 0) {
        return NULL;
    }
    if (asize / elements != size) {
        // Multiplication overflowed
        return NULL;
    }

    bp = wmalloc(asize);
    if (bp == NULL) {
        return NULL;
    }

    // Initialize all bits to 0
    memset(bp, 0, asize);

    return bp;
}



// Declare global linked list pointer
linked_list_t *packet_list = NULL;

// Initialize packet list
void init_packet_list() {
    if (packet_list != NULL) { return; }
    
    packet_list = wmalloc(sizeof(linked_list_t));

    packet_list->head = NULL;
    packet_list->list_size = 0;

}


// Insert new node at head of packet list (ie packets will be stored in reverse recieval order (recency bias order))
node_t *add_node_packet_list() {
    packet_list->list_size++;

    node_t *new_node = wmalloc(sizeof(node_t));

    new_node->next = packet_list->head;
    packet_list->head = new_node;

    return new_node;
}























#endif