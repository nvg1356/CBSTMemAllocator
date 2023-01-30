#ifndef memory_h
#define memory_h

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define FRAG_TOLER 50
#define INIT_SIZE 4096
#define MIN_ALLOC 2048
#define max(a,b) \
	((a>b) ? a : b)

#if defined(__LP64__) || defined(_LP64)
#define BLOCK_ALIGNMENT 8
#define HEADER_SIZE 32
#else
#define BLOCK_ALIGNMENT 4
#define HEADER_SIZE 16
#endif

typedef struct {
	size_t size;
	void* left;
	void* right;
	void* parent;
	void* pPayload;
} BSTNode;

static inline uintptr_t __attribute__((pure)) align(uintptr_t);
static inline void* __attribute__((pure)) HeapExtend(void*);
void __attribute__((constructor)) init_mem_pool();
static inline void reset_ancestral_links(BSTNode*, BSTNode*);
static inline void direct_child_replace_parent(BSTNode*, BSTNode*, bool);
static BSTNode* remove_n_replace(BSTNode*);
static void tree_insert(BSTNode*);
static BSTNode* check_tree(size_t);
static BSTNode* split_free(size_t, BSTNode*);
void* custom_alloc(size_t);
void* custom_realloc(void*, size_t);
void custom_free(void*);

#endif
