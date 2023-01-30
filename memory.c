#include "memory.h"
#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

static char* pBrk;
static char* pCurrent;
static BSTNode* root_node;

#if defined(__unix__) || defined(__unix)
#include <unistd.h>
#include <string.h>
#define BUILD_UNIX
#elif defined(_WIN32)
#include <Heapapi.h>
#include <windows.h>
#define BUILD_WIN
static char* pHeap;
static HANDLE heap_handle;
static inline void* __attribute__((pure)) HeapExtend(void* pNewBrk) {
	return HeapReAlloc(heap_handle, HEAP_REALLOC_IN_PLACE_ONLY, pHeap, HeapSize(heap_handle, 0, pHeap) + pNewBrk - pBrk);
}
#endif


static inline uintptr_t __attribute__((pure)) align(uintptr_t ptr) {
	return (ptr + BLOCK_ALIGNMENT -(ptr & (BLOCK_ALIGNMENT - 1)));	
}	

void __attribute__((constructor)) init_mem_pool() {
	assert((BLOCK_ALIGNMENT & (BLOCK_ALIGNMENT - 1)) == 0);
	#if defined(BUILD_UNIX)
	pCurrent = align(sbrk(0) + 1);
	pBrk = align(pCurrent + INIT_SIZE);
	assert(brk(pBrk) != -1);
	#elif defined(BUILD_WIN)
	heap_handle = GetProcessorHeap();
	pHeap = HeapAlloc(heap_handle, 0, 0);
	pCurrent = align(pHeap + 1);
	assert(HeapExtend(INIT_SIZE + pCurrent - pHeap));
	#endif
}		

static inline void reset_ancestral_links(BSTNode* old_child, BSTNode* new_child) {
	if (old_child == root_node) {
		root_node = new_child;
		return;
	}	
	if (((BSTNode*) (old_child->parent))->size > old_child->size) {
		((BSTNode*) (old_child->parent))->left = new_child;
	} else {
		((BSTNode*) (old_child->parent))->right = new_child;
	}
	new_child->parent = old_child->parent;
}	

static inline void direct_child_replace_parent(BSTNode* parent_node, BSTNode* direct_child, bool right_child) {
	if (right_child == true) {
		direct_child->left = parent_node->left;
	} else {
		direct_child->right = parent_node->right;
	}
}	

static BSTNode* remove_n_replace(BSTNode* node) {
	/* if input node is not a leaf, (final) current_node will either be node
	 * with one child or no children 
	 */
	if (node->right == NULL && node->left == NULL) { // if node is leaf
		reset_ancestral_links(node, NULL); // if node to be removed is the only free node
		return NULL;
	}	
	BSTNode* current_node = node->right; //right branch
	if (current_node != NULL) {
		while (current_node->left != NULL) {
			current_node = current_node->left;
		}
		if (current_node == node->right) {
			reset_ancestral_links(node, current_node);	
			direct_child_replace_parent(node, current_node, true);
			return current_node;
		}	
		((BSTNode*) (current_node->parent))->left = current_node->right; //detachment;

	}	
	else { //left branch
	       current_node = node->left;
		while (current_node->right != NULL) {
			current_node = current_node->right;
		}
		if (current_node == node->left) {
			reset_ancestral_links(node, current_node);
			direct_child_replace_parent(node, current_node, false);
			return current_node;
		}	
		((BSTNode*) (current_node->parent))->right = current_node->left; // detachment
	}
	reset_ancestral_links(node, current_node);
	current_node->left = node->left;
	current_node->right = node->right;
	return current_node;
	// function returns node that replaces node to be removed
	// TODO: tree may be left heavy due to almost all nodes being removed from right branch
} 

static void tree_insert(BSTNode* new_node) {
	if (root_node == NULL) {
		root_node = new_node;
		return;
	}	
	BSTNode* current_node = root_node;
	while (true) {
		size_t deviation = new_node->size - current_node->size;
		if (deviation > 0) {
			if (current_node->right == NULL) {
				current_node->right = new_node;
				return;
			}
			current_node = current_node->right;
		} else {
			if (current_node->left == NULL) {
				current_node->left = new_node;
				return;
			}
			current_node = current_node->left;
		}
	}
}	

static BSTNode* check_tree(size_t desired_size) {
	if (root_node == NULL) return NULL;
	BSTNode* current_node = root_node;
	while (current_node != NULL) {
		int deviation = desired_size  - current_node->size;
		if (deviation > 0 && current_node->right != NULL) {
			current_node = current_node->right;
			continue;
		}
		else if (deviation < 0 && current_node->left != NULL) {
			current_node = current_node->left;
			continue;
		}	
		if (deviation < FRAG_TOLER) {
			remove_n_replace(current_node);
		} else {
			remove_n_replace(current_node);
			tree_insert(split_free(desired_size, current_node));		
		}
		return current_node;
	}	
}	

static BSTNode* split_free(size_t desired_size, BSTNode* big_block) {
	BSTNode* new_free = align(big_block->pPayload + desired_size);
	new_free->size = (char*) big_block + big_block->size - (char*) new_free;
	big_block->size = (void*) new_free - big_block->pPayload;
	return new_free;
}	

void* custom_alloc(size_t desired_size) {
	BSTNode* node = check_tree(desired_size);
	if (node == NULL) {
		char* pNewUsage = align(pCurrent + HEADER_SIZE + desired_size); 
		if (pNewUsage > pBrk) {
			pBrk = ((pNewUsage > (pBrk + MIN_ALLOC)) ? pNewUsage : (pBrk + MIN_ALLOC));
			#if defined(BUILD_UNIX) 
			assert(brk(pBrk) != -1 && "Could not extend heap break.");
			#elif defined(BUILD_WIN)
			assert(HeapExtend(pBrk) != NULL && "Could not extend heap break.");
			#endif
		}
		node = pCurrent;
		pCurrent = pNewUsage;	
	}	
	node->size = desired_size;
	node->left = NULL;
	node->right = NULL;
	node->parent = NULL;
	return &(node->pPayload);
}

void* custom_realloc(void* payloadptr, size_t new_size) {
	BSTNode* node = payloadptr - HEADER_SIZE;
	if (new_size < node->size) return payloadptr;
	char* newpayloadptr = custom_alloc(new_size);
	memcpy(payloadptr, node->size, newpayloadptr);
	custom_free(payloadptr);
	return newpayloadptr;
}	

void custom_free(void* payloadptr) { 
	BSTNode* freed_node = payloadptr - HEADER_SIZE;
	assert((freed_node->parent == NULL && freed_node != root_node) && "Tried to free a freed node.");
	BSTNode* adj_node = ((char*) freed_node) + HEADER_SIZE + freed_node->size;
	while (true) {
		if (adj_node->parent == NULL && adj_node != root_node) break;
		freed_node->size += HEADER_SIZE + adj_node->size;
		remove_n_replace(adj_node);
		adj_node += HEADER_SIZE + adj_node->size;
	}	
	tree_insert(freed_node);
}	
