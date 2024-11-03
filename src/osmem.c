// SPDX-License-Identifier: BSD-3-Clause
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#include "osmem.h"
#include "block_meta.h"

struct block_meta *head;
static size_t THRESHOLD = 1024 * 128;
int preallocated;

static size_t align(size_t size)
{
	if (size % 8 == 0)
		return size;
	else
		return size + (8 - (size % 8));
}

struct block_meta *adaugareBlockBrk(size_t size)
{
	struct block_meta *current = head;

	while (current->next)
		current = current->next;

	struct block_meta *new_block = (struct block_meta *)sbrk(sizeof(struct block_meta) + size);

	DIE(new_block == (void *)-1, "Failed to allocate memory");

	new_block->prev = current;
	new_block->next = NULL;
	new_block->status = STATUS_ALLOC;
	new_block->size = size;

	current->next = new_block;
	return new_block;
}

void split(size_t size, struct block_meta *current)
{
	struct block_meta *new_block = (struct block_meta *)((char *)current + align(size + sizeof(struct block_meta)));

	new_block->prev = current;
	new_block->next = current->next;
	new_block->size = current->size - align(size + sizeof(struct block_meta));
	new_block->status = STATUS_FREE;

	current->next = new_block;
	current->size = size;
	current->status = STATUS_ALLOC;
}

struct block_meta *findBestFreeBlock(size_t size)
{
	struct block_meta *current = head;

	while (current != NULL) {
		if (current->status == STATUS_FREE && current->size >= size) {
			if (current->size >= size + sizeof(struct block_meta) + 1)
				split(size, current);
			current->status = STATUS_ALLOC;
			return current;
		} else if (!(current->next) && current->status == STATUS_FREE && current->size < size) {
			sbrk(align(size - current->size));
			current->status = STATUS_ALLOC;
			current->size = align(size);
			return current;
		}

		current = current->next;
	}
	return adaugareBlockBrk(size);
}

void mergeBlock(struct block_meta *temp)
{
	struct block_meta *temp2 = temp->next;

	temp->size += temp->next->size + sizeof(struct block_meta);
	temp->size = align(temp->size);
	if (temp->next->next) {
		temp->next->next->prev = temp;
		temp->next = temp->next->next;
	} else {
		temp->next = NULL;
	}
	temp2->prev = NULL;
	temp2->next = NULL;
	temp2->size = 0;
}

void coalesce()
{
	struct block_meta *temp = head;

	while (temp->next) {
		if (temp->status == STATUS_FREE && temp->next->status == STATUS_FREE) {
			mergeBlock(temp);
		} else {
			temp = temp->next;
		}
	}
}


void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	size = align(size);

	if (head)
		coalesce();

	if (size + sizeof(struct block_meta) < THRESHOLD) {
		if (head == NULL) {
			preallocated = 1;
			head = (struct block_meta *)sbrk(THRESHOLD);
			DIE(head == (void *)-1, "Failed to allocate memory");
			head->prev = NULL;
			head->next = NULL;
			head->status = STATUS_ALLOC;
			head->size = THRESHOLD - sizeof(struct block_meta);
			return (void *)(head + 1);
		}
			struct block_meta *new_block = findBestFreeBlock(size);

			return (void *)(new_block + 1);
	} else {
		if (!head) {
			head = (struct block_meta *)
			mmap(NULL, size + sizeof(struct block_meta), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			DIE(head == (void *)-1, "Failed to allocate memory");
			head->prev = NULL;
			head->next = NULL;
			head->size = size;
			head->status = STATUS_MAPPED;
			return (void *)(head + 1);
		}
		struct block_meta *new_block;

		new_block = (struct block_meta *)
		mmap(NULL, sizeof(struct block_meta) + size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		DIE(new_block == (void *)-1, "Failed to allocate memory");

		struct block_meta *current = head;

		while (current && current->next)
			current = current->next;

		if (current == NULL)
			new_block->prev = NULL;
		else
			new_block->prev = current;
		new_block->next = NULL;
		new_block->size = size;
		new_block->status = STATUS_MAPPED;

		if (current)
			current->next = new_block;

		return (void *)(new_block + 1);
	}
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr == NULL)
		return;

	struct block_meta *meta = (struct block_meta *)ptr - 1;

	if (meta->status == STATUS_ALLOC)
		meta->status = STATUS_FREE;

	if (meta->status == STATUS_MAPPED) {
		if (meta->next && meta->prev) {
			meta->prev->next = meta->next;
			meta->next->prev = meta->prev;
		} else if (meta->prev && !meta->next) {
			meta->prev->next = NULL;
		}
		meta->prev = NULL;
		meta->next = NULL;
		munmap(meta, meta->size + sizeof(struct block_meta));
		if (meta == (void *)head)
			head = NULL;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	if (size == 0 || nmemb == 0)
		return NULL;

	size = align(size * nmemb);

	if (head)
		coalesce();

	if (size + 32 < 4 * 1024) {
		if (head == NULL) {
			head = (struct block_meta *)sbrk(THRESHOLD);
			DIE(head == (void *)-1, "Failed to allocate memory");
			head->prev = NULL;
			head->next = NULL;
			head->status = STATUS_ALLOC;
			head->size = THRESHOLD - sizeof(struct block_meta);
			memset(head, 0, head->size);
			return (void *)(head + 1);
		}
			struct block_meta *new_block = findBestFreeBlock(size);

			memset(new_block + 1, 0, new_block->size);
			return (void *)(new_block + 1);
	} else {
		if (!head) {
			head = (struct block_meta *)
			mmap(NULL, size + sizeof(struct block_meta), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			DIE(head == (void *)-1, "Failed to allocate memory");
			head->prev = NULL;
			head->next = NULL;
			head->size = size;
			head->status = STATUS_MAPPED;
			return (void *)(head + 1);
		}
		struct block_meta *new_block;

		new_block = (struct block_meta *)
		mmap(NULL, sizeof(struct block_meta) + size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		DIE(new_block == (void *)-1, "Failed to allocate memory");

		struct block_meta *current = head;

		while (current && current->next)
			current = current->next;

		if (current == NULL)
			new_block->prev = NULL;
		else
			new_block->prev = current;
		new_block->next = NULL;
		new_block->size = size;
		new_block->status = STATUS_MAPPED;

		if (current)
			current->next = new_block;
		memset(new_block + 1, 0, new_block->size);
		return (void *)(new_block + 1);
	}
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	if (!ptr)
		return os_malloc(size);

	if (head)
		coalesce();

	struct block_meta *new_ptr = (struct block_meta *)ptr;

	if (size < new_ptr->size) {
		if (new_ptr->size >= size + sizeof(struct block_meta) + 1) {
			if (new_ptr == head) {
				head = (struct block_meta *)sbrk(THRESHOLD);
				DIE(head == (void *)-1, "Failed to allocate memory");
				head->prev = NULL;
				head->next = NULL;
				head->status = STATUS_ALLOC;
				head->size = THRESHOLD - sizeof(struct block_meta);

				munmap(new_ptr, new_ptr->size + sizeof(struct block_meta));
				return (void *)head;
			}
		} else {
			split(size, new_ptr);
		}
		return (void *)new_ptr;
	}
	if (preallocated == 0) {
		preallocated = 1;
		if (head) {
			struct block_meta *new_block = (struct block_meta *)sbrk(THRESHOLD);

			DIE(new_block == (void *)-1, "Failed to allocate memory");

			struct block_meta *temp = head;

			new_block->next = temp;
			temp->prev = new_block;
			new_block->prev = NULL;
			new_block->size = THRESHOLD;
			new_block->status = STATUS_ALLOC;
			head = new_block;
			os_free(ptr);

			memcpy(new_block, new_ptr, new_ptr->size);

			return (void *)new_block;
		}
		head = (struct block_meta *)sbrk(THRESHOLD);
		DIE(head == (void *)-1, "Failed to allocate memory");
		head->prev = NULL;
		head->next = NULL;
		head->status = STATUS_ALLOC;
		head->size = THRESHOLD - sizeof(struct block_meta);

		memcpy(head, new_ptr, new_ptr->size);

		return (void *)head;
	}
	struct block_meta *new_block = findBestFreeBlock(size);

	os_free(ptr);

	memcpy(new_block, new_ptr, new_ptr->size);

	return (void *)new_block;
}
