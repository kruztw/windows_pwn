#pragma warning( disable : 4996 )

#include <windows.h>
#include <heapapi.h>
#include <stdio.h>
#include <cstdio>

struct chunk {
	char content[0x10];
	int (*puts_ptr)(const char *);
};

struct chunk* chunks[100];

int main()
{
	HANDLE hHeap = HeapCreate(HEAP_NO_SERIALIZE, 0x2000, 0x2000);
	int op, size, idx;
	INT64 addr;

	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);

	while (1) {
		printf("1.add\n2.del\n3.show\n4.edit\n5.leak\n6.write\nop:");
		scanf("%d", &op);
		switch (op) {
		case 1:
			printf("idx:");
			scanf("%d", &idx);
			chunks[idx] = (struct chunk *)HeapAlloc(hHeap, HEAP_NO_SERIALIZE, sizeof(struct chunk));
			chunks[idx]->puts_ptr = puts;
			break;

		case 2:
			printf("idx:");
			scanf("%d", &idx);
			HeapFree(hHeap, HEAP_NO_SERIALIZE, chunks[idx]);
			break;
		
		case 3:
			printf("idx:");
			scanf("%d", &idx);
			chunks[idx]->puts_ptr(chunks[idx]->content);
			break;

		case 4:
			printf("idx & size:");
			scanf("%d%d", &idx, &size);
			getchar();
			for (int i = 0; i < size; i++)
				chunks[idx]->content[i] = getchar();
			break;

		case 5:
			printf("addr:");
			scanf("%lld", &addr);
			puts((char *)addr);
			break;
	    
		case 6:
			printf("addr:");
			scanf("%ld", &addr);
			scanf("%ld", (INT64*)addr);
			break;

		default:
			return 0;
		}
	}
}