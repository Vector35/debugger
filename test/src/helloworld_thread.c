#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32) || defined(_WIN64)
#define OS_IS_WINDOWS
#endif

#if defined(OS_IS_WINDOWS)
#include <windows.h>
#else
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#endif

#if defined(OS_IS_WINDOWS)
DWORD WINAPI ThreadFunc(void* vargp)
//#define SLEEP1SEC Sleep(1000)
#else
void *thread_func(void *vargp)
//#define SLEEP1SEC sleep(1)
#endif

#define SLEEP1SEC for(int i=0; i<99999999; ++i) { foo *= 3; }

{
	int i;
	int myid = *(int *)vargp;
	srand(myid);
	for(i=0; i<1000; ++i) {
		printf("I'm thread %d.\n", myid);
		int foo = 7;
		/* stop at random rip, visible in debugger */
		switch(rand()%10) {
			case 0: printf("rolled 0\n"); SLEEP1SEC; break;
			case 1: printf("rolled 1\n"); SLEEP1SEC; break;
			case 2: printf("rolled 2\n"); SLEEP1SEC; break;
			case 3: printf("rolled 3\n"); SLEEP1SEC; break;
			case 4: printf("rolled 4\n"); SLEEP1SEC; break;
			case 5: printf("rolled 5\n"); SLEEP1SEC; break;
			case 6: printf("rolled 6\n"); SLEEP1SEC; break;
			case 7: printf("rolled 7\n"); SLEEP1SEC; break;
			case 8: printf("rolled 8\n"); SLEEP1SEC; break;
			case 9: printf("rolled 9\n"); SLEEP1SEC; break;
		}
	}

#if defined(OS_IS_WINDOWS)
	return 0;
#else
	return NULL;
#endif
}

int main(int ac, char **av)
{
	printf("Before Thread\n");

#if defined(OS_IS_WINDOWS)
	DWORD ids[4] = {0, 1, 2, 3};
	HANDLE hThreadArray[4];
	hThreadArray[0] = CreateThread(NULL, 0, ThreadFunc, (void *)(ids+0), 0, NULL);
	hThreadArray[1] = CreateThread(NULL, 0, ThreadFunc, (void *)(ids+1), 0, NULL);
	hThreadArray[2] = CreateThread(NULL, 0, ThreadFunc, (void *)(ids+2), 0, NULL);
	hThreadArray[3] = CreateThread(NULL, 0, ThreadFunc, (void *)(ids+3), 0, NULL);
	WaitForMultipleObjects(4, hThreadArray, TRUE, INFINITE);
#else
	int ids[4] = {0, 1, 2, 3};
	pthread_t thread_id[4];
	pthread_create(&thread_id[0], NULL, thread_func, (void *)(ids+0));
	pthread_create(&thread_id[1], NULL, thread_func, (void *)(ids+1));
	pthread_create(&thread_id[2], NULL, thread_func, (void *)(ids+2));
	pthread_create(&thread_id[3], NULL, thread_func, (void *)(ids+3));
	pthread_join(thread_id[0], NULL);
	pthread_join(thread_id[1], NULL);
	pthread_join(thread_id[2], NULL);
	pthread_join(thread_id[3], NULL);
#endif

	return 12;
}
