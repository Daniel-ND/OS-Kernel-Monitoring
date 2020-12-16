/* A=219;B=0x5BAC7FBA;C=mmap;D=87;E=142;F=blocked;G=75;H=seq;I=93;J=min;K=futex*/

#include <sys/mman.h>
#include <sys/random.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

#include <pthread.h>
#include <linux/futex.h> 
#include <sys/time.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <errno.h> 


#define MEMORY_ADDRESS 0x5BAC7FBA /* B=0x5BAC7FBA */
#define MEMORY_SIZE (219 * 1024 * 1024) /* A=219 MB */
#define WRITE_THREADS_COUNT 87 /* D=87 */ 
#define FILE_SIZE (142 * 1024 * 1024) /* E=142 MB */
#define FILE_COUNT (MEMORY_SIZE / FILE_SIZE + 1)
#define IO_BLOCK_SIZE 75 /* G=75 B */
#define READ_THREADS_COUNT 93 /* I=93 */

#define FILE_OPEN_FLAGS O_RDWR | O_CREAT
#define FILE_OPEN_MODE S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH
#define FILE_TEMPLATE "/tmp/os-rand-file-%lu"

static int tmp_fd[FILE_COUNT];
static int *futex_value;

static volatile int thread_initialized;
static volatile int thread_terminate = 0;
static pthread_t write_threads[WRITE_THREADS_COUNT];
static pthread_t read_threads[READ_THREADS_COUNT];


struct write_thread_args {
    char *start;
    size_t size;
    size_t thread_num;
};

struct read_thread_args {
    off_t offset;
    size_t size;
    size_t thread_num;
    size_t file_num;
};

void setup_files(){
    size_t i;
    futex_value = malloc(sizeof(int) * FILE_COUNT);
    for (i = 0; i < FILE_COUNT; i++) {     
        char filename[22];
        sprintf(filename, FILE_TEMPLATE, i);
        tmp_fd[i] = open(filename, FILE_OPEN_FLAGS, FILE_OPEN_MODE);
        ftruncate(tmp_fd[i], FILE_SIZE);
        futex_value[i] = 1;
    }
}

static int futex(int *uaddr, int futex_op, int val, 
const struct timespec *timeout, int *uaddr2, int val3){
           return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr, val3);
}

static void futex_wait(int *futexp) {
    while (1) {
        const int one = 1;
        if (atomic_compare_exchange_strong(futexp, &one, 0))
            break;

        futex(futexp, FUTEX_WAIT, 0, NULL, NULL, 0);
    }
}

static void futex_wake(int *futexp) {
    const int zero = 0;
    if (atomic_compare_exchange_strong(futexp, &zero, 1)) {
        futex(futexp, FUTEX_WAKE, 1, NULL, NULL, 0);
    }
}

void *write_block(void *args) {
    struct write_thread_args *v_args = args;
    char *start = v_args->start;
    size_t size = v_args->size;
    size_t thread_num = v_args->thread_num;

    thread_initialized = 1;
    size_t lock_count = 0;
    while(!thread_terminate){
        getrandom(start, size, 0);
        size_t file_num = thread_num / (WRITE_THREADS_COUNT / FILE_COUNT);

        futex_wait(&futex_value[file_num]);
        lock_count++;
        fprintf(stderr, "[write %3lu] Lock to file #%lu: ACQUIRE (for the %lu time)\n", thread_num, file_num, lock_count);            
        for (size_t i = 0; i < size; i+= IO_BLOCK_SIZE){
            if(write(tmp_fd[file_num], start + i, IO_BLOCK_SIZE) < IO_BLOCK_SIZE){
                lseek(tmp_fd[file_num], 0, SEEK_SET);                   
                write(tmp_fd[file_num], start + i, IO_BLOCK_SIZE);
             }
        }

        fprintf(stderr, "[write %3lu] Lock to file #%lu: RELEASE\n", thread_num, file_num);
        futex_wake(&futex_value[file_num]);
    }
    fprintf(stderr, "[write %3lu] Thread terminated\n", thread_num);
    return NULL;
}

void write_threads_init(char *p){
    size_t i;
    size_t size = MEMORY_SIZE / WRITE_THREADS_COUNT;
    
    for (i = 0; i < WRITE_THREADS_COUNT; i++) {
        thread_initialized = 0;
        struct write_thread_args args = {p + i * size, size, i};
        pthread_create(&write_threads[i], NULL, write_block, &args);
        while (!thread_initialized);
        fprintf(stderr, "%3lu. Created write thread for block at %ld\n", (i + 1), (long) (p + i * size));
    }
}

void close_threads(void) {
    size_t i;
    thread_terminate = 1;
    for (i = 0; i < WRITE_THREADS_COUNT; i++) pthread_join(write_threads[i], NULL);
    // for (i = 0; i < READ_THREADS_COUNT; i++) pthread_join(read_threads[i], NULL);
    for (i = 0; i < FILE_COUNT; i++)  {
        close(tmp_fd[i]);
    }
    puts("All threads are terminated");
}

void *read_block(void *args) {
    struct read_thread_args *v_args = args;
    off_t offset = v_args->offset;
    size_t size = v_args->size;
    size_t thread_num = v_args->thread_num;
    size_t file_num = v_args->file_num;

    thread_initialized = 1;
    size_t lock_count = 0;
    while (!thread_terminate) {
        size_t i;
        unsigned char min = CHAR_MAX;
        unsigned char block[size];
        
        futex_wait(&futex_value[file_num]);
        lock_count++;
        fprintf(stderr, "[read %4lu] Lock to file #%lu: ACQUIRE (for the %lu time)\n", thread_num, file_num, lock_count);

        /* read a block at the offset */
        lseek(tmp_fd[file_num], offset, SEEK_SET);
        read(tmp_fd[file_num], block, size);
        for (i = 0; i < size; i++) {
            if (min > block[i]) min = block[i];
        }
        

        /* release lock */
        fprintf(stderr, "[read %4lu] Lock to file #%lu: RELEASE, aggregated result: %#hhx\n", thread_num, file_num, min);
        futex_wake(&futex_value[file_num]);
    }
    fprintf(stderr, "[read %4lu] Thread terminated\n", thread_num);

    return NULL;

}

void read_threads_init(void) {
    size_t i, j;

    size_t threads_per_file = READ_THREADS_COUNT / FILE_COUNT;
    size_t size = FILE_SIZE / threads_per_file;

    for (i = 0; i < FILE_COUNT; i++) {
        for (j = 0; j < threads_per_file; j++) {
            thread_initialized = 0;
            struct read_thread_args args = {(j * size), size, (i * threads_per_file) + j, i};

            pthread_create(&read_threads[i], NULL, read_block, &args);
            while (!thread_initialized);
            fprintf(stderr, "%3lu. Created read thread for file %lu, offset %ld, size %lu\n", (i * threads_per_file + j), i, (j * size), size);
        }
    }
}


int main(){
    srand((unsigned) time(NULL));
    setup_files();
     while (getchar() != '\n'); /* Before allocation */
    char *p = mmap(
        (void *) MEMORY_ADDRESS,
        MEMORY_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    puts("Memory allocated");
    while (getchar() != '\n'); /* After allocation */

    write_threads_init(p);
    read_threads_init();

    while (getchar() != '\n'); /* After memory filling (need to wait a little) */
    close_threads();

    munmap(p, MEMORY_SIZE);
    while (getchar() != '\n'); /* After deallocating */
    return 0;
}
