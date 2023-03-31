#include <stdio.h>
#include <stdlib.h>
#include <likwid.h>

#define DTYPE double

void dummy(void *);

int main(int argc, char *argv[]) {
    if(argc < 2) {
        printf("Usage: %s (repeat elements)...\n", argv[0]);
        return 1;
    }
    const int tests = (argc-1) / 2;
    int repeats[tests];
    int elements[tests];
    int maxelements = 0;
    for(int t=0; t<tests; t++) {
        repeats[t] = atoi(argv[1+t*2]);
        elements[t] = atoi(argv[2+t*2]);
        if(maxelements < elements[t]) {
            maxelements = elements[t];
        }
    }
    printf("kernel: update\n");
    printf("elementsize: %lu\n", sizeof(DTYPE));
    
    //SETUP
    DTYPE* a = malloc(maxelements*sizeof(DTYPE));
    for(int i=0; i<maxelements; i++) {
        a[i] = i;
    }

    likwid_markerInit();

    char cur_region_name[128];
    for(int t=0; t<tests; t++) {
        const int cur_elements = elements[t];
        const int cur_repeats = repeats[t];
        sprintf(cur_region_name, "update_%i_%i", cur_repeats, cur_elements);
        likwid_markerRegisterRegion(cur_region_name);
        printf("%s:iterations: %i\n", cur_region_name, cur_elements);
        printf("%s:repetitions: %i\n", cur_region_name, cur_repeats);

        for(int warmup = 1; warmup >= 0; --warmup) {
            int repeat = 2;
            if(warmup == 0) {
                repeat = cur_repeats;
                likwid_markerStartRegion(cur_region_name);
            }

            for(; repeat > 0; --repeat) {
                for(int i=0; i<cur_elements; i++) {
                    a[i] += 0.001;
                }

                dummy((void*)&a);
            }
        }
        likwid_markerStopRegion(cur_region_name);
    }
    likwid_markerClose();
    free(a);
    return 0;
}
