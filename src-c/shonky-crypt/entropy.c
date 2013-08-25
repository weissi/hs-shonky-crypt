/* Taken from http://rosettacode.org/wiki/Entropy#C */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

static int makehist(const char *str, int *hist, int len){
    int wherechar[256];
    int histlen=0;
    for(int i=0;i<256;i++) {
        wherechar[i]=-1;
    }
    for(int i=0;i<len;i++){
        if(wherechar[(int)str[i]]==-1){
            wherechar[(int)str[i]]=histlen;
            histlen++;
        }
        hist[wherechar[(int)str[i]]]++;
    }
    return histlen;
}

static double entropy_internal(int *hist, int histlen, int len) {
    double H = 0.0;

    for (int i=0; i<histlen; i++){
        H-=(double)hist[i]/len*log2((double)hist[i]/len);
    }
    return H;
}

double sc_entropy(const char *str, size_t len) {
    int *hist = (int *)calloc(len, sizeof(int));
    int histlen = makehist(str, hist, len);
    return entropy_internal(hist,histlen,len);
}
