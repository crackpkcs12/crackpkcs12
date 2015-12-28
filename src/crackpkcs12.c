/* crackpkcs12 is a multithreaded program to crack PKCS12 files
*  Copyright (C) 2011, 2012 Alfredo Esteban de la Torre
*
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*  In addition, as a special exception, the copyright holders give
*  permission to link the code of portions of this program with the
*  OpenSSL library under certain conditions as described in each
*  individual source file, and distribute linked combinations
*  including the two.
*  You must obey the GNU General Public License in all respects
*  for all of the code used other than OpenSSL.  If you modify
*  file(s) with this exception, you may extend this exception to your
*  version of the file(s), but you are not obligated to do so.  If you
*  do not wish to do so, delete this exception statement from your
*  version.  If you delete this exception statement from all source
*  files in the program, then also delete it here.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>

#define DEFAULTMSGINTERVAL 100000
#define DEFAULTMINWORDLENGTH 1
#define DEFAULTMAXWORDLENGTH 8
#define MINWORDLENGTH 1
#define MAXWORDLENGTH 2048
#define MINARGNUMBER 4
#define PARTIALBASESIZE 256
#define MAXBASESIZE 1024
#define ELAPSEDSECONDS 1
#define BASELENGTH 256

int nthreads;
int nthreads_total;

typedef struct {
	int id;
	FILE* dictfile;
	char *file2crack;
	pthread_mutex_t *m;
	char quiet;
	unsigned long long *count;
} workerdict;

typedef struct {
	int id;
	char *base;
	int baselength;
	int wordlength_min;
	int wordlength;
	char *word;
	char *file2crack;
	pthread_mutex_t *m;
	char quiet;
	unsigned long long *count;
} workerbrute;

void usage() {
	printf(
"\nUsage:\n\ncrackpkcs12 { -d <dictionary_file> |  -b [ -m <min_psw_length> ] [ -M <max_psw_length> ] [ -c <base_char_sets> | -s <specific_char_sets> ] } [ -t <num_of_threads> ] [ -v ] <file_to_crack>\n"
"\n"
"  -b                       Uses brute force attack\n\n"
"  -m <min_password_length> Specifies minimum length of password (implies -b)\n\n"
"  -M <max_password_length> Specifies maximum length of password (implies -b)\n\n"
"  -c <base_char_sets>      Specifies characters sets (one or more than one) and order to conform passwords (requires -b, -m or -M)\n"
"                           a = letters (abcdefghijklmnopqrstuvwxyz)\n"
"                           A = capital letters (ABCDEFGHIJKLMNOPQRSTUVWXYZ)\n"
"                           n = digits (0123456789)\n"
"                           s = special characters (!\"#$%%&'()*+,-./:;<=>?@[\\]^_`{|}~) (including blank)\n"
"                           x = all previous sets\n\n"
"  -s <specific_char_set>   Uses <specific_char_set> to conform passwords (requires -b, -m or -M)\n\n"
"  -d <dictionary_file>     Uses dictionary attack and specify dictionary file path\n\n"
"  -t <number_of_threads>   Specifies number of threads (by default number of CPU's)\n\n"
"  -v                       Verbose mode\n\n"
	);
	exit(100);
}

void *print_output(void *ptr);
char* getbase(char *scs);
void *work_dict(void *ptr);
void *work_brute(void *ptr);
void generate(workerbrute *wthread, int pivot, PKCS12 *p12, unsigned long long *gcount);
void try(workerbrute *wthread, PKCS12 *p12, unsigned long long *gcount);

int main(int argc, char** argv) {

	char *psw, *infile, *dict, *nt, *msgintstring, quiet, isdict, isbrute, *swl_min, *swl_max, *scs, *ics, *base;
	int c;
	unsigned long long *count;
	int wordlength_min = MINWORDLENGTH;
	int wordlength_max = 0;
	quiet = 1;
	psw = NULL;
	infile = NULL;
	dict = NULL;
	nt = NULL;
	msgintstring = NULL;
	scs = NULL;
	ics = NULL;
	nt = NULL;
	isdict = 0;
	isbrute = 0;
	swl_min = NULL;
	swl_max = NULL;
	base = NULL;
	nthreads = sysconf (_SC_NPROCESSORS_ONLN);
	nthreads_total = sysconf (_SC_NPROCESSORS_ONLN);

	while ((c = getopt (argc, argv, "t:d:s:vbm:M:c:")) != -1)
		switch (c) {
			case 'b':
				isbrute = 1;
				break;
			case 'M':
				isbrute = 1;
				swl_max = optarg;				
				break;
			case 'm':
				isbrute = 1;
				swl_min = optarg;				
				break;
			case 'c':
				scs = optarg;				
				break;
			case 's':
				ics = optarg;				
				break;
			case 'd':
				isdict = 1;
				dict = optarg;
				break;
			case 't':
				nt = optarg;
				break;
			case 'v':
				quiet = 0;
				break;
			case '?':
				if (optopt == 't' || optopt == 'd' || optopt == 's') {
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				}
			default:
				usage();
		}

	if (!isdict && !isbrute) {
		fprintf(stderr,"Error: Choose at least one attack type (-d for dictionary attack or -b for brute force attack)\n\n");
		usage();
	}

	if (ics != NULL && scs != NULL) {
		fprintf(stderr,"-c and -s are not compatible flags\n\n");
		usage();
	}
	
	
	if (optind != argc-1)
		usage();
	else
		infile = argv[optind];

	if (isdict == 1 && dict == NULL) {
		fprintf(stderr,"Error: No dictionary file specified\n\n");
		usage();
	}

	if (swl_min != NULL) {
		wordlength_min = strtol(swl_min, NULL, 10);
		if (errno == EINVAL)
			usage();
		if (wordlength_min < MINWORDLENGTH) {
			wordlength_min = MINWORDLENGTH;
			printf("\nForcing min word length to %d\n\n",wordlength_min);
		}
	}
	else
	    wordlength_min = DEFAULTMINWORDLENGTH;

	if (swl_max != NULL) {
		wordlength_max = strtol(swl_max, NULL, 10);
		if (errno == EINVAL)
			usage();
		if (wordlength_max > MAXWORDLENGTH) {
			wordlength_max = MAXWORDLENGTH;
			printf("\nForcing max word length to %d\n\n",wordlength_max);
		}
	}
	else
	    wordlength_max = DEFAULTMAXWORDLENGTH;

	if (wordlength_min > wordlength_max) {
		if (swl_min != NULL && swl_max != NULL) {
			fprintf(stderr,"Error: Min length is greater than max length\n\n");
			usage();
		}
		else if (swl_min != NULL && swl_max == NULL)
			wordlength_max = wordlength_min;
		else if (swl_min == NULL && swl_max != NULL)
			wordlength_min = wordlength_max;
	}

	if (isbrute) {
		if (ics != NULL) {
			base = ics;
		}
		else {
			if (scs == NULL)
				scs = "x"; // by default all character sets
			base = getbase(scs);
			if (base == NULL)
				usage();
		}
	}
	else if (scs != NULL || ics != NULL) {
		printf("-c and -s flags require -b, -m or -M flags\n");
		usage();
	}

	if (nt != NULL) {
		nthreads = strtol(nt, NULL, 10);
		if (errno == EINVAL)
			usage();
	}

	if (!quiet)
		nthreads_total++;

	OpenSSL_add_all_algorithms();

	pthread_t *thread = (pthread_t *) calloc(nthreads_total,sizeof(pthread_t));
	int *thread_ret = (int *) calloc(nthreads_total, sizeof(int));
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	count = calloc(nthreads, sizeof(unsigned long long));
	int i;
	if (isdict) {
		// Opening dictionary file
		FILE *dictfile = fopen(dict,"r");
		if (!dictfile) {
			fprintf(stderr,"Dictionary file not found: %s\n",dict);
			exit(20);
		}
		workerdict *wthread = (workerdict *) calloc(nthreads,sizeof(workerdict));
	
		printf("\nDictionary attack - Starting %d threads\n",nthreads);

		for (i=0; i<nthreads; i++) {
			wthread[i].id = i;
			wthread[i].m = &mutex;
			wthread[i].dictfile = dictfile;
			wthread[i].file2crack = infile;
			wthread[i].quiet = quiet;
			wthread[i].count = count+i;
			thread_ret[i] = pthread_create( &thread[i], NULL, work_dict, (void*) &wthread[i]);
		}
		if (!quiet)
			pthread_create(&thread[i], NULL, print_output, (void*) count);
		for (i=0; i<nthreads_total; i++) {
			pthread_join(thread[i], NULL);
		}

		if (!quiet) sleep(ELAPSEDSECONDS);
		printf("\nDictionary attack - Exhausted search\n");
	}
	
	if (isbrute) {
		workerbrute *wthread = (workerbrute *) calloc(nthreads,sizeof(workerbrute));

		printf("\nBrute force attack - Starting %d threads\n",nthreads);
		printf("\nAlphabet: %s", base);
		if (strchr(base,' ') != NULL) printf(" <(including blank)>");		
		printf("\nMin length: %d", wordlength_min);
		if (swl_min == NULL) printf(" [default]");
		printf("\nMax length: %d", wordlength_max);
		if (swl_max == NULL) printf(" [default]");
		printf("\nUse -m and -M flags to modify these values.\n");
	
		for (i=0; i<nthreads; i++) {
			wthread[i].id = i;
			wthread[i].wordlength_min = wordlength_min;
			wthread[i].wordlength = wordlength_max;
			wthread[i].word = (char *) calloc(wordlength_max, sizeof(char));
			wthread[i].base = base;
			wthread[i].baselength = strlen(base);
			wthread[i].m = &mutex;
			wthread[i].file2crack = infile;
			wthread[i].quiet = quiet;
			wthread[i].count = count+i;
			thread_ret[i] = pthread_create( &thread[i], NULL, work_brute, (void*) &wthread[i]);
		}
		if (!quiet)
			pthread_create(&thread[i], NULL, print_output, (void*) count);
		for (i=0; i<nthreads_total; i++)
			pthread_join(thread[i], NULL);

		if (!quiet) sleep(ELAPSEDSECONDS);
		printf("\nBrute force attack - Exhausted search\n");
	}

	printf("\nNo password found\n\n");

	pthread_exit(NULL);
	exit(0);
}

void *print_output(void *ptr) {
	unsigned long long *count = (unsigned long long *) ptr;
	unsigned long long sum;
	unsigned long long sum_old = 0;
	unsigned long long diff = 0;
	int i;
	printf("\n");
	fflush(stdout);
	do {
		sleep(ELAPSEDSECONDS);
		sum = 0;
		for (i = 0; i < nthreads; i++)
			sum += count[i];
		diff = sum - sum_old;
		if (diff != 0) printf("\rPerformance: %20llu passwords [%8llu passwords per second]", sum, diff);
		fflush(stdout);
		sum_old = sum;
	} while (diff != 0);
}

char* getbase(char *scs) {
	char alpha[PARTIALBASESIZE] = "abcdefghijklmnopqrstuvwxyz";
	char special[PARTIALBASESIZE] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ";
	char capital[PARTIALBASESIZE] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char numeric[PARTIALBASESIZE] = "0123456789";
	char isa = 0;
	char isA = 0;
	char isn = 0;
	char iss = 0;

	char *base = (char *)calloc(MAXBASESIZE,sizeof(char));

	int i;
	for (i=0; i<strlen(scs); i++) {
		if (scs[i] == 'a' && isa == 0) {
			strncat(base,alpha,PARTIALBASESIZE);
			isa = 1;
		}
		else if (scs[i] == 'A' && isA == 0) {
			strncat(base,capital,PARTIALBASESIZE);
			isA = 1;
		}
		else if (scs[i] == 'n' && isn == 0) {
			strncat(base,numeric,PARTIALBASESIZE);
			isn = 1;
		}
		else if (scs[i] == 's' && iss == 0) {
			strncat(base,special,PARTIALBASESIZE);
			iss = 1;
		}
		else if (scs[i] == 'x') {
			bzero(base,MAXBASESIZE * sizeof(char));
			strncat(base,alpha,PARTIALBASESIZE);
			strncat(base,capital,PARTIALBASESIZE);
			strncat(base,numeric,PARTIALBASESIZE);
			strncat(base,special,PARTIALBASESIZE);
			return base;
		}
		else
			return NULL;
	}

	return base;
}

void *work_dict( void *ptr ) {
	// Opening p12 file
	BIO* in = NULL;
	workerdict *wthread = (workerdict *) ptr;

	pthread_mutex_lock(wthread->m);

	in = BIO_new_file(wthread->file2crack, "rb");
	if (!in) {
		fprintf (stderr,"PKCS12 file not found: %s\n",wthread->file2crack);
		exit(10);
	}

	// Creating PKCS12 object
	PKCS12 *p12 = NULL;
	if (!(p12 = d2i_PKCS12_bio (in, NULL))) {
		perror("Unable to create PKCS12 object\n");
		exit(30);
	}

	pthread_mutex_unlock(wthread->m);

	char line[256];
	char found = 0;
	char stop = 0;
	int i = 0;
	char *p;
	*(wthread->count) = 0;
	// Work
	while (!found && fgets(line, sizeof line,wthread->dictfile) != NULL) {
		p = line + strlen(line) - 1;
		if (*p == '\n') *p = '\0';
		if ((p != line) && (*--p == '\r')) *p = '\0';
		(*(wthread->count))++;
		if (PKCS12_verify_mac(p12, line, -1))
			found = 1;	
	}

	if (found) {
		if (!wthread->quiet) sleep(ELAPSEDSECONDS);
		printf("\n*********************************************************\n");
		printf("Dictionary attack - Thread %d - Password found: %s\n",wthread->id+1,line);
		printf("*********************************************************\n\n");
		exit(0);
	}

	pthread_exit(0);
}

void *work_brute( void *ptr ) {
	// Opening p12 file
	BIO* in = NULL;
	workerbrute *wthread = (workerbrute *) ptr;

	pthread_mutex_lock(wthread->m);

	in = BIO_new_file(wthread->file2crack, "rb");
	if (!in) {
		fprintf (stderr,"PKCS12 file not found: %s\n",wthread->file2crack);
		exit(10);
	}

	// Creating PKCS12 object
	PKCS12 *p12 = NULL;
	if (!(p12 = d2i_PKCS12_bio (in, NULL))) {
		perror("Unable to create PKCS12 object\n");
		exit(30);
	}

	pthread_mutex_unlock(wthread->m);

	int maxwordlength = wthread->wordlength;
	int i;
	*(wthread->count) = 0;
	for (wthread->wordlength=wthread->wordlength_min; wthread->wordlength <= maxwordlength; wthread->wordlength++) {
		for (i=wthread->id; i<wthread->baselength; i+=nthreads) {
			wthread->word[0] = wthread->base[i];
			if (wthread->wordlength>1)
				generate(wthread, 1, p12, wthread->count);
			else
				try(wthread, p12, wthread->count);
		}
	}
}

void generate(workerbrute *wthread, int pivot, PKCS12 *p12, unsigned long long *gcount) {
	int i, j, ret;

	for (i=0; i<wthread->baselength; i++) {
		wthread->word[pivot] = wthread->base[i];
		if (pivot < wthread->wordlength-1)
			generate(wthread, pivot+1, p12, gcount);
		else
			try(wthread,p12,gcount);
	}
	wthread->word[pivot] = '\0';
}

void try(workerbrute *wthread, PKCS12 *p12, unsigned long long *gcount) {
	(*gcount)++;

	if (PKCS12_verify_mac(p12, wthread->word, -1)) {
		if (!wthread->quiet) sleep(ELAPSEDSECONDS);
		printf("\n**********************************************************\n");
		printf("Brute force attack - Thread %d - Password found: %s\n",wthread->id+1,wthread->word);
		printf("**********************************************************\n\n");
		exit(0);
	}
}
