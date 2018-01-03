/* This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.	If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>
#include <gcrypt.h>

#define DEFAULTMSGINTERVAL 100000
#define DEFAULTWORDLENGTH 6
#define MAXWORDLENGTH 2048
#define MINARGNUMBER 4
#define PARTIALBASESIZE 256
#define MAXBASESIZE 1024

GCRY_THREAD_OPTION_PTHREAD_IMPL;

typedef struct {
	int id;
	int num_threads;
	FILE* dictfile;
	char *file2crack;
	pthread_mutex_t *m;
	pthread_mutexattr_t *m_attr;
	int msginterval;
} workerdict;

typedef struct {
	int id;
	int num_threads;
	char *base;
	int baselength;
	int wordlength;
	char *word;
	char *file2crack;
	pthread_mutex_t *m;
	pthread_mutexattr_t *m_attr;
	int msginterval;
} workerbrute;

void usage() {
	printf(
"\nUsage:\n\ncrackpkcs12 { -d <dictionary_file> |  -b <max_psw_length> [ -c <base_char_sets> ] } [ -t <num_of_threads> ] [ -v ] [ -s <message_interval> ] <file_to_crack>\n"
"\n"
"  -b <max_password_length> Use brute force attack and specify maximum length of password\n\n"
"  -c <base_char_sets>      Specify characters sets (one or more than one) and order to conform passwords (requires -b)\n"
"                           a = letters (abcdefghijklmnopqrstuvwxyz)\n"
"                           A = capital letters (ABCDEFGHIJKLMNOPQRSTUVWXYZ)\n"
"                           n = digits (0123456789)\n"
"                           s = special characters (!\"#$%%&'()*+,-./:;<=>?@[\\]^_`{|}~)\n"
"                           x = all previous sets\n\n"
"  -d <dictionary_file>     Use dictionary attack and specify dictionary file path\n\n"
"  -t <number_of_threads>   Specify number of threads (by default number of CPU's)\n\n"
"  -v                       Verbose mode\n\n"
"  -s <message_inteval>     Number of attemps between messages (implied -v) (default 100000)\n\n"
	);
	exit(100);
}

char* getbase(char *scs);
void *work_dict(void *ptr);
void *work_brute(void *ptr);
void generate(workerbrute *wthread, int pivot, gnutls_pkcs12_t *p12, long long *gcount);
void try(workerbrute *wthread, gnutls_pkcs12_t *p12, long long *gcount);
char *fread_file (FILE * stream, size_t * length);

int main(int argc, char** argv) {

	char *psw, *infile, *dict, *nt, *msgintstring, verbose, isdict, isbrute, *swl, *scs, *base;
	int c;
	int msginterval = DEFAULTMSGINTERVAL;
	int wordlength = 0;
	verbose = 0;
	psw = NULL;
	infile = NULL;
	dict = NULL;
	nt = NULL;
	msgintstring = NULL;
	scs = NULL;
	nt = NULL;
	isdict = 0;
	isbrute = 0;
	swl = NULL;
	base = NULL;
	int nthreads = sysconf (_SC_NPROCESSORS_ONLN);

	while ((c = getopt (argc, argv, "t:d:vb:c:s:")) != -1)
		switch (c) {
			case 'b':
				isbrute = 1;
				swl = optarg;				
				break;
			case 'c':
				scs = optarg;				
				break;
			case 'd':
				isdict = 1;
				dict = optarg;
				break;
			case 't':
				nt = optarg;
				break;
			case 'v':
				verbose = 1;
				break;
			case 's':
				verbose = 1;
				msgintstring = optarg;
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

	if (optind != argc-1)
		usage();
	else
		infile = argv[optind];

	if (isdict == 1 && dict == NULL) {
		fprintf(stderr,"Error: No dictionary file specified\n\n");
		usage();
	}

	if (msgintstring != NULL) {
		msginterval = strtol(msgintstring, NULL, 10);
		if (errno == EINVAL)
			usage();
	}
	else if (verbose == 1)
		msginterval = DEFAULTMSGINTERVAL;

	if (swl != NULL) {
		wordlength = strtol(swl, NULL, 10);
		if (errno == EINVAL)
			usage();
		if (wordlength > MAXWORDLENGTH) {
			wordlength = MAXWORDLENGTH;
			printf("\nForcing max word length to %d\n\n",wordlength);
		}
	}
	else
			wordlength = DEFAULTWORDLENGTH;

	if (isbrute) {
		if (scs == NULL)
			scs = "x"; // by default all character sets
		base = getbase(scs);
		if (base == NULL)
			usage();
	}
	else if (scs != NULL) {
		printf("-c option requires -b option\n");
		usage();
	}

	if (nt != NULL) {
		nthreads = strtol(nt, NULL, 10);
		if (errno == EINVAL)
			usage();
		if (verbose)
			printf("\nStarting %d threads\n\n",nthreads);
	}

	int ret;
	ret = gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	if (ret != 0) {
		perror ("Init gcrupt\n");
		exit(3);
	}

	if ((ret = gnutls_global_init ()) < 0) {
		error (EXIT_FAILURE, 0, "global_init: %s", gnutls_strerror (ret));
		exit(2);
	}

	pthread_t *thread = (pthread_t *) calloc(nthreads,sizeof(pthread_t));
	int *thread_ret = (int *) calloc(nthreads, sizeof(int));
	pthread_mutex_t mutex;
	pthread_mutexattr_t mutex_attr;
	pthread_mutex_init(&mutex,&mutex_attr);
	int i;
	if (isdict) {
		// Opening dictionary file
		FILE *dictfile = fopen(dict,"r");
		if (!dictfile) {
			fprintf(stderr,"Dictionary file not found: %s\n",dict);
			exit(20);
		}
		workerdict *wthread = (workerdict *) calloc(nthreads,sizeof(workerdict));
	
		printf("\nDictionary attack - Starting %d threads\n\n",nthreads);

		for (i=0; i<nthreads; i++) {
			wthread[i].id = i;
			wthread[i].num_threads = nthreads;
			wthread[i].m = &mutex;
			wthread[i].m_attr = &mutex_attr;
			wthread[i].dictfile = dictfile;
			wthread[i].file2crack = infile;
			if (verbose == 1) wthread[i].msginterval = msginterval;
			thread_ret[i] = pthread_create( &thread[i], NULL, work_dict, (void*) &wthread[i]);
		}
		for (i=0; i<nthreads; i++) {
			pthread_join(thread[i], NULL);
			printf("\nDictionary attack - Exhausted search\n");
		}
	}
	
	if (isbrute) {
		workerbrute *wthread = (workerbrute *) calloc(nthreads,sizeof(workerbrute));

		printf("\nBrute force attack - Starting %d threads\n\n",nthreads);
	
		for (i=0; i<nthreads; i++) {
			wthread[i].id = i;
			wthread[i].num_threads = nthreads;
			wthread[i].wordlength = wordlength;
			wthread[i].word = (char *) calloc(wordlength, sizeof(char));
			wthread[i].base = base;
			wthread[i].baselength = strlen(base);
			wthread[i].m = &mutex;
			wthread[i].m_attr = &mutex_attr;
			wthread[i].file2crack = infile;
			if (verbose == 1) wthread[i].msginterval = msginterval;
			thread_ret[i] = pthread_create( &thread[i], NULL, work_brute, (void*) &wthread[i]);
		}
		for (i=0; i<nthreads; i++)
			pthread_join(thread[i], NULL);

		printf("\nBrute force attack - Exhausted search\n");
	}

	printf("\nNo password found\n\n");

	pthread_exit(NULL);
	exit(0);
}

char* getbase(char *scs) {
	char alpha[PARTIALBASESIZE] = "abcdefghijklmnopqrstuvwxyz";
	char special[PARTIALBASESIZE] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
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
	FILE *in;
	gnutls_pkcs12_t pkcs12;
	gnutls_datum_t data;
	workerdict *wthread = (workerdict *) ptr;
	int result;
	size_t size;

	pthread_mutex_lock(wthread->m);

	result = gnutls_pkcs12_init (&pkcs12);
	if (result < 0) {
		perror("Init gnutls_pkcs12_t error\n");
		exit(5);
	}

	in = fopen(wthread->file2crack, "r");
	if (!in) {
		fprintf(stderr, "gnutls_pkcs12_t file not read: %s\n",wthread->file2crack);
		exit(10);
	}

	// Importing gnutls_pkcs12_t object
	data.data = fread_file (in, &size);
	data.size = size;

	result = gnutls_pkcs12_import (pkcs12, &data, GNUTLS_X509_FMT_DER, 0);
	free (data.data);
	if (result < 0) {
		perror("Unable to import gnutls_pkcs12_t object\n");
		exit(30);
	}

	pthread_mutex_unlock(wthread->m);

	char line[256];
	char found = 0;
	char stop = 0;
	int count = wthread->msginterval;
	int i = 0;
	char *p;
	long long gcount = wthread->msginterval-1;

	// Work
	while (!found && fgets(line, sizeof line,wthread->dictfile) != NULL) {
		p = line + strlen(line) - 1;
		if (*p == '\n') *p = '\0';
		if ((p != line) && (*--p == '\r')) *p = '\0';
		gcount++;
		if ( wthread->msginterval > 0 ) {
			if (--count <= 0) {
				printf("Dictionary attack - Thread %d - Attemp %lld (%s)\n",wthread->id+1,gcount,line);
				count = wthread->msginterval;
			}
		}
		result = gnutls_pkcs12_verify_mac (pkcs12, line);
		if (result == 0)
			found = 1;
	}

	if (found) {
		printf("*********************************************************\n");
		printf("Dictionary attack - Thread %d - Password found: %s\n",wthread->id+1,line);
		printf("*********************************************************\n\n");
		exit(0);
	} else if (wthread->msginterval > 0)
		printf("Dictionary attack - Thread %d - Exhausted search (%lld attemps)\n",wthread->id+1,gcount);

	pthread_exit(0);
}

void *work_brute( void *ptr ) {
	// Opening p12 file
	FILE *in;
	gnutls_pkcs12_t pkcs12;
	gnutls_datum_t data;
	workerbrute *wthread = (workerbrute *) ptr;
	int result;
	size_t size;

	pthread_mutex_lock(wthread->m);

	result = gnutls_pkcs12_init (&pkcs12);
	if (result < 0) {
		perror("Init gnutls_pkcs12_t error\n");
		exit(5);
	}

	in = fopen(wthread->file2crack, "r");
	if (!in) {
		fprintf(stderr, "gnutls_pkcs12_t file not read: %s\n",wthread->file2crack);
		exit(10);
	}

	// Importing gnutls_pkcs12_t object
	data.data = fread_file (in, &size);
	data.size = size;

	result = gnutls_pkcs12_import (pkcs12, &data, GNUTLS_X509_FMT_DER, 0);
	free (data.data);
	if (result < 0) {
		perror("Unable to import gnutls_pkcs12_t object\n");
		exit(30);
	}

	pthread_mutex_unlock(wthread->m);

	int maxwordlength = wthread->wordlength;
	int i;
	long long gcount = 0;
	for (wthread->wordlength=1; wthread->wordlength <= maxwordlength; wthread->wordlength++) {
		printf("Brute force attack - Thread %d - Starting with %d characters passwords\n",wthread->id+1,wthread->wordlength);
		for (i=wthread->id; i<wthread->baselength; i+=wthread->num_threads) {
			wthread->word[0] = wthread->base[i];
			if (wthread->wordlength>1)
				generate(wthread, 1, &pkcs12, &gcount);
			else
				try(wthread,&pkcs12,&gcount);
		}
	}
}

void generate(workerbrute *wthread, int pivot, gnutls_pkcs12_t *p12, long long *gcount) {
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

void try(workerbrute *wthread, gnutls_pkcs12_t *p12, long long *gcount) {
	int result;

	if (wthread->msginterval) {
		(*gcount)++;
		if ((*gcount) % wthread->msginterval == 0) {
			printf("Brute force attack - Thread %d - Attemp %lld (%s)\n",wthread->id+1,(*gcount),wthread->word);
		}
	}
	result = gnutls_pkcs12_verify_mac (*p12, wthread->word);
	if (result == 0) {
		printf("**********************************************************\n");
		printf("Brute force attack - Thread %d - Password found: %s\n",wthread->id+1,wthread->word);
		printf("**********************************************************\n\n");
		exit(0);
	}
}

/* Code from GNUTLS

Read a STREAM and return a newly allocated string with the content,
and set *LENGTH to the length of the string.	The string is
zero-terminated, but the terminating zero byte is not counted in
*LENGTH. On errors, *LENGTH is undefined, errno preserves the
values set by system functions (if any), and NULL is returned.
*/
char *fread_file (FILE * stream, size_t * length) {
	char *buf = NULL;
	size_t alloc = 0;
	size_t size = 0;
	int save_errno;

	for (;;) {
		size_t count;
		size_t requested;

		if (size + BUFSIZ + 1 > alloc) {
			char *new_buf;

			alloc += alloc / 2;
			if (alloc < size + BUFSIZ + 1)
				alloc = size + BUFSIZ + 1;

			new_buf = realloc (buf, alloc);
			
			if (!new_buf) {
				save_errno = errno;
				break;
			}

			buf = new_buf;
		}

		requested = alloc - size - 1;
		count = fread (buf + size, 1, requested, stream);
		size += count;

		if (count != requested) {
			save_errno = errno;
			if (ferror (stream))
				break;
			buf[size] = '\0';
			*length = size;
			return buf;
		}
	}

	free (buf);
	errno = save_errno;
	return NULL;
}
