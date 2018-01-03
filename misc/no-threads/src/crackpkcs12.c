/* This program is free software: you can redistribute it and/or modify
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
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>

#define DEFAULTMSGINTERVAL 10000;
#define MINARGNUMBER 4

void usage() {
	printf(
"\nUsage: crackpkcs12 -d <dictionary_file> [ -v ] [ -s <message_interval> ] <file_to_crack>\n"
"\n"
"  -d <dictionary_file>     Specify dictionary file path\n"
"  -v                       Verbose mode\n"
"  -s <message_inteval>     Number of attemps between messages (implied -v)\n\n"
	);
	exit(100);
}

int main(int argc, char** argv) {

	if (argc < MINARGNUMBER) usage();

	char *psw, *infile, *dict, *nt, *msgintstring, c, verbose;
	int msginterval = DEFAULTMSGINTERVAL;    
	verbose = 0;
	msgintstring = NULL;
	dict = NULL;
	infile = NULL;

	while ((c = getopt (argc, argv, "d:vs:")) != -1)
		switch (c) {
			case 'd':
				dict = optarg;
				break;
			case 'v':
				verbose = 1;
				break;
			case 's':
				verbose = 1;
				msgintstring = optarg;
				break;
			case '?':
				if (optopt == 'd' || optopt == 's') {
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				}
			default:
				usage();
		}

	if (optind != argc-1)
		usage();
	else
		infile = argv[optind];

	if (dict == NULL) {
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

    // Opening p12 file   
    BIO* in = NULL;
    in = BIO_new_file(infile, "rb");
    if (!in) {
        perror("P12 file not found\n");
        exit(10);
    }

    // Creating PKCS12 object
    PKCS12 *p12 = NULL;
    if (!(p12 = d2i_PKCS12_bio (in, NULL))) {
        perror("p12 not created\n");
        exit(30);       
    }

    // Opening dictionary file
    FILE *file = fopen(dict,"r");
    if (!file) {
        perror("Dictionary file not found\n");
        exit(20);
    }

	OpenSSL_add_all_algorithms();

    char line[256];
    char found = 0;
    int count = 0;
    while (fgets ( line, sizeof line, file ) != NULL) {
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';       
		if (strlen(line) > 0 && line[strlen(line) - 1] == '\r')
			line[strlen(line) - 1] = '\0';
		if (verbose == 1) {        
			count++;
		    if (count % msginterval==0)
				printf("Attemp %d (%s)\n",count,line);
		}
        if (PKCS12_verify_mac(p12, line, -1)) {
            found = 1;           
            break;
        }
    }


	if (found) {
		if (verbose == 1) printf("\n********************************************\n");        
		printf("Password found: %s\n",line);
		if (verbose == 1) printf("********************************************\n\n");       
	}
	else {
		if (verbose == 1) printf("\n********************************************\n");        
		printf("No password found\n");
		if (verbose == 1) printf("********************************************\n\n");       
	}
}
