#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>

#include "mars.h"

#define DEBUG 0

int print_menu() {
	char input[10];
	puts("Options:");
	puts("0. New Sector");
	puts("1. Update Sector Data");
	puts("2. Read Sector Data");
	puts("3. Save Sector");
	puts("4. Load Sector");
	puts("5. Exit");
	fputs("> ", stdout);
	
	if (!fgets(input, sizeof(input), stdin)) {
		putchar('\n');
		exit(0);
	}

	char *end;
	int option = strtol(input, &end, 10);

	if (*end != '\n' && *end != '\0')
		return -1;
	
	return option;
}

void gen_random_filename(char *buff, int length) {
	FILE *f = fopen("/dev/urandom", "r");
	if(!f) {
		perror("Failed to open /dev/urandom");
		exit(EXIT_FAILURE);
	}
	int i = 0;
	while(i < length) {
		int num = fgetc(f);
		if (num == EOF) {
			perror("Failed to read from /dev/urandom");
			exit(EXIT_FAILURE);
		}
		i += snprintf(&buff[i], length - i, "%x", num);
	}
}

bool check_filename(char *name) {
	char *cur = name;
	while (*cur) {
		if ((*cur < 'a' || *cur > 'f') && (*cur < '0' || *cur > '9'))
			return false;
		++cur;
	}

	return true;
}

int main() {
	char *buffer = NULL;
	long long size = 0;

	puts(mars);
	
	puts(   "           ______           __                               __                \n"
			"          / ____/___ ______/ /_____  ____ __________ _____  / /_  __  __        \n"
			"         / /   / __ `/ ___/ __/ __ \\/ __ `/ ___/ __ `/ __ \\/ __ \\/ / / /        \n"
			"        / /___/ /_/ / /  / /_/ /_/ / /_/ / /  / /_/ / /_/ / / / / /_/ /         \n"
			"        \\____/\\__,_/_/   \\__/\\____/\\__, /_/   \\__,_/ .___/_/ /_/\\__, /          \n"
			"                                  /____/          /_/          /____/           \n");
	
	while(!feof(stdin)) {
		switch(print_menu()) {
		case 0:
		{
			char in[32];
			puts("Enter the sector's size:");
			if (!fgets(in, sizeof(in), stdin)) {
				exit(EXIT_FAILURE);
			}
			char *end;
			long long sz = strtoll(in, &end, 10);
			if ((*end != '\n' && *end != '\0') || sz < 0) {
				printf("Invalid size for sector: %s\n", in);
			} else {
				free(buffer);
				size = sz;
				buffer = calloc(1, size);
				#if DEBUG
				printf("buffer: %p, size: %llu\n", buffer, size);
				#endif
				// Provide some room for patching
				__asm__("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
				puts("Sector created!");
			}
			break;
		}
		case 1:
		{
			char in[32];
			puts("Where do you want to write?");
			if (!fgets(in, sizeof(in), stdin)) {
				exit(EXIT_FAILURE);
			}
			int pos = atoi(in);
			puts("How much do you want to write?");
			if (!fgets(in, sizeof(in), stdin)) {
				exit(EXIT_FAILURE);
			}
			int length = atoi(in);

			if(pos >= 0 && length >= 0 && pos + length <= size) {
				puts("Enter your sensor data:");
				if (fread(&buffer[pos], 1, length, stdin) != (size_t) length) {
					exit(EXIT_FAILURE);
				}
				fgetc(stdin); // Ignore newline
			} else {
				puts("Invalid range");
			}
			break;
		}
		case 2:
		{
			char in[32];
			puts("Where do you want to read?");
			if (!fgets(in, sizeof(in), stdin)) {
				exit(EXIT_FAILURE);
			}
			int pos = atoi(in);
			puts("How much do you want to read?");
			if (!fgets(in, sizeof(in), stdin)) {
				exit(EXIT_FAILURE);
			}
			int length = atoi(in);

			if(pos >= 0 && length >= 0 && pos + length <= size) {
				fwrite(&buffer[pos], length, 1, stdout);
				putchar('\n');
			} else {
				puts("Invalid range");
			}
			break;
		}
		case 3:
		{
			char filename[38] = "data/";
			gen_random_filename(&filename[5], sizeof(filename) - 5);
			FILE *f = fopen(filename, "w");
			if(f) {
				fwrite(&size, 1, sizeof(size), f);
				fwrite(buffer, size, 1, f);
				fclose(f);
				printf("Saved sector as '%s'\n", &filename[5]);
			} else {
				perror("Failed to save sector");
			}
			break;
		}
		case 4:
		{
			char filename[100] = "data/";
			puts("Enter sector name:");
			if (!fgets(&filename[5], sizeof(filename) - 5, stdin)) {
				exit(EXIT_FAILURE);
			}

			size_t len = strlen(filename);
			if (filename[len - 1] == '\n')
				filename[len - 1] = '\0';

			if (!check_filename(&filename[5])) {
				puts("Invalid sector name!");
				continue;
			}

			FILE *f = fopen(filename, "r");
			if(f != NULL) {
				free(buffer);
				if (fread(&size, sizeof(size), 1, f) != 1) {
					exit(EXIT_FAILURE);
				}
				buffer = malloc(size);
				if (fread(buffer, 1, size, f) != (size_t) size) {
					exit(EXIT_FAILURE);
				}
				puts("Sector loaded");
			} else {
				perror("Couldn't open sector");
			}
			break;
		}
		case 5:
			puts("Goodbye");
			return 0;
		default:
			puts("Invalid option");
		}
	}
	return 0;
}
