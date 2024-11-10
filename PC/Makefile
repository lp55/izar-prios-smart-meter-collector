all: cracker

cracker: prios_key_cracker.c ../ST-STEVAL-FKI868V1/Src/PRIOS.c
	gcc -O3 -fopenmp -c -Wall -Werror -std=c99 -pedantic prios_key_cracker.c -I ../ST-STEVAL-FKI868V1/Inc
	gcc -O3 -fopenmp -c -Wall -Werror -std=c99 -pedantic ../ST-STEVAL-FKI868V1/Src/PRIOS.c -I ../ST-STEVAL-FKI868V1/Inc
	gcc -O3 -fopenmp -o prios_key_cracker prios_key_cracker.o PRIOS.o -lm
