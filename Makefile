init:
	gcc -o gen_rand.o gen_rand.c -lcrypto
	sudo chown root gen_rand.o
	sudo chgrp root gen_rand.o 
	sudo chmod u+s gen_rand.o
	gcc -o fsign.o fsign.c -lcrypto
	sudo chown root fsign.o
	sudo chgrp root fsign.o 
	sudo chmod u+s fsign.o

clean:
	sudo rm *.o