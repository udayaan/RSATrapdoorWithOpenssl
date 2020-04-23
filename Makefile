init:
	gcc -o gen_rand.o gen_rand.c -lcrypto
	sudo chown root gen_rand.o
	sudo chgrp root gen_rand.o 
	sudo chmod u+s gen_rand.o
	gcc -o fsign.o fsign.c -lcrypto
	sudo chown root fsign.o
	sudo chgrp root fsign.o 
	sudo chmod u+s fsign.o
	gcc -o fput_encrypt_rsa.o fput_encrypt_rsa.c -lcrypto
	sudo chown root fput_encrypt_rsa.o
	sudo chgrp root fput_encrypt_rsa.o 
	sudo chmod u+s fput_encrypt_rsa.o
	gcc -o fverify.o fverify.c -lcrypto
	sudo chown root fverify.o
	sudo chgrp root fverify.o 
	sudo chmod u+s fverify.o
	gcc -o fget_decrypt_rsa.o fget_decrypt_rsa.c -lcrypto
	sudo chown root fget_decrypt_rsa.o
	sudo chgrp root fget_decrypt_rsa.o 
	sudo chmod u+s fget_decrypt_rsa.o

comp:
	sudo gcc -o do_exec.o do_exec.c
	sudo chown root do_exec.o
	sudo chgrp root do_exec.o
	sudo chmod u+s do_exec.o
	sudo gcc -o setacl.o setacl.c
	sudo chown root setacl.o
	sudo chgrp root setacl.o
	sudo chmod u+s setacl.o
	sudo gcc -o getacl.o getacl.c
	sudo chown root getacl.o
	sudo chgrp root getacl.o
	sudo chmod u+s getacl.o
	sudo gcc -o ls.o ls.c
	sudo chown root ls.o
	sudo chgrp root ls.o
	sudo chmod u+s ls.o
	sudo gcc -o create_dir.o create_dir.c
	sudo chown root create_dir.o
	sudo chgrp root create_dir.o
	sudo chmod u+s create_dir.o

simple_slash:
	sudo mkdir /simple_slash
	sudo mkdir /simple_slash/home
	sudo chown root /simple_slash
	sudo chown root /simple_slash/home
	sudo groupadd simple_slash
	sudo chgrp simple_slash /simple_slash
	sudo chgrp simple_slash /simple_slash/home

addusers:
	sudo useradd -m -d /simple_slash/home/larry larry
	sudo cat passwords | sudo passwd larry
	sudo useradd -m -d /simple_slash/home/nirav nirav
	sudo cat passwords | sudo passwd nirav
	sudo useradd -m -d /simple_slash/home/sarah sarah
	sudo cat passwords | sudo passwd sarah
	sudo useradd -m -d /simple_slash/home/bill bill
	sudo cat passwords | sudo passwd bill
	sudo useradd -m -d /simple_slash/home/steve steve
	sudo cat passwords | sudo passwd steve
	sudo useradd -m -d /simple_slash/home/mukesh mukesh
	sudo cat passwords | sudo passwd mukesh
	sudo useradd -m -d /simple_slash/home/azim azim
	sudo cat passwords | sudo passwd azim
	sudo useradd -m -d /simple_slash/home/mark mark
	sudo cat passwords | sudo passwd mark
	sudo useradd -m -d /simple_slash/home/fakeroot fakeroot
	sudo cat passwords | sudo passwd fakeroot

delusers:
	sudo userdel larry
	sudo userdel nirav
	sudo userdel sarah
	sudo userdel bill
	sudo userdel steve
	sudo userdel mukesh
	sudo userdel azim
	sudo userdel mark
	sudo userdel fakeroot

uninstall:
	sudo groupdel simple_slash
	sudo rm -r /simple_slash
	
clean:
	sudo rm *.o