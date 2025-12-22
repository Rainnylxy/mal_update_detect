# stolen from https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/blob/main/Dockerfile
# run with sudo :P
# https://www.youtube.com/watch?v=9nRr3R9gEb8&t=225s
wget https://www.sudo.ws/dist/sudo-1.9.16p2.tar.gz
tar xzf sudo-1.9.16p2.tar.gz
cd sudo-1.9.16p2
./configure --disable-gcrypt --prefix=/usr && make && make install
