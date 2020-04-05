#include <stdio.h>
#include <stdint.h>

void decrypt () {
	uint32_t v0=0x17c59b4a, v1=0xf8c4497, sum=0xC6EF3720, i;
	uint32_t delta=0x9e3779b9;
	uint32_t k0=0x6c645a37, k1=0x6e775667, k2=0x57433641, k3=0x4e6c7151;
	for (i=0; i<32; i++) {
		v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
		v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
		sum -= delta;
	}
	printf(" Decrypted v0  : 0x%x",v0);
	printf("\n Decrypted v1  : 0x%x\n",v1);
}

int main(void) {
	int a;
	uint32_t v0=0x31c05068, v1=0x2f2f7368, sum=0, i;
	uint32_t delta=0x9e3779b9;
	uint32_t k0=0x6c645a37, k1=0x6e775667, k2=0x57433641, k3=0x4e6c7151;   /* key */
	printf("\n Original v0   : 0x%x",v0);
	printf("\n Original v1   : 0x%x",v1);
	for (i=0; i < 32; i++) {
		sum += delta;
		v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
		v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
	}
	printf("\n-----------------------\n");
	printf(" Encrypted v0  : 0x%x",v0);
	printf("\n Encrypted v1  : 0x%x",v1);
	printf("\n-----------------------\n");
	decrypt();
}