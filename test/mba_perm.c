// Independent exhaustive proof of the permuteWrap identity (Subst.cpp): decode(encode(v)) == v for
// every v and every shift s at w=8 and w=16. Compiled and run as a normal program (no plugin).
#include <stdio.h>
#include <stdint.h>
static uint8_t  e8 (uint8_t  v, unsigned s){ return (uint8_t)(v ^ (uint8_t)(v<<s)); }
static uint8_t  d8 (uint8_t  e, unsigned s){ uint8_t  x=e; for(unsigned k=s;k<8; k*=2) x^=(uint8_t )(x<<k); return x; }
static uint16_t e16(uint16_t v, unsigned s){ return (uint16_t)(v ^ (uint16_t)(v<<s)); }
static uint16_t d16(uint16_t e, unsigned s){ uint16_t x=e; for(unsigned k=s;k<16;k*=2) x^=(uint16_t)(x<<k); return x; }
int main(void){
  for(unsigned s=1;s<8; s++) for(unsigned v=0;v<256u;  v++) if(d8 (e8 ((uint8_t )v,s),s)!=(uint8_t )v){printf("FAIL8 s=%u v=%u\n", s,v);return 1;}
  for(unsigned s=1;s<16;s++) for(unsigned v=0;v<65536u;v++) if(d16(e16((uint16_t)v,s),s)!=(uint16_t)v){printf("FAIL16 s=%u v=%u\n",s,v);return 1;}
  printf("mba_perm ok\n"); return 0;
}
