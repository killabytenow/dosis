#include<stdio.h>

main()
{
  unsigned long long i, n, p, m;

  i = 0;
  m = 0x0000FFFF;
  p = 0x0000FFFF + 1;
  //p = 2147483647;          /* marciano / mersenne */
  //p = 2305843009213693951; /* funciona de potra */
  p = 805315183;           /* guay */

  n = 0;
  
  //printf("m = %d\n", m);
  //printf("p = %d\n", p);
  //for(n = 0x2FFFFFFF; n < 0x4FFFFFFF; n++) printf("n = %d\n", n);
  //getchar();

  for(i = 0; i < m; i++)
  {
    printf("%d\n", n);
    n = (n + p) % m;
  }
}
