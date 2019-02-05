#include <iostream>
#include <vector>
#include <iterator>
#include <algorithm>

using namespace std;

std::vector<int> Primes;

template <int toTest, int factor> // factor should be odd
class IsPrime
{
   public:
      enum {
         result = ( toTest == 2 )
         ||  toTest % factor
          && IsPrime < toTest , factor - 2 >::result
      };
};

template<int toTest>
class IsPrime<toTest, 1>
{
   public:
      enum {result = ( toTest == 2 )  || ( toTest & 1 ) };
};

template <int upperBound> // upperBound should be odd or 2
class PrimePick : public PrimePick < upperBound - 2 >
{
   public:
      enum {
         isPrime = IsPrime < upperBound, ( upperBound >> 1 ) | 1 >::result
      };
      PrimePick<upperBound>() {
         if ( isPrime )
            Primes.push_back ( upperBound );
      }
};

template<>
class PrimePick<2>
{
   public:
      PrimePick<2>() {
         Primes.push_back ( 2 );
      }
};

template<>
class PrimePick<1> : public PrimePick<2> {};

template <int upperBound> // upperBound should be odd or 2
class Primxx : public Primxx < upperBound - 2 >
{
   public:
      enum {
         isPrime = IsPrime < upperBound, ( upperBound >> 1 ) | 1 >::result
      };
      Primxx<upperBound>() {
         if ( isPrime )
            Primes.push_back ( upperBound );
      }
};

template<>
class Primxx<2>
{
   public:
      Primxx<2>() {
         Primes.push_back ( 2 );
      }
};

template<>
class Primxx<1> : public Primxx<2> {};

template <int upperBound> // upperBound should be odd or 2
class Primxa : public Primxa < upperBound - 2 >
{
   public:
      enum {
         isPrime = IsPrime < upperBound, ( upperBound >> 1 ) | 1 >::result
      };
      Primxa<upperBound>() {
         if ( isPrime )
            Primes.push_back ( upperBound );
      }
};

template<>
class Primxa<2>
{
   public:
      Primxa<2>() {
         Primes.push_back ( 2 );
      }
};

template<>
class Primxa<1> : public Primxa<2> {};

template <int upperBound> // upperBound should be odd or 2
class Primxb : public Primxb < upperBound - 2 >
{
   public:
      enum {
         isPrime = IsPrime < upperBound, ( upperBound >> 1 ) | 1 >::result
      };
      Primxb<upperBound>() {
         if ( isPrime )
            Primes.push_back ( upperBound );
      }
};

template<>
class Primxb<2>
{
   public:
      Primxb<2>() {
         Primes.push_back ( 2 );
      }
};

template<>
class Primxb<1> : public Primxb<2> {};

int main()
{
   PrimePick<1601> PrimeInitializer;
   Primxx<1601> test1;
   Primxa<1601> test2;
   Primxb<1601> test3;
   int a, b;
   cin >> a >> b;
   cout << a + b;
   return 0;
}