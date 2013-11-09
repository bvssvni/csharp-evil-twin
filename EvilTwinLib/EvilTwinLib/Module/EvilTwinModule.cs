using System;
using System.Collections.Generic;

namespace EvilTwinLib
{
	/// <summary>
	/// Evil twin module.
	/// 
	/// This algorithm is using prime numbers to encode information into two parts.
	/// Each of the parts takes 64 bits.
	/// The parts must be combined to get the message.
	/// 
	/// The algorithm can be easier understood by example:
	/// 
	/// 	A: 2*3*5, B: 3*5*7
	/// 	The intersection of the factors are 3*5.
	/// 	This is the hidden message.
	/// 	The factor 2 and 7 are multiplied independently.
	/// 
	/// In our algorithm, we use 8 out of 15 primes for the message, picked randomly.
	/// A prime used in the message counts as a 0 and if it is not used it counts as 1.
	/// This leaves us a set of 7 fake primes which we split into two sets of size 3 and 4.
	/// Those two sets are complementary, but the primes used for the message are the same.
	/// When receiving the two parts, one does intersection of the primes to get the message.
	/// 
	/// If one only receives one part, one has to check for either 455 or 1365 combinations per byte.
	/// This depends on whether one get the 3 or 4 complementing sets of fake primes.
	/// 
	/// The algorithm uses primes to force attacks to run in predictable slow time.
	/// If the algorithm used direct bit insertions, it would be faster to crack.
	/// This happens at the cost of memory, where 1 byte require a total of 2*8 bytes to be sent.
	/// 
	/// </summary>
	public static class EvilTwinModule
	{
		private static UInt64[] s_primes = new UInt64[] {
			2,3,5,7,11,13,17,19,23,29,31,37,41,43,47
		};
		private const int PRIME_LENGTH = 15;

		public static UInt64[] CreateBufferArray()
		{
			return new UInt64[PRIME_LENGTH];
		}

		/// <summary>
		/// Generates a random mask of primes.
		/// </summary>
		public static void PrepareArray(Random rnd, UInt64[] array)
		{
			int mask = 0;
			int remainingPrimes = PRIME_LENGTH;
			// Pick 7 primes to use as fake primes.
			while (remainingPrimes > 8)
			{
				// Pick a random index of prime.
				int index = rnd.Next(remainingPrimes);
				remainingPrimes--;

				// Get one index that is not already picked.
				while (((mask >> (index % PRIME_LENGTH)) & 1) == 1) {index++;}

				// Add the index to the mask.
				mask |= 1 << index;

				// Write fake primes to end of buffer array.
				// These are shuffled.
				array[remainingPrimes] = s_primes[index];
			}

			// Write primes used for encoding message to start of buffer array.
			// These primes are stored in order.
			for (int i = 0; i < PRIME_LENGTH; i++)
			{
				if (((mask >> i) & 1) == 0)
				{
					array[8 - remainingPrimes] = s_primes[i];
					remainingPrimes--;
				}
			}
		}

		/// <summary>
		/// Encrypts message into two 64 bits sequences that needs to be combined in order to read message.
		/// </summary>
		public static void Encrypt(Random rnd, UInt64[] array, byte message, out UInt64 a, out UInt64 b)
		{
			PrepareArray(rnd, array);
			// Encode the message as product of primes.
			UInt64 result = 1;
			for (int i = 0; i < 8; i++)
			{
				if (((message >> i) & 1) == 1)
				{
					result *= array[i];
				}
			}

			// Insert fake complementary primes into each parts.
			a = result * array[8] * array[9] * array[10];
			b = result * array[11] * array[12] * array[13] * array[14];
			// Swap the messages by 50% chance.
			// This makes it harder to know which fake combination to check for.
			if (rnd.Next(2) == 0)
			{
				result = a;
				a = b;
				b = result;
			}
		}

		/// <summary>
		/// Decrypts message by using two sources.
		/// </summary>
		public static byte Decrypt(UInt64 a, UInt64 b)
		{
			int mask = 0;
			int k = 0;
			bool isA, isB;
			for (int i = 0; i < PRIME_LENGTH; i++)
			{
				isA = a % s_primes[i] == 0;
				isB = b % s_primes[i] == 0;
				if (isA && isB)
				{
					mask |= 1 << k;
					k++;
				}
				else if (!isA && !isB)
				{
					k++;
				}
			}

			return (byte)mask;
		}
	}
}

