using System;
using NUnit.Framework;

namespace EvilTwinLib
{
	[TestFixture()]
	public class TestEvilTwinModule
	{
		[Test()]
		public void TestCase()
		{
			var start = DateTime.Now;

			var buf = EvilTwinModule.CreateBufferArray();
			UInt64 a, b;
			var rnd = new Random();
			int n = 1 << 10;
			for (int i = 0; i < n; i++)
			{
				int msg = rnd.Next(256);
				EvilTwinModule.Encrypt(rnd, buf, (byte)msg, out a, out b);

				Assert.True(EvilTwinModule.Validate(a, b));

				var answer = EvilTwinModule.Decrypt(a, b);
			
				Assert.True(answer == msg);
			}

			var end = DateTime.Now;
			Console.WriteLine((end.Subtract(start)).TotalSeconds);
		}
	}
}

