<?php
	/* 
	 * Fast, portable, and easy-to-use Twofish implementation,  
	 * Version 0.3. 
	 * Copyright (c) 2002 by Niels Ferguson.  
	 * (See further down for the almost-unrestricted licensing terms.) 
	 * 
	 * -------------------------------------------------------------------------- 
	 * To use this library you should: 
	 * - Call new Twofish() in your program. 
	 * - Use PrepareKey(...) to convert a key to internal form. 
	 * - Use Encrypt(...) and Decrypt(...) to encrypt and decrypt 
	 *   data. 
	 * - Alternatively you can use CFB128Encrypt(...) and CFB128Decrypt(...)
	 *   to encrypt and decrypt data of variable length.
	 * See the comments down in the class for details on these functions. 
	 * -------------------------------------------------------------------------- 
	 *  
	 * There are many Twofish implementation available for free on the web. 
	 * Most of them are hard to integrate into your own program. 
	 * As we like people to use our cipher, I thought I would make it easier.  
	 * Here is a free and easy-to-integrate Twofish implementation in PHP. 
	 * 
	 * This implementation is designed for use on PC-class machines. It uses the  
	 * Twofish 'full' keying option which uses large tables. Total table size is  
	 * around 5-6 kB for static tables plus 4.5 kB for each pre-processed key. 
	 * If you need an implementation that uses less memory, 
	 * take a look at Brian Gladman's code on his web site: 
	 *     http://fp.gladman.plus.com/cryptography_technology/aes/ 
	 * He has code for all AES candidates. 
	 * His Twofish code has lots of options trading off table size vs. speed. 
	 * You can also take a look at the optimised code by Doug Whiting on the 
	 * Twofish web site 
	 *      http://www.counterpane.com/twofish.html 
	 * which has loads of options. 
	 * I believe these existing implementations are harder to re-use because they 
	 * are not clean libraries and they impose requirements on the environment.  
	 * This implementation is very careful to minimise those,  
	 * and should be easier to integrate into any larger program. 
	 * 
	 * The initialisation routine of this implementation contains a self-test. 
	 * If initialisation succeeds without calling the fatal routine, then 
	 * the implementation works. I don't think you can break the implementation 
	 * in such a way that it still passes the tests, unless you are malicious. 
	 * In other words: if the initialisation routine returns,  
	 * you have successfully ported the implementation.  
	 * (Or not implemented the fatal routine properly, but that is your problem.) 
	 * 
	 * Now for the license: 
	 * The author hereby grants a perpetual license to everybody to 
	 * use this code for any purpose as long as the copyright message is included 
	 * in the source code of this or any derived work. 
	 *  
	 * Yes, this means that you, your company, your club, and anyone else 
	 * can use this code anywhere you want. You can change it and distribute it 
	 * under the GPL, include it in your commercial product without releasing 
	 * the source code, put it on the web, etc.  
	 * The only thing you cannot do is remove my copyright message,  
	 * or distribute any source code based on this implementation that does not  
	 * include my copyright message.  
	 *  
	 * I appreciate a mention in the documentation or credits,  
	 * but I understand if that is difficult to do. 
	 * I also appreciate it if you tell me where and why you used my code. 
	 * 
	 * Please send any questions or comments to niels@ferguson.net 
	 * 
	 * Have Fun! 
	 * 
	 * Niels 
	 */ 
	 
	/* 
	 * DISCLAIMER: As I'm giving away my work for free, I'm of course not going 
	 * to accept any liability of any form. This code, or the Twofish cipher, 
	 * might very well be flawed; you have been warned. 
	 * This software is provided as-is, without any kind of warrenty or 
	 * guarantee. And that is really all you can expect when you download  
	 * code for free from the Internet.  
	 * 
	 * I think it is really sad that disclaimers like this seem to be necessary. 
	 * If people only had a little bit more common sense, and didn't come 
	 * whining like little children every time something happens.... 
	 */ 
	  
	/* 
	 * Version history: 
	 * Version 0.0, 2002-08-30 
	 *      First written. 
	 * Version 0.1, 2002-09-03 
	 *      Added disclaimer. Improved self-tests. 
	 * Version 0.2, 2002-09-09 
	 *      Removed last non-portabilities. Default now works completely within 
	 *      the C standard. UInt32 can be larger than 32 bits without problems. 
	 * Version 0.3, 2002-09-28 
	 *      Bugfix: use  instead of  to adhere to ANSI/ISO. 
	 *      Rename BIG_ENDIAN macro to CPU_IS_BIG_ENDIAN. The gcc library  
	 *      header  already defines BIG_ENDIAN, even though it is not  
	 *      supposed to. 
	 */  	 
	 
	/**
	 * Structure that contains a prepared Twofish key.
	 *
	 * A cipher key is used in two stages. In the first stage it is converted 
	 * form the original form to an internal representation.  
	 * This internal form is then used to encrypt and decrypt data.  
	 * This structure contains the internal form. It is rather large: 4256 bytes 
	 * on a platform with 32-bit unsigned values. 
	 * 
	 * Treat this as an opague structure, and don't try to manipulate the 
	 * elements in it. I wish I could hide the inside of the structure, 
	 * but C doesn't allow that. 
	 */ 
	class Twofish_key
	{
        public $s = array(array(), array(), array(), array());  /* uint32[4][256], pre-computed S-boxes */ 
        public $K = array();   									/* uint32[40], Round key words */ 
	}
	
	class Twofish
	{
		const  SUCCESS         =   1;
		//const  ERR_UINT32      =  -2;
		//const  ERR_BYTE        =  -3;
		const  ERR_GET32       =  -4;
		const  ERR_PUT32       =  -5;
		const  ERR_ROLR        =  -6;
		const  ERR_BSWAP       =  -7;
		const  ERR_SELECTB     =  -8;
		const  ERR_TEST_ENC    =  -9;
		const  ERR_TEST_DEC    = -10;
		const  ERR_SEQ_ENC     = -11;
		const  ERR_SEQ_DEC     = -12;
		const  ERR_ODD_KEY     = -13;
		//const  ERR_INIT        = -14;
		const  ERR_KEY_LEN     = -15;
		const  ERR_ILL_ARG     = -16;
		
		function __construct() { $this->Initialise(); }
		
		/**
		 * Initialise and test the Twofish implementation.  
		 *  
		 * This function MUST be called before any other function in the  
		 * Twofish implementation is called. 
		 * It only needs to be called once. 
		 *  
		 * Apart from initialising the implementation it performs a self test. 
		 * If the Twofish_fatal function is not called, the code passed the test. 
		 * (See the twofish.c file for details on the Twofish_fatal function.)
		 *
		 * @returns a negative number if an error happend, +1 otherwise
		 */ 
		function Initialise()
		{
			/* First test the various platform-specific definitions. */ 
			if (($ret = $this->TestPlatform()) < 0)
				return $ret;
		 
			/* We can now generate our tables, in the right order of course. */ 
			$this->InitialiseQBoxes(); 
			$this->InitialiseMDSTables(); 
		 
			/*  
			 * And run some tests on the whole cipher.  
			 * Yes, you need to do this every time you start your program.  
			 * It is called assurance; you have to be certain that your program 
			 * still works properly.  
			 */ 
			return $this->SelfTest(); 
		}
				
		/**
		 * Convert a cipher key to the internal form used for  
		 * encryption and decryption. 
		 *  
		 * Any key must be converted to an internal form in the Twofisk_key structure 
		 * before it can be used. 
		 * The encryption and decryption functions only work with the internal form. 
		 * The conversion to internal form need only be done once for each key value. 
		 * 
		 * Be sure to wipe all key storage, including the Twofish_key structure,  
		 * once you are done with the key data.  
		 * A simple memset( TwofishKey, 0, sizeof( TwofishKey ) ) will do just fine. 
		 * 
		 * Unlike most implementations, this one allows any key size from 0 bytes  
		 * to 32 bytes. According to the Twofish specifications,  
		 * irregular key sizes are handled by padding the key with zeroes at the end  
		 * until the key size is 16, 24, or 32 bytes, whichever 
		 * comes first. Note that each key of irregular size is equivalent to exactly 
		 * one key of 16, 24, or 32 bytes. 
		 * 
		 * WARNING: Short keys have low entropy, and result in low security. 
		 * Anything less than 8 bytes is utterly insecure. For good security 
		 * use at least 16 bytes. I prefer to use 32-byte keys to prevent 
		 * any collision attacks on the key. 
		 * 
		 * @param key      String of key bytes 
		 * @param xkey     Pointer to an Twofish_key structure that will be filled  
		 *                 with the internal form of the cipher key.
		 * @returns a negative number if an error happend, +1 otherwise
		 */ 
		function PrepareKey($key, &$xkey)
		{
			$keyLen = strlen($key);
			
			/* We use a single array to store all key material in,  
			 * to simplify the wiping of the key material at the end. 
			 * The first 32 bytes contain the actual (padded) cipher key. 
			 * The next 32 bytes contain the S-vector in its weird format, 
			 * and we have 4 bytes of overrun necessary for the RS-reduction. 
			 */ 
			/* byte[32+32+4] */
			$Ksize = 32+32+4;
			//$K = array_fill(0, $Ksize, 0);
		 
			/* Check for valid key length. */ 
			if( $keyLen < 0 || $keyLen > 32 ) 
			{ 
				/*  
				 * This can only happen if a programmer didn't read the limitations 
				 * on the key size.  
				 */ 
				$this->Fatal( 'Twofish::PrepareKey: illegal key length', self::ERR_KEY_LEN); 
				/*  
				 * A return statement just in case the fatal macro returns. 
				 * The rest of the code assumes that keyLen is in range, and would 
				 * buffer-overflow if it wasn't.  
				 * 
				 * Why do we still use a programming language that has problems like 
				 * buffer overflows, when these problems were solved in 1960 with 
				 * the development of Algol? Have we not leared anything? 
				 */ 
				return self::ERR_KEY_LEN;
			}
		 
			/* Pad the key with zeroes to the next suitable key length. */ 
			$keychars = str_split($key);
			foreach ($keychars as $i => $c) $keychars[$i] = ord($c);
			$K = array_merge($keychars, array_fill($keyLen, $Ksize - $keyLen, 0));
		 
			/*  
			 * Compute kCycles: the number of key cycles used in the cipher.  
			 * 2 for 128-bit keys, 3 for 192-bit keys, and 4 for 256-bit keys. 
			 */ 
			$kCycles = ($keyLen + 7) >> 3; 
			/* Handle the special case of very short keys: minimum 2 cycles. */ 
			if( $kCycles < 2 ) 
			{ 
				$kCycles = 2; 
			} 
		 
			/*  
			 * From now on we just pretend to have 8*kCycles bytes of  
			 * key material in K. This handles all the key size cases.  
			 */ 
		 
			/*  
			 * We first compute the 40 expanded key words,  
			 * formulas straight from the Twofish specifications. 
			 */ 
			for( $i=0; $i<40; $i+=2 ) 
			{ 
				/*  
				 * Due to the byte spacing expected by the h() function  
				 * we can pick the bytes directly from the key K. 
				 * As we use bytes, we never have the little/big endian 
				 * problem. 
				 * 
				 * Note that we apply the rotation function only to simple 
				 * variables, as the rotation macro might evaluate its argument 
				 * more than once. 
				 */ 
				$A = $this->h( $i  , $K, 0, $kCycles );
				$B = $this->h( $i+1, $K, 4, $kCycles );
				$B = $this->ROL32( $B, 8 ); 
		 
				/* Compute and store the round keys. */ 
				$A += $B; $A &= 0xffffffff;
				$B += $A; $B &= 0xffffffff;
				$xkey->K[$i]   = $A; 
				$xkey->K[$i+1] = $this->ROL32( $B, 9 ); 
			}
		 
			/* Wipe variables that contained key material. */ 
			$A=$B=0; 
		 
			/*  
			 * And now the dreaded RS multiplication that few seem to understand. 
			 * The RS matrix is not random, and is specially designed to compute the 
			 * RS matrix multiplication in a simple way. 
			 * 
			 * We work in the field GF(2)[x]/x^8+x^6+x^3+x^2+1. Note that this is a 
			 * different field than used for the MDS matrix.  
			 * (At least, it is a different representation because all GF(2^8)  
			 * representations are equivalent in some form.) 
			 *  
			 * We take 8 consecutive bytes of the key and interpret them as  
			 * a polynomial k_0 + k_1 y + k_2 y^2 + ... + k_7 y^7 where  
			 * the k_i bytes are the key bytes and are elements of the finite field. 
			 * We multiply this polynomial by y^4 and reduce it modulo 
			 *     y^4 + (x + 1/x)y^3 + (x)y^2 + (x + 1/x)y + 1.  
			 * using straightforward polynomial modulo reduction. 
			 * The coefficients of the result are the result of the RS 
			 * matrix multiplication. When we wrote the Twofish specification,  
			 * the original RS definition used the polynomials,  
			 * but that requires much more mathematical knowledge.  
			 * We were already using matrix multiplication in a finite field for  
			 * the MDS matrix, so I re-wrote the RS operation as a matrix  
			 * multiplication to reduce the difficulty of understanding it.  
			 * Some implementors have not picked up on this simpler method of 
			 * computing the RS operation, even though it is mentioned in the 
			 * specifications. 
			 * 
			 * It is possible to perform these computations faster by using 32-bit  
			 * word operations, but that is not portable and this is not a speed- 
			 * critical area. 
			 * 
			 * We explained the 1/x computation when we did the MDS matrix.  
			 * 
			 * The S vector is stored in K[32..64]. 
			 * The S vector has to be reversed, so we loop cross-wise. 
			 * 
			 * Note the weird byte spacing of the S-vector, to match the even  
			 * or odd key words arrays. See the discussion at the Hxx macros for 
			 * details. 
			 */ 
			$kptr = 8*$kCycles;          /* Start at end of key */ 
			$sptr = 32;                  /* Start at start of S */ 
		 
			/* Loop over all key material */ 
			while( $kptr > 0 )  
			{ 
				$kptr -= 8; 
				/*  
				 * Initialise the polynimial in sptr[0..12] 
				 * The first four coefficients are 0 as we have to multiply by y^4. 
				 * The next 8 coefficients are from the key material. 
				 */ 
				//memset( sptr, 0, 4 ); 
				//memcpy( sptr+4, kptr, 8 ); 
				$K[$sptr] = 0; $K[$sptr+1] = 0; $K[$sptr+2] = 0; $K[$sptr+3] = 0;
				$K[$sptr+4] = $K[$kptr];   $K[$sptr+5] = $K[$kptr+1]; $K[$sptr+6]  = $K[$kptr+2]; $K[$sptr+7]  = $K[$kptr+3]; 
				$K[$sptr+8] = $K[$kptr+4]; $K[$sptr+9] = $K[$kptr+5]; $K[$sptr+10] = $K[$kptr+6]; $K[$sptr+11] = $K[$kptr+7];
				/*  
				 * The 12 bytes starting at sptr are now the coefficients of 
				 * the polynomial we need to reduce. 
				 */ 
		 
				/* Loop over the polynomial coefficients from high to low */ 
				$t = $sptr+11; 
				/* Keep looping until polynomial is degree 3; */ 
				while( $t > $sptr+3 ) 
				{
					/* Pick up the highest coefficient of the poly. */ 
					$b = $K[$t];
		 
					/*  
					 * Compute x and (x+1/x) times this coefficient.  
					 * See the MDS matrix implementation for a discussion of  
					 * multiplication by x and 1/x. We just use different  
					 * constants here as we are in a  
					 * different finite field representation. 
					 * 
					 * These two statements set  
					 * bx = (x) * b  
					 * bxx= (x + 1/x) * b 
					 */ 
					$bx = ($b<<1) ^ $this->rs_poly_const[ $b>>7 ]; 
					$bxx= ($b>>1) ^ $this->rs_poly_div_const[ $b&1 ] ^ $bx;
		 
					/* 
					 * Subtract suitable multiple of  
					 * y^4 + (x + 1/x)y^3 + (x)y^2 + (x + 1/x)y + 1  
					 * from the polynomial, except that we don't bother 
					 * updating t[0] as it will become zero anyway. 
					 */ 
					$K[$t-1] ^= $bxx;
					$K[$t-2] ^= $bx; 
					$K[$t-3] ^= $bxx; 
					$K[$t-4] ^= $b; 
					 
					/* Go to the next coefficient. */ 
					$t--; 
				} 
		 
				/* Go to next S-vector word, obeying the weird spacing rules. */ 
				$sptr += 8; 
			} 
		 
			/* Wipe variables that contained key material. */ 
			$b = $bx = $bxx = 0; 
		 
			/* And finally, we can compute the key-dependent S-boxes. */ 
			$this->FillKeyedSboxes( $K, 32, $kCycles, $xkey ); 
		 
			/* Wipe array that contained key material. */ 
			for ($i = 0; $i < $Ksize; ++$i) $K[$i] = 0;

			return self::SUCCESS;
		}
		
		/**
		 * Encrypt a single block of data. 
		 * 
		 * This function encrypts a single block of 16 bytes of data. 
		 * If you want to encrypt a larger or variable-length message,  
		 * you will have to use a cipher mode, such as CBC or CTR.  
		 * Look for CFB128Encrypt method below.
		 * 
		 * The xkey structure is not modified by this routine, and can be 
		 * used for further encryption and decryption operations. 
		 * 
		 * @param xkey     pointer to Twofish_key, internal form of the key 
		 *                 produces by Twofish_prepare_key() 
		 * @param p        Plaintext to be encrypted 
		 * @param c        Place to store the ciphertext 
		 */ 
		function Encrypt( $xkey, $p, &$c )
		{
			$A=$B=$C=$D=$T0=$T1=0;
			
			/* Get the four plaintext words xorred with the key */ 
			$this->GetInput( $p, $A,$B,$C,$D, $xkey, 0 ); 
		 
			/* Do 8 cycles (= 16 rounds) */ 
			$this->EncryptInternal( $A,$B,$C,$D,$T0,$T1,$xkey ); 
		 
			/* Store them with the final swap and the output whitening. */ 
			$this->PutOutput( $C,$D,$A,$B, $c, $xkey, 4 ); 
		}
		
		/**
		 * Decrypt a single block of data. 
		 * 
		 * This function decrypts a single block of 16 bytes of data. 
		 * If you want to decrypt a larger or variable-length message,  
		 * you will have to use a cipher mode, such as CBC or CTR.  
		 * Look for CFB128Decrypt method below.
		 * 
		 * The xkey structure is not modified by this routine, and can be 
		 * used for further encryption and decryption operations. 
		 * 
		 * @param xkey     pointer to Twofish_key, internal form of the key 
		 *                 produces by Twofish_prepare_key() 
		 * @param c        Ciphertext to be decrypted 
		 * @param p        Place to store the plaintext 
		 */ 
		function Decrypt( $xkey, $c, &$p )
		{
			$A=$B=$C=$D=$T0=$T1=0;
 
			/* Get the four plaintext words xorred with the key */ 
			$this->GetInput( $c, $A,$B,$C,$D, $xkey, 4 ); 
		 
			/* Do 8 cycles (= 16 rounds) */ 
			$this->DecryptInternal( $A,$B,$C,$D,$T0,$T1,$xkey ); 
		 
			/* Store them with the final swap and the output whitening. */ 
			$this->PutOutput( $C,$D,$A,$B, $p, $xkey, 0 ); 
		}
		
		/**
		 * Encrypt data in CFB mode. 
		 * 
		 * This function encrypts data in CFB mode.
		 *
		 * The key structure is not modified by this routine, and can be 
		 * used for further encryption and decryption operations. 
		 * 
		 * @param keyCtx   pointer to Twofish_key, internal form of the key 
		 *                 produced by Twofish_prepare_key() 
		 * @param in       Plaintext to be encrypted 
		 * @param out      Place to store the ciphertext 
		 * @param ivec     initialization vector for this CFB mode encryption.
		 * @param num      pointer to integer that holds number of available crypto bytes.
		 */
		function CFB128Encrypt($xkey, $in, &$out,  $ivec, &$num)
		{
			$len = strlen($in);
			$n = $num;
			
			$index = 0;
			do
			{
				while ($n > 0 && $len > 0)
				{
					$ivec[$n] = chr(ord($ivec[$n]) ^ ord($in[$index]));
					$out .= $ivec[$n];
					$index++;
					--$len;
					$n = ($n+1) % 16;
				}
				while ($len>=16)
				{
					$this->Encrypt($xkey, $ivec, $ivec);
					for ($n=0; $n<16; $n++)
					{
						$ivec[$n] = chr(ord($ivec[$n]) ^ ord($in[$index+$n]));
						$out .= $ivec[$n];
					}
					$len -= 16;
					$index += 16;
				}
				$n = 0;
				if ($len)
				{
					$this->Encrypt($xkey, $ivec, $ivec);
					while ($len--)
					{
						$ivec[$n] = chr(ord($ivec[$n]) ^ ord($in[$index+$n]));
						$out .= $ivec[$n];
						++$n;
					}
				}
				$num = $n;
				return;
			} while (0);
		}
		
		/**
		 * Decrypt data in CFB mode. 
		 * 
		 * This function decrypts data in CFB. 
		 *
		 * The key structure is not modified by this routine, and can be 
		 * used for further encryption and decryption operations. 
		 * 
		 * @param keyCtx   pointer to Twofish_key, internal form of the key 
		 *                 produced by Twofish_prepare_key() 
		 * @param in       Ciphertext to be decrypted 
		 * @param out      Place to store the plaintext 
		 * @param ivec     initialization vector for this CFB mode encryption.
		 * @param num      pointer to integer that holds number of available crypto bytes.
		 */ 
		function CFB128Decrypt($xkey, $in, &$out, $ivec, &$num)
		{
			$len = strlen($in);
			$n = $num;
			
			$index = 0;
			do
			{
				while ($n && $len)
				{
					$out .= $ivec[$n] ^ ($c = $in[$index]); $ivec[$n] = $c;
					$index++;
					--$len;
					$n = ($n+1) % 16;
				}
				while ($len>=16)
				{
					$this->Encrypt($xkey, $ivec, $ivec);
					for ($n=0; $n<16; $n++)
					{
						$t = $in[$index+$n];
						$out .= $ivec[$n] ^ $t;
						$ivec[$n] = $t;
					}
					$len -= 16;
					$index += 16;
				}
				$n = 0;
				if ($len)
				{
					$this->Encrypt($xkey, $ivec, $ivec);
					while ($len--)
					{
						$out .= $ivec[$n] ^ ($c = $in[$index+$n]); $ivec[$n] = $c;
						++$n;
					}
				}
				$num = $n;
				return;
			} while (0);
		}
		
		/* 
		 * The Twofish key schedule uses an Reed-Solomon code matrix multiply. 
		 * Just like the MDS matrix, the RS-matrix is designed to be easy 
		 * to implement. Details are below in the code.  
		 * 
		 * These constants make it easy to compute in the finite field used  
		 * for the RS code. 
		 * 
		 * We use Bytes for the RS computation, but these are automatically 
		 * widened to unsigned integers in the expressions. Having unsigned 
		 * ints in these tables therefore provides the fastest access. 
		 */ 
		protected $rs_poly_const = array(0, 0x14d);
		protected $rs_poly_div_const = array(0, 0xa6);


		/* 
		 * The h() function is the heart of the Twofish cipher.  
		 * It is a complicated sequence of q-box lookups, key material xors,  
		 * and finally the MDS matrix. 
		 * We use lots of macros to make this reasonably fast. 
		 */
		/* 
		 * Now we can define the h() function given an array of key bytes.  
		 * This function is only used in the key schedule, and not to pre-compute 
		 * the keyed S-boxes. 
		 * 
		 * In the key schedule, the input is always of the form k*(1+2^8+2^16+2^24) 
		 * so we only provide k as an argument. 
		 * 
		 * Arguments: 
		 * k        input to the h() function. 
		 * L        pointer to array of key bytes at  
		 *          offsets 0,1,2,3, ... 8,9,10,11, [16,17,18,19, [24,25,26,27]] 
		 * kCycles  # key cycles, 2, 3, or 4. 
		 */ 
		protected function h($k, $L, $Lptr, $kCycles)
		{
			switch( $kCycles )
			{ 
			/* We code all 3 cases separately for speed reasons. */ 
			case 2: 
				return $this->H02($k,$L,$Lptr) ^ $this->H12($k,$L,$Lptr) ^ $this->H22($k,$L,$Lptr) ^ $this->H32($k,$L,$Lptr); 
			case 3: 
				return $this->H03($k,$L,$Lptr) ^ $this->H13($k,$L,$Lptr) ^ $this->H23($k,$L,$Lptr) ^ $this->H33($k,$L,$Lptr); 
			case 4: 
				return $this->H04($k,$L,$Lptr) ^ $this->H14($k,$L,$Lptr) ^ $this->H24($k,$L,$Lptr) ^ $this->H34($k,$L,$Lptr); 
			default:  
				/* This is always a coding error, which is fatal. */ 
				$this->Fatal( 'Twofish h(): Illegal argument', self::ERR_ILL_ARG );
			    return self::ERR_ILL_ARG;
			}
			return self::SUCCESS;
		}
		
		/* 
		 * Each macro computes one column of the h for either 2, 3, or 4 stages. 
		 * As there are 4 columns, we have 12 macros in all. 
		 *  
		 * The key bytes are stored in the Byte array L at offset  
		 * 0,1,2,3,  8,9,10,11,  [16,17,18,19,   [24,25,26,27]] as this is the 
		 * order we get the bytes from the user. If you look at the Twofish  
		 * specs, you'll see that h() is applied to the even key words or the 
		 * odd key words. The bytes of the even words appear in this spacing, 
		 * and those of the odd key words too. 
		 * 
		 * These macros are the only place where the q-boxes and the MDS table 
		 * are used. 
		 */ 
		protected function H02($y, $L, $Lptr)
		{
			return $this->MDS_table[0][$this->q_table[0][$this->q_table[0][$y]^$L[$Lptr+8]] ^$L[$Lptr+0]];
		}
		
		protected function H12($y, $L, $Lptr)
		{
			return $this->MDS_table[1][$this->q_table[0][$this->q_table[1][$y]^$L[$Lptr+9]] ^$L[$Lptr+1]];
		}

		protected function H22($y, $L, $Lptr)
		{
			return $this->MDS_table[2][$this->q_table[1][$this->q_table[0][$y]^$L[$Lptr+10]]^$L[$Lptr+2]];
		}

		protected function H32($y, $L, $Lptr)
		{
			return $this->MDS_table[3][$this->q_table[1][$this->q_table[1][$y]^$L[$Lptr+11]]^$L[$Lptr+3]];
		}

		protected function H03($y, $L, $Lptr)
		{
			return $this->H02($this->q_table[1][$y]^$L[$Lptr+16], $L, $Lptr);
		}
		
		protected function H13($y, $L, $Lptr)
		{
			return $this->H12($this->q_table[1][$y]^$L[$Lptr+17], $L, $Lptr);
		}

		protected function H23($y, $L, $Lptr)
		{
			return $this->H22($this->q_table[0][$y]^$L[$Lptr+18], $L, $Lptr);
		}
		
		protected function H33($y, $L, $Lptr)
		{
			return $this->H32($this->q_table[0][$y]^$L[$Lptr+19], $L, $Lptr);
		}

		protected function H04($y, $L, $Lptr)
		{
			return $this->H03($this->q_table[1][$y]^$L[$Lptr+24], $L, $Lptr);
		}
		
		protected function H14($y, $L, $Lptr)
		{
			return $this->H13($this->q_table[0][$y]^$L[$Lptr+25], $L, $Lptr);
		}

		protected function H24($y, $L, $Lptr)
		{
			return $this->H23($this->q_table[0][$y]^$L[$Lptr+26], $L, $Lptr);
		}
		
		protected function H34($y, $L, $Lptr)
		{
			return $this->H33($this->q_table[1][$y]^$L[$Lptr+27], $L, $Lptr);
		}		
		
		/* 
		 * Pre-compute the keyed S-boxes. 
		 * Fill the pre-computed S-box array in the expanded key structure. 
		 * Each pre-computed S-box maps 8 bits to 32 bits. 
		 * 
		 * The S argument contains half the number of bytes of the full key, but is 
		 * derived from the full key. (See Twofish specifications for details.) 
		 * S has the weird byte input order used by the Hxx macros. 
		 * 
		 * This function takes most of the time of a key expansion. 
		 * 
		 * Arguments: 
		 * S        pointer to array of 8*kCycles Bytes containing the S vector. 
		 * kCycles  number of key words, must be in the set {2,3,4} 
		 * xkey     pointer to Twofish_key structure that will contain the S-boxes. 
		 */ 
		protected function FillKeyedSboxes( $S, $Sptr, $kCycles, &$xkey )
		{
			switch( $kCycles ) { 
			/* We code all 3 cases separately for speed reasons. */ 
			case 2: 
				for( $i=0; $i<256; $i++ ) 
				{ 
					$xkey->s[0][$i]= $this->H02( $i, $S, $Sptr ); 
					$xkey->s[1][$i]= $this->H12( $i, $S, $Sptr ); 
					$xkey->s[2][$i]= $this->H22( $i, $S, $Sptr ); 
					$xkey->s[3][$i]= $this->H32( $i, $S, $Sptr ); 
				} 
				break; 
			case 3: 
				for( $i=0; $i<256; $i++ ) 
				{ 
					$xkey->s[0][$i]= $this->H03( $i, $S, $Sptr ); 
					$xkey->s[1][$i]= $this->H13( $i, $S, $Sptr ); 
					$xkey->s[2][$i]= $this->H23( $i, $S, $Sptr ); 
					$xkey->s[3][$i]= $this->H33( $i, $S, $Sptr ); 
				} 
				break; 
			case 4: 
				for( $i=0; $i<256; $i++ ) 
				{ 
					$xkey->s[0][$i]= $this->H04( $i, $S, $Sptr ); 
					$xkey->s[1][$i]= $this->H14( $i, $S, $Sptr ); 
					$xkey->s[2][$i]= $this->H24( $i, $S, $Sptr ); 
					$xkey->s[3][$i]= $this->H34( $i, $S, $Sptr ); 
				} 
				break; 
			default:  
				/* This is always a coding error, which is fatal. */ 
				$this->Fatal( 'Twofish::FillKeyedSboxes(): Illegal argument', self::ERR_ILL_ARG ); 
				return self::ERR_ILL_ARG;
			}
			return self::SUCCESS;
		}
		
		/* 
		 * A macro to read the state from the plaintext and do the initial key xors. 
		 * The koff argument allows us to use the same macro  
		 * for the decryption which uses different key words at the start. 
		 */ 
		protected function GetInput($src, &$A, &$B, &$C, &$D, $xkey, $koff)
		{
			$A = $this->Get32($src   )^$xkey->K[  $koff];
			$B = $this->Get32($src,4 )^$xkey->K[1+$koff];
			$C = $this->Get32($src,8 )^$xkey->K[2+$koff];
			$D = $this->Get32($src,12)^$xkey->K[3+$koff];
		}
		
		/* Full 16-round encryption */ 
		protected function EncryptInternal(&$A, &$B, &$C, &$D, &$T0, &$T1, $xkey)
		{
			for ($i=0; $i<8; ++$i)
				$this->EncryptCycle( $A,$B,$C,$D,$T0,$T1,$xkey, $i);
		}
		
		/* 
		 * Encrypt a single cycle, consisting of two rounds. 
		 * This avoids the swapping of the two halves.  
		 * Parameter r is now the cycle number. 
		 */
		protected function EncryptCycle(&$A, &$B, &$C, &$D, &$T0, &$T1, $xkey, $r)
		{
			$this->EncryptRnd( $A,$B,$C,$D,$T0,$T1,$xkey,2*$r  );
			$this->EncryptRnd( $C,$D,$A,$B,$T0,$T1,$xkey,2*$r+1);
		}
		
		/* 
		 * A single round of Twofish. The A,B,C,D are the four state variables, 
		 * T0 and T1 are temporaries, xkey is the expanded key, and r the  
		 * round number. 
		 * 
		 * Note that this macro does not implement the swap at the end of the round. 
		 */ 
		protected function EncryptRnd(&$A, &$B, &$C, &$D, &$T0, &$T1, $xkey, $r)
		{
			$T0 = $this->g0($A,$xkey);
			$T1 = $this->g1($B,$xkey);
			$C ^= ($T0+$T1+$xkey->K[8+2*$r]) & 0xffffffff;
			$C = $this->ROR32($C,1);
			$D = $this->ROL32($D,1);
			$D ^= ($T0+2*$T1+$xkey->K[8+2*$r+1]) & 0xffffffff;
		}

		/* 
		 * The g() function is the heart of the round function. 
		 * We have two versions of the g() function, one without an input 
		 * rotation and one with. 
		 * The pre-computed S-boxes make this pretty simple. 
		 */ 
		protected function g0($X, $xkey)
		{
			return $xkey->s[0][$this->b0($X)]^$xkey->s[1][$this->b1($X)]^$xkey->s[2][$this->b2($X)]^$xkey->s[3][$this->b3($X)];
		}
		
		protected function g1($X, $xkey)
		{
			return $xkey->s[0][$this->b3($X)]^$xkey->s[1][$this->b0($X)]^$xkey->s[2][$this->b1($X)]^$xkey->s[3][$this->b2($X)];
		}

		/* 
		 * Similar macro to put the ciphertext in the output buffer. 
		 * We xor the keys into the state variables before we use the PUT32  
		 * macro as the macro might use its argument multiple times. 
		 */ 
		protected function PutOutput(&$A, &$B, &$C, &$D, &$dst, $xkey, $koff)
		{
			$A ^= $xkey->K[  $koff];
			$B ^= $xkey->K[1+$koff];
			$C ^= $xkey->K[2+$koff];
			$D ^= $xkey->K[3+$koff];
			$dst = $this->Put32( $A, $dst    );
			$dst = $this->Put32( $B, $dst, 4 );
			$dst = $this->Put32( $C, $dst, 8 );
			$dst = $this->Put32( $D, $dst, 12);
		}
		
		/* Full 16-round decryption. */ 
		protected function DecryptInternal(&$A, &$B, &$C, &$D, &$T0, &$T1, $xkey)
		{
			for ($i=7; $i>=0; --$i)
				$this->DecryptCycle( $A,$B,$C,$D,$T0,$T1,$xkey, $i);
		}
		
		/* 
		 * Decrypt a single cycle, consisting of two rounds.  
		 * This avoids the swapping of the two halves.  
		 * Parameter r is now the cycle number. 
		 */ 
		protected function DecryptCycle(&$A, &$B, &$C, &$D, &$T0, &$T1, $xkey, $r)
		{
			$this->DecryptRnd( $A,$B,$C,$D,$T0,$T1,$xkey,2*$r+1);
			$this->DecryptRnd( $C,$D,$A,$B,$T0,$T1,$xkey,2*$r  );
		}
		
		/* 
		 * A single round of Twofish for decryption. It differs from 
		 * ENCRYTP_RND only because of the 1-bit rotations. 
		 */ 
		protected function DecryptRnd(&$A, &$B, &$C, &$D, &$T0, &$T1, $xkey, $r)
		{
			$T0 = $this->g0($A,$xkey);
			$T1 = $this->g1($B,$xkey);
			$C = $this->ROL32($C,1);
			$C ^= ($T0+$T1+$xkey->K[8+2*$r]) & 0xffffffff;
			$D ^= ($T0+2*$T1+$xkey->K[8+2*$r+1]) & 0xffffffff;
			$D = $this->ROR32($D,1);
		}

		/* 
		 * Test the platform-specific macros. 
		 * This function tests the macros defined below to make sure the  
		 * definitions are appropriate for this platform. 
		 * If you make any mistake in the platform configuration, this should detect 
		 * that and inform you what went wrong. 
		 * Somewhere, someday, this is going to save somebody a lot of time, 
		 * because misbehaving macros are hard to debug. 
		 */ 								
		protected function TestPlatform()
		{
			/* Buffer with test values. */ 
			$buf = hex2bin('123456789abcde00'); 

			/*  
			 * Sanity-check the endianness conversions.  
			 * This is just an aid to find problems. If you do the endianness 
			 * conversion macros wrong you will fail the full cipher test, 
			 * but that does not help you find the error. 
			 * Always make it easy to find the bugs!  
			 * 
			 * Start with testing GET32. We test it on all positions modulo 4  
			 * to make sure we can handly any position of inputs.
			 */ 
			if( ($this->Get32($buf) != 0x78563412) || ($this->Get32($buf, 1) != 0x9a785634)
				|| ($this->Get32($buf, 2) != 0xbc9a7856) || ($this->Get32($buf, 3) != 0xdebc9a78) ) 
			{ 
				$this->Fatal( 'Twofish code: Get32 not implemented properly', self::ERR_GET32 ); 
				return self::ERR_GET32;
			} 

			/*  
			 * We can now use GET32 to test PUT32. 
			 * We don't test the shifted versions. If GET32 can do that then 
			 * so should PUT32. 
			 */ 
			$C = $this->Get32( $buf ); 
			$buf = $this->Put32( 3*$C, $buf ); 
			if( $this->Get32( $buf ) != 0x69029c36 ) 
			{ 
				$this->Fatal( 'Twofish code: PUT32 not implemented properly', self::ERR_PUT32 ); 
				return self::ERR_PUT32;
			} 
			
			/* Test ROL and ROR */ 
			for( $i=1; $i<32; $i++ )  
			{ 
				/* Just a simple test. */ 
				$x = $this->ROR32( $C, $i ); 
				$y = $this->ROL32( $C, $i ); 
				$x ^= ($C>>$i) ^ ($C<<(32-$i)); 
				/*$y ^= ($C<>(32-$i));  */
				$y ^= ($C<<$i) ^ ($C>>(32-$i));
				$x |= $y;
				/*  
				 * Now all we check is that x is zero in the least significant 
				 * 32 bits.
				 */ 
				if( ($x & 0xffffffff) != 0 ) 
				{ 
					$this->Fatal( 'Twofish ROL or ROR not properly defined.', self::ERR_ROLR ); 
					return self::ERR_ROLR;
				} 
			}
			
			/* Test the BSWAP macro */ 
			if( $this->BSwap($C) != 0x12345678 ) 
			{ 
				/* 
				 * The BSWAP macro should always work, even if you are not using it. 
				 * A smart optimising compiler will just remove this entire test. 
				 */ 
				$this->Fatal( 'BSWAP not properly defined.', self::ERR_BSWAP );
				return self::ERR_BSWAP;
			} 

			/* And we can test the b macros which use SELECT_BYTE. */ 
			if( ($this->b0($C)!=0x12) || ($this->b1($C) != 0x34) || ($this->b2($C) != 0x56) || ($this->b3($C) != 0x78) ) 
			{ 
				/* 
				 * There are many reasons why this could fail. 
				 * Most likely is that CPU_IS_BIG_ENDIAN has the wrong value.  
				 */ 
				$this->Fatal( 'Twofish code: SELECT_BYTE not implemented properly', self::ERR_SELECTB );
				return self::ERR_SELECTB;
			}

			return self::SUCCESS;
		}
		
		/* This implementation generates all the tables during initialisation.  
		 * I don't like large tables in the code, especially since they are easily  
		 * damaged in the source without anyone noticing it. You need code to  
		 * generate them anyway, and this way all the code is close together. 
		 * Generating them in the application leads to a smaller executable  
		 * (the code is smaller than the tables it generates) and a  
		 * larger static memory footprint. 
		 * 
		 * Twofish can be implemented in many ways. I have chosen to  
		 * use large tables with a relatively long key setup time. 
		 * If you encrypt more than a few blocks of data it pays to pre-compute  
		 * as much as possible. This implementation is relatively inefficient for  
		 * applications that need to re-key every block or so. 
		 */ 
		
		/*  
		 * We start with the t-tables, directly from the Twofish definition.  
		 * These are nibble-tables, but merging them and putting them two nibbles  
		 * in one byte is more work than it is worth. 
		 */ 
		/* byte[2][4][16] */
		protected $t_table = array(
			array( 
				array(0x8,0x1,0x7,0xD,0x6,0xF,0x3,0x2,0x0,0xB,0x5,0x9,0xE,0xC,0xA,0x4), 
				array(0xE,0xC,0xB,0x8,0x1,0x2,0x3,0x5,0xF,0x4,0xA,0x6,0x7,0x0,0x9,0xD),
				array(0xB,0xA,0x5,0xE,0x6,0xD,0x9,0x0,0xC,0x8,0xF,0x3,0x2,0x4,0x7,0x1),
				array(0xD,0x7,0xF,0x4,0x1,0x2,0x6,0xE,0x9,0xB,0x3,0x0,0x8,0x5,0xC,0xA),
			), 
			array( 
				array(0x2,0x8,0xB,0xD,0xF,0x7,0x6,0xE,0x3,0x1,0x9,0x4,0x0,0xA,0xC,0x5),
        		array(0x1,0xE,0x2,0xB,0x4,0xC,0x3,0x7,0x6,0xD,0xA,0x5,0xF,0x9,0x0,0x8),
        		array(0x4,0xC,0x7,0x5,0x1,0x6,0x9,0xA,0x0,0xE,0xD,0x8,0x2,0xB,0x3,0xF),
        		array(0xB,0x9,0x5,0x1,0xC,0x3,0xD,0xE,0x6,0x4,0x7,0xF,0x2,0x0,0x8,0xA),
			), 
		);

		/*  
		 * The actual q-box tables.  
		 * There are two q-boxes, each having 256 entries. 
		 */ 		
		/* byte[2][256] */
		protected $q_table = array(array(), array());
		
		/*  
		 * Initialise both q-box tables.  
		 */ 
		protected function InitialiseQBoxes()
		{
			/* Initialise each of the q-boxes using the t-tables */ 
			$this->MakeQTable( $this->t_table[0], $this->q_table[0] );
			$this->MakeQTable( $this->t_table[1], $this->q_table[1] ); 
		}
		
		/* 
		 * Now the function that converts a single t-table into a q-table. 
		 * 
		 * Arguments: 
		 * t[4][16] : four 4->4bit lookup tables that define the q-box 
		 * q[256]   : output parameter: the resulting q-box as a lookup table. 
		 */ 
		protected function MakeQTable($t, &$q)
		{
			/* Loop over all input values and compute the q-box result. */ 
			for( $i=0; $i<256; $i++ )
			{ 
				/*  
				 * This is straight from the Twofish specifications.  
				 *  
				 * The ae variable is used for the a_i values from the specs 
				 * with even i, and ao for the odd i's. Similarly for the b's. 
				 */ 
				$ae = $i>>4; $be = $i&0xf; 
				$ao = $ae ^ $be; $bo = $ae ^ $this->ROR4By1($be) ^ (($ae<<3)&8); 
				$ae = $t[0][$ao]; $be = $t[1][$bo]; 
				$ao = $ae ^ $be; $bo = $ae ^ $this->ROR4By1($be) ^ (($ae<<3)&8); 
				$ae = $t[2][$ao]; $be = $t[3][$bo]; 
		 
				/* Store the result in the q-box table. */ 
				$q[$i] = (($be<<4) | $ae);
			} 
		}
		
		/* The actual MDS tables. */ 
		/* byte[4][256] */
		protected $MDS_table = array(array(), array(), array(), array());
		/* A small table to get easy conditional access to the 0xb4 constant. */ 
		protected $mds_poly_divx_const = array(0,0xb4);
		
		/* 
		 * Next up is the MDS matrix multiplication. 
		 * The MDS matrix multiplication operates in the field 
		 * GF(2)[x]/p(x) with p(x)=x^8+x^6+x^5+x^3+1. 
		 * If you don't understand this, read a book on finite fields. You cannot 
		 * follow the finite-field computations without some background. 
		 *  
		 * In this field, multiplication by x is easy: shift left one bit  
		 * and if bit 8 is set then xor the result with 0x169.  
		 * 
		 * The MDS coefficients use a multiplication by 1/x, 
		 * or rather a division by x. This is easy too: first make the 
		 * value 'even' (i.e. bit 0 is zero) by xorring with 0x169 if necessary,  
		 * and then shift right one position.  
		 * Even easier: shift right and xor with 0xb4 if the lsbit was set. 
		 * 
		 * The MDS coefficients are 1, EF, and 5B, and we use the fact that 
		 *   EF = 1 + 1/x + 1/x^2 
		 *   5B = 1       + 1/x^2 
		 * in this field. This makes multiplication by EF and 5B relatively easy. 
		 * 
		 * This property is no accident, the MDS matrix was designed to allow 
		 * this implementation technique to be used. 
		 * 
		 * We have four MDS tables, each mapping 8 bits to 32 bits. 
		 * Each table performs one column of the matrix multiplication.  
		 * As the MDS is always preceded by q-boxes, each of these tables 
		 * also implements the q-box just previous to that column. 
		 */ 
		/* Function to initialise the MDS tables. */ 
		protected function InitialiseMDSTables()
		{
			/* Loop over all 8-bit input values */ 
			for( $i=0; $i<256; $i++ )  
			{ 
				/*  
				 * To save some work during the key expansion we include the last 
				 * of the q-box layers from the h() function in these MDS tables. 
				 */ 
		 
				/* We first do the inputs that are mapped through the q0 table. */ 
				$q = $this->q_table[0][$i]; 
				/* 
				 * Here we divide by x, note the table to get 0xb4 only if the  
				 * lsbit is set.  
				 * This sets qef = (1/x)*q in the finite field 
				 */ 
				$qef = ($q >> 1) ^ $this->mds_poly_divx_const[ $q & 1 ]; 
				/* 
				 * Divide by x again, and add q to get (1+1/x^2)*q.  
				 * Note that (1+1/x^2) =  5B in the field, and addition in the field 
				 * is exclusive or on the bits. 
				 */ 
				$q5b = ($qef >> 1) ^ $this->mds_poly_divx_const[ $qef & 1 ] ^ $q; 
				/*  
				 * Add q5b to qef to set qef = (1+1/x+1/x^2)*q. 
				 * Again, (1+1/x+1/x^2) = EF in the field. 
				 */ 
				$qef ^= $q5b; 
		 
				/*  
				 * Now that we have q5b = 5B * q and qef = EF * q  
				 * we can fill two of the entries in the MDS matrix table.  
				 * See the Twofish specifications for the order of the constants. 
				 */ 
				$this->MDS_table[1][$i] = ($q  <<24) | ($q5b<<16) | ($qef<<8) | $qef; 
				$this->MDS_table[3][$i] = ($q5b<<24) | ($qef<<16) | ($q  <<8) | $q5b; 
		 
				/* Now we do it all again for the two columns that have a q1 box. */ 
				$q = $this->q_table[1][$i]; 
				$qef = ($q >> 1) ^ $this->mds_poly_divx_const[ $q & 1 ]; 
				$q5b = ($qef >> 1) ^ $this->mds_poly_divx_const[ $qef & 1 ] ^ $q;
				$qef ^= $q5b; 
		 
				/* The other two columns use the coefficient in a different order. */ 
				$this->MDS_table[0][$i] = ($qef<<24) | ($qef<<16) | ($q5b<<8) | $q  ; 
				$this->MDS_table[2][$i] = ($qef<<24) | ($q  <<16) | ($qef<<8) | $q5b; 
			}
		}
		
		/* 
		 * Test the Twofish implementation. 
		 * 
		 * This routine runs all the self tests, in order of importance. 
		 * It is called by the Twofish_initialise routine. 
		 *  
		 * In almost all applications the cost of running the self tests during 
		 * initialisation is insignificant, especially 
		 * compared to the time it takes to load the application from disk.  
		 * If you are very pressed for initialisation performance,  
		 * you could remove some of the tests. Make sure you did run them 
		 * once in the software and hardware configuration you are using. 
		 */ 
		protected function SelfTest()
		{
			/* The three test vectors form an absolute minimal test set. */ 
			if (($ret = $this->TestVectors()) < 0)
				return $ret;
		 
			/*  
			 * If at all possible you should run these tests too. They take 
			 * more time, but provide a more thorough coverage. 
			 */ 
			if (($ret = $this->TestSequences()) < 0)
				return $ret;
		 
			/* Test the odd-sized keys. */ 
			if (($ret = $this->TestOddSizedKeys()) < 0)
				return $ret;
			
			return self::SUCCESS;
		}
		
		/* 
		 * Check implementation using three (key,plaintext,ciphertext) 
		 * test vectors, one for each major key length. 
		 *  
		 * This is an absolutely minimal self-test.  
		 * This routine does not test odd-sized keys. 
		 */ 
		protected function TestVectors()
		{
			/* 
			 * We run three tests, one for each major key length. 
			 * These test vectors come from the Twofish specification. 
			 * One encryption and one decryption using randomish data and key 
			 * will detect almost any error, especially since we generate the 
			 * tables ourselves, so we don't have the problem of a single 
			 * damaged table entry in the source. 
			 */ 
		 
			/* 128-bit test is the I=3 case of section B.2 of the Twofish book. */ 
			$k128 = hex2bin('9F589F5CF6122C32B6BFEC2F2AE8C35A');
			$p128 = hex2bin('D491DB16E7B1C39E86CB086B789F5419'); 
			$c128 = hex2bin('019F9809DE1711858FAAC3A3BA20FBC3'); 
		 
			/* 192-bit test is the I=4 case of section B.2 of the Twofish book. */ 
			$k192 = hex2bin('88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44'); 
			$p192 = hex2bin('39DA69D6BA4997D585B6DC073CA341B2'); 
			$c192 = hex2bin('182B02D81497EA45F9DAACDC29193A65'); 
		 
			/* 256-bit test is the I=4 case of section B.2 of the Twofish book. */ 
			$k256 = hex2bin('D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F'); 
			$p256 = hex2bin('90AFE91BB288544F2C32DC239B2635E6'); 
			$c256 = hex2bin('6CB4561C40BF0A9705931CB6D408E7FA');

			/* Run the actual tests. */ 
			if (($ret = $this->TestVector( $k128, $p128, $c128 )) < 0)
			  return $ret; 
			if (($ret = $this->TestVector( $k192, $p192, $c192 )) < 0)
			  return $ret; 
			if (($ret = $this->TestVector( $k256, $p256, $c256 )) < 0)
			  return $ret;
		  
			return self::SUCCESS;
		}
		
		/* 
		 * Perform a single self test on a (plaintext,ciphertext,key) triple. 
		 * Arguments: 
		 *  key     array of key bytes 
		 *  p       plaintext 
		 *  c       ciphertext 
		 */ 
		protected function TestVector($key, $p, $c)
		{
			$tmp = '';
			$xkey = new Twofish_key;
		 
			/* Prepare the key */ 
			if (($ret = $this->PrepareKey( $key, $xkey)) < 0)
				return $reti; 
		 
			/*  
			 * We run the test twice to ensure that the xkey structure 
			 * is not damaged by the first encryption.  
			 * Those are hideous bugs to find if you get them in an application. 
			 */ 
			for( $i=0; $i<2; $i++ )  
				{ 
				/* Encrypt and test */ 
				$this->Encrypt( $xkey, $p, $tmp );
				if( $c != $tmp )  
				{ 
					$this->Fatal( 'Twofish encryption failure', self::ERR_TEST_ENC ); 
					return self::ERR_TEST_ENC;
				}
		 
				/* Decrypt and test */ 
				$this->Decrypt( $xkey, $c, $tmp ); 
				if( $p != $tmp )  
				{ 
					$this->Fatal( 'Twofish decryption failure', self::ERR_TEST_DEC );
					return self::ERR_TEST_DEC;
				} 
			} 
		 
			/* The test keys are not secret, so we don't need to wipe xkey. */
			return self::SUCCESS;
		}
		
		/*  
		 * Run all three sequence tests from the Twofish test vectors.  
		 * 
		 * This checks the most extensive test vectors currently available  
		 * for Twofish. The data is from the Twofish book, appendix B.2. 
		 */ 
		protected function TestSequences()
		{
			$r128 = hex2bin('5D9D4EEFFA9151575524F115815A12E0');
			$r192 = hex2bin('E75449212BEEF9F4A390BD860A640941');
			$r256 = hex2bin('37FE26FF1CF66175F5DDF4C33B97A205');
 
			/* Run the three sequence test vectors */
			if (($ret = $this->TestSequence( 16, $r128)) < 0)
				return $ret; 
			if (($ret = $this->TestSequence( 24, $r192)) < 0)
				return $ret; 
			if (($ret = $this->TestSequence( 32, $r256)) < 0)
				return $ret;
			return self::SUCCESS;
		}

		/* 
		 * Perform extensive test for a single key size. 
		 *  
		 * Test a single key size against the test vectors from section 
		 * B.2 in the Twofish book. This is a sequence of 49 encryptions 
		 * and decryptions. Each plaintext is equal to the ciphertext of 
		 * the previous encryption. The key is made up from the ciphertext 
		 * two and three encryptions ago. Both plaintext and key start 
		 * at the zero value.  
		 * We should have designed a cleaner recurrence relation for 
		 * these tests, but it is too late for that now. At least we learned 
		 * how to do it better next time. 
		 * For details see appendix B of the book. 
		 * 
		 * Arguments: 
		 * key_len      Number of bytes of key 
		 * final_value  Final plaintext value after 49 iterations 
		 */ 		
		protected function TestSequence($keyLen, $finalValue)
		{
			$tmp = '';						/* Temp for testing the decryption. */ 
			$xkey = new Twofish_key;		/* The expanded key */ 
		 
			/* Wipe the buffer */ 
			$bufSize = (50+3)*16;
			$buf = str_pad('', $bufSize, chr(0));     /* Buffer to hold our computation values. */ 
		 
			/* 
			 * Because the recurrence relation is done in an inconvenient manner 
			 * we end up looping backwards over the buffer. 
			 */ 
		 
			/* Pointer in buffer points to current plaintext. */ 
			$p = 50*16;
			for( $i=1; $i<50; $i++ ) 
			{ 
				/*  
				 * Prepare a key. 
				 * This automatically checks that keyLen is valid. 
				 */ 
				if (($ret = $this->PrepareKey( substr($buf, $p+16, $keyLen), $xkey )) < 0)
					return $ret; 

				/* Compute the next 16 bytes in the buffer */ 
				$this->Encrypt( $xkey, substr($buf, $p, 16), $tmp );
				$buf = substr_replace($buf, $tmp, $p-16, strlen($tmp));

				/* Check that the decryption is correct. */ 
				$this->Decrypt( $xkey, substr($buf, $p-16, 16), $tmp ); 
				if( $tmp != substr($buf, $p, 16) ) 
				{ 
					$this->Fatal( 'Twofish decryption failure in sequence', self::ERR_SEQ_DEC ); 
					return self::ERR_SEQ_DEC;
				} 
				/* Move on to next 16 bytes in the buffer. */ 
				$p -= 16; 
			} 

			/* And check the final value. */ 
			if( substr($buf, $p, 16) != $finalValue )  
			{ 
				$this->Fatal( 'Twofish encryption failure in sequence', self::ERR_SEQ_ENC );
				return self::ERR_SEQ_ENC;
			} 
		 
			/* None of the data was secret, so there is no need to wipe anything. */
			return self::SUCCESS;
		}
		
		/* 
		 * Test the odd-sized keys. 
		 * 
		 * Every odd-sized key is equivalent to a one of 128, 192, or 256 bits. 
		 * The equivalent key is found by padding at the end with zero bytes 
		 * until a regular key size is reached. 
		 * 
		 * We just test that the key expansion routine behaves properly. 
		 * If the expanded keys are identical, then the encryptions and decryptions 
		 * will behave the same. 
		 */ 
		protected function TestOddSizedKeys()
		{
			$tmp = '';
			$xkey = new Twofish_key;
			$xkey_two = new Twofish_key;
		 
			/*  
			 * We first create an all-zero key to use as PRNG key.  
			 * Normally we would not have to fill the buffer with zeroes, as we could 
			 * just pass a zero key length to the Twofish_prepare_key function. 
			 * However, this relies on using odd-sized keys, and those are just the 
			 * ones we are testing here. We can't use an untested function to test  
			 * itself.  
			 */ 
			$bufSize = 32;
			$buf = str_pad('', $bufSize, chr(0));
			if (($ret = $this->PrepareKey( substr($buf, 0, 16), $xkey)) < 0)
			  return $ret; 
		 
			/* Fill buffer with pseudo-random data derived from two encryptions */ 
			$this->Encrypt( $xkey, $buf, $tmp );
			$buf = substr_replace($buf, $tmp, 0, strlen($tmp));
			$this->Encrypt( $xkey, $buf, $tmp );
			$buf = substr_replace($buf, $tmp, 16, strlen($tmp));
		 
			/* Create all possible shorter keys that are prefixes of the buffer. */ 
			for( $i=31; $i>=0; $i-- ) 
			{ 
				/* Set a byte to zero. This is the new padding byte */ 
				$buf[$i] = chr(0); 
		 
				/* Expand the key with only i bytes of length */ 
				if (($ret = $this->PrepareKey( substr($buf, 0, $i), $xkey)) < 0)
					return $ret; 
		 
				/* Expand the corresponding padded key of regular length */ 
				if (($ret = $this->PrepareKey( substr($buf, 0, $i<=16 ? 16 : ($i<= 24 ? 24 : 32)), $xkey_two )) < 0)
					return $ret; 
		 
				/* Compare the two */ 
				if( $xkey != $xkey_two ) 
				{ 
					$this->Fatal( 'Odd sized keys do not expand properly', self::ERR_ODD_KEY );
					return self::ERR_ODD_KEY;
				} 
			} 
		 
			/* None of the key values are secret, so we don't need to wipe them. */
			return self::SUCCESS;
		}
		
		/* 
		 * We need macros to load and store UInt32 from/to strings
		 * using the least-significant-byte-first convention. 
		 * 
		 * GET32( p ) gets a UInt32 in lsb-first form from four bytes pointed to 
		 * by p. 
		 * PUT32( v, p ) writes the UInt32 value v at address p in lsb-first form. 
		 */ 
		/* Get UInt32 from four bytes pointed to by data and offset. */ 
		protected function Get32($data, $offset = 0)
		{
			//php7.1+ return unpack('V', $data, $offset)[1];
            return unpack('V', substr($data, $offset, 4))[1];
		}
		
		/* Put UInt32 into four bytes pointed to by data and offset. */  
		protected function Put32($value, $data, $offset = 0)
		{
			$newval = pack('V', $value);
			return substr_replace($data, $newval, $offset, strlen($newval));
		}
		
		/*  
		 * Macros to rotate a Twofish_UInt32 value left or right by the  
		 * specified number of bits. This should be a 32-bit rotation,  
		 * and not rotation of, say, 64-bit values. 
		 * 
		 * Every encryption or decryption operation uses 32 of these rotations, 
		 * so it is a good idea to make these macros efficient. 
		 * 
		 * This fully portable definition has one piece of tricky stuff. 
		 * The UInt32 might be larger than 32 bits, so we have to mask 
		 * any higher bits off. The simplest way to do this is to 'and' the 
		 * value first with 0xffffffff and then shift it right. An optimising 
		 * compiler that has a 32-bit type can optimise this 'and' away. 
		 *  
		 * Unfortunately there is no portable way of writing the constant 
		 * 0xffffffff. You don't know which suffix to use (U, or UL?) 
		 * The UINT32_MASK definition uses a bit of trickery. Shift-left 
		 * is only defined if the shift amount is strictly less than the size 
		 * of the UInt32, so we can't use (1<<32). The answer it to take the value 
		 * 2, cast it to a UInt32, shift it left 31 positions, and subtract one. 
		 * Another example of how to make something very simple extremely difficult. 
		 * I hate C. 
		 *  
		 * The rotation macros are straightforward. 
		 * They are only applied to UInt32 values, which are _unsigned_ 
		 * so the >> operator must do a logical shift that brings in zeroes. 
		 * On most platforms you will only need to optimise the ROL32 macro; the 
		 * ROR32 macro is not inefficient on an optimising compiler as all rotation 
		 * amounts in this code are known at compile time. 
		 * 
		 * On many platforms there is a faster solution. 
		 * For example, MS compilers have the __rotl and __rotr functions 
		 * that generate x86 rotation instructions. 
		 */ 
		protected function ROL32($x, $n)
		{
			return (($x << $n) & 0xffffffff) | ($x >> (32 - $n));
		}
		
		protected function ROR32($x, $n)
		{
			return ($x >> $n) | (($x << (32 - $n)) & 0xffffffff);
		}
		
		/* A 1-bit rotation of 4-bit values. Input must be in range 0..15 */ 
		protected function ROR4By1($x)
		{
			return ((($x)>>1) | ((($x)<<3) & 0x8));
		}
		
		/*  
		 * Macro to reverse the order of the bytes in a UInt32. 
		 * Used to convert to little-endian on big-endian machines. 
		 * This macro is always tested, but only used in the encryption and 
		 * decryption if CONVERT_USING_CASTS, and CPU_IS_BIG_ENDIAN 
		 * are both set. In other words: this macro is only speed-critical if 
		 * both these flags have been set. 
		 * 
		 * This default definition of SWAP works, but on many platforms there is a  
		 * more efficient implementation.  
		 */ 
		protected function BSwap($x)
		{
			return (($this->ROL32($x, 8) & 0x00ff00ff) | ($this->ROR32($x, 8) & 0xff00ff00));
		}
		
		/* 
		 * Macro to get Byte no. b from UInt32 value X. 
		 */ 
		protected function SelectByte($x, $b)
		{
			return ($x >> (8 * $b)) & 0xff;
		}

		/* Some shorthands because we use byte selection in large formulae. */ 
		protected function b0($x)
		{
			return $this->SelectByte($x, 0);
		}
		
		protected function b1($x)
		{
			return $this->SelectByte($x, 1);
		}
		
		protected function b2($x)
		{
			return $this->SelectByte($x, 2);
		}
		
		protected function b3($x)
		{
			return $this->SelectByte($x, 3);
		}
		
		/*  
		 * Function called if something is fatally wrong with the implementation.  
		 * This fatal function is called when a coding error is detected in the 
		 * Twofish implementation, or when somebody passes an obviously erroneous 
		 * parameter to this implementation. There is not much you can do when 
		 * the code contains bugs, so we just stop. 
		 *  
		 * The argument is a string. Ideally the fatal function prints this string 
		 * as an error message. Whatever else this function does, it should never 
		 * return. A typical implementation would stop the program completely after 
		 * printing the error message. 
		 * 
		 * This default implementation is not very useful,  
		 * but does not assume anything about your environment.  
		 * It will at least let you know something is wrong.... 
		 * I didn't want to include any libraries to print and error or so, 
		 * as this makes the code much harder to integrate in a project. 
		 * 
		 * Note that the Fatal function may not return to the caller. 
		 * Unfortunately this is not something the self-test can test for, 
		 * so you have to make sure of this yourself. 
		 * 
		 * If you want to call an external function, be careful about including 
		 * your own header files here. This code uses a lot of macros, and your 
		 * header file could easily break it. Maybe the best solution is to use 
		 * a separate extern statement for your fatal function. 
		 */ 
		protected function Fatal($errorMsg, $code)
		{
			die($errorMsg . ' (code: ' . $code);
		}
	}
