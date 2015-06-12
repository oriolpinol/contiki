/*
 * Copyright (c) 2014, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/**
 * \file
 *         Public API declarations for Big Integer arithmetic.
 *
 * \author Oriol Piñol <oriol@sics.se>
 */

#ifndef _BIGINT_H__
#define _BIGINT_H__

#include "stdint.h"

//#define COMPACT_COORDINATES

#ifdef WORDS_32_BITS
typedef uint32_t u_word;
typedef uint64_t u_doubleword;
typedef uint8_t u_byte;


#define BIGINT_WORD_BITS 32

#define MAX_BIGINT_WORD 0xffffffff
#endif /* WORDS_32_BITS */

#ifdef WORDS_16_BITS
typedef uint16_t u_word;
typedef uint32_t u_doubleword;
typedef uint8_t u_byte;


#define BIGINT_WORD_BITS 16

#define MAX_BIGINT_WORD 0xffff
#endif /* WORDS_16_BITS */

#define BIGINT_WORD_BYTES (BIGINT_WORD_BITS/8)

void bigint_null(u_word * a, u_byte digits);

void bigint_print(u_word * a, u_byte digits);

void bigint_copy(u_word * a, u_word * b, u_byte digits);

u_byte bigint_is_zero(u_word * a, u_byte digits);

u_byte bigint_digit_length(u_word * a, u_byte digits);

uint16_t bigint_bit_length(u_word * a, u_byte digits);

void bigint_to_network_bytes(uint8_t data[],u_word * a, u_byte digits);

void bigint_network_bytes_to_bigint(u_word *a, uint8_t data[], u_byte bytes);

u_byte bigint_increment(u_word * a, u_byte digits);

u_word bigint_add(u_word * a, u_word * b, u_word * c, u_byte digits);

void bigint_negate(u_word * a, u_byte digits);

u_word bigint_substract(u_word * a, u_word * b, u_word * c, u_byte digits);

void bigint_basic_mult(u_word * a, u_word b, u_word c);

void bigint_square(u_word * a, u_word * b, u_byte digits);

void bigint_multiply(u_word * a, u_word * b, u_word * c, u_byte m, u_byte n);

void bigint_multiply_trunc(u_word * a, u_word * b, u_word * c, u_byte n);

void bigint_shift_digits_left(u_word * a, u_byte positions, u_byte digits);

void bigint_shift_digits_right(u_word * a, u_byte positions, u_byte digits);

u_word bigint_shift_bits_left(u_word * a, u_byte bits, u_byte digits);

void bigint_shift_bits_right(u_word * a, u_byte bits, u_byte digits);

signed char bigint_compare(u_word * a, u_word * b, u_byte digits);


u_word reciprocal(u_word * d);

u_word basic_division(u_word * u, u_word * d, u_word * q, u_word * v);

u_word bigint_divisionNby1(u_word * u, u_word * d, u_word * q, u_byte digits);

void bigint_divisionMbyN(u_word * u, u_word * d, u_word * q, u_word * r,
                         u_byte m, u_byte n);

void bigint_amodb(u_word * r, u_word * a, u_word * b, u_byte digitsA,
                  u_byte digitsB);

void bigint_mod_add(u_word * a, u_word * b, u_word * c, u_word * n,
                    u_byte digits);

void bigint_mod_substract(u_word * a, u_word * b, u_word * c, u_word * n,
                          u_byte digits);

void bigint_mod_multiply(u_word * a, u_word * b, u_word * c, u_word * n,
                         u_byte digitsb, u_byte digitsc);

void bigint_mod_square(u_word * a, u_word * b, u_word * n, u_byte digits);

void bigint_mod_dividebypow2(u_word * a, u_word * b, u_byte power,
                             u_word * p, u_byte digits);

void bigint_mod_square_root(u_word * a, u_word * b, u_word * p,
                            u_byte digits);

void bigint_gcd(u_word * a, u_word * u, u_word * v, u_byte digitsu,
                u_byte digitsv);

void bigint_binary_gcd(u_word * a, u_word * u, u_word * v, u_byte digits);


u_byte bigint_modif_extended_euclids(u_word * u1, u_word * u, u_word * v,
                                     u_byte digits);

void bigint_modular_inverse(u_word * a, u_word * b, u_word * n,
                            u_byte digits);

void power_mod(u_word * a, u_word * b, u_byte x, u_byte digits, u_word * m,
               u_byte mdigits);

void NN_power_mod(u_word * a, u_word * b, u_word * x, u_byte digits,
                  u_word * m, u_byte mdigits);

#endif
