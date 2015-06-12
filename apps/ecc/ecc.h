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
 *         Public API declarations for Elliptic Curve Cryptography
 *
 * \author Oriol Piñol <oriol@sics.se>
 */

#ifndef _ECC_H__
#define _ECC_H__

#include "bigint.h"

typedef struct curve {
  u_word a[NUMWORDS];
  u_word b[NUMWORDS];
} ecc_curve;

typedef struct point_affine {
  u_word x[NUMWORDS];
  u_word y[NUMWORDS];
} ecc_point_a;

typedef struct point_projective {
  u_word x[NUMWORDS];
  u_word y[NUMWORDS];
  u_word z[NUMWORDS];
} ecc_point_p;

typedef struct elliptic_param {
  u_word p[NUMWORDS];

  ecc_curve curve;

  ecc_point_a point;

  u_word order[NUMWORDS + 1];

} ecc_param;

void ecc_affine_add(ecc_point_a * a, ecc_point_a * b, ecc_point_a * c,
                    u_word * p, u_word * a_c);

void ecc_aff_scalar_multiplication(ecc_point_a * R, ecc_point_a * a,
                                   u_word * k, u_byte digitsk, u_word * P,
                                   u_word * a_c);

void ecc_homogeneous_add(ecc_point_p * a, ecc_point_p * b, ecc_point_p * c,
                         u_word * p, u_word * a_c);

void ecc_scalar_point_multiplication_homo(ecc_point_a * R, ecc_point_a * a,
                                          u_word * k, u_byte digitsk,
                                          u_word * P, u_word * a_c);

void ecc_jacobian_double(ecc_point_p * a, ecc_point_p * b, u_word * p,
                         u_word * a_c);

void ecc_generate_private_key(u_word * secr, ecc_param * param);

void ecc_generate_public_key(u_word * secr, ecc_point_a * publ,
                             ecc_param * param);

#ifdef COMPACT_COORDINATES
uint8_t ecc_generate_shared_key(u_word * shar, u_word * secr, u_word * publx,
                             ecc_param * param);
#else
uint8_t ecc_generate_shared_key(u_word * shared, u_word * secr,
                             ecc_point_a * publ, ecc_param * param);
#endif /* COMPACT_COORDINATES */

void ecc_generate_signature(u_word * secr, const unsigned char *message,
                            u_word * signature, u_word * rx,
                            ecc_param * param);

uint8_t ecc_check_signature(ecc_point_a * public, const uint8_t * message,
                         u_word * signature, u_word * r, ecc_param * param);

uint32_t ecc_check_point(ecc_point_a * point, ecc_param * param);

#endif
