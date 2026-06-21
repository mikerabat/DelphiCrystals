// ###################################################################
// #### This file is part of the Crystals cryptographic algorithm library.
// #### A direct port of the reference C implementation.
// ####
// #### Copyright:(c) 2026, Michael R. . All rights reserved.
// ####
// #### Unless required by applicable law or agreed to in writing, software
// #### distributed under the License is distributed on an "AS IS" BASIS,
// #### WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// #### See the License for the specific language governing permissions and
// #### limitations under the License.
// ###################################################################

unit kyber;

interface

uses SysUtils;

// ###########################################
// #### Interface functions
type
  TKyberSymBytes = Array[0..32 - 1] of Byte;
  TKyberSymBytes2 = Array[0..1] of TKyberSymBytes;
  TKyberSharedSecretBytes = TKyberSymBytes;


  TKyber512SecretKeyBytes = Array[0..1632-1] of byte;
  TKyber512PublicKeyBytes = Array[0..800-1] of Byte;
  TKyber512CipherTextBytes = Array[0..768-1] of Byte;

  TKyber768SecretKeyBytes = Array[0..2400-1] of byte;
  TKyber768PublicKeyBytes = Array[0..1184-1] of Byte;
  TKyber768CipherTextBytes = Array[0..1088-1] of Byte;

  TKyber1024SecretKeyBytes = Array[0..3168-1] of byte;
  TKyber1024PublicKeyBytes = Array[0..1568-1] of Byte;
  TKyber1024CipherTextBytes = Array[0..1568-1] of Byte;

function kyber768_kem_dec(var ss : TKyberSharedSecretBytes; const ct : TKyber768CipherTextBytes;   const sk : TKyber768SecretKeyBytes) : integer;
function kyber768_kem_enc( var ct : TKyber768CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber768PublicKeyBytes ) : integer;
function kyber768_kem_enc_derand(var ct : TKyber768CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber768PublicKeyBytes; const coins : TKyberSymBytes) : integer;
function kyber768_kem_keypair(var pk : TKyber768PublicKeyBytes; var sk : TKyber768SecretKeyBytes) : integer;
function kyber768_kem_keypair_derand(var pk : TKyber768PublicKeyBytes; var sk : TKyber768SecretKeyBytes; const coins : TKyberSymBytes2) : integer;


function kyber512_kem_dec(var ss : TKyberSharedSecretBytes; const ct : TKyber512CipherTextBytes;   const sk : TKyber512SecretKeyBytes) : integer;
function kyber512_kem_enc( var ct : TKyber512CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber512PublicKeyBytes ) : integer;
function kyber512_kem_enc_derand(var ct : TKyber512CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber512PublicKeyBytes; const coins : TKyberSymBytes) : integer;
function kyber512_kem_keypair(var pk : TKyber512PublicKeyBytes; var sk : TKyber512SecretKeyBytes) : integer;
function kyber512_kem_keypair_derand(var pk : TKyber512PublicKeyBytes; var sk : TKyber512SecretKeyBytes; const coins : TKyberSymBytes2) : integer;

function kyber1024_kem_dec(var ss : TKyberSharedSecretBytes; const ct : TKyber1024CipherTextBytes;   const sk : TKyber1024SecretKeyBytes) : integer;
function kyber1024_kem_enc( var ct : TKyber1024CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber1024PublicKeyBytes ) : integer;
function kyber1024_kem_enc_derand(var ct : TKyber1024CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber1024PublicKeyBytes; const coins : TKyberSymBytes) : integer;
function kyber1024_kem_keypair(var pk : TKyber1024PublicKeyBytes; var sk : TKyber1024SecretKeyBytes) : integer;
function kyber1024_kem_keypair_derand(var pk : TKyber1024PublicKeyBytes; var sk : TKyber1024SecretKeyBytes; const coins : TKyberSymBytes2) : integer;

implementation

uses fips202, cryptRnd;

// ###########################################
// #### Parameter for various Kyber strengths
// ###########################################

type
  TKyberParams = record
    SecretKeySize : integer;
    PublicKeySize : integer;
    CiphertextBytes : integer;
    K : integer;
    ETA1 : integer;
    PolyCompressedBytes : integer;
    PolyVecCompressedBytes : integer;
    PolyVecSize : Integer;
  end;


const cKyber512Params : TKyberParams = ( SecretKeySize : 1632;
                                         PublicKeySize : 800;
                                         CiphertextBytes : 768;
                                         K : 2;
                                         ETA1 : 3;
                                         PolyCompressedBytes : 128;
                                         PolyVecCompressedBytes : 640;
                                         PolyVecSize : 2*384;
                                        );
      cKyber768Params : TKyberParams = ( SecretKeySize : 2400;
                                         PublicKeySize : 1184;
                                         CiphertextBytes : 1088;
                                         K : 3;
                                         ETA1 : 2;
                                         PolyCompressedBytes : 128;
                                         PolyVecCompressedBytes : 960;
                                         PolyVecSize : 3*384;
                                        );
      cKyber1024Params : TKyberParams = ( SecretKeySize : 3168;
                                         PublicKeySize : 1568;
                                         CiphertextBytes : 1568;
                                         K : 4;
                                         ETA1 : 2;
                                         PolyCompressedBytes : 160;
                                         PolyVecCompressedBytes : 1408;
                                         PolyVecSize : 4*384;
                                        );

// ###########################################
// #### Base (maximum) definitions
// ###########################################

type
  TKyberUInt32Bytes = Array[0..3] of byte;
  PKyberUInt32Bytes = ^TKyberUInt32Bytes;
  TKyber3BBytes = Array[0..2] of Byte;
  PKyber3BBytes = ^TKyber3BBytes;

const KYBER_N = 256;
      KYBER_Q  = 3329;
      KYBER_K_MAX = 4;
      KYBER_SYMBYTES = 32;
      KYBER_SSBYTES = 32;
      KYBER_POLYBYTES	=	384;
      KYBER_POLYVECBYTES_MAX = KYBER_K_MAX*KYBER_POLYBYTES;

      // aes/SHA stuff
      SHAKE128_RATE = 168;
      SHAKE256_RATE = 136;
      SHA3_256_RATE = 136;
      SHA3_512_RATE = 72;

      XOF_BLOCKBYTES = SHAKE128_RATE;


type
  TKyberBufN2_4 = Array[0..127] of Byte; //2*KYBER_N div 4 - 1];
  PKyberBufN2_4 = ^TKyberBufN2_4;
  TKyberBufN3_4 = Array[0..191] of Byte; //3*KYBER_N div 4 - 1
  PKyberBufN3_4 = ^TKyberBufN3_4;

  PInt16 = ^Smallint;
  TKyberCoeffs = Array[0..Kyber_N - 1] of SmallInt;

type
  TKyberPoly = record
    Coeffs : TKyberCoeffs;
  end;
  PKyberPoly = ^TKyberPoly;

  TKyberPolyVec = record
    vec : Array[0..KYBER_K_MAX-1] of TKyberPoly;
  end;

var GEN_MATRIX_NBLOCKS : integer = 0;
    GEN_MATRIX_NBLOCKS_X_XOF_BLOCKBYTES : integer = 0;

const KYBER_ETA2 : integer = 2;
      KYBER_INDCPA_MSGBYTES : integer = 32;// KYBER_SYMBYTES;
      KYBER_INDCPA_PUBLICKEYBYTES_MAX = 4*384 + 32; // KYBER_POLYVECBYTES + KYBER_SYMBYTES;
      KYBER_INDCPA_SECRETKEYBYTES_MAX = 4*384; // KYBER_POLYVECBYTES;
      KYBER_INDCPA_BYTES_MAX = 4*352 + 160; // KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES;


      KYBER_SECRETKEYBYTES_MAX = 4*384 + 4*384 + 32 + 2*32 ; // KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES;


type
  TKyberINDCPAPublicKeyBytes = Array[0..KYBER_INDCPA_PUBLICKEYBYTES_MAX - 1] of byte;
  PKyberINDCPAPublicKeyBytes = ^TKyberINDCPAPublicKeyBytes;
  TKyberINDCPASecretKeyBytes = Array[0..KYBER_INDCPA_SECRETKEYBYTES_MAX-1] of byte;
  TKyberPolyCompressedBytes = Array[0..4*352-1] of Byte; //Array[0..KYBER_POLYVECCOMPRESSEDBYTES-1] of byte;  // maximum see SetupETA
  PKyberPolyCompressedBytes = ^TKyberPolyCompressedBytes;
  TKyberSecretKeyBytes = Array[0..KYBER_SECRETKEYBYTES_MAX-1] of byte;
  TKyberPublicKeyBytes = TKyberINDCPAPublicKeyBytes;
  PKyberSymBytes = ^TKyberSymBytes;
  TKyberPolyVecBytes = Array[0..KYBER_POLYVECBYTES_MAX - 1] of Byte;
  TKyberPolyBytes = Array[0..KYBER_POLYBYTES-1] of Byte;
  PKyberPolyBytes = ^TKyberPolyBytes;
  PKyberPolyVec = ^TKyberPolyVec;
  TKyberINDCPABytes = Array[0..KYBER_INDCPA_BYTES_MAX-1] of Byte;
  PKyberINDCPABytes = ^TKyberINDCPABytes;
  TKyberINDCPMsgBytes = TKyberSymBytes; // Array[0..KYBER_INDCPA_MSGBYTES-1] of Byte;
  PKyberINDCPMsgBytes = ^TKyberINDCPMsgBytes;
  TKyberCipherTextBytes = TKyberINDCPABytes;

  TKyberCryptoBytes = TKyberSymBytes;

  T3Bytes = Array[0..2] of Byte;
  P3Bytes = ^T3Bytes;
  T4Bytes = Array[0..3] of Byte;
  P4Bytes = ^T4Bytes;
  T5Bytes = Array[0..4] of Byte;
  P5Bytes = ^T5Bytes;

// ###########################################
// #### Verify.c
// ###########################################

///*************************************************
//* Name:        cmov
//*
//* Description: Copy len bytes from x to r if b is 1;
//*              don't modify x if b is 0. Requires b to be in {0,1};
//*              assumes two's complement representation of negative integers.
//*              Runs in constant time.
//*
//* Arguments:   uint8_t *r:       pointer to output byte array
//*              const uint8_t *x: pointer to input byte array
//*              size_t len:       Amount of bytes to be copied
//*              uint8_t b:        Condition bit; has to be in {0,1}
//**************************************************/
procedure cmov( r, x : PByte; len : integer; b : byte);
var i : integer;
begin
     b := Byte( -ShortInt(b));

     for i := 0 to len - 1 do
     begin
          r^ := r^ xor ( b and (r^ xor x^));
          inc(r);
          inc(x);
     end;
end;

///*************************************************
//* Name:        cmov_int16
//*
//* Description: Copy input v to *r if b is 1, don't modify *r if b is 0.
//*              Requires b to be in {0,1};
//*              Runs in constant time.
//*
//* Arguments:   int16_t *r:       pointer to output int16_t
//*              int16_t v:        input int16_t
//*              uint8_t b:        Condition bit; has to be in {0,1}
//**************************************************/
procedure cmov_int16( var r : Int16; v, b : Int16);
begin
     b := -b;

     r := r xor ( b and (r xor v) );
end;

// ###########################################

// #### reduce.c
// ###########################################

const MONT : integer = -1044; // 2^16 mod q
      QINV : integer = -3327; // q^-1 mod 2^16


function SAR32( a, b : integer ) : integer; register;
{$IFDEF CPUX86}
asm
   mov ecx, edx;
   sar eax, cl;
end;
{$ELSE}
{$IFDEF CPUX64}
asm
   mov eax, ecx
   mov ecx, edx
   sar eax, cl
end;
{$ELSE}
begin
     Result := Integer( Int64(a) shr b );
end;
{$ENDIF}
{$ENDIF}



function SAR16( a, b : Int16 ) : int16; register;
{$IFDEF CPUX86}
asm
   mov cx, dx;
   sar ax, cl;
end;
{$ELSE}
{$IFDEF CPUX64}
asm
   mov ax, cx
   mov cx, dx
   sar ax, cl
end;
{$ELSE}
begin
     Result := Int16( Integer(a) shr b );
end;
{$ENDIF}
{$ENDIF}

///*************************************************
//* Name:        montgomery_reduce
//*
//* Description: Montgomery reduction; given a 32-bit integer a, computes
//*              16-bit integer congruent to a * R^-1 mod q, where R=2^16
//*
//* Arguments:   - int32_t a: input integer to be reduced;
//*                           has to be in {-q2^15,...,q2^15-1}
//*
//* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
//**************************************************/
function montgomery_reduce( a : Int32 ) : Int16;
begin
     Result := Int16(Int16(a)*QINV);
     Result := Int16( SAR32( (a - Int32(Result)*KYBER_Q), 16 ) );
end;

///*************************************************
//* Name:        barrett_reduce
//*
//* Description: Barrett reduction; given a 16-bit integer a, computes
//*              centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
//*
//* Arguments:   - int16_t a: input integer to be reduced
//*
//* Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
//**************************************************/

function barrett_reduce(a : Int16) : int16;
var t : int16;
const v : int32 = 20159; // ((Int32(1) shl 26) + KYBER_Q div 2) div KYBER_Q
begin
     t := SAR32(v*a + (1 shl 25), 26);
     t := t*KYBER_Q;
     Result := a - t;
end;

// ###########################################
// #### NTT.c
// ###########################################

const zetas : Array[0..127] of int16 = (
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628
);

///*************************************************
//* Name:        fqmul
//*
//* Description: Multiplication followed by Montgomery reduction
//*
//* Arguments:   - int16_t a: first factor
//*              - int16_t b: second factor
//*
//* Returns 16-bit integer congruent to a*b*R^{-1} mod q
//**************************************************/
function fqmul(a, b : Int16) : Int16;
begin
     Result := montgomery_reduce(Int32(a)*Int32(b));
end;

///*************************************************
//* Name:        ntt
//*
//* Description: Inplace number-theoretic transform (NTT) in Rq.
//*              input is in standard order, output is in bitreversed order
//*
//* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
//**************************************************/
procedure ntt(var r : TKyberCoeffs);
var len, start, j, k : integer;
    t, zeta : Int16;
begin
     k := 1;
     len := 128;
     while len >= 2 do
     begin
          start := 0;
          while start < 256 do
          begin
               zeta := zetas[k];
               inc(k);
               for j := start to start + len - 1 do
               begin
                    t := fqmul(zeta, r[j + len]);
                    r[j + len] := r[j] - t;
                    r[j] := r[j] + t;
               end;

               start := start + 2*len;
          end;

          len := len shr 1;
     end;

end;

///*************************************************
//* Name:        invntt_tomont
//*
//* Description: Inplace inverse number-theoretic transform in Rq and
//*              multiplication by Montgomery factor 2^16.
//*              Input is in bitreversed order, output is in standard order
//*
//* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
//**************************************************/
procedure invntt(var r : TKyberCoeffs);  // pbytearray is 0..2^15 -> should work here
var start, len, j, k : integer;
    t, zeta : Int16;
const f : int16 = 1441;
begin
     k := 127;
     len := 2;
     while len <= 128 do
     begin
          start := 0;
          while start < 256 do
          begin
               zeta := zetas[k];
               dec(k);

               for j := start to start + len - 1 do
               begin
                    t := r[j];
                    r[j] := barrett_reduce(t + r[j + len]);
                    r[j + len] := r[j + len] - t;
                    r[j + len] := fqmul(zeta, r[j + len]);
               end;
               start := start + 2*len;
          end;

          len := len shl 1;
     end;

     for j := 0 to 255 do
         r[j] := fqmul(r[j], f);
end;

///*************************************************
//* Name:        basemul
//*
//* Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
//*              used for multiplication of elements in Rq in NTT domain
//*
//* Arguments:   - int16_t r[2]: pointer to the output polynomial
//*              - const int16_t a[2]: pointer to the first factor
//*              - const int16_t b[2]: pointer to the second factor
//*              - int16_t zeta: integer defining the reduction polynomial
//**************************************************/

type TPoly2 = Array[0..1] of Int16;
     PPoly2 = ^TPoly2;

procedure basemul(r : PPoly2; const a, b : PPoly2; zeta : Int16);
begin
     r^[0] := fqmul(a^[1], b^[1]);
     r^[0] := fqmul(r^[0], zeta);
     r^[0] := r[0] + fqmul(a^[0], b^[0]);

     r^[1] := fqmul(a^[0], b^[1]);
     r^[1] := r^[1] + fqmul(a^[1], b^[0]);
end;

// ###########################################
// #### CBD.c
// ###########################################
//*************************************************
//* Name:        load32_littleendian
//*
//* Description: load 4 bytes into a 32-bit integer
//*              in little-endian order
//*
//* Arguments:   - const uint8_t *x: pointer to input byte array
//*
//* Returns 32-bit unsigned integer loaded from x
//**************************************************/
function load32_littleendian( const x : TKyberUInt32Bytes ) : UInt32;
begin
     Result := x[0] or (x[1] shl 8) or (x[2] shl 16) or (x[3] shl 24);
end;

///*************************************************
//* Name:        load24_littleendian
//*
//* Description: load 3 bytes into a 32-bit integer
//*              in little-endian order.
//*              This function is only needed for Kyber-512
//*
//* Arguments:   - const uint8_t *x: pointer to input byte array
//*
//* Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
//**************************************************/
function load24_littleendian( const x : TKyber3BBytes ) : UInt32;
begin
     Result := x[0] or (x[1] shl 8) or (x[2] shl 16);
end;

///*************************************************
//* Name:        cbd2
//*
//* Description: Given an array of uniformly random bytes, compute
//*              polynomial with coefficients distributed according to
//*              a centered binomial distribution with parameter eta=2
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const uint8_t *buf: pointer to input byte array
//**************************************************/
procedure cbd2( var r : TKyberPoly; const buf : TKyberBufN2_4 );
var i, j : UInt32;
    t, d : UInt32;
    a, b : Int16;
begin
     for i := 0 to KYBER_N div 8 - 1 do
     begin
          t := load32_littleendian( PKyberUInt32Bytes(@buf[4*i])^ );
          d := t and $55555555;
          d := d + (t shr 1) and $55555555;

          for j := 0 to 8 - 1 do
          begin
               a := (d shr (4*j + 0)) and $03;
               b := (d shr (4*j + 2)) and $03;

               r.Coeffs[8*i + j] := a - b;
          end;
     end;
end;

///*************************************************
//* Name:        cbd3
//*
//* Description: Given an array of uniformly random bytes, compute
//*              polynomial with coefficients distributed according to
//*              a centered binomial distribution with parameter eta=3.
//*              This function is only needed for Kyber-512
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const uint8_t *buf: pointer to input byte array
//**************************************************/
procedure CBD3( var r : TKyberPoly; const buf : TKyberBufN3_4);
var i, j : Uint32;
    t, d : UInt32;
    a, b : Int16;
begin
     for i := 0 to KYBER_N div 4 - 1 do
     begin
          t := load24_littleendian( PKyber3BBytes(@buf[3*i])^ );
          d := t and $00249249;
          d := d + (t shr 1) and $00249249;
          d := d + (t shr 2) and $00249249;

          for j := 0 to 4 - 1 do
          begin
               a := (d shr (6*j + 0)) and $07;
               b := (d shr (6*j + 3)) and $07;

               r.Coeffs[4*i + j] := a - b;
          end;
     end;
end;

procedure poly_cbd_eta1(KYBER_ETA1 : integer; var r : TKyberPoly; const buf : PByte );
begin
     if KYBER_ETA1 = 2
     then
         cbd2(r, PKyberBufN2_4(buf)^)
     else if KYBER_ETA1 = 3
     then
         cbd3(r, PKyberBufN3_4(buf)^)
     else
         raise Exception.Create('ETA1 only allowed to be 2, 3');
end;

procedure poly_cbd_eta2( var r : TKyberPoly; const buf : PByte );
begin
     cbd2(r, PKyberBufN2_4(buf)^)
end;

// ###########################################
// #### symmetric.c
// ###########################################


///*************************************************

//
//* Name:        kyber_shake128_absorb
//*
//* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
//*
//* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
//*              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be absorbed into state
//*              - uint8_t i: additional byte of input
//*              - uint8_t j: additional byte of input
//**************************************************/


procedure kyber_shake128_absorb( var state : TKeccakState; var seed : TKyberSymBytes; x, y : Byte);

var extseed : Array[0..KYBER_SYMBYTES + 1] of Byte;

begin

     move( seed[0], extseed[0], KYBER_SYMBYTES);
     extseed[KYBER_SYMBYTES] := x;
     extseed[KYBER_SYMBYTES + 1] := y;

     shake128_absorb_once(state, @extseed[0], sizeof(extseed));
end;


///*************************************************
//* Name:        kyber_shake256_prf
//*
//* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
//*              and then generates outlen bytes of SHAKE256 output
//*
//* Arguments:   - uint8_t *out: pointer to output
//*              - size_t outlen: number of requested output bytes
//*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
//*              - uint8_t nonce: single-byte nonce (public PRF input)
//**************************************************/
procedure kyber_shake256_prf( output : PByte; outLen : integer; const key : TKyberSymBytes; nonce : Byte);
var extkey : Array[0..KYBER_SYMBYTES] of Byte;
begin
     move(key[0], extkey[0], KYBER_SYMBYTES);
     extkey[KYBER_SYMBYTES] := nonce;

     shake256(output, outlen, @extkey[0], sizeof(extkey));
end;

///*************************************************
//* Name:        kyber_shake256_prf
//*
//* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
//*              and then generates outlen bytes of SHAKE256 output
//*
//* Arguments:   - uint8_t *out: pointer to output
//*              - size_t outlen: number of requested output bytes
//*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
//*              - uint8_t nonce: single-byte nonce (public PRF input)
//**************************************************/
procedure kyber_shake256_rkprf(KYBER_CIPHERTEXTBYTES : integer; output : PByte; const key : TKyberSymBytes; input : PByte);
var s : TKeccakState;
begin
     shake256_init(s);
     shake256_absorb(s, @key[0], KYBER_SYMBYTES);
     shake256_absorb(s, input, KYBER_CIPHERTEXTBYTES);
     shake256_finalize(s);
     shake256_squeeze(output, KYBER_SSBYTES, s);
end;

// ###########################################
// #### Poly.c
// ###########################################

///*************************************************
//* Name:        poly_compress
//*
//* Description: Compression and subsequent serialization of a polynomial
//*
//* Arguments:   - uint8_t *r: pointer to output byte array
//*                            (of length KYBER_POLYCOMPRESSEDBYTES)
//*              - const poly *a: pointer to input polynomial
//**************************************************/
procedure poly_compress(KYBER_POLYCOMPRESSEDBYTES : Integer; var r; const a : TKyberPoly);
var i, j : integer;
    u : Int16;
    d0 : UInt32;
    t : Array[0..7] of Byte;
    pR : P4Bytes;
    pR1 : P5Bytes;
begin
     if KYBER_POLYCOMPRESSEDBYTES = 128 then
     begin
          pR := @r;

          for i := 0 to KYBER_N div 8 - 1 do
          begin
               for j := 0 to 7 do
               begin
                    // map to positive standard represnatatives
                    u := a.Coeffs[8*i + j];
                    u := u + Int16( Integer(u) shr 15) and KYBER_Q;  // arhitmetic shift
                    //    t[j] = ((((uint16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15;
                    d0 := UInt32(u shl 4);
                    inc(d0, 1665);
                    d0 := UInt32( UInt64(d0)*80635 );
                    d0 := d0 shr 28;
                    t[j] := d0 and $0F;
               end;

               pR^[0] := Byte( t[0] or (t[1] shl 4) );
               pR^[1] := Byte( t[2] or (t[3] shl 4) );
               pR^[2] := Byte( t[4] or (t[5] shl 4) );
               pR^[3] := Byte( t[6] or (t[7] shl 4) );

               inc(pR);
          end;
     end
     else if KYBER_POLYCOMPRESSEDBYTES = 160 then
     begin
          pR1 := @r;
          for i := 0 to KYBER_N div 8 - 1 do
          begin
               for j := 0 to 7 do
               begin
                    // map to positive standard represnatatives
                    u := a.Coeffs[8*i + j];
                    u := u + Int16( Integer(u) shr 15) and KYBER_Q;
                    //  t[j] = ((((uint32_t)u << 5) + KYBER_Q/2)/KYBER_Q) & 31;
                    d0 := UInt32(u shl 5);
                    inc(d0, 1664);
                    d0 := UInt32( UInt64(d0)*40318 );
                    d0 := d0 shr 27;
                    t[j] := d0 and $1F;
               end;

               pR1^[0] := Byte( (t[0] shr 0) or (t[1] shl 5) );
               pR1^[1] := Byte( (t[1] shr 3) or (t[2] shl 2) or (t[3] shl 7) );
               pR1^[2] := Byte( (t[3] shr 1) or (t[4] shl 4) );
               pR1^[3] := Byte( (t[4] shr 4) or (t[5] shl 1) or (t[6] shl 6) );
               pR1^[4] := Byte( (t[6] shr 2) or (t[7] shl 3) );
               inc(pR1);
          end;

     end
     else
         raise Exception.Create('KYBER_POLYCOMPRESSEDBYTES needs to be 128 or 160');
end;

///*************************************************
//* Name:        poly_decompress
//*
//* Description: De-serialization and subsequent decompression of a polynomial;
//*              approximate inverse of poly_compress
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const uint8_t *a: pointer to input byte array
//*                                  (of length KYBER_POLYCOMPRESSEDBYTES bytes)
//**************************************************/
procedure poly_decompress(KYBER_POLYCOMPRESSEDBYTES : integer; var r : TKyberPoly; const a );
var i, j : integer;
    t : Array[0..7] of Byte;
    pA : PByte;
    pA1 : P5Bytes;
begin
     if KYBER_POLYCOMPRESSEDBYTES = 128 then
     begin
          pA := @a;
          for i := 0 to KYBER_N div 2 - 1 do
          begin
               r.Coeffs[2*i] := ( (UInt16(pA^ and $0F)*KYBER_Q) + 8) shr 4;
               r.Coeffs[2*i + 1] := ((UInt16(pA^ shr 4)*KYBER_Q) + 8) shr 4;
               inc(pA);
          end;
     end
     else if KYBER_POLYCOMPRESSEDBYTES = 160 then
     begin
          pA1 := @a;
          for i := 0 to KYBER_N div 8 - 1 do
          begin
               t[0] := pA1^[0] shr 0;
               t[1] := (pA1^[0] shr 5) or Byte(pA1^[1] shl 3);
               t[2] := (pA1^[1] shr 2);
               t[3] := (pA1^[1] shr 7) or Byte(pA1^[2] shl 1);
               t[4] := (pA1^[2] shr 4) or Byte(pA1^[3] shl 4);
               t[5] := (pA1^[3] shr 1);
               t[6] := (pA1^[3] shr 6) or Byte(pA1^[4] shl 2);
               t[7] := (pA1^[4] shr 3);
               inc(pA1);

               for j := 0 to 7 do
                   r.Coeffs[8*i + j] := (UInt32(t[j] and $1F)*KYBER_Q + $10) shr 5;
          end;
     end
     else
         raise Exception.Create('KYBER_POLYCOMPRESSEDBYTES needs to be (128, 160)');
end;

///*************************************************
//* Name:        poly_tobytes
//*
//* Description: Serialization of a polynomial
//*
//* Arguments:   - uint8_t *r: pointer to output byte array
//*                            (needs space for KYBER_POLYBYTES bytes)
//*              - const poly *a: pointer to input polynomial
//**************************************************/
procedure poly_tobytes( var r; const a : TKyberPoly);
var i : integer;
    t0, t1 : UInt16;
    pR : P3Bytes;
begin
     pR := @r;
     for i := 0 to KYBER_N div 2 - 1 do
     begin
          t0 := UInt16(a.Coeffs[2*i]);
          t0 := UInt16(Integer(t0) +  (Integer( Int16(t0) ) shr 15) and KYBER_Q); // note: constuct overflows
          t1 := UInt16(a.Coeffs[2*i + 1]);
          t1 := UInt16(Integer(t1) + (Integer( Int16(t1) ) shr 15) and KYBER_Q);

          pR^[0] := Byte(t0);
          pR^[1] := Byte( (t0 shr 8) or (t1 shl 4) );
          pR^[2] := Byte( t1 shr 4 );

          inc(pR);
     end;
end;

///*************************************************
//* Name:        poly_frombytes
//*
//* Description: De-serialization of a polynomial;
//*              inverse of poly_tobytes
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const uint8_t *a: pointer to input byte array
//*                                  (of KYBER_POLYBYTES bytes)
//**************************************************/
procedure poly_frombytes(var r : TKyberPoly; const a);
var pA : P3Bytes;
    i : integer;
begin
     pA := @a;
     for i := 0 to KYBER_N div 2 - 1 do
     begin
          r.Coeffs[2*i]     := ((pA^[0] shr 0) or (UInt16(pA^[1]) shl 8)) and $FFF;
          r.Coeffs[2*i + 1] := ((Byte( Int16(pA^[1]) shr 4) ) or (UInt16(pA^[2]) shl 4)) and $FFF;

          inc(pA);
     end;
end;

///*************************************************
//* Name:        poly_frommsg
//*
//* Description: Convert 32-byte message to polynomial
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const uint8_t *msg: pointer to input message
//**************************************************/
procedure poly_frommsg( var r : TKyberPoly; const msg : TKyberINDCPMsgBytes);
var i, j : integer;
begin
     Assert( KYBER_INDCPA_MSGBYTES = KYBER_N div 8, 'KYBER_INDCPA_MSGBYTES must be equal to KYBER_N div 8');

     for i := 0 to KYBER_N div 8 - 1 do
     begin
          for j := 0 to 8 - 1 do
          begin
               r.Coeffs[8*i + j] := 0;

               cmov_int16( r.Coeffs[8*i + j], (KYBER_Q + 1) div 2, (msg[i] shr j) and $01);
          end;
     end;
end;

///*************************************************
//* Name:        poly_tomsg
//*
//* Description: Convert polynomial to 32-byte message
//*
//* Arguments:   - uint8_t *msg: pointer to output message
//*              - const poly *a: pointer to input polynomial
//**************************************************/
procedure poly_tomsg( var msg : TKyberINDCPMsgBytes; const a : TKyberPoly);
var i, j : integer;
    t : UInt32;
begin
     for i := 0 to KYBER_N div 8 - 1 do
     begin
          msg[i] := 0;
          for j := 0 to 8 - 1 do
          begin
               t := UInt32(a.Coeffs[8*i + j]);
               t := t shl 1;
               t := UInt32( UInt64(t) + 1665 );
               t := UInt32( UInt64(t)*80635 );
               t := t shr 28;
               t := t and 1;
               msg[i] := msg[i] or (t shl j);
          end;
     end;
end;

///*************************************************
//* Name:        poly_getnoise_eta1
//*
//* Description: Sample a polynomial deterministically from a seed and a nonce,
//*              with output polynomial close to centered binomial distribution
//*              with parameter KYBER_ETA1
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const uint8_t *seed: pointer to input seed
//*                                     (of length KYBER_SYMBYTES bytes)
//*              - uint8_t nonce: one-byte input nonce
//**************************************************/
procedure poly_getnoise_eta1(eta1 : integer; var r : TKyberPoly; const seed : TKyberSymBytes; nonce : Byte);
var buf : Array[0..768 div 4 - 1] of Byte;  // maximum buffer for eta=3
begin
     Assert(eta1 in [2, 3], 'eta1 can only be 2 or 3');

     kyber_shake256_prf( @buf[0], eta1*KYBER_N div 4, seed, nonce);
     poly_cbd_eta1(eta1, r, @buf[0]);
end;

///*************************************************
//* Name:        poly_getnoise_eta2
//*
//* Description: Sample a polynomial deterministically from a seed and a nonce,
//*              with output polynomial close to centered binomial distribution
//*              with parameter KYBER_ETA2
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const uint8_t *seed: pointer to input seed
//*                                     (of length KYBER_SYMBYTES bytes)
//*              - uint8_t nonce: one-byte input nonce
//**************************************************/
procedure poly_getnoise_eta2( var r : TKyberPoly; const seed : TKyberSymBytes; nonce : Byte);
var buf : Array[0..512 div 4 - 1] of byte; //KYBER_ETA2*KYBER_N/4-1] of byte;
begin
     kyber_shake256_prf(@buf[0], KYBER_ETA2*KYBER_N div 4, seed, nonce);
     poly_cbd_eta2(r, @buf[0]);
end;

///*************************************************
//* Name:        poly_invntt_tomont
//*
//* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
//*              of a polynomial in place;
//*              inputs assumed to be in bitreversed order, output in normal order
//*
//* Arguments:   - uint16_t *a: pointer to in/output polynomial
//**************************************************/
procedure poly_invntt_tomont( var r : TKyberPoly);
begin
     invntt(r.Coeffs);
end;

///*************************************************
//* Name:        poly_basemul_montgomery
//*
//* Description: Multiplication of two polynomials in NTT domain
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const poly *a: pointer to first input polynomial
//*              - const poly *b: pointer to second input polynomial
//**************************************************/
procedure poly_basemul_montgomery(var r : TKyberPoly; const a, b : TKyberPoly);
var i : integer;
begin
     for i := 0 to KYBER_N div 4 - 1 do
     begin
          basemul( @r.Coeffs[4*i + 0], @a.Coeffs[4*i], @b.Coeffs[4*i], zetas[64 + i]);
          basemul( @r.Coeffs[4*i + 2], @a.Coeffs[4*i + 2], @b.Coeffs[4*i + 2], -zetas[64 + i]);
     end;
end;

///*************************************************
//* Name:        poly_tomont
//*
//* Description: Inplace conversion of all coefficients of a polynomial
//*              from normal domain to Montgomery domain
//*
//* Arguments:   - poly *r: pointer to input/output polynomial
//**************************************************/
procedure poly_tomont(var r : TKyberPoly);
var i : integer;
    f : UInt16;
begin
     f := UInt16(UInt64(1) shl 32 mod KYBER_Q);

     for i := 0 to KYBER_N - 1 do
         r.Coeffs[i] := montgomery_reduce( Int32(r.Coeffs[i])*f );
end;

///*************************************************
//* Name:        poly_reduce
//*
//* Description: Applies Barrett reduction to all coefficients of a polynomial
//*              for details of the Barrett reduction see comments in reduce.c
//*
//* Arguments:   - poly *r: pointer to input/output polynomial
//**************************************************/
procedure poly_reduce( var r : TKyberPoly );
var i : integer;
begin
     for i := 0 to KYBER_N - 1 do
         r.Coeffs[i] := barrett_reduce( r.Coeffs[i] );
end;

///*************************************************
//* Name:        poly_ntt
//*
//* Description: Computes negacyclic number-theoretic transform (NTT) of
//*              a polynomial in place;
//*              inputs assumed to be in normal order, output in bitreversed order
//*
//* Arguments:   - uint16_t *r: pointer to in/output polynomial
//**************************************************/
procedure poly_ntt(var r : TKyberPoly);
begin
     ntt(r.Coeffs);
     poly_reduce(r);
end;

///*************************************************
//* Name:        poly_add
//*
//* Description: Add two polynomials; no modular reduction is performed
//*
//* Arguments: - poly *r: pointer to output polynomial
//*            - const poly *a: pointer to first input polynomial
//*            - const poly *b: pointer to second input polynomial
//**************************************************/
procedure poly_add(var r : TKyberPoly; const a, b : TKyberPoly);
var i : integer;
begin
     for i := 0 to KYBER_N - 1 do
         r.Coeffs[i] := a.Coeffs[i] + b.Coeffs[i];
end;

///*************************************************
//* Name:        poly_sub
//*
//* Description: Subtract two polynomials; no modular reduction is performed
//*
//* Arguments: - poly *r:       pointer to output polynomial
//*            - const poly *a: pointer to first input polynomial
//*            - const poly *b: pointer to second input polynomial
//**************************************************/

procedure poly_sub(var r : TKyberPoly; const a, b : TKyberPoly);
var i : integer;
begin
     for i := 0 to KYBER_N - 1 do
         r.Coeffs[i] := a.Coeffs[i] - b.Coeffs[i];
end;

// ###########################################
// #### polyvec.c
// ###########################################

///*************************************************
//* Name:        polyvec_compress
//*
//* Description: Compress and serialize vector of polynomials
//*
//* Arguments:   - uint8_t *r: pointer to output byte array
//*                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
//*              - const polyvec *a: pointer to input vector of polynomials
//**************************************************/

type
  TR11 = Array[0..10] of Byte;
  PR11 = ^TR11;
  TR5 = Array[0..4] of Byte;
  PR5 = ^TR5;

procedure polyvec_compress(KYBER_POLYVECCOMPRESSEDBYTES, KYBER_K : Integer; var r; const a : TKyberPolyVec);
var i, j, k : Integer;
    t : Array[0..7] of UInt16;
    d0 : UInt64;
    pR : PR11;
    pR1 : PR5;
begin
     if KYBER_POLYVECCOMPRESSEDBYTES = KYBER_K*352 then
     begin
          pR := @r;
          for i := 0 to KYBER_K - 1 do
          begin
               for j := 0 to KYBER_N div 8 - 1 do
               begin
                    for k := 0 to High(t) do
                    begin
                         t[k] := UInt16(a.vec[i].Coeffs[8*j + k]);
                         t[k] := UInt16( UInt32( t[k] ) + UInt32( (Integer( Int16( t[k] ) ) shr 15) and KYBER_Q));
                        // t[k] := UInt16((( uint32(t[k]) shl 11) + KYBER_Q div 2) div KYBER_Q) and $7FF;
                         d0 := t[k];
                         d0 := d0 shl 11;
                         inc(d0, 1664);
                         d0 := d0*645084;
                         d0 := d0 shr 31;
                         t[k] := UInt16( d0 and $7ff );
                    end;

                    pR^[ 0] := Byte((t[0] shr  0));
                    pR^[ 1] := Byte((t[0] shr  8) or (t[1] shl 3));
                    pR^[ 2] := Byte((t[1] shr  5) or (t[2] shl 6));
                    pR^[ 3] := Byte((t[2] shr  2));
                    pR^[ 4] := Byte((t[2] shr 10) or (t[3] shl 1));
                    pR^[ 5] := Byte((t[3] shr  7) or (t[4] shl 4));
                    pR^[ 6] := Byte((t[4] shr  4) or (t[5] shl 7));
                    pR^[ 7] := Byte((t[5] shr  1));
                    pR^[ 8] := Byte((t[5] shr  9) or (t[6] shl 2));
                    pR^[ 9] := Byte((t[6] shr  6) or (t[7] shl 5));
                    pR^[10] := Byte((t[7] shr  3));
                    inc(pR);
               end;
          end;
     end
     else if KYBER_POLYVECCOMPRESSEDBYTES = (KYBER_K * 320)  then
     begin
          pR1 := PR5(@r);
          for i := 0 to KYBER_K - 1 do
          begin
               for j := 0 to KYBER_N div 4 - 1 do
               begin
                    for k := 0 to 3 do
                    begin
                         t[k] := UInt16(a.vec[i].Coeffs[4*j + k]);
                         t[k] := UInt16( UInt32(t[k]) + UInt32( Integer( Int16( t[k] ) ) shr 15) and KYBER_Q );
                         //t[k] := UInt16((( uint32(t[k]) shl 10) + KYBER_Q div 2) div KYBER_Q) and $3FF;
                         d0 := t[k];
                         d0 := d0 shl 10;
                         inc(d0, 1665);
                         d0 := d0*1290167;
                         d0 := d0 shr 32;
                         t[k] := UInt16( d0 and $3ff );
                    end;

                    pR1^[ 0] := Byte(t[0] shr 0);
                    pR1^[ 1] := Byte((t[0] shr 8) or (t[1] shl 2));
                    pR1^[ 2] := Byte((t[1] shr 6) or (t[2] shl 4));
                    pR1^[ 3] := Byte((t[2] shr 4) or (t[3] shl 6));
                    pR1^[ 4] := Byte(t[3] shr 2);
                    inc(pR1);
               end;
          end;
     end
     else
         raise Exception.Create('Error KYBER_POLYVECCOMPRESSEDBYTES needs to be 3*352 or 3*320');
end;


///*************************************************
//* Name:        polyvec_decompress
//*
//* Description: De-serialize and decompress vector of polynomials;
//*              approximate inverse of polyvec_compress
//*
//* Arguments:   - polyvec *r:       pointer to output vector of polynomials
//*              - const uint8_t *a: pointer to input byte array
//*                                  (of length KYBER_POLYVECCOMPRESSEDBYTES)
//**************************************************/
//void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES])
procedure polyvec_decompress(KYBER_POLYVECCOMPRESSEDBYTES, KYBER_K : Integer;
  var r : TKyberPolyVec; const a : TKyberPolyCompressedBytes);
var i, j, k : integer;
    t : Array[0..7] of UInt16;
    pA : PR11;
    pA1 : PR5;
begin
     if KYBER_POLYVECCOMPRESSEDBYTES = KYBER_K*352 then
     begin
          pA := @a[0];
          for i := 0 to KYBER_K - 1 do
          begin
               for j := 0 to KYBER_N div 8 - 1 do
               begin
                    t[0] := (pA^[0] shr 0) or (uint16(pA^[ 1]) shl 8);
                    t[1] := (pA^[1] shr 3) or (uint16(pA^[ 2]) shl 5);
                    t[2] := (pA^[2] shr 6) or (UInt16(pA^[ 3]) shl 2) or UInt16( (UInt16(pA^[4]) shl 10) );
                    t[3] := (pA^[4] shr 1) or (UInt16(pA^[ 5]) shl 7);
                    t[4] := (pA^[5] shr 4) or (UInt16(pA^[ 6]) shl 4);
                    t[5] := (pA^[6] shr 7) or (UInt16(pA^[ 7]) shl 1) or UInt16( (UInt16(pA^[8]) shl 9) );
                    t[6] := (pA^[8] shr 2) or (UInt16(pA^[ 9]) shl 6);
                    t[7] := (pA^[9] shr 5) or (UInt16(pA^[10]) shl 3);

                    inc(pA);
                    for k := 0 to 7 do
                        r.vec[i].Coeffs[8*j + k] := (UInt32(t[k] and $7FF)*KYBER_Q + 1024) shr 11;
               end;
          end;
     end
     else if KYBER_POLYVECCOMPRESSEDBYTES = (KYBER_K * 320) then
     begin
          pA1 := @a[0];

          for i := 0 to KYBER_K - 1 do
          begin
               for j := 0 to KYBER_N div 4 - 1 do
               begin
                    t[0] := (pA1^[0] shr 0) or (uint16(pA1^[ 1]) shl 8);
                    t[1] := (pA1^[1] shr 2) or (uint16(pA1^[ 2]) shl 6);
                    t[2] := (pA1^[2] shr 4) or (UInt16(pA1^[ 3]) shl 4);
                    t[3] := (pA1^[3] shr 6) or (UInt16(pA1^[ 4]) shl 2);

                    inc(pA1);
                    for k := 0 to 3 do
                        r.vec[i].Coeffs[4*j + k] := (UInt32(t[k] and $3FF)*KYBER_Q + 512) shr 10;
               end;
          end;

     end
     else
         raise Exception.Create('Kyber Polycompressbytes needs to be in (320*KYBER_K, 352*KYBER_K)');

end;

///*************************************************
//* Name:        polyvec_tobytes
//*
//* Description: Serialize vector of polynomials
//*
//* Arguments:   - uint8_t *r: pointer to output byte array
//*                            (needs space for KYBER_POLYVECBYTES)
//*              - const polyvec *a: pointer to input vector of polynomials
//**************************************************/
procedure polyvec_tobytes(KYBER_K : integer; var r; const a : TKyberPolyVec );
var i : integer;
    pR : PKyberPolyBytes;
begin
     pR := @r;
     for i := 0 to KYBER_K - 1 do
     begin
          poly_toBytes(pR^, a.vec[i]);
          inc(pR);
     end;
end;

///*************************************************
//* Name:        polyvec_frombytes
//*
//* Description: De-serialize vector of polynomials;
//*              inverse of polyvec_tobytes
//*
//* Arguments:   - uint8_t *r:       pointer to output byte array
//*              - const polyvec *a: pointer to input vector of polynomials
//*                                  (of length KYBER_POLYVECBYTES)
//**************************************************/
procedure polyvec_frombytes(KYBER_K : integer; var r : TKyberPolyVec; const a );
var i : integer;
    pA : PKyberPolyBytes;
begin
     pA := @a;
     for i := 0 to KYBER_K - 1 do
     begin
          poly_fromBytes(r.vec[i], pA^);
          inc(pA);
     end;
end;

///*************************************************
//* Name:        polyvec_ntt
//*
//* Description: Apply forward NTT to all elements of a vector of polynomials
//*
//* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
//**************************************************/
//void polyvec_ntt(polyvec *r)
procedure polyvec_ntt(KYBER_K : integer; var r : TKyberPolyVec);
var i : integer;
begin
     for i := 0 to KYBER_K - 1 do
         poly_ntt(r.vec[i]);
end;

///*************************************************
//* Name:        polyvec_invntt_tomont
//*
//* Description: Apply inverse NTT to all elements of a vector of polynomials
//*              and multiply by Montgomery factor 2^16
//*
//* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
//**************************************************/
procedure polyvec_invntt_tomont(KYBER_K : integer; var r : TKyberPolyVec);
var i : integer;
begin
     for i := 0 to KYBER_K - 1 do
         poly_invntt_tomont(r.vec[i]);
end;

///*************************************************
//* Name:        polyvec_basemul_acc_montgomery
//*
//* Description: Multiply elements of a and b in NTT domain, accumulate into r,
//*              and multiply by 2^-16.
//*
//* Arguments: - poly *r: pointer to output polynomial
//*            - const polyvec *a: pointer to first input vector of polynomials
//*            - const polyvec *b: pointer to second input vector of polynomials
//**************************************************/
procedure polyvec_basemul_acc_montgomery(KYBER_K : integer; var r : TKyberPoly; const a, b : TKyberPolyVec);
var i : integer;
    t : TKyberPoly;
begin
     poly_basemul_montgomery(r, a.vec[0], b.vec[0]);

     for i := 1 to KYBER_K - 1 do
     begin
          poly_basemul_montgomery(t, a.vec[i], b.vec[i]);
          poly_add(r, r, t);
     end;

     poly_reduce(r);
end;

///*************************************************
//* Name:        polyvec_reduce
//*
//* Description: Applies Barrett reduction to each coefficient
//*              of each element of a vector of polynomials;
//*              for details of the Barrett reduction see comments in reduce.c
//*
//* Arguments:   - polyvec *r: pointer to input/output polynomial
//**************************************************/
procedure polyvec_reduce(KYBER_K : integer; var r : TKyberPolyVec);
var i : integer;
begin
     for i := 0 to KYBER_K - 1 do
         poly_reduce(r.vec[i]);
end;

///*************************************************
//* Name:        polyvec_add
//*
//* Description: Add vectors of polynomials
//*
//* Arguments: - polyvec *r: pointer to output vector of polynomials
//*            - const polyvec *a: pointer to first input vector of polynomials
//*            - const polyvec *b: pointer to second input vector of polynomials
//**************************************************/
procedure polyvec_add(KYBER_K : integer; var r : TKyberPolyVec; const a, b : TKyberPolyVec);
var i : integer;
begin
     for i := 0 to KYBER_K - 1 do
         poly_add(r.vec[i], a.vec[i], b.vec[i]);
end;

// ###########################################
// #### INDCPA.c
// ###########################################

///*************************************************
//* Name:        pack_pk
//*
//* Description: Serialize the public key as concatenation of the
//*              serialized vector of polynomials pk
//*              and the public seed used to generate the matrix A.
//*
//* Arguments:   uint8_t *r: pointer to the output serialized public key
//*              polyvec *pk: pointer to the input public-key polyvec
//*              const uint8_t *seed: pointer to the input public seed
//**************************************************/
procedure pack_pk(const params : TKyberParams; var r : TKyberINDCPAPublicKeyBytes; const pk : TKyberPolyVec; const seed : TKyberSymBytes );
begin
     polyvec_tobytes(params.K, r, pk);
     Move( seed[0], r[params.PolyVecSize], KYBER_SYMBYTES);
end;

///*************************************************
//* Name:        unpack_pk
//*
//* Description: De-serialize public key from a byte array;
//*              approximate inverse of pack_pk
//*
//* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
//*              - uint8_t *seed: pointer to output seed to generate matrix A
//*              - const uint8_t *packedpk: pointer to input serialized public key
//**************************************************/
procedure unpack_pk(const params : TKyberParams; var pk : TKyberPolyVec; var seed : TKyberSymBytes; const packedpk : TKyberINDCPAPublicKeyBytes);
begin
     polyvec_frombytes(params.K, pk, packedpk);
     move( packedpk[params.PolyVecSize], seed,  KYBER_SYMBYTES);
end;

///*************************************************
//* Name:        pack_sk
//*
//* Description: Serialize the secret key
//*
//* Arguments:   - uint8_t *r: pointer to output serialized secret key
//*              - polyvec *sk: pointer to input vector of polynomials (secret key)
//**************************************************/
procedure pack_sk(const params : TKyberParams; var r : TKyberINDCPASecretKeyBytes; const sk : TKyberPolyVec);
begin
     polyvec_tobytes(params.K, r, sk);
end;

///*************************************************
//* Name:        unpack_sk
//*
//* Description: De-serialize the secret key; inverse of pack_sk
//*
//* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
//*              - const uint8_t *packedsk: pointer to input serialized secret key
//**************************************************/
procedure unpack_sk(const params : TKyberParams; var sk : TKyberPolyVec; const packedsk : TKyberINDCPASecretKeyBytes);
begin
     polyvec_frombytes(params.K, sk, packedsk);
end;

///*************************************************
//* Name:        pack_ciphertext
//*
//* Description: Serialize the ciphertext as concatenation of the
//*              compressed and serialized vector of polynomials b
//*              and the compressed and serialized polynomial v
//*
//* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
//*              poly *pk: pointer to the input vector of polynomials b
//*              poly *v: pointer to the input polynomial v
//**************************************************/
procedure pack_ciphertext(const params : TKyberParams;
 var r : TKyberINDCPABytes; const b : TKyberPolyVec; const v : TKyberPoly);
begin
     polyvec_compress(params.PolyVecCompressedBytes, params.K,  r, b);
     //poly_compress(KYBER_POLYVECCOMPRESSEDBYTES, r[KYBER_POLYVECCOMPRESSEDBYTES], v);
     poly_compress(params.PolyCompressedBytes, r[params.PolyVecCompressedBytes], v);
end;

///*************************************************
//* Name:        unpack_ciphertext
//*
//* Description: De-serialize and decompress ciphertext from a byte array;
//*              approximate inverse of pack_ciphertext
//*
//* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
//*              - poly *v: pointer to the output polynomial v
//*              - const uint8_t *c: pointer to the input serialized ciphertext
//**************************************************/
procedure unpack_ciphertext(const params : TKyberParams;
  var b : TKyberPolyVec; var v : TKyberPoly; const c);
var pC : PKyberPolyCompressedBytes;
begin
     pC := @c;
     polyvec_decompress(params.PolyVecCompressedBytes, params.K, b, pC^);
     inc(PByte(pC), params.PolyVecCompressedBytes);
     poly_decompress(params.PolyCompressedBytes, v, pC^);
end;

///*************************************************
//* Name:        rej_uniform
//*
//* Description: Run rejection sampling on uniform random bytes to generate
//*              uniform random integers mod q
//*
//* Arguments:   - int16_t *r: pointer to output buffer
//*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
//*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
//*              - unsigned int buflen: length of input buffer in bytes
//*
//* Returns number of sampled 16-bit integers (at most len)
//**************************************************/

function rej_uniform( r : PInt16; len : LongWord; buf : PByte; bufLen : LongWord ) : LongWord;
var pos : LongWord;
    val0, val1 : UInt16;
    pBuf : P3Bytes;
begin
     Result := 0;
     pos := 0;
     pBuf := P3Bytes(buf);
     while (Result < len) and (pos + 3 <= bufLen) do
     begin
          val0 := (( pBuf^[0] shr 0) or (UInt16(pBuf^[1] shl 8))) and $0FFF;
          val1 := (( pBuf^[1] shr 4) or (UInt16(pBuf^[2] shl 4))) and $0FFF;
          inc(pBuf);
          inc(pos, 3);

          if val0 < KYBER_Q then
          begin
               r^ := val0;
               inc(r);
               inc(Result);
          end;
          if (Result < len) and (val1 < KYBER_Q) then
          begin
               r^ := val1;
               inc(r);
               inc(Result);
          end;
     end;
end;

///*************************************************
//* Name:        gen_matrix
//*
//* Description: Deterministically generate matrix A (or the transpose of A)
//*              from a seed. Entries of the matrix are polynomials that look
//*              uniformly random. Performs rejection sampling on output of
//*              a XOF
//*
//* Arguments:   - polyvec *a: pointer to ouptput matrix A
//*              - const uint8_t *seed: pointer to input seed
//*              - int transposed: boolean deciding whether A or A^T is generated
//**************************************************/
procedure gen_matrix(KYBER_K : integer; a : PKyberPolyVec; var seed : TKyberSymBytes; transposed : boolean);
var ctr, i, j : UInt32;
    buflen : UInt32;
    buf : Array[0..640-1] of Byte; //[0..GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES-1] of Byte;
    state : TKeccakState;
    pCoeff : PInt16;
    ci : integer;
begin
     for i := 0 to KYBER_K - 1 do
     begin
          for j := 0 to KYBER_K - 1 do
          begin
               if transposed
               then
                   kyber_shake128_absorb(state, seed, i, j)
               else
                   kyber_shake128_absorb(state, seed, j, i);

               shake128_squeezeblocks(@buf[0], GEN_MATRIX_NBLOCKS, state);
               buflen := GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
               ctr := rej_uniform(@a^.vec[j].coeffs[0], KYBER_N, @buf[0], buflen);

               pCoeff := @a^.vec[j].coeffs[0];
               inc(pCoeff, ctr);
               while ctr < KYBER_N do
               begin
                    shake128_squeezeblocks(@buf[0], 1, state);
                    bufLen := XOF_BLOCKBYTES;

                    ci := rej_uniform(pCoeff, KYBER_N - ctr, @buf[0], buflen);
                    inc(pCoeff, ci);
                    inc(ctr, ci);
               end;

          end;
          inc(a);
     end;
end;

///*************************************************
//* Name:        indcpa_keypair_derand
//*
//* Description: Generates public and private key for the CPA-secure
//*              public-key encryption scheme underlying Kyber
//*
//* Arguments:   - uint8_t *pk: pointer to output public key
//*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
//*              - uint8_t *sk: pointer to output private key
//*                             (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
//*              - const uint8_t *coins: pointer to input randomness
//*                             (of length KYBER_SYMBYTES bytes)
//**************************************************/

procedure indcpa_keypair_derand( const params : TKyberParams;
                                 var pk : TKyberINDCPAPublicKeyBytes;
                                 var sk : TKyberINDCPASecretKeyBytes;
                                 const coins : TKyberSymBytes);
var i : integer;
    buf : TKyberSymBytes2;
    publicseed : TKyberSymBytes absolute buf;
    noiseSeed : PKyberSymBytes;
    nonce : Byte;
    a : Array[0..KYBER_K_MAX - 1] of TKyberPolyVec;
    e, pkpv, skpv : TKyberPolyVec;
    hs : TSHA512Hash absolute buf;
begin
     FillChar(a, sizeof(a), 0);
     noiseSeed := @Buf[1][0];

     move(coins[0], buf[0], KYBER_SYMBYTES);
     buf[1][0] := params.K;
     sha3_512( hs, @buf[0][0], KYBER_SYMBYTES + 1);

     gen_matrix(params.K, @a[0], publicseed, False);
     nonce := 0;

     for i := 0 to params.K - 1 do
     begin
          poly_getnoise_eta1(params.ETA1, skpv.vec[i], noiseseed^, nonce);
          inc(nonce);
     end;
     for i := 0 to params.K - 1 do
     begin
          poly_getnoise_eta1(params.ETA1, e.vec[i], noiseseed^, nonce);
          inc(nonce);
     end;

     polyvec_ntt(params.K, skpv);
     polyvec_ntt(params.K, e);

     // matrix vector mult
     for i := 0 to params.K - 1 do
     begin
          polyvec_basemul_acc_montgomery(params.K, pkpv.vec[i], a[i], skpv);
          poly_tomont(pkpv.vec[i]);
     end;

     polyvec_add(params.K, pkpv, pkpv, e);
     polyvec_reduce(params.K, pkpv);

     pack_sk(params, sk, skpv);
     pack_pk(params, pk, pkpv, publicseed);
end;

///*************************************************
//* Name:        indcpa_enc
//*
//* Description: Encryption function of the CPA-secure
//*              public-key encryption scheme underlying Kyber.
//*
//* Arguments:   - uint8_t *c: pointer to output ciphertext
//*                            (of length KYBER_INDCPA_BYTES bytes)
//*              - const uint8_t *m: pointer to input message
//*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
//*              - const uint8_t *pk: pointer to input public key
//*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
//*              - const uint8_t *coins: pointer to input random coins used as seed
//*                                      (of length KYBER_SYMBYTES) to deterministically
//*                                      generate all randomness
//**************************************************/
procedure indcpa_enc( const params : TKyberParams; var c : TKyberINDCPABytes; const m : TKyberINDCPMsgBytes;
                      const pk : TKyberINDCPAPublicKeyBytes; const coins : TKyberSymBytes);
var i : integer;
    seed : TKyberSymBytes;
    nonce : Byte;
    sp, pkpv, ep, b : TKyberPolyVec;
    at : Array[0..KYBER_K_MAX-1] of TKyberPolyVec;
    v, k, epp : TKyberPoly;
begin
     nonce := 0;

     unpack_pk(params, pkpv, seed, pk);
     poly_frommsg( k, m );
     gen_matrix(params.K, @at[0], seed, True);

     for i := 0 to params.K - 1 do
     begin
          poly_getnoise_eta1(params.ETA1, sp.vec[i], coins, nonce);
          inc(nonce);
     end;
     for i := 0 to params.K - 1 do
     begin
          poly_getnoise_eta2( ep.vec[i], coins, nonce);
          inc(nonce);
     end;

     poly_getnoise_eta2( epp, coins, nonce);
//     inc(nonce);

     polyvec_ntt(params.K, sp);

     // matrix vector multiplication
     for i := 0 to params.K - 1 do
         polyvec_basemul_acc_montgomery(params.K, b.vec[i], at[i], sp);
     polyvec_basemul_acc_montgomery(params.K, v, pkpv, sp);

     polyvec_invntt_tomont(params.K, b);
     poly_invntt_tomont(v);

     polyvec_add(params.K, b, b, ep);
     poly_add(v, v, epp);
     poly_add(v, v, k);
     polyvec_reduce(params.K, b);
     poly_reduce(v);

     pack_ciphertext(params, c, b, v);
end;

///*************************************************
//* Name:        indcpa_dec
//*
//* Description: Decryption function of the CPA-secure
//*              public-key encryption scheme underlying Kyber.
//*
//* Arguments:   - uint8_t *m: pointer to output decrypted message
//*                            (of length KYBER_INDCPA_MSGBYTES)
//*              - const uint8_t *c: pointer to input ciphertext
//*                                  (of length KYBER_INDCPA_BYTES)
//*              - const uint8_t *sk: pointer to input secret key
//*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
//**************************************************/
procedure indcpa_dec(const params : TKyberParams; var m : TKyberINDCPMsgBytes; const c : TKyberINDCPABytes;
  const sk : TKyberINDCPASecretKeyBytes);
var b, skpv : TKyberPolyVec;
    v, mp : TKyberPoly;
begin
     unpack_ciphertext(params, b, v, c[0]);
     unpack_sk(params, skpv, sk);

     polyvec_ntt(params.k, b);
     polyvec_basemul_acc_montgomery(params.K, mp, skpv, b);
     poly_invntt_tomont(mp);

     poly_sub(mp, v, mp);
     poly_reduce(mp);

     poly_tomsg(m, mp);
end;

// ###########################################
// #### kem.c
// ###########################################

///*************************************************
//* Name:        crypto_kem_keypair_derand
//*
//* Description: Generates public and private key
//*              for CCA-secure Kyber key encapsulation mechanism
//*
//* Arguments:   - uint8_t *pk: pointer to output public key
//*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
//*              - uint8_t *sk: pointer to output private key
//*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
//*              - uint8_t *coins: pointer to input randomness
//*                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes)
//**
//* Returns 0 (success)
//**************************************************/

function crypto_kem_keypair_derand_param(const params : TKyberParams; var pk : TKyberINDCPAPublicKeyBytes; var sk : TKyberSecretKeyBytes;
  const coins : TKyberSymBytes2) : integer;
var skb : TKyberINDCPASecretKeyBytes absolute sk;
    skSha : PSHA256Hash;
begin
     skSha := @sk[params.SecretKeySize (* KYBER_SECRETKEYBYTES *) - 2*KYBER_SYMBYTES];
     indcpa_keypair_derand(params, pk, skb, coins[0] );
     move( pk[0], sk[params.PolyvecSize (*KYBER_INDCPA_SECRETKEYBYTES*)], params.PublicKeySize); // KYBER_PUBLICKEYBYTES);
     sha3_256(skSha^, @pk[0], params.PublicKeySize); // KYBER_PUBLICKEYBYTES);
     move(coins[1][0], sk[params.SecretKeySize (*KYBER_INDCPA_SECRETKEYBYTES*) - KYBER_SYMBYTES], sizeof(coins[1]));
     Result := 0;
end;

function crypto_kem_keypair_derand(var pk : TKyberINDCPAPublicKeyBytes; var sk : TKyberSecretKeyBytes;
  const coins : TKyberSymBytes2) : integer;
begin
     Result := crypto_kem_keypair_derand_param(cKyber768Params, pk, sk, coins);
end;

///*************************************************
//* Name:        crypto_kem_keypair
//*
//* Description: Generates public and private key
//*              for CCA-secure Kyber key encapsulation mechanism
//*
//* Arguments:   - uint8_t *pk: pointer to output public key
//*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
//*              - uint8_t *sk: pointer to output private key
//*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
//*
//* Returns 0 (success)
//**************************************************/
function crypto_kem_keypair_param(const params : TKyberParams; var pk : TKyberPublicKeyBytes; var sk : TKyberSecretKeyBytes) : integer;
var coins : TKyberSymBytes2;
begin
     CryptRandom(coins[0][0], sizeof(coins));
     Result := crypto_kem_keypair_derand_param(params, pk, sk, coins);
end;

function crypto_kem_keypair(var pk : TKyberPublicKeyBytes; var sk : TKyberSecretKeyBytes) : integer;
begin
     Result := crypto_kem_keypair_param(cKyber768Params, pk, sk);
end;

///*************************************************
//* Name:        crypto_kem_enc_derand
//*
//* Description: Generates cipher text and shared
//*              secret for given public key
//*
//* Arguments:   - uint8_t *ct: pointer to output cipher text
//*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
//*              - uint8_t *ss: pointer to output shared secret
//*                (an already allocated array of KYBER_SSBYTES bytes)
//*              - const uint8_t *pk: pointer to input public key
//*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
//*              - const uint8_t *coins: pointer to input randomness
//*                (an already allocated array filled with KYBER_SYMBYTES random bytes)
//**
//* Returns 0 (success)
//**************************************************/
function crypto_kem_enc_derand_param(const params : TKyberParams; var ct : TKyberCipherTextBytes; var ss : TKyberSharedSecretBytes;
  const pk : TKyberPublicKeyBytes;
  const coins : TKyberSymBytes) : integer;
var buf : TKyberSymBytes2;
    // Will contain key, coins
    kr : TKyberSymBytes2;
    sh1 : PSHA256Hash;
    sh2 : PSHA512Hash;
begin
     move( coins, buf[0], sizeof(coins));

     sh1 := @buf[1][0];
     sh2 := @kr[0][0];

     // Multitarget countermeasure for coins + contributory KEM */
     sha3_256(sh1^, @pk[0], params.PublicKeySize);
     sha3_512(sh2^, @buf[0][0], 2*KYBER_SYMBYTES);

     indcpa_enc(params, ct, buf[0], pk, kr[1] );

     move(kr[0][0], ss[0], KYBER_SYMBYTES);
     Result := 0;
end;

///*************************************************
//* Name:        crypto_kem_enc
//*
//* Description: Generates cipher text and shared
//*              secret for given public key
//*
//* Arguments:   - uint8_t *ct: pointer to output cipher text
//*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
//*              - uint8_t *ss: pointer to output shared secret
//*                (an already allocated array of KYBER_SSBYTES bytes)
//*              - const uint8_t *pk: pointer to input public key
//*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
//*
//* Returns 0 (success)
//**************************************************/
function crypto_kem_enc_param(const params : TKyberParams; var ct : TKyberCipherTextBytes; var ss : TKyberSharedSecretBytes;
  const pk : TKyberPublicKeyBytes ) : integer;
var coins : TKyberSymBytes;
begin
     CryptRandom(coins[0], sizeof(coins));
     crypto_kem_enc_derand_param(params, ct, ss, pk, coins);
     Result := 0;
end;

///*************************************************
//* Name:        crypto_kem_dec
//*
//* Description: Generates shared secret for given
//*              cipher text and private key
//*
//* Arguments:   - uint8_t *ss: pointer to output shared secret
//*                (an already allocated array of KYBER_SSBYTES bytes)
//*              - const uint8_t *ct: pointer to input cipher text
//*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
//*              - const uint8_t *sk: pointer to input private key
//*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
//*
//* Returns 0.
//*
//* On failure, ss will contain a pseudo-random value.
//**************************************************/
function crypto_kem_dec_param(const params : TKyberParams; var ss : TKyberSharedSecretBytes; const ct : TKyberCipherTextBytes;
  const sk : TKyberSecretKeyBytes) : integer;
var valid : boolean;
    buf : TKyberSymBytes2;
    cmp : TKyberCipherTextBytes;
    pk : PKyberINDCPAPublicKeyBytes;
    kr : TKyberSymBytes2;
    c : TKyberINDCPABytes absolute cmp;
    sk1 : TKyberINDCPASecretKeyBytes absolute sk;
begin
     pk := @sk[params.PolyVecSize];  // KYBER_INDCPA_SECRETKEYBYTES];

     indcpa_dec(params, PKyberINDCPMsgBytes( @buf[0][0] )^, ct, sk1 );

     // Multitarget countermeasure for coins + contributory KEM
     move(sk[params.SecretKeySize - 2*KYBER_SYMBYTES], buf[1][0], KYBER_SYMBYTES);
     sha3_512( PSHA512Hash(@kr[0])^, @buf[0][0], 2*KYBER_SYMBYTES);

     // coins are in kr+KYBER_SYMBYTES
     indcpa_enc(params, c, PKyberINDCPMsgBytes( @buf[0] )^, pk^, kr[1] );
     valid := CompareMem(@ct[0], @cmp[0], params.CiphertextBytes); // KYBER_CIPHERTEXTBYTES);

     //Compute rejection key
     kyber_shake256_rkprf( params.PolyVecCompressedBytes + params.PolyCompressedBytes, @ss[0], PKyberSymBytes( @sk[ (*KYBER_SECRETKEYBYTES*)params.SecretKeySize - KYBER_SYMBYTES ] )^, @ct[0] );
     cmov(@ss[0], @kr[0], KYBER_SYMBYTES, Byte(valid));

     Result := 0;
end;

// ###########################################
// #### Interface functions
// ###########################################

function kyber768_kem_dec(var ss : TKyberSharedSecretBytes; const ct : TKyber768CipherTextBytes; const sk : TKyber768SecretKeyBytes) : integer;
var ct1 : TKyberCipherTextBytes;
    sk1 : TKyberSecretKeyBytes;
begin
     Move(ct, ct1, sizeof(ct));
     Move(sk, sk1, sizeof(sk));
     Result := crypto_kem_dec_param(cKyber768Params, ss, ct1, sk1);
end;

function kyber768_kem_enc( var ct : TKyber768CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber768PublicKeyBytes ) : integer;
var ct1 : TKyberCipherTextBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(ct, ct1, sizeof(ct));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_enc_param(cKyber768Params, ct1, ss, pk1);
     Move(ct1, ct, sizeof(ct));
end;

function kyber768_kem_enc_derand(var ct : TKyber768CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber768PublicKeyBytes; const coins : TKyberSymBytes) : integer;
var ct1 : TKyberCipherTextBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(ct, ct1, sizeof(ct));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_enc_derand_param(cKyber768Params, ct1, ss, pk1, coins);
     Move(ct1, ct, sizeof(ct));
end;

function kyber768_kem_keypair(var pk : TKyber768PublicKeyBytes; var sk : TKyber768SecretKeyBytes) : integer;
var sk1 : TKyberSecretKeyBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(sk, sk1, sizeof(sk));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_keypair_param(cKyber768Params, pk1, sk1);

     Move(sk1, sk, sizeof(sk));
     Move(pk1, pk, sizeof(pk));
end;

function kyber768_kem_keypair_derand(var pk : TKyber768PublicKeyBytes; var sk : TKyber768SecretKeyBytes; const coins : TKyberSymBytes2) : integer;
var sk1 : TKyberSecretKeyBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(sk, sk1, sizeof(sk));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_keypair_derand_param(cKyber768Params, pk1, sk1, coins);

     Move(sk1, sk, sizeof(sk));
     Move(pk1, pk, sizeof(pk));
end;

function kyber512_kem_dec(var ss : TKyberSharedSecretBytes; const ct : TKyber512CipherTextBytes; const sk : TKyber512SecretKeyBytes) : integer;
var ct1 : TKyberCipherTextBytes;
    sk1 : TKyberSecretKeyBytes;
begin
     Move(ct, ct1, sizeof(ct));
     Move(sk, sk1, sizeof(sk));
     Result := crypto_kem_dec_param(cKyber512Params, ss, ct1, sk1);
end;

function kyber512_kem_enc( var ct : TKyber512CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber512PublicKeyBytes ) : integer;
var ct1 : TKyberCipherTextBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(ct, ct1, sizeof(ct));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_enc_param(cKyber512Params, ct1, ss, pk1);
     Move(ct1, ct, sizeof(ct));
end;

function kyber512_kem_enc_derand(var ct : TKyber512CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber512PublicKeyBytes; const coins : TKyberSymBytes) : integer;
var ct1 : TKyberCipherTextBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(ct, ct1, sizeof(ct));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_enc_derand_param(cKyber512Params, ct1, ss, pk1, coins);
     Move(ct1, ct, sizeof(ct));
end;

function kyber512_kem_keypair(var pk : TKyber512PublicKeyBytes; var sk : TKyber512SecretKeyBytes) : integer;
var sk1 : TKyberSecretKeyBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(sk, sk1, sizeof(sk));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_keypair_param(cKyber512Params, pk1, sk1);

     Move(sk1, sk, sizeof(sk));
     Move(pk1, pk, sizeof(pk));
end;

function kyber512_kem_keypair_derand(var pk : TKyber512PublicKeyBytes; var sk : TKyber512SecretKeyBytes; const coins : TKyberSymBytes2) : integer;
var sk1 : TKyberSecretKeyBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(sk, sk1, sizeof(sk));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_keypair_derand_param(cKyber512Params, pk1, sk1, coins);

     Move(sk1, sk, sizeof(sk));
     Move(pk1, pk, sizeof(pk));
end;

function kyber1024_kem_dec(var ss : TKyberSharedSecretBytes; const ct : TKyber1024CipherTextBytes; const sk : TKyber1024SecretKeyBytes) : integer;
var ct1 : TKyberCipherTextBytes;
    sk1 : TKyberSecretKeyBytes;
begin
     Move(ct, ct1, sizeof(ct));
     Move(sk, sk1, sizeof(sk));
     Result := crypto_kem_dec_param(cKyber1024Params, ss, ct1, sk1);
end;

function kyber1024_kem_enc( var ct : TKyber1024CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber1024PublicKeyBytes ) : integer;
var ct1 : TKyberCipherTextBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(ct, ct1, sizeof(ct));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_enc_param(cKyber1024Params, ct1, ss, pk1);
     Move(ct1, ct, sizeof(ct));
end;

function kyber1024_kem_enc_derand(var ct : TKyber1024CipherTextBytes; var ss : TKyberSharedSecretBytes; const pk : TKyber1024PublicKeyBytes; const coins : TKyberSymBytes) : integer;
var ct1 : TKyberCipherTextBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(ct, ct1, sizeof(ct));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_enc_derand_param(cKyber1024Params, ct1, ss, pk1, coins);
     Move(ct1, ct, sizeof(ct));
end;

function kyber1024_kem_keypair(var pk : TKyber1024PublicKeyBytes; var sk : TKyber1024SecretKeyBytes) : integer;
var sk1 : TKyberSecretKeyBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(sk, sk1, sizeof(sk));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_keypair_param(cKyber1024Params, pk1, sk1);

     Move(sk1, sk, sizeof(sk));
     Move(pk1, pk, sizeof(pk));
end;

function kyber1024_kem_keypair_derand(var pk : TKyber1024PublicKeyBytes; var sk : TKyber1024SecretKeyBytes; const coins : TKyberSymBytes2) : integer;
var sk1 : TKyberSecretKeyBytes;
    pk1 : TKyberPublicKeyBytes;
begin
     Move(sk, sk1, sizeof(sk));
     Move(pk, pk1, sizeof(pk));

     Result := crypto_kem_keypair_derand_param(cKyber1024Params, pk1, sk1, coins);

     Move(sk1, sk, sizeof(sk));
     Move(pk1, pk, sizeof(pk));
end;

initialization
  GEN_MATRIX_NBLOCKS_X_XOF_BLOCKBYTES := ((12*KYBER_N div 8*(1 shl 12) div KYBER_Q + XOF_BLOCKBYTES));
  GEN_MATRIX_NBLOCKS := (GEN_MATRIX_NBLOCKS_X_XOF_BLOCKBYTES div XOF_BLOCKBYTES);

end.
