unit dilithium;

interface

// ###########################################
// #### Dilithium interface for 3 different parameter sets
// ###########################################


// ###########################################
// #### Dilithium 2

type
  TDilithium_2_PublicBytes = Array[0..1311] of Byte;
  TDilithium_2_SecretBytes = Array[0..2559] of Byte;
  TDilithium_2_SignatureBytes = Array[0..2419] of Byte;  // CRYPTO_BYTES

function pqcrystals_dilithium2_ref_keypair(var pk : TDilithium_2_PublicBytes; var sk : TDilithium_2_SecretBytes): boolean;
function pqcrystals_dilithium2_ref_signature( var sig : TDilithium_2_SignatureBytes; var siglen : integer; m : PByte; mlen : integer;
                                              ctx : PByte; ctxLen : integer; const sk : TDilithium_2_SecretBytes) : boolean;
function pqcrystals_dilithium2_ref_verify(const sig : TDilithium_2_SignatureBytes; siglen : integer;
                                          m : PByte; mlen : integer; ctx : PByte; ctxLen : integer;
                                          const pk : TDilithium_2_PublicBytes) : Boolean;

// signature + message in sigMessage
function pqcrystals_dilithium2_ref_sign( signedMessage : PByte; var smlen: integer; m : PByte; mlen : integer;
  ctx : PByte; ctxlen : integer; const sk : TDilithium_2_SecretBytes) : boolean;

function pqcrystals_dilithium2_ref_open( m : PByte; var mlen: integer; sigMessage : PByte; siglen : integer;
  ctx : PByte; ctxlen : integer; const pk : TDilithium_2_PublicBytes) : boolean;


// ###########################################
// #### Dilithium 3
type
  TDilithium_3_PublicBytes = Array[0..1951] of Byte;
  TDilithium_3_SecretBytes = Array[0..4031] of Byte;
  TDilithium_3_SignatureBytes = Array[0..3308] of Byte;  // CRYPTO_BYTES

function pqcrystals_dilithium3_ref_keypair(var pk : TDilithium_3_PublicBytes; var sk : TDilithium_3_SecretBytes): boolean;
function pqcrystals_dilithium3_ref_signature( var sig : TDilithium_3_SignatureBytes; var siglen : integer; m : PByte; mlen : integer;
                                              ctx : PByte; ctxLen : integer; const sk : TDilithium_3_SecretBytes) : boolean;
function pqcrystals_dilithium3_ref_verify(const sig : TDilithium_3_SignatureBytes; siglen : integer;
                                          m : PByte; mlen : integer; ctx : PByte; ctxLen : integer;
                                          const pk : TDilithium_3_PublicBytes) : Boolean;

// signature + message in sigMessage
function pqcrystals_dilithium3_ref_sign( signedMessage : PByte; var smlen: integer; m : PByte; mlen : integer;
  ctx : PByte; ctxlen : integer; const sk : TDilithium_3_SecretBytes) : boolean;

function pqcrystals_dilithium3_ref_open( m : PByte; var mlen: integer; sigMessage : PByte; siglen : integer;
  ctx : PByte; ctxlen : integer; const pk : TDilithium_3_PublicBytes) : boolean;


// ###########################################
// #### Dilithium 5
type
  TDilithium_5_PublicBytes = Array[0..2591] of Byte;
  TDilithium_5_SecretBytes = Array[0..4895] of Byte;
  TDilithium_5_SignatureBytes = Array[0..4626] of Byte;  // CRYPTO_BYTES

function pqcrystals_dilithium5_ref_keypair(var pk : TDilithium_5_PublicBytes; var sk : TDilithium_5_SecretBytes): boolean;
function pqcrystals_dilithium5_ref_signature( var sig : TDilithium_5_SignatureBytes; var siglen : integer; m : PByte; mlen : integer;
                                              ctx : PByte; ctxLen : integer; const sk : TDilithium_5_SecretBytes) : boolean;
function pqcrystals_dilithium5_ref_verify(const sig : TDilithium_5_SignatureBytes; siglen : integer;
                                          m : PByte; mlen : integer; ctx : PByte; ctxLen : integer;
                                          const pk : TDilithium_5_PublicBytes) : Boolean;

// signature + message in sigMessage
function pqcrystals_dilithium5_ref_sign( signedMessage : PByte; var smlen: integer; m : PByte; mlen : integer;
  ctx : PByte; ctxlen : integer; const sk : TDilithium_5_SecretBytes) : boolean;

function pqcrystals_dilithium5_ref_open( m : PByte; var mlen: integer; sigMessage : PByte; siglen : integer;
  ctx : PByte; ctxlen : integer; const pk : TDilithium_5_PublicBytes) : boolean;

implementation

uses SysUtils, Types, fips202, Windows;

// ###########################################
// #### Params
// ###########################################

const N = 256;
      SEEDBYTES = 32;
      CRHBYTES = 64;
      TRBYTES = 64;
      RNDBYTES = 32;
      Q = 8380417;
      D = 13;
      ROOT_OF_UNITY = 1753;

      POLYT1_PACKEDBYTES = 320;
      POLYT0_PACKEDBYTES = 416;

      SHAKE128_RATE = 168;
      SHAKE256_RATE = 136;

      STREAM128_BLOCKBYTES = SHAKE128_RATE;
      STREAM256_BLOCKBYTES = SHAKE256_RATE;



// dynamic parameters
type
  TDilithiumParams = record
    K : integer;
    L : integer;
    ETA : integer;
    TAU : integer;
    BETA : integer;
    GAMMA1 : integer;
    GAMMA2 : integer;
    OMEGA : integer;
    CTILDEBYTES : integer;
    POLYVECH_PACKEDBYTES : integer;
    POLYZ_PACKEDBYTES : integer;
    POLYW1_PACKEDBYTES : integer;
    POLYETA_PACKEDBYTES : integer;
    CRYPTO_PUBLICKEYBYTES : integer; // (SEEDBYTES + K*POLYT1_PACKEDBYTES)
    CRYPTO_SECRETKEYBYTES : integer; // (2*SEEDBYTES +TRBYTES + L*POLYETA_PACKEDBYTES + K*POLYETA_PACKEDBYTES + K*POLYT0_PACKEDBYTES)
    CRYPTO_BYTES : integer;          // (CTILDEBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)
  end;

  PInt32 = ^Int32;

const cDilithium2 : TDilithiumParams =
                 ( K : 4; L : 4; Eta : 2; Tau : 39; Beta : 78; Gamma1 : $20000; // 1 shl 17
                   Gamma2 : 95232 (*((Q-1)/88)*); Omega : 80; CTILDEBYTES : 32;
                   POLYVECH_PACKEDBYTES : 84; (*Omega + k*) POLYZ_PACKEDBYTES : 576;
                   POLYW1_PACKEDBYTES : 192; POLYETA_PACKEDBYTES : 96;
                   CRYPTO_PUBLICKEYBYTES : 4*320 + 32;
                   CRYPTO_SECRETKEYBYTES : 2560; CRYPTO_BYTES : 2420);

const cDilithium3 : TDilithiumParams =
                 ( K : 6; L : 5; Eta : 4; Tau : 49; Beta : 196; Gamma1 : $80000; // 1 shl 19
                   Gamma2 : 261888 (*((Q-1)/32)*); Omega : 55; CTILDEBYTES : 48;
                   POLYVECH_PACKEDBYTES : 61; (*Omega + k*) POLYZ_PACKEDBYTES : 640;
                   POLYW1_PACKEDBYTES : 128; POLYETA_PACKEDBYTES : 128;
                   CRYPTO_PUBLICKEYBYTES : 6*320 + 32;
                   CRYPTO_SECRETKEYBYTES : 4032; CRYPTO_BYTES : 3309);


const cDilithium5 : TDilithiumParams =
                 ( K : 8; L : 7; Eta : 2; Tau : 60; Beta : 120; Gamma1 : $80000;
                   Gamma2 : 261888 (*((Q-1)/32)*); Omega : 75; CTILDEBYTES : 64;
                   POLYVECH_PACKEDBYTES : 83; (*Omega + k*) POLYZ_PACKEDBYTES : 640;
                   POLYW1_PACKEDBYTES : 128; POLYETA_PACKEDBYTES : 96;
                   CRYPTO_PUBLICKEYBYTES : 8*320 + 32;
                   CRYPTO_SECRETKEYBYTES : 4896; CRYPTO_BYTES : 4627);

// maximum buffers
type
  TDilithiumPublicBytesMax = Array[0..2592 - 1] of byte; // CRYPTO_PUBLICKEYBYTES -> see params
  TDilithiumSecretBytesMax = Array[0..4896 - 1] of byte; // CRYPTO_SECRETKEYBYTES -> see params
  PDilithiumSecretBytesMax = ^TDilithiumSecretBytesMax;
  TDilithiumSeedBytes = Array[0..SEEDBYTES-1] of byte;
  PDilithiumSeedBytes = ^TDilithiumSeedBytes;
  TDilithiumRndBytes = Array[0..RNDBYTES-1] of Byte;

  TDilithiumPoly = Array[0..N-1] Of Int32;
  PDilithiumPoly = ^TDilithiumPoly;
  TDilithiumPolyVecMax = Array[0..7-1] of TDilithiumPoly;  // L max
  TDilithiumPolyVecKMax = Array[0..8-1] of TDilithiumPoly;  // K max

  TDilithiumPackedVec = Array[0..POLYT1_PACKEDBYTES-1] of byte;
  PDilithiumPackedVec = ^TDilithiumPackedVec;

  TDilithiumTRBytes = Array[0..TRBYTES-1] of byte;
  PDilithiumTRBytes = ^TDilithiumTRBytes;

  TDilithiumCryptoBytesMax = Array[0..4627-1] of Byte; // CRYPTO_BYTES -> see params
  PDilithiumCryptoBytesMax = ^TDilithiumCryptoBytesMax;
  TDilithiumCTildeBytesMax = Array[0..64-1] of Byte;   // CTILDEBYTES -> see params
  PDilithiumCTildeBytesMax = ^TDilithiumCTildeBytesMax;

  TDilithiumCRHBytes = Array[0..CRHBYTES-1] of Byte;
  PDilithiumCRHBytes = ^TDilithiumCRHBytes;
  TDilithiumMatMax = Array[0..7] of TDilithiumPolyVecMax;

  TDilithiumPolyW1PackBytes_x_K_Max = Array[0..8*192 - 1] of Byte; // see K*POLYW1_PACKEDBYTES


// ###########################################
// #### rounding.c
// ###########################################

///*************************************************
//* Name:        power2round
//*
//* Description: For finite field element a, compute a0, a1 such that
//*              a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
//*              Assumes a to be standard representative.
//*
//* Arguments:   - int32_t a: input element
//*              - int32_t *a0: pointer to output element a0
//*
//* Returns a1.
//**************************************************/

function power2round(var a0 : Int32; a : int32) : int32;
begin
     Result := Int32( (Int64(a + (1 shl (D - 1))) - 1) shr D );
     a0 := a - (Result shl D);
end;

///*************************************************
//* Name:        decompose
//*
//* Description: For finite field element a, compute high and low bits a0, a1 such
//*              that a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
//*              if a1 = (Q-1)/ALPHA where we set a1 = 0 and
//*              -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard
//*              representative.
//*
//* Arguments:   - int32_t a: input element
//*              - int32_t *a0: pointer to output element a0
//*
//* Returns a1.
//**************************************************/

function decompose(const Gamma2 : integer; var a0 : int32; a : int32) : int32;
var a1 : int32;
begin
     a1 := Int32( Int64((a + 127) ) shr 7);

     if Gamma2 = (Q-1) div 32 then
     begin
          a1 := Int32( Int64(a1*1025 + (1 shl 21)) shr 22);
          a1 := a1 and 15;
     end
     else if Gamma2 = (Q-1) div 88 then
     begin
          a1 := Int32( ( Int64(a1)*11275 + Int64(1 shl 23) ) shr 24 );
          a1 := a1 xor ( -Int32(UInt32(43 - a1) shr 31) and a1);
     end;

     a0 := a - a1*2*Gamma2;
     a0 := a0 - (Int32(UInt64(Int64((Q - 1) div 2 - a0)) shr 31) and Q);

     Result := a1;
end;

///*************************************************
//* Name:        make_hint
//*
//* Description: Compute hint bit indicating whether the low bits of the
//*              input element overflow into the high bits.
//*
//* Arguments:   - int32_t a0: low bits of input element
//*              - int32_t a1: high bits of input element
//*
//* Returns 1 if overflow.
//**************************************************/

function make_hint(Gamma2 : integer; a0, a1 : int32): int32;
begin
     Result := Integer( (a0 > gamma2) or (a0 < -Gamma2) or ( (a0 = -Gamma2) and (a1 <> 0) ) );
end;

///*************************************************
//* Name:        use_hint
//*
//* Description: Correct high bits according to hint.
//*
//* Arguments:   - int32_t a: input element
//*              - unsigned int hint: hint bit
//*
//* Returns corrected high bits.
//**************************************************/
function use_hint(gamma2 : integer; a : int32; hint : int32) : integer;
var a0, a1 : int32;
begin
     a1 := decompose(gamma2, a0, a);

     if hint = 0 then
        exit(a1);

     if gamma2 = (Q-1) div 32 then
     begin
          if a0 > 0
          then
              Result := (a1 + 1) and 15
          else
              Result := (a1 - 1) and 15;
     end
     else
     begin
          if a0 > 0
          then
              Result := Integer(a1 <> 43)*(a1 + 1)
          else
          begin
               Result := Integer(a1 = 0)*43 + Integer(a1 <> 0)*(a1 - 1);
          end;
     end;
end;

// ###########################################
// #### reduce.c
// ###########################################

const QINV = 58728449; // q^(-1) mod 2^32
      MONT = -4186625; // 2^32 mod q
      cDIV = 41978; // mont^2/256
      DIV_QINV = -8395782;

function montgomery_reduce(a : int64) : int32;
begin
     {$Q-}
     {$R-}
     Result := Int32(UInt32(a) * UInt32(QINV));
     Result := Int32(UInt64(a - Int64(Result) * Q) shr 32);
end;

///*************************************************
//* Name:        reduce32
//*
//* Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
//*              compute r \equiv a (mod Q) such that -6283008 <= r <= 6283008.
//*
//* Arguments:   - int32_t: finite field element a
//*
//* Returns r.
//**************************************************/
function reduce32(a : Int32) : Int32;
begin
     // the strange cast is due to arithmetic vs logical shift :/
     Result := Int32( UInt64( (Int64(a) + (Int64(1) shl 22)) ) shr 23);
     Result := a - Result*Q;
end;

///*************************************************
//* Name:        caddq
//*
//* Description: Add Q if input coefficient is negative.
//*
//* Arguments:   - int32_t: finite field element a
//*
//* Returns r.
//**************************************************/
function caddq( a : int32 ) : int32;
begin
     // simulate arithmetic shift
     // basically does: if a < 0 then -1 and Q else 0 and Q

     //Result := a + ((-(a shr 31)) and Q);
     Result := a + ((-Int32(UInt32(a) shr 31)) and Q);
end;

///*************************************************
//* Name:        freeze
//*
//* Description: For finite field element a, compute standard
//*              representative r = a mod^+ Q.
//*
//* Arguments:   - int32_t: finite field element a
//*
//* Returns r.
//**************************************************/

function freeze( a : int32 ) : int32;
begin
     a := reduce32(a);
     Result := caddq(a);
end;

// ###########################################
// #### dilithium ntt.c
// ###########################################

const cZetas : Array[0..N-1] of Int32 = (
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
);


///*************************************************
//* Name:        ntt
//*
//* Description: Forward NTT, in-place. No modular reduction is performed after
//*              additions or subtractions. Output vector is in bitreversed order.
//*
//* Arguments:   - uint32_t p[N]: input/output coefficient array
//**************************************************/
procedure ntt( var a : TDilithiumPoly);
var len, start, j, k : UInt32;
    zeta : integer;
    t : integer;
begin
     k := 0;
     len := 128;

     while len > 0 do
     begin
          start := 0;

          while start < N do
          begin
               inc(k);
               zeta := cZetas[k];

               for j := start to start + len - 1 do
               begin
                    t := montgomery_reduce( Int64( zeta )*a[j + len] );
                    a[j + len] := a[j] - t;
                    a[j] := a[j] + t;
               end;

               start := start + 2*len;
          end;


          len := len shr 1;
     end;

end;

///*************************************************
//* Name:        invntt_tomont
//*
//* Description: Inverse NTT and multiplication by Montgomery factor 2^32.
//*              In-place. No modular reductions after additions or
//*              subtractions; input coefficients need to be smaller than
//*              Q in absolute value. Output coefficient are smaller than Q in
//*              absolute value.
//*
//* Arguments:   - uint32_t p[N]: input/output coefficient array
//**************************************************/
procedure invntt_tomont(var a : TDilithiumPoly);
var start, len, j, k : UInt32;
    t, zeta : int32;
const f : int64 = 41978;
begin
     k := 256;

     len := 1;
     while len < N do
     begin
          start := 0;
          while start < N do
          begin
               dec(k);
               zeta := -cZetas[k];

               for j := start to start + len - 1 do
               begin
                    t := a[j];
                    a[j] := t + a[j + len];
                    a[j + len] := t - a[j + len];
                    a[j + len] := montgomery_reduce(Int64(zeta)*a[j + len]);
               end;

               inc(start, 2*len);
          end;

          len := len shl 1;
     end;

     for j := 0 to N - 1 do
         a[j] := montgomery_reduce(Int64(f)*a[j]);
end;

///*************************************************
//* Name:        polyeta_pack
//*
//* Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
//*
//* Arguments:   - uint8_t *r: pointer to output byte array with at least
//*                            POLYETA_PACKEDBYTES bytes
//*              - const poly *a: pointer to input polynomial
//**************************************************/
type
  TR3Bytes = Array[0..2] of Byte;
  PR3Bytes = ^TR3Bytes;
procedure polyeta_pack(const eta : integer; r : PByte; const a : TDilithiumPoly);
var t : Array[0..7] of Byte;
    i : integer;
    pR : PR3Bytes;
    j : integer;
begin
     if ETA = 2 then
     begin
          j := 0;
          pR := PR3Bytes(r);
          for i := 0 to N div 8 - 1 do
          begin
               t[0] := ETA - a[j + 0];
               t[1] := ETA - a[j + 1];
               t[2] := ETA - a[j + 2];
               t[3] := ETA - a[j + 3];
               t[4] := ETA - a[j + 4];
               t[5] := ETA - a[j + 5];
               t[6] := ETA - a[j + 6];
               t[7] := ETA - a[j + 7];
               inc(j, 8);

               pR^[0] := (t[0] shr 0) or (t[1] shl 3) or (t[2] shl 6);
               pR^[1] := (t[2] shr 2) or (t[3] shl 1) or (t[4] shl 4) or (t[5] shl 7);
               pR^[2] := (t[5] shr 1) or (t[6] shl 2) or (t[7] shl 5);

               inc(pR);
          end;
     end
     else if ETA = 4 then
     begin
          for i := 0 to N div 2 - 1 do
          begin
               t[0] := Byte(ETA - a[2*i]);
               t[1] := Byte(ETA - a[2*i + 1]);

               r^ := t[0] or (t[1] shl 4);
               inc(r);
          end;
     end
     else
         raise Exception.Create('ETA may only be 2 or 4');

end;

///*************************************************
//* Name:        polyeta_unpack
//*
//* Description: Unpack polynomial with coefficients in [-ETA,ETA].
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const uint8_t *a: byte array with bit-packed polynomial
//**************************************************/
type
  TPoly8 = Array[0..7] of Int32;
  PPoly8 = ^TPoly8;
procedure polyeta_unpack(const ETA : integer; var r : TDilithiumPoly; a : PByte);
var i : integer;
    pA : PR3Bytes;
    pR : PPoly8;
begin
     if ETA = 2 then
     begin
          pA := PR3Bytes(a);
          pR := PPoly8(@r[0]);
          for i := 0 to N div 8 - 1 do
          begin
               pr^[0] := (pA^[0] shr 0) and $07;
               pr^[1] := (pA^[0] shr 3) and $07;
               pr^[2] := ( (pA^[0] shr 6) and $07) or ( (pA^[1] shl 2) and $07 );
               pr^[3] := (pA^[1] shr 1) and $07;
               pr^[4] := (pA^[1] shr 4) and $07;
               pr^[5] := ((pA^[1] shr 7) and $07) or ( (pA^[2] shl 1) and $07);
               pr^[6] := (pA^[2] shr 2) and $07;
               pr^[7] := (pA^[2] shr 5) and $07;

               pr^[0] := ETA - pr^[0];
               pr^[1] := ETA - pr^[1];
               pr^[2] := ETA - pr^[2];
               pr^[3] := ETA - pr^[3];
               pr^[4] := ETA - pr^[4];
               pr^[5] := ETA - pr^[5];
               pr^[6] := ETA - pr^[6];
               pr^[7] := ETA - pr^[7];

               inc(pr);
               inc(pA);
          end;
     end
     else if ETA = 4 then
     begin
          for i := 0 to N div 2 - 1 do
          begin
               r[2*i + 0] := a[i] and $0F;
               r[2*i + 1] := a[i] shr 4;
               r[2*i + 0] := ETA - r[2*i + 0];
               r[2*i + 1] := ETA - r[2*i + 1];
          end;
     end
     else
         raise Exception.Create('Eta can only be 2 or 4');
end;

///*************************************************
//* Name:        polyt1_pack
//*
//* Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
//*              Input coefficients are assumed to be standard representatives.
//*
//* Arguments:   - uint8_t *r: pointer to output byte array with at least
//*                            POLYT1_PACKEDBYTES bytes
//*              - const poly *a: pointer to input polynomial
//**************************************************/

type
  T5Bytes = Array[0..4] of Byte;
  P5Bytes = ^T5Bytes;
  T3Bytes = Array[0..2] of Byte;
  P3Bytes = ^T3Bytes;

  TPoly4 = Array[0..3] of int32;
  PPoly4 = ^TPoly4;
  TPoly2 = Array[0..1] of int32;
  PPoly2 = ^TPoly2;
procedure polyt1_pack( r : PByte; const a : TDilithiumPoly );
var i : integer;
    pR : P5Bytes;
    pA : PPoly4;
begin
     pR := P5Bytes(r);
     pa := PPoly4(@a[0]);
     for i := 0 to N div 4 - 1 do
     begin
          pR^[0] := Byte( pA^[0] shr 0);
          pR^[1] := Byte( (pA^[0] shr 8) or (pA^[1] shl 2) );
          pR^[2] := Byte( (pA^[1] shr 6) or (pA^[2] shl 4) );
          pR^[3] := Byte( (pA^[2] shr 4) or (pA^[3] shl 6) );
          pR^[4] := Byte( pA^[3] shr 2 );

          inc(pR);
          inc(pA);
     end;
end;

///*************************************************
//* Name:        polyt1_unpack
//*
//* Description: Unpack polynomial t1 with 10-bit coefficients.
//*              Output coefficients are standard representatives.
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const uint8_t *a: byte array with bit-packed polynomial
//**************************************************/

procedure polyt1_unpack(var r : TDilithiumPoly; a : PByte );
var i : integer;
    pA : P5Bytes;
    pR : PPoly4;
begin
     pR := PPoly4(@r[0]);
     pA := P5Bytes(a);

     for i := 0 to N div 4 - 1 do
     begin
          pR^[0] := Int32(( pA^[0] shr 0) or ( UInt32( pA^[1] ) shl 8 )) and $3FF;
          pR^[1] := Int32(( pA^[1] shr 2) or ( UInt32( pA^[2] ) shl 6 )) and $3FF;
          pR^[2] := Int32(( pA^[2] shr 4) or ( UInt32( pA^[3] ) shl 4 )) and $3FF;
          pR^[3] := Int32(( pA^[3] shr 6) or ( UInt32( pA^[4] ) shl 2 )) and $3FF;

          inc(pR);
          inc(pA);
     end;
end;

///*************************************************
//* Name:        polyt0_pack
//*
//* Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
//*
//* Arguments:   - uint8_t *r: pointer to output byte array with at least
//*                            POLYT0_PACKEDBYTES bytes
//*              - const poly *a: pointer to input polynomial
//**************************************************/
type
  T13Bytes = Array[0..12] of Byte;
  P13Bytes = ^T13Bytes;
procedure polyt0_pack(r : PByte; const a : TDilithiumPoly);
var t : Array[0..7] of UInt32;
    i : integer;
    tmp : Int32;
    pA : PPoly8;
    pR : P13Bytes;
begin
     pA := PPoly8(@a[0]);
     pR := P13Bytes(r);

     tmp := 1 shl (D - 1);
     for i := 0 to N div 8 - 1 do
     begin
          t[0] := tmp - pA^[0];
          t[1] := tmp - pA^[1];
          t[2] := tmp - pA^[2];
          t[3] := tmp - pA^[3];
          t[4] := tmp - pA^[4];
          t[5] := tmp - pA^[5];
          t[6] := tmp - pA^[6];
          t[7] := tmp - pA^[7];

          pR^[0] := Byte(t[0]);
          pR^[1] := Byte( (t[0] shr 8) or (t[1] shl 5) );
          pR^[2] := Byte( t[1] shr 3 );
          pR^[3] := Byte( (t[1] shr 11) or (t[2] shl 2) );
          pR^[4] := Byte( (t[2] shr 6) or (t[3] shl 7) );
          pR^[5] := Byte( t[3] shr 1 );
          pR^[6] := Byte( (t[3] shr 9) or (t[4] shl 4) );
          pR^[7] := Byte( t[4] shr 4 );
          pR^[8] := Byte( (t[4] shr 12) or (t[5] shl 1) );
          pR^[9] := Byte( (t[5] shr 7) or (t[6] shl 6) );
          pR^[10] := Byte( t[6] shr 2 );
          pR^[11] := Byte( (t[6] shr 10) or (t[7] shl 3) );
          pR^[12] := Byte( t[7] shr 5 );

          inc(pR);
          inc(pA);
     end;
end;

///*************************************************
//* Name:        polyt0_unpack
//*
//* Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const uint8_t *a: byte array with bit-packed polynomial
//**************************************************/
procedure polyt0_unpack(var r : TDilithiumPoly; a : PByte);
var i : integer;
    pR : PPoly8;
    pA : P13Bytes;
    tmp : integer;
begin
     pR := @r[0];
     pA := @a[0];
     tmp := 1 shl (D-1);

     // note: I think these shifts are logical not arithmetic: a is unsigned...
     for i := 0 to N div 8 - 1 do
     begin
          pR^[0] := Int32( UInt32( pA^[0] ) or ( UInt32( pA^[1] ) shl 8) ) and $1FFF;
          pR^[1] := Int32( (UInt32( pA^[1] ) shr 5 ) or ( UInt32( pA^[2] ) shl 3 ) or (UInt32(pA^[3] shl 11)) ) and $1FFF;
          pR^[2] := Int32( (UInt32( pA^[3] ) shr 2 ) or ( UInt32( pA^[4] ) shl 6 ) ) and $1FFF;
          pR^[3] := Int32( (UInt32( pA^[4] ) shr 7 ) or ( UInt32( pA^[5] ) shl 1 ) or (UInt32(pA^[6] shl 9)) ) and $1FFF;
          pR^[4] := Int32( (UInt32( pA^[6] ) shr 4 ) or ( UInt32( pA^[7] ) shl 4 ) or (UInt32(pA^[8] shl 12)) ) and $1FFF;
          pR^[5] := Int32( (UInt32( pA^[8] ) shr 1 ) or ( UInt32( pA^[9] ) shl 7 ) ) and $1FFF;
          pR^[6] := Int32( (UInt32( pA^[9] ) shr 6 ) or ( UInt32( pA^[10] ) shl 2 ) or (UInt32(pA^[11] shl 10)) ) and $1FFF;
          pR^[7] := Int32( (UInt32( pA^[11] ) shr 3 ) or ( UInt32( pA^[12] ) shl 5 ) ) and $1FFF;

          pR^[0] := tmp - pR^[0];
          pR^[1] := tmp - pR^[1];
          pR^[2] := tmp - pR^[2];
          pR^[3] := tmp - pR^[3];
          pR^[4] := tmp - pR^[4];
          pR^[5] := tmp - pR^[5];
          pR^[6] := tmp - pR^[6];
          pR^[7] := tmp - pR^[7];

          inc(pA);
          inc(pR);
     end;
end;

///*************************************************
//* Name:        polyz_pack
//*
//* Description: Bit-pack polynomial with coefficients
//*              in [-(GAMMA1 - 1), GAMMA1].
//*
//* Arguments:   - uint8_t *r: pointer to output byte array with at least
//*                            POLYZ_PACKEDBYTES bytes
//*              - const poly *a: pointer to input polynomial
//**************************************************/
type
  T9Bytes = Array[0..8] of Byte;
  P9Bytes = ^T9Bytes;
  T4Poly = Array[0..3] of Int32;
  P4Poly = ^T4Poly;
  T2Poly = Array[0..1] of Int32;
  P2Poly = ^T2Poly;

procedure polyz_pack( gamma1 : integer; r : PByte; const a : TDilithiumPoly);
var i : integer;
    t : Array[0..3] of Uint32;
    pR : P9Bytes;
    pA : P4Poly;
    pR1 : P5Bytes;
    pA1 : P2Poly;
begin
     if Gamma1 = $20000 then
     begin
          pA := P4Poly( @a[0] );
          pR := P9Bytes( r );
          for i := 0 to N div 4 - 1 do
          begin
               t[0] := UInt32( gamma1 - pA^[0] );
               t[1] := UInt32( gamma1 - pA^[1] );
               t[2] := UInt32( gamma1 - pA^[2] );
               t[3] := UInt32( gamma1 - pA^[3] );

               pR^[0] := Byte( t[0] );
               pR^[1] := Byte( t[0] shr 8 );
               pR^[2] := Byte( t[0] shr 16 );
               pR^[2] := pR^[2] or Byte( t[1] shl 2 );
               pR^[3] := Byte( t[1] shr 6 );
               pR^[4] := Byte( t[1] shr 14 );
               pR^[4] := pR^[4] or Byte( t[2] shl 4 );
               pR^[5] := Byte( t[2] shr 4 );
               pR^[6] := Byte( t[2] shr 12 );
               pR^[6] := pR^[6] or Byte( t[3] shl 6 );
               pR^[7] := Byte( t[3] shr 2 );
               pR^[8] := Byte( t[3] shr 10 );

               inc(pA);
               inc(pR);
          end;
     end
     else if gamma1 = $80000 then
     begin
          pA1 := P2Poly(@a[0]);
          pR1 := P5Bytes( r );
          for i := 0 to N div 2 - 1 do
          begin
               t[0] := UInt32( gamma1 - pA1^[0] );
               t[1] := UInt32( gamma1 - pA1^[1] );

               pR1^[0] := Byte( t[0] );
               pR1^[1] := Byte( t[0] shr 8 );
               pR1^[2] := Byte( t[0] shr 16 );
               pR1^[2] := pR1^[2] or Byte( t[1] shl 4 );
               pR1^[3] := Byte( t[1] shr 4 );
               pR1^[4] := Byte( t[1] shr 12 );

               inc(pA1);
               inc(pR1);
          end;
     end
     else
         raise Exception.Create('Gamma value is not $20000 or $80000');
end;

///*************************************************
//* Name:        polyz_unpack
//*
//* Description: Unpack polynomial z with coefficients
//*              in [-(GAMMA1 - 1), GAMMA1].
//*
//* Arguments:   - poly *r: pointer to output polynomial
//*              - const uint8_t *a: byte array with bit-packed polynomial
//**************************************************/
procedure polyz_unpack(const gamma1 : integer; var r : TDilithiumPoly; a : PByte );
var i : integer;
    pR : PPoly4;
    pR1 : PPoly2;
    pA : P9Bytes;
    pA1 : P5Bytes;
begin
     if gamma1 = $20000 then
     begin
          pR := PPoly4(@r[0]);
          pA := P9Bytes(a);

          for i := 0 to N div 4 - 1 do
          begin
               pR^[0] := Int32( UInt32(pA^[0]) or ( UInt32(pA^[1]) shl 8 ) or ( UInt32(pA^[2]) shl 16 ) ) and $3FFFF;
               pR^[1] := Int32( (UInt32(pA^[2]) shr 2) or ( UInt32(pA^[3]) shl 6 ) or ( UInt32(pA^[4]) shl 14 ) ) and $3FFFF;
               pR^[2] := Int32( (UInt32(pA^[4]) shr 4) or ( UInt32(pA^[5]) shl 4 ) or ( UInt32(pA^[6]) shl 12 ) ) and $3FFFF;
               pR^[3] := Int32( (UInt32(pA^[6]) shr 6) or ( UInt32(pA^[7]) shl 2 ) or ( UInt32(pA^[8]) shl 10 ) ) and $3FFFF;

               pR^[0] := gamma1 - pR^[0];
               pR^[1] := gamma1 - pR^[1];
               pR^[2] := gamma1 - pR^[2];
               pR^[3] := gamma1 - pR^[3];

               inc(pR);
               inc(pA);
          end;
     end
     else if gamma1 = $80000 then
     begin
          pA1 := P5Bytes(a);
          pR1 := PPoly2(@r[0]);
          for i := 0 to N div 2 - 1 do
          begin
               pR1^[0] := Int32( UInt32( pA1^[0] ) or ( UInt32( pA1^[1] ) shl 8 ) or ( UInt32( pA1^[2] ) shl 16 ) ) and $FFFFF;
               pR1^[1] := Int32( (UInt32( pA1^[2] ) shr 4 ) or ( UInt32( pA1^[3] ) shl 4 ) or ( UInt32( pA1^[4] ) shl 12 ) ); // and $FFFFF;


               pR1^[0] := gamma1 - pR1^[0];
               pR1^[1] := gamma1 - pR1^[1];

               inc(pA1);
               inc(pR1);
          end;
     end
     else
         raise Exception.Create('Gamma value is not $20000 or $80000');
end;

///*************************************************
//* Name:        polyw1_pack
//*
//* Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
//*              Input coefficients are assumed to be standard representatives.
//*
//* Arguments:   - uint8_t *r: pointer to output byte array with at least
//*                            POLYW1_PACKEDBYTES bytes
//*              - const poly *a: pointer to input polynomial
//**************************************************/

procedure polyw1_pack( const Gamma2 : integer; r : PByte; const a : TDilithiumPoly );
var i : integer;
    pA : PPoly4;
    pR : P3Bytes;
begin
     if gamma2 = 95232 then // (Q-1)/88
     begin
          pA := PPoly4( @a[0] );
          pR := P3Bytes( r );
          for i := 0 to N div 4 - 1 do
          begin
               pR^[0] := Byte( pA^[0] or pA^[1] shl 6 );
               pR^[1] := Byte( (pA^[1] shr 2) or (pA^[2] shl 4) );
               pR^[2] := Byte( (pA^[2] shr 4) or (pA^[3] shl 2) );

               inc(pR);
               inc(pA);
          end;
     end else
     if gamma2 = 261888 then
     begin
          for i := 0 to N div 2 - 1 do
          begin
               r^ := Byte( a[2*i] or (a[2*i + 1] shl 4) );
               inc(r);
          end;
     end
     else
         raise Exception.Create('Gamma2 can only be (Q-1)/88 or (Q-1)/32');

end;

// ###########################################
// #### packing.c
// ###########################################

///*************************************************
//* Name:        pack_pk
//*
//* Description: Bit-pack public key pk = (rho, t1).
//*
//* Arguments:   - uint8_t pk[]: output byte array
//*              - const uint8_t rho[]: byte array containing rho
//*              - const polyveck *t1: pointer to vector t1
//**************************************************/
procedure pack_pk( K : integer; var pk : TDilithiumPublicBytesMax; const rho : TDilithiumSeedBytes; const t1 : TDilithiumPolyVecKMax);
var i : integer;
    pkRho : TDilithiumSeedBytes absolute pk;
    pPK : PDilithiumPackedVec;
begin
     pkRho := rho;

     pPK := @pk[SEEDBYTES];
     for i := 0 to K - 1 do
     begin
          polyt1_pack( PByte(pPK), t1[i] );
          inc(pPK);
     end;
end;

///*************************************************
//* Name:        unpack_pk
//*
//* Description: Unpack public key pk = (rho, t1).
//*
//* Arguments:   - const uint8_t rho[]: output byte array for rho
//*              - const polyveck *t1: pointer to output vector t1
//*              - uint8_t pk[]: byte array containing bit-packed pk
//**************************************************/
procedure unpack_pk(K : integer; var rho : TDilithiumSeedBytes; var t1 : TDilithiumPolyVecKMax; const pk : TDilithiumPublicBytesMax );
var i : integer;
    pVec : PByte;
begin
     for i := 0 to SEEDBYTES - 1 do
         rho[i] := pk[i];

     pVec := @pk[SEEDBYTES];
     for i := 0 to K - 1 do
     begin
          polyt1_unpack( t1[i], PByte(pVec) );
          inc(pVec, POLYT1_PACKEDBYTES);
     end;
end;

///*************************************************
//* Name:        pack_sk
//*
//* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
//*
//* Arguments:   - uint8_t sk[]: output byte array
//*              - const uint8_t rho[]: byte array containing rho
//*              - const uint8_t tr[]: byte array containing tr
//*              - const uint8_t key[]: byte array containing key
//*              - const polyveck *t0: pointer to vector t0
//*              - const polyvecl *s1: pointer to vector s1
//*              - const polyveck *s2: pointer to vector s2
//**************************************************/

procedure pack_sk(const params : TDilithiumParams;
  var sk : TDilithiumSecretBytesMax; const rho : TDilithiumSeedBytes;
  const tr : TDilithiumTRBytes; const key : TDilithiumSeedBytes;
  const t0 : TDilithiumPolyVecKMax; const s1 : TDilithiumPolyVecMax;
  const s2 : TDilithiumPolyVecKMax);
var i : integer;
    pSK : PByte;
begin
     pSK := @sk[0];
     Move( rho, pSK^, SEEDBYTES );
     inc(pSK, SEEDBYTES);
     Move( key, pSK^, SEEDBYTES );
     inc(pSK, SEEDBYTES);
     Move( tr, pSK^, TRBYTES );
     inc(pSK, TRBYTES);

     for i := 0 to params.L - 1 do
     begin
          polyeta_pack(params.ETA, pSK, s1[i]);
          inc(pSK, params.POLYETA_PACKEDBYTES);
     end;

     for i := 0 to params.K - 1 do
     begin
          polyeta_pack(params.ETA, pSK, s2[i]);
          inc(pSK, params.POLYETA_PACKEDBYTES);
     end;

     for i := 0 to params.K - 1 do
     begin
          polyt0_pack(pSK, t0[i]);
          inc(pSK, POLYT0_PACKEDBYTES);
     end;

end;

///*************************************************
//* Name:        unpack_sk
//*
//* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
//*
//* Arguments:   - const uint8_t rho[]: output byte array for rho
//*              - const uint8_t tr[]: output byte array for tr
//*              - const uint8_t key[]: output byte array for key
//*              - const polyveck *t0: pointer to output vector t0
//*              - const polyvecl *s1: pointer to output vector s1
//*              - const polyveck *s2: pointer to output vector s2
//*              - uint8_t sk[]: byte array containing bit-packed sk
//**************************************************/
procedure unpack_sk( const params : TDilithiumParams;
  var rho : TDilithiumSeedBytes; var tr : TDilithiumTRBytes; var key : TDilithiumSeedBytes;
  var t0 : TDilithiumPolyVecKMax; var s1 : TDilithiumPolyVecMax;
  var s2 : TDilithiumPolyVecKMax; const sk : TDilithiumSecretBytesMax);
var i : integer;
    pSK : PByte;
begin
     pSK := @sk[0];
     Move(pSK^, rho[0], SEEDBYTES);
     inc(pSK, SEEDBYTES);
     Move(pSK^, key[0], SEEDBYTES);
     inc(pSK, SEEDBYTES);
     Move(pSK^, tr[0], TRBYTES);
     inc(pSK, TRBYTES);


     for i := 0 to params.L - 1 do
     begin
          polyeta_unpack(params.ETA, s1[i], pSK);
          inc(pSK, params.POLYETA_PACKEDBYTES);
     end;

     for i := 0 to params.K - 1 do
     begin
          polyeta_unpack(params.ETA, s2[i], pSK);
          inc(pSK, params.POLYETA_PACKEDBYTES);
     end;

     for i := 0 to params.K - 1 do
     begin
          polyt0_unpack( t0[i], pSK);
          inc(pSK, POLYT0_PACKEDBYTES);
     end;
end;

///*************************************************
//* Name:        pack_sig
//*
//* Description: Bit-pack signature sig = (c, z, h).
//*
//* Arguments:   - uint8_t sig[]: output byte array
//*              - const uint8_t *c: pointer to challenge hash length SEEDBYTES
//*              - const polyvecl *z: pointer to vector z
//*              - const polyveck *h: pointer to hint vector h
//**************************************************/

procedure pack_sig(const params : TDilithiumParams; var sig : TDilithiumCryptoBytesMax; const c : TDilithiumCTildeBytesMax;
  const z : TDilithiumPolyVecMax; const h : TDilithiumPolyVecKMax );
var i, j, k : integer;
    pSig : PByte;
    pSig1 : PByte;
begin
     pSig := @sig[0];
     Move( c[0], pSig^, params.CTILDEBYTES);
     inc(pSig, params.CTILDEBYTES);

     for i := 0 to params.L - 1 do
     begin
          polyz_pack(params.GAMMA1, pSig, z[i]);
          inc(pSig, params.POLYZ_PACKEDBYTES);
     end;

     FillChar( pSig^, params.OMEGA + params.K, 0);

     k := 0;
     pSig1 := pSig;
     inc(pSig, params.OMEGA);
     for i := 0 to params.K - 1 do
     begin
          for j := 0 to N - 1 do
          begin
               if h[i][j] <> 0 then
               begin
                    pSig1^ := j;
                    inc(pSig1);
                    inc(k);
               end;
          end;

          pSig^ := k;
          inc(pSig);
     end;
end;

///*************************************************
//* Name:        unpack_sig
//*
//* Description: Unpack signature sig = (c, z, h).
//*
//* Arguments:   - uint8_t *c: pointer to output challenge hash
//*              - polyvecl *z: pointer to output vector z
//*              - polyveck *h: pointer to output hint vector h
//*              - const uint8_t sig[]: byte array containing
//*                bit-packed signature
//*
//* Returns false in case of malformed signature; otherwise true.
//**************************************************/
function unpack_sig(const params : TDilithiumParams; var c : TDilithiumCTildeBytesMax; var z : TDilithiumPolyVecMax;
  var h : TDilithiumPolyVecKMax; const sig : TDilithiumCryptoBytesMax) : boolean;
var i, j, k : integer;
    pSig : PByte;
    pSigOmega : PByte;
    pSigArr : PByteArray;
begin
     Result := False;
     pSig := @sig[0];
     Move(pSig^, c[0], params.CTILDEBYTES);
     inc(pSig, params.CTILDEBYTES);

     for i := 0 to params.L - 1 do
     begin
          polyz_unpack(params.GAMMA1, z[i], pSig );
          inc(pSig, params.POLYZ_PACKEDBYTES);
     end;

     k := 0;
     pSigOmega := pSig;
     pSigArr := PByteArray( pSig );
     inc(pSigOmega, params.OMEGA);
     for i := 0 to params.K - 1 do
     begin
          for j := 0 to N - 1 do
              h[i][j] := 0;

          if (pSigOmega^ < k) or (pSigOmega^ > params.OMEGA) then
             exit;

          for j := k to pSigOmega^ - 1 do
          begin
               if (j > k) and (pSigArr^[j] <= pSigArr^[j - 1]) then
                  exit;

               h[i][pSigArr^[j]] := 1;
          end;

          k := pSigOmega^;
          inc(pSigOmega);
     end;

     for j := k to params.OMEGA - 1 do
         if pSigArr^[j] <> 0 then
            exit;

     Result := True;
end;

// ###########################################
// #### symmetric_shake.c
// ###########################################

procedure dilithium_shake128_stream_init( var state : TKeccakState; const seed : TDilithiumSeedBytes; nonce : UInt16);
var t : Array[0..1] of Byte;
begin
     t[0] := Byte(nonce);
     t[1] := Byte( nonce shr 8 );

     shake128_init(state);
     shake128_absorb(state, @seed[0], SEEDBYTES );
     shake128_absorb(state, @t[0], 2);
     shake128_finalize(state);
end;

procedure dilithium_shake256_stream_init(var state : TKeccakState; const seed : TDilithiumCRHBytes; nonce : UInt16);
var t : Array[0..1] of Byte;
begin
     t[0] := Byte(nonce);
     t[1] := Byte( nonce shr 8 );

     shake256_init(state);
     shake256_absorb(state, @seed[0], CRHBYTES );
     shake256_absorb(state, @t[0], 2);
     shake256_finalize(state);
end;

// ###########################################
// #### poly.c
// ###########################################

///*************************************************
//* Name:        poly_reduce
//*
//* Description: Inplace reduction of all coefficients of polynomial to
//*              representative in [-6283008,6283008].
//*
//* Arguments:   - poly *a: pointer to input/output polynomial
//**************************************************/
procedure poly_reduce( var a : TDilithiumPoly );
var i : integer;
begin
     for i := 0 to N - 1 do
         a[i] := reduce32(a[i]);
end;

///*************************************************
//* Name:        poly_caddq
//*
//* Description: For all coefficients of in/out polynomial add Q if
//*              coefficient is negative.
//*
//* Arguments:   - poly *a: pointer to input/output polynomial
//**************************************************/
procedure poly_caddq(var a : TDilithiumPoly);
var i : integer;
begin
     for i := 0 to N - 1 do
         a[i] := caddq(a[i]);
end;

///*************************************************
//* Name:        poly_add
//*
//* Description: Add polynomials. No modular reduction is performed.
//*
//* Arguments:   - poly *c: pointer to output polynomial
//*              - const poly *a: pointer to first summand
//*              - const poly *b: pointer to second summand
//**************************************************/
procedure poly_add( var c : TDilithiumPoly; const a, b : TDilithiumPoly);
var i : integer;
begin
     for i := 0 to N - 1 do
         c[i] := a[i] + b[i];
end;

///*************************************************
//* Name:        poly_sub
//*
//* Description: Subtract polynomials. No modular reduction is
//*              performed.
//*
//* Arguments:   - poly *c: pointer to output polynomial
//*              - const poly *a: pointer to first input polynomial
//*              - const poly *b: pointer to second input polynomial to be
//*                               subtraced from first input polynomial
//**************************************************/
procedure poly_sub(var c : TDilithiumPoly; const a, b : TDilithiumPoly);
var i : integer;
begin
     for i := 0 to N - 1 do
         c[i] := a[i] - b[i];
end;

///*************************************************
//* Name:        poly_shiftl
//*
//* Description: Multiply polynomial by 2^D without modular reduction. Assumes
//*              input coefficients to be less than 2^{31-D} in absolute value.
//*
//* Arguments:   - poly *a: pointer to input/output polynomial
//**************************************************/
procedure poly_shiftl( var a : TDilithiumPoly );
var i : integer;
begin
     for i := 0 to N - 1 do
         a[i] := a[i] shl D;
end;

///*************************************************
//* Name:        poly_ntt
//*
//* Description: Inplace forward NTT. Coefficients can grow by
//*              8*Q in absolute value.
//*
//* Arguments:   - poly *a: pointer to input/output polynomial
//**************************************************/
procedure poly_ntt( var a : TDilithiumPoly);
begin
     ntt(a);
end;

///*************************************************
//* Name:        poly_invntt_tomont
//*
//* Description: Inplace inverse NTT and multiplication by 2^{32}.
//*              Input coefficients need to be less than Q in absolute
//*              value and output coefficients are again bounded by Q.
//*
//* Arguments:   - poly *a: pointer to input/output polynomial
//**************************************************/
procedure poly_invntt_tomont( var a : TDilithiumPoly );
begin
     invntt_tomont(a);
end;

///*************************************************
//* Name:        poly_pointwise_montgomery
//*
//* Description: Pointwise multiplication of polynomials in NTT domain
//*              representation and multiplication of resulting polynomial
//*              by 2^{-32}.
//*
//* Arguments:   - poly *c: pointer to output polynomial
//*              - const poly *a: pointer to first input polynomial
//*              - const poly *b: pointer to second input polynomial
//**************************************************/
procedure poly_pointwise_montgomery(var c : TDilithiumPoly; const a, b : TDilithiumPoly);
var i : integer;
begin
     for i := 0 to N - 1 do
         c[i] := montgomery_reduce(Int64(a[i])*Int64(b[i]));
end;

///*************************************************
//* Name:        poly_power2round
//*
//* Description: For all coefficients c of the input polynomial,
//*              compute c0, c1 such that c mod Q = c1*2^D + c0
//*              with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
//*              standard representatives.
//*
//* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
//*              - poly *a0: pointer to output polynomial with coefficients c0
//*              - const poly *a: pointer to input polynomial
//**************************************************/
procedure poly_power2round(var a1, a0 : TDilithiumPoly; const a : TDilithiumPoly);
var i : integer;
begin
     for i := 0 to N - 1 do
         a1[i] := power2round(a0[i], a[i]);
end;

///*************************************************
//* Name:        poly_decompose
//*
//* Description: For all coefficients c of the input polynomial,
//*              compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
//*              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
//*              set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
//*              Assumes coefficients to be standard representatives.
//*
//* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
//*              - poly *a0: pointer to output polynomial with coefficients c0
//*              - const poly *a: pointer to input polynomial
//**************************************************/
procedure poly_decompose(const gamma2 : integer; var a1, a0 : TDilithiumPoly;const a : TDilithiumPoly);
var i : Integer;
begin
     for i := 0 to N - 1 do
         a1[i] := decompose(gamma2, a0[i], a[i]);
end;

///*************************************************
//* Name:        poly_make_hint
//*
//* Description: Compute hint polynomial. The coefficients of which indicate
//*              whether the low bits of the corresponding coefficient of
//*              the input polynomial overflow into the high bits.
//*
//* Arguments:   - poly *h: pointer to output hint polynomial
//*              - const poly *a0: pointer to low part of input polynomial
//*              - const poly *a1: pointer to high part of input polynomial
//*
//* Returns number of 1 bits.
//**************************************************/

function poly_make_hint( const Gamma2 : integer; var h : TDilithiumPoly; const a0, a1 : TDilithiumPoly) : int32;
var i : integer;
begin
     Result := 0;

     for i := 0 to N - 1 do
     begin
          h[i] := make_hint(Gamma2, a0[i], a1[i]);
          inc(Result, h[i]);
     end;
end;

///*************************************************
//* Name:        poly_use_hint
//*
//* Description: Use hint polynomial to correct the high bits of a polynomial.
//*
//* Arguments:   - poly *b: pointer to output polynomial with corrected high bits
//*              - const poly *a: pointer to input polynomial
//*              - const poly *h: pointer to input hint polynomial
//**************************************************/
procedure poly_use_hint(const gamma2 : integer; var b : TDilithiumPoly; const a, h : TDilithiumPoly);
var i : integer;
begin
     for i := 0 to N - 1 do
         b[i] := use_hint(gamma2, a[i], h[i]);
end;

///*************************************************
//* Name:        poly_chknorm
//*
//* Description: Check infinity norm of polynomial against given bound.
//*              Assumes input coefficients were reduced by reduce32().
//*
//* Arguments:   - const poly *a: pointer to polynomial
//*              - int32_t B: norm bound
//*
//* Returns false if norm is strictly smaller than B <= (Q-1)/8 and true otherwise.
//**************************************************/
function poly_chknorm(const a : TDilithiumPoly; B : int32) : boolean;
var i : integer;
    t : int32;
begin
     Result := True;
     if B > (Q-1) div 8 then
        exit;

     for i := 0 to N - 1 do
     begin
          t := -Int32(UInt32(a[i]) shr 31);
          t := a[i] - (t and (2*a[i]));

          if t >= B then
             exit;
     end;

     Result := False;
end;

///*************************************************
//* Name:        rej_uniform
//*
//* Description: Sample uniformly random coefficients in [0, Q-1] by
//*              performing rejection sampling on array of random bytes.
//*
//* Arguments:   - int32_t *a: pointer to output array (allocated)
//*              - unsigned int len: number of coefficients to be sampled
//*              - const uint8_t *buf: array of random bytes
//*              - unsigned int buflen: length of array of random bytes
//*
//* Returns number of sampled coefficients. Can be smaller than len if not enough
//* random bytes were given.
//**************************************************/

function rej_uniform(a : PInt32; len : integer; buf : PByte; bufLen : integer ) : integer;
var pos : integer;
    t : UInt32;
begin
     Result := 0;
     pos := 0;

     while (Result < len) and (pos + 3 <= buflen) do
     begin
          t := buf[pos];
          t := t or UInt32(buf[pos + 1]) shl 8;
          t := t or UInt32(buf[pos + 2]) shl 16;

          inc(pos, 3);
          t := t and $7FFFFF;

          if t < Q then
          begin
               a^ := t;
               inc(a);
               inc(Result)
          end;
     end;
end;

///*************************************************
//* Name:        poly_uniform
//*
//* Description: Sample polynomial with uniformly random coefficients
//*              in [0,Q-1] by performing rejection sampling on the
//*              output stream of SHAKE128(seed|nonce)
//*
//* Arguments:   - poly *a: pointer to output polynomial
//*              - const uint8_t seed[]: byte array with seed of length SEEDBYTES
//*              - uint16_t nonce: 2-byte nonce
//**************************************************/

//#define POLY_UNIFORM_NBLOCKS ((768 + STREAM128_BLOCKBYTES - 1)/STREAM128_BLOCKBYTES)
const POLY_UNIFORM_NBLOCKS = 5;
procedure poly_uniform(var a : TDilithiumPoly; const seed : TDilithiumSeedBytes; nonce : UInt16);
var i, ctr, off : integer;
    bufLen : integer;
    buf : Array[0..POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES + 1] of Byte;
    state : TKeccakState;
begin
     bufLen := POLY_UNIFORM_NBLOCKS*SHAKE128_RATE;//STREAM128_BLOCKBYTES;
     dilithium_shake128_stream_init(state, seed, nonce);
     shake128_squeezeblocks(@buf[0], POLY_UNIFORM_NBLOCKS, state);

     ctr := rej_uniform( @a[0], N, @buf[0], buflen );

     while ctr < N do
     begin
          off := buflen mod 3;
          for i := 0 to off - 1 do
              buf[i] := buf[buflen - off + i];

          shake128_squeezeblocks( @buf[off], 1, state );
          buflen := off + SHAKE128_RATE;

          ctr := ctr + rej_uniform( @a[ctr], N - ctr, @buf[0], buflen);
     end;
end;

///*************************************************
//* Name:        rej_eta
//*
//* Description: Sample uniformly random coefficients in [-ETA, ETA] by
//*              performing rejection sampling on array of random bytes.
//*
//* Arguments:   - int32_t *a: pointer to output array (allocated)
//*              - unsigned int len: number of coefficients to be sampled
//*              - const uint8_t *buf: array of random bytes
//*              - unsigned int buflen: length of array of random bytes
//*
//* Returns number of sampled coefficients. Can be smaller than len if not enough
//* random bytes were given.
//**************************************************/
function rej_eta( const eta : integer; a : PInt32; len : integer; buf : PByte; bufLen : integer) : integer;
var pos : integer;
    t0, t1 : UInt32;
begin
     Result := 0;
     pos := 0;

     if eta = 2 then
     begin
          while (Result < len) and (pos < buflen) do
          begin
               t0 := buf[pos] and $0F;
               t1 := buf[pos] shr 4;
               inc(pos);

               if t0 < 15 then
               begin
                    t0 := UInt32( Int64(t0) - Int64( ((205*t0) shr 10)*5) );
                    a^ := 2 - integer(t0);
                    inc(a);
                    inc(Result);
               end;
               if (t1 < 15) and (Result < len) then
               begin
                    t1 := UInt32( Int64(t1) - Int64( ((205*t1) shr 10)*5) );
                    a^ := 2 - integer(t1);
                    inc(a);
                    inc(Result);
               end;
          end;
     end
     else if eta = 4 then
     begin
          while (Result < len) and (pos < buflen) do
          begin
               t0 := buf[pos] and $0F;
               t1 := buf[pos] shr 4;
               inc(pos);

               if t0 < 9 then
               begin
                    a^ := 4 - integer(t0);
                    inc(a);
                    inc(Result);
               end;
               if (t1 < 9) and (Result < len) then
               begin
                    a^ := 4 - integer(t1);
                    inc(a);
                    inc(Result);
               end;
          end;
     end
     else
         raise Exception.Create('ETA may only be 2 or 4');
end;

///*************************************************
//* Name:        poly_uniform_eta
//*
//* Description: Sample polynomial with uniformly random coefficients
//*              in [-ETA,ETA] by performing rejection sampling on the
//*              output stream from SHAKE256(seed|nonce)
//*
//* Arguments:   - poly *a: pointer to output polynomial
//*              - const uint8_t seed[]: byte array with seed of length CRHBYTES
//*              - uint16_t nonce: 2-byte nonce
//**************************************************/
const POLY_UNIFORM_ETA_2_NBLOCKS = 1;
      POLY_UNIFORM_ETA_4_NBLOCKS = 2;
//#if ETA == 2
//#define POLY_UNIFORM_ETA_NBLOCKS ((136 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
//#elif ETA == 4
//#define POLY_UNIFORM_ETA_NBLOCKS ((227 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
//#endif
procedure poly_uniform_eta(const eta : integer; var a : TDilithiumPoly; const seed : TDilithiumCRHBytes; nonce : uint16);
var ctr : integer;
    buflen : integer;
    buf : Array[0..POLY_UNIFORM_ETA_4_NBLOCKS*STREAM256_BLOCKBYTES - 1] of Byte;
    state : TKeccakState;
    numBlocks : integer;
begin
     if eta = 2
     then
         numBlocks := POLY_UNIFORM_ETA_2_NBLOCKS
     else if eta = 4
     then
         numBlocks := POLY_UNIFORM_ETA_4_NBLOCKS
     else
         raise Exception.Create('Eta can only be 2 or 4');

     BufLen := numBlocks*STREAM256_BLOCKBYTES;
     dilithium_shake256_stream_init(state, seed, nonce);
     shake256_squeezeblocks(@buf[0], numBlocks, state);

     ctr := rej_eta(eta, @a[0], N, @buf[0], bufLen);

     while ctr < N do
     begin
          shake256_squeezeblocks(@buf[0], 1, state);
          ctr := ctr + rej_eta(eta, @a[ctr], N - ctr, @buf[0], STREAM256_BLOCKBYTES);
     end;

end;

///*************************************************
//* Name:        poly_uniform_gamma1m1
//*
//* Description: Sample polynomial with uniformly random coefficients
//*              in [-(GAMMA1 - 1), GAMMA1] by unpacking output stream
//*              of SHAKE256(seed|nonce)
//*
//* Arguments:   - poly *a: pointer to output polynomial
//*              - const uint8_t seed[]: byte array with seed of length CRHBYTES
//*              - uint16_t nonce: 16-bit nonce
//**************************************************/
//#define POLY_UNIFORM_GAMMA1_NBLOCKS ((POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
const POLY_UNIFORM_GAMMA1_NBLOCKS_MAX = 5;

procedure poly_uniform_gamma1(const GAMMA1, POLYZ_PACKEDBYTES : integer; var a : TDilithiumPoly; const seed : TDilithiumCRHBytes; nonce : UInt16);
var gamma1NBlocks : integer;
    buf : Array[0..POLY_UNIFORM_GAMMA1_NBLOCKS_MAX*STREAM256_BLOCKBYTES - 1] of Byte;
    state : TKeccakState;
begin
     gamma1NBlocks := (POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1) div STREAM256_BLOCKBYTES;

     dilithium_shake256_stream_init(state, seed, nonce);
     shake256_squeezeblocks(@buf[0], gamma1NBlocks, state);

     polyz_unpack(GAMMA1, a, @buf[0]);
end;

///*************************************************
//* Name:        challenge
//*
//* Description: Implementation of H. Samples polynomial with TAU nonzero
//*              coefficients in {-1,1} using the output stream of
//*              SHAKE256(seed).
//*
//* Arguments:   - poly *c: pointer to output polynomial
//*              - const uint8_t mu[]: byte array containing seed of length CTILDEBYTES
//**************************************************/
procedure poly_challenge(const CTILDEBYTES, TAU : integer; var c : TDilithiumPoly; const seed : TDilithiumCTildeBytesMax);
var i, b, pos : integer;
    signs : UInt64;
    buf : Array[0..SHAKE256_RATE-1] of Byte;
    state : TKeccakState;
begin
     shake256_init(state);
     shake256_absorb(state, @seed[0], CTILDEBYTES);
     shake256_finalize(state);
     shake256_squeezeblocks(@buf[0], 1, state);

     signs := 0;
     for i := 0 to 7 do
         signs := signs or ( UInt64(buf[i]) shl (8*i) );

     pos := 8;
     for i := 0 to N - 1 do
         c[i] := 0;
     for i := N - TAU to N - 1 do
     begin
          repeat
                if pos >= SHAKE256_RATE then
                begin
                     shake256_squeezeblocks(@buf[0], 1, state);
                     pos := 0;
                end;

                b := buf[pos];
                inc(pos);
          until b <= i;

          c[i] := c[b];
          c[b] := 1 - 2*(Int32(signs) and 1);
          signs := signs shr 1;
     end;
end;

// ###########################################
// #### polyvec.c
// ###########################################

///**************************************************************/
///************ Vectors of polynomials of length L **************/
///**************************************************************/

procedure polyvecl_uniform_eta(const eta, L : integer; var v : TDilithiumPolyVecMax; const seed : TDilithiumCRHBytes; nonce : Uint16);
var i : integer;
begin
     for i := 0 to L - 1 do
     begin
          poly_uniform_eta(eta, v[i], seed, nonce);
          inc(nonce);
     end;
end;

procedure polyvecl_uniform_gamma1( const params : TDilithiumParams; var v : TDilithiumPolyVecMax; const seed : TDilithiumCRHBytes; nonce : UInt16);
var i : integer;
begin
     nonce := params.L*nonce;
     for i := 0 to params.L - 1 do
     begin
          poly_uniform_gamma1(params.GAMMA1, params.POLYZ_PACKEDBYTES, v[i], seed, nonce);
          inc(nonce);
     end;
end;

procedure polyvecl_reduce(const L : integer; var v : TDilithiumPolyVecMax);
var i : integer;
begin
     for i := 0 to L - 1 do
         poly_reduce(v[i]);
end;

///*************************************************
//* Name:        polyvecl_add
//*
//* Description: Add vectors of polynomials of length L.
//*              No modular reduction is performed.
//*
//* Arguments:   - polyvecl *w: pointer to output vector
//*              - const polyvecl *u: pointer to first summand
//*              - const polyvecl *v: pointer to second summand
//**************************************************/
procedure polyvecl_add(const L : integer; var w : TDilithiumPolyVecMax; const u, v : TDilithiumPolyVecMax);
var i : integer;
begin
     for i := 0 to L - 1 do
         poly_add(w[i], u[i], v[i] );
end;

///*************************************************
//* Name:        polyvecl_ntt
//*
//* Description: Forward NTT of all polynomials in vector of length L. Output
//*              coefficients can be up to 16*Q larger than input coefficients.
//*
//* Arguments:   - polyvecl *v: pointer to input/output vector
//**************************************************/
procedure polyvecl_ntt(const L : integer; var v : TDilithiumPolyVecMax);
var i : integer;
begin
     for i := 0 to L - 1 do
         poly_ntt(v[i]);
end;

procedure polyvecl_invntt_tomont(const L : integer; var v : TDilithiumPolyVecMax);
var i : integer;
begin
     for i := 0 to L - 1 do
         poly_invntt_tomont(v[i]);
end;

procedure polyvecl_pointwise_poly_montgomery(const L : integer; var r : TDilithiumPolyVecMax; const a : TDilithiumPoly;
 const v : TDilithiumPolyVecMax);
var i : integer;
begin
     for i := 0 to L - 1 do
         poly_pointwise_montgomery(r[i], a, v[i]);

end;

///*************************************************
//* Name:        polyvecl_pointwise_acc_montgomery
//*
//* Description: Pointwise multiply vectors of polynomials of length L, multiply
//*              resulting vector by 2^{-32} and add (accumulate) polynomials
//*              in it. Input/output vectors are in NTT domain representation.
//*
//* Arguments:   - poly *w: output polynomial
//*              - const polyvecl *u: pointer to first input vector
//*              - const polyvecl *v: pointer to second input vector
//**************************************************/
procedure polyvecl_pointwise_acc_montgomery(const L : integer; var w : TDilithiumPoly; const u, v : TDilithiumPolyVecMax);
var i : integer;
    t : TDilithiumPoly;
begin
     poly_pointwise_montgomery(w, u[0], v[0]);
     for i := 1 to L - 1 do
     begin
          poly_pointwise_montgomery(t, u[i], v[i]);
          poly_add(w, w, t);
     end;
end;

///*************************************************
//* Name:        polyvecl_chknorm
//*
//* Description: Check infinity norm of polynomials in vector of length L.
//*              Assumes input polyvecl to be reduced by polyvecl_reduce().
//*
//* Arguments:   - const polyvecl *v: pointer to vector
//*              - int32_t B: norm bound
//*
//* Returns 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
//* and 1 otherwise.
//**************************************************/
function polyvecl_chknorm(const L : integer; const v : TDilithiumPolyVecMax; bound : integer) : boolean;
var i : integer;
begin
     for i := 0 to L - 1 do
     begin
          if poly_chknorm(v[i], bound) then
             exit(true);
     end;
     Result := False;
end;

///**************************************************************/
///************ Vectors of polynomials of length K **************/
///**************************************************************/
procedure polyveck_uniform_eta(const eta, K : integer; var v : TDilithiumPolyVecKMax; const seed : TDilithiumCRHBytes; nonce : UInt16);
var i : integer;
begin
     for i := 0 to K - 1 do
     begin
          poly_uniform_eta(eta, v[i], seed, nonce);
          inc(nonce);
     end;
end;

///*************************************************
//* Name:        polyveck_reduce
//*
//* Description: Reduce coefficients of polynomials in vector of length K
//*              to representatives in [-6283008,6283008].
//*
//* Arguments:   - polyveck *v: pointer to input/output vector
//**************************************************/

procedure polyveck_reduce(const K : integer; var v : TDilithiumPolyVecKMax);
var i : integer;
begin
     for i := 0 to K - 1 do
         poly_reduce(v[i]);

end;

///*************************************************
//* Name:        polyveck_caddq
//*
//* Description: For all coefficients of polynomials in vector of length K
//*              add Q if coefficient is negative.
//*
//* Arguments:   - polyveck *v: pointer to input/output vector
//**************************************************/

procedure polyveck_caddq(const K : integer; var v : TDilithiumPolyVecKMax);
var i : integer;
begin
     for i := 0 to K - 1 do
         poly_caddq(v[i]);
end;

///*************************************************
//* Name:        polyveck_add
//*
//* Description: Add vectors of polynomials of length K.
//*              No modular reduction is performed.
//*
//* Arguments:   - polyveck *w: pointer to output vector
//*              - const polyveck *u: pointer to first summand
//*              - const polyveck *v: pointer to second summand
//**************************************************/

procedure polyveck_add(const K : integer; var w : TDilithiumPolyVecKMax; const u, v : TDilithiumPolyVecKMax);
var i : integer;
begin
     for i := 0 to K - 1 do
         poly_add(w[i], u[i], v[i]);
end;

///*************************************************
//* Name:        polyveck_sub
//*
//* Description: Subtract vectors of polynomials of length K.
//*              No modular reduction is performed.
//*
//* Arguments:   - polyveck *w: pointer to output vector
//*              - const polyveck *u: pointer to first input vector
//*              - const polyveck *v: pointer to second input vector to be
//*                                   subtracted from first input vector
//**************************************************/
procedure polyveck_sub(const K : integer; var w : TDilithiumPolyVecKMax; const u, v : TDilithiumPolyVecKMax);
var i : integer;
begin
     for i := 0 to K - 1 do
         poly_sub(w[i], u[i], v[i]);
end;

///*************************************************
//* Name:        polyveck_shiftl
//*
//* Description: Multiply vector of polynomials of Length K by 2^D without modular
//*              reduction. Assumes input coefficients to be less than 2^{31-D}.
//*
//* Arguments:   - polyveck *v: pointer to input/output vector
//**************************************************/
procedure polyveck_shiftl(const K : integer; var v : TDilithiumPolyVecKMax);
var i : integer;
begin
     for i := 0 to K - 1 do
         poly_shiftl(v[i]);
end;

///*************************************************
//* Name:        polyveck_ntt
//*
//* Description: Forward NTT of all polynomials in vector of length K. Output
//*              coefficients can be up to 16*Q larger than input coefficients.
//*
//* Arguments:   - polyveck *v: pointer to input/output vector
//**************************************************/

procedure polyveck_ntt(const K : integer; var v : TDilithiumPolyVecKMax);
var i : integer;
begin
     for i := 0 to K - 1 do
         poly_ntt(v[i]);
end;

///*************************************************
//* Name:        polyveck_invntt_tomont
//*
//* Description: Inverse NTT and multiplication by 2^{32} of polynomials
//*              in vector of length K. Input coefficients need to be less
//*              than 2*Q.
//*
//* Arguments:   - polyveck *v: pointer to input/output vector
//**************************************************/

procedure polyveck_invntt_tomont(const K : integer; var v : TDilithiumPolyVecKMax);
var i : integer;
begin
     for i := 0 to K - 1 do
         poly_invntt_tomont(v[i]);
end;

procedure polyveck_pointwise_poly_montgomery(const K : integer; var r : TDilithiumPolyVecKMax; const a : TDilithiumPoly; const v : TDilithiumPolyVecKMax);
var i : integer;
begin
     for i := 0 to K - 1 do
         poly_pointwise_montgomery(r[i], a, v[i]);
end;

///*************************************************
//* Name:        polyveck_chknorm
//*
//* Description: Check infinity norm of polynomials in vector of length K.
//*              Assumes input polyveck to be reduced by polyveck_reduce().
//*
//* Arguments:   - const polyveck *v: pointer to vector
//*              - int32_t B: norm bound
//*
//* Returns 0 if norm of all polynomials are strictly smaller than B <= (Q-1)/8
//* and 1 otherwise.
//**************************************************/
function polyveck_chknorm(const K : integer; const v : TDilithiumPolyVecKMax; bound : Int32 ) : boolean;
var i : integer;
begin
     Result := False;

     for i := 0 to K - 1 do
         if poly_chknorm(v[i], bound) then
            exit(True);
end;

///*************************************************
//* Name:        polyveck_power2round
//*
//* Description: For all coefficients a of polynomials in vector of length K,
//*              compute a0, a1 such that a mod^+ Q = a1*2^D + a0
//*              with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
//*              standard representatives.
//*
//* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
//*                              coefficients a1
//*              - polyveck *v0: pointer to output vector of polynomials with
//*                              coefficients a0
//*              - const polyveck *v: pointer to input vector
//**************************************************/
procedure polyveck_power2round(const K : integer; var v1, v0 : TDilithiumPolyVecKMax; const v : TDilithiumPolyVecKMax);
var i : integer;
begin
     for i := 0 to K - 1 do
         poly_power2round(v1[i], v0[i], v[i]);
end;

///*************************************************
//* Name:        polyveck_decompose
//*
//* Description: For all coefficients a of polynomials in vector of length K,
//*              compute high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0
//*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
//*              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
//*              Assumes coefficients to be standard representatives.
//*
//* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
//*                              coefficients a1
//*              - polyveck *v0: pointer to output vector of polynomials with
//*                              coefficients a0
//*              - const polyveck *v: pointer to input vector
//**************************************************/

procedure polyveck_decompose(const gamma2, K : integer; var v1, v0 : TDilithiumPolyVecKMax; const v : TDilithiumPolyVecKMax);
var i : integer;
begin
     for i := 0 to K - 1 do
         poly_decompose(gamma2, v1[i], v0[i], v[i]);
end;

///*************************************************
//* Name:        polyveck_make_hint
//*
//* Description: Compute hint vector.
//*
//* Arguments:   - polyveck *h: pointer to output vector
//*              - const polyveck *v0: pointer to low part of input vector
//*              - const polyveck *v1: pointer to high part of input vector
//*
//* Returns number of 1 bits.
//**************************************************/
function polyveck_make_hint( const Gamma2, K : integer; var h : TDilithiumPolyVecKMax; const v0, v1 : TDilithiumPolyVecKMax) : int32;
var i : integer;
begin
     Result := 0;
     for i := 0 to K - 1 do
         inc(Result, poly_make_hint(Gamma2, h[i], v0[i], v1[i]));
end;

///*************************************************
//* Name:        polyveck_use_hint
//*
//* Description: Use hint vector to correct the high bits of input vector.
//*
//* Arguments:   - polyveck *w: pointer to output vector of polynomials with
//*                             corrected high bits
//*              - const polyveck *u: pointer to input vector
//*              - const polyveck *h: pointer to input hint vector
//**************************************************/

procedure polyveck_use_hint(const Gamma2, K : integer; var w : TDilithiumPolyVecKMax; const u, h : TDilithiumPolyVecKMax);
var i : integer;
begin
     for I := 0 to K - 1 do
         poly_use_hint(Gamma2, w[i], u[i], h[i]);
end;

procedure polyveck_pack_w1(const params : TDilithiumParams; r : PByte; const w1 : TDilithiumPolyVecKMax);
var i : integer;
begin
     for i := 0 to params.K - 1 do
     begin
          polyw1_pack(params.GAMMA2, r, w1[i]);
          inc(r, params.POLYW1_PACKEDBYTES);
     end;
end;

///*************************************************
//* Name:        expand_mat
//*
//* Description: Implementation of ExpandA. Generates matrix A with uniformly
//*              random coefficients a_{i,j} by performing rejection
//*              sampling on the output stream of SHAKE128(rho|j|i)
//*
//* Arguments:   - polyvecl mat[K]: output matrix
//*              - const uint8_t rho[]: byte array containing seed rho
//**************************************************/

procedure polyvec_matrix_expand(const K, L : integer; var mat : TDilithiumMatMax; const rho : TDilithiumSeedBytes);
var i, j : integer;
begin
     for i := 0 to K - 1 do
         for j := 0 to L - 1 do
             poly_uniform(mat[i][j], rho, (i shl 8) + j);
end;

procedure polyvec_matrix_pointwise_montgomery(const K, L : integer; var t : TDilithiumPolyVecKMax; var mat : TDilithiumMatMax; var v : TDilithiumPolyVecMax);
var i : integer;
begin
     for i := 0 to K - 1 do
         polyvecl_pointwise_acc_montgomery(L, t[i], mat[i], v);
end;

// ###########################################
// #### Random
// ###########################################

// newer BCrypt.h API
const BCRYPT_USE_SYSTEM_PREFERRED_RNG = $00000002;   // hAlgorithm needs to be null then

type
  BCrypt_ALG_HANDLE = Pointer;
  function BCryptGenRandom(hAlgorith : BCRYPT_ALG_HANDLE; pbBuffer : PByte;
                               cbBuffer : ULong; dwFlags : ULong ) : Longint; stdcall; external 'BCrypt.dll';

// ###########################################
// #### sign.c
// ###########################################

///*************************************************
//* Name:        crypto_sign_keypair
//*
//* Description: Generates public and private key.
//*
//* Arguments:   - uint8_t *pk: pointer to output public key (allocated
//*                             array of CRYPTO_PUBLICKEYBYTES bytes)
//*              - uint8_t *sk: pointer to output private key (allocated
//*                             array of CRYPTO_SECRETKEYBYTES bytes)
//*
//* Returns true (success)
//**************************************************/
function crypto_sign_keypair(const params : TDilithiumParams; var pk : TDilithiumPublicBytesMax; var sk : TDilithiumSecretBytesMax) : boolean;
var seedbuf : Array[0..127] of Byte;
    tr : TDilithiumTRBytes;
    rho : TDilithiumSeedBytes absolute seedbuf;
    rhoPrime : PDilithiumCRHBytes;
    key : PDilithiumSeedBytes;
    mat : TDilithiumMatMax;
    s1, s1hat : TDilithiumPolyVecMax;
    s2, t1, t0 : TDilithiumPolyVecKMax;
begin
     // get randomness for rho, rhoprime and key
     BCryptGenRandom(nil, @seedbuf[0], SEEDBYTES, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
     seedbuf[SEEDBYTES] := Byte(params.K);
     seedbuf[SEEDBYTES + 1] := Byte(params.L);

     shake256( @seedbuf[0], 2*SEEDBYTES + CRHBYTES, @seedbuf[0], SEEDBYTES + 2);
     rhoprime := PDilithiumCRHBytes(@seedbuf[SEEDBYTES]);
     key := PDilithiumSeedBytes(@seedbuf[SEEDBYTES + CRHBYTES]);

     // expand matrix
     polyvec_matrix_expand( params.K, params.L, mat, rho );

     // sample short vectors s1 and s2
     polyvecl_uniform_eta(params.ETA, params.L, s1, rhoprime^, 0);
     polyveck_uniform_eta(params.ETA, params.K, s2, rhoprime^, params.L);

     // Matrix vector multiplication
     s1hat := s1;
     polyvecl_ntt(params.L, s1hat);
     polyvec_matrix_pointwise_montgomery(params.K, params.L, t1, mat, s1hat);
     polyveck_reduce(params.K, t1);
     polyveck_invntt_tomont(params.K, t1);

     // add error vector s2
     polyveck_add(params.K, t1, t1, s2);

     // extract t1 and write public key
     polyveck_caddq(params.K, t1);
     polyveck_power2round(params.K, t1, t0, t1);
     pack_pk(params.K, pk, rho, t1);

     // compute H(rho, t1) and write secret key
     shake256(@tr[0], TRBYTES, @pk[0], params.CRYPTO_PUBLICKEYBYTES);
     pack_sk(params, sk, rho, tr, key^, t0, s1, s2);

     Result := True;
end;

///*************************************************
//* Name:        crypto_sign_signature_internal
//*
//* Description: Computes signature. Internal API.
//*
//* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
//*              - size_t *siglen: pointer to output length of signature
//*              - uint8_t *m:     pointer to message to be signed
//*              - size_t mlen:    length of message
//*              - uint8_t *pre:   pointer to prefix string
//*              - size_t prelen:  length of prefix string
//*              - uint8_t *rnd:   pointer to random seed
//*              - uint8_t *sk:    pointer to bit-packed secret key
//*
//* Returns 0 (success), 1 if nonce overflows
//**************************************************/
function crypto_sign_signature_internal(const params : TDilithiumParams; var sig : TDilithiumCryptoBytesMax; var siglen : integer;
  m : PByte; mlen : Integer; pre : PByte; preLen : integer; const rnd : TDilithiumRndBytes; sk : PByte) : integer;
var n : integer;
    sigChallenge : PDilithiumCTildeBytesMax;
    nonce : UInt32;
    seedbuf : Array[0..2*SEEDBYTES + TRBYTES + 2*CRHBYTES - 1] of Byte;
    rho : TDilithiumSeedBytes absolute seedbuf;
    rhoPrime : PDilithiumCRHBytes;
    key : PDilithiumSeedBytes;
    mat : TDilithiumMatMax;
    mu : PByte;
    tr : PDilithiumTRBytes;
    s1, y, z : TDilithiumPolyVecMax;
    t0, s2, w1, w0, h : TDilithiumPolyVecKMax;
    cp : TDilithiumPoly;
    state : TKeccakState;
    maxNonce : LongWord;
begin
     nonce := 0;
     tr := @seedbuf[SEEDBYTES];
     key := @seedbuf[SEEDBYTES + TRBYTES];
     mu := @seedbuf[SEEDBYTES + TRBYTES + SEEDBYTES];
     rhoprime := @seedbuf[SEEDBYTES + TRBYTES + SEEDBYTES + CRHBYTES];
     sigChallenge := @sig[0];

     unpack_sk(params, rho, tr^, key^, t0, s1, s2, PDilithiumSecretBytesMax(sk)^);

     // compute mu = CRH(tr, pre, msg)
     shake256_init(state);
     shake256_absorb(state, PByte(tr), TRBYTES);
     shake256_absorb(state, pre, preLen);
     shake256_absorb(state, m, mlen);
     shake256_finalize(state);
     shake256_squeeze(mu, CRHBYTES, state);

     //  /* Compute rhoprime = CRH(key, rnd, mu) */
     shake256_init(state);
     shake256_absorb(state, PByte(key), SEEDBYTES);
     shake256_absorb(state, @rnd[0], RNDBYTES);
     shake256_absorb(state, mu, CRHBYTES);
     shake256_finalize(state);
     shake256_squeeze(PByte(rhoprime), CRHBYTES, state);

     // expand matrix and transform vectors
     polyvec_matrix_expand(params.K, params.L, mat, rho);
     polyvecl_ntt(params.L, s1);
     polyveck_ntt(params.K, s2);
     polyveck_ntt(params.K, t0);

     n := params.OMEGA + 1; // satisfy the compiler
     maxNonce := (High(UInt16) - (params.L - 1)) div params.L;

     repeat
           // Sample intermediate vector y
           polyvecl_uniform_gamma1(params, y, rhoprime^, UInt16( nonce) );
           inc(nonce);

           // this is just to not enter an endless loop if something is wrong
           if nonce > maxNonce then
              exit(1);

           // Matrix-vector multiplication
           z := y;
           polyvecl_ntt(params.L, z);
           polyvec_matrix_pointwise_montgomery(params.K, params.L, w1, mat, z);
           polyveck_reduce(params.K, w1);
           polyveck_invntt_tomont(params.K, w1);

           // Decompose w and call the random oracle
           polyveck_caddq(params.K, w1);
           polyveck_decompose(params.GAMMA2, params.K, w1, w0, w1);
           polyveck_pack_w1(params, @sig[0], w1);

           shake256_init(state);
           shake256_absorb(state, mu, CRHBYTES);
           shake256_absorb(state,  @sig[0], params.K*params.POLYW1_PACKEDBYTES);
           shake256_finalize(state);
           shake256_squeeze(@sig[0], params.CTILDEBYTES, state);

           poly_challenge(params.CTILDEBYTES, params.TAU, cp, sigChallenge^);
           poly_ntt(cp);

           // Compute z, reject if it reveals secret
           polyvecl_pointwise_poly_montgomery(params.L, z, cp, s1);
           polyvecl_invntt_tomont(params.L, z);

           polyvecl_add(params.L, z, z, y);
           polyvecl_reduce(params.L, z);

           if polyvecl_chknorm(params.L, z, params.GAMMA1 - params.BETA) then
              continue;

           // Check that subtracting cs2 does not change high bits of w and low bits
           // do not reveal secret information
           polyveck_pointwise_poly_montgomery(params.K, h, cp, s2);
           polyveck_invntt_tomont(params.K, h);
           polyveck_sub(params.K, w0, w0, h);
           polyveck_reduce(params.K, w0);

           if polyveck_chknorm(params.K, w0, params.GAMMA2 - params.BETA) then
              continue;

            // Compute hints for w1
            polyveck_pointwise_poly_montgomery(params.K, h, cp, t0);
            polyveck_invntt_tomont(params.K, h);
            polyveck_reduce(params.K, h);

            if polyveck_chknorm(params.K, h, params.GAMMA2) then
               continue;

            polyveck_add(params.K, w0, w0, h);
            n := polyveck_make_hint(params.GAMMA2, params.K, h, w0, w1);

     until n <= params.OMEGA;

     // write signature
     pack_sig(params, sig, sigChallenge^, z, h);
     siglen := params.CRYPTO_BYTES;

     Result := 0;
end;

///*************************************************
//* Name:        crypto_sign_signature
//*
//* Description: Computes signature.
//*
//* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
//*              - size_t *siglen: pointer to output length of signature
//*              - uint8_t *m:     pointer to message to be signed
//*              - size_t mlen:    length of message
//*              - uint8_t *ctx:   pointer to contex string
//*              - size_t ctxlen:  length of contex string
//*              - uint8_t *sk:    pointer to bit-packed secret key
//*
//* Returns true (success) or false (context string too long)
//**************************************************/
function crypto_sign_signature(const params : TDilithiumParams; var sig : TDilithiumCryptoBytesMax; var siglen : integer;
  m : PByte; mlen : Integer; ctx : PByte; ctxlen : integer; sk : PByte) : boolean;
var pre : Array[0..256] of Byte;
    rnd : TDilithiumRndBytes;
begin
     if ctxlen > 255 then
        exit(False);

     // prepare pre = (0, ctlxen, ctx)
     pre[0] := 0;
     pre[1] := Byte(ctxlen);
     Move( ctx^, pre[2], ctxlen);

     BCryptGenRandom(nil, @rnd[0], RNDBYTES, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

     Result := crypto_sign_signature_internal(params, sig, siglen, m, mlen, @pre[0], 2 + ctxlen, rnd, sk) = 0;
end;

///*************************************************
//* Name:        crypto_sign
//*
//* Description: Compute signed message.
//*
//* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
//*                             array with CRYPTO_BYTES + mlen bytes),
//*                             can be equal to m
//*              - size_t *smlen: pointer to output length of signed
//*                               message
//*              - const uint8_t *m: pointer to message to be signed
//*              - size_t mlen: length of message
//*              - const uint8_t *ctx: pointer to context string
//*              - size_t ctxlen: length of context string
//*              - const uint8_t *sk: pointer to bit-packed secret key
//*
//* Returns true (success) or false (context string too long)
//**************************************************/

function crypto_sign(const params : TDilithiumParams; sm : PByte; var smlen : integer; m : PByte; mlen : integer; ctx : PByte; ctxlen : integer; sk : PByte) : boolean;
var pSm : PByte;
begin
     pSm := sm;
     inc(pSm, params.CRYPTO_BYTES);
     Move(m^, pSm^, mlen);

     Result := crypto_sign_signature(params, PDilithiumCryptoBytesMax(sm)^, smlen, pSm, mlen, ctx, ctxlen, sk );
     inc(smlen, mlen);
end;

///*************************************************
//* Name:        crypto_sign_verify_internal
//*
//* Description: Verifies signature. Internal API.
//*
//* Arguments:   - uint8_t *m: pointer to input signature
//*              - size_t siglen: length of signature
//*              - const uint8_t *m: pointer to message
//*              - size_t mlen: length of message
//*              - const uint8_t *pre: pointer to prefix string
//*              - size_t prelen: length of prefix string
//*              - const uint8_t *pk: pointer to bit-packed public key
//*
//* Returns true if signature could be verified correctly and false otherwise
//**************************************************/

function crypto_sign_verify_internal(const params : TDilithiumParams;
  const sig : TDilithiumCryptoBytesMax; siglen : integer; m : PByte; mlen : integer; pre : PByte; prelen : integer; const pk : TDilithiumPublicBytesMax) : boolean;
var i : integer;
    buf : TDilithiumPolyW1PackBytes_x_K_Max;
    rho : TDilithiumSeedBytes;
    mu : TDilithiumTRBytes;
    c, c2 : TDilithiumCTildeBytesMax;
    cp : TDilithiumPoly;
    mat : TDilithiumMatMax;
    z : TDilithiumPolyVecMax;
    t1, w1, h : TDilithiumPolyVecKMax;
    state : TKeccakState;
begin
     Result := False;
     if siglen <> params.CRYPTO_BYTES then
        exit;

     unpack_pk(params.K, rho, t1, pk);
     if not unpack_sig(params, c, z, h, sig) then
        exit;

     if polyvecl_chknorm(params.L, z, params.GAMMA1 - params.BETA) then
        exit;

     // compute CRH(H(rho, t1) , pre, msg)
     shake256(@mu[0], TRBYTES, @pk[0], params.CRYPTO_PUBLICKEYBYTES);
     shake256_init(state);
     shake256_absorb(state, @mu[0], TRBYTES);
     shake256_absorb(state, pre, prelen);
     shake256_absorb(state, m, mlen);
     shake256_finalize(state);
     shake256_squeeze(@mu[0], CRHBYTES, state);

     // matrix vector multiplication; compute Az - c2*dt1
     poly_challenge(params.CTILDEBYTES, params.TAU, cp, c);

     polyvec_matrix_expand(params.K, params.L, mat, rho);
     polyvecl_ntt(params.L, z);
     polyvec_matrix_pointwise_montgomery(params.K, params.L, w1, mat, z);

     poly_ntt(cp);
     polyveck_shiftl(params.K, t1);
     polyveck_ntt(params.K, t1);
     polyveck_pointwise_poly_montgomery(params.K, t1, cp, t1);

     polyveck_sub(params.K, w1, w1, t1);
     polyveck_reduce(params.K, w1);
     polyveck_invntt_tomont(params.K, w1);

     // Reconstruct w1
     polyveck_caddq(params.K, w1);
     polyveck_use_hint(params.GAMMA2, params.K, w1, w1, h);
     polyveck_pack_w1(params, @buf[0], w1);

     // Call random oracle and verify challenge
     shake256_init(state);
     shake256_absorb(state, @mu[0], CRHBYTES);
     shake256_absorb(state, @buf[0], params.K*params.POLYW1_PACKEDBYTES);
     shake256_finalize(state);
     shake256_squeeze(@c2[0], params.CTILDEBYTES, state);

     for i := 0 to params.CTILDEBYTES - 1 do
         if c[i] <> c2[i] then
            exit;


     Result := True;
end;

///*************************************************
//* Name:        crypto_sign_verify
//*
//* Description: Verifies signature.
//*
//* Arguments:   - uint8_t *m: pointer to input signature
//*              - size_t siglen: length of signature
//*              - const uint8_t *m: pointer to message
//*              - size_t mlen: length of message
//*              - const uint8_t *ctx: pointer to context string
//*              - size_t ctxlen: length of context string
//*              - const uint8_t *pk: pointer to bit-packed public key
//*
//* Returns true if signature could be verified correctly and false otherwise
//**************************************************/

function crypto_sign_verify(const params : TDilithiumParams; const sig : TDilithiumCryptoBytesMax; sigLen : integer; m : PByte; mLen : integer; ctx : PByte; ctxlen : integer;
  const pk : TDilithiumPublicBytesMax) : boolean;
var pre : Array[0..256] of Byte;
begin
     REsult := False;
     if ctxlen > 255 then
        exit;

     pre[0] := 0;
     pre[1] := Byte(ctxLen);
     Move(ctx^, pre[2], ctxLen);

     Result := crypto_sign_verify_internal(params, sig, siglen, m, mlen, @pre[0], ctxlen + 2, pk );
end;

///*************************************************
//* Name:        crypto_sign_open
//*
//* Description: Verify signed message.
//*
//* Arguments:   - uint8_t *m: pointer to output message (allocated
//*                            array with smlen bytes), can be equal to sm
//*              - size_t *mlen: pointer to output length of message
//*              - const uint8_t *sm: pointer to signed message
//*              - size_t smlen: length of signed message
//*              - const uint8_t *ctx: pointer to context tring
//*              - size_t ctxlen: length of context string
//*              - const uint8_t *pk: pointer to bit-packed public key
//*
//* Returns true if signed message could be verified correctly and false otherwise
//**************************************************/
function crypto_sign_open( const params : TDilithiumParams; m : PByte; var mlen : integer; sm : PByte; smLen : integer; ctx : PByte; ctxlen : integer;
  const pk : TDilithiumPublicBytesMax) : boolean;
var pSm : PByte;
    sig : PDilithiumCryptoBytesMax;
begin
     Result := smlen >= params.CRYPTO_BYTES;

     if Result then
     begin
          mlen := smlen - params.CRYPTO_BYTES;
          sig := PDilithiumCryptoBytesMax(sm);

          pSm := sm;
          inc(pSm, params.CRYPTO_BYTES);

          Result := crypto_sign_verify(params, sig^, params.CRYPTO_BYTES, pSm, mlen, ctx, ctxlen, pk );

          // all good copy msg return true
          if Result then
             Move(pSm^, m^, mlen);
     end;

     if not Result then
     begin
          // signature failed
          mlen := 0;
          FillChar(m^, smlen, 0);
     end;
end;

// ###########################################
// #### API
// ###########################################

function pqcrystals_dilithium2_ref_keypair(var pk : TDilithium_2_PublicBytes; var sk : TDilithium_2_SecretBytes): boolean;
var pkM : TDilithiumPublicBytesMax;
    skM : TDilithiumSecretBytesMax;
begin
     Result := crypto_sign_keypair(cDilithium2, pkM, skM);

     Move(pkM[0], pk[0], sizeof(pk));
     Move(skM[0], sk[0], sizeof(sk));

     FillChar(pkM, sizeof(pkM), 0);
     FillChar(skM, sizeof(skM), 0);
end;

function pqcrystals_dilithium2_ref_signature( var sig : TDilithium_2_SignatureBytes; var siglen : integer; m : PByte; mlen : integer;
                                              ctx : PByte; ctxLen : integer; const sk : TDilithium_2_SecretBytes) : boolean;
var sigMax : TDilithiumCryptoBytesMax;
begin
     Result := crypto_sign_signature(cDilithium2, sigMax, siglen, m, mlen, ctx, ctxlen, @sk[0]);
     Move(sigMax[0], sig[0], sizeof(sig));
end;

function pqcrystals_dilithium2_ref_verify(const sig : TDilithium_2_SignatureBytes; siglen : integer;
                                          m : PByte; mlen : integer; ctx : PByte; ctxLen : integer;
                                          const pk : TDilithium_2_PublicBytes) : Boolean;
var sigM : TDilithiumCryptoBytesMax;
    pkM : TDilithiumPublicBytesMax;
begin
     Move(sig[0], sigM[0], sizeof(sig));
     Move(pk[0], pkM[0], sizeof(pk));
     Result := crypto_sign_verify(cDilithium2, sigM, siglen, m, mlen, ctx, ctxlen, pkM);
     FillChar(sigM[0], sizeof(sigM), 0);
     FillChar(pkM[0], sizeof(pkM), 0);
end;

function pqcrystals_dilithium2_ref_sign( signedMessage : PByte; var smlen: integer; m : PByte; mlen : integer;
  ctx : PByte; ctxlen : integer; const sk : TDilithium_2_SecretBytes) : boolean;
begin
     Result := crypto_sign( cDilithium2, signedMessage, smlen, m, mlen, ctx, ctxlen, @sk[0] );
end;

function pqcrystals_dilithium2_ref_open( m : PByte; var mlen: integer; sigMessage : PByte; siglen : integer;
  ctx : PByte; ctxlen : integer; const pk : TDilithium_2_PublicBytes) : boolean;
var pkM : TDilithiumPublicBytesMax;
begin
     Move(pk[0], pkM[0], sizeof(pk));
     Result := crypto_sign_open(cDilithium2, m, mlen, sigMessage, sigLen, ctx, ctxlen, pkM);
     FillChar(pkM[0], sizeof(pkM), 0);
end;


// ###########################################
// #### Dilithium 3
// ###########################################

function pqcrystals_dilithium3_ref_keypair(var pk : TDilithium_3_PublicBytes; var sk : TDilithium_3_SecretBytes): boolean;
var pkM : TDilithiumPublicBytesMax;
    skM : TDilithiumSecretBytesMax;
begin
     Result := crypto_sign_keypair(cDilithium3, pkM, skM);

     Move(pkM[0], pk[0], sizeof(pk));
     Move(skM[0], sk[0], sizeof(sk));

     FillChar(pkM, sizeof(pkM), 0);
     FillChar(skM, sizeof(skM), 0);
end;

function pqcrystals_dilithium3_ref_signature( var sig : TDilithium_3_SignatureBytes; var siglen : integer; m : PByte; mlen : integer;
                                              ctx : PByte; ctxLen : integer; const sk : TDilithium_3_SecretBytes) : boolean;
var sigMax : TDilithiumCryptoBytesMax;
begin
     Result := crypto_sign_signature(cDilithium3, sigMax, siglen, m, mlen, ctx, ctxlen, @sk[0]);
     Move(sigMax[0], sig[0], sizeof(sig));
end;

function pqcrystals_dilithium3_ref_verify(const sig : TDilithium_3_SignatureBytes; siglen : integer;
                                          m : PByte; mlen : integer; ctx : PByte; ctxLen : integer;
                                          const pk : TDilithium_3_PublicBytes) : Boolean;
var sigM : TDilithiumCryptoBytesMax;
    pkM : TDilithiumPublicBytesMax;
begin
     Move(sig[0], sigM[0], sizeof(sig));
     Move(pk[0], pkM[0], sizeof(pk));
     Result := crypto_sign_verify(cDilithium3, sigM, siglen, m, mlen, ctx, ctxlen, pkM);
     FillChar(sigM[0], sizeof(sigM), 0);
     FillChar(pkM[0], sizeof(pkM), 0);
end;

function pqcrystals_dilithium3_ref_sign( signedMessage : PByte; var smlen: integer; m : PByte; mlen : integer;
  ctx : PByte; ctxlen : integer; const sk : TDilithium_3_SecretBytes) : boolean;
begin
     Result := crypto_sign( cDilithium3, signedMessage, smlen, m, mlen, ctx, ctxlen, @sk[0] );
end;

function pqcrystals_dilithium3_ref_open( m : PByte; var mlen: integer; sigMessage : PByte; siglen : integer;
  ctx : PByte; ctxlen : integer; const pk : TDilithium_3_PublicBytes) : boolean;
var pkM : TDilithiumPublicBytesMax;
begin
     Move(pk[0], pkM[0], sizeof(pk));
     Result := crypto_sign_open(cDilithium3, m, mlen, sigMessage, sigLen, ctx, ctxlen, pkM);
     FillChar(pkM[0], sizeof(pkM), 0);
end;


// ###########################################
// #### Dilithium 5
// ###########################################

function pqcrystals_dilithium5_ref_keypair(var pk : TDilithium_5_PublicBytes; var sk : TDilithium_5_SecretBytes): boolean;
var pkM : TDilithiumPublicBytesMax;
    skM : TDilithiumSecretBytesMax;
begin
     Result := crypto_sign_keypair(cDilithium5, pkM, skM);

     Move(pkM[0], pk[0], sizeof(pk));
     Move(skM[0], sk[0], sizeof(sk));

     FillChar(pkM, sizeof(pkM), 0);
     FillChar(skM, sizeof(skM), 0);
end;

function pqcrystals_dilithium5_ref_signature( var sig : TDilithium_5_SignatureBytes; var siglen : integer; m : PByte; mlen : integer;
                                              ctx : PByte; ctxLen : integer; const sk : TDilithium_5_SecretBytes) : boolean;
var sigMax : TDilithiumCryptoBytesMax;
begin
     Result := crypto_sign_signature(cDilithium5, sigMax, siglen, m, mlen, ctx, ctxlen, @sk[0]);
     Move(sigMax[0], sig[0], sizeof(sig));
end;

function pqcrystals_dilithium5_ref_verify(const sig : TDilithium_5_SignatureBytes; siglen : integer;
                                          m : PByte; mlen : integer; ctx : PByte; ctxLen : integer;
                                          const pk : TDilithium_5_PublicBytes) : Boolean;
var sigM : TDilithiumCryptoBytesMax;
    pkM : TDilithiumPublicBytesMax;
begin
     Move(sig[0], sigM[0], sizeof(sig));
     Move(pk[0], pkM[0], sizeof(pk));
     Result := crypto_sign_verify(cDilithium5, sigM, siglen, m, mlen, ctx, ctxlen, pkM);
     FillChar(sigM[0], sizeof(sigM), 0);
     FillChar(pkM[0], sizeof(pkM), 0);
end;

function pqcrystals_dilithium5_ref_sign( signedMessage : PByte; var smlen: integer; m : PByte; mlen : integer;
  ctx : PByte; ctxlen : integer; const sk : TDilithium_5_SecretBytes) : boolean;
begin
     Result := crypto_sign( cDilithium5, signedMessage, smlen, m, mlen, ctx, ctxlen, @sk[0] );
end;

function pqcrystals_dilithium5_ref_open( m : PByte; var mlen: integer; sigMessage : PByte; siglen : integer;
  ctx : PByte; ctxlen : integer; const pk : TDilithium_5_PublicBytes) : boolean;
var pkM : TDilithiumPublicBytesMax;
begin
     Move(pk[0], pkM[0], sizeof(pk));
     Result := crypto_sign_open(cDilithium5, m, mlen, sigMessage, sigLen, ctx, ctxlen, pkM);
     FillChar(pkM[0], sizeof(pkM), 0);
end;

// ###########################################
// #### Just a test routine
// ###########################################

procedure TestUniformGamma1;
var
  seed: TDilithiumCRHBytes;
  p: TDilithiumPoly;
  i: Integer;
const cDefCoeff : Array[0..15] of integer = (
     -33612,
      15904,
      95681,
      -115244,
      -50705,
      112524,
      -128810,
      92186,
      -102268,
      -57362,
      46441,
      47325,
      -8445,
      -53129,
      117345,
      122824
   );

begin
  FillChar(seed, SizeOf(seed), 0);

  poly_uniform_gamma1(
    131072,
    576,
    p,
    seed,
    0
  );

  for i := 0 to 15 do
  begin
       if p[i] <> cDefCoeff[i] then
          raise Exception.Create('Gamm1 poly failed at index ' + IntToStr(i));
  end;
end;

initialization
  // TestUniformGamma1;

end.
