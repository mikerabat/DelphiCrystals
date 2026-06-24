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

unit fips202;

interface

{$IFDEF FPC}{$mode Delphi}{$ENDIF}

type
  TKeccakStateData = Array[0..24] of UInt64;
  TKeccakState = record
    s : TKeccakStateData;
    pos : UInt32;
  end;

type
  TSHA256Hash = Array[0..31] of Byte;
  PSHA256Hash = ^TSHA256Hash;
  TSHA512Hash = Array[0..63] of Byte;
  PSHA512Hash = ^TSHA512Hash;

procedure sha3_256(var h : TSHA256Hash; inData : PByte; inLen : integer);
procedure sha3_512(var h : TSHA512Hash; inData : PByte; inLen : integer);

procedure shake256_squeezeblocks(outData : PByte; nblocks : integer; var state : TKeccakState);
procedure shake256_absorb_once(var state : TKeccakState; inData : PByte; inLen : integer);
procedure shake256_squeeze(outData : PByte; outLen : integer; var state : TKeccakState);
procedure shake256_finalize(var state : TKeccakState);
procedure shake256_absorb(var state : TKeccakState; inData : PByte; inLen : integer);
procedure shake256_init(var state : TKeccakState);

procedure shake128_squeezeblocks( outData : PByte; nBlocks : integer; var state : TKeccakState);
procedure shake128_absorb_once(var state : TKeccakState; inData : PByte; inLen : integer);
procedure shake128_squeeze( outData : PByte; outLen : integer; var state : TKeccakState);
procedure shake128_finalize(var state : TKeccakState);
procedure shake128_absorb(var state : TKeccakState; inData : PByte; inLen : integer);
procedure shake128_init(var state : TKeccakState);

procedure shake128(outData : PByte; outLen : integer; inData : PByte; inLen : integer);
procedure shake256(outData : PByte; outLen : integer; inData : PByte; inLen : integer);

implementation

const NRounds = 24;
      SHAKE128_RATE = 168;
      SHAKE256_RATE = 136;
      SHA3_256_RATE = 136;
      SHA3_512_RATE = 72;

{$IFDEF CPUX86}
{$DEFINE LITTLE_ENDIAN}
{$ENDIF}
{$IFDEF CPUX64}
{$DEFINE LITTLE_ENDIAN}
{$ENDIF}


function ROL( a : UInt64; offset : integer ) : UInt64;
begin
     Result := UInt64(a shl offset) xor UInt64(a shr (64 - offset));
end;

///*************************************************
//* Name:        load64
//*
//* Description: Load 8 bytes into uint64_t in little-endian order
//*
//* Arguments:   - const uint8_t *x: pointer to input byte array
//*
//* Returns the loaded 64-bit unsigned integer
//**************************************************/

function load64( x : PByte ) : UInt64;
{$IFNDEF LITTLE_ENDIAN}
var i : Integer;
{$ENDIF}
begin
     {$IFDEF LITTLE_ENDIAN}
     Result := PUInt64( x ) ^;
     {$ELSE}
     Result := 0;
     for i := 0 to 7 do
     begin
          Result := Result or (UInt64(x^) shl (8*i));
          inc(x);
     end;
     {$ENDIF}
end;

///*************************************************
//* Name:        store64
//*
//* Description: Store a 64-bit integer to array of 8 bytes in little-endian order
//*
//* Arguments:   - uint8_t *x: pointer to the output byte array (allocated)
//*              - uint64_t u: input 64-bit unsigned integer
//**************************************************/
procedure store64( x : PByte; const u : UInt64 );
{$IFNDEF LITTLE_ENDIAN}
var i : Integer;
{$ENDIF}
begin
     {$IFDEF LITTLE_ENDIAN}
     PUint64(x)^ := u;
     {$ELSE}
     for i := 0 to 7 do
     begin
          x^ := Byte(u shr (8*i));
          inc(x);
     end;
     {$ENDIF}
end;

// due to a bug in FPC the constants cannot be defined as UInt64 and have the leading bit
// set to 1 -> it triggers a range check error in compile time (though it should not)
// -> disable range checking and the error is turned into a warning :/
{$IFDEF FPC} {$R-} {$ENDIF}
///* Keccak round constants */
//static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
const cKeccakF_RoundConstants : Array[0..NRounds - 1] of UInt64 =
   (
  $0000000000000001,
  $0000000000008082,
  $800000000000808a,
  $8000000080008000,
  $000000000000808b,
  $0000000080000001,
  $8000000080008081,
  $8000000000008009,
  $000000000000008a,
  $0000000000000088,
  $0000000080008009,
  $000000008000000a,
  $000000008000808b,
  $800000000000008b,
  $8000000000008089,
  $8000000000008003,
  $8000000000008002,
  $8000000000000080,
  $000000000000800a,
  $800000008000000a,
  $8000000080008081,
  $8000000000008080,
  $0000000080000001,
  $8000000080008008
  );

///*************************************************
//* Name:        KeccakF1600_StatePermute
//*
//* Description: The Keccak F1600 Permutation
//*
//* Arguments:   - uint64_t *state: pointer to input/output Keccak state
//**************************************************/
procedure KeccakF1600_StatePermute( var state : TKeccakStateData );
var round : integer;
    Aba, Abe, Abi, Abo, Abu,
    Aga, Age, Agi, Ago, Agu,
    Aka, Ake, Aki, Ako, Aku,
    Ama, Ame, Ami, Amo, Amu,
    Asa, Ase, Asi, Aso, Asu,
    BCa, BCe, BCi, BCo, BCu,
    aDa, aDe, aDi, aDo, aDu,
    Eba, Ebe, Ebi, Ebo, Ebu,
    Ega, Ege, Egi, Ego, Egu,
    Eka, Eke, Eki, Eko, Eku,
    Ema, Eme, Emi, Emo, Emu,
    Esa, Ese, Esi, Eso, Esu : UInt64;
begin
     //copyFromState(A, state)
     Aba := state[ 0];
     Abe := state[ 1];
     Abi := state[ 2];
     Abo := state[ 3];
     Abu := state[ 4];
     Aga := state[ 5];
     Age := state[ 6];
     Agi := state[ 7];
     Ago := state[ 8];
     Agu := state[ 9];
     Aka := state[10];
     Ake := state[11];
     Aki := state[12];
     Ako := state[13];
     Aku := state[14];
     Ama := state[15];
     Ame := state[16];
     Ami := state[17];
     Amo := state[18];
     Amu := state[19];
     Asa := state[20];
     Ase := state[21];
     Asi := state[22];
     Aso := state[23];
     Asu := state[24];

     round := 0;
     while round < NROUNDS do
     begin
     //for(round = 0; round < NROUNDS; round += 2) {
          //    prepareTheta
          BCa := Aba xor Aga xor Aka xor Ama xor Asa;
          BCe := Abe xor Age xor Ake xor Ame xor Ase;
          BCi := Abi xor Agi xor Aki xor Ami xor Asi;
          BCo := Abo xor Ago xor Ako xor Amo xor Aso;
          BCu := Abu xor Agu xor Aku xor Amu xor Asu;

          //thetaRhoPiChiIotaPrepareTheta(round, A, E)
          aDa := BCu xor ROL(BCe, 1);
          aDe := BCa xor ROL(BCi, 1);
          aDi := BCe xor ROL(BCo, 1);
          aDo := BCi xor ROL(BCu, 1);
          aDu := BCo xor ROL(BCa, 1);

          Aba := Aba xor aDa;
          BCa := Aba;
          Age := Age xor aDe;
          BCe := ROL(Age, 44);
          Aki := Aki xor aDi;
          BCi := ROL(Aki, 43);
          Amo := Amo xor aDo;
          BCo := ROL(Amo, 21);
          Asu := Asu xor aDu;
          BCu := ROL(Asu, 14);
          Eba :=   BCa  xor ((not BCe)and   BCi );
          Eba := Eba xor (cKeccakF_RoundConstants[round]);
          Ebe :=   BCe  xor ((not BCi)and   BCo );
          Ebi :=   BCi  xor ((not BCo)and   BCu );
          Ebo :=   BCo  xor ((not BCu)and   BCa );
          Ebu :=   BCu  xor ((not BCa)and   BCe );

          Abo := Abo xor ADo;
          BCa := ROL(Abo, 28);
          Agu := Agu xor ADu;
          BCe := ROL(Agu, 20);
          Aka := Aka xor ADa;
          BCi := ROL(Aka,  3);
          Ame := Ame xor ADe;
          BCo := ROL(Ame, 45);
          Asi := Asi xor ADi;
          BCu := ROL(Asi, 61);
          Ega :=   BCa  xor ((not BCe)and   BCi );
          Ege :=   BCe  xor ((not BCi)and   BCo );
          Egi :=   BCi  xor ((not BCo)and   BCu );
          Ego :=   BCo  xor ((not BCu)and   BCa );
          Egu :=   BCu  xor ((not BCa)and   BCe );

          Abe := Abe xor ADe;
          BCa := ROL(Abe,  1);
          Agi := Agi xor ADi;
          BCe := ROL(Agi,  6);
          Ako := Ako xor ADo;
          BCi := ROL(Ako, 25);
          Amu  := Amu xor ADu;
          BCo := ROL(Amu,  8);
          Asa := Asa xor ADa;
          BCu := ROL(Asa, 18);
          Eka :=   BCa  xor ((not BCe)and   BCi );
          Eke :=   BCe  xor ((not BCi)and   BCo );
          Eki :=   BCi  xor ((not BCo)and   BCu );
          Eko :=   BCo  xor ((not BCu)and   BCa );
          Eku :=   BCu  xor ((not BCa)and   BCe );

          Abu := Abu xor ADu;
          BCa := ROL(Abu, 27);
          Aga := Aga xor ADa;
          BCe := ROL(Aga, 36);
          Ake := Ake xor ADe;
          BCi := ROL(Ake, 10);
          Ami := Ami xor ADi;
          BCo := ROL(Ami, 15);
          Aso := Aso xor ADo;
          BCu := ROL(Aso, 56);
          Ema :=   BCa  xor ((not BCe)and   BCi );
          Eme :=   BCe  xor ((not BCi)and   BCo );
          Emi :=   BCi  xor ((not BCo)and   BCu );
          Emo :=   BCo  xor ((not BCu)and   BCa );
          Emu :=   BCu  xor ((not BCa)and   BCe );

          Abi := Abi xor ADi;
          BCa := ROL(Abi, 62);
          Ago := Ago xor ADo;
          BCe := ROL(Ago, 55);
          Aku := Aku xor ADu;
          BCi := ROL(Aku, 39);
          Ama := Ama xor ADa;
          BCo := ROL(Ama, 41);
          Ase := Ase xor ADe;
          BCu := ROL(Ase,  2);
          Esa :=   BCa  xor ((not BCe)and   BCi );
          Ese :=   BCe  xor ((not BCi)and   BCo );
          Esi :=   BCi  xor ((not BCo)and   BCu );
          Eso :=   BCo  xor ((not BCu)and   BCa );
          Esu :=   BCu  xor ((not BCa)and   BCe );

          //    prepareTheta
          BCa := Eba xor Ega xor Eka xor Ema xor Esa;
          BCe := Ebe xor Ege xor Eke xor Eme xor Ese;
          BCi := Ebi xor Egi xor Eki xor Emi xor Esi;
          BCo := Ebo xor Ego xor Eko xor Emo xor Eso;
          BCu := Ebu xor Egu xor Eku xor Emu xor Esu;

          //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
          aDa := BCu xor ROL(BCe, 1);
          aDe := BCa xor ROL(BCi, 1);
          aDi := BCe xor ROL(BCo, 1);
          aDo := BCi xor ROL(BCu, 1);
          aDu := BCo xor ROL(BCa, 1);

          Eba := Eba xor ADa;
          BCa := Eba;
          Ege := Ege xor ADe;
          BCe := ROL(Ege, 44);
          Eki := Eki xor ADi;
          BCi := ROL(Eki, 43);
          Emo := Emo xor ADo;
          BCo := ROL(Emo, 21);
          Esu := Esu xor ADu;
          BCu := ROL(Esu, 14);
          Aba :=   BCa  xor ((not BCe)and   BCi );
          Aba := Aba xor (cKeccakF_RoundConstants[round+1]);
          Abe :=   BCe  xor ((not BCi)and   BCo );
          Abi :=   BCi  xor ((not BCo)and   BCu );
          Abo :=   BCo  xor ((not BCu)and   BCa );
          Abu :=   BCu  xor ((not BCa)and   BCe );

          Ebo := Ebo xor ADo;
          BCa := ROL(Ebo, 28);
          Egu := Egu xor ADu;
          BCe := ROL(Egu, 20);
          Eka := Eka xor ADa;
          BCi := ROL(Eka, 3);
          Eme := Eme xor ADe;
          BCo := ROL(Eme, 45);
          Esi := Esi xor ADi;
          BCu := ROL(Esi, 61);
          Aga :=   BCa  xor ((not BCe)and   BCi );
          Age :=   BCe  xor ((not BCi)and   BCo );
          Agi :=   BCi  xor ((not BCo)and   BCu );
          Ago :=   BCo  xor ((not BCu)and   BCa );
          Agu :=   BCu  xor ((not BCa)and   BCe );

          Ebe := Ebe xor ADe;
          BCa := ROL(Ebe, 1);
          Egi := Egi xor aDi;
          BCe := ROL(Egi, 6);
          Eko := Eko xor ADo;
          BCi := ROL(Eko, 25);
          Emu := Emu xor ADu;
          BCo := ROL(Emu, 8);
          Esa := Esa xor ADa;
          BCu := ROL(Esa, 18);
          Aka :=   BCa  xor ((not BCe)and   BCi );
          Ake :=   BCe  xor ((not BCi)and   BCo );
          Aki :=   BCi  xor ((not BCo)and   BCu );
          Ako :=   BCo  xor ((not BCu)and   BCa );
          Aku :=   BCu  xor ((not BCa)and   BCe );

          Ebu := Ebu xor ADu;
          BCa := ROL(Ebu, 27);
          Ega := Ega xor ADa;
          BCe := ROL(Ega, 36);
          Eke := Eke xor ADe;
          BCi := ROL(Eke, 10);
          Emi := Emi xor ADi;
          BCo := ROL(Emi, 15);
          Eso := Eso xor ADo;
          BCu := ROL(Eso, 56);
          Ama :=   BCa  xor ((not BCe)and   BCi );
          Ame :=   BCe  xor ((not BCi)and   BCo );
          Ami :=   BCi  xor ((not BCo)and   BCu );
          Amo :=   BCo  xor ((not BCu)and   BCa );
          Amu :=   BCu  xor ((not BCa)and   BCe );

          Ebi := Ebi xor ADi;
          BCa := ROL(Ebi, 62);
          Ego := Ego xor ADo;
          BCe := ROL(Ego, 55);
          Eku := Eku xor ADu;
          BCi := ROL(Eku, 39);
          Ema := Ema Xor ADa;
          BCo := ROL(Ema, 41);
          Ese := Ese xor ADe;
          BCu := ROL(Ese, 2);
          Asa :=   BCa  xor ((not BCe)and   BCi );
          Ase :=   BCe  xor ((not BCi)and   BCo );
          Asi :=   BCi  xor ((not BCo)and   BCu );
          Aso :=   BCo  xor ((not BCu)and   BCa );
          Asu :=   BCu  xor ((not BCa)and   BCe );

          inc(round, 2);
      end;

      //copyToState(state, A)
      state[ 0] := Aba;
      state[ 1] := Abe;
      state[ 2] := Abi;
      state[ 3] := Abo;
      state[ 4] := Abu;
      state[ 5] := Aga;
      state[ 6] := Age;
      state[ 7] := Agi;
      state[ 8] := Ago;
      state[ 9] := Agu;
      state[10] := Aka;
      state[11] := Ake;
      state[12] := Aki;
      state[13] := Ako;
      state[14] := Aku;
      state[15] := Ama;
      state[16] := Ame;
      state[17] := Ami;
      state[18] := Amo;
      state[19] := Amu;
      state[20] := Asa;
      state[21] := Ase;
      state[22] := Asi;
      state[23] := Aso;
      state[24] := Asu;
end;

///*************************************************
//* Name:        keccak_init
//*
//* Description: Initializes the Keccak state.
//*
//* Arguments:   - uint64_t *s: pointer to Keccak state
//**************************************************/
procedure keccak_init( var s : TKeccakStateData );
begin
     FillChar( s, sizeof(s), 0);
end;

///*************************************************
//* Name:        keccak_absorb
//*
//* Description: Absorb step of Keccak; incremental.
//*
//* Arguments:   - uint64_t *s: pointer to Keccak state
//*              - unsigned int pos: position in current block to be absorbed
//*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
//*              - const uint8_t *in: pointer to input to be absorbed into s
//*              - size_t inlen: length of input in bytes
//*
//* Returns new position pos in current block
//**************************************************/
function keccak_absorb( var s : TKeccakStateData; pos, r : UInt32; inData : PByte; inLen : Integer ) : UInt32;
var i : integer;
begin
     while pos + UInt32(inlen) >= r do
     begin
          for i := pos to r - 1 do
          begin
               s[i div 8] := s[i div 8] xor UInt64( (UInt64((inData^) shl (8*(i mod 8)))));
               inc(inData);
          end;
          dec(inLen, r - pos);

          KeccakF1600_StatePermute(s);
          pos := 0;
     end;

     Result := pos;
     if inlen > 0 then
     begin
          for i := pos to pos + UInt32(inlen) - 1 do
          begin
               s[i div 8] := s[i div 8] xor UInt64( (UInt64(inData^) shl (8*(i mod 8))));
               inc(inData);
          end;

          inc(Result, UInt32(inlen));
     end;
end;

///*************************************************
//* Name:        keccak_finalize
//*
//* Description: Finalize absorb step.
//*
//* Arguments:   - uint64_t *s: pointer to Keccak state
//*              - unsigned int pos: position in current block to be absorbed
//*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
//*              - uint8_t p: domain separation byte
//**************************************************/
procedure keccak_finalize(var s : TKeccakStateData; pos, r : UInt32; p : byte);
begin
     s[pos div 8] := s[pos div 8] xor UInt64( (UInt64(p) shl (8*(pos mod 8))) );
     s[r div 8 - 1] := s[ r div 8 - 1] xor UInt64($8000000000000000); // (UInt64(1) shl 63));
end;

///*************************************************
//* Name:        keccak_squeeze
//*
//* Description: Squeeze step of Keccak. Squeezes arbitratrily many bytes.
//*              Modifies the state. Can be called multiple times to keep
//*              squeezing, i.e., is incremental.
//*
//* Arguments:   - uint8_t *out: pointer to output
//*              - size_t outlen: number of bytes to be squeezed (written to out)
//*              - uint64_t *s: pointer to input/output Keccak state
//*              - unsigned int pos: number of bytes in current block already squeezed
//*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
//*
//* Returns new position pos in current block
//**************************************************/
function keccak_squeeze( outData : PByte; outLen : integer; var s : TKeccakStateData; pos, r : UInt32) : UInt32;
var i : UInt32;
begin
     while outLen > 0 do
     begin
          if pos = r then
          begin
               KeccakF1600_StatePermute(s);
               pos := 0;
          end;

          i := pos;
          while (i < r) and (i < pos + UInt32(outlen)) do
          begin
               outData^ := Byte( s[i div 8] shr (8*(i mod 8)) );
               inc(outData);
               inc(i);
          end;

          dec(outlen, i-pos);
          pos := i;
     end;

     Result := pos;
end;

///*************************************************
//* Name:        keccak_absorb_once
//*
//* Description: Absorb step of Keccak;
//*              non-incremental, starts by zeroeing the state.
//*
//* Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
//*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
//*              - const uint8_t *in: pointer to input to be absorbed into s
//*              - size_t inlen: length of input in bytes
//*              - uint8_t p: domain-separation byte for different Keccak-derived functions
//**************************************************/
procedure keccak_absorb_once(var s : TKeccakStateData; r : UInt32; inData : PByte; inLen : integer; p : Byte);
var i : integer;
    pIn : PByte;
begin
     FillChar(s, sizeof(s), 0);

     while UInt32(inLen) >= r do
     begin
          pIn := inData;
          for i := 0 to r div 8 - 1 do
          begin
               s[i] := s[i] xor load64(pIn);
               inc(pIn, 8);
          end;

          inc(inData, r);
          dec(inLen, r);

          KeccakF1600_StatePermute(s);
     end;

     for i := 0 to inLen - 1 do
     begin
          s[i div 8] := s[i div 8] xor UInt64( (UInt64(inData^) shl (8*(i mod 8))) );
          inc(inData);
     end;

     s[inLen div 8] := s[inLen div 8] xor UInt64( (UInt64(p) shl (8*(inLen mod 8))));
     s[(r - 1) div 8] := s[(r - 1) div 8] xor $8000000000000000; // 1 shl 63 xx; //UInt64( (UInt64(1) shl 63));
end;

///*************************************************
//* Name:        keccak_squeezeblocks
//*
//* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
//*              Modifies the state. Can be called multiple times to keep
//*              squeezing, i.e., is incremental. Assumes zero bytes of current
//*              block have already been squeezed.
//*
//* Arguments:   - uint8_t *out: pointer to output blocks
//*              - size_t nblocks: number of blocks to be squeezed (written to out)
//*              - uint64_t *s: pointer to input/output Keccak state
//*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
//**************************************************/
procedure keccak_squeezeblocks(outData : PByte; nblocks : integer; var s : TKeccakStateData; r : UInt32);
var i: Integer;
    pOut : PByte;
begin
     while nblocks > 0 do
     begin
          KeccakF1600_StatePermute(s);

          pOut := outData;
          for i := 0 to r div 8 - 1 do
          begin
               store64(pOut, s[i]);
               inc(pOut, 8);
          end;

          inc(outData, r);
          dec(nblocks);
     end;
end;

///*************************************************
//* Name:        shake128_init
//*
//* Description: Initilizes Keccak state for use as SHAKE128 XOF
//*
//* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
//**************************************************/
procedure shake128_init(var state : TKeccakState);
begin
     keccak_init(state.s);
     state.pos := 0;
end;

///*************************************************
//* Name:        shake128_absorb
//*
//* Description: Absorb step of the SHAKE128 XOF; incremental.
//*
//* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
//*              - const uint8_t *in: pointer to input to be absorbed into s
//*              - size_t inlen: length of input in bytes
//**************************************************/
procedure shake128_absorb(var state : TKeccakState; inData : PByte; inLen : integer);
begin
     state.pos := keccak_absorb(state.s, state.pos, SHAKE128_RATE, inData, inLen);
end;

///*************************************************
//* Name:        shake128_finalize
//*
//* Description: Finalize absorb step of the SHAKE128 XOF.
//*
//* Arguments:   - keccak_state *state: pointer to Keccak state
//**************************************************/
procedure shake128_finalize(var state : TKeccakState);
begin
     keccak_finalize(state.s, state.pos, SHAKE128_RATE, $1F);
     state.pos := SHAKE128_RATE;
end;

///*************************************************
//* Name:        shake128_squeeze
//*
//* Description: Squeeze step of SHAKE128 XOF. Squeezes arbitraily many
//*              bytes. Can be called multiple times to keep squeezing.
//*
//* Arguments:   - uint8_t *out: pointer to output blocks
//*              - size_t outlen : number of bytes to be squeezed (written to output)
//*              - keccak_state *s: pointer to input/output Keccak state
//**************************************************/
procedure shake128_squeeze( outData : PByte; outLen : integer; var state : TKeccakState);
begin
     state.pos := keccak_squeeze(outData, outLen, state.s, state.pos, SHAKE128_RATE);
end;

///*************************************************
//* Name:        shake128_absorb_once
//*
//* Description: Initialize, absorb into and finalize SHAKE128 XOF; non-incremental.
//*
//* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
//*              - const uint8_t *in: pointer to input to be absorbed into s
//*              - size_t inlen: length of input in bytes
//**************************************************/
procedure shake128_absorb_once(var state : TKeccakState; inData : PByte; inLen : integer);
begin
     keccak_absorb_once(state.s, SHAKE128_RATE, inData, inLen, $1F);
     state.pos := SHAKE128_RATE;
end;

///*************************************************
//* Name:        shake128_squeezeblocks
//*
//* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
//*              SHAKE128_RATE bytes each. Can be called multiple times
//*              to keep squeezing. Assumes new block has not yet been
//*              started (state->pos = SHAKE128_RATE).
//*
//* Arguments:   - uint8_t *out: pointer to output blocks
//*              - size_t nblocks: number of blocks to be squeezed (written to output)
//*              - keccak_state *s: pointer to input/output Keccak state
//**************************************************/
procedure shake128_squeezeblocks( outData : PByte; nBlocks : integer; var state : TKeccakState);
begin
     keccak_squeezeblocks(outData, nBlocks, state.s, SHAKE128_RATE);
end;

///*************************************************
//* Name:        shake256_init
//*
//* Description: Initilizes Keccak state for use as SHAKE256 XOF
//*
//* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
//**************************************************/
procedure shake256_init(var state : TKeccakState);
begin
     keccak_init(state.s);
     state.pos := 0;
end;

///*************************************************
//* Name:        shake256_absorb
//*
//* Description: Absorb step of the SHAKE256 XOF; incremental.
//*
//* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
//*              - const uint8_t *in: pointer to input to be absorbed into s
//*              - size_t inlen: length of input in bytes
//**************************************************/
procedure shake256_absorb(var state : TKeccakState; inData : PByte; inLen : integer);
begin
     state.pos := keccak_absorb(state.s, state.pos, SHAKE256_RATE, inData, inLen);
end;

///*************************************************
//* Name:        shake256_finalize
//*
//* Description: Finalize absorb step of the SHAKE256 XOF.
//*
//* Arguments:   - keccak_state *state: pointer to Keccak state
//**************************************************/
procedure shake256_finalize(var state : TKeccakState);
begin
     keccak_finalize(state.s, state.pos, SHAKE256_RATE, $1F);
     state.pos := SHAKE256_RATE;
end;

///*************************************************
//* Name:        shake256_squeeze
//*
//* Description: Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
//*              bytes. Can be called multiple times to keep squeezing.
//*
//* Arguments:   - uint8_t *out: pointer to output blocks
//*              - size_t outlen : number of bytes to be squeezed (written to output)
//*              - keccak_state *s: pointer to input/output Keccak state
//**************************************************/
procedure shake256_squeeze(outData : PByte; outLen : integer; var state : TKeccakState);
begin
     state.pos := keccak_squeeze(outData, outLen, state.s, state.pos, SHAKE256_RATE);
end;

///*************************************************
//* Name:        shake256_absorb_once
//*
//* Description: Initialize, absorb into and finalize SHAKE256 XOF; non-incremental.
//*
//* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
//*              - const uint8_t *in: pointer to input to be absorbed into s
//*              - size_t inlen: length of input in bytes
//**************************************************/
procedure shake256_absorb_once(var state : TKeccakState; inData : PByte; inLen : integer);
begin
     keccak_absorb_once(state.s, SHAKE256_RATE, inData, inLen, $1F);
     state.pos := SHAKE256_RATE;
end;

///*************************************************
//* Name:        shake256_squeezeblocks
//*
//* Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
//*              SHAKE256_RATE bytes each. Can be called multiple times
//*              to keep squeezing. Assumes next block has not yet been
//*              started (state->pos = SHAKE256_RATE).
//*
//* Arguments:   - uint8_t *out: pointer to output blocks
//*              - size_t nblocks: number of blocks to be squeezed (written to output)
//*              - keccak_state *s: pointer to input/output Keccak state
//**************************************************/
procedure shake256_squeezeblocks(outData : PByte; nblocks : integer; var state : TKeccakState);
begin
     keccak_squeezeblocks(outData, nBlocks, state.s, SHAKE256_RATE);
end;

///*************************************************
//* Name:        shake128
//*
//* Description: SHAKE128 XOF with non-incremental API
//*
//* Arguments:   - uint8_t *out: pointer to output
//*              - size_t outlen: requested output length in bytes
//*              - const uint8_t *in: pointer to input
//*              - size_t inlen: length of input in bytes
//**************************************************/
procedure shake128(outData : PByte; outLen : integer; inData : PByte; inLen : integer);
var nBlocks : integer;
    state : TKeccakState;
begin
     shake128_absorb_once(state, inData, inLen);
     nblocks := outLen div SHAKE128_RATE;
     shake128_squeezeblocks(outData, nBlocks, state);
     dec(outLen, nBlocks*SHAKE128_RATE);
     inc(outData, nblocks*SHAKE128_RATE);
     shake128_squeeze(outData, outLen, state);
end;

///*************************************************
//* Name:        shake256
//*
//* Description: SHAKE256 XOF with non-incremental API
//*
//* Arguments:   - uint8_t *out: pointer to output
//*              - size_t outlen: requested output length in bytes
//*              - const uint8_t *in: pointer to input
//*              - size_t inlen: length of input in bytes
//**************************************************/
procedure shake256(outData : PByte; outLen : integer; inData : PByte; inLen : integer);
var nBlocks : integer;
    state : TKeccakState;
begin
     shake256_absorb_once(state, inData, inLen);
     nblocks := outLen div SHAKE256_RATE;
     shake256_squeezeblocks(outData, nBlocks, state);
     dec(outLen, nBlocks*SHAKE256_RATE);
     inc(outData, nblocks*SHAKE256_RATE);
     shake256_squeeze(outData, outLen, state);
end;

///*************************************************
//* Name:        sha3_256
//*
//* Description: SHA3-256 with non-incremental API
//*
//* Arguments:   - uint8_t *h: pointer to output (32 bytes)
//*              - const uint8_t *in: pointer to input
//*              - size_t inlen: length of input in bytes
//**************************************************/
procedure sha3_256(var h : TSHA256Hash; inData : PByte; inLen : integer);
var i : integer;
    s : TKeccakStateData;
begin
     keccak_absorb_once(s, SHA3_256_RATE, inData, inLen, $06);
     KeccakF1600_StatePermute(s);
     for i := 0 to 3 do
         store64(@h[8*i], s[i]);
end;

///*************************************************
//* Name:        sha3_512
//*
//* Description: SHA3-512 with non-incremental API
//*
//* Arguments:   - uint8_t *h: pointer to output (64 bytes)
//*              - const uint8_t *in: pointer to input
//*              - size_t inlen: length of input in bytes
//**************************************************/
procedure sha3_512(var h : TSHA512Hash; inData : PByte; inLen : integer);
var i : integer;
    s : TKeccakStateData;
begin
     keccak_absorb_once(s, SHA3_512_RATE, inData, inLen, $06);
     KeccakF1600_StatePermute(s);
     for i := 0 to 7 do
         store64(@h[8*i], s[i]);
end;

end.
