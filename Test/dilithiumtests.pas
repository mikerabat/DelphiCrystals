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

unit dilithiumtests;

{$IFDEF FPC}
{$mode Delphi}{$H+}
{$ENDIF}

interface

uses Classes, SysUtils;

function TestShake : boolean;
function TestSign_Dilithium_2 : boolean;
function TestSign_Dilithium_3 : boolean;
function TestSign_Dilithium_5 : boolean;

implementation

uses dilithium, cryptRnd, fips202;

const CTXLEN = 14;
      MLEN = 59;
      MLEN_CRYPTO_Max = 4627 + 59;
      {$IFDEF FPC}
      NTests = 50; // my raspi takes quite some time here -> reduce tests ;)
      {$ELSE}
      NTests = 1000;
      {$ENDIF}


function TestShake : boolean;
var buf : Array[0..31] of Byte;
    i: Integer;
const cRef : Array[0..31] of byte = ($4C, $83, $82, $07, $F7, $A3, $08, $8B, $F0, $11, $C6, $D2, $21, $A1, $72, $BF,
                                     $F9, $25, $7C, $8F, $4B, $80, $7B, $A9, $D4, $C8, $51, $FD, $20, $26, $3E, $FB );
begin
     shake256(@buf[0], 32, nil, 0);

     Result := CompareMem( @buf[0], @cRef[0], Length(cRef));

     if not Result then
     begin
          for i := 0 to 32 - 1 do
          Write(IntToHex(buf[i], 2) + ' ');
          Writeln;
     end
     else
         Writeln('Test hash success');
end;

function TestSign_Dilithium_2 : boolean;
const cDilithiumCtx : AnsiString = 'test_dilitium';
var i : integer;
    ret : boolean;
    smlen : integer;
    ctx : Array[0..CTXLEN - 1] of Byte;
    m : Array[0..MLEN_CRYPTO_MAX - 1] of Byte;
    m2 : Array[0..MLEN_CRYPTO_MAX - 1] of Byte;
    sm : Array[0..MLEN_CRYPTO_MAX - 1] of byte;
    mc : Array[0..MLEN_CRYPTO_MAX - 1] of Byte;
    pk : TDilithium_2_PublicBytes;
    sk : TDilithium_2_SecretBytes;
    sig : TDilithium_2_SignatureBytes absolute sm;
    amlen : integer;
    idx : integer;
    oldVal : byte;
begin
     Result := True;
     FillChar(ctx, sizeof(ctx), 0);
     Move(PAnsiChar(cDilithiumCtx)^, ctx[0], CTXLEN);


     smlen := 0;
     amlen := MLEN;

     for i := 0 to NTests - 1 do
     begin
          Write('Test ', i + 1, ' ... ');
          CryptRandom(m[0], Length(m));

          // ###########################################
          // #### Test for just generating a signature
          pqcrystals_dilithium2_ref_keypair(pk, sk);
          aMLen := MLEN;
          ret := pqcrystals_dilithium2_ref_signature(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, sk);
          if not ret then
          begin
               Writeln('Signature creation failed');
               Result := False;
          end
          else
          begin
               ret := pqcrystals_dilithium2_ref_verify(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, pk);

               if not ret then
               begin
                    Writeln('Failed');
                    Result := False;
                    continue;
               end
               else
                   Write('Sign verify Success');
          end;

          // ###########################################
          // #### Test for a combined message and sign buffer
          smLen := 0;
          Write('   Test message + sign...');
          ret := pqcrystals_dilithium2_ref_sign( @sm[0], smLen, @m[0], MLEN, @ctx[0], CTXLEN, sk);
          if not ret then
          begin
               Writeln('Message signing failed');
               Result := False;
               continue;
          end
          else
          begin
               amlen := 0;
               ret := pqcrystals_dilithium2_ref_open(@m2[0], amlen, @sm[0], smlen, @ctx[0], CTXLEN, pk);

               if not ret then
               begin
                    Writeln('Failed');
                    Result := False;
                    continue;
               end
               else
               begin
                    Write('Success');

                    if smlen <> MLEN + sizeof(TDilithium_2_SignatureBytes) then
                    begin
                         Writeln(' ... Signed message lengths failed');
                         Result := False;
                         continue;
                    end;
                    if amlen <> MLEN then
                    begin
                         Writeln(' ... Message length failed');
                         Result := False;
                         continue;
                    end;
                    if not CompareMem(@m2[0], @m[0], MLEN) then
                    begin
                         Writeln(' ... Messages do not match (FAILED');
                         Result := False;
                         continue;
                    end;
               end;
          end;

          // ###########################################
          // #### Test verificaiton fail by a random change in the message ->
          Write('   Test random tampering...');

          aMLen := MLEN;
          ret := pqcrystals_dilithium2_ref_signature(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, sk);
          if not ret then
          begin
               Writeln('Signature creation failed');
               Result := False;
          end
          else
          begin
               // randomly change a byte in the message
               Move(m[0], mc[0], aMLEN);

               idx := random(aMLEN);
               while mc[idx] = m[idx] do
                     mc[idx] := random($FF);

               ret := pqcrystals_dilithium2_ref_verify(sig, smlen, @mc[0], aMLEN, @ctx[0], CTXLEN, pk);

               if ret then
               begin
                    Writeln('FAILED');
                    Result := False;
               end
               else
               begin
                    idx := random(smlen);
                    oldVal := sig[idx];
                    while sig[idx] = oldVal do
                          sig[idx] := random($FF);

                    ret := pqcrystals_dilithium2_ref_verify(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, pk);

                    if ret then
                    begin
                         Writeln('FAILED');
                         Result := False;
                    end
                    else
                        Writeln('SUCCESS');
               end;
          end;
     end;
end;

function TestSign_Dilithium_3 : boolean;
const cDilithiumCtx : AnsiString = 'test_dilitium';
var i : integer;
    ret : boolean;
    smlen : integer;
    ctx : Array[0..CTXLEN - 1] of Byte;
    m : Array[0..MLEN_CRYPTO_MAX - 1] of Byte;
    m2 : Array[0..MLEN_CRYPTO_MAX - 1] of Byte;
    sm : Array[0..MLEN_CRYPTO_MAX - 1] of byte;
    mc : Array[0..MLEN_CRYPTO_MAX - 1] of Byte;
    pk : TDilithium_3_PublicBytes;
    sk : TDilithium_3_SecretBytes;
    sig : TDilithium_3_SignatureBytes absolute sm;
    amlen : integer;
    idx : integer;
    oldVal : byte;
begin
     Result := True;
     FillChar(ctx, sizeof(ctx), 0);
     Move(PAnsiChar(cDilithiumCtx)^, ctx[0], CTXLEN);


     smlen := 0;
     amlen := MLEN;

     for i := 0 to NTests - 1 do
     begin
          Write('Test ', i + 1, ' ... ');
          CryptRandom(m[0], Length(m));

          // ###########################################
          // #### Test for just generating a signature
          pqcrystals_dilithium3_ref_keypair(pk, sk);
          aMLen := MLEN;
          ret := pqcrystals_dilithium3_ref_signature(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, sk);
          if not ret then
          begin
               Writeln('Signature creation failed');
               Result := False;
          end
          else
          begin
               ret := pqcrystals_dilithium3_ref_verify(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, pk);

               if not ret then
               begin
                    Writeln('Failed');
                    Result := False;
                    continue;
               end
               else
                   Write('Sign verify Success');
          end;

          // ###########################################
          // #### Test for a combined message and sign buffer
          smLen := 0;
          Write('   Test message + sign...');
          ret := pqcrystals_dilithium3_ref_sign( @sm[0], smLen, @m[0], MLEN, @ctx[0], CTXLEN, sk);
          if not ret then
          begin
               Writeln('Message signing failed');
               Result := False;
               continue;
          end
          else
          begin
               amlen := 0;
               ret := pqcrystals_dilithium3_ref_open(@m2[0], amlen, @sm[0], smlen, @ctx[0], CTXLEN, pk);

               if not ret then
               begin
                    Writeln('Failed');
                    Result := False;
                    continue;
               end
               else
               begin
                    Write('Success');

                    if smlen <> MLEN + sizeof(TDilithium_3_SignatureBytes) then
                    begin
                         Writeln(' ... Signed message lengths failed');
                         Result := False;
                         continue;
                    end;
                    if amlen <> MLEN then
                    begin
                         Writeln(' ... Message length failed');
                         Result := False;
                         continue;
                    end;
                    if not CompareMem(@m2[0], @m[0], MLEN) then
                    begin
                         Writeln(' ... Messages do not match (FAILED');
                         Result := False;
                         continue;
                    end;
               end;
          end;

          // ###########################################
          // #### Test verificaiton fail by a random change in the message ->
          Write('   Test random tampering...');

          aMLen := MLEN;
          ret := pqcrystals_dilithium3_ref_signature(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, sk);
          if not ret then
          begin
               Writeln('Signature creation failed');
               Result := False;
          end
          else
          begin
               // randomly change a byte in the message
               Move(m[0], mc[0], aMLEN);

               idx := random(aMLEN);
               while mc[idx] = m[idx] do
                     mc[idx] := random($FF);

               ret := pqcrystals_dilithium3_ref_verify(sig, smlen, @mc[0], aMLEN, @ctx[0], CTXLEN, pk);

               if ret then
               begin
                    Writeln('FAILED');
                    Result := False;
               end
               else
               begin
                    idx := random(smlen);
                    oldVal := sig[idx];
                    while sig[idx] = oldVal do
                          sig[idx] := random($FF);

                    ret := pqcrystals_dilithium3_ref_verify(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, pk);

                    if ret then
                    begin
                         Writeln('FAILED');
                         Result := False;
                    end
                    else
                        Writeln('SUCCESS');
               end;
          end;
     end;
end;

function TestSign_Dilithium_5 : boolean;
const cDilithiumCtx : AnsiString = 'test_dilitium';
var i : integer;
    ret : boolean;
    smlen : integer;
    ctx : Array[0..CTXLEN - 1] of Byte;
    m : Array[0..MLEN_CRYPTO_MAX - 1] of Byte;
    m2 : Array[0..MLEN_CRYPTO_MAX - 1] of Byte;
    sm : Array[0..MLEN_CRYPTO_MAX - 1] of byte;
    mc : Array[0..MLEN_CRYPTO_MAX - 1] of Byte;
    pk : TDilithium_5_PublicBytes;
    sk : TDilithium_5_SecretBytes;
    sig : TDilithium_5_SignatureBytes absolute sm;
    amlen : integer;
    idx : integer;
    oldVal : byte;
begin
     Result := True;
     FillChar(ctx, sizeof(ctx), 0);
     Move(PAnsiChar(cDilithiumCtx)^, ctx[0], CTXLEN);


     smlen := 0;
     amlen := MLEN;

     for i := 0 to NTests - 1 do
     begin
          Write('Test ', i + 1, ' ... ');
          CryptRandom(m[0], Length(m));

          // ###########################################
          // #### Test for just generating a signature
          pqcrystals_dilithium5_ref_keypair(pk, sk);
          aMLen := MLEN;
          ret := pqcrystals_dilithium5_ref_signature(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, sk);
          if not ret then
          begin
               Writeln('Signature creation failed');
               Result := False;
          end
          else
          begin
               ret := pqcrystals_dilithium5_ref_verify(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, pk);

               if not ret then
               begin
                    Writeln('Failed');
                    Result := False;
                    continue;
               end
               else
                   Write('Sign verify Success');
          end;

          // ###########################################
          // #### Test for a combined message and sign buffer
          smLen := 0;
          Write('   Test message + sign...');
          ret := pqcrystals_dilithium5_ref_sign( @sm[0], smLen, @m[0], MLEN, @ctx[0], CTXLEN, sk);
          if not ret then
          begin
               Writeln('Message signing failed');
               Result := False;
               continue;
          end
          else
          begin
               amlen := 0;
               ret := pqcrystals_dilithium5_ref_open(@m2[0], amlen, @sm[0], smlen, @ctx[0], CTXLEN, pk);

               if not ret then
               begin
                    Writeln('Failed');
                    Result := False;
                    continue;
               end
               else
               begin
                    Write('Success');

                    if smlen <> MLEN + sizeof(TDilithium_5_SignatureBytes) then
                    begin
                         Writeln(' ... Signed message lengths failed');
                         Result := False;
                         continue;
                    end;
                    if amlen <> MLEN then
                    begin
                         Writeln(' ... Message length failed');
                         Result := False;
                         continue;
                    end;
                    if not CompareMem(@m2[0], @m[0], MLEN) then
                    begin
                         Writeln(' ... Messages do not match (FAILED');
                         Result := False;
                         continue;
                    end;
               end;
          end;

          // ###########################################
          // #### Test verificaiton fail by a random change in the message ->
          Write('   Test random tampering...');

          aMLen := MLEN;
          ret := pqcrystals_dilithium5_ref_signature(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, sk);
          if not ret then
          begin
               Writeln('Signature creation failed');
               Result := False;
          end
          else
          begin
               // randomly change a byte in the message
               Move(m[0], mc[0], aMLEN);

               idx := random(aMLEN);
               while mc[idx] = m[idx] do
                     mc[idx] := random($FF);

               ret := pqcrystals_dilithium5_ref_verify(sig, smlen, @mc[0], aMLEN, @ctx[0], CTXLEN, pk);

               if ret then
               begin
                    Writeln('FAILED');
                    Result := False;
               end
               else
               begin
                    idx := random(smlen);
                    oldVal := sig[idx];
                    while sig[idx] = oldVal do
                          sig[idx] := random($FF);

                    ret := pqcrystals_dilithium5_ref_verify(sig, smlen, @m[0], aMLEN, @ctx[0], CTXLEN, pk);

                    if ret then
                    begin
                         Writeln('FAILED');
                         Result := False;
                    end
                    else
                        Writeln('SUCCESS');
               end;
          end;
     end;
end;

end.

