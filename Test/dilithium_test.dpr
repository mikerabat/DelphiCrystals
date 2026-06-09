program dilithium_test;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  StrUtils,
  fips202 in '..\src\fips202.pas',
  dilithium in '..\src\dilithium.pas';

const CTXLEN = 14;
      MLEN = 59;
      CRYPTO_BYTES_MAX = 4627;
      MLEN_CRYPTO_Max = 4627 + 59;
      NTests = 1000;


procedure TestShake;
var buf : Array[0..31] of Byte;
    i: Integer;
const cRef : Array[0..31] of byte = ($4C, $83, $82, $07, $F7, $A3, $08, $8B, $F0, $11, $C6, $D2, $21, $A1, $72, $BF,
                                     $F9, $25, $7C, $8F, $4B, $80, $7B, $A9, $D4, $C8, $51, $FD, $20, $26, $3E, $FB );
begin
     shake256(@buf[0], 32, nil, 0);

     if not CompareMem( @buf[0], @cRef[0], Length(cRef)) then
     begin
          for i := 0 to 32 - 1 do
          Write(IntToHex(buf[i], 2) + ' ');
          Writeln;
     end
     else
         Writeln('Test hash success');
end;

// newer BCrypt.h API
const BCRYPT_USE_SYSTEM_PREFERRED_RNG = $00000002;   // hAlgorithm needs to be null then

type
  BCrypt_ALG_HANDLE = Pointer;
  function BCryptGenRandom(hAlgorith : BCRYPT_ALG_HANDLE; pbBuffer : PByte;
                               cbBuffer : ULong; dwFlags : ULong ) : Longint; stdcall; external 'BCrypt.dll';

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
          BCryptGenRandom(nil, @m[0], Length(m), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

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
          BCryptGenRandom(nil, @m[0], Length(m), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

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
          BCryptGenRandom(nil, @m[0], Length(m), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

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

var res2, res3, res5: boolean;
begin
  try
    Writeln('Simple "shake256" test');
    TestShake;

    Writeln('Test Dilithium 5');
    res5 := TestSign_Dilithium_5;
    Writeln('Test Dilithium 3');
    res3 := TestSign_Dilithium_3;
    Writeln('Test Dilithium 2');
    res2 := TestSign_Dilithium_2;

    Writeln;
    Writeln('Overall Result:');
    Writeln('Dilithium 5: ', Ifthen( res5, 'SUCCESS', 'FAILED'));
    Writeln('Dilithium 3: ', Ifthen( res3, 'SUCCESS', 'FAILED'));
    Writeln('Dilithium 2: ', Ifthen( res2, 'SUCCESS', 'FAILED'));


    Writeln('Hit enter to end...');
    readln
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
